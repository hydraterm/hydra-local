//! Fail-soft transport for an optional out-of-process desktop extension.
//!
//! The public desktop owns local terminal behavior. The separately installed private extension is
//! discovered only as a fixed sibling of this executable and is invoked with the single literal
//! argument `extension`. Every exchange is a fresh child with two bounded line-delimited phases:
//! host/extension hello negotiation, then exactly one typed request/response pair. Enrollment
//! material is serialized only into the second stdin frame; it is never put in argv, the
//! environment, an error, or a log message.

use maestro_extension_api::{
    decode_hello_frame, negotiate, validate_remote_desktop_response, Capability, EnrollmentCode,
    ExtensionHello, FilesystemModeMigrationNotice, FilesystemModeMigrationNoticeId,
    FilesystemModeMigrationPhase, KnownCapability, LeaseCursor, LeaseId, RemoteDesktopErrorCode,
    RemoteDesktopExchangeError, RemoteDesktopExtensionResponse, RemoteDesktopHostRequest,
    RemoteDesktopRequestId, RemoteDesktopStatus, SessionKey, ViewportGeometry,
    ViewportReclaimReason, MAX_EXTENSION_FRAME_BYTES,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{OnceLock, RwLock};
use std::thread;
use std::time::{Duration, Instant};

const EXTENSION_BINARY_NAME: &str = "hydra-agent";
const EXTENSION_COMMAND: &str = "extension";
// Lifecycle Status resumes one bounded provider retry (8s today) plus exact
// local cleanup proofs. Keep that child budget separate from the low-latency
// viewport/read-only snapshots below.
const LIFECYCLE_STATUS_TIMEOUT: Duration = Duration::from_secs(30);
const STATUS_TIMEOUT: Duration = Duration::from_secs(2);
const MUTATION_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const WORKER_COMMAND_CAPACITY: usize = 8;
const WORKER_UPDATE_CAPACITY: usize = 8;
const CHILD_FRAME_CAPACITY: usize = 2;
const RETIRED_EXTENSION_ENVIRONMENT: [&str; 6] = [
    "CODE",
    "ENROLLMENT_CODE",
    "ENROLL_CODE_FILE",
    "CLOUD",
    "CLOUD_PUBKEY",
    "HYDRA_AGENT_DIR",
];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RemoteExtensionProjection {
    pub available: bool,
    pub enrolled: bool,
    pub account_id: Option<String>,
    pub remote_open: bool,
    pub active_connections: u16,
    pub remote_owned_sessions: Vec<String>,
    pub filesystem_mode_migration: Option<FilesystemModeMigrationNotice>,
}

impl RemoteExtensionProjection {
    pub fn remote_winsize(&self) -> bool {
        !self.remote_owned_sessions.is_empty()
    }

    fn unavailable() -> Self {
        Self::default()
    }
}

static CURRENT_PROJECTION: OnceLock<RwLock<RemoteExtensionProjection>> = OnceLock::new();

fn projection_cell() -> &'static RwLock<RemoteExtensionProjection> {
    CURRENT_PROJECTION.get_or_init(|| RwLock::new(RemoteExtensionProjection::default()))
}

pub fn current_projection() -> RemoteExtensionProjection {
    projection_cell()
        .read()
        .map(|projection| projection.clone())
        .unwrap_or_default()
}

pub fn publish_projection(projection: &RemoteExtensionProjection) {
    if let Ok(mut current) = projection_cell().write() {
        *current = projection.clone();
    }
}

/// Resolve only the private executable installed beside the running public host. The composed
/// product layouts are exactly:
///
/// - macOS: `/Applications/Hydra.app/Contents/Resources/bin/{maestro-app,hydra-agent}`;
/// - Linux: `/opt/hydra/bin/{maestro-app,hydra-agent}` (the `/usr/bin/hydraterms` launcher resolves
///   to the former before this process starts).
///
/// Source builds normally have no such sibling and therefore remain local-only. There is no PATH
/// lookup, environment override, repository fallback, or caller-supplied path in the product path.
pub fn discover_installed_extension(
    current_exe: Option<&Path>,
    is_executable_file: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    let candidate = current_exe?.parent()?.join(EXTENSION_BINARY_NAME);
    is_executable_file(&candidate).then_some(candidate)
}

fn installed_extension_path() -> Option<PathBuf> {
    discover_installed_extension(std::env::current_exe().ok().as_deref(), |path| {
        if !path.is_file() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::metadata(path)
                .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        }
        #[cfg(not(unix))]
        {
            true
        }
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtensionOperation {
    Refresh,
    Enroll,
    SetRemoteOpen,
    RemoveEnrollment,
    ApplyFilesystemModeMigration,
    AcknowledgeFilesystemModeMigration,
    ReclaimViewport,
    ReclaimAllViewports,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtensionUpdate {
    pub operation: ExtensionOperation,
    pub projection: RemoteExtensionProjection,
    pub error_message: Option<&'static str>,
}

enum WorkerCommand {
    Refresh,
    Enroll(EnrollmentCode),
    SetRemoteOpen(bool),
    RemoveEnrollment,
    ApplyFilesystemModeMigration(FilesystemModeMigrationNoticeId),
    AcknowledgeFilesystemModeMigration(FilesystemModeMigrationNoticeId),
    ReclaimViewport {
        session_id: SessionKey,
        reason: ViewportReclaimReason,
    },
    ReclaimAllViewports {
        reason: ViewportReclaimReason,
    },
    Shutdown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CachedViewport {
    session_id: SessionKey,
    lease_id: LeaseId,
    cursor: LeaseCursor,
    geometry: ViewportGeometry,
}

#[derive(Default)]
struct ViewportSnapshotCache {
    epoch: Option<u64>,
    sequence: u64,
    expires_at: Option<Instant>,
    viewports: BTreeMap<String, CachedViewport>,
    retired_epochs: BTreeSet<u64>,
}

impl ViewportSnapshotCache {
    fn invalidate_leases(&mut self) {
        self.expires_at = None;
        self.viewports.clear();
    }

    fn expire_if_needed(&mut self, now: Instant) {
        if self.expires_at.is_some_and(|deadline| now >= deadline) {
            // Keep epoch/sequence after expiry so an equal replay cannot resurrect and renew the
            // discarded leases. A higher same-epoch snapshot or a fresh process epoch may recover.
            self.invalidate_leases();
        }
    }

    fn sessions(&mut self, now: Instant) -> Vec<String> {
        self.expire_if_needed(now);
        self.viewports.keys().cloned().collect()
    }

    fn lease(&mut self, session_id: &SessionKey, now: Instant) -> Option<CachedViewport> {
        self.expire_if_needed(now);
        self.viewports.get(session_id.as_str()).cloned()
    }

    fn accept(
        &mut self,
        cursor: LeaseCursor,
        ttl_ms: u32,
        viewports: &maestro_extension_api::RemoteDesktopViewportList,
        received_at: Instant,
    ) -> Result<(), SnapshotCacheError> {
        match self.epoch {
            Some(epoch) if epoch == cursor.epoch() => {
                if cursor.sequence() <= self.sequence {
                    return Err(SnapshotCacheError::StaleOrReplayed);
                }
            }
            Some(_) if self.retired_epochs.contains(&cursor.epoch()) => {
                return Err(SnapshotCacheError::RetiredEpoch);
            }
            Some(epoch) => {
                // Epoch retirement is permanent for this worker lifetime. A bounded recent-only
                // list would eventually let an old process epoch resurrect after enough restarts.
                self.retired_epochs.insert(epoch);
                self.invalidate_leases();
            }
            None => {}
        }
        let expires_at = received_at
            .checked_add(Duration::from_millis(u64::from(ttl_ms)))
            .ok_or(SnapshotCacheError::InvalidExpiry)?;
        let mut next = BTreeMap::new();
        for viewport in viewports.iter() {
            next.insert(
                viewport.session_id().as_str().to_string(),
                CachedViewport {
                    session_id: viewport.session_id().clone(),
                    lease_id: viewport.lease_id().clone(),
                    cursor: viewport.cursor(),
                    geometry: viewport.geometry(),
                },
            );
        }
        self.epoch = Some(cursor.epoch());
        self.sequence = cursor.sequence();
        self.expires_at = Some(expires_at);
        self.viewports = next;
        Ok(())
    }

    fn remove_exact(&mut self, viewport: &CachedViewport) -> bool {
        let exact = self
            .viewports
            .get(viewport.session_id.as_str())
            .is_some_and(|current| current == viewport);
        if exact {
            self.viewports.remove(viewport.session_id.as_str());
        }
        exact
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SnapshotCacheError {
    StaleOrReplayed,
    RetiredEpoch,
    InvalidExpiry,
}

#[derive(Default)]
struct WorkerState {
    viewport: ViewportSnapshotCache,
    last_projection: RemoteExtensionProjection,
    /// Exact Applied notice for which the host has sent an acknowledgement request but has not yet
    /// observed an authoritative acknowledgement. A transport failure can happen after the child
    /// unlinks the receipt; a later capable Status-with-no-notice is then the idempotent proof that
    /// lets the preserved public latch converge instead of remaining stuck forever.
    pending_acknowledgement: Option<FilesystemModeMigrationNoticeId>,
}

impl WorkerState {
    fn projection_with_live_cache(&mut self, now: Instant) -> RemoteExtensionProjection {
        let sessions = self.viewport.sessions(now);
        if sessions.is_empty() && self.viewport.expires_at.is_none() {
            if self.last_projection.filesystem_mode_migration.is_none() {
                return RemoteExtensionProjection::unavailable();
            }
            let mut projection = self.last_projection.clone();
            projection.remote_owned_sessions.clear();
            return projection;
        }
        let mut projection = self.last_projection.clone();
        projection.remote_owned_sessions = sessions;
        projection
    }

    fn projection_after_exchange_error(
        &mut self,
        error: ExtensionTransportError,
        now: Instant,
    ) -> RemoteExtensionProjection {
        if error.is_validated_refusal() {
            // A negotiated, request-correlated Error frame proves that the installed extension and
            // lifecycle capability are still present. Preserve the last authoritative lifecycle
            // projection while expiring only its separately leased viewport snapshot. Treating this
            // typed refusal like a transport loss briefly published `available=false`, which hid the
            // enrollment result and cleared the one-time code before the next Status restored it.
            let mut projection = self.last_projection.clone();
            projection.available = true;
            projection.remote_owned_sessions = self.viewport.sessions(now);
            projection
        } else {
            // Spawn, framing, compatibility, I/O, child-exit, and timeout failures provide no proof
            // that the private capability remains available. Keep their existing fail-closed path.
            self.projection_with_live_cache(now)
        }
    }
}

/// A single background owner for optional-extension calls. A slow or malicious child can consume
/// only its bounded deadline; it never blocks the GTK/Tao owner loop or the app intent listener.
pub struct OptionalExtensionWorker {
    commands: SyncSender<WorkerCommand>,
    updates: Receiver<ExtensionUpdate>,
}

impl OptionalExtensionWorker {
    pub fn spawn() -> Self {
        let (commands_tx, commands_rx) = mpsc::sync_channel(WORKER_COMMAND_CAPACITY);
        let (updates_tx, updates_rx) = mpsc::sync_channel(WORKER_UPDATE_CAPACITY);
        // Thread creation is optional capability admission, not a desktop startup invariant. If
        // it fails, the closure (and both receiving/sending channel ends it owns) is dropped;
        // callers observe a disconnected worker and the app remains fully local-only.
        let _ = thread::Builder::new()
            .name("maestro-optional-extension".to_string())
            .spawn(move || worker_main(commands_rx, updates_tx));
        Self {
            commands: commands_tx,
            updates: updates_rx,
        }
    }

    pub fn refresh(&self) {
        // Periodic/manual refresh is coalescible. If lifecycle work already fills the bounded
        // queue, the worker's own poll tick will converge status later without growing memory.
        let _ = self.commands.try_send(WorkerCommand::Refresh);
    }

    pub fn enroll(&self, code: String) -> Result<(), &'static str> {
        require_no_pending_filesystem_migration()?;
        let code = EnrollmentCode::new(code).map_err(|_| "Enter a valid enrollment code.")?;
        queue_mutation(&self.commands, WorkerCommand::Enroll(code))
    }

    pub fn set_remote_open(&self, open: bool) -> Result<(), &'static str> {
        require_no_pending_filesystem_migration()?;
        queue_mutation(&self.commands, WorkerCommand::SetRemoteOpen(open))
    }

    pub fn remove_enrollment(&self) -> Result<(), &'static str> {
        require_no_pending_filesystem_migration()?;
        queue_mutation(&self.commands, WorkerCommand::RemoveEnrollment)
    }

    pub fn apply_filesystem_mode_migration(&self, notice_id: String) -> Result<(), &'static str> {
        let notice_id = FilesystemModeMigrationNoticeId::new(notice_id)
            .map_err(|_| "The filesystem-security notice changed. Refresh and try again.")?;
        let projection = current_projection();
        let notice = projection
            .filesystem_mode_migration
            .as_ref()
            .ok_or("The filesystem-security notice changed. Refresh and try again.")?;
        if notice.notice_id() != &notice_id
            || notice.phase() == FilesystemModeMigrationPhase::Applied
        {
            return Err("The filesystem-security notice changed. Refresh and try again.");
        }
        queue_mutation(
            &self.commands,
            WorkerCommand::ApplyFilesystemModeMigration(notice_id),
        )
    }

    pub fn acknowledge_filesystem_mode_migration(
        &self,
        notice_id: String,
    ) -> Result<(), &'static str> {
        let notice_id = FilesystemModeMigrationNoticeId::new(notice_id)
            .map_err(|_| "The filesystem-security notice changed. Refresh and try again.")?;
        let projection = current_projection();
        let notice = projection
            .filesystem_mode_migration
            .as_ref()
            .ok_or("The filesystem-security notice changed. Refresh and try again.")?;
        if notice.notice_id() != &notice_id
            || notice.phase() != FilesystemModeMigrationPhase::Applied
        {
            return Err("The filesystem-security notice changed. Refresh and try again.");
        }
        queue_mutation(
            &self.commands,
            WorkerCommand::AcknowledgeFilesystemModeMigration(notice_id),
        )
    }

    pub fn reclaim_viewport(&self, session_id: String) -> Result<(), &'static str> {
        require_no_pending_filesystem_migration()?;
        let session_id = SessionKey::new(session_id)
            .map_err(|_| "The selected terminal cannot be reclaimed.")?;
        queue_mutation(
            &self.commands,
            WorkerCommand::ReclaimViewport {
                session_id,
                reason: ViewportReclaimReason::UserRequested,
            },
        )
    }

    /// Handle the legacy global owner control without restoring its former authority file. A
    /// local choice releases every currently cached exact lease. A remote choice cannot grant
    /// authority; only an authenticated remote viewing transition may do that, so it refreshes.
    pub fn request_winsize_owner_toggle(&self, remote: bool) -> Result<(), &'static str> {
        require_no_pending_filesystem_migration()?;
        if remote {
            self.refresh();
            return Ok(());
        }
        queue_mutation(
            &self.commands,
            WorkerCommand::ReclaimAllViewports {
                reason: ViewportReclaimReason::UserRequested,
            },
        )
    }

    pub fn try_recv(&self) -> Option<ExtensionUpdate> {
        self.updates.try_recv().ok()
    }
}

fn require_no_pending_filesystem_migration() -> Result<(), &'static str> {
    if current_projection().filesystem_mode_migration.is_some() {
        Err("Secure the listed files and folders before changing Remote.")
    } else {
        Ok(())
    }
}

impl Drop for OptionalExtensionWorker {
    fn drop(&mut self) {
        let _ = self.commands.try_send(WorkerCommand::Shutdown);
    }
}

fn queue_mutation(
    commands: &SyncSender<WorkerCommand>,
    command: WorkerCommand,
) -> Result<(), &'static str> {
    commands.try_send(command).map_err(|error| match error {
        TrySendError::Full(_) => "Another Remote operation is already pending.",
        TrySendError::Disconnected(_) => "Remote extension is unavailable.",
    })
}

fn worker_main(commands: Receiver<WorkerCommand>, updates: SyncSender<ExtensionUpdate>) {
    let mut next_request_id = 1_u64;
    let mut state = WorkerState::default();
    let _ = updates.send(run_operation(
        ExtensionOperation::Refresh,
        &mut next_request_id,
        None,
        &mut state,
    ));
    loop {
        let command = match commands.recv_timeout(POLL_INTERVAL) {
            Ok(command) => command,
            Err(RecvTimeoutError::Timeout) => WorkerCommand::Refresh,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        let (operation, request) = match command {
            WorkerCommand::Refresh => (ExtensionOperation::Refresh, None),
            WorkerCommand::Enroll(code) => (
                ExtensionOperation::Enroll,
                Some(PendingRequest::Enroll(code)),
            ),
            WorkerCommand::SetRemoteOpen(open) => (
                ExtensionOperation::SetRemoteOpen,
                Some(PendingRequest::SetRemoteOpen(open)),
            ),
            WorkerCommand::RemoveEnrollment => (
                ExtensionOperation::RemoveEnrollment,
                Some(PendingRequest::RemoveEnrollment),
            ),
            WorkerCommand::ApplyFilesystemModeMigration(notice_id) => (
                ExtensionOperation::ApplyFilesystemModeMigration,
                Some(PendingRequest::ApplyFilesystemModeMigration(notice_id)),
            ),
            WorkerCommand::AcknowledgeFilesystemModeMigration(notice_id) => (
                ExtensionOperation::AcknowledgeFilesystemModeMigration,
                Some(PendingRequest::AcknowledgeFilesystemModeMigration(
                    notice_id,
                )),
            ),
            WorkerCommand::ReclaimViewport { session_id, reason } => (
                ExtensionOperation::ReclaimViewport,
                Some(PendingRequest::ReclaimViewport { session_id, reason }),
            ),
            WorkerCommand::ReclaimAllViewports { reason } => (
                ExtensionOperation::ReclaimAllViewports,
                Some(PendingRequest::ReclaimAllViewports { reason }),
            ),
            WorkerCommand::Shutdown => return,
        };
        if updates
            .send(run_operation(
                operation,
                &mut next_request_id,
                request,
                &mut state,
            ))
            .is_err()
        {
            return;
        }
    }
}

enum PendingRequest {
    Enroll(EnrollmentCode),
    SetRemoteOpen(bool),
    RemoveEnrollment,
    ApplyFilesystemModeMigration(FilesystemModeMigrationNoticeId),
    AcknowledgeFilesystemModeMigration(FilesystemModeMigrationNoticeId),
    ReclaimViewport {
        session_id: SessionKey,
        reason: ViewportReclaimReason,
    },
    ReclaimAllViewports {
        reason: ViewportReclaimReason,
    },
}

fn take_request_id(next: &mut u64) -> RemoteDesktopRequestId {
    let current = (*next).max(1);
    *next = current.checked_add(1).unwrap_or(1);
    RemoteDesktopRequestId::new(current).expect("worker request ids are nonzero")
}

fn run_operation(
    operation: ExtensionOperation,
    next_request_id: &mut u64,
    pending: Option<PendingRequest>,
    state: &mut WorkerState,
) -> ExtensionUpdate {
    let now = Instant::now();
    if let Some(notice) = state.last_projection.filesystem_mode_migration.as_ref() {
        let allowed = match pending.as_ref() {
            None => true,
            Some(PendingRequest::ApplyFilesystemModeMigration(notice_id)) => {
                notice.notice_id() == notice_id
                    && notice.phase() != FilesystemModeMigrationPhase::Applied
            }
            Some(PendingRequest::AcknowledgeFilesystemModeMigration(notice_id)) => {
                notice.notice_id() == notice_id
                    && notice.phase() == FilesystemModeMigrationPhase::Applied
            }
            _ => false,
        };
        if !allowed {
            let projection = state.projection_with_live_cache(now);
            state.last_projection = projection.clone();
            return ExtensionUpdate {
                operation,
                projection,
                error_message: Some("Secure the listed files and folders before changing Remote."),
            };
        }
    } else if matches!(
        pending,
        Some(
            PendingRequest::ApplyFilesystemModeMigration(_)
                | PendingRequest::AcknowledgeFilesystemModeMigration(_)
        )
    ) {
        let projection = state.projection_with_live_cache(now);
        state.last_projection = projection.clone();
        return ExtensionUpdate {
            operation,
            projection,
            error_message: Some("The filesystem-security notice changed. Refresh and try again."),
        };
    }
    let acknowledgement_attempt = match &pending {
        Some(PendingRequest::AcknowledgeFilesystemModeMigration(notice_id)) => {
            Some(notice_id.clone())
        }
        _ => None,
    };
    if let Some(PendingRequest::ReclaimViewport { session_id, reason }) = pending {
        return run_reclaim_operation(
            operation,
            next_request_id,
            state,
            session_id,
            reason,
            now,
            STATUS_TIMEOUT,
        );
    }
    if let Some(PendingRequest::ReclaimAllViewports { reason }) = pending {
        return run_reclaim_all_operation(operation, next_request_id, state, reason, now);
    }

    let Some(binary) = installed_extension_path() else {
        let projection = state.projection_with_live_cache(now);
        state.last_projection = projection.clone();
        return ExtensionUpdate {
            operation,
            projection,
            error_message: (operation != ExtensionOperation::Refresh)
                .then_some("Install or update Hydra Remote, then try again."),
        };
    };

    let request_id = take_request_id(next_request_id);
    let (request, timeout) = match pending {
        None => (
            RemoteDesktopHostRequest::Status { request_id },
            LIFECYCLE_STATUS_TIMEOUT,
        ),
        Some(PendingRequest::Enroll(code)) => (
            RemoteDesktopHostRequest::Enroll { request_id, code },
            MUTATION_TIMEOUT,
        ),
        Some(PendingRequest::SetRemoteOpen(open)) => (
            RemoteDesktopHostRequest::SetRemoteOpen { request_id, open },
            MUTATION_TIMEOUT,
        ),
        Some(PendingRequest::RemoveEnrollment) => (
            RemoteDesktopHostRequest::RemoveEnrollment { request_id },
            MUTATION_TIMEOUT,
        ),
        Some(PendingRequest::ApplyFilesystemModeMigration(notice_id)) => (
            RemoteDesktopHostRequest::ApplyFilesystemModeMigration {
                request_id,
                notice_id,
            },
            MUTATION_TIMEOUT,
        ),
        Some(PendingRequest::AcknowledgeFilesystemModeMigration(notice_id)) => (
            RemoteDesktopHostRequest::AcknowledgeFilesystemModeMigration {
                request_id,
                notice_id,
            },
            MUTATION_TIMEOUT,
        ),
        Some(PendingRequest::ReclaimViewport { .. }) => {
            unreachable!("reclaim requests return through the exact cached-lease path above")
        }
        Some(PendingRequest::ReclaimAllViewports { .. }) => {
            unreachable!("reclaim-all requests return through the exact cached-lease path above")
        }
    };
    if let Some(notice_id) = acknowledgement_attempt {
        // Record intent before any request byte can reach the child. If transport later fails after
        // the child committed the unlink, only a subsequent capable Status-with-no-notice for this
        // same Applied id may converge the latch.
        state.pending_acknowledgement = Some(notice_id);
    }

    let result = exchange_with_binary(&binary, &request, timeout).and_then(|exchange| {
        outcome_from_response(&request, exchange.response).map(|outcome| {
            (
                outcome,
                exchange.supports_external_viewport,
                exchange.supports_filesystem_mode_migration,
            )
        })
    });
    let (outcome, supports_external_viewport, supports_filesystem_mode_migration) = match result {
        Ok(result) => result,
        Err(error) => return failed_operation_update(operation, state, error, Instant::now()),
    };

    if let OperationOutcome::Notice { notice, status } = outcome {
        // An authoritative notice proves the receipt still exists. Any earlier response-loss
        // hypothesis is false; a fresh user Ack will establish a new exact attempt.
        state.pending_acknowledgement = None;
        state.viewport.invalidate_leases();
        let mut projection = status
            .as_ref()
            .map(projection_from_status)
            .unwrap_or_else(|| state.last_projection.clone());
        projection.available = true;
        projection.remote_owned_sessions.clear();
        projection.filesystem_mode_migration = Some(notice);
        state.last_projection = projection.clone();
        return ExtensionUpdate {
            operation,
            projection,
            error_message: None,
        };
    }
    let OperationOutcome::Status(status) = outcome else {
        unreachable!("notice outcome returned above")
    };

    if !migration_latch_accepts_status(state, operation, supports_filesystem_mode_migration) {
        let projection = state.projection_with_live_cache(Instant::now());
        state.last_projection = projection.clone();
        return ExtensionUpdate {
            operation,
            projection,
            error_message: (operation != ExtensionOperation::Refresh)
                .then_some("The filesystem-security notice changed. Refresh and try again."),
        };
    }

    let mut projection = projection_from_status(&status);
    if status.remote_open() && supports_external_viewport {
        let snapshot_id = take_request_id(next_request_id);
        let snapshot_request = RemoteDesktopHostRequest::SnapshotViewports {
            request_id: snapshot_id,
        };
        match exchange_with_binary(&binary, &snapshot_request, STATUS_TIMEOUT)
            .map(|exchange| exchange.response)
        {
            Ok(RemoteDesktopExtensionResponse::ViewportSnapshot {
                request_id,
                cursor,
                ttl_ms,
                viewports,
            }) if request_id == snapshot_id => {
                let _ = state
                    .viewport
                    .accept(cursor, ttl_ms, &viewports, Instant::now());
                // A stale/equal/retired response is deliberately ignored and cannot renew TTL.
                // Until the previously accepted deadline, keep its exact projection; afterwards
                // fail local by returning an empty set.
                projection.remote_owned_sessions = state.viewport.sessions(Instant::now());
            }
            _ => {
                projection.remote_owned_sessions = state.viewport.sessions(Instant::now());
            }
        }
    } else {
        // Closing Remote invalidates all live ownership immediately but preserves the accepted
        // epoch/high-water mark. Reopening cannot make an equal old snapshot valid again.
        state.viewport.invalidate_leases();
    }

    state.last_projection = projection.clone();
    ExtensionUpdate {
        operation,
        projection,
        error_message: None,
    }
}

fn failed_operation_update(
    operation: ExtensionOperation,
    state: &mut WorkerState,
    error: ExtensionTransportError,
    now: Instant,
) -> ExtensionUpdate {
    let projection = state.projection_after_exchange_error(error, now);
    state.last_projection = projection.clone();
    ExtensionUpdate {
        operation,
        projection,
        error_message: (operation != ExtensionOperation::Refresh)
            .then_some(error.user_message(operation)),
    }
}

/// Decide whether a successful status without a migration notice may replace the preserved latch.
/// Ordinary status never clears it. The only idempotent response-loss recovery is a capable Refresh
/// after an explicit Ack attempt for the same exact Applied notice id.
fn migration_latch_accepts_status(
    state: &mut WorkerState,
    operation: ExtensionOperation,
    supports_filesystem_mode_migration: bool,
) -> bool {
    let Some(notice) = state.last_projection.filesystem_mode_migration.as_ref() else {
        return true;
    };
    let exact_acknowledgement_observed =
        operation == ExtensionOperation::AcknowledgeFilesystemModeMigration;
    let status_converges_lost_ack = operation == ExtensionOperation::Refresh
        && supports_filesystem_mode_migration
        && notice.phase() == FilesystemModeMigrationPhase::Applied
        && state
            .pending_acknowledgement
            .as_ref()
            .is_some_and(|pending| pending == notice.notice_id());
    if exact_acknowledgement_observed || status_converges_lost_ack {
        state.pending_acknowledgement = None;
        true
    } else {
        false
    }
}

fn run_reclaim_operation(
    operation: ExtensionOperation,
    next_request_id: &mut u64,
    state: &mut WorkerState,
    session_id: SessionKey,
    reason: ViewportReclaimReason,
    now: Instant,
    timeout: Duration,
) -> ExtensionUpdate {
    let Some(viewport) = state.viewport.lease(&session_id, now) else {
        let projection = state.projection_with_live_cache(now);
        state.last_projection = projection.clone();
        return ExtensionUpdate {
            operation,
            projection,
            error_message: Some("The remote viewport changed. Try again."),
        };
    };
    let Some(binary) = installed_extension_path() else {
        let projection = state.projection_with_live_cache(now);
        state.last_projection = projection.clone();
        return ExtensionUpdate {
            operation,
            projection,
            error_message: Some("Remote extension is unavailable."),
        };
    };
    let request = RemoteDesktopHostRequest::ReclaimViewport {
        request_id: take_request_id(next_request_id),
        session_id: viewport.session_id.clone(),
        lease_id: viewport.lease_id.clone(),
        cursor: viewport.cursor,
        reason,
    };
    let result = exchange_with_binary(&binary, &request, timeout).map(|exchange| exchange.response);
    let success =
        apply_reclaim_response(&mut state.viewport, &viewport, request.request_id(), result);
    let mut projection = state.last_projection.clone();
    projection.remote_owned_sessions = state.viewport.sessions(Instant::now());
    state.last_projection = projection.clone();
    ExtensionUpdate {
        operation,
        projection,
        error_message: (!success).then_some("The remote viewport changed. Try again."),
    }
}

fn run_reclaim_all_operation(
    operation: ExtensionOperation,
    next_request_id: &mut u64,
    state: &mut WorkerState,
    reason: ViewportReclaimReason,
    now: Instant,
) -> ExtensionUpdate {
    let deadline = now.checked_add(MUTATION_TIMEOUT).unwrap_or(now);
    let sessions = state.viewport.sessions(now);
    let mut failed = false;
    for raw_session in sessions {
        let current = Instant::now();
        let Some(remaining) = deadline.checked_duration_since(current) else {
            failed = true;
            break;
        };
        if remaining.is_zero() {
            failed = true;
            break;
        }
        let Ok(session_id) = SessionKey::new(raw_session) else {
            failed = true;
            continue;
        };
        let update = run_reclaim_operation(
            operation,
            next_request_id,
            state,
            session_id,
            reason,
            current,
            remaining.min(STATUS_TIMEOUT),
        );
        failed |= update.error_message.is_some();
    }
    let projection = state.projection_with_live_cache(Instant::now());
    state.last_projection = projection.clone();
    ExtensionUpdate {
        operation,
        projection,
        error_message: failed.then_some("Some remote viewports changed. Try again."),
    }
}

/// Apply only the exact typed acknowledgement for the cached lease. Transport errors, refusal,
/// stale request ids, and mismatched lease identities leave the projection untouched, which keeps
/// renderer resize suppression in force until the server TTL expires or a later snapshot advances.
fn apply_reclaim_response(
    cache: &mut ViewportSnapshotCache,
    viewport: &CachedViewport,
    expected_request_id: RemoteDesktopRequestId,
    result: Result<RemoteDesktopExtensionResponse, ExtensionTransportError>,
) -> bool {
    let success = matches!(
        result,
        Ok(RemoteDesktopExtensionResponse::ViewportReclaimed {
            request_id,
            ref session_id,
            ref lease_id,
        }) if request_id == expected_request_id
            && session_id == &viewport.session_id
            && lease_id == &viewport.lease_id
    );
    success && cache.remove_exact(viewport)
}

fn projection_from_status(status: &RemoteDesktopStatus) -> RemoteExtensionProjection {
    RemoteExtensionProjection {
        available: true,
        enrolled: status.enrollment_id().is_some(),
        account_id: status
            .account_id()
            .map(|account_id| account_id.as_str().to_string()),
        remote_open: status.remote_open(),
        active_connections: status.active_connections(),
        remote_owned_sessions: Vec::new(),
        filesystem_mode_migration: None,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum OperationOutcome {
    Status(RemoteDesktopStatus),
    Notice {
        notice: FilesystemModeMigrationNotice,
        status: Option<RemoteDesktopStatus>,
    },
}

fn outcome_from_response(
    request: &RemoteDesktopHostRequest,
    response: RemoteDesktopExtensionResponse,
) -> Result<OperationOutcome, ExtensionTransportError> {
    validate_response(request, &response)?;
    match (request, response) {
        (
            RemoteDesktopHostRequest::Status { .. },
            RemoteDesktopExtensionResponse::Status { status, .. },
        )
        | (
            RemoteDesktopHostRequest::Enroll { .. },
            RemoteDesktopExtensionResponse::Enrolled { status, .. },
        )
        | (
            RemoteDesktopHostRequest::SetRemoteOpen { .. },
            RemoteDesktopExtensionResponse::RemoteOpenSet { status, .. },
        )
        | (
            RemoteDesktopHostRequest::RemoveEnrollment { .. },
            RemoteDesktopExtensionResponse::EnrollmentRemoved { status, .. },
        )
        | (
            RemoteDesktopHostRequest::AcknowledgeFilesystemModeMigration { .. },
            RemoteDesktopExtensionResponse::FilesystemModeMigrationAcknowledged { status, .. },
        ) => Ok(OperationOutcome::Status(status)),
        (
            RemoteDesktopHostRequest::Status { .. }
            | RemoteDesktopHostRequest::Enroll { .. }
            | RemoteDesktopHostRequest::SetRemoteOpen { .. }
            | RemoteDesktopHostRequest::RemoveEnrollment { .. }
            | RemoteDesktopHostRequest::ApplyFilesystemModeMigration { .. },
            RemoteDesktopExtensionResponse::FilesystemModeMigration { notice, status, .. },
        ) => Ok(OperationOutcome::Notice { notice, status }),
        (_, RemoteDesktopExtensionResponse::Error { error, .. }) => {
            Err(ExtensionTransportError::Refused {
                code: error.code(),
                retryable: error.retryable(),
            })
        }
        _ => Err(ExtensionTransportError::UnexpectedResponse),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExtensionTransportError {
    Spawn,
    Io,
    Timeout,
    OversizedFrame,
    MalformedFrame,
    Incompatible,
    MissingCapability,
    MismatchedRequestId,
    MismatchedNoticeId,
    UnexpectedResponse,
    ExtraOutput,
    ChildFailed,
    Refused {
        code: RemoteDesktopErrorCode,
        retryable: bool,
    },
}

impl ExtensionTransportError {
    fn is_validated_refusal(self) -> bool {
        matches!(self, Self::Refused { .. })
    }

    fn user_message(self, operation: ExtensionOperation) -> &'static str {
        match self {
            Self::Refused {
                code: RemoteDesktopErrorCode::NotEnrolled,
                ..
            } => "This desktop is not enrolled. Add Remote first.",
            Self::Refused {
                code: RemoteDesktopErrorCode::AlreadyEnrolled,
                ..
            } => "This desktop is already enrolled.",
            Self::Refused {
                code: RemoteDesktopErrorCode::EnrollmentRejected,
                ..
            } => "Enrollment was rejected. Generate a fresh code and try again.",
            Self::Refused {
                code: RemoteDesktopErrorCode::RemoteUnavailable,
                retryable: true,
            } if operation == ExtensionOperation::Enroll => {
                "The code was accepted, but Remote could not start. Generate a fresh code and try again."
            }
            Self::Refused {
                code: RemoteDesktopErrorCode::RemoteUnavailable,
                retryable: true,
            } => "Remote service is temporarily unavailable. Wait a moment and try again.",
            Self::Refused {
                code: RemoteDesktopErrorCode::RemoteUnavailable,
                retryable: false,
            } => "Remote was closed for safety. Add this desktop again.",
            Self::Refused {
                code: RemoteDesktopErrorCode::Busy,
                ..
            } => "Remote is busy. Wait a moment and try again.",
            Self::Refused {
                code: RemoteDesktopErrorCode::Internal,
                retryable: true,
            } => "Remote hit an internal lifecycle error. Wait a moment and try again.",
            Self::Refused {
                code: RemoteDesktopErrorCode::Internal,
                retryable: false,
            } => "Remote lifecycle could not be verified. Restart Hydra before trying again.",
            Self::Refused {
                code: RemoteDesktopErrorCode::InvalidRequest,
                ..
            } => "Hydra Remote could not process this request. Update Hydra and try again.",
            Self::Refused {
                code: RemoteDesktopErrorCode::ViewportUnavailable,
                ..
            } => "The remote viewport changed. Try again.",
            Self::Timeout => "Remote extension timed out. Try again.",
            Self::Incompatible | Self::MissingCapability => {
                "Hydra Remote components are incompatible. Update Hydra and try again."
            }
            Self::OversizedFrame
            | Self::MalformedFrame
            | Self::MismatchedRequestId
            | Self::MismatchedNoticeId
            | Self::UnexpectedResponse
            | Self::ExtraOutput => {
                "Hydra Remote returned an invalid protocol response. Update Hydra and try again."
            }
            Self::Spawn => {
                "Hydra Remote could not start. Reinstall or update Hydra, then try again."
            }
            Self::Io | Self::ChildFailed => {
                "Hydra Remote stopped unexpectedly. Restart Hydra and try again."
            }
        }
    }
}

impl fmt::Debug for ExtensionTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused { code, retryable } => formatter
                .debug_struct("Refused")
                .field("code", code)
                .field("retryable", retryable)
                .finish(),
            Self::Spawn => formatter.write_str("Spawn"),
            Self::Io => formatter.write_str("Io"),
            Self::Timeout => formatter.write_str("Timeout"),
            Self::OversizedFrame => formatter.write_str("OversizedFrame"),
            Self::MalformedFrame => formatter.write_str("MalformedFrame"),
            Self::Incompatible => formatter.write_str("Incompatible"),
            Self::MissingCapability => formatter.write_str("MissingCapability"),
            Self::MismatchedRequestId => formatter.write_str("MismatchedRequestId"),
            Self::MismatchedNoticeId => formatter.write_str("MismatchedNoticeId"),
            Self::UnexpectedResponse => formatter.write_str("UnexpectedResponse"),
            Self::ExtraOutput => formatter.write_str("ExtraOutput"),
            Self::ChildFailed => formatter.write_str("ChildFailed"),
        }
    }
}

fn exchange_with_binary(
    binary: &Path,
    request: &RemoteDesktopHostRequest,
    timeout: Duration,
) -> Result<ExtensionExchange, ExtensionTransportError> {
    exchange_with_command(Command::new(binary), request, timeout)
}

fn exchange_with_command(
    mut command: Command,
    request: &RemoteDesktopHostRequest,
    timeout: Duration,
) -> Result<ExtensionExchange, ExtensionTransportError> {
    let deadline = Instant::now() + timeout;
    command
        .arg(EXTENSION_COMMAND)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for name in RETIRED_EXTENSION_ENVIRONMENT {
        command.env_remove(name);
    }
    let mut child = command
        .spawn()
        .map_err(|_| ExtensionTransportError::Spawn)?;
    let result = exchange_with_child(&mut child, request, deadline);
    if result.is_err() {
        terminate_child_bounded(&mut child, Duration::from_millis(250));
    }
    // `exchange_with_child` reaps a successful child through `try_wait`. On failure cleanup is
    // deliberately best-effort and deadline-bounded; never call blocking `wait()` here.
    result
}

fn exchange_with_child(
    child: &mut Child,
    request: &RemoteDesktopHostRequest,
    deadline: Instant,
) -> Result<ExtensionExchange, ExtensionTransportError> {
    let mut stdin = child.stdin.take().ok_or(ExtensionTransportError::Io)?;
    let stdout = child.stdout.take().ok_or(ExtensionTransportError::Io)?;
    let frames = spawn_frame_reader(stdout);

    let host = host_hello();
    write_json_frame(&mut stdin, &host)?;
    let extension_hello = recv_frame(&frames, deadline)?;
    let extension_hello =
        decode_hello_frame(&extension_hello).map_err(|_| ExtensionTransportError::Incompatible)?;
    let negotiated =
        negotiate(&host, &extension_hello).map_err(|_| ExtensionTransportError::Incompatible)?;
    if !negotiated.supports(KnownCapability::RemoteDesktopLifecycleV1) {
        return Err(ExtensionTransportError::MissingCapability);
    }
    if matches!(
        request,
        RemoteDesktopHostRequest::SnapshotViewports { .. }
            | RemoteDesktopHostRequest::ReclaimViewport { .. }
    ) && !negotiated.supports(KnownCapability::ExternalViewportLeaseV1)
    {
        return Err(ExtensionTransportError::MissingCapability);
    }
    if matches!(
        request,
        RemoteDesktopHostRequest::ApplyFilesystemModeMigration { .. }
            | RemoteDesktopHostRequest::AcknowledgeFilesystemModeMigration { .. }
    ) && !negotiated.supports(KnownCapability::FilesystemModeMigrationV1)
    {
        return Err(ExtensionTransportError::MissingCapability);
    }

    write_json_frame(&mut stdin, request)?;
    drop(stdin);
    let response_frame = recv_frame(&frames, deadline)?;
    let response = negotiated
        .decode_remote_desktop_extension_frame(&response_frame)
        .map_err(|_| ExtensionTransportError::MalformedFrame)?;
    validate_response(request, &response)?;
    match recv_before(&frames, deadline)? {
        ReaderEvent::Eof => {}
        ReaderEvent::Frame(_) => return Err(ExtensionTransportError::ExtraOutput),
        ReaderEvent::Error(error) => return Err(error),
    }
    let status = wait_until(child, deadline)?;
    if !status.success() {
        return Err(ExtensionTransportError::ChildFailed);
    }
    Ok(ExtensionExchange {
        response,
        supports_external_viewport: negotiated.supports(KnownCapability::ExternalViewportLeaseV1),
        supports_filesystem_mode_migration: negotiated
            .supports(KnownCapability::FilesystemModeMigrationV1),
    })
}

#[derive(Debug, PartialEq, Eq)]
struct ExtensionExchange {
    response: RemoteDesktopExtensionResponse,
    supports_external_viewport: bool,
    supports_filesystem_mode_migration: bool,
}

fn host_hello() -> ExtensionHello {
    ExtensionHello::host([
        Capability::external_viewport_lease_v1(),
        Capability::filesystem_mode_migration_v1(),
        Capability::remote_desktop_lifecycle_v1(),
    ])
    .expect("host capabilities are compile-time constants")
}

fn write_json_frame(
    writer: &mut ChildStdin,
    value: &impl serde::Serialize,
) -> Result<(), ExtensionTransportError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ExtensionTransportError::Io)?;
    if bytes.is_empty() || bytes.len() > MAX_EXTENSION_FRAME_BYTES {
        return Err(ExtensionTransportError::OversizedFrame);
    }
    writer
        .write_all(&bytes)
        .and_then(|()| writer.write_all(b"\n"))
        .and_then(|()| writer.flush())
        .map_err(|_| ExtensionTransportError::Io)
}

enum ReaderEvent {
    Frame(Vec<u8>),
    Eof,
    Error(ExtensionTransportError),
}

fn spawn_frame_reader(stdout: impl Read + Send + 'static) -> Receiver<ReaderEvent> {
    // One response plus one look-ahead event is sufficient to prove exact EOF. A flooding child
    // therefore blocks at the pipe instead of transferring up to 64 KiB frames into an unbounded
    // heap queue while the host is still validating the first response.
    let (sender, receiver) = mpsc::sync_channel(CHILD_FRAME_CAPACITY);
    // A reader-thread allocation failure closes `sender` with the dropped closure. The receiver
    // then reports a transport I/O failure; it must never panic the public desktop.
    let _ = thread::Builder::new()
        .name("maestro-extension-stdout".to_string())
        .spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let event = match read_bounded_line(&mut reader) {
                    Ok(Some(frame)) => ReaderEvent::Frame(frame),
                    Ok(None) => ReaderEvent::Eof,
                    Err(error) => ReaderEvent::Error(error),
                };
                let terminal = !matches!(event, ReaderEvent::Frame(_));
                if sender.send(event).is_err() || terminal {
                    break;
                }
            }
        });
    receiver
}

fn read_bounded_line(
    reader: &mut impl BufRead,
) -> Result<Option<Vec<u8>>, ExtensionTransportError> {
    let mut frame = Vec::new();
    loop {
        let available = reader.fill_buf().map_err(|_| ExtensionTransportError::Io)?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(ExtensionTransportError::MalformedFrame)
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index);
        if frame.len().saturating_add(take) > MAX_EXTENSION_FRAME_BYTES {
            return Err(ExtensionTransportError::OversizedFrame);
        }
        frame.extend_from_slice(&available[..take]);
        reader.consume(take + usize::from(newline.is_some()));
        if newline.is_some() {
            if frame.is_empty() || frame.last() == Some(&b'\r') {
                return Err(ExtensionTransportError::MalformedFrame);
            }
            return Ok(Some(frame));
        }
    }
}

fn recv_frame(
    receiver: &Receiver<ReaderEvent>,
    deadline: Instant,
) -> Result<Vec<u8>, ExtensionTransportError> {
    match recv_before(receiver, deadline)? {
        ReaderEvent::Frame(frame) => Ok(frame),
        ReaderEvent::Eof => Err(ExtensionTransportError::MalformedFrame),
        ReaderEvent::Error(error) => Err(error),
    }
}

fn recv_before(
    receiver: &Receiver<ReaderEvent>,
    deadline: Instant,
) -> Result<ReaderEvent, ExtensionTransportError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(ExtensionTransportError::Timeout)?;
    receiver
        .recv_timeout(remaining)
        .map_err(|error| match error {
            RecvTimeoutError::Timeout => ExtensionTransportError::Timeout,
            RecvTimeoutError::Disconnected => ExtensionTransportError::Io,
        })
}

fn wait_until(
    child: &mut Child,
    deadline: Instant,
) -> Result<std::process::ExitStatus, ExtensionTransportError> {
    loop {
        if let Some(status) = child.try_wait().map_err(|_| ExtensionTransportError::Io)? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(ExtensionTransportError::Timeout);
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn validate_response(
    request: &RemoteDesktopHostRequest,
    response: &RemoteDesktopExtensionResponse,
) -> Result<(), ExtensionTransportError> {
    validate_remote_desktop_response(request, response).map_err(|error| match error {
        RemoteDesktopExchangeError::RequestIdMismatch { .. } => {
            ExtensionTransportError::MismatchedRequestId
        }
        RemoteDesktopExchangeError::UnexpectedResponse => {
            ExtensionTransportError::UnexpectedResponse
        }
        RemoteDesktopExchangeError::NoticeIdMismatch => ExtensionTransportError::MismatchedNoticeId,
    })
}

fn terminate_child_bounded(child: &mut Child, timeout: Duration) {
    if child.try_wait().ok().flatten().is_some() {
        return;
    }
    if child.kill().is_err() {
        return;
    }
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) => thread::sleep(Duration::from_millis(5)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maestro_extension_api::{
        FilesystemMode, FilesystemModeChange, RemoteDesktopId, RemoteDesktopViewport,
        RemoteDesktopViewportList,
    };
    use std::fs;

    fn request_id() -> RemoteDesktopRequestId {
        RemoteDesktopRequestId::new(7).unwrap()
    }

    fn migration_notice(phase: FilesystemModeMigrationPhase) -> FilesystemModeMigrationNotice {
        FilesystemModeMigrationNotice::new(
            FilesystemModeMigrationNoticeId::new("a".repeat(64)).unwrap(),
            phase,
            [FilesystemModeChange::new(
                "/home/tester/.local/share/hydra-agent",
                FilesystemMode::LegacyPublicGroupWritable,
                FilesystemMode::OwnerOnly,
            )
            .unwrap()],
            (phase != FilesystemModeMigrationPhase::ReadyToApply)
                .then(|| "/home/tester/.hydra-agent-authority-migration-v1.json".to_string()),
        )
        .unwrap()
    }

    #[test]
    fn lifecycle_status_budget_is_separate_from_viewport_budget() {
        assert_eq!(LIFECYCLE_STATUS_TIMEOUT, Duration::from_secs(30));
        assert_eq!(STATUS_TIMEOUT, Duration::from_secs(2));
        assert!(LIFECYCLE_STATUS_TIMEOUT > STATUS_TIMEOUT);
    }

    #[test]
    fn discovery_is_fixed_to_one_sibling() {
        for (app, extension) in [
            ("/opt/hydra/bin/maestro-app", "/opt/hydra/bin/hydra-agent"),
            (
                "/Applications/Hydra.app/Contents/Resources/bin/maestro-app",
                "/Applications/Hydra.app/Contents/Resources/bin/hydra-agent",
            ),
        ] {
            let found = discover_installed_extension(Some(Path::new(app)), |path| {
                path == Path::new(extension)
            });
            assert_eq!(found, Some(PathBuf::from(extension)));
            assert_eq!(
                discover_installed_extension(Some(Path::new(app)), |_| false),
                None
            );
        }
        assert_eq!(discover_installed_extension(None, |_| true), None);
    }

    #[test]
    fn bounded_reader_rejects_missing_delimiter_and_oversize() {
        assert_eq!(
            read_bounded_line(&mut BufReader::new(&b"{}"[..])),
            Err(ExtensionTransportError::MalformedFrame)
        );
        let mut oversized = vec![b'x'; MAX_EXTENSION_FRAME_BYTES + 1];
        oversized.push(b'\n');
        assert_eq!(
            read_bounded_line(&mut BufReader::new(oversized.as_slice())),
            Err(ExtensionTransportError::OversizedFrame)
        );
    }

    #[cfg(unix)]
    fn script(body: &str) -> (tempfile::TempDir, PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(EXTENSION_BINARY_NAME);
        fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        (directory, path)
    }

    #[cfg(unix)]
    fn successful_script(response: &str) -> String {
        format!(
            r#"IFS= read -r hello
printf '%s\n' '{{"protocol":{{"min":1,"max":1}},"capabilities":["remote_desktop_lifecycle_v1","external_viewport_lease_v1"]}}'
IFS= read -r request
printf '%s\n' '{response}'"#
        )
    }

    #[cfg(unix)]
    #[test]
    fn fake_child_completes_two_phase_exchange() {
        let (_directory, binary) = script(&successful_script(
            r#"{"type":"status","request_id":7,"status":{"enrollment_id":null,"remote_open":false,"active_connections":0}}"#,
        ));
        let request = RemoteDesktopHostRequest::Status {
            request_id: request_id(),
        };
        assert!(matches!(
            exchange_with_binary(&binary, &request, Duration::from_secs(2))
                .unwrap()
                .response,
            RemoteDesktopExtensionResponse::Status { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn migration_requests_require_the_negotiated_capability_before_request_bytes_are_sent() {
        let (_directory, binary) = script(&successful_script(
            r#"{"type":"error","request_id":7,"error":{"code":"internal","message":"must not arrive","retryable":false}}"#,
        ));
        let request = RemoteDesktopHostRequest::ApplyFilesystemModeMigration {
            request_id: request_id(),
            notice_id: FilesystemModeMigrationNoticeId::new("a".repeat(64)).unwrap(),
        };
        assert_eq!(
            exchange_with_binary(&binary, &request, Duration::from_secs(2)),
            Err(ExtensionTransportError::MissingCapability)
        );
        assert!(host_hello().capabilities().iter().any(
            |capability| capability.known() == Some(KnownCapability::FilesystemModeMigrationV1)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn enrollment_secret_never_enters_argv_environment_or_errors() {
        let secret = "SECRET-CODE-9713";
        let directory = tempfile::tempdir().unwrap();
        let capture = directory.path().join("capture.txt");
        let capture_escaped = capture.to_string_lossy().replace('\'', "'\\''");
        let body = format!(
            r#"printf '%s\n' "$*" > '{capture_escaped}'
env >> '{capture_escaped}'
IFS= read -r hello
printf '%s\n' '{{"protocol":{{"min":1,"max":1}},"capabilities":["remote_desktop_lifecycle_v1"]}}'
IFS= read -r request
printf '%s\n' '{{"type":"error","request_id":7,"error":{{"code":"enrollment_rejected","message":"rejected","retryable":false}}}}'"#
        );
        let (_script_directory, binary) = script(&body);
        let request = RemoteDesktopHostRequest::Enroll {
            request_id: request_id(),
            code: EnrollmentCode::new(secret).unwrap(),
        };
        let mut command = Command::new(&binary);
        for name in RETIRED_EXTENSION_ENVIRONMENT {
            command.env(name, format!("AMBIENT-{name}-{secret}"));
        }
        let response = exchange_with_command(command, &request, Duration::from_secs(2))
            .unwrap()
            .response;
        let error = outcome_from_response(&request, response).unwrap_err();
        assert!(!format!("{error:?}").contains(secret));
        assert!(!error
            .user_message(ExtensionOperation::Enroll)
            .contains(secret));
        let capture = fs::read_to_string(capture).unwrap();
        assert!(!capture.contains(secret));
        for name in RETIRED_EXTENSION_ENVIRONMENT {
            assert!(
                !capture
                    .lines()
                    .any(|line| line.starts_with(&format!("{name}="))),
                "retired extension environment {name} reached the child"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn malformed_oversized_and_timeout_children_fail_closed() {
        let request = RemoteDesktopHostRequest::Status {
            request_id: request_id(),
        };
        // Parser classifications use a generous test-only deadline so host scheduler contention
        // cannot turn a prompt malformed response into the timeout case proved separately below.
        let (_directory, malformed) = script("printf '%s\\n' 'not-json'");
        assert_eq!(
            exchange_with_binary(&malformed, &request, Duration::from_secs(5)),
            Err(ExtensionTransportError::Incompatible)
        );

        let (_directory, oversized) =
            script("head -c 65537 /dev/zero | tr '\\000' x; printf '\\n'");
        assert_eq!(
            exchange_with_binary(&oversized, &request, Duration::from_secs(5)),
            Err(ExtensionTransportError::OversizedFrame)
        );

        let (_directory, timeout) = script("sleep 2");
        let started = Instant::now();
        assert_eq!(
            exchange_with_binary(&timeout, &request, Duration::from_millis(50)),
            Err(ExtensionTransportError::Timeout)
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "timeout cleanup must stay bounded"
        );
    }

    #[test]
    fn dashboard_intent_storm_is_bounded_before_extension_work_starts() {
        let (commands, _receiver) = mpsc::sync_channel(WORKER_COMMAND_CAPACITY);
        for _ in 0..WORKER_COMMAND_CAPACITY {
            assert!(commands.try_send(WorkerCommand::Refresh).is_ok());
        }
        assert_eq!(
            queue_mutation(&commands, WorkerCommand::SetRemoteOpen(true)),
            Err("Another Remote operation is already pending.")
        );
    }

    #[test]
    fn global_owner_toggle_schedules_exact_local_reclaims_but_never_remote_authority() {
        let (commands, receiver) = mpsc::sync_channel(WORKER_COMMAND_CAPACITY);
        let (_updates_tx, updates) = mpsc::sync_channel(WORKER_UPDATE_CAPACITY);
        let worker = OptionalExtensionWorker { commands, updates };

        worker.request_winsize_owner_toggle(false).unwrap();
        assert!(matches!(
            receiver.recv().unwrap(),
            WorkerCommand::ReclaimAllViewports {
                reason: ViewportReclaimReason::UserRequested,
            }
        ));

        worker.request_winsize_owner_toggle(true).unwrap();
        assert!(matches!(receiver.recv().unwrap(), WorkerCommand::Refresh));
        assert!(receiver.try_recv().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn flooding_child_is_backpressured_and_rejected_without_waiting_for_its_output() {
        let response = r#"{"type":"status","request_id":7,"status":{"enrollment_id":null,"remote_open":false,"active_connections":0}}"#;
        let body = format!(
            r#"IFS= read -r hello
printf '%s\n' '{{"protocol":{{"min":1,"max":1}},"capabilities":["remote_desktop_lifecycle_v1"]}}'
IFS= read -r request
i=0
while [ "$i" -lt 10000 ]; do
  printf '%s\n' '{response}'
  i=$((i + 1))
done"#
        );
        let (_directory, flooding) = script(&body);
        let request = RemoteDesktopHostRequest::Status {
            request_id: request_id(),
        };
        let started = Instant::now();
        assert_eq!(
            exchange_with_binary(&flooding, &request, Duration::from_secs(5)),
            Err(ExtensionTransportError::ExtraOutput)
        );
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "extra output must be rejected well before the five-second operation deadline"
        );
    }

    #[test]
    fn request_id_and_variant_must_match() {
        let request = RemoteDesktopHostRequest::Status {
            request_id: request_id(),
        };
        let wrong_id = RemoteDesktopExtensionResponse::Status {
            request_id: RemoteDesktopRequestId::new(8).unwrap(),
            status: RemoteDesktopStatus::new(None, None, false, 0, None).unwrap(),
        };
        assert_eq!(
            outcome_from_response(&request, wrong_id),
            Err(ExtensionTransportError::MismatchedRequestId)
        );
        let wrong_variant = RemoteDesktopExtensionResponse::EnrollmentRemoved {
            request_id: request_id(),
            status: RemoteDesktopStatus::new(None, None, false, 0, None).unwrap(),
        };
        assert_eq!(
            outcome_from_response(&request, wrong_variant),
            Err(ExtensionTransportError::UnexpectedResponse)
        );
    }

    #[test]
    fn status_projects_bounded_display_account_without_using_enrollment_id_as_label() {
        let status = RemoteDesktopStatus::new(
            Some(RemoteDesktopId::new("enrollment-opaque").unwrap()),
            Some(RemoteDesktopId::new("account-display").unwrap()),
            true,
            2,
            None,
        )
        .unwrap();
        assert_eq!(
            projection_from_status(&status),
            RemoteExtensionProjection {
                available: true,
                enrolled: true,
                account_id: Some("account-display".to_string()),
                remote_open: true,
                active_connections: 2,
                remote_owned_sessions: Vec::new(),
                filesystem_mode_migration: None,
            }
        );
    }

    #[test]
    fn validated_enrollment_refusals_do_not_publish_true_false_true_capability_flicker() {
        let status = RemoteDesktopStatus::new(None, None, false, 0, None).unwrap();
        let authoritative = projection_from_status(&status);
        assert!(authoritative.available);

        for (code, retryable, message) in [
            (
                RemoteDesktopErrorCode::Internal,
                false,
                "Remote lifecycle could not be verified. Restart Hydra before trying again.",
            ),
            (
                RemoteDesktopErrorCode::Busy,
                true,
                "Remote is busy. Wait a moment and try again.",
            ),
        ] {
            let request = RemoteDesktopHostRequest::Enroll {
                request_id: request_id(),
                code: EnrollmentCode::new("TEST-CODE").unwrap(),
            };
            let response = RemoteDesktopExtensionResponse::Error {
                request_id: request_id(),
                error: maestro_extension_api::RemoteDesktopResponseError::new(
                    code,
                    "bounded enrollment failure",
                    retryable,
                )
                .unwrap(),
            };
            let validated_error = outcome_from_response(&request, response).unwrap_err();
            assert_eq!(
                validated_error,
                ExtensionTransportError::Refused { code, retryable }
            );
            let mut state = WorkerState {
                last_projection: authoritative.clone(),
                ..Default::default()
            };
            let rejected = failed_operation_update(
                ExtensionOperation::Enroll,
                &mut state,
                validated_error,
                Instant::now(),
            );
            let recovered = projection_from_status(&status);

            assert_eq!(
                [
                    authoritative.available,
                    rejected.projection.available,
                    recovered.available,
                ],
                [true, true, true],
                "a validated refusal must not masquerade as capability loss"
            );
            assert_eq!(rejected.error_message, Some(message));
            assert!(!rejected.projection.enrolled);
            assert!(!rejected.projection.remote_open);
        }
    }

    #[test]
    fn lifecycle_errors_have_bounded_actionable_host_owned_messages() {
        use ExtensionOperation::{Enroll, SetRemoteOpen};
        use ExtensionTransportError as Error;
        use RemoteDesktopErrorCode as Code;

        let cases = [
            (
                Error::Refused {
                    code: Code::NotEnrolled,
                    retryable: false,
                },
                SetRemoteOpen,
                "This desktop is not enrolled. Add Remote first.",
            ),
            (
                Error::Refused {
                    code: Code::AlreadyEnrolled,
                    retryable: false,
                },
                Enroll,
                "This desktop is already enrolled.",
            ),
            (
                Error::Refused {
                    code: Code::EnrollmentRejected,
                    retryable: false,
                },
                Enroll,
                "Enrollment was rejected. Generate a fresh code and try again.",
            ),
            (
                Error::Refused {
                    code: Code::RemoteUnavailable,
                    retryable: true,
                },
                Enroll,
                "The code was accepted, but Remote could not start. Generate a fresh code and try again.",
            ),
            (
                Error::Refused {
                    code: Code::RemoteUnavailable,
                    retryable: true,
                },
                SetRemoteOpen,
                "Remote service is temporarily unavailable. Wait a moment and try again.",
            ),
            (
                Error::Refused {
                    code: Code::RemoteUnavailable,
                    retryable: false,
                },
                SetRemoteOpen,
                "Remote was closed for safety. Add this desktop again.",
            ),
            (
                Error::Refused {
                    code: Code::ViewportUnavailable,
                    retryable: false,
                },
                SetRemoteOpen,
                "The remote viewport changed. Try again.",
            ),
            (
                Error::Refused {
                    code: Code::Busy,
                    retryable: true,
                },
                Enroll,
                "Remote is busy. Wait a moment and try again.",
            ),
            (
                Error::Refused {
                    code: Code::Internal,
                    retryable: true,
                },
                Enroll,
                "Remote hit an internal lifecycle error. Wait a moment and try again.",
            ),
            (
                Error::Refused {
                    code: Code::Internal,
                    retryable: false,
                },
                Enroll,
                "Remote lifecycle could not be verified. Restart Hydra before trying again.",
            ),
            (
                Error::Refused {
                    code: Code::InvalidRequest,
                    retryable: false,
                },
                Enroll,
                "Hydra Remote could not process this request. Update Hydra and try again.",
            ),
            (
                Error::Incompatible,
                Enroll,
                "Hydra Remote components are incompatible. Update Hydra and try again.",
            ),
            (
                Error::MissingCapability,
                Enroll,
                "Hydra Remote components are incompatible. Update Hydra and try again.",
            ),
            (
                Error::OversizedFrame,
                Enroll,
                "Hydra Remote returned an invalid protocol response. Update Hydra and try again.",
            ),
            (
                Error::MalformedFrame,
                Enroll,
                "Hydra Remote returned an invalid protocol response. Update Hydra and try again.",
            ),
            (
                Error::MismatchedRequestId,
                Enroll,
                "Hydra Remote returned an invalid protocol response. Update Hydra and try again.",
            ),
            (
                Error::MismatchedNoticeId,
                Enroll,
                "Hydra Remote returned an invalid protocol response. Update Hydra and try again.",
            ),
            (
                Error::UnexpectedResponse,
                Enroll,
                "Hydra Remote returned an invalid protocol response. Update Hydra and try again.",
            ),
            (
                Error::ExtraOutput,
                Enroll,
                "Hydra Remote returned an invalid protocol response. Update Hydra and try again.",
            ),
            (
                Error::Spawn,
                Enroll,
                "Hydra Remote could not start. Reinstall or update Hydra, then try again.",
            ),
            (
                Error::Io,
                Enroll,
                "Hydra Remote stopped unexpectedly. Restart Hydra and try again.",
            ),
            (
                Error::ChildFailed,
                Enroll,
                "Hydra Remote stopped unexpectedly. Restart Hydra and try again.",
            ),
            (
                Error::Timeout,
                Enroll,
                "Remote extension timed out. Try again.",
            ),
        ];

        for (error, operation, expected) in cases {
            let message = error.user_message(operation);
            assert_eq!(message, expected);
            assert!(!message.contains("unavailable or incompatible"));
        }
    }

    #[test]
    fn validated_busy_refresh_preserves_capability_but_transport_loss_remains_fail_closed() {
        let mut state = WorkerState {
            last_projection: projection_from_status(
                &RemoteDesktopStatus::new(None, None, false, 0, None).unwrap(),
            ),
            ..Default::default()
        };

        let busy = failed_operation_update(
            ExtensionOperation::Refresh,
            &mut state,
            ExtensionTransportError::Refused {
                code: RemoteDesktopErrorCode::Busy,
                retryable: true,
            },
            Instant::now(),
        );
        assert!(busy.projection.available);
        assert_eq!(busy.error_message, None);

        let timeout = failed_operation_update(
            ExtensionOperation::Refresh,
            &mut state,
            ExtensionTransportError::Timeout,
            Instant::now(),
        );
        assert!(!timeout.projection.available);
        assert_eq!(timeout.error_message, None);
    }

    #[test]
    fn pending_migration_survives_transient_extension_loss_without_a_viewport_cache() {
        let notice = migration_notice(FilesystemModeMigrationPhase::Interrupted);
        let mut state = WorkerState {
            last_projection: RemoteExtensionProjection {
                available: true,
                enrolled: true,
                account_id: Some("account-display".to_string()),
                remote_open: false,
                active_connections: 0,
                remote_owned_sessions: Vec::new(),
                filesystem_mode_migration: Some(notice.clone()),
            },
            ..Default::default()
        };

        let projection = state.projection_with_live_cache(Instant::now());
        assert!(projection.available);
        assert_eq!(projection.filesystem_mode_migration, Some(notice));
    }

    #[test]
    fn lost_ack_response_converges_only_on_next_capable_status_without_notice() {
        let notice = migration_notice(FilesystemModeMigrationPhase::Applied);
        let notice_id = notice.notice_id().clone();
        let mut state = WorkerState {
            last_projection: RemoteExtensionProjection {
                available: true,
                filesystem_mode_migration: Some(notice),
                ..Default::default()
            },
            pending_acknowledgement: Some(notice_id.clone()),
            ..Default::default()
        };
        // The child may have unlinked the receipt even though its Ack response was lost.

        assert!(
            !migration_latch_accepts_status(&mut state, ExtensionOperation::Refresh, false),
            "an old incapable child cannot prove receipt absence"
        );
        state.pending_acknowledgement =
            Some(FilesystemModeMigrationNoticeId::new("b".repeat(64)).unwrap());
        assert!(
            !migration_latch_accepts_status(&mut state, ExtensionOperation::Refresh, true),
            "a capable status cannot clear a different exact Ack attempt"
        );
        state.pending_acknowledgement = Some(notice_id);
        assert!(migration_latch_accepts_status(
            &mut state,
            ExtensionOperation::Refresh,
            true
        ));
        assert!(state.pending_acknowledgement.is_none());

        // This is the same projection replacement performed after the helper accepts Status.
        state.last_projection =
            projection_from_status(&RemoteDesktopStatus::new(None, None, false, 0, None).unwrap());
        assert!(state.last_projection.filesystem_mode_migration.is_none());
    }

    #[test]
    fn worker_state_blocks_ordinary_remote_mutation_while_notice_is_pending() {
        let notice = migration_notice(FilesystemModeMigrationPhase::ReadyToApply);
        let mut state = WorkerState::default();
        state.last_projection.available = true;
        state.last_projection.filesystem_mode_migration = Some(notice.clone());
        let mut next_request_id = 1;

        let update = run_operation(
            ExtensionOperation::SetRemoteOpen,
            &mut next_request_id,
            Some(PendingRequest::SetRemoteOpen(true)),
            &mut state,
        );
        assert_eq!(
            update.error_message,
            Some("Secure the listed files and folders before changing Remote.")
        );
        assert_eq!(update.projection.filesystem_mode_migration, Some(notice));
        assert_eq!(next_request_id, 1, "blocked work never reaches the child");
    }

    #[test]
    fn typed_notice_and_ack_outcomes_are_distinct_and_correlated() {
        let request = RemoteDesktopHostRequest::Status {
            request_id: request_id(),
        };
        let notice = migration_notice(FilesystemModeMigrationPhase::ReadyToApply);
        assert_eq!(
            outcome_from_response(
                &request,
                RemoteDesktopExtensionResponse::FilesystemModeMigration {
                    request_id: request_id(),
                    notice: notice.clone(),
                    status: None,
                }
            ),
            Ok(OperationOutcome::Notice {
                notice,
                status: None
            })
        );

        let status = RemoteDesktopStatus::new(None, None, false, 0, None).unwrap();
        let ack = RemoteDesktopHostRequest::AcknowledgeFilesystemModeMigration {
            request_id: request_id(),
            notice_id: FilesystemModeMigrationNoticeId::new("a".repeat(64)).unwrap(),
        };
        assert_eq!(
            outcome_from_response(
                &ack,
                RemoteDesktopExtensionResponse::FilesystemModeMigrationAcknowledged {
                    request_id: request_id(),
                    status: status.clone(),
                }
            ),
            Ok(OperationOutcome::Status(status))
        );
    }

    fn viewport(session: &str, lease: &str, epoch: u64, sequence: u64) -> RemoteDesktopViewport {
        RemoteDesktopViewport::new(
            SessionKey::new(session).unwrap(),
            LeaseId::new(lease).unwrap(),
            LeaseCursor::new(epoch, sequence).unwrap(),
            ViewportGeometry::new(80, 24, 640, 384).unwrap(),
        )
    }

    #[test]
    fn snapshot_cache_accepts_multi_lease_cursors_and_equal_replay_never_renews_ttl() {
        let mut cache = ViewportSnapshotCache::default();
        let received = Instant::now();
        let entries = RemoteDesktopViewportList::new([
            viewport("s1", "l1", 4, 1),
            viewport("s2", "l2", 4, 2),
        ])
        .unwrap();
        cache
            .accept(LeaseCursor::new(4, 3).unwrap(), 100, &entries, received)
            .unwrap();
        let original_expiry = cache.expires_at;
        assert_eq!(
            cache.sessions(received + Duration::from_millis(50)),
            vec!["s1".to_string(), "s2".to_string()]
        );
        assert_eq!(
            cache.accept(
                LeaseCursor::new(4, 3).unwrap(),
                5_000,
                &entries,
                received + Duration::from_millis(50),
            ),
            Err(SnapshotCacheError::StaleOrReplayed)
        );
        assert_eq!(cache.expires_at, original_expiry);
        assert!(cache
            .sessions(received + Duration::from_millis(100))
            .is_empty());
    }

    #[test]
    fn failed_or_mismatched_reclaim_keeps_resize_suppression_until_exact_success() {
        let mut cache = ViewportSnapshotCache::default();
        let received = Instant::now();
        cache
            .accept(
                LeaseCursor::new(30, 2).unwrap(),
                1_000,
                &RemoteDesktopViewportList::new([viewport("s1", "lease-1", 30, 1)]).unwrap(),
                received,
            )
            .unwrap();
        let cached = cache
            .lease(&SessionKey::new("s1").unwrap(), received)
            .unwrap();
        let request_id = RemoteDesktopRequestId::new(41).unwrap();

        assert!(!apply_reclaim_response(
            &mut cache,
            &cached,
            request_id,
            Err(ExtensionTransportError::Timeout),
        ));
        assert_eq!(cache.sessions(received), vec!["s1"]);

        assert!(!apply_reclaim_response(
            &mut cache,
            &cached,
            request_id,
            Ok(RemoteDesktopExtensionResponse::ViewportReclaimed {
                request_id: RemoteDesktopRequestId::new(42).unwrap(),
                session_id: cached.session_id.clone(),
                lease_id: cached.lease_id.clone(),
            }),
        ));
        assert_eq!(cache.sessions(received), vec!["s1"]);

        cache
            .accept(
                LeaseCursor::new(30, 4).unwrap(),
                1_000,
                &RemoteDesktopViewportList::new([viewport("s1", "lease-1", 30, 3)]).unwrap(),
                received + Duration::from_millis(1),
            )
            .unwrap();
        assert!(!apply_reclaim_response(
            &mut cache,
            &cached,
            request_id,
            Ok(RemoteDesktopExtensionResponse::ViewportReclaimed {
                request_id,
                session_id: cached.session_id.clone(),
                lease_id: cached.lease_id.clone(),
            }),
        ));
        assert_eq!(
            cache.sessions(received + Duration::from_millis(1)),
            vec!["s1"],
            "a response for the pre-race cursor cannot remove the newer lease projection",
        );

        let current = cache
            .lease(
                &SessionKey::new("s1").unwrap(),
                received + Duration::from_millis(1),
            )
            .unwrap();
        assert!(apply_reclaim_response(
            &mut cache,
            &current,
            request_id,
            Ok(RemoteDesktopExtensionResponse::ViewportReclaimed {
                request_id,
                session_id: current.session_id.clone(),
                lease_id: current.lease_id.clone(),
            }),
        ));
        assert!(cache.sessions(received).is_empty());
    }

    #[test]
    fn transient_loss_preserves_last_snapshot_only_until_server_ttl() {
        let mut state = WorkerState {
            last_projection: RemoteExtensionProjection {
                available: true,
                enrolled: true,
                account_id: Some("account-display".to_string()),
                remote_open: true,
                active_connections: 1,
                remote_owned_sessions: Vec::new(),
                filesystem_mode_migration: None,
            },
            ..Default::default()
        };
        let received = Instant::now();
        state
            .viewport
            .accept(
                LeaseCursor::new(8, 2).unwrap(),
                80,
                &RemoteDesktopViewportList::new([viewport("s1", "l1", 8, 1)]).unwrap(),
                received,
            )
            .unwrap();
        let before_expiry = state.projection_with_live_cache(received + Duration::from_millis(79));
        assert!(before_expiry.available);
        assert_eq!(before_expiry.remote_owned_sessions, vec!["s1"]);
        let after_expiry = state.projection_with_live_cache(received + Duration::from_millis(80));
        assert!(!after_expiry.available);
        assert!(after_expiry.remote_owned_sessions.is_empty());
    }

    #[test]
    fn new_process_epoch_invalidates_old_leases_and_retired_epoch_cannot_resurrect() {
        let mut cache = ViewportSnapshotCache::default();
        let received = Instant::now();
        cache
            .accept(
                LeaseCursor::new(10, 2).unwrap(),
                1_000,
                &RemoteDesktopViewportList::new([viewport("old", "l-old", 10, 1)]).unwrap(),
                received,
            )
            .unwrap();
        cache
            .accept(
                LeaseCursor::new(20, 2).unwrap(),
                1_000,
                &RemoteDesktopViewportList::new([viewport("new", "l-new", 20, 1)]).unwrap(),
                received + Duration::from_millis(1),
            )
            .unwrap();
        assert_eq!(cache.sessions(received), vec!["new"]);
        for epoch in 21..=40 {
            cache
                .accept(
                    LeaseCursor::new(epoch, 2).unwrap(),
                    1_000,
                    &RemoteDesktopViewportList::new([viewport(
                        "new",
                        &format!("lease-{epoch}"),
                        epoch,
                        1,
                    )])
                    .unwrap(),
                    received + Duration::from_millis(epoch),
                )
                .unwrap();
        }
        assert_eq!(
            cache.accept(
                LeaseCursor::new(10, 100).unwrap(),
                1_000,
                &RemoteDesktopViewportList::new([viewport("old", "l-old", 10, 99)]).unwrap(),
                received + Duration::from_millis(2),
            ),
            Err(SnapshotCacheError::RetiredEpoch)
        );
        assert_eq!(cache.sessions(received), vec!["new"]);
    }
}
