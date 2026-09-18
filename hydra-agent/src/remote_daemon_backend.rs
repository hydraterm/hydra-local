//! S3c-wiring — the PRODUCTION daemon-backed `SessionBackend`. The S4 `TerminalBridge` drives a sync
//! `SessionBackend`; the real daemon path is async (a `UnixStream` speaking the daemon's newline-JSON
//! protocol). To keep the sync trait (so the S4 fake tests don't churn), this backend is a thin sync
//! handle that ENQUEUES `ClientRequest` JSON to an async task which owns the daemon socket: it writes the
//! requests and pumps daemon OUTPUT lines back out to a callback (the peer turns those into binary
//! `terminal_output` frames). No new daemon protocol — reuses the existing ClientRequest/event wire.
//!
//! Content-blind by construction: terminal bytes flow daemon↔backend↔peer (DTLS DataChannel) only; nothing
//! terminal touches the cloud, and only sizes/counts may be logged (never payloads).

// Prepared-session failures retain consume-once recovery receipts, and route linearization keeps
// its complete authority tuple together at the call boundary.
#![allow(clippy::result_large_err, clippy::too_many_arguments)]

use std::path::PathBuf;

use serde::Deserialize as _;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use crate::remote_bridge::{
    ResizeAdmission, SessionBackend, SessionMetadata, WorkspaceMetadata, WorkspacePaneMetadata,
    WorkspaceProjectMetadata, WorkspaceWindowMetadata,
};
use crate::session_creator::InitialTerminalSize;

/// An outbound daemon request line (already serialized JSON, no trailing newline).
type ReqLine = String;

fn unix_now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// Bound remote→daemon request batches even when the local Unix socket writer stalls. The accepted
/// terminal-input burst is 1 MiB, and worst-case JSON escaping can expand one byte to six ASCII bytes;
/// 8 MiB therefore retains the complete accepted burst plus control messages without becoming an
/// unbounded per-peer buffer. The item cap counts ordered queue tickets; a durable multi-kill operation
/// occupies one ticket while its exact aggregate bytes remain charged below.
const DAEMON_REQUEST_QUEUE_CAP: usize = 256;
const DAEMON_REQUEST_QUEUE_BYTE_CAP: usize = 8 * 1024 * 1024;

struct QueuedDaemonLine {
    line: Box<str>,
    /// Retain the exact encoded line + newline budget until the socket writer finishes this request.
    _byte_permit: tokio::sync::OwnedSemaphorePermit,
}

impl std::ops::Deref for QueuedDaemonLine {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.line
    }
}

/// A queue-position ticket published during `prepare`. The writer cannot pass this ticket, so a
/// durable operation's eventual batch is ordered ahead of every later clone send. `commit` supplies
/// the complete batch through the oneshot; dropping the prepared value cancels the ticket cleanly.
struct PendingDaemonRequestBatch {
    committed: tokio::sync::oneshot::Receiver<Vec<QueuedDaemonLine>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonRequestEnqueueError {
    ItemLimit,
    ByteLimit,
    ReceiverClosed,
    ProducerStopped,
    InvalidHeadlessAccount,
}

struct DaemonRequestQueueState {
    tx: Option<mpsc::Sender<PendingDaemonRequestBatch>>,
}

/// Acquire the shared request lifecycle state or fail the whole connection if a prior panic poisoned it.
///
/// A `PoisonError` still owns the recovered mutex guard. Close the producer through that guard directly;
/// calling `DaemonRequestStopper::stop` from the error arm would try to lock the same mutex recursively and
/// deadlock before it could wake the connection owner.
fn lock_daemon_request_state_or_stop<'a>(
    state: &'a std::sync::Mutex<DaemonRequestQueueState>,
    failure_tx: &tokio::sync::watch::Sender<bool>,
) -> Result<std::sync::MutexGuard<'a, DaemonRequestQueueState>, DaemonRequestEnqueueError> {
    match state.lock() {
        Ok(state) => Ok(state),
        Err(poisoned) => {
            let mut state = poisoned.into_inner();
            state.tx.take();
            drop(state);
            let _ = failure_tx.send(true);
            Err(DaemonRequestEnqueueError::ProducerStopped)
        }
    }
}

/// Cloneable synchronous facade for SessionBackend's synchronous methods. A limit failure atomically takes
/// the shared producer out of every clone and wakes owner teardown; no later input/resize/mutation can leap
/// over a request ticket that was refused or survive on a half-live daemon connection.
#[derive(Clone)]
struct DaemonRequestSender {
    state: std::sync::Arc<std::sync::Mutex<DaemonRequestQueueState>>,
    byte_budget: std::sync::Arc<tokio::sync::Semaphore>,
    byte_capacity: usize,
    batch_line_capacity: usize,
    failure_tx: tokio::sync::watch::Sender<bool>,
    /// Installed only by one authenticated remote control owner. All concrete creation adapters share this
    /// sender, so they can reserve the new session's request-scoped winsize lease before exposing records.
    creation_lease_publisher: std::sync::Arc<
        std::sync::Mutex<Option<crate::winsize_owner::RemoteCreationLeasePublisher>>,
    >,
    /// Exact socket and kernel peer identity of the already-reviewed operational connection.
    /// Project deletion needs a short-lived synchronous connection, but it must never rediscover
    /// authority from a desktop/systemd environment that can resolve a different socket.
    daemon_authority: std::sync::Arc<std::sync::OnceLock<ReviewedDaemonAuthority>>,
    /// Immutable launch policy inherited from the remote-peer process. Keeping it on the shared
    /// sender makes every concrete session-creation adapter apply the same policy without adding
    /// parallel mutable fields to each adapter.
    headless_server: bool,
}

#[derive(Clone)]
struct DaemonRequestStopper {
    state: std::sync::Weak<std::sync::Mutex<DaemonRequestQueueState>>,
    failure_tx: tokio::sync::watch::Sender<bool>,
}

struct DaemonRequestReceiver {
    rx: mpsc::Receiver<PendingDaemonRequestBatch>,
    pending: Option<tokio::sync::oneshot::Receiver<Vec<QueuedDaemonLine>>>,
    ready: std::collections::VecDeque<QueuedDaemonLine>,
    failure_tx: tokio::sync::watch::Sender<bool>,
    stopper: DaemonRequestStopper,
}

/// Capacity reserved before a durable desktop mutation begins. Dropping this value releases every
/// byte permit and cancels its already-ordered queue ticket; `commit` publishes the complete batch
/// only after the corresponding local record transaction succeeds and reports a stale writer.
struct PreparedDaemonRequests {
    lines: Vec<(Box<str>, usize)>,
    commit_tx: Option<tokio::sync::oneshot::Sender<Vec<QueuedDaemonLine>>>,
    byte_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    stopper: DaemonRequestStopper,
}

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_PREPARED_DAEMON_COMMIT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn fail_next_prepared_daemon_commit() {
    FAIL_NEXT_PREPARED_DAEMON_COMMIT.with(|fail| fail.set(true));
}

impl PreparedDaemonRequests {
    fn commit(mut self) -> Result<(), DaemonRequestEnqueueError> {
        #[cfg(test)]
        if FAIL_NEXT_PREPARED_DAEMON_COMMIT.with(|fail| fail.replace(false)) {
            self.stopper.stop();
            return Err(DaemonRequestEnqueueError::ProducerStopped);
        }
        let mut bytes = self
            .byte_permit
            .take()
            .expect("non-empty request batch owns a byte reservation");
        let mut committed = Vec::with_capacity(self.lines.len());
        for (line, byte_cost) in self.lines.drain(..) {
            let permit = bytes
                .split(byte_cost)
                .expect("batch byte reservation covers every prepared line");
            committed.push(QueuedDaemonLine {
                line,
                _byte_permit: permit,
            });
        }
        debug_assert_eq!(bytes.num_permits(), 0);
        let Some(commit_tx) = self.commit_tx.take() else {
            self.stopper.stop();
            return Err(DaemonRequestEnqueueError::ProducerStopped);
        };
        let Some(state) = self.stopper.state.upgrade() else {
            self.stopper.stop();
            return Err(DaemonRequestEnqueueError::ProducerStopped);
        };
        let state = lock_daemon_request_state_or_stop(&state, &self.stopper.failure_tx)?;
        if state.tx.is_none() {
            drop(state);
            self.stopper.stop();
            return Err(DaemonRequestEnqueueError::ProducerStopped);
        }
        // Serialize the lifecycle verdict with stop(): once a reader/writer failure has taken the
        // shared sender, an already-prepared durable mutation cannot publish or report success.
        let committed = commit_tx.send(committed);
        drop(state);
        if committed.is_err() {
            self.stopper.stop();
            return Err(DaemonRequestEnqueueError::ReceiverClosed);
        }
        Ok(())
    }
}

impl DaemonRequestStopper {
    fn stop(&self) {
        if let Some(state) = self.state.upgrade() {
            match state.lock() {
                Ok(mut state) => {
                    state.tx.take();
                }
                Err(poisoned) => {
                    let mut state = poisoned.into_inner();
                    state.tx.take();
                    drop(state);
                }
            }
        }
        let _ = self.failure_tx.send(true);
    }
}

fn daemon_request_channel(
    item_capacity: usize,
    byte_capacity: usize,
) -> (DaemonRequestSender, DaemonRequestReceiver) {
    daemon_request_channel_with_policy(item_capacity, byte_capacity, false)
}

fn daemon_request_channel_with_policy(
    item_capacity: usize,
    byte_capacity: usize,
    headless_server: bool,
) -> (DaemonRequestSender, DaemonRequestReceiver) {
    assert!(
        item_capacity > 0,
        "daemon request item capacity must be non-zero"
    );
    assert!(
        byte_capacity > 0 && byte_capacity <= u32::MAX as usize,
        "daemon request byte capacity must fit acquire_many_owned"
    );
    let (tx, rx) = mpsc::channel(item_capacity);
    let (failure_tx, _failure_rx) = tokio::sync::watch::channel(false);
    let state = std::sync::Arc::new(std::sync::Mutex::new(DaemonRequestQueueState {
        tx: Some(tx),
    }));
    let stopper = DaemonRequestStopper {
        state: std::sync::Arc::downgrade(&state),
        failure_tx: failure_tx.clone(),
    };
    (
        DaemonRequestSender {
            state,
            byte_budget: std::sync::Arc::new(tokio::sync::Semaphore::new(byte_capacity)),
            byte_capacity,
            batch_line_capacity: item_capacity,
            failure_tx: failure_tx.clone(),
            creation_lease_publisher: std::sync::Arc::new(std::sync::Mutex::new(None)),
            daemon_authority: std::sync::Arc::new(std::sync::OnceLock::new()),
            headless_server,
        },
        DaemonRequestReceiver {
            rx,
            pending: None,
            ready: std::collections::VecDeque::new(),
            failure_tx,
            stopper,
        },
    )
}

impl DaemonRequestSender {
    fn headless_server(&self) -> bool {
        self.headless_server
    }

    fn set_reviewed_daemon_authority(&self, authority: ReviewedDaemonAuthority) {
        self.daemon_authority
            .set(authority)
            .expect("daemon authority is immutable after connection setup");
    }

    fn reviewed_daemon_authority(&self) -> Option<ReviewedDaemonAuthority> {
        self.daemon_authority.get().cloned()
    }

    fn stop(&self) {
        self.stopper().stop();
    }

    fn stopper(&self) -> DaemonRequestStopper {
        DaemonRequestStopper {
            state: std::sync::Arc::downgrade(&self.state),
            failure_tx: self.failure_tx.clone(),
        }
    }

    fn set_creation_lease_publisher(
        &self,
        publisher: crate::winsize_owner::RemoteCreationLeasePublisher,
    ) {
        *self
            .creation_lease_publisher
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(publisher);
    }

    fn begin_remote_creation_lease(
        &self,
        session_id: &str,
        now_ms: u64,
    ) -> std::io::Result<crate::winsize_owner::RemoteCreationLeaseGuard> {
        let publisher = self
            .creation_lease_publisher
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        match publisher {
            Some(publisher) => publisher.reserve(session_id, now_ms),
            None => Ok(crate::winsize_owner::RemoteCreationLeaseGuard::noop()),
        }
    }

    fn prepare_batch(
        &self,
        lines: Vec<ReqLine>,
    ) -> Result<Option<PreparedDaemonRequests>, DaemonRequestEnqueueError> {
        if lines.is_empty() {
            return Ok(None);
        }
        if lines.len() > self.batch_line_capacity {
            self.stop();
            return Err(DaemonRequestEnqueueError::ItemLimit);
        }
        {
            let state = lock_daemon_request_state_or_stop(&self.state, &self.failure_tx)?;
            if state.tx.is_none() {
                return Err(DaemonRequestEnqueueError::ProducerStopped);
            }
        }
        let mut prepared_lines = Vec::with_capacity(lines.len());
        let mut total_bytes = 0_usize;
        for line in lines {
            let line = self.apply_headless_session_environment(line)?;
            let line = line.into_boxed_str();
            let byte_cost = line.len().checked_add(1).ok_or_else(|| {
                self.stop();
                DaemonRequestEnqueueError::ByteLimit
            })?;
            total_bytes = total_bytes.checked_add(byte_cost).ok_or_else(|| {
                self.stop();
                DaemonRequestEnqueueError::ByteLimit
            })?;
            prepared_lines.push((line, byte_cost));
        }
        if total_bytes > self.byte_capacity || total_bytes > u32::MAX as usize {
            self.stop();
            return Err(DaemonRequestEnqueueError::ByteLimit);
        }
        let byte_permit = match self
            .byte_budget
            .clone()
            .try_acquire_many_owned(total_bytes as u32)
        {
            Ok(permit) => permit,
            Err(_) => {
                self.stop();
                return Err(DaemonRequestEnqueueError::ByteLimit);
            }
        };
        let mut state = lock_daemon_request_state_or_stop(&self.state, &self.failure_tx)?;
        let Some(tx) = state.tx.as_ref() else {
            return Err(DaemonRequestEnqueueError::ProducerStopped);
        };
        let slot = match tx.clone().try_reserve_owned() {
            Ok(slot) => slot,
            Err(mpsc::error::TrySendError::Full(_)) => {
                state.tx.take();
                drop(state);
                drop(byte_permit);
                let _ = self.failure_tx.send(true);
                return Err(DaemonRequestEnqueueError::ItemLimit);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                state.tx.take();
                drop(state);
                drop(byte_permit);
                let _ = self.failure_tx.send(true);
                return Err(DaemonRequestEnqueueError::ReceiverClosed);
            }
        };
        let (commit_tx, commit_rx) = tokio::sync::oneshot::channel();
        let _sender = slot.send(PendingDaemonRequestBatch {
            committed: commit_rx,
        });
        if tx.is_closed() {
            state.tx.take();
            drop(state);
            drop(byte_permit);
            let _ = self.failure_tx.send(true);
            return Err(DaemonRequestEnqueueError::ReceiverClosed);
        }
        drop(state);
        Ok(Some(PreparedDaemonRequests {
            lines: prepared_lines,
            commit_tx: Some(commit_tx),
            byte_permit: Some(byte_permit),
            stopper: self.stopper(),
        }))
    }

    fn prepare(&self, line: ReqLine) -> Result<PreparedDaemonRequests, DaemonRequestEnqueueError> {
        self.prepare_batch(vec![line])?
            .ok_or(DaemonRequestEnqueueError::ProducerStopped)
    }

    fn send(&self, line: ReqLine) -> Result<(), DaemonRequestEnqueueError> {
        self.prepare(line)?.commit()
    }

    /// Bind every headless StartSession to the effective account's current, validated passwd
    /// HOME/SHELL at the final queue boundary. Centralizing this here covers create, split, revive,
    /// restart, and provider paths without changing desktop request bytes. If account metadata is
    /// unsafe or unavailable, fail before reserving queue bytes or publishing durable mutations.
    fn apply_headless_session_environment(
        &self,
        line: ReqLine,
    ) -> Result<ReqLine, DaemonRequestEnqueueError> {
        if !self.headless_server || !is_start_session_request(&line) {
            return Ok(line);
        }
        let mut request: maestro_protocol::ClientRequest = serde_json::from_str(&line)
            .map_err(|_| DaemonRequestEnqueueError::InvalidHeadlessAccount)?;
        let account = crate::agent_dir::trusted_session_account()
            .map_err(|_| DaemonRequestEnqueueError::InvalidHeadlessAccount)?;
        let maestro_protocol::ClientRequest::StartSession {
            child_environment, ..
        } = &mut request
        else {
            return Err(DaemonRequestEnqueueError::InvalidHeadlessAccount);
        };
        *child_environment = Some(maestro_protocol::ChildEnvironment {
            home: account
                .home
                .to_str()
                .ok_or(DaemonRequestEnqueueError::InvalidHeadlessAccount)?
                .to_string(),
            shell: account.shell,
        });
        serde_json::to_string(&request)
            .map_err(|_| DaemonRequestEnqueueError::InvalidHeadlessAccount)
    }

    #[cfg(test)]
    fn available_bytes(&self) -> usize {
        self.byte_budget.available_permits()
    }
}

impl DaemonRequestReceiver {
    async fn recv(&mut self) -> Option<QueuedDaemonLine> {
        loop {
            if let Some(line) = self.ready.pop_front() {
                return Some(line);
            }
            if self.pending.is_none() {
                self.pending = Some(self.rx.recv().await?.committed);
            }
            let committed = self
                .pending
                .as_mut()
                .expect("pending request batch was just installed")
                .await;
            self.pending = None;
            if let Ok(lines) = committed {
                self.ready.extend(lines);
            }
        }
    }

    fn failure_receiver(&self) -> tokio::sync::watch::Receiver<bool> {
        self.failure_tx.subscribe()
    }

    fn fail(&self) {
        self.stopper.stop();
    }

    #[cfg(test)]
    fn try_recv(&mut self) -> Result<String, mpsc::error::TryRecvError> {
        loop {
            if let Some(QueuedDaemonLine { line, _byte_permit }) = self.ready.pop_front() {
                return Ok(line.into_string());
            }
            if self.pending.is_none() {
                self.pending = Some(self.rx.try_recv()?.committed);
            }
            match self
                .pending
                .as_mut()
                .expect("pending request batch was just installed")
                .try_recv()
            {
                Ok(lines) => {
                    self.pending = None;
                    self.ready.extend(lines);
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {
                    return Err(mpsc::error::TryRecvError::Empty);
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                    self.pending = None;
                }
            }
        }
    }
}

impl Drop for DaemonRequestReceiver {
    fn drop(&mut self) {
        self.stopper.stop();
    }
}

/// The shared live-session cache for one daemon connection.
///
/// `live` mirrors the daemon's most recent `Sessions` event. `pending` holds RESERVATIONS: ids of
/// sessions this connection just created (a `start_session` line was successfully enqueued) that the
/// daemon has not NAMED in a `Sessions` event yet. A daemon `Sessions` event can be STALE relative to a
/// creation (snapshotted before the start line was processed) — if it simply replaced the cache, it would
/// evict the just-created id and the agent's own session_list/push would deny a session it just created
/// until the desktop's liveness repair ran ("content only flows after a local click"). So `Sessions`
/// events MERGE: they own `live` outright, but a pending reservation survives until the daemon names it
/// (at which point the id graduates to daemon-owned truth and normal add/remove semantics apply).
///
/// Content-blind: holds session IDS only, never terminal payload.
#[derive(Debug, Default)]
pub struct SessionCache {
    live: Vec<String>,
    /// Exact PTY lifetime UUIDs accepted from the current echoed Attach Grid, tied to that
    /// connection-local output generation. A Sessions inventory may revoke this proof but never
    /// grants attached mutation authority on its own.
    live_generations: std::collections::BTreeMap<String, AttachedPtyGeneration>,
    pending: std::collections::BTreeSet<String>,
    /// Protocol identity established on the operational daemon connection. `None`, an older
    /// version, and a newer version are all attach-only: only an exact current match authorizes
    /// `StartSession`. Keeping this beside the shared live-session state lets every synchronous
    /// mutation facade enforce the same fail-closed result before it writes durable topology.
    daemon_protocol_version: Option<u32>,
    generation_conditional_mutations: bool,
    attachment_aware_conditional_kill: bool,
    generation_conditional_start: bool,
    start_operation_ledger: bool,
    generation_conditional_attach: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AttachedPtyGeneration {
    output_generation: u64,
    pty_generation: String,
}

impl SessionCache {
    /// A cache whose daemon-confirmed set starts as `live` (the connect-time seed hint).
    pub fn seeded(live: Vec<String>) -> Self {
        SessionCache {
            live,
            live_generations: std::collections::BTreeMap::new(),
            pending: std::collections::BTreeSet::new(),
            daemon_protocol_version: None,
            generation_conditional_mutations: false,
            attachment_aware_conditional_kill: false,
            generation_conditional_start: false,
            start_operation_ledger: false,
            generation_conditional_attach: false,
        }
    }

    fn seeded_with_daemon_protocol(
        live: Vec<String>,
        daemon_protocol_version: Option<u32>,
        generation_conditional_mutations: bool,
        attachment_aware_conditional_kill: bool,
        generation_conditional_start: bool,
        start_operation_ledger: bool,
        generation_conditional_attach: bool,
    ) -> Self {
        SessionCache {
            live,
            live_generations: std::collections::BTreeMap::new(),
            pending: std::collections::BTreeSet::new(),
            daemon_protocol_version,
            generation_conditional_mutations,
            attachment_aware_conditional_kill,
            generation_conditional_start,
            start_operation_ledger,
            generation_conditional_attach,
        }
    }

    fn start_session_mutations_allowed(&self) -> bool {
        self.daemon_protocol_version == Some(maestro_protocol::DAEMON_PROTOCOL_VERSION)
            && self.generation_conditional_mutations
            && self.attachment_aware_conditional_kill
            && self.generation_conditional_start
            && self.start_operation_ledger
            && self.generation_conditional_attach
    }

    fn generation_conditional_mutations_allowed(&self) -> bool {
        self.daemon_protocol_version == Some(maestro_protocol::DAEMON_PROTOCOL_VERSION)
            && self.generation_conditional_mutations
            && self.attachment_aware_conditional_kill
    }

    fn generation_for_mutation(&self, session_id: &str, output_generation: u64) -> Option<String> {
        self.generation_conditional_mutations_allowed()
            .then(|| {
                self.live_generations
                    .get(session_id)
                    .filter(|proof| proof.output_generation == output_generation)
                    .map(|proof| proof.pty_generation.clone())
            })
            .flatten()
    }

    #[cfg(test)]
    fn mutation_ready_for_test() -> Self {
        Self::seeded_with_daemon_protocol(
            Vec::new(),
            Some(maestro_protocol::DAEMON_PROTOCOL_VERSION),
            true,
            true,
            true,
            true,
            true,
        )
    }

    /// The current live id set: daemon-confirmed ids plus surviving reservations (deduped, daemon order
    /// first). This is what `list_sessions`/collision checks must see.
    pub fn snapshot(&self) -> Vec<String> {
        let mut out = self.live.clone();
        for id in &self.pending {
            if !out.iter().any(|x| x == id) {
                out.push(id.clone());
            }
        }
        out
    }

    /// Reserve a just-created id (the daemon start line was successfully enqueued). The reservation
    /// survives stale `Sessions` events until the daemon names the id.
    pub fn reserve(&mut self, id: &str) {
        if !self.live.iter().any(|x| x == id) {
            self.pending.insert(id.to_string());
        }
    }

    /// Apply a daemon `Sessions` event: MERGE, don't replace. The event owns the daemon-confirmed set;
    /// any pending reservation the event NAMES graduates to daemon truth (dropped from `pending`), and
    /// unnamed reservations survive (the event may predate the create).
    pub fn apply_daemon_ids(&mut self, ids: Vec<String>) {
        self.apply_daemon_listing(ids, std::collections::BTreeMap::new());
    }

    fn apply_daemon_listing(
        &mut self,
        ids: Vec<String>,
        generations: std::collections::BTreeMap<String, String>,
    ) {
        self.pending.retain(|p| !ids.iter().any(|x| x == p));
        // A complete listing can revoke an accepted Attach proof (id disappeared or now names a
        // different PTY), but cannot create one: only the exact echoed Grid binds the PTY UUID to
        // this connection's current output route.
        self.live_generations.retain(|session_id, proof| {
            ids.iter().any(|id| id == session_id)
                && generations
                    .get(session_id)
                    .is_none_or(|generation| generation == &proof.pty_generation)
        });
        self.live = ids;
    }

    fn apply_grid_generation(
        &mut self,
        session_id: &str,
        output_generation: u64,
        generation: String,
    ) {
        // The caller only reaches this point for the exact Grid echoed by the current Attach route.
        // That is stronger lifetime proof than the connect-time Sessions snapshot: a desktop can
        // create and advertise a live session after this agent connection's one startup listing.
        // Admit that newly observed daemon lifetime here so its first accepted Grid immediately
        // unlocks generation-conditional input/resize. A later complete Sessions listing may still
        // revoke both the id and this proof.
        if !self.live.iter().any(|id| id == session_id) {
            self.live.push(session_id.to_string());
        }
        self.pending.remove(session_id);
        self.live_generations.insert(
            session_id.to_string(),
            AttachedPtyGeneration {
                output_generation,
                pty_generation: generation,
            },
        );
    }

    /// Remove ids we know are gone (e.g. a window close killed their sessions) from BOTH sets.
    pub fn remove(&mut self, ids: &[String]) {
        self.live.retain(|id| !ids.iter().any(|x| x == id));
        self.pending.retain(|id| !ids.iter().any(|x| x == id));
        self.live_generations
            .retain(|id, _| !ids.iter().any(|removed| removed == id));
    }
}

/// The `SessionCache` handle shared by the backend, the async daemon task, and every creator/closer.
type SharedSessions = std::sync::Arc<std::sync::Mutex<SessionCache>>;

fn start_session_mutations_allowed(sessions: &SharedSessions) -> bool {
    sessions
        .lock()
        .map(|sessions| sessions.start_session_mutations_allowed())
        .unwrap_or(false)
}

/// A daemon OUTPUT line addressed to a session (the raw daemon event JSON). The peer frames it.
pub struct DaemonOutput {
    pub session_id: String,
    pub line: String,
}

/// Bound daemon→peer output buffering per remote connection.
///
/// The item limit bounds fixed queue overhead and tiny-frame floods. The byte limit separately bounds the
/// terminal JSON owned by queued `String`s. A daemon line is capped at 16 MiB by the local protocol; 32 MiB
/// therefore admits one protocol-maximum line plus more than 16 MiB of ordinary output. In qualification an
/// 80×24 structured Grid is about 410 KiB, so the byte budget holds roughly 79 such snapshots without exposing
/// an unbounded per-peer allocation. On either limit we close this producer instead of skipping a strict-revision
/// Grid/Damage line and continuing with an irrecoverably broken stream.
pub const DAEMON_OUTPUT_QUEUE_CAP: usize = 256;
pub const DAEMON_OUTPUT_QUEUE_BYTE_CAP: usize = 32 * 1024 * 1024;
const _: () = assert!(DAEMON_OUTPUT_QUEUE_BYTE_CAP >= maestro_protocol::MAX_LINE_BYTES);
const _: () = assert!(DAEMON_OUTPUT_QUEUE_BYTE_CAP <= u32::MAX as usize);

struct QueuedDaemonOutput {
    output: DaemonOutput,
    attachment: DaemonOutputAttachment,
    reservation: DaemonOutputReservation,
}

/// Causal ownership of one daemon line. `Exact` is available only when the daemon advertised the
/// contract and either echoed an Attach Grid or tagged the live line itself. `Legacy` deliberately
/// preserves retained-daemon behavior; `Unconfirmed` strict-mode output is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DaemonOutputAttachment {
    Legacy,
    Unconfirmed,
    Exact(u64),
}

impl DaemonOutputAttachment {
    pub(crate) fn accepts(self, generation: u64) -> bool {
        match self {
            Self::Legacy => true,
            Self::Unconfirmed => false,
            Self::Exact(exact) => exact == generation,
        }
    }
}

struct DaemonOutputRoutes {
    output_generation_echo: bool,
    sessions: std::collections::HashMap<String, DaemonSessionOutputRoute>,
}

#[derive(Debug, Clone, Copy)]
enum DaemonSessionOutputRoute {
    Legacy,
    Pending(u64),
    Confirmed(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonMutationRoute {
    Pending(u64),
    Confirmed(u64),
    Unavailable,
}

impl DaemonOutputRoutes {
    fn new(output_generation_echo: bool) -> Self {
        Self {
            output_generation_echo,
            sessions: std::collections::HashMap::new(),
        }
    }

    fn begin_attach(
        &mut self,
        session_id: &str,
        output_generation: Option<u64>,
    ) -> Option<DaemonSessionOutputRoute> {
        if !self.output_generation_echo {
            return None;
        }
        let route = output_generation
            .map(DaemonSessionOutputRoute::Pending)
            .unwrap_or(DaemonSessionOutputRoute::Legacy);
        self.sessions.insert(session_id.to_string(), route)
    }

    fn restore_attach(&mut self, session_id: &str, prior: Option<DaemonSessionOutputRoute>) {
        if !self.output_generation_echo {
            return;
        }
        match prior {
            Some(prior) => {
                self.sessions.insert(session_id.to_string(), prior);
            }
            None => {
                self.sessions.remove(session_id);
            }
        }
    }

    fn detach(&mut self, session_id: &str) {
        self.sessions.remove(session_id);
    }

    fn mutation_route(&self, session_id: &str) -> DaemonMutationRoute {
        if !self.output_generation_echo {
            return DaemonMutationRoute::Unavailable;
        }
        match self.sessions.get(session_id) {
            Some(DaemonSessionOutputRoute::Pending(generation)) => {
                DaemonMutationRoute::Pending(*generation)
            }
            Some(DaemonSessionOutputRoute::Confirmed(generation)) => {
                DaemonMutationRoute::Confirmed(*generation)
            }
            Some(DaemonSessionOutputRoute::Legacy) | None => DaemonMutationRoute::Unavailable,
        }
    }

    fn observe(
        &mut self,
        session_id: &str,
        event: DaemonEventClass,
        output_generation: Option<u64>,
        live_output_generation: Option<u64>,
    ) -> DaemonOutputAttachment {
        if !self.output_generation_echo {
            return DaemonOutputAttachment::Legacy;
        }
        // A tagged live line owns itself and never changes the confirmed request/reply route. In particular,
        // an aborted old forwarder may finish one send after a new baseline without poisoning that baseline.
        if let Some(generation) = live_output_generation {
            return DaemonOutputAttachment::Exact(generation);
        }
        let mut rejected_echo = false;
        if let (DaemonEventClass::Grid, Some(echoed)) = (event, output_generation) {
            if let Some(route) = self.sessions.get_mut(session_id) {
                match *route {
                    DaemonSessionOutputRoute::Pending(desired) => {
                        if echoed == desired {
                            *route = DaemonSessionOutputRoute::Confirmed(desired);
                        }
                    }
                    DaemonSessionOutputRoute::Confirmed(desired) if echoed != desired => {
                        // Reject a delayed old baseline without revoking the already-proven current
                        // route. Subsequent current live lines remain admissible as generation `desired`.
                        rejected_echo = true;
                    }
                    DaemonSessionOutputRoute::Confirmed(_) | DaemonSessionOutputRoute::Legacy => {}
                }
            }
        }
        if rejected_echo {
            return DaemonOutputAttachment::Unconfirmed;
        }
        match self.sessions.get(session_id) {
            Some(DaemonSessionOutputRoute::Legacy) => DaemonOutputAttachment::Legacy,
            Some(DaemonSessionOutputRoute::Confirmed(generation)) => {
                DaemonOutputAttachment::Exact(*generation)
            }
            Some(DaemonSessionOutputRoute::Pending(_)) | None => {
                DaemonOutputAttachment::Unconfirmed
            }
        }
    }
}

/// The peer retains this opaque reservation while an event waits for codec/wire service. Sharing the original
/// queue permits keeps daemon ingress plus arbitration at one aggregate 256-item/32-MiB bound.
#[derive(Debug)]
pub(crate) struct DaemonOutputReservation {
    _item_permit: tokio::sync::OwnedSemaphorePermit,
    _byte_permit: tokio::sync::OwnedSemaphorePermit,
}

pub(crate) struct RoutedDaemonOutput {
    pub(crate) output: DaemonOutput,
    pub(crate) attachment: DaemonOutputAttachment,
    pub(crate) reservation: DaemonOutputReservation,
}

impl From<QueuedDaemonOutput> for RoutedDaemonOutput {
    fn from(queued: QueuedDaemonOutput) -> Self {
        Self {
            output: queued.output,
            attachment: queued.attachment,
            reservation: queued.reservation,
        }
    }
}

#[cfg(test)]
impl RoutedDaemonOutput {
    pub(crate) fn fixture(output: DaemonOutput, attachment: DaemonOutputAttachment) -> Self {
        let item_budget = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let byte_budget = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        Self {
            output,
            attachment,
            reservation: DaemonOutputReservation {
                _item_permit: item_budget
                    .try_acquire_owned()
                    .expect("fixture item permit"),
                _byte_permit: byte_budget
                    .try_acquire_owned()
                    .expect("fixture byte permit"),
            },
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DaemonOutputEnqueueError {
    ItemLimit,
    ByteLimit,
    ReceiverClosed,
    ProducerStopped,
}

impl DaemonOutputEnqueueError {
    fn reason(self) -> &'static str {
        match self {
            Self::ItemLimit => "item_limit",
            Self::ByteLimit => "byte_limit",
            Self::ReceiverClosed => "receiver_closed",
            Self::ProducerStopped => "producer_stopped",
        }
    }
}

/// Single-owner producer for the daemon-output queue. Any overflow is terminal: taking `tx` closes the producer
/// side immediately, so the consumer drains the already-valid prefix and then observes `None`. This is deliberate
/// fail-stop behavior for revisioned terminal frames; silently omitting one line and continuing is never safe.
struct DaemonOutputSender {
    tx: Option<mpsc::Sender<QueuedDaemonOutput>>,
    item_budget: std::sync::Arc<tokio::sync::Semaphore>,
    byte_budget: std::sync::Arc<tokio::sync::Semaphore>,
    byte_capacity: usize,
    routes: std::sync::Arc<std::sync::Mutex<DaemonOutputRoutes>>,
}

impl DaemonOutputSender {
    /// Observe every session-bearing daemon line, including a structured Grid that raw mode will
    /// intentionally filter. An echoed Attach baseline changes ownership at this exact FIFO point.
    #[cfg(test)]
    fn observe_route(
        &self,
        session_id: &str,
        event: DaemonEventClass,
        output_generation: Option<u64>,
        live_output_generation: Option<u64>,
    ) -> DaemonOutputAttachment {
        self.routes
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .observe(session_id, event, output_generation, live_output_generation)
    }

    fn try_enqueue_routed(
        &mut self,
        output: DaemonOutput,
        attachment: DaemonOutputAttachment,
    ) -> Result<(), DaemonOutputEnqueueError> {
        if self.tx.is_none() {
            return Err(DaemonOutputEnqueueError::ProducerStopped);
        }

        let item_permit = match self.item_budget.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.tx.take();
                return Err(DaemonOutputEnqueueError::ItemLimit);
            }
        };

        // Account the terminal/session bytes actually owned by the queued item. Fixed String/item overhead is
        // bounded independently by DAEMON_OUTPUT_QUEUE_CAP.
        let byte_cost = output
            .line
            .capacity()
            .saturating_add(output.session_id.capacity())
            .max(1);
        if byte_cost > self.byte_capacity || byte_cost > u32::MAX as usize {
            self.tx.take();
            return Err(DaemonOutputEnqueueError::ByteLimit);
        }
        let permit = match self
            .byte_budget
            .clone()
            .try_acquire_many_owned(byte_cost as u32)
        {
            Ok(permit) => permit,
            Err(_) => {
                self.tx.take();
                return Err(DaemonOutputEnqueueError::ByteLimit);
            }
        };
        let queued = QueuedDaemonOutput {
            output,
            attachment,
            reservation: DaemonOutputReservation {
                _item_permit: item_permit,
                _byte_permit: permit,
            },
        };

        let send_result = self
            .tx
            .as_ref()
            .expect("producer presence checked above")
            .try_send(queued);
        match send_result {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_queued)) => {
                // `_queued` drops here and returns its byte permit before the producer is stopped.
                self.tx.take();
                Err(DaemonOutputEnqueueError::ItemLimit)
            }
            Err(mpsc::error::TrySendError::Closed(_queued)) => {
                self.tx.take();
                Err(DaemonOutputEnqueueError::ReceiverClosed)
            }
        }
    }

    #[cfg(test)]
    fn try_enqueue(&mut self, output: DaemonOutput) -> Result<(), DaemonOutputEnqueueError> {
        let route = self.observe_route(&output.session_id, DaemonEventClass::Other, None, None);
        self.try_enqueue_routed(output, route)
    }

    #[cfg(test)]
    fn available_bytes(&self) -> usize {
        self.byte_budget.available_permits()
    }

    #[cfg(test)]
    fn available_items(&self) -> usize {
        self.item_budget.available_permits()
    }
}

/// Receiver facade keeps queue permits opaque. Plain consumers release them on receive; the peer's routed receive
/// transfers them into its arbiter so daemon ingress plus wire waiting remain one aggregate reservation. Dropping
/// this receiver releases every permit still held by queued items.
pub struct DaemonOutputReceiver {
    rx: mpsc::Receiver<QueuedDaemonOutput>,
    request_failure: Option<tokio::sync::watch::Receiver<bool>>,
}

impl DaemonOutputReceiver {
    pub async fn recv(&mut self) -> Option<DaemonOutput> {
        let Some(failure) = self.request_failure.as_mut() else {
            return self.rx.recv().await.map(|queued| queued.output);
        };
        if *failure.borrow() {
            return None;
        }
        tokio::select! {
            biased;
            changed = failure.changed() => {
                let _ = changed;
                None
            }
            queued = self.rx.recv() => queued.map(|queued| queued.output),
        }
    }

    pub(crate) async fn recv_routed(&mut self) -> Option<RoutedDaemonOutput> {
        let Some(failure) = self.request_failure.as_mut() else {
            return self.rx.recv().await.map(Into::into);
        };
        if *failure.borrow() {
            return None;
        }
        tokio::select! {
            biased;
            changed = failure.changed() => {
                let _ = changed;
                None
            }
            queued = self.rx.recv() => queued.map(Into::into),
        }
    }

    /// Drain at a peer wire-chunk boundary without releasing the shared item/byte reservation. Request-path
    /// failure remains fail-stop and is reported as a disconnected producer.
    pub(crate) fn try_recv_routed(
        &mut self,
    ) -> Result<RoutedDaemonOutput, mpsc::error::TryRecvError> {
        if self
            .request_failure
            .as_ref()
            .is_some_and(|failure| *failure.borrow())
        {
            return Err(mpsc::error::TryRecvError::Disconnected);
        }
        self.rx.try_recv().map(Into::into)
    }
}

#[cfg(test)]
fn daemon_output_channel(
    item_capacity: usize,
    byte_capacity: usize,
) -> (DaemonOutputSender, DaemonOutputReceiver) {
    daemon_output_channel_with_request_failure(item_capacity, byte_capacity, None)
}

#[cfg(test)]
fn daemon_output_channel_with_request_failure(
    item_capacity: usize,
    byte_capacity: usize,
    request_failure: Option<tokio::sync::watch::Receiver<bool>>,
) -> (DaemonOutputSender, DaemonOutputReceiver) {
    daemon_output_channel_with_routes(
        item_capacity,
        byte_capacity,
        request_failure,
        std::sync::Arc::new(std::sync::Mutex::new(DaemonOutputRoutes::new(false))),
    )
}

fn daemon_output_channel_with_routes(
    item_capacity: usize,
    byte_capacity: usize,
    request_failure: Option<tokio::sync::watch::Receiver<bool>>,
    routes: std::sync::Arc<std::sync::Mutex<DaemonOutputRoutes>>,
) -> (DaemonOutputSender, DaemonOutputReceiver) {
    let (tx, rx) = mpsc::channel(item_capacity);
    let item_budget = std::sync::Arc::new(tokio::sync::Semaphore::new(item_capacity));
    let byte_budget = std::sync::Arc::new(tokio::sync::Semaphore::new(byte_capacity));
    (
        DaemonOutputSender {
            tx: Some(tx),
            item_budget,
            byte_budget,
            byte_capacity,
            routes,
        },
        DaemonOutputReceiver {
            rx,
            request_failure,
        },
    )
}

/// The sync handle the `TerminalBridge` calls. Each call enqueues a `ClientRequest` line; the async task
/// (run by `spawn_daemon_task`) owns the socket. `list_sessions` returns the last-known live id set, kept
/// in sync by the async task as it sees `Sessions` events (seeded at construction).
pub struct DaemonBackend {
    tx: DaemonRequestSender,
    sessions: SharedSessions,
    session_metadata: std::sync::Arc<std::sync::Mutex<Vec<SessionMetadata>>>,
    dashboard_paths: Option<maestro_shell::AppPaths>,
    /// Renderer mode for the current attach: true ⇒ raw PTY bytes (xterm.js), false ⇒ structured
    /// Grid/Damage (canvas). Set by `attach` from the client's per-attach `raw` flag; read by the reader
    /// task to drop structured frames in raw mode. Shared so both sides see the latest mode.
    raw_output: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Capability-gated per-session Attach boundary state shared with the daemon event reader. Local request
    /// admission may make a route pending, but only the daemon's echoed restore Grid can confirm it.
    output_routes: std::sync::Arc<std::sync::Mutex<DaemonOutputRoutes>>,
    /// Latest requested geometry held until the exact echoed Attach Grid proves both the
    /// connection-local output route and the PTY generation UUID. This prevents remote Attach from
    /// sending an id-only pre-size into a same-id replacement.
    pending_attach_sizes:
        std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, PendingAttachSize>>>,
}

#[derive(Clone, Debug)]
struct PendingAttachSize {
    output_generation: u64,
    cols: u16,
    rows: u16,
    authority: crate::winsize_owner::DeferredResizeAuthority,
}

/// Linearize one daemon route observation with the PTY-generation proof and deferred first
/// resize it may authorize. The lock order is shared with local input/resize admission:
/// routes -> sessions -> pending size -> request queue. Keeping the route lock through the cache
/// update means no input can observe Confirmed(B) with the previous PTY generation A.
fn observe_route_and_apply_grid<F>(
    routes: &std::sync::Mutex<DaemonOutputRoutes>,
    sessions: &SharedSessions,
    pending_attach_sizes: &std::sync::Mutex<std::collections::BTreeMap<String, PendingAttachSize>>,
    request_tx: &DaemonRequestSender,
    session_id: &str,
    event: DaemonEventClass,
    output_generation: Option<u64>,
    live_output_generation: Option<u64>,
    pty_generation: Option<String>,
    after_route_transition: F,
) -> DaemonOutputAttachment
where
    F: FnOnce(),
{
    let mut routes = routes.lock().unwrap_or_else(|error| error.into_inner());
    let attachment = routes.observe(session_id, event, output_generation, live_output_generation);
    after_route_transition();

    let (
        DaemonEventClass::Grid,
        DaemonOutputAttachment::Exact(output_generation),
        Some(pty_generation),
    ) = (event, attachment, pty_generation)
    else {
        return attachment;
    };
    if routes.mutation_route(session_id) != DaemonMutationRoute::Confirmed(output_generation) {
        // A tagged late Grid owns generation A for output filtering, but it is not the current
        // Attach route B and therefore carries no mutation/cache authority.
        return attachment;
    }

    let mut sessions = sessions.lock().unwrap_or_else(|error| error.into_inner());
    sessions.apply_grid_generation(session_id, output_generation, pty_generation.clone());
    let pending = {
        let mut pending_sizes = pending_attach_sizes
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        pending_sizes
            .get(session_id)
            .is_some_and(|size| size.output_generation == output_generation)
            .then(|| pending_sizes.remove(session_id))
            .flatten()
    };
    if let Some(size) = pending {
        let request = maestro_protocol::ClientRequest::Resize {
            id: maestro_protocol::SessionId(session_id.to_string()),
            expected_generation: pty_generation,
            cols: size.cols,
            rows: size.rows,
        };
        let Ok(line) = serde_json::to_string(&request) else {
            size.authority.cancel();
            tracing::warn!("post-attach conditional resize could not be encoded");
            return attachment;
        };
        let queue_failed = std::cell::Cell::new(false);
        let published = size.authority.publish_resize_if_current(|| {
            let queued = request_tx.send(line).is_ok();
            queue_failed.set(!queued);
            queued
        });
        if !published && queue_failed.get() {
            tracing::warn!("post-attach conditional resize could not be queued");
        }
    }
    attachment
}

impl DaemonBackend {
    /// Install the live control connection's bounded creation-size publisher before any creation adapters are
    /// cloned from this backend. Local desktop daemon clients never call this and retain their existing behavior.
    pub(crate) fn set_remote_creation_lease_publisher(
        &self,
        publisher: crate::winsize_owner::RemoteCreationLeasePublisher,
    ) {
        self.tx.set_creation_lease_publisher(publisher);
    }

    fn send(&self, line: String) -> Result<(), String> {
        self.tx
            .send(line)
            .map_err(|_| "daemon connection unavailable".to_string())
    }

    fn send_attach(
        &self,
        id: &str,
        raw: bool,
        output_generation: Option<u64>,
        initial_size: Option<(u16, u16, crate::winsize_owner::DeferredResizeAuthority)>,
    ) -> Result<(), String> {
        self.raw_output
            .store(raw, std::sync::atomic::Ordering::Relaxed);
        let request = serde_json::to_string(&maestro_protocol::ClientRequest::Attach {
            id: maestro_protocol::SessionId(id.to_string()),
            want_raw_output: raw,
            expected_session_generation: None,
            output_generation,
            handoff: None,
        })
        .map_err(|_| "daemon request encoding failed".to_string())?;
        let mut routes = self
            .output_routes
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let prior = routes.begin_attach(id, output_generation);
        let authority_to_cancel = initial_size
            .as_ref()
            .map(|(_, _, authority)| authority.clone());
        let prior_size = {
            let mut pending = self
                .pending_attach_sizes
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            match output_generation.zip(initial_size) {
                Some((generation, (cols, rows, authority))) => pending.insert(
                    id.to_string(),
                    PendingAttachSize {
                        output_generation: generation,
                        cols,
                        rows,
                        authority,
                    },
                ),
                None => pending.remove(id),
            }
        };
        if self.tx.send(request).is_err() {
            routes.restore_attach(id, prior);
            if let Some(authority) = authority_to_cancel {
                authority.cancel();
            }
            let mut pending = self
                .pending_attach_sizes
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            match prior_size {
                Some(prior) => {
                    pending.insert(id.to_string(), prior);
                }
                None => {
                    pending.remove(id);
                }
            }
            return Err("daemon connection unavailable".to_string());
        }
        if let Some(prior) = prior_size {
            prior.authority.cancel();
        }
        Ok(())
    }

    /// Test-only seam for the held record-less creator implementation. Production deliberately has no
    /// constructor or control-channel injection for this path until ambiguous pre-Grid starts have a
    /// durable exact-daemon/token owner. `home` is the fixed default cwd used by the focused tests.
    #[cfg(test)]
    pub fn session_creator(&self, home: String) -> DaemonSessionCreator {
        DaemonSessionCreator {
            tx: self.tx.clone(),
            sessions: self.sessions.clone(),
            home,
        }
    }

    /// Build a desktop-backed splitter sharing this backend's daemon sender + dashboard store paths.
    /// Returns None when dashboard paths are unavailable, so the control channel can refuse honestly.
    pub fn pane_splitter(&self) -> Option<DaemonPaneSplitter> {
        Some(DaemonPaneSplitter {
            tx: self.tx.clone(),
            sessions: self.sessions.clone(),
            paths: self.dashboard_paths.clone()?,
        })
    }

    /// Build a desktop-backed pane reviver sharing this backend's daemon sender + dashboard store paths.
    pub fn pane_reviver(&self) -> Option<DaemonPaneReviver> {
        Some(DaemonPaneReviver {
            tx: self.tx.clone(),
            sessions: self.sessions.clone(),
            paths: self.dashboard_paths.clone()?,
        })
    }

    /// Build a virtual-viewport starter: it starts a pane's durable session without mutating desktop layout.
    pub fn pane_session_starter(&self) -> Option<DaemonPaneSessionStarter> {
        Some(DaemonPaneSessionStarter {
            tx: self.tx.clone(),
            sessions: self.sessions.clone(),
            paths: self.dashboard_paths.clone()?,
        })
    }

    /// Build a desktop-backed pane stasher sharing this backend's dashboard store paths.
    pub fn pane_stasher(&self) -> Option<DaemonPaneStasher> {
        Some(DaemonPaneStasher {
            paths: self.dashboard_paths.clone()?,
        })
    }

    /// Build a desktop-backed pane remover ("Remove from shelf") sharing this backend's dashboard store paths.
    pub fn pane_remover(&self) -> Option<DaemonPaneRemover> {
        Some(DaemonPaneRemover {
            paths: self.dashboard_paths.clone()?,
        })
    }

    /// Build a desktop-backed renamer sharing this backend's dashboard store paths.
    pub fn renamer(&self) -> Option<DaemonRenamer> {
        Some(DaemonRenamer {
            paths: self.dashboard_paths.clone()?,
        })
    }

    /// Build a desktop-backed window closer sharing this backend's daemon sender + dashboard store paths.
    pub fn window_closer(&self) -> Option<DaemonWindowCloser> {
        Some(DaemonWindowCloser {
            tx: self.tx.clone(),
            sessions: self.sessions.clone(),
            paths: self.dashboard_paths.clone()?,
        })
    }

    /// Build a desktop-backed window focuser sharing this backend's dashboard store paths. The focus itself is a
    /// LIVE runtime switch owned by the foreground maestro-app process, so this can't flip it directly; it writes
    /// a one-shot focus-request signal that the running app consumes on its idle tick and applies via the same
    /// `focus_recorded_window_pane` path its own UI uses. See maestro-shell::write_focus_window_request.
    pub fn window_focuser(&self) -> Option<DaemonWindowFocuser> {
        Some(DaemonWindowFocuser {
            paths: self.dashboard_paths.clone()?,
        })
    }

    /// Build a desktop-backed window opener sharing this backend's daemon sender + dashboard store paths.
    pub fn window_opener(&self) -> Option<DaemonWindowOpener> {
        Some(DaemonWindowOpener {
            tx: self.tx.clone(),
            sessions: self.sessions.clone(),
            paths: self.dashboard_paths.clone()?,
        })
    }

    /// Build a desktop-backed project editor sharing this backend's dashboard store paths.
    pub fn project_editor(&self) -> Option<DaemonProjectEditor> {
        Some(DaemonProjectEditor {
            tx: self.tx.clone(),
            sessions: self.sessions.clone(),
            paths: self.dashboard_paths.clone()?,
        })
    }

    /// Build a desktop-backed prior-session previewer sharing this backend's dashboard store paths.
    /// This is the explicit content-preview path for the SessionPicker; all non-preview listing stays metadata-only.
    pub fn session_previewer(&self) -> Option<DaemonSessionPreviewer> {
        Some(DaemonSessionPreviewer {
            paths: self.dashboard_paths.clone()?,
        })
    }

    /// Build a desktop-backed prior-session manager sharing this backend's dashboard store paths.
    /// This is content-blind: rename/hide/delete use only agent, session id, cwd, and label.
    pub fn session_manager(&self) -> Option<DaemonSessionManager> {
        Some(DaemonSessionManager {
            paths: self.dashboard_paths.clone()?,
        })
    }
}

/// Desktop-backed SessionPicker preview implementation. It delegates to the same agent_history reader the local
/// dashboard uses, returning only the bounded role/text lines requested by the authenticated browser.
pub struct DaemonSessionPreviewer {
    paths: maestro_shell::AppPaths,
}

impl crate::remote_control::SessionPreviewer for DaemonSessionPreviewer {
    fn preview(
        &mut self,
        request: crate::remote_control::SessionPreviewRequest,
    ) -> Vec<crate::remote_control::PreviewLine> {
        let cwd = request
            .cwd
            .map(PathBuf::from)
            .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from("/")));
        maestro_local_services::agent_history::preview_folder_session(
            &self.paths,
            &request.agent,
            &cwd,
            &request.session_id,
            request.max_lines,
        )
        .into_iter()
        .map(|line| crate::remote_control::PreviewLine {
            role: line.role,
            text: line.text,
        })
        .collect()
    }
}

/// Desktop-backed SessionPicker rename/hide/delete implementation. It delegates to the same agent_history
/// sidecar/file operations the local dashboard uses; no transcript text crosses this path.
pub struct DaemonSessionManager {
    paths: maestro_shell::AppPaths,
}

impl crate::remote_control::SessionManager for DaemonSessionManager {
    fn manage(
        &mut self,
        request: crate::remote_control::SessionManageRequest,
    ) -> Result<(), crate::remote_control::SessionManageError> {
        let result = match request.action {
            crate::remote_control::SessionManageAction::Rename { name } => {
                maestro_local_services::agent_history::set_folder_session_name(
                    &self.paths,
                    &request.agent,
                    &request.session_id,
                    name.as_deref(),
                )
            }
            crate::remote_control::SessionManageAction::Hide => {
                maestro_local_services::agent_history::hide_folder_session(
                    &self.paths,
                    &request.agent,
                    &request.session_id,
                )
            }
            crate::remote_control::SessionManageAction::Unhide { cwd: _ } => {
                // Bring a ⊘-removed session back to the visible list (desktop unhide_folder_session).
                maestro_local_services::agent_history::unhide_folder_session(
                    &self.paths,
                    &request.agent,
                    &request.session_id,
                )
            }
            crate::remote_control::SessionManageAction::Delete { cwd } => {
                let cwd = cwd
                    .map(PathBuf::from)
                    .unwrap_or_else(|| dirs::home_dir().unwrap_or_else(|| PathBuf::from("/")));
                maestro_local_services::agent_history::delete_folder_session(
                    &self.paths,
                    &request.agent,
                    &cwd,
                    &request.session_id,
                )
            }
        };
        result.map_err(map_session_manage_error)
    }
}

fn map_session_manage_error(message: String) -> crate::remote_control::SessionManageError {
    if message.to_ascii_lowercase().contains("not found") {
        crate::remote_control::SessionManageError::NotFound
    } else {
        crate::remote_control::SessionManageError::Internal
    }
}

/// A `SessionCreator` backed by the exact reviewed daemon authority. The shared sender supplies immutable
/// socket/PID and launch policy, while a short-lived synchronous client performs ledger reservation, conditional
/// Start, exact Attach/Grid proof, and retirement. The shared live set remains the collision oracle.
pub struct DaemonSessionCreator {
    tx: DaemonRequestSender,
    sessions: SharedSessions,
    home: String,
}

impl crate::session_creator::SessionCreator for DaemonSessionCreator {
    fn known_sessions(&self) -> Vec<String> {
        self.sessions
            .lock()
            .map(|s| s.snapshot())
            .unwrap_or_default()
    }
    fn start_session(
        &mut self,
        session_id: &str,
        home: &str,
    ) -> Result<(), crate::session_creator::CreateSessionError> {
        self.start_session_conditionally(session_id, home, None, InitialTerminalSize::default())
    }
    fn start_session_with_launch(
        &mut self,
        session_id: &str,
        home: &str,
        launch: Option<&crate::resume_launch::ResumeLaunch>,
    ) -> Result<(), crate::session_creator::CreateSessionError> {
        self.start_session_conditionally(session_id, home, launch, InitialTerminalSize::default())
    }
    fn start_session_with_launch_and_size(
        &mut self,
        session_id: &str,
        home: &str,
        launch: Option<&crate::resume_launch::ResumeLaunch>,
        initial_size: crate::session_creator::InitialTerminalSize,
    ) -> Result<(), crate::session_creator::CreateSessionError> {
        self.start_session_conditionally(session_id, home, launch, initial_size)
    }
    fn home(&self) -> String {
        self.home.clone()
    }
    fn default_cwd(&self) -> Result<String, crate::session_creator::CreateSessionError> {
        self.default_cwd_with(crate::agent_dir::trusted_session_account)
    }
}

impl DaemonSessionCreator {
    fn start_session_conditionally(
        &mut self,
        session_id: &str,
        cwd: &str,
        launch: Option<&crate::resume_launch::ResumeLaunch>,
        initial_size: InitialTerminalSize,
    ) -> Result<(), crate::session_creator::CreateSessionError> {
        if !start_session_mutations_allowed(&self.sessions) {
            return Err(crate::session_creator::CreateSessionError::DaemonUnavailable);
        }
        let creation_lease = self
            .tx
            .begin_remote_creation_lease(session_id, unix_now_ms())
            .map_err(|_| crate::session_creator::CreateSessionError::DaemonUnavailable)?;
        start_remote_session_with_grid(
            &self.tx,
            session_id,
            cwd,
            launch,
            initial_size,
            maestro_protocol::SessionStartPrecondition::Absent {
                excluded_generation: None,
            },
        )
        .map_err(|_| crate::session_creator::CreateSessionError::DaemonUnavailable)?;
        if let Ok(mut sessions) = self.sessions.lock() {
            // Reservation is published only after exact Grid, never after queue admission or ACK.
            sessions.reserve(session_id);
        }
        creation_lease.commit();
        Ok(())
    }

    fn default_cwd_with(
        &self,
        resolver: impl FnOnce() -> std::io::Result<crate::agent_dir::TrustedSessionAccount>,
    ) -> Result<String, crate::session_creator::CreateSessionError> {
        if !self.tx.headless_server() {
            return Ok(self.home.clone());
        }
        resolver()
            .and_then(|account| {
                account.home.to_str().map(str::to_owned).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "effective account home is not UTF-8",
                    )
                })
            })
            .map_err(|_| crate::session_creator::CreateSessionError::DaemonUnavailable)
    }
}

fn mutation_protocol_for_policy(
    observed: Option<u32>,
    headless_server: bool,
    child_environment: bool,
) -> Option<u32> {
    (observed == Some(maestro_protocol::DAEMON_PROTOCOL_VERSION)
        && (!headless_server || child_environment))
        .then_some(maestro_protocol::DAEMON_PROTOCOL_VERSION)
}

/// A real remote split implementation: validate the desktop window layout, copy the source pane's durable
/// session context, persist a new session record + split tab, then ask the daemon to start the new session.
pub struct DaemonPaneSplitter {
    tx: DaemonRequestSender,
    sessions: SharedSessions,
    paths: maestro_shell::AppPaths,
}

#[cfg(test)]
#[allow(dead_code)] // Reserved for targeted rollback fault-injection coverage.
fn cleanup_created_pane_session(
    tx: &DaemonRequestSender,
    paths: &maestro_shell::AppPaths,
    expected_without_tab: &maestro_shell::WindowLayoutSnapshot,
    tab_id: &str,
    session: &maestro_shell::SessionRecord,
    now_ms: u64,
    context: &str,
) {
    // A NULL-generation row does not identify any daemon lifetime. Prove the id absent before
    // deleting it; observing an existing generation retains the row rather than laundering that
    // unrelated PTY into a release target.
    let mut client = match connect_reviewed_daemon_client(tx) {
        Ok(client) => client,
        Err(error) => {
            eprintln!(
                "{context}: conditional session cleanup retained session={} because daemon absence was unproved: {error}",
                session.session_id
            );
            return;
        }
    };
    let resolutions = match maestro_shell::pre_resolve_session_generations(
        &mut client,
        [session.session_id.as_str()],
    ) {
        Ok(resolutions) => resolutions,
        Err(error) => {
            eprintln!(
                "{context}: conditional session cleanup retained session={} because daemon absence was unproved: {error}",
                session.session_id
            );
            return;
        }
    };
    if !matches!(
        resolutions.get(&session.session_id),
        Some(maestro_shell::PreResolvedSessionState::ConfirmedAbsent)
    ) {
        eprintln!(
            "{context}: conditional session cleanup retained session={} because a daemon generation exists",
            session.session_id
        );
        return;
    }
    let cleanup = maestro_shell::WindowLayoutService::new(paths)
        .delete_created_session_if_unreferenced_with_resolutions(
            expected_without_tab,
            tab_id,
            session,
            &resolutions,
            now_ms,
        );
    if !matches!(
        cleanup,
        Ok(maestro_shell::ConditionalCreatedSessionDelete::Deleted {
            release_receipt: None,
            ref unresolved_release_session_ids,
        }) if unresolved_release_session_ids.is_empty()
    ) {
        eprintln!(
            "{context}: conditional session cleanup retained session={} outcome={cleanup:?}",
            session.session_id
        );
    }
}

#[cfg(test)]
#[allow(dead_code)] // Reserved for targeted rollback fault-injection coverage.
fn rollback_created_pane_and_session(
    tx: &DaemonRequestSender,
    paths: &maestro_shell::AppPaths,
    created_layout: &maestro_shell::WindowLayoutSnapshot,
    tab_id: &str,
    session: &maestro_shell::SessionRecord,
    now_ms: u64,
    context: &str,
) {
    let layouts = maestro_shell::WindowLayoutService::new(paths);
    match layouts.close_created_tab_if_unchanged(
        created_layout,
        tab_id,
        &session.session_id,
        now_ms,
    ) {
        Ok(closed_layout) => cleanup_created_pane_session(
            tx,
            paths,
            &closed_layout,
            tab_id,
            session,
            now_ms,
            context,
        ),
        Err(error) => eprintln!(
            "{context}: conditional tab rollback retained session={} tab={tab_id}: {error}",
            session.session_id
        ),
    }
}

impl crate::remote_control::PaneSplitter for DaemonPaneSplitter {
    fn split_pane(
        &mut self,
        request: crate::remote_control::SplitPaneRequest,
    ) -> Result<crate::remote_control::SplitPaneCreated, crate::remote_control::SplitPaneCreateError>
    {
        self.split_pane_with_initial_size(request, InitialTerminalSize::default())
    }

    fn split_pane_with_initial_size(
        &mut self,
        request: crate::remote_control::SplitPaneRequest,
        initial_size: InitialTerminalSize,
    ) -> Result<crate::remote_control::SplitPaneCreated, crate::remote_control::SplitPaneCreateError>
    {
        // This operation always creates and starts a fresh PTY. Refuse before the first durable
        // SessionRecord/layout write when the operational daemon did not prove the exact current
        // protocol. A v1 StartSession can reap unrelated retained exit snapshots as a side effect.
        if !start_session_mutations_allowed(&self.sessions) {
            return Err(crate::remote_control::SplitPaneCreateError::DaemonUnavailable);
        }
        let initial_layout = maestro_shell::WindowLayoutService::new(&self.paths)
            .load_snapshot(&request.window_id)
            .map_err(|_| crate::remote_control::SplitPaneCreateError::Internal)?
            .ok_or(crate::remote_control::SplitPaneCreateError::WindowNotFound)?;
        let layout = &initial_layout.layout;
        let live_tabs: Vec<_> = layout.tabs.iter().filter(|tab| !tab.stashed).collect();
        if live_tabs.len() >= 4 {
            return Err(crate::remote_control::SplitPaneCreateError::PaneLimit);
        }
        let source_session_id = live_tabs
            .iter()
            .find(|tab| tab.tab_id == request.from_pane_id)
            .map(|tab| tab.session_id.clone())
            .ok_or(crate::remote_control::SplitPaneCreateError::PaneNotFound)?;
        let source_session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &self.paths,
            maestro_shell::RecordKind::Session,
            &source_session_id,
        ) {
            Ok(Some(maestro_shell::LoadOutcome::Loaded(session))) => session,
            Ok(Some(_)) | Ok(None) | Err(_) => {
                return Err(crate::remote_control::SplitPaneCreateError::Internal);
            }
        };
        let workspace = match maestro_shell::load_one::<maestro_shell::Workspace>(
            &self.paths,
            maestro_shell::RecordKind::Workspace,
            &source_session.workspace_id,
        ) {
            Ok(Some(maestro_shell::LoadOutcome::Loaded(workspace))) => workspace,
            _ => return Err(crate::remote_control::SplitPaneCreateError::Internal),
        };
        let project_id = initial_layout
            .project_id
            .as_deref()
            .ok_or(crate::remote_control::SplitPaneCreateError::Internal)?;
        let project = maestro_shell::ProjectService::new(&self.paths)
            .load(project_id)
            .map_err(|_| crate::remote_control::SplitPaneCreateError::Internal)?
            .ok_or(crate::remote_control::SplitPaneCreateError::Internal)?;
        if workspace.project_id != project.project_id {
            return Err(crate::remote_control::SplitPaneCreateError::Internal);
        }

        let tab_id = pick_remote_tab_id(layout);
        let now = request.now_ms;
        // Desktop-parity: a split can RESUME a prior agent session (screens/local/splitright.jpg), not only start
        // fresh. The browser sends the same structured {agent, launch_flags:{resumeMode,resumeSessionId}} the
        // create-session path uses, so build the resume launch the SAME content-blind way (Gemini file resolved
        // desktop-side; agent allowlisted). If a resume launch is built, the pane starts as that resumed agent;
        // otherwise it stays a fresh agent (or inherits the sibling), exactly as before.
        // The new pane's working directory: an explicit request.cwd (picked in the split dialog) wins;
        // absent → inherit the source pane's cwd, the local-desktop split contract.
        let pane_cwd = request
            .cwd
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .unwrap_or(source_session.cwd_resolved.as_str())
            .to_string();
        let mut resume_launch = crate::remote_control::resume_descriptor_from_launch_flags(
            request.agent.clone(),
            request.launch_flags.clone(),
        )
        .and_then(|mut descriptor| {
            crate::remote_control::resolve_gemini_resume_file(
                &mut descriptor,
                Some(pane_cwd.as_str()),
            );
            crate::resume_launch::build_resume_launch(&descriptor)
        });
        // Content-blind model NAME from the split dialog (validated in model_from_launch_flags): appended
        // to the launch argv as the discrete pair ["--model", <name>] — on a resume launch here; on a
        // fresh explicit-agent launch below. Never shell-interpolated, never applied to a terminal pane.
        let model = crate::remote_control::model_from_launch_flags(&request.launch_flags);
        let dangerous = crate::remote_control::dangerous_from_launch_flags(&request.launch_flags);
        if let (Some(resume), Some(model), Some(agent)) = (
            resume_launch.as_mut(),
            model.as_deref(),
            request.agent.as_deref(),
        ) {
            append_remote_model(resume, agent, model);
        }
        if let (Some(resume), Some(agent)) = (resume_launch.as_mut(), request.agent.as_deref()) {
            append_remote_dangerous_flag(resume, agent, dangerous);
        }
        // "terminal" is a first-class choice for a plain-bash pane: recorded as Shell + OptOut, never an Agent that
        // would try to exec "terminal" on reattach (records are daemon-persistent).
        let is_terminal = request
            .agent
            .as_deref()
            .map(str::trim)
            .is_some_and(|a| a.eq_ignore_ascii_case("terminal"));
        // A FRESH explicit-agent split must actually LAUNCH that agent (record/launch parity): the record
        // below says KnownSafe{agent, ...}, so the PTY must run `<agent> [--model <name>]`, not a bare
        // shell. (Previously only the with-model case launched; a fresh agent WITHOUT a model recorded
        // "claude" while the daemon started plain bash — the "remote split creates an empty bash terminal"
        // bug.) The agent is already allowlisted upstream (sanitize_split_agent or
        // "terminal", which is excluded here) and the argv is discrete, never shell-interpolated.
        let fresh_launch = match (&resume_launch, is_terminal, request.agent.as_ref()) {
            (None, false, Some(agent)) => {
                fresh_remote_agent_launch(agent, model.as_deref(), dangerous)
            }
            _ => None,
        };
        // The launch the daemon start line uses (resume wins; else fresh explicit agent). An
        // inherit-from-sibling split derives a new provider identity below; it must never copy the
        // source pane's exact resume selector or mutable latest selector.
        let start_launch = resume_launch.or(fresh_launch);
        let kind = if is_terminal {
            maestro_shell::SessionKind::Shell
        } else if request.agent.is_some() {
            maestro_shell::SessionKind::Agent
        } else {
            source_session.kind
        };
        // The split dialog's pane name wins as the tab title; else the pre-existing agent derivation.
        let title = request.pane_name.clone().unwrap_or_else(|| {
            request
                .agent
                .as_deref()
                .map(agent_title)
                .unwrap_or("Pane")
                .to_string()
        });
        let axis = match request.dir {
            crate::remote_control::SplitPaneDir::Right => maestro_shell::SplitAxis::Right,
            crate::remote_control::SplitPaneDir::Down => maestro_shell::SplitAxis::Down,
        };
        let launch = if is_terminal {
            crate::session_creator::empty_session_launch(self.tx.headless_server())
        } else if let Some(launch) = start_launch {
            launch
        } else {
            match fresh_inherited_remote_session_launch(&source_session) {
                Ok(Some(launch)) => launch,
                Ok(None) => crate::session_creator::empty_session_launch(self.tx.headless_server()),
                Err(()) => return Err(crate::remote_control::SplitPaneCreateError::Internal),
            }
        };
        let layout_service = maestro_shell::WindowLayoutService::new(&self.paths);
        let mut occupied = self
            .known_sessions()
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        let session_id = (0..REMOTE_SESSION_ID_ATTEMPTS)
            .find_map(|_| {
                let session_id = crate::session_creator::generate_session_id(rand::random::<u8>);
                if !occupied.insert(session_id.clone()) {
                    return None;
                }
                let creation_lease = self.tx.begin_remote_creation_lease(&session_id, now).ok()?;
                let (spec, launch_environment) = prepared_remote_session_spec(
                    &self.tx,
                    &workspace,
                    &session_id,
                    &pane_cwd,
                    kind,
                    &launch,
                    initial_size,
                    now,
                )
                .ok()?;
                let start = match layout_service.prepare_new_split_session_from_source_with_spec(
                    &initial_layout,
                    &project,
                    &workspace,
                    &source_session,
                    spec,
                    &request.from_pane_id,
                    &tab_id,
                    &title,
                    axis,
                ) {
                    Ok(start) => start,
                    Err(maestro_shell::WindowLayoutError::SessionAlreadyExists { .. })
                    | Err(maestro_shell::WindowLayoutError::SessionIdentityReferenced { .. }) => {
                        return None;
                    }
                    Err(_) => {
                        return Some(Err(crate::remote_control::SplitPaneCreateError::Internal))
                    }
                };
                let started = match start_prepared_remote_session(
                    &self.tx,
                    &self.paths,
                    start,
                    launch_environment,
                ) {
                    Ok(started) => started,
                    Err(error) => {
                        compensate_prepared_remote_start_error(
                            &self.tx,
                            &self.sessions,
                            &self.paths,
                            error,
                            now,
                            "remote split start",
                        );
                        return Some(Err(
                            crate::remote_control::SplitPaneCreateError::DaemonUnavailable,
                        ));
                    }
                };
                let (record, compensation) = started.into_parts();
                if record.status != maestro_shell::SessionStatus::Live
                    || record.last_known_generation.is_none()
                {
                    consume_prepared_compensation_outcome(
                        &self.tx,
                        &self.sessions,
                        &self.paths,
                        match layout_service.compensate_prepared_new_session(compensation, now) {
                            Ok(outcome) => outcome,
                            Err(_) => {
                                return Some(Err(
                                    crate::remote_control::SplitPaneCreateError::Internal,
                                ));
                            }
                        },
                        "remote split invalid publication",
                    );
                    return Some(Err(crate::remote_control::SplitPaneCreateError::Internal));
                }
                drop(compensation);
                if let Ok(mut sessions) = self.sessions.lock() {
                    sessions.reserve(&session_id);
                }
                creation_lease.commit();
                Some(Ok(session_id))
            })
            .unwrap_or(Err(crate::remote_control::SplitPaneCreateError::Internal))?;

        // The agent only owns durable records; the running desktop app owns RendererTabRuntime.
        // Queue the same foreground focus path used by remote window focus so the local app adopts
        // the new split immediately instead of waiting for an app restart to reload layout records.
        if let Err(e) =
            maestro_shell::write_focus_pane_request(&self.paths, &request.window_id, &tab_id, now)
        {
            eprintln!(
                "remote split: queue focus pane request failed window={} tab={}: {e}",
                request.window_id, tab_id
            );
        }

        Ok(crate::remote_control::SplitPaneCreated { session_id, tab_id })
    }

    fn new_pane(
        &mut self,
        request: crate::remote_control::SplitPaneRequest,
    ) -> Result<crate::remote_control::SplitPaneCreated, crate::remote_control::SplitPaneCreateError>
    {
        self.new_pane_with_initial_size(request, InitialTerminalSize::default())
    }

    fn new_pane_with_initial_size(
        &mut self,
        request: crate::remote_control::SplitPaneRequest,
        initial_size: InitialTerminalSize,
    ) -> Result<crate::remote_control::SplitPaneCreated, crate::remote_control::SplitPaneCreateError>
    {
        // New Pane is an explicit create intent: persist its browser-only (desktop-stashed) existence and
        // start the retained PTY in this operation. The later viewport handshake is then an idempotent
        // confirmation, not the first launch. This matters for fresh agent recipes: canonicalizing a record
        // before its first start turns `claude` into `claude --continue` and resumes unrelated history.
        // Refuse before writing durable topology when the StartSession mutation is unsupported.
        if !start_session_mutations_allowed(&self.sessions) {
            return Err(crate::remote_control::SplitPaneCreateError::DaemonUnavailable);
        }
        let initial_layout = maestro_shell::WindowLayoutService::new(&self.paths)
            .load_snapshot(&request.window_id)
            .map_err(|_| crate::remote_control::SplitPaneCreateError::Internal)?
            .ok_or(crate::remote_control::SplitPaneCreateError::WindowNotFound)?;
        let layout = &initial_layout.layout;
        let source_session_id = layout
            .tabs
            .iter()
            .find(|tab| tab.tab_id == request.from_pane_id)
            .map(|tab| tab.session_id.clone())
            .ok_or(crate::remote_control::SplitPaneCreateError::PaneNotFound)?;
        let source_session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &self.paths,
            maestro_shell::RecordKind::Session,
            &source_session_id,
        ) {
            Ok(Some(maestro_shell::LoadOutcome::Loaded(session))) => session,
            Ok(Some(_)) | Ok(None) | Err(_) => {
                return Err(crate::remote_control::SplitPaneCreateError::Internal);
            }
        };
        let workspace = match maestro_shell::load_one::<maestro_shell::Workspace>(
            &self.paths,
            maestro_shell::RecordKind::Workspace,
            &source_session.workspace_id,
        ) {
            Ok(Some(maestro_shell::LoadOutcome::Loaded(workspace))) => workspace,
            _ => return Err(crate::remote_control::SplitPaneCreateError::Internal),
        };
        let project_id = initial_layout
            .project_id
            .as_deref()
            .ok_or(crate::remote_control::SplitPaneCreateError::Internal)?;
        let project = maestro_shell::ProjectService::new(&self.paths)
            .load(project_id)
            .map_err(|_| crate::remote_control::SplitPaneCreateError::Internal)?
            .ok_or(crate::remote_control::SplitPaneCreateError::Internal)?;
        if workspace.project_id != project.project_id {
            return Err(crate::remote_control::SplitPaneCreateError::Internal);
        }

        let tab_id = pick_remote_tab_id(layout);
        let now = request.now_ms;
        let pane_cwd = request
            .cwd
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .unwrap_or(source_session.cwd_resolved.as_str())
            .to_string();
        let mut resume_launch = crate::remote_control::resume_descriptor_from_launch_flags(
            request.agent.clone(),
            request.launch_flags.clone(),
        )
        .and_then(|mut descriptor| {
            crate::remote_control::resolve_gemini_resume_file(
                &mut descriptor,
                Some(pane_cwd.as_str()),
            );
            crate::resume_launch::build_resume_launch(&descriptor)
        });
        let model = crate::remote_control::model_from_launch_flags(&request.launch_flags);
        let dangerous = crate::remote_control::dangerous_from_launch_flags(&request.launch_flags);
        if let (Some(resume), Some(model), Some(agent)) = (
            resume_launch.as_mut(),
            model.as_deref(),
            request.agent.as_deref(),
        ) {
            append_remote_model(resume, agent, model);
        }
        if let (Some(resume), Some(agent)) = (resume_launch.as_mut(), request.agent.as_deref()) {
            append_remote_dangerous_flag(resume, agent, dangerous);
        }
        let is_terminal = request
            .agent
            .as_deref()
            .map(str::trim)
            .is_some_and(|a| a.eq_ignore_ascii_case("terminal"));
        let fresh_launch = match (&resume_launch, is_terminal, request.agent.as_ref()) {
            (None, false, Some(agent)) => {
                fresh_remote_agent_launch(agent, model.as_deref(), dangerous)
            }
            _ => None,
        };
        let start_launch = resume_launch.or(fresh_launch);
        let kind = if is_terminal {
            maestro_shell::SessionKind::Shell
        } else if request.agent.is_some() {
            maestro_shell::SessionKind::Agent
        } else {
            source_session.kind
        };
        let title = request.pane_name.clone().unwrap_or_else(|| {
            request
                .agent
                .as_deref()
                .map(agent_title)
                .unwrap_or("Pane")
                .to_string()
        });
        let launch = if is_terminal {
            crate::session_creator::empty_session_launch(self.tx.headless_server())
        } else if let Some(launch) = start_launch {
            launch
        } else {
            match fresh_inherited_remote_session_launch(&source_session) {
                Ok(Some(launch)) => launch,
                Ok(None) => crate::session_creator::empty_session_launch(self.tx.headless_server()),
                Err(()) => return Err(crate::remote_control::SplitPaneCreateError::Internal),
            }
        };
        let layout_service = maestro_shell::WindowLayoutService::new(&self.paths);
        let mut occupied = self
            .known_sessions()
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        let session_id = (0..REMOTE_SESSION_ID_ATTEMPTS)
            .find_map(|_| {
                let session_id = crate::session_creator::generate_session_id(rand::random::<u8>);
                if !occupied.insert(session_id.clone()) {
                    return None;
                }
                let creation_lease = self.tx.begin_remote_creation_lease(&session_id, now).ok()?;
                let (spec, launch_environment) = prepared_remote_session_spec(
                    &self.tx,
                    &workspace,
                    &session_id,
                    &pane_cwd,
                    kind,
                    &launch,
                    initial_size,
                    now,
                )
                .ok()?;
                let start = match layout_service.prepare_new_stashed_tab_session_with_spec(
                    &initial_layout,
                    &project,
                    &workspace,
                    spec,
                    &tab_id,
                    &title,
                    false,
                    maestro_shell::AttentionState::default(),
                ) {
                    Ok(start) => start,
                    Err(maestro_shell::WindowLayoutError::SessionAlreadyExists { .. })
                    | Err(maestro_shell::WindowLayoutError::SessionIdentityReferenced { .. }) => {
                        return None;
                    }
                    Err(maestro_shell::WindowLayoutError::WindowLayoutNotFound { .. }) => {
                        return Some(Err(
                            crate::remote_control::SplitPaneCreateError::WindowNotFound,
                        ));
                    }
                    Err(_) => {
                        return Some(Err(crate::remote_control::SplitPaneCreateError::Internal));
                    }
                };
                let started = match start_prepared_remote_session(
                    &self.tx,
                    &self.paths,
                    start,
                    launch_environment,
                ) {
                    Ok(started) => started,
                    Err(error) => {
                        compensate_prepared_remote_start_error(
                            &self.tx,
                            &self.sessions,
                            &self.paths,
                            error,
                            now,
                            "remote new_pane start",
                        );
                        return Some(Err(
                            crate::remote_control::SplitPaneCreateError::DaemonUnavailable,
                        ));
                    }
                };
                let (record, compensation) = started.into_parts();
                if record.status != maestro_shell::SessionStatus::Live
                    || record.last_known_generation.is_none()
                {
                    consume_prepared_compensation_outcome(
                        &self.tx,
                        &self.sessions,
                        &self.paths,
                        match layout_service.compensate_prepared_new_session(compensation, now) {
                            Ok(outcome) => outcome,
                            Err(_) => {
                                return Some(Err(
                                    crate::remote_control::SplitPaneCreateError::Internal,
                                ));
                            }
                        },
                        "remote new_pane invalid publication",
                    );
                    return Some(Err(crate::remote_control::SplitPaneCreateError::Internal));
                }
                drop(compensation);
                if let Ok(mut sessions) = self.sessions.lock() {
                    sessions.reserve(&session_id);
                }
                creation_lease.commit();
                Some(Ok(session_id))
            })
            .unwrap_or(Err(crate::remote_control::SplitPaneCreateError::Internal))?;

        Ok(crate::remote_control::SplitPaneCreated { session_id, tab_id })
    }
}

impl DaemonPaneSplitter {
    fn known_sessions(&self) -> Vec<String> {
        self.sessions
            .lock()
            .map(|s| s.snapshot())
            .unwrap_or_default()
    }
}

const REMOTE_SESSION_ID_ATTEMPTS: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(test)]
enum RemotePaneSessionAllocationError {
    Lease,
    Store,
    Exhausted,
}

/// Reserve and durably create one fresh Session identity for remote window/pane publication.
///
/// The daemon cache is an initial collision filter only. Every candidate that survives it is
/// inserted through maestro-shell's `BEGIN IMMEDIATE` insert-if-absent seam, so a concurrent or
/// previously durable row can never be adopted or overwritten. `AlreadyExists` drops that
/// candidate's lease and retries; exhaustion returns without handing the caller any tab/start or
/// rollback authority.
#[cfg(test)]
fn create_fresh_remote_session<L>(
    paths: &maestro_shell::AppPaths,
    daemon_known: &[String],
    template: maestro_shell::SessionRecord,
    written_at_ms: u64,
    mut rand_byte: impl FnMut() -> u8,
    mut reserve_lease: impl FnMut(&str, u64) -> std::io::Result<L>,
) -> Result<(maestro_shell::SessionRecord, L), RemotePaneSessionAllocationError> {
    let mut occupied = daemon_known
        .iter()
        .cloned()
        .collect::<std::collections::HashSet<_>>();
    for _ in 0..REMOTE_SESSION_ID_ATTEMPTS {
        let session_id = crate::session_creator::generate_session_id(&mut rand_byte);
        if !occupied.insert(session_id.clone()) {
            continue;
        }
        let creation_lease = reserve_lease(&session_id, written_at_ms)
            .map_err(|_| RemotePaneSessionAllocationError::Lease)?;
        let mut candidate = template.clone();
        candidate.session_id = session_id;
        match maestro_shell::create_session_record_if_absent(paths, &candidate, written_at_ms)
            .map_err(|_| RemotePaneSessionAllocationError::Store)?
        {
            maestro_shell::CreateSessionRecordOutcome::Created => {
                return Ok((candidate, creation_lease));
            }
            maestro_shell::CreateSessionRecordOutcome::AlreadyExists => {
                // The candidate was inserted into `occupied` above. Dropping this iteration's
                // guard rolls back its temporary viewport lease before another id is tried.
            }
        }
    }
    Err(RemotePaneSessionAllocationError::Exhausted)
}

fn pick_remote_tab_id(layout: &maestro_shell::WindowLayout) -> String {
    for _ in 0..10 {
        let suffix = crate::session_creator::generate_session_id(rand::random::<u8>);
        let tab_id = format!("pane-{suffix}");
        if !layout.tabs.iter().any(|tab| tab.tab_id == tab_id) {
            return tab_id;
        }
    }
    format!(
        "pane-{}",
        crate::session_creator::generate_session_id(rand::random::<u8>)
    )
}

fn agent_title(agent: &str) -> &'static str {
    match agent {
        "claude" => "Claude",
        "codex" => "Codex",
        "copilot" => "Copilot",
        "antigravity" | "agy" => "Antigravity",
        "kimi" => "Kimi",
        "kiro" | "kiro-cli" => "Kiro",
        "cursor" | "agent" => "Cursor",
        "amp" => "Amp",
        "devin" => "Devin",
        "factory" | "droid" => "Factory",
        "gemini" => "Gemini",
        "opencode" => "OpenCode",
        "terminal" => "Terminal",
        _ => "Pane",
    }
}

/// Turn the UI/wire provider identity into the exact executable launch. This is deliberately used before
/// persisting a SessionRecord so record params and the first daemon StartSession stay identical. Copilot's
/// helper assigns its durable provider UUID once here; Antigravity maps to the `agy` executable.
fn fresh_remote_agent_launch(
    agent: &str,
    model: Option<&str>,
    dangerous: bool,
) -> Option<crate::resume_launch::ResumeLaunch> {
    let provider = crate::resume_launch::ResumeAgent::parse(agent)?;
    let mut launch = crate::resume_launch::build_fresh_launch(provider);
    if let Some(model) = model {
        append_remote_model(&mut launch, agent, model);
    }
    append_remote_dangerous_flag(&mut launch, agent, dangerous);
    Some(launch)
}

fn append_remote_model(launch: &mut crate::resume_launch::ResumeLaunch, agent: &str, model: &str) {
    // Amp and Factory do not expose Hydra's generic interactive `--model` contract. Stale or forged model
    // metadata must not leak into either launch.
    if matches!(agent, "amp" | "factory") {
        return;
    }
    launch.args.push("--model".to_string());
    launch.args.push(model.to_string());
}

fn append_remote_dangerous_flag(
    launch: &mut crate::resume_launch::ResumeLaunch,
    agent: &str,
    dangerous: bool,
) {
    if !dangerous {
        return;
    }
    let Some(provider) = crate::resume_launch::ResumeAgent::parse(agent) else {
        return;
    };
    let flag = provider.dangerous_flag();
    if !launch.args.iter().any(|arg| arg == flag) {
        launch.args.push(flag.to_string());
    }
}

fn continue_remote_agent_launch(agent: &str) -> Option<crate::resume_launch::ResumeLaunch> {
    let provider = crate::resume_launch::ResumeAgent::parse(agent)?;
    let args = match provider {
        crate::resume_launch::ResumeAgent::Codex => vec!["resume".into(), "--last".into()],
        crate::resume_launch::ResumeAgent::Gemini => {
            vec!["--resume".into(), "latest".into()]
        }
        crate::resume_launch::ResumeAgent::Kiro => vec!["chat".into(), "--resume".into()],
        crate::resume_launch::ResumeAgent::Claude
        | crate::resume_launch::ResumeAgent::Copilot
        | crate::resume_launch::ResumeAgent::Antigravity
        | crate::resume_launch::ResumeAgent::Kimi
        | crate::resume_launch::ResumeAgent::Cursor
        | crate::resume_launch::ResumeAgent::Opencode => vec!["--continue".into()],
        crate::resume_launch::ResumeAgent::Amp => vec!["last".into()],
        crate::resume_launch::ResumeAgent::Devin => vec!["--continue".into()],
        crate::resume_launch::ResumeAgent::Factory => vec!["--resume".into()],
    };
    Some(crate::resume_launch::ResumeLaunch {
        command: provider.command().to_string(),
        args,
    })
}

/// A real remote revive implementation: un-stash the pane through the desktop layout service and ensure the
/// preserved session id is running on the daemon so the browser can attach it.
pub struct DaemonPaneReviver {
    tx: DaemonRequestSender,
    sessions: SharedSessions,
    paths: maestro_shell::AppPaths,
}

impl crate::remote_control::PaneReviver for DaemonPaneReviver {
    fn revive_pane(
        &mut self,
        request: crate::remote_control::RevivePaneRequest,
    ) -> Result<crate::remote_control::RevivePaneCreated, crate::remote_control::RevivePaneError>
    {
        self.revive_pane_with_initial_size(request, InitialTerminalSize::default())
    }

    fn revive_pane_with_initial_size(
        &mut self,
        request: crate::remote_control::RevivePaneRequest,
        initial_size: InitialTerminalSize,
    ) -> Result<crate::remote_control::RevivePaneCreated, crate::remote_control::RevivePaneError>
    {
        // Revive is a durable layout mutation and may also replace a retained PTY generation.
        // A legacy/partially capable daemon remains strictly attach-only, even when its startup
        // listing happened to name this session as live.
        if !start_session_mutations_allowed(&self.sessions) {
            return Err(crate::remote_control::RevivePaneError::Internal);
        }
        let paths = self.paths.clone();
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        let before = layouts
            .load(&request.window_id)
            .map_err(map_revive_layout_error)?
            .ok_or(crate::remote_control::RevivePaneError::WindowNotFound)?;
        let target = before
            .tabs
            .iter()
            .find(|tab| tab.tab_id == request.pane_id)
            .ok_or(crate::remote_control::RevivePaneError::PaneNotFound)?;
        let creation_lease = self
            .tx
            .begin_remote_creation_lease(&target.session_id, request.now_ms)
            .map_err(|_| crate::remote_control::RevivePaneError::Internal)?;
        let evicted_pane = if target.stashed {
            let live_tabs: Vec<_> = before
                .tabs
                .iter()
                .filter(|tab| !tab.stashed && tab.tab_id != request.pane_id)
                .collect();
            if live_tabs.len() >= 4 {
                live_tabs
                    .iter()
                    .find(|tab| tab.tab_id != request.pane_id)
                    .map(|tab| tab.tab_id.clone())
            } else {
                None
            }
        } else {
            None
        };
        if let Some(pane_id) = evicted_pane.as_deref() {
            layouts
                .stash_pane(&request.window_id, pane_id, request.now_ms)
                .map_err(map_revive_layout_error)?;
        }
        let layout = match layouts
            .revive_pane(&request.window_id, &request.pane_id, request.now_ms)
            .map_err(map_revive_layout_error)
        {
            Ok(layout) => layout,
            Err(err) => {
                if let Some(pane_id) = evicted_pane.as_deref() {
                    let _ = layouts.revive_pane(&request.window_id, pane_id, request.now_ms);
                }
                return Err(err);
            }
        };
        let tab = layout
            .tabs
            .iter()
            .find(|tab| tab.tab_id == request.pane_id)
            .ok_or(crate::remote_control::RevivePaneError::PaneNotFound)?;
        let session_id = tab.session_id.clone();
        // Exact recovery authorizes the durable bytes as loaded. Running the legacy restart
        // canonicalizer here could collapse conflicting selectors or invent `latest` from a bare
        // provider row before the exact-resume gate sees it.
        let session = load_unmodified_remote_session_for_exact_start(&self.paths, &session_id)?;
        if let Err(err) = self.ensure_session_running(&session, initial_size, request.now_ms) {
            let _ = layouts.stash_pane(&request.window_id, &request.pane_id, request.now_ms);
            if let Some(pane_id) = evicted_pane.as_deref() {
                let _ = layouts.revive_pane(&request.window_id, pane_id, request.now_ms);
            }
            return Err(err);
        }
        creation_lease.commit();
        Ok(crate::remote_control::RevivePaneCreated { session_id })
    }
}

impl DaemonPaneReviver {
    fn known_sessions(&self) -> Vec<String> {
        self.sessions
            .lock()
            .map(|s| s.snapshot())
            .unwrap_or_default()
    }

    fn ensure_session_running(
        &mut self,
        session: &maestro_shell::SessionRecord,
        initial_size: InitialTerminalSize,
        now_ms: u64,
    ) -> Result<(), crate::remote_control::RevivePaneError> {
        if self
            .known_sessions()
            .iter()
            .any(|id| id == &session.session_id)
        {
            return Ok(());
        }
        if !start_session_mutations_allowed(&self.sessions) {
            return Err(crate::remote_control::RevivePaneError::Internal);
        }
        let record = resolve_existing_remote_session_exact(
            &self.tx,
            &self.sessions,
            &self.paths,
            session,
            initial_size,
            now_ms,
        )
        .map_err(|_| crate::remote_control::RevivePaneError::Internal)?;
        if record.status != maestro_shell::SessionStatus::Live
            || record.last_known_generation.is_none()
        {
            return Err(crate::remote_control::RevivePaneError::Internal);
        }
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.reserve(&session.session_id);
        }
        Ok(())
    }
}

/// Virtual remote viewport starter: make a pane's durable session daemon-live without changing the local desktop
/// window's stash/layout state. This is the normal browser "view this pane" recovery path.
pub struct DaemonPaneSessionStarter {
    tx: DaemonRequestSender,
    sessions: SharedSessions,
    paths: maestro_shell::AppPaths,
}

impl crate::remote_control::PaneSessionStarter for DaemonPaneSessionStarter {
    fn start_pane_session(
        &mut self,
        request: crate::remote_control::RevivePaneRequest,
    ) -> Result<crate::remote_control::RevivePaneCreated, crate::remote_control::RevivePaneError>
    {
        self.start_pane_session_with_initial_size(request, InitialTerminalSize::default())
    }

    fn start_pane_session_with_initial_size(
        &mut self,
        request: crate::remote_control::RevivePaneRequest,
        initial_size: InitialTerminalSize,
    ) -> Result<crate::remote_control::RevivePaneCreated, crate::remote_control::RevivePaneError>
    {
        let layout = maestro_shell::WindowLayoutService::new(&self.paths)
            .load(&request.window_id)
            .map_err(map_revive_layout_error)?
            .ok_or(crate::remote_control::RevivePaneError::WindowNotFound)?;
        let tab = layout
            .tabs
            .iter()
            .find(|tab| tab.tab_id == request.pane_id)
            .ok_or(crate::remote_control::RevivePaneError::PaneNotFound)?;
        let session_id = tab.session_id.clone();
        let session_is_live = self
            .sessions
            .lock()
            .map(|s| s.snapshot().iter().any(|id| id == &session_id))
            .unwrap_or(false);
        // The create operation reserves the id as soon as its first StartSession is enqueued. A viewport
        // handshake arriving behind it must be a true no-op: in particular, do not canonicalize the fresh
        // durable recipe into a provider resume fallback before returning success.
        if session_is_live {
            return Ok(crate::remote_control::RevivePaneCreated { session_id });
        }
        if !start_session_mutations_allowed(&self.sessions) {
            return Err(crate::remote_control::RevivePaneError::Internal);
        }
        let creation_lease = self
            .tx
            .begin_remote_creation_lease(&session_id, request.now_ms)
            .map_err(|_| crate::remote_control::RevivePaneError::Internal)?;
        // Never migrate or sanitize a recovery candidate before exact authorization. Legacy bare,
        // latest, duplicate, conflicting, or ad-hoc rows remain byte-identical and fail closed.
        let session = load_unmodified_remote_session_for_exact_start(&self.paths, &session_id)?;
        let record = resolve_existing_remote_session_exact(
            &self.tx,
            &self.sessions,
            &self.paths,
            &session,
            initial_size,
            request.now_ms,
        )
        .map_err(|_| crate::remote_control::RevivePaneError::Internal)?;
        if record.status != maestro_shell::SessionStatus::Live
            || record.last_known_generation.is_none()
        {
            return Err(crate::remote_control::RevivePaneError::Internal);
        }
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.reserve(&session.session_id);
        }
        creation_lease.commit();
        Ok(crate::remote_control::RevivePaneCreated { session_id })
    }
}

fn resolve_existing_remote_session_exact(
    tx: &DaemonRequestSender,
    sessions: &SharedSessions,
    paths: &maestro_shell::AppPaths,
    session: &maestro_shell::SessionRecord,
    initial_size: InitialTerminalSize,
    now_ms: u64,
) -> Result<maestro_shell::SessionRecord, maestro_shell::SessionServiceError> {
    if !start_session_mutations_allowed(sessions) {
        return Err(maestro_shell::SessionServiceError::AttachAuthorityLost {
            session_id: session.session_id.clone(),
        });
    }
    let workspace = match maestro_shell::load_one::<maestro_shell::Workspace>(
        paths,
        maestro_shell::RecordKind::Workspace,
        &session.workspace_id,
    )? {
        Some(maestro_shell::LoadOutcome::Loaded(workspace)) => workspace,
        _ => {
            return Err(maestro_shell::SessionServiceError::AttachAuthorityLost {
                session_id: session.session_id.clone(),
            });
        }
    };
    let launch_environment =
        remote_launch_environment(tx).map_err(maestro_shell::SessionServiceError::Daemon)?;
    let attach = maestro_shell::ExistingSessionAttach::exact(session, &workspace, now_ms)?;
    let start = maestro_shell::ExistingSessionStart::known_safe_exact(
        session,
        &workspace,
        &launch_environment,
        initial_size.cols(),
        initial_size.rows(),
        now_ms,
    )?;
    let client =
        connect_reviewed_daemon_client(tx).map_err(maestro_shell::SessionServiceError::Daemon)?;
    maestro_shell::SessionService::new(paths)
        .resolve_existing_exact_headless_with_child_environment(
            client,
            &attach,
            Some(maestro_shell::ExistingSessionMissingStart::KnownSafe(
                &start,
            )),
            launch_environment.child_environment,
        )
}

fn load_unmodified_remote_session_for_exact_start(
    paths: &maestro_shell::AppPaths,
    session_id: &str,
) -> Result<maestro_shell::SessionRecord, crate::remote_control::RevivePaneError> {
    match maestro_shell::load_one::<maestro_shell::SessionRecord>(
        paths,
        maestro_shell::RecordKind::Session,
        session_id,
    ) {
        Ok(Some(maestro_shell::LoadOutcome::Loaded(session))) => Ok(session),
        Ok(Some(_)) | Ok(None) | Err(_) => Err(crate::remote_control::RevivePaneError::Internal),
    }
}

fn shell_quote_arg(arg: &str) -> String {
    format!("'{}'", arg.replace('\'', "'\\''"))
}

fn resolve_login_shell_command_from_homes(
    command: &str,
    headless_server: bool,
    ambient_home: Option<&std::path::Path>,
    trusted_home: Option<&std::path::Path>,
) -> String {
    if command == "opencode" {
        #[cfg(target_os = "linux")]
        let home = if headless_server {
            trusted_home
        } else {
            ambient_home
        };
        #[cfg(not(target_os = "linux"))]
        let home = {
            let _ = (headless_server, trusted_home);
            ambient_home
        };
        if let Some(home) = home {
            let candidate = home.join(".opencode").join("bin").join("opencode");
            if candidate.is_file() {
                return candidate.to_string_lossy().into_owned();
            }
        }
    }
    command.to_string()
}

fn resolve_login_shell_command(command: &str, headless_server: bool) -> String {
    let ambient_home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    #[cfg(target_os = "linux")]
    let trusted_home = headless_server
        .then(crate::agent_dir::trusted_home_dir)
        .transpose()
        .ok()
        .flatten();
    #[cfg(not(target_os = "linux"))]
    let trusted_home: Option<std::path::PathBuf> = None;
    resolve_login_shell_command_from_homes(
        command,
        headless_server,
        ambient_home.as_deref(),
        trusted_home.as_deref(),
    )
}

/// Use the login shell the desktop user actually configured. The macOS product defaults to zsh,
/// but Linux packages neither require nor install zsh; hard-coding `/bin/zsh` here made the
/// browser-only `new_pane -> start_pane_session` path enqueue an executable that does not exist on
/// a stock Ubuntu install. Keep this in lockstep with maestro-app's recorded-session launch policy.
fn login_shell_program_from(shell: Option<&str>) -> String {
    match shell.map(str::trim).filter(|shell| !shell.is_empty()) {
        Some(shell) => shell.to_string(),
        None if cfg!(target_os = "macos") => "/bin/zsh".to_string(),
        None => "/bin/sh".to_string(),
    }
}

fn login_shell_program() -> String {
    login_shell_program_from(std::env::var("SHELL").ok().as_deref())
}

fn login_shell_program_for_policy(headless_server: bool) -> String {
    #[cfg(target_os = "linux")]
    if headless_server {
        return crate::agent_dir::trusted_login_shell().unwrap_or_else(|_| "/dev/null".to_string());
    }
    let _ = headless_server;
    login_shell_program()
}

fn login_shell_launch_with_program(
    command: &str,
    args: &[String],
    login_shell: &str,
    headless_server: bool,
) -> crate::resume_launch::ResumeLaunch {
    let mut argv = Vec::with_capacity(1 + args.len());
    argv.push(resolve_login_shell_command(command, headless_server));
    argv.extend(args.iter().cloned());
    let command_line = argv
        .iter()
        .map(|arg| shell_quote_arg(arg))
        .collect::<Vec<_>>()
        .join(" ");
    crate::resume_launch::ResumeLaunch {
        command: login_shell.to_string(),
        args: vec![
            maestro_local_services::LOGIN_SHELL_COMMAND_FLAGS.to_string(),
            command_line,
        ],
    }
}

fn login_shell_launch(
    command: &str,
    args: &[String],
    headless_server: bool,
) -> crate::resume_launch::ResumeLaunch {
    login_shell_launch_with_program(
        command,
        args,
        &login_shell_program_for_policy(headless_server),
        headless_server,
    )
}

fn is_remote_agent_command(command: &str) -> bool {
    matches!(
        command,
        "claude"
            | "codex"
            | "copilot"
            | "agy"
            | "kimi"
            | "kiro-cli"
            | "agent"
            | "amp"
            | "devin"
            | "droid"
            | "gemini"
            | "opencode"
    )
}

#[cfg(test)]
fn recorded_remote_session_launch(
    session: &maestro_shell::SessionRecord,
    headless_server: bool,
) -> Option<crate::resume_launch::ResumeLaunch> {
    match &session.launch {
        maestro_shell::LaunchSpec::KnownSafe {
            launch_spec_id,
            params,
        } if !launch_spec_id.is_empty() => match launch_spec_id.as_str() {
            command if is_remote_agent_command(command) => {
                Some(login_shell_launch(launch_spec_id, params, headless_server))
            }
            _ => Some(crate::resume_launch::ResumeLaunch {
                command: launch_spec_id.clone(),
                args: params.clone(),
            }),
        },
        maestro_shell::LaunchSpec::AdHocRedacted { argv, .. } if !argv.is_empty() => {
            let (command, args) = argv.split_first()?;
            match command.as_str() {
                command if is_remote_agent_command(command) => {
                    Some(login_shell_launch(command, args, headless_server))
                }
                _ => Some(crate::resume_launch::ResumeLaunch {
                    command: command.clone(),
                    args: args.to_vec(),
                }),
            }
        }
        _ => None,
    }
}

/// Derive an implicit child-pane launch without inheriting the source provider conversation.
///
/// "No agent selected" inherits the provider *profile*, not its session identity. A reviewed
/// provider recipe is reduced to a fresh launch of the same CLI, retaining only its bounded model
/// and dangerous-mode choices. Claude, Gemini, and Copilot therefore receive a newly generated
/// UUID; providers without caller-assigned identities remain fresh and non-replayable. An opaque
/// Agent shell wrapper fails closed because it could conceal an exact provider resume command.
fn fresh_inherited_remote_session_launch(
    session: &maestro_shell::SessionRecord,
) -> Result<Option<crate::resume_launch::ResumeLaunch>, ()> {
    use crate::resume_launch::ResumeAgent;

    let (provider, params) = match &session.launch {
        maestro_shell::LaunchSpec::KnownSafe {
            launch_spec_id,
            params,
        } => {
            let Some(provider) = resume_agent_from_command(launch_spec_id) else {
                return if session.kind == maestro_shell::SessionKind::Shell {
                    // `KnownSafe` is not itself provider provenance: an absolute provider path or
                    // login-shell wrapper can hide a resume selector under an unrecognized id.
                    // Implicit inheritance never replays unknown Shell bytes.
                    Ok(None)
                } else {
                    Err(())
                };
            };
            if session.kind != maestro_shell::SessionKind::Agent {
                return Err(());
            }
            let mut source = Vec::with_capacity(1 + params.len());
            source.push(launch_spec_id.clone());
            source.extend(params.iter().cloned());
            if !maestro_shell::is_strict_prepared_provider_launch(launch_spec_id, &source) {
                return Err(());
            }
            (provider, params.as_slice())
        }
        maestro_shell::LaunchSpec::AdHocRedacted { argv, .. } => {
            let (command, params) = argv.split_first().ok_or(())?;
            let leaf = std::path::Path::new(command)
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .ok_or(())?;
            let Some(provider) = resume_agent_from_command(leaf) else {
                // A previous Hydra build could have persisted a provider command inside an opaque
                // Agent login-shell wrapper. Replaying it might duplicate a hidden resume identity.
                // Ordinary AdHoc Shell bytes are non-replayable too, so a child receives the
                // reviewed empty shell rather than this arbitrary command.
                return if session.kind == maestro_shell::SessionKind::Shell {
                    Ok(None)
                } else {
                    Err(())
                };
            };
            if session.kind != maestro_shell::SessionKind::Agent {
                return Err(());
            }
            let canonical_command = provider.command();
            let mut source = Vec::with_capacity(1 + params.len());
            source.push(canonical_command.to_string());
            source.extend(params.iter().cloned());
            if !maestro_shell::is_strict_prepared_provider_launch(canonical_command, &source) {
                return Err(());
            }
            (provider, params)
        }
        maestro_shell::LaunchSpec::OptOut => {
            return if session.kind == maestro_shell::SessionKind::Shell {
                Ok(None)
            } else {
                Err(())
            }
        }
    };

    let model = params
        .windows(2)
        .find(|pair| pair[0] == "--model")
        .and_then(|pair| crate::remote_control::sanitize_model_name(&pair[1]));
    let dangerous = params
        .iter()
        .any(|value| value == provider.dangerous_flag());
    let mut launch = crate::resume_launch::build_fresh_launch(provider);
    if let Some(model) = model {
        if !matches!(provider, ResumeAgent::Amp | ResumeAgent::Factory) {
            launch.args.extend(["--model".to_string(), model]);
        }
    }
    if dangerous {
        let flag = provider.dangerous_flag();
        if !launch.args.iter().any(|value| value == flag) {
            launch.args.push(flag.to_string());
        }
    }
    Ok(Some(launch))
}

fn resume_agent_from_command(command: &str) -> Option<crate::resume_launch::ResumeAgent> {
    use crate::resume_launch::ResumeAgent;

    Some(match command {
        "claude" => ResumeAgent::Claude,
        "codex" => ResumeAgent::Codex,
        "copilot" => ResumeAgent::Copilot,
        "agy" => ResumeAgent::Antigravity,
        "kimi" => ResumeAgent::Kimi,
        "kiro-cli" => ResumeAgent::Kiro,
        "agent" => ResumeAgent::Cursor,
        "amp" => ResumeAgent::Amp,
        "devin" => ResumeAgent::Devin,
        "droid" => ResumeAgent::Factory,
        "gemini" => ResumeAgent::Gemini,
        "opencode" => ResumeAgent::Opencode,
        _ => return None,
    })
}

fn map_revive_layout_error(
    e: maestro_shell::WindowLayoutError,
) -> crate::remote_control::RevivePaneError {
    match e {
        maestro_shell::WindowLayoutError::WindowLayoutNotFound { .. } => {
            crate::remote_control::RevivePaneError::WindowNotFound
        }
        maestro_shell::WindowLayoutError::TabNotFound { .. } => {
            crate::remote_control::RevivePaneError::PaneNotFound
        }
        _ => crate::remote_control::RevivePaneError::Internal,
    }
}

/// A real remote stash implementation: stash a live pane through the desktop layout service.
pub struct DaemonPaneStasher {
    paths: maestro_shell::AppPaths,
}

impl crate::remote_control::PaneStasher for DaemonPaneStasher {
    fn stash_pane(
        &mut self,
        request: crate::remote_control::StashPaneRequest,
    ) -> Result<(), crate::remote_control::RevivePaneError> {
        maestro_shell::WindowLayoutService::new(&self.paths)
            .stash_pane(&request.window_id, &request.pane_id, request.now_ms)
            .map(|_| ())
            .map_err(map_revive_layout_error)
    }
}

/// A real remote remove implementation ("Remove from shelf"): drop a pane record via the desktop layout service's
/// close_pane, which removes only the layout/shelf record (the daemon session is not killed).
pub struct DaemonPaneRemover {
    paths: maestro_shell::AppPaths,
}

impl crate::remote_control::PaneRemover for DaemonPaneRemover {
    fn remove_pane(
        &mut self,
        request: crate::remote_control::RemovePaneRequest,
    ) -> Result<(), crate::remote_control::RevivePaneError> {
        match maestro_shell::WindowLayoutService::new(&self.paths)
            .close_pane_with_removed_preserving_global_last(
                &request.window_id,
                &request.pane_id,
                request.now_ms,
            )
            .map_err(map_revive_layout_error)?
        {
            maestro_shell::GuardedWindowTabClose::Closed(_) => Ok(()),
            maestro_shell::GuardedWindowTabClose::GloballyLastVisible => {
                Err(crate::remote_control::RevivePaneError::GloballyLastVisible)
            }
        }
    }
}

/// A real remote rename implementation: rename either a pane/tab or a window via the desktop layout service.
pub struct DaemonRenamer {
    paths: maestro_shell::AppPaths,
}

impl crate::remote_control::Renamer for DaemonRenamer {
    fn rename(
        &mut self,
        request: crate::remote_control::RenameRequest,
    ) -> Result<(), crate::remote_control::RenameError> {
        let layouts = maestro_shell::WindowLayoutService::new(&self.paths);
        let result = if let Some(pane_id) = request.pane_id {
            layouts.rename_tab(&request.window_id, &pane_id, &request.name, request.now_ms)
        } else {
            layouts.rename_window(&request.window_id, &request.name, request.now_ms)
        };
        result.map(|_| ()).map_err(map_rename_layout_error)
    }
}

fn map_rename_layout_error(
    e: maestro_shell::WindowLayoutError,
) -> crate::remote_control::RenameError {
    match e {
        maestro_shell::WindowLayoutError::WindowLayoutNotFound { .. } => {
            crate::remote_control::RenameError::WindowNotFound
        }
        maestro_shell::WindowLayoutError::TabNotFound { .. } => {
            crate::remote_control::RenameError::PaneNotFound
        }
        _ => crate::remote_control::RenameError::Internal,
    }
}

/// A real remote close implementation: remove the desktop window layout and tear down its pane sessions.
pub struct DaemonWindowCloser {
    tx: DaemonRequestSender,
    sessions: SharedSessions,
    paths: maestro_shell::AppPaths,
}

impl crate::remote_control::WindowCloser for DaemonWindowCloser {
    fn close_window(
        &mut self,
        window_id: String,
        now_ms: u64,
    ) -> Result<(), crate::remote_control::CloseWindowError> {
        if window_id == maestro_shell::PRODUCT_RECOVERY_WINDOW_ID {
            return Err(crate::remote_control::CloseWindowError::WindowNotFound);
        }
        let layouts = maestro_shell::WindowLayoutService::new(&self.paths);
        let close_snapshot = layouts
            .load_close_snapshot(&window_id)
            .map_err(|_| crate::remote_control::CloseWindowError::Internal)?
            .ok_or(crate::remote_control::CloseWindowError::WindowNotFound)?;
        let session_ids = close_snapshot
            .window
            .layout
            .tabs
            .iter()
            .map(|tab| tab.session_id.as_str())
            .collect::<Vec<_>>();
        let mut client = connect_reviewed_daemon_client(&self.tx)
            .map_err(|_| crate::remote_control::CloseWindowError::Internal)?;
        let resolutions = maestro_shell::pre_resolve_session_generations(
            &mut client,
            session_ids.iter().copied(),
        )
        .map_err(|_| crate::remote_control::CloseWindowError::Internal)?;
        // The release worker opens a fresh reviewed connection. Drop the pre-resolution client at
        // the exact plan/commit boundary so a single-threaded daemon (and bounded production
        // accept loops) never deadlocks waiting for an otherwise-idle first connection.
        drop(client);
        let mut deletion = match layouts
            .delete_if_unchanged_with_resolutions_preserving_global_last(
                &close_snapshot.window,
                &resolutions,
                now_ms,
            )
            .map_err(|_| crate::remote_control::CloseWindowError::Internal)?
        {
            maestro_shell::GuardedConditionalWindowDelete::Deleted(receipt) => receipt,
            maestro_shell::GuardedConditionalWindowDelete::Missing => {
                return Err(crate::remote_control::CloseWindowError::WindowNotFound);
            }
            maestro_shell::GuardedConditionalWindowDelete::Changed => {
                return Err(crate::remote_control::CloseWindowError::Internal);
            }
            maestro_shell::GuardedConditionalWindowDelete::GloballyLastVisible => {
                return Err(crate::remote_control::CloseWindowError::GloballyLastVisible);
            }
        };
        if !deletion.unresolved_release_session_ids().is_empty() {
            tracing::warn!("remote window deletion retained unresolved release targets");
        }
        if let Some(receipt) = deletion.take_release_receipt() {
            drain_owned_session_release(&self.tx, &self.sessions, &self.paths, receipt);
        }
        Ok(())
    }
}

/// Desktop-backed window focuser. The live window switch is owned by the FOREGROUND maestro-app runtime
/// (RendererTabRuntime) — a background daemon can't flip it directly and must NOT fake it by mutating records. So
/// this validates the window exists, then writes a one-shot focus-request signal (maestro-shell) that the running
/// app consumes on its idle tick and applies through the same `focus_recorded_window_pane` path its own UI uses.
pub struct DaemonWindowFocuser {
    paths: maestro_shell::AppPaths,
}

impl crate::remote_control::WindowFocuser for DaemonWindowFocuser {
    fn focus_window(
        &mut self,
        window_id: String,
        now_ms: u64,
    ) -> Result<(), crate::remote_control::FocusWindowError> {
        // Confirm the window layout exists before signalling (don't queue a focus for a nonexistent window).
        maestro_shell::WindowLayoutService::new(&self.paths)
            .load(&window_id)
            .map_err(|_| crate::remote_control::FocusWindowError::Internal)?
            .ok_or(crate::remote_control::FocusWindowError::WindowNotFound)?;
        // Signal the foreground app; it performs the real live switch on its next idle tick.
        maestro_shell::write_focus_window_request(&self.paths, &window_id, now_ms)
            .map_err(|_| crate::remote_control::FocusWindowError::Internal)
    }
}

/// A real remote new-window implementation: create the same durable project/workspace/window/session records
/// the desktop dashboard creates, open the first pane, and start that session on the daemon.
pub struct DaemonWindowOpener {
    tx: DaemonRequestSender,
    sessions: SharedSessions,
    paths: maestro_shell::AppPaths,
}

impl crate::remote_control::WindowOpener for DaemonWindowOpener {
    fn new_window(
        &mut self,
        request: crate::remote_control::NewWindowRequest,
    ) -> Result<crate::remote_control::NewWindowCreated, crate::remote_control::NewWindowError>
    {
        self.new_window_with_initial_size(request, InitialTerminalSize::default())
    }

    fn new_window_with_initial_size(
        &mut self,
        request: crate::remote_control::NewWindowRequest,
        initial_size: InitialTerminalSize,
    ) -> Result<crate::remote_control::NewWindowCreated, crate::remote_control::NewWindowError>
    {
        // A new window always seeds a fresh daemon session. Refuse before creating workspace,
        // session, window, or project-order records when the operational connection is attach-only.
        if !start_session_mutations_allowed(&self.sessions) {
            return Err(crate::remote_control::NewWindowError::DaemonUnavailable);
        }
        // Product recovery is a private desktop fallback, never a user workspace. Older agents
        // accidentally advertised it, so stale browsers may still know the reserved id. Treat it
        // as absent before any durable write or PTY start.
        if request.project_id == PRODUCT_RECOVERY_PROJECT_ID {
            return Err(crate::remote_control::NewWindowError::ProjectNotFound);
        }
        let project_snapshot = maestro_shell::WindowLayoutService::new(&self.paths)
            .load_project_window_graph_snapshot(&request.project_id)
            .map_err(|_| crate::remote_control::NewWindowError::Internal)?
            .ok_or(crate::remote_control::NewWindowError::ProjectNotFound)?;
        let project = project_snapshot.project();
        let now = request.now_ms;
        let title = if request.name.trim().is_empty() {
            "Window".to_string()
        } else {
            request.name.trim().to_string()
        };
        let root = request
            .cwd
            .as_deref()
            .map(str::trim)
            .filter(|cwd| !cwd.is_empty())
            .unwrap_or(project.root.as_str())
            .to_string();
        // Inherit the saved project launch defaults exactly like desktop CreateWindow does (shared helper), so a
        // browser-created window is NOT a separate environment: an absent request agent falls back to the
        // project's saved default agent. custom_command is intentionally NOT applied here — remote sessions are
        // constrained to KnownSafe launch specs (an allowlisted agent line), never an arbitrary command, to keep
        // the content-blind / no-remote-code-execution guarantee.
        let inherited = maestro_local_services::inherited_project_launch_inputs(
            Some(project),
            request.agent.as_deref(),
            None,
        );
        let agent = inherited.agent.as_deref().unwrap_or("claude").to_string();
        // "terminal" (the project default OR an explicit request) means a plain-bash window: Shell + OptOut, not an
        // Agent defaulting to claude. This also fixes the prior "remote new-window is always Agent+claude" bug.
        let is_terminal = agent.eq_ignore_ascii_case("terminal")
            || request
                .agent
                .as_deref()
                .is_some_and(|a| a.eq_ignore_ascii_case("terminal"));
        // Launch context from the browser's launch_flags — split_pane parity. A new window can RESUME a
        // prior agent session ({resumeMode:'resume', resumeSessionId}) and/or carry a model NAME; both are
        // built the same content-blind way (agent allowlisted; Gemini file resolved desktop-side; the model
        // appended as the discrete argv pair ["--model", <name>]). Previously launch_flags was ignored here
        // and the first pane always started fresh with no flags.
        let mut resume_launch = if is_terminal {
            None
        } else {
            crate::remote_control::resume_descriptor_from_launch_flags(
                Some(agent.clone()),
                request.launch_flags.clone(),
            )
            .and_then(|mut descriptor| {
                crate::remote_control::resolve_gemini_resume_file(
                    &mut descriptor,
                    Some(root.as_str()),
                );
                crate::resume_launch::build_resume_launch(&descriptor)
            })
        };
        let model = crate::remote_control::model_from_launch_flags(&request.launch_flags);
        let dangerous = crate::remote_control::dangerous_from_launch_flags(&request.launch_flags);
        if let (Some(resume), Some(model)) = (resume_launch.as_mut(), model.as_deref()) {
            append_remote_model(resume, &agent, model);
        }
        if let Some(resume) = resume_launch.as_mut() {
            append_remote_dangerous_flag(resume, &agent, dangerous);
        }
        // The launch the daemon start uses: resume wins; otherwise the resolved explicit/inherited
        // allowlisted provider starts fresh. This keeps the first PTY bytes aligned with the selected
        // project default instead of recording an Agent while executing an unrelated bare shell.
        let start_launch = if is_terminal {
            None
        } else {
            resume_launch.or_else(|| fresh_remote_agent_launch(&agent, model.as_deref(), dangerous))
        };
        let kind = if is_terminal {
            maestro_shell::SessionKind::Shell
        } else {
            maestro_shell::SessionKind::Agent
        };
        let launch = start_launch.unwrap_or_else(|| {
            crate::session_creator::empty_session_launch(self.tx.headless_server())
        });
        let mut occupied = self
            .known_sessions()
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        let base_window_id = format!("{}-window-{now}", project.project_id);
        let layouts = maestro_shell::WindowLayoutService::new(&self.paths);
        for attempt in 0..REMOTE_SESSION_ID_ATTEMPTS {
            let session_id = crate::session_creator::generate_session_id(rand::random::<u8>);
            if !occupied.insert(session_id.clone()) {
                continue;
            }
            // The viewport lease precedes every durable candidate. A conflict/error drops it;
            // only a successfully queued daemon start commits it.
            let creation_lease = self
                .tx
                .begin_remote_creation_lease(&session_id, now)
                .map_err(|_| crate::remote_control::NewWindowError::Internal)?;
            let window_id = if attempt == 0 {
                base_window_id.clone()
            } else {
                format!(
                    "{}-{}",
                    base_window_id,
                    crate::session_creator::generate_session_id(rand::random::<u8>)
                )
            };
            let workspace_id = format!("{window_id}-workspace");
            let workspace = maestro_shell::Workspace {
                workspace_id,
                project_id: project.project_id.clone(),
                root: root.clone(),
                policy: maestro_shell::WorkspacePolicy::ScratchCwd,
                consent: maestro_shell::WorkspaceConsent::default(),
            };
            let (session, launch_environment) = prepared_remote_session_spec(
                &self.tx,
                &workspace,
                &session_id,
                &root,
                kind,
                &launch,
                initial_size,
                now,
            )
            .map_err(|_| crate::remote_control::NewWindowError::DaemonUnavailable)?;
            let spec = maestro_shell::PreparedFreshWindowGraphSpec {
                workspace,
                session,
                window_id: window_id.clone(),
                window_name: title.clone(),
                tab_id: "pane-1".into(),
                tab_title: agent_title(&agent).into(),
                tab_pinned: false,
                tab_attention: maestro_shell::AttentionState::default(),
                touch_project: false,
            };
            let created = match layouts
                .create_prepared_fresh_window_graph(&project_snapshot, spec)
                .map_err(|_| crate::remote_control::NewWindowError::Internal)?
            {
                maestro_shell::PreparedFreshWindowGraphCreateOutcome::Created(created) => created,
                maestro_shell::PreparedFreshWindowGraphCreateOutcome::ProjectMissing { .. } => {
                    return Err(crate::remote_control::NewWindowError::ProjectNotFound);
                }
                maestro_shell::PreparedFreshWindowGraphCreateOutcome::ProjectChanged { .. } => {
                    return Err(crate::remote_control::NewWindowError::Internal);
                }
                maestro_shell::PreparedFreshWindowGraphCreateOutcome::Conflict(_) => continue,
            };
            let started = match start_prepared_remote_session(
                &self.tx,
                &self.paths,
                created.start,
                launch_environment,
            ) {
                Ok(started) => started,
                Err(error) => {
                    compensate_prepared_remote_start_error(
                        &self.tx,
                        &self.sessions,
                        &self.paths,
                        error,
                        now,
                        "remote new_window start",
                    );
                    return Err(crate::remote_control::NewWindowError::DaemonUnavailable);
                }
            };
            let (record, compensation) = started.into_parts();
            if record.status != maestro_shell::SessionStatus::Live
                || record.last_known_generation.is_none()
            {
                consume_prepared_compensation_outcome(
                    &self.tx,
                    &self.sessions,
                    &self.paths,
                    layouts
                        .compensate_prepared_new_session(compensation, now)
                        .map_err(|_| crate::remote_control::NewWindowError::Internal)?,
                    "remote new_window invalid publication",
                );
                return Err(crate::remote_control::NewWindowError::Internal);
            }
            drop(compensation);
            if let Ok(mut sessions) = self.sessions.lock() {
                sessions.reserve(&session_id);
            }
            creation_lease.commit();
            return Ok(crate::remote_control::NewWindowCreated {
                window_id,
                session_id,
            });
        }
        Err(crate::remote_control::NewWindowError::Internal)
    }
}

impl DaemonWindowOpener {
    fn known_sessions(&self) -> Vec<String> {
        self.sessions
            .lock()
            .map(|s| s.snapshot())
            .unwrap_or_default()
    }
}

/// A real remote project editor: write the same project metadata records the local dashboard form owns.
pub struct DaemonProjectEditor {
    tx: DaemonRequestSender,
    sessions: SharedSessions,
    paths: maestro_shell::AppPaths,
}

impl crate::remote_control::ProjectEditor for DaemonProjectEditor {
    fn create_project(
        &mut self,
        request: crate::remote_control::ProjectEditRequest,
    ) -> Result<crate::remote_control::ProjectEdited, crate::remote_control::ProjectEditError> {
        self.create_project_with_initial_size(request, InitialTerminalSize::default())
    }

    fn create_project_with_initial_size(
        &mut self,
        request: crate::remote_control::ProjectEditRequest,
        initial_size: InitialTerminalSize,
    ) -> Result<crate::remote_control::ProjectEdited, crate::remote_control::ProjectEditError> {
        // Project creation seeds and starts its first pane. The protocol gate must precede the
        // ProjectService write; otherwise a legacy daemon refusal would leave a durable but dead
        // project/window/session hierarchy behind.
        if !start_session_mutations_allowed(&self.sessions) {
            return Err(crate::remote_control::ProjectEditError::Internal);
        }
        let name = required_project_field(request.name.as_deref())
            .ok_or(crate::remote_control::ProjectEditError::InvalidName)?;
        let root = required_project_field(request.root.as_deref())
            .ok_or(crate::remote_control::ProjectEditError::InvalidRoot)?;
        let known_sessions = self
            .known_sessions()?
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        let project_id =
            pick_remote_project_id(&name, request.now_ms, &self.paths, &known_sessions)
                .ok_or(crate::remote_control::ProjectEditError::Internal)?;
        let seeded_session_id = default_remote_project_pane_session_id(&project_id);
        // Project create is one logical remote allocation. Establish the session's bounded viewport authority
        // before even the ProjectRecord becomes observable, then retain the same guard through project,
        // workspace, session, layout, and daemon-start publication.
        let creation_lease = self
            .tx
            .begin_remote_creation_lease(&seeded_session_id, request.now_ms)
            .map_err(|_| crate::remote_control::ProjectEditError::Internal)?;
        // Capture the seeding inputs before the fields move into launch_defaults: the FIRST pane honors the
        // form's launch choices (resume target / resume policy / model / dangerous), Tier-1 item 6.
        let seed = SeedLaunchInputs {
            agent: request.agent.clone(),
            resume_mode: request.resume_mode.clone(),
            resume_session_id: request.resume_session_id.clone(),
            model: request.model.clone(),
            dangerous: request.dangerous.unwrap_or(false),
        };
        // Build defaultLaunchFlags from any provided launch defaults (agent / resume_mode / model / dangerous /
        // custom_command). An empty custom_command clears it (None at the record level).
        let custom_command = request.custom_command.filter(|c| !c.is_empty());
        let launch_defaults = (request.agent.is_some()
            || request.resume_mode.is_some()
            || request.model.is_some()
            || request.dangerous.is_some()
            || custom_command.is_some())
        .then_some(maestro_shell::ProjectLaunchDefaults {
            agent: request.agent,
            resume_mode: request.resume_mode,
            model: request.model,
            dangerous_skip_permissions: request.dangerous,
            custom_command,
        });
        let directories = request.directories.map(dirs_to_records).unwrap_or_default();
        let project_opts = maestro_shell::NewProject {
            icon: request.icon,
            accent_color: request.accent_color,
            launch_defaults,
            directories,
            ..Default::default()
        };
        let prepared = self.prepare_initial_window_and_pane(
            &project_id,
            &root,
            &seed,
            initial_size,
            request.now_ms,
        )?;
        let seeded_session_id = prepared.session_id.clone();
        let layouts = maestro_shell::WindowLayoutService::new(&self.paths);
        let created = match layouts
            .create_prepared_fresh_project_window_graph(
                &project_id,
                name,
                root,
                project_opts,
                prepared.spec,
            )
            .map_err(|_| crate::remote_control::ProjectEditError::Internal)?
        {
            maestro_shell::PreparedFreshWindowGraphCreateOutcome::Created(created) => created,
            maestro_shell::PreparedFreshWindowGraphCreateOutcome::Conflict(_)
            | maestro_shell::PreparedFreshWindowGraphCreateOutcome::ProjectMissing { .. }
            | maestro_shell::PreparedFreshWindowGraphCreateOutcome::ProjectChanged { .. } => {
                return Err(crate::remote_control::ProjectEditError::Internal);
            }
        };
        let started = match start_prepared_remote_session(
            &self.tx,
            &self.paths,
            created.start,
            prepared.launch_environment,
        ) {
            Ok(started) => started,
            Err(error) => {
                compensate_prepared_remote_start_error(
                    &self.tx,
                    &self.sessions,
                    &self.paths,
                    error,
                    request.now_ms,
                    "remote create_project start",
                );
                return Err(crate::remote_control::ProjectEditError::Internal);
            }
        };
        let (record, compensation) = started.into_parts();
        if record.status != maestro_shell::SessionStatus::Live
            || record.last_known_generation.is_none()
        {
            consume_prepared_compensation_outcome(
                &self.tx,
                &self.sessions,
                &self.paths,
                layouts
                    .compensate_prepared_new_session(compensation, request.now_ms)
                    .map_err(|_| crate::remote_control::ProjectEditError::Internal)?,
                "remote create_project invalid publication",
            );
            return Err(crate::remote_control::ProjectEditError::Internal);
        }
        drop(compensation);
        if let Ok(mut live) = self.sessions.lock() {
            live.reserve(&seeded_session_id);
        }
        creation_lease.commit();
        Ok(crate::remote_control::ProjectEdited {
            project_id,
            session_id: Some(seeded_session_id),
        })
    }

    fn update_project(
        &mut self,
        request: crate::remote_control::ProjectEditRequest,
    ) -> Result<crate::remote_control::ProjectEdited, crate::remote_control::ProjectEditError> {
        let project_id = request
            .project_id
            .clone()
            .ok_or(crate::remote_control::ProjectEditError::ProjectNotFound)?;
        // Fail closed for stale/older browsers that learned the private recovery id before it was
        // filtered from workspace metadata. Mutating this record breaks desktop recovery startup.
        if project_id == PRODUCT_RECOVERY_PROJECT_ID {
            return Err(crate::remote_control::ProjectEditError::ProjectNotFound);
        }
        let existing = maestro_shell::ProjectService::new(&self.paths)
            .load(&project_id)
            .map_err(map_project_edit_error)?
            .ok_or(crate::remote_control::ProjectEditError::ProjectNotFound)?;
        let launch_defaults = (request.agent.is_some()
            || request.resume_mode.is_some()
            || request.model.is_some()
            || request.dangerous.is_some()
            || request.custom_command.is_some())
        .then(|| {
            let mut defaults = existing.launch_defaults.clone().unwrap_or_default();
            if request.agent.is_some() {
                defaults.agent = request.agent;
            }
            if request.resume_mode.is_some() {
                defaults.resume_mode = request.resume_mode;
            }
            if request.model.is_some() {
                defaults.model = request.model;
            }
            if request.dangerous.is_some() {
                defaults.dangerous_skip_permissions = request.dangerous;
            }
            if let Some(cmd) = request.custom_command {
                // empty string clears the custom command; non-empty sets it.
                defaults.custom_command = (!cmd.is_empty()).then_some(cmd);
            }
            defaults
        });
        maestro_shell::ProjectService::new(&self.paths)
            .update(
                &project_id,
                maestro_shell::ProjectUpdate {
                    name: request.name,
                    root: request.root,
                    icon: request.icon.map(Some),
                    accent_color: request.accent_color.map(Some),
                    launch_defaults: launch_defaults.map(Some),
                    // None = unchanged; Some(list) = replace (Some([]) clears).
                    directories: request.directories.map(dirs_to_records),
                    ..Default::default()
                },
                request.now_ms,
            )
            .map_err(map_project_edit_error)?;
        // Update never seeds a pane → no session id on the reply (the wire key stays absent).
        Ok(crate::remote_control::ProjectEdited {
            project_id,
            session_id: None,
        })
    }

    fn delete_project(
        &mut self,
        project_id: String,
        now_ms: u64,
    ) -> Result<crate::remote_control::ProjectEdited, crate::remote_control::ProjectEditError> {
        if project_id == PRODUCT_RECOVERY_PROJECT_ID {
            return Err(crate::remote_control::ProjectEditError::ProjectNotFound);
        }
        let projects = maestro_shell::ProjectService::new(&self.paths);
        let plan = projects
            .plan_delete(&project_id)
            .map_err(map_project_edit_error)?;
        if !plan.project_exists {
            return Err(crate::remote_control::ProjectEditError::ProjectNotFound);
        }
        let mut client = if plan.kill_session_ids.is_empty() {
            None
        } else {
            Some(
                connect_reviewed_daemon_client(&self.tx)
                    .map_err(|_| crate::remote_control::ProjectEditError::DaemonUnavailable)?,
            )
        };
        let pre_resolved = match client.as_mut() {
            Some(client) => maestro_shell::pre_resolve_session_generations(
                client,
                plan.unresolved_release_session_ids(),
            )
            .map_err(|_| crate::remote_control::ProjectEditError::DaemonUnavailable)?,
            None => maestro_shell::PreResolvedSessionGenerations::new(),
        };
        let removed = projects
            .commit_delete_preserving_global_last(&plan, &pre_resolved, now_ms)
            .map_err(map_project_edit_error)?;
        if !removed.removed {
            return Err(crate::remote_control::ProjectEditError::ProjectNotFound);
        }

        let mut confirmed_session_ids = Vec::new();
        if let Some(receipt) = removed.release_receipt {
            let Some(client) = client.as_mut() else {
                // Every non-empty release receipt is durable and remains recoverable. This branch
                // is defensive because a non-empty kill cohort opened a reviewed client above.
                tracing::warn!("project release was journaled without a reviewed daemon client");
                return Ok(crate::remote_control::ProjectEdited {
                    project_id,
                    session_id: None,
                });
            };
            let release = maestro_shell::SessionReleaseService::new(&self.paths)
                .attempt_owned_with_daemon(receipt, client);
            confirmed_session_ids.extend(
                release
                    .confirmed_lifetimes()
                    .iter()
                    .map(|target| target.session_id().to_string()),
            );
            if !matches!(
                release.outcome(),
                maestro_shell::ReleaseOperationOutcome::Complete { .. }
            ) {
                tracing::warn!("project session release remains in the durable forward journal");
            }
        }
        if !confirmed_session_ids.is_empty() {
            if let Ok(mut live) = self.sessions.lock() {
                live.remove(&confirmed_session_ids);
            }
        }
        Ok(crate::remote_control::ProjectEdited {
            project_id,
            session_id: None,
        })
    }
}

/// The New Project form's launch choices, captured off the ProjectEditRequest for seeding the FIRST pane
/// (Tier-1 item 6). custom_command is deliberately absent: free-form exec stays desktop-only (it is already
/// persisted into the project's launch_defaults); remote seeding is constrained to KnownSafe argv.
struct SeedLaunchInputs {
    agent: Option<String>,
    /// Desktop vocabulary: "resume" | "continue" | "none" (legacy "new" tolerated as fresh).
    resume_mode: Option<String>,
    resume_session_id: Option<String>,
    model: Option<String>,
    dangerous: bool,
}

/// Fully prepared first-pane graph. No durable row exists while this value is built, and dropping
/// it cancels the reserved daemon queue ticket. The shell service publishes all records together.
struct PreparedInitialProjectGraph {
    spec: maestro_shell::PreparedFreshWindowGraphSpec,
    session_id: String,
    launch_environment: RemoteLaunchEnvironment,
}

impl DaemonProjectEditor {
    fn known_sessions(&self) -> Result<Vec<String>, crate::remote_control::ProjectEditError> {
        self.sessions
            .lock()
            .map(|sessions| sessions.snapshot())
            .map_err(|_| crate::remote_control::ProjectEditError::Internal)
    }

    /// Prepare the first pane without publishing either its daemon request or any durable row.
    fn prepare_initial_window_and_pane(
        &self,
        project_id: &str,
        root: &str,
        inputs: &SeedLaunchInputs,
        initial_size: InitialTerminalSize,
        now: u64,
    ) -> Result<PreparedInitialProjectGraph, crate::remote_control::ProjectEditError> {
        if !start_session_mutations_allowed(&self.sessions) {
            return Err(crate::remote_control::ProjectEditError::Internal);
        }
        let window_id = default_remote_project_window_id(project_id);
        let workspace_id = default_remote_project_workspace_id(project_id);
        let session_id = default_remote_project_pane_session_id(project_id);
        let pane_id = "pane-1";
        let agent = inputs.agent.as_deref().unwrap_or("claude").to_string();
        // A "terminal" project seeds a plain pane: no resume/model/dangerous argv (same rule as new_window).
        let is_terminal = agent.eq_ignore_ascii_case("terminal");
        // Base argv from the form's resume policy, the same content-blind pattern new_window uses:
        //   'resume' + a picked session id → the agent's resume argv (Gemini's local session file resolved
        //   desktop-side against the project root; an unresolvable target falls back to fresh);
        //   'continue' → `{agent} --continue`;
        //   'none' / legacy 'new' / absent → fresh.
        let resume_mode = inputs.resume_mode.as_deref().unwrap_or("none");
        let mut start_launch: Option<crate::resume_launch::ResumeLaunch> = if is_terminal {
            None
        } else {
            match resume_mode {
                "resume" => inputs
                    .resume_session_id
                    .as_deref()
                    .and_then(|sid| {
                        crate::remote_control::resume_descriptor_from_launch_flags(
                            Some(agent.clone()),
                            Some(serde_json::json!({
                                "resumeMode": "resume",
                                "resumeSessionId": sid,
                            })),
                        )
                    })
                    .and_then(|mut descriptor| {
                        crate::remote_control::resolve_gemini_resume_file(
                            &mut descriptor,
                            Some(root),
                        );
                        crate::resume_launch::build_resume_launch(&descriptor)
                    }),
                "continue" => continue_remote_agent_launch(&agent),
                _ => None,
            }
        };
        // Model NAME (a plain request field here, unlike the launch_flags paths — same strict argv-safe
        // sanitizer) rides the launch as the discrete ["--model", <name>] pair; the per-agent dangerous flag
        // is appended AFTER the model args. Either one upgrades a fresh launch to an explicit argv so the
        // record and the start line stay identical.
        let model = if is_terminal {
            None
        } else {
            inputs
                .model
                .as_deref()
                .and_then(crate::remote_control::sanitize_model_name)
        };
        // Record/launch parity (same fix as split_pane/new_window): a fresh EXPLICIT agent must actually be
        // launched — the record below says KnownSafe{agent, ...}, so the seeded pane's PTY must run the
        // agent, not a bare shell. Model/dangerous still upgrade an inherited-default agent to an explicit
        // launch (pre-existing); an ABSENT form agent with no flags keeps the bare-shell start (unchanged).
        if !is_terminal
            && start_launch.is_none()
            && (inputs.agent.is_some() || model.is_some() || inputs.dangerous)
        {
            start_launch = fresh_remote_agent_launch(&agent, None, false);
        }
        if let (Some(launch), Some(model)) = (start_launch.as_mut(), model.as_deref()) {
            append_remote_model(launch, &agent, model);
        }
        if inputs.dangerous && !is_terminal {
            if let Some(launch) = start_launch.as_mut() {
                append_remote_dangerous_flag(launch, &agent, true);
            }
        }
        let workspace = maestro_shell::Workspace {
            workspace_id: workspace_id.clone(),
            project_id: project_id.to_string(),
            root: root.to_string(),
            policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            consent: maestro_shell::WorkspaceConsent::default(),
        };
        let kind = if is_terminal {
            maestro_shell::SessionKind::Shell
        } else {
            maestro_shell::SessionKind::Agent
        };
        let launch = start_launch.unwrap_or_else(|| {
            crate::session_creator::empty_session_launch(self.tx.headless_server())
        });
        let (session, launch_environment) = prepared_remote_session_spec(
            &self.tx,
            &workspace,
            &session_id,
            root,
            kind,
            &launch,
            initial_size,
            now,
        )
        .map_err(|_| crate::remote_control::ProjectEditError::Internal)?;

        Ok(PreparedInitialProjectGraph {
            spec: maestro_shell::PreparedFreshWindowGraphSpec {
                workspace,
                session,
                window_id,
                window_name: "Window 1".into(),
                tab_id: pane_id.into(),
                tab_title: "Pane 1".into(),
                tab_pinned: false,
                tab_attention: maestro_shell::AttentionState::default(),
                touch_project: false,
            },
            session_id,
            launch_environment,
        })
    }
}

fn required_project_field(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

/// Convert sanitized wire directories into desktop ProjectDirectory records, minting a stable, deterministic id
/// per entry (slug of path + index — no Date/random, so it's resume-safe and reproducible).
fn dirs_to_records(
    dirs: Vec<crate::remote_control::ProjectDirectoryWire>,
) -> Vec<maestro_shell::ProjectDirectory> {
    dirs.into_iter()
        .enumerate()
        .map(|(i, d)| {
            let slug: String = d
                .path
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() {
                        c.to_ascii_lowercase()
                    } else {
                        '-'
                    }
                })
                .collect::<String>()
                .trim_matches('-')
                .chars()
                .take(40)
                .collect();
            maestro_shell::ProjectDirectory {
                id: format!("dir-{i}-{slug}"),
                name: d.name,
                path: d.path,
            }
        })
        .collect()
}

fn pick_remote_project_id(
    name: &str,
    now_ms: u64,
    paths: &maestro_shell::AppPaths,
    known_sessions: &std::collections::HashSet<String>,
) -> Option<String> {
    let slug = slug_project_name(name);
    let base = format!("proj-{slug}-{now_ms}");
    for attempt in 0..=10 {
        let candidate = if attempt == 0 {
            base.clone()
        } else {
            format!(
                "{base}-{}",
                crate::session_creator::generate_session_id(rand::random::<u8>)
            )
        };
        if known_sessions.contains(&default_remote_project_pane_session_id(&candidate)) {
            continue;
        }
        if matches!(
            maestro_shell::ProjectService::new(paths).load(&candidate),
            Ok(None)
        ) {
            return Some(candidate);
        }
    }
    None
}

fn slug_project_name(name: &str) -> String {
    let mut out = String::new();
    for ch in name.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
        } else if (ch.is_ascii_whitespace() || ch == '-' || ch == '_') && !out.ends_with('-') {
            out.push('-');
        }
        if out.len() >= 40 {
            break;
        }
    }
    let out = out.trim_matches('-').to_string();
    if out.is_empty() {
        "project".to_string()
    } else {
        out
    }
}

fn default_remote_project_workspace_id(project_id: &str) -> String {
    format!("{project_id}-workspace")
}

fn default_remote_project_window_id(project_id: &str) -> String {
    format!("{project_id}-window-1")
}

fn default_remote_project_pane_session_id(project_id: &str) -> String {
    format!("{project_id}-pane-1")
}

fn map_project_edit_error(
    e: maestro_shell::ProjectServiceError,
) -> crate::remote_control::ProjectEditError {
    match e {
        maestro_shell::ProjectServiceError::ProjectNotFound { .. } => {
            crate::remote_control::ProjectEditError::ProjectNotFound
        }
        maestro_shell::ProjectServiceError::InvalidField { field, .. } if field == "name" => {
            crate::remote_control::ProjectEditError::InvalidName
        }
        maestro_shell::ProjectServiceError::InvalidField { .. } => {
            crate::remote_control::ProjectEditError::Internal
        }
        maestro_shell::ProjectServiceError::GloballyLastVisibleWindow { .. } => {
            crate::remote_control::ProjectEditError::GloballyLastVisible
        }
        _ => crate::remote_control::ProjectEditError::Internal,
    }
}

impl SessionBackend for DaemonBackend {
    fn list_sessions(&self) -> Vec<String> {
        let mut ids = std::collections::BTreeSet::<String>::new();
        if let Ok(sessions) = self.sessions.lock() {
            ids.extend(sessions.snapshot());
        }
        // The daemon's in-memory `sessions` cache updates only when this connection observes a daemon
        // Sessions event/reply. A desktop-created project can write its SessionRecord as `Live` before this
        // connection has refreshed that cache, so a live-sync poll would keep redacting the pane forever until a
        // page refresh. Merge the same SQLite dashboard truth used for workspace metadata so existing connections
        // see the newly-live pane on their next poll.
        if let Some(paths) = self.dashboard_paths.as_ref() {
            ids.extend(live_session_ids_from_dashboard(paths));
        }
        // The private startup fallback may be live in the daemon cache even though its project is never
        // remotely visible. Do not advertise a directly attachable orphan after filtering its topology.
        ids.remove(PRODUCT_RECOVERY_SESSION_ID);
        ids.into_iter().collect()
    }
    fn session_metadata(&self) -> Vec<SessionMetadata> {
        self.session_metadata
            .lock()
            .map(|s| s.clone())
            .unwrap_or_default()
    }
    fn workspace_metadata(&self) -> Option<WorkspaceMetadata> {
        let paths = self.dashboard_paths.as_ref()?;
        workspace_metadata_from_dashboard(paths)
    }
    fn attach(&mut self, id: &str, _cols: u16, _rows: u16, raw: bool) -> Result<(), String> {
        // FALSE → STRUCTURED Grid + Damage (the canvas renderer paints those). TRUE → raw PTY bytes as
        // `Output` events for the xterm.js renderer. The CLIENT picks per attach (raw flag in the attach
        // message); this also records the mode so the reader drops structured frames in raw mode.
        // HONEST attach: a dropped daemon channel (the async task/socket is gone) means the attach can never
        // deliver output — surface it so the bridge replies `attach_failed` instead of a false attach_ok the
        // browser would wait on forever. Content-blind: a fixed reason, no id/payload in the error.
        self.send_attach(id, raw, None, None)
    }
    fn attach_with_output_generation(
        &mut self,
        id: &str,
        cols: u16,
        rows: u16,
        raw: bool,
        output_generation: u64,
        deferred_resize_authority: Option<crate::winsize_owner::DeferredResizeAuthority>,
    ) -> Result<(), String> {
        self.send_attach(
            id,
            raw,
            Some(output_generation),
            deferred_resize_authority.map(|authority| (cols, rows, authority)),
        )
    }
    fn input(&mut self, id: &str, bytes: &[u8]) -> Result<(), String> {
        let data = String::from_utf8_lossy(bytes);
        let routes = self
            .output_routes
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let DaemonMutationRoute::Confirmed(output_generation) = routes.mutation_route(id) else {
            return Err("terminal attach generation unconfirmed".to_string());
        };
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| "terminal generation unavailable".to_string())?;
        let generation = sessions
            .generation_for_mutation(id, output_generation)
            .ok_or_else(|| "terminal generation unavailable".to_string())?;
        let request = maestro_protocol::ClientRequest::Write {
            id: maestro_protocol::SessionId(id.to_string()),
            expected_generation: generation,
            data: data.into_owned(),
        };
        self.tx
            .send(
                serde_json::to_string(&request)
                    .map_err(|_| "daemon request encoding failed".to_string())?,
            )
            .map_err(|_| "daemon connection unavailable".to_string())
    }
    fn resize(&mut self, id: &str, cols: u16, rows: u16) -> Result<(), String> {
        self.resize_with_admission(id, cols, rows).map(|_| ())
    }
    fn resize_with_admission(
        &mut self,
        id: &str,
        cols: u16,
        rows: u16,
    ) -> Result<ResizeAdmission, String> {
        // Resize participates in the active structured attach's ordered pre-size contract. Be as honest as
        // attach: if the daemon writer is gone, report failure instead of claiming the first Grid can use these
        // dimensions. Ordinary post-attach resizes also benefit from a real `resize_failed` reply.
        let routes = self
            .output_routes
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| "terminal generation unavailable".to_string())?;
        if !sessions.generation_conditional_mutations_allowed() {
            return Err("terminal mutation unsupported".to_string());
        }
        let output_generation = match routes.mutation_route(id) {
            DaemonMutationRoute::Pending(output_generation) => {
                let mut pending = self
                    .pending_attach_sizes
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                let Some(size) = pending.get_mut(id) else {
                    return Err("terminal attach generation unconfirmed".to_string());
                };
                if size.output_generation != output_generation {
                    return Err("terminal attach generation unconfirmed".to_string());
                }
                if !size.authority.update_geometry_if_current(cols, rows) {
                    return Err("terminal winsize authority changed".to_string());
                }
                size.cols = cols;
                size.rows = rows;
                return Ok(ResizeAdmission::Deferred);
            }
            DaemonMutationRoute::Confirmed(output_generation) => output_generation,
            DaemonMutationRoute::Unavailable => {
                return Err("terminal attach generation unconfirmed".to_string())
            }
        };
        let generation = sessions
            .generation_for_mutation(id, output_generation)
            .ok_or_else(|| "terminal generation unavailable".to_string())?;
        let request = maestro_protocol::ClientRequest::Resize {
            id: maestro_protocol::SessionId(id.to_string()),
            expected_generation: generation,
            cols,
            rows,
        };
        self.tx
            .send(
                serde_json::to_string(&request)
                    .map_err(|_| "daemon request encoding failed".to_string())?,
            )
            .map_err(|_| "daemon connection unavailable".to_string())?;
        Ok(ResizeAdmission::Queued)
    }
    fn scrollback(&mut self, id: &str, offset_from_top: u32, count: u16) -> Result<(), String> {
        // daemon `Scrollback` → it replies with a ScrollbackRows event (routed back as terminal_output).
        self.send(
            serde_json::json!({ "op": "scrollback", "id": id, "offset_from_top": offset_from_top, "count": count })
                .to_string(),
        )
    }
    fn detach(&mut self, id: &str) {
        let mut routes = self
            .output_routes
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        routes.detach(id);
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.live_generations.remove(id);
        }
        if let Some(pending) = self
            .pending_attach_sizes
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(id)
        {
            pending.authority.cancel();
        }
        let _ = self
            .tx
            .send(serde_json::json!({ "op": "detach", "id": id }).to_string());
    }
}

/// Connect the daemon socket and spawn the async task that owns it. Returns the sync `DaemonBackend` (for
/// the bridge) + a receiver of daemon OUTPUT lines (for the peer to frame). `seed_sessions` is the live id
/// set the bridge lists until the async task observes a fresh `Sessions` event.
///
/// The task: writes enqueued request lines; reads daemon event lines; for each output-bearing line that
/// carries a session id, forwards it as `DaemonOutput`; updates the session set on `Sessions` events.
/// The desktop app's CURRENTLY-published daemon socket (from `<MAESTRO_APP_SUPPORT_DIR>/daemon/endpoint.json`), or
/// `fallback` if none is published / the env var is unset. The app republishes a NEW socket on every restart/window
/// cycle, so a per-session connect must re-read this rather than trust a path captured at process start (which goes
/// stale → `os error 2` on connect). Mirrors supervise::live_daemon_socket / main::resolve_desktop_daemon_sock.
pub fn current_daemon_socket(fallback: &std::path::Path) -> PathBuf {
    let Some(base) = std::env::var_os("MAESTRO_APP_SUPPORT_DIR") else {
        return fallback.to_path_buf();
    };
    if base.is_empty() {
        return fallback.to_path_buf();
    }
    let paths = maestro_shell::AppPaths::with_base(PathBuf::from(base));
    match maestro_shell::load_endpoint(&paths) {
        Ok(Some(ep)) if !ep.socket_path.trim().is_empty() => PathBuf::from(ep.socket_path),
        _ => fallback.to_path_buf(),
    }
}

const DAEMON_INFO_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(750);

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReviewedDaemonAuthority {
    socket_path: PathBuf,
    server_pid: Option<u32>,
}

/// Open an auxiliary synchronous client only against the exact daemon already reviewed for the
/// operational remote stream.  The socket path alone is not authority: on Linux a replacement
/// listener must also have the same kernel-authenticated PID captured from that stream.
fn connect_reviewed_daemon_client(
    tx: &DaemonRequestSender,
) -> Result<maestro_shell::DaemonClient, maestro_shell::DaemonClientError> {
    let authority = tx.reviewed_daemon_authority().ok_or_else(|| {
        maestro_shell::DaemonClientError::Protocol {
            detail: "reviewed remote daemon authority is unavailable".into(),
        }
    })?;
    let client = maestro_shell::DaemonClient::connect(&authority.socket_path)?;
    if authority
        .server_pid
        .is_some_and(|expected| client.server_pid() != Some(expected))
    {
        return Err(maestro_shell::DaemonClientError::Protocol {
            detail: "remote daemon process changed after operational peer review".into(),
        });
    }
    Ok(client)
}

struct RemoteLaunchEnvironment {
    shell: Option<String>,
    home: Option<std::ffi::OsString>,
    child_environment: Option<maestro_protocol::ChildEnvironment>,
}

impl maestro_shell::LaunchEnvLookup for RemoteLaunchEnvironment {
    fn shell_utf8(&self) -> Option<String> {
        self.shell.clone()
    }

    fn home_os(&self) -> Option<std::ffi::OsString> {
        self.home.clone()
    }
}

fn remote_launch_environment(
    tx: &DaemonRequestSender,
) -> Result<RemoteLaunchEnvironment, maestro_shell::DaemonClientError> {
    if !tx.headless_server() {
        return Ok(RemoteLaunchEnvironment {
            shell: std::env::var("SHELL").ok(),
            home: std::env::var_os("HOME"),
            child_environment: None,
        });
    }
    let account = crate::agent_dir::trusted_session_account().map_err(|_| {
        maestro_shell::DaemonClientError::Protocol {
            detail: "trusted headless session account is unavailable".into(),
        }
    })?;
    let home = account
        .home
        .to_str()
        .ok_or_else(|| maestro_shell::DaemonClientError::Protocol {
            detail: "trusted headless HOME is not UTF-8".into(),
        })?
        .to_string();
    Ok(RemoteLaunchEnvironment {
        shell: Some(account.shell.clone()),
        home: Some(account.home.into_os_string()),
        child_environment: Some(maestro_protocol::ChildEnvironment {
            home,
            shell: account.shell,
        }),
    })
}

fn connect_reviewed_conditional_start_client(
    tx: &DaemonRequestSender,
) -> Result<
    (
        maestro_shell::DaemonClient,
        maestro_shell::ConditionalStartPeerIdentity,
    ),
    maestro_shell::DaemonClientError,
> {
    let mut client = connect_reviewed_daemon_client(tx)?;
    let peer = client.conditional_start_peer_identity()?;
    Ok((client, peer))
}

fn runtime_remote_session_launch(
    launch: Option<&crate::resume_launch::ResumeLaunch>,
    headless_server: bool,
) -> crate::resume_launch::ResumeLaunch {
    match launch {
        Some(launch) if is_remote_agent_command(&launch.command) => {
            login_shell_launch(&launch.command, &launch.args, headless_server)
        }
        Some(launch) => launch.clone(),
        None => crate::session_creator::empty_session_launch(headless_server),
    }
}

fn prepared_remote_session_spec(
    tx: &DaemonRequestSender,
    workspace: &maestro_shell::Workspace,
    session_id: &str,
    cwd: &str,
    kind: maestro_shell::SessionKind,
    launch: &crate::resume_launch::ResumeLaunch,
    initial_size: InitialTerminalSize,
    now_ms: u64,
) -> Result<
    (maestro_shell::PreparedSessionSpec, RemoteLaunchEnvironment),
    maestro_shell::DaemonClientError,
> {
    let launch_environment = remote_launch_environment(tx)?;
    let prepared_workspace = maestro_shell::PreparedWorkspace::unsealed(
        workspace.policy,
        workspace.workspace_id.clone(),
        session_id,
        PathBuf::from(cwd),
    );
    let mut argv = Vec::with_capacity(1 + launch.args.len());
    argv.push(launch.command.clone());
    argv.extend(launch.args.iter().cloned());
    let spec = if kind == maestro_shell::SessionKind::Agent
        && maestro_shell::is_strict_prepared_provider_launch(&launch.command, &argv)
    {
        prepared_workspace.provider_session_spec(
            &launch.command,
            &argv,
            &launch_environment,
            initial_size.cols(),
            initial_size.rows(),
            now_ms,
        )
    } else {
        prepared_workspace.adhoc_session_spec_with_env(
            kind,
            &argv,
            &launch_environment,
            initial_size.cols(),
            initial_size.rows(),
            now_ms,
        )
    }
    .map_err(|_| maestro_shell::DaemonClientError::Protocol {
        detail: "remote prepared launch is outside the sealed launch contract".into(),
    })?;
    Ok((spec, launch_environment))
}

fn start_remote_session_with_grid(
    tx: &DaemonRequestSender,
    session_id: &str,
    cwd: &str,
    launch: Option<&crate::resume_launch::ResumeLaunch>,
    initial_size: InitialTerminalSize,
    precondition: maestro_protocol::SessionStartPrecondition,
) -> Result<String, maestro_shell::DaemonClientError> {
    let launch_environment = remote_launch_environment(tx)?;
    let (mut client, peer) = connect_reviewed_conditional_start_client(tx)?;
    let launch = runtime_remote_session_launch(launch, tx.headless_server());
    let (attached, recovery) = client.start_and_attach_conditionally_with_environment(
        maestro_protocol::SessionId(session_id.to_string()),
        cwd,
        &launch.command,
        &launch.args,
        launch_environment.child_environment,
        initial_size.cols(),
        initial_size.rows(),
        precondition,
        &peer,
    )?;
    let generation = attached.generation;
    if recovery.grid_proven_generation() != Some(generation.as_str())
        || recovery.operation_applied_generation() != Some(generation.as_str())
    {
        return Err(maestro_shell::DaemonClientError::Protocol {
            detail: "remote conditional Start returned mismatched operation/Grid authority".into(),
        });
    }
    match client.retire_applied_start_operation_in_place(&recovery, &generation) {
        Ok(
            maestro_protocol::SessionStartOperationRetireOutcome::Retired
            | maestro_protocol::SessionStartOperationRetireOutcome::AlreadyRetired,
        ) => {}
        Ok(maestro_protocol::SessionStartOperationRetireOutcome::Conflict { .. }) | Err(_) => {
            // Grid is already authoritative, so returning an error here would hide a live PTY
            // from the browser. Keep the existing record-less success contract and surface the
            // failed retirement in telemetry; recovery ownership is not retained by this path.
            tracing::warn!("remote conditional Start ledger retirement remains pending");
        }
    }
    Ok(generation)
}

/// Drain at most one crash-recovered release operation.  The durable journal owns retry; this
/// bounded worker never loops on one unavailable daemon and never needs maestro-app to be alive.
fn drain_one_pending_session_release(
    tx: &DaemonRequestSender,
    sessions: &SharedSessions,
    paths: &maestro_shell::AppPaths,
) {
    let service = maestro_shell::SessionReleaseService::new(paths);
    let claim = match service.claim_next() {
        Ok(Some(claim)) => claim,
        Ok(None) => return,
        Err(_) => {
            tracing::warn!("could not claim pending remote session release");
            return;
        }
    };
    let attempt = match connect_reviewed_daemon_client(tx) {
        Ok(mut client) => service.attempt_claimed_with_daemon(claim, &mut client),
        Err(error) => service.attempt_claimed_with_daemon_unavailable(claim, error),
    };
    let (outcome, confirmed) = attempt.into_parts();
    let confirmed_ids = confirmed
        .iter()
        .map(|target| target.session_id().to_string())
        .collect::<Vec<_>>();
    if !confirmed_ids.is_empty() {
        if let Ok(mut cache) = sessions.lock() {
            cache.remove(&confirmed_ids);
        }
    }
    if !matches!(
        outcome,
        maestro_shell::ReleaseOperationOutcome::Complete { .. }
    ) {
        tracing::debug!("pending remote session release remains forward-recoverable");
    }
}

fn drain_owned_session_release(
    tx: &DaemonRequestSender,
    sessions: &SharedSessions,
    paths: &maestro_shell::AppPaths,
    receipt: maestro_shell::PendingReleaseReceipt,
) {
    let service = maestro_shell::SessionReleaseService::new(paths);
    let attempt = match connect_reviewed_daemon_client(tx) {
        Ok(mut client) => service.attempt_owned_with_daemon(receipt, &mut client),
        Err(error) => service.attempt_owned_with_daemon_unavailable(receipt, error),
    };
    let (outcome, confirmed) = attempt.into_parts();
    let confirmed_ids = confirmed
        .iter()
        .map(|target| target.session_id().to_string())
        .collect::<Vec<_>>();
    if !confirmed_ids.is_empty() {
        if let Ok(mut cache) = sessions.lock() {
            cache.remove(&confirmed_ids);
        }
    }
    match outcome {
        maestro_shell::ReleaseOperationOutcome::Complete { .. } => {}
        maestro_shell::ReleaseOperationOutcome::UnpublishedFailure { compensation, .. } => {
            if service.release_unpublished_for_retry(compensation).is_err() {
                tracing::warn!("remote session release could not be made forward-claimable");
            }
        }
        maestro_shell::ReleaseOperationOutcome::ForwardOnly { .. } => {
            tracing::debug!("remote session release remains forward-recoverable");
        }
    }
}

fn consume_prepared_compensation_outcome(
    tx: &DaemonRequestSender,
    sessions: &SharedSessions,
    paths: &maestro_shell::AppPaths,
    outcome: maestro_shell::ConditionalPreparedNewSessionCompensation,
    context: &str,
) {
    match outcome {
        maestro_shell::ConditionalPreparedNewSessionCompensation::Unplaced(_) => {}
        maestro_shell::ConditionalPreparedNewSessionCompensation::ExistingWindow(outcome) => {
            match outcome {
                maestro_shell::ConditionalCreatedTabSessionRollback::RolledBack(mut rollback) => {
                    if !rollback.unresolved_release_session_ids.is_empty() {
                        tracing::warn!(%context, "prepared pane compensation has unresolved release targets");
                    }
                    if let Some(receipt) = rollback.release_receipt.take() {
                        drain_owned_session_release(tx, sessions, paths, receipt);
                    }
                }
                _ => tracing::warn!(%context, "prepared pane compensation was retained"),
            }
        }
        maestro_shell::ConditionalPreparedNewSessionCompensation::FreshWindowGraph(outcome) => {
            match outcome {
                maestro_shell::ConditionalFreshWindowGraphDelete::Deleted {
                    release_receipt,
                    ref unresolved_release_session_ids,
                } => {
                    if !unresolved_release_session_ids.is_empty() {
                        tracing::warn!(%context, "prepared graph compensation has unresolved release targets");
                    }
                    if let Some(receipt) = release_receipt {
                        drain_owned_session_release(tx, sessions, paths, receipt);
                    }
                }
                _ => tracing::warn!(%context, "prepared graph compensation was retained"),
            }
        }
    }
}

fn compensate_prepared_remote_start_error(
    tx: &DaemonRequestSender,
    sessions: &SharedSessions,
    paths: &maestro_shell::AppPaths,
    error: maestro_shell::PreparedNewSessionStartError,
    now_ms: u64,
    context: &str,
) {
    let layouts = maestro_shell::WindowLayoutService::new(paths);
    let compensation = match error {
        maestro_shell::PreparedNewSessionStartError::DefinitelyUnpublished { start, .. } => {
            layouts.cancel_prepared_new_session(start, now_ms)
        }
        maestro_shell::PreparedNewSessionStartError::Refused { compensation, .. } => {
            layouts.compensate_prepared_new_session(compensation, now_ms)
        }
        maestro_shell::PreparedNewSessionStartError::PossiblyApplied { .. } => {
            tracing::warn!(%context, "prepared remote Start remains durably ambiguous");
            return;
        }
    };
    match compensation {
        Ok(outcome) => consume_prepared_compensation_outcome(tx, sessions, paths, outcome, context),
        Err(_) => tracing::warn!(%context, "prepared remote Start compensation failed"),
    }
}

fn start_prepared_remote_session(
    tx: &DaemonRequestSender,
    paths: &maestro_shell::AppPaths,
    start: maestro_shell::PreparedNewSessionStart,
    launch_environment: RemoteLaunchEnvironment,
) -> Result<maestro_shell::PreparedNewSessionStarted, maestro_shell::PreparedNewSessionStartError> {
    let (client, peer) = match connect_reviewed_conditional_start_client(tx) {
        Ok(connected) => connected,
        Err(error) => {
            return Err(
                maestro_shell::PreparedNewSessionStartError::DefinitelyUnpublished {
                    error: maestro_shell::SessionServiceError::Daemon(error),
                    start,
                },
            )
        }
    };
    maestro_shell::SessionService::new(paths).start_prepared_new_session_with_child_environment(
        client,
        start,
        &peer,
        launch_environment.child_environment,
    )
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DaemonPeerIdentity {
    uid: u32,
    pid: u32,
}

#[cfg(any(target_os = "linux", test))]
fn validate_daemon_peer_identity(
    peer: DaemonPeerIdentity,
    effective_uid: u32,
    expected_manager_pid: Option<u32>,
) -> std::io::Result<()> {
    if peer.uid != effective_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "terminal daemon socket is owned by a different account",
        ));
    }
    if peer.pid == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "terminal daemon socket peer has no process identity",
        ));
    }
    if expected_manager_pid.is_some_and(|expected| peer.pid != expected) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "terminal daemon socket peer is not the reviewed systemd service process",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_daemon_peer_identity(stream: &UnixStream) -> std::io::Result<DaemonPeerIdentity> {
    use std::os::fd::AsRawFd as _;

    let mut credentials = std::mem::MaybeUninit::<libc::ucred>::uninit();
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of::<libc::ucred>() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "terminal daemon socket returned malformed peer credentials",
        ));
    }
    let credentials = unsafe { credentials.assume_init() };
    let pid = u32::try_from(credentials.pid).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "terminal daemon socket peer has an invalid process identity",
        )
    })?;
    Ok(DaemonPeerIdentity {
        uid: credentials.uid,
        pid,
    })
}

#[cfg(target_os = "linux")]
fn parse_headless_daemon_main_pid(output: &[u8]) -> std::io::Result<u32> {
    if output.len() > 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "systemd returned an oversized terminal daemon process identity",
        ));
    }
    let text = std::str::from_utf8(output).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "systemd returned a non-UTF-8 terminal daemon process identity",
        )
    })?;
    let value = text.strip_suffix('\n').unwrap_or(text);
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "systemd returned an invalid terminal daemon process identity",
        ));
    }
    let pid = value.parse::<u32>().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "systemd returned an invalid terminal daemon process identity",
        )
    })?;
    if pid == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "the reviewed terminal daemon service is not running",
        ));
    }
    Ok(pid)
}

#[cfg(target_os = "linux")]
async fn headless_daemon_main_pid() -> std::io::Result<u32> {
    tokio::task::spawn_blocking(|| {
        let args = vec![
            "--user".to_string(),
            "show".to_string(),
            format!("{}.service", crate::headless::DAEMON_UNIT_NAME),
            "--property=MainPID".to_string(),
            "--value".to_string(),
        ];
        let output =
            crate::service::manager_output_bounded(crate::headless::SYSTEMCTL_PATH, &args)?;
        if output.stderr.len() > 256 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "systemd returned an oversized terminal daemon error",
            ));
        }
        if !output.status.success() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "the reviewed terminal daemon service is unavailable",
            ));
        }
        parse_headless_daemon_main_pid(&output.stdout)
    })
    .await
    .map_err(|error| std::io::Error::other(format!("systemd identity task failed: {error}")))?
}

/// Prove the peer on the exact operational stream before sending even the protocol probe. A setup-time
/// readiness check is insufficient: the headless socket lives at a predictable `/tmp` path and can disappear
/// during a daemon restart. Kernel credentials close that replacement window; fixed headless mode additionally
/// binds the peer PID to the currently reviewed systemd user unit.
async fn verify_connected_daemon_peer(
    stream: &UnixStream,
    headless_server: bool,
) -> std::io::Result<()> {
    // The explicit return is part of the durable peer-binding contract: the validated
    // SO_PEERCRED/MainPID result must be this function's result, not a discarded check.
    #[allow(clippy::needless_return)]
    #[cfg(target_os = "linux")]
    {
        let peer = linux_daemon_peer_identity(stream)?;
        let expected_manager_pid = if headless_server {
            Some(headless_daemon_main_pid().await?)
        } else {
            None
        };
        return validate_daemon_peer_identity(
            peer,
            unsafe { libc::geteuid() },
            expected_manager_pid,
        );
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = stream;
        if headless_server {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "headless server daemon verification is supported only on Linux",
            ));
        }
        Ok(())
    }
}

async fn connect_reviewed_daemon(
    sock_path: &std::path::Path,
    headless_server: bool,
) -> std::io::Result<UnixStream> {
    let stream = UnixStream::connect(sock_path).await?;
    verify_connected_daemon_peer(&stream, headless_server).await?;
    Ok(stream)
}

/// Establish mutation authority on the SAME stream that will carry daemon requests. A legacy
/// daemon may reject or close on the unknown `daemon_info` operation; in that case this candidate
/// is discarded and a fresh attach-only connection is opened. Keeping an exact-v2 candidate avoids
/// a probe/connect TOCTOU where the published socket could be replaced between two connections.
/// A partial current-version peer that lacks the attachment-owner fence is also discarded: its
/// generation-CAS surface cannot safely release a lifetime still owned by another client.
async fn connect_daemon_with_protocol(
    sock_path: &std::path::Path,
    headless_server: bool,
) -> std::io::Result<(
    UnixStream,
    Option<u32>,
    bool,
    bool,
    bool,
    bool,
    bool,
    bool,
    bool,
)> {
    let mut candidate = connect_reviewed_daemon(sock_path, headless_server).await?;
    let (
        observed,
        output_generation_echo,
        child_environment,
        generation_conditional_mutations,
        attachment_aware_conditional_kill,
        generation_conditional_start,
        start_operation_ledger,
        generation_conditional_attach,
    ) = match tokio::time::timeout(
        DAEMON_INFO_PROBE_TIMEOUT,
        request_daemon_protocol(&mut candidate),
    )
    .await
    {
        Ok(Ok(handshake)) => handshake,
        Ok(Err(_)) | Err(_) => (None, false, false, false, false, false, false, false),
    };
    if observed == Some(maestro_protocol::DAEMON_PROTOCOL_VERSION)
        && generation_conditional_mutations
        && attachment_aware_conditional_kill
        && generation_conditional_start
        && start_operation_ledger
        && generation_conditional_attach
    {
        return Ok((
            candidate,
            observed,
            output_generation_echo,
            child_environment,
            true,
            true,
            true,
            true,
            true,
        ));
    }

    // The probe stream is never reused without an exact match. In particular, an old daemon may
    // have replied with an error but left the connection open; reconnecting gives attach/list a
    // clean legacy-compatible stream with no unknown request pending on it.
    drop(candidate);
    connect_reviewed_daemon(sock_path, headless_server)
        .await
        .map(|stream| {
            (
                stream, observed, false, false, false, false, false, false, false,
            )
        })
}

async fn request_daemon_protocol(
    stream: &mut UnixStream,
) -> std::io::Result<(Option<u32>, bool, bool, bool, bool, bool, bool, bool)> {
    let request = serde_json::to_string(&maestro_protocol::ClientRequest::DaemonInfo)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;

    // Read exactly one line without a buffered over-read: on an exact match this same stream is
    // handed to the operational reader, so bytes beyond the DaemonInfo reply must stay untouched.
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            return Ok((None, false, false, false, false, false, false, false));
        }
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
        if line.len() > maestro_protocol::MAX_LINE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "daemon info reply exceeds protocol line limit",
            ));
        }
    }
    let line = std::str::from_utf8(&line)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    match maestro_protocol::ShellEvent::from_line(line) {
        Ok(maestro_protocol::ShellEvent::DaemonInfo {
            protocol_version,
            output_generation_echo,
            child_environment,
            generation_conditional_mutations,
            attachment_aware_conditional_kill,
            generation_conditional_start,
            start_operation_ledger,
            generation_conditional_attach,
            ..
        }) => Ok((
            Some(protocol_version),
            output_generation_echo,
            child_environment,
            generation_conditional_mutations,
            attachment_aware_conditional_kill,
            generation_conditional_start,
            start_operation_ledger,
            generation_conditional_attach,
        )),
        Ok(_) | Err(_) => Ok((None, false, false, false, false, false, false, false)),
    }
}

fn is_start_session_request(line: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(line.trim())
        .ok()
        .and_then(|value| {
            value
                .get("op")
                .and_then(|op| op.as_str())
                .map(str::to_owned)
        })
        .as_deref()
        == Some("start_session")
}

fn is_generation_conditional_mutation_request(line: &str) -> bool {
    matches!(
        serde_json::from_str::<serde_json::Value>(line.trim())
            .ok()
            .and_then(|value| value.get("op")?.as_str().map(str::to_owned))
            .as_deref(),
        Some("write" | "resize" | "kill")
    )
}

fn is_generation_conditional_attach_request(line: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(line.trim())
        .ok()
        .is_some_and(|value| {
            value.get("op").and_then(|op| op.as_str()) == Some("attach")
                && value.get("expected_session_generation").is_some()
        })
}

pub async fn spawn_daemon_task(
    sock_path: PathBuf,
    seed_sessions: Vec<String>,
) -> std::io::Result<(DaemonBackend, DaemonOutputReceiver)> {
    spawn_daemon_task_with_policy(sock_path, seed_sessions, false).await
}

pub async fn spawn_daemon_task_with_policy(
    sock_path: PathBuf,
    seed_sessions: Vec<String>,
    headless_server: bool,
) -> std::io::Result<(DaemonBackend, DaemonOutputReceiver)> {
    let (
        stream,
        daemon_protocol_version,
        output_generation_echo,
        child_environment,
        generation_conditional_mutations,
        attachment_aware_conditional_kill,
        generation_conditional_start,
        start_operation_ledger,
        generation_conditional_attach,
    ) = connect_daemon_with_protocol(&sock_path, headless_server).await?;
    #[cfg(target_os = "linux")]
    let daemon_server_pid = Some(linux_daemon_peer_identity(&stream)?.pid);
    #[cfg(not(target_os = "linux"))]
    let daemon_server_pid = None;
    let mutation_protocol_version = (generation_conditional_mutations
        && attachment_aware_conditional_kill)
        .then(|| {
            mutation_protocol_for_policy(
                daemon_protocol_version,
                headless_server,
                child_environment,
            )
        })
        .flatten();
    let start_mutation_allowed = mutation_protocol_version.is_some();
    let start_mutation_allowed = start_mutation_allowed
        && generation_conditional_start
        && start_operation_ledger
        && generation_conditional_attach;
    let (read_half, mut write_half) = stream.into_split();
    let (req_tx, mut req_rx) = if headless_server {
        daemon_request_channel_with_policy(
            DAEMON_REQUEST_QUEUE_CAP,
            DAEMON_REQUEST_QUEUE_BYTE_CAP,
            true,
        )
    } else {
        daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP)
    };
    req_tx.set_reviewed_daemon_authority(ReviewedDaemonAuthority {
        socket_path: sock_path.clone(),
        server_pid: daemon_server_pid,
    });
    let mut request_failure_for_writer = req_rx.failure_receiver();
    let request_failure_for_output = req_rx.failure_receiver();
    let mut request_failure_for_reader = req_rx.failure_receiver();
    let mut request_failure_for_release_worker = req_rx.failure_receiver();
    let request_stopper_from_reader = req_tx.stopper();
    let output_routes = std::sync::Arc::new(std::sync::Mutex::new(DaemonOutputRoutes::new(
        output_generation_echo,
    )));
    let pending_attach_sizes =
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::<
            String,
            PendingAttachSize,
        >::new()));
    let pending_attach_sizes_reader = pending_attach_sizes.clone();
    let req_tx_for_reader = req_tx.clone();
    let (mut out_tx, out_rx) = daemon_output_channel_with_routes(
        DAEMON_OUTPUT_QUEUE_CAP,
        DAEMON_OUTPUT_QUEUE_BYTE_CAP,
        Some(request_failure_for_output),
        output_routes.clone(),
    );
    let sessions = std::sync::Arc::new(std::sync::Mutex::new(
        SessionCache::seeded_with_daemon_protocol(
            seed_sessions,
            mutation_protocol_version,
            generation_conditional_mutations,
            attachment_aware_conditional_kill,
            generation_conditional_start,
            start_operation_ledger,
            generation_conditional_attach,
        ),
    ));
    let sessions_task = sessions.clone();
    let session_metadata =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::<SessionMetadata>::new()));
    let session_metadata_task = session_metadata.clone();
    let dashboard_paths = maestro_shell::AppPaths::production().ok();
    // RAW (xterm.js) mode: the daemon still emits Grid/Damage alongside the raw Output stream, but the
    // xterm renderer only consumes `output` — forwarding the (large) structured frames would just flood the
    // relay and re-introduce the streaming "wave". So in raw mode we drop grid/damage/resync at the agent.
    // The flag is set per-attach by the client (see DaemonBackend::attach); shared with the reader task.
    let raw_output = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let raw_output_reader = raw_output.clone();

    // Prime the live session cache from the daemon authority. `seed_sessions` is only the configured
    // startup hint; the daemon may already have sessions created by another local client.
    let _ = req_tx.send(serde_json::json!({ "op": "list_sessions" }).to_string());

    // Headless and unattended desktop agents own their own durable release recovery.  Claim one
    // bounded operation per tick on an auxiliary exact-PID-reviewed socket; a failed attempt
    // relinquishes its forward lease and never blocks terminal output or the operational writer.
    if let Some(paths) = dashboard_paths.clone() {
        let release_tx = req_tx.clone();
        let release_sessions = sessions.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    biased;
                    changed = request_failure_for_release_worker.changed() => {
                        if changed.is_err() || *request_failure_for_release_worker.borrow() {
                            break;
                        }
                    }
                    _ = interval.tick() => {
                        let tx = release_tx.clone();
                        let sessions = release_sessions.clone();
                        let paths = paths.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            drain_one_pending_session_release(&tx, &sessions, &paths);
                        }).await;
                    }
                }
            }
        });
    }

    // request-writer
    tokio::spawn(async move {
        loop {
            let line = tokio::select! {
                biased;
                _ = request_failure_for_writer.changed() => break,
                line = req_rx.recv() => match line {
                    Some(line) => line,
                    None => break,
                },
            };
            // Defense in depth: every mutation facade checks before claiming success, but an
            // accidentally added raw sender still cannot mutate an attach-only legacy/future
            // daemon through this production writer.
            let mutation_refused = (is_start_session_request(&line) && !start_mutation_allowed)
                || (is_generation_conditional_mutation_request(&line)
                    && !(generation_conditional_mutations && attachment_aware_conditional_kill))
                || (is_generation_conditional_attach_request(&line)
                    && !generation_conditional_attach);
            if mutation_refused {
                tracing::warn!(
                    "daemon mutation suppressed: exact v3 conditional capability was not established"
                );
                continue;
            }
            let body = tokio::select! {
                biased;
                _ = request_failure_for_writer.changed() => break,
                result = write_half.write_all(line.as_bytes()) => result,
            };
            if body.is_err() {
                break;
            }
            let delimiter = tokio::select! {
                biased;
                _ = request_failure_for_writer.changed() => break,
                result = write_half.write_all(b"\n") => result,
            };
            if delimiter.is_err() {
                break;
            }
            let flushed = tokio::select! {
                biased;
                _ = request_failure_for_writer.changed() => break,
                result = write_half.flush() => result,
            };
            if flushed.is_err() {
                break;
            }
        }
        // Queue pressure, socket failure, ordinary owner teardown, and task completion all converge on
        // one signal. It interrupts a stalled write, stops the daemon reader, closes daemon output, and
        // therefore retires the same remote owner through the existing output-forwarder liveness path.
        req_rx.fail();
    });

    // event-reader: pump daemon output lines to the peer; track session ids.
    tokio::spawn(async move {
        let mut lines = BufReader::new(read_half).lines();
        loop {
            let line = tokio::select! {
                biased;
                _ = request_failure_for_reader.changed() => break,
                line = lines.next_line() => match line {
                    Ok(Some(line)) => line,
                    Ok(None) | Err(_) => break,
                },
            };
            if line.is_empty() {
                continue;
            }
            // Stream the daemon envelope once. Multi-MiB Grid/Damage payloads stay opaque: the visitor retains
            // only the event class + routing id and skips the terminal tree with `IgnoredAny`. Previously this
            // path built one full `serde_json::Value` to find the id, built a second full tree while checking for
            // a Sessions event, and then scanned the line repeatedly with `contains` for its trace label.
            let DaemonLineMetadata {
                event,
                session_id,
                output_generation,
                live_output_generation,
                pty_generation,
                sessions,
            } = daemon_line_metadata(&line).unwrap_or_default();
            let output_event = session_id.as_ref().map(|_| {
                // STAGE: which daemon event + size is forwarded to the peer (no payload content).
                event.output_label()
            });
            // keep the live-session set fresh when the daemon reports it. MERGE, don't replace: a Sessions
            // event snapshotted before a just-created session's start line must not evict its reservation
            // (see SessionCache::apply_daemon_ids) — replacing here was why the agent's own session_list
            // denied a session it had just created until the desktop's liveness repair ran.
            if let Some((ids, metadata, generations)) = sessions {
                if let Ok(mut s) = sessions_task.lock() {
                    s.apply_daemon_listing(ids, generations);
                }
                if let Ok(mut m) = session_metadata_task.lock() {
                    *m = metadata;
                }
            }
            if let (Some(session_id), Some(ev)) = (session_id, output_event) {
                // Observe the explicit Attach baseline even when raw renderer mode filters its structured Grid.
                // Ordered request replies cut over here; every live-forwarder line also carries its own tag so
                // an aborted old task cannot race across the baseline and inherit the new attachment.
                let attachment = observe_route_and_apply_grid(
                    out_tx.routes.as_ref(),
                    &sessions_task,
                    pending_attach_sizes_reader.as_ref(),
                    &req_tx_for_reader,
                    &session_id,
                    event,
                    output_generation,
                    live_output_generation,
                    pty_generation,
                    || {},
                );
                // RAW mode: only the raw `output` stream goes to xterm.js; drop structured frames so they
                // don't flood the DataChannel/relay. This intentional renderer-mode filter is the only output
                // omission path; queue pressure below is fail-stop rather than lossy.
                if raw_output_reader.load(std::sync::atomic::Ordering::Relaxed)
                    && (ev == "grid" || ev == "damage" || ev == "resync_required")
                {
                    continue;
                }
                tracing::debug!("STAGE daemon_out ev={ev} bytes={}", line.len());
                if let Err(error) =
                    out_tx.try_enqueue_routed(DaemonOutput { session_id, line }, attachment)
                {
                    tracing::warn!(reason = error.reason(), "STAGE daemon_out producer stopped");
                    break;
                }
            }
        }
        request_stopper_from_reader.stop();
    });

    Ok((
        DaemonBackend {
            tx: req_tx,
            sessions,
            session_metadata,
            dashboard_paths,
            raw_output, // same flag drives the attach mode + the structured-frame drop above
            output_routes,
            pending_attach_sizes,
        },
        out_rx,
    ))
}

/// Pick the active project id = the one with the greatest `last_active_at_ms`, breaking ties by id for
/// determinism. Returns None for an empty iterator. Pure so the parity-step-9 "which project is active" rule is
/// unit-tested without a full dashboard-record fixture.
fn active_project_id_by_recency<'a>(
    projects: impl Iterator<Item = (&'a str, u64)>,
) -> Option<String> {
    projects
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(b.0)))
        .map(|(id, _)| id.to_string())
}

// Product-owned startup fallback. The local dashboard excludes this exact durable identity from every
// app-facing projection; the remote boundary must do the same. Keep ordinary hidden projects visible.
// Mirrored from maestro-app::PRODUCT_RECOVERY_PROJECT_ID without adding a hydra-agent -> maestro-app
// dependency cycle.
const PRODUCT_RECOVERY_PROJECT_ID: &str = "system-product-recovery";
const PRODUCT_RECOVERY_SESSION_ID: &str = "system-product-recovery-session";

fn workspace_metadata_from_dashboard(paths: &maestro_shell::AppPaths) -> Option<WorkspaceMetadata> {
    let snapshot = maestro_shell::DashboardSnapshotService::new(paths)
        .snapshot(None)
        .ok()?;
    let projects = snapshot
        .projects
        .into_iter()
        .filter(|project| project.project_id != PRODUCT_RECOVERY_PROJECT_ID)
        .collect::<Vec<_>>();
    // Mark the ACTIVE project so the browser dashboard mirrors the desktop's active state (parity step 9) instead
    // of showing every project as unselected. The desktop's active WINDOW is live runtime state (not in records —
    // same reason focus_window needs a runtime bridge), but the active PROJECT is derivable from records:
    // last_active_at_ms. Content-blind (a timestamp and an id, no terminal content).
    let active_project_id: Option<String> = active_project_id_by_recency(
        projects
            .iter()
            .map(|p| (p.project_id.as_str(), p.last_active_at_ms)),
    );
    // Map one DashboardWindow → WorkspaceWindowMetadata (tabs → panes). Shared by the per-project windows AND the
    // unassigned windows below.
    let map_window = |window: maestro_shell::DashboardWindow| -> WorkspaceWindowMetadata {
        let panes: Vec<WorkspacePaneMetadata> = window
            .tabs
            .into_iter()
            .map(|tab| WorkspacePaneMetadata {
                id: tab.tab_id,
                session_id: tab.session_id,
                name: Some(tab.title),
                stashed: tab.stashed,
                // Surface the pane's resolved cwd so the browser split picker can default to the source window's
                // folder (mirrors local). `DashboardTab.cwd` is "" when the session record is missing → None.
                cwd: Some(tab.cwd).filter(|c| !c.is_empty()),
            })
            .collect();
        WorkspaceWindowMetadata {
            id: window.window_id,
            name: window.name,
            focused: false,
            stashed: false,
            panes,
        }
    };
    // A window whose tabs don't associate to any project AND has no window_order owner lands in
    // `unassigned_windows` — the snapshot NEVER drops it, but this metadata builder used to. That hid the user's
    // SECOND window from the browser ("only the focused/active window comes through"). Surface them under the active
    // project (or the first) so every real local window reaches the remote dashboard.
    let unassigned: Vec<WorkspaceWindowMetadata> = snapshot
        .unassigned_windows
        .into_iter()
        .map(map_window)
        .collect();
    let attach_to_project_id: Option<String> = active_project_id
        .clone()
        .or_else(|| projects.first().map(|p| p.project_id.clone()));
    let projects: Vec<WorkspaceProjectMetadata> = projects
        .into_iter()
        .map(|project| {
            // Surface EVERY window (even one with no visible panes) and EVERY project (even one with no live
            // windows). The local desktop dashboard shows idle projects/windows in the sidebar tree; dropping them
            // here was why the user's real local projects didn't appear in the browser ("reach local projects in
            // same dashboard view structure"). The browser tree renders an empty project as Project → Window →
            // default pane, so idle projects are navigable + can be launched into, exactly like local.
            let mut windows: Vec<WorkspaceWindowMetadata> =
                project.windows.into_iter().map(map_window).collect();
            // Append any unassigned windows to the project they belong under (active/first).
            if attach_to_project_id.as_deref() == Some(project.project_id.as_str()) {
                windows.extend(unassigned.clone());
            }
            // Surface persisted launch defaults + directories for Edit Project prefill (config metadata, not
            // terminal content). Omit when nothing is set.
            let launch_defaults =
                project
                    .launch_defaults
                    .map(|d| crate::remote_bridge::WorkspaceLaunchDefaults {
                        agent: d.agent,
                        // Desktop vocabulary is continue|resume|none; early remote builds STORED "new" for the
                        // fresh policy. Normalize on read so old records prefill the browser form correctly.
                        resume_mode: d.resume_mode.map(|m| {
                            if m == "new" {
                                "none".to_string()
                            } else {
                                m
                            }
                        }),
                        model: d.model,
                        dangerous: d.dangerous_skip_permissions,
                        custom_command: d.custom_command,
                    });
            let directories = project
                .directories
                .into_iter()
                .map(|d| crate::remote_bridge::WorkspaceDirectory {
                    name: d.name,
                    path: d.path,
                })
                .collect();
            let selected = active_project_id
                .as_deref()
                .map(|active| active == project.project_id)
                .unwrap_or(false);
            WorkspaceProjectMetadata {
                id: project.project_id,
                name: project.name,
                root: project.root,
                icon: project.icon,
                accent_color: project.accent_color,
                selected,
                launch_defaults,
                directories,
                system: project.system,
                hidden: project.hidden,
                windows,
            }
        })
        .collect();
    if projects.is_empty() {
        None
    } else {
        Some(WorkspaceMetadata { projects })
    }
}

fn live_session_ids_from_dashboard(paths: &maestro_shell::AppPaths) -> Vec<String> {
    let Ok(snapshot) = maestro_shell::DashboardSnapshotService::new(paths).snapshot(None) else {
        return Vec::new();
    };
    let mut ids = std::collections::BTreeSet::<String>::new();
    for window in snapshot
        .projects
        .iter()
        .filter(|project| project.project_id != PRODUCT_RECOVERY_PROJECT_ID)
        .flat_map(|project| project.windows.iter())
        .chain(snapshot.unassigned_windows.iter())
    {
        for tab in &window.tabs {
            if tab.session_status == Some(maestro_shell::SessionStatus::Live) {
                ids.insert(tab.session_id.clone());
            }
        }
    }
    ids.into_iter().collect()
}

/// Extract the session id of a daemon event line. Most events carry top-level `"id"` (grid/output/
/// resync_required/…), but a `damage` event nests it under `frame.id` — check both, or the damage frame is
/// dropped (the browser then never sees incremental updates → only full-grid resyncs). Terminal payload is
/// traversed only for JSON validity; it is never materialized or interpreted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum DaemonEventClass {
    Grid,
    Damage,
    Output,
    ResyncRequired,
    Sessions,
    #[default]
    Other,
}

impl DaemonEventClass {
    fn from_value(value: &serde_json::Value) -> Self {
        match value.as_str() {
            Some("grid") => Self::Grid,
            Some("damage") => Self::Damage,
            Some("output") => Self::Output,
            Some("resync_required") => Self::ResyncRequired,
            Some("sessions") => Self::Sessions,
            _ => Self::Other,
        }
    }

    fn output_label(self) -> &'static str {
        match self {
            Self::Grid => "grid",
            Self::Damage => "damage",
            Self::Output => "output",
            Self::ResyncRequired => "resync_required",
            Self::Sessions | Self::Other => "other",
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct DamageRoute {
    id: Option<String>,
}

impl<'de> serde::Deserialize<'de> for DamageRoute {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DamageRouteVisitor;

        impl<'de> serde::de::Visitor<'de> for DamageRouteVisitor {
            type Value = DamageRoute;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a daemon damage-frame object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut id = None;
                while let Some(key) = map.next_key::<String>()? {
                    if key == "id" {
                        let value = map.next_value::<serde_json::Value>()?;
                        id = value.as_str().map(str::to_owned);
                    } else {
                        map.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
                Ok(DamageRoute { id })
            }
        }

        deserializer.deserialize_map(DamageRouteVisitor)
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct GridGeneration {
    generation: Option<String>,
}

impl<'de> serde::Deserialize<'de> for GridGeneration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct GridGenerationVisitor;

        impl<'de> serde::de::Visitor<'de> for GridGenerationVisitor {
            type Value = GridGeneration;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a daemon grid snapshot object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut generation = None;
                while let Some(key) = map.next_key::<String>()? {
                    if key == "generation" {
                        let value = map.next_value::<serde_json::Value>()?;
                        generation = value.as_str().map(str::to_owned);
                    } else {
                        map.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
                Ok(GridGeneration { generation })
            }
        }

        deserializer.deserialize_map(GridGenerationVisitor)
    }
}

/// The only information the remote agent needs from one daemon line. Terminal payload stays in the original
/// `String`; this metadata never owns cells, damage operations, output bytes, or scrollback rows.
#[derive(Debug, Default, PartialEq, Eq)]
struct DaemonLineMetadata {
    event: DaemonEventClass,
    session_id: Option<String>,
    output_generation: Option<u64>,
    live_output_generation: Option<u64>,
    pty_generation: Option<String>,
    sessions: Option<DaemonSessionListing>,
}

/// The bounded session inventory carried by a daemon `sessions` control event.
type DaemonSessionListing = (
    Vec<String>,
    Vec<SessionMetadata>,
    std::collections::BTreeMap<String, String>,
);

/// Route and session-inventory result produced by the legacy JSON-tree extractor used for parity
/// tests against the streaming metadata parser.
#[cfg(test)]
type LegacyDaemonLineMetadata = (Option<String>, Option<DaemonSessionListing>);

impl<'de> serde::Deserialize<'de> for DaemonLineMetadata {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct DaemonLineVisitor;

        impl<'de> serde::de::Visitor<'de> for DaemonLineVisitor {
            type Value = DaemonLineMetadata;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a daemon event object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut event = DaemonEventClass::Other;
                let mut top_level_id = None;
                let mut damage_id = None;
                let mut pty_generation = None;
                let mut output_generation = None;
                let mut live_output_generation = None;
                // Sessions is a small control-plane event. Preserve its legacy tolerant filtering exactly while
                // keeping every terminal-heavy field on the zero-tree `IgnoredAny` path.
                let mut ids = None;
                let mut session_entries = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "ev" => {
                            let value = map.next_value::<serde_json::Value>()?;
                            event = DaemonEventClass::from_value(&value);
                        }
                        "id" => {
                            let value = map.next_value::<serde_json::Value>()?;
                            top_level_id = value.as_str().map(str::to_owned);
                        }
                        "output_generation" => {
                            let value = map.next_value::<serde_json::Value>()?;
                            output_generation = value.as_u64();
                        }
                        "live_output_generation" => {
                            let value = map.next_value::<serde_json::Value>()?;
                            live_output_generation = value.as_u64();
                        }
                        "frame" => {
                            damage_id = map.next_value::<DamageRoute>()?.id;
                        }
                        "grid" => {
                            pty_generation = map.next_value::<GridGeneration>()?.generation;
                        }
                        "ids" => ids = Some(map.next_value::<serde_json::Value>()?),
                        "sessions" => {
                            session_entries = Some(map.next_value::<serde_json::Value>()?)
                        }
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }

                let sessions = if event == DaemonEventClass::Sessions {
                    ids.as_ref()
                        .and_then(serde_json::Value::as_array)
                        .map(|ids| {
                            let ids = ids
                                .iter()
                                .filter_map(|id| id.as_str().map(str::to_owned))
                                .collect();
                            let metadata = session_entries
                                .as_ref()
                                .and_then(serde_json::Value::as_array)
                                .map(|items| {
                                    items
                                        .iter()
                                        .filter_map(|item| {
                                            let id = item
                                                .get("id")
                                                .and_then(serde_json::Value::as_str)?
                                                .to_owned();
                                            let cwd = item
                                                .get("cwd")
                                                .and_then(serde_json::Value::as_str)
                                                .map(str::to_owned);
                                            Some(SessionMetadata { id, cwd })
                                        })
                                        .collect()
                                })
                                .unwrap_or_default();
                            let generations = session_entries
                                .as_ref()
                                .and_then(serde_json::Value::as_array)
                                .map(|items| {
                                    items
                                        .iter()
                                        .filter_map(|item| {
                                            Some((
                                                item.get("id")?.as_str()?.to_owned(),
                                                item.get("generation")?.as_str()?.to_owned(),
                                            ))
                                        })
                                        .collect()
                                })
                                .unwrap_or_default();
                            (ids, metadata, generations)
                        })
                } else {
                    None
                };

                Ok(DaemonLineMetadata {
                    event,
                    // Preserve the existing route rule: a top-level id wins, with damage.frame.id as fallback.
                    session_id: top_level_id.or(damage_id),
                    output_generation,
                    live_output_generation,
                    pty_generation,
                    sessions,
                })
            }
        }

        deserializer.deserialize_map(DaemonLineVisitor)
    }
}

fn daemon_line_metadata(line: &str) -> Option<DaemonLineMetadata> {
    let mut deserializer = serde_json::Deserializer::from_str(line);
    let metadata = DaemonLineMetadata::deserialize(&mut deserializer).ok()?;
    deserializer.end().ok()?;
    Some(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_control::{
        PaneRemover, PaneStasher, ProjectEditor, Renamer, WindowCloser, WindowFocuser, WindowOpener,
    };
    use crate::session_creator::SessionCreator;
    use std::sync::{atomic::AtomicBool, atomic::Ordering, Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;

    struct ConditionalStartTestDaemon {
        socket_path: std::path::PathBuf,
        _dir: tempfile::TempDir,
        stop: Arc<AtomicBool>,
        requests: Arc<Mutex<Vec<serde_json::Value>>>,
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl ConditionalStartTestDaemon {
        fn requests(&self) -> Vec<serde_json::Value> {
            self.requests.lock().unwrap().clone()
        }

        fn start_requests(&self) -> Vec<serde_json::Value> {
            self.requests()
                .into_iter()
                .filter(|request| request["op"] == "start_session")
                .collect()
        }
    }

    fn only_conditional_start(daemon: &ConditionalStartTestDaemon) -> serde_json::Value {
        let starts = daemon.start_requests();
        assert_eq!(
            starts.len(),
            1,
            "expected exactly one conditional StartSession"
        );
        let start = starts.into_iter().next().unwrap();
        assert!(
            start["conditional_start"].is_object(),
            "StartSession must carry opaque ledger authority: {start}"
        );
        assert_eq!(start["conditional_start"]["precondition"]["kind"], "absent");
        assert!(
            start.get("restart_exited").is_none(),
            "prepared create must never use blind restart_exited: {start}"
        );
        start
    }

    fn assert_provider_start_executes_exact_source(
        start: &serde_json::Value,
        session_id: &str,
        cwd: &str,
        source_argv: &[String],
        initial_size: InitialTerminalSize,
    ) {
        let expected =
            maestro_shell::login_shell_argv(source_argv, &maestro_shell::ProcessLaunchEnv);
        assert_eq!(start["op"], "start_session");
        assert_eq!(start["id"], session_id);
        assert_eq!(start["cwd"], cwd);
        assert_eq!(start["command"], expected[0]);
        assert_eq!(
            start["args"],
            serde_json::to_value(&expected[1..]).unwrap(),
            "first wire launch must execute the exact reviewed provider argv"
        );
        assert_eq!(start["cols"], initial_size.cols());
        assert_eq!(start["rows"], initial_size.rows());
        assert!(start["conditional_start"].is_object());
    }

    impl Drop for ConditionalStartTestDaemon {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = std::os::unix::net::UnixStream::connect(&self.socket_path);
            if let Some(handle) = self.handle.take() {
                handle.join().unwrap();
            }
        }
    }

    fn install_conditional_start_test_daemon(
        tx: &DaemonRequestSender,
    ) -> ConditionalStartTestDaemon {
        install_conditional_start_test_daemon_with_live(tx, std::collections::BTreeMap::new())
    }

    fn install_conditional_start_test_daemon_with_live(
        tx: &DaemonRequestSender,
        initial_live: std::collections::BTreeMap<String, String>,
    ) -> ConditionalStartTestDaemon {
        install_conditional_start_test_daemon_with_options(tx, initial_live, false)
    }

    fn install_conditional_start_test_daemon_with_retire_eof(
        tx: &DaemonRequestSender,
    ) -> ConditionalStartTestDaemon {
        install_conditional_start_test_daemon_with_options(
            tx,
            std::collections::BTreeMap::new(),
            true,
        )
    }

    fn install_conditional_start_test_daemon_with_options(
        tx: &DaemonRequestSender,
        initial_live: std::collections::BTreeMap<String, String>,
        retire_with_eof: bool,
    ) -> ConditionalStartTestDaemon {
        use std::io::{BufRead as _, Write as _};

        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("conditional-start.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_for_thread = Arc::clone(&requests);
        let live = Arc::new(Mutex::new(initial_live));
        let live_for_thread = Arc::clone(&live);
        let mirror_tx = tx.clone();
        let handle = std::thread::spawn(move || {
            const INSTANCE: &str = "22222222222242228222222222222222";
            let mut next_generation = 1_u64;
            while let Ok((mut stream, _)) = listener.accept() {
                if stop_for_thread.load(Ordering::SeqCst) {
                    break;
                }
                let mut reader = std::io::BufReader::new(stream.try_clone().unwrap());
                loop {
                    let mut line = String::new();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    let request: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
                    requests_for_thread.lock().unwrap().push(request.clone());
                    match request["op"].as_str().unwrap_or_default() {
                        "daemon_info" => {
                            writeln!(
                                stream,
                                "{}",
                                serde_json::json!({
                                    "ev": "daemon_info",
                                    "protocol_version": maestro_protocol::DAEMON_PROTOCOL_VERSION,
                                    "build_version": "hydra-test-ledger",
                                    "daemon_instance_id": INSTANCE,
                                    "output_generation_echo": true,
                                    "child_environment": true,
                                    "generation_conditional_mutations": true,
                                    "attachment_aware_conditional_kill": true,
                                    "generation_conditional_start": true,
                                    "start_operation_ledger": true,
                                    "generation_conditional_attach": true,
                                })
                            )
                            .unwrap();
                        }
                        "reserve_start_operation" => {
                            writeln!(
                                stream,
                                "{}",
                                serde_json::json!({
                                    "ev": "start_operation_reserved",
                                    "id": request["id"],
                                    "operation_token": request["operation_token"],
                                    "daemon_instance_id": INSTANCE,
                                    "outcome": {"status": "reserved"},
                                })
                            )
                            .unwrap();
                        }
                        "start_session" => {
                            // Existing Hydra behavior tests inspect the first-start argv through
                            // the historical request receiver. Mirror only a compatibility
                            // projection there; the real operation under test is the reviewed
                            // Reserve/conditional Start/Grid/retire exchange on this socket.
                            let mut mirrored = request.clone();
                            mirrored
                                .as_object_mut()
                                .unwrap()
                                .remove("conditional_start");
                            let _ = mirror_tx.send(mirrored.to_string());
                            let generation = format!("hydra-test-generation-{next_generation}");
                            next_generation += 1;
                            live_for_thread.lock().unwrap().insert(
                                request["id"].as_str().unwrap().to_string(),
                                generation.clone(),
                            );
                            writeln!(
                                stream,
                                "{}",
                                serde_json::json!({
                                    "ev": "conditional_session_start",
                                    "id": request["id"],
                                    "operation_token": request["conditional_start"]["operation_token"],
                                    "daemon_instance_id": INSTANCE,
                                    "outcome": {"status": "applied", "generation": generation},
                                })
                            )
                            .unwrap();
                        }
                        "attach" => {
                            let id = request["id"].as_str().unwrap();
                            let expected = request["expected_session_generation"].as_str();
                            let generation = live_for_thread.lock().unwrap().get(id).cloned();
                            match (generation, expected) {
                                (Some(generation), Some(expected)) if generation == expected => {
                                    writeln!(
                                        stream,
                                        "{}",
                                        serde_json::json!({
                                            "ev": "grid",
                                            "id": id,
                                            "output_generation": request["output_generation"],
                                            "grid": {"generation": generation, "revision": 1},
                                        })
                                    )
                                    .unwrap();
                                }
                                _ => {
                                    writeln!(
                                        stream,
                                        "{}",
                                        serde_json::json!({
                                            "ev": "session_attach_refused",
                                            "id": id,
                                            "expected_generation": expected.unwrap_or_default(),
                                            "daemon_instance_id": INSTANCE,
                                            "reason": "missing",
                                        })
                                    )
                                    .unwrap();
                                }
                            }
                        }
                        "retire_start_operation" => {
                            if retire_with_eof {
                                // Close only after Reserve + conditional Start + exact Attach/Grid
                                // have succeeded. The production caller must not turn this
                                // post-Grid cleanup failure into an unnamed live session.
                                break;
                            }
                            writeln!(
                                stream,
                                "{}",
                                serde_json::json!({
                                    "ev": "start_operation_retired",
                                    "id": request["id"],
                                    "operation_token": request["operation_token"],
                                    "daemon_instance_id": INSTANCE,
                                    "outcome": {"status": "retired"},
                                })
                            )
                            .unwrap();
                        }
                        "kill" => {
                            let id = request["id"].as_str().unwrap();
                            let expected = request["expected_generation"].as_str().unwrap();
                            let mut live = live_for_thread.lock().unwrap();
                            if live
                                .get(id)
                                .is_some_and(|generation| generation == expected)
                            {
                                live.remove(id);
                            }
                        }
                        "list_sessions" => {
                            let live = live_for_thread.lock().unwrap();
                            let ids = live.keys().cloned().collect::<Vec<_>>();
                            let sessions = live
                                .iter()
                                .map(|(id, generation)| {
                                    serde_json::json!({"id": id, "generation": generation})
                                })
                                .collect::<Vec<_>>();
                            writeln!(
                                stream,
                                "{}",
                                serde_json::json!({"ev": "sessions", "ids": ids, "sessions": sessions})
                            )
                            .unwrap();
                        }
                        _ => {}
                    }
                    stream.flush().unwrap();
                }
            }
        });
        #[cfg(target_os = "linux")]
        let server_pid = Some(std::process::id());
        #[cfg(not(target_os = "linux"))]
        let server_pid = None;
        tx.set_reviewed_daemon_authority(ReviewedDaemonAuthority {
            socket_path: socket_path.clone(),
            server_pid,
        });
        ConditionalStartTestDaemon {
            socket_path,
            _dir: dir,
            stop,
            requests,
            handle: Some(handle),
        }
    }

    struct TestPaneCreationLease {
        session_id: String,
        dropped: Arc<Mutex<Vec<String>>>,
    }

    impl Drop for TestPaneCreationLease {
        fn drop(&mut self) {
            self.dropped.lock().unwrap().push(self.session_id.clone());
        }
    }

    fn install_creation_lease_publisher(tx: &DaemonRequestSender, dir: &std::path::Path) {
        std::fs::create_dir_all(dir).unwrap();
        let owner = Arc::new(Mutex::new(crate::winsize_owner::WinsizeOwner::new()));
        owner.lock().unwrap().set_serving(1, 0);
        tx.set_creation_lease_publisher(crate::winsize_owner::RemoteCreationLeasePublisher::new(
            owner,
            dir.to_path_buf(),
            "test-connection".into(),
        ));
    }

    fn assert_creation_lease(dir: &std::path::Path, session_id: &str) {
        assert_eq!(
            crate::winsize_owner::read_remote_owned_sessions(dir),
            vec![session_id.to_string()]
        );
    }

    fn test_window_epoch(paths: &maestro_shell::AppPaths) -> u32 {
        let connection = maestro_shell::db::conn_for(paths.base()).unwrap();
        let guard = connection.lock().unwrap();
        guard
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn daemon_request_sender_preserves_its_launch_policy_across_clones() {
        let (desktop, _desktop_rx) = daemon_request_channel_with_policy(1, 1024, false);
        let (headless, _headless_rx) = daemon_request_channel_with_policy(1, 1024, true);
        assert!(!desktop.headless_server());
        assert!(headless.headless_server());
        assert!(headless.clone().headless_server());
    }

    #[test]
    fn child_environment_capability_gates_only_headless_mutation() {
        let v2 = Some(maestro_protocol::DAEMON_PROTOCOL_VERSION);
        assert_eq!(
            mutation_protocol_for_policy(v2, false, false),
            v2,
            "a retained desktop v2 daemon keeps its established mutation contract"
        );
        assert_eq!(
            mutation_protocol_for_policy(v2, true, false),
            None,
            "headless mutation stays attach-only without the additive capability"
        );
        assert_eq!(mutation_protocol_for_policy(v2, true, true), v2);
        assert_eq!(mutation_protocol_for_policy(Some(1), false, true), None);
        assert_eq!(mutation_protocol_for_policy(None, true, true), None);
    }

    #[test]
    fn desktop_request_sender_preserves_start_session_bytes() {
        let (tx, mut rx) = daemon_request_channel_with_policy(2, 4096, false);
        let original = crate::supervise::start_session_line("desktop-byte-fixture", "/tmp");
        tx.send(original.clone()).unwrap();
        assert_eq!(rx.try_recv().unwrap(), original);
    }

    #[test]
    fn daemon_peer_identity_requires_the_effective_account_and_reviewed_manager_pid() {
        let reviewed = DaemonPeerIdentity { uid: 501, pid: 42 };
        assert!(validate_daemon_peer_identity(reviewed, 501, None).is_ok());
        assert!(validate_daemon_peer_identity(reviewed, 501, Some(42)).is_ok());

        let foreign =
            validate_daemon_peer_identity(DaemonPeerIdentity { uid: 502, pid: 42 }, 501, Some(42))
                .unwrap_err();
        assert_eq!(foreign.kind(), std::io::ErrorKind::PermissionDenied);

        let wrong_process = validate_daemon_peer_identity(reviewed, 501, Some(43)).unwrap_err();
        assert_eq!(wrong_process.kind(), std::io::ErrorKind::PermissionDenied);

        let missing_process =
            validate_daemon_peer_identity(DaemonPeerIdentity { uid: 501, pid: 0 }, 501, None)
                .unwrap_err();
        assert_eq!(missing_process.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn headless_provider_launch_uses_trusted_shell_not_ambient_shell() {
        let launch = login_shell_launch("codex", &["--model".into(), "test".into()], true);
        assert_eq!(
            launch.command,
            crate::agent_dir::trusted_login_shell().unwrap_or_else(|_| "/dev/null".to_string())
        );
        assert_eq!(
            launch.args[0],
            maestro_local_services::LOGIN_SHELL_COMMAND_FLAGS
        );
        assert_eq!(launch.args[1], "'codex' '--model' 'test'");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn headless_opencode_resolution_ignores_ambient_home() {
        use std::os::unix::fs::PermissionsExt as _;

        let base = std::env::temp_dir().join(format!(
            "hydra-headless-opencode-policy-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let ambient = base.join("ambient");
        let trusted = base.join("trusted");
        let ambient_binary = ambient.join(".opencode/bin/opencode");
        let trusted_binary = trusted.join(".opencode/bin/opencode");
        std::fs::create_dir_all(ambient_binary.parent().unwrap()).unwrap();
        std::fs::create_dir_all(trusted_binary.parent().unwrap()).unwrap();
        std::fs::write(&ambient_binary, "#!/bin/sh\n").unwrap();
        std::fs::write(&trusted_binary, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&ambient_binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&trusted_binary, std::fs::Permissions::from_mode(0o755)).unwrap();

        assert_eq!(
            resolve_login_shell_command_from_homes(
                "opencode",
                true,
                Some(&ambient),
                Some(&trusted),
            ),
            trusted_binary.to_string_lossy()
        );
        assert_eq!(
            resolve_login_shell_command_from_homes(
                "opencode",
                false,
                Some(&ambient),
                Some(&trusted),
            ),
            ambient_binary.to_string_lossy()
        );
        let _ = std::fs::remove_dir_all(base);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn headless_session_creator_uses_the_account_login_shell() {
        let (tx, mut rx) = daemon_request_channel_with_policy(
            DAEMON_REQUEST_QUEUE_CAP,
            DAEMON_REQUEST_QUEUE_BYTE_CAP,
            true,
        );
        let _daemon = install_conditional_start_test_daemon(&tx);
        let mut creator = DaemonSessionCreator {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            home: "/tmp".into(),
        };
        creator.start_session("s-headless", "/tmp").unwrap();

        let line = rx.try_recv().unwrap();
        let request: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        let expected = crate::session_creator::empty_session_launch(true);
        let account = crate::agent_dir::trusted_session_account().unwrap();
        assert_eq!(request["command"], expected.command);
        assert_eq!(request["args"], serde_json::json!(expected.args));
        assert_eq!(
            request["child_environment"]["home"],
            account.home.to_str().unwrap()
        );
        assert_eq!(request["child_environment"]["shell"], account.shell);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn headless_sender_overwrites_a_forged_child_environment_at_final_queue() {
        let (tx, mut rx) = daemon_request_channel_with_policy(2, 4096, true);
        let forged = serde_json::json!({
            "op":"start_session",
            "id":"forged-environment",
            "cwd":"/tmp",
            "command":"/bin/sh",
            "args":[],
            "child_environment":{"home":"/attacker/home","shell":"/attacker/shell"},
            "cols":80,
            "rows":24
        })
        .to_string();
        tx.send(forged).unwrap();
        let queued: maestro_protocol::ClientRequest =
            serde_json::from_str(&rx.try_recv().unwrap()).unwrap();
        let account = crate::agent_dir::trusted_session_account().unwrap();
        let maestro_protocol::ClientRequest::StartSession {
            child_environment: Some(environment),
            ..
        } = queued
        else {
            panic!("headless sender omitted the fixed typed environment");
        };
        assert_eq!(environment.home, account.home.to_str().unwrap());
        assert_eq!(environment.shell, account.shell);
    }

    #[test]
    fn headless_default_cwd_refreshes_while_desktop_stays_cached() {
        let (headless_tx, _headless_rx) = daemon_request_channel_with_policy(1, 1024, true);
        let headless = DaemonSessionCreator {
            tx: headless_tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            home: "/cached/home".into(),
        };
        let account = |home: &str| crate::agent_dir::TrustedSessionAccount {
            home: std::path::PathBuf::from(home),
            shell: "/bin/sh".into(),
        };
        assert_eq!(
            headless
                .default_cwd_with(|| Ok(account("/current/home-one")))
                .unwrap(),
            "/current/home-one"
        );
        assert_eq!(
            headless
                .default_cwd_with(|| Ok(account("/current/home-two")))
                .unwrap(),
            "/current/home-two"
        );

        let (desktop_tx, _desktop_rx) = daemon_request_channel_with_policy(1, 1024, false);
        let desktop = DaemonSessionCreator {
            tx: desktop_tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            home: "/cached/desktop-home".into(),
        };
        assert_eq!(
            desktop
                .default_cwd_with(|| panic!("desktop must not query passwd on each create"))
                .unwrap(),
            "/cached/desktop-home"
        );
    }

    #[test]
    fn login_shell_launch_uses_the_configured_shell_and_platform_flags() {
        let launch = login_shell_launch_with_program(
            "codex",
            &["--model".into(), "gpt-5.2-codex".into()],
            "/bin/bash",
            false,
        );
        assert_eq!(launch.command, "/bin/bash");
        assert_eq!(
            launch.args,
            vec![
                maestro_local_services::LOGIN_SHELL_COMMAND_FLAGS.to_string(),
                "'codex' '--model' 'gpt-5.2-codex'".to_string(),
            ]
        );
        assert_eq!(login_shell_program_from(Some(" /bin/bash ")), "/bin/bash");
    }

    #[test]
    fn inherited_provider_profile_never_copies_a_source_session_selector() {
        const UUID: &str = "10000000-0000-4000-8000-000000000001";
        let cases = [
            ("claude", vec!["--resume", UUID]),
            ("codex", vec!["resume", UUID]),
            (
                "copilot",
                vec!["--resume=10000000-0000-4000-8000-000000000001"],
            ),
            ("agy", vec!["--conversation", UUID]),
            (
                "kimi",
                vec!["--session", "session_10000000-0000-4000-8000-000000000001"],
            ),
            ("kiro-cli", vec!["chat", "--resume-id", UUID]),
            ("agent", vec!["--resume", UUID]),
            ("amp", vec!["threads", "continue", "thread-source"]),
            ("devin", vec!["--resume", "devin-source"]),
            ("droid", vec!["--resume", "factory-source"]),
            ("gemini", vec!["--resume", UUID]),
            ("opencode", vec!["--session", "opencode-source"]),
        ];

        for (command, params) in cases {
            let source_markers = params
                .iter()
                .copied()
                .filter(|value| {
                    !matches!(
                        *value,
                        "--resume"
                            | "resume"
                            | "--conversation"
                            | "--session"
                            | "chat"
                            | "--resume-id"
                            | "threads"
                            | "continue"
                    )
                })
                .collect::<Vec<_>>();
            let session = maestro_shell::SessionRecord {
                session_id: format!("source-{command}"),
                workspace_id: "ws".into(),
                kind: maestro_shell::SessionKind::Agent,
                launch: maestro_shell::LaunchSpec::KnownSafe {
                    launch_spec_id: command.into(),
                    params: params.into_iter().map(str::to_string).collect(),
                },
                cwd_resolved: "/tmp".into(),
                agent_task_id: None,
                created_at_ms: 1,
                last_attached_at_ms: 1,
                last_known_generation: Some("source-generation".into()),
                status: maestro_shell::SessionStatus::Live,
            };
            let fresh = fresh_inherited_remote_session_launch(&session)
                .unwrap_or_else(|()| panic!("{command} provider profile must be accepted"))
                .unwrap_or_else(|| {
                    panic!("{command} provider profile must produce a fresh launch")
                });
            assert_eq!(fresh.command, command);
            for marker in source_markers {
                assert!(
                    fresh.args.iter().all(|value| !value.contains(marker)),
                    "{command} inherited the source selector {marker:?}: {:?}",
                    fresh.args
                );
            }
            match command {
                "claude" | "gemini" => {
                    assert_eq!(fresh.args.first().map(String::as_str), Some("--session-id"));
                    assert!(fresh
                        .args
                        .get(1)
                        .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok()));
                }
                "copilot" => assert!(fresh
                    .args
                    .first()
                    .and_then(|value| value.strip_prefix("--session-id="))
                    .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())),
                "kiro-cli" => assert_eq!(fresh.args, vec!["chat"]),
                _ => assert!(fresh.args.is_empty(), "agent={command}"),
            }
        }
    }

    #[test]
    fn inherited_launch_refuses_kind_mismatches_and_opaque_agent_wrappers() {
        let record = |kind, launch| maestro_shell::SessionRecord {
            session_id: "source".into(),
            workspace_id: "ws".into(),
            kind,
            launch,
            cwd_resolved: "/tmp".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: Some("source-generation".into()),
            status: maestro_shell::SessionStatus::Live,
        };
        let exact = maestro_shell::LaunchSpec::KnownSafe {
            launch_spec_id: "claude".into(),
            params: vec![
                "--resume".into(),
                "10000000-0000-4000-8000-000000000001".into(),
            ],
        };
        assert_eq!(
            fresh_inherited_remote_session_launch(&record(
                maestro_shell::SessionKind::Shell,
                exact,
            )),
            Err(()),
            "Shell/provider kind mismatch must never clone or relabel provider identity"
        );
        assert_eq!(
            fresh_inherited_remote_session_launch(&record(
                maestro_shell::SessionKind::Agent,
                maestro_shell::LaunchSpec::KnownSafe {
                    launch_spec_id: "unknown-agent".into(),
                    params: Vec::new(),
                },
            )),
            Err(()),
            "unknown Agent KnownSafe provenance must fail closed"
        );
        assert_eq!(
            fresh_inherited_remote_session_launch(&record(
                maestro_shell::SessionKind::Agent,
                maestro_shell::LaunchSpec::AdHocRedacted {
                    argv: vec![
                        "/bin/zsh".into(),
                        "-lic".into(),
                        "'claude' '--resume' '10000000-0000-4000-8000-000000000001'".into(),
                    ],
                    redacted: true,
                    restart_requires_user: true,
                },
            )),
            Err(()),
            "opaque Agent wrapper must not replay a hidden provider selector"
        );
        for launch in [
            maestro_shell::LaunchSpec::KnownSafe {
                launch_spec_id: "/usr/local/bin/claude".into(),
                params: vec![
                    "--resume".into(),
                    "10000000-0000-4000-8000-000000000001".into(),
                ],
            },
            maestro_shell::LaunchSpec::KnownSafe {
                launch_spec_id: "/bin/zsh".into(),
                params: vec!["-lic".into(), "'claude' '--continue'".into()],
            },
        ] {
            assert_eq!(
                fresh_inherited_remote_session_launch(&record(
                    maestro_shell::SessionKind::Shell,
                    launch,
                )),
                Ok(None),
                "unknown Shell recipe must become an empty child, never replay hidden provider bytes"
            );
        }
        assert_eq!(
            fresh_inherited_remote_session_launch(&record(
                maestro_shell::SessionKind::Shell,
                maestro_shell::LaunchSpec::OptOut,
            )),
            Ok(None),
            "an ordinary terminal inherits the reviewed empty shell"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn remote_provider_launch_resolves_a_zshrc_only_executable() {
        use std::os::unix::fs::PermissionsExt;

        let home = std::env::temp_dir().join(format!(
            "hydra-remote-login-shell-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        let bin = home.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(
            home.join(".zshrc"),
            "export PATH=\"$HOME/bin:/usr/bin:/bin\"\n",
        )
        .unwrap();
        let codex = bin.join("codex");
        std::fs::write(&codex, "#!/bin/sh\nprintf 'remote-codex-resolved\\n'\n").unwrap();
        std::fs::set_permissions(&codex, std::fs::Permissions::from_mode(0o755)).unwrap();

        let launch = login_shell_launch_with_program("codex", &[], "/bin/zsh", false);
        let output = std::process::Command::new(&launch.command)
            .args(&launch.args)
            .env("HOME", &home)
            .env("ZDOTDIR", &home)
            .env("PATH", "/usr/bin:/bin")
            .output()
            .unwrap();

        std::fs::remove_dir_all(&home).unwrap();
        assert!(
            output.status.success(),
            "stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            "remote-codex-resolved\n"
        );
    }

    #[test]
    fn every_remote_provider_first_start_uses_the_login_shell() {
        for command in [
            "claude", "codex", "copilot", "agy", "kimi", "kiro-cli", "agent", "amp", "devin",
            "droid", "gemini", "opencode",
        ] {
            let launch = crate::resume_launch::ResumeLaunch {
                command: command.into(),
                args: vec!["--model".into(), "value with spaces".into()],
            };
            let runtime = runtime_remote_session_launch(Some(&launch), false);
            assert_eq!(runtime.command, login_shell_program(), "provider={command}");
            assert_eq!(
                runtime.args[0],
                maestro_local_services::LOGIN_SHELL_COMMAND_FLAGS,
                "provider={command}"
            );
            let command_line = &runtime.args[1];
            assert!(
                command_line.contains("'--model' 'value with spaces'"),
                "provider={command}: {command_line}"
            );
        }
    }

    #[test]
    fn remote_non_provider_and_terminal_starts_remain_direct() {
        let utility = crate::resume_launch::ResumeLaunch {
            command: "/usr/bin/env".into(),
            args: vec!["true".into()],
        };
        let runtime = runtime_remote_session_launch(Some(&utility), false);
        assert_eq!(runtime.command, "/usr/bin/env");
        assert_eq!(runtime.args, vec!["true"]);

        let runtime = runtime_remote_session_launch(None, false);
        let expected = crate::session_creator::empty_session_launch(false);
        assert_eq!(runtime, expected);
    }

    #[test]
    fn recorded_terminal_restart_uses_the_same_platform_shell_policy() {
        let session = maestro_shell::SessionRecord {
            session_id: "s-terminal".into(),
            workspace_id: "ws".into(),
            kind: maestro_shell::SessionKind::Shell,
            launch: maestro_shell::LaunchSpec::OptOut,
            cwd_resolved: "/tmp/project".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status: maestro_shell::SessionStatus::Exited,
        };
        let runtime = recorded_remote_session_launch(&session, false)
            .unwrap_or_else(|| crate::session_creator::empty_session_launch(false));
        let expected = crate::session_creator::empty_session_launch(false);
        assert_eq!(runtime, expected);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recorded_headless_provider_restart_uses_the_trusted_login_shell() {
        let session = maestro_shell::SessionRecord {
            session_id: "s-provider".into(),
            workspace_id: "ws".into(),
            kind: maestro_shell::SessionKind::Agent,
            launch: maestro_shell::LaunchSpec::KnownSafe {
                launch_spec_id: "codex".into(),
                params: vec!["resume".into(), "opaque-id".into()],
            },
            cwd_resolved: "/tmp/project".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status: maestro_shell::SessionStatus::Exited,
        };
        let runtime = recorded_remote_session_launch(&session, true).unwrap();
        assert_eq!(
            runtime.command,
            crate::agent_dir::trusted_login_shell().unwrap_or_else(|_| "/dev/null".to_string())
        );
        assert_eq!(
            runtime.args,
            vec![
                maestro_local_services::LOGIN_SHELL_COMMAND_FLAGS,
                "'codex' 'resume' 'opaque-id'"
            ]
        );
    }

    #[test]
    fn an_already_wrapped_provider_launch_is_not_nested() {
        let wrapped = login_shell_launch_with_program(
            "claude",
            &["--dangerously-skip-permissions".into()],
            "/bin/zsh",
            false,
        );
        let runtime = runtime_remote_session_launch(Some(&wrapped), false);
        assert_eq!(runtime.command, "/bin/zsh");
        assert_eq!(
            runtime.args,
            vec![
                maestro_local_services::LOGIN_SHELL_COMMAND_FLAGS,
                "'claude' '--dangerously-skip-permissions'"
            ]
        );
    }

    #[test]
    fn fresh_provider_launch_maps_identity_and_preserves_model_as_one_argv() {
        let copilot = fresh_remote_agent_launch("copilot", Some("auto"), true).unwrap();
        assert_eq!(copilot.command, "copilot");
        assert_eq!(copilot.args.len(), 4);
        let id = copilot.args[0].strip_prefix("--session-id=").unwrap();
        assert_eq!(
            uuid::Uuid::parse_str(id).unwrap().hyphenated().to_string(),
            id
        );
        assert_eq!(&copilot.args[1..], &["--model", "auto", "--yolo"]);

        assert_eq!(
            fresh_remote_agent_launch(
                "antigravity",
                Some("Gemini 3.5 Flash (High) / preview"),
                false,
            ),
            Some(crate::resume_launch::ResumeLaunch {
                command: "agy".into(),
                args: vec!["--model".into(), "Gemini 3.5 Flash (High) / preview".into(),],
            })
        );
        assert_eq!(agent_title("copilot"), "Copilot");
        assert_eq!(agent_title("antigravity"), "Antigravity");
        assert_eq!(agent_title("kimi"), "Kimi");
        assert_eq!(agent_title("kiro"), "Kiro");
        assert_eq!(agent_title("cursor"), "Cursor");
        assert_eq!(agent_title("amp"), "Amp");
        assert_eq!(agent_title("devin"), "Devin");
        assert_eq!(agent_title("factory"), "Factory");
        assert_eq!(
            fresh_remote_agent_launch("kimi", Some("kimi-code/k3"), true),
            Some(crate::resume_launch::ResumeLaunch {
                command: "kimi".into(),
                args: vec!["--model".into(), "kimi-code/k3".into(), "--yolo".into()],
            })
        );
        assert_eq!(
            fresh_remote_agent_launch("kiro", Some("claude-sonnet-4.5"), true),
            Some(crate::resume_launch::ResumeLaunch {
                command: "kiro-cli".into(),
                args: vec![
                    "chat".into(),
                    "--model".into(),
                    "claude-sonnet-4.5".into(),
                    "--trust-all-tools".into(),
                ],
            })
        );
        assert_eq!(
            fresh_remote_agent_launch("cursor", Some("composer-2.5"), true),
            Some(crate::resume_launch::ResumeLaunch {
                command: "agent".into(),
                args: vec!["--model".into(), "composer-2.5".into(), "--yolo".into()],
            })
        );
        assert_eq!(
            fresh_remote_agent_launch("amp", Some("must-not-leak"), true),
            Some(crate::resume_launch::ResumeLaunch {
                command: "amp".into(),
                args: vec!["--dangerously-allow-all".into()],
            })
        );
        assert_eq!(
            fresh_remote_agent_launch("devin", Some("opus"), true),
            Some(crate::resume_launch::ResumeLaunch {
                command: "devin".into(),
                args: vec![
                    "--model".into(),
                    "opus".into(),
                    "--permission-mode=dangerous".into(),
                ],
            })
        );
        assert_eq!(
            fresh_remote_agent_launch("factory", Some("must-not-leak"), true),
            Some(crate::resume_launch::ResumeLaunch {
                command: "droid".into(),
                args: vec!["--auto=high".into()],
            })
        );
    }

    #[test]
    fn continue_provider_launch_uses_each_exact_cli_shape() {
        for (agent, command, args) in [
            ("claude", "claude", vec!["--continue"]),
            ("codex", "codex", vec!["resume", "--last"]),
            ("copilot", "copilot", vec!["--continue"]),
            ("antigravity", "agy", vec!["--continue"]),
            ("kimi", "kimi", vec!["--continue"]),
            ("kiro", "kiro-cli", vec!["chat", "--resume"]),
            ("cursor", "agent", vec!["--continue"]),
            ("amp", "amp", vec!["last"]),
            ("devin", "devin", vec!["--continue"]),
            ("factory", "droid", vec!["--resume"]),
            ("gemini", "gemini", vec!["--resume", "latest"]),
            ("opencode", "opencode", vec!["--continue"]),
        ] {
            assert_eq!(
                continue_remote_agent_launch(agent),
                Some(crate::resume_launch::ResumeLaunch {
                    command: command.into(),
                    args: args.into_iter().map(str::to_string).collect(),
                }),
                "provider={agent}"
            );
        }
    }

    #[test]
    fn login_shell_quotes_provider_model_labels_without_evaluation() {
        let launch = login_shell_launch_with_program(
            "agy",
            &["--model".into(), "Gemini 3.5 Flash (High) / preview".into()],
            "/bin/bash",
            false,
        );
        assert_eq!(launch.command, "/bin/bash");
        assert_eq!(
            launch.args,
            vec![
                maestro_local_services::LOGIN_SHELL_COMMAND_FLAGS.to_string(),
                "'agy' '--model' 'Gemini 3.5 Flash (High) / preview'".to_string(),
            ]
        );
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn login_shell_launch_has_a_portable_non_macos_fallback() {
        assert_eq!(login_shell_program_from(None), "/bin/sh");
        assert_eq!(login_shell_program_from(Some("   ")), "/bin/sh");
    }

    #[test]
    fn daemon_metadata_routes_top_level_and_damage_ids() {
        assert_eq!(
            daemon_line_metadata(r#"{"ev":"output","id":"s1","data":"AAAA"}"#)
                .and_then(|metadata| metadata.session_id),
            Some("s1".into())
        );
        assert_eq!(
            daemon_line_metadata(r#"{"ev":"sessions","ids":["s1"]}"#)
                .and_then(|metadata| metadata.session_id),
            None
        ); // no top-level id
        assert_eq!(daemon_line_metadata("not json"), None);
        assert_eq!(
            daemon_line_metadata(r#"{"ev":"output","id":"s1"} trailing"#),
            None,
            "the streaming parser must preserve serde_json::from_str's trailing-data rejection"
        );
        // REGRESSION: a `damage` event nests its id under frame.id (no top-level id). It MUST be routed,
        // or the browser gets no incremental updates and falls back to full-grid resyncs every keypress.
        assert_eq!(
            daemon_line_metadata(r#"{"ev":"damage","frame":{"id":"s1","schema":1,"ops":[]}}"#)
                .and_then(|metadata| metadata.session_id),
            Some("s1".into())
        );
        assert_eq!(
            daemon_line_metadata(r#"{"frame":{"ops":[],"id":"nested"},"id":"top","ev":"damage"}"#)
                .and_then(|metadata| metadata.session_id),
            Some("top".into()),
            "the historical top-level-id precedence must survive member reordering"
        );
        let echoed = daemon_line_metadata(
            r#"{"ev":"grid","id":"s1","output_generation":42,"grid":{"rows_cells":[]}}"#,
        )
        .expect("echoed attach baseline metadata");
        assert_eq!(echoed.event, DaemonEventClass::Grid);
        assert_eq!(echoed.output_generation, Some(42));
        let live = daemon_line_metadata(
            r#"{"ev":"damage","live_output_generation":41,"frame":{"id":"s1","ops":[]}}"#,
        )
        .expect("tagged live output metadata");
        assert_eq!(live.live_output_generation, Some(41));
    }

    #[test]
    fn daemon_metadata_reads_the_live_set_in_the_same_pass() {
        assert_eq!(
            daemon_line_metadata(r#"{"ev":"sessions","ids":["s1","s2"]}"#)
                .and_then(|metadata| metadata.sessions),
            Some((
                vec!["s1".into(), "s2".into()],
                vec![],
                std::collections::BTreeMap::new(),
            ))
        );
        assert_eq!(
            daemon_line_metadata(
                r#"{"ev":"sessions","ids":["s1"],"sessions":[{"id":"s1","cwd":"/workspace/app","generation":"pty-s1"}]}"#
            )
            .and_then(|metadata| metadata.sessions),
            Some((
                vec!["s1".into()],
                vec![SessionMetadata {
                    id: "s1".into(),
                    cwd: Some("/workspace/app".into())
                }],
                std::collections::BTreeMap::from([("s1".into(), "pty-s1".into())]),
            ))
        );
        assert_eq!(
            daemon_line_metadata(r#"{"ev":"output","id":"s1"}"#)
                .and_then(|metadata| metadata.sessions),
            None
        );
        assert_eq!(daemon_line_metadata("nope"), None);
    }

    #[test]
    fn daemon_metadata_skips_large_terminal_trees_without_route_confusion() {
        let large_cell_payload = "x".repeat(4 * 1024 * 1024);
        let grid = format!(
            r#"{{"ev":"grid","id":"grid-session","grid":{{"rows_cells":[[{{"text":"{large_cell_payload}","decoy":{{"id":"wrong"}}}}]]}}}}"#
        );
        let grid_metadata = daemon_line_metadata(&grid).expect("large canonical Grid must parse");
        assert_eq!(grid_metadata.event, DaemonEventClass::Grid);
        assert_eq!(grid_metadata.session_id.as_deref(), Some("grid-session"));
        assert_eq!(grid_metadata.sessions, None);

        let damage = format!(
            r#"{{"ev":"damage","frame":{{"schema":1,"id":"damage-session","ops":[{{"payload":"{large_cell_payload}","id":"wrong"}}]}}}}"#
        );
        let damage_metadata =
            daemon_line_metadata(&damage).expect("large canonical Damage must parse");
        assert_eq!(damage_metadata.event, DaemonEventClass::Damage);
        assert_eq!(
            damage_metadata.session_id.as_deref(),
            Some("damage-session")
        );
        assert_eq!(damage_metadata.sessions, None);
    }

    #[test]
    fn daemon_metadata_uses_exact_event_values_not_payload_substrings() {
        let metadata = daemon_line_metadata(
            r#"{"ev":"output","id":"s1","data":"embedded \"ev\":\"grid\" marker"}"#,
        )
        .expect("valid output event");
        assert_eq!(metadata.event, DaemonEventClass::Output);
        assert_eq!(metadata.event.output_label(), "output");
    }

    #[test]
    fn streaming_metadata_preserves_legacy_route_and_sessions_results() {
        fn legacy(line: &str) -> Option<LegacyDaemonLineMetadata> {
            let value: serde_json::Value = serde_json::from_str(line).ok()?;
            let session_id = value
                .get("id")
                .and_then(serde_json::Value::as_str)
                .or_else(|| {
                    value
                        .get("frame")
                        .and_then(|frame| frame.get("id"))
                        .and_then(serde_json::Value::as_str)
                })
                .map(str::to_owned);
            let sessions = (value.get("ev").and_then(serde_json::Value::as_str)
                == Some("sessions"))
            .then(|| {
                let ids = value
                    .get("ids")?
                    .as_array()?
                    .iter()
                    .filter_map(|id| id.as_str().map(str::to_owned))
                    .collect();
                let metadata = value
                    .get("sessions")
                    .and_then(serde_json::Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|item| {
                                let id = item.get("id")?.as_str()?.to_owned();
                                let cwd = item
                                    .get("cwd")
                                    .and_then(serde_json::Value::as_str)
                                    .map(str::to_owned);
                                Some(SessionMetadata { id, cwd })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let generations = value
                    .get("sessions")
                    .and_then(serde_json::Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|item| {
                                Some((
                                    item.get("id")?.as_str()?.to_owned(),
                                    item.get("generation")?.as_str()?.to_owned(),
                                ))
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                Some((ids, metadata, generations))
            })
            .flatten();
            Some((session_id, sessions))
        }

        let fixtures = [
            r#"{"ev":"grid","id":"s1","grid":{"rows_cells":[]}}"#,
            r#"{"grid":{"rows_cells":[]},"id":"s1","ev":"grid"}"#,
            r#"{"ev":"damage","frame":{"schema":1,"id":"s2","ops":[]}}"#,
            r#"{"frame":{"ops":[],"id":"nested"},"id":"top","ev":"damage"}"#,
            r#"{"ev":"sessions","ids":["s1",7,"s2"],"sessions":[{"id":"s1","cwd":"/workspace"},{"cwd":"ignored"},7]}"#,
            r#"{"ev":"unknown","id":"still-routed","payload":{"id":"decoy"}}"#,
            r#"{"ev":"sessions","ids":"wrong-shape","sessions":[]}"#,
            r#"{"ev":"output","id":7,"data":"AAAA"}"#,
        ];
        for line in fixtures {
            let expected = legacy(line).expect("legacy fixture JSON");
            let actual = daemon_line_metadata(line).expect("streaming fixture JSON");
            assert_eq!(
                (actual.session_id, actual.sessions),
                expected,
                "fixture={line}"
            );
        }
    }

    #[test]
    fn daemon_backend_list_sessions_merges_live_sqlite_sessions_when_daemon_cache_is_stale() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-live-session-merge-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let project = maestro_shell::Project {
            project_id: "proj-new".into(),
            name: "New".into(),
            root: "/tmp/new".into(),
            default_workspace_policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            created_at_ms: 1,
            last_active_at_ms: 1,
            icon: None,
            accent_color: None,
            launch_defaults: None,
            directories: Vec::new(),
            window_order: vec!["win-new".into()],
            system: false,
            hidden: false,
        };
        let workspace = maestro_shell::Workspace {
            workspace_id: "ws-new".into(),
            project_id: project.project_id.clone(),
            root: project.root.clone(),
            policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            consent: maestro_shell::WorkspaceConsent::default(),
        };
        let session = maestro_shell::SessionRecord {
            session_id: "s-new".into(),
            workspace_id: workspace.workspace_id.clone(),
            kind: maestro_shell::SessionKind::Agent,
            launch: maestro_shell::LaunchSpec::KnownSafe {
                launch_spec_id: "claude".into(),
                params: Vec::new(),
            },
            cwd_resolved: project.root.clone(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status: maestro_shell::SessionStatus::Live,
        };
        let window = maestro_shell::WindowLayout {
            window_id: "win-new".into(),
            name: Some("Window 1".into()),
            tabs: vec![maestro_shell::TabRecord {
                tab_id: "pane-1".into(),
                session_id: session.session_id.clone(),
                index: 0,
                title: "Pane 1".into(),
                pinned: false,
                attention: maestro_shell::AttentionState::default(),
                split_from: None,
                pane_rect: None,
                stashed_from: None,
                stashed: false,
            }],
        };
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Project,
            &project.project_id,
            1,
            &project,
        )
        .unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Workspace,
            &workspace.workspace_id,
            1,
            &workspace,
        )
        .unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Session,
            &session.session_id,
            1,
            &session,
        )
        .unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::WindowLayout,
            &window.window_id,
            1,
            &window,
        )
        .unwrap();

        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let backend = DaemonBackend {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::seeded(vec![
                "s-old".into(),
                PRODUCT_RECOVERY_SESSION_ID.into(),
            ]))),
            session_metadata: Arc::new(Mutex::new(Vec::new())),
            dashboard_paths: Some(paths),
            raw_output: Arc::new(AtomicBool::new(false)),
            output_routes: Arc::new(Mutex::new(DaemonOutputRoutes::new(false))),
            pending_attach_sizes: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
        };

        assert_eq!(
            backend.list_sessions(),
            vec!["s-new".to_string(), "s-old".to_string()]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn workspace_metadata_from_dashboard_uses_local_project_window_pane_records() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-dashboard-metadata-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let project = maestro_shell::Project {
            project_id: "proj-capacity".into(),
            name: "capacity total".into(),
            root: "/Users/test/Desktop/project-example".into(),
            default_workspace_policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            created_at_ms: 1,
            last_active_at_ms: 2,
            icon: Some("◉".into()),
            accent_color: Some("#34d399".into()),
            // launch defaults + directories must SURFACE in metadata (Edit Project prefill path).
            launch_defaults: Some(maestro_shell::ProjectLaunchDefaults {
                agent: Some("codex".into()),
                resume_mode: Some("resume".into()),
                model: Some("claude-opus-4-8".into()),
                dangerous_skip_permissions: Some(true),
                custom_command: Some("claude --foo".into()),
            }),
            directories: vec![maestro_shell::ProjectDirectory {
                id: "dir-0-api".into(),
                name: "api".into(),
                path: "/Users/test/api".into(),
            }],
            window_order: vec!["win-main".into()],
            system: false,
            hidden: false,
        };
        let workspace = maestro_shell::Workspace {
            workspace_id: "ws-capacity".into(),
            project_id: project.project_id.clone(),
            root: project.root.clone(),
            policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            consent: maestro_shell::WorkspaceConsent::default(),
        };
        let session = maestro_shell::SessionRecord {
            session_id: "s-build".into(),
            workspace_id: workspace.workspace_id.clone(),
            kind: maestro_shell::SessionKind::Agent,
            launch: maestro_shell::LaunchSpec::KnownSafe {
                launch_spec_id: "claude".into(),
                params: Vec::new(),
            },
            cwd_resolved: project.root.clone(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status: maestro_shell::SessionStatus::Live,
        };
        let window = maestro_shell::WindowLayout {
            window_id: "win-main".into(),
            name: Some("Main window".into()),
            tabs: vec![maestro_shell::TabRecord {
                tab_id: "pane-build".into(),
                session_id: session.session_id.clone(),
                index: 0,
                title: "Build".into(),
                pinned: false,
                attention: maestro_shell::AttentionState::default(),
                split_from: None,
                pane_rect: Some(maestro_shell::PaneRect {
                    x: 0,
                    y: 0,
                    w: 1000,
                    h: 1000,
                }),
                stashed_from: None,
                stashed: true,
            }],
        };
        // The installed product always owns this hidden fallback topology. It is newer than the user project on
        // purpose: the remote projection must remove it BEFORE active-project selection, while retaining the
        // ordinary project and its complete metadata.
        let recovery_project = maestro_shell::Project {
            project_id: PRODUCT_RECOVERY_PROJECT_ID.into(),
            name: "Product Recovery".into(),
            root: "/Users/test/home".into(),
            default_workspace_policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            created_at_ms: 1,
            last_active_at_ms: 99,
            icon: None,
            accent_color: None,
            launch_defaults: None,
            directories: Vec::new(),
            window_order: vec!["system-product-recovery-window".into()],
            system: true,
            hidden: true,
        };
        let recovery_window = maestro_shell::WindowLayout {
            window_id: "system-product-recovery-window".into(),
            name: Some("Recovery".into()),
            tabs: vec![maestro_shell::TabRecord {
                tab_id: "system-product-recovery-pane".into(),
                session_id: PRODUCT_RECOVERY_SESSION_ID.into(),
                index: 0,
                title: "Terminal".into(),
                pinned: false,
                attention: maestro_shell::AttentionState::default(),
                split_from: None,
                pane_rect: None,
                stashed_from: None,
                stashed: false,
            }],
        };
        let recovery_workspace = maestro_shell::Workspace {
            workspace_id: "system-product-recovery-workspace".into(),
            project_id: PRODUCT_RECOVERY_PROJECT_ID.into(),
            root: recovery_project.root.clone(),
            policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            consent: maestro_shell::WorkspaceConsent::default(),
        };
        let recovery_session = maestro_shell::SessionRecord {
            session_id: PRODUCT_RECOVERY_SESSION_ID.into(),
            workspace_id: recovery_workspace.workspace_id.clone(),
            kind: maestro_shell::SessionKind::Shell,
            launch: maestro_shell::LaunchSpec::OptOut,
            cwd_resolved: recovery_project.root.clone(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 99,
            last_known_generation: None,
            status: maestro_shell::SessionStatus::Live,
        };

        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Project,
            &project.project_id,
            1,
            &project,
        )
        .unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Workspace,
            &workspace.workspace_id,
            1,
            &workspace,
        )
        .unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Session,
            &session.session_id,
            1,
            &session,
        )
        .unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Project,
            &recovery_project.project_id,
            99,
            &recovery_project,
        )
        .unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Workspace,
            &recovery_workspace.workspace_id,
            99,
            &recovery_workspace,
        )
        .unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Session,
            &recovery_session.session_id,
            99,
            &recovery_session,
        )
        .unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::WindowLayout,
            &window.window_id,
            1,
            &window,
        )
        .unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::WindowLayout,
            &recovery_window.window_id,
            99,
            &recovery_window,
        )
        .unwrap();

        assert_eq!(
            workspace_metadata_from_dashboard(&paths),
            Some(WorkspaceMetadata {
                projects: vec![WorkspaceProjectMetadata {
                    id: "proj-capacity".into(),
                    name: "capacity total".into(),
                    root: "/Users/test/Desktop/project-example".into(),
                    icon: Some("◉".into()),
                    accent_color: Some("#34d399".into()),
                    // The sole project is the active one (max last_active_at_ms), so it is marked selected — the
                    // browser mirrors the desktop's active project (parity step 9).
                    selected: true,
                    system: false,
                    hidden: false,
                    // launch defaults + directories surface for Edit Project prefill (mapped from the record).
                    launch_defaults: Some(crate::remote_bridge::WorkspaceLaunchDefaults {
                        agent: Some("codex".into()),
                        resume_mode: Some("resume".into()),
                        model: Some("claude-opus-4-8".into()),
                        dangerous: Some(true),
                        custom_command: Some("claude --foo".into()),
                    }),
                    directories: vec![crate::remote_bridge::WorkspaceDirectory {
                        name: "api".into(),
                        path: "/Users/test/api".into(),
                    }],
                    windows: vec![WorkspaceWindowMetadata {
                        id: "win-main".into(),
                        name: Some("Main window".into()),
                        focused: false,
                        stashed: false,
                        panes: vec![WorkspacePaneMetadata {
                            id: "pane-build".into(),
                            session_id: "s-build".into(),
                            name: Some("Build".into()),
                            stashed: true,
                            cwd: Some("/Users/test/Desktop/project-example".into()),
                        }],
                    }],
                }],
            })
        );
        assert_eq!(
            live_session_ids_from_dashboard(&paths),
            vec!["s-build".to_string()],
            "private recovery session must not leak through the flat live-session projection"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn active_project_is_the_most_recently_active_one() {
        // parity step 9: exactly the greatest last_active_at_ms is the active/selected project.
        assert_eq!(
            active_project_id_by_recency([("a", 10u64), ("b", 30), ("c", 20)].into_iter())
                .as_deref(),
            Some("b")
        );
        // ties break deterministically by id (so the browser doesn't flicker between equal-timestamp projects).
        assert_eq!(
            active_project_id_by_recency([("z", 5u64), ("a", 5)].into_iter()).as_deref(),
            Some("z")
        );
        // empty → none selected.
        assert_eq!(
            active_project_id_by_recency(std::iter::empty::<(&str, u64)>()),
            None
        );
    }

    #[test]
    fn project_surfaces_with_its_window_even_when_the_window_has_no_live_panes() {
        // The user's real local projects were missing from the browser because a window whose panes are all stashed
        // (no visible panes) — and a project with only such windows — was dropped by the metadata builder. The local
        // dashboard shows these; so must the browser. Mirrors the full-metadata fixture but the sole tab is stashed
        // (so panes come through, but the window would previously have been filterable). Pins: project + window
        // surface; the window is present.
        let dir =
            std::env::temp_dir().join(format!("hydra-idle-window-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let project = maestro_shell::Project {
            project_id: "proj-idle".into(),
            name: "idle".into(),
            root: "/Users/test/idle".into(),
            default_workspace_policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            created_at_ms: 1,
            last_active_at_ms: 1,
            icon: None,
            accent_color: None,
            launch_defaults: None,
            directories: Vec::new(),
            window_order: vec!["win-idle".into()],
            system: false,
            hidden: false,
        };
        let workspace = maestro_shell::Workspace {
            workspace_id: "ws-idle".into(),
            project_id: project.project_id.clone(),
            root: project.root.clone(),
            policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            consent: maestro_shell::WorkspaceConsent::default(),
        };
        let session = maestro_shell::SessionRecord {
            session_id: "s-idle".into(),
            workspace_id: workspace.workspace_id.clone(),
            kind: maestro_shell::SessionKind::Agent,
            launch: maestro_shell::LaunchSpec::KnownSafe {
                launch_spec_id: "claude".into(),
                params: Vec::new(),
            },
            cwd_resolved: project.root.clone(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status: maestro_shell::SessionStatus::Exited,
        };
        let window = maestro_shell::WindowLayout {
            window_id: "win-idle".into(),
            name: Some("Window 1".into()),
            tabs: vec![maestro_shell::TabRecord {
                tab_id: "pane-1".into(),
                session_id: session.session_id.clone(),
                index: 0,
                title: "Pane 1".into(),
                pinned: false,
                attention: maestro_shell::AttentionState::default(),
                split_from: None,
                pane_rect: None,
                stashed_from: None,
                stashed: true, // dormant — the window has no VISIBLE panes
            }],
        };
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Project,
            &project.project_id,
            1,
            &project,
        )
        .unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Workspace,
            &workspace.workspace_id,
            1,
            &workspace,
        )
        .unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Session,
            &session.session_id,
            1,
            &session,
        )
        .unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::WindowLayout,
            &window.window_id,
            1,
            &window,
        )
        .unwrap();

        let meta = workspace_metadata_from_dashboard(&paths).expect("metadata present");
        let proj = meta
            .projects
            .iter()
            .find(|p| p.id == "proj-idle")
            .expect("idle project must surface");
        assert_eq!(
            proj.windows.len(),
            1,
            "the window must surface even though its pane is stashed"
        );
        assert_eq!(proj.windows[0].name.as_deref(), Some("Window 1"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn project_surfaces_with_empty_window_linked_by_window_order() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-empty-window-order-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let project = maestro_shell::Project {
            project_id: "proj-empty".into(),
            name: "empty".into(),
            root: "/Users/test/empty".into(),
            default_workspace_policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            created_at_ms: 1,
            last_active_at_ms: 1,
            icon: None,
            accent_color: None,
            launch_defaults: None,
            directories: Vec::new(),
            window_order: vec!["win-empty".into()],
            system: false,
            hidden: false,
        };
        let window = maestro_shell::WindowLayout {
            window_id: "win-empty".into(),
            name: Some("Window 1".into()),
            tabs: Vec::new(),
        };
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Project,
            &project.project_id,
            1,
            &project,
        )
        .unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::WindowLayout,
            &window.window_id,
            1,
            &window,
        )
        .unwrap();

        let meta = workspace_metadata_from_dashboard(&paths).expect("metadata present");
        let proj = meta
            .projects
            .iter()
            .find(|p| p.id == "proj-empty")
            .expect("empty project must surface");
        assert_eq!(proj.windows.len(), 1);
        assert_eq!(proj.windows[0].id, "win-empty");
        assert_eq!(proj.windows[0].name.as_deref(), Some("Window 1"));
        assert!(proj.windows[0].panes.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_project_editor_persists_desktop_project_fields() {
        let dir =
            std::env::temp_dir().join(format!("hydra-project-edit-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let project_root = dir.join("project-root");
        std::fs::create_dir_all(&project_root).unwrap();
        let project_root = project_root.to_string_lossy().into_owned();
        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let daemon = install_conditional_start_test_daemon(&tx);
        let lease_dir = dir.join("creation-lease");
        install_creation_lease_publisher(&tx, &lease_dir);
        let sessions = std::sync::Arc::new(std::sync::Mutex::new(
            SessionCache::mutation_ready_for_test(),
        ));
        let mut editor = DaemonProjectEditor {
            tx,
            sessions: sessions.clone(),
            paths: paths.clone(),
        };

        let created = editor
            .create_project_with_initial_size(
                crate::remote_control::ProjectEditRequest {
                    project_id: None,
                    name: Some("Capacity Total".into()),
                    root: Some(project_root.clone()),
                    icon: Some("KP".into()),
                    accent_color: Some("#34d399".into()),
                    agent: Some("codex".into()),
                    resume_mode: None,
                    resume_session_id: None,
                    model: None,
                    dangerous: None,
                    custom_command: None,
                    directories: None,
                    now_ms: 4242,
                },
                InitialTerminalSize::from_optional_pair(Some(132), Some(43)),
            )
            .unwrap();

        assert_eq!(created.project_id, "proj-capacity-total-4242");
        // Item C: the CREATE result carries the seeded first pane's session id (browser auto-attach).
        assert_eq!(
            created.session_id,
            Some(default_remote_project_pane_session_id(&created.project_id))
        );
        assert_creation_lease(
            &lease_dir,
            created.session_id.as_deref().expect("seeded session id"),
        );
        let project = maestro_shell::ProjectService::new(&paths)
            .load(&created.project_id)
            .unwrap()
            .unwrap();
        assert_eq!(project.name, "Capacity Total");
        assert_eq!(project.root, project_root);
        assert_eq!(project.icon.as_deref(), Some("KP"));
        assert_eq!(project.accent_color.as_deref(), Some("#34d399"));
        assert_eq!(
            project
                .launch_defaults
                .as_ref()
                .and_then(|defaults| defaults.agent.as_deref()),
            Some("codex")
        );
        let window_id = default_remote_project_window_id(&created.project_id);
        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load(&window_id)
            .unwrap()
            .unwrap();
        assert_eq!(layout.name.as_deref(), Some("Window 1"));
        assert_eq!(layout.tabs.len(), 1);
        assert_eq!(layout.tabs[0].tab_id, "pane-1");
        assert_eq!(layout.tabs[0].title, "Pane 1");
        assert_eq!(
            layout.tabs[0].session_id,
            default_remote_project_pane_session_id(&created.project_id)
        );
        let session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &layout.tabs[0].session_id,
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(session) => session,
            _ => panic!("expected loaded default project pane session"),
        };
        assert_eq!(session.cwd_resolved, project_root);
        assert_eq!(
            session.workspace_id,
            default_remote_project_workspace_id(&created.project_id)
        );
        assert!(
            matches!(
                session.launch,
                maestro_shell::LaunchSpec::AdHocRedacted {
                    redacted: true,
                    restart_requires_user: true,
                    ..
                }
            ),
            "fresh Codex has no caller-assigned identity and must remain non-replayable"
        );
        // Record/launch parity (Bug A class): the form picked codex EXPLICITLY, so the seeded pane's PTY
        // must actually run codex — previously the record said codex while the daemon started a bare shell.
        assert_provider_start_executes_exact_source(
            &only_conditional_start(&daemon),
            &layout.tabs[0].session_id,
            &session.cwd_resolved,
            &["codex".into()],
            InitialTerminalSize::from_optional_pair(Some(132), Some(43)),
        );
        assert_eq!(
            sessions.lock().unwrap().snapshot(),
            vec![layout.tabs[0].session_id.clone()]
        );
        // REGRESSION (the NULL-project_id corruption class): the seeded window's ownership FK must
        // be stamped — browser-created projects used to skip set_window_project entirely, leaving
        // the window NULL-owned. And the whole store must satisfy the Stability-B invariant oracle.
        assert_eq!(
            maestro_shell::store::window_project_owners(&paths)
                .unwrap()
                .into_iter()
                .find(|(wid, _)| wid == &window_id)
                .and_then(|(_, pid)| pid)
                .as_deref(),
            Some(created.project_id.as_str()),
            "seeded window must carry its owner FK"
        );
        assert_eq!(
            maestro_shell::invariants::check_store_invariants(&paths).unwrap(),
            Vec::new(),
            "browser project_create must leave a coherent store"
        );

        let updated = editor
            .update_project(crate::remote_control::ProjectEditRequest {
                project_id: Some(created.project_id.clone()),
                name: Some("Capacity Browser".into()),
                root: Some("/tmp/capacity-browser".into()),
                icon: Some("CB".into()),
                accent_color: Some("#f59e0b".into()),
                agent: Some("claude".into()),
                resume_mode: Some("resume".into()),
                resume_session_id: None,
                model: Some("claude-opus-4-8".into()),
                dangerous: Some(true),
                custom_command: Some("claude --foo".into()),
                directories: None,
                now_ms: 5000,
            })
            .unwrap();
        // Item C: UPDATE seeds nothing → no session id on the result (key stays off the wire).
        assert_eq!(updated.session_id, None);
        let project = maestro_shell::ProjectService::new(&paths)
            .load(&created.project_id)
            .unwrap()
            .unwrap();
        assert_eq!(project.name, "Capacity Browser");
        assert_eq!(project.root, "/tmp/capacity-browser");
        assert_eq!(project.icon.as_deref(), Some("CB"));
        assert_eq!(project.accent_color.as_deref(), Some("#f59e0b"));
        assert_eq!(
            project
                .launch_defaults
                .as_ref()
                .and_then(|defaults| defaults.agent.as_deref()),
            Some("claude")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remote_project_delete_releases_a_tabless_workspace_session_before_cascade() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = maestro_shell::AppPaths::with_base(tmp.path().join("Maestro"));
        maestro_shell::ProjectService::new(&paths)
            .create(
                "remote-owned",
                "Remote owned",
                "/tmp",
                maestro_shell::NewProject::default(),
                1,
            )
            .unwrap();
        let workspace = maestro_shell::Workspace {
            workspace_id: "remote-workspace".into(),
            project_id: "remote-owned".into(),
            root: "/tmp".into(),
            policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            consent: maestro_shell::WorkspaceConsent::default(),
        };
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Workspace,
            "remote-workspace",
            1,
            &workspace,
        )
        .unwrap();
        let session = maestro_shell::SessionRecord {
            session_id: "remote-tabless-live".into(),
            workspace_id: "remote-workspace".into(),
            kind: maestro_shell::SessionKind::Agent,
            launch: maestro_shell::LaunchSpec::OptOut,
            cwd_resolved: "/tmp".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status: maestro_shell::SessionStatus::Live,
        };
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Session,
            "remote-tabless-live",
            1,
            &session,
        )
        .unwrap();

        assert!(
            maestro_shell::load_endpoint(&paths).unwrap().is_none(),
            "the headless regression must not rely on a desktop endpoint record"
        );
        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let daemon = install_conditional_start_test_daemon_with_live(
            &tx,
            std::collections::BTreeMap::from([(
                "remote-tabless-live".to_string(),
                "gen-live".to_string(),
            )]),
        );
        let sessions = Arc::new(Mutex::new(SessionCache::mutation_ready_for_test()));
        sessions.lock().unwrap().reserve("remote-tabless-live");
        let mut editor = DaemonProjectEditor {
            tx,
            sessions: sessions.clone(),
            paths: paths.clone(),
        };
        let deleted = editor.delete_project("remote-owned".into(), 2).unwrap();

        assert_eq!(deleted.project_id, "remote-owned");
        let kills = daemon
            .requests()
            .into_iter()
            .filter(|request| request["op"] == "kill")
            .collect::<Vec<_>>();
        assert_eq!(
            kills,
            vec![serde_json::json!({
                "op": "kill",
                "id": "remote-tabless-live",
                "expected_generation": "gen-live",
            })],
            "project deletion must release the exact pre-resolved daemon lifetime"
        );
        assert!(maestro_shell::ProjectService::new(&paths)
            .load("remote-owned")
            .unwrap()
            .is_none());
        assert!(
            maestro_shell::store::load_one::<maestro_shell::SessionRecord>(
                &paths,
                maestro_shell::RecordKind::Session,
                "remote-tabless-live"
            )
            .unwrap()
            .is_none()
        );
        assert!(!sessions
            .lock()
            .unwrap()
            .snapshot()
            .contains(&"remote-tabless-live".to_string()));
    }

    #[test]
    fn remote_project_delete_without_reviewed_daemon_authority_preserves_every_record() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = maestro_shell::AppPaths::with_base(tmp.path().join("Maestro"));
        maestro_shell::ProjectService::new(&paths)
            .create(
                "remote-preserved",
                "Remote preserved",
                "/tmp",
                maestro_shell::NewProject::default(),
                1,
            )
            .unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Workspace,
            "preserved-workspace",
            1,
            &maestro_shell::Workspace {
                workspace_id: "preserved-workspace".into(),
                project_id: "remote-preserved".into(),
                root: "/tmp".into(),
                policy: maestro_shell::WorkspacePolicy::ScratchCwd,
                consent: maestro_shell::WorkspaceConsent::default(),
            },
        )
        .unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Session,
            "preserved-live",
            1,
            &maestro_shell::SessionRecord {
                session_id: "preserved-live".into(),
                workspace_id: "preserved-workspace".into(),
                kind: maestro_shell::SessionKind::Agent,
                launch: maestro_shell::LaunchSpec::OptOut,
                cwd_resolved: "/tmp".into(),
                agent_task_id: None,
                created_at_ms: 1,
                last_attached_at_ms: 1,
                last_known_generation: None,
                status: maestro_shell::SessionStatus::Live,
            },
        )
        .unwrap();

        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let mut editor = DaemonProjectEditor {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            paths: paths.clone(),
        };
        assert_eq!(
            editor.delete_project("remote-preserved".into(), 2),
            Err(crate::remote_control::ProjectEditError::DaemonUnavailable)
        );
        assert!(maestro_shell::ProjectService::new(&paths)
            .load("remote-preserved")
            .unwrap()
            .is_some());
        assert!(
            maestro_shell::store::load_one::<maestro_shell::SessionRecord>(
                &paths,
                maestro_shell::RecordKind::Session,
                "preserved-live"
            )
            .unwrap()
            .is_some(),
            "a daemon authority failure must happen before the project cascade"
        );
    }

    #[test]
    fn remote_mutations_cannot_target_the_private_product_recovery_project() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-private-recovery-mutation-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        maestro_shell::ProjectService::new(&paths)
            .create(
                PRODUCT_RECOVERY_PROJECT_ID,
                "Product Recovery",
                "/tmp/recovery",
                maestro_shell::NewProject {
                    system: true,
                    ..Default::default()
                },
                1,
            )
            .unwrap();

        let (tx, mut rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let sessions = Arc::new(Mutex::new(SessionCache::mutation_ready_for_test()));
        let mut editor = DaemonProjectEditor {
            tx: tx.clone(),
            sessions: sessions.clone(),
            paths: paths.clone(),
        };

        assert_eq!(
            editor.update_project(crate::remote_control::ProjectEditRequest {
                project_id: Some(PRODUCT_RECOVERY_PROJECT_ID.into()),
                name: Some("Visible ghost".into()),
                root: None,
                icon: None,
                accent_color: None,
                agent: None,
                resume_mode: None,
                resume_session_id: None,
                model: None,
                dangerous: None,
                custom_command: None,
                directories: None,
                now_ms: 2,
            }),
            Err(crate::remote_control::ProjectEditError::ProjectNotFound)
        );
        assert_eq!(
            editor.delete_project(PRODUCT_RECOVERY_PROJECT_ID.into(), 3),
            Err(crate::remote_control::ProjectEditError::ProjectNotFound)
        );

        let mut opener = DaemonWindowOpener {
            tx,
            sessions,
            paths: paths.clone(),
        };
        assert_eq!(
            opener.new_window(crate::remote_control::NewWindowRequest {
                project_id: PRODUCT_RECOVERY_PROJECT_ID.into(),
                name: "Should not exist".into(),
                cwd: None,
                agent: Some("terminal".into()),
                launch_flags: None,
                now_ms: 4,
            }),
            Err(crate::remote_control::NewWindowError::ProjectNotFound)
        );

        assert_eq!(
            maestro_shell::ProjectService::new(&paths)
                .load(PRODUCT_RECOVERY_PROJECT_ID)
                .unwrap()
                .unwrap()
                .name,
            "Product Recovery"
        );
        assert!(
            rx.try_recv().is_err(),
            "private recovery rejects before daemon IO"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn project_creation_refuses_before_project_record_when_creation_lease_cannot_publish() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-project-lease-first-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let (tx, mut rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let owner = Arc::new(Mutex::new(crate::winsize_owner::WinsizeOwner::new()));
        owner.lock().unwrap().set_serving(1, 0);
        // Intentionally absent parent: the browser-size suppression cannot become visible to the desktop.
        tx.set_creation_lease_publisher(crate::winsize_owner::RemoteCreationLeasePublisher::new(
            owner,
            dir.join("missing-parent").join("lease"),
            "test-connection".into(),
        ));
        let mut editor = DaemonProjectEditor {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            paths: paths.clone(),
        };

        assert!(editor
            .create_project_with_initial_size(
                crate::remote_control::ProjectEditRequest {
                    project_id: None,
                    name: Some("Lease first".into()),
                    root: Some("/tmp/lease-first".into()),
                    icon: None,
                    accent_color: None,
                    agent: Some("terminal".into()),
                    resume_mode: None,
                    resume_session_id: None,
                    model: None,
                    dangerous: None,
                    custom_command: None,
                    directories: None,
                    now_ms: 4_242,
                },
                InitialTerminalSize::from_optional_pair(Some(132), Some(43)),
            )
            .is_err());
        assert!(maestro_shell::ProjectService::new(&paths)
            .load("proj-lease-first-4242")
            .unwrap()
            .is_none());
        assert!(rx.try_recv().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn project_seed_session_collision_preserves_winner_and_publishes_no_layout_or_start() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = maestro_shell::AppPaths::with_base(tmp.path().join("Maestro"));
        maestro_shell::ProjectService::new(&paths)
            .create(
                "foreign-session-owner",
                "Foreign session owner",
                "/tmp/foreign",
                maestro_shell::NewProject::default(),
                1,
            )
            .unwrap();
        let foreign_workspace = maestro_shell::Workspace {
            workspace_id: "foreign-session-workspace".into(),
            project_id: "foreign-session-owner".into(),
            root: "/tmp/foreign".into(),
            policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            consent: maestro_shell::WorkspaceConsent::default(),
        };
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Workspace,
            &foreign_workspace.workspace_id,
            1,
            &foreign_workspace,
        )
        .unwrap();
        let target_project_id = pick_remote_project_id(
            "Collision seed",
            4242,
            &paths,
            &std::collections::HashSet::new(),
        )
        .unwrap();
        let target_session_id = default_remote_project_pane_session_id(&target_project_id);
        let existing = maestro_shell::SessionRecord {
            session_id: target_session_id.clone(),
            workspace_id: foreign_workspace.workspace_id.clone(),
            kind: maestro_shell::SessionKind::Shell,
            launch: maestro_shell::LaunchSpec::OptOut,
            cwd_resolved: foreign_workspace.root.clone(),
            agent_task_id: None,
            created_at_ms: 2,
            last_attached_at_ms: 2,
            last_known_generation: Some("foreign-generation".into()),
            status: maestro_shell::SessionStatus::Live,
        };
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Session,
            &target_session_id,
            2,
            &existing,
        )
        .unwrap();
        let foreign_layouts = maestro_shell::WindowLayoutService::new(&paths);
        foreign_layouts
            .create_empty("foreign-session-window", 2)
            .unwrap();
        let foreign_layout = foreign_layouts
            .open_tab(
                "foreign-session-window",
                "foreign-session-pane",
                &target_session_id,
                "Foreign",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .unwrap();
        let (tx, mut rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let _daemon = install_conditional_start_test_daemon(&tx);
        let mut editor = DaemonProjectEditor {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            paths: paths.clone(),
        };

        let result = editor.create_project(crate::remote_control::ProjectEditRequest {
            project_id: None,
            name: Some("Collision seed".into()),
            root: Some("/tmp/new-project".into()),
            icon: None,
            accent_color: None,
            agent: Some("terminal".into()),
            resume_mode: None,
            resume_session_id: None,
            model: None,
            dangerous: None,
            custom_command: None,
            directories: None,
            now_ms: 4242,
        });

        assert_eq!(
            result,
            Err(crate::remote_control::ProjectEditError::Internal)
        );
        let existing_after = maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &target_session_id,
        )
        .unwrap();
        assert!(
            matches!(existing_after, Some(maestro_shell::LoadOutcome::Loaded(ref row)) if row == &existing)
        );
        assert_eq!(
            foreign_layouts
                .load("foreign-session-window")
                .unwrap()
                .unwrap(),
            foreign_layout
        );
        assert!(foreign_layouts
            .load(&default_remote_project_window_id(&target_project_id))
            .unwrap()
            .is_none());
        assert!(
            maestro_shell::ProjectService::new(&paths)
                .load(&target_project_id)
                .unwrap()
                .is_none(),
            "a fixed Session collision must roll back the fresh Project"
        );
        assert!(
            maestro_shell::load_one::<maestro_shell::Workspace>(
                &paths,
                maestro_shell::RecordKind::Workspace,
                &default_remote_project_workspace_id(&target_project_id),
            )
            .unwrap()
            .is_none(),
            "a fixed Session collision must roll back the fresh Workspace"
        );
        assert!(
            rx.try_recv().is_err(),
            "collision must enqueue no daemon start"
        );
    }

    #[test]
    fn project_seed_skips_daemon_live_session_id_before_publishing_graph() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = maestro_shell::AppPaths::with_base(tmp.path().join("Maestro"));
        let project_root = tmp.path().join("new-project");
        std::fs::create_dir_all(&project_root).unwrap();
        let base_project_id = "proj-live-daemon-collision-4343";
        let daemon_winner = default_remote_project_pane_session_id(base_project_id);
        let sessions = Arc::new(Mutex::new(SessionCache::seeded_with_daemon_protocol(
            vec![daemon_winner.clone()],
            Some(maestro_protocol::DAEMON_PROTOCOL_VERSION),
            true,
            true,
            true,
            true,
            true,
        )));
        let (tx, mut rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let _daemon = install_conditional_start_test_daemon(&tx);
        let mut editor = DaemonProjectEditor {
            tx,
            sessions: Arc::clone(&sessions),
            paths: paths.clone(),
        };

        let created = editor
            .create_project(crate::remote_control::ProjectEditRequest {
                project_id: None,
                name: Some("Live daemon collision".into()),
                root: Some(project_root.to_string_lossy().into_owned()),
                icon: None,
                accent_color: None,
                agent: Some("terminal".into()),
                resume_mode: None,
                resume_session_id: None,
                model: None,
                dangerous: None,
                custom_command: None,
                directories: None,
                now_ms: 4343,
            })
            .unwrap();

        assert_ne!(created.project_id, base_project_id);
        assert_ne!(created.session_id.as_deref(), Some(daemon_winner.as_str()));
        assert!(maestro_shell::ProjectService::new(&paths)
            .load(base_project_id)
            .unwrap()
            .is_none());
        assert!(maestro_shell::WindowLayoutService::new(&paths)
            .load(&default_remote_project_window_id(base_project_id))
            .unwrap()
            .is_none());
        assert!(maestro_shell::load_one::<maestro_shell::Workspace>(
            &paths,
            maestro_shell::RecordKind::Workspace,
            &default_remote_project_workspace_id(base_project_id),
        )
        .unwrap()
        .is_none());
        assert!(sessions.lock().unwrap().snapshot().contains(&daemon_winner));
        let start: serde_json::Value = serde_json::from_str(rx.try_recv().unwrap().trim()).unwrap();
        assert_eq!(start["op"], "start_session");
        assert_eq!(start["id"], created.session_id.unwrap());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn new_window_lease_failure_rolls_back_every_durable_record() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = maestro_shell::AppPaths::with_base(tmp.path().join("Maestro"));
        maestro_shell::ProjectService::new(&paths)
            .create(
                "lease-window-project",
                "Lease window",
                "/tmp",
                maestro_shell::NewProject::default(),
                1,
            )
            .unwrap();
        let project_before = maestro_shell::ProjectService::new(&paths)
            .load("lease-window-project")
            .unwrap()
            .unwrap();
        let (tx, mut rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let owner = Arc::new(Mutex::new(crate::winsize_owner::WinsizeOwner::new()));
        owner.lock().unwrap().set_serving(1, 0);
        tx.set_creation_lease_publisher(crate::winsize_owner::RemoteCreationLeasePublisher::new(
            owner,
            tmp.path().join("missing-parent").join("lease"),
            "test-window-connection".into(),
        ));
        let mut opener = DaemonWindowOpener {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            paths: paths.clone(),
        };

        assert!(opener
            .new_window(crate::remote_control::NewWindowRequest {
                project_id: "lease-window-project".into(),
                name: "Must roll back".into(),
                cwd: None,
                agent: Some("terminal".into()),
                launch_flags: None,
                now_ms: 4_545,
            })
            .is_err());
        assert!(
            maestro_shell::store::load_all::<maestro_shell::Workspace>(
                &paths,
                maestro_shell::RecordKind::Workspace,
            )
            .unwrap()
            .is_empty(),
            "lease failure before Session creation must not leave a Workspace"
        );
        assert!(
            maestro_shell::store::load_all::<maestro_shell::SessionRecord>(
                &paths,
                maestro_shell::RecordKind::Session,
            )
            .unwrap()
            .is_empty()
        );
        assert!(
            maestro_shell::store::load_all::<maestro_shell::WindowLayout>(
                &paths,
                maestro_shell::RecordKind::WindowLayout,
            )
            .unwrap()
            .is_empty()
        );
        assert_eq!(
            maestro_shell::ProjectService::new(&paths)
                .load("lease-window-project")
                .unwrap()
                .unwrap(),
            project_before
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn new_window_queue_pressure_cannot_replace_exact_ledger_publication() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = maestro_shell::AppPaths::with_base(tmp.path().join("Maestro"));
        let project = maestro_shell::ProjectService::new(&paths)
            .create(
                "pressure-window-project",
                "Pressure window",
                "/tmp",
                maestro_shell::NewProject::default(),
                1,
            )
            .unwrap();
        let epoch_before = test_window_epoch(&paths);
        let (tx, mut rx) = daemon_request_channel(1, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        tx.send("already-queued".into()).unwrap();
        let daemon = install_conditional_start_test_daemon(&tx);
        let sessions = Arc::new(Mutex::new(SessionCache::mutation_ready_for_test()));
        let mut opener = DaemonWindowOpener {
            tx,
            sessions: Arc::clone(&sessions),
            paths: paths.clone(),
        };

        let created = opener
            .new_window(crate::remote_control::NewWindowRequest {
                project_id: project.project_id.clone(),
                name: "Exact publication".into(),
                cwd: None,
                agent: Some("terminal".into()),
                launch_flags: None,
                now_ms: 4_546,
            })
            .unwrap();
        let project_after = maestro_shell::ProjectService::new(&paths)
            .load(&project.project_id)
            .unwrap()
            .unwrap();
        assert_eq!(project_after.project_id, project.project_id);
        assert_eq!(project_after.name, project.name);
        assert_eq!(project_after.root, project.root);
        assert!(project_after.window_order.contains(&created.window_id));
        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load(&created.window_id)
            .unwrap()
            .unwrap();
        assert_eq!(layout.tabs[0].session_id, created.session_id);
        let session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &created.session_id,
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(session) => session,
            other => panic!("expected a live exact-ledger Session row, got {other:?}"),
        };
        assert_eq!(session.status, maestro_shell::SessionStatus::Live);
        assert!(session.last_known_generation.is_some());
        assert_eq!(only_conditional_start(&daemon)["id"], created.session_id);
        let epoch_after = test_window_epoch(&paths);
        assert!(epoch_after > epoch_before);
        assert!(sessions
            .lock()
            .unwrap()
            .snapshot()
            .contains(&created.session_id));
        // The generic operational queue was already full and remains untouched: neither its old
        // entry nor enqueue success is accepted as PTY liveness. The reviewed ledger socket and
        // Grid proof above are the only reason durable Live publication succeeded.
        assert_eq!(rx.try_recv().unwrap(), "already-queued");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn daemon_project_create_pressure_rolls_back_every_durable_record() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-project-pressure-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let (tx, mut rx) = daemon_request_channel(1, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        tx.send("already-queued".into()).unwrap();
        let mut editor = DaemonProjectEditor {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            paths: paths.clone(),
        };
        let project_id = "proj-pressure-5150";

        assert!(editor
            .create_project(crate::remote_control::ProjectEditRequest {
                project_id: None,
                name: Some("Pressure".into()),
                root: Some("/tmp/pressure".into()),
                icon: None,
                accent_color: None,
                agent: Some("terminal".into()),
                resume_mode: None,
                resume_session_id: None,
                model: None,
                dangerous: None,
                custom_command: None,
                directories: None,
                now_ms: 5150,
            })
            .is_err());
        assert!(maestro_shell::ProjectService::new(&paths)
            .load(project_id)
            .unwrap()
            .is_none());
        assert!(maestro_shell::WindowLayoutService::new(&paths)
            .load(&default_remote_project_window_id(project_id))
            .unwrap()
            .is_none());
        assert!(maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &default_remote_project_pane_session_id(project_id),
        )
        .unwrap()
        .is_none());
        assert!(maestro_shell::load_one::<maestro_shell::Workspace>(
            &paths,
            maestro_shell::RecordKind::Workspace,
            &default_remote_project_workspace_id(project_id),
        )
        .unwrap()
        .is_none());
        assert_eq!(rx.try_recv().unwrap(), "already-queued");
        assert!(
            rx.try_recv().is_err(),
            "failed create must enqueue no start"
        );
        assert_eq!(
            maestro_shell::invariants::check_store_invariants(&paths).unwrap(),
            Vec::new()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Shared helper for the seeding-launch tests: create a project through the editor and return
    /// (start line the daemon received, the seeded pane's SessionRecord).
    fn seed_project_and_capture(
        test_tag: &str,
        request: crate::remote_control::ProjectEditRequest,
    ) -> (serde_json::Value, maestro_shell::SessionRecord) {
        let dir = std::env::temp_dir().join(format!(
            "hydra-project-seed-{test_tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(root) = request.root.as_deref() {
            std::fs::create_dir_all(root).unwrap();
        }
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let daemon = install_conditional_start_test_daemon(&tx);
        let mut editor = DaemonProjectEditor {
            tx,
            sessions: std::sync::Arc::new(std::sync::Mutex::new(
                SessionCache::mutation_ready_for_test(),
            )),
            paths: paths.clone(),
        };
        let created = editor.create_project(request).unwrap();
        let session_id = default_remote_project_pane_session_id(&created.project_id);
        // Item C: CREATE surfaces the seeded first pane's session id for browser auto-attach.
        assert_eq!(created.session_id.as_deref(), Some(session_id.as_str()));
        let session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &session_id,
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(session) => session,
            _ => panic!("expected loaded seeded pane session"),
        };
        let start = only_conditional_start(&daemon);
        let _ = std::fs::remove_dir_all(&dir);
        (start, session)
    }

    #[test]
    fn daemon_project_editor_seeds_model_and_dangerous_into_first_pane_launch() {
        // Tier-1 item 6: the New Project form's model + dangerous flag reach BOTH the daemon start line and
        // the durable session record (record/launch parity), with the dangerous flag AFTER the model args.
        let (start, session) = seed_project_and_capture(
            "model-dangerous",
            crate::remote_control::ProjectEditRequest {
                project_id: None,
                name: Some("Launchy".into()),
                root: Some("/tmp/launchy".into()),
                icon: None,
                accent_color: None,
                agent: Some("claude".into()),
                resume_mode: Some("continue".into()),
                resume_session_id: None,
                model: Some("claude-opus-4-8".into()),
                dangerous: Some(true),
                custom_command: None,
                directories: None,
                now_ms: 7000,
            },
        );
        let expected_args = vec![
            "--continue".to_string(),
            "--model".to_string(),
            "claude-opus-4-8".to_string(),
            "--dangerously-skip-permissions".to_string(),
        ];
        assert_eq!(
            session.launch,
            maestro_shell::LaunchSpec::KnownSafe {
                launch_spec_id: "claude".into(),
                params: expected_args.clone(),
            }
        );
        let mut source_argv = vec!["claude".to_string()];
        source_argv.extend(expected_args);
        assert_provider_start_executes_exact_source(
            &start,
            &session.session_id,
            "/tmp/launchy",
            &source_argv,
            InitialTerminalSize::default(),
        );
    }

    #[test]
    fn daemon_project_editor_seeds_resume_target_into_first_pane_launch() {
        // Item 5 + 6: a resume_session_id picked in the New Project dialog produces the agent's RESUME argv
        // for the seeded pane (codex shape here), with the per-agent dangerous flag appended after.
        let (start, session) = seed_project_and_capture(
            "resume-target",
            crate::remote_control::ProjectEditRequest {
                project_id: None,
                name: Some("Resumey".into()),
                root: Some("/tmp/resumey".into()),
                icon: None,
                accent_color: None,
                agent: Some("codex".into()),
                resume_mode: Some("resume".into()),
                resume_session_id: Some("50000000-0000-4000-8000-000000000010".into()),
                model: None,
                dangerous: Some(true),
                custom_command: None,
                directories: None,
                now_ms: 7100,
            },
        );
        let expected_args = vec![
            "resume".to_string(),
            "50000000-0000-4000-8000-000000000010".to_string(),
            "--dangerously-bypass-approvals-and-sandbox".to_string(),
        ];
        assert_eq!(
            session.launch,
            maestro_shell::LaunchSpec::KnownSafe {
                launch_spec_id: "codex".into(),
                params: expected_args.clone(),
            }
        );
        let mut source_argv = vec!["codex".to_string()];
        source_argv.extend(expected_args);
        assert_provider_start_executes_exact_source(
            &start,
            &session.session_id,
            "/tmp/resumey",
            &source_argv,
            InitialTerminalSize::default(),
        );
    }

    #[test]
    fn daemon_project_editor_fresh_copilot_record_and_start_share_one_uuid() {
        let (start, session) = seed_project_and_capture(
            "fresh-copilot",
            crate::remote_control::ProjectEditRequest {
                project_id: None,
                name: Some("Copilot".into()),
                root: Some("/tmp/copilot".into()),
                icon: None,
                accent_color: None,
                agent: Some("copilot".into()),
                resume_mode: Some("none".into()),
                resume_session_id: None,
                model: Some("auto".into()),
                dangerous: Some(true),
                custom_command: None,
                directories: None,
                now_ms: 7150,
            },
        );
        let maestro_shell::LaunchSpec::KnownSafe {
            launch_spec_id,
            params,
        } = &session.launch
        else {
            panic!("Copilot seed must be KnownSafe");
        };
        assert_eq!(launch_spec_id, "copilot");
        assert_eq!(params.len(), 4);
        let provider_id = params[0].strip_prefix("--resume=").unwrap();
        assert_eq!(
            uuid::Uuid::parse_str(provider_id)
                .unwrap()
                .hyphenated()
                .to_string(),
            provider_id
        );
        assert_eq!(&params[1..], &["--model", "auto", "--yolo"]);
        let source_argv = vec![
            "copilot".to_string(),
            format!("--session-id={provider_id}"),
            "--model".to_string(),
            "auto".to_string(),
            "--yolo".to_string(),
        ];
        assert_provider_start_executes_exact_source(
            &start,
            &session.session_id,
            "/tmp/copilot",
            &source_argv,
            InitialTerminalSize::default(),
        );
    }

    #[test]
    fn daemon_project_editor_antigravity_resume_model_and_dangerous_are_exact() {
        let conversation = "5f082f93-2ca4-4b7b-bc58-048e899edebb";
        let model = "Gemini 3.5 Flash (High)";
        let (start, session) = seed_project_and_capture(
            "antigravity-resume",
            crate::remote_control::ProjectEditRequest {
                project_id: None,
                name: Some("Antigravity".into()),
                root: Some("/tmp/antigravity".into()),
                icon: None,
                accent_color: None,
                agent: Some("antigravity".into()),
                resume_mode: Some("resume".into()),
                resume_session_id: Some(conversation.into()),
                model: Some(model.into()),
                dangerous: Some(true),
                custom_command: None,
                directories: None,
                now_ms: 7160,
            },
        );
        let expected = vec![
            "--conversation".to_string(),
            conversation.to_string(),
            "--model".to_string(),
            model.to_string(),
            "--dangerously-skip-permissions".to_string(),
        ];
        assert_eq!(
            session.launch,
            maestro_shell::LaunchSpec::KnownSafe {
                launch_spec_id: "agy".into(),
                params: expected.clone(),
            }
        );
        let mut source_argv = vec!["agy".to_string()];
        source_argv.extend(expected);
        assert_provider_start_executes_exact_source(
            &start,
            &session.session_id,
            "/tmp/antigravity",
            &source_argv,
            InitialTerminalSize::default(),
        );
    }

    #[test]
    fn daemon_project_editor_amp_exact_target_survives_start_record_and_restart() {
        let target = "é".repeat(200); // 200 chars, 400 UTF-8 bytes: valid under AMP's character bound.
        let (start, session) = seed_project_and_capture(
            "amp-resume",
            crate::remote_control::ProjectEditRequest {
                project_id: None,
                name: Some("Amp".into()),
                root: Some("/tmp/amp".into()),
                icon: None,
                accent_color: None,
                agent: Some("amp".into()),
                resume_mode: Some("resume".into()),
                resume_session_id: Some(target.clone()),
                model: Some("must-not-leak".into()),
                dangerous: Some(true),
                custom_command: None,
                directories: None,
                now_ms: 7165,
            },
        );
        let expected = vec![
            "threads".to_string(),
            "continue".to_string(),
            target,
            "--dangerously-allow-all".to_string(),
        ];
        let expected_launch = maestro_shell::LaunchSpec::KnownSafe {
            launch_spec_id: "amp".into(),
            params: expected.clone(),
        };
        assert_eq!(session.launch, expected_launch);
        assert_eq!(
            maestro_shell::canonical_launch_for_restart(&session.launch),
            expected_launch,
        );
        let mut source_argv = vec!["amp".to_string()];
        source_argv.extend(expected);
        assert_provider_start_executes_exact_source(
            &start,
            &session.session_id,
            "/tmp/amp",
            &source_argv,
            InitialTerminalSize::default(),
        );
    }

    #[test]
    fn daemon_project_editor_kiro_resume_keeps_chat_and_record_start_parity() {
        let provider_id = "fc9dbfd4-22f4-4b50-9fa4-68bf7816137d";
        let (start, session) = seed_project_and_capture(
            "kiro-resume",
            crate::remote_control::ProjectEditRequest {
                project_id: None,
                name: Some("Kiro".into()),
                root: Some("/tmp/kiro".into()),
                icon: None,
                accent_color: None,
                agent: Some("kiro".into()),
                resume_mode: Some("resume".into()),
                resume_session_id: Some(provider_id.into()),
                model: Some("claude-sonnet-4.5".into()),
                dangerous: Some(true),
                custom_command: None,
                directories: None,
                now_ms: 7170,
            },
        );
        let expected = vec![
            "chat".to_string(),
            "--resume-id".to_string(),
            provider_id.to_string(),
            "--model".to_string(),
            "claude-sonnet-4.5".to_string(),
            "--trust-all-tools".to_string(),
        ];
        assert_eq!(
            session.launch,
            maestro_shell::LaunchSpec::KnownSafe {
                launch_spec_id: "kiro-cli".into(),
                params: expected.clone(),
            }
        );
        let mut source_argv = vec!["kiro-cli".to_string()];
        source_argv.extend(expected);
        assert_provider_start_executes_exact_source(
            &start,
            &session.session_id,
            "/tmp/kiro",
            &source_argv,
            InitialTerminalSize::default(),
        );
    }

    #[test]
    fn daemon_project_editor_maps_legacy_new_resume_mode_to_fresh_seed() {
        // An OLD browser's "new" (or any non-vocabulary value reaching the editor directly) seeds a FRESH
        // pane — never a resume argv. Fresh with the form's EXPLICIT agent means the pane actually launches
        // `claude` (record/launch parity; previously the record said claude while the PTY ran a bare shell).
        let (start, session) = seed_project_and_capture(
            "legacy-new",
            crate::remote_control::ProjectEditRequest {
                project_id: None,
                name: Some("Freshy".into()),
                root: Some("/tmp/freshy".into()),
                icon: None,
                accent_color: None,
                agent: Some("claude".into()),
                resume_mode: Some("new".into()),
                resume_session_id: None,
                model: None,
                dangerous: None,
                custom_command: None,
                directories: None,
                now_ms: 7200,
            },
        );
        let maestro_shell::LaunchSpec::KnownSafe {
            launch_spec_id,
            params,
        } = &session.launch
        else {
            panic!("fresh Claude project seed must publish an exact recipe")
        };
        assert_eq!(launch_spec_id, "claude");
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], "--resume");
        let provider_id = &params[1];
        assert_eq!(
            uuid::Uuid::parse_str(provider_id)
                .unwrap()
                .hyphenated()
                .to_string(),
            *provider_id
        );
        assert_provider_start_executes_exact_source(
            &start,
            &session.session_id,
            "/tmp/freshy",
            &["claude".into(), "--session-id".into(), provider_id.clone()],
            InitialTerminalSize::default(),
        );
    }

    #[test]
    fn daemon_project_editor_rejects_missing_create_root() {
        let dir =
            std::env::temp_dir().join(format!("hydra-project-edit-invalid-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let mut editor = DaemonProjectEditor {
            tx,
            sessions: std::sync::Arc::new(std::sync::Mutex::new(
                SessionCache::mutation_ready_for_test(),
            )),
            paths,
        };

        assert_eq!(
            editor.create_project(crate::remote_control::ProjectEditRequest {
                project_id: None,
                name: Some("Capacity".into()),
                root: Some(" ".into()),
                icon: None,
                accent_color: None,
                agent: None,
                resume_mode: None,
                resume_session_id: None,
                model: None,
                dangerous: None,
                custom_command: None,
                directories: None,
                now_ms: 1,
            }),
            Err(crate::remote_control::ProjectEditError::InvalidRoot)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_pane_stasher_stashes_live_desktop_pane() {
        let dir =
            std::env::temp_dir().join(format!("hydra-stash-pane-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts.create_empty("win-main", 1).unwrap();
        layouts
            .open_tab(
                "win-main",
                "pane-a",
                "s-a",
                "A",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .unwrap();
        layouts
            .split_tab(
                "win-main",
                "pane-a",
                "pane-b",
                "s-b",
                "B",
                maestro_shell::SplitAxis::Right,
                3,
            )
            .unwrap();
        let mut stasher = DaemonPaneStasher {
            paths: paths.clone(),
        };

        stasher
            .stash_pane(crate::remote_control::StashPaneRequest {
                window_id: "win-main".into(),
                pane_id: "pane-b".into(),
                now_ms: 4,
            })
            .unwrap();

        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load("win-main")
            .unwrap()
            .unwrap();
        assert!(
            !layout
                .tabs
                .iter()
                .find(|tab| tab.tab_id == "pane-a")
                .unwrap()
                .stashed
        );
        assert!(
            layout
                .tabs
                .iter()
                .find(|tab| tab.tab_id == "pane-b")
                .unwrap()
                .stashed
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_pane_split_resumes_a_prior_agent_session_from_launch_flags() {
        // Desktop-parity (screens/local/splitright.jpg): a split can RESUME a prior session, not only start fresh.
        // The browser sends {agent, launch_flags:{resumeMode:'resume', resumeSessionId}}; the split must build the
        // real resume launch (codex resume <id>), same as create_session — previously launch_flags was ignored and
        // the split silently started a fresh session.
        use crate::remote_control::PaneSplitter;
        let dir =
            std::env::temp_dir().join(format!("hydra-split-resume-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let work = dir.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let work = work.to_string_lossy().into_owned();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        // Seed the FK parent chain (project → workspace "ws") the session below references (sessions.workspace_id FK).
        maestro_shell::project::ProjectService::new(&paths)
            .create(
                "p",
                "P",
                &work,
                maestro_shell::project::NewProject::default(),
                1,
            )
            .ok();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Workspace,
            "ws",
            1,
            &maestro_shell::records::Workspace {
                workspace_id: "ws".into(),
                project_id: "p".into(),
                root: work.clone(),
                policy: maestro_shell::policy::WorkspacePolicy::ScratchCwd,
                consent: Default::default(),
            },
        )
        .unwrap();
        // A source pane + its session record (the splitter loads the source session).
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts.create_empty("win-main", 1).unwrap();
        layouts
            .open_tab(
                "win-main",
                "pane-a",
                "s-a",
                "A",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .unwrap();
        maestro_shell::store::set_window_project(&paths, "win-main", "p").unwrap();
        maestro_shell::ProjectService::new(&paths)
            .reorder_windows("p", &["win-main".into()], 2)
            .unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Session,
            "s-a",
            2,
            &maestro_shell::SessionRecord {
                session_id: "s-a".into(),
                workspace_id: "ws".into(),
                kind: maestro_shell::SessionKind::Agent,
                launch: maestro_shell::LaunchSpec::KnownSafe {
                    launch_spec_id: "claude".into(),
                    params: Vec::new(),
                },
                cwd_resolved: work.clone(),
                agent_task_id: None,
                created_at_ms: 2,
                last_attached_at_ms: 2,
                last_known_generation: None,
                status: maestro_shell::SessionStatus::Live,
            },
        )
        .unwrap();
        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let daemon = install_conditional_start_test_daemon(&tx);
        let lease_dir = dir.join("creation-lease");
        install_creation_lease_publisher(&tx, &lease_dir);
        let mut splitter = DaemonPaneSplitter {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            paths: paths.clone(),
        };

        let created = splitter
            .split_pane_with_initial_size(
                crate::remote_control::SplitPaneRequest {
                    window_id: "win-main".into(),
                    from_pane_id: "pane-a".into(),
                    dir: crate::remote_control::SplitPaneDir::Right,
                    agent: Some("codex".into()),
                    launch_flags: Some(serde_json::json!({
                        "resumeMode": "resume",
                        "resumeSessionId": "50000000-0000-4000-8000-000000000012",
                        "model": "gpt-5.2-codex",
                    })),
                    cwd: None,
                    pane_name: Some("Build pane".into()),
                    now_ms: 5,
                },
                InitialTerminalSize::from_optional_pair(Some(133), Some(44)),
            )
            .unwrap();
        assert_creation_lease(&lease_dir, &created.session_id);

        // The new split session launches as the RESUMED codex session, not a fresh one — and the dialog's
        // model NAME rides the same discrete argv (record params == launched args).
        let session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &created.session_id,
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(s) => s,
            _ => panic!("session should load"),
        };
        assert_eq!(
            session.launch,
            maestro_shell::LaunchSpec::KnownSafe {
                launch_spec_id: "codex".into(),
                params: vec![
                    "resume".into(),
                    "50000000-0000-4000-8000-000000000012".into(),
                    "--model".into(),
                    "gpt-5.2-codex".into()
                ],
            }
        );
        // The daemon start line launches that exact argv (launch/record parity end-to-end).
        assert_provider_start_executes_exact_source(
            &only_conditional_start(&daemon),
            &created.session_id,
            &work,
            &[
                "codex".into(),
                "resume".into(),
                "50000000-0000-4000-8000-000000000012".into(),
                "--model".into(),
                "gpt-5.2-codex".into(),
            ],
            InitialTerminalSize::from_optional_pair(Some(133), Some(44)),
        );
        // The split dialog's pane name becomes the tab title (else it would fall back to "Codex").
        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load("win-main")
            .unwrap()
            .unwrap();
        let tab = layout
            .tabs
            .iter()
            .find(|tab| tab.tab_id == created.tab_id)
            .expect("split tab exists");
        assert_eq!(tab.title, "Build pane");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_new_pane_creates_stashed_record_without_local_focus() {
        use crate::remote_control::PaneSplitter;
        let dir =
            std::env::temp_dir().join(format!("hydra-new-pane-tab-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let work = dir.join("work");
        let review = dir.join("review");
        std::fs::create_dir_all(&work).unwrap();
        std::fs::create_dir_all(&review).unwrap();
        let work = work.to_string_lossy().into_owned();
        let review = review.to_string_lossy().into_owned();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        maestro_shell::project::ProjectService::new(&paths)
            .create(
                "p",
                "P",
                &work,
                maestro_shell::project::NewProject::default(),
                1,
            )
            .ok();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Workspace,
            "ws",
            1,
            &maestro_shell::records::Workspace {
                workspace_id: "ws".into(),
                project_id: "p".into(),
                root: work.clone(),
                policy: maestro_shell::policy::WorkspacePolicy::ScratchCwd,
                consent: Default::default(),
            },
        )
        .unwrap();
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts.create_empty("win-main", 1).unwrap();
        layouts
            .open_tab(
                "win-main",
                "pane-a",
                "s-a",
                "A",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .unwrap();
        maestro_shell::store::set_window_project(&paths, "win-main", "p").unwrap();
        maestro_shell::ProjectService::new(&paths)
            .reorder_windows("p", &["win-main".into()], 2)
            .unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Session,
            "s-a",
            2,
            &maestro_shell::SessionRecord {
                session_id: "s-a".into(),
                workspace_id: "ws".into(),
                kind: maestro_shell::SessionKind::Agent,
                launch: maestro_shell::LaunchSpec::KnownSafe {
                    launch_spec_id: "claude".into(),
                    params: Vec::new(),
                },
                cwd_resolved: work,
                agent_task_id: None,
                created_at_ms: 2,
                last_attached_at_ms: 2,
                last_known_generation: None,
                status: maestro_shell::SessionStatus::Live,
            },
        )
        .unwrap();
        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let daemon = install_conditional_start_test_daemon(&tx);
        let lease_dir = dir.join("creation-lease");
        install_creation_lease_publisher(&tx, &lease_dir);
        let mut splitter = DaemonPaneSplitter {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            paths: paths.clone(),
        };

        let created = splitter
            .new_pane_with_initial_size(
                crate::remote_control::SplitPaneRequest {
                    window_id: "win-main".into(),
                    from_pane_id: "pane-a".into(),
                    dir: crate::remote_control::SplitPaneDir::Right,
                    agent: Some("terminal".into()),
                    launch_flags: None,
                    cwd: Some(review),
                    pane_name: Some("Review".into()),
                    now_ms: 5,
                },
                InitialTerminalSize::from_optional_pair(Some(134), Some(45)),
            )
            .unwrap();
        assert_creation_lease(&lease_dir, &created.session_id);

        let start = only_conditional_start(&daemon);
        assert_eq!(start["op"], "start_session");
        assert_eq!(start["id"], created.session_id);
        assert_eq!(
            start["command"],
            crate::session_creator::empty_session_launch(false).command
        );
        assert_eq!(start["cols"], 134);
        assert_eq!(start["rows"], 45);
        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load("win-main")
            .unwrap()
            .unwrap();
        assert_eq!(layout.tabs.len(), 2);
        assert_eq!(
            layout
                .tabs
                .iter()
                .find(|tab| tab.tab_id == "pane-a")
                .unwrap()
                .split_from,
            None
        );
        let tab = layout
            .tabs
            .iter()
            .find(|tab| tab.tab_id == created.tab_id)
            .expect("new pane tab exists");
        assert_eq!(tab.title, "Review");
        assert_eq!(tab.split_from, None);
        assert_eq!(tab.pane_rect, None);
        assert!(
            tab.stashed,
            "remote-created panes start as sidebar/viewport records"
        );
        assert_eq!(
            maestro_shell::take_focus_window_request(&paths).unwrap(),
            None
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_new_pane_fresh_agent_starts_once_without_becoming_continue() {
        use crate::remote_control::{PaneSessionStarter, PaneSplitter};
        let dir = std::env::temp_dir().join(format!(
            "hydra-new-pane-fresh-agent-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = seed_split_fixture(&dir);
        let review = dir.join("review");
        std::fs::create_dir_all(&review).unwrap();
        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let daemon = install_conditional_start_test_daemon(&tx);
        let sessions = Arc::new(Mutex::new(SessionCache::mutation_ready_for_test()));
        let mut splitter = DaemonPaneSplitter {
            tx: tx.clone(),
            sessions: sessions.clone(),
            paths: paths.clone(),
        };

        let created = splitter
            .new_pane(crate::remote_control::SplitPaneRequest {
                window_id: "win-main".into(),
                from_pane_id: "pane-a".into(),
                dir: crate::remote_control::SplitPaneDir::Right,
                agent: Some("claude".into()),
                launch_flags: None,
                cwd: Some(review.to_string_lossy().into_owned()),
                pane_name: Some("Fresh Claude".into()),
                now_ms: 5,
            })
            .unwrap();

        let first_start = only_conditional_start(&daemon);
        assert_eq!(first_start["op"], "start_session");
        assert_eq!(first_start["id"], created.session_id);
        assert_eq!(first_start["command"], login_shell_program());
        let command_line = first_start["args"][1].as_str().unwrap();
        assert!(command_line.contains("'claude'"));
        assert!(
            !command_line.contains("--continue"),
            "a fresh New Pane must not resume unrelated Claude history: {command_line}"
        );

        let before = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &created.session_id,
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(session) => session,
            other => panic!("expected fresh session record, got {other:?}"),
        };
        let maestro_shell::LaunchSpec::KnownSafe {
            launch_spec_id,
            params,
        } = &before.launch
        else {
            panic!("fresh Claude pane must publish an exact recipe")
        };
        assert_eq!(launch_spec_id, "claude");
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], "--resume");
        let provider_id = &params[1];
        assert_eq!(
            uuid::Uuid::parse_str(provider_id)
                .unwrap()
                .hyphenated()
                .to_string(),
            *provider_id
        );
        assert!(
            command_line.contains("--session-id") && command_line.contains(provider_id),
            "first wire launch must create the same assigned Claude identity: {command_line}"
        );

        // The browser's follow-up viewport handshake observes the create-time reservation. It succeeds
        // without sending a second StartSession or changing the exact provider identity published after Grid.
        let mut starter = DaemonPaneSessionStarter {
            tx,
            sessions,
            paths: paths.clone(),
        };
        let confirmed = starter
            .start_pane_session(crate::remote_control::RevivePaneRequest {
                window_id: "win-main".into(),
                pane_id: created.tab_id.clone(),
                now_ms: 6,
            })
            .unwrap();
        assert_eq!(confirmed.session_id, created.session_id);
        assert_eq!(
            daemon.start_requests().len(),
            1,
            "viewport confirmation must not publish a second ledger operation"
        );
        let after = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &created.session_id,
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(session) => session,
            other => panic!("expected confirmed session record, got {other:?}"),
        };
        assert_eq!(after.launch, before.launch);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_new_pane_inherits_provider_profile_with_a_fresh_identity() {
        use crate::remote_control::PaneSplitter;

        const SOURCE_PROVIDER_ID: &str = "10000000-0000-4000-8000-000000000001";
        let dir = std::env::temp_dir().join(format!(
            "hydra-new-pane-inherited-provider-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = seed_split_fixture(&dir);
        let source = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            "s-a",
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(mut source) => {
                source.launch = maestro_shell::LaunchSpec::KnownSafe {
                    launch_spec_id: "claude".into(),
                    params: vec![
                        "--resume".into(),
                        SOURCE_PROVIDER_ID.into(),
                        "--model".into(),
                        "opus".into(),
                        "--dangerously-skip-permissions".into(),
                    ],
                };
                source
            }
            other => panic!("expected source session, got {other:?}"),
        };
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Session,
            "s-a",
            3,
            &source,
        )
        .unwrap();

        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let daemon = install_conditional_start_test_daemon(&tx);
        let mut splitter = DaemonPaneSplitter {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            paths: paths.clone(),
        };
        let created = splitter
            .new_pane(crate::remote_control::SplitPaneRequest {
                window_id: "win-main".into(),
                from_pane_id: "pane-a".into(),
                dir: crate::remote_control::SplitPaneDir::Right,
                agent: None,
                launch_flags: None,
                cwd: None,
                pane_name: Some("Inherited Claude".into()),
                now_ms: 5,
            })
            .unwrap();

        let child = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &created.session_id,
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(child) => child,
            other => panic!("expected child session, got {other:?}"),
        };
        let maestro_shell::LaunchSpec::KnownSafe {
            launch_spec_id,
            params,
        } = &child.launch
        else {
            panic!("inherited Claude pane must publish an exact child identity")
        };
        assert_eq!(launch_spec_id, "claude");
        assert_eq!(params[0], "--resume");
        let child_provider_id = &params[1];
        assert_ne!(child_provider_id, SOURCE_PROVIDER_ID);
        assert_eq!(
            uuid::Uuid::parse_str(child_provider_id)
                .unwrap()
                .hyphenated()
                .to_string(),
            *child_provider_id
        );
        assert_eq!(
            &params[2..],
            &["--model", "opus", "--dangerously-skip-permissions"]
        );
        assert_provider_start_executes_exact_source(
            &only_conditional_start(&daemon),
            &created.session_id,
            &source.cwd_resolved,
            &[
                "claude".into(),
                "--session-id".into(),
                child_provider_id.clone(),
                "--model".into(),
                "opus".into(),
                "--dangerously-skip-permissions".into(),
            ],
            InitialTerminalSize::default(),
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_new_pane_does_not_evict_live_panes_when_window_is_full() {
        use crate::remote_control::PaneSplitter;
        let dir =
            std::env::temp_dir().join(format!("hydra-new-pane-evict-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let fifth = dir.join("fifth");
        std::fs::create_dir_all(&fifth).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        maestro_shell::project::ProjectService::new(&paths)
            .create(
                "p",
                "P",
                "/r",
                maestro_shell::project::NewProject::default(),
                1,
            )
            .ok();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Workspace,
            "ws",
            1,
            &maestro_shell::records::Workspace {
                workspace_id: "ws".into(),
                project_id: "p".into(),
                root: "/r".into(),
                policy: maestro_shell::policy::WorkspacePolicy::ScratchCwd,
                consent: Default::default(),
            },
        )
        .unwrap();
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts.create_empty("win-main", 1).unwrap();
        layouts
            .open_tab(
                "win-main",
                "pane-a",
                "s-a",
                "A",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .unwrap();
        maestro_shell::store::set_window_project(&paths, "win-main", "p").unwrap();
        maestro_shell::ProjectService::new(&paths)
            .reorder_windows("p", &["win-main".into()], 2)
            .unwrap();
        for (idx, (from, pane, session)) in [
            ("pane-a", "pane-b", "s-b"),
            ("pane-b", "pane-c", "s-c"),
            ("pane-c", "pane-d", "s-d"),
        ]
        .into_iter()
        .enumerate()
        {
            let now = 3 + idx as u64;
            layouts
                .split_tab(
                    "win-main",
                    from,
                    pane,
                    session,
                    pane,
                    maestro_shell::SplitAxis::Right,
                    now,
                )
                .unwrap();
        }
        for (idx, (session_id, cwd)) in [
            ("s-a", "/Users/test/a"),
            ("s-b", "/Users/test/b"),
            ("s-c", "/Users/test/c"),
            ("s-d", "/Users/test/d"),
        ]
        .into_iter()
        .enumerate()
        {
            let now = 10 + idx as u64;
            maestro_shell::write_record(
                &paths,
                maestro_shell::RecordKind::Session,
                session_id,
                now,
                &maestro_shell::SessionRecord {
                    session_id: session_id.into(),
                    workspace_id: "ws".into(),
                    kind: maestro_shell::SessionKind::Agent,
                    launch: maestro_shell::LaunchSpec::KnownSafe {
                        launch_spec_id: "claude".into(),
                        params: Vec::new(),
                    },
                    cwd_resolved: cwd.into(),
                    agent_task_id: None,
                    created_at_ms: now,
                    last_attached_at_ms: now,
                    last_known_generation: None,
                    status: maestro_shell::SessionStatus::Live,
                },
            )
            .unwrap();
        }
        let before = maestro_shell::WindowLayoutService::new(&paths)
            .load("win-main")
            .unwrap()
            .unwrap();
        assert_eq!(before.tabs.iter().filter(|tab| !tab.stashed).count(), 4);

        let (tx, mut rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let _daemon = install_conditional_start_test_daemon(&tx);
        let mut splitter = DaemonPaneSplitter {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            paths: paths.clone(),
        };

        let created = splitter
            .new_pane(crate::remote_control::SplitPaneRequest {
                window_id: "win-main".into(),
                from_pane_id: "pane-a".into(),
                dir: crate::remote_control::SplitPaneDir::Right,
                agent: Some("terminal".into()),
                launch_flags: None,
                cwd: Some(fifth.to_string_lossy().into_owned()),
                pane_name: Some("Fifth".into()),
                now_ms: 50,
            })
            .unwrap();

        let start = serde_json::from_str::<serde_json::Value>(rx.try_recv().unwrap().trim())
            .expect("fifth pane start request is valid JSON");
        assert_eq!(start["op"], "start_session");
        assert_eq!(start["id"], created.session_id);
        assert!(rx.try_recv().is_err());
        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load("win-main")
            .unwrap()
            .unwrap();
        let live: Vec<_> = layout.tabs.iter().filter(|tab| !tab.stashed).collect();
        assert_eq!(
            live.len(),
            4,
            "remote create keeps the local window at the 4-live-pane cap"
        );
        assert!(
            layout
                .tabs
                .iter()
                .any(|tab| tab.tab_id == "pane-b" && !tab.stashed),
            "remote create does not evict an existing local live pane"
        );
        assert!(
            live.iter().any(|tab| tab.tab_id == "pane-a"),
            "source pane remains live"
        );
        assert!(
            layout
                .tabs
                .iter()
                .any(|tab| tab.tab_id == created.tab_id && tab.stashed),
            "new remote-created pane is stashed for remote viewport placement"
        );
        assert_eq!(
            maestro_shell::take_focus_window_request(&paths).unwrap(),
            None
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_pane_reviver_evicts_one_live_pane_when_window_is_full() {
        use crate::remote_control::PaneReviver;
        let dir = std::env::temp_dir().join(format!(
            "hydra-revive-pane-evict-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let old_cwd = dir.join("old");
        std::fs::create_dir_all(&old_cwd).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        maestro_shell::project::ProjectService::new(&paths)
            .create(
                "p",
                "P",
                "/r",
                maestro_shell::project::NewProject::default(),
                1,
            )
            .ok();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Workspace,
            "ws",
            1,
            &maestro_shell::records::Workspace {
                workspace_id: "ws".into(),
                project_id: "p".into(),
                root: "/r".into(),
                policy: maestro_shell::policy::WorkspacePolicy::ScratchCwd,
                consent: Default::default(),
            },
        )
        .unwrap();
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts.create_empty("win-main", 1).unwrap();
        layouts
            .open_tab(
                "win-main",
                "pane-a",
                "s-a",
                "A",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .unwrap();
        for (idx, (from, pane, session)) in [
            ("pane-a", "pane-b", "s-b"),
            ("pane-b", "pane-c", "s-c"),
            ("pane-c", "pane-d", "s-d"),
        ]
        .into_iter()
        .enumerate()
        {
            layouts
                .split_tab(
                    "win-main",
                    from,
                    pane,
                    session,
                    pane,
                    maestro_shell::SplitAxis::Right,
                    3 + idx as u64,
                )
                .unwrap();
        }
        layouts
            .open_tab(
                "win-main",
                "pane-old",
                "s-old",
                "Old",
                false,
                maestro_shell::AttentionState::default(),
                8,
            )
            .unwrap();
        layouts.stash_pane("win-main", "pane-old", 9).unwrap();
        for (idx, (session_id, cwd)) in [
            ("s-a", "/Users/test/a"),
            ("s-b", "/Users/test/b"),
            ("s-c", "/Users/test/c"),
            ("s-d", "/Users/test/d"),
            ("s-old", "/Users/test/old"),
        ]
        .into_iter()
        .enumerate()
        {
            let now = 10 + idx as u64;
            maestro_shell::write_record(
                &paths,
                maestro_shell::RecordKind::Session,
                session_id,
                now,
                &maestro_shell::SessionRecord {
                    session_id: session_id.into(),
                    workspace_id: "ws".into(),
                    kind: maestro_shell::SessionKind::Agent,
                    launch: maestro_shell::LaunchSpec::KnownSafe {
                        launch_spec_id: "claude".into(),
                        params: if session_id == "s-old" {
                            vec![
                                "--resume".into(),
                                "70000000-0000-4000-8000-000000000001".into(),
                            ]
                        } else {
                            Vec::new()
                        },
                    },
                    cwd_resolved: if session_id == "s-old" {
                        old_cwd.to_string_lossy().into_owned()
                    } else {
                        cwd.into()
                    },
                    agent_task_id: None,
                    created_at_ms: now,
                    last_attached_at_ms: now,
                    last_known_generation: None,
                    status: maestro_shell::SessionStatus::Live,
                },
            )
            .unwrap();
        }

        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let daemon = install_conditional_start_test_daemon(&tx);
        let lease_dir = dir.join("creation-lease");
        install_creation_lease_publisher(&tx, &lease_dir);
        let mut reviver = DaemonPaneReviver {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            paths: paths.clone(),
        };
        let revived = reviver
            .revive_pane_with_initial_size(
                crate::remote_control::RevivePaneRequest {
                    window_id: "win-main".into(),
                    pane_id: "pane-old".into(),
                    now_ms: 50,
                },
                InitialTerminalSize::from_optional_pair(Some(135), Some(46)),
            )
            .unwrap();

        assert_eq!(revived.session_id, "s-old");
        assert_creation_lease(&lease_dir, &revived.session_id);
        let start = daemon.start_requests().pop().unwrap();
        let line = start.to_string();
        assert!(
            start["conditional_start"].is_object(),
            "revive must carry exact ledger/precondition authority"
        );
        assert_eq!(start["cols"], 135);
        assert_eq!(start["rows"], 46);
        assert_eq!(
            start["command"],
            login_shell_program(),
            "agent pane revive must use the user's login shell: {line}"
        );
        assert!(
            line.contains("claude"),
            "recorded KnownSafe claude session should revive claude, got: {line}"
        );
        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load("win-main")
            .unwrap()
            .unwrap();
        let live: Vec<_> = layout.tabs.iter().filter(|tab| !tab.stashed).collect();
        assert_eq!(live.len(), 4);
        assert!(layout
            .tabs
            .iter()
            .any(|tab| tab.tab_id == "pane-a" && tab.stashed));
        assert!(live.iter().any(|tab| tab.tab_id == "pane-old"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_pane_session_starter_refuses_legacy_adhoc_opencode_without_reviving_layout() {
        use crate::remote_control::PaneSessionStarter;
        let dir = std::env::temp_dir().join(format!(
            "hydra-start-pane-session-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let old_cwd = dir.join("old");
        std::fs::create_dir_all(&old_cwd).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        maestro_shell::project::ProjectService::new(&paths)
            .create(
                "p",
                "P",
                "/r",
                maestro_shell::project::NewProject::default(),
                1,
            )
            .ok();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Workspace,
            "ws",
            1,
            &maestro_shell::records::Workspace {
                workspace_id: "ws".into(),
                project_id: "p".into(),
                root: "/r".into(),
                policy: maestro_shell::policy::WorkspacePolicy::ScratchCwd,
                consent: Default::default(),
            },
        )
        .unwrap();
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts.create_empty("win-main", 1).unwrap();
        layouts
            .open_tab(
                "win-main",
                "pane-a",
                "s-a",
                "A",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .unwrap();
        layouts
            .split_tab(
                "win-main",
                "pane-a",
                "pane-old",
                "s-old",
                "Old",
                maestro_shell::SplitAxis::Right,
                2,
            )
            .unwrap();
        layouts.stash_pane("win-main", "pane-old", 3).unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Session,
            "s-old",
            4,
            &maestro_shell::SessionRecord {
                session_id: "s-old".into(),
                workspace_id: "ws".into(),
                kind: maestro_shell::SessionKind::Agent,
                launch: maestro_shell::LaunchSpec::AdHocRedacted {
                    argv: vec![
                        "opencode".into(),
                        "--mini".into(),
                        "--session".into(),
                        "ses_abc".into(),
                    ],
                    redacted: false,
                    restart_requires_user: true,
                },
                cwd_resolved: old_cwd.to_string_lossy().into_owned(),
                agent_task_id: None,
                created_at_ms: 4,
                last_attached_at_ms: 4,
                last_known_generation: None,
                status: maestro_shell::SessionStatus::Live,
            },
        )
        .unwrap();

        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let daemon = install_conditional_start_test_daemon(&tx);
        let lease_dir = dir.join("creation-lease");
        install_creation_lease_publisher(&tx, &lease_dir);
        let mut starter = DaemonPaneSessionStarter {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            paths: paths.clone(),
        };
        assert_eq!(
            starter.start_pane_session_with_initial_size(
                crate::remote_control::RevivePaneRequest {
                    window_id: "win-main".into(),
                    pane_id: "pane-old".into(),
                    now_ms: 50,
                },
                InitialTerminalSize::from_optional_pair(Some(136), Some(47)),
            ),
            Err(crate::remote_control::RevivePaneError::Internal),
            "ordinary AdHoc records cannot gain exact replay authority by canonicalization"
        );
        assert!(
            daemon.start_requests().is_empty(),
            "refused AdHoc replay must publish no ledger StartSession"
        );
        assert!(
            crate::winsize_owner::read_remote_owned_sessions(&lease_dir).is_empty(),
            "refused AdHoc replay must release its temporary viewport lease"
        );
        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load("win-main")
            .unwrap()
            .unwrap();
        assert!(
            layout
                .tabs
                .iter()
                .any(|tab| tab.tab_id == "pane-old" && tab.stashed),
            "virtual start must not revive or otherwise mutate the local desktop layout"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remote_exact_start_never_canonicalizes_bare_or_conflicting_provider_rows() {
        use crate::remote_control::PaneSessionStarter;

        let tmp = tempfile::tempdir().unwrap();
        let paths = seed_split_fixture(tmp.path());
        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let daemon = install_conditional_start_test_daemon(&tx);
        let lease_dir = tmp.path().join("creation-lease");
        install_creation_lease_publisher(&tx, &lease_dir);
        let mut starter = DaemonPaneSessionStarter {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            paths: paths.clone(),
        };
        let load = || match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            "s-a",
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(session) => session,
            other => panic!("expected source session, got {other:?}"),
        };

        for (now_ms, launch) in [
            (
                10,
                maestro_shell::LaunchSpec::KnownSafe {
                    launch_spec_id: "claude".into(),
                    params: Vec::new(),
                },
            ),
            (
                20,
                maestro_shell::LaunchSpec::KnownSafe {
                    launch_spec_id: "claude".into(),
                    params: vec![
                        "--resume".into(),
                        "10000000-0000-4000-8000-000000000001".into(),
                        "--resume".into(),
                        "20000000-0000-4000-8000-000000000002".into(),
                    ],
                },
            ),
        ] {
            let mut before = load();
            before.launch = launch;
            maestro_shell::write_record(
                &paths,
                maestro_shell::RecordKind::Session,
                "s-a",
                now_ms,
                &before,
            )
            .unwrap();
            assert_eq!(
                starter.start_pane_session(crate::remote_control::RevivePaneRequest {
                    window_id: "win-main".into(),
                    pane_id: "pane-a".into(),
                    now_ms: now_ms + 1,
                }),
                Err(crate::remote_control::RevivePaneError::Internal)
            );
            assert_eq!(
                load(),
                before,
                "exact recovery must authorize original durable bytes without migration"
            );
        }
        assert!(daemon.start_requests().is_empty());
        assert!(crate::winsize_owner::read_remote_owned_sessions(&lease_dir).is_empty());
    }

    #[test]
    fn daemon_pane_session_starter_replaces_exact_exited_generation_after_grid_proof() {
        use crate::remote_control::PaneSessionStarter;

        let tmp = tempfile::tempdir().unwrap();
        let paths = seed_split_fixture(tmp.path());
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        let mut session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            "s-a",
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(session) => session,
            other => panic!("expected exact starter Session row, got {other:?}"),
        };
        session.launch = maestro_shell::LaunchSpec::KnownSafe {
            launch_spec_id: "claude".into(),
            params: vec![
                "--resume".into(),
                "70000000-0000-4000-8000-000000000002".into(),
            ],
        };
        session.status = maestro_shell::SessionStatus::Exited;
        session.last_known_generation = Some("generation-a".into());
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Session,
            "s-a",
            4,
            &session,
        )
        .unwrap();
        let layout_before = layouts.load("win-main").unwrap().unwrap();

        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let daemon = install_conditional_start_test_daemon_with_live(
            &tx,
            std::collections::BTreeMap::from([("s-a".to_string(), "generation-a".to_string())]),
        );
        let lease_dir = tmp.path().join("creation-lease");
        install_creation_lease_publisher(&tx, &lease_dir);
        let sessions = Arc::new(Mutex::new(SessionCache::mutation_ready_for_test()));
        let mut starter = DaemonPaneSessionStarter {
            tx,
            sessions: Arc::clone(&sessions),
            paths: paths.clone(),
        };

        let started = starter
            .start_pane_session_with_initial_size(
                crate::remote_control::RevivePaneRequest {
                    window_id: "win-main".into(),
                    pane_id: "pane-a".into(),
                    now_ms: 50,
                },
                InitialTerminalSize::from_optional_pair(Some(136), Some(47)),
            )
            .unwrap();
        assert_eq!(started.session_id, "s-a");
        let starts = daemon.start_requests();
        assert_eq!(starts.len(), 1);
        let start = &starts[0];
        assert_eq!(start["id"], "s-a");
        assert_eq!(start["cols"], 136);
        assert_eq!(start["rows"], 47);
        assert_eq!(
            start["conditional_start"]["precondition"],
            serde_json::json!({
                "kind": "exited_generation",
                "expected_generation": "generation-a",
            })
        );
        assert!(start["command"]
            .as_str()
            .is_some_and(|command| !command.is_empty()));
        assert!(start["args"]
            .as_array()
            .is_some_and(
                |args| args.iter().any(|arg| arg.as_str().is_some_and(|arg| {
                    arg.contains("claude") && arg.contains("70000000-0000-4000-8000-000000000002")
                }))
            ));
        assert_eq!(layouts.load("win-main").unwrap().unwrap(), layout_before);
        let published = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            "s-a",
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(session) => session,
            other => panic!("expected published exact starter Session, got {other:?}"),
        };
        assert_eq!(published.status, maestro_shell::SessionStatus::Live);
        assert_eq!(
            published.last_known_generation.as_deref(),
            Some("hydra-test-generation-1")
        );
        assert!(sessions
            .lock()
            .unwrap()
            .snapshot()
            .contains(&"s-a".to_string()));
        assert_eq!(
            crate::winsize_owner::read_remote_owned_sessions(&lease_dir),
            vec!["s-a".to_string()]
        );
        assert!(daemon
            .requests()
            .iter()
            .any(|request| request["op"] == "retire_start_operation"));
    }

    #[test]
    fn daemon_pane_split_fresh_agent_with_model_launches_agent_with_model_argv() {
        // Tier-1 model support: a FRESH explicit-agent split with a model must actually launch
        // `<agent> --model <name>` and record the same params (previously the model was dropped: the
        // record said KnownSafe{claude, []} and the daemon started a bare shell).
        use crate::remote_control::PaneSplitter;
        let dir = std::env::temp_dir().join(format!(
            "hydra-split-fresh-model-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let work = dir.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let work = work.to_string_lossy().into_owned();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        maestro_shell::project::ProjectService::new(&paths)
            .create(
                "p",
                "P",
                &work,
                maestro_shell::project::NewProject::default(),
                1,
            )
            .ok();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Workspace,
            "ws",
            1,
            &maestro_shell::records::Workspace {
                workspace_id: "ws".into(),
                project_id: "p".into(),
                root: work.clone(),
                policy: maestro_shell::policy::WorkspacePolicy::ScratchCwd,
                consent: Default::default(),
            },
        )
        .unwrap();
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts.create_empty("win-main", 1).unwrap();
        layouts
            .open_tab(
                "win-main",
                "pane-a",
                "s-a",
                "A",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .unwrap();
        maestro_shell::store::set_window_project(&paths, "win-main", "p").unwrap();
        maestro_shell::ProjectService::new(&paths)
            .reorder_windows("p", &["win-main".into()], 2)
            .unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Session,
            "s-a",
            2,
            &maestro_shell::SessionRecord {
                session_id: "s-a".into(),
                workspace_id: "ws".into(),
                kind: maestro_shell::SessionKind::Agent,
                launch: maestro_shell::LaunchSpec::KnownSafe {
                    launch_spec_id: "claude".into(),
                    params: Vec::new(),
                },
                cwd_resolved: work.clone(),
                agent_task_id: None,
                created_at_ms: 2,
                last_attached_at_ms: 2,
                last_known_generation: None,
                status: maestro_shell::SessionStatus::Live,
            },
        )
        .unwrap();
        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let daemon = install_conditional_start_test_daemon(&tx);
        let mut splitter = DaemonPaneSplitter {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            paths: paths.clone(),
        };

        let created = splitter
            .split_pane(crate::remote_control::SplitPaneRequest {
                window_id: "win-main".into(),
                from_pane_id: "pane-a".into(),
                dir: crate::remote_control::SplitPaneDir::Down,
                agent: Some("claude".into()),
                launch_flags: Some(serde_json::json!({ "model": "claude-opus-4-8" })),
                cwd: None,
                pane_name: None,
                now_ms: 5,
            })
            .unwrap();

        let session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &created.session_id,
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(s) => s,
            _ => panic!("session should load"),
        };
        let maestro_shell::LaunchSpec::KnownSafe {
            launch_spec_id,
            params,
        } = &session.launch
        else {
            panic!("fresh Claude split must publish an exact recipe")
        };
        assert_eq!(launch_spec_id, "claude");
        assert_eq!(params.len(), 4);
        assert_eq!(params[0], "--resume");
        let provider_id = &params[1];
        assert_eq!(
            uuid::Uuid::parse_str(provider_id)
                .unwrap()
                .hyphenated()
                .to_string(),
            *provider_id
        );
        assert_eq!(&params[2..], &["--model", "claude-opus-4-8"]);
        assert_provider_start_executes_exact_source(
            &only_conditional_start(&daemon),
            &created.session_id,
            &work,
            &[
                "claude".into(),
                "--session-id".into(),
                provider_id.clone(),
                "--model".into(),
                "claude-opus-4-8".into(),
            ],
            InitialTerminalSize::default(),
        );
        // No pane_name → the pre-existing agent-derived title is unchanged.
        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load("win-main")
            .unwrap()
            .unwrap();
        let tab = layout
            .tabs
            .iter()
            .find(|tab| tab.tab_id == created.tab_id)
            .expect("split tab exists");
        assert_eq!(tab.title, "Claude");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_pane_split_fresh_agent_without_model_launches_that_agent_not_bash() {
        // BUG A regression: a fresh split with an EXPLICIT agent and NO model recorded KnownSafe{claude, []}
        // but started the daemon session with the launch-less bare line (bash --norc) — the pane came up as
        // an empty bash terminal while its record claimed claude. Record/launch parity: the start line's
        // command must be the picked agent. "terminal" and inherit (absent agent) keep the bare-shell start.
        use crate::remote_control::PaneSplitter;
        let dir = std::env::temp_dir().join(format!(
            "hydra-split-fresh-nomodel-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let work = dir.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let work = work.to_string_lossy().into_owned();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        maestro_shell::project::ProjectService::new(&paths)
            .create(
                "p",
                "P",
                &work,
                maestro_shell::project::NewProject::default(),
                1,
            )
            .ok();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Workspace,
            "ws",
            1,
            &maestro_shell::records::Workspace {
                workspace_id: "ws".into(),
                project_id: "p".into(),
                root: work.clone(),
                policy: maestro_shell::policy::WorkspacePolicy::ScratchCwd,
                consent: Default::default(),
            },
        )
        .unwrap();
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts.create_empty("win-main", 1).unwrap();
        layouts
            .open_tab(
                "win-main",
                "pane-a",
                "s-a",
                "A",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .unwrap();
        maestro_shell::store::set_window_project(&paths, "win-main", "p").unwrap();
        maestro_shell::ProjectService::new(&paths)
            .reorder_windows("p", &["win-main".into()], 2)
            .unwrap();
        let source_launch = maestro_shell::LaunchSpec::KnownSafe {
            launch_spec_id: "gemini".into(),
            params: vec!["--resume".into(), "latest".into()],
        };
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Session,
            "s-a",
            2,
            &maestro_shell::SessionRecord {
                session_id: "s-a".into(),
                workspace_id: "ws".into(),
                kind: maestro_shell::SessionKind::Agent,
                launch: source_launch.clone(),
                cwd_resolved: work.clone(),
                agent_task_id: None,
                created_at_ms: 2,
                last_attached_at_ms: 2,
                last_known_generation: None,
                status: maestro_shell::SessionStatus::Live,
            },
        )
        .unwrap();
        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let daemon = install_conditional_start_test_daemon(&tx);
        let mut splitter = DaemonPaneSplitter {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            paths: paths.clone(),
        };
        let split = |splitter: &mut DaemonPaneSplitter, agent: Option<&str>, now: u64| {
            splitter
                .split_pane(crate::remote_control::SplitPaneRequest {
                    window_id: "win-main".into(),
                    from_pane_id: "pane-a".into(),
                    dir: crate::remote_control::SplitPaneDir::Right,
                    agent: agent.map(str::to_string),
                    launch_flags: None,
                    cwd: None,
                    pane_name: None,
                    now_ms: now,
                })
                .unwrap()
        };
        let load_session =
            |paths: &maestro_shell::AppPaths, id: &str| match maestro_shell::load_one::<
                maestro_shell::SessionRecord,
            >(
                paths,
                maestro_shell::RecordKind::Session,
                id,
            )
            .unwrap()
            .unwrap()
            {
                maestro_shell::LoadOutcome::Loaded(s) => s,
                _ => panic!("session should load"),
            };

        // 1) Fresh EXPLICIT agent, no model → the start line's command IS the agent (not bash).
        let fresh = split(&mut splitter, Some("claude"), 5);
        let fresh_session = load_session(&paths, &fresh.session_id);
        let maestro_shell::LaunchSpec::KnownSafe {
            launch_spec_id,
            params,
        } = &fresh_session.launch
        else {
            panic!("fresh Claude split must publish an exact recipe")
        };
        assert_eq!(launch_spec_id, "claude");
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], "--resume");
        let claude_provider_id = &params[1];
        assert_eq!(
            uuid::Uuid::parse_str(claude_provider_id)
                .unwrap()
                .hyphenated()
                .to_string(),
            *claude_provider_id
        );
        assert_provider_start_executes_exact_source(
            &only_conditional_start(&daemon),
            &fresh.session_id,
            &work,
            &[
                "claude".into(),
                "--session-id".into(),
                claude_provider_id.clone(),
            ],
            InitialTerminalSize::default(),
        );
        // Keep room under the four-live-pane cap for the provider-specific parity case below.
        maestro_shell::WindowLayoutService::new(&paths)
            .stash_pane("win-main", &fresh.tab_id, 5)
            .unwrap();

        // 2) "terminal" → an exact prepared bare-shell launch that remains non-replayable.
        let term = split(&mut splitter, Some("terminal"), 6);
        let term_session = load_session(&paths, &term.session_id);
        assert_eq!(term_session.kind, maestro_shell::SessionKind::Shell);
        assert!(matches!(
            term_session.launch,
            maestro_shell::LaunchSpec::AdHocRedacted {
                restart_requires_user: true,
                ..
            }
        ));
        let starts = daemon.start_requests();
        assert_eq!(starts.len(), 2);
        let terminal_launch = crate::session_creator::empty_session_launch(false);
        assert_eq!(starts[1]["id"], term.session_id);
        assert_eq!(starts[1]["cwd"], work);
        assert_eq!(starts[1]["command"], terminal_launch.command);
        assert_eq!(
            starts[1]["args"],
            serde_json::to_value(terminal_launch.args).unwrap()
        );
        assert!(starts[1]["conditional_start"].is_object());

        // 3) INHERIT (absent agent) → inherit Gemini's provider profile, never its mutable
        // `latest` selector. The child receives a fresh UUID and publishes only that exact resume.
        let inherit = split(&mut splitter, None, 7);
        let inherit_session = load_session(&paths, &inherit.session_id);
        let maestro_shell::LaunchSpec::KnownSafe {
            launch_spec_id,
            params,
        } = &inherit_session.launch
        else {
            panic!("inherited Gemini split must publish its own exact recipe")
        };
        assert_eq!(launch_spec_id, "gemini");
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], "--resume");
        let inherited_provider_id = &params[1];
        assert_eq!(
            uuid::Uuid::parse_str(inherited_provider_id)
                .unwrap()
                .hyphenated()
                .to_string(),
            *inherited_provider_id
        );
        assert_ne!(inherit_session.launch, source_launch);
        let starts = daemon.start_requests();
        assert_eq!(starts.len(), 3);
        assert_provider_start_executes_exact_source(
            &starts[2],
            &inherit.session_id,
            &work,
            &[
                "gemini".into(),
                "--session-id".into(),
                inherited_provider_id.clone(),
            ],
            InitialTerminalSize::default(),
        );

        // 4) Fresh Copilot → one Hydra-owned UUID is written to the record and sent on the first start.
        let copilot = split(&mut splitter, Some("copilot"), 8);
        let copilot_session = load_session(&paths, &copilot.session_id);
        let maestro_shell::LaunchSpec::KnownSafe {
            launch_spec_id,
            params,
        } = &copilot_session.launch
        else {
            panic!("Copilot split must be KnownSafe");
        };
        assert_eq!(launch_spec_id, "copilot");
        assert_eq!(params.len(), 1);
        let provider_id = params[0].strip_prefix("--resume=").unwrap();
        assert_eq!(
            uuid::Uuid::parse_str(provider_id)
                .unwrap()
                .hyphenated()
                .to_string(),
            provider_id
        );
        let starts = daemon.start_requests();
        assert_eq!(starts.len(), 4);
        assert_provider_start_executes_exact_source(
            &starts[3],
            &copilot.session_id,
            &work,
            &["copilot".into(), format!("--session-id={provider_id}")],
            InitialTerminalSize::default(),
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_window_opener_fresh_agent_without_model_launches_that_agent_not_bash() {
        // BUG A regression (new_window flavor): an explicit-agent window with NO model/launch_flags recorded
        // KnownSafe{agent, []} but started plain bash. The first pane must actually run the agent.
        let dir = std::env::temp_dir().join(format!(
            "hydra-new-window-fresh-nomodel-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let project_root = dir.join("project-root");
        std::fs::create_dir_all(&project_root).unwrap();
        let project_root = project_root.to_string_lossy().into_owned();
        let project = maestro_shell::Project {
            project_id: "proj-fresh".into(),
            name: "fresh".into(),
            root: project_root.clone(),
            default_workspace_policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            created_at_ms: 1,
            last_active_at_ms: 2,
            icon: None,
            accent_color: None,
            launch_defaults: None,
            directories: Vec::new(),
            window_order: Vec::new(),
            system: false,
            hidden: false,
        };
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Project,
            &project.project_id,
            1,
            &project,
        )
        .unwrap();
        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let daemon = install_conditional_start_test_daemon(&tx);
        let mut opener = DaemonWindowOpener {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            paths: paths.clone(),
        };

        let created = opener
            .new_window(crate::remote_control::NewWindowRequest {
                project_id: "proj-fresh".into(),
                name: "W".into(),
                cwd: None,
                agent: Some("gemini".into()),
                launch_flags: None,
                now_ms: 9000,
            })
            .unwrap();
        let session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &created.session_id,
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(s) => s,
            _ => panic!("session loadable"),
        };
        let maestro_shell::LaunchSpec::KnownSafe {
            launch_spec_id,
            params,
        } = &session.launch
        else {
            panic!("fresh Gemini window must publish an exact recipe")
        };
        assert_eq!(launch_spec_id, "gemini");
        assert_eq!(params.len(), 2);
        assert_eq!(params[0], "--resume");
        let gemini_provider_id = &params[1];
        assert_eq!(
            uuid::Uuid::parse_str(gemini_provider_id)
                .unwrap()
                .hyphenated()
                .to_string(),
            *gemini_provider_id
        );
        assert_provider_start_executes_exact_source(
            &only_conditional_start(&daemon),
            &created.session_id,
            &project_root,
            &[
                "gemini".into(),
                "--session-id".into(),
                gemini_provider_id.clone(),
            ],
            InitialTerminalSize::default(),
        );

        let copilot_created = opener
            .new_window(crate::remote_control::NewWindowRequest {
                project_id: "proj-fresh".into(),
                name: "Copilot W".into(),
                cwd: None,
                agent: Some("copilot".into()),
                launch_flags: Some(serde_json::json!({"model": "auto"})),
                now_ms: 9001,
            })
            .unwrap();
        let copilot_session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &copilot_created.session_id,
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(s) => s,
            _ => panic!("Copilot window session loadable"),
        };
        let maestro_shell::LaunchSpec::KnownSafe {
            launch_spec_id,
            params,
        } = &copilot_session.launch
        else {
            panic!("Copilot window must be KnownSafe");
        };
        assert_eq!(launch_spec_id, "copilot");
        assert_eq!(params.len(), 3);
        let provider_id = params[0].strip_prefix("--resume=").unwrap();
        assert_eq!(
            uuid::Uuid::parse_str(provider_id)
                .unwrap()
                .hyphenated()
                .to_string(),
            provider_id
        );
        assert_eq!(&params[1..], &["--model", "auto"]);
        let starts = daemon.start_requests();
        assert_eq!(starts.len(), 2);
        assert_provider_start_executes_exact_source(
            &starts[1],
            &copilot_created.session_id,
            &project_root,
            &[
                "copilot".into(),
                format!("--session-id={provider_id}"),
                "--model".into(),
                "auto".into(),
            ],
            InitialTerminalSize::default(),
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_window_focuser_signals_a_focus_request_for_an_existing_window() {
        let dir =
            std::env::temp_dir().join(format!("hydra-focus-window-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts.create_empty("win-main", 1).unwrap();
        layouts
            .open_tab(
                "win-main",
                "pane-a",
                "s-a",
                "A",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .unwrap();
        let mut focuser = DaemonWindowFocuser {
            paths: paths.clone(),
        };

        // focusing a nonexistent window → WindowNotFound, and NO focus request is written.
        assert!(matches!(
            focuser.focus_window("missing".into(), 10),
            Err(crate::remote_control::FocusWindowError::WindowNotFound)
        ));
        assert!(maestro_shell::take_focus_window_request(&paths)
            .unwrap()
            .is_none());

        // focusing an existing window → Ok, and a fresh one-shot focus request is queued for the
        // foreground app. The production signal rejects timestamps older than its bounded freshness
        // window, so this test must not use an epoch-adjacent fixture value.
        let requested_at_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        focuser
            .focus_window("win-main".into(), requested_at_ms)
            .unwrap();
        let req = maestro_shell::take_focus_window_request(&paths)
            .unwrap()
            .expect("focus request written");
        assert_eq!(req.window_id, "win-main");
        assert_eq!(req.requested_at_ms, requested_at_ms);
        // it is one-shot: a second take() finds nothing.
        assert!(maestro_shell::take_focus_window_request(&paths)
            .unwrap()
            .is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_renamer_renames_desktop_window_and_pane() {
        let dir = std::env::temp_dir().join(format!("hydra-rename-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts.create_empty("win-main", 1).unwrap();
        layouts
            .open_tab(
                "win-main",
                "pane-a",
                "s-a",
                "A",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .unwrap();
        let mut renamer = DaemonRenamer {
            paths: paths.clone(),
        };

        renamer
            .rename(crate::remote_control::RenameRequest {
                window_id: "win-main".into(),
                pane_id: Some("pane-a".into()),
                name: "Build pane".into(),
                now_ms: 3,
            })
            .unwrap();
        renamer
            .rename(crate::remote_control::RenameRequest {
                window_id: "win-main".into(),
                pane_id: None,
                name: "Main window".into(),
                now_ms: 4,
            })
            .unwrap();

        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load("win-main")
            .unwrap()
            .unwrap();
        assert_eq!(layout.name.as_deref(), Some("Main window"));
        assert_eq!(layout.tabs[0].title, "Build pane");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_pane_remover_refuses_the_globally_last_visible_window() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-remove-pane-global-last-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        maestro_shell::ProjectService::new(&paths)
            .create(
                "project-main",
                "Main",
                "/tmp",
                maestro_shell::NewProject::default(),
                1,
            )
            .unwrap();
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts.create_empty("win-main", 1).unwrap();
        layouts
            .open_tab(
                "win-main",
                "pane-a",
                "s-a",
                "A",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .unwrap();
        maestro_shell::store::set_window_project(&paths, "win-main", "project-main").unwrap();
        let before = layouts.load("win-main").unwrap().unwrap();
        let mut remover = DaemonPaneRemover {
            paths: paths.clone(),
        };

        assert_eq!(
            remover.remove_pane(crate::remote_control::RemovePaneRequest {
                window_id: "win-main".into(),
                pane_id: "pane-a".into(),
                now_ms: 3,
            }),
            Err(crate::remote_control::RevivePaneError::GloballyLastVisible)
        );
        assert_eq!(layouts.load("win-main").unwrap().unwrap(), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_window_closer_deletes_layout_and_kills_pane_sessions() {
        let dir =
            std::env::temp_dir().join(format!("hydra-close-window-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts.create_empty("win-main", 1).unwrap();
        layouts
            .open_tab(
                "win-main",
                "pane-a",
                "s-a",
                "A",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .unwrap();
        layouts
            .split_tab(
                "win-main",
                "pane-a",
                "pane-b",
                "s-b",
                "B",
                maestro_shell::SplitAxis::Right,
                3,
            )
            .unwrap();
        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let daemon = install_conditional_start_test_daemon_with_live(
            &tx,
            std::collections::BTreeMap::from([
                ("s-a".to_string(), "generation-a".to_string()),
                ("s-b".to_string(), "generation-b".to_string()),
                ("s-other".to_string(), "generation-other".to_string()),
            ]),
        );
        let mut cache = SessionCache::mutation_ready_for_test();
        cache.apply_daemon_ids(vec!["s-a".into(), "s-b".into(), "s-other".into()]);
        let sessions = Arc::new(Mutex::new(cache));
        let mut closer = DaemonWindowCloser {
            tx,
            sessions: sessions.clone(),
            paths: paths.clone(),
        };

        closer.close_window("win-main".into(), 4).unwrap();

        assert!(maestro_shell::WindowLayoutService::new(&paths)
            .load("win-main")
            .unwrap()
            .is_none());
        let mut kills = daemon
            .requests()
            .into_iter()
            .filter(|request| request["op"] == "kill")
            .collect::<Vec<_>>();
        kills.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        assert_eq!(
            kills,
            vec![
                serde_json::json!({"op":"kill","id":"s-a","expected_generation":"generation-a"}),
                serde_json::json!({"op":"kill","id":"s-b","expected_generation":"generation-b"}),
            ]
        );
        assert_eq!(sessions.lock().unwrap().snapshot(), ["s-other"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_window_closer_refuses_the_globally_last_project_window() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-close-global-last-window-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        maestro_shell::ProjectService::new(&paths)
            .create(
                "project-main",
                "Main",
                "/tmp",
                maestro_shell::NewProject::default(),
                1,
            )
            .unwrap();
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts.create_empty("win-main", 1).unwrap();
        layouts
            .open_tab(
                "win-main",
                "pane-a",
                "s-a",
                "A",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .unwrap();
        maestro_shell::store::set_window_project(&paths, "win-main", "project-main").unwrap();

        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let daemon = install_conditional_start_test_daemon_with_live(
            &tx,
            std::collections::BTreeMap::from([("s-a".to_string(), "generation-a".to_string())]),
        );
        let mut cache = SessionCache::mutation_ready_for_test();
        cache.apply_daemon_ids(vec!["s-a".into()]);
        let sessions = Arc::new(Mutex::new(cache));
        let mut closer = DaemonWindowCloser {
            tx,
            sessions: sessions.clone(),
            paths: paths.clone(),
        };

        assert_eq!(
            closer.close_window("win-main".into(), 3),
            Err(crate::remote_control::CloseWindowError::GloballyLastVisible)
        );
        assert!(layouts.load("win-main").unwrap().is_some());
        assert!(daemon
            .requests()
            .into_iter()
            .all(|request| request["op"] != "kill"));
        assert_eq!(sessions.lock().unwrap().snapshot(), ["s-a"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_window_closer_never_deletes_the_reserved_recovery_window() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-close-recovery-window-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        maestro_shell::ProjectService::new(&paths)
            .create_hidden_system(
                maestro_shell::PRODUCT_RECOVERY_PROJECT_ID,
                "Recovery",
                "/tmp",
                maestro_shell::NewProject::default(),
                1,
            )
            .unwrap();
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts
            .create_empty(maestro_shell::PRODUCT_RECOVERY_WINDOW_ID, 1)
            .unwrap();
        maestro_shell::store::set_window_project(
            &paths,
            maestro_shell::PRODUCT_RECOVERY_WINDOW_ID,
            maestro_shell::PRODUCT_RECOVERY_PROJECT_ID,
        )
        .unwrap();
        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let mut closer = DaemonWindowCloser {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            paths: paths.clone(),
        };

        assert_eq!(
            closer.close_window(maestro_shell::PRODUCT_RECOVERY_WINDOW_ID.into(), 2),
            Err(crate::remote_control::CloseWindowError::WindowNotFound)
        );
        assert!(layouts
            .load(maestro_shell::PRODUCT_RECOVERY_WINDOW_ID)
            .unwrap()
            .is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_window_close_refuses_changed_snapshot_without_committing_kills() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-close-window-changed-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts.create_empty("win-changed", 1).unwrap();
        layouts
            .open_tab(
                "win-changed",
                "pane-a",
                "session-a",
                "A",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .unwrap();
        let prepared_from = layouts.load_snapshot("win-changed").unwrap().unwrap();
        // A second writer commits after the exact close snapshot. The transaction-local
        // revalidation must preserve that edit and must not create a release journal entry.
        layouts
            .rename_window("win-changed", "concurrent edit", 3)
            .unwrap();
        assert!(matches!(
            layouts
                .delete_if_unchanged_with_resolutions(
                    &prepared_from,
                    &maestro_shell::PreResolvedSessionGenerations::new(),
                    4,
                )
                .unwrap(),
            maestro_shell::ConditionalWindowDelete::Changed
        ));
        assert_eq!(
            layouts
                .load("win-changed")
                .unwrap()
                .unwrap()
                .name
                .as_deref(),
            Some("concurrent edit")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_window_close_refuses_byte_identical_recreation_without_committing_kills() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-close-window-aba-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts.create_empty("win-aba", 1).unwrap();
        layouts
            .open_tab(
                "win-aba",
                "pane-a",
                "session-a",
                "A",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .unwrap();
        let prepared_from = layouts.load_snapshot("win-aba").unwrap().unwrap();
        assert!(layouts.delete("win-aba").unwrap());
        layouts.create_empty("win-aba", 3).unwrap();
        layouts
            .open_tab(
                "win-aba",
                "pane-a",
                "session-a",
                "A",
                false,
                maestro_shell::AttentionState::default(),
                4,
            )
            .unwrap();
        assert_eq!(
            layouts.load("win-aba").unwrap().unwrap(),
            prepared_from.layout,
            "the public bytes intentionally reproduce the ABA input"
        );
        assert!(matches!(
            layouts
                .delete_if_unchanged_with_resolutions(
                    &prepared_from,
                    &maestro_shell::PreResolvedSessionGenerations::new(),
                    5,
                )
                .unwrap(),
            maestro_shell::ConditionalWindowDelete::Changed
        ));
        assert!(layouts.load("win-aba").unwrap().is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_window_close_preserves_a_session_referenced_by_another_window() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-close-window-shared-session-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        for (window_id, pane_id) in [("win-close", "pane-a"), ("win-survive", "pane-b")] {
            layouts.create_empty(window_id, 1).unwrap();
            layouts
                .open_tab(
                    window_id,
                    pane_id,
                    "shared-session",
                    pane_id,
                    false,
                    maestro_shell::AttentionState::default(),
                    2,
                )
                .unwrap();
        }
        let (tx, _rx) = daemon_request_channel(2, 1024);
        let daemon = install_conditional_start_test_daemon_with_live(
            &tx,
            std::collections::BTreeMap::from([(
                "shared-session".to_string(),
                "shared-generation".to_string(),
            )]),
        );
        let mut cache = SessionCache::mutation_ready_for_test();
        cache.apply_daemon_ids(vec!["shared-session".into()]);
        let sessions = Arc::new(Mutex::new(cache));
        let mut closer = DaemonWindowCloser {
            tx,
            sessions: sessions.clone(),
            paths: paths.clone(),
        };
        closer.close_window("win-close".into(), 3).unwrap();
        assert!(layouts.load("win-close").unwrap().is_none());
        assert!(layouts.load("win-survive").unwrap().is_some());
        assert!(
            daemon
                .requests()
                .into_iter()
                .all(|request| request["op"] != "kill"),
            "shared session must not be killed"
        );
        // The closer removes only the exclusive cohort from its cache.
        assert_eq!(sessions.lock().unwrap().snapshot(), ["shared-session"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_window_close_pressure_leaves_layout_and_sessions_untouched() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-close-window-pressure-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts.create_empty("win-pressure", 1).unwrap();
        layouts
            .open_tab(
                "win-pressure",
                "pane-a",
                "s-a",
                "A",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .unwrap();

        let (tx, mut rx) = daemon_request_channel(1, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        tx.send("already-queued".into()).unwrap();
        let sessions = Arc::new(Mutex::new(SessionCache::seeded(vec!["s-a".into()])));
        let mut closer = DaemonWindowCloser {
            tx,
            sessions: sessions.clone(),
            paths: paths.clone(),
        };

        assert_eq!(
            closer.close_window("win-pressure".into(), 3),
            Err(crate::remote_control::CloseWindowError::Internal)
        );
        assert!(layouts.load("win-pressure").unwrap().is_some());
        assert_eq!(sessions.lock().unwrap().snapshot(), ["s-a"]);
        assert_eq!(rx.try_recv().unwrap(), "already-queued");
        assert!(rx.try_recv().is_err(), "no partial kill batch may enqueue");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Retired with queue-after-delete compensation: close now commits a durable, retryable
    // generation-bound release journal instead of attempting to roll the graph back on I/O loss.
    #[cfg(any())]
    #[test]
    fn daemon_window_close_compensation_preserves_a_concurrent_recreation_and_owner() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-close-window-recreate-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let projects = maestro_shell::ProjectService::new(&paths);
        for (project_id, name) in [
            ("project-before", "Before project"),
            ("project-recreated", "Recreated project"),
        ] {
            projects
                .create(
                    project_id,
                    name,
                    ".",
                    maestro_shell::NewProject::default(),
                    1,
                )
                .unwrap();
        }
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts.create_empty("win-recreate", 1).unwrap();
        layouts
            .open_tab(
                "win-recreate",
                "old-pane",
                "old-session",
                "Old",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .unwrap();
        maestro_shell::store::set_window_project(&paths, "win-recreate", "project-before").unwrap();
        let prepared_from = layouts.load_snapshot("win-recreate").unwrap().unwrap();

        let mut recreation_before_compensation = None;
        assert_eq!(
            delete_window_and_run_commit(&paths, 3, &prepared_from, || {
                // Deterministic injected daemon-publication failure: another writer recreates the
                // id after the conditional delete committed and before compensation begins.
                layouts.create_empty("win-recreate", 4).unwrap();
                layouts
                    .rename_window("win-recreate", "new window", 5)
                    .unwrap();
                layouts
                    .open_tab(
                        "win-recreate",
                        "new-pane",
                        "new-session",
                        "New",
                        true,
                        maestro_shell::AttentionState::default(),
                        6,
                    )
                    .unwrap();
                maestro_shell::store::set_window_project(
                    &paths,
                    "win-recreate",
                    "project-recreated",
                )
                .unwrap();
                recreation_before_compensation =
                    Some(layouts.load_snapshot("win-recreate").unwrap().unwrap());
                Err(())
            }),
            Err(crate::remote_control::CloseWindowError::Internal)
        );

        let before = recreation_before_compensation.unwrap();
        let after = layouts.load_snapshot("win-recreate").unwrap().unwrap();
        assert_eq!(
            serde_json::to_vec(&after.layout).unwrap(),
            serde_json::to_vec(&before.layout).unwrap(),
            "create-only compensation must leave the concurrent layout byte-identical"
        );
        assert_eq!(after.project_id, before.project_id);
        assert_eq!(after.project_id.as_deref(), Some("project-recreated"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(any())]
    #[test]
    fn daemon_window_close_compensation_does_not_resurrect_after_recreate_delete_aba() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-close-window-compensation-aba-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts.create_empty("win-compensation-aba", 1).unwrap();
        layouts
            .open_tab(
                "win-compensation-aba",
                "old-pane",
                "old-session",
                "Old",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .unwrap();
        let prepared_from = layouts
            .load_snapshot("win-compensation-aba")
            .unwrap()
            .unwrap();

        assert_eq!(
            delete_window_and_run_commit(&paths, 3, &prepared_from, || {
                layouts.create_empty("win-compensation-aba", 4).unwrap();
                assert!(layouts.delete("win-compensation-aba").unwrap());
                Err(())
            }),
            Err(crate::remote_control::CloseWindowError::Internal)
        );
        assert!(
            layouts.load("win-compensation-aba").unwrap().is_none(),
            "the first incarnation's receipt is stale after recreate-delete ABA"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(any())]
    #[test]
    fn daemon_window_close_stale_commit_restores_the_deleted_layout() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-close-window-stale-commit-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        maestro_shell::ProjectService::new(&paths)
            .create(
                "project-stale",
                "Stale project",
                ".",
                maestro_shell::NewProject::default(),
                1,
            )
            .unwrap();
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts.create_empty("win-stale", 1).unwrap();
        layouts
            .open_tab(
                "win-stale",
                "pane-a",
                "session-a",
                "A",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .unwrap();
        maestro_shell::store::set_window_project(&paths, "win-stale", "project-stale").unwrap();
        let before = layouts.load_snapshot("win-stale").unwrap().unwrap();

        let (tx, rx) = daemon_request_channel(2, 1024);
        let prepared = tx.prepare(kill_session_line("session-a")).unwrap();
        // This is the precise prepare→durable-mutation→commit failure boundary: the queue ticket
        // exists, then its writer disappears before the local delete begins.
        drop(rx);
        assert_eq!(
            delete_window_and_commit_kills(&paths, 3, &before, Some(prepared),),
            Err(crate::remote_control::CloseWindowError::Internal)
        );
        let restored = layouts.load_snapshot("win-stale").unwrap().unwrap();
        assert_eq!(restored.layout, before.layout);
        assert_eq!(restored.project_id, before.project_id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_window_opener_persists_desktop_window_hierarchy_and_starts_session() {
        let dir =
            std::env::temp_dir().join(format!("hydra-new-window-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let experiment = dir.join("experiment");
        std::fs::create_dir_all(&experiment).unwrap();
        let experiment = experiment.to_string_lossy().into_owned();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let project = maestro_shell::Project {
            project_id: "proj-capacity".into(),
            name: "capacity total".into(),
            root: "/Users/test/Desktop/project-example".into(),
            default_workspace_policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            created_at_ms: 1,
            last_active_at_ms: 2,
            icon: Some("◉".into()),
            accent_color: Some("#34d399".into()),
            launch_defaults: None,
            directories: Vec::new(),
            window_order: vec!["win-main".into()],
            system: false,
            hidden: false,
        };
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Project,
            &project.project_id,
            1,
            &project,
        )
        .unwrap();
        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let daemon = install_conditional_start_test_daemon(&tx);
        let lease_dir = dir.join("creation-lease");
        install_creation_lease_publisher(&tx, &lease_dir);
        let sessions = Arc::new(Mutex::new(SessionCache::mutation_ready_for_test()));
        let mut opener = DaemonWindowOpener {
            tx,
            sessions: sessions.clone(),
            paths: paths.clone(),
        };

        let created = opener
            .new_window_with_initial_size(
                crate::remote_control::NewWindowRequest {
                    project_id: "proj-capacity".into(),
                    name: "Experiment".into(),
                    cwd: Some(experiment.clone()),
                    agent: Some("codex".into()),
                    launch_flags: None,
                    now_ms: 1234,
                },
                InitialTerminalSize::from_optional_pair(Some(137), Some(48)),
            )
            .unwrap();

        assert_eq!(created.window_id, "proj-capacity-window-1234");
        assert_creation_lease(&lease_dir, &created.session_id);
        assert!(sessions
            .lock()
            .unwrap()
            .snapshot()
            .contains(&created.session_id));
        assert_provider_start_executes_exact_source(
            &only_conditional_start(&daemon),
            &created.session_id,
            &experiment,
            &["codex".into()],
            InitialTerminalSize::from_optional_pair(Some(137), Some(48)),
        );

        let project = maestro_shell::ProjectService::new(&paths)
            .load("proj-capacity")
            .unwrap()
            .unwrap();
        assert_eq!(
            project.window_order,
            vec!["win-main".to_string(), created.window_id.clone()]
        );
        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load(&created.window_id)
            .unwrap()
            .unwrap();
        assert_eq!(layout.name.as_deref(), Some("Experiment"));
        assert_eq!(layout.tabs.len(), 1);
        assert_eq!(layout.tabs[0].tab_id, "pane-1");
        assert_eq!(layout.tabs[0].session_id, created.session_id);
        assert_eq!(layout.tabs[0].title, "Codex");
        // A remote-created window stamps windows.project_id (symmetric with the desktop) so cascade-delete reaches it.
        {
            let arc = maestro_shell::db::conn_for(paths.base()).unwrap();
            let conn = arc.lock().unwrap();
            let owner: Option<String> = conn
                .query_row(
                    "SELECT project_id FROM windows WHERE window_id = ?1",
                    [&created.window_id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                owner.as_deref(),
                Some("proj-capacity"),
                "remote window must own its project"
            );
        }
        let session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &created.session_id,
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(session) => session,
            _ => panic!("session should be loadable"),
        };
        assert_eq!(session.cwd_resolved, experiment);
        assert!(
            matches!(
                session.launch,
                maestro_shell::LaunchSpec::AdHocRedacted {
                    redacted: true,
                    restart_requires_user: true,
                    ..
                }
            ),
            "fresh Codex window must not manufacture a latest-session restart"
        );
        let workspace = match maestro_shell::load_one::<maestro_shell::Workspace>(
            &paths,
            maestro_shell::RecordKind::Workspace,
            &session.workspace_id,
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(workspace) => workspace,
            _ => panic!("workspace should be loadable"),
        };
        assert_eq!(workspace.project_id, "proj-capacity");
        assert_eq!(workspace.root, experiment);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_window_opener_inherits_saved_project_agent_when_request_agent_absent() {
        // Parity with desktop CreateWindow: a browser-created window with no explicit agent inherits the project's
        // saved launch-default agent (via the shared inherited_project_launch_inputs helper) rather than always
        // falling back to "claude" — so the browser is not a separate environment from the desktop. The saved
        // custom_command is deliberately NOT applied (remote sessions stay KnownSafe/allowlisted).
        let dir = std::env::temp_dir().join(format!(
            "hydra-new-window-inherit-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let project_root = dir.join("project-root");
        std::fs::create_dir_all(&project_root).unwrap();
        let project_root = project_root.to_string_lossy().into_owned();
        let project = maestro_shell::Project {
            project_id: "proj-inherit".into(),
            name: "inherit".into(),
            root: project_root.clone(),
            default_workspace_policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            created_at_ms: 1,
            last_active_at_ms: 2,
            icon: None,
            accent_color: None,
            launch_defaults: Some(maestro_shell::ProjectLaunchDefaults {
                agent: Some("codex".into()),
                model: Some("opus".into()),
                resume_mode: Some("new".into()),
                dangerous_skip_permissions: Some(false),
                custom_command: Some("codex --sneaky".into()),
            }),
            directories: Vec::new(),
            window_order: Vec::new(),
            system: false,
            hidden: false,
        };
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Project,
            &project.project_id,
            1,
            &project,
        )
        .unwrap();
        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let daemon = install_conditional_start_test_daemon(&tx);
        let sessions = Arc::new(Mutex::new(SessionCache::mutation_ready_for_test()));
        let mut opener = DaemonWindowOpener {
            tx,
            sessions,
            paths: paths.clone(),
        };

        let created = opener
            .new_window(crate::remote_control::NewWindowRequest {
                project_id: "proj-inherit".into(),
                name: "Inherited".into(),
                cwd: None,
                agent: None, // absent → inherit the saved project default (codex)
                launch_flags: None,
                now_ms: 5000,
            })
            .unwrap();

        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load(&created.window_id)
            .unwrap()
            .unwrap();
        // Tab titled from the inherited agent, not the "claude" fallback.
        assert_eq!(layout.tabs[0].title, "Codex");
        let session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &created.session_id,
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(session) => session,
            _ => panic!("session should be loadable"),
        };
        // Launch is the inherited agent as a KnownSafe allowlisted spec — the saved custom_command is NOT applied.
        assert!(
            matches!(
                session.launch,
                maestro_shell::LaunchSpec::AdHocRedacted {
                    redacted: true,
                    restart_requires_user: true,
                    ..
                }
            ),
            "inherited fresh Codex must remain non-replayable without an exact identity"
        );
        assert_provider_start_executes_exact_source(
            &only_conditional_start(&daemon),
            &created.session_id,
            &project_root,
            &["codex".into()],
            InitialTerminalSize::default(),
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_window_opener_terminal_agent_is_exact_nonreplayable_shell() {
        // A remote new-window that inherits a Terminal project is a plain-bash window: SessionKind::Shell +
        // LaunchSpec::OptOut + "Terminal" tab, NOT an Agent record. A stale saved custom command must remain
        // ignored at the remote KnownSafe boundary.
        let dir = std::env::temp_dir().join(format!(
            "hydra-new-window-terminal-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let project_root = dir.join("project-root");
        std::fs::create_dir_all(&project_root).unwrap();
        let project_root = project_root.to_string_lossy().into_owned();
        for (project_id, saved_agent) in [
            ("proj-inherited-terminal", "terminal"),
            ("proj-explicit-terminal", "claude"),
        ] {
            let project = maestro_shell::Project {
                project_id: project_id.into(),
                name: "T".into(),
                root: project_root.clone(),
                default_workspace_policy: maestro_shell::WorkspacePolicy::ScratchCwd,
                created_at_ms: 1,
                last_active_at_ms: 2,
                icon: None,
                accent_color: None,
                launch_defaults: Some(maestro_shell::ProjectLaunchDefaults {
                    agent: Some(saved_agent.into()),
                    model: Some("stale-model".into()),
                    resume_mode: Some("resume".into()),
                    dangerous_skip_permissions: Some(true),
                    custom_command: Some("must-not-run --sentinel".into()),
                }),
                directories: Vec::new(),
                window_order: Vec::new(),
                system: false,
                hidden: false,
            };
            maestro_shell::write_record(
                &paths,
                maestro_shell::RecordKind::Project,
                &project.project_id,
                1,
                &project,
            )
            .unwrap();
        }
        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let daemon = install_conditional_start_test_daemon(&tx);
        let mut opener = DaemonWindowOpener {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            paths: paths.clone(),
        };

        for (index, (project_id, request_agent)) in [
            ("proj-inherited-terminal", None),
            ("proj-explicit-terminal", Some("terminal")),
        ]
        .into_iter()
        .enumerate()
        {
            let created = opener
                .new_window(crate::remote_control::NewWindowRequest {
                    project_id: project_id.into(),
                    name: "Term".into(),
                    cwd: None,
                    agent: request_agent.map(str::to_string),
                    launch_flags: None,
                    now_ms: 5000 + index as u64,
                })
                .unwrap();

            let layout = maestro_shell::WindowLayoutService::new(&paths)
                .load(&created.window_id)
                .unwrap()
                .unwrap();
            assert_eq!(layout.tabs[0].title, "Terminal");
            let session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
                &paths,
                maestro_shell::RecordKind::Session,
                &created.session_id,
            )
            .unwrap()
            .unwrap()
            {
                maestro_shell::LoadOutcome::Loaded(s) => s,
                _ => panic!("session loadable"),
            };
            assert_eq!(
                session.kind,
                maestro_shell::SessionKind::Shell,
                "terminal → Shell"
            );
            assert!(
                matches!(
                    session.launch,
                    maestro_shell::LaunchSpec::AdHocRedacted {
                        restart_requires_user: true,
                        ..
                    }
                ),
                "terminal → exact non-replayable AdHoc, got {:?}",
                session.launch
            );
            let starts = daemon.start_requests();
            assert_eq!(starts.len(), index + 1);
            let terminal = crate::session_creator::empty_session_launch(false);
            assert_eq!(starts[index]["id"], created.session_id);
            assert_eq!(starts[index]["cwd"], project_root);
            assert_eq!(starts[index]["command"], terminal.command);
            assert_eq!(
                starts[index]["args"],
                serde_json::to_value(terminal.args).unwrap()
            );
            assert!(starts[index]["conditional_start"].is_object());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_window_opener_honors_launch_flags_resume_and_model() {
        // Tier-1: new_window must honor the dialog's launch_flags like split_pane does — previously they
        // were ignored and the first pane always started fresh with no flags. Covers both shapes:
        //  1) resume + model → `codex resume <id> --model <name>` (record params == launched args)
        //  2) model only (fresh) → `claude --model <name>`
        let dir = std::env::temp_dir().join(format!(
            "hydra-new-window-flags-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let project_root = dir.join("project-root");
        std::fs::create_dir_all(&project_root).unwrap();
        let project_root = project_root.to_string_lossy().into_owned();
        let project = maestro_shell::Project {
            project_id: "proj-flags".into(),
            name: "flags".into(),
            root: project_root.clone(),
            default_workspace_policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            created_at_ms: 1,
            last_active_at_ms: 2,
            icon: None,
            accent_color: None,
            launch_defaults: None,
            directories: Vec::new(),
            window_order: Vec::new(),
            system: false,
            hidden: false,
        };
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Project,
            &project.project_id,
            1,
            &project,
        )
        .unwrap();
        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let daemon = install_conditional_start_test_daemon(&tx);
        let mut opener = DaemonWindowOpener {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            paths: paths.clone(),
        };

        // 1) resume + model
        let created = opener
            .new_window(crate::remote_control::NewWindowRequest {
                project_id: "proj-flags".into(),
                name: "Resumed".into(),
                cwd: None,
                agent: Some("codex".into()),
                launch_flags: Some(serde_json::json!({
                    "resumeMode": "resume",
                    "resumeSessionId": "50000000-0000-4000-8000-000000000011",
                    "model": "gpt-5.2-codex",
                })),
                now_ms: 1000,
            })
            .unwrap();
        let session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &created.session_id,
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(s) => s,
            _ => panic!("session should load"),
        };
        let expected_args = vec![
            "resume".to_string(),
            "50000000-0000-4000-8000-000000000011".to_string(),
            "--model".to_string(),
            "gpt-5.2-codex".to_string(),
        ];
        assert_eq!(
            session.launch,
            maestro_shell::LaunchSpec::KnownSafe {
                launch_spec_id: "codex".into(),
                params: expected_args.clone(),
            }
        );
        let mut source_argv = vec!["codex".to_string()];
        source_argv.extend(expected_args);
        assert_provider_start_executes_exact_source(
            &only_conditional_start(&daemon),
            &created.session_id,
            &project_root,
            &source_argv,
            InitialTerminalSize::default(),
        );

        // 2) model only → fresh `<agent> --model <name>`
        let created = opener
            .new_window(crate::remote_control::NewWindowRequest {
                project_id: "proj-flags".into(),
                name: "Modeled".into(),
                cwd: None,
                agent: Some("claude".into()),
                launch_flags: Some(serde_json::json!({ "model": "claude-opus-4-8" })),
                now_ms: 2000,
            })
            .unwrap();
        let session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &created.session_id,
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(s) => s,
            _ => panic!("session should load"),
        };
        let maestro_shell::LaunchSpec::KnownSafe {
            launch_spec_id,
            params,
        } = &session.launch
        else {
            panic!("modeled fresh Claude window must publish an exact recipe")
        };
        assert_eq!(launch_spec_id, "claude");
        assert_eq!(params.len(), 4);
        assert_eq!(params[0], "--resume");
        let provider_id = &params[1];
        assert_eq!(
            uuid::Uuid::parse_str(provider_id)
                .unwrap()
                .hyphenated()
                .to_string(),
            *provider_id
        );
        assert_eq!(&params[2..], &["--model", "claude-opus-4-8"]);
        let starts = daemon.start_requests();
        assert_eq!(starts.len(), 2);
        assert_provider_start_executes_exact_source(
            &starts[1],
            &created.session_id,
            &project_root,
            &[
                "claude".into(),
                "--session-id".into(),
                provider_id.clone(),
                "--model".into(),
                "claude-opus-4-8".into(),
            ],
            InitialTerminalSize::default(),
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_window_opener_rolls_back_layout_when_reviewed_daemon_is_unavailable() {
        // With no reviewed daemon authority, the prepared graph reaches its exact compensation
        // path and must disappear without publishing a session as Live.
        let dir = std::env::temp_dir().join(format!(
            "hydra-new-window-rollback-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all("/tmp/hydra-test-work").unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let project = maestro_shell::ProjectService::new(&paths)
            .create(
                "proj-rb",
                "rollback",
                "/tmp/hydra-test-work",
                maestro_shell::NewProject::default(),
                1,
            )
            .unwrap();
        let epoch_before = test_window_epoch(&paths);
        let (tx, mut rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let sessions = Arc::new(Mutex::new(SessionCache::mutation_ready_for_test()));
        let mut opener = DaemonWindowOpener {
            tx,
            sessions: Arc::clone(&sessions),
            paths: paths.clone(),
        };
        let err = opener
            .new_window(crate::remote_control::NewWindowRequest {
                project_id: "proj-rb".into(),
                name: "Doomed".into(),
                cwd: None,
                agent: Some("claude".into()),
                launch_flags: None,
                now_ms: 7000,
            })
            .unwrap_err();
        assert_eq!(
            err,
            crate::remote_control::NewWindowError::DaemonUnavailable,
            "the original publication error must surface"
        );

        let window_id = "proj-rb-window-7000";
        assert!(maestro_shell::WindowLayoutService::new(&paths)
            .load(window_id)
            .unwrap()
            .is_none());
        assert!(maestro_shell::store::load_all::<maestro_shell::Workspace>(
            &paths,
            maestro_shell::RecordKind::Workspace
        )
        .unwrap()
        .is_empty());
        assert!(
            maestro_shell::store::load_all::<maestro_shell::SessionRecord>(
                &paths,
                maestro_shell::RecordKind::Session
            )
            .unwrap()
            .is_empty()
        );
        assert_eq!(
            maestro_shell::ProjectService::new(&paths)
                .load("proj-rb")
                .unwrap(),
            Some(project),
            "receipt compensation restores the exact pre-create Project bytes"
        );
        let epoch_after = test_window_epoch(&paths);
        assert_eq!(epoch_after, epoch_before + 2);
        assert!(sessions.lock().unwrap().snapshot().is_empty());
        assert!(rx.try_recv().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_project_editor_receipt_cleans_graph_when_prepared_start_commit_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = maestro_shell::AppPaths::with_base(tmp.path().join("Maestro"));
        maestro_shell::ProjectService::new(&paths).list().unwrap();
        let (tx, mut rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let sessions = Arc::new(Mutex::new(SessionCache::mutation_ready_for_test()));
        let mut editor = DaemonProjectEditor {
            tx,
            sessions: Arc::clone(&sessions),
            paths: paths.clone(),
        };
        fail_next_prepared_daemon_commit();
        assert_eq!(
            editor.create_project(crate::remote_control::ProjectEditRequest {
                project_id: None,
                name: Some("Commit failure".into()),
                root: Some("/tmp/commit-failure".into()),
                icon: None,
                accent_color: None,
                agent: Some("terminal".into()),
                resume_mode: None,
                resume_session_id: None,
                model: None,
                dangerous: None,
                custom_command: None,
                directories: None,
                now_ms: 7_100,
            }),
            Err(crate::remote_control::ProjectEditError::Internal)
        );
        assert!(maestro_shell::ProjectService::new(&paths)
            .list()
            .unwrap()
            .is_empty());
        assert!(
            maestro_shell::store::load_all::<maestro_shell::WindowLayout>(
                &paths,
                maestro_shell::RecordKind::WindowLayout,
            )
            .unwrap()
            .is_empty()
        );
        assert!(maestro_shell::store::load_all::<maestro_shell::Workspace>(
            &paths,
            maestro_shell::RecordKind::Workspace,
        )
        .unwrap()
        .is_empty());
        assert!(
            maestro_shell::store::load_all::<maestro_shell::SessionRecord>(
                &paths,
                maestro_shell::RecordKind::Session,
            )
            .unwrap()
            .is_empty()
        );
        assert!(sessions.lock().unwrap().snapshot().is_empty());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn daemon_window_opener_dedupes_window_title_within_project() {
        // Item D: desktop unique_window_name parity — a requested title that collides with a sibling
        // window's name in the SAME project gets the smallest free " N" suffix: "Focus" → "Focus 2",
        // and a second collision → "Focus 3".
        let dir = std::env::temp_dir().join(format!(
            "hydra-new-window-dedupe-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let project_root = dir.join("project-root");
        std::fs::create_dir_all(&project_root).unwrap();
        let project_root = project_root.to_string_lossy().into_owned();
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts.create_empty("win-a", 1).unwrap();
        layouts.rename_window("win-a", "Focus", 1).unwrap();
        let project = maestro_shell::Project {
            project_id: "proj-dupe".into(),
            name: "dupe".into(),
            root: project_root,
            default_workspace_policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            created_at_ms: 1,
            last_active_at_ms: 2,
            icon: None,
            accent_color: None,
            launch_defaults: None,
            directories: Vec::new(),
            window_order: vec!["win-a".into()],
            system: false,
            hidden: false,
        };
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Project,
            &project.project_id,
            1,
            &project,
        )
        .unwrap();
        // The Window FK is authoritative; window_order is only the presentation order.
        maestro_shell::store::set_window_project(&paths, "win-a", &project.project_id).unwrap();
        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let _daemon = install_conditional_start_test_daemon(&tx);
        let mut opener = DaemonWindowOpener {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
            paths: paths.clone(),
        };
        let request = |now_ms: u64| crate::remote_control::NewWindowRequest {
            project_id: "proj-dupe".into(),
            name: "Focus".into(),
            cwd: None,
            agent: Some("claude".into()),
            launch_flags: None,
            now_ms,
        };

        let first = opener.new_window(request(100)).unwrap();
        assert_eq!(
            layouts
                .load(&first.window_id)
                .unwrap()
                .unwrap()
                .name
                .as_deref(),
            Some("Focus 2"),
            "first collision gets the ' 2' suffix"
        );

        let second = opener.new_window(request(200)).unwrap();
        assert_eq!(
            layouts
                .load(&second.window_id)
                .unwrap()
                .unwrap()
                .name
                .as_deref(),
            Some("Focus 3"),
            "second collision gets the ' 3' suffix"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn output(session_id: &str, line: &str) -> DaemonOutput {
        DaemonOutput {
            session_id: session_id.into(),
            line: line.into(),
        }
    }

    fn poison_request_queue_state(tx: &DaemonRequestSender) {
        let state = tx.state.clone();
        let panic = std::thread::spawn(move || {
            let _state = state.lock().expect("request queue state starts healthy");
            panic!("intentional request queue state poison");
        })
        .join();
        assert!(panic.is_err(), "poisoning thread must panic");
        assert!(tx.state.is_poisoned());
    }

    #[tokio::test]
    async fn request_queue_holds_exact_bytes_until_the_writer_drops_the_line() {
        let line = "request".to_string();
        let cap = line.len() + 1;
        let (tx, mut rx) = daemon_request_channel(2, cap);
        tx.send(line.clone()).unwrap();
        assert_eq!(tx.available_bytes(), 0);

        let queued = rx.recv().await.unwrap();
        assert_eq!(&*queued, line);
        assert_eq!(
            tx.available_bytes(),
            0,
            "the socket writer must retain the permit while it owns the line"
        );
        drop(queued);
        assert_eq!(tx.available_bytes(), cap);
    }

    #[tokio::test]
    async fn request_queue_byte_overflow_stops_every_sender_clone() {
        let first = "first".to_string();
        let cap = first.len() + 1;
        let (tx, mut rx) = daemon_request_channel(4, cap);
        let mut failure = rx.failure_receiver();
        let clone_a = tx.clone();
        let clone_b = tx.clone();
        tx.send(first.clone()).unwrap();
        assert_eq!(
            clone_a.send("x".into()),
            Err(DaemonRequestEnqueueError::ByteLimit)
        );
        assert_eq!(
            clone_b.send("later".into()),
            Err(DaemonRequestEnqueueError::ProducerStopped)
        );

        let queued = rx.recv().await.unwrap();
        assert_eq!(&*queued, first);
        drop(queued);
        assert_eq!(tx.available_bytes(), cap);
        assert!(
            rx.recv().await.is_none(),
            "overflow must close after the already-valid ordered prefix"
        );
        tokio::time::timeout(Duration::from_secs(1), failure.changed())
            .await
            .expect("overflow must wake the connection owner")
            .unwrap();
        assert!(*failure.borrow());
    }

    #[tokio::test]
    async fn request_queue_item_overflow_stops_every_sender_clone() {
        let (tx, mut rx) = daemon_request_channel(1, 1024);
        let clone = tx.clone();
        tx.send("first".into()).unwrap();
        assert_eq!(
            clone.send("second".into()),
            Err(DaemonRequestEnqueueError::ItemLimit)
        );
        assert_eq!(
            tx.send("third".into()),
            Err(DaemonRequestEnqueueError::ProducerStopped)
        );
        assert_eq!(&*rx.recv().await.unwrap(), "first");
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn poisoned_request_state_before_prepare_stops_clones_and_wakes_owner() {
        let (tx, mut rx) = daemon_request_channel(4, 1024);
        let clone = tx.clone();
        let mut failure = rx.failure_receiver();
        poison_request_queue_state(&tx);

        assert_eq!(
            tx.send("first".into()),
            Err(DaemonRequestEnqueueError::ProducerStopped)
        );
        assert_eq!(
            clone.send("later".into()),
            Err(DaemonRequestEnqueueError::ProducerStopped)
        );
        tokio::time::timeout(Duration::from_secs(1), failure.changed())
            .await
            .expect("poison recovery must wake the connection owner")
            .unwrap();
        assert!(*failure.borrow());
        assert!(
            rx.recv().await.is_none(),
            "poison recovery must close the shared producer"
        );
    }

    #[tokio::test]
    async fn poisoned_request_state_during_commit_fails_without_recursive_relock() {
        let (tx, mut rx) = daemon_request_channel(4, 1024);
        let clone = tx.clone();
        let mut failure = rx.failure_receiver();
        let prepared = tx.prepare("prepared".into()).unwrap();
        assert!(tx.available_bytes() < 1024);
        poison_request_queue_state(&tx);

        assert_eq!(
            prepared.commit(),
            Err(DaemonRequestEnqueueError::ProducerStopped)
        );
        assert_eq!(tx.available_bytes(), 1024);
        assert_eq!(
            clone.send("later".into()),
            Err(DaemonRequestEnqueueError::ProducerStopped)
        );
        tokio::time::timeout(Duration::from_secs(1), failure.changed())
            .await
            .expect("poisoned commit must wake the connection owner")
            .unwrap();
        assert!(*failure.borrow());
        assert!(
            rx.recv().await.is_none(),
            "poisoned commit must cancel its ticket and close the producer"
        );
    }

    #[test]
    fn request_queue_receiver_close_releases_budget_and_stops_producers() {
        let (tx, rx) = daemon_request_channel(2, 1024);
        drop(rx);
        assert_eq!(
            tx.send("request".into()),
            Err(DaemonRequestEnqueueError::ProducerStopped)
        );
        assert_eq!(tx.available_bytes(), 1024);
        assert_eq!(
            tx.send("later".into()),
            Err(DaemonRequestEnqueueError::ProducerStopped)
        );
    }

    #[tokio::test]
    async fn prepared_request_batch_is_atomic_ordered_and_releases_when_abandoned() {
        let (tx, mut rx) = daemon_request_channel(3, 1024);
        let abandoned = tx
            .prepare_batch(vec!["abandoned-a".into(), "abandoned-b".into()])
            .unwrap()
            .unwrap();
        assert_eq!(tx.available_bytes(), 1024 - 24);
        drop(abandoned);
        assert_eq!(tx.available_bytes(), 1024);
        assert!(rx.try_recv().is_err());

        tx.prepare_batch(vec!["first".into(), "second".into()])
            .unwrap()
            .unwrap()
            .commit()
            .unwrap();
        assert_eq!(rx.try_recv().unwrap(), "first");
        assert_eq!(rx.try_recv().unwrap(), "second");
        assert_eq!(tx.available_bytes(), 1024);
    }

    #[tokio::test]
    async fn prepared_batch_keeps_its_queue_position_against_a_later_clone() {
        let (tx, mut rx) = daemon_request_channel(4, 1024);
        let earlier = tx
            .prepare_batch(vec!["earlier-a".into(), "earlier-b".into()])
            .unwrap()
            .unwrap();

        // The later clone can commit while the durable operation owning `earlier` is still in
        // progress, but its already-published ticket remains behind the earlier batch ticket.
        tx.clone().send("later".into()).unwrap();
        earlier.commit().unwrap();

        assert_eq!(rx.try_recv().unwrap(), "earlier-a");
        assert_eq!(rx.try_recv().unwrap(), "earlier-b");
        assert_eq!(rx.try_recv().unwrap(), "later");
    }

    #[test]
    fn receiver_failure_between_prepare_and_commit_is_reported_and_stops_clones() {
        let (tx, rx) = daemon_request_channel(4, 1024);
        let clone = tx.clone();
        let prepared = tx.prepare("prepared".into()).unwrap();
        assert!(tx.available_bytes() < 1024);

        drop(rx);
        assert_eq!(
            prepared.commit(),
            Err(DaemonRequestEnqueueError::ProducerStopped)
        );
        assert_eq!(
            clone.send("later".into()),
            Err(DaemonRequestEnqueueError::ProducerStopped)
        );
        assert_eq!(tx.available_bytes(), 1024);
    }

    #[test]
    fn signalled_writer_failure_stales_a_live_prepared_ticket_immediately() {
        let (tx, rx) = daemon_request_channel(4, 1024);
        let clone = tx.clone();
        let prepared = tx.prepare("prepared".into()).unwrap();

        // `fail` is the exact writer/reader task exit path. The receiver and its oneshot are still
        // alive here, so commit must consult shared lifecycle state rather than merely trusting a
        // successful oneshot send.
        rx.fail();
        assert_eq!(
            prepared.commit(),
            Err(DaemonRequestEnqueueError::ProducerStopped)
        );
        assert_eq!(
            clone.send("later".into()),
            Err(DaemonRequestEnqueueError::ProducerStopped)
        );
        assert_eq!(tx.available_bytes(), 1024);
    }

    #[test]
    fn individually_oversized_request_stops_the_whole_producer() {
        let (tx, mut rx) = daemon_request_channel(2, 32);
        assert_eq!(
            tx.send("x".repeat(32)),
            Err(DaemonRequestEnqueueError::ByteLimit)
        );
        assert_eq!(
            tx.send("small".into()),
            Err(DaemonRequestEnqueueError::ProducerStopped)
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(tx.available_bytes(), 32);
    }

    #[test]
    fn oversized_multi_line_batch_cannot_bypass_the_item_envelope_bound() {
        let (tx, mut rx) = daemon_request_channel(2, 1024);
        assert_eq!(
            tx.prepare_batch(vec!["a".into(), "b".into(), "c".into()])
                .err(),
            Some(DaemonRequestEnqueueError::ItemLimit)
        );
        assert_eq!(
            tx.send("later".into()),
            Err(DaemonRequestEnqueueError::ProducerStopped)
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(tx.available_bytes(), 1024);
    }

    #[tokio::test]
    async fn request_queue_accepts_the_complete_worst_case_input_burst() {
        const BURST_FRAMES: usize =
            crate::input_rate::DEFAULT_CAPACITY as usize / crate::remote_frame::MAX_INPUT_PAYLOAD;
        let (tx, mut rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let payload = vec![0_u8; crate::remote_frame::MAX_INPUT_PAYLOAD];

        for sequence in 0..BURST_FRAMES {
            let line = serde_json::json!({
                "op": "write",
                "id": format!("burst-{sequence}"),
                "expected_generation": format!("pty-burst-{sequence}"),
                "data": String::from_utf8_lossy(&payload),
            })
            .to_string();
            tx.send(line).unwrap_or_else(|error| {
                panic!("accepted 1 MiB input burst failed at frame {sequence}: {error:?}")
            });
        }
        assert!(tx.available_bytes() < DAEMON_REQUEST_QUEUE_BYTE_CAP);

        for sequence in 0..BURST_FRAMES {
            let queued = rx.recv().await.expect("queued burst request");
            let value: serde_json::Value = serde_json::from_str(&queued).unwrap();
            assert_eq!(value["op"], "write");
            assert_eq!(value["id"], format!("burst-{sequence}"));
            assert_eq!(
                value["data"].as_str().unwrap().len(),
                crate::remote_frame::MAX_INPUT_PAYLOAD
            );
        }
        assert_eq!(tx.available_bytes(), DAEMON_REQUEST_QUEUE_BYTE_CAP);
    }

    #[tokio::test]
    async fn output_queue_preserves_normal_delivery_order() {
        let (mut tx, mut rx) = daemon_output_channel(4, 128);
        tx.try_enqueue(output("s1", "first")).unwrap();
        tx.try_enqueue(output("s2", "second")).unwrap();

        let first = rx.recv().await.unwrap();
        let second = rx.recv().await.unwrap();
        assert_eq!(
            (first.session_id.as_str(), first.line.as_str()),
            ("s1", "first")
        );
        assert_eq!(
            (second.session_id.as_str(), second.line.as_str()),
            ("s2", "second")
        );
    }

    #[tokio::test]
    async fn routed_output_retains_the_one_aggregate_queue_reservation() {
        let (mut tx, mut rx) = daemon_output_channel(1, 20);
        tx.try_enqueue(output("s", "12345")).unwrap(); // 6 bytes
        let routed = rx.recv_routed().await.expect("routed output");
        assert_eq!(tx.available_items(), 0);
        assert_eq!(tx.available_bytes(), 14);
        assert_eq!(
            tx.try_enqueue(output("s", "later")),
            Err(DaemonOutputEnqueueError::ItemLimit),
            "moving an item into peer arbitration must not free a second ingress slot"
        );
        drop(routed);
        assert_eq!(tx.available_items(), 1);
        assert_eq!(tx.available_bytes(), 20);
    }

    #[tokio::test]
    async fn echoed_attach_grid_is_the_exact_generation_boundary() {
        let (mut backend, mut request_rx) = backend_with_rx();
        let routes = Arc::new(Mutex::new(DaemonOutputRoutes::new(true)));
        backend.output_routes = routes.clone();
        let (mut tx, mut rx) = daemon_output_channel_with_routes(4, 512, None, routes);

        backend
            .attach_with_output_generation("s", 80, 24, false, 1, None)
            .unwrap();
        let first_attach = next_json(&mut request_rx);
        assert_eq!(first_attach["op"], "attach");
        assert_eq!(first_attach["output_generation"], 1);
        let first_baseline = output("s", "first-baseline");
        let route = tx.observe_route("s", DaemonEventClass::Grid, Some(1), None);
        tx.try_enqueue_routed(first_baseline, route).unwrap();

        backend.detach("s");
        assert_eq!(next_json(&mut request_rx)["op"], "detach");
        backend
            .attach_with_output_generation("s", 80, 24, false, 2, None)
            .unwrap();
        let second_attach = next_json(&mut request_rx);
        assert_eq!(second_attach["op"], "attach");
        assert_eq!(second_attach["output_generation"], 2);

        // This generation-1 response is deliberately observed only after generation 2 has been admitted
        // locally. Until the daemon's echoed baseline arrives, it cannot be relabelled generation 2.
        let old = output("s", "delayed-old-response");
        let route = tx.observe_route("s", DaemonEventClass::Other, None, None);
        tx.try_enqueue_routed(old, route).unwrap();

        let second_baseline = output("s", "second-baseline");
        let route = tx.observe_route("s", DaemonEventClass::Grid, Some(2), None);
        tx.try_enqueue_routed(second_baseline, route).unwrap();
        let new = output("s", "new-response");
        let route = tx.observe_route("s", DaemonEventClass::Other, None, None);
        tx.try_enqueue_routed(new, route).unwrap();

        assert_eq!(
            rx.recv_routed().await.unwrap().attachment,
            DaemonOutputAttachment::Exact(1)
        );
        let delayed = rx.recv_routed().await.unwrap();
        assert_eq!(delayed.output.line, "delayed-old-response");
        assert_eq!(delayed.attachment, DaemonOutputAttachment::Unconfirmed);
        assert_eq!(
            rx.recv_routed().await.unwrap().attachment,
            DaemonOutputAttachment::Exact(2)
        );
        assert_eq!(
            rx.recv_routed().await.unwrap().attachment,
            DaemonOutputAttachment::Exact(2)
        );
    }

    #[test]
    fn grid_route_transition_and_pty_generation_publish_atomically_before_input() {
        let (mut backend, mut request_rx) = backend_with_rx();
        let routes = Arc::new(Mutex::new(DaemonOutputRoutes::new(true)));
        backend.output_routes = routes.clone();
        backend.sessions.lock().unwrap().apply_daemon_listing(
            vec!["s".into()],
            std::collections::BTreeMap::from([("s".into(), "pty-a".into())]),
        );
        let (_owner, authority) = deferred_resize_authority("connection", "s", 80, 24);
        backend
            .attach_with_output_generation("s", 80, 24, false, 1, Some(authority))
            .unwrap();
        assert_eq!(next_json(&mut request_rx)["op"], "attach");

        let (transitioned_tx, transitioned_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let routes_for_grid = routes.clone();
        let sessions_for_grid = backend.sessions.clone();
        let pending_for_grid = backend.pending_attach_sizes.clone();
        let request_tx_for_grid = backend.tx.clone();
        let grid = std::thread::spawn(move || {
            observe_route_and_apply_grid(
                routes_for_grid.as_ref(),
                &sessions_for_grid,
                pending_for_grid.as_ref(),
                &request_tx_for_grid,
                "s",
                DaemonEventClass::Grid,
                Some(1),
                None,
                Some("pty-a".into()),
                || {
                    transitioned_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                },
            )
        });
        transitioned_rx.recv().unwrap();

        let mut input_backend = clone_backend_for_test(&backend);
        let (input_done_tx, input_done_rx) = std::sync::mpsc::channel();
        let input = std::thread::spawn(move || {
            let result = input_backend.input("s", b"x");
            input_done_tx.send(result).unwrap();
        });
        assert!(
            input_done_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "input crossed a Confirmed route before its PTY generation was published"
        );

        release_tx.send(()).unwrap();
        assert_eq!(grid.join().unwrap(), DaemonOutputAttachment::Exact(1));
        assert_eq!(input_done_rx.recv().unwrap(), Ok(()));
        input.join().unwrap();

        let first_resize = next_json(&mut request_rx);
        assert_eq!(first_resize["op"], "resize");
        assert_eq!(first_resize["expected_generation"], "pty-a");
        let input = next_json(&mut request_rx);
        assert_eq!(input["op"], "write");
        assert_eq!(input["expected_generation"], "pty-a");
    }

    #[test]
    fn local_reclaim_between_attach_and_grid_emits_no_deferred_resize() {
        let (mut backend, mut request_rx) = backend_with_rx();
        let routes = Arc::new(Mutex::new(DaemonOutputRoutes::new(true)));
        backend.output_routes = routes.clone();
        backend.sessions.lock().unwrap().apply_daemon_listing(
            vec!["s".into()],
            std::collections::BTreeMap::from([("s".into(), "pty-a".into())]),
        );
        let (owner, authority) = deferred_resize_authority("connection-a", "s", 132, 43);
        backend
            .attach_with_output_generation("s", 132, 43, false, 1, Some(authority))
            .unwrap();
        assert_eq!(next_json(&mut request_rx)["op"], "attach");
        assert!(owner.lock().unwrap().reclaim_viewport("s"));

        assert_eq!(
            observe_route_and_apply_grid(
                routes.as_ref(),
                &backend.sessions,
                backend.pending_attach_sizes.as_ref(),
                &backend.tx,
                "s",
                DaemonEventClass::Grid,
                Some(1),
                None,
                Some("pty-a".into()),
                || {},
            ),
            DaemonOutputAttachment::Exact(1)
        );
        assert!(
            request_rx.try_recv().is_err(),
            "a local reclaim newer than Attach must leave its exact Grid mutation-free"
        );
    }

    #[test]
    fn viewer_handoff_between_attach_and_grid_emits_no_deferred_resize() {
        let (mut backend, mut request_rx) = backend_with_rx();
        let routes = Arc::new(Mutex::new(DaemonOutputRoutes::new(true)));
        backend.output_routes = routes.clone();
        backend.sessions.lock().unwrap().apply_daemon_listing(
            vec!["s".into()],
            std::collections::BTreeMap::from([("s".into(), "pty-a".into())]),
        );
        let (owner, authority) = deferred_resize_authority("connection-a", "s", 132, 43);
        backend
            .attach_with_output_generation("s", 132, 43, false, 1, Some(authority))
            .unwrap();
        assert_eq!(next_json(&mut request_rx)["op"], "attach");
        assert!(
            owner
                .lock()
                .unwrap()
                .note_remote_viewing("connection-b", "other"),
            "the second viewer establishes a newer authority claim"
        );

        assert_eq!(
            observe_route_and_apply_grid(
                routes.as_ref(),
                &backend.sessions,
                backend.pending_attach_sizes.as_ref(),
                &backend.tx,
                "s",
                DaemonEventClass::Grid,
                Some(1),
                None,
                Some("pty-a".into()),
                || {},
            ),
            DaemonOutputAttachment::Exact(1)
        );
        assert!(
            request_rx.try_recv().is_err(),
            "a newer viewer/pane handoff must invalidate the delayed Attach resize"
        );
    }

    #[test]
    fn attach_without_winsize_admission_keeps_exact_grid_mutation_free() {
        let (mut backend, mut request_rx) = backend_with_rx();
        let routes = Arc::new(Mutex::new(DaemonOutputRoutes::new(true)));
        backend.output_routes = routes.clone();
        backend.sessions.lock().unwrap().apply_daemon_listing(
            vec!["background".into()],
            std::collections::BTreeMap::from([("background".into(), "pty-background".into())]),
        );

        backend
            .attach_with_output_generation("background", 132, 43, false, 1, None)
            .unwrap();
        let attach = next_json(&mut request_rx);
        assert_eq!(attach["op"], "attach");
        assert_eq!(attach["output_generation"], 1);
        assert_eq!(
            observe_route_and_apply_grid(
                routes.as_ref(),
                &backend.sessions,
                backend.pending_attach_sizes.as_ref(),
                &backend.tx,
                "background",
                DaemonEventClass::Grid,
                Some(1),
                None,
                Some("pty-background".into()),
                || {},
            ),
            DaemonOutputAttachment::Exact(1)
        );
        assert!(
            request_rx.try_recv().is_err(),
            "an exact Grid must not manufacture Resize authority for an attach denied winsize admission"
        );
        backend.resize("background", 132, 43).unwrap();
        let resize = next_json(&mut request_rx);
        assert_eq!(resize["op"], "resize");
        assert_eq!(resize["expected_generation"], "pty-background");
        assert_eq!(resize["cols"], 132);
        assert_eq!(resize["rows"], 43);
    }

    #[test]
    fn exact_attach_grid_admits_a_desktop_session_created_after_the_startup_listing() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-late-desktop-session-grid-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));

        let (mut backend, mut request_rx) = backend_with_rx();
        backend.dashboard_paths = Some(paths);
        let routes = Arc::new(Mutex::new(DaemonOutputRoutes::new(true)));
        backend.output_routes = routes.clone();

        // This models the operational connection's one startup Sessions inventory: S did not
        // exist yet, so neither the daemon cache nor the merged dashboard view names it.
        assert!(!backend.list_sessions().iter().any(|id| id == "s-a"));
        assert!(!backend
            .sessions
            .lock()
            .unwrap()
            .snapshot()
            .iter()
            .any(|id| id == "s-a"));

        // The desktop creates the durable/live topology later. The normal list merge advertises
        // it without mutating the connection's stale daemon cache.
        let seeded_paths = seed_split_fixture(&dir);
        backend.dashboard_paths = Some(seeded_paths);
        assert!(backend.list_sessions().iter().any(|id| id == "s-a"));
        assert!(!backend
            .sessions
            .lock()
            .unwrap()
            .snapshot()
            .iter()
            .any(|id| id == "s-a"));

        backend
            .attach_with_output_generation("s-a", 80, 24, false, 7, None)
            .unwrap();
        let attach = next_json(&mut request_rx);
        assert_eq!(attach["op"], "attach");
        assert_eq!(attach["output_generation"], 7);
        assert_eq!(
            observe_route_and_apply_grid(
                routes.as_ref(),
                &backend.sessions,
                backend.pending_attach_sizes.as_ref(),
                &backend.tx,
                "s-a",
                DaemonEventClass::Grid,
                Some(7),
                None,
                Some("pty-late".into()),
                || {},
            ),
            DaemonOutputAttachment::Exact(7)
        );
        assert!(request_rx.try_recv().is_err());

        backend.input("s-a", b"x").unwrap();
        backend.resize("s-a", 132, 43).unwrap();
        let write = next_json(&mut request_rx);
        assert_eq!(write["op"], "write");
        assert_eq!(write["expected_generation"], "pty-late");
        let resize = next_json(&mut request_rx);
        assert_eq!(resize["op"], "resize");
        assert_eq!(resize["expected_generation"], "pty-late");
        assert!(backend
            .sessions
            .lock()
            .unwrap()
            .snapshot()
            .iter()
            .any(|id| id == "s-a"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pending_same_id_attach_and_stale_tagged_grid_never_reuse_old_pty_generation() {
        let (mut backend, mut request_rx) = backend_with_rx();
        let routes = Arc::new(Mutex::new(DaemonOutputRoutes::new(true)));
        backend.output_routes = routes.clone();
        backend.sessions.lock().unwrap().apply_daemon_listing(
            vec!["s".into()],
            std::collections::BTreeMap::from([("s".into(), "pty-a".into())]),
        );
        let owner = Arc::new(Mutex::new(crate::winsize_owner::WinsizeOwner::new()));
        owner.lock().unwrap().set_serving(1, 0);
        let first_authority = crate::winsize_owner::DeferredResizeAuthority::reserve(
            &owner,
            "connection",
            "s",
            80,
            24,
        )
        .unwrap()
        .unwrap();

        backend
            .attach_with_output_generation("s", 80, 24, false, 1, Some(first_authority))
            .unwrap();
        assert_eq!(next_json(&mut request_rx)["output_generation"], 1);
        assert_eq!(
            observe_route_and_apply_grid(
                routes.as_ref(),
                &backend.sessions,
                backend.pending_attach_sizes.as_ref(),
                &backend.tx,
                "s",
                DaemonEventClass::Grid,
                Some(1),
                None,
                Some("pty-a".into()),
                || {},
            ),
            DaemonOutputAttachment::Exact(1)
        );
        assert_eq!(next_json(&mut request_rx)["expected_generation"], "pty-a");

        let second_authority = crate::winsize_owner::DeferredResizeAuthority::reserve(
            &owner,
            "connection",
            "s",
            90,
            30,
        )
        .unwrap()
        .unwrap();
        backend
            .attach_with_output_generation("s", 90, 30, false, 2, Some(second_authority))
            .unwrap();
        assert_eq!(next_json(&mut request_rx)["output_generation"], 2);
        backend.sessions.lock().unwrap().apply_daemon_listing(
            vec!["s".into()],
            std::collections::BTreeMap::from([("s".into(), "pty-b".into())]),
        );
        assert!(backend.input("s", b"must-not-send").is_err());
        backend.resize("s", 101, 33).unwrap();
        assert!(
            request_rx.try_recv().is_err(),
            "Pending Attach emitted Write/Resize before its exact Grid"
        );

        assert_eq!(
            observe_route_and_apply_grid(
                routes.as_ref(),
                &backend.sessions,
                backend.pending_attach_sizes.as_ref(),
                &backend.tx,
                "s",
                DaemonEventClass::Grid,
                Some(2),
                None,
                Some("pty-b".into()),
                || {},
            ),
            DaemonOutputAttachment::Exact(2)
        );
        let deferred = next_json(&mut request_rx);
        assert_eq!(deferred["op"], "resize");
        assert_eq!(deferred["expected_generation"], "pty-b");
        assert_eq!(deferred["cols"], 101);
        assert_eq!(deferred["rows"], 33);

        // A delayed A forwarder may still identify its own output generation, but cannot change
        // the current B route's PTY proof or trigger another deferred resize.
        assert_eq!(
            observe_route_and_apply_grid(
                routes.as_ref(),
                &backend.sessions,
                backend.pending_attach_sizes.as_ref(),
                &backend.tx,
                "s",
                DaemonEventClass::Grid,
                None,
                Some(1),
                Some("pty-a".into()),
                || {},
            ),
            DaemonOutputAttachment::Exact(1)
        );
        assert!(request_rx.try_recv().is_err());
        backend.input("s", b"b").unwrap();
        let input = next_json(&mut request_rx);
        assert_eq!(input["op"], "write");
        assert_eq!(input["expected_generation"], "pty-b");
    }

    #[tokio::test]
    async fn output_queue_byte_limit_is_hard_and_fail_stop() {
        let (mut tx, mut rx) = daemon_output_channel(4, 10);
        // session id + line = 6 bytes.
        tx.try_enqueue(output("s", "12345")).unwrap();
        assert_eq!(tx.available_bytes(), 4);
        assert_eq!(
            tx.try_enqueue(output("s", "1234")),
            Err(DaemonOutputEnqueueError::ByteLimit)
        );
        assert_eq!(
            tx.try_enqueue(output("s", "x")),
            Err(DaemonOutputEnqueueError::ProducerStopped),
            "capacity becoming available must not resume a revision-broken producer"
        );

        assert_eq!(rx.recv().await.unwrap().line, "12345");
        assert!(
            rx.recv().await.is_none(),
            "overflow closes after the valid prefix"
        );
    }

    #[tokio::test]
    async fn output_queue_item_overflow_closes_instead_of_silent_continuation() {
        let (mut tx, mut rx) = daemon_output_channel(1, 128);
        tx.try_enqueue(output("s1", "first")).unwrap();
        assert_eq!(
            tx.try_enqueue(output("s1", "second")),
            Err(DaemonOutputEnqueueError::ItemLimit)
        );
        assert_eq!(
            tx.try_enqueue(output("s1", "third")),
            Err(DaemonOutputEnqueueError::ProducerStopped)
        );

        assert_eq!(rx.recv().await.unwrap().line, "first");
        assert!(
            rx.recv().await.is_none(),
            "item overflow closes the producer"
        );
    }

    #[tokio::test]
    async fn output_queue_byte_permits_release_on_consume_and_receiver_drop() {
        let (mut tx, mut rx) = daemon_output_channel(3, 20);
        tx.try_enqueue(output("s", "12345")).unwrap(); // 6 bytes
        assert_eq!(tx.available_bytes(), 14);
        assert_eq!(rx.recv().await.unwrap().line, "12345");
        assert_eq!(tx.available_bytes(), 20, "recv releases the queued permit");

        tx.try_enqueue(output("s", "1234567")).unwrap(); // 8 bytes
        assert_eq!(tx.available_bytes(), 12);
        drop(rx);
        assert_eq!(
            tx.available_bytes(),
            20,
            "dropping the receiver releases permits held by queued items"
        );
    }

    #[tokio::test]
    async fn output_queue_closed_receiver_stops_producer_without_leaking_budget() {
        let (mut tx, rx) = daemon_output_channel(2, 20);
        drop(rx);
        assert_eq!(
            tx.try_enqueue(output("s", "payload")),
            Err(DaemonOutputEnqueueError::ReceiverClosed)
        );
        assert_eq!(tx.available_bytes(), 20);
        assert_eq!(
            tx.try_enqueue(output("s", "later")),
            Err(DaemonOutputEnqueueError::ProducerStopped)
        );
    }

    #[tokio::test]
    async fn spawn_daemon_task_primes_sessions_from_daemon_authority() {
        let dir =
            std::env::temp_dir().join(format!("hydra-daemon-backend-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("daemon.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut lines = BufReader::new(read).lines();
            let probe = lines.next_line().await.unwrap().unwrap();
            let probe: serde_json::Value = serde_json::from_str(&probe).unwrap();
            assert_eq!(probe["op"], "daemon_info");
            write
                .write_all(
                    format!(
                        "{{\"ev\":\"daemon_info\",\"protocol_version\":{},\"build_version\":\"test\",\"generation_conditional_mutations\":true,\"attachment_aware_conditional_kill\":true,\"generation_conditional_start\":true,\"start_operation_ledger\":true,\"generation_conditional_attach\":true}}\n",
                        maestro_protocol::DAEMON_PROTOCOL_VERSION
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let line = lines.next_line().await.unwrap().unwrap();
            let v: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(v["op"], "list_sessions");
            write
                .write_all(
                    br#"{"ev":"sessions","ids":["s-live"],"sessions":[{"id":"s-live","cwd":"/Users/test/home"}]}"#,
                )
                .await
                .unwrap();
            write.write_all(b"\n").await.unwrap();
        });

        let (backend, _out_rx) = spawn_daemon_task(sock, Vec::new()).await.unwrap();
        for _ in 0..20 {
            if backend.list_sessions() == ["s-live".to_string()] {
                server.await.unwrap();
                assert_eq!(
                    backend.session_metadata(),
                    vec![SessionMetadata {
                        id: "s-live".into(),
                        cwd: Some("/Users/test/home".into()),
                    }]
                );
                let _ = std::fs::remove_dir_all(&dir);
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        let _ = std::fs::remove_dir_all(&dir);
        panic!("backend did not refresh sessions from daemon list response");
    }

    #[tokio::test]
    async fn delayed_old_socket_response_is_rejected_after_generation_two_admission() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-daemon-output-generation-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("daemon.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut lines = BufReader::new(read).lines();

            let probe: serde_json::Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(probe["op"], "daemon_info");
            write
                .write_all(
                    format!(
                        "{{\"ev\":\"daemon_info\",\"protocol_version\":{},\"build_version\":\"test\",\"output_generation_echo\":true,\"generation_conditional_mutations\":true,\"attachment_aware_conditional_kill\":true,\"generation_conditional_start\":true,\"start_operation_ledger\":true,\"generation_conditional_attach\":true}}\n",
                        maestro_protocol::DAEMON_PROTOCOL_VERSION
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

            let list: serde_json::Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(list["op"], "list_sessions");
            let attach_one: serde_json::Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(attach_one["op"], "attach");
            assert_eq!(attach_one["output_generation"], 1);

            let detach: serde_json::Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(detach["op"], "detach");
            let attach_two: serde_json::Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(attach_two["op"], "attach");
            assert_eq!(attach_two["output_generation"], 2);

            // The old response is held until generation 2 is already admitted locally. The echoed Grid,
            // not request admission time, is the causal request/reply cutover. The tagged late Damage models
            // an aborted generation-1 forwarder racing after the new baseline.
            write
                .write_all(
                    b"{\"ev\":\"grid\",\"id\":\"s\",\"output_generation\":1,\"grid\":{}}\n\
{\"ev\":\"scrollback_rows\",\"id\":\"s\",\"rows\":[]}\n\
{\"ev\":\"grid\",\"id\":\"s\",\"output_generation\":2,\"grid\":{}}\n\
{\"ev\":\"damage\",\"live_output_generation\":1,\"frame\":{\"id\":\"s\"}}\n\
{\"ev\":\"output\",\"id\":\"s\",\"live_output_generation\":2,\"data\":\"new\"}\n",
                )
                .await
                .unwrap();
            write.flush().await.unwrap();
            let _ = release_rx.await;
        });

        let (mut backend, mut daemon_out) = spawn_daemon_task(sock, Vec::new()).await.unwrap();
        backend
            .attach_with_output_generation("s", 80, 24, false, 1, None)
            .unwrap();
        backend.detach("s");
        backend
            .attach_with_output_generation("s", 80, 24, false, 2, None)
            .unwrap();

        let delayed_baseline = daemon_out.recv_routed().await.unwrap();
        assert!(
            !delayed_baseline.attachment.accepts(2),
            "the delayed generation-1 baseline must be rejected by generation 2"
        );
        assert_eq!(
            delayed_baseline.attachment,
            DaemonOutputAttachment::Unconfirmed
        );
        let delayed_scrollback = daemon_out.recv_routed().await.unwrap();
        assert!(
            !delayed_scrollback.attachment.accepts(2),
            "a response behind the stale baseline must remain rejected"
        );
        assert_eq!(
            delayed_scrollback.attachment,
            DaemonOutputAttachment::Unconfirmed
        );
        let second_baseline = daemon_out.recv_routed().await.unwrap();
        assert_eq!(second_baseline.attachment, DaemonOutputAttachment::Exact(2));
        let late_old_live = daemon_out.recv_routed().await.unwrap();
        assert_eq!(late_old_live.attachment, DaemonOutputAttachment::Exact(1));
        assert!(
            !late_old_live.attachment.accepts(2),
            "an aborted old forwarder cannot race output onto generation 2"
        );
        let new = daemon_out.recv_routed().await.unwrap();
        assert!(new.attachment.accepts(2));

        let _ = release_tx.send(());
        server.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn raw_mode_observes_the_filtered_attach_grid_before_routing_followup_output() {
        let dir = std::env::temp_dir().join(format!("hydra-raw-gen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("daemon.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut lines = BufReader::new(read).lines();
            let probe: serde_json::Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(probe["op"], "daemon_info");
            write
                .write_all(
                    format!(
                        "{{\"ev\":\"daemon_info\",\"protocol_version\":{},\"build_version\":\"test\",\"output_generation_echo\":true,\"generation_conditional_mutations\":true,\"attachment_aware_conditional_kill\":true,\"generation_conditional_start\":true,\"start_operation_ledger\":true,\"generation_conditional_attach\":true}}\n",
                        maestro_protocol::DAEMON_PROTOCOL_VERSION
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let list: serde_json::Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(list["op"], "list_sessions");
            let attach: serde_json::Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(attach["op"], "attach");
            assert_eq!(attach["want_raw_output"], true);
            assert_eq!(attach["output_generation"], 7);
            write
                .write_all(
                    b"{\"ev\":\"grid\",\"id\":\"s\",\"output_generation\":7,\"grid\":{}}\n\
{\"ev\":\"scrollback_rows\",\"id\":\"s\",\"rows\":[]}\n\
{\"ev\":\"output\",\"id\":\"s\",\"live_output_generation\":7,\"data\":\"new\"}\n",
                )
                .await
                .unwrap();
            write.flush().await.unwrap();
            let _ = release_rx.await;
        });

        let (mut backend, mut daemon_out) = spawn_daemon_task(sock, Vec::new()).await.unwrap();
        backend
            .attach_with_output_generation("s", 80, 24, true, 7, None)
            .unwrap();
        let followup = daemon_out.recv_routed().await.unwrap();
        assert!(
            followup.output.line.contains("scrollback_rows"),
            "the structured baseline itself must be filtered in raw mode"
        );
        assert_eq!(followup.attachment, DaemonOutputAttachment::Exact(7));
        let live = daemon_out.recv_routed().await.unwrap();
        assert!(live.output.line.contains("\"ev\":\"output\""));
        assert_eq!(live.attachment, DaemonOutputAttachment::Exact(7));

        let _ = release_tx.send(());
        server.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn stalled_daemon_writer_pressure_closes_output_and_reclaims_the_socket() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-daemon-stalled-writer-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("daemon.sock");
        let listener = UnixListener::bind(&sock).unwrap();
        let (inspect_tx, inspect_rx) = tokio::sync::oneshot::channel::<()>();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut probe = String::new();
            stream.read_line(&mut probe).await.unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(probe.trim()).unwrap()["op"],
                "daemon_info"
            );
            stream
                .get_mut()
                .write_all(
                    format!(
                        "{{\"ev\":\"daemon_info\",\"protocol_version\":{},\"build_version\":\"test\",\"generation_conditional_mutations\":true,\"attachment_aware_conditional_kill\":true}}\n",
                        maestro_protocol::DAEMON_PROTOCOL_VERSION
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();

            // Deliberately do not read the request stream until the test has filled the bounded queue
            // and observed owner failure. This forces the Unix writer into real kernel backpressure.
            inspect_rx.await.unwrap();
            let mut remainder = Vec::new();
            tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut remainder))
                .await
                .expect("stalled daemon socket remained owned after request-queue failure")
                .unwrap();
        });

        let (backend, mut daemon_out) = spawn_daemon_task(sock, Vec::new()).await.unwrap();
        let payload = vec![0_u8; crate::remote_frame::MAX_INPUT_PAYLOAD];
        let request = serde_json::to_string(&maestro_protocol::ClientRequest::Write {
            id: maestro_protocol::SessionId("stalled".into()),
            expected_generation: "pty-stalled".into(),
            data: String::from_utf8_lossy(&payload).into_owned(),
        })
        .unwrap();
        let mut failed = false;
        for _ in 0..128 {
            if backend.tx.send(request.clone()).is_err() {
                failed = true;
                break;
            }
        }
        assert!(
            failed,
            "bounded request queue never reached its pressure verdict"
        );
        assert!(
            tokio::time::timeout(Duration::from_secs(1), daemon_out.recv())
                .await
                .expect("request failure did not wake the daemon-output owner")
                .is_none(),
            "request failure must close output rather than leave a half-live peer"
        );
        drop(backend);
        let _ = inspect_tx.send(());
        server.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn legacy_probe_reconnects_attach_only_and_never_sends_start_session() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-daemon-backend-legacy-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("daemon.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        let server = tokio::spawn(async move {
            // Connection 1 is the operational candidate. Simulate a retained v1 daemon rejecting
            // the unknown probe; the client must discard this connection.
            let (probe_stream, _) = listener.accept().await.unwrap();
            let (probe_read, mut probe_write) = probe_stream.into_split();
            let mut probe_lines = BufReader::new(probe_read).lines();
            let probe = probe_lines.next_line().await.unwrap().unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&probe).unwrap()["op"],
                "daemon_info"
            );
            probe_write
                .write_all(b"{\"ev\":\"error\",\"message\":\"invalid request\"}\n")
                .await
                .unwrap();
            drop(probe_write);

            // Connection 2 is clean and attach-only. It must receive the read-only cache prime and
            // attach, with no StartSession inserted between them.
            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut lines = BufReader::new(read).lines();
            let list = lines.next_line().await.unwrap().unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&list).unwrap()["op"],
                "list_sessions"
            );
            write
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[\"legacy-live\"]}\n")
                .await
                .unwrap();
            let attach = tokio::time::timeout(Duration::from_secs(1), lines.next_line())
                .await
                .expect("attach request should remain legacy-compatible")
                .unwrap()
                .unwrap();
            let attach: serde_json::Value = serde_json::from_str(&attach).unwrap();
            assert_eq!(attach["op"], "attach");
            assert_eq!(attach["id"], "legacy-live");
        });

        let (mut backend, _out_rx) = spawn_daemon_task(sock, Vec::new()).await.unwrap();
        let mut creator = backend.session_creator("/tmp".into());
        assert_eq!(
            creator.start_session("must-not-start", "/tmp"),
            Err(crate::session_creator::CreateSessionError::DaemonUnavailable)
        );
        assert!(!creator
            .known_sessions()
            .contains(&"must-not-start".to_string()));
        backend
            .attach("legacy-live", 80, 24, false)
            .expect("read-only attach remains compatible");
        server.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn partial_v3_without_attachment_fence_reconnects_read_only() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-daemon-backend-partial-v3-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("daemon.sock");
        let listener = UnixListener::bind(&sock).unwrap();

        let server = tokio::spawn(async move {
            let (probe_stream, _) = listener.accept().await.unwrap();
            let (probe_read, mut probe_write) = probe_stream.into_split();
            let mut probe_lines = BufReader::new(probe_read).lines();
            let probe: serde_json::Value =
                serde_json::from_str(&probe_lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(probe["op"], "daemon_info");
            probe_write
                .write_all(
                    format!(
                        "{{\"ev\":\"daemon_info\",\"protocol_version\":{},\"build_version\":\"partial\",\"generation_conditional_mutations\":true,\"attachment_aware_conditional_kill\":false}}\n",
                        maestro_protocol::DAEMON_PROTOCOL_VERSION
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            drop(probe_write);

            let (stream, _) = listener.accept().await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut lines = BufReader::new(read).lines();
            let list: serde_json::Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(list["op"], "list_sessions");
            write
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[\"partial-live\"]}\n")
                .await
                .unwrap();
            let attach = tokio::time::timeout(Duration::from_secs(1), lines.next_line())
                .await
                .expect("read-only attach should reach the clean fallback connection")
                .unwrap()
                .unwrap();
            let attach: serde_json::Value = serde_json::from_str(&attach).unwrap();
            assert_eq!(attach["op"], "attach");
            assert_eq!(attach["id"], "partial-live");
            assert!(
                tokio::time::timeout(Duration::from_millis(100), lines.next_line())
                    .await
                    .is_err(),
                "no mutation may follow the partial-v3 probe"
            );
        });

        let (mut backend, _out_rx) = spawn_daemon_task(sock, Vec::new()).await.unwrap();
        let mut creator = backend.session_creator("/tmp".into());
        assert_eq!(
            creator.start_session("must-not-start", "/tmp"),
            Err(crate::session_creator::CreateSessionError::DaemonUnavailable)
        );
        backend
            .attach("partial-live", 80, 24, false)
            .expect("partial v3 remains read-only attach compatible");
        server.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn backend_with_rx() -> (DaemonBackend, DaemonRequestReceiver) {
        let (tx, rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        (
            DaemonBackend {
                tx,
                sessions: Arc::new(Mutex::new(SessionCache::mutation_ready_for_test())),
                session_metadata: Arc::new(Mutex::new(Vec::new())),
                dashboard_paths: None,
                raw_output: Arc::new(AtomicBool::new(false)),
                output_routes: Arc::new(Mutex::new(DaemonOutputRoutes::new(false))),
                pending_attach_sizes: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            },
            rx,
        )
    }

    fn clone_backend_for_test(backend: &DaemonBackend) -> DaemonBackend {
        DaemonBackend {
            tx: backend.tx.clone(),
            sessions: backend.sessions.clone(),
            session_metadata: backend.session_metadata.clone(),
            dashboard_paths: backend.dashboard_paths.clone(),
            raw_output: backend.raw_output.clone(),
            output_routes: backend.output_routes.clone(),
            pending_attach_sizes: backend.pending_attach_sizes.clone(),
        }
    }

    fn next_json(rx: &mut DaemonRequestReceiver) -> serde_json::Value {
        let line = rx.try_recv().expect("daemon request line");
        serde_json::from_str(&line).expect("request is valid JSON")
    }

    fn deferred_resize_authority(
        connection_id: &str,
        session_id: &str,
        cols: u16,
        rows: u16,
    ) -> (
        Arc<Mutex<crate::winsize_owner::WinsizeOwner>>,
        crate::winsize_owner::DeferredResizeAuthority,
    ) {
        let owner = Arc::new(Mutex::new(crate::winsize_owner::WinsizeOwner::new()));
        owner.lock().unwrap().set_serving(1, 0);
        let authority = crate::winsize_owner::DeferredResizeAuthority::reserve(
            &owner,
            connection_id,
            session_id,
            cols,
            rows,
        )
        .expect("winsize authority generation available")
        .expect("viewed structured attach authority");
        (owner, authority)
    }

    #[test]
    fn daemon_session_creator_reserves_created_ids_until_daemon_reports_sessions() {
        let (backend, mut rx) = backend_with_rx();
        let _daemon = install_conditional_start_test_daemon(&backend.tx);
        let mut creator = backend.session_creator("/tmp".into());

        creator.start_session("s-created", "/tmp").unwrap();

        assert_eq!(creator.known_sessions(), vec!["s-created".to_string()]);
        let start = next_json(&mut rx);
        assert_eq!(start["op"], "start_session");
        assert_eq!(start["id"], "s-created");
        assert_eq!(start["cwd"], "/tmp");
    }

    #[test]
    fn daemon_session_creator_starts_remote_session_at_exact_initial_geometry() {
        let (backend, mut rx) = backend_with_rx();
        let _daemon = install_conditional_start_test_daemon(&backend.tx);
        let mut creator = backend.session_creator("/tmp".into());
        let size =
            crate::session_creator::InitialTerminalSize::from_optional_pair(Some(132), Some(43));

        creator
            .start_session_with_launch_and_size("s-sized", "/tmp", None, size)
            .unwrap();

        let start = next_json(&mut rx);
        assert_eq!(start["op"], "start_session");
        assert_eq!(start["id"], "s-sized");
        assert_eq!(start["cols"], 132);
        assert_eq!(start["rows"], 43);
    }

    #[test]
    fn daemon_session_creator_publishes_and_retains_remote_creation_size_ownership() {
        let dir =
            std::env::temp_dir().join(format!("hydra-daemon-create-lease-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let owner = Arc::new(Mutex::new(crate::winsize_owner::WinsizeOwner::new()));
        owner.lock().unwrap().set_serving(1, 0);
        let (backend, mut rx) = backend_with_rx();
        let _daemon = install_conditional_start_test_daemon(&backend.tx);
        backend.set_remote_creation_lease_publisher(
            crate::winsize_owner::RemoteCreationLeasePublisher::new(
                owner,
                dir.clone(),
                "connection-1".into(),
            ),
        );
        let mut creator = backend.session_creator("/tmp".into());

        creator
            .start_session_with_launch_and_size(
                "s-sized",
                "/tmp",
                None,
                InitialTerminalSize::from_optional_pair(Some(132), Some(43)),
            )
            .unwrap();

        assert_eq!(
            crate::winsize_owner::read_remote_owned_sessions(&dir),
            vec!["s-sized".to_string()]
        );
        assert_eq!(next_json(&mut rx)["id"], "s-sized");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn daemon_session_creator_keeps_grid_proven_success_when_retire_hits_eof() {
        let tmp = tempfile::tempdir().unwrap();
        let lease_dir = tmp.path().join("creation-lease");
        std::fs::create_dir_all(&lease_dir).unwrap();
        let owner = Arc::new(Mutex::new(crate::winsize_owner::WinsizeOwner::new()));
        owner.lock().unwrap().set_serving(1, 0);
        let (backend, mut rx) = backend_with_rx();
        let daemon = install_conditional_start_test_daemon_with_retire_eof(&backend.tx);
        backend.set_remote_creation_lease_publisher(
            crate::winsize_owner::RemoteCreationLeasePublisher::new(
                owner,
                lease_dir.clone(),
                "retire-eof-connection".into(),
            ),
        );
        let mut creator = backend.session_creator("/tmp".into());

        assert_eq!(creator.start_session("s-retire-eof", "/tmp"), Ok(()));
        assert_eq!(creator.known_sessions(), vec!["s-retire-eof".to_string()]);
        assert_eq!(
            crate::winsize_owner::read_remote_owned_sessions(&lease_dir),
            vec!["s-retire-eof".to_string()],
            "Grid-proven success must commit, not roll back, its viewport lease"
        );

        let starts = daemon.start_requests();
        assert_eq!(starts.len(), 1, "retire EOF must never republish Start");
        assert_eq!(starts[0]["id"], "s-retire-eof");
        assert!(starts[0]["conditional_start"].is_object());
        let requests = daemon.requests();
        assert_eq!(
            requests
                .iter()
                .filter(|request| request["op"] == "reserve_start_operation")
                .count(),
            1
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request["op"] == "attach")
                .count(),
            1
        );
        assert_eq!(
            requests
                .iter()
                .filter(|request| request["op"] == "retire_start_operation")
                .count(),
            1
        );
        let mirrored: serde_json::Value =
            serde_json::from_str(rx.try_recv().unwrap().trim()).unwrap();
        assert_eq!(mirrored["op"], "start_session");
        assert_eq!(mirrored["id"], "s-retire-eof");
        assert!(
            rx.try_recv().is_err(),
            "post-Grid retirement failure must not enqueue a second Start"
        );
    }

    #[test]
    fn failed_daemon_creation_rolls_back_remote_size_ownership() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-daemon-create-lease-rollback-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let owner = Arc::new(Mutex::new(crate::winsize_owner::WinsizeOwner::new()));
        owner.lock().unwrap().set_serving(1, 0);
        let (backend, rx) = backend_with_rx();
        backend.set_remote_creation_lease_publisher(
            crate::winsize_owner::RemoteCreationLeasePublisher::new(
                owner,
                dir.clone(),
                "connection-1".into(),
            ),
        );
        drop(rx);
        let mut creator = backend.session_creator("/Users/test/home".into());

        assert_eq!(
            creator
                .start_session_with_launch_and_size(
                    "s-sized",
                    "/Users/test/home",
                    None,
                    InitialTerminalSize::from_optional_pair(Some(132), Some(43)),
                )
                .unwrap_err(),
            crate::session_creator::CreateSessionError::DaemonUnavailable
        );
        assert!(crate::winsize_owner::read_remote_owned_sessions(&dir).is_empty());
        assert_eq!(
            std::fs::read_to_string(dir.join(crate::winsize_owner::OWNER_FILE_NAME)).unwrap(),
            "local"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn session_cache_reservation_survives_stale_daemon_sessions_event_until_named() {
        let mut cache = SessionCache::seeded(vec!["s-old".into()]);
        cache.reserve("s-created");
        // daemon-confirmed ids first, then reservations.
        assert_eq!(
            cache.snapshot(),
            vec!["s-old".to_string(), "s-created".to_string()]
        );

        // A STALE daemon Sessions event (snapshotted before the create, so it doesn't name the new id)
        // must NOT evict the reservation — this was the "agent denies the session it just created" bug.
        cache.apply_daemon_ids(vec!["s-old".into()]);
        assert!(
            cache.snapshot().contains(&"s-created".to_string()),
            "stale Sessions event evicted a just-created reservation"
        );

        // Once the daemon NAMES the id, it graduates to daemon-owned truth…
        cache.apply_daemon_ids(vec!["s-old".into(), "s-created".into()]);
        assert!(cache.snapshot().contains(&"s-created".to_string()));
        // …so a LATER event without it is a real removal (the session exited), not staleness.
        cache.apply_daemon_ids(vec!["s-old".into()]);
        assert_eq!(cache.snapshot(), vec!["s-old".to_string()]);
    }

    #[test]
    fn session_cache_remove_drops_pending_reservations_too() {
        let mut cache = SessionCache::seeded(vec!["s-live".into()]);
        cache.reserve("s-created");
        cache.remove(&["s-live".to_string(), "s-created".to_string()]);
        assert!(cache.snapshot().is_empty());
        // and a stale event can't resurrect the removed reservation.
        cache.apply_daemon_ids(Vec::new());
        assert!(cache.snapshot().is_empty());
    }

    #[test]
    fn backend_attach_is_honest_when_the_daemon_channel_is_gone() {
        // PATCH: attach used to be fire-and-forget (always Ok) → the browser got attach_ok even when the
        // daemon leg was dead and no output could ever arrive. A dropped daemon task must surface as Err so
        // the bridge replies attach_failed instead.
        let (mut backend, rx) = backend_with_rx();
        drop(rx);
        let err = backend
            .attach("s1", 80, 24, false)
            .expect_err("attach over a dead daemon channel must fail");
        // content-blind: the error names no session id and carries no payload.
        assert!(!err.contains("s1"));
    }

    #[test]
    fn backend_resize_is_honest_when_the_daemon_channel_is_gone() {
        let (mut backend, rx) = backend_with_rx();
        drop(rx);
        let err = backend
            .resize("s1", 80, 24)
            .expect_err("resize over a dead daemon channel must fail");
        assert!(!err.contains("s1"));
    }

    #[test]
    fn daemon_session_creator_does_not_reserve_when_send_fails() {
        let (backend, rx) = backend_with_rx();
        drop(rx);
        let mut creator = backend.session_creator("/Users/test/home".into());

        assert_eq!(
            creator
                .start_session("s-created", "/Users/test/home")
                .unwrap_err(),
            crate::session_creator::CreateSessionError::DaemonUnavailable
        );
        assert!(creator.known_sessions().is_empty());
    }

    #[test]
    fn daemon_request_builders_json_escape_session_ids_and_payloads() {
        let (mut backend, mut rx) = backend_with_rx();
        let id = "s\"quoted\\id";
        let routes = Arc::new(Mutex::new(DaemonOutputRoutes::new(true)));
        backend.output_routes = routes.clone();
        backend.sessions.lock().unwrap().apply_daemon_listing(
            vec![id.into()],
            std::collections::BTreeMap::from([(id.into(), "pty-quoted".into())]),
        );

        backend
            .attach_with_output_generation(id, 80, 24, true, 9, None)
            .unwrap();
        let attach = next_json(&mut rx);
        assert_eq!(attach["op"], "attach");
        assert_eq!(attach["id"], id);
        assert_eq!(attach["want_raw_output"], true);
        assert_eq!(attach["output_generation"], 9);
        observe_route_and_apply_grid(
            routes.as_ref(),
            &backend.sessions,
            backend.pending_attach_sizes.as_ref(),
            &backend.tx,
            id,
            DaemonEventClass::Grid,
            Some(9),
            None,
            Some("pty-quoted".into()),
            || {},
        );
        assert!(
            rx.try_recv().is_err(),
            "a raw attach must not retain or emit a deferred geometry mutation"
        );

        backend.input(id, b"hello \"quoted\" \\ bytes").unwrap();
        let input = next_json(&mut rx);
        assert_eq!(input["op"], "write");
        assert_eq!(input["id"], id);
        assert_eq!(input["expected_generation"], "pty-quoted");
        assert_eq!(input["data"], "hello \"quoted\" \\ bytes");

        backend.resize(id, 132, 43).unwrap();
        let resize = next_json(&mut rx);
        assert_eq!(resize["op"], "resize");
        assert_eq!(resize["id"], id);
        assert_eq!(resize["expected_generation"], "pty-quoted");
        assert_eq!(resize["cols"], 132);
        assert_eq!(resize["rows"], 43);

        backend.scrollback(id, 12, 40).unwrap();
        let scrollback = next_json(&mut rx);
        assert_eq!(scrollback["op"], "scrollback");
        assert_eq!(scrollback["id"], id);
        assert_eq!(scrollback["offset_from_top"], 12);
        assert_eq!(scrollback["count"], 40);

        backend.detach(id);
        let detach = next_json(&mut rx);
        assert_eq!(detach["op"], "detach");
        assert_eq!(detach["id"], id);
    }

    /// Seed the minimal desktop store a split needs: project `p` owning window `win-main` with one live
    /// pane `pane-a`/`s-a` (workspace `ws`). Returns the store paths.
    fn seed_split_fixture(dir: &std::path::Path) -> maestro_shell::AppPaths {
        let work = dir.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let work = work.to_string_lossy().into_owned();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        maestro_shell::project::ProjectService::new(&paths)
            .create(
                "p",
                "P",
                &work,
                maestro_shell::project::NewProject::default(),
                1,
            )
            .unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Workspace,
            "ws",
            1,
            &maestro_shell::records::Workspace {
                workspace_id: "ws".into(),
                project_id: "p".into(),
                root: work.clone(),
                policy: maestro_shell::policy::WorkspacePolicy::ScratchCwd,
                consent: Default::default(),
            },
        )
        .unwrap();
        let layouts = maestro_shell::WindowLayoutService::new(&paths);
        layouts.create_empty("win-main", 1).unwrap();
        layouts
            .open_tab(
                "win-main",
                "pane-a",
                "s-a",
                "A",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .unwrap();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Session,
            "s-a",
            2,
            &maestro_shell::SessionRecord {
                session_id: "s-a".into(),
                workspace_id: "ws".into(),
                kind: maestro_shell::SessionKind::Agent,
                launch: maestro_shell::LaunchSpec::KnownSafe {
                    launch_spec_id: "claude".into(),
                    params: Vec::new(),
                },
                cwd_resolved: work,
                agent_task_id: None,
                created_at_ms: 2,
                last_attached_at_ms: 2,
                last_known_generation: None,
                status: maestro_shell::SessionStatus::Live,
            },
        )
        .unwrap();
        maestro_shell::store::set_window_project(&paths, "win-main", "p").unwrap();
        maestro_shell::project::ProjectService::new(&paths)
            .reorder_windows("p", &["win-main".to_string()], 2)
            .unwrap();
        paths
    }

    fn pane_session_template(workspace_id: &str, now_ms: u64) -> maestro_shell::SessionRecord {
        maestro_shell::SessionRecord {
            session_id: String::new(),
            workspace_id: workspace_id.into(),
            kind: maestro_shell::SessionKind::Agent,
            launch: maestro_shell::LaunchSpec::KnownSafe {
                launch_spec_id: "claude".into(),
                params: Vec::new(),
            },
            cwd_resolved: "/tmp/hydra-test-work".into(),
            agent_task_id: None,
            created_at_ms: now_ms,
            last_attached_at_ms: now_ms,
            last_known_generation: None,
            status: maestro_shell::SessionStatus::Live,
        }
    }

    #[test]
    fn remote_pane_session_allocation_skips_daemon_and_durable_collisions_without_adoption() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = seed_split_fixture(tmp.path());
        let daemon_id = crate::session_creator::generate_session_id(|| 0);
        let durable_id = crate::session_creator::generate_session_id(|| 1);
        let fresh_id = crate::session_creator::generate_session_id(|| 2);
        let mut durable = pane_session_template("ws", 40);
        durable.session_id = durable_id.clone();
        durable.cwd_resolved = "/durable/foreign-owner".into();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Session,
            &durable_id,
            40,
            &durable,
        )
        .unwrap();
        let layout_before = maestro_shell::WindowLayoutService::new(&paths)
            .load("win-main")
            .unwrap()
            .unwrap();

        let mut bytes = [vec![0_u8; 6], vec![1_u8; 6], vec![2_u8; 6]]
            .concat()
            .into_iter();
        let leased = Arc::new(Mutex::new(Vec::new()));
        let dropped = Arc::new(Mutex::new(Vec::new()));
        let leased_for_reserve = Arc::clone(&leased);
        let dropped_for_reserve = Arc::clone(&dropped);
        let (created, creation_lease) = create_fresh_remote_session(
            &paths,
            std::slice::from_ref(&daemon_id),
            pane_session_template("ws", 50),
            50,
            move || bytes.next().expect("three deterministic id candidates"),
            move |session_id, _| {
                leased_for_reserve
                    .lock()
                    .unwrap()
                    .push(session_id.to_string());
                Ok(TestPaneCreationLease {
                    session_id: session_id.to_string(),
                    dropped: Arc::clone(&dropped_for_reserve),
                })
            },
        )
        .unwrap();

        assert_eq!(created.session_id, fresh_id);
        assert_eq!(
            leased.lock().unwrap().as_slice(),
            &[durable_id.clone(), fresh_id.clone()],
            "daemon-known candidates are skipped before a lease; a durable collision's lease is retried"
        );
        assert_eq!(
            dropped.lock().unwrap().as_slice(),
            std::slice::from_ref(&durable_id),
            "the durable collision leaves no temporary creation authority"
        );
        let durable_after = maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &durable_id,
        )
        .unwrap();
        assert!(
            matches!(durable_after, Some(maestro_shell::LoadOutcome::Loaded(ref row)) if row == &durable)
        );
        let created_after = maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &fresh_id,
        )
        .unwrap();
        assert!(
            matches!(created_after, Some(maestro_shell::LoadOutcome::Loaded(ref row)) if row == &created)
        );
        assert_eq!(
            maestro_shell::WindowLayoutService::new(&paths)
                .load("win-main")
                .unwrap()
                .unwrap(),
            layout_before,
            "allocation alone publishes no tab and cannot start or clean up the collided identity"
        );
        drop(creation_lease);
    }

    #[test]
    fn remote_pane_session_allocation_exhaustion_returns_without_tab_or_start_authority() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = seed_split_fixture(tmp.path());
        let durable_id = crate::session_creator::generate_session_id(|| 0);
        let mut durable = pane_session_template("ws", 60);
        durable.session_id = durable_id.clone();
        durable.cwd_resolved = "/durable/exhaustion-owner".into();
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Session,
            &durable_id,
            60,
            &durable,
        )
        .unwrap();
        let layout_before = maestro_shell::WindowLayoutService::new(&paths)
            .load("win-main")
            .unwrap()
            .unwrap();
        let leased = Arc::new(Mutex::new(Vec::new()));
        let dropped = Arc::new(Mutex::new(Vec::new()));
        let leased_for_reserve = Arc::clone(&leased);
        let dropped_for_reserve = Arc::clone(&dropped);

        let result = create_fresh_remote_session(
            &paths,
            &[],
            pane_session_template("ws", 61),
            61,
            || 0,
            move |session_id, _| {
                leased_for_reserve
                    .lock()
                    .unwrap()
                    .push(session_id.to_string());
                Ok(TestPaneCreationLease {
                    session_id: session_id.to_string(),
                    dropped: Arc::clone(&dropped_for_reserve),
                })
            },
        );

        assert!(matches!(
            result,
            Err(RemotePaneSessionAllocationError::Exhausted)
        ));
        assert_eq!(
            leased.lock().unwrap().as_slice(),
            std::slice::from_ref(&durable_id)
        );
        assert_eq!(
            dropped.lock().unwrap().as_slice(),
            std::slice::from_ref(&durable_id)
        );
        let durable_after = maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &durable_id,
        )
        .unwrap();
        assert!(
            matches!(durable_after, Some(maestro_shell::LoadOutcome::Loaded(ref row)) if row == &durable)
        );
        assert_eq!(
            maestro_shell::WindowLayoutService::new(&paths)
                .load("win-main")
                .unwrap()
                .unwrap(),
            layout_before
        );
    }

    #[test]
    fn attach_only_split_refuses_before_writing_session_or_layout() {
        use crate::remote_control::PaneSplitter;
        let dir =
            std::env::temp_dir().join(format!("hydra-v1-split-gate-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = seed_split_fixture(&dir);
        let before_layout = maestro_shell::WindowLayoutService::new(&paths)
            .load("win-main")
            .unwrap()
            .unwrap();
        let before_sessions = maestro_shell::store::load_all::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
        )
        .unwrap()
        .len();
        let (tx, mut rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let mut splitter = DaemonPaneSplitter {
            tx,
            // A retained session may be known, but no exact daemon_info means attach-only.
            sessions: Arc::new(Mutex::new(SessionCache::seeded(vec!["s-a".into()]))),
            paths: paths.clone(),
        };

        let error = splitter
            .split_pane(crate::remote_control::SplitPaneRequest {
                window_id: "win-main".into(),
                from_pane_id: "pane-a".into(),
                dir: crate::remote_control::SplitPaneDir::Right,
                agent: Some("terminal".into()),
                launch_flags: None,
                cwd: None,
                pane_name: None,
                now_ms: 5,
            })
            .unwrap_err();
        assert_eq!(
            error,
            crate::remote_control::SplitPaneCreateError::DaemonUnavailable
        );
        assert_eq!(
            splitter.new_pane(crate::remote_control::SplitPaneRequest {
                window_id: "win-main".into(),
                from_pane_id: "pane-a".into(),
                dir: crate::remote_control::SplitPaneDir::Right,
                agent: Some("terminal".into()),
                launch_flags: None,
                cwd: None,
                pane_name: None,
                now_ms: 6,
            }),
            Err(crate::remote_control::SplitPaneCreateError::DaemonUnavailable)
        );
        assert!(rx.try_recv().is_err(), "v1 must receive no daemon mutation");
        assert_eq!(
            maestro_shell::WindowLayoutService::new(&paths)
                .load("win-main")
                .unwrap()
                .unwrap(),
            before_layout
        );
        assert_eq!(
            maestro_shell::store::load_all::<maestro_shell::SessionRecord>(
                &paths,
                maestro_shell::RecordKind::Session,
            )
            .unwrap()
            .len(),
            before_sessions
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn attach_only_revive_and_virtual_start_refuse_before_durable_changes() {
        use crate::remote_control::{PaneReviver, PaneSessionStarter};
        let dir =
            std::env::temp_dir().join(format!("hydra-v1-revive-gate-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = seed_split_fixture(&dir);
        let before_layout = maestro_shell::WindowLayoutService::new(&paths)
            .load("win-main")
            .unwrap()
            .unwrap();
        let before_session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            "s-a",
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(session) => session,
            other => panic!("expected session, got {other:?}"),
        };
        let (revive_tx, mut revive_rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let mut reviver = DaemonPaneReviver {
            tx: revive_tx,
            sessions: Arc::new(Mutex::new(SessionCache::default())),
            paths: paths.clone(),
        };
        assert_eq!(
            reviver.revive_pane(crate::remote_control::RevivePaneRequest {
                window_id: "win-main".into(),
                pane_id: "pane-a".into(),
                now_ms: 50,
            }),
            Err(crate::remote_control::RevivePaneError::Internal)
        );
        assert!(revive_rx.try_recv().is_err());

        let (start_tx, mut start_rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let mut starter = DaemonPaneSessionStarter {
            tx: start_tx,
            sessions: Arc::new(Mutex::new(SessionCache::default())),
            paths: paths.clone(),
        };
        assert_eq!(
            starter.start_pane_session(crate::remote_control::RevivePaneRequest {
                window_id: "win-main".into(),
                pane_id: "pane-a".into(),
                now_ms: 51,
            }),
            Err(crate::remote_control::RevivePaneError::Internal)
        );
        assert!(start_rx.try_recv().is_err());
        assert_eq!(
            maestro_shell::WindowLayoutService::new(&paths)
                .load("win-main")
                .unwrap()
                .unwrap(),
            before_layout
        );
        let after_session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            "s-a",
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(session) => session,
            other => panic!("expected session, got {other:?}"),
        };
        assert_eq!(after_session, before_session);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_live_virtual_start_is_read_only_but_durable_revive_refuses() {
        use crate::remote_control::{PaneReviver, PaneSessionStarter};
        let dir =
            std::env::temp_dir().join(format!("hydra-v1-live-revive-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = seed_split_fixture(&dir);
        let before_layout = maestro_shell::WindowLayoutService::new(&paths)
            .load("win-main")
            .unwrap()
            .unwrap();
        let before_session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            "s-a",
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(session) => session,
            other => panic!("expected session, got {other:?}"),
        };
        let (revive_tx, mut revive_rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let mut reviver = DaemonPaneReviver {
            tx: revive_tx,
            sessions: Arc::new(Mutex::new(SessionCache::seeded(vec!["s-a".into()]))),
            paths: paths.clone(),
        };
        assert_eq!(
            reviver.revive_pane(crate::remote_control::RevivePaneRequest {
                window_id: "win-main".into(),
                pane_id: "pane-a".into(),
                now_ms: 50,
            }),
            Err(crate::remote_control::RevivePaneError::Internal)
        );
        assert!(
            revive_rx.try_recv().is_err(),
            "attach-only durable revive must send no daemon mutation"
        );

        let (start_tx, mut start_rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let mut starter = DaemonPaneSessionStarter {
            tx: start_tx,
            sessions: Arc::new(Mutex::new(SessionCache::seeded(vec!["s-a".into()]))),
            paths: paths.clone(),
        };
        let viewed = starter
            .start_pane_session(crate::remote_control::RevivePaneRequest {
                window_id: "win-main".into(),
                pane_id: "pane-a".into(),
                now_ms: 51,
            })
            .unwrap();
        assert_eq!(viewed.session_id, "s-a");
        assert!(
            start_rx.try_recv().is_err(),
            "legacy live viewport start must be a pure read-only no-op"
        );
        assert_eq!(
            maestro_shell::WindowLayoutService::new(&paths)
                .load("win-main")
                .unwrap()
                .unwrap(),
            before_layout
        );
        let after_session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            "s-a",
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(session) => session,
            other => panic!("expected session, got {other:?}"),
        };
        assert_eq!(after_session, before_session);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn attach_only_new_window_refuses_before_writing_hierarchy() {
        let dir =
            std::env::temp_dir().join(format!("hydra-v1-window-gate-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        maestro_shell::ProjectService::new(&paths)
            .create("p", "P", "/r", maestro_shell::NewProject::default(), 1)
            .unwrap();
        let (tx, mut rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let mut opener = DaemonWindowOpener {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::default())),
            paths: paths.clone(),
        };
        assert_eq!(
            opener.new_window(crate::remote_control::NewWindowRequest {
                project_id: "p".into(),
                name: "Blocked".into(),
                cwd: None,
                agent: Some("terminal".into()),
                launch_flags: None,
                now_ms: 5,
            }),
            Err(crate::remote_control::NewWindowError::DaemonUnavailable)
        );
        assert!(rx.try_recv().is_err());
        assert!(maestro_shell::store::load_all::<maestro_shell::Workspace>(
            &paths,
            maestro_shell::RecordKind::Workspace
        )
        .unwrap()
        .is_empty());
        assert!(
            maestro_shell::store::load_all::<maestro_shell::SessionRecord>(
                &paths,
                maestro_shell::RecordKind::Session
            )
            .unwrap()
            .is_empty()
        );
        assert!(
            maestro_shell::store::load_all::<maestro_shell::WindowLayout>(
                &paths,
                maestro_shell::RecordKind::WindowLayout
            )
            .unwrap()
            .is_empty()
        );
        assert!(maestro_shell::ProjectService::new(&paths)
            .load("p")
            .unwrap()
            .unwrap()
            .window_order
            .is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn attach_only_project_create_is_atomic_but_metadata_update_remains_allowed() {
        let dir =
            std::env::temp_dir().join(format!("hydra-v1-project-gate-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = maestro_shell::AppPaths::with_base(dir.join("Maestro"));
        let (tx, mut rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let mut editor = DaemonProjectEditor {
            tx,
            sessions: Arc::new(Mutex::new(SessionCache::default())),
            paths: paths.clone(),
        };
        let blocked = crate::remote_control::ProjectEditRequest {
            project_id: None,
            name: Some("Blocked".into()),
            root: Some("/tmp/blocked".into()),
            icon: None,
            accent_color: None,
            agent: Some("terminal".into()),
            resume_mode: None,
            resume_session_id: None,
            model: None,
            dangerous: None,
            custom_command: None,
            directories: None,
            now_ms: 5,
        };
        assert_eq!(
            editor.create_project(blocked),
            Err(crate::remote_control::ProjectEditError::Internal)
        );
        assert!(rx.try_recv().is_err());
        assert!(maestro_shell::store::load_all::<maestro_shell::Project>(
            &paths,
            maestro_shell::RecordKind::Project
        )
        .unwrap()
        .is_empty());

        maestro_shell::ProjectService::new(&paths)
            .create(
                "existing",
                "Before",
                "/tmp/existing",
                maestro_shell::NewProject::default(),
                6,
            )
            .unwrap();
        let updated = editor
            .update_project(crate::remote_control::ProjectEditRequest {
                project_id: Some("existing".into()),
                name: Some("After".into()),
                root: None,
                icon: None,
                accent_color: None,
                agent: None,
                resume_mode: None,
                resume_session_id: None,
                model: None,
                dangerous: None,
                custom_command: None,
                directories: None,
                now_ms: 7,
            })
            .expect("metadata-only update needs no daemon mutation");
        assert_eq!(updated.project_id, "existing");
        assert_eq!(
            maestro_shell::ProjectService::new(&paths)
                .load("existing")
                .unwrap()
                .unwrap()
                .name,
            "After"
        );
        assert!(rx.try_recv().is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remote_split_lists_the_new_session_live_immediately_even_after_a_stale_sessions_event() {
        // The "must click locally" root, both halves:
        //  (a) the created SessionRecord is Live (not Unknown), so live_session_ids_from_dashboard counts
        //      it without waiting for the desktop's liveness repair;
        //  (b) the daemon-cache reservation survives a STALE daemon Sessions event that doesn't name the
        //      new id (merge, don't replace).
        use crate::remote_control::PaneSplitter;
        let dir = std::env::temp_dir().join(format!(
            "hydra-split-immediate-live-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = seed_split_fixture(&dir);
        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let _daemon = install_conditional_start_test_daemon(&tx);
        let sessions = Arc::new(Mutex::new(SessionCache::seeded_with_daemon_protocol(
            vec!["s-a".into()],
            Some(maestro_protocol::DAEMON_PROTOCOL_VERSION),
            true,
            true,
            true,
            true,
            true,
        )));
        let mut splitter = DaemonPaneSplitter {
            tx: tx.clone(),
            sessions: sessions.clone(),
            paths: paths.clone(),
        };

        let created = splitter
            .split_pane(crate::remote_control::SplitPaneRequest {
                window_id: "win-main".into(),
                from_pane_id: "pane-a".into(),
                dir: crate::remote_control::SplitPaneDir::Right,
                agent: Some("claude".into()),
                launch_flags: None,
                cwd: None,
                pane_name: None,
                now_ms: 5,
            })
            .unwrap();

        // (a) the record is written Live → the SQLite dashboard truth lists it immediately.
        let record = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &created.session_id,
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(s) => s,
            _ => panic!("session should load"),
        };
        assert_eq!(record.status, maestro_shell::SessionStatus::Live);
        assert!(
            live_session_ids_from_dashboard(&paths).contains(&created.session_id),
            "dashboard-live merge must count the just-created session without a liveness repair"
        );

        // (b) a STALE daemon Sessions event (snapshotted before the split) arrives — exactly what the
        // reader task applies. It must NOT evict the reservation.
        sessions
            .lock()
            .unwrap()
            .apply_daemon_ids(vec!["s-a".into()]);
        let backend = DaemonBackend {
            tx,
            sessions: sessions.clone(),
            session_metadata: Arc::new(Mutex::new(Vec::new())),
            dashboard_paths: Some(paths),
            raw_output: Arc::new(AtomicBool::new(false)),
            output_routes: Arc::new(Mutex::new(DaemonOutputRoutes::new(false))),
            pending_attach_sizes: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
        };
        assert!(
            backend.list_sessions().contains(&created.session_id),
            "the agent must not deny a session it just created after a stale Sessions event"
        );
        assert!(
            sessions
                .lock()
                .unwrap()
                .snapshot()
                .contains(&created.session_id),
            "the daemon-cache reservation must survive the stale Sessions event on its own"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn split_commit_push_payload_carries_the_new_session_live_within_one_poll_cycle() {
        // PATCH 3 verification — why the trace showed NO workspace_update after a split's DB commit, and
        // what fires it now. Two findings pinned here:
        //
        // (1) SQLite's `PRAGMA data_version` moves only for commits by a DIFFERENT connection, and the
        //     agent's own creation writes go through the SAME cached conn_for handle the shared watcher
        //     polls — so the data_version watcher is BLIND to the agent's own split commit (asserted
        //     below). The wake that catches a remote-triggered creation is the per-connection
        //     LIVE_SESSION_POLL_INTERVAL tick (remote_peer), which re-evaluates the payload every second
        //     regardless of DB commits.
        //
        // (2) That poll only pushes when the payload BYTE-DIFFERS — and before PATCH 2 it never did: the
        //     Unknown record + the evicted daemon-cache reservation kept the new pane redacted forever, so
        //     every re-evaluation converged to the same non-live bytes and no push followed until the
        //     desktop's liveness repair (a local click) rewrote the record. With PATCH 2 the recomputed
        //     payload differs immediately after the commit and carries the pane's session id LIVE (listed
        //     in `sessions`, unredacted in metadata) — so the next poll cycle pushes an attachable pane,
        //     no local click required. PATCH 2 alone is what makes the push fire.
        use crate::remote_control::PaneSplitter;
        let dir = std::env::temp_dir().join(format!(
            "hydra-split-push-payload-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = seed_split_fixture(&dir);
        let (tx, _rx) =
            daemon_request_channel(DAEMON_REQUEST_QUEUE_CAP, DAEMON_REQUEST_QUEUE_BYTE_CAP);
        let _daemon = install_conditional_start_test_daemon(&tx);
        let sessions = Arc::new(Mutex::new(SessionCache::seeded_with_daemon_protocol(
            vec!["s-a".into()],
            Some(maestro_protocol::DAEMON_PROTOCOL_VERSION),
            true,
            true,
            true,
            true,
            true,
        )));
        let backend = DaemonBackend {
            tx,
            sessions: sessions.clone(),
            session_metadata: Arc::new(Mutex::new(Vec::new())),
            dashboard_paths: Some(paths.clone()),
            raw_output: Arc::new(AtomicBool::new(false)),
            output_routes: Arc::new(Mutex::new(DaemonOutputRoutes::new(false))),
            pending_attach_sizes: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
        };
        // The splitter the control channel would use — derived from the SAME backend (shared cache + tx).
        let mut splitter = backend.pane_splitter().expect("dashboard paths present");
        let bridge = crate::remote_bridge::TerminalBridge::new(
            backend,
            crate::remote_policy::SameAsLocalPolicy,
            crate::remote_token::TokenClaims {
                account_id: "acct".into(),
                device_id: "dev_a".into(),
                session_id: None,
                signal_session_id: None,
                target_device_id: None,
                browser_pubkey: None,
                browser_pubkey_alg: None,
                refresh_parent_sha256: None,
                iat_ms: 0,
                exp_ms: 1_000_000,
            },
        );

        let baseline = bridge
            .workspace_push_payload()
            .expect("listing allowed → payload present");
        let baseline_bytes = serde_json::to_string(&baseline).unwrap();
        let v0 = maestro_shell::db::data_version_for(paths.base())
            .expect("store exists → data_version readable");

        let created = splitter
            .split_pane(crate::remote_control::SplitPaneRequest {
                window_id: "win-main".into(),
                from_pane_id: "pane-a".into(),
                dir: crate::remote_control::SplitPaneDir::Right,
                agent: Some("claude".into()),
                launch_flags: None,
                cwd: None,
                pane_name: Some("Split pane".into()),
                now_ms: 5,
            })
            .unwrap();
        // Adversarial: a stale daemon Sessions event lands right after the commit (reader-task behavior).
        sessions
            .lock()
            .unwrap()
            .apply_daemon_ids(vec!["s-a".into()]);

        // (1) the agent's OWN commit does NOT move data_version on the cached connection (same-connection
        // rule) — documenting that the DB-commit watcher cannot be the wake for remote-triggered
        // creations; the 1s session poll is. If this ever starts failing, the watcher gained same-process
        // visibility and this comment (plus the poll's justification) should be revisited.
        let v1 = maestro_shell::db::data_version_for(paths.base()).unwrap();
        assert_eq!(
            v0, v1,
            "data_version is connection-local: the agent's own commit must not bump it"
        );

        // (2) the recomputed payload differs from the baseline (the poll-cycle byte-diff FIRES a
        // workspace_update)…
        let pushed = bridge
            .workspace_push_payload()
            .expect("still allowed to list");
        let pushed_bytes = serde_json::to_string(&pushed).unwrap();
        assert_ne!(
            baseline_bytes, pushed_bytes,
            "the push payload must change after a split commit"
        );
        // …and the push carries the new pane's session LIVE: listed and unredacted (attachable).
        let (live_ids, _meta, workspace) = pushed;
        assert!(
            live_ids.contains(&created.session_id),
            "pushed `sessions` must list the just-created session as live"
        );
        let workspace = workspace.expect("workspace metadata present");
        let pane = workspace
            .projects
            .iter()
            .flat_map(|p| p.windows.iter())
            .flat_map(|w| w.panes.iter())
            .find(|pane| pane.id == created.tab_id)
            .expect("the split pane appears in the pushed workspace metadata");
        assert_eq!(
            pane.session_id, created.session_id,
            "the split pane must not be redacted in the push"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
