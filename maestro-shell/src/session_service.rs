//! Record-backed one-session start/attach and reconciliation between durable records
//! (`store` + `records`) and the [`DaemonClient`].
//!
//! This is the first place the shell's PRODUCT state (a durable [`SessionRecord`]) and the daemon's
//! RUNTIME state (a live PTY behind an opaque `SessionId`) are reconciled. The contract is
//! deliberately small and crash-safe:
//!
//! - **Record-before-daemon.** [`SessionService::start_and_attach`] persists the `SessionRecord`
//!   with `status: Unknown` BEFORE it asks the daemon to start anything. If the process dies between
//!   the daemon spawning a PTY and us learning it went live, the next run still finds the record and
//!   reconciliation ([`SessionService::reconcile`]) repairs its status from the daemon's live set —
//!   rather than orphaning a running session we have no record of.
//! - **Retained attach is mutation-free.** [`SessionService::attach_existing`] first proves an
//!   already-retained grid without sending `StartSession`, then refreshes or adopts local metadata.
//!   This lets a newer GUI reopen sessions owned by an older attach-compatible daemon.
//! - **Liveness is only ever claimed on proof.** A record is marked `Live` only after the daemon
//!   delivers the grid baseline ([`AttachedSession`]). A daemon error, an immediate session exit, or
//!   a start failure NEVER flips a record to `Live`; the prewritten record is kept as-is (`Unknown`)
//!   or moved to `Exited` only when the daemon actually reports the session ended.
//! - **Secret-aware launch.** The service takes an already-built [`LaunchSpec`]; it never accepts or
//!   persists raw unredacted ad-hoc argv. An optional convenience constructor routes an ad-hoc argv
//!   through the existing `redact::adhoc_launch_spec` before it is ever stored.
//!
//! Out of scope here (and enforced by NOT depending on them): no daemon spawning/lifecycle, no PTY
//! attach, no git, no worktree, no scratch-dir creation, no tabs/AgentTask invention, no writes
//! outside the injected app-support base.

// Start/publication errors intentionally retain consume-once receipts and recovery authorities.
#![allow(
    clippy::large_enum_variant,
    clippy::result_large_err,
    clippy::too_many_arguments
)]

use crate::daemon_client::{
    AttachmentHandoffAuthority, AttachmentHandoffFailure, AttachmentHandoffSeed,
    ConditionalStartGridRecovery, ConditionalStartPeerIdentity, ConditionalStartRecovery,
    ConditionalStartRecoveryAuthority, DaemonClient, DaemonClientError,
    GenerationConditionalRendererAttach,
};
use crate::launch_environment::LaunchEnvLookup;
use crate::paths::{AppPaths, RecordKind};
use crate::records::{AgentTask, LaunchSpec, SessionKind, SessionRecord, SessionStatus, Workspace};
use crate::reserved_product_shell::ReservedProductShellStart;
use crate::session_release::{SessionReleaseTarget, SessionRowPolicy};
use crate::store::{self, LoadOutcome, StoreError};
use crate::window_layout::{
    PreparedAgentTaskPublication, PreparedAgentTaskSessionCompensation,
    PreparedAgentTaskSessionStart, PreparedNewSessionCompensationReceipt, PreparedNewSessionStart,
    WindowLayoutService,
};
use maestro_protocol::{
    SessionStartOperationLifecycle, SessionStartOperationRetireOutcome, SessionStartOperationStatus,
};

#[cfg(test)]
thread_local! {
    static RECONCILE_AFTER_SNAPSHOT_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
fn install_reconcile_after_snapshot_hook(hook: impl FnOnce() + 'static) {
    RECONCILE_AFTER_SNAPSHOT_HOOK.with(|slot| {
        *slot.borrow_mut() = Some(Box::new(hook));
    });
}

#[cfg(test)]
fn run_reconcile_after_snapshot_hook() {
    RECONCILE_AFTER_SNAPSHOT_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(not(test))]
fn run_reconcile_after_snapshot_hook() {}

/// Everything that can go wrong starting/attaching a record-backed session. Typed so a caller can
/// tell "the cwd was bad" (nothing was persisted, no daemon call) from "the daemon refused" (the
/// `Unknown` record is persisted) from "the session exited immediately" (the record is `Exited`).
#[derive(Debug)]
pub enum SessionServiceError {
    /// The cwd was not an existing directory. Returned BEFORE any record is written and BEFORE any
    /// daemon request — nothing is persisted, so there is no half-baked record to clean up.
    InvalidCwd { cwd: String },
    /// Persisting a record failed (IO / id validation / envelope). Carries the store error.
    Store(StoreError),
    /// The daemon answered with an error, or was unreachable, while starting/attaching. The
    /// `Unknown` record IS persisted (we could not prove liveness, but we also did not prove the
    /// session never existed), so reconciliation can later repair it.
    Daemon(DaemonClientError),
    /// The conditional Start crossed its publication boundary, but the bounded exact-peer
    /// acknowledgement/lookup recovery could not prove its final state. Durable A/Unknown remains
    /// untouched. The opaque authority retains the exact reviewed connection, operation token,
    /// daemon instance, and any pending renderer handoff for later exact cancellation/repair.
    ConditionalStartPossiblyApplied {
        session_id: String,
        authority: ConditionalStartRecoveryAuthority,
        source: Box<SessionServiceError>,
    },
    /// A lower-level caller borrowed the daemon client, so the exact operation facts cannot yet be
    /// joined to an owning recovery authority. Runtime owners must bind this error to that same
    /// reviewed client before reducing it to text or dropping it.
    UnboundConditionalStartPossiblyApplied {
        session_id: String,
        recovery: ConditionalStartRecovery,
        source: Box<SessionServiceError>,
    },
    /// A renderer handoff was installed, but a later durable-finalization failure could not obtain
    /// an exact typed cancellation acknowledgement before the shared deadline. The authority keeps
    /// the reviewed daemon connection and token alive; dropping it is a conservative daemon-side
    /// safe pin, never permission to rediscover another socket and cancel there.
    AttachmentHandoffPossiblyPending {
        session_id: String,
        authority: AttachmentHandoffAuthority,
        source: Box<SessionServiceError>,
    },
    /// A Grid proved a daemon lifetime, but the complete Session row written before Start changed
    /// or disappeared before that lifetime could be published durably.  The caller must drop (and,
    /// when applicable, cancel) its attachment/handoff authority; stale launch bytes are never
    /// allowed to recreate the row over a concurrent destructive transaction.
    AttachAuthorityLost { session_id: String },
}

impl std::fmt::Display for SessionServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionServiceError::InvalidCwd { .. } => {
                f.write_str("cwd is not an existing directory")
            }
            SessionServiceError::Store(e) => write!(f, "session store error: {e}"),
            SessionServiceError::Daemon(e) => write!(f, "session daemon error: {e}"),
            SessionServiceError::ConditionalStartPossiblyApplied { session_id, .. }
            | SessionServiceError::UnboundConditionalStartPossiblyApplied { session_id, .. } => {
                write!(
                    f,
                    "conditional session start may have been applied for {session_id:?}"
                )
            }
            SessionServiceError::AttachmentHandoffPossiblyPending { session_id, .. } => write!(
                f,
                "renderer attachment handoff may remain pending for {session_id:?}"
            ),
            SessionServiceError::AttachAuthorityLost { session_id } => write!(
                f,
                "session attach authority changed before finalization: {session_id:?}"
            ),
        }
    }
}

impl std::error::Error for SessionServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SessionServiceError::Store(e) => Some(e),
            SessionServiceError::Daemon(e) => Some(e),
            SessionServiceError::ConditionalStartPossiblyApplied { source, .. } => Some(source),
            SessionServiceError::UnboundConditionalStartPossiblyApplied { source, .. } => {
                Some(source)
            }
            SessionServiceError::AttachmentHandoffPossiblyPending { source, .. } => Some(source),
            SessionServiceError::InvalidCwd { .. }
            | SessionServiceError::AttachAuthorityLost { .. } => None,
        }
    }
}

impl SessionServiceError {
    pub(crate) fn bind_conditional_start_recovery(self, mut client: DaemonClient) -> Self {
        match self {
            SessionServiceError::Daemon(DaemonClientError::ConditionalStartPossiblyApplied {
                id,
                recovery,
                source,
            }) => {
                client.finish_generation_mutation();
                SessionServiceError::ConditionalStartPossiblyApplied {
                    session_id: id.0,
                    authority: ConditionalStartRecoveryAuthority::new(recovery, client),
                    source: Box::new(SessionServiceError::Daemon(*source)),
                }
            }
            SessionServiceError::UnboundConditionalStartPossiblyApplied {
                session_id,
                recovery,
                source,
            } => {
                client.finish_generation_mutation();
                SessionServiceError::ConditionalStartPossiblyApplied {
                    session_id,
                    authority: ConditionalStartRecoveryAuthority::new(recovery, client),
                    source,
                }
            }
            other => other,
        }
    }

    fn preserve_conditional_start_recovery(self, recovery: ConditionalStartRecovery) -> Self {
        SessionServiceError::UnboundConditionalStartPossiblyApplied {
            session_id: recovery.session_id().0.clone(),
            recovery,
            source: Box::new(self),
        }
    }

    fn bind_owned_attach_failure(
        failure: SessionAttachFailure,
        mut client: DaemonClient,
        session_id: &str,
    ) -> SessionServiceError {
        client.finish_generation_mutation();
        match failure.pending_handoff {
            Some(seed) => SessionServiceError::AttachmentHandoffPossiblyPending {
                session_id: session_id.to_string(),
                authority: AttachmentHandoffAuthority::from_offer(seed, client),
                source: Box::new(failure.error),
            },
            None => failure.error.bind_conditional_start_recovery(client),
        }
    }
}

impl From<StoreError> for SessionServiceError {
    fn from(e: StoreError) -> Self {
        SessionServiceError::Store(e)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExistingSessionStartMode {
    /// The reviewed daemon still retains exact exited generation A.
    ReplaceExited,
    /// A reviewed fresh daemon proved the id absent; A exists only in the durable row.
    FreshDaemonAbsent,
}

struct SessionAttachFailure {
    error: SessionServiceError,
    pending_handoff: Option<AttachmentHandoffSeed>,
}

impl SessionAttachFailure {
    fn new(error: SessionServiceError) -> Self {
        Self {
            error,
            pending_handoff: None,
        }
    }

    fn with_pending_handoff(
        error: SessionServiceError,
        pending_handoff: Option<AttachmentHandoffSeed>,
    ) -> Self {
        Self {
            error,
            pending_handoff,
        }
    }
}

impl From<SessionServiceError> for SessionAttachFailure {
    fn from(error: SessionServiceError) -> Self {
        Self::new(error)
    }
}

impl From<StoreError> for SessionAttachFailure {
    fn from(error: StoreError) -> Self {
        Self::new(SessionServiceError::Store(error))
    }
}

/// The inputs to start ONE record-backed session. The `cwd` MUST already be an existing directory
/// (a caller-supplied safe cwd, or one resolved by `policy::resolved_cwd`); this service NEVER
/// creates it. The `launch` is an already-built, secret-aware [`LaunchSpec`].
#[derive(Clone)]
pub struct StartParams {
    /// The opaque id used BOTH as the durable record's `session_id` AND as the daemon `SessionId`.
    pub session_id: String,
    /// FK to the owning workspace record.
    pub workspace_id: String,
    pub kind: SessionKind,
    /// Already-redacted/secret-aware launch description (see [`StartParams::adhoc`]).
    pub launch: LaunchSpec,
    /// An EXISTING directory. Used verbatim as the daemon `StartSession` cwd and stored as
    /// `cwd_resolved`.
    pub cwd: String,
    /// The command + args actually handed to the daemon. Kept separate from `launch` because the
    /// daemon needs the real argv to spawn, while `launch` is the persisted (possibly redacted)
    /// description. The caller is responsible for not putting secrets the record shouldn't hold into
    /// `launch`; the live argv here is never persisted by this service.
    pub command: String,
    pub args: Vec<String>,
    pub cols: u16,
    pub rows: u16,
    /// Optional FK to an `AgentTask` this session serves. This service does NOT create or mutate
    /// AgentTask records — it only stores the FK if given.
    pub agent_task_id: Option<String>,
    /// Wall-clock millis to stamp `created_at_ms` / initial `last_attached_at_ms`.
    pub now_ms: u64,
}

/// Successful publication of one transaction-prepared Session. The exact compensation receipt
/// is the Live(G)-rebased successor minted by the same final writer transaction; neither value is
/// cloneable through this aggregate.
pub struct PreparedNewSessionStarted {
    record: SessionRecord,
    compensation: PreparedNewSessionCompensationReceipt,
    agent_task: Option<AgentTask>,
}

impl PreparedNewSessionStarted {
    pub fn record(&self) -> &SessionRecord {
        &self.record
    }

    pub fn agent_task(&self) -> Option<&AgentTask> {
        self.agent_task.as_ref()
    }

    pub fn into_parts(self) -> (SessionRecord, PreparedNewSessionCompensationReceipt) {
        (self.record, self.compensation)
    }
}

impl std::fmt::Debug for PreparedNewSessionStarted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedNewSessionStarted")
            .field("session_id", &self.record.session_id)
            .field(
                "generation_present",
                &self.record.last_known_generation.is_some(),
            )
            .field("compensation", &self.compensation)
            .finish_non_exhaustive()
    }
}

/// Every consuming prepared-start failure owns an explicit durable disposition. Only zero-wire
/// failures return retryable Prepared authority; a typed daemon refusal burns retry authority and
/// returns compensation-only ownership; ambiguous/applied paths grant neither rollback nor retry.
pub enum PreparedNewSessionStartError {
    DefinitelyUnpublished {
        error: SessionServiceError,
        start: PreparedNewSessionStart,
    },
    Refused {
        error: SessionServiceError,
        compensation: PreparedNewSessionCompensationReceipt,
    },
    PossiblyApplied {
        error: SessionServiceError,
    },
}

/// Consume-once recovery authority for one task-aware conditional Start whose daemon publication
/// and durable Session+AgentTask finalization could not be observed as one terminal result.
///
/// It joins the exact operation-token/same-peer proof to the sealed durable A -> B graph. Neither
/// half is independently accessible, so callers cannot retry Start, compensate an ambiguous
/// lifetime, or combine the daemon proof with a different Task/Session.
pub struct PreparedAgentTaskPublicationRecoveryAuthority {
    start: PreparedAgentTaskSessionStart,
    daemon: ConditionalStartRecoveryAuthority,
}

impl PreparedAgentTaskPublicationRecoveryAuthority {
    pub fn session_id(&self) -> &str {
        self.start.session_id()
    }

    pub fn agent_task_id(&self) -> &str {
        self.start.agent_task_id()
    }

    fn new(
        start: PreparedAgentTaskSessionStart,
        daemon: ConditionalStartRecoveryAuthority,
    ) -> Self {
        debug_assert_eq!(start.session_id(), daemon.session_id().0);
        Self { start, daemon }
    }
}

impl std::fmt::Debug for PreparedAgentTaskPublicationRecoveryAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedAgentTaskPublicationRecoveryAuthority")
            .field("session_id", &self.session_id())
            .field("agent_task_id", &self.agent_task_id())
            .field(
                "applied_generation_known",
                &self.daemon.applied_generation().is_some(),
            )
            .finish_non_exhaustive()
    }
}

pub(crate) enum PreparedAgentTaskSessionStartError {
    DefinitelyUnpublished {
        error: SessionServiceError,
        start: PreparedAgentTaskSessionStart,
    },
    Refused {
        error: SessionServiceError,
        compensation: PreparedAgentTaskSessionCompensation,
    },
    PossiblyApplied {
        error: SessionServiceError,
        recovery: PreparedAgentTaskPublicationRecoveryAuthority,
    },
}

pub(crate) enum PreparedAgentTaskPublicationSettlement {
    Published(PreparedNewSessionStarted),
    Pending {
        recovery: PreparedAgentTaskPublicationRecoveryAuthority,
        error: Option<SessionServiceError>,
    },
    Changed {
        recovery: PreparedAgentTaskPublicationRecoveryAuthority,
        error: SessionServiceError,
    },
}

enum PreparedAgentTaskFinalize {
    Published(PreparedNewSessionStarted),
    Changed,
}

impl PreparedNewSessionStartError {
    pub fn error(&self) -> &SessionServiceError {
        match self {
            Self::DefinitelyUnpublished { error, .. }
            | Self::Refused { error, .. }
            | Self::PossiblyApplied { error } => error,
        }
    }
}

impl std::fmt::Debug for PreparedNewSessionStartError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DefinitelyUnpublished { error, start } => formatter
                .debug_struct("PreparedNewSessionStartError::DefinitelyUnpublished")
                .field("error", error)
                .field("start", start)
                .finish(),
            Self::Refused {
                error,
                compensation,
            } => formatter
                .debug_struct("PreparedNewSessionStartError::Refused")
                .field("error", error)
                .field("compensation", compensation)
                .finish(),
            Self::PossiblyApplied { error } => formatter
                .debug_struct("PreparedNewSessionStartError::PossiblyApplied")
                .field("error", error)
                .finish(),
        }
    }
}

/// Caller-reviewed durable authority for a start against a newly-created daemon instance.
///
/// The distinction is deliberate: an existing Session may only be replaced after its complete
/// Session and Workspace rows are revalidated, while a new Session may only use the exact
/// Workspace bytes the caller intended before daemon publication. In particular, the service
/// never discovers an encountered Workspace after the daemon starts and treats those bytes as the
/// caller's desired authority.
#[derive(Clone, Copy)]
pub enum FreshDaemonSessionStart<'a> {
    Existing {
        start: &'a ExistingSessionStart,
    },
    ReservedProductShell {
        start: &'a ReservedProductShellStart,
    },
    New {
        workspace: &'a Workspace,
    },
}

/// Optional replay authority consumed only after an exact retained Attach proves `Missing` (or
/// durable A has no generation and therefore skips Attach), or by an explicit reviewed headless
/// revive of exact exited generation A. Every variant is an opaque execution bundle. The explicit
/// shell variant is renderer-only and launches the separately reviewed fallback shell rather than
/// replaying an unknown prior command; it never widens automatic or headless `OptOut` replay.
#[derive(Clone, Copy)]
pub enum ExistingSessionMissingStart<'a> {
    KnownSafe(&'a ExistingSessionStart),
    ExplicitUserShell(&'a ExistingSessionStart),
    ReservedProductShell(&'a ReservedProductShellStart),
}

impl<'a> ExistingSessionMissingStart<'a> {
    fn session(&self) -> &SessionRecord {
        match self {
            Self::KnownSafe(start) | Self::ExplicitUserShell(start) => &start.session,
            Self::ReservedProductShell(start) => start.session(),
        }
    }

    fn workspace(&self) -> &Workspace {
        match self {
            Self::KnownSafe(start) | Self::ExplicitUserShell(start) => &start.workspace,
            Self::ReservedProductShell(start) => start.workspace(),
        }
    }

    fn params(&self) -> &StartParams {
        match self {
            Self::KnownSafe(start) | Self::ExplicitUserShell(start) => start.params(),
            Self::ReservedProductShell(start) => start.params(),
        }
    }

    pub(crate) fn reserved(self) -> Option<&'a ReservedProductShellStart> {
        match self {
            Self::KnownSafe(_) | Self::ExplicitUserShell(_) => None,
            Self::ReservedProductShell(start) => Some(start),
        }
    }
}

/// Caller-reviewed authority for replacing or recreating one existing durable Session. It owns the
/// complete Session A, Workspace W, and exact live [`StartParams`] as one indivisible proof bundle:
/// callers cannot validate one argv/cwd tuple and later send another. This checkpoint preserves
/// every durable identity byte, including A's launch and cwd; reviewed launch migration needs a
/// separate non-forgeable policy proof and is deliberately declined here.
#[derive(Clone)]
pub struct ExistingSessionStart {
    session: SessionRecord,
    workspace: Workspace,
    params: StartParams,
    scope: ExistingSessionStartScope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExistingSessionStartScope {
    ExactConversation,
    ExplicitUserLatest,
    ExplicitUserShell,
}

/// Immutable durable authority for resolving one existing durable row. Unlike Start authority it
/// carries no execution tuple: it proves complete Session A + Workspace W. A valid durable
/// generation permits daemon-atomic Attach; `None` permits only a same-client conditional
/// `Absent(None)` start when a separate [`ExistingSessionStart`] is supplied. It never permits an
/// id-only Attach or adoption of an encountered daemon generation.
#[derive(Clone)]
pub struct ExistingSessionAttach {
    session: SessionRecord,
    workspace: Workspace,
    now_ms: u64,
}

impl ExistingSessionAttach {
    pub fn exact(
        session: &SessionRecord,
        workspace: &Workspace,
        now_ms: u64,
    ) -> Result<Self, SessionServiceError> {
        let valid_generation = session
            .last_known_generation
            .as_deref()
            .is_none_or(|generation| !generation.is_empty() && generation.len() <= 128);
        if workspace.workspace_id != session.workspace_id || !valid_generation {
            return Err(SessionServiceError::AttachAuthorityLost {
                session_id: session.session_id.clone(),
            });
        }
        Ok(Self {
            session: session.clone(),
            workspace: workspace.clone(),
            now_ms,
        })
    }

    pub(crate) fn session_id(&self) -> &str {
        &self.session.session_id
    }

    pub(crate) fn now_ms(&self) -> u64 {
        self.now_ms
    }
}

pub(crate) struct RetainedDaemonAbsentStartAuthority {
    client: DaemonClient,
    session: SessionRecord,
    workspace: Workspace,
    peer: ConditionalStartPeerIdentity,
}

pub(crate) enum ExactExistingAttach {
    Attached(SessionRecord, Option<AttachmentHandoffAuthority>),
    StartIfAbsent(RetainedDaemonAbsentStartAuthority),
}

impl ExistingSessionStart {
    /// Build the only currently authorized existing-row execution: one exact retained KnownSafe
    /// provider conversation. Live argv is derived here from durable A rather than accepted from a
    /// caller, so metadata and executed bytes cannot diverge. Ad-hoc, OptOut, ambiguous/latest, and
    /// legacy migration recipes fail closed.
    pub fn known_safe_exact(
        session: &SessionRecord,
        workspace: &Workspace,
        env: &impl LaunchEnvLookup,
        cols: u16,
        rows: u16,
        now_ms: u64,
    ) -> Result<Self, SessionServiceError> {
        let session_id = session.session_id.clone();
        if workspace.workspace_id != session.workspace_id
            || !crate::restart_recipe::known_safe_provider_has_exact_resume(&session.launch)
        {
            return Err(SessionServiceError::AttachAuthorityLost { session_id });
        }
        let argv =
            crate::launch_environment::known_safe_provider_login_shell_argv(&session.launch, env)
                .ok_or_else(|| SessionServiceError::AttachAuthorityLost {
                session_id: session.session_id.clone(),
            })?;
        let (command, args) =
            argv.split_first()
                .ok_or_else(|| SessionServiceError::AttachAuthorityLost {
                    session_id: session.session_id.clone(),
                })?;
        let params = StartParams {
            session_id: session.session_id.clone(),
            workspace_id: session.workspace_id.clone(),
            kind: session.kind,
            launch: session.launch.clone(),
            cwd: session.cwd_resolved.clone(),
            command: command.clone(),
            args: args.to_vec(),
            cols,
            rows,
            agent_task_id: session.agent_task_id.clone(),
            now_ms,
        };
        Ok(Self {
            session: session.clone(),
            workspace: workspace.clone(),
            params,
            scope: ExistingSessionStartScope::ExactConversation,
        })
    }

    /// Build a complete existing-row execution bundle for an explicit user `Reopen` action.
    ///
    /// Unlike [`Self::known_safe_exact`], this checkpoint may accept a current Hydra-authored
    /// provider recipe whose reviewed meaning is explicitly non-exact (`claude --continue`,
    /// `codex resume --last`, and provider equivalents). Those recipes cannot identify one exact
    /// provider conversation, so callers must never use this constructor for automatic startup or
    /// reboot recovery. The durable Session+Workspace bytes, cwd, provider grammar, and executed
    /// argv remain sealed exactly; arbitrary commands, wrappers, unknown flags, and legacy ad-hoc
    /// records still fail closed.
    pub fn known_safe_explicit_user_restart(
        session: &SessionRecord,
        workspace: &Workspace,
        env: &impl LaunchEnvLookup,
        cols: u16,
        rows: u16,
        now_ms: u64,
    ) -> Result<Self, SessionServiceError> {
        let session_id = session.session_id.clone();
        let LaunchSpec::KnownSafe {
            launch_spec_id,
            params,
        } = &session.launch
        else {
            return Err(SessionServiceError::AttachAuthorityLost { session_id });
        };
        let mut provider_argv = Vec::with_capacity(1 + params.len());
        provider_argv.push(launch_spec_id.clone());
        provider_argv.extend(params.iter().cloned());
        let valid_generation = session
            .last_known_generation
            .as_deref()
            .is_some_and(|generation| !generation.is_empty() && generation.len() <= 128);
        if session.kind != SessionKind::Agent
            || session.status != SessionStatus::Exited
            || !valid_generation
            || workspace.workspace_id != session.workspace_id
            || !crate::restart_recipe::is_strict_prepared_provider_launch(
                launch_spec_id,
                &provider_argv,
            )
        {
            return Err(SessionServiceError::AttachAuthorityLost { session_id });
        }
        let argv =
            crate::launch_environment::known_safe_provider_login_shell_argv(&session.launch, env)
                .ok_or_else(|| SessionServiceError::AttachAuthorityLost {
                session_id: session.session_id.clone(),
            })?;
        let (command, args) =
            argv.split_first()
                .ok_or_else(|| SessionServiceError::AttachAuthorityLost {
                    session_id: session.session_id.clone(),
                })?;
        let params = StartParams {
            session_id: session.session_id.clone(),
            workspace_id: session.workspace_id.clone(),
            kind: session.kind,
            launch: session.launch.clone(),
            cwd: session.cwd_resolved.clone(),
            command: command.clone(),
            args: args.to_vec(),
            cols,
            rows,
            agent_task_id: session.agent_task_id.clone(),
            now_ms,
        };
        Ok(Self {
            session: session.clone(),
            workspace: workspace.clone(),
            params,
            scope: if crate::restart_recipe::known_safe_provider_has_exact_resume(&session.launch) {
                ExistingSessionStartScope::ExactConversation
            } else {
                ExistingSessionStartScope::ExplicitUserLatest
            },
        })
    }

    /// Seal one fresh default-shell execution for an explicit user `Reopen` of an exited plain
    /// terminal pane. `OptOut` means the prior process argv is intentionally unavailable, so this
    /// constructor never attempts to replay it: the caller supplies the independently reviewed
    /// product/user-configured fallback shell argv. Automatic startup, fresh-daemon recovery, and
    /// every headless coordinator reject this scope; only the renderer's explicit Reopen path may
    /// consume it after the complete Session+Workspace and retained generation are revalidated.
    pub fn explicit_user_shell_restart(
        session: &SessionRecord,
        workspace: &Workspace,
        argv: Vec<String>,
        cols: u16,
        rows: u16,
        now_ms: u64,
    ) -> Result<Self, SessionServiceError> {
        let session_id = session.session_id.clone();
        let valid_generation = session
            .last_known_generation
            .as_deref()
            .is_some_and(|generation| !generation.is_empty() && generation.len() <= 128);
        let (command, args) = argv
            .split_first()
            .filter(|(command, _)| !command.trim().is_empty())
            .ok_or_else(|| SessionServiceError::AttachAuthorityLost {
                session_id: session_id.clone(),
            })?;
        if session.kind != SessionKind::Shell
            || session.launch != LaunchSpec::OptOut
            || session.status != SessionStatus::Exited
            || session.agent_task_id.is_some()
            || !valid_generation
            || workspace.workspace_id != session.workspace_id
            || !std::path::Path::new(&session.cwd_resolved).is_dir()
        {
            return Err(SessionServiceError::AttachAuthorityLost { session_id });
        }
        let params = StartParams {
            session_id: session.session_id.clone(),
            workspace_id: session.workspace_id.clone(),
            kind: session.kind,
            launch: session.launch.clone(),
            cwd: session.cwd_resolved.clone(),
            command: command.clone(),
            args: args.to_vec(),
            cols,
            rows,
            agent_task_id: None,
            now_ms,
        };
        Ok(Self {
            session: session.clone(),
            workspace: workspace.clone(),
            params,
            scope: ExistingSessionStartScope::ExplicitUserShell,
        })
    }

    pub(crate) fn params(&self) -> &StartParams {
        &self.params
    }

    fn has_exact_conversation_scope(&self) -> bool {
        self.scope == ExistingSessionStartScope::ExactConversation
    }
}

impl StartParams {
    /// Convenience for an AD-HOC launch: routes the raw argv through the existing redaction model so
    /// no unredacted secret-shaped token is ever persisted, and uses the same argv as the live
    /// command/args handed to the daemon. The FIRST token is the command; the rest are args.
    ///
    /// The persisted `launch` is `LaunchSpec::AdHocRedacted` (redacted, `restart_requires_user`);
    /// the live `command`/`args` are the UNREDACTED real tokens (needed to actually spawn), which
    /// this service passes to the daemon but never writes to a record.
    // Mirrors the durable `StartParams` field set (id, workspace, kind, cwd, argv, cols, rows, clock)
    // one-to-one; collapsing them into a struct would just duplicate `StartParams` itself.
    #[allow(clippy::too_many_arguments)]
    pub fn adhoc(
        session_id: impl Into<String>,
        workspace_id: impl Into<String>,
        kind: SessionKind,
        cwd: impl Into<String>,
        argv: &[String],
        cols: u16,
        rows: u16,
        now_ms: u64,
    ) -> Self {
        let launch = crate::redact::adhoc_launch_spec(argv);
        let (command, args) = match argv.split_first() {
            Some((cmd, rest)) => (cmd.clone(), rest.to_vec()),
            None => (String::new(), Vec::new()),
        };
        StartParams {
            session_id: session_id.into(),
            workspace_id: workspace_id.into(),
            kind,
            launch,
            cwd: cwd.into(),
            command,
            args,
            cols,
            rows,
            agent_task_id: None,
            now_ms,
        }
    }
}

/// One session's outcome after reconciliation. Reports what the record's status was changed TO and
/// whether a write happened, so a caller can log/surface the delta without re-reading.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconciledSession {
    pub session_id: String,
    pub status: SessionStatus,
    /// True if the record's status changed and it was written back.
    pub rewritten: bool,
}

/// Result of applying one renderer-observed daemon exit to a single durable session record.
///
/// This API is intentionally conservative: only an exact match between `observed_generation` and
/// the record's `last_known_generation` can change `Live`/`Unknown` to `Exited`. Every other outcome
/// is read-only, so a delayed exit from an older same-id process lifetime cannot retire a newer one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionExitObservation {
    /// Matching current generation was `Live` or `Unknown` and is now persisted as `Exited`.
    MarkedExited,
    /// The matching generation was already persisted as `Exited`; no write was needed.
    AlreadyExited,
    /// No session record exists for this id.
    Missing,
    /// The event had no proven generation, or it did not match the record's generation.
    GenerationMismatch,
    /// The record could not be decoded and was deliberately left untouched.
    Quarantined,
}

/// A live daemon session that has NO durable `SessionRecord` this build could load — an orphan
/// "recovered" session. Reconciliation only reports it; the native app's lifecycle policy may use
/// repeated complete dashboard snapshots to release it when no active or stashed pane represents
/// the id. Carries only the daemon-reported id: this build deliberately invents no metadata for a
/// session it never persisted.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RecoveredSession {
    pub session_id: String,
}

/// The result of a reconciliation pass: per-session outcomes, the live daemon ids that had no
/// loadable durable record (recovered/orphan sessions), plus the paths of records LEFT UNTOUCHED
/// because they came from a newer Maestro (future schema version). Those are never rewritten —
/// doing so could drop fields this build does not model.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    pub sessions: Vec<ReconciledSession>,
    /// Live daemon ids with no loaded current-version `SessionRecord`, sorted by `session_id`.
    /// Reconciliation itself only reports them and never writes, attaches, or kills. A caller may
    /// apply a separately fenced lifecycle policy. A future-version record for an id counts as "no
    /// loaded current-version record", so a live id whose only record is future-version is reported
    /// here (its bytes are still left untouched and listed in `skipped_future_version`).
    pub recovered_sessions: Vec<RecoveredSession>,
    /// Generation-bearing automatic-cleanup authority for the same recovered cohort. Kept out of
    /// dashboard JSON projection; lifecycle code requires two identical `(id,generation)`
    /// snapshots before it invokes the writer-fenced release path.
    pub recovered_session_targets: Vec<SessionReleaseTarget>,
    /// Exact generation-bearing authority for every live session in the same strict daemon
    /// snapshot, not only daemon-only rows. A loadable current Session row uses
    /// `MatchingRowIsProof`; daemon-only/future-version/unloadable rows use `RowMustBeAbsent`.
    /// Desktop orphan cleanup intersects these opaque targets with the complete dashboard orphan
    /// cohort across two snapshots instead of manufacturing mutation authority from ids.
    pub live_session_release_targets: Vec<SessionReleaseTarget>,
    /// Paths of future-version session records that were observed but deliberately not rewritten.
    pub skipped_future_version: Vec<std::path::PathBuf>,
}

/// Record-backed session operations over one injected app-support base. Holds no socket and no
/// daemon handle: each call takes the [`DaemonClient`] it needs, so the service owns persistence and
/// the caller owns the connection lifetime.
pub struct SessionService<'a> {
    paths: &'a AppPaths,
}

impl<'a> SessionService<'a> {
    pub fn new(paths: &'a AppPaths) -> Self {
        SessionService { paths }
    }

    /// Persist one generation-attributed exit observation without consulting the daemon's global
    /// live-set snapshot.
    ///
    /// `SessionExited` has no generation on the daemon wire, so the caller supplies the generation
    /// from its last accepted authoritative grid. The write is allowed only when that value exactly
    /// matches `SessionRecord::last_known_generation`. This makes the operation idempotent and safe
    /// against delayed events after a same-id restart. A missing observation (`None`) proves no
    /// lifetime and is therefore a no-op.
    pub fn observe_exit(
        &self,
        session_id: &str,
        observed_generation: Option<&str>,
        now_ms: u64,
    ) -> Result<SessionExitObservation, SessionServiceError> {
        let Some(observed_generation) = observed_generation else {
            return Ok(SessionExitObservation::GenerationMismatch);
        };

        let outcome = store::mark_session_exited_if_generation(
            self.paths,
            session_id,
            observed_generation,
            now_ms,
        )?;
        Ok(match outcome {
            store::ConditionalSessionExit::MarkedExited => SessionExitObservation::MarkedExited,
            store::ConditionalSessionExit::AlreadyExited => SessionExitObservation::AlreadyExited,
            store::ConditionalSessionExit::Missing => SessionExitObservation::Missing,
            store::ConditionalSessionExit::GenerationMismatch => {
                SessionExitObservation::GenerationMismatch
            }
            store::ConditionalSessionExit::Quarantined => SessionExitObservation::Quarantined,
        })
    }

    /// Persist a fresh `SessionRecord` with `status: Unknown`. The `session_id` is validated by the
    /// store (a traversing/illegal id is refused before any path is built). `cwd_resolved` is the
    /// caller-supplied cwd; `last_known_generation` is `None` until the daemon proves a grid.
    fn unknown_record(&self, params: &StartParams) -> Result<SessionRecord, StoreError> {
        // FK: sessions.workspace_id → workspaces (NOT NULL). In the JSON era an ad-hoc/scratch workspace_id (e.g.
        // "maestro-app-dev") could be referenced without a persisted Workspace row; SQLite's FK rejects that. Ensure a
        // minimal ad-hoc workspace (+ owning project) exists for this session's workspace_id before the write.
        self.ensure_workspace(&params.workspace_id, params.now_ms)?;
        Ok(SessionRecord {
            session_id: params.session_id.clone(),
            workspace_id: params.workspace_id.clone(),
            kind: params.kind,
            launch: params.launch.clone(),
            cwd_resolved: params.cwd.clone(),
            agent_task_id: params.agent_task_id.clone(),
            created_at_ms: params.now_ms,
            last_attached_at_ms: params.now_ms,
            last_known_generation: None,
            status: SessionStatus::Unknown,
        })
    }

    fn write_unknown_record(&self, params: &StartParams) -> Result<SessionRecord, StoreError> {
        let record = self.unknown_record(params)?;
        store::write_record(
            self.paths,
            RecordKind::Session,
            &params.session_id,
            params.now_ms,
            &record,
        )?;
        Ok(record)
    }

    /// Idempotently ensure a Workspace row exists for `workspace_id` so a session can reference it under the FK
    /// (`sessions.workspace_id → workspaces`). A workspace that's already persisted (the normal project-owned case) is
    /// left untouched. An ad-hoc/scratch id with no row is attached to an EXISTING project — NEVER a new "Scratch"
    /// project: the built-in "system-terminal" project (always bootstrapped) is preferred, else the first available
    /// project. If somehow NO project exists at all, none is invented here — the caller's session write will then
    /// surface a real FK error (the app bootstraps the Terminal project on launch, so this is not reached in practice).
    fn ensure_workspace(&self, workspace_id: &str, now_ms: u64) -> Result<(), StoreError> {
        // Already persisted → nothing to do (don't clobber a real project-owned workspace).
        if matches!(
            store::load_one::<crate::records::Workspace>(
                self.paths,
                RecordKind::Workspace,
                workspace_id
            ),
            Ok(Some(crate::store::LoadOutcome::Loaded(_)))
        ) {
            return Ok(());
        }
        // Attach to an existing project — the built-in Terminal if present, else the first project. No new project.
        let Some(owner_project_id) = self.adhoc_owner_project() else {
            return Ok(()); // no project to own it — let the session write surface the FK error (shouldn't happen)
        };
        let workspace = crate::records::Workspace {
            workspace_id: workspace_id.to_string(),
            project_id: owner_project_id,
            root: ".".to_string(),
            policy: crate::policy::WorkspacePolicy::ScratchCwd,
            consent: crate::records::WorkspaceConsent::default(),
        };
        store::write_record(
            self.paths,
            RecordKind::Workspace,
            workspace_id,
            now_ms,
            &workspace,
        )
    }

    /// The project an ad-hoc/scratch workspace should hang off: the built-in "system-terminal" (always present) if it
    /// exists, otherwise the first available project. `None` only if there are literally no projects.
    fn adhoc_owner_project(&self) -> Option<String> {
        const SYSTEM_TERMINAL_PROJECT_ID: &str = "system-terminal";
        let svc = crate::project::ProjectService::new(self.paths);
        if matches!(svc.load(SYSTEM_TERMINAL_PROJECT_ID), Ok(Some(_))) {
            return Some(SYSTEM_TERMINAL_PROJECT_ID.to_string());
        }
        svc.list().ok()?.into_iter().next().map(|p| p.project_id)
    }

    /// Start ONE session and attach to it, keeping a durable record in lock-step.
    ///
    /// Ordering (crash-safe):
    /// 1. Validate the cwd is an existing directory. If not, return `InvalidCwd` — NOTHING is
    ///    persisted and the daemon is never contacted.
    /// 2. Persist the `SessionRecord` as `Unknown` (record-before-daemon).
    /// 3. Ask the daemon to `start_and_attach`.
    /// 4. On the grid baseline: update the record to `Live` + `last_known_generation` +
    ///    `last_attached_at_ms` and persist it; return the live record.
    /// 5. On `SessionExited`: persist the record as `Exited` and return the typed daemon error.
    /// 6. On any other daemon error (refused/unreachable/protocol): LEAVE the `Unknown` record as
    ///    persisted (we did not prove liveness, nor that it never started) and return the error.
    pub fn start_and_attach(
        &self,
        client: &mut DaemonClient,
        params: &StartParams,
    ) -> Result<SessionRecord, SessionServiceError> {
        self.start_and_attach_with_restart(client, params, false, false, None)
            .map(|(record, _)| record)
            .map_err(|failure| failure.error)
    }

    /// Runtime-preflight form. The exact connection has already proved the complete conditional
    /// Start peer before endpoint/Session persistence, so publication reuses that opaque proof and
    /// must not issue a second DaemonInfo request.
    pub(crate) fn start_and_attach_after_peer_proof(
        &self,
        client: &mut DaemonClient,
        params: &StartParams,
        expected_peer: &ConditionalStartPeerIdentity,
    ) -> Result<SessionRecord, SessionServiceError> {
        self.start_and_attach_with_restart(client, params, false, false, Some(expected_peer))
            .map(|(record, _)| record)
            .map_err(|failure| failure.error)
    }

    /// Start a session while reserving one exact one-shot ownership handoff for the renderer that
    /// will replace this starter connection. Runtime must supply its pre-durable peer proof.
    pub(crate) fn start_and_attach_after_peer_proof_for_renderer(
        &self,
        mut client: DaemonClient,
        params: &StartParams,
        expected_peer: &ConditionalStartPeerIdentity,
    ) -> Result<(SessionRecord, AttachmentHandoffAuthority), SessionServiceError> {
        let (record, seed) = match self.start_and_attach_with_restart(
            &mut client,
            params,
            false,
            true,
            Some(expected_peer),
        ) {
            Ok(result) => result,
            Err(failure) => {
                return Err(SessionServiceError::bind_owned_attach_failure(
                    failure,
                    client,
                    &params.session_id,
                ));
            }
        };
        let seed = seed.ok_or_else(|| SessionServiceError::AttachAuthorityLost {
            session_id: params.session_id.clone(),
        })?;
        client.finish_generation_mutation();
        Ok((record, AttachmentHandoffAuthority::from_offer(seed, client)))
    }

    /// Start a replacement generation for a retained exited same-id session after the caller has
    /// obtained explicit user authority. This keeps the record-before-daemon ordering of ordinary
    /// starts while setting the protocol-v2 restart bit at the mutation boundary.
    pub(crate) fn restart_exited_and_attach(
        &self,
        client: &mut DaemonClient,
        params: &StartParams,
    ) -> Result<SessionRecord, SessionServiceError> {
        self.restart_exited_and_attach_exact(
            client,
            params,
            ExistingSessionStartMode::ReplaceExited,
            false,
            None,
            None,
            None,
            None,
            None,
        )
        .map(|(record, _)| record)
        .map_err(|failure| failure.error)
    }

    pub(crate) fn restart_exited_and_attach_for_renderer(
        &self,
        client: DaemonClient,
        params: &StartParams,
    ) -> Result<(SessionRecord, AttachmentHandoffAuthority), SessionServiceError> {
        self.restart_exited_and_attach_for_renderer_inner(client, params, None, None)
    }

    pub(crate) fn restart_exited_and_attach_for_renderer_expected_after_peer_proof(
        &self,
        client: DaemonClient,
        start: &ExistingSessionStart,
        expected_peer: &ConditionalStartPeerIdentity,
    ) -> Result<(SessionRecord, AttachmentHandoffAuthority), SessionServiceError> {
        self.restart_exited_and_attach_for_renderer_inner(
            client,
            start.params(),
            Some(start),
            Some(expected_peer),
        )
    }

    /// Sealed product-only retained restart. Generic `OptOut` records never reach this seam: the
    /// opaque authority owns one fixed reserved graph, exact argv/cwd, and is revalidated both
    /// before the daemon request and inside the final publication transaction.
    pub(crate) fn restart_reserved_product_shell_and_attach_for_renderer(
        &self,
        mut client: DaemonClient,
        start: &ReservedProductShellStart,
    ) -> Result<(SessionRecord, AttachmentHandoffAuthority), SessionServiceError> {
        let params = start.params();
        let (record, seed) = match self.restart_exited_and_attach_exact(
            &mut client,
            params,
            ExistingSessionStartMode::ReplaceExited,
            true,
            None,
            None,
            None,
            Some(start),
            None,
        ) {
            Ok(result) => result,
            Err(failure) => {
                return Err(SessionServiceError::bind_owned_attach_failure(
                    failure,
                    client,
                    &params.session_id,
                ));
            }
        };
        let seed = seed.ok_or_else(|| SessionServiceError::AttachAuthorityLost {
            session_id: params.session_id.clone(),
        })?;
        client.finish_generation_mutation();
        Ok((record, AttachmentHandoffAuthority::from_offer(seed, client)))
    }

    fn restart_exited_and_attach_for_renderer_inner(
        &self,
        mut client: DaemonClient,
        params: &StartParams,
        expected_start: Option<&ExistingSessionStart>,
        expected_peer: Option<&ConditionalStartPeerIdentity>,
    ) -> Result<(SessionRecord, AttachmentHandoffAuthority), SessionServiceError> {
        let (record, seed) = match self.restart_exited_and_attach_exact(
            &mut client,
            params,
            ExistingSessionStartMode::ReplaceExited,
            true,
            expected_peer,
            None,
            expected_start,
            None,
            None,
        ) {
            Ok(result) => result,
            Err(failure) => {
                return Err(SessionServiceError::bind_owned_attach_failure(
                    failure,
                    client,
                    &params.session_id,
                ));
            }
        };
        let seed = seed.ok_or_else(|| SessionServiceError::AttachAuthorityLost {
            session_id: params.session_id.clone(),
        })?;
        client.finish_generation_mutation();
        Ok((record, AttachmentHandoffAuthority::from_offer(seed, client)))
    }

    /// Recreate an exact durable exited lifetime after a reviewed fresh-daemon snapshot proved the
    /// daemon map absent. Durable A remains byte-for-byte until the daemon atomically applies an
    /// `Absent { excluded_generation: A }` start, returns B, and the full-row A -> B store CAS wins.
    pub(crate) fn start_absent_excluding_and_attach(
        &self,
        client: &mut DaemonClient,
        params: &StartParams,
        durable_start: FreshDaemonSessionStart<'_>,
        expected_peer: &ConditionalStartPeerIdentity,
    ) -> Result<SessionRecord, SessionServiceError> {
        let reserved_start = match durable_start {
            FreshDaemonSessionStart::ReservedProductShell { start } => Some(start),
            FreshDaemonSessionStart::Existing { .. } | FreshDaemonSessionStart::New { .. } => None,
        };
        let (expected, expected_workspace) =
            self.ensure_fresh_daemon_start_row(params, durable_start)?;
        self.restart_exited_and_attach_exact(
            client,
            params,
            ExistingSessionStartMode::FreshDaemonAbsent,
            false,
            Some(expected_peer),
            Some((expected, expected_workspace)),
            None,
            reserved_start,
            None,
        )
        .map(|(record, _)| record)
        .map_err(|failure| failure.error)
    }

    pub(crate) fn start_absent_excluding_and_attach_for_renderer(
        &self,
        mut client: DaemonClient,
        params: &StartParams,
        durable_start: FreshDaemonSessionStart<'_>,
        expected_peer: &ConditionalStartPeerIdentity,
    ) -> Result<(SessionRecord, AttachmentHandoffAuthority), SessionServiceError> {
        let reserved_start = match durable_start {
            FreshDaemonSessionStart::ReservedProductShell { start } => Some(start),
            FreshDaemonSessionStart::Existing { .. } | FreshDaemonSessionStart::New { .. } => None,
        };
        let (expected, expected_workspace) =
            self.ensure_fresh_daemon_start_row(params, durable_start)?;
        let (record, seed) = match self.restart_exited_and_attach_exact(
            &mut client,
            params,
            ExistingSessionStartMode::FreshDaemonAbsent,
            true,
            Some(expected_peer),
            Some((expected, expected_workspace)),
            None,
            reserved_start,
            None,
        ) {
            Ok(result) => result,
            Err(failure) => {
                return Err(SessionServiceError::bind_owned_attach_failure(
                    failure,
                    client,
                    &params.session_id,
                ));
            }
        };
        let seed = seed.ok_or_else(|| SessionServiceError::AttachAuthorityLost {
            session_id: params.session_id.clone(),
        })?;
        client.finish_generation_mutation();
        Ok((record, AttachmentHandoffAuthority::from_offer(seed, client)))
    }

    /// Task-aware headless prepared Start. Unlike the generic path, every ambiguous boundary owns
    /// both the exact daemon operation and the sealed Task/Session A -> B transition so a later
    /// settlement cannot rediscover or mix either half by id.
    pub(crate) fn start_prepared_agent_task_session(
        &self,
        mut client: DaemonClient,
        mut start: PreparedAgentTaskSessionStart,
        expected_peer: &ConditionalStartPeerIdentity,
    ) -> Result<PreparedNewSessionStarted, PreparedAgentTaskSessionStartError> {
        let session_id = start.session_id().to_string();
        if !std::path::Path::new(&start.as_inner().params().cwd).is_dir() {
            return Err(PreparedAgentTaskSessionStartError::DefinitelyUnpublished {
                error: SessionServiceError::InvalidCwd {
                    cwd: start.as_inner().params().cwd.clone(),
                },
                start,
            });
        }
        match start.graph_matches_in_snapshot(self.paths) {
            Ok(true) => {}
            Ok(false) => {
                return Err(PreparedAgentTaskSessionStartError::DefinitelyUnpublished {
                    error: SessionServiceError::AttachAuthorityLost { session_id },
                    start,
                });
            }
            Err(error) => {
                return Err(PreparedAgentTaskSessionStartError::DefinitelyUnpublished {
                    error: SessionServiceError::Store(error),
                    start,
                });
            }
        }
        if !std::path::Path::new(&start.as_inner().params().cwd).is_dir() {
            return Err(PreparedAgentTaskSessionStartError::DefinitelyUnpublished {
                error: SessionServiceError::InvalidCwd {
                    cwd: start.as_inner().params().cwd.clone(),
                },
                start,
            });
        }

        let daemon_result = {
            let operation_token = start.journal().operation_token().clone();
            let params = start.as_inner().params();
            client.start_absent_and_attach_after_peer_proof_with_recovery(
                maestro_protocol::SessionId(params.session_id.clone()),
                operation_token,
                expected_peer,
                &params.cwd,
                &params.command,
                &params.args,
                params.cols,
                params.rows,
            )
        };
        let (attached, daemon_recovery) = match daemon_result {
            Ok(result) => result,
            Err(
                error @ (DaemonClientError::ConditionalStartRefused { .. }
                | DaemonClientError::StartOperationTerminal {
                    status: SessionStartOperationStatus::Refused,
                    ..
                }),
            ) => {
                client.finish_generation_mutation();
                let daemon = ConditionalStartRecoveryAuthority::from_bound_absent_journal(
                    maestro_protocol::SessionId(session_id.clone()),
                    start.journal().operation_token().clone(),
                    start.journal().daemon_instance_id().clone(),
                    None,
                    client,
                );
                match daemon.retire_unapplied_operation() {
                    Ok(SessionStartOperationRetireOutcome::Retired)
                    | Ok(SessionStartOperationRetireOutcome::AlreadyRetired) => {
                        let (start, journal) = start.into_parts();
                        let compensation = PreparedAgentTaskSessionCompensation::from_parts(
                            start.initial_compensation(),
                            journal,
                        )
                        .expect("task-aware start cannot lose its private task transition");
                        return Err(PreparedAgentTaskSessionStartError::Refused {
                            error: SessionServiceError::Daemon(error),
                            compensation,
                        });
                    }
                    Ok(SessionStartOperationRetireOutcome::Conflict { current }) => {
                        return Err(PreparedAgentTaskSessionStartError::PossiblyApplied {
                            error: SessionServiceError::Daemon(
                                DaemonClientError::StartOperationTerminal {
                                    id: maestro_protocol::SessionId(session_id),
                                    status: current,
                                },
                            ),
                            recovery: PreparedAgentTaskPublicationRecoveryAuthority::new(
                                start, daemon,
                            ),
                        });
                    }
                    Err(retire_error) => {
                        return Err(PreparedAgentTaskSessionStartError::PossiblyApplied {
                            error: SessionServiceError::Daemon(retire_error),
                            recovery: PreparedAgentTaskPublicationRecoveryAuthority::new(
                                start, daemon,
                            ),
                        });
                    }
                }
            }
            Err(error @ DaemonClientError::StartOperationTerminal { .. }) => {
                let applied_generation = match &error {
                    DaemonClientError::StartOperationTerminal {
                        status: SessionStartOperationStatus::Applied { generation, .. },
                        ..
                    } => Some(generation.clone()),
                    _ => None,
                };
                client.finish_generation_mutation();
                let daemon = ConditionalStartRecoveryAuthority::from_bound_absent_journal(
                    maestro_protocol::SessionId(session_id),
                    start.journal().operation_token().clone(),
                    start.journal().daemon_instance_id().clone(),
                    applied_generation,
                    client,
                );
                return Err(PreparedAgentTaskSessionStartError::PossiblyApplied {
                    error: SessionServiceError::Daemon(error),
                    recovery: PreparedAgentTaskPublicationRecoveryAuthority::new(start, daemon),
                });
            }
            Err(DaemonClientError::ConditionalStartPossiblyApplied {
                recovery, source, ..
            }) => {
                client.finish_generation_mutation();
                let daemon = ConditionalStartRecoveryAuthority::new(recovery, client);
                return Err(PreparedAgentTaskSessionStartError::PossiblyApplied {
                    error: SessionServiceError::Daemon(*source),
                    recovery: PreparedAgentTaskPublicationRecoveryAuthority::new(start, daemon),
                });
            }
            Err(error) => {
                client.abort_connection();
                return Err(PreparedAgentTaskSessionStartError::DefinitelyUnpublished {
                    error: SessionServiceError::Daemon(error),
                    start,
                });
            }
        };

        #[cfg(test)]
        crate::store_sqlite::run_window_layout_test_hook(
            "after-prepared-session-grid-before-finalize",
            start.as_inner().trace_scope_id(),
        );
        let generation = attached.generation.clone();
        let journal_marked = match WindowLayoutService::new(self.paths)
            .mark_prepared_agent_task_start_applied(start.journal_mut(), &generation, "live")
        {
            Ok(marked) => marked,
            Err(error) => {
                client.finish_generation_mutation();
                let daemon = ConditionalStartRecoveryAuthority::new(daemon_recovery, client);
                return Err(PreparedAgentTaskSessionStartError::PossiblyApplied {
                    error: SessionServiceError::Store(StoreError::Map(error.to_string())),
                    recovery: PreparedAgentTaskPublicationRecoveryAuthority::new(start, daemon),
                });
            }
        };
        if !journal_marked {
            client.finish_generation_mutation();
            let daemon = ConditionalStartRecoveryAuthority::new(daemon_recovery, client);
            return Err(PreparedAgentTaskSessionStartError::PossiblyApplied {
                error: SessionServiceError::AttachAuthorityLost { session_id },
                recovery: PreparedAgentTaskPublicationRecoveryAuthority::new(start, daemon),
            });
        }
        match self.finalize_prepared_agent_task_publication(
            &mut start,
            &generation,
            SessionStatus::Live,
            "live",
        ) {
            Ok(PreparedAgentTaskFinalize::Published(started)) => {
                client.finish_generation_mutation();
                let daemon = ConditionalStartRecoveryAuthority::new(daemon_recovery, client);
                self.retire_published_agent_task_operation(&start, &daemon, &generation);
                Ok(started)
            }
            Ok(PreparedAgentTaskFinalize::Changed) => {
                client.finish_generation_mutation();
                let daemon = ConditionalStartRecoveryAuthority::new(daemon_recovery, client);
                Err(PreparedAgentTaskSessionStartError::PossiblyApplied {
                    error: SessionServiceError::AttachAuthorityLost { session_id },
                    recovery: PreparedAgentTaskPublicationRecoveryAuthority::new(start, daemon),
                })
            }
            Err(error) => {
                client.finish_generation_mutation();
                let daemon = ConditionalStartRecoveryAuthority::new(daemon_recovery, client);
                Err(PreparedAgentTaskSessionStartError::PossiblyApplied {
                    error: SessionServiceError::Store(error),
                    recovery: PreparedAgentTaskPublicationRecoveryAuthority::new(start, daemon),
                })
            }
        }
    }

    fn finalize_prepared_agent_task_publication(
        &self,
        start: &mut PreparedAgentTaskSessionStart,
        generation: &str,
        publication_status: SessionStatus,
        journal_state: &'static str,
    ) -> Result<PreparedAgentTaskFinalize, StoreError> {
        if publication_status == SessionStatus::Unknown
            || !matches!(journal_state, "live" | "exited" | "removed")
            || (publication_status == SessionStatus::Live && journal_state != "live")
            || (publication_status == SessionStatus::Exited && journal_state == "live")
        {
            return Err(StoreError::Map(
                "invalid AgentTask publication status/journal state pair".into(),
            ));
        }
        let journal_now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| StoreError::Map("system clock precedes Unix epoch".into()))?
            .as_millis()
            .try_into()
            .map_err(|_| StoreError::Map("system clock exceeds u64 milliseconds".into()))?;
        let inner = start.as_inner();
        let replacement =
            inner.publication_record_for_generation_and_status(generation, publication_status)?;
        let mut rebased_compensation = None;
        let mut published_agent_task = None;
        let finalized = store::finalize_session_attach_if_unchanged_with_workspace_and_guard(
            self.paths,
            inner.unknown(),
            &replacement,
            Some(inner.workspace()),
            generation,
            inner.params().now_ms,
            |transaction| {
                if !start
                    .journal()
                    .is_bound_finalize_applied(generation, journal_state)
                    || !start.graph_matches_connection_at(transaction, journal_now_ms)?
                {
                    return Ok(false);
                }
                let compensation = inner.rebased_compensation(&replacement)?;
                match inner.publish_agent_task_in_connection(transaction)? {
                    PreparedAgentTaskPublication::Published(task) => {
                        published_agent_task = Some(task);
                    }
                    PreparedAgentTaskPublication::NotTaskAware
                    | PreparedAgentTaskPublication::Changed => {
                        return Err(StoreError::Map(
                            "prepared AgentTask changed after its final publication guard".into(),
                        ));
                    }
                }
                if !start
                    .journal()
                    .transition_to_release_in_connection_at(transaction, journal_now_ms)?
                {
                    return Err(StoreError::Map(
                        "prepared AgentTask journal changed during final release transition".into(),
                    ));
                }
                rebased_compensation = Some(compensation);
                Ok(true)
            },
        )?;

        let mut release_committed = matches!(
            finalized,
            store::ConditionalSessionAttachFinalize::Finalized { .. }
        );
        if !matches!(
            finalized,
            store::ConditionalSessionAttachFinalize::Finalized { .. }
        ) {
            let arc = crate::db::conn_for(self.paths.base())
                .map_err(|error| StoreError::Db(error.to_string()))?;
            let mut conn = arc.lock().unwrap();
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
                .map_err(|error| StoreError::Db(error.to_string()))?;
            let journal_absent: bool = tx
                .query_row(
                    "SELECT NOT EXISTS(SELECT 1 FROM pending_agent_task_starts \
                     WHERE session_id = ?1 OR operation_token = ?2)",
                    rusqlite::params![
                        start.session_id(),
                        start.journal().operation_token().as_str(),
                    ],
                    |row| row.get(0),
                )
                .map_err(|error| StoreError::Db(error.to_string()))?;
            let release_present = start.journal().matches_release_in_connection(&tx)?;
            let already_published = (journal_absent || release_present)
                && inner.published_agent_task_graph_matches_connection(&tx, &replacement)?;
            tx.commit()
                .map_err(|error| StoreError::Db(error.to_string()))?;
            if !already_published {
                return Ok(PreparedAgentTaskFinalize::Changed);
            }
            release_committed = release_present;
            rebased_compensation = Some(inner.rebased_compensation(&replacement)?);
            published_agent_task = inner.published_agent_task().cloned();
        }

        let compensation = rebased_compensation
            .expect("task-aware finalizer mints compensation before publishing Live");
        let task =
            published_agent_task.expect("task-aware finalizer returns the exact committed Task B");
        let fields = serde_json::to_value(&task)
            .ok()
            .and_then(|value| {
                value
                    .as_object()
                    .map(|object| object.keys().cloned().collect::<Vec<_>>())
            })
            .unwrap_or_default();
        crate::write_trace::trace_write(
            self.paths.base(),
            "AgentTask",
            &task.agent_task_id,
            &fields,
            inner.params().now_ms,
        );
        if release_committed {
            start.journal_mut().mark_release_committed();
        }
        Ok(PreparedAgentTaskFinalize::Published(
            PreparedNewSessionStarted {
                record: replacement,
                compensation,
                agent_task: Some(task),
            },
        ))
    }

    fn retire_published_agent_task_operation(
        &self,
        start: &PreparedAgentTaskSessionStart,
        daemon: &ConditionalStartRecoveryAuthority,
        generation: &str,
    ) {
        let retired = daemon.retire_applied_operation(generation);
        if matches!(
            retired,
            Ok(SessionStartOperationRetireOutcome::Retired
                | SessionStartOperationRetireOutcome::AlreadyRetired)
        ) {
            // This cleanup is intentionally best-effort after the durable B+release transaction.
            // Any failure leaves the exact release row for the lease-based recovery worker.
            let _ = WindowLayoutService::new(self.paths)
                .delete_prepared_agent_task_release_after_operation_retired(
                    start.journal(),
                    generation,
                );
        }
    }

    pub(crate) fn settle_prepared_agent_task_publication(
        &self,
        mut recovery: PreparedAgentTaskPublicationRecoveryAuthority,
    ) -> PreparedAgentTaskPublicationSettlement {
        let operation_status = match recovery.daemon.lookup_operation_status() {
            Ok(status) => status,
            Err(error) => {
                return PreparedAgentTaskPublicationSettlement::Pending {
                    recovery,
                    error: Some(SessionServiceError::Daemon(error)),
                };
            }
        };
        let (generation, publication_status, journal_state) = match operation_status {
            SessionStartOperationStatus::Applied {
                generation: _,
                lifecycle: SessionStartOperationLifecycle::Live,
            } => match recovery.daemon.recover_with_exact_grid() {
                Ok(ConditionalStartGridRecovery::GridProven {
                    attached,
                    lifecycle_at_lookup,
                }) => {
                    let (publication_status, journal_state) = match lifecycle_at_lookup {
                        SessionStartOperationLifecycle::Live => (SessionStatus::Live, "live"),
                        SessionStartOperationLifecycle::Exited => (SessionStatus::Exited, "exited"),
                        SessionStartOperationLifecycle::Removed => {
                            return PreparedAgentTaskPublicationSettlement::Pending {
                                recovery,
                                error: Some(SessionServiceError::AttachAuthorityLost {
                                    session_id: attached.id.0,
                                }),
                            };
                        }
                    };
                    (attached.generation, publication_status, journal_state)
                }
                Ok(ConditionalStartGridRecovery::OperationStatus(
                    SessionStartOperationStatus::Applied {
                        generation,
                        lifecycle: SessionStartOperationLifecycle::Exited,
                    },
                )) => (generation, SessionStatus::Exited, "exited"),
                Ok(ConditionalStartGridRecovery::OperationStatus(
                    SessionStartOperationStatus::Applied {
                        generation,
                        lifecycle: SessionStartOperationLifecycle::Removed,
                    },
                )) => (generation, SessionStatus::Exited, "removed"),
                Ok(ConditionalStartGridRecovery::OperationStatus(_)) => {
                    return PreparedAgentTaskPublicationSettlement::Pending {
                        recovery,
                        error: None,
                    };
                }
                Err(error) => {
                    return PreparedAgentTaskPublicationSettlement::Pending {
                        recovery,
                        error: Some(SessionServiceError::Daemon(error)),
                    };
                }
            },
            SessionStartOperationStatus::Applied {
                generation,
                lifecycle: SessionStartOperationLifecycle::Exited,
            } => (generation, SessionStatus::Exited, "exited"),
            SessionStartOperationStatus::Applied {
                generation,
                lifecycle: SessionStartOperationLifecycle::Removed,
            } => (generation, SessionStatus::Exited, "removed"),
            SessionStartOperationStatus::Unknown
            | SessionStartOperationStatus::Reserved
            | SessionStartOperationStatus::Refused => {
                return PreparedAgentTaskPublicationSettlement::Pending {
                    recovery,
                    error: None,
                };
            }
        };
        let journal_marked = match WindowLayoutService::new(self.paths)
            .mark_prepared_agent_task_start_applied(
                recovery.start.journal_mut(),
                &generation,
                journal_state,
            ) {
            Ok(marked) => marked,
            Err(error) => {
                return PreparedAgentTaskPublicationSettlement::Pending {
                    recovery,
                    error: Some(SessionServiceError::Store(StoreError::Map(
                        error.to_string(),
                    ))),
                };
            }
        };
        if !journal_marked {
            let session_id = recovery.session_id().to_string();
            return PreparedAgentTaskPublicationSettlement::Changed {
                recovery,
                error: SessionServiceError::AttachAuthorityLost { session_id },
            };
        }
        match self.finalize_prepared_agent_task_publication(
            &mut recovery.start,
            &generation,
            publication_status,
            journal_state,
        ) {
            Ok(PreparedAgentTaskFinalize::Published(started)) => {
                self.retire_published_agent_task_operation(
                    &recovery.start,
                    &recovery.daemon,
                    &generation,
                );
                PreparedAgentTaskPublicationSettlement::Published(started)
            }
            Ok(PreparedAgentTaskFinalize::Changed) => {
                let session_id = recovery.session_id().to_string();
                PreparedAgentTaskPublicationSettlement::Changed {
                    recovery,
                    error: SessionServiceError::AttachAuthorityLost { session_id },
                }
            }
            Err(error) => PreparedAgentTaskPublicationSettlement::Pending {
                recovery,
                error: Some(SessionServiceError::Store(error)),
            },
        }
    }

    /// Consume one transaction-prepared start authority and publish exactly one conditional
    /// `Absent(None)` daemon lifetime. The caller must supply the peer proof captured on this same
    /// reviewed client before the final prewire graph snapshot.
    pub fn start_prepared_new_session(
        &self,
        client: DaemonClient,
        start: PreparedNewSessionStart,
        expected_peer: &ConditionalStartPeerIdentity,
    ) -> Result<PreparedNewSessionStarted, PreparedNewSessionStartError> {
        self.start_prepared_new_session_inner(client, start, expected_peer, false, None)
            .map(|(started, authority)| {
                debug_assert!(authority.is_none());
                started
            })
    }

    /// Headless prepared-session counterpart that applies only the daemon protocol's restricted
    /// typed child environment. The captured peer proof must advertise the capability, and the
    /// environment remains coupled to the same conditional Start/Reserve/Grid/publication flow.
    pub fn start_prepared_new_session_with_child_environment(
        &self,
        client: DaemonClient,
        start: PreparedNewSessionStart,
        expected_peer: &ConditionalStartPeerIdentity,
        child_environment: Option<maestro_protocol::ChildEnvironment>,
    ) -> Result<PreparedNewSessionStarted, PreparedNewSessionStartError> {
        self.start_prepared_new_session_inner(
            client,
            start,
            expected_peer,
            false,
            child_environment,
        )
        .map(|(started, authority)| {
            debug_assert!(authority.is_none());
            started
        })
    }

    /// Renderer-handoff counterpart to [`Self::start_prepared_new_session`]. The Offer authority
    /// escapes only after the full placement/A/W finalizer commits and the rebased compensation
    /// receipt has been minted.
    pub fn start_prepared_new_session_for_renderer(
        &self,
        client: DaemonClient,
        start: PreparedNewSessionStart,
        expected_peer: &ConditionalStartPeerIdentity,
    ) -> Result<(PreparedNewSessionStarted, AttachmentHandoffAuthority), PreparedNewSessionStartError>
    {
        self.start_prepared_new_session_inner(client, start, expected_peer, true, None)
            .and_then(|(started, authority)| match authority {
                Some(authority) => Ok((started, authority)),
                None => Err(PreparedNewSessionStartError::PossiblyApplied {
                    error: SessionServiceError::AttachAuthorityLost {
                        session_id: started.record.session_id.clone(),
                    },
                }),
            })
    }

    fn start_prepared_new_session_inner(
        &self,
        mut client: DaemonClient,
        start: PreparedNewSessionStart,
        expected_peer: &ConditionalStartPeerIdentity,
        offer_renderer_handoff: bool,
        child_environment: Option<maestro_protocol::ChildEnvironment>,
    ) -> Result<
        (
            PreparedNewSessionStarted,
            Option<AttachmentHandoffAuthority>,
        ),
        PreparedNewSessionStartError,
    > {
        let session_id = start.session_id().to_string();
        if !std::path::Path::new(&start.params().cwd).is_dir() {
            return Err(PreparedNewSessionStartError::DefinitelyUnpublished {
                error: SessionServiceError::InvalidCwd {
                    cwd: start.params().cwd.clone(),
                },
                start,
            });
        }
        match start.graph_matches_in_snapshot(self.paths) {
            Ok(true) => {}
            Ok(false) => {
                return Err(PreparedNewSessionStartError::DefinitelyUnpublished {
                    error: SessionServiceError::AttachAuthorityLost { session_id },
                    start,
                });
            }
            Err(error) => {
                return Err(PreparedNewSessionStartError::DefinitelyUnpublished {
                    error: SessionServiceError::Store(error),
                    start,
                });
            }
        }

        // Recheck cwd immediately before the first mutation frame. Preparation may precede this
        // call by an arbitrary interval, and deleting the directory must remain a zero-wire,
        // compensation-authorized refusal.
        if !std::path::Path::new(&start.params().cwd).is_dir() {
            return Err(PreparedNewSessionStartError::DefinitelyUnpublished {
                error: SessionServiceError::InvalidCwd {
                    cwd: start.params().cwd.clone(),
                },
                start,
            });
        }

        let daemon_result = {
            let params = start.params();
            if offer_renderer_handoff {
                client.start_absent_and_attach_after_peer_proof_for_renderer(
                    maestro_protocol::SessionId(params.session_id.clone()),
                    expected_peer,
                    &params.cwd,
                    &params.command,
                    &params.args,
                    params.cols,
                    params.rows,
                )
            } else {
                client.start_and_attach_conditionally_with_environment(
                    maestro_protocol::SessionId(params.session_id.clone()),
                    &params.cwd,
                    &params.command,
                    &params.args,
                    child_environment,
                    params.cols,
                    params.rows,
                    maestro_protocol::SessionStartPrecondition::Absent {
                        excluded_generation: None,
                    },
                    expected_peer,
                )
            }
        };
        let (mut attached, daemon_recovery) = match daemon_result {
            Ok(result) => result,
            Err(error @ DaemonClientError::ConditionalStartRefused { .. }) => {
                client.abort_connection();
                return Err(PreparedNewSessionStartError::Refused {
                    error: SessionServiceError::Daemon(error),
                    compensation: start.initial_compensation(),
                });
            }
            Err(error @ DaemonClientError::ConditionalStartPossiblyApplied { .. }) => {
                return Err(PreparedNewSessionStartError::PossiblyApplied {
                    error: SessionServiceError::Daemon(error)
                        .bind_conditional_start_recovery(client),
                });
            }
            Err(error @ DaemonClientError::SessionExited { .. }) => {
                client.abort_connection();
                return Err(PreparedNewSessionStartError::PossiblyApplied {
                    error: SessionServiceError::Daemon(error),
                });
            }
            Err(error) => {
                client.abort_connection();
                return Err(PreparedNewSessionStartError::DefinitelyUnpublished {
                    error: SessionServiceError::Daemon(error),
                    start,
                });
            }
        };

        #[cfg(test)]
        crate::store_sqlite::run_window_layout_test_hook(
            "after-prepared-session-grid-before-finalize",
            start.trace_scope_id(),
        );
        let generation = attached.generation.clone();
        let mut replacement = start.unknown().clone();
        replacement.status = SessionStatus::Live;
        replacement.last_known_generation = Some(generation.clone());
        replacement.last_attached_at_ms = start.params().now_ms;
        replacement.launch = start.publication_launch().clone();
        let mut rebased_compensation = None;
        let mut published_agent_task = None;
        let finalized = store::finalize_session_attach_if_unchanged_with_workspace_and_guard(
            self.paths,
            start.unknown(),
            &replacement,
            Some(start.workspace()),
            &generation,
            start.params().now_ms,
            |transaction| {
                if !start.graph_matches_connection(transaction)? {
                    return Ok(false);
                }
                match start.publish_agent_task_in_connection(transaction)? {
                    PreparedAgentTaskPublication::NotTaskAware => {}
                    PreparedAgentTaskPublication::Published(task) => {
                        published_agent_task = Some(task);
                    }
                    PreparedAgentTaskPublication::Changed => return Ok(false),
                }
                rebased_compensation = Some(start.rebased_compensation(&replacement)?);
                Ok(true)
            },
        );
        match finalized {
            Ok(store::ConditionalSessionAttachFinalize::Finalized { .. }) => {}
            Ok(store::ConditionalSessionAttachFinalize::Missing)
            | Ok(store::ConditionalSessionAttachFinalize::Changed)
            | Ok(store::ConditionalSessionAttachFinalize::Quarantined) => {
                let _ = attached.take_attachment_handoff_seed();
                return Err(PreparedNewSessionStartError::PossiblyApplied {
                    error: SessionServiceError::AttachAuthorityLost { session_id }
                        .preserve_conditional_start_recovery(daemon_recovery)
                        .bind_conditional_start_recovery(client),
                });
            }
            Err(error) => {
                let _ = attached.take_attachment_handoff_seed();
                return Err(PreparedNewSessionStartError::PossiblyApplied {
                    error: SessionServiceError::Store(error)
                        .preserve_conditional_start_recovery(daemon_recovery)
                        .bind_conditional_start_recovery(client),
                });
            }
        }
        let compensation = rebased_compensation
            .expect("prepared finalizer mints compensation before committing Live");
        if let Some(task) = &published_agent_task {
            let fields = serde_json::to_value(task)
                .ok()
                .and_then(|value| {
                    value
                        .as_object()
                        .map(|object| object.keys().cloned().collect::<Vec<_>>())
                })
                .unwrap_or_default();
            crate::write_trace::trace_write(
                self.paths.base(),
                "AgentTask",
                &task.agent_task_id,
                &fields,
                start.params().now_ms,
            );
        }
        // Durable B is now committed. Retiring is an exact Applied(G) CAS and deliberately occurs
        // before the client is moved into renderer handoff ownership. A transient retirement
        // failure cannot roll back the already-published Session row or revoke its Grid proof.
        let _ = client.retire_applied_start_operation_in_place(&daemon_recovery, &generation);
        let seed = attached.take_attachment_handoff_seed();
        let started = PreparedNewSessionStarted {
            record: replacement,
            compensation,
            agent_task: published_agent_task,
        };
        if offer_renderer_handoff {
            let Some(seed) = seed else {
                client.abort_connection();
                return Err(PreparedNewSessionStartError::PossiblyApplied {
                    error: SessionServiceError::AttachAuthorityLost { session_id },
                });
            };
            client.finish_generation_mutation();
            Ok((
                started,
                Some(AttachmentHandoffAuthority::from_offer(seed, client)),
            ))
        } else {
            client.finish_generation_mutation();
            Ok((started, None))
        }
    }

    /// Choose the fresh-daemon durable boundary without an App-side load/write race. Any existing
    /// current Session row remains byte-for-byte A until the later full-row finalize CAS. Only a
    /// caller-reviewed New authority may insert an `Unknown` row before daemon publication; a
    /// concurrent creator is a hard refusal and is never adopted as this operation's authority.
    fn ensure_fresh_daemon_start_row(
        &self,
        params: &StartParams,
        durable_start: FreshDaemonSessionStart<'_>,
    ) -> Result<(SessionRecord, Workspace), SessionServiceError> {
        if let FreshDaemonSessionStart::Existing { start } = durable_start {
            if !start.has_exact_conversation_scope() {
                return Err(SessionServiceError::AttachAuthorityLost {
                    session_id: start.session.session_id.clone(),
                });
            }
            let expected = &start.session;
            let expected_workspace = &start.workspace;
            let reviewed = &start.params;
            let params_match_expected = expected.session_id == params.session_id
                && expected.workspace_id == params.workspace_id
                && expected.kind == params.kind
                && expected.launch == params.launch
                && expected.cwd_resolved == params.cwd
                && expected.agent_task_id == params.agent_task_id
                && expected_workspace.workspace_id == expected.workspace_id
                && reviewed.session_id == params.session_id
                && reviewed.workspace_id == params.workspace_id
                && reviewed.kind == params.kind
                && reviewed.launch == params.launch
                && reviewed.cwd == params.cwd
                && reviewed.command == params.command
                && reviewed.args == params.args
                && reviewed.cols == params.cols
                && reviewed.rows == params.rows
                && reviewed.agent_task_id == params.agent_task_id
                && reviewed.now_ms == params.now_ms;
            if !params_match_expected {
                return Err(SessionServiceError::AttachAuthorityLost {
                    session_id: params.session_id.clone(),
                });
            }
            if !store::session_workspace_rows_match_in_snapshot(
                self.paths,
                expected,
                expected_workspace,
            )? {
                return Err(SessionServiceError::AttachAuthorityLost {
                    session_id: params.session_id.clone(),
                });
            }
            return Ok((expected.clone(), expected_workspace.clone()));
        }

        if let FreshDaemonSessionStart::ReservedProductShell { start } = durable_start {
            let expected = start.session();
            let expected_workspace = start.workspace();
            let reviewed = start.params();
            let params_match_expected = expected.session_id == params.session_id
                && expected.workspace_id == params.workspace_id
                && expected.kind == params.kind
                && expected.launch == params.launch
                && expected.cwd_resolved == params.cwd
                && expected.agent_task_id == params.agent_task_id
                && expected_workspace.workspace_id == expected.workspace_id
                && reviewed.session_id == params.session_id
                && reviewed.workspace_id == params.workspace_id
                && reviewed.kind == params.kind
                && reviewed.launch == params.launch
                && reviewed.cwd == params.cwd
                && reviewed.command == params.command
                && reviewed.args == params.args
                && reviewed.cols == params.cols
                && reviewed.rows == params.rows
                && reviewed.agent_task_id == params.agent_task_id
                && reviewed.now_ms == params.now_ms;
            if !params_match_expected || !start.graph_matches_in_snapshot(self.paths)? {
                return Err(SessionServiceError::AttachAuthorityLost {
                    session_id: params.session_id.clone(),
                });
            }
            return Ok((expected.clone(), expected_workspace.clone()));
        }

        let workspace = match durable_start {
            FreshDaemonSessionStart::New { workspace } => workspace.clone(),
            FreshDaemonSessionStart::Existing { .. }
            | FreshDaemonSessionStart::ReservedProductShell { .. } => {
                unreachable!("existing fresh-daemon start returned after exact validation")
            }
        };
        if workspace.workspace_id != params.workspace_id {
            return Err(SessionServiceError::AttachAuthorityLost {
                session_id: params.session_id.clone(),
            });
        }
        let unknown = SessionRecord {
            session_id: params.session_id.clone(),
            workspace_id: params.workspace_id.clone(),
            kind: params.kind,
            launch: params.launch.clone(),
            cwd_resolved: params.cwd.clone(),
            agent_task_id: params.agent_task_id.clone(),
            created_at_ms: params.now_ms,
            last_attached_at_ms: params.now_ms,
            last_known_generation: None,
            status: SessionStatus::Unknown,
        };
        match store::create_workspace_and_session_if_absent(
            self.paths,
            &workspace,
            &unknown,
            params.now_ms,
        )? {
            store::CreateWorkspaceSessionOutcome::Created { .. } => Ok((unknown, workspace)),
            store::CreateWorkspaceSessionOutcome::Conflict => {
                Err(SessionServiceError::AttachAuthorityLost {
                    session_id: params.session_id.clone(),
                })
            }
        }
    }

    /// Replace one exact retained exited lifetime without publishing an intermediate durable
    /// `Unknown` row. The complete Exited row and its generation remain the durable authority until
    /// a different daemon Grid is proven; only then does one IMMEDIATE transaction compare the full
    /// old row and publish the replacement. A refused start, a lost daemon Error followed by the old
    /// Grid, or a concurrent record change leaves the old row byte-for-byte unchanged.
    fn restart_exited_and_attach_exact(
        &self,
        client: &mut DaemonClient,
        params: &StartParams,
        mode: ExistingSessionStartMode,
        offer_renderer_handoff: bool,
        expected_peer: Option<&ConditionalStartPeerIdentity>,
        expected_fresh_row: Option<(SessionRecord, Workspace)>,
        expected_replaced_start: Option<&ExistingSessionStart>,
        reserved_product_shell: Option<&ReservedProductShellStart>,
        child_environment: Option<maestro_protocol::ChildEnvironment>,
    ) -> Result<(SessionRecord, Option<AttachmentHandoffSeed>), SessionAttachFailure> {
        if !std::path::Path::new(&params.cwd).is_dir() {
            return Err(SessionServiceError::InvalidCwd {
                cwd: params.cwd.clone(),
            }
            .into());
        }

        let (expected, expected_workspace) = if mode == ExistingSessionStartMode::FreshDaemonAbsent
        {
            let (expected, expected_workspace) = expected_fresh_row
                .expect("fresh-daemon start carries exact durable Session+Workspace rows");
            if !store::session_workspace_rows_match_in_snapshot(
                self.paths,
                &expected,
                &expected_workspace,
            )? {
                return Err(SessionServiceError::AttachAuthorityLost {
                    session_id: params.session_id.clone(),
                }
                .into());
            }
            (expected, Some(expected_workspace))
        } else if let Some(reviewed) = expected_replaced_start {
            if reviewed.params.session_id != params.session_id
                || reviewed.params.workspace_id != params.workspace_id
                || reviewed.params.kind != params.kind
                || reviewed.params.launch != params.launch
                || reviewed.params.cwd != params.cwd
                || reviewed.params.command != params.command
                || reviewed.params.args != params.args
                || reviewed.params.cols != params.cols
                || reviewed.params.rows != params.rows
                || reviewed.params.agent_task_id != params.agent_task_id
                || reviewed.params.now_ms != params.now_ms
                || reviewed.session.session_id != params.session_id
                || reviewed.session.status != SessionStatus::Exited
                || !store::session_workspace_rows_match_in_snapshot(
                    self.paths,
                    &reviewed.session,
                    &reviewed.workspace,
                )?
            {
                return Err(SessionServiceError::AttachAuthorityLost {
                    session_id: params.session_id.clone(),
                }
                .into());
            }
            (reviewed.session.clone(), Some(reviewed.workspace.clone()))
        } else if let Some(reserved) = reserved_product_shell {
            let reviewed = reserved.params();
            if reviewed.session_id != params.session_id
                || reviewed.workspace_id != params.workspace_id
                || reviewed.kind != params.kind
                || reviewed.launch != params.launch
                || reviewed.cwd != params.cwd
                || reviewed.command != params.command
                || reviewed.args != params.args
                || reviewed.cols != params.cols
                || reviewed.rows != params.rows
                || reviewed.agent_task_id != params.agent_task_id
                || reviewed.now_ms != params.now_ms
                || reserved.session().status != SessionStatus::Exited
            {
                return Err(SessionServiceError::AttachAuthorityLost {
                    session_id: params.session_id.clone(),
                }
                .into());
            }
            (
                reserved.session().clone(),
                Some(reserved.workspace().clone()),
            )
        } else {
            return Err(SessionServiceError::AttachAuthorityLost {
                session_id: params.session_id.clone(),
            }
            .into());
        };
        if let Some(reserved) = reserved_product_shell {
            let Some(expected_workspace) = expected_workspace.as_ref() else {
                return Err(SessionServiceError::AttachAuthorityLost {
                    session_id: params.session_id.clone(),
                }
                .into());
            };
            if reserved.session() != &expected
                || reserved.workspace() != expected_workspace
                || !reserved.graph_matches_in_snapshot(self.paths)?
            {
                return Err(SessionServiceError::AttachAuthorityLost {
                    session_id: params.session_id.clone(),
                }
                .into());
            }
        }
        let previous_generation = match expected.last_known_generation.as_deref() {
            Some(generation) if !generation.is_empty() && generation.len() <= 128 => {
                Some(generation)
            }
            None if mode == ExistingSessionStartMode::FreshDaemonAbsent => None,
            _ => {
                return Err(SessionAttachFailure::new(
                    SessionServiceError::AttachAuthorityLost {
                        session_id: params.session_id.clone(),
                    },
                ));
            }
        };

        let session_id = maestro_protocol::SessionId(params.session_id.clone());
        let started = if let (false, Some(expected_peer)) = (offer_renderer_handoff, expected_peer)
        {
            let precondition = match mode {
                ExistingSessionStartMode::ReplaceExited => {
                    maestro_protocol::SessionStartPrecondition::ExitedGeneration {
                        expected_generation: previous_generation
                            .expect("retained restart requires exact generation")
                            .to_string(),
                    }
                }
                ExistingSessionStartMode::FreshDaemonAbsent => {
                    maestro_protocol::SessionStartPrecondition::Absent {
                        excluded_generation: previous_generation.map(str::to_string),
                    }
                }
            };
            client.start_and_attach_conditionally_with_environment(
                session_id,
                &params.cwd,
                &params.command,
                &params.args,
                child_environment,
                params.cols,
                params.rows,
                precondition,
                expected_peer,
            )
        } else {
            debug_assert!(
                child_environment.is_none(),
                "renderer and unreviewed legacy seams never apply a headless child environment"
            );
            match (mode, offer_renderer_handoff) {
                (ExistingSessionStartMode::ReplaceExited, true) => match expected_peer {
                    Some(expected_peer) => client
                        .restart_exited_and_attach_after_peer_proof_for_renderer(
                            session_id,
                            previous_generation
                                .expect("retained restart requires exact generation"),
                            expected_peer,
                            &params.cwd,
                            &params.command,
                            &params.args,
                            params.cols,
                            params.rows,
                        ),
                    None => client.restart_exited_and_attach_for_renderer(
                        session_id,
                        previous_generation.expect("retained restart requires exact generation"),
                        &params.cwd,
                        &params.command,
                        &params.args,
                        params.cols,
                        params.rows,
                    ),
                },
                (ExistingSessionStartMode::ReplaceExited, false) => client
                    .restart_exited_and_attach(
                        session_id,
                        previous_generation.expect("retained restart requires exact generation"),
                        &params.cwd,
                        &params.command,
                        &params.args,
                        params.cols,
                        params.rows,
                    ),
                (ExistingSessionStartMode::FreshDaemonAbsent, true) => client
                    .start_absent_excluding_and_attach_for_renderer(
                        session_id,
                        previous_generation,
                        expected_peer.expect("fresh-daemon start requires reviewed peer identity"),
                        &params.cwd,
                        &params.command,
                        &params.args,
                        params.cols,
                        params.rows,
                    ),
                (ExistingSessionStartMode::FreshDaemonAbsent, false) => client
                    .start_absent_excluding_and_attach(
                        session_id,
                        previous_generation,
                        expected_peer.expect("fresh-daemon start requires reviewed peer identity"),
                        &params.cwd,
                        &params.command,
                        &params.args,
                        params.cols,
                        params.rows,
                    ),
            }
        };
        let (mut attached, daemon_recovery) = started
            .map_err(SessionServiceError::Daemon)
            .map_err(SessionAttachFailure::new)?;
        let generation = attached.generation.clone();
        let mut replacement = expected.clone();
        replacement.launch = params.launch.clone();
        replacement.status = SessionStatus::Live;
        replacement.last_known_generation = Some(generation.clone());
        replacement.last_attached_at_ms = params.now_ms;

        let finalized = match reserved_product_shell {
            Some(reserved) => store::finalize_session_attach_if_unchanged_with_workspace_and_guard(
                self.paths,
                &expected,
                &replacement,
                expected_workspace.as_ref(),
                &generation,
                params.now_ms,
                |transaction| reserved.graph_matches_connection(transaction),
            ),
            None => store::finalize_session_attach_if_unchanged_with_workspace(
                self.paths,
                &expected,
                &replacement,
                expected_workspace.as_ref(),
                &generation,
                params.now_ms,
            ),
        };
        match finalized {
            Ok(store::ConditionalSessionAttachFinalize::Finalized { .. }) => {
                let _ =
                    client.retire_applied_start_operation_in_place(&daemon_recovery, &generation);
                Ok((replacement, attached.take_attachment_handoff_seed()))
            }
            Ok(store::ConditionalSessionAttachFinalize::Missing)
            | Ok(store::ConditionalSessionAttachFinalize::Changed)
            | Ok(store::ConditionalSessionAttachFinalize::Quarantined) => {
                let _ = attached.take_attachment_handoff_seed();
                Err(SessionAttachFailure::new(
                    SessionServiceError::AttachAuthorityLost {
                        session_id: params.session_id.clone(),
                    }
                    .preserve_conditional_start_recovery(daemon_recovery),
                ))
            }
            Err(error) => {
                let _ = attached.take_attachment_handoff_seed();
                Err(SessionAttachFailure::new(
                    SessionServiceError::Store(error)
                        .preserve_conditional_start_recovery(daemon_recovery),
                ))
            }
        }
    }

    fn start_and_attach_with_restart(
        &self,
        client: &mut DaemonClient,
        params: &StartParams,
        restart_exited: bool,
        offer_renderer_handoff: bool,
        expected_peer: Option<&ConditionalStartPeerIdentity>,
    ) -> Result<(SessionRecord, Option<AttachmentHandoffSeed>), SessionAttachFailure> {
        debug_assert!(!restart_exited, "restart uses exact Exited-row CAS path");
        // (1) cwd must be an existing directory, matching the daemon (and DaemonClient) boundary.
        // Checked BEFORE any record write so a bad cwd leaves nothing behind.
        if !std::path::Path::new(&params.cwd).is_dir() {
            return Err(SessionServiceError::InvalidCwd {
                cwd: params.cwd.clone(),
            }
            .into());
        }

        // (2) record-before-daemon: the Unknown record exists before the PTY can.
        let mut record = self.write_unknown_record(params)?;

        // (3) start + attach.
        let id = maestro_protocol::SessionId(params.session_id.clone());
        let started = match (offer_renderer_handoff, expected_peer) {
            (true, Some(expected_peer)) => client
                .start_absent_and_attach_after_peer_proof_for_renderer(
                    id,
                    expected_peer,
                    &params.cwd,
                    &params.command,
                    &params.args,
                    params.cols,
                    params.rows,
                ),
            (false, Some(expected_peer)) => client.start_absent_and_attach_after_peer_proof(
                id,
                expected_peer,
                &params.cwd,
                &params.command,
                &params.args,
                params.cols,
                params.rows,
            ),
            (true, None) => client.start_and_attach_for_renderer(
                id,
                &params.cwd,
                &params.command,
                &params.args,
                params.cols,
                params.rows,
            ),
            (false, None) => client.start_and_attach(
                id,
                &params.cwd,
                &params.command,
                &params.args,
                params.cols,
                params.rows,
            ),
        };
        match started {
            // (4) proven live: stamp generation + attach time, flip to Live, persist.
            Ok((mut attached, daemon_recovery)) => {
                let generation = attached.generation.clone();
                let expected = record.clone();
                record.status = SessionStatus::Live;
                record.last_known_generation = Some(generation.clone());
                record.last_attached_at_ms = params.now_ms;
                match store::finalize_session_attach_if_unchanged(
                    self.paths,
                    &expected,
                    &record,
                    &generation,
                    params.now_ms,
                ) {
                    Ok(store::ConditionalSessionAttachFinalize::Finalized { .. }) => {
                        let _ = client
                            .retire_applied_start_operation_in_place(&daemon_recovery, &generation);
                        Ok((record, attached.take_attachment_handoff_seed()))
                    }
                    Ok(store::ConditionalSessionAttachFinalize::Missing)
                    | Ok(store::ConditionalSessionAttachFinalize::Changed)
                    | Ok(store::ConditionalSessionAttachFinalize::Quarantined) => {
                        let _ = attached.take_attachment_handoff_seed();
                        Err(SessionAttachFailure::new(
                            SessionServiceError::AttachAuthorityLost {
                                session_id: params.session_id.clone(),
                            }
                            .preserve_conditional_start_recovery(daemon_recovery),
                        ))
                    }
                    Err(error) => {
                        let _ = attached.take_attachment_handoff_seed();
                        Err(SessionAttachFailure::new(
                            SessionServiceError::Store(error)
                                .preserve_conditional_start_recovery(daemon_recovery),
                        ))
                    }
                }
            }
            // (5) An exact conditional Start ACK followed by a matching Attach-scoped exit proves
            // that the just-started generation ended even though no Grid escaped. Preserve the
            // operation recovery authority, but durably attribute the terminal generation instead
            // of leaving an honestly-known exit as Unknown.
            Err(e @ DaemonClientError::ConditionalStartPossiblyApplied { .. }) => {
                let exited_generation = match &e {
                    DaemonClientError::ConditionalStartPossiblyApplied {
                        recovery, source, ..
                    } if matches!(source.as_ref(), DaemonClientError::SessionExited { .. }) => {
                        Some(recovery.operation_applied_generation().map(str::to_string))
                    }
                    _ => None,
                };
                if let Some(generation) = exited_generation {
                    record.status = SessionStatus::Exited;
                    record.last_known_generation = generation;
                    store::write_record(
                        self.paths,
                        RecordKind::Session,
                        &params.session_id,
                        params.now_ms,
                        &record,
                    )?;
                }
                Err(SessionAttachFailure::new(SessionServiceError::Daemon(e)))
            }
            // A legacy/direct exit proof before a grid is likewise terminal.
            Err(e @ DaemonClientError::SessionExited { .. }) => {
                record.status = SessionStatus::Exited;
                // Best-effort persist of the Exited status; if even that write fails, surface the
                // store error rather than the daemon one (the daemon outcome is already known).
                store::write_record(
                    self.paths,
                    RecordKind::Session,
                    &params.session_id,
                    params.now_ms,
                    &record,
                )?;
                Err(SessionAttachFailure::new(SessionServiceError::Daemon(e)))
            }
            // (6) refused / unreachable / protocol / oversized / timeout: keep the Unknown record.
            // We have NOT proven liveness, but neither have we proven the session never started, so
            // Unknown is the honest state for reconciliation to repair later.
            Err(e) => Err(SessionAttachFailure::new(SessionServiceError::Daemon(e))),
        }
    }

    /// Attach to an already-retained daemon session without sending `StartSession`. No durable
    /// state is written until the daemon proves the session with a matching grid baseline. A
    /// current record is refreshed only if its complete pre-attach row remains unchanged. A
    /// missing row is inserted conditionally before Attach; a concurrent replacement or an
    /// unreadable row fails closed rather than being overwritten. A future-version record is never
    /// overwritten: the method returns an in-memory projection so the GUI can still reopen the PTY
    /// while preserving bytes this build does not understand.
    pub fn attach_existing(
        &self,
        client: &mut DaemonClient,
        params: &StartParams,
    ) -> Result<SessionRecord, SessionServiceError> {
        self.attach_existing_with_renderer_handoff(client, params, false)
            .map(|(record, _)| record)
            .map_err(|failure| failure.error)
    }

    pub(crate) fn attach_existing_for_renderer(
        &self,
        mut client: DaemonClient,
        params: &StartParams,
    ) -> Result<(SessionRecord, AttachmentHandoffAuthority), SessionServiceError> {
        let (record, seed) =
            match self.attach_existing_with_renderer_handoff(&mut client, params, true) {
                Ok(result) => result,
                Err(failure) => {
                    return Err(SessionServiceError::bind_owned_attach_failure(
                        failure,
                        client,
                        &params.session_id,
                    ));
                }
            };
        let seed = seed.ok_or_else(|| SessionServiceError::AttachAuthorityLost {
            session_id: params.session_id.clone(),
        })?;
        Ok((record, AttachmentHandoffAuthority::from_offer(seed, client)))
    }

    /// Resolve A with a daemon-atomic generation precondition. The renderer path sends one Offer
    /// directly, so no ordinary forwarder can flood or impersonate its exact routed Grid; typed
    /// Missing reconnects to the exact same daemon instance/PID inside the inherited budget. The
    /// headless path keeps its no-Offer Missing socket. Complete A+W bytes are checked before the
    /// first request and again in the final IMMEDIATE publication.
    pub(crate) fn attach_existing_exact_for_renderer(
        &self,
        client: DaemonClient,
        proof: &ExistingSessionAttach,
        reserved_product_shell: Option<&ReservedProductShellStart>,
    ) -> Result<ExactExistingAttach, SessionServiceError> {
        self.attach_existing_exact(client, proof, true, reserved_product_shell)
    }

    pub(crate) fn attach_existing_exact_headless(
        &self,
        client: DaemonClient,
        proof: &ExistingSessionAttach,
        reserved_product_shell: Option<&ReservedProductShellStart>,
    ) -> Result<ExactExistingAttach, SessionServiceError> {
        self.attach_existing_exact(client, proof, false, reserved_product_shell)
    }

    /// Resolve one existing durable Session for a reviewed headless/remote caller without ever
    /// falling back to id-only Start semantics.
    ///
    /// Live/Unknown A first receives an exact generation-conditional Attach. A typed `Missing`
    /// result may consume the supplied opaque replay authority for one `Absent { excluded: A }`
    /// conditional Start. Exited A instead requires that same explicit authority and replaces only
    /// its exact retained generation. Every Start path waits for the exact Grid, publishes full-row
    /// A+W -> Live(G) with one transaction, and retires the matching process-lifetime operation.
    /// Arbitrary/redacted/OptOut records cannot construct replay authority and therefore fail
    /// closed. The optional child environment is applied only to a new headless child and must have
    /// been advertised by the exact reviewed daemon peer before any Start is reserved.
    pub fn resolve_existing_exact_headless_with_child_environment(
        &self,
        mut client: DaemonClient,
        proof: &ExistingSessionAttach,
        start: Option<ExistingSessionMissingStart<'_>>,
        child_environment: Option<maestro_protocol::ChildEnvironment>,
    ) -> Result<SessionRecord, SessionServiceError> {
        if start.is_some_and(|start| {
            start.session() != &proof.session
                || start.workspace() != &proof.workspace
                || matches!(
                    start,
                    ExistingSessionMissingStart::KnownSafe(start)
                        | ExistingSessionMissingStart::ExplicitUserShell(start)
                        if !start.has_exact_conversation_scope()
                )
        }) {
            client.abort_connection();
            return Err(SessionServiceError::AttachAuthorityLost {
                session_id: proof.session.session_id.clone(),
            });
        }

        if proof.session.status == SessionStatus::Exited
            && proof.session.last_known_generation.is_some()
        {
            let Some(start) = start else {
                client.abort_connection();
                return Err(SessionServiceError::AttachAuthorityLost {
                    session_id: proof.session.session_id.clone(),
                });
            };
            let peer = client
                .conditional_start_peer_identity()
                .map_err(SessionServiceError::Daemon)?;
            let params = start.params();
            let expected_replaced_start = match start {
                ExistingSessionMissingStart::KnownSafe(start) => Some(start),
                ExistingSessionMissingStart::ExplicitUserShell(_) => None,
                ExistingSessionMissingStart::ReservedProductShell(_) => None,
            };
            let reserved_product_shell = start.reserved();
            let (record, seed) = match self.restart_exited_and_attach_exact(
                &mut client,
                params,
                ExistingSessionStartMode::ReplaceExited,
                false,
                Some(&peer),
                None,
                expected_replaced_start,
                reserved_product_shell,
                child_environment,
            ) {
                Ok(result) => result,
                Err(failure) => {
                    return Err(SessionServiceError::bind_owned_attach_failure(
                        failure,
                        client,
                        &params.session_id,
                    ));
                }
            };
            if seed.is_some() {
                client.abort_connection();
                return Err(SessionServiceError::AttachAuthorityLost {
                    session_id: params.session_id.clone(),
                });
            }
            client.finish_generation_mutation();
            return Ok(record);
        }

        let reserved_product_shell = start.and_then(ExistingSessionMissingStart::reserved);
        match self.attach_existing_exact_headless(client, proof, reserved_product_shell)? {
            ExactExistingAttach::Attached(record, None) => Ok(record),
            ExactExistingAttach::Attached(_, Some(_)) => {
                unreachable!("headless exact Attach never offers renderer authority")
            }
            ExactExistingAttach::StartIfAbsent(authority) => {
                let Some(start) = start else {
                    return Err(SessionServiceError::AttachAuthorityLost {
                        session_id: proof.session.session_id.clone(),
                    });
                };
                self.start_retained_absent(authority, start, false, child_environment)
                    .map(|(record, _)| record)
            }
        }
    }

    fn attach_existing_exact(
        &self,
        mut client: DaemonClient,
        proof: &ExistingSessionAttach,
        offer_renderer_handoff: bool,
        reserved_product_shell: Option<&ReservedProductShellStart>,
    ) -> Result<ExactExistingAttach, SessionServiceError> {
        let durable_authority_matches = match reserved_product_shell {
            Some(reserved) => {
                reserved.session() == &proof.session
                    && reserved.workspace() == &proof.workspace
                    && reserved.graph_matches_in_snapshot(self.paths)?
            }
            None => store::session_workspace_rows_match_in_snapshot(
                self.paths,
                &proof.session,
                &proof.workspace,
            )?,
        };
        if !durable_authority_matches {
            return Err(SessionServiceError::AttachAuthorityLost {
                session_id: proof.session.session_id.clone(),
            });
        }
        let current_session = proof.session.clone();
        let current_workspace = proof.workspace.clone();
        let Some(expected_generation) = proof.session.last_known_generation.as_deref() else {
            // A durable row without a lifetime proof must not send Attach at all. Preserve the
            // reviewed client and full A+W bytes only as one-shot authority for an atomic
            // `Absent(None)` Start; an encountered daemon lifetime will be refused under its map
            // lock before any Grid or foreign bytes cross this socket.
            let peer = client
                .conditional_start_peer_identity_before_current_deadline()
                .map_err(SessionServiceError::Daemon)?;
            return Ok(ExactExistingAttach::StartIfAbsent(
                RetainedDaemonAbsentStartAuthority {
                    client,
                    session: current_session,
                    workspace: current_workspace,
                    peer,
                },
            ));
        };
        let id = maestro_protocol::SessionId(proof.session.session_id.clone());
        let mut attached = if offer_renderer_handoff {
            match client
                .attach_existing_for_renderer_or_reconnect_missing(id, expected_generation)
                .map_err(|failure| SessionServiceError::Daemon(failure.source))?
            {
                GenerationConditionalRendererAttach::Attached(attached) => attached,
                GenerationConditionalRendererAttach::StartIfAbsent(peer) => {
                    return Ok(ExactExistingAttach::StartIfAbsent(
                        RetainedDaemonAbsentStartAuthority {
                            client,
                            session: current_session,
                            workspace: current_workspace,
                            peer,
                        },
                    ));
                }
            }
        } else {
            match client.attach_existing_if_generation(id, expected_generation) {
                Err(DaemonClientError::ConditionalAttachRefused {
                    reason: maestro_protocol::SessionAttachRefusal::Missing,
                    ..
                }) => {
                    let peer = client
                        .conditional_start_peer_identity_before_current_deadline()
                        .map_err(SessionServiceError::Daemon)?;
                    return Ok(ExactExistingAttach::StartIfAbsent(
                        RetainedDaemonAbsentStartAuthority {
                            client,
                            session: current_session,
                            workspace: current_workspace,
                            peer,
                        },
                    ));
                }
                Err(error) => return Err(SessionServiceError::Daemon(error)),
                Ok(attached) if attached.generation == expected_generation => attached,
                Ok(_) => {
                    return Err(SessionServiceError::AttachAuthorityLost {
                        session_id: proof.session.session_id.clone(),
                    });
                }
            }
        };
        #[cfg(test)]
        crate::store_sqlite::run_window_layout_test_hook(
            "after-exact-attach-grid-before-finalize",
            &proof.session.session_id,
        );
        let mut record = current_session.clone();
        if record.status != SessionStatus::Exited {
            record.status = SessionStatus::Live;
        }
        record.last_attached_at_ms = proof.now_ms;
        let finalized = match reserved_product_shell {
            Some(reserved) => store::finalize_session_attach_if_unchanged_with_workspace_and_guard(
                self.paths,
                &current_session,
                &record,
                Some(&current_workspace),
                expected_generation,
                proof.now_ms,
                |transaction| reserved.graph_matches_connection(transaction),
            ),
            None => store::finalize_session_attach_if_unchanged_with_workspace(
                self.paths,
                &current_session,
                &record,
                Some(&current_workspace),
                expected_generation,
                proof.now_ms,
            ),
        };
        match finalized {
            Ok(store::ConditionalSessionAttachFinalize::Finalized { .. }) => {}
            Ok(store::ConditionalSessionAttachFinalize::Missing)
            | Ok(store::ConditionalSessionAttachFinalize::Changed)
            | Ok(store::ConditionalSessionAttachFinalize::Quarantined) => {
                client.abort_connection();
                return Err(SessionServiceError::AttachAuthorityLost {
                    session_id: proof.session.session_id.clone(),
                });
            }
            Err(error) => {
                client.abort_connection();
                return Err(SessionServiceError::Store(error));
            }
        }
        let authority = match (
            offer_renderer_handoff,
            attached.take_attachment_handoff_seed(),
        ) {
            (true, Some(seed)) => {
                client.finish_generation_mutation();
                Some(AttachmentHandoffAuthority::from_offer(seed, client))
            }
            (true, None) => {
                client.abort_connection();
                return Err(SessionServiceError::AttachAuthorityLost {
                    session_id: proof.session.session_id.clone(),
                });
            }
            (false, None) => {
                client.finish_generation_mutation();
                None
            }
            (false, Some(_)) => unreachable!("headless exact Attach never offers a handoff"),
        };
        Ok(ExactExistingAttach::Attached(record, authority))
    }

    pub(crate) fn start_retained_absent_for_renderer(
        &self,
        authority: RetainedDaemonAbsentStartAuthority,
        start: ExistingSessionMissingStart<'_>,
    ) -> Result<(SessionRecord, AttachmentHandoffAuthority), SessionServiceError> {
        let (record, authority) = self.start_retained_absent(authority, start, true, None)?;
        Ok((
            record,
            authority.expect("renderer retained Absent start returns Offer authority"),
        ))
    }

    pub(crate) fn start_retained_absent_headless(
        &self,
        authority: RetainedDaemonAbsentStartAuthority,
        start: ExistingSessionMissingStart<'_>,
    ) -> Result<SessionRecord, SessionServiceError> {
        if matches!(
            start,
            ExistingSessionMissingStart::KnownSafe(start)
                | ExistingSessionMissingStart::ExplicitUserShell(start)
                if !start.has_exact_conversation_scope()
        ) {
            let session_id = start.session().session_id.clone();
            authority.client.abort_connection();
            return Err(SessionServiceError::AttachAuthorityLost { session_id });
        }
        self.start_retained_absent(authority, start, false, None)
            .map(|(record, _)| record)
    }

    fn start_retained_absent(
        &self,
        mut authority: RetainedDaemonAbsentStartAuthority,
        start: ExistingSessionMissingStart<'_>,
        offer_renderer_handoff: bool,
        child_environment: Option<maestro_protocol::ChildEnvironment>,
    ) -> Result<(SessionRecord, Option<AttachmentHandoffAuthority>), SessionServiceError> {
        if &authority.session != start.session() || &authority.workspace != start.workspace() {
            return Err(SessionServiceError::AttachAuthorityLost {
                session_id: start.session().session_id.clone(),
            });
        }
        let params = start.params();
        let (record, seed) = match self.restart_exited_and_attach_exact(
            &mut authority.client,
            params,
            ExistingSessionStartMode::FreshDaemonAbsent,
            offer_renderer_handoff,
            Some(&authority.peer),
            Some((authority.session, authority.workspace)),
            None,
            start.reserved(),
            child_environment,
        ) {
            Ok(result) => result,
            Err(failure) => {
                return Err(SessionServiceError::bind_owned_attach_failure(
                    failure,
                    authority.client,
                    &params.session_id,
                ));
            }
        };
        match (offer_renderer_handoff, seed) {
            (true, Some(seed)) => {
                authority.client.finish_generation_mutation();
                Ok((
                    record,
                    Some(AttachmentHandoffAuthority::from_offer(
                        seed,
                        authority.client,
                    )),
                ))
            }
            (false, None) => {
                authority.client.finish_generation_mutation();
                Ok((record, None))
            }
            _ => {
                authority.client.abort_connection();
                Err(SessionServiceError::AttachAuthorityLost {
                    session_id: params.session_id.clone(),
                })
            }
        }
    }

    fn attach_existing_with_renderer_handoff(
        &self,
        client: &mut DaemonClient,
        params: &StartParams,
        offer_renderer_handoff: bool,
    ) -> Result<(SessionRecord, Option<AttachmentHandoffSeed>), SessionAttachFailure> {
        let loaded =
            store::load_one::<SessionRecord>(self.paths, RecordKind::Session, &params.session_id)?;
        let (expected, future_projection) = match loaded {
            Some(LoadOutcome::Loaded(record)) => (Some(record), false),
            Some(LoadOutcome::FutureVersion { .. }) => (None, true),
            Some(LoadOutcome::Quarantined { .. }) => {
                return Err(SessionServiceError::AttachAuthorityLost {
                    session_id: params.session_id.clone(),
                }
                .into());
            }
            None => {
                let record = self.unknown_record(params)?;
                match store::create_session_record_if_absent(self.paths, &record, params.now_ms)? {
                    store::CreateSessionRecordOutcome::Created => (Some(record), false),
                    store::CreateSessionRecordOutcome::AlreadyExists => {
                        return Err(SessionServiceError::AttachAuthorityLost {
                            session_id: params.session_id.clone(),
                        }
                        .into());
                    }
                }
            }
        };

        let mut attached = if offer_renderer_handoff {
            client
                .attach_existing_for_renderer(maestro_protocol::SessionId(
                    params.session_id.clone(),
                ))
                .map_err(
                    |AttachmentHandoffFailure {
                         source,
                         pending_seed,
                     }| {
                        SessionAttachFailure::with_pending_handoff(
                            SessionServiceError::Daemon(source),
                            pending_seed,
                        )
                    },
                )?
        } else {
            client
                .attach_existing(maestro_protocol::SessionId(params.session_id.clone()))
                .map_err(SessionServiceError::Daemon)
                .map_err(SessionAttachFailure::new)?
        };
        let generation = attached.generation.clone();

        if future_projection {
            return Ok((
                SessionRecord {
                    session_id: params.session_id.clone(),
                    workspace_id: params.workspace_id.clone(),
                    kind: params.kind,
                    launch: params.launch.clone(),
                    cwd_resolved: params.cwd.clone(),
                    agent_task_id: params.agent_task_id.clone(),
                    created_at_ms: params.now_ms,
                    last_attached_at_ms: params.now_ms,
                    last_known_generation: Some(generation),
                    status: SessionStatus::Live,
                },
                attached.take_attachment_handoff_seed(),
            ));
        }
        let expected = expected.expect("non-future attach established an exact Session row");
        let mut record = expected.clone();

        // A retained final-grid record stays Exited; attaching is inspection, not restart
        // authority. Every other record has a live Grid proof and may be marked Live.
        if record.status != SessionStatus::Exited {
            record.status = SessionStatus::Live;
        }
        record.last_attached_at_ms = params.now_ms;
        record.last_known_generation = Some(generation.clone());
        match store::finalize_session_attach_if_unchanged(
            self.paths,
            &expected,
            &record,
            &generation,
            params.now_ms,
        ) {
            Ok(store::ConditionalSessionAttachFinalize::Finalized { .. }) => {
                Ok((record, attached.take_attachment_handoff_seed()))
            }
            Ok(store::ConditionalSessionAttachFinalize::Missing)
            | Ok(store::ConditionalSessionAttachFinalize::Changed)
            | Ok(store::ConditionalSessionAttachFinalize::Quarantined) => {
                let pending_handoff = attached.take_attachment_handoff_seed().and_then(|seed| {
                    client
                        .cancel_attachment_handoff_seed(&seed)
                        .err()
                        .map(|_| seed)
                });
                Err(SessionAttachFailure::with_pending_handoff(
                    SessionServiceError::AttachAuthorityLost {
                        session_id: params.session_id.clone(),
                    },
                    pending_handoff,
                ))
            }
            Err(error) => {
                let pending_handoff = attached.take_attachment_handoff_seed().and_then(|seed| {
                    client
                        .cancel_attachment_handoff_seed(&seed)
                        .err()
                        .map(|_| seed)
                });
                Err(SessionAttachFailure::with_pending_handoff(
                    SessionServiceError::Store(error),
                    pending_handoff,
                ))
            }
        }
    }

    /// Reconcile persisted session records against the daemon's live id set.
    ///
    /// - A non-exited persisted session whose id IS in the live set -> `Live`.
    /// - A persisted session whose id is ABSENT -> `Exited`.
    /// - An already-`Exited` record stays sticky against every passive snapshot. Only an explicit
    ///   generation-bound start/restart operation may revive it; otherwise a snapshot captured just
    ///   before a renderer exit could race and rewrite that newer durable exit back to `Live`.
    /// - A record whose status already matches is left as-is (no needless rewrite).
    /// - A FUTURE-version record (written by a newer Maestro) is observed but NEVER rewritten; its
    ///   path is reported in `skipped_future_version`.
    /// - Corrupt records were already quarantined by the store on load and simply don't appear.
    /// - A live daemon id with NO loaded current-version record (never persisted, or only present as
    ///   a future-version record this build cannot inspect) is reported in `recovered_sessions`,
    ///   sorted by id. This call only surfaces it; callers must establish their own ownership proof
    ///   before applying a lifecycle action.
    ///
    /// This does NOT invent or touch UI tabs or AgentTask state — it only repairs `SessionStatus`
    /// for records it owns and reports daemon-only live ids to the native lifecycle owner.
    pub fn reconcile(
        &self,
        client: &mut DaemonClient,
    ) -> Result<ReconcileReport, SessionServiceError> {
        // Automatic mutation authority comes only from the bounded protocol-v3 capability probe
        // plus one complete, duplicate-free generation snapshot. A clean legacy capability refusal
        // falls back to the historical read-only listing for status projection, but yields no
        // release targets. Any other strict-snapshot failure aborts reconciliation rather than
        // silently treating partial metadata as absence.
        let (live_ids, live_generations, strict_generation_authority) =
            match client.generation_mutation_snapshot() {
                Ok(snapshot) => {
                    let generations: std::collections::HashMap<String, String> = snapshot
                        .iter()
                        .map(|(session_id, generation)| {
                            (session_id.to_string(), generation.to_string())
                        })
                        .collect();
                    let ids = generations.keys().cloned().collect();
                    (ids, generations, true)
                }
                Err(DaemonClientError::MutationProtocolUnsupported { .. }) => {
                    let live = client
                        .list_sessions_snapshot()
                        .map_err(SessionServiceError::Daemon)?;
                    let ids: std::collections::HashSet<String> =
                        live.ids.into_iter().map(|id| id.0).collect();
                    // Legacy metadata remains useful for read-only status reconciliation, but it
                    // grants no cleanup authority because completeness/capability was not proven.
                    let generations = live
                        .sessions
                        .into_iter()
                        .filter_map(|info| {
                            let id = info.id.0;
                            (ids.contains(&id)).then_some((id, info.generation?))
                        })
                        .collect();
                    (ids, generations, false)
                }
                Err(error) => return Err(SessionServiceError::Daemon(error)),
            };

        // Test-only deterministic seam for the snapshot -> durable-row race. Production executes
        // an empty function; no capability or timing hook is exposed across the crate boundary.
        run_reconcile_after_snapshot_hook();

        let outcomes: Vec<LoadOutcome<SessionRecord>> =
            store::load_all(self.paths, RecordKind::Session)?;

        // Ids we held a loadable CURRENT-version record for, and the narrower subset whose durable
        // generation exactly represented the strict daemon snapshot. Same-id presence alone is not
        // lifetime authority: None/mismatch must stay unrepresented and must never mint a
        // MatchingRowIsProof release target.
        let mut loaded_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut exact_live_row_ids: std::collections::HashSet<String> =
            std::collections::HashSet::new();

        let mut report = ReconcileReport::default();
        for outcome in outcomes {
            match outcome {
                LoadOutcome::Loaded(record) => {
                    loaded_ids.insert(record.session_id.clone());
                    let live_generation = live_generations.get(&record.session_id);
                    let exact_live_generation = strict_generation_authority
                        && live_generation.is_some()
                        && record.last_known_generation.as_ref() == live_generation;
                    if exact_live_generation {
                        exact_live_row_ids.insert(record.session_id.clone());
                    }
                    let desired_status = if record.status == SessionStatus::Exited {
                        SessionStatus::Exited
                    } else if exact_live_generation {
                        SessionStatus::Live
                    } else if strict_generation_authority && live_generation.is_none() {
                        // Completeness plus absence may mark the exact durable row Exited, but its
                        // last-known generation remains A. Presence with None/mismatched A is not
                        // adoptable and receives no write at all.
                        SessionStatus::Exited
                    } else {
                        record.status
                    };
                    let desired_generation = record.last_known_generation.as_deref();

                    let expected_generation = record.last_known_generation.clone();
                    let needs_write = record.status != desired_status
                        || expected_generation.as_deref() != desired_generation;
                    let (status, rewritten) = if needs_write {
                        match store::reconcile_session_if_unchanged(
                            self.paths,
                            &record.session_id,
                            record.status,
                            expected_generation.as_deref(),
                            desired_status,
                            desired_generation,
                            record.last_attached_at_ms,
                        )? {
                            store::ConditionalSessionReconcile::Updated(current) => {
                                (current.status, true)
                            }
                            store::ConditionalSessionReconcile::Unchanged(current)
                            | store::ConditionalSessionReconcile::Stale(current) => {
                                (current.status, false)
                            }
                            // A concurrent delete/corruption is left untouched and omitted from
                            // this one report; the next pass will classify it normally.
                            store::ConditionalSessionReconcile::Missing
                            | store::ConditionalSessionReconcile::Quarantined => continue,
                        }
                    } else {
                        (record.status, false)
                    };
                    report.sessions.push(ReconciledSession {
                        session_id: record.session_id,
                        status,
                        rewritten,
                    });
                }
                // Never rewrite a record from a newer build — that could drop fields we don't model.
                LoadOutcome::FutureVersion { path, .. } => {
                    report.skipped_future_version.push(path);
                }
                // Corrupt records were quarantined on load; they don't reach here as data.
                LoadOutcome::Quarantined { .. } => {}
            }
        }

        // Carry exact authority for ALL strict live metadata. The caller still needs a complete
        // dashboard no-pane proof across two snapshots; this report only binds that later policy to
        // the daemon generation and transaction-local row expectation observed here.
        report.live_session_release_targets = strict_generation_authority
            .then_some(())
            .into_iter()
            .flat_map(|()| live_generations.iter())
            .filter_map(|(session_id, generation)| {
                let row_policy = if exact_live_row_ids.contains(session_id) {
                    SessionRowPolicy::MatchingRowIsProof
                } else {
                    SessionRowPolicy::RowMustBeAbsent
                };
                SessionReleaseTarget::new_recovered(
                    session_id.clone(),
                    generation.clone(),
                    row_policy,
                )
                .ok()
            })
            .collect();
        report.live_session_release_targets.sort();

        // Strict same-id None/mismatch is as unrepresented as a daemon-only id. Legacy snapshots
        // have no generation authority, so they retain the historical read-only id classification.
        let mut recovered_ids: Vec<String> = live_ids
            .into_iter()
            .filter(|id| {
                if strict_generation_authority {
                    !exact_live_row_ids.contains(id)
                } else {
                    !loaded_ids.contains(id)
                }
            })
            .collect();
        recovered_ids.sort();
        report.recovered_session_targets = strict_generation_authority
            .then_some(())
            .into_iter()
            .flat_map(|()| recovered_ids.iter())
            .filter_map(|session_id| {
                live_generations.get(session_id).and_then(|generation| {
                    SessionReleaseTarget::new_recovered(
                        session_id.clone(),
                        generation.clone(),
                        SessionRowPolicy::RowMustBeAbsent,
                    )
                    // Daemon session metadata is wire input.  A malformed id/generation still
                    // appears in the read-only recovered-session report, but grants no durable
                    // mutation authority and must never panic the host process.
                    .ok()
                })
            })
            .collect();
        let mut recovered: Vec<RecoveredSession> = recovered_ids
            .into_iter()
            .map(|session_id| RecoveredSession { session_id })
            .collect();
        recovered.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        report.recovered_sessions = recovered;

        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maestro_protocol::SessionId;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream as StdUnixStream};
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::thread::JoinHandle;
    use tempfile::TempDir;

    // ---- loopback stub daemon (no real pty-daemon) ------------------------------------------

    /// A loopback stub daemon on a temp socket, identical in spirit to the daemon_client tests: one
    /// accept thread runs a caller script `(requests_tx, &mut stream)`. NOT a real daemon — no PTY,
    /// no git. Request lines are echoed back over an mpsc for assertions.
    struct StubDaemon {
        path: PathBuf,
        _dir: TempDir,
        handle: Option<JoinHandle<()>>,
        requests: mpsc::Receiver<String>,
    }

    impl StubDaemon {
        fn spawn<F>(serve: F) -> StubDaemon
        where
            F: FnOnce(&mpsc::Sender<String>, &mut StdUnixStream) + Send + 'static,
        {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("stub.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let (req_tx, req_rx) = mpsc::channel::<String>();
            let handle = std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    // This fixture models one exact reviewed daemon connection. Recovery tests
                    // must not accidentally reconnect into a still-listening but unserviced
                    // backlog and wait for a timeout instead of observing the intended peer loss.
                    drop(listener);
                    serve(&req_tx, &mut stream);
                    drop(stream);
                }
            });
            StubDaemon {
                path,
                _dir: dir,
                handle: Some(handle),
                requests: req_rx,
            }
        }

        fn collected_requests(&self) -> Vec<String> {
            self.requests.try_iter().collect()
        }
    }

    impl Drop for StubDaemon {
        fn drop(&mut self) {
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    fn read_request(reader: &mut impl BufRead, tx: &mpsc::Sender<String>) -> Option<String> {
        let mut line = String::new();
        let n = reader.read_line(&mut line).unwrap();
        if n == 0 {
            return None;
        }
        let trimmed = line.trim().to_string();
        let _ = tx.send(trimmed.clone());
        Some(trimmed)
    }

    fn answer_v3_generation_snapshot(
        reader: &mut impl BufRead,
        tx: &mpsc::Sender<String>,
        stream: &mut StdUnixStream,
        sessions: &[(&str, &str)],
    ) {
        assert_eq!(
            read_request(reader, tx).as_deref(),
            Some(r#"{"op":"daemon_info"}"#)
        );
        writeln!(
            stream,
            "{}",
            serde_json::json!({
                "ev": "daemon_info",
                "protocol_version": maestro_protocol::DAEMON_PROTOCOL_VERSION,
                "build_version": "session-service-test",
                "daemon_instance_id": "22222222222242228222222222222222",
                "generation_conditional_mutations": true,
                "attachment_aware_conditional_kill": true,
            })
        )
        .unwrap();
        stream.flush().unwrap();
        assert_eq!(
            read_request(reader, tx).as_deref(),
            Some(r#"{"op":"list_sessions"}"#)
        );
        let ids: Vec<&str> = sessions.iter().map(|(id, _)| *id).collect();
        let metadata: Vec<_> = sessions
            .iter()
            .map(|(id, generation)| serde_json::json!({"id": id, "generation": generation}))
            .collect();
        writeln!(
            stream,
            "{}",
            serde_json::json!({"ev": "sessions", "ids": ids, "sessions": metadata})
        )
        .unwrap();
        stream.flush().unwrap();
        let mut remainder = String::new();
        reader.read_to_string(&mut remainder).unwrap();
        assert!(remainder.is_empty());
    }

    fn answer_legacy_snapshot(
        reader: &mut impl BufRead,
        tx: &mpsc::Sender<String>,
        stream: &mut StdUnixStream,
        ids: &[&str],
    ) {
        assert_eq!(
            read_request(reader, tx).as_deref(),
            Some(r#"{"op":"daemon_info"}"#)
        );
        writeln!(
            stream,
            "{}",
            serde_json::json!({
                "ev": "daemon_info",
                "protocol_version": 1,
                "build_version": "legacy-session-service-test",
            })
        )
        .unwrap();
        stream.flush().unwrap();
        assert_eq!(
            read_request(reader, tx).as_deref(),
            Some(r#"{"op":"list_sessions"}"#)
        );
        writeln!(
            stream,
            "{}",
            serde_json::json!({"ev": "sessions", "ids": ids})
        )
        .unwrap();
        stream.flush().unwrap();
    }

    // ---- helpers ----------------------------------------------------------------------------

    fn paths_in(tmp: &TempDir) -> AppPaths {
        let paths = AppPaths::with_base(tmp.path().join("Maestro"));
        // The relational store enforces sessions.workspace_id → workspaces → projects (FKs). Every SessionRecord these
        // tests write uses workspace_id "ws1"; seed project → workspace so a write doesn't violate the constraint
        // (production always creates the project + workspace before a session).
        seed_workspace(&paths, "ws1", "proj-1");
        paths
    }

    /// Persist a minimal parent Project so an FK-bearing Workspace can reference it.
    fn seed_project(paths: &AppPaths, id: &str) {
        crate::project::ProjectService::new(paths)
            .create(id, id, "/r", crate::project::NewProject::default(), 1)
            .ok();
    }

    /// Seed the project → workspace chain a SessionRecord needs (sessions.workspace_id → workspaces.project_id).
    fn seed_workspace(paths: &AppPaths, workspace_id: &str, project_id: &str) {
        seed_project(paths, project_id);
        let workspace = crate::records::Workspace {
            workspace_id: workspace_id.into(),
            project_id: project_id.into(),
            root: "/tmp".into(),
            policy: crate::policy::WorkspacePolicy::ScratchCwd,
            consent: crate::records::WorkspaceConsent {
                worktree_create: false,
                repo_write: false,
                granted_at_ms: None,
            },
        };
        store::write_record(paths, RecordKind::Workspace, workspace_id, 0, &workspace).ok();
    }

    fn known_safe(spec_id: &str) -> LaunchSpec {
        LaunchSpec::KnownSafe {
            launch_spec_id: spec_id.into(),
            params: vec![],
        }
    }

    fn params(session_id: &str, cwd: &str) -> StartParams {
        StartParams {
            session_id: session_id.into(),
            workspace_id: "ws1".into(),
            kind: SessionKind::Shell,
            launch: known_safe("ls-1"),
            cwd: cwd.into(),
            command: "bash".into(),
            args: vec!["-l".into()],
            cols: 80,
            rows: 24,
            agent_task_id: None,
            now_ms: 1000,
        }
    }

    const PREPARED_DAEMON_INSTANCE: &str = "22222222222242228222222222222222";

    fn answer_prepared_daemon_info(stream: &mut StdUnixStream) {
        writeln!(
            stream,
            "{}",
            serde_json::json!({
                "ev": "daemon_info",
                "protocol_version": maestro_protocol::DAEMON_PROTOCOL_VERSION,
                "build_version": "prepared-session-test",
                "daemon_instance_id": PREPARED_DAEMON_INSTANCE,
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
        stream.flush().unwrap();
    }

    fn prepared_existing_start(
        paths: &AppPaths,
        cwd: &std::path::Path,
        suffix: &str,
    ) -> PreparedNewSessionStart {
        let service = crate::WindowLayoutService::new(paths);
        let window_id = format!("prepared-service-window-{suffix}");
        service.create_empty_snapshot(&window_id, 10).unwrap();
        assert!(matches!(
            service
                .ensure_project_assignment(&window_id, "proj-1", 11)
                .unwrap(),
            crate::ConditionalWindowProjectAssignment::Applied(_)
        ));
        let window = service.load_snapshot(&window_id).unwrap().unwrap();
        let project = crate::ProjectService::new(paths)
            .load("proj-1")
            .unwrap()
            .unwrap();
        let workspace = match store::load_one::<Workspace>(paths, RecordKind::Workspace, "ws1")
            .unwrap()
            .unwrap()
        {
            LoadOutcome::Loaded(workspace) => workspace,
            other => panic!("expected prepared Workspace, got {other:?}"),
        };
        let mut start_params = params(
            &format!("prepared-service-session-{suffix}"),
            cwd.to_string_lossy().as_ref(),
        );
        let mut live_argv = vec![start_params.command.clone()];
        live_argv.extend(start_params.args.iter().cloned());
        start_params.launch = crate::redact::adhoc_launch_spec(&live_argv);
        service
            .prepare_new_tab_session(
                &window,
                &project,
                &workspace,
                start_params,
                &format!("prepared-service-tab-{suffix}"),
                "Prepared",
                false,
                crate::AttentionState::default(),
            )
            .unwrap()
    }

    fn prepared_fresh_start(
        paths: &AppPaths,
        cwd: &std::path::Path,
        suffix: &str,
    ) -> PreparedNewSessionStart {
        let project_id = format!("prepared-fresh-service-project-{suffix}");
        crate::ProjectService::new(paths)
            .create(
                &project_id,
                "Prepared",
                cwd.to_string_lossy().as_ref(),
                crate::NewProject::default(),
                10,
            )
            .unwrap();
        let service = crate::WindowLayoutService::new(paths);
        let graph = service
            .load_project_window_graph_snapshot(&project_id)
            .unwrap()
            .unwrap();
        let workspace_id = format!("prepared-fresh-service-workspace-{suffix}");
        let mut start_params = params(
            &format!("prepared-fresh-service-session-{suffix}"),
            cwd.to_string_lossy().as_ref(),
        );
        start_params.workspace_id = workspace_id.clone();
        let mut live_argv = vec![start_params.command.clone()];
        live_argv.extend(start_params.args.iter().cloned());
        start_params.launch = crate::redact::adhoc_launch_spec(&live_argv);
        let prepared_workspace = crate::PreparedWorkspace::unsealed(
            crate::WorkspacePolicy::ScratchCwd,
            workspace_id.clone(),
            start_params.session_id.clone(),
            cwd,
        );
        let session = prepared_workspace
            .adhoc_session_spec(
                crate::SessionKind::Shell,
                &live_argv,
                start_params.cols,
                start_params.rows,
                start_params.now_ms,
            )
            .unwrap();
        match service
            .create_prepared_fresh_window_graph(
                &graph,
                crate::PreparedFreshWindowGraphSpec {
                    workspace: Workspace {
                        workspace_id,
                        project_id,
                        root: cwd.to_string_lossy().into_owned(),
                        policy: crate::WorkspacePolicy::ScratchCwd,
                        consent: crate::WorkspaceConsent::default(),
                    },
                    session,
                    window_id: format!("prepared-fresh-service-window-{suffix}"),
                    window_name: "Prepared".into(),
                    tab_id: format!("prepared-fresh-service-tab-{suffix}"),
                    tab_title: "Prepared".into(),
                    tab_pinned: false,
                    tab_attention: crate::AttentionState::default(),
                    touch_project: false,
                },
            )
            .unwrap()
        {
            crate::PreparedFreshWindowGraphCreateOutcome::Created(created) => created.start,
            other => panic!("expected prepared fresh graph, got {other:?}"),
        }
    }

    struct PreparedProviderEnv;

    impl crate::LaunchEnvLookup for PreparedProviderEnv {
        fn shell_utf8(&self) -> Option<String> {
            Some("/bin/prepared-provider-shell".into())
        }

        fn home_os(&self) -> Option<std::ffi::OsString> {
            None
        }
    }

    fn prepared_fresh_provider_start(
        paths: &AppPaths,
        cwd: &std::path::Path,
        suffix: &str,
        selected_provider: &str,
        source_argv: &[String],
    ) -> PreparedNewSessionStart {
        let project_id = format!("prepared-provider-project-{suffix}");
        crate::ProjectService::new(paths)
            .create(
                &project_id,
                "Prepared Provider",
                cwd.to_string_lossy().as_ref(),
                crate::NewProject::default(),
                10,
            )
            .unwrap();
        let service = crate::WindowLayoutService::new(paths);
        let graph = service
            .load_project_window_graph_snapshot(&project_id)
            .unwrap()
            .unwrap();
        let workspace_id = format!("prepared-provider-workspace-{suffix}");
        let session_id = format!("prepared-provider-session-{suffix}");
        let prepared_workspace = crate::PreparedWorkspace::unsealed(
            crate::WorkspacePolicy::ScratchCwd,
            workspace_id.clone(),
            session_id,
            cwd,
        );
        let session = prepared_workspace
            .provider_session_spec(
                selected_provider,
                source_argv,
                &PreparedProviderEnv,
                80,
                24,
                1000,
            )
            .unwrap();
        match service
            .create_prepared_fresh_window_graph(
                &graph,
                crate::PreparedFreshWindowGraphSpec {
                    workspace: Workspace {
                        workspace_id,
                        project_id,
                        root: cwd.to_string_lossy().into_owned(),
                        policy: crate::WorkspacePolicy::ScratchCwd,
                        consent: crate::WorkspaceConsent::default(),
                    },
                    session,
                    window_id: format!("prepared-provider-window-{suffix}"),
                    window_name: "Prepared Provider".into(),
                    tab_id: format!("prepared-provider-tab-{suffix}"),
                    tab_title: "Prepared Provider".into(),
                    tab_pinned: false,
                    tab_attention: crate::AttentionState::default(),
                    touch_project: false,
                },
            )
            .unwrap()
        {
            crate::PreparedFreshWindowGraphCreateOutcome::Created(created) => created.start,
            other => panic!("expected prepared provider graph, got {other:?}"),
        }
    }

    fn answer_prepared_start_applied(
        reader: &mut impl BufRead,
        tx: &mpsc::Sender<String>,
        stream: &mut StdUnixStream,
        generation: &str,
        expect_handoff: bool,
        expect_retirement: bool,
    ) {
        let (id, operation_token, output_generation) =
            answer_prepared_start_prefix(reader, tx, stream, generation, expect_handoff);
        writeln!(
            stream,
            "{}",
            serde_json::json!({
                "ev": "grid",
                "id": id,
                "output_generation": output_generation,
                "grid": {"generation": generation, "revision": 7},
            })
        )
        .unwrap();
        stream.flush().unwrap();

        if expect_retirement {
            answer_applied_start_operation_retired(
                reader,
                tx,
                stream,
                &id,
                &operation_token,
                generation,
            );
        }
    }

    fn answer_prepared_start_prefix(
        reader: &mut impl BufRead,
        tx: &mpsc::Sender<String>,
        stream: &mut StdUnixStream,
        generation: &str,
        expect_handoff: bool,
    ) -> (
        maestro_protocol::SessionId,
        maestro_protocol::SessionStartOperationToken,
        u64,
    ) {
        let (reserved_id, reserved_token) = answer_start_operation_reserved(reader, tx, stream);
        let request = serde_json::from_str::<maestro_protocol::ClientRequest>(
            &read_request(reader, tx).expect("one prepared StartSession"),
        )
        .unwrap();
        let (id, operation_token) = match request {
            maestro_protocol::ClientRequest::StartSession {
                id,
                restart_exited: false,
                conditional_start:
                    Some(maestro_protocol::ConditionalSessionStart {
                        operation_token,
                        precondition:
                            maestro_protocol::SessionStartPrecondition::Absent {
                                excluded_generation: None,
                            },
                    }),
                ..
            } => (id, operation_token),
            other => panic!("expected one Absent(None) StartSession, got {other:?}"),
        };
        assert_eq!(id, reserved_id);
        assert_eq!(operation_token, reserved_token);
        writeln!(
            stream,
            "{}",
            serde_json::json!({
                "ev": "conditional_session_start",
                "id": id,
                "operation_token": operation_token.as_str(),
                "daemon_instance_id": PREPARED_DAEMON_INSTANCE,
                "outcome": {"status": "applied", "generation": generation},
            })
        )
        .unwrap();
        stream.flush().unwrap();

        let attach = serde_json::from_str::<maestro_protocol::ClientRequest>(
            &read_request(reader, tx).expect("post-start exact Attach"),
        )
        .unwrap();
        let output_generation = match attach {
            maestro_protocol::ClientRequest::Attach {
                id: attached_id,
                expected_session_generation: Some(attached_generation),
                output_generation: Some(output_generation),
                handoff,
                ..
            } if attached_id == id
                && attached_generation == generation
                && handoff.is_some() == expect_handoff =>
            {
                output_generation
            }
            other => panic!("expected exact post-start Attach, got {other:?}"),
        };
        (id, operation_token, output_generation)
    }

    fn answer_start_operation_reserved(
        reader: &mut impl BufRead,
        tx: &mpsc::Sender<String>,
        stream: &mut StdUnixStream,
    ) -> (
        maestro_protocol::SessionId,
        maestro_protocol::SessionStartOperationToken,
    ) {
        let request = serde_json::from_str::<maestro_protocol::ClientRequest>(
            &read_request(reader, tx).expect("ReserveStartOperation request"),
        )
        .unwrap();
        let (id, operation_token) = match request {
            maestro_protocol::ClientRequest::ReserveStartOperation {
                id,
                operation_token,
            } => (id, operation_token),
            other => panic!("expected ReserveStartOperation, got {other:?}"),
        };
        writeln!(
            stream,
            "{}",
            serde_json::json!({
                "ev": "start_operation_reserved",
                "id": id,
                "operation_token": operation_token.as_str(),
                "daemon_instance_id": PREPARED_DAEMON_INSTANCE,
                "outcome": {"status": "reserved"},
            })
        )
        .unwrap();
        stream.flush().unwrap();
        (id, operation_token)
    }

    fn answer_applied_start_operation_retired(
        reader: &mut impl BufRead,
        tx: &mpsc::Sender<String>,
        stream: &mut StdUnixStream,
        expected_id: &maestro_protocol::SessionId,
        expected_token: &maestro_protocol::SessionStartOperationToken,
        expected_generation: &str,
    ) {
        let request = serde_json::from_str::<maestro_protocol::ClientRequest>(
            &read_request(reader, tx).expect("RetireStartOperation request"),
        )
        .unwrap();
        assert!(matches!(
            request,
            maestro_protocol::ClientRequest::RetireStartOperation {
                ref id,
                ref operation_token,
                expected:
                    maestro_protocol::SessionStartOperationRetireExpectation::Applied {
                        ref generation,
                    },
            } if id == expected_id
                && operation_token == expected_token
                && generation == expected_generation
        ));
        writeln!(
            stream,
            "{}",
            serde_json::json!({
                "ev": "start_operation_retired",
                "id": expected_id,
                "operation_token": expected_token.as_str(),
                "daemon_instance_id": PREPARED_DAEMON_INSTANCE,
                "outcome": {"status": "retired"},
            })
        )
        .unwrap();
        stream.flush().unwrap();
    }

    fn answer_unapplied_start_operation_retired(
        reader: &mut impl BufRead,
        tx: &mpsc::Sender<String>,
        stream: &mut StdUnixStream,
        expected_id: &maestro_protocol::SessionId,
        expected_token: &maestro_protocol::SessionStartOperationToken,
    ) {
        let request = serde_json::from_str::<maestro_protocol::ClientRequest>(
            &read_request(reader, tx).expect("unapplied RetireStartOperation request"),
        )
        .unwrap();
        assert!(matches!(
            request,
            maestro_protocol::ClientRequest::RetireStartOperation {
                ref id,
                ref operation_token,
                expected: maestro_protocol::SessionStartOperationRetireExpectation::Unapplied,
            } if id == expected_id && operation_token == expected_token
        ));
        writeln!(
            stream,
            "{}",
            serde_json::json!({
                "ev": "start_operation_retired",
                "id": expected_id,
                "operation_token": expected_token.as_str(),
                "daemon_instance_id": PREPARED_DAEMON_INSTANCE,
                "outcome": {"status": "retired"},
            })
        )
        .unwrap();
        stream.flush().unwrap();
    }

    fn answer_regular_start_applied_and_retired(
        reader: &mut impl BufRead,
        tx: &mpsc::Sender<String>,
        stream: &mut StdUnixStream,
        generation: &str,
    ) {
        assert_eq!(
            read_request(reader, tx).as_deref(),
            Some(r#"{"op":"daemon_info"}"#)
        );
        answer_prepared_daemon_info(stream);
        answer_prepared_start_applied(reader, tx, stream, generation, false, true);
    }

    fn load_record(paths: &AppPaths, id: &str) -> SessionRecord {
        match store::load_one::<SessionRecord>(paths, RecordKind::Session, id)
            .unwrap()
            .unwrap()
        {
            LoadOutcome::Loaded(r) => r,
            other => panic!("expected Loaded record, got {other:?}"),
        }
    }

    fn exit_record(id: &str, status: SessionStatus, generation: Option<&str>) -> SessionRecord {
        SessionRecord {
            session_id: id.to_string(),
            workspace_id: "ws1".into(),
            kind: SessionKind::Shell,
            launch: known_safe("exit-observation-test"),
            cwd_resolved: "/tmp".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: generation.map(str::to_string),
            status,
        }
    }

    fn session_write_count(id: &str) -> usize {
        crate::write_trace::recent()
            .into_iter()
            .filter(|event| event.op == "write" && event.kind == "Session" && event.id == id)
            .count()
    }

    // ---- tests ------------------------------------------------------------------------------

    /// The record is persisted as `Unknown` BEFORE the daemon sends its grid: we prove it by having
    /// the stub assert the record already exists on disk at the moment it receives `StartSession`,
    /// then reply with the grid.
    #[test]
    fn record_is_written_unknown_before_daemon_requests() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();

        // The stub captures the on-disk record status seen at StartSession time via a channel.
        let (seen_tx, seen_rx) = mpsc::channel::<String>();
        let probe_paths = paths.clone();
        let stub = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"daemon_info"}"#)
            );
            answer_prepared_daemon_info(stream);
            let (reserved_id, operation_token) =
                answer_start_operation_reserved(&mut reader, tx, stream);
            // StartSession arrives: the Unknown record must already be on disk.
            let start: maestro_protocol::ClientRequest = serde_json::from_str(
                &read_request(&mut reader, tx).expect("conditional StartSession"),
            )
            .unwrap();
            assert!(matches!(
                start,
                maestro_protocol::ClientRequest::StartSession {
                    ref id,
                    conditional_start: Some(maestro_protocol::ConditionalSessionStart {
                        operation_token: ref token,
                        precondition: maestro_protocol::SessionStartPrecondition::Absent {
                            excluded_generation: None,
                        },
                    }),
                    ..
                } if id == &reserved_id && token == &operation_token
            ));
            let status =
                match store::load_one::<SessionRecord>(&probe_paths, RecordKind::Session, "s1")
                    .unwrap()
                {
                    Some(LoadOutcome::Loaded(r)) => format!("{:?}", r.status),
                    other => format!("missing-or-bad: {other:?}"),
                };
            let _ = seen_tx.send(status);
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "conditional_session_start",
                    "id": reserved_id,
                    "operation_token": operation_token.as_str(),
                    "daemon_instance_id": PREPARED_DAEMON_INSTANCE,
                    "outcome": {"status": "applied", "generation": "gen-1"},
                })
            )
            .unwrap();
            stream.flush().unwrap();
            // Attach arrives.
            let attach: maestro_protocol::ClientRequest =
                serde_json::from_str(&read_request(&mut reader, tx).expect("exact Attach"))
                    .unwrap();
            let output_generation = match attach {
                maestro_protocol::ClientRequest::Attach {
                    id,
                    expected_session_generation: Some(generation),
                    output_generation: Some(output_generation),
                    ..
                } if id == reserved_id && generation == "gen-1" => output_generation,
                other => panic!("expected exact Attach, got {other:?}"),
            };
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "grid",
                    "id": reserved_id,
                    "output_generation": output_generation,
                    "grid": {"generation": "gen-1", "revision": 3},
                })
            )
            .unwrap();
            stream.flush().unwrap();
            answer_applied_start_operation_retired(
                &mut reader,
                tx,
                stream,
                &reserved_id,
                &operation_token,
                "gen-1",
            );
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let svc = SessionService::new(&paths);
        let rec = svc
            .start_and_attach(&mut client, &params("s1", &cwd_path))
            .unwrap();

        // What the daemon saw at StartSession time:
        let seen = seen_rx.recv().unwrap();
        assert_eq!(seen, "Unknown", "record must be Unknown before daemon grid");
        // Final record is Live with the generation.
        assert_eq!(rec.status, SessionStatus::Live);
        assert_eq!(rec.last_known_generation.as_deref(), Some("gen-1"));
    }

    /// A successful start/attach updates the persisted record: `Live`, the grid generation, the
    /// resolved cwd, and the attach timestamp.
    #[test]
    fn successful_start_updates_status_generation_and_timestamp() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();

        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_regular_start_applied_and_retired(&mut reader, tx, stream, "gen-xyz");
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let svc = SessionService::new(&paths);
        let mut p = params("s1", &cwd_path);
        p.now_ms = 4242;
        let rec = svc.start_and_attach(&mut client, &p).unwrap();

        assert_eq!(rec.status, SessionStatus::Live);
        assert_eq!(rec.last_known_generation.as_deref(), Some("gen-xyz"));
        assert_eq!(rec.cwd_resolved, cwd_path);
        assert_eq!(rec.last_attached_at_ms, 4242);

        // Persisted on disk, not just in-memory.
        let on_disk = load_record(&paths, "s1");
        assert_eq!(on_disk, rec);
    }

    /// A missing cwd fails BEFORE any daemon request AND before any record is written — the safe
    /// state is "nothing persisted".
    #[test]
    fn missing_cwd_fails_before_daemon_and_writes_no_record() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let svc = SessionService::new(&paths);
        let err = svc
            .start_and_attach(&mut client, &params("s1", "/no/such/dir/xyz"))
            .unwrap_err();
        let rendered = err.to_string();
        assert!(!rendered.contains("/no/such/dir/xyz"));
        assert!(!rendered.contains("xyz"));
        assert!(matches!(err, SessionServiceError::InvalidCwd { .. }));

        let nested = SessionServiceError::Daemon(DaemonClientError::InvalidCwd {
            cwd: "/private/repo/unique-cwd-name".into(),
        });
        let nested_rendered = nested.to_string();
        assert!(!nested_rendered.contains("/private/repo/unique-cwd-name"));
        assert!(!nested_rendered.contains("unique-cwd-name"));
        drop(client);

        assert!(
            stub.collected_requests().is_empty(),
            "no daemon request when cwd is invalid"
        );
        // No record was written.
        let on_disk = store::load_one::<SessionRecord>(&paths, RecordKind::Session, "s1").unwrap();
        assert!(on_disk.is_none(), "no record may be written for a bad cwd");
    }

    /// An EXISTING regular file (not a directory) as cwd also fails before any daemon request /
    /// record write — matching the daemon's `is_dir()` boundary.
    #[test]
    fn non_directory_cwd_fails_before_daemon_and_writes_no_record() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let file_dir = TempDir::new().unwrap();
        let file_path = file_dir.path().join("a-file");
        std::fs::write(&file_path, b"not a dir").unwrap();
        let file_cwd = file_path.to_string_lossy().to_string();

        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let svc = SessionService::new(&paths);
        let err = svc
            .start_and_attach(&mut client, &params("s1", &file_cwd))
            .unwrap_err();
        assert!(matches!(err, SessionServiceError::InvalidCwd { .. }));
        drop(client);
        assert!(stub.collected_requests().is_empty());
        assert!(
            store::load_one::<SessionRecord>(&paths, RecordKind::Session, "s1")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn prepared_new_session_sends_exactly_one_absent_start_and_rebases_compensation() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let start = prepared_existing_start(&paths, cwd.path(), "success");
        let session_id = start.session_id().to_string();
        let stub = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"daemon_info"}"#)
            );
            answer_prepared_daemon_info(stream);
            answer_prepared_start_applied(
                &mut reader,
                tx,
                stream,
                "prepared-generation",
                false,
                true,
            );
            let mut remainder = String::new();
            reader.read_to_string(&mut remainder).unwrap();
            assert!(remainder.is_empty(), "no second Start or extra request");
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let peer = client.conditional_start_peer_identity().unwrap();
        let started = SessionService::new(&paths)
            .start_prepared_new_session(client, start, &peer)
            .unwrap();
        assert_eq!(started.record().status, SessionStatus::Live);
        assert_eq!(
            started.record().last_known_generation.as_deref(),
            Some("prepared-generation")
        );
        assert_eq!(load_record(&paths, &session_id), *started.record());
        let (_, compensation) = started.into_parts();
        assert!(matches!(
            crate::WindowLayoutService::new(&paths)
                .compensate_prepared_new_session(compensation, 1001)
                .unwrap(),
            crate::ConditionalPreparedNewSessionCompensation::ExistingWindow(
                crate::ConditionalCreatedTabSessionRollback::RolledBack(_)
            )
        ));
        assert!(
            store::load_one::<SessionRecord>(&paths, RecordKind::Session, &session_id)
                .unwrap()
                .is_none()
        );
        drop(stub);
    }

    #[test]
    fn prepared_provider_transition_publishes_b_and_rebases_fresh_compensation_atomically() {
        const CLAUDE_ID: &str = "10000000-0000-4000-8000-000000000001";
        const GEMINI_ID: &str = "20000000-0000-4000-8000-000000000001";
        let cases = [
            (
                "claude",
                vec!["claude", "--session-id", CLAUDE_ID, "--model", "opus"],
                vec!["--resume", CLAUDE_ID, "--model", "opus"],
            ),
            (
                "gemini",
                vec![
                    "gemini",
                    "--session-id",
                    GEMINI_ID,
                    "--model",
                    "gemini-2.5-pro",
                ],
                vec!["--resume", GEMINI_ID, "--model", "gemini-2.5-pro"],
            ),
            (
                "copilot",
                vec![
                    "copilot",
                    "--session-id=30000000-0000-4000-8000-000000000001",
                    "--model",
                    "gpt-5",
                ],
                vec![
                    "--resume=30000000-0000-4000-8000-000000000001",
                    "--model",
                    "gpt-5",
                ],
            ),
        ];

        for (provider, source, publication) in cases {
            let tmp = TempDir::new().unwrap();
            let paths = paths_in(&tmp);
            let cwd = TempDir::new().unwrap();
            let source = source.into_iter().map(str::to_string).collect::<Vec<_>>();
            let start =
                prepared_fresh_provider_start(&paths, cwd.path(), provider, provider, &source);
            let session_id = start.session_id().to_string();
            let unknown = load_record(&paths, &session_id);
            let LaunchSpec::AdHocRedacted {
                ref argv,
                redacted: true,
                restart_requires_user: true,
            } = unknown.launch
            else {
                panic!("{provider} durable A must be non-replayable")
            };
            assert!(
                argv.iter().any(|arg| arg.contains("<redacted>")),
                "{provider} durable A must not expose its assigned identity"
            );
            assert_eq!(unknown.status, SessionStatus::Unknown);

            let stub = StubDaemon::spawn(|tx, stream| {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                read_request(&mut reader, tx).expect("DaemonInfo request");
                answer_prepared_daemon_info(stream);
                answer_prepared_start_applied(
                    &mut reader,
                    tx,
                    stream,
                    "prepared-provider-generation",
                    false,
                    true,
                );
                let mut remainder = String::new();
                reader.read_to_string(&mut remainder).unwrap();
                assert!(
                    remainder.is_empty(),
                    "provider transition emitted extra bytes"
                );
            });
            let mut client = DaemonClient::connect(&stub.path).unwrap();
            let peer = client.conditional_start_peer_identity().unwrap();
            let started = SessionService::new(&paths)
                .start_prepared_new_session(client, start, &peer)
                .unwrap();
            assert_eq!(
                started.record().launch,
                LaunchSpec::KnownSafe {
                    launch_spec_id: provider.into(),
                    params: publication.into_iter().map(str::to_string).collect(),
                },
                "{provider} must publish only its exact resume recipe"
            );
            assert_eq!(
                started.record().last_known_generation.as_deref(),
                Some("prepared-provider-generation")
            );
            assert_eq!(load_record(&paths, &session_id), *started.record());

            let wire = stub
                .collected_requests()
                .into_iter()
                .filter_map(|line| {
                    serde_json::from_str::<maestro_protocol::ClientRequest>(&line).ok()
                })
                .find_map(|request| match request {
                    maestro_protocol::ClientRequest::StartSession { command, args, .. } => {
                        Some((command, args))
                    }
                    _ => None,
                })
                .expect("one provider StartSession request");
            assert_eq!(wire.0, "/bin/prepared-provider-shell");
            let packed = wire.1.last().expect("login-shell provider command");
            assert!(packed.contains(provider));
            assert!(packed.contains("--session-id"));
            assert!(
                !packed.contains("--resume"),
                "{provider} first wire launch must create, not resume"
            );

            let (_, compensation) = started.into_parts();
            assert!(matches!(
                crate::WindowLayoutService::new(&paths)
                    .compensate_prepared_new_session(compensation, 1001)
                    .unwrap(),
                crate::ConditionalPreparedNewSessionCompensation::FreshWindowGraph(
                    crate::ConditionalFreshWindowGraphDelete::Deleted { .. }
                )
            ));
            assert!(
                store::load_one::<SessionRecord>(&paths, RecordKind::Session, &session_id)
                    .unwrap()
                    .is_none()
            );
            drop(stub);
        }
    }

    #[test]
    fn prepared_new_session_zero_wire_refusals_return_retryable_start() {
        for case in ["cwd", "project", "aba"] {
            let tmp = TempDir::new().unwrap();
            let paths = paths_in(&tmp);
            let cwd = TempDir::new().unwrap();
            let start = prepared_existing_start(&paths, cwd.path(), case);
            let session_id = start.session_id().to_string();
            let stub = StubDaemon::spawn(|tx, stream| {
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                assert_eq!(
                    read_request(&mut reader, tx).as_deref(),
                    Some(r#"{"op":"daemon_info"}"#)
                );
                answer_prepared_daemon_info(stream);
                let mut remainder = String::new();
                reader.read_to_string(&mut remainder).unwrap();
                assert!(remainder.is_empty(), "prewire refusal emitted daemon bytes");
            });
            let mut client = DaemonClient::connect(&stub.path).unwrap();
            let peer = client.conditional_start_peer_identity().unwrap();
            if case == "cwd" {
                drop(cwd);
            } else if case == "project" {
                let mut project = crate::ProjectService::new(&paths)
                    .load("proj-1")
                    .unwrap()
                    .unwrap();
                project.name.push_str(" foreign");
                store::write_record(
                    &paths,
                    RecordKind::Project,
                    &project.project_id,
                    50,
                    &project,
                )
                .unwrap();
            } else {
                let window_id = start
                    .window_id()
                    .expect("existing-window prepared start owns a window")
                    .to_string();
                let snapshot = crate::WindowLayoutService::new(&paths)
                    .load_snapshot(&window_id)
                    .unwrap()
                    .unwrap();
                let project_id = snapshot.project_id.clone().unwrap();
                let value = serde_json::to_value(&snapshot.layout).unwrap();
                let arc = crate::db::conn_for(paths.base()).unwrap();
                let mut conn = arc.lock().unwrap();
                let transaction = conn
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .unwrap();
                assert!(crate::store_sqlite::delete(
                    &transaction,
                    RecordKind::WindowLayout,
                    &window_id,
                )
                .unwrap());
                crate::store_sqlite::upsert(
                    &transaction,
                    RecordKind::WindowLayout,
                    &window_id,
                    &value,
                )
                .unwrap();
                assert_eq!(
                    transaction
                        .execute(
                            "UPDATE windows SET project_id = ?2 WHERE window_id = ?1",
                            rusqlite::params![window_id, project_id],
                        )
                        .unwrap(),
                    1
                );
                crate::db::bump_window_mutation_epoch(&transaction).unwrap();
                transaction.commit().unwrap();
            }
            let returned = match SessionService::new(&paths)
                .start_prepared_new_session(client, start, &peer)
            {
                Err(PreparedNewSessionStartError::DefinitelyUnpublished { start, .. }) => start,
                other => panic!("expected retryable zero-wire refusal, got {other:?}"),
            };
            assert_eq!(returned.session_id(), session_id);
            assert_eq!(
                load_record(&paths, &session_id).status,
                SessionStatus::Unknown
            );
            drop(returned);
            drop(stub);
        }
    }

    #[test]
    fn prepared_fresh_session_foreign_workspace_provenance_refuses_before_start() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let start = prepared_fresh_start(&paths, cwd.path(), "provenance");
        let session_id = start.session_id().to_string();
        let workspace_id = start.workspace_id().to_string();
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx).expect("DaemonInfo request");
            answer_prepared_daemon_info(stream);
            let mut remainder = String::new();
            reader.read_to_string(&mut remainder).unwrap();
            assert!(
                remainder.is_empty(),
                "foreign Workspace owner emitted Start"
            );
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let peer = client.conditional_start_peer_identity().unwrap();
        let provenance = crate::WorktreeProvenance {
            workspace_id,
            session_id: "foreign-prepared-provenance-session".into(),
            repo_root: cwd.path().to_string_lossy().into_owned(),
            target_path: cwd.path().join("foreign").to_string_lossy().into_owned(),
            branch: "maestro/foreign/prepared".into(),
            created_at_ms: 1001,
        };
        store::write_record(
            &paths,
            RecordKind::WorktreeProvenance,
            &provenance.session_id,
            1001,
            &provenance,
        )
        .unwrap();

        assert!(matches!(
            SessionService::new(&paths).start_prepared_new_session(client, start, &peer),
            Err(PreparedNewSessionStartError::DefinitelyUnpublished { .. })
        ));
        assert_eq!(
            load_record(&paths, &session_id).status,
            SessionStatus::Unknown
        );
        drop(stub);
    }

    #[test]
    fn prepared_new_session_typed_refusal_burns_retry_and_returns_compensation() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let start = prepared_existing_start(&paths, cwd.path(), "refused");
        let session_id = start.session_id().to_string();
        let stub = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx).expect("DaemonInfo request");
            answer_prepared_daemon_info(stream);
            let (reserved_id, reserved_token) =
                answer_start_operation_reserved(&mut reader, tx, stream);
            let request = serde_json::from_str::<maestro_protocol::ClientRequest>(
                &read_request(&mut reader, tx).expect("conditional Start request"),
            )
            .unwrap();
            let (id, token) = match request {
                maestro_protocol::ClientRequest::StartSession {
                    id,
                    conditional_start: Some(conditional),
                    ..
                } => (id, conditional.operation_token),
                other => panic!("expected conditional Start, got {other:?}"),
            };
            assert_eq!(id, reserved_id);
            assert_eq!(token, reserved_token);
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "conditional_session_start",
                    "id": id,
                    "operation_token": token.as_str(),
                    "daemon_instance_id": PREPARED_DAEMON_INSTANCE,
                    "outcome": {"status": "refused", "reason": "precondition_failed"},
                })
            )
            .unwrap();
            stream.flush().unwrap();
            answer_unapplied_start_operation_retired(&mut reader, tx, stream, &id, &token);
            let mut remainder = String::new();
            reader.read_to_string(&mut remainder).unwrap();
            assert!(
                remainder.is_empty(),
                "refusal must not Attach or retry Start"
            );
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let peer = client.conditional_start_peer_identity().unwrap();
        let compensation =
            match SessionService::new(&paths).start_prepared_new_session(client, start, &peer) {
                Err(PreparedNewSessionStartError::Refused { compensation, .. }) => compensation,
                other => panic!("expected typed refusal compensation, got {other:?}"),
            };
        assert!(matches!(
            crate::WindowLayoutService::new(&paths)
                .compensate_prepared_new_session(compensation, 1001)
                .unwrap(),
            crate::ConditionalPreparedNewSessionCompensation::ExistingWindow(
                crate::ConditionalCreatedTabSessionRollback::RolledBack(_)
            )
        ));
        assert!(
            store::load_one::<SessionRecord>(&paths, RecordKind::Session, &session_id)
                .unwrap()
                .is_none()
        );
        drop(stub);
    }

    #[test]
    fn prepared_new_session_ack_loss_is_possibly_applied_without_retry_or_compensation() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let start = prepared_existing_start(&paths, cwd.path(), "ack-loss");
        let session_id = start.session_id().to_string();
        let stub = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx).expect("DaemonInfo request");
            answer_prepared_daemon_info(stream);
            let (reserved_id, reserved_token) =
                answer_start_operation_reserved(&mut reader, tx, stream);
            let request = serde_json::from_str::<maestro_protocol::ClientRequest>(
                &read_request(&mut reader, tx).expect("single conditional Start"),
            )
            .unwrap();
            assert!(matches!(
                request,
                maestro_protocol::ClientRequest::StartSession {
                    ref id,
                    conditional_start: Some(maestro_protocol::ConditionalSessionStart {
                        operation_token: ref token,
                        precondition: maestro_protocol::SessionStartPrecondition::Absent {
                            excluded_generation: None
                        },
                    }),
                    ..
                } if id == &reserved_id && token == &reserved_token
            ));
            stream.shutdown(std::net::Shutdown::Both).unwrap();
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let peer = client.conditional_start_peer_identity().unwrap();
        assert!(matches!(
            SessionService::new(&paths).start_prepared_new_session(client, start, &peer),
            Err(PreparedNewSessionStartError::PossiblyApplied { .. })
        ));
        assert_eq!(
            load_record(&paths, &session_id).status,
            SessionStatus::Unknown
        );
        drop(stub);
    }

    #[test]
    fn prepared_new_session_post_grid_graph_race_never_publishes_or_returns_offer() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let start = prepared_existing_start(&paths, cwd.path(), "post-grid-race");
        let session_id = start.session_id().to_string();
        let window_id = start
            .window_id()
            .expect("existing-window prepared start owns a window")
            .to_string();
        let expected_unknown = start.unknown().clone();
        let mutation_paths = paths.clone();
        let hook_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook_fired_worker = std::sync::Arc::clone(&hook_fired);
        let _hook =
            crate::store_sqlite::install_window_layout_test_hook(window_id, move |stage, _| {
                if stage != "after-prepared-session-grid-before-finalize"
                    || hook_fired_worker.swap(true, std::sync::atomic::Ordering::SeqCst)
                {
                    return;
                }
                let mut project = crate::ProjectService::new(&mutation_paths)
                    .load("proj-1")
                    .unwrap()
                    .unwrap();
                project.name.push_str(" post-grid-winner");
                store::write_record(
                    &mutation_paths,
                    RecordKind::Project,
                    &project.project_id,
                    1001,
                    &project,
                )
                .unwrap();
            });
        let stub = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx).expect("DaemonInfo request");
            answer_prepared_daemon_info(stream);
            answer_prepared_start_applied(
                &mut reader,
                tx,
                stream,
                "prepared-race-generation",
                true,
                false,
            );
            let mut remainder = String::new();
            reader.read_to_string(&mut remainder).unwrap();
            assert!(
                remainder.is_empty(),
                "failed final CAS must not retry or cancel inline"
            );
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let peer = client.conditional_start_peer_identity().unwrap();
        assert!(matches!(
            SessionService::new(&paths)
                .start_prepared_new_session_for_renderer(client, start, &peer),
            Err(PreparedNewSessionStartError::PossiblyApplied { .. })
        ));
        assert!(hook_fired.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(load_record(&paths, &session_id), expected_unknown);
        assert!(crate::ProjectService::new(&paths)
            .load("proj-1")
            .unwrap()
            .unwrap()
            .name
            .ends_with("post-grid-winner"));
        drop(stub);
    }

    /// A daemon `Error` reply surfaces the error AND keeps the prewritten `Unknown` record (we could
    /// not prove liveness, but also did not prove the session never existed).
    #[test]
    fn daemon_error_keeps_unknown_record_and_surfaces() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();

        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"daemon_info"}"#)
            );
            answer_prepared_daemon_info(stream);
            let _ = answer_prepared_start_prefix(&mut reader, tx, stream, "gen-error", false);
            stream
                .write_all(b"{\"ev\":\"error\",\"message\":\"nope\"}\n")
                .unwrap();
            stream.flush().unwrap();
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let svc = SessionService::new(&paths);
        let err = svc
            .start_and_attach(&mut client, &params("s1", &cwd_path))
            .unwrap_err();
        match err {
            SessionServiceError::Daemon(DaemonClientError::ConditionalStartPossiblyApplied {
                source,
                ..
            }) if matches!(source.as_ref(), DaemonClientError::DaemonError { message } if message == "nope") =>
                {}
            other => panic!("expected daemon error, got {other:?}"),
        }
        // The Unknown record is still there.
        let on_disk = load_record(&paths, "s1");
        assert_eq!(on_disk.status, SessionStatus::Unknown);
        assert_eq!(on_disk.last_known_generation, None);
    }

    /// A `SessionExited` before the grid marks the record `Exited` deterministically AND surfaces the
    /// typed daemon error.
    #[test]
    fn session_exited_before_grid_marks_record_exited() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();

        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"daemon_info"}"#)
            );
            answer_prepared_daemon_info(stream);
            let _ = answer_prepared_start_prefix(&mut reader, tx, stream, "gen-exited", false);
            stream
                .write_all(b"{\"ev\":\"session_exited\",\"id\":\"s1\",\"code\":2}\n")
                .unwrap();
            stream.flush().unwrap();
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let svc = SessionService::new(&paths);
        let err = svc
            .start_and_attach(&mut client, &params("s1", &cwd_path))
            .unwrap_err();
        match err {
            SessionServiceError::Daemon(DaemonClientError::ConditionalStartPossiblyApplied {
                source,
                ..
            }) if matches!(source.as_ref(), DaemonClientError::SessionExited { id, code }
                if id == &SessionId("s1".into()) && code == &Some(2)) => {}
            other => panic!("expected SessionExited, got {other:?}"),
        }
        let on_disk = load_record(&paths, "s1");
        assert_eq!(on_disk.status, SessionStatus::Exited);
        assert_eq!(on_disk.last_known_generation.as_deref(), Some("gen-exited"));
    }

    #[test]
    fn targeted_exit_requires_matching_generation_and_is_idempotent() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let id = "targeted-exit-idempotent";
        store::write_record(
            &paths,
            RecordKind::Session,
            id,
            1,
            &exit_record(id, SessionStatus::Live, Some("gen-current")),
        )
        .unwrap();
        let svc = SessionService::new(&paths);
        let writes_after_seed = session_write_count(id);

        assert_eq!(
            svc.observe_exit(id, Some("gen-stale"), 2).unwrap(),
            SessionExitObservation::GenerationMismatch
        );
        assert_eq!(
            svc.observe_exit(id, None, 3).unwrap(),
            SessionExitObservation::GenerationMismatch
        );
        assert_eq!(session_write_count(id), writes_after_seed);
        assert_eq!(load_record(&paths, id).status, SessionStatus::Live);

        assert_eq!(
            svc.observe_exit(id, Some("gen-current"), 4).unwrap(),
            SessionExitObservation::MarkedExited
        );
        assert_eq!(load_record(&paths, id).status, SessionStatus::Exited);
        assert_eq!(session_write_count(id), writes_after_seed + 1);

        assert_eq!(
            svc.observe_exit(id, Some("gen-current"), 5).unwrap(),
            SessionExitObservation::AlreadyExited
        );
        assert_eq!(
            session_write_count(id),
            writes_after_seed + 1,
            "duplicate matching exits must not rewrite the record"
        );
    }

    #[test]
    fn targeted_exit_marks_generation_known_unknown_but_not_missing_record() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let id = "targeted-exit-unknown";
        store::write_record(
            &paths,
            RecordKind::Session,
            id,
            1,
            &exit_record(id, SessionStatus::Unknown, Some("gen-known")),
        )
        .unwrap();
        let svc = SessionService::new(&paths);

        assert_eq!(
            svc.observe_exit(id, Some("gen-known"), 2).unwrap(),
            SessionExitObservation::MarkedExited
        );
        assert_eq!(load_record(&paths, id).status, SessionStatus::Exited);

        let missing = "targeted-exit-missing";
        let before = session_write_count(missing);
        assert_eq!(
            svc.observe_exit(missing, Some("gen"), 3).unwrap(),
            SessionExitObservation::Missing
        );
        assert_eq!(session_write_count(missing), before);
    }

    #[test]
    fn targeted_exit_leaves_quarantined_record_untouched() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let id = "targeted-exit-quarantined";
        store::write_record(
            &paths,
            RecordKind::Session,
            id,
            1,
            &exit_record(id, SessionStatus::Live, Some("gen")),
        )
        .unwrap();
        let writes_after_seed = session_write_count(id);

        // Make only this row fail SessionRecord deserialization while retaining it in SQLite.
        let conn = crate::db::conn_for(paths.base()).unwrap();
        conn.lock()
            .unwrap()
            .execute(
                "UPDATE sessions SET launch_json = '{\"unexpected\":true}' WHERE session_id = ?1",
                [id],
            )
            .unwrap();

        let svc = SessionService::new(&paths);
        assert_eq!(
            svc.observe_exit(id, Some("gen"), 2).unwrap(),
            SessionExitObservation::Quarantined
        );
        assert_eq!(session_write_count(id), writes_after_seed);
        assert!(matches!(
            store::load_one::<SessionRecord>(&paths, RecordKind::Session, id).unwrap(),
            Some(LoadOutcome::Quarantined { .. })
        ));
    }

    #[test]
    fn targeted_exit_refuses_future_database_without_writing() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let id = "targeted-exit-future-db";
        store::write_record(
            &paths,
            RecordKind::Session,
            id,
            1,
            &exit_record(id, SessionStatus::Live, Some("gen")),
        )
        .unwrap();

        let conn = crate::db::conn_for(paths.base()).unwrap();
        conn.lock()
            .unwrap()
            .execute(
                "UPDATE schema_meta SET version = ?1 WHERE id = 1",
                [crate::db::DB_SCHEMA_VERSION + 1],
            )
            .unwrap();
        drop(conn);
        crate::db::forget_cached(paths.base());

        let svc = SessionService::new(&paths);
        assert!(matches!(
            svc.observe_exit(id, Some("gen"), 2),
            Err(SessionServiceError::Store(StoreError::Db(_)))
        ));

        // Bypass this build's intentional future-version refusal only to verify no status write.
        let raw = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
        let status: String = raw
            .query_row(
                "SELECT status FROM sessions WHERE session_id = ?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(serde_json::from_str::<String>(&status).unwrap(), "live");
    }

    #[test]
    fn reconcile_cannot_revive_event_confirmed_exit_from_id_only_snapshot() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let id = "sticky-event-exit";
        store::write_record(
            &paths,
            RecordKind::Session,
            id,
            1,
            &exit_record(id, SessionStatus::Exited, Some("gen-ended")),
        )
        .unwrap();
        let writes_after_seed = session_write_count(id);

        let stub = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_legacy_snapshot(&mut reader, tx, stream, &[id]);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let report = SessionService::new(&paths).reconcile(&mut client).unwrap();

        let entry = report.sessions.iter().find(|s| s.session_id == id).unwrap();
        assert_eq!(entry.status, SessionStatus::Exited);
        assert!(!entry.rewritten);
        assert!(report.recovered_session_targets.is_empty());
        assert!(report.live_session_release_targets.is_empty());
        assert_eq!(load_record(&paths, id).status, SessionStatus::Exited);
        assert_eq!(session_write_count(id), writes_after_seed);
    }

    #[test]
    fn reconcile_snapshot_cannot_overwrite_a_newer_exact_exit_with_live() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let id = "snapshot-before-exit";
        let generation = "generation-exact";
        store::write_record(
            &paths,
            RecordKind::Session,
            id,
            1,
            &exit_record(id, SessionStatus::Live, Some(generation)),
        )
        .unwrap();

        // The daemon snapshot is captured first. Before reconcile loads durable rows, model the
        // exact renderer lifecycle event committing Exited/G. Passive reconciliation must not use
        // its older live/G snapshot to revive that newer exit.
        let hook_paths = paths.clone();
        install_reconcile_after_snapshot_hook(move || {
            assert!(matches!(
                SessionService::new(&hook_paths).observe_exit(id, Some(generation), 2),
                Ok(SessionExitObservation::MarkedExited)
            ));
        });
        let stub = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_v3_generation_snapshot(&mut reader, tx, stream, &[(id, generation)]);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let report = SessionService::new(&paths).reconcile(&mut client).unwrap();

        let entry = report
            .sessions
            .iter()
            .find(|entry| entry.session_id == id)
            .expect("exact exited row remains represented");
        assert_eq!(entry.status, SessionStatus::Exited);
        assert!(!entry.rewritten);
        let current = load_record(&paths, id);
        assert_eq!(current.status, SessionStatus::Exited);
        assert_eq!(current.last_known_generation.as_deref(), Some(generation));
    }

    #[test]
    fn generation_metadata_does_not_bless_a_row_without_an_exact_durable_generation() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let id = "queued-start-reconcile-race";
        store::write_record(
            &paths,
            RecordKind::Session,
            id,
            1,
            &exit_record(id, SessionStatus::Live, None),
        )
        .unwrap();

        // Model the remote fire-and-forget window: the durable Live record exists, but the queued
        // StartSession has not reached the daemon when the first snapshot is taken.
        let absent = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_v3_generation_snapshot(&mut reader, tx, stream, &[]);
        });
        let mut client = DaemonClient::connect(&absent.path).unwrap();
        SessionService::new(&paths).reconcile(&mut client).unwrap();
        assert_eq!(load_record(&paths, id).status, SessionStatus::Exited);

        // Once the daemon reports the same textual id at a new generation, that snapshot describes
        // an unrepresented lifetime. It cannot mint the missing durable proof or revive A.
        let live = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_v3_generation_snapshot(&mut reader, tx, stream, &[(id, "gen-new")]);
        });
        let mut client = DaemonClient::connect(&live.path).unwrap();
        let report = SessionService::new(&paths).reconcile(&mut client).unwrap();
        let entry = report
            .sessions
            .iter()
            .find(|entry| entry.session_id == id)
            .unwrap();
        assert_eq!(entry.status, SessionStatus::Exited);
        assert!(!entry.rewritten);
        let record = load_record(&paths, id);
        assert_eq!(record.status, SessionStatus::Exited);
        assert_eq!(record.last_known_generation, None);
        assert_eq!(
            report.recovered_sessions,
            vec![RecoveredSession {
                session_id: id.into()
            }]
        );
        let target = report
            .live_session_release_targets
            .iter()
            .find(|target| target.session_id() == id)
            .expect("unrepresented live target");
        assert_eq!(target.expected_generation(), "gen-new");
        assert_eq!(target.row_policy(), SessionRowPolicy::RowMustBeAbsent);
    }

    #[test]
    fn reconcile_preserves_a_mismatched_row_and_reports_the_live_generation_as_unrepresented() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let id = "same-id-foreign-generation";
        let original = exit_record(id, SessionStatus::Unknown, Some("generation-A"));
        store::write_record(&paths, RecordKind::Session, id, 1, &original).unwrap();
        let writes_after_seed = session_write_count(id);

        let stub = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_v3_generation_snapshot(&mut reader, tx, stream, &[(id, "generation-B")]);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let report = SessionService::new(&paths).reconcile(&mut client).unwrap();

        let entry = report
            .sessions
            .iter()
            .find(|entry| entry.session_id == id)
            .expect("durable A remains in the report");
        assert_eq!(entry.status, SessionStatus::Unknown);
        assert!(!entry.rewritten);
        assert_eq!(load_record(&paths, id), original);
        assert_eq!(session_write_count(id), writes_after_seed);
        assert_eq!(
            report.recovered_sessions,
            vec![RecoveredSession {
                session_id: id.into()
            }]
        );
        let target = report
            .live_session_release_targets
            .iter()
            .find(|target| target.session_id() == id)
            .expect("foreign lifetime is represented only by a RowMustBeAbsent target");
        assert_eq!(target.expected_generation(), "generation-B");
        assert_eq!(target.row_policy(), SessionRowPolicy::RowMustBeAbsent);
        assert_eq!(report.recovered_session_targets, vec![target.clone()]);
    }

    #[test]
    fn reconciliation_cas_never_overwrites_a_concurrent_new_generation() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let id = "reconcile-cas-new-generation";
        store::write_record(
            &paths,
            RecordKind::Session,
            id,
            1,
            &exit_record(id, SessionStatus::Live, Some("gen-old")),
        )
        .unwrap();

        // The reconciler's snapshot expected Live/gen-old, but another writer published a fresh
        // lifetime before its transaction began.
        store::write_record(
            &paths,
            RecordKind::Session,
            id,
            2,
            &exit_record(id, SessionStatus::Live, Some("gen-new")),
        )
        .unwrap();
        let outcome = store::reconcile_session_if_unchanged(
            &paths,
            id,
            SessionStatus::Live,
            Some("gen-old"),
            SessionStatus::Exited,
            Some("gen-old"),
            3,
        )
        .unwrap();
        assert!(matches!(
            outcome,
            store::ConditionalSessionReconcile::Stale(ref current)
                if current.status == SessionStatus::Live
                    && current.last_known_generation.as_deref() == Some("gen-new")
        ));
        let current = load_record(&paths, id);
        assert_eq!(current.status, SessionStatus::Live);
        assert_eq!(current.last_known_generation.as_deref(), Some("gen-new"));
    }

    #[test]
    fn new_start_grid_explicitly_revives_same_id_with_new_generation() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let id = "sticky-exit-restarted";
        store::write_record(
            &paths,
            RecordKind::Session,
            id,
            1,
            &exit_record(id, SessionStatus::Exited, Some("gen-old")),
        )
        .unwrap();

        let stub = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_regular_start_applied_and_retired(&mut reader, tx, stream, "gen-new");
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let record = SessionService::new(&paths)
            .start_and_attach(&mut client, &params(id, &cwd_path))
            .unwrap();

        assert_eq!(record.status, SessionStatus::Live);
        assert_eq!(record.last_known_generation.as_deref(), Some("gen-new"));
        assert_eq!(load_record(&paths, id), record);
    }

    /// Reconciliation marks records whose ids the daemon reports live as `Live`, and persisted
    /// records the daemon does NOT report as `Exited`, writing the changes back.
    #[test]
    fn reconcile_marks_present_live_and_absent_exited() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);

        // Two persisted sessions, both Unknown to start. Only alive carries the exact generation
        // that the strict daemon snapshot will report.
        let svc = SessionService::new(&paths);
        for id in ["alive", "dead"] {
            let rec = SessionRecord {
                session_id: id.into(),
                workspace_id: "ws1".into(),
                kind: SessionKind::Shell,
                launch: known_safe("ls"),
                cwd_resolved: "/tmp".into(),
                agent_task_id: None,
                created_at_ms: 1,
                last_attached_at_ms: 1,
                last_known_generation: (id == "alive").then(|| "gen-alive".into()),
                status: SessionStatus::Unknown,
            };
            store::write_record(&paths, RecordKind::Session, id, 1, &rec).unwrap();
        }

        // The daemon reports only "alive" live.
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_v3_generation_snapshot(&mut reader, tx, stream, &[("alive", "gen-alive")]);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let report = svc.reconcile(&mut client).unwrap();

        // Both reconciled; statuses as expected.
        let by_id = |id: &str| {
            report
                .sessions
                .iter()
                .find(|s| s.session_id == id)
                .cloned()
                .unwrap()
        };
        assert_eq!(by_id("alive").status, SessionStatus::Live);
        assert!(by_id("alive").rewritten);
        assert_eq!(by_id("dead").status, SessionStatus::Exited);
        assert!(by_id("dead").rewritten);
        assert!(report.skipped_future_version.is_empty());
        // Both live ids the daemon reported were persisted -> nothing recovered.
        assert!(report.recovered_sessions.is_empty());

        // Persisted to disk.
        assert_eq!(load_record(&paths, "alive").status, SessionStatus::Live);
        assert_eq!(load_record(&paths, "dead").status, SessionStatus::Exited);
    }

    /// A live daemon id with NO persisted record is reported as a recovered/orphan session — and is
    /// NOT written to the store (no record file appears for it).
    #[test]
    fn reconcile_reports_unrecorded_live_id_as_recovered_without_writing() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let svc = SessionService::new(&paths);

        // One persisted record the daemon will report live.
        let rec = SessionRecord {
            session_id: "known".into(),
            workspace_id: "ws1".into(),
            kind: SessionKind::Shell,
            launch: known_safe("ls"),
            cwd_resolved: "/tmp".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: Some("gen-known".into()),
            status: SessionStatus::Unknown,
        };
        store::write_record(&paths, RecordKind::Session, "known", 1, &rec).unwrap();

        // Daemon reports BOTH the known id and an orphan it has no record for.
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_v3_generation_snapshot(
                &mut reader,
                tx,
                stream,
                &[("known", "gen-known"), ("orphan", "gen-orphan")],
            );
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let report = svc.reconcile(&mut client).unwrap();

        // "known" reconciled Live; "orphan" surfaced as recovered, not in the reconciled set.
        assert_eq!(
            report.recovered_sessions,
            vec![RecoveredSession {
                session_id: "orphan".into()
            }]
        );
        assert!(report.sessions.iter().all(|s| s.session_id != "orphan"));
        assert_eq!(load_record(&paths, "known").status, SessionStatus::Live);
        let known_target = report
            .live_session_release_targets
            .iter()
            .find(|target| target.session_id() == "known")
            .expect("record-backed live target");
        assert_eq!(known_target.expected_generation(), "gen-known");
        assert_eq!(
            known_target.row_policy(),
            SessionRowPolicy::MatchingRowIsProof
        );
        let orphan_target = report
            .live_session_release_targets
            .iter()
            .find(|target| target.session_id() == "orphan")
            .expect("daemon-only live target");
        assert_eq!(orphan_target.expected_generation(), "gen-orphan");
        assert_eq!(
            orphan_target.row_policy(),
            SessionRowPolicy::RowMustBeAbsent
        );
        assert_eq!(
            report.recovered_session_targets,
            vec![orphan_target.clone()]
        );

        // The orphan was NEVER written: no record file exists for it.
        assert!(
            store::load_one::<SessionRecord>(&paths, RecordKind::Session, "orphan")
                .unwrap()
                .is_none(),
            "recovered/orphan session must not be persisted"
        );
    }

    /// Mixed set: several persisted (some live, some exited) and several daemon-only orphans. The
    /// recovered list contains exactly the unrecorded live ids, deterministically sorted.
    #[test]
    fn reconcile_recovered_sessions_are_sorted_and_exclude_persisted() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let svc = SessionService::new(&paths);

        for id in ["p-live", "p-dead"] {
            let rec = SessionRecord {
                session_id: id.into(),
                workspace_id: "ws1".into(),
                kind: SessionKind::Shell,
                launch: known_safe("ls"),
                cwd_resolved: "/tmp".into(),
                agent_task_id: None,
                created_at_ms: 1,
                last_attached_at_ms: 1,
                last_known_generation: (id == "p-live").then(|| "gen-live".into()),
                status: SessionStatus::Unknown,
            };
            store::write_record(&paths, RecordKind::Session, id, 1, &rec).unwrap();
        }

        // Daemon live set: one persisted-live id + three orphans in non-sorted order. "p-dead" is
        // persisted but NOT live -> Exited, never recovered.
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_v3_generation_snapshot(
                &mut reader,
                tx,
                stream,
                &[
                    ("orphan-c", "gen-c"),
                    ("p-live", "gen-live"),
                    ("orphan-a", "gen-a"),
                    ("orphan-b", "gen-b"),
                ],
            );
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let report = svc.reconcile(&mut client).unwrap();

        assert_eq!(
            report.recovered_sessions,
            vec![
                RecoveredSession {
                    session_id: "orphan-a".into()
                },
                RecoveredSession {
                    session_id: "orphan-b".into()
                },
                RecoveredSession {
                    session_id: "orphan-c".into()
                },
            ]
        );
        // p-live reconciled Live, p-dead reconciled Exited, neither recovered.
        let by_id = |id: &str| {
            report
                .sessions
                .iter()
                .find(|s| s.session_id == id)
                .cloned()
                .unwrap()
        };
        assert_eq!(by_id("p-live").status, SessionStatus::Live);
        assert_eq!(by_id("p-dead").status, SessionStatus::Exited);
        assert!(report
            .recovered_sessions
            .iter()
            .all(|r| r.session_id != "p-live" && r.session_id != "p-dead"));
    }

    // NOTE: the old `reconcile_tolerates_future_version_without_rewriting` and
    // `reconcile_reports_live_future_version_id_as_recovered_but_leaves_file` tests hand-wrote a raw future-version
    // envelope FILE and asserted reconcile skipped it (populating `skipped_future_version`). The SQLite store reads
    // rows from the DB, not per-record files, so a per-record FutureVersion outcome no longer exists: future-version
    // is now a DB-LEVEL guard that refuses to open a newer DB (see store::future_version_db_is_refused_on_open).
    // A row that won't deserialize surfaces as Quarantined (store::row_that_wont_deserialize_is_quarantined_and_excluded).
    // These tests were removed rather than adapted because the `LoadOutcome::FutureVersion` path they exercised is gone.

    /// The service never creates repo-root scratch or Maestro metadata outside the injected base:
    /// after a full start/attach, the ONLY thing under the base is the sessions record dir, and no
    /// scratch/worktree dirs were created.
    #[test]
    fn no_scratch_or_repo_metadata_is_created() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();

        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_regular_start_applied_and_retired(&mut reader, tx, stream, "g");
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let svc = SessionService::new(&paths);
        svc.start_and_attach(&mut client, &params("s1", &cwd_path))
            .unwrap();

        // No scratch / worktree dirs were created by this service.
        assert!(
            !paths.scratch_base().exists(),
            "scratch base must not be created"
        );
        assert!(
            !paths.worktree_base().exists(),
            "worktree base must not be created"
        );
        // The cwd dir is the caller's temp dir, untouched (still empty — nothing written into it).
        let entries: Vec<_> = std::fs::read_dir(cwd.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        assert!(
            entries.is_empty(),
            "the cwd must not have Maestro metadata written into it"
        );
    }

    /// An ad-hoc launch routes argv through redaction: the persisted record's `LaunchSpec` carries a
    /// `<redacted>` placeholder and never the raw secret, while the LIVE command/args sent to the
    /// daemon are the real tokens.
    #[test]
    fn adhoc_launch_persists_redacted_but_sends_real_argv() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();

        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_regular_start_applied_and_retired(&mut reader, tx, stream, "g");
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let svc = SessionService::new(&paths);

        let argv = vec![
            "mytool".to_string(),
            "--api-key=sk-supersecretvalue123".to_string(),
        ];
        let p = StartParams::adhoc("s1", "ws1", SessionKind::Agent, &cwd_path, &argv, 80, 24, 7);
        let rec = svc.start_and_attach(&mut client, &p).unwrap();
        drop(client);

        // Persisted launch is redacted — the secret never reached disk.
        match &rec.launch {
            LaunchSpec::AdHocRedacted { argv, redacted, .. } => {
                assert!(*redacted);
                assert!(argv.iter().any(|a| a.contains("<redacted>")));
                assert!(
                    !argv.iter().any(|a| a.contains("supersecret")),
                    "secret must not be persisted: {argv:?}"
                );
            }
            other => panic!("expected AdHocRedacted, got {other:?}"),
        }
        // But the daemon received the REAL argv (so the tool actually works).
        let reqs = stub.collected_requests();
        let start_request = reqs
            .iter()
            .find(|request| request.contains(r#""op":"start_session""#))
            .expect("one conditional StartSession request");
        assert!(
            start_request.contains("sk-supersecretvalue123"),
            "daemon must receive the real argv: {reqs:?}"
        );
        // And what's on disk matches the redacted in-memory record.
        let on_disk = load_record(&paths, "s1");
        assert_eq!(on_disk.launch, rec.launch);
    }

    #[test]
    fn fresh_new_uses_caller_intended_workspace_and_never_adopts_incompatible_row() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let svc = SessionService::new(&paths);
        let existing = match store::load_one::<Workspace>(&paths, RecordKind::Workspace, "ws1")
            .unwrap()
            .unwrap()
        {
            LoadOutcome::Loaded(workspace) => workspace,
            other => panic!("expected Workspace, got {other:?}"),
        };
        let mut intended = existing.clone();
        intended.root = "/caller-intended-root".into();

        let error = svc
            .ensure_fresh_daemon_start_row(
                &params("new-session", "/tmp"),
                FreshDaemonSessionStart::New {
                    workspace: &intended,
                },
            )
            .unwrap_err();
        assert!(matches!(
            error,
            SessionServiceError::AttachAuthorityLost { .. }
        ));
        match store::load_one::<Workspace>(&paths, RecordKind::Workspace, "ws1").unwrap() {
            Some(LoadOutcome::Loaded(current)) => assert_eq!(current, existing),
            other => panic!("expected unchanged Workspace, got {other:?}"),
        }
        assert!(
            store::load_one::<SessionRecord>(&paths, RecordKind::Session, "new-session")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn fresh_new_atomically_persists_exact_desired_workspace_and_unknown_session() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let desired = Workspace {
            workspace_id: "fresh-workspace".into(),
            project_id: "proj-1".into(),
            root: "/reviewed-root".into(),
            policy: crate::policy::WorkspacePolicy::ScratchCwd,
            consent: crate::records::WorkspaceConsent::default(),
        };
        let mut start = params("fresh-session", "/tmp");
        start.workspace_id = desired.workspace_id.clone();

        let (unknown, workspace) = SessionService::new(&paths)
            .ensure_fresh_daemon_start_row(
                &start,
                FreshDaemonSessionStart::New {
                    workspace: &desired,
                },
            )
            .unwrap();
        assert_eq!(workspace, desired);
        assert_eq!(unknown.status, SessionStatus::Unknown);
        assert_eq!(unknown.last_known_generation, None);
        assert_eq!(load_record(&paths, "fresh-session"), unknown);
        match store::load_one::<Workspace>(&paths, RecordKind::Workspace, "fresh-workspace")
            .unwrap()
        {
            Some(LoadOutcome::Loaded(current)) => assert_eq!(current, desired),
            other => panic!("expected exact desired Workspace, got {other:?}"),
        }
    }

    #[test]
    fn fresh_existing_rejects_workspace_change_without_touching_session() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let mut expected = params("existing-session", "/tmp");
        let session = SessionRecord {
            session_id: expected.session_id.clone(),
            workspace_id: expected.workspace_id.clone(),
            kind: expected.kind,
            launch: expected.launch.clone(),
            cwd_resolved: expected.cwd.clone(),
            agent_task_id: None,
            created_at_ms: 7,
            last_attached_at_ms: 8,
            last_known_generation: Some("generation-a".into()),
            status: SessionStatus::Live,
        };
        store::write_record(
            &paths,
            RecordKind::Session,
            &session.session_id,
            9,
            &session,
        )
        .unwrap();
        let workspace = match store::load_one::<Workspace>(&paths, RecordKind::Workspace, "ws1")
            .unwrap()
            .unwrap()
        {
            LoadOutcome::Loaded(workspace) => workspace,
            other => panic!("expected Workspace, got {other:?}"),
        };
        let mut changed = workspace.clone();
        changed.root = "/foreign-change".into();
        store::write_record(&paths, RecordKind::Workspace, "ws1", 10, &changed).unwrap();
        expected.now_ms = 11;
        let reviewed = ExistingSessionStart {
            session: session.clone(),
            workspace: workspace.clone(),
            params: expected.clone(),
            scope: ExistingSessionStartScope::ExactConversation,
        };

        let error = SessionService::new(&paths)
            .ensure_fresh_daemon_start_row(
                &expected,
                FreshDaemonSessionStart::Existing { start: &reviewed },
            )
            .unwrap_err();
        assert!(matches!(
            error,
            SessionServiceError::AttachAuthorityLost { .. }
        ));
        assert_eq!(load_record(&paths, "existing-session"), session);
        match store::load_one::<Workspace>(&paths, RecordKind::Workspace, "ws1").unwrap() {
            Some(LoadOutcome::Loaded(current)) => assert_eq!(current, changed),
            other => panic!("expected foreign Workspace bytes, got {other:?}"),
        }
    }

    #[test]
    fn explicit_user_restart_accepts_strict_latest_without_widening_exact_authority() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let workspace = match store::load_one::<Workspace>(&paths, RecordKind::Workspace, "ws1")
            .unwrap()
            .unwrap()
        {
            LoadOutcome::Loaded(workspace) => workspace,
            other => panic!("expected Workspace, got {other:?}"),
        };
        let session = SessionRecord {
            session_id: "explicit-latest".into(),
            workspace_id: workspace.workspace_id.clone(),
            kind: SessionKind::Agent,
            launch: LaunchSpec::KnownSafe {
                launch_spec_id: "claude".into(),
                params: vec!["--continue".into(), "--dangerously-skip-permissions".into()],
            },
            cwd_resolved: "/tmp".into(),
            agent_task_id: None,
            created_at_ms: 7,
            last_attached_at_ms: 8,
            last_known_generation: Some("generation-a".into()),
            status: SessionStatus::Exited,
        };

        assert!(matches!(
            ExistingSessionStart::known_safe_exact(
                &session,
                &workspace,
                &PreparedProviderEnv,
                91,
                33,
                20,
            ),
            Err(SessionServiceError::AttachAuthorityLost { .. })
        ));
        store::write_record(
            &paths,
            RecordKind::Session,
            &session.session_id,
            9,
            &session,
        )
        .unwrap();
        let explicit = ExistingSessionStart::known_safe_explicit_user_restart(
            &session,
            &workspace,
            &PreparedProviderEnv,
            91,
            33,
            20,
        )
        .expect("strict current-provider latest recipe is authorized only by explicit Reopen");
        assert_eq!(explicit.session, session);
        assert_eq!(explicit.workspace, workspace);
        assert_eq!(explicit.params.command, "/bin/prepared-provider-shell");
        assert_eq!(explicit.params.args[0], crate::LOGIN_SHELL_COMMAND_FLAGS);
        assert!(explicit.params.args[1].contains("'claude' '--continue'"));
        assert!(matches!(
            SessionService::new(&paths).ensure_fresh_daemon_start_row(
                explicit.params(),
                FreshDaemonSessionStart::Existing { start: &explicit },
            ),
            Err(SessionServiceError::AttachAuthorityLost { .. })
        ));
        assert_eq!(load_record(&paths, &session.session_id), session);

        let mut non_exited = session.clone();
        non_exited.status = SessionStatus::Live;
        assert!(matches!(
            ExistingSessionStart::known_safe_explicit_user_restart(
                &non_exited,
                &workspace,
                &PreparedProviderEnv,
                91,
                33,
                20,
            ),
            Err(SessionServiceError::AttachAuthorityLost { .. })
        ));

        let mut generationless = session.clone();
        generationless.last_known_generation = None;
        assert!(matches!(
            ExistingSessionStart::known_safe_explicit_user_restart(
                &generationless,
                &workspace,
                &PreparedProviderEnv,
                91,
                33,
                20,
            ),
            Err(SessionServiceError::AttachAuthorityLost { .. })
        ));

        let mut malformed = session;
        malformed.launch = LaunchSpec::KnownSafe {
            launch_spec_id: "claude".into(),
            params: vec!["--continue".into(), "--foreign-wrapper-flag".into()],
        };
        assert!(matches!(
            ExistingSessionStart::known_safe_explicit_user_restart(
                &malformed,
                &workspace,
                &PreparedProviderEnv,
                91,
                33,
                20,
            ),
            Err(SessionServiceError::AttachAuthorityLost { .. })
        ));
    }

    #[test]
    fn explicit_user_shell_restart_seals_fallback_and_stays_renderer_only() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let workspace = match store::load_one::<Workspace>(&paths, RecordKind::Workspace, "ws1")
            .unwrap()
            .unwrap()
        {
            LoadOutcome::Loaded(workspace) => workspace,
            other => panic!("expected Workspace, got {other:?}"),
        };
        let session = SessionRecord {
            session_id: "explicit-shell".into(),
            workspace_id: workspace.workspace_id.clone(),
            kind: SessionKind::Shell,
            launch: LaunchSpec::OptOut,
            cwd_resolved: "/tmp".into(),
            agent_task_id: None,
            created_at_ms: 7,
            last_attached_at_ms: 8,
            last_known_generation: Some("generation-shell-a".into()),
            status: SessionStatus::Exited,
        };
        store::write_record(
            &paths,
            RecordKind::Session,
            &session.session_id,
            9,
            &session,
        )
        .unwrap();
        let explicit = ExistingSessionStart::explicit_user_shell_restart(
            &session,
            &workspace,
            vec!["/bin/reviewed-shell".into(), "-l".into()],
            91,
            33,
            20,
        )
        .expect("explicit plain-terminal Reopen seals the reviewed fallback shell");
        assert_eq!(explicit.session, session);
        assert_eq!(explicit.workspace, workspace);
        assert_eq!(explicit.params.command, "/bin/reviewed-shell");
        assert_eq!(explicit.params.args, ["-l"]);
        assert_eq!(explicit.scope, ExistingSessionStartScope::ExplicitUserShell);
        assert!(matches!(
            SessionService::new(&paths).ensure_fresh_daemon_start_row(
                explicit.params(),
                FreshDaemonSessionStart::Existing { start: &explicit },
            ),
            Err(SessionServiceError::AttachAuthorityLost { .. })
        ));
        assert_eq!(load_record(&paths, &session.session_id), session);

        for invalid in [
            SessionRecord {
                status: SessionStatus::Live,
                ..session.clone()
            },
            SessionRecord {
                kind: SessionKind::Agent,
                ..session.clone()
            },
            SessionRecord {
                launch: LaunchSpec::KnownSafe {
                    launch_spec_id: "shell".into(),
                    params: Vec::new(),
                },
                ..session.clone()
            },
            SessionRecord {
                last_known_generation: None,
                ..session.clone()
            },
            SessionRecord {
                cwd_resolved: tmp.path().join("missing").to_string_lossy().into_owned(),
                ..session.clone()
            },
        ] {
            assert!(matches!(
                ExistingSessionStart::explicit_user_shell_restart(
                    &invalid,
                    &workspace,
                    vec!["/bin/reviewed-shell".into()],
                    91,
                    33,
                    20,
                ),
                Err(SessionServiceError::AttachAuthorityLost { .. })
            ));
        }
        assert!(matches!(
            ExistingSessionStart::explicit_user_shell_restart(
                &session,
                &workspace,
                Vec::new(),
                91,
                33,
                20,
            ),
            Err(SessionServiceError::AttachAuthorityLost { .. })
        ));
    }

    #[test]
    fn exact_attach_preflight_never_combines_session_and_workspace_from_different_snapshots() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let actual_workspace =
            match store::load_one::<Workspace>(&paths, RecordKind::Workspace, "ws1")
                .unwrap()
                .unwrap()
            {
                LoadOutcome::Loaded(workspace) => workspace,
                other => panic!("expected Workspace, got {other:?}"),
            };
        let mut expected_workspace = actual_workspace.clone();
        expected_workspace.root = "/reviewed-root-that-is-not-current-yet".into();
        let expected_session = SessionRecord {
            session_id: "snapshot-session".into(),
            workspace_id: actual_workspace.workspace_id.clone(),
            kind: SessionKind::Shell,
            launch: known_safe("ls-1"),
            cwd_resolved: "/tmp".into(),
            agent_task_id: None,
            created_at_ms: 7,
            last_attached_at_ms: 8,
            last_known_generation: Some("generation-a".into()),
            status: SessionStatus::Live,
        };
        store::write_record(
            &paths,
            RecordKind::Session,
            &expected_session.session_id,
            9,
            &expected_session,
        )
        .unwrap();
        let proof =
            ExistingSessionAttach::exact(&expected_session, &expected_workspace, 10).unwrap();

        // Initially the DB contains A0+W1. Immediately after the helper reads A0, one other
        // connection atomically publishes A1+W0. The reviewed A0+W0 pair therefore never existed.
        // A torn pair of autocommit reads would falsely accept it; one DEFERRED snapshot sees W1.
        let db_path = crate::db::db_path(paths.base());
        let mut replacement_session = expected_session.clone();
        replacement_session.last_attached_at_ms = 999;
        let hook_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook_fired_worker = std::sync::Arc::clone(&hook_fired);
        let expected_workspace_for_hook = expected_workspace.clone();
        let replacement_session_for_hook = replacement_session.clone();
        let _hook = crate::store_sqlite::install_window_layout_test_hook(
            expected_session.session_id.clone(),
            move |stage, _| {
                if stage != "after-exact-session-before-workspace"
                    || hook_fired_worker.swap(true, std::sync::atomic::Ordering::SeqCst)
                {
                    return;
                }
                let mut other = rusqlite::Connection::open(&db_path).unwrap();
                other.pragma_update(None, "foreign_keys", "ON").unwrap();
                other.pragma_update(None, "busy_timeout", 5000).unwrap();
                let tx = other
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .unwrap();
                crate::store_sqlite::upsert(
                    &tx,
                    RecordKind::Workspace,
                    &expected_workspace_for_hook.workspace_id,
                    &serde_json::to_value(&expected_workspace_for_hook).unwrap(),
                )
                .unwrap();
                crate::store_sqlite::upsert(
                    &tx,
                    RecordKind::Session,
                    &replacement_session_for_hook.session_id,
                    &serde_json::to_value(&replacement_session_for_hook).unwrap(),
                )
                .unwrap();
                tx.commit().unwrap();
            },
        );

        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            while read_request(&mut reader, tx).is_some() {}
        });
        let client = DaemonClient::connect(&stub.path).unwrap();
        let error = match SessionService::new(&paths)
            .attach_existing_exact_headless(client, &proof, None)
        {
            Err(error) => error,
            Ok(_) => panic!("Frankenstein A/W snapshot must be refused before daemon IO"),
        };
        assert!(matches!(
            error,
            SessionServiceError::AttachAuthorityLost { .. }
        ));
        assert!(hook_fired.load(std::sync::atomic::Ordering::SeqCst));
        assert!(matches!(
            stub.requests
                .recv_timeout(std::time::Duration::from_secs(1)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
        assert_eq!(load_record(&paths, "snapshot-session"), replacement_session);
        match store::load_one::<Workspace>(&paths, RecordKind::Workspace, "ws1").unwrap() {
            Some(LoadOutcome::Loaded(current)) => assert_eq!(current, expected_workspace),
            other => panic!("expected replacement Workspace, got {other:?}"),
        }
    }

    #[test]
    fn reviewed_headless_exited_restart_threads_child_environment_and_retires() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let workspace = match store::load_one::<Workspace>(&paths, RecordKind::Workspace, "ws1")
            .unwrap()
            .unwrap()
        {
            LoadOutcome::Loaded(workspace) => workspace,
            other => panic!("expected Workspace, got {other:?}"),
        };
        let session = SessionRecord {
            session_id: "headless-exited".into(),
            workspace_id: workspace.workspace_id.clone(),
            kind: SessionKind::Agent,
            launch: LaunchSpec::KnownSafe {
                launch_spec_id: "codex".into(),
                params: vec![
                    "resume".into(),
                    "60000000-0000-4000-8000-000000000001".into(),
                ],
            },
            cwd_resolved: "/tmp".into(),
            agent_task_id: None,
            created_at_ms: 7,
            last_attached_at_ms: 8,
            last_known_generation: Some("generation-a".into()),
            status: SessionStatus::Exited,
        };
        store::write_record(
            &paths,
            RecordKind::Session,
            &session.session_id,
            9,
            &session,
        )
        .unwrap();
        let attach = ExistingSessionAttach::exact(&session, &workspace, 20).unwrap();
        let start = ExistingSessionStart::known_safe_exact(
            &session,
            &workspace,
            &PreparedProviderEnv,
            91,
            33,
            20,
        )
        .unwrap();
        let child_environment = maestro_protocol::ChildEnvironment {
            home: "/home/test".into(),
            shell: "/bin/reviewed-shell".into(),
        };
        let expected_child_environment = child_environment.clone();
        let stub = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"daemon_info"}"#)
            );
            answer_prepared_daemon_info(stream);
            let (reserved_id, reserved_token) =
                answer_start_operation_reserved(&mut reader, tx, stream);
            let request = serde_json::from_str::<maestro_protocol::ClientRequest>(
                &read_request(&mut reader, tx).expect("conditional exited StartSession"),
            )
            .unwrap();
            let (id, operation_token) = match request {
                maestro_protocol::ClientRequest::StartSession {
                    id,
                    command,
                    args,
                    child_environment: Some(environment),
                    cols: 91,
                    rows: 33,
                    restart_exited: false,
                    conditional_start:
                        Some(maestro_protocol::ConditionalSessionStart {
                            operation_token,
                            precondition:
                                maestro_protocol::SessionStartPrecondition::ExitedGeneration {
                                    expected_generation,
                                },
                        }),
                    ..
                } if expected_generation == "generation-a"
                    && environment == expected_child_environment
                    && command == "/bin/prepared-provider-shell"
                    && args.first().map(String::as_str) == Some("-lic") =>
                {
                    (id, operation_token)
                }
                other => panic!("expected reviewed exited headless Start, got {other:?}"),
            };
            assert_eq!(id, reserved_id);
            assert_eq!(operation_token, reserved_token);
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "conditional_session_start",
                    "id": id,
                    "operation_token": operation_token.as_str(),
                    "daemon_instance_id": PREPARED_DAEMON_INSTANCE,
                    "outcome": {"status": "applied", "generation": "generation-b"},
                })
            )
            .unwrap();
            stream.flush().unwrap();
            let attach_request = serde_json::from_str::<maestro_protocol::ClientRequest>(
                &read_request(&mut reader, tx).expect("exact replacement Attach"),
            )
            .unwrap();
            let output_generation = match attach_request {
                maestro_protocol::ClientRequest::Attach {
                    id: attached_id,
                    expected_session_generation: Some(generation),
                    output_generation: Some(output_generation),
                    handoff: None,
                    ..
                } if attached_id == id && generation == "generation-b" => output_generation,
                other => panic!("expected exact replacement Attach, got {other:?}"),
            };
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "grid",
                    "id": id,
                    "output_generation": output_generation,
                    "grid": {"generation": "generation-b", "revision": 1},
                })
            )
            .unwrap();
            stream.flush().unwrap();
            answer_applied_start_operation_retired(
                &mut reader,
                tx,
                stream,
                &id,
                &operation_token,
                "generation-b",
            );
        });

        let record = SessionService::new(&paths)
            .resolve_existing_exact_headless_with_child_environment(
                DaemonClient::connect(&stub.path).unwrap(),
                &attach,
                Some(ExistingSessionMissingStart::KnownSafe(&start)),
                Some(child_environment),
            )
            .unwrap();
        assert_eq!(record.status, SessionStatus::Live);
        assert_eq!(
            record.last_known_generation.as_deref(),
            Some("generation-b")
        );
        assert_eq!(load_record(&paths, "headless-exited"), record);
        assert!(stub
            .collected_requests()
            .iter()
            .any(|request| request.contains("retire_start_operation")));
    }
}
