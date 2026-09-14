//! A MINIMAL, synchronous daemon client over the Unix-domain-socket protocol — the Phase 1B safe
//! unit of the App Shell. It is the first code in `maestro-shell` that actually talks to a running
//! `pty-daemon`, and it deliberately does the SMALLEST useful thing: connect to a caller-supplied
//! socket, prove mutation compatibility with a read-only `DaemonInfo` request, reserve a bounded
//! process-lifetime operation tuple, drive one
//! `StartSession -> Attach{want_raw_output:false} -> Grid` flow, attach read-only to an existing
//! retained session, read the live session set with `ListSessions`, and request a single session be
//! killed and confirmed gone with `kill_session`
//! (over the daemon's existing `Kill` request). Everything else the daemon protocol can do (write,
//! resize, scrollback, channels, raw output) is out of scope here.
//!
//! All wire types come from `maestro-protocol`: requests via [`ClientRequest`], the framing cap via
//! [`MAX_LINE_BYTES`], and replies via the lightweight [`ShellEvent`] decoder. This client never
//! models the daemon's full event/grid types, so it stays decoupled from daemon runtime internals
//! exactly as the shared-crate design intended.
//!
//! ## Safety / robustness invariants
//!
//! - **Bounded lines, both directions.** A reply line is read with a hard cap of [`MAX_LINE_BYTES`];
//!   a longer line is a framing violation that errors
//!   ([`DaemonClientError::LineTooLong`] with [`Direction::Inbound`]) rather than growing memory
//!   without limit — mirroring the daemon's own `read_until` cap. The SAME cap is applied to
//!   outbound request lines: an oversized request is rejected ([`Direction::Outbound`]) BEFORE any
//!   bytes are written, so a pathological request never lands a partial/oversized line on the wire.
//! - **Timeouts.** Read and write deadlines are set on the socket so a silent or wedged daemon
//!   surfaces as [`DaemonClientError::Timeout`] instead of hanging the caller forever.
//! - **Mutual local identity.** The daemon already checks every client's kernel peer UID. The
//!   client likewise reads the connected server's kernel peer UID before sending any request and
//!   rejects a different or unidentifiable OS user. A planted socket in a shared temporary
//!   directory therefore cannot impersonate the user's daemon.
//! - **Clean teardown.** The `UnixStream` is owned by [`DaemonClient`]; every method returns by
//!   value or error and the stream is dropped (closing the fd) when the client is dropped — there is
//!   no path that leaks the socket.
//! - **No daemon lifecycle.** This client never spawns, supervises, or kills a daemon process, never
//!   opens a PTY, never runs git, and never creates directories. It only checks that a caller-given
//!   cwd is an existing directory before sending `StartSession`.

// Mutation failures intentionally retain protocol receipts and consume-once recovery authorities;
// boxing or splitting those values would weaken the ownership contract at this boundary.
#![allow(
    clippy::large_enum_variant,
    clippy::result_large_err,
    clippy::too_many_arguments,
    clippy::type_complexity
)]

use std::collections::{BTreeMap, BTreeSet};
mod startup_probe;
#[cfg(test)]
use std::io::Read;
use std::io::{BufRead, BufReader, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use maestro_protocol::{
    AttachmentHandoff, AttachmentHandoffToken, ChildEnvironment, ClientRequest,
    ConditionalSessionStart, ConditionalSessionStartOutcome, ConditionalSessionStartRefusal,
    DaemonInstanceId, SessionAttachRefusal, SessionId, SessionListInfo,
    SessionStartOperationLifecycle, SessionStartOperationReserveOutcome,
    SessionStartOperationReserveRefusal, SessionStartOperationRetireExpectation,
    SessionStartOperationRetireOutcome, SessionStartOperationStatus, SessionStartOperationToken,
    SessionStartPrecondition, ShellEvent, MAX_LINE_BYTES,
};

/// A response-wait operation may tolerate additive/unrelated events, but never an unbounded stream
/// of them. The byte budget admits several maximum-sized legacy grid snapshots while still placing
/// one finite resource ceiling over a whole public operation.
pub const MAX_REPLY_EVENTS_PER_OPERATION: usize = 256;
pub const MAX_REPLY_BYTES_PER_OPERATION: usize = 4 * MAX_LINE_BYTES;

/// Which side of the framed connection a [`DaemonClientError::LineTooLong`] applies to: an inbound
/// reply line the daemon sent us, or an outbound request line we were about to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// A reply line read FROM the daemon.
    Inbound,
    /// A request line we were about to write TO the daemon.
    Outbound,
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Direction::Inbound => write!(f, "reply"),
            Direction::Outbound => write!(f, "request"),
        }
    }
}

/// Everything that can go wrong driving the daemon, as TYPED variants so a caller (and the tests)
/// can distinguish "daemon isn't there" from "daemon said no" from "my cwd is bad" without string
/// matching.
#[derive(Debug)]
pub enum DaemonClientError {
    /// The socket could not be connected (refused / missing path / not a socket). The daemon is not
    /// reachable; this is distinct from a daemon that answered with an error.
    DaemonUnavailable {
        path: String,
        source: std::io::Error,
    },
    /// A socket accepted the connection, but the kernel could not prove that its server endpoint
    /// belongs to this effective OS user. No protocol bytes are sent to an untrusted endpoint.
    UntrustedDaemon {
        path: String,
        expected_uid: u32,
        observed_uid: Option<u32>,
        detail: String,
    },
    /// The caller-supplied cwd is not an existing directory. Returned BEFORE any request is written,
    /// so a bad cwd never reaches the daemon as a half-issued `StartSession`. This matches the
    /// daemon's own `Path::is_dir()` boundary: a missing path OR an existing non-directory (e.g. a
    /// regular file) is rejected here.
    InvalidCwd { cwd: String },
    /// A read or write exceeded its deadline — a silent/wedged daemon. Surfaced rather than hanging.
    Timeout { during: &'static str },
    /// A framed line exceeded [`MAX_LINE_BYTES`]: a framing violation. For `Inbound`, a reply over
    /// the cap is abandoned without buffering further (mirroring the daemon's read cap);
    /// for `Outbound`, an oversized request is rejected BEFORE any bytes are written.
    LineTooLong { direction: Direction, limit: usize },
    /// The peer kept sending bounded but irrelevant frames until the whole-operation event/byte
    /// budget was exhausted. This closes the liveness gap left by per-read socket deadlines.
    ReplyBudgetExceeded { during: &'static str },
    /// The daemon replied with an `Error { message }` event.
    DaemonError { message: String },
    /// The connected retained daemon is attach-compatible but does not implement the mutation
    /// semantics required to start a session without risking unrelated retained snapshots.
    MutationProtocolUnsupported {
        required: u32,
        observed: Option<u32>,
    },
    /// An attach-only upgrade requested a stable retained id that the daemon did not report. The
    /// client never substitutes another session implicitly and never sends `StartSession` here.
    RetainedSessionUnavailable { id: SessionId },
    /// An explicit same-id restart returned the exact retained generation it was authorized to
    /// replace. This can happen when another attachment still fences the exited object and a
    /// best-effort daemon Error is lost before the following Attach/Grid. The old Grid is never
    /// accepted as proof that a replacement started.
    RestartGenerationUnchanged { id: SessionId },
    /// The daemon atomically refused the exact conditional-start precondition. AttachmentInUse is
    /// the only retryable reason for the explicit-revive coordinator; every other reason leaves
    /// durable A untouched and fails closed.
    ConditionalStartRefused {
        id: SessionId,
        reason: ConditionalSessionStartRefusal,
    },
    /// The daemon refused the content-blind reservation before any Start frame was sent.
    StartOperationReservationRefused {
        id: SessionId,
        reason: SessionStartOperationReserveRefusal,
    },
    /// A durable/reused operation token was already terminal before this client could Start. The
    /// exact status is preserved so a recovery worker can distinguish Refused from Applied.
    StartOperationTerminal {
        id: SessionId,
        status: SessionStartOperationStatus,
    },
    /// A daemon-atomic Attach precondition refused before acquiring a guard or exposing a Grid.
    ConditionalAttachRefused {
        id: SessionId,
        expected_generation: String,
        reason: SessionAttachRefusal,
    },
    /// The operation reservation or StartSession frame crossed its socket-write boundary but no
    /// exact terminal proof was obtained. The caller must preserve durable A/Unknown and retain
    /// this authority for lookup/retirement; it must not issue a fresh Absent mutation.
    ConditionalStartPossiblyApplied {
        id: SessionId,
        recovery: ConditionalStartRecovery,
        source: Box<DaemonClientError>,
    },
    /// The session exited before the awaited `Grid` arrived (e.g. the command failed immediately).
    SessionExited { id: SessionId, code: Option<i32> },
    /// The connection closed (EOF) before the awaited reply arrived.
    UnexpectedEof { during: &'static str },
    /// A reply line was not valid UTF-8 or not valid JSON for any modeled/tolerated event.
    Protocol { detail: String },
    /// A lower-level IO error not covered by the more specific variants above.
    Io(std::io::Error),
}

/// Opaque recovery facts retained whenever a conditional Start crossed its publication boundary.
/// It carries the exact operation token and daemon instance without exposing either in Debug. A
/// consuming service may bind it to the still-open reviewed client for lookup/retry/cancellation.
#[derive(Clone)]
pub struct ConditionalStartRecovery {
    session_id: SessionId,
    operation_token: SessionStartOperationToken,
    daemon_instance_id: DaemonInstanceId,
    precondition: SessionStartPrecondition,
    /// Daemon-ledger proof only. This never authorizes durable Live without a later exact Attach
    /// Grid on the same generation.
    operation_applied_generation: Option<String>,
    /// Exact Attach + echoed route Grid proof. Only this accessor may authorize durable Live.
    grid_proven_generation: Option<String>,
    handoff_seed: Option<AttachmentHandoffSeed>,
}

impl ConditionalStartRecovery {
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn daemon_instance_id(&self) -> &DaemonInstanceId {
        &self.daemon_instance_id
    }

    pub fn operation_applied_generation(&self) -> Option<&str> {
        self.operation_applied_generation.as_deref()
    }

    pub fn grid_proven_generation(&self) -> Option<&str> {
        self.grid_proven_generation.as_deref()
    }

    /// Backward-compatible safe accessor: "applied" here means operation Applied *and* exact Grid
    /// proven. An ACK or Lookup alone deliberately leaves this `None`.
    pub fn applied_generation(&self) -> Option<&str> {
        self.grid_proven_generation()
    }
}

impl std::fmt::Debug for ConditionalStartRecovery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConditionalStartRecovery")
            .field("session_id", &self.session_id)
            .field(
                "operation_applied_generation_known",
                &self.operation_applied_generation.is_some(),
            )
            .field(
                "grid_proven_generation_known",
                &self.grid_proven_generation.is_some(),
            )
            .field("handoff_offered", &self.handoff_seed.is_some())
            .finish_non_exhaustive()
    }
}

/// Owns the exact reviewed connection and opaque operation facts after a conditional Start could
/// not be conclusively finalized. Keeping this value preserves any installed handoff token and the
/// only same-instance cancellation channel; Debug never reveals tokens or daemon identity.
pub struct ConditionalStartRecoveryAuthority {
    state: std::sync::Mutex<ConditionalStartRecoveryState>,
}

/// Durable recovery result that keeps daemon-ledger knowledge separate from exact Attach/Grid
/// proof. Only `GridProven` may feed a durable Live publication.
#[derive(Debug)]
pub(crate) enum ConditionalStartGridRecovery {
    OperationStatus(SessionStartOperationStatus),
    GridProven {
        attached: AttachedSession,
        lifecycle_at_lookup: SessionStartOperationLifecycle,
    },
}

/// Exact peer identity captured from one reviewed generation-conditional Start capability probe.
///
/// Fresh-daemon recovery carries this value from child readiness to the later `Absent` mutation so
/// a socket-path rebind cannot redirect durable A -> B recovery to an unrelated daemon instance.
/// Linux additionally binds the kernel-authenticated server PID; other platforms rely on the
/// daemon's per-process random instance id plus the ordinary peer-UID/path review.
#[derive(Clone, PartialEq, Eq)]
pub struct ConditionalStartPeerIdentity {
    daemon_instance_id: DaemonInstanceId,
    server_pid: Option<u32>,
    child_environment: bool,
}

impl std::fmt::Debug for ConditionalStartPeerIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConditionalStartPeerIdentity")
            .field("daemon_instance", &"<redacted>")
            .field("kernel_pid_bound", &self.server_pid.is_some())
            .field("child_environment", &self.child_environment)
            .finish()
    }
}

impl ConditionalStartPeerIdentity {
    pub(crate) fn daemon_instance_id(&self) -> &DaemonInstanceId {
        &self.daemon_instance_id
    }

    /// Kernel-authenticated daemon PID where the platform exposes one (Linux today).
    pub fn server_pid(&self) -> Option<u32> {
        self.server_pid
    }

    /// Whether this exact capability probe proved the daemon applies the restricted typed child
    /// environment on `StartSession` instead of silently inheriting its desktop environment.
    pub fn supports_child_environment(&self) -> bool {
        self.child_environment
    }
}

struct ConditionalStartRecoveryState {
    recovery: ConditionalStartRecovery,
    client: DaemonClient,
}

impl ConditionalStartRecoveryAuthority {
    pub(crate) fn new(recovery: ConditionalStartRecovery, client: DaemonClient) -> Self {
        Self {
            state: std::sync::Mutex::new(ConditionalStartRecoveryState { recovery, client }),
        }
    }

    pub(crate) fn from_bound_absent_journal(
        session_id: SessionId,
        operation_token: SessionStartOperationToken,
        daemon_instance_id: DaemonInstanceId,
        applied_generation: Option<String>,
        client: DaemonClient,
    ) -> Self {
        Self::new(
            ConditionalStartRecovery {
                session_id,
                operation_token,
                daemon_instance_id,
                precondition: SessionStartPrecondition::Absent {
                    excluded_generation: None,
                },
                operation_applied_generation: applied_generation,
                grid_proven_generation: None,
                handoff_seed: None,
            },
            client,
        )
    }

    pub fn session_id(&self) -> SessionId {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recovery
            .session_id
            .clone()
    }

    pub fn applied_generation(&self) -> Option<String> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recovery
            .grid_proven_generation
            .clone()
    }

    pub fn operation_applied_generation(&self) -> Option<String> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recovery
            .operation_applied_generation
            .clone()
    }

    pub fn has_pending_handoff(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recovery
            .handoff_seed
            .is_some()
    }

    /// Return the exact process-ledger state. Applied is intentionally distinct from Grid proof;
    /// callers must exact-Attach the reported generation before publishing durable Live.
    pub(crate) fn lookup_operation_status(
        &self,
    ) -> Result<SessionStartOperationStatus, DaemonClientError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::cancel_pending_handoff_before_reconnect(&mut state)?;
        let expected_instance = state.recovery.daemon_instance_id.clone();
        let expected_session = state.recovery.session_id.clone();
        let expected_token = state.recovery.operation_token.clone();
        let mut budget = state.client.generation_kill_budget()?;
        let mut replacement = state
            .client
            .reconnect_same_daemon_before(&expected_instance, &mut budget)?;
        let lookup = replacement.lookup_start_operation_before(
            &expected_session,
            &expected_token,
            &expected_instance,
            &mut budget,
        );
        let restored = replacement.restore_timeouts(&budget);
        match (lookup, restored) {
            (Ok(status), Ok(())) => {
                if let SessionStartOperationStatus::Applied { generation, .. } = &status {
                    state.recovery.operation_applied_generation = Some(generation.clone());
                }
                replacement.finish_generation_mutation();
                state.client = replacement;
                Ok(status)
            }
            (Ok(_), Err(error)) | (Err(error), _) => {
                replacement.abort_connection();
                Err(error)
            }
        }
    }

    /// Reconnect to the exact daemon, lookup the operation, and—only for Applied(G)—perform an
    /// exact-generation Attach and require its echoed Grid route. A Removed/Reserved/Refused/
    /// Unknown status is returned without manufacturing Live authority.
    pub(crate) fn recover_with_exact_grid(
        &self,
    ) -> Result<ConditionalStartGridRecovery, DaemonClientError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::cancel_pending_handoff_before_reconnect(&mut state)?;
        let expected_instance = state.recovery.daemon_instance_id.clone();
        let expected_session = state.recovery.session_id.clone();
        let expected_token = state.recovery.operation_token.clone();
        let mut budget = state.client.generation_kill_budget()?;
        let mut replacement = state
            .client
            .reconnect_same_daemon_before(&expected_instance, &mut budget)?;
        let status = replacement.lookup_start_operation_before(
            &expected_session,
            &expected_token,
            &expected_instance,
            &mut budget,
        )?;
        let SessionStartOperationStatus::Applied {
            generation,
            lifecycle,
        } = status
        else {
            let restored = replacement.restore_timeouts(&budget);
            if let Err(error) = restored {
                replacement.abort_connection();
                return Err(error);
            }
            replacement.finish_generation_mutation();
            state.client = replacement;
            return Ok(ConditionalStartGridRecovery::OperationStatus(status));
        };
        state.recovery.operation_applied_generation = Some(generation.clone());
        if lifecycle == SessionStartOperationLifecycle::Removed {
            let restored = replacement.restore_timeouts(&budget);
            if let Err(error) = restored {
                replacement.abort_connection();
                return Err(error);
            }
            replacement.finish_generation_mutation();
            state.client = replacement;
            return Ok(ConditionalStartGridRecovery::OperationStatus(
                SessionStartOperationStatus::Applied {
                    generation,
                    lifecycle,
                },
            ));
        }

        let recovery = state.recovery.clone();
        let attached = replacement.attach_after_conditional_start_before(
            expected_session,
            generation,
            expected_instance,
            false,
            recovery,
            &mut budget,
        );
        let restored = replacement.restore_timeouts(&budget);
        match (attached, restored) {
            (Ok((attached, recovery)), Ok(())) => {
                replacement.finish_generation_mutation();
                state.recovery = recovery;
                state.client = replacement;
                Ok(ConditionalStartGridRecovery::GridProven {
                    attached,
                    lifecycle_at_lookup: lifecycle,
                })
            }
            (Ok(_), Err(error)) | (Err(error), _) => {
                replacement.abort_connection();
                Err(error)
            }
        }
    }

    /// Barrier a never-applied Reserved/Refused operation. A conflicting Applied result preserves
    /// its exact generation in the typed outcome and never removes it.
    pub(crate) fn retire_unapplied_operation(
        &self,
    ) -> Result<SessionStartOperationRetireOutcome, DaemonClientError> {
        self.retire_operation(SessionStartOperationRetireExpectation::Unapplied)
    }

    /// Retire only an exact Applied generation after the caller has finished durable publication
    /// or forward exact-generation cleanup.
    pub(crate) fn retire_applied_operation(
        &self,
        generation: &str,
    ) -> Result<SessionStartOperationRetireOutcome, DaemonClientError> {
        validate_expected_attach_generation(generation)?;
        self.retire_operation(SessionStartOperationRetireExpectation::Applied {
            generation: generation.to_string(),
        })
    }

    fn retire_operation(
        &self,
        expected: SessionStartOperationRetireExpectation,
    ) -> Result<SessionStartOperationRetireOutcome, DaemonClientError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Self::cancel_pending_handoff_before_reconnect(&mut state)?;
        let expected_instance = state.recovery.daemon_instance_id.clone();
        let expected_session = state.recovery.session_id.clone();
        let expected_token = state.recovery.operation_token.clone();
        let mut budget = state.client.generation_kill_budget()?;
        let mut replacement = state
            .client
            .reconnect_same_daemon_before(&expected_instance, &mut budget)?;
        let retired = replacement.retire_start_operation_before(
            &expected_session,
            &expected_token,
            &expected_instance,
            expected,
            &mut budget,
        );
        let restored = replacement.restore_timeouts(&budget);
        match (retired, restored) {
            (Ok(outcome), Ok(())) => {
                replacement.finish_generation_mutation();
                state.client = replacement;
                Ok(outcome)
            }
            (Ok(_), Err(error)) | (Err(error), _) => {
                replacement.abort_connection();
                Err(error)
            }
        }
    }

    /// Reconnection would drop the original Offer-owning attachment guard. First retire its exact
    /// pending token on that same connection; only an acknowledged cancellation permits replacing
    /// the client. A failed cancellation leaves both the seed and original connection intact.
    fn cancel_pending_handoff_before_reconnect(
        state: &mut ConditionalStartRecoveryState,
    ) -> Result<(), DaemonClientError> {
        let Some(seed) = state.recovery.handoff_seed.clone() else {
            return Ok(());
        };
        state.client.cancel_attachment_handoff_seed(&seed)?;
        state.recovery.handoff_seed = None;
        Ok(())
    }

    /// Best-effort exact cancellation on the original reviewed connection. Success clears the
    /// retained seed; failure keeps both the seed and connection for a later retry.
    pub fn cancel_pending_handoff(&self) -> Result<(), DaemonClientError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(seed) = state.recovery.handoff_seed.clone() else {
            return Ok(());
        };
        state.client.cancel_attachment_handoff_seed(&seed)?;
        state.recovery.handoff_seed = None;
        Ok(())
    }
}

impl std::fmt::Debug for ConditionalStartRecoveryAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        formatter
            .debug_struct("ConditionalStartRecoveryAuthority")
            .field("session_id", &state.recovery.session_id)
            .field(
                "operation_applied_generation_known",
                &state.recovery.operation_applied_generation.is_some(),
            )
            .field(
                "grid_proven_generation_known",
                &state.recovery.grid_proven_generation.is_some(),
            )
            .field("handoff_offered", &state.recovery.handoff_seed.is_some())
            .finish_non_exhaustive()
    }
}

/// A conditional Kill failure annotated with the only publication boundary a compensating
/// lifecycle caller can safely use.
///
/// `NotPublished` proves that no Kill frame write was attempted (validation, capability probing,
/// or request framing failed first). `PossiblyPublished` means the client crossed the socket-write
/// boundary; even a write/flush error can follow a partial frame, and an EOF/timeout while
/// confirming cannot prove whether the daemon acted. Callers must never restore durable ownership
/// merely because a `PossiblyPublished` operation was not confirmed.
#[derive(Debug)]
pub enum KillSessionPublicationError {
    NotPublished { source: DaemonClientError },
    PossiblyPublished { source: DaemonClientError },
}

impl KillSessionPublicationError {
    /// Preserve the legacy error surface for callers that perform no compensating durable write.
    pub fn into_daemon_error(self) -> DaemonClientError {
        match self {
            Self::NotPublished { source } | Self::PossiblyPublished { source } => source,
        }
    }
}

impl std::fmt::Display for KillSessionPublicationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPublished { source } => write!(f, "kill was not published: {source}"),
            Self::PossiblyPublished { source } => {
                write!(f, "kill may have been published: {source}")
            }
        }
    }
}

impl std::error::Error for KillSessionPublicationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::NotPublished { source } | Self::PossiblyPublished { source } => source,
        })
    }
}

/// Socket-option restoration cannot revoke an already-established daemon-lifetime fact. Keep the
/// original publication result and leave client disposal/replacement to the caller if restoration
/// itself failed.
fn finalize_exact_lifetime_release(
    result: Result<(), KillSessionPublicationError>,
    _restored: Result<(), DaemonClientError>,
) -> Result<(), KillSessionPublicationError> {
    result
}

impl std::fmt::Display for DaemonClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonClientError::DaemonUnavailable { path, source } => {
                write!(f, "daemon unavailable at {path}: {source}")
            }
            DaemonClientError::UntrustedDaemon {
                path,
                expected_uid,
                observed_uid,
                detail,
            } => match observed_uid {
                Some(observed_uid) => write!(
                    f,
                    "untrusted daemon at {path}: peer uid {observed_uid} does not match client uid {expected_uid} ({detail})"
                ),
                None => write!(
                    f,
                    "untrusted daemon at {path}: kernel peer identity was unavailable for client uid {expected_uid} ({detail})"
                ),
            },
            DaemonClientError::InvalidCwd { .. } => {
                f.write_str("cwd is not an existing directory")
            }
            DaemonClientError::Timeout { during } => {
                write!(f, "timed out while {during}")
            }
            DaemonClientError::LineTooLong { direction, limit } => {
                write!(f, "{direction} line exceeds {limit} bytes; closing")
            }
            DaemonClientError::ReplyBudgetExceeded { during } => {
                write!(f, "reply budget exhausted while {during}")
            }
            DaemonClientError::DaemonError { message } => {
                write!(f, "daemon error: {message}")
            }
            DaemonClientError::MutationProtocolUnsupported { required, observed } => match observed {
                Some(observed) => write!(
                    f,
                    "retained daemon protocol {observed} is attach-only; session creation requires protocol {required}"
                ),
                None => write!(
                    f,
                    "legacy retained daemon is attach-only; session creation requires protocol {required}"
                ),
            },
            DaemonClientError::RetainedSessionUnavailable { id } => {
                write!(f, "retained session {id} is not available for attach-only launch")
            }
            DaemonClientError::RestartGenerationUnchanged { id } => write!(
                f,
                "session {id} restart returned the retained generation instead of a replacement"
            ),
            DaemonClientError::ConditionalStartRefused { id, reason } => {
                write!(f, "conditional start for session {id} was refused: {reason:?}")
            }
            DaemonClientError::StartOperationReservationRefused { id, reason } => write!(
                f,
                "start operation reservation for session {id} was refused: {reason:?}"
            ),
            DaemonClientError::StartOperationTerminal { id, status } => write!(
                f,
                "start operation for session {id} was already terminal: {status:?}"
            ),
            DaemonClientError::ConditionalAttachRefused {
                id,
                expected_generation,
                reason,
            } => write!(
                f,
                "conditional attach for session {id} generation {expected_generation:?} was refused: {reason:?}"
            ),
            DaemonClientError::ConditionalStartPossiblyApplied { id, source, .. } => write!(
                f,
                "conditional start for session {id} may have been applied: {source}"
            ),
            DaemonClientError::SessionExited { id, code } => {
                write!(f, "session {id} exited before grid (code {code:?})")
            }
            DaemonClientError::UnexpectedEof { during } => {
                write!(f, "connection closed while {during}")
            }
            DaemonClientError::Protocol { detail } => {
                write!(f, "protocol error: {detail}")
            }
            DaemonClientError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for DaemonClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DaemonClientError::DaemonUnavailable { source, .. } => Some(source),
            DaemonClientError::ConditionalStartPossiblyApplied { source, .. } => Some(source),
            DaemonClientError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Map an IO error to a typed timeout when the kernel reports the deadline elapsed, otherwise keep
/// it as a generic IO error. A socket read/write timeout surfaces as `WouldBlock` or `TimedOut`
/// depending on platform, so both are treated as a deadline hit.
fn classify_io(e: std::io::Error, during: &'static str) -> DaemonClientError {
    match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
            DaemonClientError::Timeout { during }
        }
        _ => DaemonClientError::Io(e),
    }
}

fn validate_expected_attach_generation(generation: &str) -> Result<(), DaemonClientError> {
    if generation.is_empty() || generation.len() > 128 {
        return Err(DaemonClientError::Protocol {
            detail: "expected Attach generation must be 1..=128 bytes".into(),
        });
    }
    Ok(())
}

/// Ask the kernel which effective UID owns the process at the connected server end.
#[cfg(not(target_os = "linux"))]
fn connected_server_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `stream` owns a connected Unix-domain socket for the duration of this call and both
    // output pointers refer to correctly sized live values.
    let status = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if status != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(uid as u32)
}

/// Linux exposes the connected server identity through `SO_PEERCRED`.
#[cfg(target_os = "linux")]
fn connected_server_uid(stream: &UnixStream) -> std::io::Result<u32> {
    Ok(connected_server_credentials(stream)?.uid)
}

#[cfg(target_os = "linux")]
fn connected_server_credentials(stream: &UnixStream) -> std::io::Result<libc::ucred> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `stream` owns a connected socket and `credentials`/`length` are correctly sized
    // writable outputs for `SO_PEERCRED`.
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut libc::ucred as *mut libc::c_void,
            &mut length,
        )
    };
    if status != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if length as usize != std::mem::size_of::<libc::ucred>() || credentials.pid <= 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "kernel returned an invalid Unix peer identity",
        ));
    }
    Ok(credentials)
}

fn effective_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() as u32 }
}

/// Connect an AF_UNIX stream without allowing the kernel's connect/backlog wait to escape the
/// caller's absolute deadline. `UnixStream::connect` is otherwise a blocking operation to which
/// read/write socket timeouts do not apply.
fn connect_unix_with_timeout(path: &Path, timeout: Duration) -> std::io::Result<UnixStream> {
    if timeout.is_zero() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "daemon connect deadline elapsed",
        ));
    }
    let path_bytes = path.as_os_str().as_bytes();
    let max_path = unsafe { std::mem::zeroed::<libc::sockaddr_un>() }
        .sun_path
        .len();
    if path_bytes.is_empty() || path_bytes.len() >= max_path {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Unix-domain socket path is empty or too long",
        ));
    }

    // SAFETY: `socket` returns a new owned fd on success. Wrapping it immediately in `OwnedFd`
    // closes it on every subsequent error path.
    let raw_fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if raw_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    // Mark close-on-exec and nonblocking before connect. The returned stream is restored to
    // blocking mode after poll completes; ordinary read/write deadlines are installed later.
    let descriptor_flags = unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFD) };
    if descriptor_flags < 0
        || unsafe {
            libc::fcntl(
                owned.as_raw_fd(),
                libc::F_SETFD,
                descriptor_flags | libc::FD_CLOEXEC,
            )
        } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let status_flags = unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFL) };
    if status_flags < 0
        || unsafe {
            libc::fcntl(
                owned.as_raw_fd(),
                libc::F_SETFL,
                status_flags | libc::O_NONBLOCK,
            )
        } < 0
    {
        return Err(std::io::Error::last_os_error());
    }

    let mut address = unsafe { std::mem::zeroed::<libc::sockaddr_un>() };
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (destination, source) in address.sun_path.iter_mut().zip(path_bytes.iter().copied()) {
        *destination = source as libc::c_char;
    }
    let address_len = std::mem::offset_of!(libc::sockaddr_un, sun_path)
        .checked_add(path_bytes.len() + 1)
        .and_then(|length| libc::socklen_t::try_from(length).ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unix-domain socket address length overflow",
            )
        })?;
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        address.sun_len = u8::try_from(address_len).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unix-domain socket address length exceeded platform limit",
            )
        })?;
    }

    let connected = unsafe {
        libc::connect(
            owned.as_raw_fd(),
            &address as *const libc::sockaddr_un as *const libc::sockaddr,
            address_len,
        )
    };
    if connected != 0 {
        let error = std::io::Error::last_os_error();
        let raw_error = error.raw_os_error();
        let in_progress = raw_error == Some(libc::EINPROGRESS)
            || raw_error == Some(libc::EALREADY)
            || raw_error == Some(libc::EWOULDBLOCK);
        if !in_progress {
            return Err(error);
        }

        let poll_deadline = Instant::now() + timeout;
        let mut descriptor = libc::pollfd {
            fd: owned.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        loop {
            let remaining = poll_deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "daemon connect deadline elapsed",
                    )
                })?;
            let timeout_ms = remaining.as_millis().max(1).min(i32::MAX as u128) as i32;
            let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
            if result > 0 {
                break;
            }
            if result == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "daemon connect deadline elapsed",
                ));
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }

        let mut socket_error: libc::c_int = 0;
        let mut socket_error_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                owned.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut socket_error as *mut libc::c_int as *mut libc::c_void,
                &mut socket_error_len,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if socket_error != 0 {
            return Err(std::io::Error::from_raw_os_error(socket_error));
        }
    }

    if unsafe {
        libc::fcntl(
            owned.as_raw_fd(),
            libc::F_SETFL,
            status_flags & !libc::O_NONBLOCK,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error());
    }

    Ok(UnixStream::from(owned))
}

fn verify_connected_server_identity(
    path: &Path,
    expected_uid: u32,
    observed: std::io::Result<u32>,
) -> Result<(), DaemonClientError> {
    match observed {
        Ok(observed_uid) if observed_uid == expected_uid => Ok(()),
        Ok(observed_uid) => Err(DaemonClientError::UntrustedDaemon {
            path: path.display().to_string(),
            expected_uid,
            observed_uid: Some(observed_uid),
            detail: "kernel peer credential mismatch".into(),
        }),
        Err(error) => Err(DaemonClientError::UntrustedDaemon {
            path: path.display().to_string(),
            expected_uid,
            observed_uid: None,
            detail: error.to_string(),
        }),
    }
}

/// The result of a successful `start_and_attach`: the session is live and the daemon has delivered
/// its authoritative grid baseline. Carries only the lightweight identity the shell needs — never
/// the cell payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachedSession {
    /// The session id the attach baseline arrived for (echoes the requested id).
    pub id: SessionId,
    /// The grid lifetime id. A change across attaches means the daemon respawned a fresh grid; the
    /// shell persists this to detect that on a later reattach.
    pub generation: String,
    /// The revision the baseline snapshot is at, when the daemon included it.
    pub revision: Option<u64>,
    /// Opaque one-shot authority offered to the intended renderer. Ordinary/headless attaches
    /// carry no token. The token's own Debug/Display implementations are redacted.
    handoff_seed: Option<AttachmentHandoffSeed>,
}

impl AttachedSession {
    pub(crate) fn take_attachment_handoff_seed(&mut self) -> Option<AttachmentHandoffSeed> {
        self.handoff_seed.take()
    }
}

/// Result of the renderer's single generation-conditional Offer attempt. A typed Missing refusal
/// poisons that request socket, so the client reconnects to the exact same daemon instance/PID
/// inside the inherited deadline before returning `StartIfAbsent`.
pub(crate) enum GenerationConditionalRendererAttach {
    Attached(AttachedSession),
    StartIfAbsent(ConditionalStartPeerIdentity),
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AttachmentHandoffSeed {
    session_id: SessionId,
    token: AttachmentHandoffToken,
    expected_daemon_instance: DaemonInstanceId,
    /// Filled only after the exact Grid baseline is accepted. A pre-Grid cancellation seed keeps
    /// this absent because cancellation needs only id/token/instance; a public renderer authority
    /// is never constructed until the generation is known.
    expected_generation: Option<String>,
}

impl std::fmt::Debug for AttachmentHandoffSeed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AttachmentHandoffSeed")
            .finish_non_exhaustive()
    }
}

pub(crate) struct AttachmentHandoffFailure {
    pub(crate) source: DaemonClientError,
    pub(crate) pending_seed: Option<AttachmentHandoffSeed>,
}

impl std::fmt::Debug for AttachmentHandoffFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AttachmentHandoffFailure")
            .field("source", &self.source)
            .field("handoff_pending", &self.pending_seed.is_some())
            .finish()
    }
}

/// Opaque renderer handoff authority bound to the exact daemon process that installed its token.
/// Private fields prevent callers from mixing a token from daemon B with an identity from daemon A;
/// Debug intentionally reveals neither value.
pub struct AttachmentHandoffAuthority {
    core: std::sync::Arc<AttachmentHandoffAuthorityCore>,
}

/// Whether a renderer Claim may have crossed its writer publication boundary before cancellation.
/// This is shared by every clone of one authority, so a losing duplicate can never report a
/// compensation-safe cancellation while another renderer has begun publishing the Claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachmentHandoffClaimStatus {
    Unpublished,
    PossiblyApplied,
}

/// Exact cancellation failure annotated with the global Claim publication status. The authority
/// itself remains armed and owned by the caller for retry.
#[derive(Debug)]
pub struct AttachmentHandoffCancelError {
    claim_status: AttachmentHandoffClaimStatus,
    source: DaemonClientError,
}

impl AttachmentHandoffCancelError {
    pub fn claim_status(&self) -> AttachmentHandoffClaimStatus {
        self.claim_status
    }

    pub fn into_source(self) -> DaemonClientError {
        self.source
    }
}

impl std::fmt::Display for AttachmentHandoffCancelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "attachment handoff cancellation failed: {}",
            self.source
        )
    }
}

impl std::error::Error for AttachmentHandoffCancelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

struct AttachmentHandoffAuthorityCore {
    session_id: SessionId,
    token: AttachmentHandoffToken,
    expected_daemon_instance: DaemonInstanceId,
    /// Kernel-authenticated server PID captured from the reviewed Offer connection. Linux requires
    /// an exact match on the renderer's Claim connection; other supported Unix platforms expose no
    /// peer PID and retain `None` alongside the per-process daemon instance identity.
    expected_server_pid: Option<u32>,
    expected_generation: String,
    claim_admitted: std::sync::atomic::AtomicBool,
    state: std::sync::Mutex<AttachmentHandoffAuthorityState>,
    state_changed: std::sync::Condvar,
}

enum AttachmentHandoffAuthorityState {
    /// The original Offer connection stays live, preserving its exact active guard in addition to
    /// the pending token until the renderer proves Claim or cancellation is acknowledged.
    Pending(DaemonClient),
    /// The exact cancellation I/O owns the retained client outside the mutex. A concurrent exact
    /// Grid proof records `claim_proven` without waiting for socket I/O; proof wins when the worker
    /// returns because the Claim may have consumed the token before an idempotent Cancel ACK.
    CancelInFlight {
        claim_proven: bool,
    },
    Claimed,
    Cancelled,
}

impl AttachmentHandoffAuthority {
    pub(crate) fn from_offer(seed: AttachmentHandoffSeed, client: DaemonClient) -> Self {
        let expected_generation = seed
            .expected_generation
            .expect("renderer handoff authority requires an accepted exact Grid generation");
        let expected_server_pid = client.server_pid();
        Self {
            core: std::sync::Arc::new(AttachmentHandoffAuthorityCore {
                session_id: seed.session_id,
                token: seed.token,
                expected_daemon_instance: seed.expected_daemon_instance,
                expected_server_pid,
                expected_generation,
                claim_admitted: std::sync::atomic::AtomicBool::new(false),
                state: std::sync::Mutex::new(AttachmentHandoffAuthorityState::Pending(client)),
                state_changed: std::sync::Condvar::new(),
            }),
        }
    }

    pub fn token(&self) -> &AttachmentHandoffToken {
        &self.core.token
    }

    pub fn expected_daemon_instance(&self) -> &DaemonInstanceId {
        &self.core.expected_daemon_instance
    }

    /// Kernel-authenticated PID of the reviewed Offer peer where the platform exposes one (Linux).
    /// The value is deliberately omitted from Debug output and is useful only for exact Claim-peer
    /// comparison; it is not process-management authority.
    pub fn expected_server_pid(&self) -> Option<u32> {
        self.core.expected_server_pid
    }

    /// The exact daemon lifetime whose Grid completed the Offer-side attach. A renderer may retire
    /// this authority only after its Claim yields the same id and generation on the same daemon
    /// instance.
    pub fn expected_generation(&self) -> &str {
        &self.core.expected_generation
    }

    pub fn session_id(&self) -> &SessionId {
        &self.core.session_id
    }

    /// Record the conservative writer publication boundary before attempting to enqueue a Claim.
    /// The bit is sticky: even a local enqueue refusal cannot safely downgrade another clone that
    /// may concurrently be publishing the same one-shot token.
    pub fn mark_claim_admitted(&self) {
        self.core
            .claim_admitted
            .store(true, std::sync::atomic::Ordering::Release);
    }

    pub fn claim_status(&self) -> AttachmentHandoffClaimStatus {
        if self
            .core
            .claim_admitted
            .load(std::sync::atomic::Ordering::Acquire)
        {
            AttachmentHandoffClaimStatus::PossiblyApplied
        } else {
            AttachmentHandoffClaimStatus::Unpublished
        }
    }

    /// Exact Claim/Grid proof transfers ownership to the renderer. Dropping the original Offer
    /// connection after that proof is safe because Claim installed the renderer's ordinary guard
    /// while atomically retiring the pending token.
    pub fn mark_claimed(&self) {
        let mut state = self
            .core
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match &mut *state {
            AttachmentHandoffAuthorityState::Pending(_) => {
                *state = AttachmentHandoffAuthorityState::Claimed;
                self.core.state_changed.notify_all();
            }
            AttachmentHandoffAuthorityState::CancelInFlight { claim_proven } => {
                *claim_proven = true;
            }
            // A successful cancellation ACK is idempotent and cannot prove an already-admitted
            // Claim was unpublished. A later exact Grid therefore upgrades Cancelled to Claimed.
            AttachmentHandoffAuthorityState::Cancelled => {
                *state = AttachmentHandoffAuthorityState::Claimed;
                self.core.state_changed.notify_all();
            }
            AttachmentHandoffAuthorityState::Claimed => {}
        }
    }

    /// Cancel through the original, already-reviewed Offer connection and require an exact typed
    /// ACK. Failure retains the connection and authority for a later retry; it never falls back to
    /// same-path rediscovery.
    pub fn cancel(&self) -> Result<AttachmentHandoffClaimStatus, AttachmentHandoffCancelError> {
        let mut state = self
            .core
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            match &*state {
                AttachmentHandoffAuthorityState::Claimed
                | AttachmentHandoffAuthorityState::Cancelled => return Ok(self.claim_status()),
                AttachmentHandoffAuthorityState::CancelInFlight { .. } => {
                    state = self
                        .core
                        .state_changed
                        .wait(state)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    continue;
                }
                AttachmentHandoffAuthorityState::Pending(_) => {}
            }

            let AttachmentHandoffAuthorityState::Pending(mut client) = std::mem::replace(
                &mut *state,
                AttachmentHandoffAuthorityState::CancelInFlight {
                    claim_proven: false,
                },
            ) else {
                unreachable!("pending handoff state changed while its mutex was held");
            };
            drop(state);

            let result = client.cancel_attachment_handoff_exact(
                self.session_id(),
                self.token(),
                self.expected_daemon_instance(),
            );

            state = self
                .core
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let claim_proven = matches!(
                &*state,
                AttachmentHandoffAuthorityState::CancelInFlight { claim_proven: true }
            );
            if claim_proven {
                *state = AttachmentHandoffAuthorityState::Claimed;
                self.core.state_changed.notify_all();
                return Ok(AttachmentHandoffClaimStatus::PossiblyApplied);
            }
            debug_assert!(matches!(
                &*state,
                AttachmentHandoffAuthorityState::CancelInFlight {
                    claim_proven: false
                }
            ));
            match result {
                Ok(()) => {
                    *state = AttachmentHandoffAuthorityState::Cancelled;
                    self.core.state_changed.notify_all();
                    return Ok(self.claim_status());
                }
                Err(error) => {
                    *state = AttachmentHandoffAuthorityState::Pending(client);
                    self.core.state_changed.notify_all();
                    return Err(AttachmentHandoffCancelError {
                        claim_status: self.claim_status(),
                        source: error,
                    });
                }
            }
        }
    }
}

impl Clone for AttachmentHandoffAuthority {
    fn clone(&self) -> Self {
        Self {
            core: self.core.clone(),
        }
    }
}

impl PartialEq for AttachmentHandoffAuthority {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.core, &other.core)
    }
}

impl Eq for AttachmentHandoffAuthority {}

impl std::fmt::Debug for AttachmentHandoffAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AttachmentHandoffAuthority(<redacted>)")
    }
}

/// The result of a successful [`DaemonClient::kill_session`]: the named session is no longer in the
/// daemon's live session list. This is a "session is no longer live" confirmation, NOT a claim that
/// this client personally killed it — an already-absent session yields the same `Ok` (idempotent).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KilledSession {
    /// The session id that is confirmed absent from the daemon's live list.
    pub id: SessionId,
}

/// One atomic `ListSessions` reply. `ids` remains the compatibility authority for retained legacy
/// daemons; `sessions` carries additive generation identity when the running daemon supports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedSessions {
    pub ids: Vec<SessionId>,
    pub sessions: Vec<SessionListInfo>,
}

/// One strict, generation-bearing live-session snapshot from a protocol-v3 daemon. The map is
/// complete for the accompanying `ids` set; legacy/incomplete metadata is rejected rather than
/// interpreted as absence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerationMutationSnapshot {
    generations: BTreeMap<String, String>,
}

impl GenerationMutationSnapshot {
    pub fn generation_for(&self, session_id: &str) -> Option<&str> {
        self.generations.get(session_id).map(String::as_str)
    }

    pub fn session_count(&self) -> usize {
        self.generations.len()
    }

    /// Iterate the complete validated live `(session id, generation)` map. Values are borrowed so
    /// callers may derive read-only lifecycle cohorts without gaining mutation authority or
    /// rewriting the snapshot.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.generations
            .iter()
            .map(|(session_id, generation)| (session_id.as_str(), generation.as_str()))
    }
}

/// How many `ListSessions` confirmations `kill_session` will read before giving up. The daemon
/// removes a killed session synchronously, so the FIRST `Sessions` reply after `Kill` normally
/// already excludes it; the extra rounds only cover a daemon that interleaves an in-flight
/// `Sessions` snapshot taken before the kill landed. Bounded so a daemon that keeps reporting the
/// id can never wedge the caller — once the rounds are spent a typed protocol error is returned.
const KILL_CONFIRM_ROUNDS: usize = 4;

/// Maximum wall-clock time for one generation-conditional kill, including its capability probe,
/// Kill publication attempt, and absence confirmation. The release journal lease is 120 seconds;
/// keeping this per-target bound at 30 seconds leaves ample time for the caller to record the
/// outcome or renew before the lease can expire.
pub const GENERATION_KILL_DEADLINE_MS: u64 = 30_000;

/// Bound unsolicited events across BOTH the capability probe and confirmation phases. The
/// absolute deadline bounds slow/trickled input; this count independently bounds a daemon that can
/// keep the socket continuously readable with irrelevant events.
const GENERATION_KILL_MAX_UNRELATED_EVENTS: usize = 256;

/// Default read/write deadline. Generous enough for a local daemon to answer a snapshot, short
/// enough that a silent daemon fails fast instead of wedging the caller.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

struct ReplyBudget {
    during: &'static str,
    deadline: Instant,
    original_read_timeout: Option<Duration>,
    read_timeout_configuration_unavailable: bool,
    events: usize,
    bytes: usize,
}

impl ReplyBudget {
    fn with_deadline(
        during: &'static str,
        deadline: Instant,
        original_read_timeout: Option<Duration>,
    ) -> Self {
        Self {
            during,
            deadline,
            original_read_timeout,
            read_timeout_configuration_unavailable: false,
            events: 0,
            bytes: 0,
        }
    }

    fn remaining(&self) -> Result<Duration, DaemonClientError> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(DaemonClientError::Timeout {
                during: self.during,
            })
    }

    fn read_timeout(&self) -> Result<Duration, DaemonClientError> {
        let remaining = self.remaining()?;
        Ok(self
            .original_read_timeout
            .map_or(remaining, |timeout| timeout.min(remaining)))
    }

    fn observe(&mut self, bytes: usize) -> Result<(), DaemonClientError> {
        self.events = self.events.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
        if self.events > MAX_REPLY_EVENTS_PER_OPERATION
            || self.bytes > MAX_REPLY_BYTES_PER_OPERATION
        {
            return Err(DaemonClientError::ReplyBudgetExceeded {
                during: self.during,
            });
        }
        Ok(())
    }
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    limit: usize,
    overflowed: bool,
}

impl BoundedJsonWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(8 * 1024)),
            limit,
            overflowed: false,
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(new_len) = self.bytes.len().checked_add(bytes.len()) else {
            self.overflowed = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bounded JSON frame length overflow",
            ));
        };
        if new_len > self.limit {
            self.overflowed = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bounded JSON frame exceeds limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Per-target bounds captured before a conditional Kill begins. Socket timeouts are continually
/// shortened to the remaining wall-clock budget so a peer that trickles bytes cannot restart the
/// deadline on every read.
struct GenerationKillBudget {
    deadline: Instant,
    original_read_timeout: Option<Duration>,
    original_write_timeout: Option<Duration>,
    unrelated_events_remaining: Arc<AtomicUsize>,
}

impl GenerationKillBudget {
    fn new(
        original_read_timeout: Option<Duration>,
        original_write_timeout: Option<Duration>,
    ) -> Self {
        Self::with_deadline(
            original_read_timeout,
            original_write_timeout,
            Instant::now() + Duration::from_millis(GENERATION_KILL_DEADLINE_MS),
        )
    }

    fn with_deadline(
        original_read_timeout: Option<Duration>,
        original_write_timeout: Option<Duration>,
        deadline: Instant,
    ) -> Self {
        Self::with_deadline_and_counter(
            original_read_timeout,
            original_write_timeout,
            deadline,
            Arc::new(AtomicUsize::new(GENERATION_KILL_MAX_UNRELATED_EVENTS)),
        )
    }

    fn with_deadline_and_counter(
        original_read_timeout: Option<Duration>,
        original_write_timeout: Option<Duration>,
        deadline: Instant,
        unrelated_events_remaining: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            deadline,
            original_read_timeout,
            original_write_timeout,
            unrelated_events_remaining,
        }
    }

    fn remaining(&self, during: &'static str) -> Result<Duration, DaemonClientError> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(DaemonClientError::Timeout { during })
    }

    fn read_timeout(&self, during: &'static str) -> Result<Duration, DaemonClientError> {
        let remaining = self.remaining(during)?;
        Ok(self
            .original_read_timeout
            .map_or(remaining, |timeout| timeout.min(remaining)))
    }

    fn write_timeout(&self, during: &'static str) -> Result<Duration, DaemonClientError> {
        let remaining = self.remaining(during)?;
        Ok(self
            .original_write_timeout
            .map_or(remaining, |timeout| timeout.min(remaining)))
    }

    fn tolerate_unrelated(&mut self, during: &'static str) -> Result<(), DaemonClientError> {
        self.remaining(during)?;
        if self
            .unrelated_events_remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                remaining.checked_sub(1)
            })
            .is_err()
        {
            return Err(DaemonClientError::Protocol {
                detail: format!(
                    "generation-conditional operation exceeded its {GENERATION_KILL_MAX_UNRELATED_EVENTS}-event unrelated reply budget while {during}"
                ),
            });
        }
        Ok(())
    }
}

/// Tracks whether a deadline-aware write crossed its first socket-write attempt. This keeps the
/// Kill publication classification exact even if configuring its initial timeout fails.
struct DeadlineWriteFailure {
    source: DaemonClientError,
    write_attempted: bool,
}

/// A synchronous, single-connection client to a running `pty-daemon`. Owns one `UnixStream`; the
/// socket is closed when this value is dropped. Not `Clone` — one connection, one owner.
pub struct DaemonClient {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
    socket_path: PathBuf,
    connect_timeout: Duration,
    /// Production conditional-start clients capture this before their initial connect so connect,
    /// capability proof, mutation, acknowledgement, attach, and cancellation share one deadline.
    operation_deadline: Option<Instant>,
    /// All phases under `operation_deadline` share one unsolicited-event allowance. Re-entering a
    /// socket timeout scope must not mint another allowance for the same mutation.
    operation_unrelated_events_remaining: Option<Arc<AtomicUsize>>,
    /// Kernel-authenticated server PID on Linux. Other supported Unix platforms expose only UID.
    server_pid: Option<u32>,
    /// Exact daemon-process identity learned from a typed DaemonInfo reply on this socket. It is
    /// sticky: a conflicting later reply is a protocol failure, never a silent authority rebind.
    daemon_instance_id: Option<DaemonInstanceId>,
    /// Checked connection-local Attach route ids. Never reused; exhaustion fails before wire.
    next_output_generation: u64,
}

impl DaemonClient {
    pub(crate) fn mint_start_operation_token(
    ) -> Result<SessionStartOperationToken, DaemonClientError> {
        uuid::Uuid::new_v4()
            .simple()
            .to_string()
            .parse()
            .map_err(|error| DaemonClientError::Protocol {
                detail: format!("could not construct conditional start token: {error}"),
            })
    }
    /// Connect to the daemon at `socket_path` with the default timeout.
    ///
    /// A refused/missing socket returns [`DaemonClientError::DaemonUnavailable`] — the daemon isn't
    /// there — so a caller can distinguish "no daemon" from "daemon said no".
    pub fn connect(socket_path: impl AsRef<Path>) -> Result<Self, DaemonClientError> {
        Self::connect_with_timeout(socket_path, DEFAULT_TIMEOUT)
    }

    /// Connect with an explicit read/write deadline. Splits the connected stream into a buffered
    /// reader and a writer half (cloned fds onto the same socket) so reads and writes don't share a
    /// cursor; both carry the same timeout.
    pub fn connect_with_timeout(
        socket_path: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Self, DaemonClientError> {
        let path = socket_path.as_ref();
        let stream = connect_unix_with_timeout(path, timeout).map_err(|source| {
            DaemonClientError::DaemonUnavailable {
                path: path.display().to_string(),
                source,
            }
        })?;
        Self::from_connected_stream(path, stream, timeout, None)
    }

    /// Start a generation-conditional operation's absolute budget before the initial AF_UNIX
    /// connect. This is the production constructor for StartSession mutation flows.
    pub(crate) fn connect_for_generation_mutation(
        socket_path: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Self, DaemonClientError> {
        let deadline = Instant::now() + Duration::from_millis(GENERATION_KILL_DEADLINE_MS);
        Self::connect_for_generation_mutation_before(socket_path, timeout, deadline)
    }

    /// Join a caller-owned generation-mutation budget. Retry coordinators pass the same absolute
    /// deadline to every fresh connection so no attempt silently acquires another 30-second window.
    pub(crate) fn connect_for_generation_mutation_before(
        socket_path: impl AsRef<Path>,
        timeout: Duration,
        deadline: Instant,
    ) -> Result<Self, DaemonClientError> {
        let path = socket_path.as_ref();
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(DaemonClientError::Timeout {
                during: "connecting for generation mutation",
            })?;
        let connect_timeout = timeout.min(remaining);
        let stream = connect_unix_with_timeout(path, connect_timeout).map_err(|source| {
            DaemonClientError::DaemonUnavailable {
                path: path.display().to_string(),
                source,
            }
        })?;
        if Instant::now() >= deadline {
            return Err(DaemonClientError::Timeout {
                during: "connecting for generation mutation",
            });
        }
        Self::from_connected_stream(path, stream, timeout, Some(deadline))
    }

    fn from_connected_stream(
        path: &Path,
        stream: UnixStream,
        timeout: Duration,
        operation_deadline: Option<Instant>,
    ) -> Result<Self, DaemonClientError> {
        verify_connected_server_identity(path, effective_uid(), connected_server_uid(&stream))?;
        #[cfg(target_os = "linux")]
        let server_pid = Some(
            connected_server_credentials(&stream)
                .map_err(|error| DaemonClientError::UntrustedDaemon {
                    path: path.display().to_string(),
                    expected_uid: effective_uid(),
                    observed_uid: Some(effective_uid()),
                    detail: format!("kernel peer PID was unavailable: {error}"),
                })?
                .pid as u32,
        );
        #[cfg(not(target_os = "linux"))]
        let server_pid = None;
        // A silent daemon must not hang us: bound every read and write by the deadline.
        stream
            .set_read_timeout(Some(timeout))
            .map_err(DaemonClientError::Io)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(DaemonClientError::Io)?;
        // A second handle on the SAME socket for the buffered reader, so writing a request and then
        // reading replies never trips over a shared stream position.
        let reader_stream = stream.try_clone().map_err(DaemonClientError::Io)?;
        Ok(DaemonClient {
            writer: stream,
            reader: BufReader::new(reader_stream),
            socket_path: path.to_path_buf(),
            connect_timeout: timeout,
            operation_deadline,
            operation_unrelated_events_remaining: operation_deadline
                .map(|_| Arc::new(AtomicUsize::new(GENERATION_KILL_MAX_UNRELATED_EVENTS))),
            server_pid,
            daemon_instance_id: None,
            next_output_generation: 0,
        })
    }

    fn allocate_output_generation(&mut self) -> Result<u64, DaemonClientError> {
        let next = self.next_output_generation.checked_add(1).ok_or_else(|| {
            DaemonClientError::Protocol {
                detail: "connection-local Attach output generation exhausted".into(),
            }
        })?;
        self.next_output_generation = next;
        Ok(next)
    }

    /// Return the kernel-authenticated PID at the connected server end when the platform exposes it.
    /// This lets a service owner bind protocol readiness to the exact PID its manager reports.
    pub fn server_pid(&self) -> Option<u32> {
        self.server_pid
    }

    pub fn daemon_instance_id(&self) -> Option<&DaemonInstanceId> {
        self.daemon_instance_id.as_ref()
    }

    /// Capture the exact mutation-capable daemon identity on this already-reviewed connection.
    /// This is read-only; callers use the opaque result to bind a later fresh-daemon `Absent`
    /// conditional Start to the same daemon process.
    pub fn conditional_start_peer_identity(
        &mut self,
    ) -> Result<ConditionalStartPeerIdentity, DaemonClientError> {
        let (daemon_instance_id, child_environment) =
            self.require_start_session_protocol_proof()?;
        Ok(ConditionalStartPeerIdentity {
            daemon_instance_id,
            server_pid: self.server_pid,
            child_environment,
        })
    }

    /// Same-socket peer proof for a typed conditional-Attach Missing result. It inherits the
    /// connect-time absolute deadline and shared unrelated-event allowance from the probe rather
    /// than opening a fresh default-timeout phase.
    pub(crate) fn conditional_start_peer_identity_before_current_deadline(
        &mut self,
    ) -> Result<ConditionalStartPeerIdentity, DaemonClientError> {
        let mut budget = self.generation_kill_budget()?;
        let result = self
            .require_start_session_protocol_proof_before(&mut budget)
            .map(
                |(daemon_instance_id, child_environment)| ConditionalStartPeerIdentity {
                    daemon_instance_id,
                    server_pid: self.server_pid,
                    child_environment,
                },
            );
        let restored = self.restore_timeouts(&budget);
        match (result, restored) {
            (Ok(peer), Ok(())) => Ok(peer),
            (_, Err(error)) => {
                self.abort_connection();
                Err(error)
            }
            (Err(error), Ok(())) => Err(error),
        }
    }

    /// Read-only same-socket proof that a later fresh-daemon `Absent` start is still connected to
    /// the exact readiness peer. Callers run this before any durable Session/endpoint mutation.
    pub(crate) fn require_conditional_start_peer_identity(
        &mut self,
        expected: &ConditionalStartPeerIdentity,
    ) -> Result<(), DaemonClientError> {
        let mut budget = self.generation_kill_budget()?;
        let result = self
            .require_start_session_protocol_before(&mut budget)
            .and_then(|instance| self.require_conditional_start_peer(&instance, expected));
        let restored = self.restore_timeouts(&budget);
        match (result, restored) {
            (Ok(()), Ok(())) => Ok(()),
            (Ok(()), Err(error)) | (Err(error), _) => Err(error),
        }
    }

    fn require_conditional_start_peer(
        &self,
        observed_instance: &DaemonInstanceId,
        expected: &ConditionalStartPeerIdentity,
    ) -> Result<(), DaemonClientError> {
        if observed_instance != &expected.daemon_instance_id {
            return Err(DaemonClientError::Protocol {
                detail: "fresh-daemon conditional Start peer identity changed".into(),
            });
        }
        #[cfg(target_os = "linux")]
        if self.server_pid != expected.server_pid || self.server_pid.is_none() {
            return Err(DaemonClientError::Protocol {
                detail: "fresh-daemon conditional Start kernel peer PID changed".into(),
            });
        }
        Ok(())
    }

    /// End the initial conditional-start budget after the service has durably finalized (or
    /// declined) the resulting row. Any retained authority then receives its own fresh bounded
    /// cancellation budget instead of inheriting an already-expired start deadline forever.
    pub(crate) fn finish_generation_mutation(&mut self) {
        self.operation_deadline = None;
        self.operation_unrelated_events_remaining = None;
    }

    /// Immediately close both halves of this reviewed transport. Before an Offer authority escapes
    /// the service, EOF is the frame-safe retirement path after a partial write, malformed reply,
    /// timeout, or timeout-restoration failure; Cancel bytes must never be appended to a socket whose
    /// request boundary is uncertain.
    pub(crate) fn abort_connection(&self) {
        let _ = self.writer.shutdown(Shutdown::Both);
    }

    fn bind_daemon_instance_id(
        &mut self,
        observed: Option<DaemonInstanceId>,
    ) -> Result<Option<DaemonInstanceId>, DaemonClientError> {
        if let (Some(expected), Some(observed)) =
            (self.daemon_instance_id.as_ref(), observed.as_ref())
        {
            if expected != observed {
                return Err(DaemonClientError::Protocol {
                    detail: "daemon instance identity changed on one connected socket".into(),
                });
            }
        }
        if self.daemon_instance_id.is_none() {
            self.daemon_instance_id = observed.clone();
        }
        Ok(observed)
    }

    /// Serialize and bound one request without writing any bytes. Keeping framing separate from
    /// the socket write gives compensating lifecycle code a precise Kill publication boundary.
    fn encode_request(req: &ClientRequest) -> Result<Vec<u8>, DaemonClientError> {
        // Stream serde into a capped writer. `to_string` would first allocate the complete hostile
        // request and only then notice it exceeded the wire limit.
        let mut encoded = BoundedJsonWriter::new(MAX_LINE_BYTES.saturating_sub(1));
        if let Err(error) = serde_json::to_writer(&mut encoded, req) {
            if encoded.overflowed {
                return Err(DaemonClientError::LineTooLong {
                    direction: Direction::Outbound,
                    limit: MAX_LINE_BYTES,
                });
            }
            return Err(DaemonClientError::Protocol {
                detail: error.to_string(),
            });
        }
        encoded.bytes.push(b'\n');
        Ok(encoded.bytes)
    }

    /// Attempt one already-framed request write. Once this is called, a failure cannot prove that
    /// the peer observed none of the frame.
    fn write_encoded_request(&mut self, line: &[u8]) -> Result<(), DaemonClientError> {
        self.writer
            .write_all(line)
            .map_err(|e| classify_io(e, "writing request"))?;
        self.writer
            .flush()
            .map_err(|e| classify_io(e, "flushing request"))
    }

    /// Serialize a request and write it as one newline-delimited JSON line.
    fn send(&mut self, req: &ClientRequest) -> Result<(), DaemonClientError> {
        let line = Self::encode_request(req)?;
        self.write_encoded_request(&line)
    }

    fn reply_budget(&self, during: &'static str) -> Result<ReplyBudget, DaemonClientError> {
        let original_read_timeout = self
            .reader
            .get_ref()
            .read_timeout()
            .map_err(DaemonClientError::Io)?;
        let local_deadline = Instant::now()
            .checked_add(self.connect_timeout)
            .ok_or(DaemonClientError::Timeout { during })?;
        let deadline = self
            .operation_deadline
            .map_or(local_deadline, |deadline| deadline.min(local_deadline));
        let budget = ReplyBudget::with_deadline(during, deadline, original_read_timeout);
        budget.remaining()?;
        Ok(budget)
    }

    fn generation_kill_budget(&self) -> Result<GenerationKillBudget, DaemonClientError> {
        let original_read_timeout = self
            .reader
            .get_ref()
            .read_timeout()
            .map_err(DaemonClientError::Io)?;
        let original_write_timeout = self.writer.write_timeout().map_err(DaemonClientError::Io)?;
        Ok(match self.operation_deadline {
            Some(deadline) => GenerationKillBudget::with_deadline_and_counter(
                original_read_timeout,
                original_write_timeout,
                deadline,
                self.operation_unrelated_events_remaining
                    .clone()
                    .unwrap_or_else(|| {
                        Arc::new(AtomicUsize::new(GENERATION_KILL_MAX_UNRELATED_EVENTS))
                    }),
            ),
            None => GenerationKillBudget::new(original_read_timeout, original_write_timeout),
        })
    }

    fn restore_timeouts(&self, budget: &GenerationKillBudget) -> Result<(), DaemonClientError> {
        self.reader
            .get_ref()
            .set_read_timeout(budget.original_read_timeout)
            .map_err(DaemonClientError::Io)?;
        self.writer
            .set_write_timeout(budget.original_write_timeout)
            .map_err(DaemonClientError::Io)
    }

    /// Open a fresh reviewed connection to the same daemon instance within the caller's existing
    /// absolute/event budget. Cross-platform identity is the daemon's 128-bit process nonce;
    /// Linux additionally requires the kernel-authenticated server PID to remain exact.
    fn reconnect_same_daemon_before(
        &self,
        expected_instance: &DaemonInstanceId,
        budget: &mut GenerationKillBudget,
    ) -> Result<DaemonClient, DaemonClientError> {
        let remaining = budget.remaining("reconnecting for conditional start recovery")?;
        let timeout = self.connect_timeout.min(remaining);
        let stream = connect_unix_with_timeout(&self.socket_path, timeout).map_err(|source| {
            DaemonClientError::DaemonUnavailable {
                path: self.socket_path.display().to_string(),
                source,
            }
        })?;
        budget.remaining("reconnecting for conditional start recovery")?;
        let mut replacement = DaemonClient::from_connected_stream(
            &self.socket_path,
            stream,
            self.connect_timeout,
            Some(budget.deadline),
        )?;
        replacement.operation_unrelated_events_remaining =
            Some(Arc::clone(&budget.unrelated_events_remaining));
        #[cfg(target_os = "linux")]
        if replacement.server_pid != self.server_pid {
            return Err(DaemonClientError::Protocol {
                detail: "conditional start recovery connected to a different daemon PID".into(),
            });
        }
        let observed_instance = replacement.require_start_session_protocol_before(budget)?;
        if &observed_instance != expected_instance {
            return Err(DaemonClientError::Protocol {
                detail: "conditional start recovery connected to a different daemon instance"
                    .into(),
            });
        }
        Ok(replacement)
    }

    /// Write a framed request while continually shrinking the socket timeout to an absolute
    /// operation deadline. The returned flag distinguishes failures before the first `write` call
    /// from failures after a frame may have partially crossed the socket boundary.
    fn write_encoded_request_before(
        &mut self,
        line: &[u8],
        budget: &GenerationKillBudget,
        during: &'static str,
    ) -> Result<(), DeadlineWriteFailure> {
        let mut remaining = line;
        let mut write_attempted = false;
        while !remaining.is_empty() {
            let timeout = budget
                .write_timeout(during)
                .map_err(|source| DeadlineWriteFailure {
                    source,
                    write_attempted,
                })?;
            self.writer
                .set_write_timeout(Some(timeout))
                .map_err(|error| DeadlineWriteFailure {
                    source: DaemonClientError::Io(error),
                    write_attempted,
                })?;
            write_attempted = true;
            let written = self
                .writer
                .write(remaining)
                .map_err(|error| DeadlineWriteFailure {
                    source: classify_io(error, during),
                    write_attempted,
                })?;
            if written == 0 {
                return Err(DeadlineWriteFailure {
                    source: DaemonClientError::Io(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "failed to write request before operation deadline",
                    )),
                    write_attempted,
                });
            }
            remaining = &remaining[written..];
        }

        let timeout = budget
            .write_timeout(during)
            .map_err(|source| DeadlineWriteFailure {
                source,
                write_attempted,
            })?;
        self.writer
            .set_write_timeout(Some(timeout))
            .map_err(|error| DeadlineWriteFailure {
                source: DaemonClientError::Io(error),
                write_attempted,
            })?;
        self.writer.flush().map_err(|error| DeadlineWriteFailure {
            source: classify_io(error, during),
            write_attempted,
        })?;
        budget
            .remaining(during)
            .map(|_| ())
            .map_err(|source| DeadlineWriteFailure {
                source,
                write_attempted,
            })
    }

    fn send_before(
        &mut self,
        req: &ClientRequest,
        budget: &GenerationKillBudget,
        during: &'static str,
    ) -> Result<(), DaemonClientError> {
        let line = Self::encode_request(req)?;
        self.write_encoded_request_before(&line, budget, during)
            .map_err(|failure| failure.source)
    }

    fn decode_event_buffer(buf: &[u8]) -> Result<Option<ShellEvent>, DaemonClientError> {
        let line = std::str::from_utf8(buf)
            .map_err(|error| DaemonClientError::Protocol {
                detail: error.to_string(),
            })?
            .trim();
        if line.is_empty() {
            return Ok(Some(ShellEvent::Other));
        }
        ShellEvent::from_line(line)
            .map(Some)
            .map_err(|error| DaemonClientError::Protocol {
                detail: error.to_string(),
            })
    }

    /// Deadline-aware equivalent of [`Self::read_event`]. `BufRead::read_until` applies one static
    /// socket timeout to every underlying read, so a byte trickle can repeatedly restart it. This
    /// loop uses `fill_buf` one read at a time and shrinks the timeout whenever the absolute time
    /// remaining becomes tighter than the connection's original bound.
    fn read_event_before(
        &mut self,
        budget: &GenerationKillBudget,
        during: &'static str,
    ) -> Result<Option<ShellEvent>, DaemonClientError> {
        let mut buf = Vec::new();
        loop {
            let timeout = budget.read_timeout(during)?;
            // `fill_buf` performs a kernel read only when its internal buffer is empty. Avoid
            // rewriting the socket option while draining a burst that is already in userspace, or
            // while the original timeout is already at least as strict. This also avoids a
            // redundant setsockopt after a peer has closed with buffered replies still readable.
            // The budget check above still executes for every decoded event/line.
            if self.reader.buffer().is_empty()
                && budget
                    .original_read_timeout
                    .is_none_or(|original| timeout < original)
            {
                self.reader
                    .get_ref()
                    .set_read_timeout(Some(timeout))
                    .map_err(DaemonClientError::Io)?;
            }

            let (consumed, terminated, eof) = {
                let available = self
                    .reader
                    .fill_buf()
                    .map_err(|error| classify_io(error, during))?;
                if available.is_empty() {
                    (0, false, true)
                } else {
                    let capacity = (MAX_LINE_BYTES + 1).saturating_sub(buf.len());
                    let newline_len = available
                        .iter()
                        .position(|byte| *byte == b'\n')
                        .map(|index| index + 1);
                    let consumed = newline_len.unwrap_or(available.len()).min(capacity);
                    buf.extend_from_slice(&available[..consumed]);
                    (consumed, newline_len == Some(consumed), false)
                }
            };
            self.reader.consume(consumed);

            if eof {
                if buf.is_empty() {
                    return Ok(None);
                }
                break;
            }
            if buf.len() > MAX_LINE_BYTES {
                return Err(DaemonClientError::LineTooLong {
                    direction: Direction::Inbound,
                    limit: MAX_LINE_BYTES,
                });
            }
            if terminated {
                break;
            }
        }

        budget.remaining(during)?;
        let event = Self::decode_event_buffer(&buf)?;
        budget.remaining(during)?;
        Ok(event)
    }

    /// Read ONE newline-delimited reply line, bounded to [`MAX_LINE_BYTES`], and decode it into a
    /// [`ShellEvent`]. The cap is enforced by reading at most `MAX_LINE_BYTES + 1` bytes: if that
    /// many arrive, the line is over the limit even when the last byte is a newline, and we stop.
    /// Returns `Ok(None)` on a clean EOF (connection closed with no partial line).
    fn read_event(
        &mut self,
        during: &'static str,
        budget: &mut ReplyBudget,
    ) -> Result<Option<ShellEvent>, DaemonClientError> {
        let result = self.read_event_with_reply_budget(during, budget);
        let restored = if budget.read_timeout_configuration_unavailable {
            Ok(())
        } else {
            self.reader
                .get_ref()
                .set_read_timeout(budget.original_read_timeout)
                .map_err(DaemonClientError::Io)
        };
        match (result, restored) {
            (Ok(event), Ok(())) => Ok(event),
            (Err(error), Ok(())) => Err(error),
            (result, Err(DaemonClientError::Io(error)))
                if cfg!(target_os = "macos")
                    && error.kind() == std::io::ErrorKind::InvalidInput =>
            {
                // Darwin rejects SO_RCVTIMEO changes with EINVAL after the peer closes, even while
                // already-queued reply bytes remain readable. Preserve the complete decoded result
                // and drain only those queued bytes/EOF; the absolute deadline is still checked on
                // every loop and no later operation can write successfully to the closed peer.
                budget.read_timeout_configuration_unavailable = true;
                result
            }
            (_, Err(error)) => {
                self.abort_connection();
                Err(error)
            }
        }
    }

    fn read_event_with_reply_budget(
        &mut self,
        during: &'static str,
        budget: &mut ReplyBudget,
    ) -> Result<Option<ShellEvent>, DaemonClientError> {
        let mut buf = Vec::new();
        loop {
            let timeout = budget.read_timeout()?;
            if !budget.read_timeout_configuration_unavailable
                && self.reader.buffer().is_empty()
                && budget
                    .original_read_timeout
                    .is_none_or(|original| timeout < original)
            {
                let configured = self.reader.get_ref().set_read_timeout(Some(timeout));
                if let Err(error) = configured {
                    if cfg!(target_os = "macos") && error.kind() == std::io::ErrorKind::InvalidInput
                    {
                        budget.read_timeout_configuration_unavailable = true;
                    } else {
                        return Err(DaemonClientError::Io(error));
                    }
                }
            }

            let (consumed, terminated, eof) = {
                let available = match self.reader.fill_buf() {
                    Ok(available) => available,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(classify_io(error, during)),
                };
                if available.is_empty() {
                    (0, false, true)
                } else {
                    let capacity = (MAX_LINE_BYTES + 1).saturating_sub(buf.len());
                    let newline_len = available
                        .iter()
                        .position(|byte| *byte == b'\n')
                        .map(|index| index + 1);
                    let consumed = newline_len.unwrap_or(available.len()).min(capacity);
                    buf.extend_from_slice(&available[..consumed]);
                    (consumed, newline_len == Some(consumed), false)
                }
            };
            self.reader.consume(consumed);

            if eof {
                if buf.is_empty() {
                    budget.remaining()?;
                    return Ok(None);
                }
                break;
            }
            if buf.len() > MAX_LINE_BYTES {
                return Err(DaemonClientError::LineTooLong {
                    direction: Direction::Inbound,
                    limit: MAX_LINE_BYTES,
                });
            }
            if terminated {
                break;
            }
        }

        budget.remaining()?;
        budget.observe(buf.len())?;
        let event = Self::decode_event_buffer(&buf)?;
        budget.remaining()?;
        Ok(event)
    }

    /// Non-mutating identity probe used before reusing a retained daemon.
    pub fn daemon_info(&mut self) -> Result<(u32, String), DaemonClientError> {
        let (protocol_version, build_version, _, _, _, _, _, _, _, _) =
            self.daemon_capabilities()?;
        Ok((protocol_version, build_version))
    }

    /// Full additive daemon capabilities. Retained daemons decode omitted booleans as false.
    pub fn daemon_capabilities(
        &mut self,
    ) -> Result<
        (
            u32,
            String,
            bool,
            bool,
            bool,
            bool,
            bool,
            bool,
            bool,
            Option<DaemonInstanceId>,
        ),
        DaemonClientError,
    > {
        let mut budget = self.reply_budget("reading daemon_info reply")?;
        self.send(&ClientRequest::DaemonInfo)?;
        loop {
            match self.read_event("reading daemon_info reply", &mut budget)? {
                Some(ShellEvent::DaemonInfo {
                    protocol_version,
                    build_version,
                    daemon_instance_id,
                    output_generation_echo,
                    child_environment,
                    generation_conditional_mutations,
                    attachment_aware_conditional_kill,
                    generation_conditional_start,
                    start_operation_ledger,
                    generation_conditional_attach,
                }) => {
                    let daemon_instance_id = self.bind_daemon_instance_id(daemon_instance_id)?;
                    return Ok((
                        protocol_version,
                        build_version,
                        output_generation_echo,
                        child_environment,
                        generation_conditional_mutations,
                        attachment_aware_conditional_kill,
                        generation_conditional_start,
                        start_operation_ledger,
                        generation_conditional_attach,
                        daemon_instance_id,
                    ));
                }
                Some(ShellEvent::Error { message }) => {
                    return Err(DaemonClientError::DaemonError { message })
                }
                Some(_) => continue,
                None => {
                    return Err(DaemonClientError::UnexpectedEof {
                        during: "reading daemon_info reply",
                    })
                }
            }
        }
    }

    fn daemon_capabilities_before(
        &mut self,
        budget: &mut GenerationKillBudget,
    ) -> Result<
        (
            u32,
            String,
            bool,
            bool,
            bool,
            bool,
            bool,
            bool,
            bool,
            Option<DaemonInstanceId>,
        ),
        DaemonClientError,
    > {
        self.send_before(
            &ClientRequest::DaemonInfo,
            budget,
            "publishing generation mutation capability probe",
        )?;
        loop {
            match self.read_event_before(budget, "reading generation mutation capability reply")? {
                Some(ShellEvent::DaemonInfo {
                    protocol_version,
                    build_version,
                    daemon_instance_id,
                    output_generation_echo,
                    child_environment,
                    generation_conditional_mutations,
                    attachment_aware_conditional_kill,
                    generation_conditional_start,
                    start_operation_ledger,
                    generation_conditional_attach,
                }) => {
                    let daemon_instance_id = self.bind_daemon_instance_id(daemon_instance_id)?;
                    return Ok((
                        protocol_version,
                        build_version,
                        output_generation_echo,
                        child_environment,
                        generation_conditional_mutations,
                        attachment_aware_conditional_kill,
                        generation_conditional_start,
                        start_operation_ledger,
                        generation_conditional_attach,
                        daemon_instance_id,
                    ));
                }
                Some(ShellEvent::Error { message }) => {
                    return Err(DaemonClientError::DaemonError { message })
                }
                Some(_) => {
                    budget.tolerate_unrelated("reading generation mutation capability reply")?
                }
                None => {
                    return Err(DaemonClientError::UnexpectedEof {
                        during: "reading generation mutation capability reply",
                    })
                }
            }
        }
    }

    /// Require exact protocol v3 plus generation-conditional mutation capability before any
    /// `StartSession` is sent. Retained/partial daemons remain attach/read-only; their historical
    /// start semantics can reap unrelated exited snapshots, and a daemon that cannot CAS later
    /// lifecycle mutations cannot safely own a newly created session for this client.
    pub fn require_start_session_protocol(&mut self) -> Result<(), DaemonClientError> {
        self.require_start_session_protocol_proof().map(|_| ())
    }

    fn require_start_session_protocol_proof(
        &mut self,
    ) -> Result<(DaemonInstanceId, bool), DaemonClientError> {
        let required = maestro_protocol::DAEMON_PROTOCOL_VERSION;
        match self.daemon_capabilities() {
            Ok((
                observed,
                _,
                true,
                child_environment,
                true,
                true,
                true,
                true,
                true,
                Some(instance),
            )) if observed == required => Ok((instance, child_environment)),
            Ok((observed, _, _, _, _, _, _, _, _, _)) => {
                Err(DaemonClientError::MutationProtocolUnsupported {
                    required,
                    observed: Some(observed),
                })
            }
            Err(_) => Err(DaemonClientError::MutationProtocolUnsupported {
                required,
                observed: None,
            }),
        }
    }

    fn require_start_session_protocol_before(
        &mut self,
        budget: &mut GenerationKillBudget,
    ) -> Result<DaemonInstanceId, DaemonClientError> {
        self.require_start_session_protocol_proof_before(budget)
            .map(|(instance, _)| instance)
    }

    fn require_start_session_protocol_proof_before(
        &mut self,
        budget: &mut GenerationKillBudget,
    ) -> Result<(DaemonInstanceId, bool), DaemonClientError> {
        let required = maestro_protocol::DAEMON_PROTOCOL_VERSION;
        match self.daemon_capabilities_before(budget)? {
            (
                observed,
                _,
                true,
                child_environment,
                true,
                true,
                true,
                true,
                true,
                Some(instance),
            ) if observed == required => Ok((instance, child_environment)),
            (observed, _, _, _, _, _, _, _, _, _) => {
                Err(DaemonClientError::MutationProtocolUnsupported {
                    required,
                    observed: Some(observed),
                })
            }
        }
    }

    /// Require exact protocol-v3 generation-conditional mutation authority on this same socket.
    /// A retained v1/v2 daemon remains attach/read-only; callers must never retry with an id-only
    /// Write/Resize/Kill after this returns an error.
    pub fn require_generation_conditional_mutations(&mut self) -> Result<(), DaemonClientError> {
        let required = maestro_protocol::DAEMON_PROTOCOL_VERSION;
        match self.daemon_capabilities() {
            Ok((observed, _, _, _, true, true, _, _, _, Some(_))) if observed == required => Ok(()),
            Ok((observed, _, _, _, _, _, _, _, _, _)) => {
                Err(DaemonClientError::MutationProtocolUnsupported {
                    required,
                    observed: Some(observed),
                })
            }
            Err(_) => Err(DaemonClientError::MutationProtocolUnsupported {
                required,
                observed: None,
            }),
        }
    }

    fn require_generation_conditional_mutations_before(
        &mut self,
        budget: &mut GenerationKillBudget,
    ) -> Result<(), DaemonClientError> {
        let required = maestro_protocol::DAEMON_PROTOCOL_VERSION;
        match self.daemon_capabilities_before(budget)? {
            (observed, _, _, _, true, true, _, _, _, Some(_)) if observed == required => Ok(()),
            (observed, _, _, _, _, _, _, _, _, _) => {
                Err(DaemonClientError::MutationProtocolUnsupported {
                    required,
                    observed: Some(observed),
                })
            }
        }
    }

    /// Prove this exact reviewed socket can refuse a mismatched retained lifetime before guard/Grid.
    fn require_generation_conditional_attach_before(
        &mut self,
        budget: &mut GenerationKillBudget,
    ) -> Result<DaemonInstanceId, DaemonClientError> {
        let required = maestro_protocol::DAEMON_PROTOCOL_VERSION;
        match self.daemon_capabilities_before(budget)? {
            (observed, _, true, _, true, true, _, _, true, Some(instance))
                if observed == required =>
            {
                Ok(instance)
            }
            (observed, _, _, _, _, _, _, _, _, _) => {
                Err(DaemonClientError::MutationProtocolUnsupported {
                    required,
                    observed: Some(observed),
                })
            }
        }
    }

    fn strict_generation_snapshot(
        ids: Vec<SessionId>,
        sessions: Vec<SessionListInfo>,
    ) -> Result<GenerationMutationSnapshot, DaemonClientError> {
        let mut live_ids = BTreeSet::new();
        for id in ids {
            crate::ids::validate_id(&id.0).map_err(|error| DaemonClientError::Protocol {
                detail: format!("invalid session id in strict daemon snapshot: {error}"),
            })?;
            if !live_ids.insert(id.0.clone()) {
                return Err(DaemonClientError::Protocol {
                    detail: format!("strict daemon snapshot contains duplicate id {:?}", id.0),
                });
            }
        }

        let mut generations = BTreeMap::new();
        for session in sessions {
            crate::ids::validate_id(&session.id.0).map_err(|error| {
                DaemonClientError::Protocol {
                    detail: format!(
                        "invalid session metadata id in strict daemon snapshot: {error}"
                    ),
                }
            })?;
            if !live_ids.contains(&session.id.0) {
                return Err(DaemonClientError::Protocol {
                    detail: format!(
                        "strict daemon snapshot metadata names unlisted session {:?}",
                        session.id.0
                    ),
                });
            }
            let generation = session
                .generation
                .ok_or_else(|| DaemonClientError::Protocol {
                    detail: format!(
                        "strict daemon snapshot omits generation for session {:?}",
                        session.id.0
                    ),
                })?;
            if generation.is_empty() || generation.len() > 128 {
                return Err(DaemonClientError::Protocol {
                    detail: format!(
                        "strict daemon snapshot generation for session {:?} must be 1..=128 bytes",
                        session.id.0
                    ),
                });
            }
            if generations
                .insert(session.id.0.clone(), generation)
                .is_some()
            {
                return Err(DaemonClientError::Protocol {
                    detail: format!(
                        "strict daemon snapshot contains duplicate metadata for session {:?}",
                        session.id.0
                    ),
                });
            }
        }
        if generations.len() != live_ids.len() {
            let missing = live_ids
                .into_iter()
                .find(|session_id| !generations.contains_key(session_id))
                .unwrap_or_else(|| "<unknown>".into());
            return Err(DaemonClientError::Protocol {
                detail: format!(
                    "strict daemon snapshot lacks generation metadata for live session {missing:?}"
                ),
            });
        }
        Ok(GenerationMutationSnapshot { generations })
    }

    fn read_generation_snapshot_reply_before(
        &mut self,
        budget: &mut GenerationKillBudget,
        during: &'static str,
    ) -> Result<GenerationMutationSnapshot, DaemonClientError> {
        loop {
            match self.read_event_before(budget, during)? {
                Some(ShellEvent::Sessions { ids, sessions }) => {
                    let snapshot = Self::strict_generation_snapshot(ids, sessions)?;
                    budget.remaining(during)?;
                    return Ok(snapshot);
                }
                Some(ShellEvent::Error { message }) => {
                    return Err(DaemonClientError::DaemonError { message })
                }
                Some(_) => budget.tolerate_unrelated(during)?,
                None => return Err(DaemonClientError::UnexpectedEof { during }),
            }
        }
    }

    fn generation_mutation_snapshot_before(
        &mut self,
        budget: &mut GenerationKillBudget,
    ) -> Result<GenerationMutationSnapshot, DaemonClientError> {
        self.require_generation_conditional_mutations_before(budget)?;
        self.send_before(
            &ClientRequest::ListSessions,
            budget,
            "publishing strict generation snapshot request",
        )?;
        self.read_generation_snapshot_reply_before(
            budget,
            "reading strict generation snapshot reply",
        )
    }

    /// Read one exact protocol-v3 + generation-CAS + complete generation-bearing Sessions
    /// snapshot under a shared absolute/event budget. This is the only mutation pre-resolution
    /// seam used by the release journal; legacy or partial metadata remains read-only.
    pub fn generation_mutation_snapshot(
        &mut self,
    ) -> Result<GenerationMutationSnapshot, DaemonClientError> {
        let mut budget = self.generation_kill_budget()?;
        let result = self.generation_mutation_snapshot_before(&mut budget);
        let restored = self.restore_timeouts(&budget);
        match (result, restored) {
            (Ok(snapshot), Ok(())) => Ok(snapshot),
            (Ok(_), Err(error)) | (Err(error), _) => Err(error),
        }
    }

    /// List the daemon's live session ids. Sends `ListSessions`, then reads until the `Sessions`
    /// reply, tolerating any unrelated events ([`ShellEvent::Other`]) that arrive first. A daemon
    /// `Error` reply is surfaced as [`DaemonClientError::DaemonError`].
    pub fn list_sessions(&mut self) -> Result<Vec<SessionId>, DaemonClientError> {
        Ok(self.list_sessions_snapshot()?.ids)
    }

    /// Read one atomic live-session snapshot, including additive generation metadata when supplied
    /// by a new daemon. Old retained daemons decode with an empty `sessions` vector.
    pub fn list_sessions_snapshot(&mut self) -> Result<ListedSessions, DaemonClientError> {
        let mut budget = self.reply_budget("reading list_sessions reply")?;
        self.send(&ClientRequest::ListSessions)?;
        loop {
            match self.read_event("reading list_sessions reply", &mut budget)? {
                Some(ShellEvent::Sessions { ids, sessions }) => {
                    return Ok(ListedSessions { ids, sessions })
                }
                Some(ShellEvent::Error { message }) => {
                    return Err(DaemonClientError::DaemonError { message })
                }
                Some(ShellEvent::Other) => continue,
                // A Grid / SessionExited here is unrelated to our query — tolerate and keep reading.
                Some(_) => continue,
                None => {
                    return Err(DaemonClientError::UnexpectedEof {
                        during: "reading list_sessions reply",
                    })
                }
            }
        }
    }

    /// Start a session and attach to it structured-only, returning once the daemon delivers the
    /// session's grid baseline.
    ///
    /// Flow: validate the cwd is an existing directory -> send `StartSession` -> send
    /// `Attach{want_raw_output:false}` -> read until the first `Grid` whose id matches, tolerating
    /// unrelated events. The structured opt-out means NO raw PTY bytes reach this client — it never
    /// paints, it only needs the grid's generation/revision to confirm the session is live.
    ///
    /// Cwd policy: the cwd is a caller-supplied EXISTING DIRECTORY (or one already resolved by Phase
    /// 0 policy). If it is not an existing directory — missing, or an existing non-directory such as
    /// a regular file — [`DaemonClientError::InvalidCwd`] is returned BEFORE any request is written.
    /// This mirrors the daemon's own `Path::is_dir()` boundary, so the client rejects the same cwds
    /// the daemon would. This client never CREATES the cwd (no scratch-dir mkdir) and never runs
    /// git — directory/worktree creation is a later phase.
    pub fn start_and_attach(
        &mut self,
        id: SessionId,
        cwd: &str,
        command: &str,
        args: &[String],
        cols: u16,
        rows: u16,
    ) -> Result<(AttachedSession, ConditionalStartRecovery), DaemonClientError> {
        self.start_and_attach_conditionally(
            id,
            cwd,
            command,
            args,
            (cols, rows),
            SessionStartPrecondition::Absent {
                excluded_generation: None,
            },
            false,
            None,
        )
    }

    /// Start and attach while offering one opaque, exact-lifetime ownership handoff to the
    /// renderer that will take over after this starter connection closes.
    pub(crate) fn start_and_attach_for_renderer(
        &mut self,
        id: SessionId,
        cwd: &str,
        command: &str,
        args: &[String],
        cols: u16,
        rows: u16,
    ) -> Result<(AttachedSession, ConditionalStartRecovery), DaemonClientError> {
        self.start_and_attach_conditionally(
            id,
            cwd,
            command,
            args,
            (cols, rows),
            SessionStartPrecondition::Absent {
                excluded_generation: None,
            },
            true,
            None,
        )
    }

    /// Explicitly replace a retained exited same-id session, then attach to the replacement.
    ///
    /// Callers must obtain user restart authority before reaching this boundary. The protocol-v2
    /// capability check belongs in the runtime so this request is never sent to an older daemon
    /// whose historical same-id mutation semantics were ambiguous.
    pub(crate) fn restart_exited_and_attach(
        &mut self,
        id: SessionId,
        expected_previous_generation: &str,
        cwd: &str,
        command: &str,
        args: &[String],
        cols: u16,
        rows: u16,
    ) -> Result<(AttachedSession, ConditionalStartRecovery), DaemonClientError> {
        self.start_and_attach_conditionally(
            id,
            cwd,
            command,
            args,
            (cols, rows),
            SessionStartPrecondition::ExitedGeneration {
                expected_generation: expected_previous_generation.to_string(),
            },
            false,
            None,
        )
    }

    /// Explicit-restart counterpart to [`Self::start_and_attach_for_renderer`].
    pub(crate) fn restart_exited_and_attach_for_renderer(
        &mut self,
        id: SessionId,
        expected_previous_generation: &str,
        cwd: &str,
        command: &str,
        args: &[String],
        cols: u16,
        rows: u16,
    ) -> Result<(AttachedSession, ConditionalStartRecovery), DaemonClientError> {
        self.start_and_attach_conditionally(
            id,
            cwd,
            command,
            args,
            (cols, rows),
            SessionStartPrecondition::ExitedGeneration {
                expected_generation: expected_previous_generation.to_string(),
            },
            true,
            None,
        )
    }

    /// Exact-restart form used after Runtime has already proved this connection's complete v3
    /// conditional-start peer before any endpoint write. Reusing the opaque receipt avoids a
    /// second DaemonInfo while preserving the Exited-generation CAS and renderer Offer.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn restart_exited_and_attach_after_peer_proof_for_renderer(
        &mut self,
        id: SessionId,
        expected_previous_generation: &str,
        expected_peer: &ConditionalStartPeerIdentity,
        cwd: &str,
        command: &str,
        args: &[String],
        cols: u16,
        rows: u16,
    ) -> Result<(AttachedSession, ConditionalStartRecovery), DaemonClientError> {
        self.start_and_attach_conditionally_after_peer_proof(
            id,
            cwd,
            command,
            args,
            (cols, rows),
            SessionStartPrecondition::ExitedGeneration {
                expected_generation: expected_previous_generation.to_string(),
            },
            true,
            expected_peer,
        )
    }

    /// Recreate a durable exited lifetime after a daemon restart proved the id absent, while
    /// excluding durable generation A before the replacement child is spawned.
    pub(crate) fn start_absent_excluding_and_attach_for_renderer(
        &mut self,
        id: SessionId,
        excluded_generation: Option<&str>,
        expected_peer: &ConditionalStartPeerIdentity,
        cwd: &str,
        command: &str,
        args: &[String],
        cols: u16,
        rows: u16,
    ) -> Result<(AttachedSession, ConditionalStartRecovery), DaemonClientError> {
        self.start_and_attach_conditionally(
            id,
            cwd,
            command,
            args,
            (cols, rows),
            SessionStartPrecondition::Absent {
                excluded_generation: excluded_generation.map(str::to_string),
            },
            true,
            Some(expected_peer),
        )
    }

    /// Prepared-session form used after this exact connection has already completed the full
    /// conditional-start capability/peer proof. No further protocol read occurs before the
    /// conditional Start frame, allowing the Shell store to run its final prewire graph snapshot
    /// between proof and publication.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start_absent_and_attach_after_peer_proof_for_renderer(
        &mut self,
        id: SessionId,
        expected_peer: &ConditionalStartPeerIdentity,
        cwd: &str,
        command: &str,
        args: &[String],
        cols: u16,
        rows: u16,
    ) -> Result<(AttachedSession, ConditionalStartRecovery), DaemonClientError> {
        self.start_and_attach_conditionally_after_peer_proof(
            id,
            cwd,
            command,
            args,
            (cols, rows),
            SessionStartPrecondition::Absent {
                excluded_generation: None,
            },
            true,
            expected_peer,
        )
    }

    /// Headless counterpart to [`Self::start_absent_excluding_and_attach_for_renderer`].
    /// The daemon must prove the id absent atomically and must mint a generation distinct from the
    /// durable exited lifetime before it spawns the replacement child.
    pub(crate) fn start_absent_excluding_and_attach(
        &mut self,
        id: SessionId,
        excluded_generation: Option<&str>,
        expected_peer: &ConditionalStartPeerIdentity,
        cwd: &str,
        command: &str,
        args: &[String],
        cols: u16,
        rows: u16,
    ) -> Result<(AttachedSession, ConditionalStartRecovery), DaemonClientError> {
        self.start_and_attach_conditionally(
            id,
            cwd,
            command,
            args,
            (cols, rows),
            SessionStartPrecondition::Absent {
                excluded_generation: excluded_generation.map(str::to_string),
            },
            false,
            Some(expected_peer),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start_absent_and_attach_after_peer_proof(
        &mut self,
        id: SessionId,
        expected_peer: &ConditionalStartPeerIdentity,
        cwd: &str,
        command: &str,
        args: &[String],
        cols: u16,
        rows: u16,
    ) -> Result<(AttachedSession, ConditionalStartRecovery), DaemonClientError> {
        self.start_and_attach_conditionally_after_peer_proof(
            id,
            cwd,
            command,
            args,
            (cols, rows),
            SessionStartPrecondition::Absent {
                excluded_generation: None,
            },
            false,
            expected_peer,
        )
    }

    /// Start one exact conditional generation on this already-capability-probed, reviewed daemon
    /// connection while applying the protocol's restricted headless child environment. A requested
    /// environment fails before Reserve/Start unless the captured peer proof advertised support.
    #[allow(clippy::too_many_arguments)]
    pub fn start_and_attach_conditionally_with_environment(
        &mut self,
        id: SessionId,
        cwd: &str,
        command: &str,
        args: &[String],
        child_environment: Option<ChildEnvironment>,
        cols: u16,
        rows: u16,
        precondition: SessionStartPrecondition,
        expected_peer: &ConditionalStartPeerIdentity,
    ) -> Result<(AttachedSession, ConditionalStartRecovery), DaemonClientError> {
        if child_environment.is_some() && !expected_peer.supports_child_environment() {
            return Err(DaemonClientError::MutationProtocolUnsupported {
                required: maestro_protocol::DAEMON_PROTOCOL_VERSION,
                observed: self
                    .daemon_instance_id
                    .as_ref()
                    .map(|_| maestro_protocol::DAEMON_PROTOCOL_VERSION),
            });
        }
        self.start_and_attach_conditionally_after_peer_proof_with_recovery_and_environment(
            id,
            cwd,
            command,
            args,
            (cols, rows),
            precondition,
            false,
            expected_peer,
            None,
            child_environment,
        )
    }

    /// Task-aware headless counterpart that retains the exact conditional operation proof after
    /// `Grid`.  The caller either retires it after the atomic Session+AgentTask publication or
    /// binds it to a non-cloneable recovery authority if that final transaction is uncertain.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start_absent_and_attach_after_peer_proof_with_recovery(
        &mut self,
        id: SessionId,
        operation_token: SessionStartOperationToken,
        expected_peer: &ConditionalStartPeerIdentity,
        cwd: &str,
        command: &str,
        args: &[String],
        cols: u16,
        rows: u16,
    ) -> Result<(AttachedSession, ConditionalStartRecovery), DaemonClientError> {
        self.start_and_attach_conditionally_after_peer_proof_with_recovery(
            id,
            cwd,
            command,
            args,
            (cols, rows),
            SessionStartPrecondition::Absent {
                excluded_generation: None,
            },
            false,
            expected_peer,
            Some(operation_token),
        )
    }

    /// Retire the exact Applied(G) operation on this already-reviewed connection after the caller
    /// has durably published the matching Grid-proven generation. The recovery value and any
    /// renderer handoff seed remain owned by the caller; this method mutates only the daemon's
    /// process-lifetime ledger and leaves the connection available for handoff ownership.
    pub fn retire_applied_start_operation_in_place(
        &mut self,
        recovery: &ConditionalStartRecovery,
        generation: &str,
    ) -> Result<SessionStartOperationRetireOutcome, DaemonClientError> {
        validate_expected_attach_generation(generation)?;
        if recovery.operation_applied_generation() != Some(generation)
            || recovery.grid_proven_generation() != Some(generation)
        {
            return Err(DaemonClientError::Protocol {
                detail: "start operation retirement requires matching Applied and exact-Grid proof"
                    .into(),
            });
        }
        if self.daemon_instance_id.as_ref() != Some(recovery.daemon_instance_id()) {
            return Err(DaemonClientError::Protocol {
                detail: "start operation retirement connection no longer matches its reviewed daemon instance"
                    .into(),
            });
        }

        let mut budget = self.generation_kill_budget()?;
        let result = self.retire_start_operation_before(
            recovery.session_id(),
            &recovery.operation_token,
            recovery.daemon_instance_id(),
            SessionStartOperationRetireExpectation::Applied {
                generation: generation.to_string(),
            },
            &mut budget,
        );
        let restored = self.restore_timeouts(&budget);
        match (result, restored) {
            (Ok(outcome), Ok(())) => Ok(outcome),
            (Ok(_), Err(error)) | (Err(error), _) => Err(error),
        }
    }

    fn start_and_attach_conditionally(
        &mut self,
        id: SessionId,
        cwd: &str,
        command: &str,
        args: &[String],
        dimensions: (u16, u16),
        precondition: SessionStartPrecondition,
        offer_renderer_handoff: bool,
        expected_peer: Option<&ConditionalStartPeerIdentity>,
    ) -> Result<(AttachedSession, ConditionalStartRecovery), DaemonClientError> {
        let (cols, rows) = dimensions;
        // The cwd is checked FIRST, before any byte is written, so a bad cwd never leaves a dangling
        // StartSession on the wire. `is_dir()` matches the daemon's boundary (`daemon.rs`: it
        // rejects a non-directory cwd with `Path::is_dir()`), so a missing path OR an existing
        // regular file is rejected here rather than round-tripping to a daemon error. We only
        // INSPECT — we do NOT create the directory.
        if !Path::new(cwd).is_dir() {
            return Err(DaemonClientError::InvalidCwd {
                cwd: cwd.to_string(),
            });
        }

        let mut budget = self.generation_kill_budget()?;
        let result = self.start_and_attach_conditionally_before(
            id,
            cwd,
            command,
            args,
            (cols, rows),
            precondition,
            offer_renderer_handoff,
            expected_peer,
            false,
            None,
            None,
            &mut budget,
        );
        let restored = self.restore_timeouts(&budget);
        match (result, restored) {
            (Ok((attached, recovery)), Ok(())) => Ok((attached, recovery)),
            (Ok((_, mut recovery)), Err(source)) => {
                // The conditional Start and exact Grid already succeeded, but this connection is
                // not fit to escape as an Offer authority. EOF retires the unclaimed Offer without
                // blocking; the durable publication remains conservatively possibly applied.
                recovery.handoff_seed = None;
                self.abort_connection();
                Err(Self::conditional_start_possibly_applied(&recovery, source))
            }
            (Err(error), _) => Err(error),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn start_and_attach_conditionally_after_peer_proof(
        &mut self,
        id: SessionId,
        cwd: &str,
        command: &str,
        args: &[String],
        dimensions: (u16, u16),
        precondition: SessionStartPrecondition,
        offer_renderer_handoff: bool,
        expected_peer: &ConditionalStartPeerIdentity,
    ) -> Result<(AttachedSession, ConditionalStartRecovery), DaemonClientError> {
        self.start_and_attach_conditionally_after_peer_proof_with_recovery(
            id,
            cwd,
            command,
            args,
            dimensions,
            precondition,
            offer_renderer_handoff,
            expected_peer,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn start_and_attach_conditionally_after_peer_proof_with_recovery(
        &mut self,
        id: SessionId,
        cwd: &str,
        command: &str,
        args: &[String],
        dimensions: (u16, u16),
        precondition: SessionStartPrecondition,
        offer_renderer_handoff: bool,
        expected_peer: &ConditionalStartPeerIdentity,
        operation_token: Option<SessionStartOperationToken>,
    ) -> Result<(AttachedSession, ConditionalStartRecovery), DaemonClientError> {
        self.start_and_attach_conditionally_after_peer_proof_with_recovery_and_environment(
            id,
            cwd,
            command,
            args,
            dimensions,
            precondition,
            offer_renderer_handoff,
            expected_peer,
            operation_token,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn start_and_attach_conditionally_after_peer_proof_with_recovery_and_environment(
        &mut self,
        id: SessionId,
        cwd: &str,
        command: &str,
        args: &[String],
        dimensions: (u16, u16),
        precondition: SessionStartPrecondition,
        offer_renderer_handoff: bool,
        expected_peer: &ConditionalStartPeerIdentity,
        operation_token: Option<SessionStartOperationToken>,
        child_environment: Option<ChildEnvironment>,
    ) -> Result<(AttachedSession, ConditionalStartRecovery), DaemonClientError> {
        if !Path::new(cwd).is_dir() {
            return Err(DaemonClientError::InvalidCwd {
                cwd: cwd.to_string(),
            });
        }
        let mut budget = self.generation_kill_budget()?;
        let result = self.start_and_attach_conditionally_before(
            id,
            cwd,
            command,
            args,
            dimensions,
            precondition,
            offer_renderer_handoff,
            Some(expected_peer),
            true,
            operation_token,
            child_environment,
            &mut budget,
        );
        let restored = self.restore_timeouts(&budget);
        match (result, restored) {
            (Ok((attached, recovery)), Ok(())) => Ok((attached, recovery)),
            (Ok((_, mut recovery)), Err(source)) => {
                recovery.handoff_seed = None;
                self.abort_connection();
                Err(Self::conditional_start_possibly_applied(&recovery, source))
            }
            (Err(error), _) => Err(error),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn start_and_attach_conditionally_before(
        &mut self,
        id: SessionId,
        cwd: &str,
        command: &str,
        args: &[String],
        dimensions: (u16, u16),
        precondition: SessionStartPrecondition,
        offer_renderer_handoff: bool,
        expected_peer: Option<&ConditionalStartPeerIdentity>,
        peer_already_proven: bool,
        operation_token: Option<SessionStartOperationToken>,
        child_environment: Option<ChildEnvironment>,
        budget: &mut GenerationKillBudget,
    ) -> Result<(AttachedSession, ConditionalStartRecovery), DaemonClientError> {
        let (cols, rows) = dimensions;
        let operation_token = match operation_token {
            Some(operation_token) => operation_token,
            None => Self::mint_start_operation_token()?,
        };
        let request = ClientRequest::StartSession {
            id: id.clone(),
            cwd: cwd.to_string(),
            command: command.to_string(),
            args: args.to_vec(),
            child_environment,
            cols,
            rows,
            // Conditional authority is additive and the old restart bit stays false. If a retained
            // daemon ignored the new field, it would preserve exited A and could not emit the typed
            // acknowledgement required below.
            restart_exited: false,
            conditional_start: Some(ConditionalSessionStart {
                operation_token: operation_token.clone(),
                precondition: precondition.clone(),
            }),
        };
        // Bound the full Start frame before capability probing or reserving a process-lifetime
        // ledger slot. Oversized argv/cwd can therefore leave neither wire bytes nor authority.
        let encoded = Self::encode_request(&request)?;
        let daemon_instance_id = if peer_already_proven {
            let expected_peer = expected_peer.ok_or_else(|| DaemonClientError::Protocol {
                detail: "prepared conditional Start omitted its reviewed peer".into(),
            })?;
            let observed =
                self.daemon_instance_id
                    .clone()
                    .ok_or_else(|| DaemonClientError::Protocol {
                        detail: "prepared conditional Start lost its reviewed daemon instance"
                            .into(),
                    })?;
            self.require_conditional_start_peer(&observed, expected_peer)?;
            observed
        } else {
            let observed = self.require_start_session_protocol_before(budget)?;
            if let Some(expected_peer) = expected_peer {
                self.require_conditional_start_peer(&observed, expected_peer)?;
            }
            observed
        };
        let mut recovery = ConditionalStartRecovery {
            session_id: id.clone(),
            operation_token: operation_token.clone(),
            daemon_instance_id: daemon_instance_id.clone(),
            precondition: precondition.clone(),
            operation_applied_generation: None,
            grid_proven_generation: None,
            handoff_seed: None,
        };
        if let Some((generation, lifecycle)) = self.ensure_start_operation_reserved_before(
            &id,
            &operation_token,
            &daemon_instance_id,
            &recovery,
            budget,
        )? {
            // A reused durable token may already be Applied. This is only an operation fact; the
            // exact generation still has to pass Attach and its echoed Grid below. A lifecycle
            // already known not-Live cannot be upgraded to Live merely because an exited retained
            // Session can still provide its final Grid.
            recovery.operation_applied_generation = Some(generation.clone());
            if lifecycle != SessionStartOperationLifecycle::Live {
                return Err(Self::conditional_start_possibly_applied(
                    &recovery,
                    DaemonClientError::StartOperationTerminal {
                        id,
                        status: SessionStartOperationStatus::Applied {
                            generation,
                            lifecycle,
                        },
                    },
                ));
            }
            return self.finish_conditional_start_after_ack_before(
                id,
                generation,
                daemon_instance_id,
                offer_renderer_handoff,
                recovery,
                budget,
            );
        }
        if let Err(failure) =
            self.write_encoded_request_before(&encoded, budget, "publishing conditional start")
        {
            if failure.write_attempted {
                let generation = self.recover_conditional_start_before(
                    &request,
                    &recovery,
                    failure.source,
                    budget,
                )?;
                return self.finish_conditional_start_after_ack_before(
                    id,
                    generation,
                    daemon_instance_id,
                    offer_renderer_handoff,
                    recovery,
                    budget,
                );
            }
            let source = failure.source;
            return match self.retire_start_operation_before(
                &id,
                &operation_token,
                &daemon_instance_id,
                SessionStartOperationRetireExpectation::Unapplied,
                budget,
            ) {
                Ok(SessionStartOperationRetireOutcome::Retired)
                | Ok(SessionStartOperationRetireOutcome::AlreadyRetired) => Err(source),
                Ok(SessionStartOperationRetireOutcome::Conflict {
                    current:
                        SessionStartOperationStatus::Applied {
                            generation,
                            lifecycle: _,
                        },
                }) => {
                    recovery.operation_applied_generation = Some(generation);
                    Err(Self::conditional_start_possibly_applied(&recovery, source))
                }
                Ok(SessionStartOperationRetireOutcome::Conflict { .. }) | Err(_) => {
                    Err(Self::conditional_start_possibly_applied(&recovery, source))
                }
            };
        }

        let generation = match self.read_conditional_start_ack_before(
            &id,
            &operation_token,
            &daemon_instance_id,
            budget,
        ) {
            Ok(generation) => generation,
            Err(error @ DaemonClientError::ConditionalStartRefused { .. }) => {
                return match self.retire_start_operation_before(
                    &id,
                    &operation_token,
                    &daemon_instance_id,
                    SessionStartOperationRetireExpectation::Unapplied,
                    budget,
                ) {
                    Ok(SessionStartOperationRetireOutcome::Retired)
                    | Ok(SessionStartOperationRetireOutcome::AlreadyRetired) => Err(error),
                    Ok(SessionStartOperationRetireOutcome::Conflict {
                        current:
                            SessionStartOperationStatus::Applied {
                                generation,
                                lifecycle: _,
                            },
                    }) => {
                        recovery.operation_applied_generation = Some(generation);
                        Err(Self::conditional_start_possibly_applied(&recovery, error))
                    }
                    Ok(SessionStartOperationRetireOutcome::Conflict { .. }) | Err(_) => {
                        Err(Self::conditional_start_possibly_applied(&recovery, error))
                    }
                };
            }
            Err(first_error) => {
                self.recover_conditional_start_before(&request, &recovery, first_error, budget)?
            }
        };

        self.finish_conditional_start_after_ack_before(
            id,
            generation,
            daemon_instance_id,
            offer_renderer_handoff,
            recovery,
            budget,
        )
    }

    /// Establish the content-blind operation tuple before any Start frame is emitted. Reservation
    /// is idempotent, so an ambiguous ACK is retried only on a fresh same-daemon connection. A
    /// pre-existing Applied result is returned as an operation fact and still requires exact Grid.
    fn ensure_start_operation_reserved_before(
        &mut self,
        id: &SessionId,
        operation_token: &SessionStartOperationToken,
        daemon_instance_id: &DaemonInstanceId,
        recovery: &ConditionalStartRecovery,
        budget: &mut GenerationKillBudget,
    ) -> Result<Option<(String, SessionStartOperationLifecycle)>, DaemonClientError> {
        let request = ClientRequest::ReserveStartOperation {
            id: id.clone(),
            operation_token: operation_token.clone(),
        };
        let first = self
            .send_before(
                &request,
                budget,
                "publishing conditional start operation reservation",
            )
            .and_then(|()| {
                self.read_start_operation_reserve_ack_before(
                    id,
                    operation_token,
                    daemon_instance_id,
                    budget,
                )
            });
        let outcome = match first {
            Ok(outcome) => outcome,
            Err(first_error) => {
                let mut recovered =
                    match self.reconnect_same_daemon_before(daemon_instance_id, budget) {
                        Ok(recovered) => recovered,
                        Err(_) => {
                            return Err(Self::conditional_start_possibly_applied(
                                recovery,
                                first_error,
                            ))
                        }
                    };
                if let Err(error) = recovered.send_before(
                    &request,
                    budget,
                    "replaying conditional start operation reservation",
                ) {
                    *self = recovered;
                    return Err(Self::conditional_start_possibly_applied(recovery, error));
                }
                let outcome = match recovered.read_start_operation_reserve_ack_before(
                    id,
                    operation_token,
                    daemon_instance_id,
                    budget,
                ) {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        *self = recovered;
                        return Err(Self::conditional_start_possibly_applied(recovery, error));
                    }
                };
                *self = recovered;
                outcome
            }
        };
        match outcome {
            SessionStartOperationReserveOutcome::Reserved
            | SessionStartOperationReserveOutcome::AlreadyReserved => Ok(None),
            SessionStartOperationReserveOutcome::Refused {
                reason: SessionStartOperationReserveRefusal::AlreadyTerminal,
            } => {
                let status = match self.lookup_start_operation_before(
                    id,
                    operation_token,
                    daemon_instance_id,
                    budget,
                ) {
                    Ok(status) => status,
                    Err(error) => {
                        return Err(Self::conditional_start_possibly_applied(recovery, error))
                    }
                };
                match status {
                    SessionStartOperationStatus::Applied {
                        generation,
                        lifecycle,
                    } => Ok(Some((generation, lifecycle))),
                    status @ SessionStartOperationStatus::Refused => Err(
                        Self::retire_recovered_refused_start_before(self, recovery, status, budget),
                    ),
                    status @ SessionStartOperationStatus::Reserved => {
                        Err(Self::conditional_start_possibly_applied(
                            recovery,
                            DaemonClientError::StartOperationTerminal {
                                id: id.clone(),
                                status,
                            },
                        ))
                    }
                    status @ SessionStartOperationStatus::Unknown => {
                        Err(DaemonClientError::StartOperationTerminal {
                            id: id.clone(),
                            status,
                        })
                    }
                }
            }
            SessionStartOperationReserveOutcome::Refused { reason } => {
                Err(DaemonClientError::StartOperationReservationRefused {
                    id: id.clone(),
                    reason,
                })
            }
        }
    }

    fn read_start_operation_reserve_ack_before(
        &mut self,
        expected_id: &SessionId,
        expected_token: &SessionStartOperationToken,
        expected_daemon_instance: &DaemonInstanceId,
        budget: &mut GenerationKillBudget,
    ) -> Result<SessionStartOperationReserveOutcome, DaemonClientError> {
        loop {
            match self.read_event_before(budget, "reading start operation reservation")? {
                Some(ShellEvent::StartOperationReserved {
                    id,
                    operation_token,
                    daemon_instance_id,
                    outcome,
                }) if &id == expected_id
                    && &operation_token == expected_token
                    && &daemon_instance_id == expected_daemon_instance => return Ok(outcome),
                Some(ShellEvent::StartOperationReserved { .. }) => {
                    return Err(DaemonClientError::Protocol {
                        detail: "start operation reservation acknowledgement did not match exact id, token, and daemon instance".into(),
                    })
                }
                Some(ShellEvent::Error { message }) => {
                    return Err(DaemonClientError::DaemonError { message })
                }
                Some(_) => budget.tolerate_unrelated("reading start operation reservation")?,
                None => {
                    return Err(DaemonClientError::UnexpectedEof {
                        during: "reading start operation reservation",
                    })
                }
            }
        }
    }

    fn finish_conditional_start_after_ack_before(
        &mut self,
        id: SessionId,
        generation: String,
        daemon_instance_id: DaemonInstanceId,
        offer_renderer_handoff: bool,
        mut recovery: ConditionalStartRecovery,
        budget: &mut GenerationKillBudget,
    ) -> Result<(AttachedSession, ConditionalStartRecovery), DaemonClientError> {
        let precondition = recovery.precondition.clone();

        let excluded_generation = match &precondition {
            SessionStartPrecondition::Absent {
                excluded_generation,
            } => excluded_generation.as_deref(),
            SessionStartPrecondition::ExitedGeneration {
                expected_generation,
            } => Some(expected_generation.as_str()),
        };
        // The ACK/Lookup already proves Applied(G), even when G violates the caller's exclusion.
        // Cache only that operation fact before rejecting; exact Grid authority remains absent.
        recovery.operation_applied_generation = Some(generation.clone());
        if excluded_generation == Some(generation.as_str()) {
            return Err(DaemonClientError::ConditionalStartPossiblyApplied {
                id: id.clone(),
                recovery,
                source: Box::new(DaemonClientError::RestartGenerationUnchanged { id }),
            });
        }

        self.attach_after_conditional_start_before(
            id,
            generation,
            daemon_instance_id,
            offer_renderer_handoff,
            recovery,
            budget,
        )
    }

    /// Recover one ambiguous conditional Start on a fresh connection to the exact same daemon.
    /// `Reserved` is the daemon-atomic proof that no Start has linearized yet, so the exact request
    /// may be replayed once. `Unknown` is never a terminal negative and never authorizes a spawn.
    fn recover_conditional_start_before(
        &mut self,
        request: &ClientRequest,
        recovery: &ConditionalStartRecovery,
        first_error: DaemonClientError,
        budget: &mut GenerationKillBudget,
    ) -> Result<String, DaemonClientError> {
        let mut recovered =
            match self.reconnect_same_daemon_before(&recovery.daemon_instance_id, budget) {
                Ok(client) => client,
                Err(_) => {
                    return Err(Self::conditional_start_possibly_applied(
                        recovery,
                        first_error,
                    ))
                }
            };
        match recovered.lookup_start_operation_before(
            &recovery.session_id,
            &recovery.operation_token,
            &recovery.daemon_instance_id,
            budget,
        ) {
            Ok(SessionStartOperationStatus::Applied {
                generation,
                lifecycle,
            }) => {
                let result = Self::lookup_applied_generation_for_start_recovery(
                    recovery, generation, lifecycle,
                );
                *self = recovered;
                result
            }
            Ok(SessionStartOperationStatus::Reserved) => {
                if let Err(error) = recovered.send_before(
                    request,
                    budget,
                    "retrying exact reserved conditional start",
                ) {
                    *self = recovered;
                    return Err(Self::conditional_start_possibly_applied(recovery, error));
                }
                match recovered.read_conditional_start_ack_before(
                    &recovery.session_id,
                    &recovery.operation_token,
                    &recovery.daemon_instance_id,
                    budget,
                ) {
                    Ok(generation) => {
                        *self = recovered;
                        Ok(generation)
                    }
                    Err(replay_error) => {
                        let mut final_lookup = match recovered
                            .reconnect_same_daemon_before(&recovery.daemon_instance_id, budget)
                        {
                            Ok(client) => client,
                            Err(_) => {
                                *self = recovered;
                                return Err(Self::conditional_start_possibly_applied(
                                    recovery,
                                    replay_error,
                                ));
                            }
                        };
                        match final_lookup.lookup_start_operation_before(
                            &recovery.session_id,
                            &recovery.operation_token,
                            &recovery.daemon_instance_id,
                            budget,
                        ) {
                            Ok(SessionStartOperationStatus::Applied {
                                generation,
                                lifecycle,
                            }) => {
                                let result = Self::lookup_applied_generation_for_start_recovery(
                                    recovery, generation, lifecycle,
                                );
                                *self = final_lookup;
                                result
                            }
                            Ok(status @ SessionStartOperationStatus::Refused) => {
                                let error = Self::retire_recovered_refused_start_before(
                                    &mut final_lookup,
                                    recovery,
                                    status,
                                    budget,
                                );
                                *self = final_lookup;
                                Err(error)
                            }
                            Ok(SessionStartOperationStatus::Unknown)
                            | Ok(SessionStartOperationStatus::Reserved)
                            | Err(_) => {
                                *self = final_lookup;
                                Err(Self::conditional_start_possibly_applied(
                                    recovery,
                                    replay_error,
                                ))
                            }
                        }
                    }
                }
            }
            Ok(status @ SessionStartOperationStatus::Refused) => {
                let error = Self::retire_recovered_refused_start_before(
                    &mut recovered,
                    recovery,
                    status,
                    budget,
                );
                *self = recovered;
                Err(error)
            }
            Ok(SessionStartOperationStatus::Unknown) | Err(_) => {
                *self = recovered;
                Err(Self::conditional_start_possibly_applied(
                    recovery,
                    first_error,
                ))
            }
        }
    }

    /// A retained exited Session can still yield its final Grid, so Lookup lifecycle—not Grid
    /// availability—must stop a known non-Live operation from becoming a normal Live success.
    fn lookup_applied_generation_for_start_recovery(
        recovery: &ConditionalStartRecovery,
        generation: String,
        lifecycle: SessionStartOperationLifecycle,
    ) -> Result<String, DaemonClientError> {
        if lifecycle == SessionStartOperationLifecycle::Live {
            return Ok(generation);
        }
        let mut recovery = recovery.clone();
        recovery.operation_applied_generation = Some(generation.clone());
        Err(Self::conditional_start_possibly_applied(
            &recovery,
            DaemonClientError::StartOperationTerminal {
                id: recovery.session_id.clone(),
                status: SessionStartOperationStatus::Applied {
                    generation,
                    lifecycle,
                },
            },
        ))
    }

    /// A Lookup-only Refused observation still occupies one bounded ledger slot. Remove it with the
    /// exact Unapplied CAS before returning a terminal refusal. If that barrier is ambiguous or
    /// races a later Applied generation, preserve the opaque recovery authority instead of losing
    /// the only token capable of eventual cleanup.
    fn retire_recovered_refused_start_before(
        client: &mut DaemonClient,
        recovery: &ConditionalStartRecovery,
        status: SessionStartOperationStatus,
        budget: &mut GenerationKillBudget,
    ) -> DaemonClientError {
        debug_assert_eq!(status, SessionStartOperationStatus::Refused);
        let terminal = || DaemonClientError::StartOperationTerminal {
            id: recovery.session_id.clone(),
            status: status.clone(),
        };
        match client.retire_start_operation_before(
            &recovery.session_id,
            &recovery.operation_token,
            &recovery.daemon_instance_id,
            SessionStartOperationRetireExpectation::Unapplied,
            budget,
        ) {
            Ok(SessionStartOperationRetireOutcome::Retired)
            | Ok(SessionStartOperationRetireOutcome::AlreadyRetired) => terminal(),
            Ok(SessionStartOperationRetireOutcome::Conflict {
                current:
                    SessionStartOperationStatus::Applied {
                        generation,
                        lifecycle: _,
                    },
            }) => {
                let mut recovery = recovery.clone();
                recovery.operation_applied_generation = Some(generation);
                Self::conditional_start_possibly_applied(&recovery, terminal())
            }
            Ok(SessionStartOperationRetireOutcome::Conflict { .. }) | Err(_) => {
                Self::conditional_start_possibly_applied(recovery, terminal())
            }
        }
    }

    fn read_conditional_start_ack_before(
        &mut self,
        expected_id: &SessionId,
        expected_token: &SessionStartOperationToken,
        expected_daemon_instance: &DaemonInstanceId,
        budget: &mut GenerationKillBudget,
    ) -> Result<String, DaemonClientError> {
        loop {
            match self.read_event_before(budget, "reading conditional start acknowledgement")? {
                Some(ShellEvent::ConditionalSessionStart {
                    id,
                    operation_token,
                    daemon_instance_id,
                    outcome,
                }) if &id == expected_id
                    && &operation_token == expected_token
                    && &daemon_instance_id == expected_daemon_instance =>
                {
                    return match outcome {
                        ConditionalSessionStartOutcome::Applied { generation }
                        | ConditionalSessionStartOutcome::AlreadyApplied { generation } => {
                            if generation.is_empty() || generation.len() > 128 {
                                Err(DaemonClientError::Protocol {
                                    detail: "conditional start acknowledgement generation must be 1..=128 bytes".into(),
                                })
                            } else {
                                Ok(generation)
                            }
                        }
                        ConditionalSessionStartOutcome::Refused { reason } => {
                            Err(DaemonClientError::ConditionalStartRefused { id, reason })
                        }
                    }
                }
                Some(ShellEvent::ConditionalSessionStart { .. }) => {
                    return Err(DaemonClientError::Protocol {
                        detail: "conditional start acknowledgement did not match exact id, token, and daemon instance".into(),
                    })
                }
                Some(ShellEvent::Error { message }) => {
                    return Err(DaemonClientError::DaemonError { message })
                }
                Some(_) => {
                    budget.tolerate_unrelated("reading conditional start acknowledgement")?
                }
                None => {
                    return Err(DaemonClientError::UnexpectedEof {
                        during: "reading conditional start acknowledgement",
                    })
                }
            }
        }
    }

    fn lookup_start_operation_before(
        &mut self,
        expected_id: &SessionId,
        expected_token: &SessionStartOperationToken,
        expected_daemon_instance: &DaemonInstanceId,
        budget: &mut GenerationKillBudget,
    ) -> Result<SessionStartOperationStatus, DaemonClientError> {
        self.send_before(
            &ClientRequest::LookupStartOperation {
                id: expected_id.clone(),
                operation_token: expected_token.clone(),
            },
            budget,
            "publishing conditional start lookup",
        )?;
        loop {
            match self.read_event_before(budget, "reading conditional start lookup")? {
                Some(ShellEvent::StartOperationStatus {
                    id,
                    operation_token,
                    daemon_instance_id,
                    status,
                }) if &id == expected_id
                    && &operation_token == expected_token
                    && &daemon_instance_id == expected_daemon_instance =>
                {
                    return match status {
                        SessionStartOperationStatus::Applied {
                            generation,
                            lifecycle,
                        } => {
                            if generation.is_empty() || generation.len() > 128 {
                                Err(DaemonClientError::Protocol {
                                    detail: "conditional start lookup generation must be 1..=128 bytes".into(),
                                })
                            } else {
                                Ok(SessionStartOperationStatus::Applied {
                                    generation,
                                    lifecycle,
                                })
                            }
                        }
                        status @ (SessionStartOperationStatus::Unknown
                        | SessionStartOperationStatus::Reserved
                        | SessionStartOperationStatus::Refused) => Ok(status),
                    }
                }
                Some(ShellEvent::StartOperationStatus { .. }) => {
                    return Err(DaemonClientError::Protocol {
                        detail: "conditional start lookup did not match exact id, token, and daemon instance".into(),
                    })
                }
                Some(ShellEvent::Error { message }) => {
                    return Err(DaemonClientError::DaemonError { message })
                }
                Some(_) => budget.tolerate_unrelated("reading conditional start lookup")?,
                None => {
                    return Err(DaemonClientError::UnexpectedEof {
                        during: "reading conditional start lookup",
                    })
                }
            }
        }
    }

    fn retire_start_operation_before(
        &mut self,
        expected_id: &SessionId,
        expected_token: &SessionStartOperationToken,
        expected_daemon_instance: &DaemonInstanceId,
        expected: SessionStartOperationRetireExpectation,
        budget: &mut GenerationKillBudget,
    ) -> Result<SessionStartOperationRetireOutcome, DaemonClientError> {
        self.send_before(
            &ClientRequest::RetireStartOperation {
                id: expected_id.clone(),
                operation_token: expected_token.clone(),
                expected,
            },
            budget,
            "publishing start operation retirement barrier",
        )?;
        loop {
            match self.read_event_before(budget, "reading start operation retirement barrier")? {
                Some(ShellEvent::StartOperationRetired {
                    id,
                    operation_token,
                    daemon_instance_id,
                    outcome,
                }) if &id == expected_id
                    && &operation_token == expected_token
                    && &daemon_instance_id == expected_daemon_instance =>
                {
                    if let SessionStartOperationRetireOutcome::Conflict {
                        current: SessionStartOperationStatus::Applied { generation, .. },
                    } = &outcome
                    {
                        validate_expected_attach_generation(generation)?;
                    }
                    return Ok(outcome);
                }
                Some(ShellEvent::StartOperationRetired { .. }) => {
                    return Err(DaemonClientError::Protocol {
                        detail: "start operation retirement acknowledgement did not match exact id, token, and daemon instance".into(),
                    })
                }
                Some(ShellEvent::Error { message }) => {
                    return Err(DaemonClientError::DaemonError { message })
                }
                Some(_) => {
                    budget.tolerate_unrelated("reading start operation retirement barrier")?
                }
                None => {
                    return Err(DaemonClientError::UnexpectedEof {
                        during: "reading start operation retirement barrier",
                    })
                }
            }
        }
    }

    fn attach_after_conditional_start_before(
        &mut self,
        id: SessionId,
        expected_generation: String,
        daemon_instance_id: DaemonInstanceId,
        offer_renderer_handoff: bool,
        mut recovery: ConditionalStartRecovery,
        budget: &mut GenerationKillBudget,
    ) -> Result<(AttachedSession, ConditionalStartRecovery), DaemonClientError> {
        let handoff_seed = if offer_renderer_handoff {
            let token: AttachmentHandoffToken =
                match uuid::Uuid::new_v4().simple().to_string().parse() {
                    Ok(token) => token,
                    Err(error) => {
                        return Err(Self::conditional_start_possibly_applied(
                            &recovery,
                            DaemonClientError::Protocol {
                                detail: format!(
                                    "could not construct attachment handoff token: {error}"
                                ),
                            },
                        ))
                    }
                };
            Some(AttachmentHandoffSeed {
                session_id: id.clone(),
                token,
                expected_daemon_instance: daemon_instance_id.clone(),
                expected_generation: Some(expected_generation.clone()),
            })
        } else {
            None
        };
        let handoff = handoff_seed.as_ref().map(|seed| AttachmentHandoff::Offer {
            token: seed.token.clone(),
        });
        let output_generation = self
            .allocate_output_generation()
            .map_err(|source| Self::conditional_start_possibly_applied(&recovery, source))?;
        recovery.handoff_seed = handoff_seed.clone();
        if let Err(error) = self.send_before(
            &ClientRequest::Attach {
                id: id.clone(),
                want_raw_output: false,
                expected_session_generation: Some(expected_generation.clone()),
                output_generation: Some(output_generation),
                handoff,
            },
            budget,
            "publishing post-start exact attach",
        ) {
            return Err(self.fail_after_handoff_offer_before(&mut recovery, error, false, budget));
        }

        loop {
            let event = self.read_event_before(budget, "reading post-start exact grid");
            match event {
                Ok(Some(ShellEvent::Grid {
                    id: got,
                    output_generation: Some(got_output_generation),
                    grid,
                })) if got == id && got_output_generation == output_generation => {
                    if grid.generation != expected_generation {
                        let source = DaemonClientError::Protocol {
                            detail: "post-start Grid generation did not match exact typed acknowledgement".into(),
                        };
                        return Err(self.fail_after_handoff_offer_before(
                            &mut recovery,
                            source,
                            true,
                            budget,
                        ));
                    }
                    recovery.grid_proven_generation = Some(grid.generation.clone());
                    return Ok((
                        AttachedSession {
                            id: got,
                            generation: grid.generation,
                            revision: grid.revision,
                            handoff_seed,
                        },
                        recovery,
                    ));
                }
                Ok(Some(ShellEvent::Grid { .. })) => {
                    if let Err(error) = budget.tolerate_unrelated("reading post-start exact grid") {
                        return Err(self.fail_after_handoff_offer_before(
                            &mut recovery,
                            error,
                            true,
                            budget,
                        ));
                    }
                }
                Ok(Some(ShellEvent::SessionAttachRefused {
                    id: got,
                    expected_generation: got_generation,
                    daemon_instance_id: got_instance,
                    reason,
                })) if got == id
                    && got_generation == expected_generation
                    && got_instance == daemon_instance_id =>
                {
                    // The daemon refused before installing this Offer. B was already acknowledged,
                    // so preserve the conditional-start recovery classification but do not retain
                    // or cancel a token that provably never crossed the guard boundary.
                    recovery.handoff_seed = None;
                    self.abort_connection();
                    return Err(Self::conditional_start_possibly_applied(
                        &recovery,
                        DaemonClientError::ConditionalAttachRefused {
                            id: got,
                            expected_generation: got_generation,
                            reason,
                        },
                    ));
                }
                Ok(Some(ShellEvent::SessionAttachRefused { .. })) => {
                    return Err(self.fail_after_handoff_offer_before(
                        &mut recovery,
                        DaemonClientError::Protocol {
                            detail: "post-start conditional Attach refusal did not match exact id, generation, and daemon instance".into(),
                        },
                        true,
                        budget,
                    ));
                }
                Ok(Some(ShellEvent::SessionExited { id: got, code })) if got == id => {
                    return Err(self.fail_after_handoff_offer_before(
                        &mut recovery,
                        DaemonClientError::SessionExited { id: got, code },
                        true,
                        budget,
                    ))
                }
                Ok(Some(ShellEvent::Error { message })) => {
                    return Err(self.fail_after_handoff_offer_before(
                        &mut recovery,
                        DaemonClientError::DaemonError { message },
                        true,
                        budget,
                    ))
                }
                Ok(Some(_)) => {
                    if let Err(error) = budget.tolerate_unrelated("reading post-start exact grid") {
                        return Err(self.fail_after_handoff_offer_before(
                            &mut recovery,
                            error,
                            true,
                            budget,
                        ));
                    }
                }
                Ok(None) => {
                    return Err(self.fail_after_handoff_offer_before(
                        &mut recovery,
                        DaemonClientError::UnexpectedEof {
                            during: "reading post-start exact grid",
                        },
                        false,
                        budget,
                    ))
                }
                Err(error) => {
                    return Err(self.fail_after_handoff_offer_before(
                        &mut recovery,
                        error,
                        false,
                        budget,
                    ))
                }
            }
        }
    }

    fn fail_after_handoff_offer_before(
        &mut self,
        recovery: &mut ConditionalStartRecovery,
        source: DaemonClientError,
        _stream_is_frame_aligned: bool,
        _budget: &mut GenerationKillBudget,
    ) -> DaemonClientError {
        // No public authority exists yet. Closing the original connection is bounded and preserves
        // framing: daemon ClientState EOF retirement removes a pending Offer, while a Claim that
        // already won remains conservatively represented by the conditional-start recovery facts.
        recovery.handoff_seed = None;
        self.abort_connection();
        Self::conditional_start_possibly_applied(recovery, source)
    }

    fn conditional_start_possibly_applied(
        recovery: &ConditionalStartRecovery,
        source: DaemonClientError,
    ) -> DaemonClientError {
        DaemonClientError::ConditionalStartPossiblyApplied {
            id: recovery.session_id.clone(),
            recovery: recovery.clone(),
            source: Box::new(source),
        }
    }

    /// Attach to an already-retained session without sending any mutation request, returning after
    /// its first structured grid baseline. This is the safe app-upgrade path for an older daemon:
    /// legacy daemons remain useful for list/attach/read observation, while every mutation remains
    /// disabled unless exact protocol-v3 generation-conditional support is proved.
    pub fn attach_existing(&mut self, id: SessionId) -> Result<AttachedSession, DaemonClientError> {
        self.attach_existing_with_handoff(id, None, None, None)
    }

    /// Attach only if the daemon map still contains exact generation A. Capability proof, request,
    /// refusal/Grid, and socket restoration share this client's absolute operation deadline.
    pub(crate) fn attach_existing_if_generation(
        &mut self,
        id: SessionId,
        expected_generation: &str,
    ) -> Result<AttachedSession, DaemonClientError> {
        validate_expected_attach_generation(expected_generation)?;
        let mut budget = self.generation_kill_budget()?;
        let daemon_instance = self.require_generation_conditional_attach_before(&mut budget)?;
        let output_generation = self.allocate_output_generation()?;
        let result = self.attach_existing_with_handoff_before(
            id,
            expected_generation.to_string(),
            daemon_instance,
            output_generation,
            None,
            None,
            &mut budget,
        );
        let restored = self.restore_timeouts(&budget);
        match (result, restored) {
            (Ok(attached), Ok(())) => Ok(attached),
            (_, Err(error)) => {
                self.abort_connection();
                Err(error)
            }
            (Err(error), Ok(())) => Err(error),
        }
    }

    /// Attach an already-retained lifetime and offer its ownership to the intended renderer.
    /// Exact protocol/capability proof is required on this same socket so an older daemon cannot
    /// silently ignore the token and expose a starter-to-renderer kill gap.
    pub(crate) fn attach_existing_for_renderer(
        &mut self,
        id: SessionId,
    ) -> Result<AttachedSession, AttachmentHandoffFailure> {
        self.attach_existing_for_renderer_after_capability(id)
    }

    /// Publish one generation-bound Offer without first installing an ordinary forwarder. A
    /// successful exact Grid returns the Offer seed. Typed Missing closes the refusal-latched
    /// socket and reconnects to the exact same daemon instance/PID under this operation's shared
    /// deadline and unrelated-event counter, yielding one-shot authority for `Absent` Start.
    pub(crate) fn attach_existing_for_renderer_or_reconnect_missing(
        &mut self,
        id: SessionId,
        expected_generation: &str,
    ) -> Result<GenerationConditionalRendererAttach, AttachmentHandoffFailure> {
        validate_expected_attach_generation(expected_generation).map_err(|source| {
            AttachmentHandoffFailure {
                source,
                pending_seed: None,
            }
        })?;
        let mut budget =
            self.generation_kill_budget()
                .map_err(|source| AttachmentHandoffFailure {
                    source,
                    pending_seed: None,
                })?;
        let daemon_instance = self
            .require_generation_conditional_attach_before(&mut budget)
            .map_err(|source| AttachmentHandoffFailure {
                source,
                pending_seed: None,
            })?;
        let expected_peer = ConditionalStartPeerIdentity {
            daemon_instance_id: daemon_instance.clone(),
            server_pid: self.server_pid,
            child_environment: false,
        };
        let token: AttachmentHandoffToken = uuid::Uuid::new_v4()
            .simple()
            .to_string()
            .parse()
            .map_err(|error| AttachmentHandoffFailure {
                source: DaemonClientError::Protocol {
                    detail: format!("could not construct attachment handoff token: {error}"),
                },
                pending_seed: None,
            })?;
        let seed = AttachmentHandoffSeed {
            session_id: id.clone(),
            token: token.clone(),
            expected_daemon_instance: daemon_instance.clone(),
            expected_generation: Some(expected_generation.to_string()),
        };
        let output_generation =
            self.allocate_output_generation()
                .map_err(|source| AttachmentHandoffFailure {
                    source,
                    pending_seed: None,
                })?;
        let result = self.attach_existing_with_handoff_before(
            id,
            expected_generation.to_string(),
            daemon_instance.clone(),
            output_generation,
            Some(AttachmentHandoff::Offer { token }),
            Some(seed.clone()),
            &mut budget,
        );
        match result {
            Ok(attached) => match self.restore_timeouts(&budget) {
                Ok(()) => Ok(GenerationConditionalRendererAttach::Attached(attached)),
                Err(source) => {
                    self.abort_connection();
                    Err(AttachmentHandoffFailure {
                        source,
                        pending_seed: None,
                    })
                }
            },
            Err(DaemonClientError::ConditionalAttachRefused {
                reason: maestro_protocol::SessionAttachRefusal::Missing,
                ..
            }) => {
                // The exact refusal proves this Offer was never installed, but the daemon poisons
                // a handoff-bearing refusal socket so queued frames cannot overtake its ACK. Close
                // it and rejoin the same peer within the existing absolute/event budget.
                self.abort_connection();
                let replacement = self
                    .reconnect_same_daemon_before(&daemon_instance, &mut budget)
                    .map_err(|source| AttachmentHandoffFailure {
                        source,
                        pending_seed: None,
                    })?;
                if let Err(source) = replacement.restore_timeouts(&budget) {
                    replacement.abort_connection();
                    return Err(AttachmentHandoffFailure {
                        source,
                        pending_seed: None,
                    });
                }
                *self = replacement;
                Ok(GenerationConditionalRendererAttach::StartIfAbsent(
                    expected_peer,
                ))
            }
            Err(source) => {
                // No authority has escaped yet. Closing the original Offer connection is both
                // bounded and frame-safe; daemon-side ClientState EOF retirement removes a pending
                // token, while a Claim that already won remains conservatively attached.
                self.abort_connection();
                Err(AttachmentHandoffFailure {
                    source,
                    pending_seed: None,
                })
            }
        }
    }

    fn attach_existing_for_renderer_after_capability(
        &mut self,
        id: SessionId,
    ) -> Result<AttachedSession, AttachmentHandoffFailure> {
        let raw = uuid::Uuid::new_v4().simple().to_string();
        let token =
            AttachmentHandoffToken::try_from(raw).map_err(|error| AttachmentHandoffFailure {
                source: DaemonClientError::Protocol {
                    detail: format!("could not construct attachment handoff token: {error}"),
                },
                pending_seed: None,
            })?;
        let daemon_instance_id =
            self.daemon_instance_id
                .clone()
                .ok_or(AttachmentHandoffFailure {
                    source: DaemonClientError::MutationProtocolUnsupported {
                        required: maestro_protocol::DAEMON_PROTOCOL_VERSION,
                        observed: None,
                    },
                    pending_seed: None,
                })?;
        let seed = AttachmentHandoffSeed {
            session_id: id.clone(),
            token: token.clone(),
            expected_daemon_instance: daemon_instance_id,
            expected_generation: None,
        };
        let result = self.attach_existing_with_handoff(
            id.clone(),
            None,
            Some(AttachmentHandoff::Offer {
                token: token.clone(),
            }),
            Some(seed.clone()),
        );
        result.map_err(|source| {
            // The seed has not escaped. Do not append Cancel to a stream that may contain a partial
            // Attach frame; close it and let daemon-side EOF retirement settle any installed Offer.
            self.abort_connection();
            AttachmentHandoffFailure {
                source,
                pending_seed: None,
            }
        })
    }

    fn attach_existing_with_handoff_before(
        &mut self,
        id: SessionId,
        expected_generation: String,
        expected_daemon_instance: DaemonInstanceId,
        output_generation: u64,
        handoff: Option<AttachmentHandoff>,
        offered_seed: Option<AttachmentHandoffSeed>,
        budget: &mut GenerationKillBudget,
    ) -> Result<AttachedSession, DaemonClientError> {
        debug_assert_eq!(handoff.is_some(), offered_seed.is_some());
        self.send_before(
            &ClientRequest::Attach {
                id: id.clone(),
                want_raw_output: false,
                expected_session_generation: Some(expected_generation.clone()),
                output_generation: Some(output_generation),
                handoff,
            },
            budget,
            "publishing generation-conditional attach",
        )?;

        loop {
            match self.read_event_before(budget, "reading generation-conditional attach")? {
                Some(ShellEvent::Grid {
                    id: got,
                    output_generation: Some(got_output_generation),
                    grid,
                }) if got == id && got_output_generation == output_generation => {
                    if grid.generation != expected_generation {
                        return Err(DaemonClientError::Protocol {
                            detail: "conditional Attach Grid contradicted its daemon-atomic generation precondition".into(),
                        });
                    }
                    return Ok(AttachedSession {
                        id: got,
                        generation: grid.generation,
                        revision: grid.revision,
                        handoff_seed: offered_seed,
                    });
                }
                Some(ShellEvent::SessionAttachRefused {
                    id: got,
                    expected_generation: got_generation,
                    daemon_instance_id,
                    reason,
                }) if got == id
                    && got_generation == expected_generation
                    && daemon_instance_id == expected_daemon_instance =>
                {
                    return Err(DaemonClientError::ConditionalAttachRefused {
                        id: got,
                        expected_generation: got_generation,
                        reason,
                    })
                }
                Some(ShellEvent::SessionAttachRefused { .. }) => {
                    return Err(DaemonClientError::Protocol {
                        detail: "conditional Attach refusal did not match exact id, generation, and daemon instance".into(),
                    })
                }
                Some(ShellEvent::Grid { .. }) => {
                    budget.tolerate_unrelated("reading generation-conditional attach")?
                }
                Some(ShellEvent::SessionExited { id: got, code }) if got == id => {
                    return Err(DaemonClientError::SessionExited { id: got, code })
                }
                Some(ShellEvent::Error { message }) => {
                    return Err(DaemonClientError::DaemonError { message })
                }
                Some(_) => budget.tolerate_unrelated("reading generation-conditional attach")?,
                None => {
                    return Err(DaemonClientError::UnexpectedEof {
                        during: "reading generation-conditional attach",
                    })
                }
            }
        }
    }

    fn attach_existing_with_handoff(
        &mut self,
        id: SessionId,
        expected_session_generation: Option<String>,
        handoff: Option<AttachmentHandoff>,
        offered_seed: Option<AttachmentHandoffSeed>,
    ) -> Result<AttachedSession, DaemonClientError> {
        debug_assert_eq!(handoff.is_some(), offered_seed.is_some());
        let mut budget = self.reply_budget("awaiting grid baseline")?;
        self.send(&ClientRequest::Attach {
            id: id.clone(),
            want_raw_output: false,
            expected_session_generation,
            output_generation: None,
            handoff,
        })?;

        loop {
            match self.read_event("awaiting grid baseline", &mut budget)? {
                Some(ShellEvent::Grid { id: got, grid, .. }) if got == id => {
                    let handoff_seed = offered_seed.map(|mut seed| {
                        seed.expected_generation = Some(grid.generation.clone());
                        seed
                    });
                    return Ok(AttachedSession {
                        id: got,
                        generation: grid.generation,
                        revision: grid.revision,
                        handoff_seed,
                    });
                }
                // A grid for a different session (the daemon may multiplex) is not ours — skip it.
                Some(ShellEvent::Grid { .. }) => continue,
                Some(ShellEvent::SessionExited { id: got, code }) if got == id => {
                    return Err(DaemonClientError::SessionExited { id: got, code });
                }
                Some(ShellEvent::SessionExited { .. }) => continue,
                Some(ShellEvent::Error { message }) => {
                    return Err(DaemonClientError::DaemonError { message })
                }
                // Sessions reply / damage / output / future events before our grid: tolerate.
                Some(ShellEvent::Sessions { .. })
                | Some(ShellEvent::DaemonInfo { .. })
                | Some(ShellEvent::Other)
                | Some(ShellEvent::ConditionalSessionStart { .. })
                | Some(ShellEvent::StartOperationReserved { .. })
                | Some(ShellEvent::StartOperationStatus { .. })
                | Some(ShellEvent::StartOperationRetired { .. })
                | Some(ShellEvent::SessionAttachRefused { .. })
                | Some(ShellEvent::AttachmentHandoffCancelled { .. }) => continue,
                None => {
                    return Err(DaemonClientError::UnexpectedEof {
                        during: "awaiting grid baseline",
                    })
                }
            }
        }
    }

    /// Retire one known-abandoned renderer handoff and require the exact daemon-instance-bound ACK.
    fn cancel_attachment_handoff_exact(
        &mut self,
        id: &SessionId,
        token: &AttachmentHandoffToken,
        expected_daemon_instance: &DaemonInstanceId,
    ) -> Result<(), DaemonClientError> {
        let mut budget = self.generation_kill_budget()?;
        let result = self.cancel_attachment_handoff_exact_before(
            id,
            token,
            expected_daemon_instance,
            &mut budget,
        );
        let _ = self.restore_timeouts(&budget);
        result
    }

    fn cancel_attachment_handoff_exact_before(
        &mut self,
        id: &SessionId,
        token: &AttachmentHandoffToken,
        expected_daemon_instance: &DaemonInstanceId,
        budget: &mut GenerationKillBudget,
    ) -> Result<(), DaemonClientError> {
        if self.daemon_instance_id.as_ref() != Some(expected_daemon_instance) {
            return Err(DaemonClientError::Protocol {
                detail: "attachment handoff cancellation targeted a different daemon instance"
                    .into(),
            });
        }
        self.send_before(
            &ClientRequest::CancelAttachmentHandoff {
                id: id.clone(),
                token: token.clone(),
                expected_daemon_instance: expected_daemon_instance.clone(),
            },
            budget,
            "publishing attachment handoff cancellation",
        )?;
        loop {
            match self.read_event_before(
                budget,
                "reading attachment handoff cancellation acknowledgement",
            )? {
                Some(ShellEvent::AttachmentHandoffCancelled {
                    id: acknowledged_id,
                    token: acknowledged_token,
                    daemon_instance_id,
                }) if &acknowledged_id == id
                    && &acknowledged_token == token
                    && &daemon_instance_id == expected_daemon_instance =>
                {
                    return Ok(())
                }
                Some(ShellEvent::AttachmentHandoffCancelled { .. }) => {
                    return Err(DaemonClientError::Protocol {
                        detail: "attachment handoff cancellation acknowledgement did not match exact authority".into(),
                    })
                }
                Some(ShellEvent::Error { message }) => {
                    return Err(DaemonClientError::DaemonError { message })
                }
                Some(_) => budget.tolerate_unrelated(
                    "reading attachment handoff cancellation acknowledgement",
                )?,
                None => {
                    return Err(DaemonClientError::UnexpectedEof {
                        during: "reading attachment handoff cancellation acknowledgement",
                    })
                }
            }
        }
    }

    pub(crate) fn cancel_attachment_handoff_seed(
        &mut self,
        seed: &AttachmentHandoffSeed,
    ) -> Result<(), DaemonClientError> {
        self.cancel_attachment_handoff_exact(
            &seed.session_id,
            &seed.token,
            &seed.expected_daemon_instance,
        )
    }

    /// String-id convenience for consumers that intentionally depend only on `maestro-shell`'s
    /// reviewed handoff surface. Validation remains daemon-side and a failed write is a safe leak.
    pub fn cancel_attachment_handoff_for_session(
        &self,
        session_id: &str,
        authority: AttachmentHandoffAuthority,
    ) -> Result<AttachmentHandoffClaimStatus, AttachmentHandoffCancelError> {
        if authority.session_id().0 != session_id {
            return Err(AttachmentHandoffCancelError {
                claim_status: authority.claim_status(),
                source: DaemonClientError::Protocol {
                    detail: "attachment handoff cancellation session did not match authority"
                        .into(),
                },
            });
        }
        authority.cancel()
    }

    /// Kill and remove one live session, then confirm it is no longer in the daemon's live list.
    ///
    /// Uses the protocol-v3 conditional daemon `Kill` request, carrying the exact PTY generation.
    /// Because `Kill` has no direct ack for a non-attached client, success is NOT
    /// inferred from the send succeeding; it is confirmed by a subsequent `ListSessions` whose
    /// `Sessions` reply does not contain `id`.
    ///
    /// Flow: prove v3+capability -> send `Kill{id,expected_generation}` -> send `ListSessions` ->
    /// read until `Sessions`. If `id` is absent,
    /// return `Ok(KilledSession{id})`. If it is still present (a daemon `Sessions` snapshot taken
    /// before the kill landed), send another `ListSessions` and re-check, up to
    /// [`KILL_CONFIRM_ROUNDS`] times. Unrelated `Grid` / `SessionExited` / `Other` events are
    /// tolerated while waiting. A daemon `Error` becomes [`DaemonClientError::DaemonError`]; EOF,
    /// timeout, oversized line, protocol, and I/O faults surface through the existing typed errors.
    ///
    /// Idempotent: an already-absent session is `Ok` — this means "no longer live", not "this client
    /// killed it". That is the right shape for tab-close cleanup, where repeated cleanup or a
    /// naturally exited session must not become a fatal user-facing error. The whole capability +
    /// Kill + confirmation sequence has one absolute [`GENERATION_KILL_DEADLINE_MS`] wall-clock
    /// budget and one unrelated-event budget, so neither slow trickles nor a readable event flood
    /// can hold a release-journal lease forever.
    pub fn kill_session_if_generation(
        &mut self,
        id: SessionId,
        expected_generation: impl Into<String>,
    ) -> Result<KilledSession, DaemonClientError> {
        self.kill_session_if_generation_with_publication(id, expected_generation)
            .map_err(KillSessionPublicationError::into_daemon_error)
    }

    /// Publication-aware form of [`Self::kill_session_if_generation`] for callers that may
    /// compensate or forward-commit durable ownership after a failure.
    ///
    /// Every failure before the Kill frame's first socket-write attempt is `NotPublished`. From
    /// immediately before that attempt through all ListSessions confirmation work, failures are
    /// `PossiblyPublished`; a lost confirmation is not evidence that the daemon did nothing.
    pub fn kill_session_if_generation_with_publication(
        &mut self,
        id: SessionId,
        expected_generation: impl Into<String>,
    ) -> Result<KilledSession, KillSessionPublicationError> {
        let expected_generation = expected_generation.into();
        if expected_generation.is_empty() {
            return Err(KillSessionPublicationError::NotPublished {
                source: DaemonClientError::Protocol {
                    detail: "terminal mutation requires a non-empty PTY generation".into(),
                },
            });
        }
        let mut budget = self
            .generation_kill_budget()
            .map_err(|source| KillSessionPublicationError::NotPublished { source })?;
        let result = self.kill_session_if_generation_before(id, expected_generation, &mut budget);
        let restored = self.restore_timeouts(&budget);
        match (result, restored) {
            (Ok(killed), Ok(())) => Ok(killed),
            (Ok(_), Err(source)) => Err(KillSessionPublicationError::PossiblyPublished { source }),
            (Err(error), _) => Err(error),
        }
    }

    /// Release one exact daemon lifetime for the durable journal. Unlike the compatibility Kill
    /// wrapper above, this path first obtains a strict generation snapshot, treats a different
    /// live same-id generation as proof the old lifetime is gone, and sends the exact conditional
    /// Kill when the expected generation is live *or absent from the live-only snapshot*. The
    /// latter is required to remove a retained exited session. Strict generation metadata is used
    /// during confirmation, and one absolute/event budget covers the whole one-socket attempt.
    pub(crate) fn release_session_lifetime_with_publication(
        &mut self,
        id: SessionId,
        expected_generation: impl Into<String>,
    ) -> Result<(), KillSessionPublicationError> {
        let expected_generation = expected_generation.into();
        if expected_generation.is_empty() || expected_generation.len() > 128 {
            return Err(KillSessionPublicationError::NotPublished {
                source: DaemonClientError::Protocol {
                    detail: "terminal release requires a generation length of 1..=128 bytes".into(),
                },
            });
        }
        let mut budget = self
            .generation_kill_budget()
            .map_err(|source| KillSessionPublicationError::NotPublished { source })?;
        let result = self.release_session_lifetime_before(id, &expected_generation, &mut budget);
        // Timeout restoration is connection hygiene, not a daemon-lifetime fact. Once the strict
        // snapshot or exact Kill confirmation proves the old generation gone, a local setsockopt
        // failure must never downgrade that proof into compensation authority. Callers may discard
        // the client independently after this attempt.
        let restored = self.restore_timeouts(&budget);
        finalize_exact_lifetime_release(result, restored)
    }

    fn release_session_lifetime_before(
        &mut self,
        id: SessionId,
        expected_generation: &str,
        budget: &mut GenerationKillBudget,
    ) -> Result<(), KillSessionPublicationError> {
        let snapshot = self
            .generation_mutation_snapshot_before(budget)
            .map_err(|source| KillSessionPublicationError::NotPublished { source })?;
        if snapshot
            .generation_for(&id.0)
            .is_some_and(|generation| generation != expected_generation)
        {
            return Ok(());
        }

        let kill_line = Self::encode_request(&ClientRequest::Kill {
            id: id.clone(),
            expected_generation: expected_generation.to_string(),
        })
        .map_err(|source| KillSessionPublicationError::NotPublished { source })?;
        self.write_encoded_request_before(
            &kill_line,
            budget,
            "publishing exact session lifetime release",
        )
        .map_err(|failure| {
            if failure.write_attempted {
                KillSessionPublicationError::PossiblyPublished {
                    source: failure.source,
                }
            } else {
                KillSessionPublicationError::NotPublished {
                    source: failure.source,
                }
            }
        })?;

        for _ in 0..KILL_CONFIRM_ROUNDS {
            self.send_before(
                &ClientRequest::ListSessions,
                budget,
                "publishing exact lifetime confirmation request",
            )
            .map_err(|source| KillSessionPublicationError::PossiblyPublished { source })?;
            let snapshot = self
                .read_generation_snapshot_reply_before(budget, "confirming exact lifetime release")
                .map_err(|source| KillSessionPublicationError::PossiblyPublished { source })?;
            if snapshot.generation_for(&id.0) != Some(expected_generation) {
                return Ok(());
            }
        }
        Err(KillSessionPublicationError::PossiblyPublished {
            source: DaemonClientError::Protocol {
                detail: format!(
                    "session {id:?} retained generation {expected_generation:?} after \
                     {KILL_CONFIRM_ROUNDS} exact lifetime confirmation rounds"
                ),
            },
        })
    }

    fn kill_session_if_generation_before(
        &mut self,
        id: SessionId,
        expected_generation: String,
        budget: &mut GenerationKillBudget,
    ) -> Result<KilledSession, KillSessionPublicationError> {
        self.require_generation_conditional_mutations_before(budget)
            .map_err(|source| KillSessionPublicationError::NotPublished { source })?;
        // 1) Ask the daemon to kill and drop the session. No ack is expected for a non-attached
        //    client, so this is fire-and-confirm: the ListSessions round below is the source of
        //    truth, not the success of this write.
        let kill_line = Self::encode_request(&ClientRequest::Kill {
            id: id.clone(),
            expected_generation,
        })
        .map_err(|source| KillSessionPublicationError::NotPublished { source })?;
        // This is the publication boundary. A socket `write` may partially write before returning
        // an error, and `flush` failure likewise cannot establish that the daemon saw nothing.
        self.write_encoded_request_before(
            &kill_line,
            budget,
            "publishing generation-conditional kill",
        )
        .map_err(|failure| {
            if failure.write_attempted {
                KillSessionPublicationError::PossiblyPublished {
                    source: failure.source,
                }
            } else {
                KillSessionPublicationError::NotPublished {
                    source: failure.source,
                }
            }
        })?;

        // 2) Confirm absence via ListSessions. Re-issue a bounded number of times so a daemon that
        //    answers with a pre-kill snapshot on the first round still converges, while a daemon
        //    that keeps reporting the id cannot wedge us — the rounds are finite and each read is
        //    timeout-bounded.
        for _ in 0..KILL_CONFIRM_ROUNDS {
            self.send_before(
                &ClientRequest::ListSessions,
                budget,
                "publishing kill confirmation request",
            )
            .map_err(|source| KillSessionPublicationError::PossiblyPublished { source })?;
            loop {
                match self
                    .read_event_before(budget, "confirming kill via list_sessions")
                    .map_err(|source| KillSessionPublicationError::PossiblyPublished { source })?
                {
                    Some(ShellEvent::Sessions { ids, .. }) => {
                        if !ids.contains(&id) {
                            budget
                                .remaining("confirming kill via list_sessions")
                                .map_err(|source| {
                                    KillSessionPublicationError::PossiblyPublished { source }
                                })?;
                            return Ok(KilledSession { id });
                        }
                        // Still present: break to the outer loop and re-issue ListSessions.
                        break;
                    }
                    Some(ShellEvent::Error { message }) => {
                        return Err(KillSessionPublicationError::PossiblyPublished {
                            source: DaemonClientError::DaemonError { message },
                        })
                    }
                    // A Grid / SessionExited / blank line here is unrelated to our confirmation —
                    // tolerate and keep reading for the Sessions reply.
                    Some(_) => budget
                        .tolerate_unrelated("confirming kill via list_sessions")
                        .map_err(|source| KillSessionPublicationError::PossiblyPublished {
                            source,
                        })?,
                    None => {
                        return Err(KillSessionPublicationError::PossiblyPublished {
                            source: DaemonClientError::UnexpectedEof {
                                during: "confirming kill via list_sessions",
                            },
                        })
                    }
                }
            }
        }

        // The id was still present after every bounded confirmation round. Surface this as a
        // protocol-level failure rather than blocking — the kill did not take effect within the
        // confirmation budget.
        Err(KillSessionPublicationError::PossiblyPublished {
            source: DaemonClientError::Protocol {
                detail: format!(
                    "session {id:?} still present after {KILL_CONFIRM_ROUNDS} kill confirmation rounds"
                ),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::{UnixListener, UnixStream as StdUnixStream};
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::thread::JoinHandle;

    #[test]
    fn kernel_peer_identity_accepts_only_the_same_effective_uid() {
        let path = Path::new("/tmp/synthetic-daemon.sock");
        assert!(verify_connected_server_identity(path, 501, Ok(501)).is_ok());

        let mismatch = verify_connected_server_identity(path, 501, Ok(502))
            .expect_err("a different OS user must never be accepted as the daemon");
        assert!(matches!(
            mismatch,
            DaemonClientError::UntrustedDaemon {
                expected_uid: 501,
                observed_uid: Some(502),
                ..
            }
        ));

        let unavailable = verify_connected_server_identity(
            path,
            501,
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "synthetic missing peer credentials",
            )),
        )
        .expect_err("an unidentifiable server must fail closed");
        assert!(matches!(
            unavailable,
            DaemonClientError::UntrustedDaemon {
                expected_uid: 501,
                observed_uid: None,
                ..
            }
        ));
    }

    #[test]
    fn connected_local_stub_reports_this_process_as_its_server_owner() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peer-identity.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let connector = std::thread::spawn({
            let path = path.clone();
            move || StdUnixStream::connect(path).unwrap()
        });
        let (server, _) = listener.accept().unwrap();
        let client = connector.join().unwrap();

        assert_eq!(connected_server_uid(&client).unwrap(), effective_uid());
        assert_eq!(connected_server_uid(&server).unwrap(), effective_uid());
        #[cfg(target_os = "linux")]
        {
            assert_eq!(connected_server_credentials(&client).unwrap().pid, unsafe {
                libc::getpid()
            });
            assert_eq!(connected_server_credentials(&server).unwrap().pid, unsafe {
                libc::getpid()
            });
        }
    }

    /// A loopback stub daemon: a real Unix socket on a temp path, served by one accept thread that
    /// runs a caller-supplied script `(reader, writer) -> ()`. This is NOT the real daemon — it lets
    /// us assert exactly what the client writes and control exactly what it reads, with no PTY, no
    /// git, and no `pty-daemon` process. The captured request lines are sent back over an mpsc so the
    /// test can assert their JSON shape.
    struct StubDaemon {
        path: PathBuf,
        // Kept so the socket file + temp dir outlive the test; dropping cleans them up.
        _dir: tempfile::TempDir,
        handle: Option<JoinHandle<()>>,
        requests: mpsc::Receiver<String>,
    }

    impl StubDaemon {
        /// Spawn a stub that, on the first connection, runs `serve(reader_lines_tx, writer)`. The
        /// closure receives a channel to publish each request line it reads (for assertions) and the
        /// write half to push replies.
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
                    serve(&req_tx, &mut stream);
                    // Dropping the stream closes the peer (the client sees EOF).
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

        /// Collect all request lines the stub recorded (after the serve closure has finished).
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

    /// Read one newline-delimited request line from `stream` and publish it on `tx`. Returns the
    /// parsed line (trimmed), or None on EOF.
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

    fn sid(s: &str) -> SessionId {
        SessionId(s.to_string())
    }

    fn strict_daemon_info_line(instance: &str, conditional_attach: bool) -> String {
        strict_daemon_info_line_with_child_environment(instance, conditional_attach, true)
    }

    fn strict_daemon_info_line_with_child_environment(
        instance: &str,
        conditional_attach: bool,
        child_environment: bool,
    ) -> String {
        serde_json::json!({
            "ev": "daemon_info",
            "protocol_version": maestro_protocol::DAEMON_PROTOCOL_VERSION,
            "build_version": "conditional-attach-test",
            "daemon_instance_id": instance,
            "output_generation_echo": true,
            "child_environment": child_environment,
            "generation_conditional_mutations": true,
            "attachment_aware_conditional_kill": true,
            "generation_conditional_start": true,
            "start_operation_ledger": true,
            "generation_conditional_attach": conditional_attach,
        })
        .to_string()
    }

    #[test]
    fn renderer_conditional_attach_uses_one_offer_without_a_probe_forwarder_window() {
        let instance = "22222222222242228222222222222222";
        let instance_for_stub = instance.to_string();
        let stub = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert!(matches!(
                serde_json::from_str::<ClientRequest>(
                    &read_request(&mut reader, tx).expect("DaemonInfo request")
                )
                .unwrap(),
                ClientRequest::DaemonInfo
            ));
            writeln!(
                stream,
                "{}",
                strict_daemon_info_line(&instance_for_stub, true)
            )
            .unwrap();
            stream.flush().unwrap();

            let attach_line = read_request(&mut reader, tx).expect("single conditional Offer");
            let attach: ClientRequest = serde_json::from_str(&attach_line).unwrap();
            assert!(matches!(
                attach,
                ClientRequest::Attach {
                    ref id,
                    expected_session_generation: Some(ref generation),
                    output_generation: Some(1),
                    handoff: Some(AttachmentHandoff::Offer { .. }),
                    ..
                } if id == &sid("exact-A") && generation == "generation-A"
            ));
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "grid",
                    "id": "exact-A",
                    "output_generation": 1,
                    "grid": {"generation": "generation-A", "revision": 8}
                })
            )
            .unwrap();
            stream.flush().unwrap();
            let _ = read_request(&mut reader, tx);
        });

        let mut client = DaemonClient::connect_for_generation_mutation_before(
            &stub.path,
            Duration::from_secs(2),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        let GenerationConditionalRendererAttach::Attached(mut offered) = client
            .attach_existing_for_renderer_or_reconnect_missing(sid("exact-A"), "generation-A")
            .unwrap()
        else {
            panic!("exact live A must return its single Offer")
        };
        assert_eq!(offered.generation, "generation-A");
        let seed = offered
            .take_attachment_handoff_seed()
            .expect("exact Offer seed");
        assert_eq!(seed.expected_generation.as_deref(), Some("generation-A"));
        client.abort_connection();
        drop(client);
        assert_eq!(
            stub.collected_requests().len(),
            2,
            "renderer path must send one DaemonInfo and one Offer Attach only"
        );
    }

    #[test]
    fn conditional_attach_missing_is_exact_and_retains_same_deadline_peer() {
        let instance = "33333333333343338333333333333333";
        let instance_for_stub = instance.to_string();
        let stub = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert!(read_request(&mut reader, tx)
                .unwrap()
                .contains("daemon_info"));
            writeln!(
                stream,
                "{}",
                strict_daemon_info_line(&instance_for_stub, true)
            )
            .unwrap();
            stream.flush().unwrap();
            let attach: ClientRequest =
                serde_json::from_str(&read_request(&mut reader, tx).unwrap()).unwrap();
            assert!(matches!(
                attach,
                ClientRequest::Attach {
                    output_generation: Some(1),
                    ..
                }
            ));
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "session_attach_refused",
                    "id": "missing-A",
                    "expected_generation": "generation-A",
                    "daemon_instance_id": instance_for_stub,
                    "reason": "missing"
                })
            )
            .unwrap();
            stream.flush().unwrap();
            assert!(read_request(&mut reader, tx)
                .unwrap()
                .contains("daemon_info"));
            writeln!(stream, "{}", strict_daemon_info_line(instance, true)).unwrap();
            stream.flush().unwrap();
            let _ = read_request(&mut reader, tx);
        });

        let mut client = DaemonClient::connect_for_generation_mutation_before(
            &stub.path,
            Duration::from_secs(2),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        assert!(matches!(
            client.attach_existing_if_generation(sid("missing-A"), "generation-A"),
            Err(DaemonClientError::ConditionalAttachRefused {
                reason: SessionAttachRefusal::Missing,
                ..
            })
        ));
        let peer = client
            .conditional_start_peer_identity_before_current_deadline()
            .unwrap();
        assert_eq!(peer.daemon_instance_id.as_str(), instance);
        client.abort_connection();
    }

    #[test]
    fn renderer_missing_offer_reconnects_to_the_exact_peer_under_the_same_budget() {
        let instance = "55555555555545559555555555555555";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("renderer-missing-reconnect.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (request_tx, request_rx) = mpsc::channel();
        let expected_instance = instance.to_string();
        let server = std::thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            let mut first_reader = BufReader::new(first.try_clone().unwrap());
            assert!(read_request(&mut first_reader, &request_tx)
                .unwrap()
                .contains("daemon_info"));
            writeln!(
                first,
                "{}",
                strict_daemon_info_line(&expected_instance, true)
            )
            .unwrap();
            first.flush().unwrap();
            let attach: ClientRequest = serde_json::from_str(
                &read_request(&mut first_reader, &request_tx).expect("single Offer Attach"),
            )
            .unwrap();
            assert!(matches!(
                attach,
                ClientRequest::Attach {
                    expected_session_generation: Some(ref generation),
                    handoff: Some(AttachmentHandoff::Offer { .. }),
                    output_generation: Some(1),
                    ..
                } if generation == "generation-A"
            ));
            writeln!(
                first,
                "{}",
                serde_json::json!({
                    "ev": "session_attach_refused",
                    "id": "missing-A",
                    "expected_generation": "generation-A",
                    "daemon_instance_id": expected_instance,
                    "reason": "missing"
                })
            )
            .unwrap();
            first.flush().unwrap();

            let (mut replacement, _) = listener.accept().unwrap();
            let mut replacement_reader = BufReader::new(replacement.try_clone().unwrap());
            assert!(read_request(&mut replacement_reader, &request_tx)
                .unwrap()
                .contains("daemon_info"));
            writeln!(replacement, "{}", strict_daemon_info_line(instance, true)).unwrap();
            replacement.flush().unwrap();
            let _ = read_request(&mut replacement_reader, &request_tx);
        });

        let mut client = DaemonClient::connect_for_generation_mutation_before(
            &path,
            Duration::from_secs(2),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        let GenerationConditionalRendererAttach::StartIfAbsent(peer) = client
            .attach_existing_for_renderer_or_reconnect_missing(sid("missing-A"), "generation-A")
            .unwrap()
        else {
            panic!("typed Missing must return exact-peer Absent authority")
        };
        assert_eq!(peer.daemon_instance_id.as_str(), instance);
        client.abort_connection();
        drop(client);
        server.join().unwrap();
        assert_eq!(
            request_rx.try_iter().count(),
            3,
            "one Offer socket plus one exact-peer reconnect capability probe"
        );
    }

    #[test]
    fn output_route_exhaustion_fails_before_any_attach_write() {
        let (client_stream, mut server_stream) = StdUnixStream::pair().unwrap();
        server_stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut client = DaemonClient::from_connected_stream(
            Path::new("/tmp/output-route-exhaustion.sock"),
            client_stream,
            Duration::from_secs(1),
            None,
        )
        .unwrap();
        client.next_output_generation = u64::MAX;
        assert!(matches!(
            client.allocate_output_generation(),
            Err(DaemonClientError::Protocol { .. })
        ));
        let mut byte = [0_u8; 1];
        assert!(matches!(
            server_stream.read(&mut byte),
            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)
        ));
    }

    #[test]
    fn partial_conditional_attach_capability_sends_zero_attach_bytes() {
        let instance = "44444444444444448444444444444444";
        let stub = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert!(read_request(&mut reader, tx)
                .unwrap()
                .contains("daemon_info"));
            writeln!(stream, "{}", strict_daemon_info_line(instance, false)).unwrap();
            stream.flush().unwrap();
            let _ = read_request(&mut reader, tx);
        });
        let mut client = DaemonClient::connect_for_generation_mutation_before(
            &stub.path,
            Duration::from_secs(2),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        assert!(matches!(
            client.attach_existing_if_generation(sid("exact-A"), "generation-A"),
            Err(DaemonClientError::MutationProtocolUnsupported { .. })
        ));
        client.abort_connection();
        drop(client);
        let requests = stub.collected_requests();
        assert_eq!(
            requests.len(),
            1,
            "partial capability must stop before Attach"
        );
    }

    #[test]
    fn conditional_start_without_operation_ledger_sends_zero_reserve_or_start_bytes() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let instance = "6666666666664666a666666666666666";
        let stub = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"daemon_info"}"#)
            );
            let mut info: serde_json::Value =
                serde_json::from_str(&strict_daemon_info_line(instance, true)).unwrap();
            info["start_operation_ledger"] = serde_json::Value::Bool(false);
            writeln!(stream, "{info}").unwrap();
            stream.flush().unwrap();
            let _ = read_request(&mut reader, tx);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        assert!(matches!(
            client.start_and_attach(sid("s1"), &cwd_path, "sh", &[], 80, 24),
            Err(DaemonClientError::MutationProtocolUnsupported { .. })
        ));
        client.abort_connection();
        drop(client);
        assert_eq!(
            stub.collected_requests(),
            vec![r#"{"op":"daemon_info"}"#.to_string()],
            "generation-conditional Start alone is insufficient; no Reserve or Start may cross"
        );
    }

    #[test]
    fn twice_ambiguous_reservation_preserves_opaque_cleanup_authority() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ambiguous-reserve.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (request_tx, request_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let instance = "22222222222242228222222222222222";
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                assert_eq!(
                    read_request(&mut reader, &request_tx).as_deref(),
                    Some(r#"{"op":"daemon_info"}"#)
                );
                writeln!(stream, "{}", strict_daemon_info_line(instance, true)).unwrap();
                stream.flush().unwrap();
                assert!(matches!(
                    serde_json::from_str::<ClientRequest>(
                        &read_request(&mut reader, &request_tx).expect("ReserveStartOperation")
                    )
                    .unwrap(),
                    ClientRequest::ReserveStartOperation { .. }
                ));
                // The reservation may already have linearized, but neither attempt receives its
                // acknowledgement. Closing both copies forces the bounded recovery result.
                drop(reader);
                drop(stream);
            }
        });

        let mut client = DaemonClient::connect(&path).unwrap();
        let recovery = match client
            .start_and_attach(sid("s1"), &cwd_path, "sh", &[], 80, 24)
            .unwrap_err()
        {
            DaemonClientError::ConditionalStartPossiblyApplied {
                recovery, source, ..
            } => {
                assert!(matches!(*source, DaemonClientError::UnexpectedEof { .. }));
                recovery
            }
            other => panic!("expected recovery-bearing reservation ambiguity, got {other:?}"),
        };
        assert_eq!(recovery.session_id(), &sid("s1"));
        assert_eq!(recovery.operation_applied_generation(), None);
        assert_eq!(recovery.grid_proven_generation(), None);
        client.abort_connection();
        drop(client);
        server.join().unwrap();

        let requests: Vec<_> = request_rx.try_iter().collect();
        assert_eq!(requests.len(), 4);
        let first: ClientRequest = serde_json::from_str(&requests[1]).unwrap();
        let second: ClientRequest = serde_json::from_str(&requests[3]).unwrap();
        let first_token = match first {
            ClientRequest::ReserveStartOperation {
                operation_token, ..
            } => operation_token,
            other => panic!("expected first ReserveStartOperation, got {other:?}"),
        };
        let second_token = match second {
            ClientRequest::ReserveStartOperation {
                operation_token, ..
            } => operation_token,
            other => panic!("expected replayed ReserveStartOperation, got {other:?}"),
        };
        assert_eq!(first_token, second_token);
        assert_eq!(recovery.operation_token, first_token);
    }

    #[test]
    fn already_applied_exited_operation_cannot_turn_retained_grid_into_live_success() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"daemon_info"}"#)
            );
            let instance = "22222222222242228222222222222222";
            writeln!(stream, "{}", strict_daemon_info_line(instance, true)).unwrap();
            stream.flush().unwrap();
            let reserve: ClientRequest = serde_json::from_str(
                &read_request(&mut reader, tx).expect("ReserveStartOperation"),
            )
            .unwrap();
            let operation_token = match reserve {
                ClientRequest::ReserveStartOperation {
                    id,
                    operation_token,
                } => {
                    assert_eq!(id, sid("s1"));
                    operation_token
                }
                other => panic!("expected ReserveStartOperation, got {other:?}"),
            };
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "start_operation_reserved",
                    "id": "s1",
                    "operation_token": operation_token.as_str(),
                    "daemon_instance_id": instance,
                    "outcome": {"status": "refused", "reason": "already_terminal"}
                })
            )
            .unwrap();
            stream.flush().unwrap();
            assert!(matches!(
                serde_json::from_str::<ClientRequest>(
                    &read_request(&mut reader, tx).expect("terminal LookupStartOperation")
                )
                .unwrap(),
                ClientRequest::LookupStartOperation { .. }
            ));
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "start_operation_status",
                    "id": "s1",
                    "operation_token": operation_token.as_str(),
                    "daemon_instance_id": instance,
                    "status": {
                        "status": "applied",
                        "generation": "gen-exited",
                        "lifecycle": "exited"
                    }
                })
            )
            .unwrap();
            stream.flush().unwrap();
            let _ = read_request(&mut reader, tx);
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        match client
            .start_and_attach(sid("s1"), &cwd_path, "sh", &[], 80, 24)
            .unwrap_err()
        {
            DaemonClientError::ConditionalStartPossiblyApplied {
                recovery, source, ..
            } => {
                assert_eq!(recovery.operation_applied_generation(), Some("gen-exited"));
                assert_eq!(recovery.grid_proven_generation(), None);
                assert!(matches!(
                    *source,
                    DaemonClientError::StartOperationTerminal {
                        status: SessionStartOperationStatus::Applied {
                            lifecycle: SessionStartOperationLifecycle::Exited,
                            ..
                        },
                        ..
                    }
                ));
            }
            other => panic!("expected Exited operation recovery, got {other:?}"),
        }
        client.abort_connection();
        drop(client);
        assert_eq!(
            stub.collected_requests().len(),
            3,
            "known Exited must stop before Start or Attach"
        );
    }

    fn authority_pair() -> (AttachmentHandoffAuthority, StdUnixStream) {
        let (client_stream, server_stream) = StdUnixStream::pair().unwrap();
        let instance: DaemonInstanceId = "22222222222242228222222222222222".parse().unwrap();
        let token: AttachmentHandoffToken = "0123456789abcdef0123456789abcdef".parse().unwrap();
        let mut client = DaemonClient::from_connected_stream(
            Path::new("/tmp/renderer-handoff-authority-test.sock"),
            client_stream,
            Duration::from_secs(2),
            None,
        )
        .unwrap();
        client.daemon_instance_id = Some(instance.clone());
        let authority = AttachmentHandoffAuthority::from_offer(
            AttachmentHandoffSeed {
                session_id: sid("sid-B"),
                token,
                expected_daemon_instance: instance,
                expected_generation: Some("gen-C".to_string()),
            },
            client,
        );
        (authority, server_stream)
    }

    #[test]
    fn attachment_handoff_cancel_io_does_not_block_exact_claim_proof() {
        let (authority, mut server) = authority_pair();
        let expected_pid = authority.expected_server_pid();
        let clone = authority.clone();
        assert_eq!(clone.expected_server_pid(), expected_pid);
        assert_eq!(clone.expected_generation(), "gen-C");
        assert_eq!(
            format!("{clone:?}"),
            "AttachmentHandoffAuthority(<redacted>)"
        );

        let (request_seen_tx, request_seen_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let server_thread = std::thread::spawn(move || {
            let mut reader = BufReader::new(server.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.contains("cancel_attachment_handoff"));
            request_seen_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            server
                .write_all(b"{\"ev\":\"attachment_handoff_cancelled\",\"id\":\"sid-B\",\"token\":\"0123456789abcdef0123456789abcdef\",\"daemon_instance_id\":\"22222222222242228222222222222222\"}\n")
                .unwrap();
            server.flush().unwrap();
        });
        let cancelling = authority.clone();
        let cancel_thread = std::thread::spawn(move || cancelling.cancel());
        request_seen_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("cancel entered socket I/O");

        authority.mark_claim_admitted();
        let started = Instant::now();
        authority.mark_claimed();
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "Grid proof must not wait for cancellation socket I/O"
        );
        release_tx.send(()).unwrap();
        assert_eq!(
            cancel_thread.join().unwrap().unwrap(),
            AttachmentHandoffClaimStatus::PossiblyApplied
        );
        server_thread.join().unwrap();
        assert_eq!(
            authority.claim_status(),
            AttachmentHandoffClaimStatus::PossiblyApplied
        );
        assert!(matches!(
            &*authority
                .core
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            AttachmentHandoffAuthorityState::Claimed
        ));
    }

    #[test]
    fn late_exact_grid_proof_upgrades_cancelled_authority_to_claimed() {
        let (authority, mut server) = authority_pair();
        let server_thread = std::thread::spawn(move || {
            let mut reader = BufReader::new(server.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            server
                .write_all(b"{\"ev\":\"attachment_handoff_cancelled\",\"id\":\"sid-B\",\"token\":\"0123456789abcdef0123456789abcdef\",\"daemon_instance_id\":\"22222222222242228222222222222222\"}\n")
                .unwrap();
            server.flush().unwrap();
        });
        assert_eq!(
            authority.cancel().unwrap(),
            AttachmentHandoffClaimStatus::Unpublished
        );
        server_thread.join().unwrap();
        authority.mark_claim_admitted();
        authority.mark_claimed();
        assert_eq!(
            authority.claim_status(),
            AttachmentHandoffClaimStatus::PossiblyApplied
        );
        assert!(matches!(
            &*authority
                .core
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            AttachmentHandoffAuthorityState::Claimed
        ));
    }

    /// A canonical full daemon `Grid` line for session `id` at the given generation/revision — the
    /// heavy snapshot the client must read `generation`/`revision` out of without modeling cells.
    fn grid_line(id: &str, generation: &str, revision: u64) -> String {
        format!(
            r#"{{"ev":"grid","id":"{id}","grid":{{"version":2,"generation":"{generation}","revision":{revision},"base_revision":0,"cols":1,"rows":1,"rows_cells":[[{{"text":"x","fg":{{"kind":"named","name":"foreground"}},"bg":{{"kind":"named","name":"background"}},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":1}}]],"cursor_line":0,"cursor_col":0,"cursor_visible":true,"cursor_shape":"block","alt_screen":false,"app_cursor":false,"bracketed_paste":false,"focus_reporting":false,"mouse_report":false,"mouse_drag":false,"mouse_motion":false,"mouse_sgr":false}}}}"#
        )
    }

    fn routed_grid_line(
        id: &str,
        generation: &str,
        revision: Option<u64>,
        output_generation: u64,
    ) -> String {
        let mut value: serde_json::Value = serde_json::from_str(&match revision {
            Some(revision) => grid_line(id, generation, revision),
            None => {
                format!(r#"{{"ev":"grid","id":"{id}","grid":{{"generation":"{generation}"}}}}"#)
            }
        })
        .unwrap();
        value["output_generation"] = serde_json::json!(output_generation);
        value.to_string()
    }

    /// Drive the capability -> Reserve -> Start ACK -> exact Attach prefix used by conditional
    /// start tests. Returns the decoded Start request and the Attach route generation so each test
    /// can choose its own terminal reply (Grid, exit, error, malformed line, etc.).
    fn accept_conditional_start_prefix(
        reader: &mut impl BufRead,
        tx: &mpsc::Sender<String>,
        stream: &mut StdUnixStream,
        expected_id: &str,
        generation: &str,
    ) -> (ClientRequest, u64) {
        assert_eq!(
            read_request(reader, tx).as_deref(),
            Some(r#"{"op":"daemon_info"}"#)
        );
        let instance = "22222222222242228222222222222222";
        stream
            .write_all(format!("{}\n", strict_daemon_info_line(instance, true)).as_bytes())
            .unwrap();
        stream.flush().unwrap();

        let reserve_line = read_request(reader, tx).expect("ReserveStartOperation request");
        let reserve: ClientRequest = serde_json::from_str(&reserve_line).unwrap();
        let operation_token = match reserve {
            ClientRequest::ReserveStartOperation {
                id,
                operation_token,
            } => {
                assert_eq!(id, sid(expected_id));
                operation_token
            }
            other => panic!("expected ReserveStartOperation, got {other:?}"),
        };
        stream
            .write_all(
                format!(
                    "{{\"ev\":\"start_operation_reserved\",\"id\":\"{expected_id}\",\"operation_token\":\"{}\",\"daemon_instance_id\":\"{instance}\",\"outcome\":{{\"status\":\"reserved\"}}}}\n",
                    operation_token.as_str()
                )
                .as_bytes(),
            )
            .unwrap();
        stream.flush().unwrap();

        let start_line = read_request(reader, tx).expect("conditional StartSession request");
        let start: ClientRequest = serde_json::from_str(&start_line).unwrap();
        match &start {
            ClientRequest::StartSession {
                id,
                conditional_start: Some(conditional),
                restart_exited,
                ..
            } => {
                assert_eq!(id, &sid(expected_id));
                assert_eq!(&conditional.operation_token, &operation_token);
                assert!(!restart_exited);
            }
            other => panic!("expected conditional StartSession, got {other:?}"),
        }
        stream
            .write_all(
                format!(
                    "{{\"ev\":\"conditional_session_start\",\"id\":\"{expected_id}\",\"operation_token\":\"{}\",\"daemon_instance_id\":\"{instance}\",\"outcome\":{{\"status\":\"applied\",\"generation\":\"{generation}\"}}}}\n",
                    operation_token.as_str()
                )
                .as_bytes(),
            )
            .unwrap();
        stream.flush().unwrap();

        let attach_line = read_request(reader, tx).expect("exact Attach request");
        let attach: ClientRequest = serde_json::from_str(&attach_line).unwrap();
        let output_generation = match attach {
            ClientRequest::Attach {
                id,
                expected_session_generation: Some(expected),
                output_generation: Some(output_generation),
                ..
            } => {
                assert_eq!(id, sid(expected_id));
                assert_eq!(expected, generation);
                output_generation
            }
            other => panic!("expected exact routed Attach, got {other:?}"),
        };
        (start, output_generation)
    }

    fn answer_conditional_mutation_probe(
        reader: &mut impl BufRead,
        tx: &mpsc::Sender<String>,
        stream: &mut StdUnixStream,
    ) {
        assert_eq!(
            read_request(reader, tx).as_deref(),
            Some(r#"{"op":"daemon_info"}"#)
        );
        stream
            .write_all(
                format!(
                    "{}\n",
                    strict_daemon_info_line("22222222222242228222222222222222", true)
                )
                .as_bytes(),
            )
            .unwrap();
        stream.flush().unwrap();
    }

    /// The core happy path is capability -> Reserve -> conditional Start -> exact Attach/Grid.
    #[test]
    fn start_and_attach_sends_requests_in_order_and_returns_grid() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();

        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let (_, output_generation) =
                accept_conditional_start_prefix(&mut reader, tx, stream, "s1", "gen-aaa");
            stream
                .write_all(
                    format!(
                        "{}\n",
                        routed_grid_line("s1", "gen-aaa", Some(7), output_generation)
                    )
                    .as_bytes(),
                )
                .unwrap();
            stream.flush().unwrap();
            let _ = read_request(&mut reader, tx);
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let (attached, recovery) = client
            .start_and_attach(sid("s1"), &cwd_path, "bash", &["-l".to_string()], 80, 24)
            .unwrap();
        assert_eq!(
            attached,
            AttachedSession {
                id: sid("s1"),
                generation: "gen-aaa".to_string(),
                revision: Some(7),
                handoff_seed: None,
            }
        );
        assert_eq!(recovery.operation_applied_generation(), Some("gen-aaa"));
        assert_eq!(recovery.grid_proven_generation(), Some("gen-aaa"));
        drop(client); // close our side so the stub's reader sees EOF and the thread joins.

        let reqs = stub.collected_requests();
        assert_eq!(
            reqs.len(),
            4,
            "expected probe, Reserve, Start, Attach: {reqs:?}"
        );
        assert_eq!(reqs[0], r#"{"op":"daemon_info"}"#);
        assert!(matches!(
            serde_json::from_str::<ClientRequest>(&reqs[1]).unwrap(),
            ClientRequest::ReserveStartOperation { id, .. } if id == sid("s1")
        ));
        assert!(matches!(
            serde_json::from_str::<ClientRequest>(&reqs[2]).unwrap(),
            ClientRequest::StartSession {
                id,
                ref cwd,
                ref command,
                ref args,
                restart_exited: false,
                conditional_start: Some(ConditionalSessionStart {
                    precondition: SessionStartPrecondition::Absent { .. },
                    ..
                }),
                ..
            } if id == sid("s1") && cwd == &cwd_path && command == "bash" && args == &["-l"]
        ));
        assert!(matches!(
            serde_json::from_str::<ClientRequest>(&reqs[3]).unwrap(),
            ClientRequest::Attach {
                id,
                want_raw_output: false,
                expected_session_generation: Some(ref generation),
                output_generation: Some(_),
                ..
            } if id == sid("s1") && generation == "gen-aaa"
        ));
    }

    #[test]
    fn reviewed_conditional_start_applies_typed_child_environment_and_retires_exact_generation() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"daemon_info"}"#)
            );
            let instance = "22222222222242228222222222222222";
            writeln!(stream, "{}", strict_daemon_info_line(instance, true)).unwrap();
            stream.flush().unwrap();

            let reserve: ClientRequest = serde_json::from_str(
                &read_request(&mut reader, tx).expect("ReserveStartOperation"),
            )
            .unwrap();
            let token = match reserve {
                ClientRequest::ReserveStartOperation {
                    id,
                    operation_token,
                } => {
                    assert_eq!(id, sid("headless"));
                    operation_token
                }
                other => panic!("expected ReserveStartOperation, got {other:?}"),
            };
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "start_operation_reserved",
                    "id": "headless",
                    "operation_token": token.as_str(),
                    "daemon_instance_id": instance,
                    "outcome": {"status": "reserved"},
                })
            )
            .unwrap();
            stream.flush().unwrap();

            let start: ClientRequest = serde_json::from_str(
                &read_request(&mut reader, tx).expect("conditional StartSession"),
            )
            .unwrap();
            assert!(matches!(
                start,
                ClientRequest::StartSession {
                    id,
                    child_environment: Some(ChildEnvironment { ref home, ref shell }),
                    conditional_start: Some(ConditionalSessionStart {
                        operation_token,
                        precondition: SessionStartPrecondition::Absent {
                            excluded_generation: None,
                        },
                    }),
                    ..
                } if id == sid("headless")
                    && home == "/Users/test"
                    && shell == "/bin/zsh"
                    && operation_token == token
            ));
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "conditional_session_start",
                    "id": "headless",
                    "operation_token": token.as_str(),
                    "daemon_instance_id": instance,
                    "outcome": {"status": "applied", "generation": "generation-headless"},
                })
            )
            .unwrap();
            stream.flush().unwrap();

            let attach: ClientRequest =
                serde_json::from_str(&read_request(&mut reader, tx).expect("exact Attach"))
                    .unwrap();
            let output_generation = match attach {
                ClientRequest::Attach {
                    id,
                    expected_session_generation: Some(generation),
                    output_generation: Some(output_generation),
                    ..
                } if id == sid("headless") && generation == "generation-headless" => {
                    output_generation
                }
                other => panic!("expected exact Attach, got {other:?}"),
            };
            writeln!(
                stream,
                "{}",
                routed_grid_line(
                    "headless",
                    "generation-headless",
                    Some(3),
                    output_generation
                )
            )
            .unwrap();
            stream.flush().unwrap();

            assert!(matches!(
                serde_json::from_str::<ClientRequest>(
                    &read_request(&mut reader, tx).expect("exact retirement")
                )
                .unwrap(),
                ClientRequest::RetireStartOperation {
                    id,
                    operation_token,
                    expected: SessionStartOperationRetireExpectation::Applied { ref generation },
                } if id == sid("headless")
                    && operation_token == token
                    && generation == "generation-headless"
            ));
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "start_operation_retired",
                    "id": "headless",
                    "operation_token": token.as_str(),
                    "daemon_instance_id": instance,
                    "outcome": {"status": "retired"},
                })
            )
            .unwrap();
            stream.flush().unwrap();
            let _ = read_request(&mut reader, tx);
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let peer = client.conditional_start_peer_identity().unwrap();
        assert!(peer.supports_child_environment());
        let (attached, recovery) = client
            .start_and_attach_conditionally_with_environment(
                sid("headless"),
                &cwd_path,
                "zsh",
                &[],
                Some(ChildEnvironment {
                    home: "/Users/test".into(),
                    shell: "/bin/zsh".into(),
                }),
                80,
                24,
                SessionStartPrecondition::Absent {
                    excluded_generation: None,
                },
                &peer,
            )
            .unwrap();
        assert_eq!(attached.generation, "generation-headless");
        assert_eq!(
            client
                .retire_applied_start_operation_in_place(&recovery, &attached.generation)
                .unwrap(),
            SessionStartOperationRetireOutcome::Retired
        );
        drop(client);
    }

    #[test]
    fn reviewed_child_environment_fails_before_reserve_when_capability_is_absent() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx).expect("DaemonInfo request");
            writeln!(
                stream,
                "{}",
                strict_daemon_info_line_with_child_environment(
                    "22222222222242228222222222222222",
                    true,
                    false,
                )
            )
            .unwrap();
            stream.flush().unwrap();
            let _ = read_request(&mut reader, tx);
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let peer = client.conditional_start_peer_identity().unwrap();
        assert!(!peer.supports_child_environment());
        assert!(matches!(
            client.start_and_attach_conditionally_with_environment(
                sid("unsupported-headless"),
                &cwd_path,
                "zsh",
                &[],
                Some(ChildEnvironment {
                    home: "/Users/test".into(),
                    shell: "/bin/zsh".into(),
                }),
                80,
                24,
                SessionStartPrecondition::Absent {
                    excluded_generation: None,
                },
                &peer,
            ),
            Err(DaemonClientError::MutationProtocolUnsupported { .. })
        ));
        drop(client);
        assert_eq!(stub.collected_requests().len(), 1);
    }

    #[test]
    fn grid_proven_success_retires_applied_in_place_without_consuming_handoff() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let (start, output_generation) =
                accept_conditional_start_prefix(&mut reader, tx, stream, "s1", "gen-retire");
            let operation_token = match start {
                ClientRequest::StartSession {
                    conditional_start: Some(conditional),
                    ..
                } => conditional.operation_token,
                other => panic!("expected conditional StartSession, got {other:?}"),
            };
            stream
                .write_all(
                    format!(
                        "{}\n",
                        routed_grid_line("s1", "gen-retire", Some(8), output_generation)
                    )
                    .as_bytes(),
                )
                .unwrap();
            stream.flush().unwrap();

            let retired: ClientRequest = serde_json::from_str(
                &read_request(&mut reader, tx).expect("in-place RetireStartOperation"),
            )
            .unwrap();
            assert!(matches!(
                retired,
                ClientRequest::RetireStartOperation {
                    id,
                    operation_token: ref got_token,
                    expected: SessionStartOperationRetireExpectation::Applied {
                        ref generation,
                    },
                } if id == sid("s1")
                    && got_token == &operation_token
                    && generation == "gen-retire"
            ));
            stream
                .write_all(
                    format!(
                        "{{\"ev\":\"start_operation_retired\",\"id\":\"s1\",\"operation_token\":\"{}\",\"daemon_instance_id\":\"22222222222242228222222222222222\",\"outcome\":{{\"status\":\"retired\"}}}}\n",
                        operation_token.as_str()
                    )
                    .as_bytes(),
                )
                .unwrap();
            stream.flush().unwrap();
            let _ = read_request(&mut reader, tx);
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let (attached, recovery) = client
            .start_and_attach_for_renderer(sid("s1"), &cwd_path, "bash", &[], 80, 24)
            .unwrap();
        assert!(attached.handoff_seed.is_some());
        assert!(recovery.handoff_seed.is_some());
        assert_eq!(
            client
                .retire_applied_start_operation_in_place(&recovery, "gen-retire")
                .unwrap(),
            SessionStartOperationRetireOutcome::Retired
        );
        assert!(
            attached.handoff_seed.is_some(),
            "ledger retirement must not consume renderer handoff authority"
        );
        assert!(recovery.handoff_seed.is_some());
        drop(client);
        assert_eq!(stub.collected_requests().len(), 5);
    }

    #[test]
    fn lookup_and_retire_preserve_typed_lifecycle_and_exact_cas_outcome() {
        let instance = "22222222222242228222222222222222";
        let token = "11111111111141118111111111111111";
        let stub = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"daemon_info"}"#)
            );
            stream
                .write_all(format!("{}\n", strict_daemon_info_line(instance, true)).as_bytes())
                .unwrap();
            stream.flush().unwrap();

            let lookup = read_request(&mut reader, tx).unwrap();
            assert_eq!(
                lookup,
                format!(
                    r#"{{"op":"lookup_start_operation","id":"s1","operation_token":"{token}"}}"#
                )
            );
            stream
                .write_all(
                    format!(
                        "{{\"ev\":\"start_operation_status\",\"id\":\"s1\",\"operation_token\":\"{token}\",\"daemon_instance_id\":\"{instance}\",\"status\":{{\"status\":\"applied\",\"generation\":\"gen-b\",\"lifecycle\":\"exited\"}}}}\n"
                    )
                    .as_bytes(),
                )
                .unwrap();
            stream.flush().unwrap();

            let retire = read_request(&mut reader, tx).unwrap();
            assert_eq!(
                retire,
                format!(
                    r#"{{"op":"retire_start_operation","id":"s1","operation_token":"{token}","expected":{{"state":"applied","generation":"gen-b"}}}}"#
                )
            );
            stream
                .write_all(
                    format!(
                        "{{\"ev\":\"start_operation_retired\",\"id\":\"s1\",\"operation_token\":\"{token}\",\"daemon_instance_id\":\"{instance}\",\"outcome\":{{\"status\":\"conflict\",\"current\":{{\"status\":\"applied\",\"generation\":\"gen-b\",\"lifecycle\":\"removed\"}}}}}}\n"
                    )
                    .as_bytes(),
                )
                .unwrap();
            stream.flush().unwrap();
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let capabilities = client.daemon_capabilities().unwrap();
        let expected_instance = capabilities.9.unwrap();
        let operation_token: SessionStartOperationToken = token.parse().unwrap();
        let mut budget = client.generation_kill_budget().unwrap();
        assert_eq!(
            client
                .lookup_start_operation_before(
                    &sid("s1"),
                    &operation_token,
                    &expected_instance,
                    &mut budget,
                )
                .unwrap(),
            SessionStartOperationStatus::Applied {
                generation: "gen-b".into(),
                lifecycle: SessionStartOperationLifecycle::Exited,
            }
        );
        assert_eq!(
            client
                .retire_start_operation_before(
                    &sid("s1"),
                    &operation_token,
                    &expected_instance,
                    SessionStartOperationRetireExpectation::Applied {
                        generation: "gen-b".into(),
                    },
                    &mut budget,
                )
                .unwrap(),
            SessionStartOperationRetireOutcome::Conflict {
                current: SessionStartOperationStatus::Applied {
                    generation: "gen-b".into(),
                    lifecycle: SessionStartOperationLifecycle::Removed,
                }
            }
        );
    }

    #[test]
    fn refused_start_is_exactly_retired_before_returning_refusal() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let instance = "22222222222242228222222222222222";
        let stub = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"daemon_info"}"#)
            );
            writeln!(stream, "{}", strict_daemon_info_line(instance, true)).unwrap();
            stream.flush().unwrap();

            let reserve: ClientRequest = serde_json::from_str(
                &read_request(&mut reader, tx).expect("ReserveStartOperation"),
            )
            .unwrap();
            let operation_token = match reserve {
                ClientRequest::ReserveStartOperation {
                    id,
                    operation_token,
                } => {
                    assert_eq!(id, sid("s1"));
                    operation_token
                }
                other => panic!("expected reservation, got {other:?}"),
            };
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "start_operation_reserved",
                    "id": "s1",
                    "operation_token": operation_token.as_str(),
                    "daemon_instance_id": instance,
                    "outcome": {"status": "reserved"}
                })
            )
            .unwrap();
            stream.flush().unwrap();

            assert!(matches!(
                serde_json::from_str::<ClientRequest>(
                    &read_request(&mut reader, tx).expect("conditional Start")
                )
                .unwrap(),
                ClientRequest::StartSession { .. }
            ));
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "conditional_session_start",
                    "id": "s1",
                    "operation_token": operation_token.as_str(),
                    "daemon_instance_id": instance,
                    "outcome": {"status": "refused", "reason": "precondition_failed"}
                })
            )
            .unwrap();
            stream.flush().unwrap();

            let retire: ClientRequest =
                serde_json::from_str(&read_request(&mut reader, tx).expect("RetireStartOperation"))
                    .unwrap();
            assert!(matches!(
                retire,
                ClientRequest::RetireStartOperation {
                    id,
                    operation_token: ref retired_token,
                    expected: SessionStartOperationRetireExpectation::Unapplied,
                } if id == sid("s1") && retired_token == &operation_token
            ));
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "start_operation_retired",
                    "id": "s1",
                    "operation_token": operation_token.as_str(),
                    "daemon_instance_id": instance,
                    "outcome": {"status": "retired"}
                })
            )
            .unwrap();
            stream.flush().unwrap();
            let _ = read_request(&mut reader, tx);
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        assert!(matches!(
            client.start_and_attach(sid("s1"), &cwd_path, "sh", &[], 80, 24),
            Err(DaemonClientError::ConditionalStartRefused {
                reason: ConditionalSessionStartRefusal::PreconditionFailed,
                ..
            })
        ));
    }

    #[test]
    fn ambiguous_start_replay_refusal_is_retired_on_final_lookup() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ambiguous-refused.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let (request_tx, request_rx) = mpsc::channel();
        let server = std::thread::spawn(move || {
            let instance = "22222222222242228222222222222222";

            let (mut initial, _) = listener.accept().unwrap();
            let mut initial_reader = BufReader::new(initial.try_clone().unwrap());
            assert_eq!(
                read_request(&mut initial_reader, &request_tx).as_deref(),
                Some(r#"{"op":"daemon_info"}"#)
            );
            writeln!(initial, "{}", strict_daemon_info_line(instance, true)).unwrap();
            initial.flush().unwrap();
            let reserve: ClientRequest = serde_json::from_str(
                &read_request(&mut initial_reader, &request_tx).expect("initial Reserve"),
            )
            .unwrap();
            let operation_token = match reserve {
                ClientRequest::ReserveStartOperation {
                    id,
                    operation_token,
                } => {
                    assert_eq!(id, sid("s1"));
                    operation_token
                }
                other => panic!("expected ReserveStartOperation, got {other:?}"),
            };
            writeln!(
                initial,
                "{}",
                serde_json::json!({
                    "ev": "start_operation_reserved",
                    "id": "s1",
                    "operation_token": operation_token.as_str(),
                    "daemon_instance_id": instance,
                    "outcome": {"status": "reserved"}
                })
            )
            .unwrap();
            initial.flush().unwrap();
            let initial_start =
                read_request(&mut initial_reader, &request_tx).expect("initial Start");
            assert!(initial_start.contains("\"conditional_start\""));
            drop(initial_reader);
            drop(initial);

            let (mut replay, _) = listener.accept().unwrap();
            let mut replay_reader = BufReader::new(replay.try_clone().unwrap());
            assert_eq!(
                read_request(&mut replay_reader, &request_tx).as_deref(),
                Some(r#"{"op":"daemon_info"}"#)
            );
            writeln!(replay, "{}", strict_daemon_info_line(instance, true)).unwrap();
            replay.flush().unwrap();
            let lookup: ClientRequest = serde_json::from_str(
                &read_request(&mut replay_reader, &request_tx).expect("Reserved lookup"),
            )
            .unwrap();
            assert!(matches!(lookup, ClientRequest::LookupStartOperation { .. }));
            writeln!(
                replay,
                "{}",
                serde_json::json!({
                    "ev": "start_operation_status",
                    "id": "s1",
                    "operation_token": operation_token.as_str(),
                    "daemon_instance_id": instance,
                    "status": {"status": "reserved"}
                })
            )
            .unwrap();
            replay.flush().unwrap();
            let replay_start =
                read_request(&mut replay_reader, &request_tx).expect("replayed Start");
            assert_eq!(replay_start, initial_start);
            writeln!(
                replay,
                "{}",
                serde_json::json!({
                    "ev": "conditional_session_start",
                    "id": "s1",
                    "operation_token": operation_token.as_str(),
                    "daemon_instance_id": instance,
                    "outcome": {"status": "refused", "reason": "precondition_failed"}
                })
            )
            .unwrap();
            replay.flush().unwrap();
            drop(replay_reader);
            drop(replay);

            let (mut final_lookup, _) = listener.accept().unwrap();
            let mut final_reader = BufReader::new(final_lookup.try_clone().unwrap());
            assert_eq!(
                read_request(&mut final_reader, &request_tx).as_deref(),
                Some(r#"{"op":"daemon_info"}"#)
            );
            writeln!(final_lookup, "{}", strict_daemon_info_line(instance, true)).unwrap();
            final_lookup.flush().unwrap();
            assert!(matches!(
                serde_json::from_str::<ClientRequest>(
                    &read_request(&mut final_reader, &request_tx).expect("Refused lookup")
                )
                .unwrap(),
                ClientRequest::LookupStartOperation { .. }
            ));
            writeln!(
                final_lookup,
                "{}",
                serde_json::json!({
                    "ev": "start_operation_status",
                    "id": "s1",
                    "operation_token": operation_token.as_str(),
                    "daemon_instance_id": instance,
                    "status": {"status": "refused"}
                })
            )
            .unwrap();
            final_lookup.flush().unwrap();
            assert!(matches!(
                serde_json::from_str::<ClientRequest>(
                    &read_request(&mut final_reader, &request_tx).expect("Refused retirement")
                )
                .unwrap(),
                ClientRequest::RetireStartOperation {
                    expected: SessionStartOperationRetireExpectation::Unapplied,
                    ..
                }
            ));
            writeln!(
                final_lookup,
                "{}",
                serde_json::json!({
                    "ev": "start_operation_retired",
                    "id": "s1",
                    "operation_token": operation_token.as_str(),
                    "daemon_instance_id": instance,
                    "outcome": {"status": "retired"}
                })
            )
            .unwrap();
            final_lookup.flush().unwrap();
            let _ = read_request(&mut final_reader, &request_tx);
        });

        let mut client = DaemonClient::connect(&path).unwrap();
        assert!(matches!(
            client.start_and_attach(sid("s1"), &cwd_path, "sh", &[], 80, 24),
            Err(DaemonClientError::StartOperationTerminal {
                status: SessionStartOperationStatus::Refused,
                ..
            })
        ));
        client.abort_connection();
        drop(client);
        server.join().unwrap();
        assert!(request_rx
            .try_iter()
            .any(|request| request.contains("retire_start_operation")));
    }

    #[test]
    fn explicit_exited_restart_sets_protocol_authority_before_attach() {
        let cwd = tempfile::TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let (start, output_generation) =
                accept_conditional_start_prefix(&mut reader, tx, stream, "s1", "gen-restarted");
            assert!(matches!(
                start,
                ClientRequest::StartSession {
                    restart_exited: false,
                    conditional_start: Some(ConditionalSessionStart {
                        precondition: SessionStartPrecondition::ExitedGeneration {
                            ref expected_generation,
                        },
                        ..
                    }),
                    ..
                } if expected_generation == "gen-exited"
            ));
            stream
                .write_all(
                    format!(
                        "{}\n",
                        routed_grid_line("s1", "gen-restarted", Some(1), output_generation)
                    )
                    .as_bytes(),
                )
                .unwrap();
            stream.flush().unwrap();
            let _ = read_request(&mut reader, tx);
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let (attached, _recovery) = client
            .restart_exited_and_attach(sid("s1"), "gen-exited", &cwd_path, "bash", &[], 80, 24)
            .unwrap();
        assert_eq!(attached.generation, "gen-restarted");
        drop(client);

        let reqs = stub.collected_requests();
        assert_eq!(reqs.len(), 4);
    }

    #[test]
    fn unchanged_restart_ack_preserves_operation_fact_without_grid_authority() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"daemon_info"}"#)
            );
            let instance = "22222222222242228222222222222222";
            writeln!(stream, "{}", strict_daemon_info_line(instance, true)).unwrap();
            stream.flush().unwrap();
            let reserve: ClientRequest = serde_json::from_str(
                &read_request(&mut reader, tx).expect("ReserveStartOperation"),
            )
            .unwrap();
            let operation_token = match reserve {
                ClientRequest::ReserveStartOperation {
                    operation_token, ..
                } => operation_token,
                other => panic!("expected ReserveStartOperation, got {other:?}"),
            };
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "start_operation_reserved",
                    "id": "s1",
                    "operation_token": operation_token.as_str(),
                    "daemon_instance_id": instance,
                    "outcome": {"status": "reserved"}
                })
            )
            .unwrap();
            stream.flush().unwrap();
            assert!(matches!(
                serde_json::from_str::<ClientRequest>(
                    &read_request(&mut reader, tx).expect("conditional StartSession")
                )
                .unwrap(),
                ClientRequest::StartSession {
                    conditional_start: Some(ConditionalSessionStart {
                        precondition: SessionStartPrecondition::ExitedGeneration {
                            ref expected_generation,
                        },
                        ..
                    }),
                    ..
                } if expected_generation == "gen-exited"
            ));
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "conditional_session_start",
                    "id": "s1",
                    "operation_token": operation_token.as_str(),
                    "daemon_instance_id": instance,
                    "outcome": {"status": "applied", "generation": "gen-exited"}
                })
            )
            .unwrap();
            stream.flush().unwrap();
            let _ = read_request(&mut reader, tx);
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        match client
            .restart_exited_and_attach(sid("s1"), "gen-exited", &cwd_path, "bash", &[], 80, 24)
            .unwrap_err()
        {
            DaemonClientError::ConditionalStartPossiblyApplied {
                recovery, source, ..
            } => {
                assert_eq!(recovery.operation_applied_generation(), Some("gen-exited"));
                assert_eq!(recovery.grid_proven_generation(), None);
                assert!(matches!(
                    *source,
                    DaemonClientError::RestartGenerationUnchanged { .. }
                ));
            }
            other => panic!("expected unchanged-generation recovery, got {other:?}"),
        }
        client.abort_connection();
        drop(client);
        assert_eq!(stub.collected_requests().len(), 3);
    }

    #[test]
    fn attach_existing_sends_no_start_session_mutation() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            stream
                .write_all(format!("{}\n", grid_line("kept", "gen-kept", 9)).as_bytes())
                .unwrap();
            stream.flush().unwrap();
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let attached = client.attach_existing(sid("kept")).unwrap();
        assert_eq!(attached.id, sid("kept"));
        assert_eq!(attached.generation, "gen-kept");
        assert_eq!(attached.revision, Some(9));
        drop(client);

        assert_eq!(
            stub.collected_requests(),
            vec![r#"{"op":"attach","id":"kept","want_raw_output":false}"#.to_string()]
        );
    }

    /// A `Grid` whose snapshot omits `revision` still attaches; generation is the only required
    /// field, revision comes back `None`.
    #[test]
    fn grid_without_revision_returns_none_revision() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let (_, output_generation) =
                accept_conditional_start_prefix(&mut reader, tx, stream, "s1", "g-only");
            stream
                .write_all(routed_grid_line("s1", "g-only", None, output_generation).as_bytes())
                .unwrap();
            stream.write_all(b"\n").unwrap();
            stream.flush().unwrap();
            let _ = read_request(&mut reader, tx);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let (attached, _recovery) = client
            .start_and_attach(sid("s1"), &cwd_path, "sh", &[], 80, 24)
            .unwrap();
        assert_eq!(attached.generation, "g-only");
        assert_eq!(attached.revision, None);
    }

    /// `list_sessions` sends `{"op":"list_sessions"}` and decodes the live ids from the `Sessions`
    /// reply.
    #[test]
    fn list_sessions_decodes_live_ids() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[\"a\",\"b\",\"c\"]}\n")
                .unwrap();
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let ids = client.list_sessions().unwrap();
        assert_eq!(ids, vec![sid("a"), sid("b"), sid("c")]);
        drop(client);
        let reqs = stub.collected_requests();
        assert_eq!(reqs, vec![r#"{"op":"list_sessions"}"#.to_string()]);
    }

    #[test]
    fn list_sessions_snapshot_decodes_generation_metadata_and_legacy_default() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            stream
                .write_all(
                    b"{\"ev\":\"sessions\",\"ids\":[\"a\"],\"sessions\":[{\"id\":\"a\",\"cwd\":\"/tmp\",\"generation\":\"gen-a\"}]}\n",
                )
                .unwrap();
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let snapshot = client.list_sessions_snapshot().unwrap();
        assert_eq!(snapshot.ids, vec![sid("a")]);
        assert_eq!(snapshot.sessions.len(), 1);
        assert_eq!(snapshot.sessions[0].id, sid("a"));
        assert_eq!(snapshot.sessions[0].generation.as_deref(), Some("gen-a"));
    }

    /// An `Error` reply is surfaced as a typed `DaemonError`, not swallowed.
    #[test]
    fn error_reply_is_surfaced() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            stream
                .write_all(b"{\"ev\":\"error\",\"message\":\"boom\"}\n")
                .unwrap();
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let err = client
            .start_and_attach(sid("s1"), &cwd_path, "sh", &[], 80, 24)
            .unwrap_err();
        match err {
            DaemonClientError::DaemonError { message } => assert_eq!(message, "boom"),
            other => panic!("expected DaemonError, got {other:?}"),
        }
    }

    /// A `SessionExited` for our session BEFORE any `Grid` is surfaced as a typed `SessionExited`
    /// (e.g. the command failed to launch / exited immediately).
    #[test]
    fn session_exited_before_grid_is_surfaced() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let _ =
                accept_conditional_start_prefix(&mut reader, tx, stream, "s1", "gen-exited-fast");
            stream
                .write_all(b"{\"ev\":\"session_exited\",\"id\":\"s1\",\"code\":3}\n")
                .unwrap();
            stream.flush().unwrap();
            let _ = read_request(&mut reader, tx);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let err = client
            .start_and_attach(sid("s1"), &cwd_path, "sh", &[], 80, 24)
            .unwrap_err();
        match err {
            DaemonClientError::ConditionalStartPossiblyApplied {
                recovery, source, ..
            } => {
                assert_eq!(
                    recovery.operation_applied_generation(),
                    Some("gen-exited-fast")
                );
                assert_eq!(recovery.grid_proven_generation(), None);
                assert_eq!(
                    recovery.applied_generation(),
                    None,
                    "typed Start ACK alone must never become durable-Live authority"
                );
                match *source {
                    DaemonClientError::SessionExited { id, code } => {
                        assert_eq!(id, sid("s1"));
                        assert_eq!(code, Some(3));
                    }
                    other => panic!("expected nested SessionExited, got {other:?}"),
                }
            }
            other => panic!("expected PossiblyApplied, got {other:?}"),
        }
    }

    /// Unrelated events streamed BEFORE the grid (a structured attach emits damage continuously,
    /// plus output/resync/channel/scrollback and even a grid for a DIFFERENT session) are all
    /// tolerated; the client keeps reading until ITS grid arrives.
    #[test]
    fn unrelated_events_before_grid_are_tolerated() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let (_, output_generation) =
                accept_conditional_start_prefix(&mut reader, tx, stream, "s1", "gen-mine");
            let mut send = |s: &str| {
                stream.write_all(s.as_bytes()).unwrap();
                stream.write_all(b"\n").unwrap();
            };
            // A grab-bag of events the client must skip.
            send(r#"{"ev":"output","id":"s1","generation":"g","revision":1,"data":"aGk="}"#);
            send(r#"{"ev":"resync_required","id":"s1"}"#);
            send(
                r#"{"ev":"channel","event":{"channel":"c1","from":null,"kind":"chat_msg","text":"hi","ts":1}}"#,
            );
            send(r#"{"ev":"some_future_event","x":1}"#);
            // A grid for a DIFFERENT session — not ours, must be skipped.
            send(&grid_line("other", "gen-other", 99));
            // A sessions reply mid-stream — also tolerated.
            send(r#"{"ev":"sessions","ids":["s1"]}"#);
            // Finally OUR grid.
            send(&routed_grid_line(
                "s1",
                "gen-mine",
                Some(42),
                output_generation,
            ));
            stream.flush().unwrap();
            let _ = read_request(&mut reader, tx);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let (attached, _recovery) = client
            .start_and_attach(sid("s1"), &cwd_path, "sh", &[], 80, 24)
            .unwrap();
        assert_eq!(attached.id, sid("s1"));
        assert_eq!(attached.generation, "gen-mine");
        assert_eq!(attached.revision, Some(42));
    }

    #[test]
    fn endless_unrelated_events_exhaust_one_operation_budget() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            for _ in 0..=MAX_REPLY_EVENTS_PER_OPERATION {
                if stream
                    .write_all(b"{\"ev\":\"some_future_event\"}\n")
                    .is_err()
                {
                    break;
                }
            }
            let _ = stream.flush();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        assert!(matches!(
            client.list_sessions(),
            Err(DaemonClientError::ReplyBudgetExceeded {
                during: "reading list_sessions reply"
            })
        ));
    }

    #[test]
    fn newline_in_byte_after_frame_limit_is_still_oversized() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            let mut line = vec![b' '; MAX_LINE_BYTES + 1];
            *line.last_mut().unwrap() = b'\n';
            let _ = stream.write_all(&line);
            let _ = stream.flush();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        assert!(matches!(
            client.list_sessions(),
            Err(DaemonClientError::LineTooLong {
                direction: Direction::Inbound,
                limit: MAX_LINE_BYTES,
            })
        ));
    }

    #[test]
    fn deadline_reader_rejects_newline_in_byte_after_frame_limit() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            let mut line = vec![b' '; MAX_LINE_BYTES + 1];
            *line.last_mut().unwrap() = b'\n';
            let _ = stream.write_all(&line);
            let _ = stream.flush();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        assert!(matches!(
            client.generation_mutation_snapshot(),
            Err(DaemonClientError::LineTooLong {
                direction: Direction::Inbound,
                limit: MAX_LINE_BYTES,
            })
        ));
    }

    #[test]
    fn ordinary_reply_deadline_bounds_a_byte_trickle_and_restores_timeout() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            for byte in b"{\"ev\":\"sessions\",\"ids\":[]}\n" {
                if stream.write_all(&[*byte]).is_err() || stream.flush().is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(75));
            }
        });
        let timeout = Duration::from_millis(200);
        let mut client = DaemonClient::connect_with_timeout(&stub.path, timeout).unwrap();
        assert!(matches!(
            client.list_sessions(),
            Err(DaemonClientError::Timeout {
                during: "reading list_sessions reply"
            })
        ));
        assert_eq!(
            client.reader.get_ref().read_timeout().unwrap(),
            Some(timeout)
        );
        client.abort_connection();
    }

    /// An oversized reply line (no newline within the cap) is rejected as `LineTooLong` WITHOUT the
    /// client buffering the whole thing — it stops at one byte over the limit. We prove rejection;
    /// the bound is structural in the capped `fill_buf` loop.
    #[test]
    fn oversized_line_is_rejected_without_unbounded_buffering() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let _ = accept_conditional_start_prefix(&mut reader, tx, stream, "s1", "gen-oversized");
            // Start a JSON line and never terminate it; push more than the cap so the client's
            // bounded read trips. Write in chunks; ignore a broken pipe once the client gives up.
            let chunk = vec![b'a'; 1024 * 1024];
            let mut written = 0usize;
            stream
                .write_all(b"{\"ev\":\"grid\",\"id\":\"s1\",\"junk\":\"")
                .unwrap();
            while written <= MAX_LINE_BYTES + 1 {
                if stream.write_all(&chunk).is_err() {
                    break;
                }
                written += chunk.len();
            }
            let _ = stream.flush();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let err = client
            .start_and_attach(sid("s1"), &cwd_path, "sh", &[], 80, 24)
            .unwrap_err();
        match err {
            DaemonClientError::ConditionalStartPossiblyApplied { source, .. } => match *source {
                DaemonClientError::LineTooLong { direction, limit } => {
                    assert_eq!(direction, Direction::Inbound);
                    assert_eq!(limit, MAX_LINE_BYTES);
                }
                other => panic!("expected nested inbound LineTooLong, got {other:?}"),
            },
            other => panic!("expected PossiblyApplied, got {other:?}"),
        }
    }

    /// An oversized OUTBOUND request (here a `StartSession` with enormous args) is rejected before
    /// any bytes reach the daemon: the stub records ZERO requests and the error is an `Outbound`
    /// `LineTooLong`. This is the request-side mirror of the inbound cap.
    #[test]
    fn oversized_request_is_rejected_before_any_bytes_written() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let stub = StubDaemon::spawn(|tx, stream| {
            // The client must NOT write anything; if it does, capture it so the assertion fails.
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        // One arg larger than the whole line cap guarantees the serialized request exceeds it.
        let huge_arg = "a".repeat(MAX_LINE_BYTES + 1);
        let err = client
            .start_and_attach(sid("s1"), &cwd_path, "sh", &[huge_arg], 80, 24)
            .unwrap_err();
        match err {
            DaemonClientError::LineTooLong { direction, limit } => {
                assert_eq!(direction, Direction::Outbound);
                assert_eq!(limit, MAX_LINE_BYTES);
            }
            other => panic!("expected outbound LineTooLong, got {other:?}"),
        }
        drop(client); // close so the stub's read sees EOF.
        assert!(
            stub.collected_requests().is_empty(),
            "no request bytes must be written when the request line is oversized"
        );
    }

    /// Connecting to a nonexistent socket path returns the typed daemon-unavailable error, distinct
    /// from a daemon that answered with an error.
    #[test]
    fn connect_to_missing_socket_is_daemon_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        // `DaemonClient` owns a socket and is not `Debug`, so match on the `Result` directly rather
        // than `unwrap_err()` (which would require `Ok` to be `Debug`).
        match DaemonClient::connect(&missing) {
            Err(DaemonClientError::DaemonUnavailable { path, .. }) => {
                assert!(path.contains("does-not-exist.sock"), "path was {path}");
            }
            Err(other) => panic!("expected DaemonUnavailable, got {other:?}"),
            Ok(_) => panic!("expected DaemonUnavailable, got a connected client"),
        }
    }

    /// A missing cwd returns `InvalidCwd` BEFORE any request is written — the stub records zero
    /// requests, proving the check is pre-flight (no half-issued StartSession on the wire).
    #[test]
    fn missing_cwd_returns_invalid_cwd_before_any_request() {
        let stub = StubDaemon::spawn(|tx, stream| {
            // If the client (incorrectly) sent anything, capture it so the assertion below fails.
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            // Non-blocking-ish: try to read one line; on EOF (the expected case) this returns None.
            read_request(&mut reader, tx);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let err = client
            .start_and_attach(sid("s1"), "/no/such/dir/anywhere-xyz", "sh", &[], 80, 24)
            .unwrap_err();
        let rendered = err.to_string();
        assert!(!rendered.contains("/no/such/dir/anywhere-xyz"));
        assert!(!rendered.contains("anywhere-xyz"));
        match err {
            DaemonClientError::InvalidCwd { cwd } => {
                assert_eq!(cwd, "/no/such/dir/anywhere-xyz")
            }
            other => panic!("expected InvalidCwd, got {other:?}"),
        }
        drop(client); // close so the stub's read sees EOF.
        assert!(
            stub.collected_requests().is_empty(),
            "no request must be written when cwd is invalid"
        );
    }

    /// An EXISTING regular file (not a directory) is rejected as `InvalidCwd` BEFORE any request is
    /// written — the stub records zero requests. This is the `is_dir()` boundary: `exists()` would
    /// have wrongly accepted the file, but the daemon rejects a non-directory cwd, so the client
    /// must too.
    #[test]
    fn existing_file_cwd_returns_invalid_cwd_before_any_request() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("not-a-dir.txt");
        std::fs::write(&file_path, b"i am a file").unwrap();
        let file_cwd = file_path.to_string_lossy().to_string();
        assert!(Path::new(&file_cwd).exists() && !Path::new(&file_cwd).is_dir());

        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let err = client
            .start_and_attach(sid("s1"), &file_cwd, "sh", &[], 80, 24)
            .unwrap_err();
        match err {
            DaemonClientError::InvalidCwd { cwd } => assert_eq!(cwd, file_cwd),
            other => panic!("expected InvalidCwd, got {other:?}"),
        }
        drop(client); // close so the stub's read sees EOF.
        assert!(
            stub.collected_requests().is_empty(),
            "no request must be written when cwd is an existing file"
        );
    }

    /// A silent daemon (accepts, then never replies) makes a read hit the deadline, surfaced as a
    /// typed `Timeout` rather than hanging the caller. We use a very short timeout to keep the test
    /// fast.
    #[test]
    fn silent_daemon_times_out() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let stub = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            // Deliberately send NOTHING. Hold the connection open until the test releases us, so the
            // client's read blocks and then times out.
            let _ = release_rx.recv();
        });
        let mut client =
            DaemonClient::connect_with_timeout(&stub.path, Duration::from_millis(150)).unwrap();
        let err = client
            .start_and_attach(sid("s1"), &cwd_path, "sh", &[], 80, 24)
            .unwrap_err();
        match err {
            DaemonClientError::Timeout { .. } => {}
            other => panic!("expected Timeout, got {other:?}"),
        }
        // Let the stub thread exit.
        let _ = release_tx.send(());
    }

    /// Conditional kill writes the exact v3 daemon wire shape, including `expected_generation`.
    /// FOLLOWED by `{"op":"list_sessions"}`, then returns `Ok(KilledSession{id})` once the post-kill
    /// `Sessions` reply no longer contains the id. This pins the no-new-protocol guarantee: kill
    /// reuses `ClientRequest::Kill` and confirmation reuses `ListSessions`.
    #[test]
    fn kill_session_sends_kill_then_list_and_confirms_absent() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_conditional_mutation_probe(&mut reader, tx, stream);
            // First request: Kill.
            read_request(&mut reader, tx);
            // Second request: ListSessions.
            read_request(&mut reader, tx);
            // Reply with a session list that does NOT contain s1 (the others survive).
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[\"s2\",\"s3\"]}\n")
                .unwrap();
            stream.flush().unwrap();
            let _ = read_request(&mut reader, tx);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let killed = client
            .kill_session_if_generation(sid("s1"), "gen-s1")
            .unwrap();
        assert_eq!(killed, KilledSession { id: sid("s1") });
        drop(client);
        let reqs = stub.collected_requests();
        assert_eq!(
            reqs,
            vec![
                r#"{"op":"daemon_info"}"#.to_string(),
                r#"{"op":"kill","id":"s1","expected_generation":"gen-s1"}"#.to_string(),
                r#"{"op":"list_sessions"}"#.to_string(),
            ]
        );
    }

    #[test]
    fn publication_aware_kill_capability_refusal_proves_no_kill_was_published() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"daemon_info"}"#)
            );
            stream
                .write_all(
                    format!(
                        "{{\"ev\":\"daemon_info\",\"protocol_version\":{},\"build_version\":\"test-v3\",\"output_generation_echo\":true,\"child_environment\":true,\"generation_conditional_mutations\":false}}\n",
                        maestro_protocol::DAEMON_PROTOCOL_VERSION
                    )
                    .as_bytes(),
                )
                .unwrap();
            stream.flush().unwrap();
            // Capture any forbidden post-probe request. Expected path reaches EOF after the client
            // reports NotPublished and is dropped.
            read_request(&mut reader, tx);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let error = client
            .kill_session_if_generation_with_publication(sid("s1"), "gen-s1")
            .unwrap_err();
        assert!(matches!(
            error,
            KillSessionPublicationError::NotPublished {
                source: DaemonClientError::MutationProtocolUnsupported { .. }
            }
        ));
        drop(client);
        assert_eq!(
            stub.collected_requests(),
            vec![r#"{"op":"daemon_info"}"#.to_string()]
        );
    }

    #[test]
    fn publication_aware_kill_framing_refusal_proves_no_kill_was_published() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_conditional_mutation_probe(&mut reader, tx, stream);
            read_request(&mut reader, tx);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let huge_generation = "g".repeat(MAX_LINE_BYTES + 1);
        let error = client
            .kill_session_if_generation_with_publication(sid("s1"), huge_generation)
            .unwrap_err();
        assert!(matches!(
            error,
            KillSessionPublicationError::NotPublished {
                source: DaemonClientError::LineTooLong {
                    direction: Direction::Outbound,
                    ..
                }
            }
        ));
        drop(client);
        assert_eq!(
            stub.collected_requests(),
            vec![r#"{"op":"daemon_info"}"#.to_string()]
        );
    }

    #[test]
    fn publication_aware_kill_eof_after_frame_is_possibly_published() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_conditional_mutation_probe(&mut reader, tx, stream);
            read_request(&mut reader, tx); // Kill crossed the peer boundary.
                                           // Drop immediately. The following ListSessions write may fail, or it may land and its
                                           // confirmation read sees EOF; either way publication cannot be disproved.
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let error = client
            .kill_session_if_generation_with_publication(sid("s1"), "gen-s1")
            .unwrap_err();
        assert!(matches!(
            error,
            KillSessionPublicationError::PossiblyPublished { .. }
        ));
        drop(client);
        assert_eq!(
            stub.collected_requests()[..2],
            [
                r#"{"op":"daemon_info"}"#.to_string(),
                r#"{"op":"kill","id":"s1","expected_generation":"gen-s1"}"#.to_string(),
            ]
        );
    }

    /// Idempotent already-absent: killing a session the daemon already doesn't know about returns
    /// `Ok` — "no longer live", not an error. The first `Sessions` reply omits it (e.g. it exited on
    /// its own), and the method succeeds without retrying.
    #[test]
    fn kill_session_already_absent_is_ok() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_conditional_mutation_probe(&mut reader, tx, stream);
            read_request(&mut reader, tx); // Kill
            read_request(&mut reader, tx); // ListSessions
                                           // s1 was never (or no longer) in the list.
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[]}\n")
                .unwrap();
            stream.flush().unwrap();
            let _ = read_request(&mut reader, tx);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let killed = client
            .kill_session_if_generation(sid("s1"), "gen-s1")
            .unwrap();
        assert_eq!(killed.id, sid("s1"));
    }

    /// If the FIRST `Sessions` snapshot still lists the id (a daemon reply taken before the kill
    /// landed), the method re-issues `ListSessions` and confirms on a later round. Here the first
    /// reply still contains s1, the second does not — success, with exactly two ListSessions sent.
    #[test]
    fn kill_session_present_then_absent_retries_and_succeeds() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_conditional_mutation_probe(&mut reader, tx, stream);
            read_request(&mut reader, tx); // Kill
            read_request(&mut reader, tx); // ListSessions (round 1)
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[\"s1\"]}\n")
                .unwrap();
            stream.flush().unwrap();
            read_request(&mut reader, tx); // ListSessions (round 2)
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[]}\n")
                .unwrap();
            stream.flush().unwrap();
            let _ = read_request(&mut reader, tx);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let killed = client
            .kill_session_if_generation(sid("s1"), "gen-s1")
            .unwrap();
        assert_eq!(killed.id, sid("s1"));
        drop(client);
        let reqs = stub.collected_requests();
        assert_eq!(
            reqs,
            vec![
                r#"{"op":"daemon_info"}"#.to_string(),
                r#"{"op":"kill","id":"s1","expected_generation":"gen-s1"}"#.to_string(),
                r#"{"op":"list_sessions"}"#.to_string(),
                r#"{"op":"list_sessions"}"#.to_string(),
            ]
        );
    }

    /// Unrelated `Grid` / `SessionExited` / blank events arriving before the `Sessions` reply are
    /// tolerated; the confirmation loop keeps reading until it sees the session list.
    #[test]
    fn kill_session_tolerates_unrelated_events_before_sessions() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_conditional_mutation_probe(&mut reader, tx, stream);
            read_request(&mut reader, tx); // Kill
            read_request(&mut reader, tx); // ListSessions
            let mut send = |s: &str| {
                stream.write_all(s.as_bytes()).unwrap();
                stream.write_all(b"\n").unwrap();
            };
            // A SessionExited for the very session we killed — informational, must be tolerated.
            send(r#"{"ev":"session_exited","id":"s1","code":0}"#);
            // A grid for a different session mid-stream.
            send(&grid_line("other", "gen-other", 5));
            // A blank line (decoded as Other).
            send("");
            // Finally the sessions reply with s1 absent.
            send(r#"{"ev":"sessions","ids":["other"]}"#);
            stream.flush().unwrap();
            let _ = read_request(&mut reader, tx);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let killed = client
            .kill_session_if_generation(sid("s1"), "gen-s1")
            .unwrap();
        assert_eq!(killed.id, sid("s1"));
    }

    /// The unrelated-event budget is shared across capability preflight and post-publication
    /// confirmation. A continuously readable peer therefore cannot keep a journal lease occupied
    /// forever by flooding valid but irrelevant events. Because this flood exhausts the budget only
    /// AFTER the Kill frame was read by the peer, its typed result must remain `PossiblyPublished`.
    #[test]
    fn publication_aware_kill_unrelated_event_flood_is_bounded_after_publication() {
        const PREFLIGHT_EVENTS: usize = GENERATION_KILL_MAX_UNRELATED_EVENTS / 2;
        const CONFIRMATION_EVENTS: usize =
            GENERATION_KILL_MAX_UNRELATED_EVENTS - PREFLIGHT_EVENTS + 1;
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"daemon_info"}"#)
            );
            let unrelated = b"{\"ev\":\"session_exited\",\"id\":\"other\",\"code\":0}\n";
            for _ in 0..PREFLIGHT_EVENTS {
                stream.write_all(unrelated).unwrap();
            }
            stream
                .write_all(
                    format!(
                        "{}\n",
                        strict_daemon_info_line("22222222222242228222222222222222", true)
                    )
                    .as_bytes(),
                )
                .unwrap();
            stream.flush().unwrap();

            read_request(&mut reader, tx); // Kill crossed the peer boundary.
            read_request(&mut reader, tx); // ListSessions confirmation request.
            for _ in 0..CONFIRMATION_EVENTS {
                stream.write_all(unrelated).unwrap();
            }
            stream.flush().unwrap();
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let error = client
            .kill_session_if_generation_with_publication(sid("s1"), "gen-s1")
            .unwrap_err();
        match error {
            KillSessionPublicationError::PossiblyPublished {
                source: DaemonClientError::Protocol { detail },
            } => assert!(
                detail.contains("unrelated reply budget"),
                "unexpected bounded-flood detail: {detail}"
            ),
            other => panic!("expected post-publication bounded flood, got {other:?}"),
        }
        drop(client);
        assert_eq!(
            stub.collected_requests(),
            vec![
                r#"{"op":"daemon_info"}"#.to_string(),
                r#"{"op":"kill","id":"s1","expected_generation":"gen-s1"}"#.to_string(),
                r#"{"op":"list_sessions"}"#.to_string(),
            ]
        );
    }

    /// A daemon `Error` reply during confirmation is surfaced as a typed `DaemonError`, not
    /// swallowed or treated as success.
    #[test]
    fn kill_session_daemon_error_is_surfaced() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_conditional_mutation_probe(&mut reader, tx, stream);
            read_request(&mut reader, tx); // Kill
            read_request(&mut reader, tx); // ListSessions
            stream
                .write_all(b"{\"ev\":\"error\",\"message\":\"nope\"}\n")
                .unwrap();
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let err = client
            .kill_session_if_generation(sid("s1"), "gen-s1")
            .unwrap_err();
        match err {
            DaemonClientError::DaemonError { message } => assert_eq!(message, "nope"),
            other => panic!("expected DaemonError, got {other:?}"),
        }
    }

    /// A daemon that keeps reporting the killed id on EVERY confirmation round eventually gives up
    /// with a bounded `Protocol` error rather than blocking forever. The stub answers every
    /// `ListSessions` with the id still present; the method must stop after `KILL_CONFIRM_ROUNDS`.
    #[test]
    fn kill_session_persistently_present_is_bounded_protocol_error() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_conditional_mutation_probe(&mut reader, tx, stream);
            read_request(&mut reader, tx); // Kill
                                           // Answer every ListSessions with s1 still present, until the client gives up and EOFs.
            while read_request(&mut reader, tx).is_some() {
                if stream
                    .write_all(b"{\"ev\":\"sessions\",\"ids\":[\"s1\"]}\n")
                    .is_err()
                {
                    break;
                }
                let _ = stream.flush();
            }
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let err = client
            .kill_session_if_generation(sid("s1"), "gen-s1")
            .unwrap_err();
        match err {
            DaemonClientError::Protocol { detail } => {
                assert!(detail.contains("still present"), "detail was {detail}");
            }
            other => panic!("expected bounded Protocol error, got {other:?}"),
        }
        drop(client);
        // Exactly one Kill + KILL_CONFIRM_ROUNDS ListSessions were written — the loop is bounded.
        let reqs = stub.collected_requests();
        assert_eq!(reqs[0], r#"{"op":"daemon_info"}"#);
        assert_eq!(
            reqs[1],
            r#"{"op":"kill","id":"s1","expected_generation":"gen-s1"}"#
        );
        assert_eq!(
            reqs.len(),
            2 + KILL_CONFIRM_ROUNDS,
            "expected probe + Kill + {KILL_CONFIRM_ROUNDS} ListSessions: {reqs:?}"
        );
    }

    /// An oversized `Sessions` reply (no newline within the cap) during kill confirmation is still
    /// bounded by `MAX_LINE_BYTES`: the client rejects it as inbound `LineTooLong` rather than
    /// buffering unboundedly.
    #[test]
    fn kill_session_oversized_reply_is_bounded() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_conditional_mutation_probe(&mut reader, tx, stream);
            read_request(&mut reader, tx); // Kill
            read_request(&mut reader, tx); // ListSessions
                                           // Begin a never-terminated line and push past the cap.
            let chunk = vec![b'a'; 1024 * 1024];
            stream
                .write_all(b"{\"ev\":\"sessions\",\"junk\":\"")
                .unwrap();
            let mut written = 0usize;
            while written <= MAX_LINE_BYTES + 1 {
                if stream.write_all(&chunk).is_err() {
                    break;
                }
                written += chunk.len();
            }
            let _ = stream.flush();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let err = client
            .kill_session_if_generation(sid("s1"), "gen-s1")
            .unwrap_err();
        match err {
            DaemonClientError::LineTooLong { direction, limit } => {
                assert_eq!(direction, Direction::Inbound);
                assert_eq!(limit, MAX_LINE_BYTES);
            }
            other => panic!("expected inbound LineTooLong, got {other:?}"),
        }
    }

    /// `kill_session` against a missing socket never gets a client at all: connect fails with
    /// `DaemonUnavailable` BEFORE any Kill request can be written.
    #[test]
    fn kill_session_missing_socket_is_daemon_unavailable_before_request() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        match DaemonClient::connect(&missing) {
            Err(DaemonClientError::DaemonUnavailable { path, .. }) => {
                assert!(path.contains("does-not-exist.sock"), "path was {path}");
            }
            Err(other) => panic!("expected DaemonUnavailable, got {other:?}"),
            Ok(_) => panic!("expected DaemonUnavailable, got a connected client"),
        }
    }

    /// A silent daemon during kill confirmation (accepts Kill + ListSessions, then never replies)
    /// hits the read deadline and surfaces a typed `Timeout` rather than hanging.
    #[test]
    fn kill_session_silent_daemon_times_out() {
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let stub = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_conditional_mutation_probe(&mut reader, tx, stream);
            read_request(&mut reader, tx); // Kill
            read_request(&mut reader, tx); // ListSessions
                                           // Send nothing; hold the connection open so the client's read blocks then times out.
            let _ = release_rx.recv();
        });
        let mut client =
            DaemonClient::connect_with_timeout(&stub.path, Duration::from_millis(150)).unwrap();
        let err = client
            .kill_session_if_generation(sid("s1"), "gen-s1")
            .unwrap_err();
        match err {
            DaemonClientError::Timeout { .. } => {}
            other => panic!("expected Timeout, got {other:?}"),
        }
        let _ = release_tx.send(());
    }

    /// A daemon that drops the connection (clean EOF) during kill confirmation surfaces
    /// `UnexpectedEof`, not a hang or a false success.
    #[test]
    fn kill_session_eof_during_confirm_is_unexpected_eof() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_conditional_mutation_probe(&mut reader, tx, stream);
            read_request(&mut reader, tx); // Kill
            read_request(&mut reader, tx); // ListSessions
                                           // Return without replying: the accept thread drops the owned stream, so the
                                           // client sees a clean EOF while awaiting the Sessions reply.
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let err = client
            .kill_session_if_generation(sid("s1"), "gen-s1")
            .unwrap_err();
        match err {
            DaemonClientError::UnexpectedEof { .. } => {}
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    #[test]
    fn strict_generation_snapshot_rejects_incomplete_and_duplicate_metadata() {
        let incomplete = DaemonClient::strict_generation_snapshot(vec![sid("s1")], Vec::new())
            .expect_err("every live id needs exact generation metadata");
        assert!(matches!(incomplete, DaemonClientError::Protocol { .. }));

        let duplicate = DaemonClient::strict_generation_snapshot(
            vec![sid("s1")],
            vec![
                SessionListInfo {
                    id: sid("s1"),
                    generation: Some("gen-a".into()),
                },
                SessionListInfo {
                    id: sid("s1"),
                    generation: Some("gen-a".into()),
                },
            ],
        )
        .expect_err("duplicate metadata cannot grant mutation authority");
        assert!(matches!(duplicate, DaemonClientError::Protocol { .. }));
    }

    #[test]
    fn strict_generation_snapshot_uses_probe_then_list_and_rejects_partial_wire_metadata() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_conditional_mutation_probe(&mut reader, tx, stream);
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"list_sessions"}"#)
            );
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[\"s1\"],\"sessions\":[]}\n")
                .unwrap();
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        assert!(matches!(
            client.generation_mutation_snapshot(),
            Err(DaemonClientError::Protocol { .. })
        ));
        drop(client);
        assert_eq!(
            stub.collected_requests(),
            vec![
                r#"{"op":"daemon_info"}"#.to_string(),
                r#"{"op":"list_sessions"}"#.to_string(),
            ]
        );
    }

    #[test]
    fn exact_lifetime_release_skips_kill_only_for_a_different_live_generation() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_conditional_mutation_probe(&mut reader, tx, stream);
            read_request(&mut reader, tx); // strict ListSessions
            stream
                .write_all(
                    b"{\"ev\":\"sessions\",\"ids\":[\"s1\"],\"sessions\":[{\"id\":\"s1\",\"generation\":\"gen-b\"}]}\n",
                )
                .unwrap();
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        client
            .release_session_lifetime_with_publication(sid("s1"), "gen-a")
            .unwrap();
        drop(client);
        assert_eq!(
            stub.collected_requests(),
            vec![
                r#"{"op":"daemon_info"}"#.to_string(),
                r#"{"op":"list_sessions"}"#.to_string(),
            ]
        );
    }

    #[test]
    fn exact_lifetime_release_sends_kill_when_live_snapshot_is_absent() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_conditional_mutation_probe(&mut reader, tx, stream);
            read_request(&mut reader, tx); // strict ListSessions: exited sessions are omitted.
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[],\"sessions\":[]}\n")
                .unwrap();
            stream.flush().unwrap();
            read_request(&mut reader, tx); // exact Kill removes a retained exit-latched object.
            read_request(&mut reader, tx); // strict confirmation ListSessions.
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[],\"sessions\":[]}\n")
                .unwrap();
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        client
            .release_session_lifetime_with_publication(sid("s1"), "gen-a")
            .unwrap();
        drop(client);
        assert_eq!(
            stub.collected_requests(),
            vec![
                r#"{"op":"daemon_info"}"#.to_string(),
                r#"{"op":"list_sessions"}"#.to_string(),
                r#"{"op":"kill","id":"s1","expected_generation":"gen-a"}"#.to_string(),
                r#"{"op":"list_sessions"}"#.to_string(),
            ]
        );
    }

    #[test]
    fn exact_lifetime_release_kills_live_a_and_accepts_live_b_as_confirmation() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_conditional_mutation_probe(&mut reader, tx, stream);
            read_request(&mut reader, tx); // strict snapshot has A.
            stream
                .write_all(
                    b"{\"ev\":\"sessions\",\"ids\":[\"s1\"],\"sessions\":[{\"id\":\"s1\",\"generation\":\"gen-a\"}]}\n",
                )
                .unwrap();
            stream.flush().unwrap();
            read_request(&mut reader, tx); // exact Kill A
            read_request(&mut reader, tx); // confirmation snapshot
            stream
                .write_all(
                    b"{\"ev\":\"sessions\",\"ids\":[\"s1\"],\"sessions\":[{\"id\":\"s1\",\"generation\":\"gen-b\"}]}\n",
                )
                .unwrap();
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        client
            .release_session_lifetime_with_publication(sid("s1"), "gen-a")
            .unwrap();
        drop(client);
        assert_eq!(
            stub.collected_requests(),
            vec![
                r#"{"op":"daemon_info"}"#.to_string(),
                r#"{"op":"list_sessions"}"#.to_string(),
                r#"{"op":"kill","id":"s1","expected_generation":"gen-a"}"#.to_string(),
                r#"{"op":"list_sessions"}"#.to_string(),
            ]
        );
    }

    #[test]
    fn exact_lifetime_release_post_write_eof_stays_possibly_published() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_conditional_mutation_probe(&mut reader, tx, stream);
            read_request(&mut reader, tx); // strict ListSessions
            stream
                .write_all(
                    b"{\"ev\":\"sessions\",\"ids\":[\"s1\"],\"sessions\":[{\"id\":\"s1\",\"generation\":\"gen-a\"}]}\n",
                )
                .unwrap();
            stream.flush().unwrap();
            read_request(&mut reader, tx); // Kill crossed the publication boundary.
            read_request(&mut reader, tx); // confirmation request, then EOF.
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        assert!(matches!(
            client.release_session_lifetime_with_publication(sid("s1"), "gen-a"),
            Err(KillSessionPublicationError::PossiblyPublished {
                source: DaemonClientError::UnexpectedEof { .. }
            })
        ));
    }

    #[test]
    fn later_fresh_client_proves_a_superseded_lifetime_without_an_inline_reconnect() {
        let ambiguous = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_conditional_mutation_probe(&mut reader, tx, stream);
            read_request(&mut reader, tx);
            stream
                .write_all(
                    b"{\"ev\":\"sessions\",\"ids\":[\"s1\"],\"sessions\":[{\"id\":\"s1\",\"generation\":\"gen-a\"}]}\n",
                )
                .unwrap();
            stream.flush().unwrap();
            read_request(&mut reader, tx); // Kill
            read_request(&mut reader, tx); // confirmation, then EOF
        });
        let mut first = DaemonClient::connect(&ambiguous.path).unwrap();
        assert!(matches!(
            first.release_session_lifetime_with_publication(sid("s1"), "gen-a"),
            Err(KillSessionPublicationError::PossiblyPublished { .. })
        ));
        drop(first);

        let replacement = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_conditional_mutation_probe(&mut reader, tx, stream);
            read_request(&mut reader, tx);
            stream
                .write_all(
                    b"{\"ev\":\"sessions\",\"ids\":[\"s1\"],\"sessions\":[{\"id\":\"s1\",\"generation\":\"gen-b\"}]}\n",
                )
                .unwrap();
            stream.flush().unwrap();
        });
        let mut second = DaemonClient::connect(&replacement.path).unwrap();
        second
            .release_session_lifetime_with_publication(sid("s1"), "gen-a")
            .unwrap();
        drop(second);
        assert_eq!(replacement.collected_requests().len(), 2);
    }

    #[test]
    fn timeout_restore_failure_cannot_downgrade_a_confirmed_lifetime() {
        let restored = Err(DaemonClientError::Io(std::io::Error::other(
            "synthetic timeout restoration failure",
        )));
        assert!(finalize_exact_lifetime_release(Ok(()), restored).is_ok());
    }
}
