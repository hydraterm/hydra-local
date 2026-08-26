//! One-session shell RUNTIME composition that ties these pieces together end to end:
//!
//! 1. endpoint discovery ([`resolve_socket_path`]) — WHICH socket to use;
//! 2. daemon client ([`DaemonClient::connect_with_timeout`]) — connect to an
//!    ALREADY-RUNNING daemon;
//! 3. record-backed session service ([`SessionService`]) — start/attach + durable record.
//!
//! This module is COMPOSITION ONLY. It owns no new persistence format and does NOT spawn, supervise,
//! or kill a daemon, open a PTY, run git, or create scratch/worktree directories. After the real
//! `DaemonClient` connect, a start path performs one non-mutating protocol-capability request on that
//! same connection; this is not a second liveness socket.
//!
//! ## Ordering and invariants
//!
//! `start_session` runs: resolve socket -> connect -> validate cwd -> require current mutation
//! protocol -> (persist endpoint) -> start/attach. Any failure before persistence returns before a
//! session record is written. The endpoint record is persisted ONLY after a successful compatible
//! connect. The `DaemonEndpoint` then points at the socket path ACTUALLY used.
//! Everything past connect delegates to [`SessionService::start_and_attach`], so its guarantees
//! hold unchanged:
//!
//! - a missing / non-directory cwd fails before any `StartSession` and writes no session record;
//! - the session record is written `Unknown` BEFORE `StartSession`;
//! - it becomes `Live` only on the daemon's `Grid` proof;
//! - a `SessionExited` before the grid deterministically marks the record `Exited`;
//! - raw ad-hoc argv is never persisted (the redaction lives in `StartParams`).
//!
//! `attach_existing_session` is the upgrade-safe inverse: resolve/connect -> list -> require the
//! requested retained id -> Attach -> Grid -> persist refreshed local metadata. A durable `Exited`
//! record may be omitted from a current daemon's live-only list; that exact id is still attached so
//! its retained final grid can reopen. This path never sends `StartSession`.
//!
//! Note on cwd vs. connect ordering: the runtime mirrors SessionService's cwd `is_dir()` check after
//! connecting and before the capability probe. So for a bad cwd the connect happens first by design,
//! but still NO request is sent and NO session
//! record is written — the invariant the caller cares about (nothing persisted, no session request)
//! is preserved. The endpoint record may have been persisted (the connect succeeded), which is
//! correct: the daemon really is reachable at that socket.

// Runtime errors carry the original consume-once start/recovery authority back to their caller.
#![allow(clippy::large_enum_variant, clippy::result_large_err)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::daemon_client::{
    AttachmentHandoffAuthority, ConditionalStartPeerIdentity, DaemonClient, DaemonClientError,
    DEFAULT_TIMEOUT,
};
use crate::daemon_endpoint::{self, DaemonEndpoint, EnvLookup};
use crate::paths::{AppPaths, RecordKind};
use crate::records::{SessionRecord, SessionStatus};
use crate::session_service::{
    ExactExistingAttach, ExistingSessionAttach, ExistingSessionMissingStart, ExistingSessionStart,
    FreshDaemonSessionStart, PreparedAgentTaskPublicationRecoveryAuthority,
    PreparedAgentTaskPublicationSettlement, PreparedAgentTaskSessionStartError,
    PreparedNewSessionStartError, PreparedNewSessionStarted, ReconcileReport, SessionService,
    SessionServiceError, StartParams,
};
use crate::store::{self, LoadOutcome, StoreError};
use crate::window_layout::{
    PreparedAgentTaskSessionCompensation, PreparedAgentTaskSessionStart, WindowLayoutError,
    WindowLayoutService,
};
use crate::ReservedProductShellStart;
use crate::{PreparedNewSessionCompensationReceipt, PreparedNewSessionStart};

/// Everything that can go wrong composing a one-session runtime. Each underlying layer keeps its own
/// typed error so a caller can still tell "couldn't figure out / persist the socket path"
/// (`Store`), "couldn't reach the daemon" (`Daemon`), and "the daemon refused / session work failed"
/// (`Session`) apart.
#[derive(Debug)]
pub enum ShellRuntimeError {
    /// Endpoint resolution, endpoint persistence, or another store operation failed.
    Store(StoreError),
    /// Connecting to the daemon failed (refused/missing socket, timeout, IO).
    Daemon(DaemonClientError),
    /// The session service failed (bad cwd, daemon refusal after connect, session exited, store).
    Session(SessionServiceError),
}

impl std::fmt::Display for ShellRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShellRuntimeError::Store(e) => write!(f, "shell runtime store error: {e}"),
            ShellRuntimeError::Daemon(e) => write!(f, "shell runtime daemon error: {e}"),
            ShellRuntimeError::Session(e) => write!(f, "shell runtime session error: {e}"),
        }
    }
}

impl std::error::Error for ShellRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ShellRuntimeError::Store(e) => Some(e),
            ShellRuntimeError::Daemon(e) => Some(e),
            ShellRuntimeError::Session(e) => Some(e),
        }
    }
}

impl From<StoreError> for ShellRuntimeError {
    fn from(e: StoreError) -> Self {
        ShellRuntimeError::Store(e)
    }
}

impl From<DaemonClientError> for ShellRuntimeError {
    fn from(e: DaemonClientError) -> Self {
        ShellRuntimeError::Daemon(e)
    }
}

impl From<SessionServiceError> for ShellRuntimeError {
    fn from(e: SessionServiceError) -> Self {
        ShellRuntimeError::Session(e)
    }
}

/// The result of a successful one-session start/attach through the runtime: the socket path that was
/// actually resolved + connected, and the final durable [`SessionRecord`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartSessionOutcome {
    pub socket_path: PathBuf,
    pub record: SessionRecord,
    attachment_handoff: Option<AttachmentHandoffAuthority>,
}

/// Runtime result for a transaction-prepared Session. It owns the rebased compensation receipt
/// and, for renderer launches, the only handoff authority for the finalized lifetime.
pub struct PreparedNewSessionRuntimeOutcome {
    pub socket_path: PathBuf,
    started: PreparedNewSessionStarted,
    attachment_handoff: Option<AttachmentHandoffAuthority>,
}

impl PreparedNewSessionRuntimeOutcome {
    pub fn record(&self) -> &SessionRecord {
        self.started.record()
    }

    pub fn take_attachment_handoff(&mut self) -> Option<AttachmentHandoffAuthority> {
        self.attachment_handoff.take()
    }

    pub(crate) fn agent_task(&self) -> Option<&crate::records::AgentTask> {
        self.started.agent_task()
    }

    pub fn into_parts(
        self,
    ) -> (
        PathBuf,
        SessionRecord,
        PreparedNewSessionCompensationReceipt,
        Option<AttachmentHandoffAuthority>,
    ) {
        let (record, compensation) = self.started.into_parts();
        (
            self.socket_path,
            record,
            compensation,
            self.attachment_handoff,
        )
    }
}

impl std::fmt::Debug for PreparedNewSessionRuntimeOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedNewSessionRuntimeOutcome")
            .field("socket_path", &self.socket_path)
            .field("started", &self.started)
            .field("handoff_offered", &self.attachment_handoff.is_some())
            .finish_non_exhaustive()
    }
}

/// Runtime-level ownership-preserving error for a consumed prepared start.
pub enum PreparedNewSessionRuntimeError {
    DefinitelyUnpublished {
        error: ShellRuntimeError,
        start: PreparedNewSessionStart,
    },
    Refused {
        error: ShellRuntimeError,
        compensation: PreparedNewSessionCompensationReceipt,
    },
    PossiblyApplied {
        error: ShellRuntimeError,
    },
}

pub(crate) enum PreparedAgentTaskSessionRuntimeError {
    DefinitelyUnpublished {
        error: ShellRuntimeError,
        start: PreparedAgentTaskSessionStart,
    },
    Refused {
        error: ShellRuntimeError,
        compensation: PreparedAgentTaskSessionCompensation,
    },
    PossiblyApplied {
        error: ShellRuntimeError,
        recovery: PreparedAgentTaskSessionRuntimeRecovery,
    },
}

pub(crate) struct PreparedAgentTaskSessionRuntimeRecovery {
    socket_path: PathBuf,
    publication: PreparedAgentTaskPublicationRecoveryAuthority,
}

impl PreparedAgentTaskSessionRuntimeRecovery {
    pub(crate) fn session_id(&self) -> &str {
        self.publication.session_id()
    }

    pub(crate) fn agent_task_id(&self) -> &str {
        self.publication.agent_task_id()
    }
}

impl std::fmt::Debug for PreparedAgentTaskSessionRuntimeRecovery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedAgentTaskSessionRuntimeRecovery")
            .field("session_id", &self.session_id())
            .field("agent_task_id", &self.agent_task_id())
            .finish_non_exhaustive()
    }
}

pub(crate) enum PreparedAgentTaskSessionRuntimeSettlement {
    Published(PreparedNewSessionRuntimeOutcome),
    Pending {
        recovery: PreparedAgentTaskSessionRuntimeRecovery,
        error: Option<ShellRuntimeError>,
    },
    Changed {
        recovery: PreparedAgentTaskSessionRuntimeRecovery,
        error: ShellRuntimeError,
    },
}

impl std::fmt::Debug for PreparedNewSessionRuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DefinitelyUnpublished { error, start } => formatter
                .debug_struct("PreparedNewSessionRuntimeError::DefinitelyUnpublished")
                .field("error", error)
                .field("start", start)
                .finish(),
            Self::Refused {
                error,
                compensation,
            } => formatter
                .debug_struct("PreparedNewSessionRuntimeError::Refused")
                .field("error", error)
                .field("compensation", compensation)
                .finish(),
            Self::PossiblyApplied { error } => formatter
                .debug_struct("PreparedNewSessionRuntimeError::PossiblyApplied")
                .field("error", error)
                .finish(),
        }
    }
}

impl StartSessionOutcome {
    pub fn new(socket_path: PathBuf, record: SessionRecord) -> Self {
        Self {
            socket_path,
            record,
            attachment_handoff: None,
        }
    }

    pub fn for_renderer(
        socket_path: PathBuf,
        record: SessionRecord,
        attachment_handoff: AttachmentHandoffAuthority,
    ) -> Self {
        Self {
            socket_path,
            record,
            attachment_handoff: Some(attachment_handoff),
        }
    }

    pub fn attachment_handoff(&self) -> Option<&AttachmentHandoffAuthority> {
        self.attachment_handoff.as_ref()
    }

    pub fn take_attachment_handoff(&mut self) -> Option<AttachmentHandoffAuthority> {
        self.attachment_handoff.take()
    }
}

/// The result of a reconciliation pass through the runtime: the socket path used + the
/// [`ReconcileReport`] from the session service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcileOutcome {
    pub socket_path: PathBuf,
    pub report: ReconcileReport,
}

/// One-session shell runtime over an injected [`AppPaths`]. Holds only borrowed config; owns no
/// daemon, no socket, no process.
pub struct ShellRuntime<'a> {
    paths: &'a AppPaths,
    connect_timeout: Duration,
    /// When true (default), a successful connect persists/updates the singleton `DaemonEndpoint`
    /// record for the socket path that was actually used, so a later run can reattach to the same
    /// daemon. The endpoint is NEVER written before a successful connect.
    persist_endpoint: bool,
}

impl<'a> ShellRuntime<'a> {
    /// A runtime with the default connect timeout that persists the endpoint after a successful
    /// connect.
    pub fn new(paths: &'a AppPaths) -> Self {
        ShellRuntime {
            paths,
            connect_timeout: DEFAULT_TIMEOUT,
            persist_endpoint: true,
        }
    }

    /// Override the connect timeout.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Disable persisting the `DaemonEndpoint` record after connect (resolution still consults an
    /// existing record, it just won't be written/updated here).
    pub fn without_endpoint_persist(mut self) -> Self {
        self.persist_endpoint = false;
        self
    }

    /// Resolve the socket (`explicit` > stored record > default) and connect to
    /// the already-running daemon. Returns the connected client AND the path used. No session record
    /// or endpoint write happens here.
    fn resolve_and_connect(
        &self,
        explicit: Option<PathBuf>,
        env: &impl EnvLookup,
    ) -> Result<(DaemonClient, PathBuf), ShellRuntimeError> {
        let socket_path = daemon_endpoint::resolve_socket_path(self.paths, explicit, env)?;
        let client = DaemonClient::connect_with_timeout(&socket_path, self.connect_timeout)?;
        Ok((client, socket_path))
    }

    /// Conditional Start captures its absolute deadline before the initial AF_UNIX connect. The
    /// returned client carries that deadline through capability proof, mutation, acknowledgement,
    /// recovery lookup/replay, Attach/Grid, and any exact handoff cancellation.
    fn resolve_and_connect_for_generation_mutation(
        &self,
        explicit: Option<PathBuf>,
        env: &impl EnvLookup,
    ) -> Result<(DaemonClient, PathBuf), ShellRuntimeError> {
        let socket_path = daemon_endpoint::resolve_socket_path(self.paths, explicit, env)?;
        let client =
            DaemonClient::connect_for_generation_mutation(&socket_path, self.connect_timeout)?;
        Ok((client, socket_path))
    }

    fn resolve_and_connect_for_generation_mutation_before(
        &self,
        explicit: Option<PathBuf>,
        env: &impl EnvLookup,
        deadline: Instant,
    ) -> Result<(DaemonClient, PathBuf), ShellRuntimeError> {
        let socket_path = daemon_endpoint::resolve_socket_path(self.paths, explicit, env)?;
        let client = DaemonClient::connect_for_generation_mutation_before(
            &socket_path,
            self.connect_timeout,
            deadline,
        )?;
        Ok((client, socket_path))
    }

    /// Resolve + connect + (persist endpoint) + start/attach ONE session, persisting the record per
    /// the record-backed session semantics described above.
    ///
    /// On a resolution or connect failure this returns BEFORE any session record is written. After a
    /// successful connect, the endpoint record is persisted (if enabled) for the socket actually
    /// used, then the call delegates to [`SessionService::start_and_attach`] — see the module docs
    /// for the full invariant list this preserves.
    pub fn start_session(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        params: &StartParams,
    ) -> Result<StartSessionOutcome, ShellRuntimeError> {
        self.start_session_with_restart(explicit_socket, env, params, false, false)
    }

    pub fn start_session_for_renderer(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        params: &StartParams,
    ) -> Result<StartSessionOutcome, ShellRuntimeError> {
        self.start_session_with_restart(explicit_socket, env, params, false, true)
    }

    pub fn start_prepared_new_session(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        start: PreparedNewSessionStart,
    ) -> Result<PreparedNewSessionRuntimeOutcome, PreparedNewSessionRuntimeError> {
        self.start_prepared_new_session_inner(explicit_socket, env, start, false, None)
    }

    pub fn start_prepared_new_session_for_renderer(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        start: PreparedNewSessionStart,
    ) -> Result<PreparedNewSessionRuntimeOutcome, PreparedNewSessionRuntimeError> {
        self.start_prepared_new_session_inner(explicit_socket, env, start, true, None)
    }

    pub(crate) fn start_prepared_agent_task_session(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        mut start: PreparedAgentTaskSessionStart,
        expected_peer: Option<&ConditionalStartPeerIdentity>,
    ) -> Result<PreparedNewSessionRuntimeOutcome, PreparedAgentTaskSessionRuntimeError> {
        let now_ms = start.as_inner().params().now_ms;
        let (mut client, socket_path) = match self
            .resolve_and_connect_for_generation_mutation(explicit_socket, env)
        {
            Ok(connected) => connected,
            Err(error) => {
                return Err(
                    PreparedAgentTaskSessionRuntimeError::DefinitelyUnpublished { error, start },
                )
            }
        };
        let observed_peer = match client.conditional_start_peer_identity_before_current_deadline() {
            Ok(peer) => peer,
            Err(error) => {
                return Err(
                    PreparedAgentTaskSessionRuntimeError::DefinitelyUnpublished {
                        error: ShellRuntimeError::Daemon(error),
                        start,
                    },
                )
            }
        };
        if expected_peer.is_some_and(|expected| expected != &observed_peer) {
            return Err(
                PreparedAgentTaskSessionRuntimeError::DefinitelyUnpublished {
                    error: ShellRuntimeError::Session(SessionServiceError::AttachAuthorityLost {
                        session_id: start.session_id().to_string(),
                    }),
                    start,
                },
            );
        }
        let expected_peer = expected_peer.unwrap_or(&observed_peer);
        if let Err(error) = self.persist_endpoint_if_enabled(&socket_path, now_ms) {
            return Err(
                PreparedAgentTaskSessionRuntimeError::DefinitelyUnpublished { error, start },
            );
        }
        if let Err(error) = WindowLayoutService::new(self.paths).bind_prepared_agent_task_start(
            &mut start,
            observed_peer.daemon_instance_id(),
            observed_peer.server_pid(),
            &socket_path,
        ) {
            let error = match error {
                WindowLayoutError::Store(error) => ShellRuntimeError::Store(error),
                _ => ShellRuntimeError::Session(SessionServiceError::AttachAuthorityLost {
                    session_id: start.session_id().to_string(),
                }),
            };
            return Err(
                PreparedAgentTaskSessionRuntimeError::DefinitelyUnpublished { error, start },
            );
        }
        match SessionService::new(self.paths).start_prepared_agent_task_session(
            client,
            start,
            expected_peer,
        ) {
            Ok(started) => Ok(PreparedNewSessionRuntimeOutcome {
                socket_path,
                started,
                attachment_handoff: None,
            }),
            Err(PreparedAgentTaskSessionStartError::DefinitelyUnpublished { error, start }) => Err(
                PreparedAgentTaskSessionRuntimeError::DefinitelyUnpublished {
                    error: ShellRuntimeError::Session(error),
                    start,
                },
            ),
            Err(PreparedAgentTaskSessionStartError::Refused {
                error,
                compensation,
            }) => Err(PreparedAgentTaskSessionRuntimeError::Refused {
                error: ShellRuntimeError::Session(error),
                compensation,
            }),
            Err(PreparedAgentTaskSessionStartError::PossiblyApplied { error, recovery }) => {
                Err(PreparedAgentTaskSessionRuntimeError::PossiblyApplied {
                    error: ShellRuntimeError::Session(error),
                    recovery: PreparedAgentTaskSessionRuntimeRecovery {
                        socket_path,
                        publication: recovery,
                    },
                })
            }
        }
    }

    pub(crate) fn settle_prepared_agent_task_session(
        &self,
        recovery: PreparedAgentTaskSessionRuntimeRecovery,
    ) -> PreparedAgentTaskSessionRuntimeSettlement {
        let PreparedAgentTaskSessionRuntimeRecovery {
            socket_path,
            publication,
        } = recovery;
        match SessionService::new(self.paths).settle_prepared_agent_task_publication(publication) {
            PreparedAgentTaskPublicationSettlement::Published(started) => {
                PreparedAgentTaskSessionRuntimeSettlement::Published(
                    PreparedNewSessionRuntimeOutcome {
                        socket_path,
                        started,
                        attachment_handoff: None,
                    },
                )
            }
            PreparedAgentTaskPublicationSettlement::Pending { recovery, error } => {
                PreparedAgentTaskSessionRuntimeSettlement::Pending {
                    recovery: PreparedAgentTaskSessionRuntimeRecovery {
                        socket_path,
                        publication: recovery,
                    },
                    error: error.map(ShellRuntimeError::Session),
                }
            }
            PreparedAgentTaskPublicationSettlement::Changed { recovery, error } => {
                PreparedAgentTaskSessionRuntimeSettlement::Changed {
                    recovery: PreparedAgentTaskSessionRuntimeRecovery {
                        socket_path,
                        publication: recovery,
                    },
                    error: ShellRuntimeError::Session(error),
                }
            }
        }
    }

    fn start_prepared_new_session_inner(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        start: PreparedNewSessionStart,
        offer_renderer_handoff: bool,
        externally_expected_peer: Option<&ConditionalStartPeerIdentity>,
    ) -> Result<PreparedNewSessionRuntimeOutcome, PreparedNewSessionRuntimeError> {
        let (mut client, socket_path) = match self
            .resolve_and_connect_for_generation_mutation(explicit_socket, env)
        {
            Ok(connected) => connected,
            Err(error) => {
                return Err(PreparedNewSessionRuntimeError::DefinitelyUnpublished { error, start })
            }
        };
        let observed_peer = match client.conditional_start_peer_identity_before_current_deadline() {
            Ok(peer) => peer,
            Err(error) => {
                return Err(PreparedNewSessionRuntimeError::DefinitelyUnpublished {
                    error: ShellRuntimeError::Daemon(error),
                    start,
                })
            }
        };
        if externally_expected_peer.is_some_and(|expected| expected != &observed_peer) {
            return Err(PreparedNewSessionRuntimeError::DefinitelyUnpublished {
                error: ShellRuntimeError::Session(SessionServiceError::AttachAuthorityLost {
                    session_id: start.session_id().to_string(),
                }),
                start,
            });
        }
        let expected_peer = externally_expected_peer.unwrap_or(&observed_peer);
        if let Err(error) = self.persist_endpoint_if_enabled(&socket_path, start.params().now_ms) {
            return Err(PreparedNewSessionRuntimeError::DefinitelyUnpublished { error, start });
        }

        let service = SessionService::new(self.paths);
        let result = if offer_renderer_handoff {
            service
                .start_prepared_new_session_for_renderer(client, start, expected_peer)
                .map(|(started, authority)| (started, Some(authority)))
        } else {
            service
                .start_prepared_new_session(client, start, expected_peer)
                .map(|started| (started, None))
        };
        match result {
            Ok((started, attachment_handoff)) => Ok(PreparedNewSessionRuntimeOutcome {
                socket_path,
                started,
                attachment_handoff,
            }),
            Err(PreparedNewSessionStartError::DefinitelyUnpublished { error, start }) => {
                Err(PreparedNewSessionRuntimeError::DefinitelyUnpublished {
                    error: ShellRuntimeError::Session(error),
                    start,
                })
            }
            Err(PreparedNewSessionStartError::Refused {
                error,
                compensation,
            }) => Err(PreparedNewSessionRuntimeError::Refused {
                error: ShellRuntimeError::Session(error),
                compensation,
            }),
            Err(PreparedNewSessionStartError::PossiblyApplied { error }) => {
                Err(PreparedNewSessionRuntimeError::PossiblyApplied {
                    error: ShellRuntimeError::Session(error),
                })
            }
        }
    }

    /// Replace a retained exited same-id session after an explicit product/user restart action.
    /// The same protocol-v2 proof and record-before-daemon ordering as an ordinary start apply;
    /// only the daemon request's narrowly scoped `restart_exited` authority differs.
    pub fn restart_exited_session(
        &self,
        _explicit_socket: Option<PathBuf>,
        _env: &impl EnvLookup,
        params: &StartParams,
    ) -> Result<StartSessionOutcome, ShellRuntimeError> {
        Err(ShellRuntimeError::Session(
            SessionServiceError::AttachAuthorityLost {
                session_id: params.session_id.clone(),
            },
        ))
    }

    pub fn restart_exited_session_for_renderer(
        &self,
        _explicit_socket: Option<PathBuf>,
        _env: &impl EnvLookup,
        params: &StartParams,
    ) -> Result<StartSessionOutcome, ShellRuntimeError> {
        Err(ShellRuntimeError::Session(
            SessionServiceError::AttachAuthorityLost {
                session_id: params.session_id.clone(),
            },
        ))
    }

    /// Restart one exact durable Exited row inside a caller-owned absolute deadline. Every retry
    /// opens a fresh reviewed connection but inherits this same deadline and must still match the
    /// complete original row before any conditional mutation is admitted.
    pub fn restart_exited_session_for_renderer_before(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        start: &ExistingSessionStart,
        deadline: Instant,
    ) -> Result<StartSessionOutcome, ShellRuntimeError> {
        self.start_session_with_restart_before(
            explicit_socket,
            env,
            start.params(),
            true,
            true,
            Some((start, deadline)),
        )
    }

    /// Product-only retained restart for one sealed reserved shell graph. This is deliberately a
    /// separate API from [`ExistingSessionStart`]: an ordinary `Shell + OptOut` row may receive only
    /// the renderer-scoped explicit default-shell authority represented there, never this reserved
    /// product authority. The fixed graph is fenced before wire and in the final IMMEDIATE
    /// publication transaction.
    pub fn restart_reserved_product_shell_for_renderer_before(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        start: &ReservedProductShellStart,
        deadline: Instant,
    ) -> Result<StartSessionOutcome, ShellRuntimeError> {
        let (client, socket_path) = self.resolve_and_connect_for_generation_mutation_before(
            explicit_socket,
            env,
            deadline,
        )?;
        let params = start.params();
        if !std::path::Path::new(&params.cwd).is_dir() {
            return Err(ShellRuntimeError::Session(
                SessionServiceError::InvalidCwd {
                    cwd: params.cwd.clone(),
                },
            ));
        }
        self.persist_endpoint_if_enabled(&socket_path, params.now_ms)?;
        let (record, authority) = SessionService::new(self.paths)
            .restart_reserved_product_shell_and_attach_for_renderer(client, start)?;
        Ok(StartSessionOutcome::for_renderer(
            socket_path,
            record,
            authority,
        ))
    }

    /// Recreate exact durable exited generation A after a reviewed fresh daemon proved the id
    /// absent. This is deliberately separate from retained-daemon restart: the wire precondition is
    /// `Absent { excluded_generation: A }`, never `ExitedGeneration(A)`.
    pub fn start_absent_excluding_session(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        params: &StartParams,
        durable_start: FreshDaemonSessionStart<'_>,
        expected_peer: &ConditionalStartPeerIdentity,
    ) -> Result<StartSessionOutcome, ShellRuntimeError> {
        self.start_absent_excluding_session_inner(
            explicit_socket,
            env,
            params,
            durable_start,
            expected_peer,
            false,
        )
    }

    pub fn start_absent_excluding_session_for_renderer(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        params: &StartParams,
        durable_start: FreshDaemonSessionStart<'_>,
        expected_peer: &ConditionalStartPeerIdentity,
    ) -> Result<StartSessionOutcome, ShellRuntimeError> {
        self.start_absent_excluding_session_inner(
            explicit_socket,
            env,
            params,
            durable_start,
            expected_peer,
            true,
        )
    }

    fn start_absent_excluding_session_inner(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        params: &StartParams,
        durable_start: FreshDaemonSessionStart<'_>,
        expected_peer: &ConditionalStartPeerIdentity,
        offer_renderer_handoff: bool,
    ) -> Result<StartSessionOutcome, ShellRuntimeError> {
        let params = match durable_start {
            FreshDaemonSessionStart::Existing { start } => start.params(),
            FreshDaemonSessionStart::ReservedProductShell { start } => start.params(),
            FreshDaemonSessionStart::New { .. } => params,
        };
        let (mut client, socket_path) =
            self.resolve_and_connect_for_generation_mutation(explicit_socket, env)?;
        if !std::path::Path::new(&params.cwd).is_dir() {
            return Err(ShellRuntimeError::Session(
                SessionServiceError::InvalidCwd {
                    cwd: params.cwd.clone(),
                },
            ));
        }
        // Fresh-daemon authority is process-specific, not path-specific. Re-prove the exact
        // readiness instance (and Linux kernel peer PID) on this same socket before endpoint,
        // workspace, or Session persistence. A path rebound therefore produces zero durable or
        // daemon mutation.
        client.require_conditional_start_peer_identity(expected_peer)?;
        self.persist_endpoint_if_enabled(&socket_path, params.now_ms)?;

        let service = SessionService::new(self.paths);
        if offer_renderer_handoff {
            let (record, authority) = service.start_absent_excluding_and_attach_for_renderer(
                client,
                params,
                durable_start,
                expected_peer,
            )?;
            Ok(StartSessionOutcome::for_renderer(
                socket_path,
                record,
                authority,
            ))
        } else {
            let record = match service.start_absent_excluding_and_attach(
                &mut client,
                params,
                durable_start,
                expected_peer,
            ) {
                Ok(record) => record,
                Err(error) => {
                    return Err(ShellRuntimeError::Session(
                        error.bind_conditional_start_recovery(client),
                    ))
                }
            };
            Ok(StartSessionOutcome::new(socket_path, record))
        }
    }

    fn start_session_with_restart(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        params: &StartParams,
        restart_exited: bool,
        offer_renderer_handoff: bool,
    ) -> Result<StartSessionOutcome, ShellRuntimeError> {
        self.start_session_with_restart_before(
            explicit_socket,
            env,
            params,
            restart_exited,
            offer_renderer_handoff,
            None,
        )
    }

    fn start_session_with_restart_before(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        params: &StartParams,
        restart_exited: bool,
        offer_renderer_handoff: bool,
        expected_and_deadline: Option<(&ExistingSessionStart, Instant)>,
    ) -> Result<StartSessionOutcome, ShellRuntimeError> {
        let (mut client, socket_path) = match expected_and_deadline {
            Some((_, deadline)) => self.resolve_and_connect_for_generation_mutation_before(
                explicit_socket,
                env,
                deadline,
            )?,
            None => self.resolve_and_connect_for_generation_mutation(explicit_socket, env)?,
        };

        // Keep malformed cwd behavior mutation-free (including no capability probe) and aligned
        // with SessionService's trust boundary.
        if !std::path::Path::new(&params.cwd).is_dir() {
            return Err(ShellRuntimeError::Session(
                SessionServiceError::InvalidCwd {
                    cwd: params.cwd.clone(),
                },
            ));
        }

        // Every start/restart proves the complete v3 peer before any endpoint or Session write.
        // The opaque receipt is then reused by SessionService, so this exact connection emits one
        // DaemonInfo request total while exact restart paths retain their sealed row CAS.
        let start_peer = client.conditional_start_peer_identity_before_current_deadline()?;

        // Only AFTER a mutation-compatible peer proof do we advertise this socket durably.
        self.persist_endpoint_if_enabled(&socket_path, params.now_ms)?;

        let svc = SessionService::new(self.paths);
        let (record, attachment_handoff) = if restart_exited && offer_renderer_handoff {
            let (record, authority) = match expected_and_deadline {
                Some((expected, _)) => svc
                    .restart_exited_and_attach_for_renderer_expected_after_peer_proof(
                        client,
                        expected,
                        &start_peer,
                    )?,
                None => svc.restart_exited_and_attach_for_renderer(client, params)?,
            };
            (record, Some(authority))
        } else if restart_exited {
            let record = match svc.restart_exited_and_attach(&mut client, params) {
                Ok(record) => record,
                Err(error) => {
                    return Err(ShellRuntimeError::Session(
                        error.bind_conditional_start_recovery(client),
                    ))
                }
            };
            (record, None)
        } else if offer_renderer_handoff {
            let (record, authority) =
                svc.start_and_attach_after_peer_proof_for_renderer(client, params, &start_peer)?;
            (record, Some(authority))
        } else {
            let record =
                match svc.start_and_attach_after_peer_proof(&mut client, params, &start_peer) {
                    Ok(record) => record,
                    Err(error) => {
                        return Err(ShellRuntimeError::Session(
                            error.bind_conditional_start_recovery(client),
                        ))
                    }
                };
            (record, None)
        };
        Ok(match attachment_handoff {
            Some(token) => StartSessionOutcome::for_renderer(socket_path, record, token),
            None => StartSessionOutcome::new(socket_path, record),
        })
    }

    /// Reopen one stable retained session without any daemon mutation. The requested id must be in
    /// the daemon's read-only snapshot, except that a durable `Exited` record is allowed to proceed
    /// to an exact-id Attach because current daemons intentionally omit retained exit latches from
    /// their live-only list. This method never silently substitutes a different PTY. Endpoint and
    /// session metadata are written only after a matching grid baseline proves attachability.
    pub fn attach_existing_session(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        params: &StartParams,
    ) -> Result<StartSessionOutcome, ShellRuntimeError> {
        self.attach_existing_session_with_renderer_handoff(explicit_socket, env, params, false)
    }

    pub fn attach_existing_session_for_renderer(
        &self,
        _explicit_socket: Option<PathBuf>,
        _env: &impl EnvLookup,
        params: &StartParams,
    ) -> Result<StartSessionOutcome, ShellRuntimeError> {
        Err(ShellRuntimeError::Session(
            SessionServiceError::AttachAuthorityLost {
                session_id: params.session_id.clone(),
            },
        ))
    }

    fn attach_existing_session_with_renderer_handoff(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        params: &StartParams,
        offer_renderer_handoff: bool,
    ) -> Result<StartSessionOutcome, ShellRuntimeError> {
        let (mut client, socket_path) = self.resolve_and_connect(explicit_socket, env)?;
        let ids = client.list_sessions()?;
        let wanted = maestro_protocol::SessionId(params.session_id.clone());
        let listed = ids.iter().any(|id| id == &wanted);
        let durable_exited = if listed {
            false
        } else {
            matches!(
                store::load_one::<SessionRecord>(
                    self.paths,
                    RecordKind::Session,
                    &params.session_id,
                )?,
                Some(LoadOutcome::Loaded(SessionRecord {
                    status: SessionStatus::Exited,
                    ..
                }))
            )
        };
        if !listed && !durable_exited {
            return Err(ShellRuntimeError::Daemon(
                DaemonClientError::RetainedSessionUnavailable { id: wanted },
            ));
        }

        if offer_renderer_handoff {
            client.require_generation_conditional_mutations()?;
            // A post-publication endpoint Store error must never discard the only Offer authority.
            self.persist_endpoint_if_enabled(&socket_path, params.now_ms)?;
        }

        let attached = if offer_renderer_handoff {
            SessionService::new(self.paths)
                .attach_existing_for_renderer(client, params)
                .map(|(record, authority)| (record, Some(authority)))
        } else {
            SessionService::new(self.paths)
                .attach_existing(&mut client, params)
                .map(|record| (record, None))
        };
        let (record, attachment_handoff) = match attached {
            Ok(attached) => attached,
            // A durable Exited record is allowed past the live-only list specifically to probe its
            // retained latch. If this daemon no longer owns that exact id (for example it restarted),
            // translate the authoritative lookup miss back to the normal unavailable signal so the
            // product startup caller may create the one now-missing stable session.
            Err(SessionServiceError::Daemon(DaemonClientError::DaemonError { message }))
                if durable_exited
                    && message == format!("no such session: {}", params.session_id) =>
            {
                return Err(ShellRuntimeError::Daemon(
                    DaemonClientError::RetainedSessionUnavailable { id: wanted },
                ));
            }
            Err(error) => return Err(ShellRuntimeError::Session(error)),
        };
        if !offer_renderer_handoff {
            // Compatibility attach remains entirely non-durable until exact Grid proves the
            // requested retained lifetime. A typed miss therefore leaves no endpoint advertisement.
            self.persist_endpoint_if_enabled(&socket_path, params.now_ms)?;
        }
        Ok(match attachment_handoff {
            Some(token) => StartSessionOutcome::for_renderer(socket_path, record, token),
            None => StartSessionOutcome::new(socket_path, record),
        })
    }

    /// Exact-id renderer reopen used by the product target path. Unlike the compatibility helper
    /// above, this deliberately does not use the live-only list as an existence gate: an exited
    /// retained grid is attachable even though it is absent there. Exact v3 attachment-fence
    /// capability is proved before the Session service may insert or refresh durable state.
    pub fn attach_existing_session_exact_for_renderer(
        &self,
        _explicit_socket: Option<PathBuf>,
        _env: &impl EnvLookup,
        params: &StartParams,
    ) -> Result<StartSessionOutcome, ShellRuntimeError> {
        Err(ShellRuntimeError::Session(
            SessionServiceError::AttachAuthorityLost {
                session_id: params.session_id.clone(),
            },
        ))
    }

    /// Headless exact retained-lifetime coordinator. It uses the same conditional probe and
    /// same-client Missing -> Absent A+W CAS as the renderer path, but never creates an Offer token.
    pub fn attach_or_start_existing_session_before(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        attach: &ExistingSessionAttach,
        missing_start: Option<ExistingSessionMissingStart<'_>>,
        deadline: Instant,
    ) -> Result<StartSessionOutcome, ShellRuntimeError> {
        self.attach_or_start_existing_session_inner(
            explicit_socket,
            env,
            attach,
            missing_start,
            deadline,
            false,
        )
    }

    /// Exact renderer retained-lifetime coordinator. One inherited absolute/event budget carries a
    /// single conditional Offer. Typed Missing closes the refusal-latched socket, reconnects to the
    /// exact same daemon instance/PID, and continues with conditional Absent start.
    pub fn attach_or_start_existing_session_for_renderer_before(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        attach: &ExistingSessionAttach,
        missing_start: Option<ExistingSessionMissingStart<'_>>,
        deadline: Instant,
    ) -> Result<StartSessionOutcome, ShellRuntimeError> {
        self.attach_or_start_existing_session_inner(
            explicit_socket,
            env,
            attach,
            missing_start,
            deadline,
            true,
        )
    }

    fn attach_or_start_existing_session_inner(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        attach: &ExistingSessionAttach,
        missing_start: Option<ExistingSessionMissingStart<'_>>,
        deadline: Instant,
        offer_renderer_handoff: bool,
    ) -> Result<StartSessionOutcome, ShellRuntimeError> {
        let (client, socket_path) = self.resolve_and_connect_for_generation_mutation_before(
            explicit_socket,
            env,
            deadline,
        )?;
        // Endpoint persistence is separately authorized local metadata. Complete it before the
        // first conditional Attach/Start frame so a Store failure remains definitely unpublished;
        // a post-publication endpoint error must never discard the only renderer Offer authority.
        self.persist_endpoint_if_enabled(&socket_path, attach.now_ms())?;
        let service = SessionService::new(self.paths);
        let reserved_product_shell = missing_start.and_then(|start| start.reserved());
        let attached = if offer_renderer_handoff {
            service.attach_existing_exact_for_renderer(client, attach, reserved_product_shell)?
        } else {
            service.attach_existing_exact_headless(client, attach, reserved_product_shell)?
        };
        let (record, authority) = match attached {
            ExactExistingAttach::Attached(record, authority) => (record, authority),
            ExactExistingAttach::StartIfAbsent(authority) => {
                let start = missing_start.ok_or_else(|| {
                    ShellRuntimeError::Daemon(DaemonClientError::RetainedSessionUnavailable {
                        id: maestro_protocol::SessionId(attach.session_id().to_string()),
                    })
                })?;
                if offer_renderer_handoff {
                    let (record, authority) =
                        service.start_retained_absent_for_renderer(authority, start)?;
                    (record, Some(authority))
                } else {
                    (
                        service.start_retained_absent_headless(authority, start)?,
                        None,
                    )
                }
            }
        };
        match authority {
            Some(authority) => Ok(StartSessionOutcome::for_renderer(
                socket_path,
                record,
                authority,
            )),
            None => Ok(StartSessionOutcome::new(socket_path, record)),
        }
    }

    /// Resolve + connect + reconcile persisted session records against the daemon's live set.
    ///
    /// The endpoint is persisted after a successful connect (if enabled), so a reconcile run also
    /// keeps the endpoint record fresh. Delegates to [`SessionService::reconcile`].
    pub fn reconcile_sessions(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        now_ms: u64,
    ) -> Result<ReconcileOutcome, ShellRuntimeError> {
        let (mut client, socket_path) = self.resolve_and_connect(explicit_socket, env)?;
        self.persist_endpoint_if_enabled(&socket_path, now_ms)?;

        let svc = SessionService::new(self.paths);
        let report = svc.reconcile(&mut client)?;
        Ok(ReconcileOutcome {
            socket_path,
            report,
        })
    }

    /// Persist/update the singleton endpoint record for `socket_path`, if persistence is enabled.
    /// Called ONLY after a successful connect.
    fn persist_endpoint_if_enabled(
        &self,
        socket_path: &std::path::Path,
        now_ms: u64,
    ) -> Result<(), ShellRuntimeError> {
        if !self.persist_endpoint {
            return Ok(());
        }
        let endpoint =
            DaemonEndpoint::new(socket_path.to_string_lossy().into_owned(), None, now_ms);
        daemon_endpoint::store_endpoint(self.paths, &endpoint, now_ms)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_endpoint::ENDPOINT_ID;
    use crate::paths::RecordKind;
    use crate::records::{LaunchSpec, SessionKind, SessionStatus};
    use crate::store::{self, LoadOutcome};
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::unix::net::{UnixListener, UnixStream as StdUnixStream};
    use std::sync::mpsc;
    use std::thread::JoinHandle;
    use tempfile::TempDir;

    // ---- env stub ---------------------------------------------------------------------------

    struct MapEnv(HashMap<String, String>);
    impl MapEnv {
        fn new(pairs: &[(&str, &str)]) -> Self {
            MapEnv(
                pairs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            )
        }
    }
    impl EnvLookup for MapEnv {
        fn get(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
    }

    struct RestartLaunchEnv;

    impl crate::LaunchEnvLookup for RestartLaunchEnv {
        fn shell_utf8(&self) -> Option<String> {
            Some("/bin/sh".into())
        }

        fn home_os(&self) -> Option<std::ffi::OsString> {
            None
        }
    }

    // ---- loopback stub daemon (no real pty-daemon) ------------------------------------------

    struct StubDaemon {
        handle: Option<JoinHandle<()>>,
    }

    impl StubDaemon {
        /// Spawn a stub on a CALLER-CHOSEN socket path (so a test can point a stored/explicit
        /// endpoint at it). The accept thread runs `serve(requests_tx, &mut stream)`. The caller
        /// owns the socket path (and its temp dir); request lines are echoed over the supplied
        /// `requests_tx` only when the serve script chooses to.
        fn spawn_at<F>(path: PathBuf, serve: F) -> StubDaemon
        where
            F: FnOnce(&mpsc::Sender<String>, &mut StdUnixStream) + Send + 'static,
        {
            let listener = UnixListener::bind(&path).unwrap();
            let (req_tx, _req_rx) = mpsc::channel::<String>();
            let handle = std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    serve(&req_tx, &mut stream);
                    drop(stream);
                }
            });
            StubDaemon {
                handle: Some(handle),
            }
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

    fn grid_line(id: &str, generation: &str, revision: u64) -> String {
        format!(
            r#"{{"ev":"grid","id":"{id}","grid":{{"generation":"{generation}","revision":{revision}}}}}"#
        )
    }

    fn accept_start_protocol(
        reader: &mut impl BufRead,
        stream: &mut StdUnixStream,
        tx: &mpsc::Sender<String>,
    ) {
        let request = read_request(reader, tx).expect("daemon_info request");
        assert_eq!(request, r#"{"op":"daemon_info"}"#);
        writeln!(
            stream,
            "{{\"ev\":\"daemon_info\",\"protocol_version\":{},\"build_version\":\"test\",\"daemon_instance_id\":\"22222222222242228222222222222222\",\"output_generation_echo\":true,\"generation_conditional_mutations\":true,\"attachment_aware_conditional_kill\":true,\"generation_conditional_start\":true,\"start_operation_ledger\":true,\"generation_conditional_attach\":true}}",
            maestro_protocol::DAEMON_PROTOCOL_VERSION
        )
        .unwrap();
        stream.flush().unwrap();
    }

    const STUB_DAEMON_INSTANCE: &str = "22222222222242228222222222222222";

    fn accept_start_operation(
        reader: &mut impl BufRead,
        stream: &mut StdUnixStream,
        tx: &mpsc::Sender<String>,
    ) -> (
        maestro_protocol::SessionId,
        maestro_protocol::SessionStartOperationToken,
    ) {
        let request: maestro_protocol::ClientRequest =
            serde_json::from_str(&read_request(reader, tx).expect("ReserveStartOperation request"))
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
                "daemon_instance_id": STUB_DAEMON_INSTANCE,
                "outcome": {"status": "reserved"},
            })
        )
        .unwrap();
        stream.flush().unwrap();
        (id, operation_token)
    }

    fn accept_conditional_start_and_attach(
        reader: &mut impl BufRead,
        stream: &mut StdUnixStream,
        tx: &mpsc::Sender<String>,
        expected_id: &str,
        generation: &str,
    ) -> (
        maestro_protocol::SessionId,
        maestro_protocol::SessionStartOperationToken,
        u64,
    ) {
        let (reserved_id, reserved_token) = accept_start_operation(reader, stream, tx);
        let request: maestro_protocol::ClientRequest = serde_json::from_str(
            &read_request(reader, tx).expect("conditional StartSession request"),
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
            other => panic!("expected conditional Absent StartSession, got {other:?}"),
        };
        assert_eq!(id, reserved_id);
        assert_eq!(id.0, expected_id);
        assert_eq!(operation_token, reserved_token);
        writeln!(
            stream,
            "{}",
            serde_json::json!({
                "ev": "conditional_session_start",
                "id": id,
                "operation_token": operation_token.as_str(),
                "daemon_instance_id": STUB_DAEMON_INSTANCE,
                "outcome": {"status": "applied", "generation": generation},
            })
        )
        .unwrap();
        stream.flush().unwrap();

        let attach: maestro_protocol::ClientRequest = serde_json::from_str(
            &read_request(reader, tx).expect("generation-conditional Attach request"),
        )
        .unwrap();
        let output_generation = match attach {
            maestro_protocol::ClientRequest::Attach {
                id: attached_id,
                want_raw_output: false,
                expected_session_generation: Some(attached_generation),
                output_generation: Some(output_generation),
                handoff: None,
            } if attached_id == id && attached_generation == generation => output_generation,
            other => panic!("expected exact post-start Attach, got {other:?}"),
        };
        (id, operation_token, output_generation)
    }

    fn accept_applied_retirement(
        reader: &mut impl BufRead,
        stream: &mut StdUnixStream,
        tx: &mpsc::Sender<String>,
        expected_id: &maestro_protocol::SessionId,
        expected_token: &maestro_protocol::SessionStartOperationToken,
        expected_generation: &str,
    ) {
        let request: maestro_protocol::ClientRequest =
            serde_json::from_str(&read_request(reader, tx).expect("RetireStartOperation request"))
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
                "daemon_instance_id": STUB_DAEMON_INSTANCE,
                "outcome": {"status": "retired"},
            })
        )
        .unwrap();
        stream.flush().unwrap();
    }

    /// Answers ReserveStartOperation+conditional StartSession+Attach+Grid+retirement.
    fn serve_grid(
        id: &'static str,
        generation: &'static str,
    ) -> impl FnOnce(&mpsc::Sender<String>, &mut StdUnixStream) + Send + 'static {
        move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            accept_start_protocol(&mut reader, stream, tx);
            let (id, operation_token, output_generation) =
                accept_conditional_start_and_attach(&mut reader, stream, tx, id, generation);
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "grid",
                    "id": id,
                    "output_generation": output_generation,
                    "grid": {"generation": generation, "revision": 1},
                })
            )
            .unwrap();
            stream.flush().unwrap();
            accept_applied_retirement(&mut reader, stream, tx, &id, &operation_token, generation);
        }
    }

    // ---- helpers ----------------------------------------------------------------------------

    fn paths_in(tmp: &TempDir) -> AppPaths {
        let paths = AppPaths::with_base(tmp.path().join("Maestro"));
        // Seed the FK parents BEFORE any session is written: every session started here uses
        // workspace "ws1" (sessions.workspace_id → workspaces), which needs its project first
        // (workspaces.project_id → projects). Production always creates the project + workspace
        // before a session.
        seed_project(&paths, "proj-1");
        seed_workspace(&paths, "ws1", "proj-1");
        paths
    }

    /// Persist a minimal parent Project so an FK-bearing Workspace can reference it.
    fn seed_project(paths: &AppPaths, id: &str) {
        crate::project::ProjectService::new(paths)
            .create(id, id, "/r", crate::project::NewProject::default(), 1)
            .ok();
    }

    /// Seed the project → workspace chain a SessionRecord needs (sessions.workspace_id →
    /// workspaces.project_id).
    fn seed_workspace(paths: &AppPaths, workspace_id: &str, project_id: &str) {
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

    fn stub_socket_path() -> (TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stub.sock");
        (dir, path)
    }

    fn load_endpoint_record(paths: &AppPaths) -> Option<DaemonEndpoint> {
        match store::load_one::<DaemonEndpoint>(paths, RecordKind::DaemonEndpoint, ENDPOINT_ID)
            .unwrap()
        {
            Some(LoadOutcome::Loaded(ep)) => Some(ep),
            _ => None,
        }
    }

    // ---- tests ------------------------------------------------------------------------------

    /// An EXPLICIT socket path is used to connect and is returned in the outcome (and wins over any
    /// default).
    #[test]
    fn explicit_socket_is_used_and_returned() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), serve_grid("s1", "gen-1"));

        // A default would point elsewhere; explicit must win.
        let env = MapEnv::new(&[("TMPDIR", "/var/tmp")]);
        let rt = ShellRuntime::new(&paths);
        let out = rt
            .start_session(Some(sock_path.clone()), &env, &params("s1", &cwd_path))
            .unwrap();

        assert_eq!(out.socket_path, sock_path);
        assert_eq!(out.record.status, SessionStatus::Live);
        drop(stub);
        drop(sock_dir);
    }

    #[test]
    fn raw_exited_restart_is_rejected_before_connect_or_record_change() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();

        let mut old = params("s1", &cwd_path);
        old.now_ms = 10;
        let old_record = SessionRecord {
            session_id: old.session_id.clone(),
            workspace_id: old.workspace_id.clone(),
            kind: old.kind,
            launch: old.launch.clone(),
            cwd_resolved: old.cwd.clone(),
            agent_task_id: old.agent_task_id.clone(),
            created_at_ms: 1,
            last_attached_at_ms: 2,
            last_known_generation: Some("gen-old".into()),
            status: SessionStatus::Exited,
        };
        store::write_record(&paths, RecordKind::Session, "s1", 3, &old_record).unwrap();

        let error = ShellRuntime::new(&paths)
            .restart_exited_session(
                Some(tmp.path().join("must-not-connect.sock")),
                &MapEnv::new(&[]),
                &old,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ShellRuntimeError::Session(SessionServiceError::AttachAuthorityLost { .. })
        ));
        assert!(matches!(
            store::load_one::<SessionRecord>(&paths, RecordKind::Session, "s1").unwrap(),
            Some(LoadOutcome::Loaded(ref current)) if current == &old_record
        ));
    }

    #[test]
    fn reviewed_exited_restart_refuses_v1_before_endpoint_or_record_change() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let workspace = match store::load_one::<crate::records::Workspace>(
            &paths,
            RecordKind::Workspace,
            "ws1",
        )
        .unwrap()
        .unwrap()
        {
            LoadOutcome::Loaded(workspace) => workspace,
            other => panic!("expected Workspace, got {other:?}"),
        };
        let old_record = SessionRecord {
            session_id: "reviewed-restart".into(),
            workspace_id: workspace.workspace_id.clone(),
            kind: SessionKind::Agent,
            launch: LaunchSpec::KnownSafe {
                launch_spec_id: "codex".into(),
                params: vec![
                    "resume".into(),
                    "60000000-0000-4000-8000-000000000002".into(),
                ],
            },
            cwd_resolved: cwd.path().to_string_lossy().into_owned(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 2,
            last_known_generation: Some("gen-old".into()),
            status: SessionStatus::Exited,
        };
        store::write_record(
            &paths,
            RecordKind::Session,
            &old_record.session_id,
            3,
            &old_record,
        )
        .unwrap();
        let start = ExistingSessionStart::known_safe_exact(
            &old_record,
            &workspace,
            &RestartLaunchEnv,
            80,
            24,
            1000,
        )
        .unwrap();

        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"daemon_info"}"#)
            );
            stream
                .write_all(
                    b"{\"ev\":\"daemon_info\",\"protocol_version\":1,\"build_version\":\"legacy\"}\n",
                )
                .unwrap();
            stream.flush().unwrap();
            assert!(
                read_request(&mut reader, tx).is_none(),
                "v1 restart preflight emits no Reserve or Start"
            );
        });

        let error = ShellRuntime::new(&paths)
            .restart_exited_session_for_renderer_before(
                Some(sock_path),
                &MapEnv::new(&[]),
                &start,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ShellRuntimeError::Daemon(DaemonClientError::MutationProtocolUnsupported {
                required: maestro_protocol::DAEMON_PROTOCOL_VERSION,
                observed: Some(1),
            })
        ));
        assert!(load_endpoint_record(&paths).is_none());
        assert!(matches!(
            store::load_one::<SessionRecord>(&paths, RecordKind::Session, &old_record.session_id)
                .unwrap(),
            Some(LoadOutcome::Loaded(ref current)) if current == &old_record
        ));
        drop(stub);
        drop(sock_dir);
    }

    #[test]
    fn headless_runtime_rejects_renderer_only_scopes_after_exact_missing_without_start() {
        for explicit_shell in [false, true] {
            let tmp = TempDir::new().unwrap();
            let paths = paths_in(&tmp);
            let cwd = TempDir::new().unwrap();
            let workspace = match store::load_one::<crate::records::Workspace>(
                &paths,
                RecordKind::Workspace,
                "ws1",
            )
            .unwrap()
            .unwrap()
            {
                LoadOutcome::Loaded(workspace) => workspace,
                other => panic!("expected Workspace, got {other:?}"),
            };
            let session_id = if explicit_shell {
                "explicit-shell-headless"
            } else {
                "explicit-latest-headless"
            };
            let old_record = SessionRecord {
                session_id: session_id.into(),
                workspace_id: workspace.workspace_id.clone(),
                kind: if explicit_shell {
                    SessionKind::Shell
                } else {
                    SessionKind::Agent
                },
                launch: if explicit_shell {
                    LaunchSpec::OptOut
                } else {
                    LaunchSpec::KnownSafe {
                        launch_spec_id: "claude".into(),
                        params: vec!["--continue".into(), "--dangerously-skip-permissions".into()],
                    }
                },
                cwd_resolved: cwd.path().to_string_lossy().into_owned(),
                agent_task_id: None,
                created_at_ms: 1,
                last_attached_at_ms: 2,
                last_known_generation: Some("generation-A".into()),
                status: SessionStatus::Exited,
            };
            store::write_record(
                &paths,
                RecordKind::Session,
                &old_record.session_id,
                3,
                &old_record,
            )
            .unwrap();
            let start = if explicit_shell {
                ExistingSessionStart::explicit_user_shell_restart(
                    &old_record,
                    &workspace,
                    vec!["/bin/sh".into(), "-l".into()],
                    80,
                    24,
                    1000,
                )
            } else {
                ExistingSessionStart::known_safe_explicit_user_restart(
                    &old_record,
                    &workspace,
                    &RestartLaunchEnv,
                    80,
                    24,
                    1000,
                )
            }
            .unwrap();
            let attach = ExistingSessionAttach::exact(&old_record, &workspace, 1000).unwrap();

            let (sock_dir, sock_path) = stub_socket_path();
            let listener = UnixListener::bind(&sock_path).unwrap();
            let (request_tx, request_rx) = mpsc::channel::<String>();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());

                accept_start_protocol(&mut reader, &mut stream, &request_tx);
                let attach_request: maestro_protocol::ClientRequest = serde_json::from_str(
                    &read_request(&mut reader, &request_tx).expect("exact headless Attach"),
                )
                .unwrap();
                assert!(matches!(
                    attach_request,
                    maestro_protocol::ClientRequest::Attach {
                        id: maestro_protocol::SessionId(ref id),
                        want_raw_output: false,
                        expected_session_generation: Some(ref generation),
                        output_generation: Some(_),
                        handoff: None,
                    } if id == session_id && generation == "generation-A"
                ));
                writeln!(
                    stream,
                    "{}",
                    serde_json::json!({
                        "ev": "session_attach_refused",
                        "id": session_id,
                        "expected_generation": "generation-A",
                        "daemon_instance_id": STUB_DAEMON_INSTANCE,
                        "reason": "missing",
                    })
                )
                .unwrap();
                stream.flush().unwrap();

                assert_eq!(
                    read_request(&mut reader, &request_tx).as_deref(),
                    Some(r#"{"op":"daemon_info"}"#),
                    "typed Missing may only re-prove the same daemon peer"
                );
                writeln!(
                    stream,
                    "{{\"ev\":\"daemon_info\",\"protocol_version\":{},\"build_version\":\"test\",\"daemon_instance_id\":\"{}\",\"output_generation_echo\":true,\"generation_conditional_mutations\":true,\"attachment_aware_conditional_kill\":true,\"generation_conditional_start\":true,\"start_operation_ledger\":true,\"generation_conditional_attach\":true}}",
                    maestro_protocol::DAEMON_PROTOCOL_VERSION,
                    STUB_DAEMON_INSTANCE,
                )
                .unwrap();
                stream.flush().unwrap();

                let mut remainder = String::new();
                reader.read_to_string(&mut remainder).unwrap();
                assert!(
                    remainder.is_empty(),
                    "headless renderer-only denial must send no Reserve or Start: {remainder}"
                );
            });

            let missing_start = if explicit_shell {
                ExistingSessionMissingStart::ExplicitUserShell(&start)
            } else {
                ExistingSessionMissingStart::KnownSafe(&start)
            };
            let error = ShellRuntime::new(&paths)
                .attach_or_start_existing_session_before(
                    Some(sock_path),
                    &MapEnv::new(&[]),
                    &attach,
                    Some(missing_start),
                    Instant::now() + Duration::from_secs(2),
                )
                .unwrap_err();
            assert!(matches!(
                error,
                ShellRuntimeError::Session(SessionServiceError::AttachAuthorityLost {
                    ref session_id,
                }) if session_id == &old_record.session_id
            ));
            server.join().unwrap();
            let requests = request_rx.try_iter().collect::<Vec<_>>();
            assert_eq!(
                requests.len(),
                3,
                "only DaemonInfo, exact Attach, and same-peer DaemonInfo are allowed"
            );
            assert!(requests.iter().all(|request| {
                !request.contains("reserve_start_operation") && !request.contains("start_session")
            }));
            assert!(matches!(
                store::load_one::<SessionRecord>(
                    &paths,
                    RecordKind::Session,
                    &old_record.session_id,
                )
                .unwrap(),
                Some(LoadOutcome::Loaded(ref current)) if current == &old_record
            ));
            drop(sock_dir);
        }
    }

    /// With NO explicit path, a stored endpoint record's socket is used.
    #[test]
    fn stored_endpoint_socket_is_used_when_no_explicit() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), serve_grid("s1", "gen-2"));

        // Pre-store an endpoint pointing at the stub; resolution should pick it (default would not
        // match the stub).
        daemon_endpoint::store_endpoint(
            &paths,
            &DaemonEndpoint::new(sock_path.to_string_lossy().into_owned(), None, 1),
            1,
        )
        .unwrap();
        let env = MapEnv::new(&[("TMPDIR", "/var/tmp")]);

        let rt = ShellRuntime::new(&paths);
        let out = rt
            .start_session(None, &env, &params("s1", &cwd_path))
            .unwrap();
        assert_eq!(out.socket_path, sock_path);
        assert_eq!(out.record.status, SessionStatus::Live);
        drop(stub);
        drop(sock_dir);
    }

    /// With neither explicit nor stored, the DEFAULT path is used. We point the default (via TMPDIR)
    /// at a directory holding the stub socket filename.
    #[test]
    fn default_endpoint_socket_is_used_when_no_explicit_or_stored() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();

        // Put the stub at <tmpdir>/<daemon socket filename> so the default resolves onto it.
        let runtime_dir = tempfile::tempdir().unwrap();
        let env = MapEnv::new(&[("TMPDIR", &runtime_dir.path().to_string_lossy())]);
        let sock_path = daemon_endpoint::default_socket_path(&env);
        let stub = StubDaemon::spawn_at(sock_path.clone(), serve_grid("s1", "gen-3"));

        let rt = ShellRuntime::new(&paths);
        let out = rt
            .start_session(None, &env, &params("s1", &cwd_path))
            .unwrap();
        assert_eq!(out.socket_path, sock_path);
        assert_eq!(out.record.status, SessionStatus::Live);
        drop(stub);
    }

    /// A connect failure (no daemon at the resolved path) returns a typed daemon error and writes NO
    /// session record AND NO endpoint record (we never advertise an unreachable socket).
    #[test]
    fn connect_failure_returns_daemon_error_and_writes_nothing() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();

        // Explicit path to a socket that does not exist.
        let missing = tmp.path().join("nope.sock");
        let env = MapEnv::new(&[]);
        let rt = ShellRuntime::new(&paths);
        let err = rt
            .start_session(Some(missing), &env, &params("s1", &cwd_path))
            .unwrap_err();
        assert!(
            matches!(
                err,
                ShellRuntimeError::Daemon(DaemonClientError::DaemonUnavailable { .. })
            ),
            "expected DaemonUnavailable, got {err:?}"
        );

        // No session record, no endpoint record.
        assert!(
            store::load_one::<SessionRecord>(&paths, RecordKind::Session, "s1")
                .unwrap()
                .is_none()
        );
        assert!(
            load_endpoint_record(&paths).is_none(),
            "endpoint must not be persisted when connect fails"
        );
    }

    /// A successful start writes the endpoint AFTER connect, and persists the session as `Live`.
    #[test]
    fn success_persists_endpoint_after_connect_then_live_session() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), serve_grid("s1", "gen-9"));
        let env = MapEnv::new(&[]);

        // No endpoint exists yet.
        assert!(load_endpoint_record(&paths).is_none());

        let rt = ShellRuntime::new(&paths);
        let out = rt
            .start_session(Some(sock_path.clone()), &env, &params("s1", &cwd_path))
            .unwrap();

        // Session persisted Live.
        assert_eq!(out.record.status, SessionStatus::Live);
        // Endpoint now persisted, pointing at the socket actually used.
        let ep = load_endpoint_record(&paths).expect("endpoint persisted after connect");
        assert_eq!(ep.socket_path, sock_path.to_string_lossy());
        drop(stub);
        drop(sock_dir);
    }

    /// A daemon `Error` after the ledger reservation frame crossed the writer boundary leaves the
    /// prewritten row `Unknown` and owns exact possibly-applied recovery. The endpoint remains
    /// persisted because capability proof established a genuinely reachable current daemon.
    #[test]
    fn daemon_error_after_start_operation_reservation_is_possibly_applied_and_leaves_record_unknown(
    ) {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            accept_start_protocol(&mut reader, stream, tx);
            assert!(matches!(
                serde_json::from_str::<maestro_protocol::ClientRequest>(
                    &read_request(&mut reader, tx).expect("ReserveStartOperation request")
                )
                .unwrap(),
                maestro_protocol::ClientRequest::ReserveStartOperation { .. }
            ));
            stream
                .write_all(b"{\"ev\":\"error\",\"message\":\"nope\"}\n")
                .unwrap();
            stream.flush().unwrap();
        });
        let env = MapEnv::new(&[]);

        let rt = ShellRuntime::new(&paths);
        let err = rt
            .start_session(Some(sock_path.clone()), &env, &params("s1", &cwd_path))
            .unwrap_err();
        match err {
            ShellRuntimeError::Session(SessionServiceError::ConditionalStartPossiblyApplied {
                session_id,
                source,
                ..
            }) => {
                assert_eq!(session_id, "s1");
                assert!(matches!(
                    *source,
                    SessionServiceError::Daemon(DaemonClientError::DaemonError {
                        ref message
                    }) if message == "nope"
                ));
            }
            other => panic!("expected owned conditional-start recovery, got {other:?}"),
        }

        // Record persisted, still Unknown.
        let on_disk = match store::load_one::<SessionRecord>(&paths, RecordKind::Session, "s1")
            .unwrap()
            .unwrap()
        {
            LoadOutcome::Loaded(r) => r,
            other => panic!("expected Loaded, got {other:?}"),
        };
        assert_eq!(on_disk.status, SessionStatus::Unknown);
        // Endpoint persisted (connect succeeded).
        assert!(load_endpoint_record(&paths).is_some());
        drop(stub);
        drop(sock_dir);
    }

    #[test]
    fn retained_v1_daemon_is_attach_only_and_start_writes_no_records() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"daemon_info"}"#)
            );
            stream
                .write_all(
                    b"{\"ev\":\"daemon_info\",\"protocol_version\":1,\"build_version\":\"legacy\"}\n",
                )
                .unwrap();
            stream.flush().unwrap();
            assert!(
                read_request(&mut reader, tx).is_none(),
                "no StartSession may follow an attach-only protocol probe"
            );
        });

        let error = ShellRuntime::new(&paths)
            .start_session(Some(sock_path), &MapEnv::new(&[]), &params("s1", &cwd_path))
            .unwrap_err();
        assert!(matches!(
            error,
            ShellRuntimeError::Daemon(DaemonClientError::MutationProtocolUnsupported {
                required: maestro_protocol::DAEMON_PROTOCOL_VERSION,
                observed: Some(1)
            })
        ));
        assert!(
            store::load_one::<SessionRecord>(&paths, RecordKind::Session, "s1")
                .unwrap()
                .is_none(),
            "refusing a legacy mutation must not create a ghost record"
        );
        assert!(load_endpoint_record(&paths).is_none());
        drop(stub);
        drop(sock_dir);
    }

    #[test]
    fn attach_only_upgrade_lists_then_attaches_without_start_session() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"list_sessions"}"#)
            );
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[\"kept\"]}\n")
                .unwrap();
            stream.flush().unwrap();
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"attach","id":"kept","want_raw_output":false}"#)
            );
            stream
                .write_all(format!("{}\n", grid_line("kept", "legacy-grid", 4)).as_bytes())
                .unwrap();
            stream.flush().unwrap();
        });

        let out = ShellRuntime::new(&paths)
            .attach_existing_session(
                Some(sock_path.clone()),
                &MapEnv::new(&[]),
                &params("kept", &cwd_path),
            )
            .unwrap();
        assert_eq!(out.socket_path, sock_path);
        assert_eq!(out.record.session_id, "kept");
        assert_eq!(out.record.status, SessionStatus::Live);
        assert_eq!(
            out.record.last_known_generation.as_deref(),
            Some("legacy-grid")
        );
        assert!(load_endpoint_record(&paths).is_some());
        drop(stub);
        drop(sock_dir);
    }

    #[test]
    fn attach_only_reopens_durable_exited_session_omitted_from_live_list() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let start = params("kept-exited", &cwd_path);
        let exited = SessionRecord {
            session_id: start.session_id.clone(),
            workspace_id: start.workspace_id.clone(),
            kind: start.kind,
            launch: start.launch.clone(),
            cwd_resolved: start.cwd.clone(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 2,
            last_known_generation: Some("retained-old".into()),
            status: SessionStatus::Exited,
        };
        store::write_record(&paths, RecordKind::Session, &exited.session_id, 2, &exited).unwrap();

        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"list_sessions"}"#)
            );
            // Current daemons report only live ids here, while retaining the exited final grid.
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[]}\n")
                .unwrap();
            stream.flush().unwrap();
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"attach","id":"kept-exited","want_raw_output":false}"#)
            );
            stream
                .write_all(format!("{}\n", grid_line("kept-exited", "retained-grid", 9)).as_bytes())
                .unwrap();
            stream.flush().unwrap();
        });

        let out = ShellRuntime::new(&paths)
            .attach_existing_session(Some(sock_path.clone()), &MapEnv::new(&[]), &start)
            .unwrap();
        assert_eq!(out.socket_path, sock_path);
        assert_eq!(out.record.status, SessionStatus::Exited);
        assert_eq!(
            out.record.last_known_generation.as_deref(),
            Some("retained-grid")
        );
        assert_eq!(out.record.created_at_ms, 1);
        assert!(load_endpoint_record(&paths).is_some());
        drop(stub);
        drop(sock_dir);
    }

    #[test]
    fn attach_only_exited_record_with_lost_daemon_maps_exact_miss_to_unavailable() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let start = params("lost-exited", &cwd_path);
        let exited = SessionRecord {
            session_id: start.session_id.clone(),
            workspace_id: start.workspace_id.clone(),
            kind: start.kind,
            launch: start.launch.clone(),
            cwd_resolved: start.cwd.clone(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 2,
            last_known_generation: Some("lost-grid".into()),
            status: SessionStatus::Exited,
        };
        store::write_record(&paths, RecordKind::Session, &exited.session_id, 2, &exited).unwrap();

        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"list_sessions"}"#)
            );
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[]}\n")
                .unwrap();
            stream.flush().unwrap();
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"attach","id":"lost-exited","want_raw_output":false}"#)
            );
            stream
                .write_all(b"{\"ev\":\"error\",\"message\":\"no such session: lost-exited\"}\n")
                .unwrap();
            stream.flush().unwrap();
        });

        let error = ShellRuntime::new(&paths)
            .attach_existing_session(Some(sock_path), &MapEnv::new(&[]), &start)
            .unwrap_err();
        assert!(matches!(
            error,
            ShellRuntimeError::Daemon(DaemonClientError::RetainedSessionUnavailable { id })
                if id.0 == "lost-exited"
        ));
        let stored =
            match store::load_one::<SessionRecord>(&paths, RecordKind::Session, "lost-exited")
                .unwrap()
            {
                Some(LoadOutcome::Loaded(record)) => record,
                other => panic!("expected exited record, got {other:?}"),
            };
        assert_eq!(stored, exited);
        assert!(load_endpoint_record(&paths).is_none());
        drop(stub);
        drop(sock_dir);
    }

    #[test]
    fn attach_only_upgrade_refuses_missing_id_without_writes() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert_eq!(
                read_request(&mut reader, tx).as_deref(),
                Some(r#"{"op":"list_sessions"}"#)
            );
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[\"other\"]}\n")
                .unwrap();
            stream.flush().unwrap();
        });

        let error = ShellRuntime::new(&paths)
            .attach_existing_session(
                Some(sock_path),
                &MapEnv::new(&[]),
                &params("missing", &cwd_path),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            ShellRuntimeError::Daemon(DaemonClientError::RetainedSessionUnavailable { id })
                if id.0 == "missing"
        ));
        assert!(
            store::load_one::<SessionRecord>(&paths, RecordKind::Session, "missing")
                .unwrap()
                .is_none()
        );
        assert!(load_endpoint_record(&paths).is_none());
        drop(stub);
        drop(sock_dir);
    }

    /// A non-directory cwd: connect happens first by design (the cwd check lives in the session
    /// service), but NO `StartSession` is sent and NO session record is written. Documented and
    /// tested here.
    #[test]
    fn non_directory_cwd_sends_no_session_request_and_writes_no_record() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        // A regular file used as cwd.
        let file_dir = TempDir::new().unwrap();
        let file_path = file_dir.path().join("a-file");
        std::fs::write(&file_path, b"not a dir").unwrap();
        let file_cwd = file_path.to_string_lossy().to_string();

        let (sock_dir, sock_path) = stub_socket_path();
        // The stub records any request it receives; we assert it receives NONE.
        let stub = StubDaemon::spawn_at(sock_path.clone(), |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            // Block on a read; the runtime should never send anything for a bad cwd.
            read_request(&mut reader, tx);
        });
        let env = MapEnv::new(&[]);

        let rt = ShellRuntime::new(&paths);
        let err = rt
            .start_session(Some(sock_path.clone()), &env, &params("s1", &file_cwd))
            .unwrap_err();
        assert!(
            matches!(
                err,
                ShellRuntimeError::Session(SessionServiceError::InvalidCwd { .. })
            ),
            "expected Session(InvalidCwd), got {err:?}"
        );

        // No session record written.
        assert!(
            store::load_one::<SessionRecord>(&paths, RecordKind::Session, "s1")
                .unwrap()
                .is_none(),
            "no session record for a bad cwd"
        );
        // No StartSession/Attach reached the daemon.
        drop(stub);
        assert!(
            {
                std::thread::sleep(Duration::from_millis(20));
                true
            },
            "settle"
        );
        drop(sock_dir);
    }

    /// Reconciliation composes endpoint -> connect -> SessionService::reconcile and returns the
    /// resolved socket path with the report.
    #[test]
    fn reconcile_composes_endpoint_connect_and_reconcile() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);

        // Two persisted Unknown sessions.
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

        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx); // DaemonInfo
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "daemon_info",
                    "protocol_version": maestro_protocol::DAEMON_PROTOCOL_VERSION,
                    "build_version": "shell-runtime-test",
                    "daemon_instance_id": STUB_DAEMON_INSTANCE,
                    "output_generation_echo": true,
                    "generation_conditional_mutations": true,
                    "attachment_aware_conditional_kill": true,
                    "generation_conditional_start": true,
                    "start_operation_ledger": true,
                    "generation_conditional_attach": true,
                })
            )
            .unwrap();
            read_request(&mut reader, tx); // strict ListSessions
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "sessions",
                    "ids": ["alive"],
                    "sessions": [{"id": "alive", "generation": "gen-alive"}],
                })
            )
            .unwrap();
            stream.flush().unwrap();
            let mut remainder = String::new();
            reader.read_to_string(&mut remainder).unwrap();
            assert!(remainder.is_empty());
        });
        let env = MapEnv::new(&[]);

        let rt = ShellRuntime::new(&paths);
        let out = rt
            .reconcile_sessions(Some(sock_path.clone()), &env, 50)
            .unwrap();
        assert_eq!(out.socket_path, sock_path);

        let status_of = |id: &str| {
            out.report
                .sessions
                .iter()
                .find(|s| s.session_id == id)
                .map(|s| s.status)
        };
        assert_eq!(status_of("alive"), Some(SessionStatus::Live));
        assert_eq!(status_of("dead"), Some(SessionStatus::Exited));
        assert!(out.report.recovered_sessions.is_empty());
        drop(stub);
        drop(sock_dir);
    }

    /// A live daemon id with no persisted record is visible through the runtime layer:
    /// `ReconcileOutcome.report.recovered_sessions` carries the orphan id (pass-through, no API
    /// change beyond the new field).
    #[test]
    fn reconcile_exposes_recovered_sessions_through_runtime() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);

        // One persisted record the daemon reports live.
        let rec = SessionRecord {
            session_id: "kept".into(),
            workspace_id: "ws1".into(),
            kind: SessionKind::Shell,
            launch: known_safe("ls"),
            cwd_resolved: "/tmp".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: Some("gen-kept".into()),
            status: SessionStatus::Unknown,
        };
        store::write_record(&paths, RecordKind::Session, "kept", 1, &rec).unwrap();

        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx); // DaemonInfo
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "daemon_info",
                    "protocol_version": maestro_protocol::DAEMON_PROTOCOL_VERSION,
                    "build_version": "shell-runtime-test",
                    "daemon_instance_id": STUB_DAEMON_INSTANCE,
                    "output_generation_echo": true,
                    "generation_conditional_mutations": true,
                    "attachment_aware_conditional_kill": true,
                    "generation_conditional_start": true,
                    "start_operation_ledger": true,
                    "generation_conditional_attach": true,
                })
            )
            .unwrap();
            read_request(&mut reader, tx); // strict ListSessions
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "sessions",
                    "ids": ["kept", "ghost"],
                    "sessions": [
                        {"id": "kept", "generation": "gen-kept"},
                        {"id": "ghost", "generation": "gen-ghost"},
                    ],
                })
            )
            .unwrap();
            stream.flush().unwrap();
            let mut remainder = String::new();
            reader.read_to_string(&mut remainder).unwrap();
            assert!(remainder.is_empty());
        });
        let env = MapEnv::new(&[]);

        let rt = ShellRuntime::new(&paths);
        let out = rt
            .reconcile_sessions(Some(sock_path.clone()), &env, 50)
            .unwrap();

        assert_eq!(
            out.report.recovered_sessions,
            vec![crate::session_service::RecoveredSession {
                session_id: "ghost".into()
            }]
        );
        assert!(out.report.sessions.iter().any(|s| s.session_id == "kept"));
        drop(stub);
        drop(sock_dir);
    }

    /// The runtime creates NO scratch / worktree / repo-metadata directories during a full
    /// start/attach composition.
    #[test]
    fn creates_no_scratch_or_worktree_metadata() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), serve_grid("s1", "gen-1"));
        let env = MapEnv::new(&[]);

        let rt = ShellRuntime::new(&paths);
        rt.start_session(Some(sock_path.clone()), &env, &params("s1", &cwd_path))
            .unwrap();

        assert!(!paths.scratch_base().exists(), "no scratch dir");
        assert!(!paths.worktree_base().exists(), "no worktree dir");
        drop(stub);
        drop(sock_dir);
    }
}
