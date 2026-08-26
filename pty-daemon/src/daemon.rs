//! The Daemon owns every Session and Channel. It is the single authority for
//! process lifetime (tier-(a) persistence) and the routing point between PTY
//! output and channels. A UI client attaches over a socket; the daemon outlives
//! the client.

use crate::channel::Channel;
use crate::ids::{ChannelId, SessionId};
use crate::protocol::{now_millis, ChannelEvent, ChannelEventKind, SessionInfo};
use crate::revision::SessionGeneration;
use crate::session::{AttachmentGuard, Session};
#[cfg(test)]
use crate::session::{MAX_ATTACHMENT_HANDOFF_TOKENS, MAX_RETIRED_ATTACHMENT_HANDOFF_TOKENS};
use anyhow::{anyhow, Result};
use maestro_protocol::request::{
    AttachmentHandoff, AttachmentHandoffToken, ConditionalSessionStart, DaemonInstanceId,
    SessionStartOperationToken, SessionStartPrecondition,
};
use maestro_protocol::{
    ConditionalSessionStartOutcome, ConditionalSessionStartRefusal, SessionAttachRefusal,
    SessionStartOperationLifecycle, SessionStartOperationReserveOutcome,
    SessionStartOperationReserveRefusal, SessionStartOperationRetireExpectation,
    SessionStartOperationRetireOutcome, SessionStartOperationStatus,
    MAX_START_OPERATION_SESSION_ID_BYTES,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Ceiling on concurrently live sessions. Each session is a child process plus
/// a VT grid (~`cols * (rows + history)` cells); an unbounded client could
/// exhaust process/file-descriptor/memory limits by spawning without end. A
/// reattach to an existing id never counts against this (it's a no-op).
const MAX_SESSIONS: usize = 64;
/// Channels retain replay and broadcast state, so they require an independent
/// ceiling rather than inheriting the session limit accidentally.
const MAX_CHANNELS: usize = 64;
const MAX_CHANNEL_ID_BYTES: usize = 512;
/// Operation entries have no TTL/LRU and are removed only by exact CAS retirement. Once this cap
/// is full, only a brand-new reservation is refused; lookup, exact Start replay, and retirement of
/// existing entries remain admitted so callers can safely recover capacity.
pub(crate) const MAX_START_OPERATION_LEDGER_ENTRIES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
enum StartOperationLedgerEntry {
    Reserved {
        id: SessionId,
    },
    Applied {
        id: SessionId,
        generation: String,
    },
    Refused {
        id: SessionId,
        reason: ConditionalSessionStartRefusal,
    },
}

impl StartOperationLedgerEntry {
    fn id(&self) -> &SessionId {
        match self {
            Self::Reserved { id } | Self::Applied { id, .. } | Self::Refused { id, .. } => id,
        }
    }
}

pub struct Daemon {
    sessions: HashMap<SessionId, Session>,
    channels: HashMap<ChannelId, Channel>,
    /// Content-blind process-lifetime start ledger. Values contain only opaque ids, opaque tokens,
    /// generation identities, and enum state—never cwd, argv, environment, grid, or output.
    start_operations: HashMap<SessionStartOperationToken, StartOperationLedgerEntry>,
    instance_id: DaemonInstanceId,
    #[cfg(test)]
    force_next_conditional_generation_collision: bool,
}

#[derive(Debug)]
pub enum SessionAttachmentAcquireError {
    Refused(SessionAttachRefusal),
    Invalid(anyhow::Error),
}

impl Default for Daemon {
    fn default() -> Self {
        let instance_id = uuid::Uuid::new_v4()
            .simple()
            .to_string()
            .parse()
            .expect("Uuid::new_v4 simple encoding is a valid DaemonInstanceId");
        Self {
            sessions: HashMap::new(),
            channels: HashMap::new(),
            start_operations: HashMap::new(),
            instance_id,
            #[cfg(test)]
            force_next_conditional_generation_collision: false,
        }
    }
}

/// Outcome of `Daemon::shutdown`: how many owned children were confirmed reaped
/// before state was cleared, and the ids of any that did NOT confirm within the
/// per-child timeout. `all_reaped()` is the clean-exit predicate; a non-empty
/// `unconfirmed` is a degraded shutdown the caller can log or exit non-zero on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownReport {
    /// Sessions that existed when shutdown began.
    pub total: usize,
    /// Children whose reaping was confirmed via the exit latch within the budget.
    pub reaped: usize,
    /// Ids of children that did not confirm reaped before the timeout. Their
    /// sessions were still dropped (PTYs closed); they just weren't confirmed.
    pub unconfirmed: Vec<SessionId>,
}

impl ShutdownReport {
    /// True when every child that existed at shutdown confirmed it was reaped.
    pub fn all_reaped(&self) -> bool {
        self.unconfirmed.is_empty()
    }
}

pub type SharedDaemon = Arc<Mutex<Daemon>>;

/// Result of atomically comparing a caller's lifetime proof with the current id mapping and, on
/// an exact match, removing that one Session from the map. The caller kills the returned Session
/// after releasing the daemon mutex, so a blocking child operation cannot stall unrelated ids and
/// can never retarget a replacement inserted after removal.
pub enum ConditionalSessionTake {
    Absent,
    GenerationMismatch,
    AttachmentInUse,
    Taken(Session),
}

impl Daemon {
    pub fn shared() -> SharedDaemon {
        Arc::new(Mutex::new(Daemon::default()))
    }

    pub fn instance_id(&self) -> &DaemonInstanceId {
        &self.instance_id
    }

    #[expect(
        dead_code,
        reason = "used by channel fan-out path once wired (channels commit)"
    )]
    pub fn has_session(&self, id: &SessionId) -> bool {
        self.sessions.contains_key(id)
    }

    pub fn start_session(
        &mut self,
        id: SessionId,
        cwd: &str,
        command: &str,
        args: &[String],
        cols: u16,
        rows: u16,
    ) -> Result<()> {
        self.start_session_with_environment(id, cwd, command, args, None, cols, rows)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn start_session_with_environment(
        &mut self,
        id: SessionId,
        cwd: &str,
        command: &str,
        args: &[String],
        child_environment: Option<&maestro_protocol::ChildEnvironment>,
        cols: u16,
        rows: u16,
    ) -> Result<()> {
        self.start_session_with_restart_and_environment(
            id,
            cwd,
            command,
            args,
            child_environment,
            cols,
            rows,
            false,
        )
    }

    /// Start a genuinely new id, reattach to a live same-id session, or (only with explicit
    /// authority) replace an exited retained same-id session. Ordinary focus/startup callers use
    /// [`start_session`](Self::start_session), whose safe default preserves an exited final grid.
    #[allow(clippy::too_many_arguments)]
    pub fn start_session_with_restart(
        &mut self,
        id: SessionId,
        cwd: &str,
        command: &str,
        args: &[String],
        cols: u16,
        rows: u16,
        restart_exited: bool,
    ) -> Result<()> {
        self.start_session_with_restart_and_environment(
            id,
            cwd,
            command,
            args,
            None,
            cols,
            rows,
            restart_exited,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn start_session_with_restart_and_environment(
        &mut self,
        id: SessionId,
        cwd: &str,
        command: &str,
        args: &[String],
        child_environment: Option<&maestro_protocol::ChildEnvironment>,
        cols: u16,
        rows: u16,
        restart_exited: bool,
    ) -> Result<()> {
        // Reattach semantics: a live same-id session is never respawned. An exited same-id entry is
        // replaced only by an explicit restart request; an ordinary StartSession preserves its
        // final grid, scrollback, and exit latch even if the durable status update is still racing.
        // When restart is explicit, the old entry remains installed until replacement spawn
        // succeeds, so invalid cwd/argv/exec never destroys the retained terminal.
        let replacing_exited_same_id = match self.sessions.get(&id) {
            Some(existing) if existing.exit_state().is_none() => return Ok(()),
            Some(_) if !restart_exited => {
                return Err(anyhow!(
                    "session {id} has exited and is retained; explicit restart authority is required"
                ));
            }
            Some(existing) if existing.attachment_in_use() => {
                return Err(anyhow!(
                    "session {id} has an active attachment or pending attachment handoff"
                ));
            }
            Some(_) => true,
            None => false,
        };
        // Validate client-supplied spawn inputs at this trust boundary. An empty
        // command would spawn nothing useful; a command carrying a NUL can't be
        // passed to execvp and would surface as an opaque OS error. cwd, if set,
        // must be a real directory — otherwise the spawn fails deep inside
        // portable-pty with a confusing message instead of a clear one here.
        if command.is_empty() {
            return Err(anyhow!("command must not be empty"));
        }
        if command.contains('\0') || args.iter().any(|a| a.contains('\0')) {
            return Err(anyhow!("command and args must not contain NUL bytes"));
        }
        validate_child_environment(child_environment)?;
        if !cwd.is_empty() && !std::path::Path::new(cwd).is_dir() {
            return Err(anyhow!("cwd is not a directory: {cwd}"));
        }
        // Reject a grid whose worst-case JSON snapshot could not cross the socket as a
        // single newline-delimited line (`MAX_LINE_BYTES`). A direct protocol request
        // gets an explicit error (the native UI computes a compliant size before
        // sending; a misbehaving direct client learns its request is out of bounds
        // rather than silently getting a clamped grid). Checked on the SAME normalized
        // dims spawn will use, so the accepted grid is always wire-shippable.
        let (n_cols, n_rows) = crate::grid::normalize_dims(cols, rows);
        if !crate::grid::fits_snapshot_budget(n_cols, n_rows) {
            return Err(anyhow!(
                "grid {n_cols}x{n_rows} exceeds the snapshot cell budget ({} cells); \
                 request a smaller size",
                crate::grid::MAX_SNAPSHOT_CELLS
            ));
        }

        // A same-id replacement does not consume another map slot. A genuinely new id at capacity
        // may use one retained exited snapshot's slot, but never evict that snapshot before spawn:
        // if spawn fails, every retained terminal remains untouched.
        let needs_capacity_eviction =
            !replacing_exited_same_id && self.sessions.len() >= MAX_SESSIONS;
        if needs_capacity_eviction
            && !self
                .sessions
                .values()
                .any(|session| session.exit_state().is_some() && !session.attachment_in_use())
        {
            return Err(anyhow!(
                "session limit reached ({MAX_SESSIONS}); kill a session before starting another"
            ));
        }

        let session = Session::spawn(
            id.clone(),
            cwd,
            command,
            args,
            child_environment,
            cols,
            rows,
        )?;

        if needs_capacity_eviction {
            // The preflight above proved at least one candidate while the daemon mutex was held.
            // Reader threads may only add more exit latches; they cannot remove map entries. Evict
            // exactly one snapshot (the one slot required), preserving all other final output.
            let exited_id = self
                .sessions
                .iter()
                .find_map(|(candidate_id, candidate)| {
                    (candidate.exit_state().is_some() && !candidate.attachment_in_use())
                        .then(|| candidate_id.clone())
                })
                .expect("capacity eviction candidate remains installed under daemon lock");
            self.sessions.remove(&exited_id);
        }

        // HashMap::insert drops the old exited same-id Session only now, after the replacement PTY
        // exists. A live same-id entry returned above and can never reach this point.
        self.sessions.insert(id, session);
        Ok(())
    }

    /// Atomically compare one exact daemon-map precondition and, only on a match, create a fresh
    /// Session and publish its generation into the reserved ledger entry. The global daemon mutex
    /// is held by the caller across this entire method, so no Attach/Kill/other Start can interleave
    /// between the predicate, Session insertion, and Reserved-to-Applied transition.
    #[allow(clippy::too_many_arguments)]
    pub fn start_session_conditionally(
        &mut self,
        id: SessionId,
        cwd: &str,
        command: &str,
        args: &[String],
        child_environment: Option<&maestro_protocol::ChildEnvironment>,
        cols: u16,
        rows: u16,
        conditional: &ConditionalSessionStart,
    ) -> ConditionalSessionStartOutcome {
        // Conditional Start is legal only for the exact, previously reserved content-blind tuple.
        // Applied and Refused are idempotent replay answers even after the Session map removes or
        // replaces the resulting generation, until an explicit exact retirement removes them.
        match self.start_operations.get(&conditional.operation_token) {
            Some(StartOperationLedgerEntry::Reserved { id: reserved_id }) if reserved_id == &id => {
            }
            Some(StartOperationLedgerEntry::Applied {
                id: applied_id,
                generation,
            }) if applied_id == &id => {
                return ConditionalSessionStartOutcome::AlreadyApplied {
                    generation: generation.clone(),
                }
            }
            Some(StartOperationLedgerEntry::Refused {
                id: refused_id,
                reason,
            }) if refused_id == &id => {
                return ConditionalSessionStartOutcome::Refused { reason: *reason }
            }
            Some(_) | None => {
                return ConditionalSessionStartOutcome::Refused {
                    reason: ConditionalSessionStartRefusal::PreconditionFailed,
                }
            }
        }

        let restart_exited = match &conditional.precondition {
            SessionStartPrecondition::Absent {
                excluded_generation,
            } => {
                if excluded_generation
                    .as_ref()
                    .is_some_and(|generation| generation.is_empty() || generation.len() > 128)
                {
                    return self.refuse_reserved_start(
                        &id,
                        &conditional.operation_token,
                        ConditionalSessionStartRefusal::PreconditionFailed,
                    );
                }
                if self.sessions.contains_key(&id) {
                    return self.refuse_reserved_start(
                        &id,
                        &conditional.operation_token,
                        ConditionalSessionStartRefusal::PreconditionFailed,
                    );
                }
                false
            }
            SessionStartPrecondition::ExitedGeneration {
                expected_generation,
            } => {
                if expected_generation.is_empty() || expected_generation.len() > 128 {
                    return self.refuse_reserved_start(
                        &id,
                        &conditional.operation_token,
                        ConditionalSessionStartRefusal::PreconditionFailed,
                    );
                }
                let Some(existing) = self.sessions.get(&id) else {
                    return self.refuse_reserved_start(
                        &id,
                        &conditional.operation_token,
                        ConditionalSessionStartRefusal::PreconditionFailed,
                    );
                };
                if existing.generation() != *expected_generation || existing.exit_state().is_none()
                {
                    return self.refuse_reserved_start(
                        &id,
                        &conditional.operation_token,
                        ConditionalSessionStartRefusal::PreconditionFailed,
                    );
                }
                if existing.attachment_in_use() {
                    return self.refuse_reserved_start(
                        &id,
                        &conditional.operation_token,
                        ConditionalSessionStartRefusal::AttachmentInUse,
                    );
                }
                true
            }
        };

        // Conditional start never reaps an unrelated retained snapshot to make room: its authority
        // is one exact id predicate, not a global capacity mutation. Same-id replacement reuses its
        // slot; an Absent start at capacity fails without touching any existing mapping.
        if !restart_exited && self.sessions.len() >= MAX_SESSIONS {
            return self.refuse_reserved_start(
                &id,
                &conditional.operation_token,
                ConditionalSessionStartRefusal::SpawnFailed,
            );
        }

        // Validate every spawn input before creating a candidate. The old exact Session remains
        // mapped throughout validation and spawn, so any failure preserves its exit latch, grid,
        // attachments, and operation token byte-for-byte.
        if command.is_empty()
            || command.contains('\0')
            || args.iter().any(|argument| argument.contains('\0'))
            || validate_child_environment(child_environment).is_err()
            || (!cwd.is_empty() && !std::path::Path::new(cwd).is_dir())
        {
            return self.refuse_reserved_start(
                &id,
                &conditional.operation_token,
                ConditionalSessionStartRefusal::SpawnFailed,
            );
        }
        let (normalized_cols, normalized_rows) = crate::grid::normalize_dims(cols, rows);
        if !crate::grid::fits_snapshot_budget(normalized_cols, normalized_rows) {
            return self.refuse_reserved_start(
                &id,
                &conditional.operation_token,
                ConditionalSessionStartRefusal::SpawnFailed,
            );
        }
        #[cfg(test)]
        if std::mem::take(&mut self.force_next_conditional_generation_collision) {
            // Deterministic proof seam: collision refusal occurs before PTY creation/exec, so the
            // test command cannot leave even an external side effect marker.
            return self.refuse_reserved_start(
                &id,
                &conditional.operation_token,
                ConditionalSessionStartRefusal::SpawnFailed,
            );
        }
        let candidate_generation = match &conditional.precondition {
            SessionStartPrecondition::Absent {
                excluded_generation,
            } => excluded_generation
                .as_deref()
                .map_or_else(SessionGeneration::new, SessionGeneration::new_excluding),
            SessionStartPrecondition::ExitedGeneration {
                expected_generation,
            } => SessionGeneration::new_excluding(expected_generation),
        };
        let generation = candidate_generation.to_string();
        let candidate = match Session::spawn_with_generation(
            id.clone(),
            cwd,
            command,
            args,
            child_environment,
            cols,
            rows,
            candidate_generation,
        ) {
            Ok(candidate) => candidate,
            Err(_) => {
                return self.refuse_reserved_start(
                    &id,
                    &conditional.operation_token,
                    ConditionalSessionStartRefusal::SpawnFailed,
                )
            }
        };
        debug_assert_eq!(candidate.generation(), generation);
        // This is the sole destructive map publication. Candidate validation, generation proof,
        // and ledger reservation proof all completed first, so inserting can no longer fail.
        self.sessions.insert(id.clone(), candidate);
        let entry = self
            .start_operations
            .get_mut(&conditional.operation_token)
            .expect("exact reserved operation remains present under daemon lock");
        debug_assert!(matches!(
            entry,
            StartOperationLedgerEntry::Reserved { id: reserved_id } if reserved_id == &id
        ));
        *entry = StartOperationLedgerEntry::Applied {
            id,
            generation: generation.clone(),
        };
        ConditionalSessionStartOutcome::Applied { generation }
    }

    fn refuse_reserved_start(
        &mut self,
        id: &SessionId,
        operation_token: &SessionStartOperationToken,
        reason: ConditionalSessionStartRefusal,
    ) -> ConditionalSessionStartOutcome {
        let entry = self
            .start_operations
            .get_mut(operation_token)
            .expect("conditional Start reached validation only with a reserved operation");
        debug_assert!(matches!(
            entry,
            StartOperationLedgerEntry::Reserved { id: reserved_id } if reserved_id == id
        ));
        *entry = StartOperationLedgerEntry::Refused {
            id: id.clone(),
            reason,
        };
        ConditionalSessionStartOutcome::Refused { reason }
    }

    /// Reserve one content-blind tuple retained until exact retirement. Existing entries are
    /// always handled before the cap check, so replay/recovery remains available even after new
    /// reservations are exhausted.
    pub fn reserve_start_operation(
        &mut self,
        id: SessionId,
        operation_token: SessionStartOperationToken,
    ) -> SessionStartOperationReserveOutcome {
        if id.0.is_empty()
            || id.0.len() > MAX_START_OPERATION_SESSION_ID_BYTES
            || id.0.chars().any(char::is_control)
        {
            return SessionStartOperationReserveOutcome::Refused {
                reason: SessionStartOperationReserveRefusal::InvalidSessionId,
            };
        }
        if let Some(existing) = self.start_operations.get(&operation_token) {
            return match existing {
                StartOperationLedgerEntry::Reserved { id: reserved_id } if reserved_id == &id => {
                    SessionStartOperationReserveOutcome::AlreadyReserved
                }
                StartOperationLedgerEntry::Applied { id: applied_id, .. }
                | StartOperationLedgerEntry::Refused { id: applied_id, .. }
                    if applied_id == &id =>
                {
                    SessionStartOperationReserveOutcome::Refused {
                        reason: SessionStartOperationReserveRefusal::AlreadyTerminal,
                    }
                }
                _ => SessionStartOperationReserveOutcome::Refused {
                    reason: SessionStartOperationReserveRefusal::TokenInUse,
                },
            };
        }
        if self.start_operations.len() >= MAX_START_OPERATION_LEDGER_ENTRIES {
            return SessionStartOperationReserveOutcome::Refused {
                reason: SessionStartOperationReserveRefusal::LedgerFull,
            };
        }
        self.start_operations
            .insert(operation_token, StartOperationLedgerEntry::Reserved { id });
        SessionStartOperationReserveOutcome::Reserved
    }

    /// Read-only recovery for a conditional start whose acknowledgement was ambiguous. An exact
    /// tuple reports its retained operation state even after Session removal/replacement.
    pub fn lookup_start_operation(
        &self,
        id: &SessionId,
        operation_token: &SessionStartOperationToken,
    ) -> SessionStartOperationStatus {
        match self.start_operations.get(operation_token) {
            Some(StartOperationLedgerEntry::Reserved { id: reserved_id }) if reserved_id == id => {
                SessionStartOperationStatus::Reserved
            }
            Some(StartOperationLedgerEntry::Refused { id: refused_id, .. }) if refused_id == id => {
                SessionStartOperationStatus::Refused
            }
            Some(StartOperationLedgerEntry::Applied {
                id: applied_id,
                generation,
            }) if applied_id == id => {
                let lifecycle = match self.sessions.get(id) {
                    Some(session) if session.generation() == *generation => {
                        if session.exit_state().is_some() {
                            SessionStartOperationLifecycle::Exited
                        } else {
                            SessionStartOperationLifecycle::Live
                        }
                    }
                    Some(_) | None => SessionStartOperationLifecycle::Removed,
                };
                SessionStartOperationStatus::Applied {
                    generation: generation.clone(),
                    lifecycle,
                }
            }
            Some(_) | None => SessionStartOperationStatus::Unknown,
        }
    }

    /// Exact CAS retirement. The daemon mutex held by the caller makes removal a barrier with
    /// Start: either Start observes Reserved first and publishes Applied(G), or the later Start
    /// observes Missing and refuses without spawning.
    pub fn retire_start_operation(
        &mut self,
        id: &SessionId,
        operation_token: &SessionStartOperationToken,
        expected: &SessionStartOperationRetireExpectation,
    ) -> SessionStartOperationRetireOutcome {
        let current = self.lookup_start_operation(id, operation_token);
        let may_retire = match (expected, &current) {
            (
                SessionStartOperationRetireExpectation::Unapplied,
                SessionStartOperationStatus::Reserved | SessionStartOperationStatus::Refused,
            ) => true,
            (
                SessionStartOperationRetireExpectation::Applied {
                    generation: expected_generation,
                },
                SessionStartOperationStatus::Applied { generation, .. },
            ) => expected_generation == generation,
            _ => false,
        };
        if may_retire {
            let entry = self
                .start_operations
                .get(operation_token)
                .expect("retirable exact operation remains present under daemon lock");
            debug_assert_eq!(entry.id(), id);
            self.start_operations.remove(operation_token);
            return SessionStartOperationRetireOutcome::Retired;
        }
        if current == SessionStartOperationStatus::Unknown {
            return SessionStartOperationRetireOutcome::AlreadyRetired;
        }
        SessionStartOperationRetireOutcome::Conflict { current }
    }

    #[cfg(test)]
    #[allow(dead_code)] // Reserved fault-injection seam for conditional-start collision tests.
    pub fn force_next_conditional_generation_collision_for_test(&mut self) {
        self.force_next_conditional_generation_collision = true;
    }

    pub fn session(&self, id: &SessionId) -> Result<&Session> {
        self.sessions
            .get(id)
            .ok_or_else(|| anyhow!("no such session: {id}"))
    }

    /// Acquire a non-cloneable owner guard on the current exact Session object. Callers invoke this
    /// while holding the daemon mutex, so it linearizes with conditional Kill and same-id restart.
    pub fn acquire_session_attachment(
        &self,
        id: &SessionId,
        handoff: Option<&AttachmentHandoff>,
        owner_nonce: u64,
    ) -> Result<AttachmentGuard> {
        self.session(id)?.acquire_attachment(handoff, owner_nonce)
    }

    /// Generation-conditional attachment linearizes the lifetime comparison and guard acquisition
    /// under the daemon map lock held by the caller. A refusal therefore exposes no Grid and cannot
    /// suffer a list/probe-to-Attach ABA window.
    pub fn acquire_session_attachment_if_generation(
        &self,
        id: &SessionId,
        expected_generation: &str,
        handoff: Option<&AttachmentHandoff>,
        owner_nonce: u64,
    ) -> std::result::Result<AttachmentGuard, SessionAttachmentAcquireError> {
        let session = self
            .sessions
            .get(id)
            .ok_or(SessionAttachmentAcquireError::Refused(
                SessionAttachRefusal::Missing,
            ))?;
        if session.generation() != expected_generation {
            return Err(SessionAttachmentAcquireError::Refused(
                SessionAttachRefusal::GenerationMismatch,
            ));
        }
        session
            .acquire_attachment(handoff, owner_nonce)
            .map_err(SessionAttachmentAcquireError::Invalid)
    }

    pub fn cancel_session_attachment_handoff(
        &self,
        id: &SessionId,
        token: &AttachmentHandoffToken,
    ) {
        if let Some(session) = self.sessions.get(id) {
            session.cancel_attachment_handoff(token);
        }
    }

    #[cfg(test)]
    pub fn kill_session(&mut self, id: &SessionId) {
        // Terminate the child explicitly first — dropping the Session closes the
        // PTY, but a child sitting in its own read loop may not exit on PTY
        // close alone. kill_child guarantees it goes away.
        if let Some(s) = self.sessions.get(id) {
            s.kill_child();
        }
        self.sessions.remove(id);
    }

    pub fn take_session_if_generation(
        &mut self,
        id: &SessionId,
        expected_generation: &str,
    ) -> ConditionalSessionTake {
        let Some(session) = self.sessions.get(id) else {
            return ConditionalSessionTake::Absent;
        };
        if session.generation() != expected_generation {
            return ConditionalSessionTake::GenerationMismatch;
        }
        if session.attachment_in_use() {
            return ConditionalSessionTake::AttachmentInUse;
        }
        ConditionalSessionTake::Taken(
            self.sessions
                .remove(id)
                .expect("generation-matched session remains mapped under daemon lock"),
        )
    }

    #[cfg(test)]
    pub fn session_ids(&self) -> Vec<SessionId> {
        self.sessions
            .iter()
            .filter(|(_, session)| session.exit_state().is_none())
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn session_infos(&self) -> Vec<SessionInfo> {
        self.sessions
            .values()
            .filter_map(|s| {
                s.live_generation().map(|generation| SessionInfo {
                    id: s.id.clone(),
                    cwd: if s.cwd.is_empty() {
                        None
                    } else {
                        Some(s.cwd.clone())
                    },
                    generation: Some(generation),
                })
            })
            .collect()
    }

    /// Drop every session whose child has already exited, returning its slot to
    /// the MAX_SESSIONS budget. A naturally-ended session (user typed `exit`,
    /// agent finished) is never killed by anyone, so without an explicit reap it
    /// would occupy capacity forever. Dropping the Session here closes its PTY
    /// and frees its grid/scrollback buffers.
    #[cfg(test)]
    pub fn reap_exited_sessions(&mut self) {
        self.sessions
            .retain(|_, s| s.exit_state().is_none() || s.attachment_in_use());
    }

    /// Terminate and reap every owned child, then drop all sessions. Without
    /// this, daemon exit just drops the session map: the PTY masters close, but a
    /// child sitting in its own loop may linger as an orphan/zombie rather than
    /// being collected. `shutdown` kills each child and waits for the reader
    /// thread to `wait()` it (observable via the exit latch). Per-child wait is
    /// bounded so one stuck child can't wedge the whole shutdown.
    ///
    /// Returns a `ShutdownReport` recording how many children confirmed reaped vs.
    /// timed out, so the caller can distinguish a clean shutdown from a degraded
    /// one (and log/exit accordingly) rather than silently assuming every child
    /// was collected. State is cleared regardless — a child that didn't confirm
    /// is still dropped (its PTY closes); we just report that it was unconfirmed
    /// instead of overstating "all reaped".
    pub fn shutdown(&mut self) -> ShutdownReport {
        const PER_CHILD_REAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
        self.shutdown_with_timeout(PER_CHILD_REAP_TIMEOUT)
    }

    /// `shutdown` with an explicit per-child reap budget. Split out so a test can
    /// force the timeout branch deterministically (a `Duration::ZERO` budget makes
    /// every still-running child report unconfirmed) without waiting on a real
    /// stuck child.
    fn shutdown_with_timeout(&mut self, per_child: std::time::Duration) -> ShutdownReport {
        let total = self.sessions.len();
        let mut reaped = 0usize;
        let mut unconfirmed: Vec<SessionId> = Vec::new();
        for (id, session) in self.sessions.iter() {
            if session.kill_and_wait(per_child) {
                reaped += 1;
            } else {
                unconfirmed.push(id.clone());
            }
        }
        self.sessions.clear();
        self.channels.clear();
        ShutdownReport {
            total,
            reaped,
            unconfirmed,
        }
    }

    pub fn open_channel(&mut self, id: ChannelId) -> Result<()> {
        if id.0.is_empty()
            || id.0.len() > MAX_CHANNEL_ID_BYTES
            || id.0.chars().any(char::is_control)
        {
            return Err(anyhow!(
                "channel id must be non-empty, control-free, and at most {MAX_CHANNEL_ID_BYTES} bytes"
            ));
        }
        if self.channels.contains_key(&id) {
            return Ok(());
        }
        if self.channels.len() >= MAX_CHANNELS {
            return Err(anyhow!(
                "channel limit reached ({MAX_CHANNELS}); reuse or close a channel before opening another"
            ));
        }
        self.channels.insert(id.clone(), Channel::new(id));
        Ok(())
    }

    pub fn join_channel(&mut self, channel: &ChannelId, session: &SessionId) -> Result<()> {
        if !self.sessions.contains_key(session) {
            return Err(anyhow!("no such session: {session}"));
        }
        let ch = self
            .channels
            .get_mut(channel)
            .ok_or_else(|| anyhow!("no such channel: {channel}"))?;
        ch.join(session.clone());
        if let Some(s) = self.sessions.get_mut(session) {
            if !s.subscriptions.contains(channel) {
                s.subscriptions.push(channel.clone());
            }
        }
        Ok(())
    }

    pub fn publish(&mut self, event: ChannelEvent) -> Result<()> {
        let ch = self
            .channels
            .get_mut(&event.channel)
            .ok_or_else(|| anyhow!("no such channel: {}", event.channel))?;
        let sender = event
            .from
            .as_ref()
            .ok_or_else(|| anyhow!("channel publish requires a sender session"))?;
        if !self.sessions.contains_key(sender) {
            return Err(anyhow!("no such sender session: {sender}"));
        }
        if !ch.members.contains(sender) {
            return Err(anyhow!(
                "sender session {sender} is not a member of channel {}",
                event.channel
            ));
        }
        ch.publish(event)
    }

    /// Helper: fan a session's raw output onto every channel it belongs to as an
    /// Output event. Takes `&[u8]` — the PTY emits raw bytes, and a chunk boundary can
    /// split a multibyte grapheme, so the fan-out surface must NOT be `&str` (that would
    /// re-introduce the UTF-8-split corruption the rest of the daemon avoids).
    ///
    /// The wire event still carries `text: String`; the lossy conversion here is the
    /// ONE remaining boundary defect. Before this can be wired into the per-session pump,
    /// `ChannelEventKind::Output { text }` must become a raw-byte field so split graphemes
    /// survive end to end. Until then this helper is dead code and the lossy step is
    /// explicitly flagged rather than hidden behind a `&str` signature.
    #[expect(dead_code, reason = "reserved for raw-byte channel fan-out")]
    pub fn fan_output_to_channels(&mut self, id: &SessionId, bytes: &[u8]) {
        let subs = match self.sessions.get(id) {
            Some(s) => s.subscriptions.clone(),
            None => return,
        };
        // BOUNDARY DEFECT (see doc comment): lossy until the channel wire event carries
        // base64 raw bytes. Kept lossy-not-panicking so a split grapheme never aborts.
        let text = String::from_utf8_lossy(bytes).into_owned();
        for channel in subs {
            if let Some(ch) = self.channels.get_mut(&channel) {
                let _ = ch.publish(ChannelEvent {
                    channel: channel.clone(),
                    from: Some(id.clone()),
                    kind: ChannelEventKind::Output { text: text.clone() },
                    ts: now_millis(),
                });
            }
        }
    }
}

fn validate_child_environment(
    environment: Option<&maestro_protocol::ChildEnvironment>,
) -> Result<()> {
    let Some(environment) = environment else {
        return Ok(());
    };
    let home = std::path::Path::new(&environment.home);
    let shell = std::path::Path::new(&environment.shell);
    let normalized_absolute = |path: &std::path::Path| {
        path.is_absolute()
            && path.components().all(|component| {
                matches!(
                    component,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
    };
    if environment.home.is_empty()
        || environment.shell.is_empty()
        || environment.home.len() > 4096
        || environment.shell.len() > 4096
        || environment.home.contains(['\0', '\n', '\r'])
        || environment.shell.contains(['\0', '\n', '\r'])
        || !normalized_absolute(home)
        || !normalized_absolute(shell)
        || home == std::path::Path::new("/")
        || !home.is_dir()
    {
        return Err(anyhow!("headless child environment is invalid"));
    }
    let metadata =
        std::fs::metadata(shell).map_err(|_| anyhow!("headless child environment is invalid"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o111 == 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(anyhow!("headless child environment is invalid"));
        }
    }
    #[cfg(not(unix))]
    if !metadata.is_file() {
        return Err(anyhow!("headless child environment is invalid"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn sid(s: &str) -> SessionId {
        SessionId(s.to_string())
    }

    /// Spin until the session's child has exited (or we time out). Spawning a
    /// child + reaching EOF on its PTY is inherently async, so we poll the
    /// persisted exit_state rather than sleeping a fixed amount.
    fn wait_for_exit(d: &Daemon, id: &SessionId) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Some(s) = d.sessions.get(id) {
                if s.exit_state().is_some() {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("session {id} did not record an exit within the timeout");
    }

    fn token(value: &str) -> AttachmentHandoffToken {
        value.parse().expect("test token is fixed lowercase hex")
    }

    fn start_token(index: usize) -> SessionStartOperationToken {
        let mut value = format!("{index:032x}");
        value.replace_range(12..13, "4");
        value.replace_range(16..17, "8");
        value.parse().expect("forced UUIDv4 token is valid")
    }

    fn absent_start(token: SessionStartOperationToken) -> ConditionalSessionStart {
        ConditionalSessionStart {
            operation_token: token,
            precondition: SessionStartPrecondition::Absent {
                excluded_generation: None,
            },
        }
    }

    #[test]
    fn conditional_start_requires_exact_prior_reservation() {
        let mut daemon = Daemon::default();
        let id = sid("reserve-required");
        let operation = absent_start(start_token(1));

        assert_eq!(
            daemon.start_session_conditionally(
                id.clone(),
                ".",
                "sleep",
                &["30".into()],
                None,
                80,
                24,
                &operation,
            ),
            ConditionalSessionStartOutcome::Refused {
                reason: ConditionalSessionStartRefusal::PreconditionFailed,
            }
        );
        assert!(daemon.session(&id).is_err());
        assert_eq!(
            daemon.lookup_start_operation(&id, &operation.operation_token),
            SessionStartOperationStatus::Unknown,
            "an unreserved Start refusal must not consume ledger capacity"
        );
    }

    #[test]
    fn applied_operation_survives_exit_removal_and_replays_idempotently() {
        let mut daemon = Daemon::default();
        let id = sid("operation-lifecycle");
        let operation = absent_start(start_token(2));
        assert_eq!(
            daemon.reserve_start_operation(id.clone(), operation.operation_token.clone()),
            SessionStartOperationReserveOutcome::Reserved
        );
        assert_eq!(
            daemon.reserve_start_operation(id.clone(), operation.operation_token.clone()),
            SessionStartOperationReserveOutcome::AlreadyReserved
        );
        let applied = daemon.start_session_conditionally(
            id.clone(),
            ".",
            "true",
            &[],
            None,
            80,
            24,
            &operation,
        );
        let generation = match applied {
            ConditionalSessionStartOutcome::Applied { generation } => generation,
            other => panic!("reserved operation should apply, got {other:?}"),
        };
        wait_for_exit(&daemon, &id);
        assert_eq!(
            daemon.lookup_start_operation(&id, &operation.operation_token),
            SessionStartOperationStatus::Applied {
                generation: generation.clone(),
                lifecycle: SessionStartOperationLifecycle::Exited,
            }
        );

        daemon.reap_exited_sessions();
        assert_eq!(
            daemon.lookup_start_operation(&id, &operation.operation_token),
            SessionStartOperationStatus::Applied {
                generation: generation.clone(),
                lifecycle: SessionStartOperationLifecycle::Removed,
            }
        );
        assert_eq!(
            daemon.start_session_conditionally(
                id.clone(),
                ".",
                "sleep",
                &["30".into()],
                None,
                80,
                24,
                &operation,
            ),
            ConditionalSessionStartOutcome::AlreadyApplied {
                generation: generation.clone(),
            },
            "same-token replay must not respawn after map removal"
        );
        assert!(daemon.session(&id).is_err());
    }

    #[test]
    fn applied_lookup_distinguishes_live_from_same_id_replacement() {
        let mut daemon = Daemon::default();
        let id = sid("operation-replacement");
        let operation = absent_start(start_token(20_002));
        assert_eq!(
            daemon.reserve_start_operation(id.clone(), operation.operation_token.clone()),
            SessionStartOperationReserveOutcome::Reserved
        );
        let generation = match daemon.start_session_conditionally(
            id.clone(),
            ".",
            "sleep",
            &["30".into()],
            None,
            80,
            24,
            &operation,
        ) {
            ConditionalSessionStartOutcome::Applied { generation } => generation,
            other => panic!("reserved operation should apply, got {other:?}"),
        };
        assert_eq!(
            daemon.lookup_start_operation(&id, &operation.operation_token),
            SessionStartOperationStatus::Applied {
                generation: generation.clone(),
                lifecycle: SessionStartOperationLifecycle::Live,
            }
        );

        daemon.kill_session(&id);
        daemon
            .start_session(id.clone(), ".", "sleep", &["30".into()], 80, 24)
            .unwrap();
        let replacement_generation = daemon.session(&id).unwrap().generation();
        assert_ne!(replacement_generation, generation);
        assert_eq!(
            daemon.lookup_start_operation(&id, &operation.operation_token),
            SessionStartOperationStatus::Applied {
                generation: generation.clone(),
                lifecycle: SessionStartOperationLifecycle::Removed,
            }
        );
        assert_eq!(
            daemon.start_session_conditionally(
                id.clone(),
                ".",
                "sleep",
                &["30".into()],
                None,
                80,
                24,
                &operation,
            ),
            ConditionalSessionStartOutcome::AlreadyApplied {
                generation: generation.clone(),
            },
            "same-token replay must not disturb a later same-id generation"
        );
        assert_eq!(
            daemon.session(&id).unwrap().generation(),
            replacement_generation
        );
        daemon.kill_session(&id);
    }

    #[test]
    fn retire_is_a_start_barrier_and_wrong_tuple_never_removes_authority() {
        let mut daemon = Daemon::default();
        let id = sid("retire-before-start");
        let wrong_id = sid("foreign-id");
        let operation = absent_start(start_token(3));
        daemon.reserve_start_operation(id.clone(), operation.operation_token.clone());

        assert_eq!(
            daemon.retire_start_operation(
                &wrong_id,
                &operation.operation_token,
                &SessionStartOperationRetireExpectation::Unapplied,
            ),
            SessionStartOperationRetireOutcome::AlreadyRetired,
            "wrong tuple is content-blind Unknown, but must not mutate the real entry"
        );
        assert_eq!(
            daemon.lookup_start_operation(&id, &operation.operation_token),
            SessionStartOperationStatus::Reserved
        );
        assert_eq!(
            daemon.retire_start_operation(
                &id,
                &operation.operation_token,
                &SessionStartOperationRetireExpectation::Unapplied,
            ),
            SessionStartOperationRetireOutcome::Retired
        );
        assert_eq!(
            daemon.start_session_conditionally(
                id.clone(),
                ".",
                "sleep",
                &["30".into()],
                None,
                80,
                24,
                &operation,
            ),
            ConditionalSessionStartOutcome::Refused {
                reason: ConditionalSessionStartRefusal::PreconditionFailed,
            },
            "a delayed Start after the retire barrier sees Missing and cannot spawn"
        );
        assert!(daemon.session(&id).is_err());
    }

    #[test]
    fn concurrent_start_and_retire_linearize_to_exactly_one_safe_winner() {
        let shared = Daemon::shared();
        let id = sid("start-retire-race");
        let operation = absent_start(start_token(30_000));
        let setup = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        setup.block_on(async {
            assert_eq!(
                shared
                    .lock()
                    .await
                    .reserve_start_operation(id.clone(), operation.operation_token.clone()),
                SessionStartOperationReserveOutcome::Reserved
            );
        });

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let start_shared = shared.clone();
        let start_id = id.clone();
        let start_operation = operation.clone();
        let start_barrier = barrier.clone();
        let starter = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            start_barrier.wait();
            runtime.block_on(async {
                start_shared.lock().await.start_session_conditionally(
                    start_id,
                    ".",
                    "sleep",
                    &["30".into()],
                    None,
                    80,
                    24,
                    &start_operation,
                )
            })
        });
        let retire_shared = shared.clone();
        let retire_id = id.clone();
        let retire_token = operation.operation_token.clone();
        let retire_barrier = barrier.clone();
        let retirer = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            retire_barrier.wait();
            runtime.block_on(async {
                retire_shared.lock().await.retire_start_operation(
                    &retire_id,
                    &retire_token,
                    &SessionStartOperationRetireExpectation::Unapplied,
                )
            })
        });
        barrier.wait();
        let start_outcome = starter.join().unwrap();
        let retire_outcome = retirer.join().unwrap();

        setup.block_on(async {
            let mut daemon = shared.lock().await;
            match (start_outcome, retire_outcome) {
                (
                    ConditionalSessionStartOutcome::Applied { generation },
                    SessionStartOperationRetireOutcome::Conflict {
                        current:
                            SessionStartOperationStatus::Applied {
                                generation: conflict_generation,
                                ..
                            },
                    },
                ) => {
                    assert_eq!(generation, conflict_generation);
                    assert_eq!(daemon.session(&id).unwrap().generation(), generation);
                    daemon.kill_session(&id);
                }
                (
                    ConditionalSessionStartOutcome::Refused {
                        reason: ConditionalSessionStartRefusal::PreconditionFailed,
                    },
                    SessionStartOperationRetireOutcome::Retired,
                ) => assert!(daemon.session(&id).is_err()),
                unexpected => panic!("unsafe Start/Retire race outcome: {unexpected:?}"),
            }
        });
    }

    #[test]
    fn applied_retirement_is_generation_cas() {
        let mut daemon = Daemon::default();
        let id = sid("retire-applied");
        let operation = absent_start(start_token(4));
        daemon.reserve_start_operation(id.clone(), operation.operation_token.clone());
        let generation = match daemon.start_session_conditionally(
            id.clone(),
            ".",
            "sleep",
            &["30".into()],
            None,
            80,
            24,
            &operation,
        ) {
            ConditionalSessionStartOutcome::Applied { generation } => generation,
            other => panic!("reserved operation should apply, got {other:?}"),
        };

        assert!(matches!(
            daemon.retire_start_operation(
                &id,
                &operation.operation_token,
                &SessionStartOperationRetireExpectation::Unapplied,
            ),
            SessionStartOperationRetireOutcome::Conflict {
                current: SessionStartOperationStatus::Applied { .. }
            }
        ));
        assert!(matches!(
            daemon.retire_start_operation(
                &id,
                &operation.operation_token,
                &SessionStartOperationRetireExpectation::Applied {
                    generation: "wrong-generation".into(),
                },
            ),
            SessionStartOperationRetireOutcome::Conflict {
                current: SessionStartOperationStatus::Applied { .. }
            }
        ));
        assert_eq!(
            daemon.retire_start_operation(
                &id,
                &operation.operation_token,
                &SessionStartOperationRetireExpectation::Applied {
                    generation: generation.clone(),
                },
            ),
            SessionStartOperationRetireOutcome::Retired
        );
        assert_eq!(
            daemon.lookup_start_operation(&id, &operation.operation_token),
            SessionStartOperationStatus::Unknown
        );
        daemon.kill_session(&id);
    }

    #[test]
    fn operation_cap_blocks_only_new_reservations_and_exact_retire_recovers_capacity() {
        let mut daemon = Daemon::default();
        let id = sid("ledger-cap");
        for index in 0..MAX_START_OPERATION_LEDGER_ENTRIES {
            assert_eq!(
                daemon.reserve_start_operation(id.clone(), start_token(index + 10)),
                SessionStartOperationReserveOutcome::Reserved
            );
        }
        let existing = start_token(10);
        assert_eq!(
            daemon.reserve_start_operation(id.clone(), existing.clone()),
            SessionStartOperationReserveOutcome::AlreadyReserved
        );
        assert_eq!(
            daemon.lookup_start_operation(&id, &existing),
            SessionStartOperationStatus::Reserved
        );

        let overflow = start_token(MAX_START_OPERATION_LEDGER_ENTRIES + 20);
        assert_eq!(
            daemon.reserve_start_operation(id.clone(), overflow.clone()),
            SessionStartOperationReserveOutcome::Refused {
                reason: SessionStartOperationReserveRefusal::LedgerFull,
            }
        );

        // Start and replay remain admitted at cap. A deterministic input refusal is retained and
        // replayed without a spawn or a new entry.
        let existing_operation = absent_start(existing.clone());
        let refused = daemon.start_session_conditionally(
            id.clone(),
            ".",
            "",
            &[],
            None,
            80,
            24,
            &existing_operation,
        );
        assert_eq!(
            refused,
            ConditionalSessionStartOutcome::Refused {
                reason: ConditionalSessionStartRefusal::SpawnFailed,
            }
        );
        assert_eq!(
            daemon.lookup_start_operation(&id, &existing),
            SessionStartOperationStatus::Refused
        );
        assert_eq!(
            daemon.start_session_conditionally(
                id.clone(),
                ".",
                "sleep",
                &["30".into()],
                None,
                80,
                24,
                &existing_operation,
            ),
            refused,
            "terminal replay remains admitted at the cap"
        );
        assert_eq!(
            daemon.retire_start_operation(
                &id,
                &existing,
                &SessionStartOperationRetireExpectation::Unapplied,
            ),
            SessionStartOperationRetireOutcome::Retired
        );
        assert_eq!(
            daemon.reserve_start_operation(id, overflow),
            SessionStartOperationReserveOutcome::Reserved,
            "only an explicit exact retire frees one ledger slot"
        );
    }

    #[test]
    fn reservation_rejects_unbounded_or_control_bearing_ids_without_retention() {
        let mut daemon = Daemon::default();
        for (index, id) in [
            sid(""),
            sid("bad\nidentity"),
            sid(&"x".repeat(MAX_START_OPERATION_SESSION_ID_BYTES + 1)),
        ]
        .into_iter()
        .enumerate()
        {
            let token = start_token(index + 5000);
            assert_eq!(
                daemon.reserve_start_operation(id.clone(), token.clone()),
                SessionStartOperationReserveOutcome::Refused {
                    reason: SessionStartOperationReserveRefusal::InvalidSessionId,
                }
            );
            assert_eq!(
                daemon.lookup_start_operation(&id, &token),
                SessionStartOperationStatus::Unknown
            );
        }
        assert!(daemon.start_operations.is_empty());
    }

    #[test]
    fn exact_attachment_guards_block_kill_until_the_last_owner_detaches() {
        let mut daemon = Daemon::default();
        let id = sid("attachment-owners");
        daemon
            .start_session(id.clone(), ".", "sleep", &["30".into()], 80, 24)
            .unwrap();
        let generation = daemon.session(&id).unwrap().generation();

        let first = daemon.acquire_session_attachment(&id, None, 1).unwrap();
        let second = daemon.acquire_session_attachment(&id, None, 2).unwrap();
        assert!(matches!(
            daemon.take_session_if_generation(&id, &generation),
            ConditionalSessionTake::AttachmentInUse
        ));

        first.detach();
        assert_eq!(
            daemon.session(&id).unwrap().attachment_fence_counts(),
            (1, 0),
            "one detach must not erase the other exact owner"
        );
        assert!(matches!(
            daemon.take_session_if_generation(&id, &generation),
            ConditionalSessionTake::AttachmentInUse
        ));

        second.detach();
        let ConditionalSessionTake::Taken(session) =
            daemon.take_session_if_generation(&id, &generation)
        else {
            panic!("last detach must make the exact lifetime conditionally removable");
        };
        session.kill_child();
    }

    #[test]
    fn raw_guard_drop_preserves_pending_offer_for_same_client_replacement() {
        let mut daemon = Daemon::default();
        let id = sid("handoff-starter-first");
        daemon
            .start_session(id.clone(), ".", "sleep", &["30".into()], 80, 24)
            .unwrap();
        let exact = token("00000000000000000000000000000001");
        let wrong = token("00000000000000000000000000000002");
        let offer = AttachmentHandoff::Offer {
            token: exact.clone(),
        };
        let starter = daemon
            .acquire_session_attachment(&id, Some(&offer), 10)
            .unwrap();
        assert!(
            daemon
                .acquire_session_attachment(&id, Some(&offer), 11)
                .is_err(),
            "another client cannot share a duplicate offer"
        );
        // Raw guard Drop is deliberately non-retiring. The connection owner (`ClientState`) uses
        // explicit detach on EOF; keeping this lower-level behavior is what lets same-client
        // replacement acquire a new guard before releasing the old one.
        drop(starter);
        assert_eq!(
            daemon.session(&id).unwrap().attachment_fence_counts(),
            (0, 1)
        );

        let wrong_claim = AttachmentHandoff::Claim { token: wrong };
        assert!(daemon
            .acquire_session_attachment(&id, Some(&wrong_claim), 20)
            .is_err());
        assert_eq!(
            daemon.session(&id).unwrap().attachment_fence_counts(),
            (0, 1),
            "wrong claim must not steal or consume the pending token"
        );

        let exact_claim = AttachmentHandoff::Claim {
            token: exact.clone(),
        };
        let renderer = daemon
            .acquire_session_attachment(&id, Some(&exact_claim), 20)
            .unwrap();
        assert_eq!(
            daemon.session(&id).unwrap().attachment_fence_counts(),
            (1, 0),
            "claim atomically replaces Pending with an ordinary active owner"
        );
        assert!(
            daemon
                .acquire_session_attachment(&id, Some(&exact_claim), 20)
                .is_err(),
            "one-shot claim cannot be replayed"
        );
        assert!(
            daemon
                .acquire_session_attachment(&id, Some(&offer), 10)
                .is_err(),
            "a claimed one-shot token cannot be re-offered"
        );
        drop(renderer); // one-shot correction: no automatic re-pend
        assert_eq!(
            daemon.session(&id).unwrap().attachment_fence_counts(),
            (0, 0)
        );
        daemon.kill_session(&id);
    }

    #[test]
    fn generation_conditional_attach_refuses_missing_and_mismatch_before_guard() {
        let mut daemon = Daemon::default();
        let id = sid("conditional-attach-core");
        assert!(matches!(
            daemon.acquire_session_attachment_if_generation(&id, "generation-a", None, 1),
            Err(SessionAttachmentAcquireError::Refused(
                SessionAttachRefusal::Missing
            ))
        ));

        daemon
            .start_session(id.clone(), ".", "sleep", &["30".into()], 80, 24)
            .unwrap();
        let actual = daemon.session(&id).unwrap().generation();
        assert_ne!(actual, "generation-a");
        assert!(matches!(
            daemon.acquire_session_attachment_if_generation(&id, "generation-a", None, 2),
            Err(SessionAttachmentAcquireError::Refused(
                SessionAttachRefusal::GenerationMismatch
            ))
        ));
        assert_eq!(
            daemon.session(&id).unwrap().attachment_fence_counts(),
            (0, 0)
        );
        let guard = daemon
            .acquire_session_attachment_if_generation(&id, &actual, None, 3)
            .unwrap();
        assert_eq!(
            daemon.session(&id).unwrap().attachment_fence_counts(),
            (1, 0)
        );
        guard.detach();
        daemon.kill_session(&id);
    }

    #[test]
    fn renderer_claim_before_starter_eof_has_no_ownerless_interval() {
        let mut daemon = Daemon::default();
        let id = sid("handoff-renderer-first");
        daemon
            .start_session(id.clone(), ".", "sleep", &["30".into()], 80, 24)
            .unwrap();
        let value = token("00000000000000000000000000000003");
        let offer = AttachmentHandoff::Offer {
            token: value.clone(),
        };
        let claim = AttachmentHandoff::Claim { token: value };
        let starter = daemon
            .acquire_session_attachment(&id, Some(&offer), 30)
            .unwrap();
        let renderer = daemon
            .acquire_session_attachment(&id, Some(&claim), 31)
            .unwrap();
        assert_eq!(
            daemon.session(&id).unwrap().attachment_fence_counts(),
            (2, 0)
        );
        drop(starter);
        assert_eq!(
            daemon.session(&id).unwrap().attachment_fence_counts(),
            (1, 0),
            "starter EOF cannot erase the already-installed renderer owner"
        );
        let generation = daemon.session(&id).unwrap().generation();
        assert!(matches!(
            daemon.take_session_if_generation(&id, &generation),
            ConditionalSessionTake::AttachmentInUse
        ));
        drop(renderer);
        daemon.kill_session(&id);
    }

    #[test]
    fn exact_cancel_releases_pending_fence_but_wrong_cancel_does_not() {
        let mut daemon = Daemon::default();
        let id = sid("handoff-cancel");
        daemon
            .start_session(id.clone(), ".", "sleep", &["30".into()], 80, 24)
            .unwrap();
        let exact = token("00000000000000000000000000000004");
        let wrong = token("00000000000000000000000000000005");
        let offer = AttachmentHandoff::Offer {
            token: exact.clone(),
        };
        drop(
            daemon
                .acquire_session_attachment(&id, Some(&offer), 40)
                .unwrap(),
        );
        daemon.cancel_session_attachment_handoff(&id, &wrong);
        assert!(daemon.session(&id).unwrap().attachment_in_use());
        daemon.cancel_session_attachment_handoff(&id, &exact);
        assert!(!daemon.session(&id).unwrap().attachment_in_use());
        assert!(
            daemon
                .acquire_session_attachment(&id, Some(&offer), 40)
                .is_err(),
            "a cancelled one-shot token cannot be re-offered"
        );
        daemon.kill_session(&id);
    }

    #[test]
    fn pending_handoff_tokens_are_bounded_and_claims_release_capacity() {
        let mut daemon = Daemon::default();
        let id = sid("handoff-bound");
        daemon
            .start_session(id.clone(), ".", "sleep", &["30".into()], 80, 24)
            .unwrap();
        let mut tokens = Vec::new();
        for index in 0..MAX_ATTACHMENT_HANDOFF_TOKENS {
            let value = token(&format!("{index:032x}"));
            let offer = AttachmentHandoff::Offer {
                token: value.clone(),
            };
            drop(
                daemon
                    .acquire_session_attachment(&id, Some(&offer), index as u64 + 1)
                    .unwrap(),
            );
            tokens.push(value);
        }
        assert_eq!(
            daemon.session(&id).unwrap().attachment_fence_counts(),
            (0, MAX_ATTACHMENT_HANDOFF_TOKENS)
        );
        let overflow = token("ffffffffffffffffffffffffffffffff");
        assert!(daemon
            .acquire_session_attachment(
                &id,
                Some(&AttachmentHandoff::Offer {
                    token: overflow.clone(),
                }),
                999,
            )
            .is_err());

        let claimed = daemon
            .acquire_session_attachment(
                &id,
                Some(&AttachmentHandoff::Claim {
                    token: tokens[0].clone(),
                }),
                1000,
            )
            .unwrap();
        drop(claimed);
        drop(
            daemon
                .acquire_session_attachment(
                    &id,
                    Some(&AttachmentHandoff::Offer {
                        token: overflow.clone(),
                    }),
                    999,
                )
                .expect("consuming one pending token frees one bounded slot"),
        );
        for value in tokens.into_iter().skip(1).chain(std::iter::once(overflow)) {
            daemon.cancel_session_attachment_handoff(&id, &value);
        }
        assert!(!daemon.session(&id).unwrap().attachment_in_use());
        daemon.kill_session(&id);
    }

    #[test]
    fn retired_handoff_replay_cache_is_bounded_without_exhausting_new_offers() {
        let mut daemon = Daemon::default();
        let id = sid("handoff-retired-bound");
        daemon
            .start_session(id.clone(), ".", "sleep", &["30".into()], 80, 24)
            .unwrap();

        for index in 0..(MAX_RETIRED_ATTACHMENT_HANDOFF_TOKENS + 32) {
            let value = token(&format!("{index:032x}"));
            let guard = daemon
                .acquire_session_attachment(
                    &id,
                    Some(&AttachmentHandoff::Offer { token: value }),
                    index as u64 + 1,
                )
                .expect("a fresh token must not consume the pending budget permanently");
            guard.detach();
        }
        assert_eq!(
            daemon
                .session(&id)
                .unwrap()
                .retired_attachment_handoff_count(),
            MAX_RETIRED_ATTACHMENT_HANDOFF_TOKENS
        );
        assert_eq!(
            daemon.session(&id).unwrap().attachment_fence_counts(),
            (0, 0)
        );

        let recent = token(&format!(
            "{:032x}",
            MAX_RETIRED_ATTACHMENT_HANDOFF_TOKENS + 31
        ));
        assert!(
            daemon
                .acquire_session_attachment(
                    &id,
                    Some(&AttachmentHandoff::Offer { token: recent }),
                    999,
                )
                .is_err(),
            "a recent retired token is replay-protected"
        );
        let fresh = token("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        let guard = daemon
            .acquire_session_attachment(
                &id,
                Some(&AttachmentHandoff::Offer {
                    token: fresh.clone(),
                }),
                1000,
            )
            .expect("bounded retired cache must not exhaust future fresh offers");
        drop(guard);
        daemon.cancel_session_attachment_handoff(&id, &fresh);

        // Once the bounded LRU evicts its oldest value, caller-side cryptographic uniqueness is the
        // remaining replay defense. Even if a violating caller reuses that value, it can pin only
        // this exact Session A: the pending fence is still visible to conditional Kill and is
        // removed only by exact cancel/detach.
        let evicted_oldest = token("00000000000000000000000000000000");
        let generation_a = daemon.session(&id).unwrap().generation();
        drop(
            daemon
                .acquire_session_attachment(
                    &id,
                    Some(&AttachmentHandoff::Offer {
                        token: evicted_oldest.clone(),
                    }),
                    2000,
                )
                .expect("the bounded LRU has evicted the oldest retired value"),
        );
        assert!(matches!(
            daemon.take_session_if_generation(&id, &generation_a),
            ConditionalSessionTake::AttachmentInUse
        ));
        daemon.cancel_session_attachment_handoff(&id, &evicted_oldest);
        let ConditionalSessionTake::Taken(session_a) =
            daemon.take_session_if_generation(&id, &generation_a)
        else {
            panic!("exact cancel must reopen conditional Kill for A");
        };
        session_a.kill_child();

        daemon
            .start_session(id.clone(), ".", "sleep", &["30".into()], 80, 24)
            .unwrap();
        let generation_b = daemon.session(&id).unwrap().generation();
        assert_ne!(generation_a, generation_b);
        assert!(
            daemon
                .acquire_session_attachment(
                    &id,
                    Some(&AttachmentHandoff::Claim {
                        token: evicted_oldest,
                    }),
                    2001,
                )
                .is_err(),
            "A's pending token never transfers to same-id replacement B"
        );
        let ConditionalSessionTake::Taken(session_b) =
            daemon.take_session_if_generation(&id, &generation_b)
        else {
            panic!("unrelated replacement B must remain conditionally killable");
        };
        session_b.kill_child();
    }

    #[test]
    fn protected_exited_a_cannot_be_restarted_reaped_or_claimed_as_b() {
        let mut daemon = Daemon::default();
        let id = sid("handoff-generation-a");
        daemon
            .start_session(id.clone(), ".", "true", &[], 80, 24)
            .unwrap();
        wait_for_exit(&daemon, &id);
        let generation_a = daemon.session(&id).unwrap().generation();
        let value = token("00000000000000000000000000000006");
        let offer = AttachmentHandoff::Offer {
            token: value.clone(),
        };
        drop(
            daemon
                .acquire_session_attachment(&id, Some(&offer), 50)
                .unwrap(),
        );

        daemon.reap_exited_sessions();
        assert!(
            daemon.session(&id).is_ok(),
            "pending exited A is not evictable"
        );
        assert!(
            daemon
                .start_session_with_restart(id.clone(), ".", "sleep", &["30".into()], 80, 24, true,)
                .is_err(),
            "pending exited A cannot be bypassed by explicit restart"
        );
        assert_eq!(daemon.session(&id).unwrap().generation(), generation_a);

        daemon.cancel_session_attachment_handoff(&id, &value);
        daemon
            .start_session_with_restart(id.clone(), ".", "sleep", &["30".into()], 80, 24, true)
            .unwrap();
        assert_ne!(daemon.session(&id).unwrap().generation(), generation_a);
        let stale_claim = AttachmentHandoff::Claim { token: value };
        assert!(
            daemon
                .acquire_session_attachment(&id, Some(&stale_claim), 51)
                .is_err(),
            "A's token must not protect or attach to replacement B"
        );
        daemon.kill_session(&id);
    }

    #[test]
    fn capacity_refuses_when_every_exited_candidate_is_active_or_pending() {
        let mut daemon = Daemon::default();
        let mut active_guards = Vec::new();
        let mut pending = Vec::new();

        for index in 0..MAX_SESSIONS {
            let id = sid(&format!("protected-capacity-{index}"));
            daemon
                .start_session(id.clone(), ".", "true", &[], 80, 24)
                .unwrap();
            wait_for_exit(&daemon, &id);
            if index % 2 == 0 {
                active_guards.push(
                    daemon
                        .acquire_session_attachment(&id, None, index as u64 + 1)
                        .unwrap(),
                );
            } else {
                let value = token(&format!("{:032x}", index + 10_000));
                drop(
                    daemon
                        .acquire_session_attachment(
                            &id,
                            Some(&AttachmentHandoff::Offer {
                                token: value.clone(),
                            }),
                            index as u64 + 1,
                        )
                        .unwrap(),
                );
                pending.push((id, value));
            }
        }
        assert_eq!(daemon.sessions.len(), MAX_SESSIONS);
        let before: std::collections::HashSet<_> = daemon.sessions.keys().cloned().collect();
        let error = daemon
            .start_session(
                sid("must-not-evict-protected"),
                ".",
                "sleep",
                &["30".into()],
                80,
                24,
            )
            .expect_err("no protected exited snapshot is a capacity eviction candidate");
        assert!(error.to_string().contains("session limit reached"));
        assert_eq!(daemon.sessions.len(), MAX_SESSIONS);
        assert_eq!(
            daemon
                .sessions
                .keys()
                .cloned()
                .collect::<std::collections::HashSet<_>>(),
            before,
            "capacity refusal must not evict any protected exited Session"
        );

        drop(active_guards);
        for (id, value) in pending {
            daemon.cancel_session_attachment_handoff(&id, &value);
        }
        daemon.reap_exited_sessions();
        assert!(daemon.sessions.is_empty());
    }

    /// An in-flight PTY write for one session must NOT hold
    /// the global daemon lock, so unrelated requests stay responsive.
    ///
    /// We can't reproduce a truly blocked PTY write on macOS (portable-pty
    /// buffers the master write so it never blocks even at 80 MB), so we prove
    /// the locking discipline directly: a worker thread holds the per-session
    /// `writer` lock (exactly what the real `PtyHandle::write_input` holds for
    /// the duration of the syscall), and meanwhile the daemon lock must remain
    /// acquirable. Keeping the writer inside `Session` *behind the daemon lock*
    /// would let a blocking write freeze every other request; this test would
    /// hang on that design.
    #[test]
    fn in_flight_write_does_not_hold_daemon_lock() {
        let shared = Daemon::shared();
        // Borrow a tiny current-thread runtime to drive the async daemon Mutex,
        // matching how the real request handlers `.lock().await`.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        // Spawn a long-lived session and grab its PTY write handle.
        let handle = rt.block_on(async {
            let mut d = shared.lock().await;
            d.start_session(sid("writer"), ".", "sleep", &["30".to_string()], 80, 24)
                .expect("spawn session");
            d.session(&sid("writer")).unwrap().pty_handle()
        });

        // Simulate an in-progress blocking write: hold the writer lock on a
        // worker thread for a full second. A barrier makes sure the main thread
        // only probes once the lock is actually held.
        let writer_lock = handle.writer_lock_for_test();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let b2 = barrier.clone();
        let writer = std::thread::spawn(move || {
            let _guard = writer_lock.lock().unwrap();
            b2.wait();
            std::thread::sleep(Duration::from_secs(1));
        });
        barrier.wait();

        // While the "write" is in flight, an unrelated request (ListSessions →
        // session_ids) must acquire the daemon lock and return promptly. If the
        // daemon lock were held across the write, this would block ~1s.
        let started = Instant::now();
        let ids = rt.block_on(async {
            let d = shared.lock().await;
            d.session_ids()
        });
        let elapsed = started.elapsed();

        assert!(
            ids.contains(&sid("writer")),
            "the session should be listed: {ids:?}"
        );
        assert!(
            elapsed < Duration::from_millis(300),
            "acquiring the daemon lock took {elapsed:?} while a write was in flight — \
             the daemon lock is being held across PTY IO"
        );

        writer.join().unwrap();
        rt.block_on(async { shared.lock().await.kill_session(&sid("writer")) });
    }

    #[test]
    fn exited_session_releases_capacity() {
        let mut d = Daemon::default();

        // A child that exits on its own the instant it starts. Nobody calls
        // kill_session for it, so only the reap path can reclaim its slot.
        d.start_session(sid("ephemeral"), ".", "true", &[], 80, 24)
            .expect("spawn the short-lived session");
        assert_eq!(d.sessions.len(), 1, "session is in the map while/after run");

        wait_for_exit(&d, &sid("ephemeral"));

        // Starting another session below capacity preserves the final snapshot for inspection.
        d.start_session(sid("live"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn the long-lived session");
        assert!(
            d.sessions.contains_key(&sid("ephemeral")),
            "an unrelated start must preserve retained final output below capacity"
        );

        // The explicit reap path still releases capacity and keeps live children.
        d.reap_exited_sessions();

        assert!(
            !d.sessions.contains_key(&sid("ephemeral")),
            "the exited session must be reaped, freeing its capacity slot"
        );
        assert!(
            d.sessions.contains_key(&sid("live")),
            "the still-running session must survive the reap"
        );

        d.kill_session(&sid("live"));
    }

    #[test]
    fn exit_latched_session_is_not_listed_live_but_remains_late_attachable() {
        let mut d = Daemon::default();
        let id = sid("latched-exit");
        d.start_session(id.clone(), ".", "true", &[], 80, 24)
            .expect("spawn the short-lived session");
        wait_for_exit(&d, &id);

        assert!(
            !d.session_ids().contains(&id),
            "ListSessions ids must exclude an exit-latched process"
        );
        assert!(
            d.session_infos().iter().all(|info| info.id != id),
            "ListSessions metadata must use the same live-only predicate"
        );

        // Filtering is deliberately non-destructive. Attach still finds the Session, can send its
        // authoritative restore Grid, and then uses this persisted latch to replay SessionExited to
        // a client that subscribed after the one-shot broadcast. The full wire ordering remains
        // covered by tests/resync_and_late_attach.rs.
        let retained = d.session(&id).expect("latched Session remains in the map");
        let attach = retained.attach_state();
        assert_eq!(attach.snapshot.rows, 24);
        assert!(
            retained.exit_state().is_some(),
            "late attach observes the exit latch"
        );
        assert!(
            d.sessions.contains_key(&id),
            "live-list filtering must not reap/remove retained late-attach state"
        );
    }

    #[test]
    fn live_same_id_start_is_noop() {
        let mut d = Daemon::default();

        // A long-lived child. A second StartSession with the same id is a
        // reattach (the UI reconnected) and must NOT respawn it.
        d.start_session(sid("agent"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn the long-lived session");
        assert!(
            d.sessions
                .get(&sid("agent"))
                .expect("session present")
                .exit_state()
                .is_none(),
            "freshly spawned session must be alive"
        );

        // Reattach: same id, still alive. Returns Ok, leaves the live session
        // untouched (no respawn), and never grows the map.
        d.start_session(sid("agent"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("reattach to a live session is Ok");
        assert_eq!(d.sessions.len(), 1, "reattach must not add a session");
        assert!(
            d.sessions
                .get(&sid("agent"))
                .expect("live session still present")
                .exit_state()
                .is_none(),
            "the live session must survive the reattach unchanged"
        );

        d.kill_session(&sid("agent"));
    }

    #[test]
    fn exited_same_id_start_is_an_explicit_new_generation() {
        let mut d = Daemon::default();
        let id = sid("restart-ended");
        d.start_session(id.clone(), ".", "true", &[], 80, 24)
            .expect("spawn short-lived session");
        wait_for_exit(&d, &id);
        let ended_generation = d
            .session(&id)
            .expect("retained ended session")
            .attach_state()
            .snapshot
            .generation;

        d.start_session_with_restart(id.clone(), ".", "sleep", &["30".to_string()], 80, 24, true)
            .expect("same-id start explicitly restarts an ended session");

        let restarted = d.session(&id).expect("new session generation");
        assert!(restarted.exit_state().is_none());
        assert_ne!(
            restarted.attach_state().snapshot.generation,
            ended_generation,
            "restart must not reuse the ended generation"
        );
        d.kill_session(&id);
    }

    #[test]
    fn failed_same_id_restart_preserves_the_retained_final_snapshot() {
        let mut d = Daemon::default();
        let id = sid("restart-failure-retains-final-output");
        d.start_session(id.clone(), ".", "true", &[], 80, 24)
            .expect("spawn short-lived session");
        wait_for_exit(&d, &id);
        let ended_generation = d
            .session(&id)
            .expect("retained ended session")
            .attach_state()
            .snapshot
            .generation;

        let error = d
            .start_session_with_restart(
                id.clone(),
                ".",
                "/definitely/not/a/hydra/executable",
                &[],
                80,
                24,
                true,
            )
            .expect_err("replacement spawn must fail");
        assert!(!error.to_string().is_empty());

        let retained = d
            .session(&id)
            .expect("old snapshot survives failed restart");
        assert!(retained.exit_state().is_some());
        assert_eq!(
            retained.attach_state().snapshot.generation,
            ended_generation,
            "failed replacement must not discard or replace the ended generation"
        );
    }

    #[test]
    fn invalid_child_environment_is_rejected_before_exited_snapshot_replacement() {
        let mut daemon = Daemon::default();
        let id = sid("invalid-child-environment-retains-snapshot");
        daemon
            .start_session(id.clone(), ".", "true", &[], 80, 24)
            .expect("spawn short-lived session");
        wait_for_exit(&daemon, &id);
        let ended_generation = daemon
            .session(&id)
            .expect("retained ended session")
            .attach_state()
            .snapshot
            .generation;
        let environment = maestro_protocol::ChildEnvironment {
            home: "/definitely/not/a/hydra/home".into(),
            shell: "/bin/sh".into(),
        };

        let error = daemon
            .start_session_with_restart_and_environment(
                id.clone(),
                ".",
                "/bin/sh",
                &[],
                Some(&environment),
                80,
                24,
                true,
            )
            .expect_err("invalid typed environment must fail before spawn");
        assert_eq!(error.to_string(), "headless child environment is invalid");
        let retained = daemon.session(&id).expect("old snapshot remains installed");
        assert!(retained.exit_state().is_some());
        assert_eq!(
            retained.attach_state().snapshot.generation,
            ended_generation,
            "validation failure must not evict the retained final grid"
        );
    }

    /// Targeted: killed session reaps its child without leaving a zombie. The
    /// reader thread sets the exit latch ONLY after `child.wait()` returns, so a
    /// set latch proves the kernel process-table entry was collected (no zombie).
    /// `kill_and_wait` blocks until that latch is set.
    #[test]
    fn killed_session_reaps_child_without_zombie() {
        let mut d = Daemon::default();
        d.start_session(sid("victim"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn a long-lived session");
        assert!(
            d.sessions
                .get(&sid("victim"))
                .unwrap()
                .exit_state()
                .is_none(),
            "precondition: the child is alive (not yet reaped)"
        );

        // Kill and confirm the reader thread reaped it (latch set) within budget.
        let reaped = d
            .sessions
            .get(&sid("victim"))
            .unwrap()
            .kill_and_wait(Duration::from_secs(5));
        assert!(
            reaped,
            "the killed child must be reaped (exit latch set) — a zombie would leave it None"
        );
        assert!(
            d.sessions
                .get(&sid("victim"))
                .unwrap()
                .exit_state()
                .is_some(),
            "exit_state must be Some after the child is reaped"
        );

        d.kill_session(&sid("victim"));
    }

    /// Targeted: a killed session is removed from MAX_SESSIONS capacity
    /// accounting. (Companion to `exited_session_releases_capacity`, which covers
    /// the natural-exit path; this covers the explicit-kill path.)
    #[test]
    fn killed_session_releases_capacity() {
        let mut d = Daemon::default();
        d.start_session(sid("k"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn");
        assert_eq!(d.sessions.len(), 1);

        d.kill_session(&sid("k"));
        assert_eq!(
            d.sessions.len(),
            0,
            "kill_session must drop the session, freeing its capacity slot"
        );
        assert!(!d.sessions.contains_key(&sid("k")));
    }

    /// Targeted: client detach must NOT kill a live session. Detach is a
    /// client-forwarder concern handled in main.rs (it aborts the forwarder task);
    /// the daemon's Session is untouched. We assert the structural invariant at the
    /// daemon level: nothing in the detach path removes or kills the session, so a
    /// session that no one kill_session's stays alive and listed.
    #[test]
    fn detach_does_not_kill_live_session() {
        let mut d = Daemon::default();
        d.start_session(sid("persist"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn");

        // The daemon exposes no detach mutation — detach lives entirely in the
        // client handler and only aborts that client's forwarder. So after any
        // number of client attach/detach cycles (which never call into Daemon to
        // mutate session lifetime), the session remains alive and listed.
        assert!(d.sessions.contains_key(&sid("persist")));
        assert!(
            d.sessions
                .get(&sid("persist"))
                .unwrap()
                .exit_state()
                .is_none(),
            "a detach must never cause the session's child to exit"
        );
        assert!(
            d.session_ids().contains(&sid("persist")),
            "the live session stays listed across detach"
        );

        d.kill_session(&sid("persist"));
    }

    /// Targeted: a successful shutdown reports every child reaped. Each child's
    /// reaping is confirmed via its exit latch inside `kill_and_wait`, so a report
    /// of `all_reaped()` with `reaped == total` means every process-table entry
    /// was collected (no orphans/zombies), and state is cleared.
    #[test]
    fn successful_shutdown_reports_all_children_reaped() {
        let mut d = Daemon::default();
        d.start_session(sid("a"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn a");
        d.start_session(sid("b"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn b");
        d.start_session(sid("c"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn c");
        assert_eq!(d.sessions.len(), 3, "three live children before shutdown");

        let report = d.shutdown();

        assert!(
            report.all_reaped(),
            "every child must confirm reaped: {report:?}"
        );
        assert_eq!(report.total, 3, "report counts all pre-shutdown sessions");
        assert_eq!(report.reaped, 3, "all three confirmed reaped");
        assert!(report.unconfirmed.is_empty(), "no unconfirmed children");
        assert_eq!(
            d.sessions.len(),
            0,
            "shutdown must drop every session after reaping its child"
        );
        assert!(d.channels.is_empty(), "shutdown clears channels too");
    }

    /// Targeted: shutdown REPORTS timeout/failure when a child doesn't confirm
    /// reaped within the budget — it must not overstate "all reaped". We force the
    /// branch deterministically with a zero per-child budget: kill_and_wait checks
    /// the exit latch once and, since the reader thread cannot have run `wait()`
    /// in zero time, reports the child unconfirmed. State is still cleared.
    #[test]
    fn shutdown_reports_unconfirmed_when_child_does_not_confirm_in_time() {
        let mut d = Daemon::default();
        d.start_session(sid("slow"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn");
        d.start_session(sid("slow2"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn");

        // Zero budget: no child can confirm reaped, so every one is unconfirmed.
        let report = d.shutdown_with_timeout(std::time::Duration::ZERO);

        assert!(
            !report.all_reaped(),
            "a zero-timeout shutdown must NOT claim all reaped: {report:?}"
        );
        assert_eq!(report.total, 2);
        assert_eq!(report.reaped, 0, "no child confirmed within a zero budget");
        assert_eq!(
            report.unconfirmed.len(),
            2,
            "both children reported unconfirmed"
        );
        assert_eq!(
            d.sessions.len(),
            0,
            "state is cleared even on a degraded shutdown (PTYs still closed)"
        );
    }

    #[test]
    fn shutdown_report_all_reaped_predicate() {
        // Empty/clean report is trivially all-reaped; a non-empty unconfirmed is not.
        let clean = ShutdownReport {
            total: 2,
            reaped: 2,
            unconfirmed: vec![],
        };
        assert!(clean.all_reaped());
        let degraded = ShutdownReport {
            total: 2,
            reaped: 1,
            unconfirmed: vec![sid("x")],
        };
        assert!(!degraded.all_reaped());
    }

    #[test]
    fn channel_registry_rejects_invalid_ids_and_stops_at_its_ceiling() {
        let mut d = Daemon::default();

        for index in 0..MAX_CHANNELS {
            d.open_channel(ChannelId(format!("channel-{index}")))
                .expect("channel below the limit opens");
        }
        assert_eq!(d.channels.len(), MAX_CHANNELS);

        d.open_channel(ChannelId("channel-0".into()))
            .expect("existing channel remains reusable at capacity");
        assert_eq!(d.channels.len(), MAX_CHANNELS);

        let error = d
            .open_channel(ChannelId("one-too-many".into()))
            .expect_err("new channel over the limit must fail");
        assert!(error.to_string().contains("channel limit reached"));
        assert_eq!(d.channels.len(), MAX_CHANNELS);

        for invalid in [
            ChannelId(String::new()),
            ChannelId("control\ncharacter".into()),
            ChannelId("x".repeat(MAX_CHANNEL_ID_BYTES + 1)),
        ] {
            let mut empty = Daemon::default();
            assert!(empty.open_channel(invalid).is_err());
            assert!(empty.channels.is_empty());
        }
    }

    #[test]
    fn channel_event_sender_must_exist_and_belong_to_the_target_channel() {
        let mut d = Daemon::default();
        let channel = ChannelId("members-only".into());
        let sender = sid("sender");
        d.open_channel(channel.clone()).unwrap();
        d.start_session(sender.clone(), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn sender session");

        let event_from = |from: Option<SessionId>, ts| ChannelEvent {
            channel: channel.clone(),
            from,
            kind: ChannelEventKind::ChatMsg {
                text: "bounded message".into(),
            },
            ts,
        };

        let missing = d
            .publish(event_from(Some(sid("missing")), 1))
            .expect_err("unknown sender cannot be impersonated");
        assert!(missing.to_string().contains("no such sender session"));

        let non_member = d
            .publish(event_from(Some(sender.clone()), 2))
            .expect_err("existing non-member cannot publish as a member");
        assert!(non_member.to_string().contains("is not a member"));

        d.join_channel(&channel, &sender).unwrap();
        d.publish(event_from(Some(sender.clone()), 3))
            .expect("a real member may publish under its own id");
        assert_eq!(d.channels[&channel].replay().len(), 1);

        let anonymous = d
            .publish(event_from(None, 4))
            .expect_err("socket callers cannot publish without a member identity");
        assert!(anonymous.to_string().contains("requires a sender session"));
        assert_eq!(d.channels[&channel].replay().len(), 1);

        d.kill_session(&sender);
    }

    #[test]
    fn ordinary_same_id_start_preserves_exit_and_explicit_restart_respawns() {
        let mut d = Daemon::default();

        // A child that exits the instant it starts. Nobody kills it, so its dead
        // Session lingers in the map under id "slot".
        d.start_session(sid("slot"), ".", "true", &[], 80, 24)
            .expect("spawn the short-lived session");
        wait_for_exit(&d, &sid("slot"));
        assert!(
            d.sessions
                .get(&sid("slot"))
                .expect("dead session lingers")
                .exit_state()
                .is_some(),
            "the child has exited and its corpse still occupies the id"
        );

        // Ordinary StartSession is what window focus/startup uses. Even if the durable Exited
        // status has not landed yet, it must preserve the retained final grid rather than infer
        // restart authority merely from a same-id command.
        let error = d
            .start_session(sid("slot"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect_err("ordinary same-id start must refuse ambiguous restart authority");
        assert!(
            error.to_string().contains("explicit restart authority"),
            "refusal explains how the retained session can be replaced"
        );
        assert!(
            d.sessions
                .get(&sid("slot"))
                .expect("retained session present")
                .exit_state()
                .is_some(),
            "focus/startup must leave the exited retained generation intact"
        );

        // A future explicit Restart action carries the separate authority bit and replaces the
        // corpse only after the new child has spawned successfully.
        d.start_session_with_restart(sid("slot"), ".", "sleep", &["30".to_string()], 80, 24, true)
            .expect("explicit restart respawns a fresh session");
        assert!(
            d.sessions
                .get(&sid("slot"))
                .expect("respawned session present")
                .exit_state()
                .is_none(),
            "the dead session must be replaced by a live one, not left as a corpse"
        );

        // Targeted: the respawn must not retain a stale PTY/process handle from
        // the corpse. The corpse's PTY master/writer were dropped when its Session
        // was replaced in the map (HashMap::insert drops the old value), so the
        // new session must expose a working, distinct PTY surface. A successful
        // write through the new handle proves the writer is the fresh child's, not
        // the dead one's (whose PTY is closed → write would error).
        let handle = d.sessions.get(&sid("slot")).unwrap().pty_handle();
        handle
            .write_input(b"")
            .expect("respawned session's PTY writer is live, not the corpse's closed one");

        d.kill_session(&sid("slot"));
    }
}
