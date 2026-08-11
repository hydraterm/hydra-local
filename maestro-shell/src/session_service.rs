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

use crate::daemon_client::{AttachedSession, DaemonClient, DaemonClientError};
use crate::paths::{AppPaths, RecordKind};
use crate::records::{LaunchSpec, SessionKind, SessionRecord, SessionStatus};
use crate::store::{self, LoadOutcome, StoreError};

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
}

impl std::fmt::Display for SessionServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionServiceError::InvalidCwd { cwd } => {
                write!(f, "cwd is not an existing directory: {cwd}")
            }
            SessionServiceError::Store(e) => write!(f, "session store error: {e}"),
            SessionServiceError::Daemon(e) => write!(f, "session daemon error: {e}"),
        }
    }
}

impl std::error::Error for SessionServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SessionServiceError::Store(e) => Some(e),
            SessionServiceError::Daemon(e) => Some(e),
            SessionServiceError::InvalidCwd { .. } => None,
        }
    }
}

impl From<StoreError> for SessionServiceError {
    fn from(e: StoreError) -> Self {
        SessionServiceError::Store(e)
    }
}

/// The inputs to start ONE record-backed session. The `cwd` MUST already be an existing directory
/// (a caller-supplied safe cwd, or one resolved by `policy::resolved_cwd`); this service NEVER
/// creates it. The `launch` is an already-built, secret-aware [`LaunchSpec`].
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
/// "recovered" session. Surfaced (not mutated) so a future UI/resume flow can let the user
/// title/keep/kill it. Carries only the daemon-reported id: this build deliberately invents no
/// metadata for a session it never persisted.
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
    /// Live daemon ids with no loaded current-version `SessionRecord`, sorted by `session_id`. These
    /// are only REPORTED — never written, attached, or killed. A future-version record for an id
    /// counts as "no loaded current-version record", so a live id whose only record is future-version
    /// is reported here (its bytes are still left untouched and listed in `skipped_future_version`).
    pub recovered_sessions: Vec<RecoveredSession>,
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
    fn write_unknown_record(&self, params: &StartParams) -> Result<SessionRecord, StoreError> {
        // FK: sessions.workspace_id → workspaces (NOT NULL). In the JSON era an ad-hoc/scratch workspace_id (e.g.
        // "maestro-app-dev") could be referenced without a persisted Workspace row; SQLite's FK rejects that. Ensure a
        // minimal ad-hoc workspace (+ owning project) exists for this session's workspace_id before the write.
        self.ensure_workspace(&params.workspace_id, params.now_ms)?;
        let record = SessionRecord {
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
        self.start_and_attach_with_restart(client, params, false)
    }

    /// Start a replacement generation for a retained exited same-id session after the caller has
    /// obtained explicit user authority. This keeps the record-before-daemon ordering of ordinary
    /// starts while setting the protocol-v2 restart bit at the mutation boundary.
    pub fn restart_exited_and_attach(
        &self,
        client: &mut DaemonClient,
        params: &StartParams,
    ) -> Result<SessionRecord, SessionServiceError> {
        self.start_and_attach_with_restart(client, params, true)
    }

    fn start_and_attach_with_restart(
        &self,
        client: &mut DaemonClient,
        params: &StartParams,
        restart_exited: bool,
    ) -> Result<SessionRecord, SessionServiceError> {
        // (1) cwd must be an existing directory, matching the daemon (and DaemonClient) boundary.
        // Checked BEFORE any record write so a bad cwd leaves nothing behind.
        if !std::path::Path::new(&params.cwd).is_dir() {
            return Err(SessionServiceError::InvalidCwd {
                cwd: params.cwd.clone(),
            });
        }

        // (2) record-before-daemon: the Unknown record exists before the PTY can.
        let mut record = self.write_unknown_record(params)?;

        // (3) start + attach.
        let started = if restart_exited {
            client.restart_exited_and_attach(
                maestro_protocol::SessionId(params.session_id.clone()),
                &params.cwd,
                &params.command,
                &params.args,
                params.cols,
                params.rows,
            )
        } else {
            client.start_and_attach(
                maestro_protocol::SessionId(params.session_id.clone()),
                &params.cwd,
                &params.command,
                &params.args,
                params.cols,
                params.rows,
            )
        };
        match started {
            // (4) proven live: stamp generation + attach time, flip to Live, persist.
            Ok(AttachedSession {
                generation, id: _, ..
            }) => {
                record.status = SessionStatus::Live;
                record.last_known_generation = Some(generation);
                record.last_attached_at_ms = params.now_ms;
                store::write_record(
                    self.paths,
                    RecordKind::Session,
                    &params.session_id,
                    params.now_ms,
                    &record,
                )?;
                Ok(record)
            }
            // (5) the daemon proved the session ended before a grid: mark Exited deterministically.
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
                Err(SessionServiceError::Daemon(e))
            }
            // (6) refused / unreachable / protocol / oversized / timeout: keep the Unknown record.
            // We have NOT proven liveness, but neither have we proven the session never started, so
            // Unknown is the honest state for reconciliation to repair later.
            Err(e) => Err(SessionServiceError::Daemon(e)),
        }
    }

    /// Attach to an already-retained daemon session without sending `StartSession`. No durable
    /// state is written until the daemon proves the session with a matching grid baseline. A
    /// current record is refreshed in place; a missing/quarantined record is adopted from the
    /// caller's secret-aware parameters. A future-version record is never overwritten: the method
    /// returns an in-memory projection so the GUI can still reopen the PTY while preserving bytes
    /// this build does not understand.
    pub fn attach_existing(
        &self,
        client: &mut DaemonClient,
        params: &StartParams,
    ) -> Result<SessionRecord, SessionServiceError> {
        let AttachedSession { generation, .. } = client
            .attach_existing(maestro_protocol::SessionId(params.session_id.clone()))
            .map_err(SessionServiceError::Daemon)?;

        let loaded =
            store::load_one::<SessionRecord>(self.paths, RecordKind::Session, &params.session_id)?;
        let mut record = match loaded {
            Some(LoadOutcome::Loaded(record)) => record,
            Some(LoadOutcome::FutureVersion { .. }) => {
                return Ok(SessionRecord {
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
                });
            }
            Some(LoadOutcome::Quarantined { .. }) | None => self.write_unknown_record(params)?,
        };

        // A retained final-grid record stays Exited; attaching is inspection, not restart
        // authority. Every other record has a live Grid proof and may be marked Live.
        if record.status != SessionStatus::Exited {
            record.status = SessionStatus::Live;
        }
        record.last_attached_at_ms = params.now_ms;
        record.last_known_generation = Some(generation);
        store::write_record(
            self.paths,
            RecordKind::Session,
            &params.session_id,
            params.now_ms,
            &record,
        )?;
        Ok(record)
    }

    /// Reconcile persisted session records against the daemon's live id set.
    ///
    /// - A non-exited persisted session whose id IS in the live set -> `Live`.
    /// - A persisted session whose id is ABSENT -> `Exited`.
    /// - An already-`Exited` record stays sticky against a legacy id-only snapshot (old daemons may
    ///   list exit-latched entries), while new-daemon generation metadata is authoritative proof
    ///   that the same id currently has a live grid and may safely revive/update the record.
    /// - A record whose status already matches is left as-is (no needless rewrite).
    /// - A FUTURE-version record (written by a newer Maestro) is observed but NEVER rewritten; its
    ///   path is reported in `skipped_future_version`.
    /// - Corrupt records were already quarantined by the store on load and simply don't appear.
    /// - A live daemon id with NO loaded current-version record (never persisted, or only present as
    ///   a future-version record this build cannot inspect) is reported in `recovered_sessions`,
    ///   sorted by id. It is only SURFACED — never written, attached to, or killed.
    ///
    /// This does NOT invent or touch UI tabs or AgentTask state — it only repairs `SessionStatus`
    /// for records it owns and reports daemon-only live ids for a future UI/resume flow.
    pub fn reconcile(
        &self,
        client: &mut DaemonClient,
    ) -> Result<ReconcileReport, SessionServiceError> {
        let live = client
            .list_sessions_snapshot()
            .map_err(SessionServiceError::Daemon)?;
        let live_ids: std::collections::HashSet<String> =
            live.ids.into_iter().map(|id| id.0).collect();
        // Presence of generation metadata is also the capability proof that the daemon implements
        // the live-only ListSessions contract. Retained legacy daemons omit this vector and may
        // still list exit-latched entries, so they cannot safely revive a sticky Exited record.
        let live_generations: std::collections::HashMap<String, String> = live
            .sessions
            .into_iter()
            .filter_map(|info| {
                let id = info.id.0;
                (live_ids.contains(&id)).then_some((id, info.generation?))
            })
            .collect();

        let outcomes: Vec<LoadOutcome<SessionRecord>> =
            store::load_all(self.paths, RecordKind::Session)?;

        // Ids we held a loadable CURRENT-version record for. A future-version record does NOT count:
        // this build can't inspect it, so a live id whose only record is future-version is still an
        // orphan from our perspective (and is reported as recovered while the file is left intact).
        let mut loaded_ids: std::collections::HashSet<String> = std::collections::HashSet::new();

        let mut report = ReconcileReport::default();
        for outcome in outcomes {
            match outcome {
                LoadOutcome::Loaded(record) => {
                    loaded_ids.insert(record.session_id.clone());
                    let live_generation = live_generations.get(&record.session_id);
                    let (desired_status, desired_generation) =
                        if let Some(generation) = live_generation {
                            // New-daemon metadata is an authoritative live proof. It repairs both a
                            // same-id restart and the narrow fire-and-forget race where reconciliation
                            // observed absence before the queued StartSession reached the daemon.
                            (SessionStatus::Live, Some(generation.as_str()))
                        } else if record.status == SessionStatus::Exited {
                            // A retained legacy daemon supplies ids only and historically included
                            // exit-latched entries. Never let that ambiguous snapshot revive Exited.
                            (
                                SessionStatus::Exited,
                                record.last_known_generation.as_deref(),
                            )
                        } else if live_ids.contains(&record.session_id) {
                            (SessionStatus::Live, record.last_known_generation.as_deref())
                        } else {
                            (
                                SessionStatus::Exited,
                                record.last_known_generation.as_deref(),
                            )
                        };

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

        // Daemon-only live ids: live, but no current-version record loaded. Report (don't mutate).
        let mut recovered: Vec<RecoveredSession> = live_ids
            .into_iter()
            .filter(|id| !loaded_ids.contains(id))
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
    use std::io::{BufRead, BufReader, Write};
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

    fn grid_line(id: &str, generation: &str, revision: u64) -> String {
        format!(
            r#"{{"ev":"grid","id":"{id}","grid":{{"generation":"{generation}","revision":{revision}}}}}"#
        )
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
            // StartSession arrives: the Unknown record must already be on disk.
            read_request(&mut reader, tx);
            let status =
                match store::load_one::<SessionRecord>(&probe_paths, RecordKind::Session, "s1")
                    .unwrap()
                {
                    Some(LoadOutcome::Loaded(r)) => format!("{:?}", r.status),
                    other => format!("missing-or-bad: {other:?}"),
                };
            let _ = seen_tx.send(status);
            // Attach arrives.
            read_request(&mut reader, tx);
            stream
                .write_all(format!("{}\n", grid_line("s1", "gen-1", 3)).as_bytes())
                .unwrap();
            stream.flush().unwrap();
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
            read_request(&mut reader, tx);
            read_request(&mut reader, tx);
            stream
                .write_all(format!("{}\n", grid_line("s1", "gen-xyz", 9)).as_bytes())
                .unwrap();
            stream.flush().unwrap();
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
        assert!(matches!(err, SessionServiceError::InvalidCwd { .. }));
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
            read_request(&mut reader, tx);
            read_request(&mut reader, tx);
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
            SessionServiceError::Daemon(DaemonClientError::DaemonError { message }) => {
                assert_eq!(message, "nope")
            }
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
            read_request(&mut reader, tx);
            read_request(&mut reader, tx);
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
            SessionServiceError::Daemon(DaemonClientError::SessionExited { id, code }) => {
                assert_eq!(id, SessionId("s1".into()));
                assert_eq!(code, Some(2));
            }
            other => panic!("expected SessionExited, got {other:?}"),
        }
        let on_disk = load_record(&paths, "s1");
        assert_eq!(on_disk.status, SessionStatus::Exited);
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
            read_request(&mut reader, tx);
            stream
                .write_all(format!("{{\"ev\":\"sessions\",\"ids\":[\"{id}\"]}}\n").as_bytes())
                .unwrap();
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let report = SessionService::new(&paths).reconcile(&mut client).unwrap();

        let entry = report.sessions.iter().find(|s| s.session_id == id).unwrap();
        assert_eq!(entry.status, SessionStatus::Exited);
        assert!(!entry.rewritten);
        assert_eq!(load_record(&paths, id).status, SessionStatus::Exited);
        assert_eq!(session_write_count(id), writes_after_seed);
    }

    #[test]
    fn generation_metadata_repairs_a_start_queued_after_an_absent_snapshot() {
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
            read_request(&mut reader, tx);
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[]}\n")
                .unwrap();
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&absent.path).unwrap();
        SessionService::new(&paths).reconcile(&mut client).unwrap();
        assert_eq!(load_record(&paths, id).status, SessionStatus::Exited);

        // Once the new daemon processes StartSession, its additive generation metadata is a live
        // proof and repairs the transient Exited status (including the previously-unknown gen).
        let live = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            stream
                .write_all(
                    format!(
                        "{{\"ev\":\"sessions\",\"ids\":[\"{id}\"],\"sessions\":[{{\"id\":\"{id}\",\"generation\":\"gen-new\"}}]}}\n"
                    )
                    .as_bytes(),
                )
                .unwrap();
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&live.path).unwrap();
        let report = SessionService::new(&paths).reconcile(&mut client).unwrap();
        let entry = report
            .sessions
            .iter()
            .find(|entry| entry.session_id == id)
            .unwrap();
        assert_eq!(entry.status, SessionStatus::Live);
        assert!(entry.rewritten);
        let record = load_record(&paths, id);
        assert_eq!(record.status, SessionStatus::Live);
        assert_eq!(record.last_known_generation.as_deref(), Some("gen-new"));
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
            read_request(&mut reader, tx); // StartSession
            read_request(&mut reader, tx); // Attach
            stream
                .write_all(format!("{}\n", grid_line(id, "gen-new", 1)).as_bytes())
                .unwrap();
            stream.flush().unwrap();
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

        // Two persisted sessions, both Unknown to start.
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
                last_known_generation: None,
                status: SessionStatus::Unknown,
            };
            store::write_record(&paths, RecordKind::Session, id, 1, &rec).unwrap();
        }

        // The daemon reports only "alive" live.
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[\"alive\"]}\n")
                .unwrap();
            stream.flush().unwrap();
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
            last_known_generation: None,
            status: SessionStatus::Unknown,
        };
        store::write_record(&paths, RecordKind::Session, "known", 1, &rec).unwrap();

        // Daemon reports BOTH the known id and an orphan it has no record for.
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[\"known\",\"orphan\"]}\n")
                .unwrap();
            stream.flush().unwrap();
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
                last_known_generation: None,
                status: SessionStatus::Unknown,
            };
            store::write_record(&paths, RecordKind::Session, id, 1, &rec).unwrap();
        }

        // Daemon live set: one persisted-live id + three orphans in non-sorted order. "p-dead" is
        // persisted but NOT live -> Exited, never recovered.
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[\"orphan-c\",\"p-live\",\"orphan-a\",\"orphan-b\"]}\n")
                .unwrap();
            stream.flush().unwrap();
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
            read_request(&mut reader, tx);
            read_request(&mut reader, tx);
            stream
                .write_all(format!("{}\n", grid_line("s1", "g", 1)).as_bytes())
                .unwrap();
            stream.flush().unwrap();
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
            read_request(&mut reader, tx); // StartSession (carries the real argv)
            read_request(&mut reader, tx); // Attach
            stream
                .write_all(format!("{}\n", grid_line("s1", "g", 1)).as_bytes())
                .unwrap();
            stream.flush().unwrap();
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
        assert!(
            reqs[0].contains("sk-supersecretvalue123"),
            "daemon must receive the real argv: {reqs:?}"
        );
        // And what's on disk matches the redacted in-memory record.
        let on_disk = load_record(&paths, "s1");
        assert_eq!(on_disk.launch, rec.launch);
    }
}
