//! Local `AgentTask` <-> `SessionRecord` reconciliation.
//!
//! [`AgentTaskReconciler`] is a READ/REPORT-ONLY scan over the durable records currently on
//! disk: it joins every `AgentTask` to its `current_session_id`'s `SessionRecord` (if any) and
//! reports, per task, the linked session's recorded status, whether the session record is
//! missing, and a derived `needs_attention` flag — plus dangling session->task references and
//! future-version/quarantined records on both sides.
//!
//! Hard boundaries (all tested):
//!
//! - NO daemon connect, no `ShellRuntime`, no `SessionService` — this reads records only. It
//!   assumes session liveness was already repaired by `SessionService::reconcile` when the
//!   caller wants daemon-aware status; otherwise statuses are simply whatever is on disk.
//! - NO writes: no task state is mutated, no session record is rewritten, and in particular
//!   `Succeeded`/`Failed` are NEVER inferred from an exited session. The only disk mutation is
//!   the store's own corrupt-record quarantine, which `load_all` performs during the scan.
//! - Future-version records are left byte-identical in place and reported in
//!   `skipped_future_tasks` / `skipped_future_sessions`.
//! - Corrupt records are quarantined by the store and REPORTED (in `quarantined_tasks` /
//!   `quarantined_sessions`) rather than surfaced as a typed error: a reconciliation report
//!   should describe everything it saw in one pass instead of aborting on the first bad file.
//!   The only error this module returns is the store's own [`StoreError`] (directory IO).
//!
//! ## `needs_attention` semantics (state-first, documented choice)
//!
//! - `WaitingOnUser` / `Blocked`: ALWAYS true — user input is by definition required,
//!   regardless of any session record.
//! - `Running`: true iff the current session is not provably-recorded `Live` — i.e. its record
//!   says `Exited`/`Unknown`, or the record is missing. A `Running` task with NO current
//!   session id is not flagged (nothing actionable is recorded).
//! - `Draft`: false, EXCEPT a `Draft` pointing at a missing session record (anomalous link).
//! - Terminal (`Succeeded`/`Failed`/`Cancelled`): ALWAYS false, including `Failed` and
//!   including a missing session record. Failure was explicitly asserted by the shell and is
//!   already a final, user-visible outcome; the attention flag marks tasks needing
//!   intervention to MAKE PROGRESS. The terminal state itself is reported as-is, never mutated.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use crate::paths::{AppPaths, RecordKind};
use crate::records::{AgentTask, AgentTaskState, SessionRecord, SessionStatus};
use crate::store::{self, LoadOutcome, StoreError};

/// One task joined against the session records on disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconciledAgentTask {
    pub agent_task_id: String,
    /// The task's durable state, reported AS-IS (never mutated by reconciliation).
    pub state: AgentTaskState,
    pub current_session_id: Option<String>,
    /// The linked session record's recorded status; `None` when the task has no current
    /// session or the record is missing.
    pub current_session_status: Option<SessionStatus>,
    /// True only when `current_session_id` is set but no session record exists for it.
    pub session_record_missing: bool,
    /// See the module docs for the exact derivation.
    pub needs_attention: bool,
}

/// A session record whose `agent_task_id` points at a task that has no loaded record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DanglingSessionTaskRef {
    pub session_id: String,
    pub agent_task_id: String,
    pub session_status: SessionStatus,
}

/// A corrupt record the store quarantined during this scan (bytes preserved at `moved_to`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct QuarantinedRecord {
    pub original: PathBuf,
    pub moved_to: PathBuf,
    pub reason: String,
}

/// The full local reconciliation view. Deterministic: tasks sorted by `agent_task_id`,
/// dangling refs by `session_id`, skipped/quarantined paths lexically.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentTaskReconcileReport {
    pub tasks: Vec<ReconciledAgentTask>,
    pub dangling_session_task_refs: Vec<DanglingSessionTaskRef>,
    /// Future-version task records: left byte-identical in place, never rewritten.
    pub skipped_future_tasks: Vec<PathBuf>,
    /// Future-version session records: left byte-identical in place, never rewritten.
    pub skipped_future_sessions: Vec<PathBuf>,
    pub quarantined_tasks: Vec<QuarantinedRecord>,
    pub quarantined_sessions: Vec<QuarantinedRecord>,
}

/// Read-only reconciler over an injected [`AppPaths`]. Holds no daemon handle, no socket, no
/// services — records in, report out.
pub struct AgentTaskReconciler<'a> {
    paths: &'a AppPaths,
}

impl<'a> AgentTaskReconciler<'a> {
    pub fn new(paths: &'a AppPaths) -> Self {
        AgentTaskReconciler { paths }
    }

    /// Scan all `AgentTask` and `SessionRecord` records and produce the joined report. Missing
    /// record directories are fine (empty report). The only error is the store's own directory
    /// IO; per-file problems (future-version, corrupt) land in the report instead.
    pub fn reconcile(&self) -> Result<AgentTaskReconcileReport, StoreError> {
        let mut report = AgentTaskReconcileReport::default();

        let mut tasks: Vec<AgentTask> = Vec::new();
        for outcome in store::load_all::<AgentTask>(self.paths, RecordKind::AgentTask)? {
            match outcome {
                LoadOutcome::Loaded(t) => tasks.push(t),
                LoadOutcome::FutureVersion { path, .. } => {
                    report.skipped_future_tasks.push(path);
                }
                LoadOutcome::Quarantined {
                    original,
                    moved_to,
                    reason,
                } => report.quarantined_tasks.push(QuarantinedRecord {
                    original,
                    moved_to,
                    reason,
                }),
            }
        }

        let mut sessions: Vec<SessionRecord> = Vec::new();
        for outcome in store::load_all::<SessionRecord>(self.paths, RecordKind::Session)? {
            match outcome {
                LoadOutcome::Loaded(s) => sessions.push(s),
                LoadOutcome::FutureVersion { path, .. } => {
                    report.skipped_future_sessions.push(path);
                }
                LoadOutcome::Quarantined {
                    original,
                    moved_to,
                    reason,
                } => report.quarantined_sessions.push(QuarantinedRecord {
                    original,
                    moved_to,
                    reason,
                }),
            }
        }

        let session_by_id: HashMap<&str, &SessionRecord> = sessions
            .iter()
            .map(|s| (s.session_id.as_str(), s))
            .collect();
        let task_ids: HashSet<&str> = tasks.iter().map(|t| t.agent_task_id.as_str()).collect();

        for task in &tasks {
            let (current_session_status, session_record_missing) = match &task.current_session_id {
                None => (None, false),
                Some(id) => match session_by_id.get(id.as_str()) {
                    Some(session) => (Some(session.status), false),
                    None => (None, true),
                },
            };
            report.tasks.push(ReconciledAgentTask {
                agent_task_id: task.agent_task_id.clone(),
                state: task.state,
                current_session_id: task.current_session_id.clone(),
                current_session_status,
                session_record_missing,
                needs_attention: needs_attention(
                    task.state,
                    current_session_status,
                    session_record_missing,
                ),
            });
        }

        for session in &sessions {
            if let Some(task_id) = &session.agent_task_id {
                if !task_ids.contains(task_id.as_str()) {
                    report
                        .dangling_session_task_refs
                        .push(DanglingSessionTaskRef {
                            session_id: session.session_id.clone(),
                            agent_task_id: task_id.clone(),
                            session_status: session.status,
                        });
                }
            }
        }

        report
            .tasks
            .sort_by(|a, b| a.agent_task_id.cmp(&b.agent_task_id));
        report
            .dangling_session_task_refs
            .sort_by(|a, b| a.session_id.cmp(&b.session_id));
        report.skipped_future_tasks.sort();
        report.skipped_future_sessions.sort();
        report
            .quarantined_tasks
            .sort_by(|a, b| a.original.cmp(&b.original));
        report
            .quarantined_sessions
            .sort_by(|a, b| a.original.cmp(&b.original));
        Ok(report)
    }
}

/// The attention derivation documented in the module docs. Pure; never mutates anything.
fn needs_attention(
    state: AgentTaskState,
    current_session_status: Option<SessionStatus>,
    session_record_missing: bool,
) -> bool {
    match state {
        AgentTaskState::WaitingOnUser | AgentTaskState::Blocked => true,
        AgentTaskState::Succeeded | AgentTaskState::Failed | AgentTaskState::Cancelled => false,
        AgentTaskState::Running => {
            session_record_missing
                || matches!(
                    current_session_status,
                    Some(SessionStatus::Exited) | Some(SessionStatus::Unknown)
                )
        }
        AgentTaskState::Draft => session_record_missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::LaunchSpec;
    use tempfile::TempDir;

    fn temp_paths() -> (TempDir, AppPaths) {
        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::with_base(tmp.path().join("Maestro"));
        (tmp, paths)
    }

    /// Persist a minimal parent Project so an FK-bearing AgentTask (agent_tasks.project_id →
    /// projects) can be written. Idempotent.
    fn seed_project(paths: &AppPaths, id: &str) {
        crate::project::ProjectService::new(paths)
            .create(id, id, "/r", crate::project::NewProject::default(), 1)
            .ok();
    }

    /// Seed the project → workspace chain a SessionRecord needs (sessions.workspace_id →
    /// workspaces.project_id). Idempotent AND non-destructive: because the workspace upsert is
    /// `INSERT OR REPLACE` (DELETE+INSERT → cascades to sessions), re-seeding an existing
    /// workspace would wipe sessions already written under it, so we only write it once.
    fn seed_workspace(paths: &AppPaths, workspace_id: &str, project_id: &str) {
        seed_project(paths, project_id);
        if store::load_one::<crate::records::Workspace>(paths, RecordKind::Workspace, workspace_id)
            .unwrap()
            .is_some()
        {
            return;
        }
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

    fn task(id: &str, state: AgentTaskState, current: Option<&str>) -> AgentTask {
        AgentTask {
            agent_task_id: id.into(),
            project_id: "proj-1".into(),
            goal: "goal".into(),
            state,
            current_session_id: current.map(str::to_string),
            session_history: vec![],
            created_at_ms: 1,
            updated_at_ms: 1,
            result_summary: None,
        }
    }

    fn session(id: &str, task_ref: Option<&str>, status: SessionStatus) -> SessionRecord {
        SessionRecord {
            session_id: id.into(),
            workspace_id: "ws1".into(),
            kind: crate::records::SessionKind::Agent,
            launch: LaunchSpec::KnownSafe {
                launch_spec_id: "ls-1".into(),
                params: vec![],
            },
            cwd_resolved: "/tmp".into(),
            agent_task_id: task_ref.map(str::to_string),
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status,
        }
    }

    fn write_task(paths: &AppPaths, t: &AgentTask) {
        // agent_tasks.project_id → projects: seed the parent (all tasks here use "proj-1").
        seed_project(paths, &t.project_id);
        store::write_record(paths, RecordKind::AgentTask, &t.agent_task_id, 1, t).unwrap();
    }

    fn write_session(paths: &AppPaths, s: &SessionRecord) {
        // sessions.workspace_id → workspaces: seed the project → workspace chain (all sessions
        // here use "ws1").
        seed_workspace(paths, &s.workspace_id, "proj-1");
        // sessions.agent_task_id → agent_tasks (ON DELETE SET NULL) still requires the referenced
        // task to EXIST at insert. If this session references a task, seed a matching Draft first
        // so the write doesn't violate the FK. (Tests that want an ORPHANED ref use
        // `write_dangling_session`, which deletes the parent afterward with FKs off.)
        if let Some(task_id) = &s.agent_task_id {
            if store::load_one::<AgentTask>(paths, RecordKind::AgentTask, task_id)
                .unwrap()
                .is_none()
            {
                write_task(paths, &task(task_id, AgentTaskState::Draft, None));
            }
        }
        store::write_record(paths, RecordKind::Session, &s.session_id, 1, s).unwrap();
    }

    /// Persist a session whose `agent_task_id` points at a task that then vanishes — reproducing
    /// the legacy/pre-FK orphan the reconciler is built to report. We satisfy the FK on insert by
    /// seeding the ghost task, then delete that task row with `foreign_keys=OFF` so the session's
    /// ref is left dangling (a normal ON DELETE would SET NULL it, erasing the very state under
    /// test).
    fn write_dangling_session(
        paths: &AppPaths,
        id: &str,
        ghost_task_id: &str,
        status: SessionStatus,
    ) {
        write_session(paths, &session(id, Some(ghost_task_id), status));
        let arc = crate::db::conn_for(paths.base()).unwrap();
        let conn = arc.lock().unwrap();
        conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
        conn.execute(
            "DELETE FROM agent_tasks WHERE agent_task_id = ?1",
            [ghost_task_id],
        )
        .unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
    }

    fn reconcile(paths: &AppPaths) -> AgentTaskReconcileReport {
        AgentTaskReconciler::new(paths).reconcile().unwrap()
    }

    fn one_task(report: &AgentTaskReconcileReport, id: &str) -> ReconciledAgentTask {
        report
            .tasks
            .iter()
            .find(|t| t.agent_task_id == id)
            .unwrap_or_else(|| panic!("task {id} missing from report"))
            .clone()
    }

    /// Every task + session record currently loadable through the store, so tests can prove the
    /// read-only scan mutated nothing. (The file-era `all_record_bytes` byte-comparison is gone
    /// now that records are SQLite rows; loading them back through the API is the behavioral
    /// equivalent — same records in, same records out.)
    fn all_records(paths: &AppPaths) -> (Vec<AgentTask>, Vec<SessionRecord>) {
        fn loaded<T: serde::de::DeserializeOwned>(paths: &AppPaths, kind: RecordKind) -> Vec<T> {
            store::load_all::<T>(paths, kind)
                .unwrap()
                .into_iter()
                .filter_map(|o| match o {
                    LoadOutcome::Loaded(r) => Some(r),
                    _ => None,
                })
                .collect()
        }
        let mut tasks: Vec<AgentTask> = loaded(paths, RecordKind::AgentTask);
        tasks.sort_by(|a, b| a.agent_task_id.cmp(&b.agent_task_id));
        let mut sessions: Vec<SessionRecord> = loaded(paths, RecordKind::Session);
        sessions.sort_by(|a, b| a.session_id.cmp(&b.session_id));
        (tasks, sessions)
    }

    #[test]
    fn running_task_with_live_session_is_not_attention() {
        let (_tmp, paths) = temp_paths();
        write_task(&paths, &task("t1", AgentTaskState::Running, Some("s1")));
        write_session(&paths, &session("s1", Some("t1"), SessionStatus::Live));

        let r = one_task(&reconcile(&paths), "t1");
        assert_eq!(r.state, AgentTaskState::Running);
        assert_eq!(r.current_session_status, Some(SessionStatus::Live));
        assert!(!r.session_record_missing);
        assert!(!r.needs_attention);
    }

    #[test]
    fn running_task_with_exited_session_is_attention_and_nothing_is_mutated() {
        let (_tmp, paths) = temp_paths();
        write_task(&paths, &task("t1", AgentTaskState::Running, Some("s1")));
        write_session(&paths, &session("s1", Some("t1"), SessionStatus::Exited));
        let before = all_records(&paths);

        let r = one_task(&reconcile(&paths), "t1");
        assert_eq!(r.state, AgentTaskState::Running, "state reported as-is");
        assert_eq!(r.current_session_status, Some(SessionStatus::Exited));
        assert!(r.needs_attention);

        // The scan wrote NOTHING: every record loads back identical (no Failed inference, no
        // session rewrite).
        assert_eq!(all_records(&paths), before);
    }

    #[test]
    fn running_task_with_unknown_session_is_attention() {
        let (_tmp, paths) = temp_paths();
        write_task(&paths, &task("t1", AgentTaskState::Running, Some("s1")));
        write_session(&paths, &session("s1", Some("t1"), SessionStatus::Unknown));

        let r = one_task(&reconcile(&paths), "t1");
        assert_eq!(r.current_session_status, Some(SessionStatus::Unknown));
        assert!(r.needs_attention);
    }

    #[test]
    fn waiting_and_blocked_tasks_are_attention_even_with_a_live_session() {
        let (_tmp, paths) = temp_paths();
        write_task(
            &paths,
            &task("t1", AgentTaskState::WaitingOnUser, Some("s1")),
        );
        write_task(&paths, &task("t2", AgentTaskState::Blocked, Some("s2")));
        // Blocked with NO current session still needs attention (state alone demands input).
        write_task(&paths, &task("t3", AgentTaskState::Blocked, None));
        write_session(&paths, &session("s1", Some("t1"), SessionStatus::Live));
        write_session(&paths, &session("s2", Some("t2"), SessionStatus::Live));

        let report = reconcile(&paths);
        assert!(one_task(&report, "t1").needs_attention);
        assert!(one_task(&report, "t2").needs_attention);
        let t3 = one_task(&report, "t3");
        assert!(t3.needs_attention);
        assert!(!t3.session_record_missing);
        assert_eq!(t3.current_session_status, None);
    }

    #[test]
    fn terminal_tasks_are_reported_as_is_and_never_attention_or_mutated() {
        let (_tmp, paths) = temp_paths();
        let states = [
            ("t-ok", AgentTaskState::Succeeded),
            ("t-bad", AgentTaskState::Failed),
            ("t-x", AgentTaskState::Cancelled),
        ];
        for (id, state) in states {
            write_task(&paths, &task(id, state, Some("s1")));
        }
        write_session(&paths, &session("s1", None, SessionStatus::Exited));
        let before = all_records(&paths);

        let report = reconcile(&paths);
        for (id, state) in states {
            let r = one_task(&report, id);
            assert_eq!(r.state, state, "terminal state reported as-is");
            assert_eq!(r.current_session_status, Some(SessionStatus::Exited));
            assert!(
                !r.needs_attention,
                "terminal {state:?} is final; attention flags mark tasks needing progress"
            );
        }
        assert_eq!(all_records(&paths), before, "nothing rewritten");
    }

    #[test]
    fn task_with_missing_session_record_is_flagged_and_attention_unless_terminal() {
        let (_tmp, paths) = temp_paths();
        write_task(
            &paths,
            &task("t-run", AgentTaskState::Running, Some("gone")),
        );
        write_task(
            &paths,
            &task("t-draft", AgentTaskState::Draft, Some("gone")),
        );
        write_task(
            &paths,
            &task("t-done", AgentTaskState::Succeeded, Some("gone")),
        );
        write_task(
            &paths,
            &task("t-fail", AgentTaskState::Failed, Some("gone")),
        );

        let report = reconcile(&paths);
        for id in ["t-run", "t-draft", "t-done", "t-fail"] {
            let r = one_task(&report, id);
            assert!(
                r.session_record_missing,
                "{id} must flag the missing record"
            );
            assert_eq!(r.current_session_status, None);
        }
        assert!(one_task(&report, "t-run").needs_attention);
        assert!(one_task(&report, "t-draft").needs_attention);
        assert!(!one_task(&report, "t-done").needs_attention, "terminal");
        assert!(!one_task(&report, "t-fail").needs_attention, "terminal");
    }

    #[test]
    fn task_without_current_session_has_no_missing_flag_and_no_attention() {
        let (_tmp, paths) = temp_paths();
        write_task(&paths, &task("t1", AgentTaskState::Draft, None));
        write_task(&paths, &task("t2", AgentTaskState::Running, None));

        let report = reconcile(&paths);
        for id in ["t1", "t2"] {
            let r = one_task(&report, id);
            assert!(!r.session_record_missing);
            assert_eq!(r.current_session_status, None);
            assert!(!r.needs_attention);
        }
    }

    #[test]
    fn session_ref_to_missing_task_is_dangling_and_existing_task_is_not() {
        let (_tmp, paths) = temp_paths();
        write_task(
            &paths,
            &task("t-real", AgentTaskState::Running, Some("s-ok")),
        );
        write_session(
            &paths,
            &session("s-ok", Some("t-real"), SessionStatus::Live),
        );
        write_dangling_session(&paths, "s-orphan", "t-ghost", SessionStatus::Exited);
        write_session(&paths, &session("s-plain", None, SessionStatus::Live));
        let before = all_records(&paths);

        let report = reconcile(&paths);
        assert_eq!(
            report.dangling_session_task_refs,
            vec![DanglingSessionTaskRef {
                session_id: "s-orphan".into(),
                agent_task_id: "t-ghost".into(),
                session_status: SessionStatus::Exited,
            }],
            "only the orphan ref dangles; FK-less and well-linked sessions do not"
        );
        assert_eq!(all_records(&paths), before, "session never rewritten");
    }

    // The file-era per-record `future_version_records_are_skipped_and_left_byte_identical` and
    // `corrupt_records_are_quarantined_and_reported_not_an_error` tests are gone: the store no
    // longer hand-writes JSON envelope FILES. Future-version is now a DB-level guard (whole DB
    // refused on open — see store.rs::future_version_db_is_refused_on_open), and an
    // un-deserializable row is surfaced as `Quarantined` and excluded from the loaded set (see
    // store.rs::row_that_wont_deserialize_is_quarantined_and_excluded). The reconcile report's
    // `skipped_future_*` / `quarantined_*` plumbing is still exercised end-to-end wherever those
    // outcomes flow up from `load_all`.

    #[test]
    fn empty_store_yields_an_empty_report() {
        let (_tmp, paths) = temp_paths();
        // The read-only scan surfaces no records (no projects/tasks/sessions were seeded). The
        // store's DB file existing after a load is expected now (records live in SQLite, not
        // per-record files), so the invariant is "the report is empty", not "no base dir".
        assert_eq!(reconcile(&paths), AgentTaskReconcileReport::default());
    }

    #[test]
    fn report_ordering_is_deterministic() {
        let (_tmp, paths) = temp_paths();
        // Written deliberately out of order.
        for id in ["t-c", "t-a", "t-b"] {
            write_task(&paths, &task(id, AgentTaskState::Draft, None));
        }
        for id in ["s-z", "s-m", "s-a"] {
            write_dangling_session(&paths, id, "t-ghost", SessionStatus::Exited);
        }

        let report = reconcile(&paths);
        let task_ids: Vec<&str> = report
            .tasks
            .iter()
            .map(|t| t.agent_task_id.as_str())
            .collect();
        assert_eq!(task_ids, vec!["t-a", "t-b", "t-c"]);
        let dangling_ids: Vec<&str> = report
            .dangling_session_task_refs
            .iter()
            .map(|d| d.session_id.as_str())
            .collect();
        assert_eq!(dangling_ids, vec!["s-a", "s-m", "s-z"]);
    }
}
