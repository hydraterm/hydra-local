//! Durable [`AgentTask`] lifecycle.
//!
//! [`AgentTaskService`] owns creating and transitioning `AgentTask` records under app-support
//! through the shared store (atomic envelope writes, corrupt-record quarantine, future-version
//! read-only semantics). It is STORE/LOCAL-STATE ONLY: no daemon, no socket, no PTY, no git, no
//! renderer — task state is product metadata, deliberately decoupled from process liveness. A
//! restart is `mark_running` with a new session id on the SAME task; success/failure is asserted
//! by the shell, never inferred from session status here.
//!
//! Transition validation is deliberately PERMISSIVE: any state may move to any
//! other (the normal flows `Draft -> Running -> WaitingOnUser/Blocked -> Running ->
//! Succeeded/Failed/Cancelled`, and terminal -> `Running` for retry, all work). What IS strict:
//! - transition methods never create a missing task ([`AgentTaskServiceError::TaskNotFound`])
//! - [`create_draft`](AgentTaskService::create_draft) never overwrites an existing task
//!   ([`AgentTaskServiceError::TaskAlreadyExists`]) — clobbering a possibly-`Running` task with
//!   a fresh `Draft` would silently lose its history
//! - future-version records are left byte-identical on disk and never rewritten
//! - corrupt records are quarantined by the store and surfaced, never trusted or rewritten

use std::path::PathBuf;

use crate::paths::{AppPaths, RecordKind};
use crate::records::{AgentTask, AgentTaskState};
use crate::store::{load_one, write_record, LoadOutcome, StoreError};

/// Why an agent-task operation failed.
#[derive(Debug)]
pub enum AgentTaskServiceError {
    /// No task record exists under this id; transitions never create one implicitly.
    TaskNotFound { agent_task_id: String },
    /// A task record already exists under this id; `create_draft` refuses to overwrite it.
    TaskAlreadyExists { agent_task_id: String },
    /// The task record was written by a NEWER Maestro. It is left exactly as on disk —
    /// rewriting it could drop fields this build does not model — so it cannot be transitioned
    /// (or replaced) from this build.
    FutureVersion { path: PathBuf, ours: u32, got: u32 },
    /// The task record was corrupt; the store quarantined it (moved to `corrupt/`, preserved)
    /// and it is surfaced here. Nothing was rewritten.
    Corrupt {
        original: PathBuf,
        moved_to: PathBuf,
        reason: String,
    },
    /// Underlying store failure (io / envelope / id). An unsafe `agent_task_id` surfaces here
    /// as `Store(Id(..))` BEFORE any path is built or file touched.
    Store(StoreError),
}

impl std::fmt::Display for AgentTaskServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentTaskServiceError::TaskNotFound { agent_task_id } => {
                write!(f, "no agent task record found for id {agent_task_id:?}")
            }
            AgentTaskServiceError::TaskAlreadyExists { agent_task_id } => write!(
                f,
                "an agent task record already exists for id {agent_task_id:?}; refusing to \
                 overwrite it with a new draft"
            ),
            AgentTaskServiceError::FutureVersion { path, ours, got } => write!(
                f,
                "agent task record {} was written by a newer Maestro (schema version {got} > \
                 {ours}); left in place, not modified",
                path.display()
            ),
            AgentTaskServiceError::Corrupt {
                original,
                moved_to,
                reason,
            } => write!(
                f,
                "agent task record {} was corrupt ({reason}); quarantined at {}",
                original.display(),
                moved_to.display()
            ),
            AgentTaskServiceError::Store(e) => write!(f, "agent task store error: {e}"),
        }
    }
}

impl std::error::Error for AgentTaskServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AgentTaskServiceError::Store(e) => Some(e),
            _ => None,
        }
    }
}

impl From<StoreError> for AgentTaskServiceError {
    fn from(e: StoreError) -> Self {
        AgentTaskServiceError::Store(e)
    }
}

/// Store-backed lifecycle service for [`AgentTask`] records. Borrows [`AppPaths`] so callers
/// keep the IO boundary visible — there is no hidden global store.
pub struct AgentTaskService<'a> {
    paths: &'a AppPaths,
}

impl<'a> AgentTaskService<'a> {
    pub fn new(paths: &'a AppPaths) -> Self {
        AgentTaskService { paths }
    }

    /// Create and persist a brand-new `Draft` task.
    ///
    /// - `state = Draft`, `current_session_id = None`, `session_history = []`,
    ///   `result_summary = None`, `created_at_ms = updated_at_ms = now_ms`.
    /// - The `agent_task_id` is validated by the store/id path BEFORE any file or directory is
    ///   touched; an unsafe id fails as `Store(Id(..))` with nothing on disk.
    /// - `project_id` is stored verbatim; this store does not enforce referential integrity against
    ///   `Project` records. No project/workspace/session is created or checked here.
    /// - An existing record under the same id is a typed [`TaskAlreadyExists`]
    ///   (`AgentTaskServiceError::TaskAlreadyExists`) and is never overwritten; a
    ///   future-version or corrupt record under the id surfaces with the usual store semantics.
    pub fn create_draft(
        &self,
        agent_task_id: impl Into<String>,
        project_id: impl Into<String>,
        goal: impl Into<String>,
        now_ms: u64,
    ) -> Result<AgentTask, AgentTaskServiceError> {
        let agent_task_id = agent_task_id.into();
        // load_one validates the id first (StoreError::Id before any path exists), then tells
        // us whether the id is free. Loaded/FutureVersion are refusals; a corrupt record is
        // quarantined by this very load and surfaced (the caller may retry once it has seen it).
        match load_one::<AgentTask>(self.paths, RecordKind::AgentTask, &agent_task_id)? {
            None => {}
            Some(LoadOutcome::Loaded(_)) => {
                return Err(AgentTaskServiceError::TaskAlreadyExists { agent_task_id });
            }
            Some(LoadOutcome::FutureVersion { path, ours, got }) => {
                return Err(AgentTaskServiceError::FutureVersion { path, ours, got });
            }
            Some(LoadOutcome::Quarantined {
                original,
                moved_to,
                reason,
            }) => {
                return Err(AgentTaskServiceError::Corrupt {
                    original,
                    moved_to,
                    reason,
                });
            }
        }

        let task = AgentTask {
            agent_task_id: agent_task_id.clone(),
            project_id: project_id.into(),
            goal: goal.into(),
            state: AgentTaskState::Draft,
            current_session_id: None,
            session_history: Vec::new(),
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
            result_summary: None,
        };
        write_record(
            self.paths,
            RecordKind::AgentTask,
            &agent_task_id,
            now_ms,
            &task,
        )?;
        Ok(task)
    }

    /// Move the task to `Running` on `session_id` (start, restart, or retry — the daemon is
    /// never consulted).
    ///
    /// History rules, exactly:
    /// - previous `current_session_id == None` -> nothing is pushed
    /// - previous `Some(old)` with `old != session_id` -> `old` is appended to
    ///   `session_history` exactly once (each real switch records one entry, oldest first)
    /// - previous `Some(old)` with `old == session_id` -> idempotent, nothing pushed
    /// - the NEW session id is never pushed at this transition (it becomes current, not history)
    ///
    /// `result_summary` is always cleared: `Running` means active work, so a summary from an
    /// earlier terminal state (retry) no longer describes the task. Coming from a non-terminal
    /// state the summary is already `None`, so this is only observable on terminal -> Running.
    pub fn mark_running(
        &self,
        agent_task_id: &str,
        session_id: impl Into<String>,
        now_ms: u64,
    ) -> Result<AgentTask, AgentTaskServiceError> {
        let session_id = session_id.into();
        self.transition(agent_task_id, now_ms, |task| {
            if let Some(old) = task.current_session_id.take() {
                if old != session_id {
                    task.session_history.push(old);
                }
            }
            task.state = AgentTaskState::Running;
            task.current_session_id = Some(session_id);
            task.result_summary = None;
        })
    }

    /// Move to `WaitingOnUser`. Preserves `current_session_id`, `session_history`, and
    /// `result_summary`; only state and `updated_at_ms` change.
    pub fn mark_waiting_on_user(
        &self,
        agent_task_id: &str,
        now_ms: u64,
    ) -> Result<AgentTask, AgentTaskServiceError> {
        self.transition(agent_task_id, now_ms, |task| {
            task.state = AgentTaskState::WaitingOnUser;
        })
    }

    /// Move to `Blocked`. Preserves `current_session_id`, `session_history`, and
    /// `result_summary`; only state and `updated_at_ms` change.
    pub fn mark_blocked(
        &self,
        agent_task_id: &str,
        now_ms: u64,
    ) -> Result<AgentTask, AgentTaskServiceError> {
        self.transition(agent_task_id, now_ms, |task| {
            task.state = AgentTaskState::Blocked;
        })
    }

    /// Terminal: `Succeeded`. Sets `result_summary = summary`; preserves
    /// `current_session_id` and `session_history`.
    pub fn mark_succeeded(
        &self,
        agent_task_id: &str,
        summary: Option<String>,
        now_ms: u64,
    ) -> Result<AgentTask, AgentTaskServiceError> {
        self.finish(agent_task_id, AgentTaskState::Succeeded, summary, now_ms)
    }

    /// Terminal: `Failed`. Sets `result_summary = summary`; preserves `current_session_id`
    /// and `session_history`. Failure is asserted by the caller, never inferred from a
    /// session's exit status here.
    pub fn mark_failed(
        &self,
        agent_task_id: &str,
        summary: Option<String>,
        now_ms: u64,
    ) -> Result<AgentTask, AgentTaskServiceError> {
        self.finish(agent_task_id, AgentTaskState::Failed, summary, now_ms)
    }

    /// Terminal: `Cancelled`. Sets `result_summary = summary`; preserves
    /// `current_session_id` and `session_history`.
    pub fn mark_cancelled(
        &self,
        agent_task_id: &str,
        summary: Option<String>,
        now_ms: u64,
    ) -> Result<AgentTask, AgentTaskServiceError> {
        self.finish(agent_task_id, AgentTaskState::Cancelled, summary, now_ms)
    }

    /// Load one task. `Ok(None)` means "no record"; a future-version record is a typed error
    /// (left in place), and a corrupt record is quarantined by the store and surfaced.
    pub fn load(&self, agent_task_id: &str) -> Result<Option<AgentTask>, AgentTaskServiceError> {
        match load_one::<AgentTask>(self.paths, RecordKind::AgentTask, agent_task_id)? {
            None => Ok(None),
            Some(LoadOutcome::Loaded(task)) => Ok(Some(task)),
            Some(LoadOutcome::FutureVersion { path, ours, got }) => {
                Err(AgentTaskServiceError::FutureVersion { path, ours, got })
            }
            Some(LoadOutcome::Quarantined {
                original,
                moved_to,
                reason,
            }) => Err(AgentTaskServiceError::Corrupt {
                original,
                moved_to,
                reason,
            }),
        }
    }

    /// Shared terminal transition: set `state`, set `result_summary = summary`, stamp time.
    fn finish(
        &self,
        agent_task_id: &str,
        state: AgentTaskState,
        summary: Option<String>,
        now_ms: u64,
    ) -> Result<AgentTask, AgentTaskServiceError> {
        self.transition(agent_task_id, now_ms, |task| {
            task.state = state;
            task.result_summary = summary;
        })
    }

    /// Load-modify-write for one existing task: load (typed `TaskNotFound` when absent;
    /// future-version/corrupt surface without a rewrite), apply the change, stamp
    /// `updated_at_ms = now_ms`, and atomically rewrite the record through the store.
    fn transition(
        &self,
        agent_task_id: &str,
        now_ms: u64,
        apply: impl FnOnce(&mut AgentTask),
    ) -> Result<AgentTask, AgentTaskServiceError> {
        let mut task =
            self.load(agent_task_id)?
                .ok_or_else(|| AgentTaskServiceError::TaskNotFound {
                    agent_task_id: agent_task_id.to_string(),
                })?;
        apply(&mut task);
        task.updated_at_ms = now_ms;
        write_record(
            self.paths,
            RecordKind::AgentTask,
            agent_task_id,
            now_ms,
            &task,
        )?;
        Ok(task)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_paths() -> (TempDir, AppPaths) {
        let tmp = TempDir::new().expect("temp dir");
        let paths = AppPaths::with_base(tmp.path().join("Maestro"));
        // The relational store enforces agent_tasks.project_id → projects (FK). Seed the parent projects the tests
        // reference so a create_draft doesn't violate the constraint (production always creates the project first).
        seed_project(&paths, "proj-1");
        seed_project(&paths, "other-proj");
        seed_project(&paths, "p");
        (tmp, paths)
    }

    /// Persist a minimal parent Project so FK-bearing child records (agent_tasks) can be written.
    fn seed_project(paths: &AppPaths, id: &str) {
        crate::project::ProjectService::new(paths)
            .create(id, id, "/r", crate::project::NewProject::default(), 1)
            .ok();
    }

    /// Read the task straight from the store, asserting it is a clean `Loaded` record.
    fn on_disk(paths: &AppPaths, id: &str) -> AgentTask {
        match load_one::<AgentTask>(paths, RecordKind::AgentTask, id)
            .expect("load")
            .expect("record must exist")
        {
            LoadOutcome::Loaded(task) => task,
            other => panic!("expected Loaded, got {other:?}"),
        }
    }

    fn draft(paths: &AppPaths) -> AgentTask {
        AgentTaskService::new(paths)
            .create_draft("task-1", "proj-1", "ship dashboard update", 100)
            .unwrap()
    }

    // ---- create_draft ----

    #[test]
    fn create_draft_writes_the_expected_record_fields() {
        let (_tmp, paths) = temp_paths();
        let task = draft(&paths);

        assert_eq!(task.agent_task_id, "task-1");
        assert_eq!(task.project_id, "proj-1");
        assert_eq!(task.goal, "ship dashboard update");
        assert_eq!(task.state, AgentTaskState::Draft);
        assert_eq!(task.current_session_id, None);
        assert!(task.session_history.is_empty());
        assert_eq!(task.created_at_ms, 100);
        assert_eq!(task.updated_at_ms, 100);
        assert_eq!(task.result_summary, None);
        // Durable and identical on disk.
        assert_eq!(on_disk(&paths, "task-1"), task);
    }

    #[test]
    fn create_draft_rejects_unsafe_id_before_touching_disk() {
        let (_tmp, paths) = temp_paths();
        let svc = AgentTaskService::new(&paths);
        for bad in ["../escape", "..", "a/b", "/abs", "a b", ""] {
            let r = svc.create_draft(bad, "proj-1", "goal", 1);
            assert!(
                matches!(r, Err(AgentTaskServiceError::Store(StoreError::Id(_)))),
                "id {bad:?} must fail with a store id error, got {r:?}"
            );
        }
        // The unsafe id was refused before any query — no task row exists for any of them.
        let svc = AgentTaskService::new(&paths);
        for bad in ["../escape", "..", "a/b", "/abs", "a b", ""] {
            assert!(
                svc.load(bad).unwrap_or(None).is_none(),
                "id {bad:?} must not have been persisted"
            );
        }
    }

    #[test]
    fn create_draft_refuses_to_overwrite_an_existing_task() {
        let (_tmp, paths) = temp_paths();
        let svc = AgentTaskService::new(&paths);
        let original = draft(&paths);
        // Advance it so an overwrite would be visible (and destructive).
        svc.mark_running("task-1", "sess-1", 200).unwrap();

        let r = svc.create_draft("task-1", "other-proj", "other goal", 300);
        assert!(
            matches!(r, Err(AgentTaskServiceError::TaskAlreadyExists { ref agent_task_id }) if agent_task_id == "task-1"),
            "existing task must be TaskAlreadyExists, got {r:?}"
        );
        // The running record is untouched (not reset to the new draft or the old one).
        let kept = on_disk(&paths, "task-1");
        assert_eq!(kept.state, AgentTaskState::Running);
        assert_eq!(kept.project_id, original.project_id);
        assert_eq!(kept.goal, original.goal);
    }

    // ---- mark_running / restart history ----

    #[test]
    fn mark_running_from_draft_sets_current_session_and_pushes_nothing() {
        let (_tmp, paths) = temp_paths();
        draft(&paths);
        let svc = AgentTaskService::new(&paths);

        let task = svc.mark_running("task-1", "sess-1", 200).unwrap();
        assert_eq!(task.state, AgentTaskState::Running);
        assert_eq!(task.current_session_id.as_deref(), Some("sess-1"));
        assert!(
            task.session_history.is_empty(),
            "no previous session, nothing to push"
        );
        assert_eq!(task.updated_at_ms, 200);
        assert_eq!(task.created_at_ms, 100, "created_at is immutable");
        assert_eq!(on_disk(&paths, "task-1"), task);
    }

    #[test]
    fn mark_running_with_a_different_session_pushes_the_old_one_exactly_once() {
        let (_tmp, paths) = temp_paths();
        draft(&paths);
        let svc = AgentTaskService::new(&paths);
        svc.mark_running("task-1", "sess-1", 200).unwrap();

        let task = svc.mark_running("task-1", "sess-2", 300).unwrap();
        assert_eq!(task.current_session_id.as_deref(), Some("sess-2"));
        assert_eq!(
            task.session_history,
            vec!["sess-1".to_string()],
            "the OLD session goes to history exactly once; the new one never does"
        );

        // A further switch records each stint, oldest first.
        let task = svc.mark_running("task-1", "sess-3", 400).unwrap();
        assert_eq!(
            task.session_history,
            vec!["sess-1".to_string(), "sess-2".to_string()]
        );
        assert_eq!(on_disk(&paths, "task-1"), task);
    }

    #[test]
    fn mark_running_with_the_same_session_is_idempotent() {
        let (_tmp, paths) = temp_paths();
        draft(&paths);
        let svc = AgentTaskService::new(&paths);
        svc.mark_running("task-1", "sess-1", 200).unwrap();

        let task = svc.mark_running("task-1", "sess-1", 300).unwrap();
        assert_eq!(task.state, AgentTaskState::Running);
        assert_eq!(task.current_session_id.as_deref(), Some("sess-1"));
        assert!(
            task.session_history.is_empty(),
            "same session must not be duplicated into history"
        );
        assert_eq!(task.updated_at_ms, 300, "time still advances");
    }

    #[test]
    fn mark_running_from_terminal_clears_summary_and_preserves_history_semantics() {
        let (_tmp, paths) = temp_paths();
        draft(&paths);
        let svc = AgentTaskService::new(&paths);
        svc.mark_running("task-1", "sess-1", 200).unwrap();
        svc.mark_succeeded("task-1", Some("done".into()), 300)
            .unwrap();

        // Retry on a NEW session: summary cleared, previous current pushed once.
        let task = svc.mark_running("task-1", "sess-2", 400).unwrap();
        assert_eq!(task.state, AgentTaskState::Running);
        assert_eq!(task.result_summary, None, "stale summary must be cleared");
        assert_eq!(task.current_session_id.as_deref(), Some("sess-2"));
        assert_eq!(task.session_history, vec!["sess-1".to_string()]);

        // And from Failed, retrying on the SAME session: summary cleared, no duplicate.
        svc.mark_failed("task-1", Some("broke".into()), 500)
            .unwrap();
        let task = svc.mark_running("task-1", "sess-2", 600).unwrap();
        assert_eq!(task.result_summary, None);
        assert_eq!(task.session_history, vec!["sess-1".to_string()]);
        assert_eq!(on_disk(&paths, "task-1"), task);
    }

    // ---- non-running transitions ----

    #[test]
    fn waiting_on_user_and_blocked_preserve_session_history_and_summary() {
        let (_tmp, paths) = temp_paths();
        draft(&paths);
        let svc = AgentTaskService::new(&paths);
        svc.mark_running("task-1", "sess-1", 200).unwrap();
        svc.mark_running("task-1", "sess-2", 300).unwrap();

        let task = svc.mark_waiting_on_user("task-1", 400).unwrap();
        assert_eq!(task.state, AgentTaskState::WaitingOnUser);
        assert_eq!(task.current_session_id.as_deref(), Some("sess-2"));
        assert_eq!(task.session_history, vec!["sess-1".to_string()]);
        assert_eq!(task.result_summary, None);
        assert_eq!(task.updated_at_ms, 400);

        let task = svc.mark_blocked("task-1", 500).unwrap();
        assert_eq!(task.state, AgentTaskState::Blocked);
        assert_eq!(task.current_session_id.as_deref(), Some("sess-2"));
        assert_eq!(task.session_history, vec!["sess-1".to_string()]);
        assert_eq!(task.updated_at_ms, 500);

        // Back to running on the same session: the documented normal flow round-trips.
        let task = svc.mark_running("task-1", "sess-2", 600).unwrap();
        assert_eq!(task.state, AgentTaskState::Running);
        assert_eq!(task.session_history, vec!["sess-1".to_string()]);
        assert_eq!(on_disk(&paths, "task-1"), task);
    }

    #[test]
    fn terminal_transitions_set_state_and_summary_preserving_sessions() {
        let (_tmp, paths) = temp_paths();
        let svc = AgentTaskService::new(&paths);
        for (i, (state, mark)) in [
            (
                AgentTaskState::Succeeded,
                (|s: &AgentTaskService<'_>, id: &str, sum, now| s.mark_succeeded(id, sum, now))
                    as fn(&AgentTaskService<'_>, &str, Option<String>, u64) -> _,
            ),
            (AgentTaskState::Failed, |s, id, sum, now| {
                s.mark_failed(id, sum, now)
            }),
            (AgentTaskState::Cancelled, |s, id, sum, now| {
                s.mark_cancelled(id, sum, now)
            }),
        ]
        .into_iter()
        .enumerate()
        {
            let id = format!("task-{i}");
            svc.create_draft(&id, "proj-1", "goal", 100).unwrap();
            svc.mark_running(&id, "sess-1", 200).unwrap();

            let task = mark(&svc, &id, Some(format!("outcome {i}")), 300).unwrap();
            assert_eq!(task.state, state);
            assert_eq!(
                task.result_summary.as_deref(),
                Some(&*format!("outcome {i}"))
            );
            assert_eq!(
                task.current_session_id.as_deref(),
                Some("sess-1"),
                "terminal states keep the last session for inspection/retry"
            );
            assert!(task.session_history.is_empty());
            assert_eq!(task.updated_at_ms, 300);
            assert_eq!(on_disk(&paths, &id), task);

            // A None summary is also allowed and stored as None.
            let task = mark(&svc, &id, None, 400).unwrap();
            assert_eq!(task.result_summary, None);
        }
    }

    // ---- missing / future-version / corrupt records ----

    #[test]
    fn transitions_on_a_missing_task_are_task_not_found_and_create_nothing() {
        let (_tmp, paths) = temp_paths();
        let svc = AgentTaskService::new(&paths);

        let results = [
            svc.mark_running("absent", "sess-1", 1).err(),
            svc.mark_waiting_on_user("absent", 1).err(),
            svc.mark_blocked("absent", 1).err(),
            svc.mark_succeeded("absent", None, 1).err(),
            svc.mark_failed("absent", None, 1).err(),
            svc.mark_cancelled("absent", None, 1).err(),
        ];
        for r in results {
            assert!(
                matches!(r, Some(AgentTaskServiceError::TaskNotFound { ref agent_task_id }) if agent_task_id == "absent"),
                "missing task must be TaskNotFound, got {r:?}"
            );
        }
        // No record was implicitly created.
        assert!(svc.load("absent").unwrap().is_none());
    }

    // NOTE: the old per-record `future_version_task_...` and `corrupt_task_...` tests wrote raw JSON envelope FILES,
    // which no longer exist in the SQLite store. Future-version is now a DB-LEVEL guard (see store::future_version_db_
    // is_refused_on_open) and a row that won't deserialize surfaces as Quarantined (store::row_that_wont_deserialize_*).

    // ---- load ----

    #[test]
    fn load_returns_none_for_absent_and_the_task_for_valid_records() {
        let (_tmp, paths) = temp_paths();
        let svc = AgentTaskService::new(&paths);
        assert!(svc.load("task-1").unwrap().is_none());

        let created = draft(&paths);
        assert_eq!(svc.load("task-1").unwrap(), Some(created));
    }
}
