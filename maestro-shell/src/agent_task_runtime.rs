//! Agent-task START and RESUME composition.
//!
//! [`AgentTaskRuntime`] composes the two primitives that already exist, in a fixed safe order:
//!
//! 1. [`AgentTaskService`] — durable `AgentTask` lifecycle (store only);
//! 2. [`ShellRuntime`] — resolve socket -> connect -> (persist endpoint) -> start/attach
//!    ONE session with record-backed semantics.
//!
//! This module is COMPOSITION ONLY: no new persistence format, no new wire behavior, no tabs UI,
//! no CLI. It proves the durable task record and the durable session record move TOGETHER on the
//! successful path while every failure stays honest and recoverable.
//!
//! ## Ordering and invariants
//!
//! `start_new_agent_task` runs, strictly in order:
//!
//! 1. **Validate inputs before any write or connect.** `params.kind` must be
//!    [`SessionKind::Agent`] (a shell session is never silently started as an agent task), and
//!    `params.agent_task_id` must be `None` or equal to the task id argument. A validation
//!    failure touches NOTHING: no task record, no session record, no endpoint, no daemon connect.
//! 2. **Create the durable `AgentTask` as `Draft`.** If this fails (already exists,
//!    future-version, corrupt, store/id) the daemon is never contacted.
//! 3. **Force the FK** — `params.agent_task_id = Some(agent_task_id)` — then delegate to
//!    [`ShellRuntime::start_session`], which preserves its ordering: connect first,
//!    endpoint only after a successful connect, session record `Unknown` before `StartSession`,
//!    `Live` only on the daemon's `Grid` proof.
//! 4. **Only after a live session** call [`AgentTaskService::mark_running`] — the task moves
//!    `Draft -> Running` with `current_session_id = Some(session_id)` and nothing pushed to
//!    history for a fresh draft.
//!
//! If anything past step 2 fails, the task is LEFT AS `Draft` — `mark_running` is never called
//! on a failed start, and any session-record behavior (`Unknown` / `Exited`) is exactly what
//! `ShellRuntime` / `SessionService` already wrote. Nothing here infers `Succeeded`/`Failed`
//! from daemon or session errors; reconciliation and attention handling are separate concerns.
//!
//! [`resume_agent_task`](AgentTaskRuntime::resume_agent_task) uses the SAME ordering
//! for an EXISTING task — validate, then LOAD the task (a missing/future-version/corrupt task
//! prevents the daemon connect and any session record), start the session with the forced FK,
//! and `mark_running` only on live proof. The task record is never mutated before the session
//! is live, so any failed resume leaves it exactly as it was.
//!
//! ## Secret-aware boundary (deliberate non-feature)
//!
//! There is NO "restart from the stored `LaunchSpec`" here. The caller must supply fresh
//! [`StartParams`] for every start/resume: ad-hoc launches are persisted REDACTED
//! (`restart_requires_user`), so replaying them silently could not include the secrets the
//! original argv carried — and must not try. These methods are safe composition primitives,
//! not silent command replay.

use std::path::PathBuf;
use std::time::Duration;

use crate::agent_tasks::{AgentTaskService, AgentTaskServiceError};
use crate::daemon_client::DEFAULT_TIMEOUT;
use crate::daemon_endpoint::EnvLookup;
use crate::paths::AppPaths;
use crate::records::{AgentTask, SessionKind, SessionRecord};
use crate::session_service::StartParams;
use crate::shell_runtime::{ShellRuntime, ShellRuntimeError};

/// Why starting an agent-backed session failed, keeping each layer's typed error intact so a
/// caller can tell validation, task-store, and shell/daemon failures apart.
#[derive(Debug)]
pub enum AgentTaskRuntimeError {
    /// `params.kind` was not [`SessionKind::Agent`]. A shell session is never silently started
    /// as an agent task. Nothing was written and no connect was attempted.
    InvalidSessionKind { kind: SessionKind },
    /// `params.agent_task_id` was `Some(got)` but differed from the task id argument. Nothing
    /// was written and no connect was attempted.
    AgentTaskIdMismatch { expected: String, got: String },
    /// The task store refused (already exists, future-version, corrupt, store/id, not found).
    Task(AgentTaskServiceError),
    /// The shell runtime failed (endpoint store, daemon connect, session start). If the draft
    /// was already created, it remains `Draft`.
    Shell(ShellRuntimeError),
}

impl std::fmt::Display for AgentTaskRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentTaskRuntimeError::InvalidSessionKind { kind } => write!(
                f,
                "agent task start requires SessionKind::Agent, got {kind:?}; refusing to start \
                 a non-agent session as an agent task"
            ),
            AgentTaskRuntimeError::AgentTaskIdMismatch { expected, got } => write!(
                f,
                "StartParams.agent_task_id {got:?} does not match the agent task being started \
                 ({expected:?})"
            ),
            AgentTaskRuntimeError::Task(e) => write!(f, "agent task runtime task error: {e}"),
            AgentTaskRuntimeError::Shell(e) => write!(f, "agent task runtime shell error: {e}"),
        }
    }
}

impl std::error::Error for AgentTaskRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AgentTaskRuntimeError::Task(e) => Some(e),
            AgentTaskRuntimeError::Shell(e) => Some(e),
            _ => None,
        }
    }
}

impl From<AgentTaskServiceError> for AgentTaskRuntimeError {
    fn from(e: AgentTaskServiceError) -> Self {
        AgentTaskRuntimeError::Task(e)
    }
}

impl From<ShellRuntimeError> for AgentTaskRuntimeError {
    fn from(e: ShellRuntimeError) -> Self {
        AgentTaskRuntimeError::Shell(e)
    }
}

/// The result of a successful agent-task start: the socket actually used, the task now
/// `Running` on the session, and the `Live` session record carrying the task FK.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartAgentTaskOutcome {
    pub socket_path: PathBuf,
    pub task: AgentTask,
    pub session: SessionRecord,
}

/// Agent-task runtime over an injected [`AppPaths`]. Holds only borrowed config — the same
/// builder knobs as [`ShellRuntime`], which it constructs internally with identical settings.
pub struct AgentTaskRuntime<'a> {
    paths: &'a AppPaths,
    connect_timeout: Duration,
    persist_endpoint: bool,
}

impl<'a> AgentTaskRuntime<'a> {
    /// Default connect timeout; persists the endpoint after a successful connect (matching
    /// [`ShellRuntime::new`]).
    pub fn new(paths: &'a AppPaths) -> Self {
        AgentTaskRuntime {
            paths,
            connect_timeout: DEFAULT_TIMEOUT,
            persist_endpoint: true,
        }
    }

    /// Override the daemon connect timeout (forwarded to the inner [`ShellRuntime`]).
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Disable persisting the `DaemonEndpoint` record after connect (forwarded to the inner
    /// [`ShellRuntime`]).
    pub fn without_endpoint_persist(mut self) -> Self {
        self.persist_endpoint = false;
        self
    }

    /// Create a NEW agent task and start its first session. See the module docs for the exact
    /// ordering; in short: validate -> durable `Draft` -> `ShellRuntime::start_session` (with
    /// `params.agent_task_id` forced to this task) -> `mark_running` only after the session is
    /// `Live` -> outcome.
    ///
    /// On failure after the draft was created, the task is left as `Draft` (recoverable: the
    /// caller can retry the start against the same task through the resume path).
    pub fn start_new_agent_task(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        agent_task_id: impl Into<String>,
        project_id: impl Into<String>,
        goal: impl Into<String>,
        params: StartParams,
    ) -> Result<StartAgentTaskOutcome, AgentTaskRuntimeError> {
        let agent_task_id = agent_task_id.into();

        // 1. Validate BEFORE any write or connect.
        validate_params(&agent_task_id, &params)?;

        // 2. Durable Draft first; any task-store refusal returns before a daemon connect.
        let tasks = AgentTaskService::new(self.paths);
        tasks.create_draft(&agent_task_id, project_id, goal, params.now_ms)?;

        // 3.+4. Start with the forced FK, then mark Running only on live proof. On error the
        // task stays Draft: mark_running is never called on a failed start.
        self.start_session_then_mark_running(explicit_socket, env, &agent_task_id, params)
    }

    /// Resume/retry an EXISTING agent task on a brand-new session.
    ///
    /// Ordering: validate (`Agent` kind, matching/absent `params.agent_task_id`) -> LOAD the
    /// task (a missing task is a typed `Task(TaskNotFound)`; future-version/corrupt/store/id
    /// errors surface typed — all BEFORE any daemon connect or session record) -> start through
    /// [`ShellRuntime::start_session`] with `params.agent_task_id` forced to this task ->
    /// [`AgentTaskService::mark_running`] only after the live grid-proven session.
    ///
    /// The task record is NEVER mutated before the session is live: a validation, load,
    /// connect, daemon, or session failure leaves it record-equal to its pre-call state (any
    /// session-record behavior is exactly what `ShellRuntime`/`SessionService` already wrote).
    /// History/retry semantics come from `mark_running`: a different previous current session
    /// is pushed into `session_history` exactly once; the same session id is idempotent; a
    /// summary from an earlier terminal state is cleared.
    ///
    /// Secret-aware boundary: this takes fresh caller-supplied [`StartParams`] and never
    /// replays the task's stored `LaunchSpec` (see module docs).
    pub fn resume_agent_task(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        agent_task_id: &str,
        params: StartParams,
    ) -> Result<StartAgentTaskOutcome, AgentTaskRuntimeError> {
        // 1. Validate BEFORE any load, write, or connect.
        validate_params(agent_task_id, &params)?;

        // 2. The task must already exist and be readable; nothing is created implicitly and
        // nothing is mutated yet. Missing/future-version/corrupt all return BEFORE a connect.
        let tasks = AgentTaskService::new(self.paths);
        if tasks.load(agent_task_id)?.is_none() {
            return Err(AgentTaskRuntimeError::Task(
                AgentTaskServiceError::TaskNotFound {
                    agent_task_id: agent_task_id.to_string(),
                },
            ));
        }

        // 3.+4. Start with the forced FK, then mark Running only on live proof. On error the
        // task keeps its pre-call state: mark_running is never called on a failed start.
        self.start_session_then_mark_running(explicit_socket, env, agent_task_id, params)
    }

    /// Shared tail of both start paths: force the FK into `params`, start ONE session through
    /// an identically-configured [`ShellRuntime`] (connect -> endpoint -> `Unknown` record ->
    /// daemon -> `Live` on grid), and only then move the task to `Running` on that session.
    fn start_session_then_mark_running(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        agent_task_id: &str,
        mut params: StartParams,
    ) -> Result<StartAgentTaskOutcome, AgentTaskRuntimeError> {
        params.agent_task_id = Some(agent_task_id.to_string());
        let shell = {
            let rt = ShellRuntime::new(self.paths).with_connect_timeout(self.connect_timeout);
            if self.persist_endpoint {
                rt
            } else {
                rt.without_endpoint_persist()
            }
        };
        let started = shell.start_session(explicit_socket, env, &params)?;

        let task = AgentTaskService::new(self.paths).mark_running(
            agent_task_id,
            started.record.session_id.clone(),
            params.now_ms,
        )?;

        Ok(StartAgentTaskOutcome {
            socket_path: started.socket_path,
            task,
            session: started.record,
        })
    }
}

/// Shared input validation (run BEFORE any write, load, or connect): the session must be an
/// `Agent` session, and a caller-supplied `params.agent_task_id` must match the task argument.
fn validate_params(agent_task_id: &str, params: &StartParams) -> Result<(), AgentTaskRuntimeError> {
    if params.kind != SessionKind::Agent {
        return Err(AgentTaskRuntimeError::InvalidSessionKind { kind: params.kind });
    }
    if let Some(got) = &params.agent_task_id {
        if got != agent_task_id {
            return Err(AgentTaskRuntimeError::AgentTaskIdMismatch {
                expected: agent_task_id.to_string(),
                got: got.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_client::DaemonClientError;
    use crate::daemon_endpoint::{self, DaemonEndpoint, ENDPOINT_ID};
    use crate::paths::RecordKind;
    use crate::records::{AgentTaskState, LaunchSpec, SessionStatus};
    use crate::session_service::SessionServiceError;
    use crate::store::{self, LoadOutcome};
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::{UnixListener, UnixStream as StdUnixStream};
    use std::sync::mpsc;
    use std::thread::JoinHandle;
    use tempfile::TempDir;

    // ---- env stub ---------------------------------------------------------------------------

    struct MapEnv(HashMap<String, String>);
    impl MapEnv {
        fn empty() -> Self {
            MapEnv(HashMap::new())
        }
    }
    impl EnvLookup for MapEnv {
        fn get(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
    }

    // ---- loopback stub daemon (no real pty-daemon) — same style as shell_runtime tests ------

    struct StubDaemon {
        handle: Option<JoinHandle<()>>,
    }

    impl StubDaemon {
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

    fn accept_start_protocol(
        reader: &mut impl BufRead,
        stream: &mut StdUnixStream,
        tx: &mpsc::Sender<String>,
    ) {
        assert_eq!(
            read_request(reader, tx).as_deref(),
            Some(r#"{"op":"daemon_info"}"#)
        );
        writeln!(
            stream,
            "{{\"ev\":\"daemon_info\",\"protocol_version\":{},\"build_version\":\"test\"}}",
            maestro_protocol::DAEMON_PROTOCOL_VERSION
        )
        .unwrap();
        stream.flush().unwrap();
    }

    /// Answers StartSession+Attach with a grid (a successful start).
    fn serve_grid(
        id: &'static str,
        generation: &'static str,
    ) -> impl FnOnce(&mpsc::Sender<String>, &mut StdUnixStream) + Send + 'static {
        move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            accept_start_protocol(&mut reader, stream, tx);
            read_request(&mut reader, tx); // StartSession
            read_request(&mut reader, tx); // Attach
            stream
                .write_all(
                    format!(
                        r#"{{"ev":"grid","id":"{id}","grid":{{"generation":"{generation}","revision":1}}}}"#
                    )
                    .as_bytes(),
                )
                .unwrap();
            stream.write_all(b"\n").unwrap();
            stream.flush().unwrap();
        }
    }

    // ---- helpers ----------------------------------------------------------------------------

    fn paths_in(tmp: &TempDir) -> AppPaths {
        let paths = AppPaths::with_base(tmp.path().join("Maestro"));
        // Seed the FK parents every test relies on BEFORE any child is written: the agent_tasks
        // created here reference projects "proj-1"/"proj-0" (agent_tasks.project_id → projects),
        // and the sessions started here reference workspace "ws1" (sessions.workspace_id →
        // workspaces). Production always creates the project + workspace first.
        seed_project(&paths, "proj-1");
        seed_project(&paths, "proj-0");
        seed_workspace(&paths, "ws1", "proj-1");
        paths
    }

    /// Persist a minimal parent Project so an FK-bearing AgentTask can be written. Idempotent.
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

    fn agent_params(session_id: &str, cwd: &str) -> StartParams {
        StartParams {
            session_id: session_id.into(),
            workspace_id: "ws1".into(),
            kind: SessionKind::Agent,
            launch: LaunchSpec::KnownSafe {
                launch_spec_id: "ls-agent".into(),
                params: vec![],
            },
            cwd: cwd.into(),
            command: "agent".into(),
            args: vec![],
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

    fn task_on_disk(paths: &AppPaths, id: &str) -> Option<AgentTask> {
        match store::load_one::<AgentTask>(paths, RecordKind::AgentTask, id).unwrap() {
            None => None,
            Some(LoadOutcome::Loaded(t)) => Some(t),
            other => panic!("unexpected task load outcome: {other:?}"),
        }
    }

    fn session_on_disk(paths: &AppPaths, id: &str) -> Option<SessionRecord> {
        match store::load_one::<SessionRecord>(paths, RecordKind::Session, id).unwrap() {
            None => None,
            Some(LoadOutcome::Loaded(r)) => Some(r),
            other => panic!("unexpected session load outcome: {other:?}"),
        }
    }

    fn endpoint_on_disk(paths: &AppPaths) -> Option<DaemonEndpoint> {
        match store::load_one::<DaemonEndpoint>(paths, RecordKind::DaemonEndpoint, ENDPOINT_ID)
            .unwrap()
        {
            Some(LoadOutcome::Loaded(ep)) => Some(ep),
            _ => None,
        }
    }

    fn assert_nothing_written(paths: &AppPaths, task_id: &str, session_id: &str) {
        assert!(
            task_on_disk(paths, task_id).is_none(),
            "no task record may exist"
        );
        assert!(
            session_on_disk(paths, session_id).is_none(),
            "no session record may exist"
        );
        assert!(
            endpoint_on_disk(paths).is_none(),
            "no endpoint record may exist"
        );
    }

    // ---- tests ------------------------------------------------------------------------------

    /// The full successful path: durable Draft, session started as Agent with the task FK, task
    /// finishes Running on the live session with EMPTY history, endpoint persisted after connect
    /// (matching ShellRuntime).
    #[test]
    fn successful_start_moves_task_and_session_together() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), serve_grid("s1", "gen-1"));

        let rt = AgentTaskRuntime::new(&paths);
        let out = rt
            .start_new_agent_task(
                Some(sock_path.clone()),
                &MapEnv::empty(),
                "task-1",
                "proj-1",
                "ship it",
                agent_params("s1", &cwd_path),
            )
            .unwrap();

        assert_eq!(out.socket_path, sock_path);

        // Session: Live, Agent, carrying the task FK (params.agent_task_id was None — the
        // runtime forces the FK) in the returned outcome.
        assert_eq!(out.session.status, SessionStatus::Live);
        assert_eq!(out.session.kind, SessionKind::Agent);
        assert_eq!(out.session.agent_task_id.as_deref(), Some("task-1"));
        // The durable session matches the returned record exactly — INCLUDING the task FK. The task upsert is an
        // in-place ON CONFLICT DO UPDATE (not a DELETE+INSERT), so the step-4 mark_running no longer clears the
        // session's back-reference via ON DELETE SET NULL.
        assert_eq!(session_on_disk(&paths, "s1").unwrap(), out.session);

        // Task: Running on the session, fresh draft pushed NOTHING to history, summary None.
        assert_eq!(out.task.state, AgentTaskState::Running);
        assert_eq!(out.task.current_session_id.as_deref(), Some("s1"));
        assert!(out.task.session_history.is_empty());
        assert_eq!(out.task.result_summary, None);
        assert_eq!(out.task.project_id, "proj-1");
        assert_eq!(out.task.goal, "ship it");
        assert_eq!(task_on_disk(&paths, "task-1").unwrap(), out.task);

        // Endpoint persisted for the socket actually used (ShellRuntime behavior preserved).
        let ep = endpoint_on_disk(&paths).expect("endpoint persisted after connect");
        assert_eq!(ep.socket_path, sock_path.to_string_lossy());
        drop(stub);
        drop(sock_dir);
    }

    /// `params.kind == Shell` is a typed error BEFORE any side effect: no task, no session, no
    /// endpoint, no connect — proved by pointing at a MISSING socket and still not getting a
    /// daemon error.
    #[test]
    fn shell_kind_is_rejected_before_any_side_effect() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let missing = tmp.path().join("nope.sock");

        let mut params = agent_params("s1", "/tmp");
        params.kind = SessionKind::Shell;

        let rt = AgentTaskRuntime::new(&paths);
        let err = rt
            .start_new_agent_task(
                Some(missing),
                &MapEnv::empty(),
                "task-1",
                "proj-1",
                "goal",
                params,
            )
            .unwrap_err();
        assert!(
            matches!(
                err,
                AgentTaskRuntimeError::InvalidSessionKind {
                    kind: SessionKind::Shell
                }
            ),
            "expected InvalidSessionKind, got {err:?}"
        );
        assert_nothing_written(&paths, "task-1", "s1");
    }

    /// A mismatched `params.agent_task_id` is a typed error before any side effect.
    #[test]
    fn mismatched_agent_task_id_is_rejected_before_any_side_effect() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let missing = tmp.path().join("nope.sock");

        let mut params = agent_params("s1", "/tmp");
        params.agent_task_id = Some("task-OTHER".into());

        let rt = AgentTaskRuntime::new(&paths);
        let err = rt
            .start_new_agent_task(
                Some(missing),
                &MapEnv::empty(),
                "task-1",
                "proj-1",
                "goal",
                params,
            )
            .unwrap_err();
        match &err {
            AgentTaskRuntimeError::AgentTaskIdMismatch { expected, got } => {
                assert_eq!(expected, "task-1");
                assert_eq!(got, "task-OTHER");
            }
            other => panic!("expected AgentTaskIdMismatch, got {other:?}"),
        }
        assert_nothing_written(&paths, "task-1", "s1");
    }

    /// An existing task id is `TaskAlreadyExists` and never reaches the daemon (missing socket,
    /// yet the error is the task error) or writes a session/endpoint. The existing task record
    /// is untouched.
    #[test]
    fn existing_task_id_fails_without_connecting_or_writing_a_session() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let missing = tmp.path().join("nope.sock");

        let existing = AgentTaskService::new(&paths)
            .create_draft("task-1", "proj-0", "original goal", 5)
            .unwrap();

        let rt = AgentTaskRuntime::new(&paths);
        let err = rt
            .start_new_agent_task(
                Some(missing),
                &MapEnv::empty(),
                "task-1",
                "proj-1",
                "goal",
                agent_params("s1", "/tmp"),
            )
            .unwrap_err();
        assert!(
            matches!(
                &err,
                AgentTaskRuntimeError::Task(AgentTaskServiceError::TaskAlreadyExists {
                    agent_task_id
                }) if agent_task_id == "task-1"
            ),
            "expected Task(TaskAlreadyExists), got {err:?}"
        );

        // Existing draft untouched; nothing else written.
        assert_eq!(task_on_disk(&paths, "task-1").unwrap(), existing);
        assert!(session_on_disk(&paths, "s1").is_none());
        assert!(endpoint_on_disk(&paths).is_none());
    }

    /// A connect failure AFTER the draft leaves the task `Draft` and writes no session record
    /// and no endpoint (ShellRuntime invariant). mark_running was never called.
    #[test]
    fn connect_failure_after_draft_leaves_the_task_draft() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let missing = tmp.path().join("nope.sock");

        let rt = AgentTaskRuntime::new(&paths);
        let err = rt
            .start_new_agent_task(
                Some(missing),
                &MapEnv::empty(),
                "task-1",
                "proj-1",
                "goal",
                agent_params("s1", "/tmp"),
            )
            .unwrap_err();
        assert!(
            matches!(
                err,
                AgentTaskRuntimeError::Shell(ShellRuntimeError::Daemon(
                    DaemonClientError::DaemonUnavailable { .. }
                ))
            ),
            "expected Shell(Daemon(DaemonUnavailable)), got {err:?}"
        );

        let task = task_on_disk(&paths, "task-1").expect("draft persists");
        assert_eq!(task.state, AgentTaskState::Draft);
        assert_eq!(task.current_session_id, None);
        assert!(task.session_history.is_empty());
        assert!(session_on_disk(&paths, "s1").is_none());
        assert!(endpoint_on_disk(&paths).is_none());
    }

    /// A daemon `Error` reply after connect preserves the SessionService behavior (record
    /// written `Unknown`, endpoint persisted because the daemon was reachable) and the task
    /// stays `Draft`.
    #[test]
    fn daemon_error_after_draft_preserves_session_semantics_and_leaves_task_draft() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            accept_start_protocol(&mut reader, stream, tx);
            read_request(&mut reader, tx); // StartSession
            read_request(&mut reader, tx); // Attach
            stream
                .write_all(b"{\"ev\":\"error\",\"message\":\"nope\"}\n")
                .unwrap();
            stream.flush().unwrap();
        });

        let rt = AgentTaskRuntime::new(&paths);
        let err = rt
            .start_new_agent_task(
                Some(sock_path.clone()),
                &MapEnv::empty(),
                "task-1",
                "proj-1",
                "goal",
                agent_params("s1", &cwd_path),
            )
            .unwrap_err();
        assert!(
            matches!(
                err,
                AgentTaskRuntimeError::Shell(ShellRuntimeError::Session(
                    SessionServiceError::Daemon(DaemonClientError::DaemonError { .. })
                ))
            ),
            "expected Shell(Session(Daemon)), got {err:?}"
        );

        // SessionService behavior preserved: record exists, still Unknown, carrying the FK the
        // runtime forced before the start.
        let session = session_on_disk(&paths, "s1").expect("Unknown record persists");
        assert_eq!(session.status, SessionStatus::Unknown);
        assert_eq!(session.agent_task_id.as_deref(), Some("task-1"));

        // Task untouched since the draft.
        let task = task_on_disk(&paths, "task-1").unwrap();
        assert_eq!(task.state, AgentTaskState::Draft);
        assert_eq!(task.current_session_id, None);

        // Endpoint persisted — the connect genuinely succeeded.
        assert!(endpoint_on_disk(&paths).is_some());
        drop(stub);
        drop(sock_dir);
    }

    /// `without_endpoint_persist()` is forwarded to the inner ShellRuntime: a successful start
    /// writes NO endpoint record, while task and session still complete.
    #[test]
    fn without_endpoint_persist_is_respected() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), serve_grid("s1", "gen-2"));

        let rt = AgentTaskRuntime::new(&paths)
            .with_connect_timeout(Duration::from_secs(2))
            .without_endpoint_persist();
        let out = rt
            .start_new_agent_task(
                Some(sock_path.clone()),
                &MapEnv::empty(),
                "task-1",
                "proj-1",
                "goal",
                agent_params("s1", &cwd_path),
            )
            .unwrap();

        assert_eq!(out.session.status, SessionStatus::Live);
        assert_eq!(out.task.state, AgentTaskState::Running);
        assert!(
            endpoint_on_disk(&paths).is_none(),
            "endpoint must not be persisted when disabled"
        );
        drop(stub);
        drop(sock_dir);
    }

    /// `params.agent_task_id = Some(<same id>)` is accepted and produces the same FK.
    #[test]
    fn matching_agent_task_id_in_params_is_accepted() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), serve_grid("s1", "gen-3"));

        let mut params = agent_params("s1", &cwd_path);
        params.agent_task_id = Some("task-1".into());

        let rt = AgentTaskRuntime::new(&paths);
        let out = rt
            .start_new_agent_task(
                Some(sock_path.clone()),
                &MapEnv::empty(),
                "task-1",
                "proj-1",
                "goal",
                params,
            )
            .unwrap();
        assert_eq!(out.session.agent_task_id.as_deref(), Some("task-1"));
        assert_eq!(out.task.current_session_id.as_deref(), Some("s1"));
        drop(stub);
        drop(sock_dir);
    }

    /// The composition itself adds no scratch/worktree side effects (everything it writes is
    /// records), and a stored-endpoint resolution path also works without an explicit socket.
    #[test]
    fn stored_endpoint_resolution_works_and_no_scratch_or_worktree_appears() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), serve_grid("s1", "gen-4"));

        daemon_endpoint::store_endpoint(
            &paths,
            &DaemonEndpoint::new(sock_path.to_string_lossy().into_owned(), None, 1),
            1,
        )
        .unwrap();

        let rt = AgentTaskRuntime::new(&paths);
        let out = rt
            .start_new_agent_task(
                None,
                &MapEnv::empty(),
                "task-1",
                "proj-1",
                "goal",
                agent_params("s1", &cwd_path),
            )
            .unwrap();
        assert_eq!(out.socket_path, sock_path);
        assert!(!paths.scratch_base().exists(), "no scratch dir");
        assert!(!paths.worktree_base().exists(), "no worktree dir");
        drop(stub);
        drop(sock_dir);
    }

    // ---- resume_agent_task -----------------------------------------------------------------

    /// Resuming an existing `Draft` task starts a live agent session and marks the task
    /// `Running` on it — same outcome shape as a fresh start, but the task was NOT created by
    /// this call.
    #[test]
    fn resume_from_draft_starts_live_session_and_marks_running() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), serve_grid("s1", "gen-r1"));

        AgentTaskService::new(&paths)
            .create_draft("task-1", "proj-1", "resume me", 5)
            .unwrap();

        let rt = AgentTaskRuntime::new(&paths);
        let out = rt
            .resume_agent_task(
                Some(sock_path.clone()),
                &MapEnv::empty(),
                "task-1",
                agent_params("s1", &cwd_path),
            )
            .unwrap();

        assert_eq!(out.session.status, SessionStatus::Live);
        assert_eq!(out.session.kind, SessionKind::Agent);
        assert_eq!(out.session.agent_task_id.as_deref(), Some("task-1"));
        assert_eq!(out.task.state, AgentTaskState::Running);
        assert_eq!(out.task.current_session_id.as_deref(), Some("s1"));
        assert!(
            out.task.session_history.is_empty(),
            "a Draft had no previous session to push"
        );
        // The draft's identity fields survived (resume never recreates the task).
        assert_eq!(out.task.project_id, "proj-1");
        assert_eq!(out.task.goal, "resume me");
        assert_eq!(out.task.created_at_ms, 5);
        assert_eq!(task_on_disk(&paths, "task-1").unwrap(), out.task);
        // Durable session equals the returned record exactly, FK included (the task upsert is an in-place
        // ON CONFLICT DO UPDATE, so mark_running no longer clears the session's back-reference).
        assert_eq!(session_on_disk(&paths, "s1").unwrap(), out.session);
        drop(stub);
        drop(sock_dir);
    }

    /// A retry from a TERMINAL state: `mark_running` clears the old summary, sets the new
    /// current session, and pushes the previous current session into history exactly once.
    #[test]
    fn resume_retry_from_failed_clears_summary_and_pushes_previous_session_once() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), serve_grid("s2", "gen-r2"));

        let tasks = AgentTaskService::new(&paths);
        tasks.create_draft("task-1", "proj-1", "goal", 5).unwrap();
        tasks.mark_running("task-1", "s-old", 6).unwrap();
        tasks
            .mark_failed("task-1", Some("it broke".into()), 7)
            .unwrap();

        let rt = AgentTaskRuntime::new(&paths);
        let out = rt
            .resume_agent_task(
                Some(sock_path.clone()),
                &MapEnv::empty(),
                "task-1",
                agent_params("s2", &cwd_path),
            )
            .unwrap();

        assert_eq!(out.task.state, AgentTaskState::Running);
        assert_eq!(out.task.current_session_id.as_deref(), Some("s2"));
        assert_eq!(out.task.session_history, vec!["s-old".to_string()]);
        assert_eq!(out.task.result_summary, None, "terminal summary cleared");
        assert_eq!(out.session.agent_task_id.as_deref(), Some("task-1"));
        assert_eq!(out.session.status, SessionStatus::Live);
        drop(stub);
        drop(sock_dir);
    }

    /// Resuming onto the SAME current session id is idempotent for history (mark_running
    /// semantics): nothing is pushed and nothing is duplicated.
    #[test]
    fn resume_with_the_same_current_session_is_idempotent_for_history() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), serve_grid("s1", "gen-r3"));

        let tasks = AgentTaskService::new(&paths);
        tasks.create_draft("task-1", "proj-1", "goal", 5).unwrap();
        tasks.mark_running("task-1", "s1", 6).unwrap();

        let rt = AgentTaskRuntime::new(&paths);
        let out = rt
            .resume_agent_task(
                Some(sock_path.clone()),
                &MapEnv::empty(),
                "task-1",
                agent_params("s1", &cwd_path),
            )
            .unwrap();

        assert_eq!(out.task.current_session_id.as_deref(), Some("s1"));
        assert!(
            out.task.session_history.is_empty(),
            "same session id must not be pushed into history"
        );
        drop(stub);
        drop(sock_dir);
    }

    /// `params.kind == Shell` on resume fails BEFORE any task mutation, connect, or session
    /// record — the pre-existing task stays record-equal.
    #[test]
    fn resume_shell_kind_is_rejected_before_task_mutation_or_connect() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let missing = tmp.path().join("nope.sock");

        let before = AgentTaskService::new(&paths)
            .create_draft("task-1", "proj-1", "goal", 5)
            .unwrap();

        let mut params = agent_params("s1", "/tmp");
        params.kind = SessionKind::Shell;

        let rt = AgentTaskRuntime::new(&paths);
        let err = rt
            .resume_agent_task(Some(missing), &MapEnv::empty(), "task-1", params)
            .unwrap_err();
        assert!(
            matches!(
                err,
                AgentTaskRuntimeError::InvalidSessionKind {
                    kind: SessionKind::Shell
                }
            ),
            "expected InvalidSessionKind, got {err:?}"
        );
        assert_eq!(task_on_disk(&paths, "task-1").unwrap(), before);
        assert!(session_on_disk(&paths, "s1").is_none());
        assert!(endpoint_on_disk(&paths).is_none());
    }

    /// A mismatched `params.agent_task_id` on resume fails before any side effect.
    #[test]
    fn resume_mismatched_agent_task_id_is_rejected_before_side_effects() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let missing = tmp.path().join("nope.sock");

        let before = AgentTaskService::new(&paths)
            .create_draft("task-1", "proj-1", "goal", 5)
            .unwrap();

        let mut params = agent_params("s1", "/tmp");
        params.agent_task_id = Some("task-OTHER".into());

        let rt = AgentTaskRuntime::new(&paths);
        let err = rt
            .resume_agent_task(Some(missing), &MapEnv::empty(), "task-1", params)
            .unwrap_err();
        match &err {
            AgentTaskRuntimeError::AgentTaskIdMismatch { expected, got } => {
                assert_eq!(expected, "task-1");
                assert_eq!(got, "task-OTHER");
            }
            other => panic!("expected AgentTaskIdMismatch, got {other:?}"),
        }
        assert_eq!(task_on_disk(&paths, "task-1").unwrap(), before);
        assert!(session_on_disk(&paths, "s1").is_none());
        assert!(endpoint_on_disk(&paths).is_none());
    }

    /// A missing task is `Task(TaskNotFound)` BEFORE any daemon connect (missing socket, yet
    /// the error is the task error) and never creates a task, session, or endpoint.
    #[test]
    fn resume_missing_task_is_task_not_found_before_connect() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let missing = tmp.path().join("nope.sock");

        let rt = AgentTaskRuntime::new(&paths);
        let err = rt
            .resume_agent_task(
                Some(missing),
                &MapEnv::empty(),
                "task-ghost",
                agent_params("s1", "/tmp"),
            )
            .unwrap_err();
        assert!(
            matches!(
                &err,
                AgentTaskRuntimeError::Task(AgentTaskServiceError::TaskNotFound {
                    agent_task_id
                }) if agent_task_id == "task-ghost"
            ),
            "expected Task(TaskNotFound), got {err:?}"
        );
        assert_nothing_written(&paths, "task-ghost", "s1");
    }

    // The file-era `resume_future_version_task_prevents_connect_and_is_not_rewritten` test
    // hand-wrote a raw schema_version=9999 envelope FILE to force a per-record `FutureVersion` on
    // the resume load path. That mechanism is gone: future-version is now a DB-LEVEL guard (the
    // whole DB is refused on open — see store.rs::future_version_db_is_refused_on_open), so a
    // single future task record can no longer be forged through the store. The "resume refuses
    // before connect / never rewrites" invariant is still covered by the shell-kind, mismatched-id,
    // missing-task, and connect-failure resume tests below.

    /// A connect failure on resume leaves the existing task record-equal to its pre-call state
    /// — including a non-trivial state (Running on an old session) — and writes no session and
    /// no endpoint.
    #[test]
    fn resume_connect_failure_leaves_the_task_record_equal_and_writes_no_session() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let missing = tmp.path().join("nope.sock");

        let tasks = AgentTaskService::new(&paths);
        tasks.create_draft("task-1", "proj-1", "goal", 5).unwrap();
        let before = tasks.mark_running("task-1", "s-old", 6).unwrap();

        let rt = AgentTaskRuntime::new(&paths);
        let err = rt
            .resume_agent_task(
                Some(missing),
                &MapEnv::empty(),
                "task-1",
                agent_params("s2", "/tmp"),
            )
            .unwrap_err();
        assert!(
            matches!(
                err,
                AgentTaskRuntimeError::Shell(ShellRuntimeError::Daemon(
                    DaemonClientError::DaemonUnavailable { .. }
                ))
            ),
            "expected Shell(Daemon(DaemonUnavailable)), got {err:?}"
        );
        assert_eq!(
            task_on_disk(&paths, "task-1").unwrap(),
            before,
            "failed resume must not mutate the task"
        );
        assert!(session_on_disk(&paths, "s2").is_none());
        assert!(endpoint_on_disk(&paths).is_none());
    }

    /// A daemon `Error` reply after the session record is written preserves the
    /// `SessionService` behavior (`Unknown` record carrying the FK, endpoint persisted) while
    /// the task stays record-equal — no Failed/Blocked/Cancelled inference.
    #[test]
    fn resume_daemon_error_preserves_session_semantics_and_leaves_task_unchanged() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            accept_start_protocol(&mut reader, stream, tx);
            read_request(&mut reader, tx); // StartSession
            read_request(&mut reader, tx); // Attach
            stream
                .write_all(b"{\"ev\":\"error\",\"message\":\"nope\"}\n")
                .unwrap();
            stream.flush().unwrap();
        });

        let tasks = AgentTaskService::new(&paths);
        tasks.create_draft("task-1", "proj-1", "goal", 5).unwrap();
        tasks.mark_running("task-1", "s-old", 6).unwrap();
        let before = tasks
            .mark_failed("task-1", Some("old failure".into()), 7)
            .unwrap();

        let rt = AgentTaskRuntime::new(&paths);
        let err = rt
            .resume_agent_task(
                Some(sock_path.clone()),
                &MapEnv::empty(),
                "task-1",
                agent_params("s2", &cwd_path),
            )
            .unwrap_err();
        assert!(
            matches!(
                err,
                AgentTaskRuntimeError::Shell(ShellRuntimeError::Session(
                    SessionServiceError::Daemon(DaemonClientError::DaemonError { .. })
                ))
            ),
            "expected Shell(Session(Daemon)), got {err:?}"
        );

        // Session semantics preserved verbatim: Unknown record with the forced FK.
        let session = session_on_disk(&paths, "s2").expect("Unknown record persists");
        assert_eq!(session.status, SessionStatus::Unknown);
        assert_eq!(session.agent_task_id.as_deref(), Some("task-1"));
        // Task untouched: still Failed with its old summary and old current session.
        assert_eq!(task_on_disk(&paths, "task-1").unwrap(), before);
        // Endpoint persisted — the connect genuinely succeeded.
        assert!(endpoint_on_disk(&paths).is_some());
        drop(stub);
        drop(sock_dir);
    }

    /// `without_endpoint_persist()` is respected on the resume path too.
    #[test]
    fn resume_without_endpoint_persist_is_respected() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), serve_grid("s1", "gen-r4"));

        AgentTaskService::new(&paths)
            .create_draft("task-1", "proj-1", "goal", 5)
            .unwrap();

        let rt = AgentTaskRuntime::new(&paths).without_endpoint_persist();
        let out = rt
            .resume_agent_task(
                Some(sock_path.clone()),
                &MapEnv::empty(),
                "task-1",
                agent_params("s1", &cwd_path),
            )
            .unwrap();

        assert_eq!(out.session.status, SessionStatus::Live);
        assert_eq!(out.task.state, AgentTaskState::Running);
        assert!(
            endpoint_on_disk(&paths).is_none(),
            "endpoint must not be persisted when disabled"
        );
        drop(stub);
        drop(sock_dir);
    }
}
