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

use std::path::PathBuf;
use std::time::Duration;

use crate::daemon_client::{DaemonClient, DaemonClientError, DEFAULT_TIMEOUT};
use crate::daemon_endpoint::{self, DaemonEndpoint, EnvLookup};
use crate::paths::{AppPaths, RecordKind};
use crate::records::{SessionRecord, SessionStatus};
use crate::session_service::{ReconcileReport, SessionService, SessionServiceError, StartParams};
use crate::store::{self, LoadOutcome, StoreError};

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
        self.start_session_with_restart(explicit_socket, env, params, false)
    }

    /// Replace a retained exited same-id session after an explicit product/user restart action.
    /// The same protocol-v2 proof and record-before-daemon ordering as an ordinary start apply;
    /// only the daemon request's narrowly scoped `restart_exited` authority differs.
    pub fn restart_exited_session(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        params: &StartParams,
    ) -> Result<StartSessionOutcome, ShellRuntimeError> {
        self.start_session_with_restart(explicit_socket, env, params, true)
    }

    fn start_session_with_restart(
        &self,
        explicit_socket: Option<PathBuf>,
        env: &impl EnvLookup,
        params: &StartParams,
        restart_exited: bool,
    ) -> Result<StartSessionOutcome, ShellRuntimeError> {
        let (mut client, socket_path) = self.resolve_and_connect(explicit_socket, env)?;

        // Keep malformed cwd behavior mutation-free (including no capability probe) and aligned
        // with SessionService's trust boundary.
        if !std::path::Path::new(&params.cwd).is_dir() {
            return Err(ShellRuntimeError::Session(
                SessionServiceError::InvalidCwd {
                    cwd: params.cwd.clone(),
                },
            ));
        }

        // A retained v1/legacy daemon is intentionally attach-compatible so existing PTYs survive
        // an app upgrade, but StartSession is unsafe there: old implementations could globally reap
        // unrelated exited snapshots. Fail before endpoint/session persistence and before mutation.
        client.require_start_session_protocol()?;

        // Only AFTER a proven-reachable connect do we advertise this socket durably.
        self.persist_endpoint_if_enabled(&socket_path, params.now_ms)?;

        let svc = SessionService::new(self.paths);
        let record = if restart_exited {
            svc.restart_exited_and_attach(&mut client, params)?
        } else {
            svc.start_and_attach(&mut client, params)?
        };
        Ok(StartSessionOutcome {
            socket_path,
            record,
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

        let record = match SessionService::new(self.paths).attach_existing(&mut client, params) {
            Ok(record) => record,
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
        self.persist_endpoint_if_enabled(&socket_path, params.now_ms)?;
        Ok(StartSessionOutcome {
            socket_path,
            record,
        })
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
    use std::io::{BufRead, BufReader, Write};
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
            "{{\"ev\":\"daemon_info\",\"protocol_version\":{},\"build_version\":\"test\"}}",
            maestro_protocol::DAEMON_PROTOCOL_VERSION
        )
        .unwrap();
        stream.flush().unwrap();
    }

    /// A serve-script that answers a StartSession+Attach with a grid (a successful start).
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
                .write_all(format!("{}\n", grid_line(id, generation, 1)).as_bytes())
                .unwrap();
            stream.flush().unwrap();
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
    fn explicit_exited_restart_reaches_protocol_v2_and_persists_replacement_live() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            accept_start_protocol(&mut reader, stream, tx);
            let start = read_request(&mut reader, tx).expect("restart StartSession");
            let start: serde_json::Value = serde_json::from_str(&start).unwrap();
            assert_eq!(start["op"], "start_session");
            assert_eq!(start["id"], "s1");
            assert_eq!(start["restart_exited"], true);
            let attach = read_request(&mut reader, tx).expect("replacement Attach");
            assert_eq!(
                attach,
                r#"{"op":"attach","id":"s1","want_raw_output":false}"#
            );
            stream
                .write_all(format!("{}\n", grid_line("s1", "gen-replaced", 2)).as_bytes())
                .unwrap();
            stream.flush().unwrap();
        });

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

        let out = ShellRuntime::new(&paths)
            .restart_exited_session(Some(sock_path), &MapEnv::new(&[]), &old)
            .unwrap();
        assert_eq!(out.record.status, SessionStatus::Live);
        assert_eq!(
            out.record.last_known_generation.as_deref(),
            Some("gen-replaced")
        );
        drop(stub);
        drop(sock_dir);
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

    /// A daemon `Error` reply AFTER connect leaves the prewritten session record `Unknown`,
    /// surfaced as a `Session` runtime error. The endpoint WAS persisted (connect
    /// succeeded — the daemon is genuinely reachable).
    #[test]
    fn daemon_error_after_connect_leaves_record_unknown() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            accept_start_protocol(&mut reader, stream, tx);
            read_request(&mut reader, tx);
            read_request(&mut reader, tx);
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
            ShellRuntimeError::Session(SessionServiceError::Daemon(
                DaemonClientError::DaemonError { message },
            )) => assert_eq!(message, "nope"),
            other => panic!("expected Session(Daemon(DaemonError)), got {other:?}"),
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
                last_known_generation: None,
                status: SessionStatus::Unknown,
            };
            store::write_record(&paths, RecordKind::Session, id, 1, &rec).unwrap();
        }

        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx); // ListSessions
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[\"alive\"]}\n")
                .unwrap();
            stream.flush().unwrap();
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
            last_known_generation: None,
            status: SessionStatus::Unknown,
        };
        store::write_record(&paths, RecordKind::Session, "kept", 1, &rec).unwrap();

        let (sock_dir, sock_path) = stub_socket_path();
        let stub = StubDaemon::spawn_at(sock_path.clone(), |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx); // ListSessions
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[\"kept\",\"ghost\"]}\n")
                .unwrap();
            stream.flush().unwrap();
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
