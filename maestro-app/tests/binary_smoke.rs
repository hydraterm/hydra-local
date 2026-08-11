//! Binary-level smoke coverage for the `maestro-app` process wiring.
//!
//! These tests run under `cargo test -p maestro-app`. They invoke the real `maestro-app` binary
//! (resolved via `CARGO_BIN_EXE_maestro-app`) and assert its NON-GUI output and socket-cleanup
//! contracts: the help/bad-usage output contract, pre-serve failure, a successful headless launch,
//! the failure-after-spawn owned-socket cleanup regression, and reused-daemon safety.
//!
//! Daemon behavior is driven by a fake daemon that is PRIVATE TO THIS TEST BINARY — there is no
//! separate `fake-daemon` package binary, so a normal `cargo build --workspace --release` never
//! emits a `fake-daemon` artifact. The fake daemon server lives in this file and is reached by
//! RE-EXECING this very test binary in "fake daemon mode": each test first calls
//! [`maybe_run_fake_daemon`], which — when `MAESTRO_FAKE_DAEMON_SOCKET` is set in the environment —
//! binds that socket, serves one `DaemonInfo -> StartSession -> Attach -> Grid` exchange per
//! connection, and exits
//! WITHOUT running any test body. Tests hand `maestro-app` a tiny temp wrapper script (via
//! `--daemon <wrapper>`) that re-execs this test binary with that env var set, so the app spawns the
//! fake daemon through its normal `--daemon <path> <socket>` code path. Everything stays deterministic
//! and depends on neither a real `pty-daemon` nor any user-local paths or prebuilt release artifacts.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tempfile::TempDir;

const APP_BIN: &str = env!("CARGO_BIN_EXE_maestro-app");

/// Env var that switches THIS test binary into fake-daemon mode. Its value is the socket path to
/// bind. Set only by the wrapper script (and the reused-daemon test), never during normal test runs.
const FAKE_DAEMON_ENV: &str = "MAESTRO_FAKE_DAEMON_SOCKET";
/// Optional stable session id that switches the fake into a protocol-v1 attach-only fixture.
const FAKE_DAEMON_LEGACY_SESSION_ENV: &str = "MAESTRO_FAKE_DAEMON_LEGACY_SESSION";
/// Optional append-only request transcript for the protocol-v1 fixture.
const FAKE_DAEMON_REQUEST_LOG_ENV: &str = "MAESTRO_FAKE_DAEMON_REQUEST_LOG";
/// Opt into a modern fake whose session set survives across connections. Product-startup tests use
/// this to prove that the first open starts one stable session and the second open only reattaches.
const FAKE_DAEMON_STATEFUL_ENV: &str = "MAESTRO_FAKE_DAEMON_STATEFUL";
/// Optional marker file: while present, the stateful fixture omits retained ids from its
/// live-only ListSessions response but continues serving exact Attach requests for them.
const FAKE_DAEMON_OMIT_LIST_FILE_ENV: &str = "MAESTRO_FAKE_DAEMON_OMIT_LIST_FILE";

/// Optional env var: a file path the fake daemon writes its own PID to once bound. The agent-command
/// smokes use it to kill the daemon they intentionally KEEP alive on success, so a kept-daemon test
/// never leaks a process. Threaded through the wrapper script alongside the socket.
const FAKE_DAEMON_PIDFILE_ENV: &str = "MAESTRO_FAKE_DAEMON_PIDFILE";

// ============================================================================================
// Fake daemon (private to this test binary)
// ============================================================================================

/// If `MAESTRO_FAKE_DAEMON_SOCKET` is set, run the fake daemon on that socket and exit WITHOUT
/// running any test body. Called as the first statement of every test so that whichever test the
/// libtest harness happens to schedule first in a re-execed process becomes the daemon.
fn maybe_run_fake_daemon() {
    if let Some(socket) = std::env::var_os(FAKE_DAEMON_ENV) {
        run_fake_daemon(Path::new(&socket));
    }
}

/// Bind `socket`, then serve each accepted connection on its own thread: answer the read-only
/// protocol identity probe, read the `StartSession` and `Attach` request lines, and reply with one
/// lightweight `grid` event echoing the requested session id. No real terminal behavior — no
/// resize/scrollback/damage. Serving each connection independently lets an already-bound instance
/// be reused by a second `maestro-app` launch.
fn run_fake_daemon(socket: &Path) -> ! {
    let listener = UnixListener::bind(socket)
        .unwrap_or_else(|e| panic!("fake daemon could not bind {}: {e}", socket.display()));
    let legacy_session = std::env::var(FAKE_DAEMON_LEGACY_SESSION_ENV).ok();
    let request_log = std::env::var_os(FAKE_DAEMON_REQUEST_LOG_ENV).map(PathBuf::from);
    let stateful = std::env::var_os(FAKE_DAEMON_STATEFUL_ENV).is_some();
    let omit_list_file = std::env::var_os(FAKE_DAEMON_OMIT_LIST_FILE_ENV).map(PathBuf::from);
    let sessions = Arc::new(Mutex::new(HashSet::<String>::new()));

    // Once bound, record our PID if asked, so a test that keeps this daemon alive can kill it.
    if let Some(pidfile) = std::env::var_os(FAKE_DAEMON_PIDFILE_ENV) {
        let _ = std::fs::write(&pidfile, std::process::id().to_string());
    }

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let legacy_session = legacy_session.clone();
                let request_log = request_log.clone();
                let sessions = Arc::clone(&sessions);
                let omit_list_file = omit_list_file.clone();
                std::thread::spawn(move || match legacy_session {
                    Some(session_id) => {
                        serve_one_legacy(stream, &session_id, request_log.as_deref())
                    }
                    None if stateful => serve_one_stateful(
                        stream,
                        &sessions,
                        request_log.as_deref(),
                        omit_list_file.as_deref(),
                    ),
                    None => serve_one(stream),
                });
            }
            Err(_) => break,
        }
    }
    std::process::exit(0);
}

fn append_fake_request(path: Option<&Path>, request: &str) {
    let Some(path) = path else { return };
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{request}");
    }
}

/// Protocol-v1 fixture: identity reports v1; list/attach remain available; every mutation is
/// refused. It deliberately serves multiple connections so `ensure_daemon`, the v2 mutation probe,
/// and the attach-only fallback exercise the same retained process.
fn serve_one_legacy(mut stream: UnixStream, session_id: &str, request_log: Option<&Path>) {
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(stream) => stream,
        Err(_) => return,
    });
    while let Some(request) = read_line(&mut reader) {
        if request.is_empty() {
            continue;
        }
        append_fake_request(request_log, &request);
        if request.contains("daemon_info") {
            let _ = stream.write_all(
                b"{\"ev\":\"daemon_info\",\"protocol_version\":1,\"build_version\":\"legacy-fixture\"}\n",
            );
        } else if request.contains("list_sessions") {
            let ids = serde_json::to_string(&[session_id]).expect("encode legacy session id");
            let _ = writeln!(stream, "{{\"ev\":\"sessions\",\"ids\":{ids}}}");
        } else if request.contains("\"op\":\"attach\"") {
            let requested = extract_id(&request).unwrap_or_default();
            if requested == session_id {
                let _ = writeln!(
                    stream,
                    "{{\"ev\":\"grid\",\"id\":{},\"grid\":{{\"generation\":\"legacy-grid\",\"revision\":7}}}}",
                    serde_json::to_string(session_id).expect("encode grid id")
                );
            } else {
                let _ = stream.write_all(b"{\"ev\":\"error\",\"message\":\"not found\"}\n");
            }
        } else {
            let _ = stream.write_all(b"{\"ev\":\"error\",\"message\":\"mutation refused\"}\n");
        }
        let _ = stream.flush();
    }
}

/// Modern multi-connection fixture with one process-wide retained-session set. It implements only
/// the protocol surface product startup needs: identity, list, start, and attach/grid.
fn serve_one_stateful(
    mut stream: UnixStream,
    sessions: &Arc<Mutex<HashSet<String>>>,
    request_log: Option<&Path>,
    omit_list_file: Option<&Path>,
) {
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(stream) => stream,
        Err(_) => return,
    });
    while let Some(request) = read_line(&mut reader) {
        if request.is_empty() {
            continue;
        }
        append_fake_request(request_log, &request);
        if request.contains("daemon_info") {
            let _ = writeln!(
                stream,
                "{{\"ev\":\"daemon_info\",\"protocol_version\":{},\"build_version\":\"stateful-binary-smoke\"}}",
                maestro_protocol::DAEMON_PROTOCOL_VERSION
            );
        } else if request.contains("list_sessions") {
            let mut ids: Vec<String> = if omit_list_file.is_some_and(Path::exists) {
                Vec::new()
            } else {
                sessions
                    .lock()
                    .expect("session lock")
                    .iter()
                    .cloned()
                    .collect()
            };
            ids.sort();
            let ids = serde_json::to_string(&ids).expect("encode session ids");
            let _ = writeln!(stream, "{{\"ev\":\"sessions\",\"ids\":{ids}}}");
        } else if request.contains("start_session") {
            if let Some(id) = extract_id(&request) {
                sessions.lock().expect("session lock").insert(id);
            }
        } else if request.contains("\"op\":\"attach\"") {
            let id = extract_id(&request).unwrap_or_default();
            if sessions.lock().expect("session lock").contains(&id) {
                let encoded = serde_json::to_string(&id).expect("encode grid id");
                let _ = writeln!(
                    stream,
                    "{{\"ev\":\"grid\",\"id\":{encoded},\"grid\":{{\"generation\":\"stateful-grid\",\"revision\":1}}}}"
                );
            } else {
                let message = serde_json::to_string(&format!("no such session: {id}"))
                    .expect("encode missing-session error");
                let _ = writeln!(stream, "{{\"ev\":\"error\",\"message\":{message}}}");
            }
        }
        let _ = stream.flush();
    }
}

/// Serve ONE `maestro-app` connection: answer DaemonInfo, read StartSession + Attach, and reply with
/// a grid for the id.
///
/// A connection whose FIRST line is a `list_sessions` reconcile (attach-tab's reconcile, NOT the
/// StartSession launch handshake) is answered with an EMPTY live set `{"ev":"sessions","ids":[]}` and
/// closed. That lets a SPAWNED fake daemon drive attach-tab to its `tab_session_not_live` post-spawn
/// failure (so the owned-socket cleanup path is exercised), while launch/agent-start callers — which
/// send DaemonInfo before StartSession — fall through to the grid handshake unchanged.
fn serve_one(mut stream: UnixStream) {
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });

    // Line 1: DaemonInfo (mutation preflight), StartSession (legacy fixture tolerance), OR
    // list_sessions (attach-tab reconcile).
    let mut first = match read_line(&mut reader) {
        Some(line) => line,
        None => return,
    };
    if first.contains("daemon_info") {
        let info = format!(
            "{{\"ev\":\"daemon_info\",\"protocol_version\":{},\"build_version\":\"binary-smoke\"}}\n",
            maestro_protocol::DAEMON_PROTOCOL_VERSION
        );
        if stream.write_all(info.as_bytes()).is_err() || stream.flush().is_err() {
            return;
        }
        first = match read_line(&mut reader) {
            Some(line) => line,
            None => return,
        };
    }
    if first.contains("list_sessions") {
        let _ = stream.write_all(b"{\"ev\":\"sessions\",\"ids\":[]}\n");
        let _ = stream.flush();
        return;
    }
    // StartSession: extract its `id` so the grid echoes the requested session id.
    let id = extract_id(&first).unwrap_or_else(|| "unknown".to_string());

    // Line 2: Attach. Its content is tolerated; we only need the connection to stay open.
    let _ = read_line(&mut reader);

    let grid =
        format!(r#"{{"ev":"grid","id":"{id}","grid":{{"generation":"gen-fake","revision":1}}}}"#);
    let _ = stream.write_all(format!("{grid}\n").as_bytes());
    let _ = stream.flush();
}

fn read_line(reader: &mut impl BufRead) -> Option<String> {
    let mut line = String::new();
    match reader.read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_string()),
    }
}

/// Pull the `"id":"..."` value out of a request line without a full JSON parser (test-only).
fn extract_id(line: &str) -> Option<String> {
    let key = "\"id\":\"";
    let start = line.find(key)? + key.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Write an executable wrapper script that re-execs THIS test binary in fake-daemon mode. The app
/// spawns the daemon as `<wrapper> <socket-path>`, so the wrapper forwards `$1` (the socket path)
/// through `MAESTRO_FAKE_DAEMON_SOCKET`. Returns the wrapper path (kept alive by `dir`).
fn write_fake_daemon_wrapper(dir: &Path) -> PathBuf {
    write_fake_daemon_wrapper_with_pidfile(dir, None)
}

/// Like [`write_fake_daemon_wrapper`], but optionally also threads a pidfile env var through to the
/// fake daemon so a test that KEEPS the spawned daemon alive (the agent commands on success) can
/// kill it afterward and never leak the process.
fn write_fake_daemon_wrapper_with_pidfile(dir: &Path, pidfile: Option<&Path>) -> PathBuf {
    let test_bin = std::env::current_exe().expect("current test exe");
    let wrapper = dir.join("fake-daemon-wrapper.sh");
    let pid_env = match pidfile {
        Some(p) => format!(
            " {env}={val}",
            env = FAKE_DAEMON_PIDFILE_ENV,
            val = shell_quote(p)
        ),
        None => String::new(),
    };
    let script = format!(
        "#!/bin/sh\nexec env {env}=\"$1\"{pid_env} {bin}\n",
        env = FAKE_DAEMON_ENV,
        bin = shell_quote(&test_bin),
    );
    std::fs::write(&wrapper, script).expect("write wrapper script");
    let mut perms = std::fs::metadata(&wrapper)
        .expect("wrapper metadata")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&wrapper, perms).expect("chmod wrapper");
    wrapper
}

fn write_stateful_fake_daemon_wrapper(
    dir: &Path,
    pidfile: &Path,
    request_log: &Path,
    omit_list_file: &Path,
) -> PathBuf {
    let test_bin = std::env::current_exe().expect("current test exe");
    let wrapper = dir.join("stateful-fake-daemon-wrapper.sh");
    let script = format!(
        "#!/bin/sh\nexec env {socket_env}=\"$1\" {stateful_env}=1 {pid_env}={pidfile} {log_env}={request_log} {omit_env}={omit_list_file} {bin}\n",
        socket_env = FAKE_DAEMON_ENV,
        stateful_env = FAKE_DAEMON_STATEFUL_ENV,
        pid_env = FAKE_DAEMON_PIDFILE_ENV,
        pidfile = shell_quote(pidfile),
        log_env = FAKE_DAEMON_REQUEST_LOG_ENV,
        request_log = shell_quote(request_log),
        omit_env = FAKE_DAEMON_OMIT_LIST_FILE_ENV,
        omit_list_file = shell_quote(omit_list_file),
        bin = shell_quote(&test_bin),
    );
    std::fs::write(&wrapper, script).expect("write stateful wrapper script");
    let mut perms = std::fs::metadata(&wrapper)
        .expect("stateful wrapper metadata")
        .permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&wrapper, perms).expect("chmod stateful wrapper");
    wrapper
}

/// Minimal single-quote shell escaping for the test binary path (paths may contain spaces).
fn shell_quote(path: &Path) -> String {
    let s = path.to_string_lossy();
    format!("'{}'", s.replace('\'', "'\\''"))
}

// ============================================================================================
// Test workspace + helpers
// ============================================================================================

/// A private temp workspace: a unique socket path and a `--base` records dir, both inside one temp
/// dir that is removed on drop. Sockets live in a SHORT temp root to stay under the ~104-char
/// `sockaddr_un` path limit.
struct Workspace {
    dir: TempDir,
    socket: PathBuf,
    base: PathBuf,
}

impl Workspace {
    fn new() -> Workspace {
        let dir = TempDir::new().expect("temp dir");
        let socket = dir.path().join("d.sock");
        let base = dir.path().join("base");
        std::fs::create_dir_all(&base).expect("base dir");
        Workspace { dir, socket, base }
    }
}

// ---------------------------------------------------------------------------------------------
// FK-safe seeding helpers.
//
// The local store is SQLite with `foreign_keys=ON`, so a child record can only be written after
// its parent exists (project → workspace → agent_task → session → window/tabs). These helpers
// persist a parent chain into a `--base` records dir so a subsequently-written (or CLI-written)
// child does not trip a FOREIGN KEY constraint.
// ---------------------------------------------------------------------------------------------

/// The ad-hoc workspace id every `launch` session is persisted under (see `StartParams::adhoc`
/// call in `run_launch`). A `launch` with an empty base needs this workspace (and a parent
/// project) to exist before it writes its `SessionRecord`.
const ADHOC_WORKSPACE_ID: &str = "maestro-app-dev";
/// A parent project id used purely to satisfy the `workspaces.project_id`/`agent_tasks.project_id`
/// FK for the ad-hoc launch chain.
const ADHOC_PROJECT_ID: &str = "test-adhoc-project";

/// Persist a minimal `Project` so records that carry a `project_id` FK can be written. Idempotent.
fn seed_project(base: &Path, project_id: &str) {
    use maestro_shell::paths::AppPaths;
    let paths = AppPaths::with_base(base);
    maestro_shell::project::ProjectService::new(&paths)
        .create(
            project_id,
            project_id,
            "/",
            maestro_shell::project::NewProject::default(),
            1,
        )
        .ok();
}

/// Persist a minimal `Workspace` (creating its parent project first). Idempotent.
fn seed_workspace(base: &Path, workspace_id: &str, project_id: &str) {
    use maestro_shell::paths::{AppPaths, RecordKind};
    seed_project(base, project_id);
    let paths = AppPaths::with_base(base);
    let ws = maestro_shell::records::Workspace {
        workspace_id: workspace_id.into(),
        project_id: project_id.into(),
        root: "/".into(),
        policy: maestro_shell::policy::WorkspacePolicy::ScratchCwd,
        consent: Default::default(),
    };
    maestro_shell::store::write_record(&paths, RecordKind::Workspace, workspace_id, 1, &ws)
        .expect("seed workspace");
}

/// Seed the project → workspace chain the ad-hoc `launch` path needs before it persists a session.
fn seed_adhoc_launch_chain(base: &Path) {
    seed_workspace(base, ADHOC_WORKSPACE_ID, ADHOC_PROJECT_ID);
}

/// Assert a successful command emitted no UNEXPECTED stderr.
///
/// The `launch` path unconditionally writes ONE diagnostic line to stderr
/// (`hydra-dashboard launch react_chrome=... mode=... record_window=... product_startup=...
/// top_tab_bar=...`) — a
/// production log line, not an error. It predates the SQLite store and is unrelated to it. This
/// helper tolerates exactly that known diagnostic line (and blank lines) while still failing on any
/// other stderr output, preserving the "no error output on success" intent of the original
/// `stderr.is_empty()` checks.
fn assert_stderr_quiet(stderr: &[u8]) {
    let text = String::from_utf8_lossy(stderr);
    let unexpected: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter(|l| !l.starts_with("hydra-dashboard launch "))
        .collect();
    assert!(
        unexpected.is_empty(),
        "stderr should carry no unexpected output on success, got: {unexpected:?}"
    );
}

fn is_restart_recipe_canonicalization_diagnostic(line: &str) -> bool {
    line.strip_prefix("launch: canonicalized ")
        .and_then(|rest| rest.strip_suffix(" session restart recipe(s)"))
        .is_some_and(|count| !count.is_empty() && count.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Build a `maestro-app launch` command pointed at the fake-daemon wrapper, headless.
///
/// Seeds the ad-hoc launch workspace chain (project → `maestro-app-dev` workspace) so the launch's
/// persisted `SessionRecord` satisfies `sessions.workspace_id → workspaces` under the SQLite store's
/// `foreign_keys=ON`.
fn headless_launch(ws: &Workspace) -> Command {
    seed_adhoc_launch_chain(&ws.base);
    let wrapper = write_fake_daemon_wrapper(ws.dir.path());
    let mut cmd = Command::new(APP_BIN);
    cmd.arg("launch")
        .arg("--socket")
        .arg(&ws.socket)
        .arg("--base")
        .arg(&ws.base)
        .arg("--daemon")
        .arg(&wrapper)
        .arg("--no-run-renderer")
        .stdin(Stdio::null());
    cmd
}

/// True if a Unix-socket connection to `path` currently succeeds (a daemon is serving it).
fn can_connect(path: &Path) -> bool {
    UnixStream::connect(path).is_ok()
}

/// Block until `path` accepts connections, or panic after a bounded timeout (fail fast).
fn wait_until_connectable(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if can_connect(path) {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("socket {} never became connectable", path.display());
}

/// Parse exactly one JSON value from `bytes`, asserting it is a single complete value.
///
/// The `launch` path unconditionally writes ONE non-JSON diagnostic line to stderr
/// (`hydra-dashboard launch ...`, a production log line unrelated to the SQLite store) BEFORE its
/// structured result JSON. Strip that known diagnostic line if present so a launch-failure JSON on
/// stderr still parses as exactly one value; all other output must still be a single JSON value.
fn parse_single_json(bytes: &[u8]) -> serde_json::Value {
    let text = std::str::from_utf8(bytes).expect("output is utf-8");
    // Strip known non-JSON diagnostic lines the launch/bootstrap path writes to stderr (production log lines unrelated
    // to the structured result): the dashboard launch line + the create/split/seed debug traces.
    const DIAG_PREFIXES: &[&str] = &[
        "hydra-dashboard launch ",
        "seed:",
        "createProject:",
        "createWindow:",
        "split:",
    ];
    let stripped: String = text
        .lines()
        .filter(|l| !DIAG_PREFIXES.iter().any(|p| l.starts_with(p)))
        .collect::<Vec<_>>()
        .join("\n");
    let trimmed = stripped.trim();
    assert!(
        !trimmed.is_empty(),
        "expected one JSON value, got empty output"
    );
    // A single JSON value with no trailing tokens: `from_str` rejects trailing data.
    serde_json::from_str(trimmed)
        .unwrap_or_else(|e| panic!("expected exactly one JSON value, got {trimmed:?}: {e}"))
}

// ============================================================================================
// 1. Help path
// ============================================================================================

#[test]
fn help_exits_zero_with_usage_on_stdout_and_empty_stderr() {
    maybe_run_fake_daemon();
    let out = Command::new(APP_BIN)
        .arg("--help")
        .output()
        .expect("run maestro-app --help");

    assert_eq!(out.status.code(), Some(0), "help should exit 0");
    let stdout = String::from_utf8(out.stdout).expect("stdout utf-8");
    assert!(
        stdout.contains("maestro-app launch"),
        "stdout should contain usage, got: {stdout}"
    );
    assert!(out.stderr.is_empty(), "stderr should be empty for help");
}

// ============================================================================================
// 2. Bad usage path
// ============================================================================================

#[test]
fn bad_usage_exits_two_with_single_bad_usage_json_on_stderr() {
    maybe_run_fake_daemon();
    let out = Command::new(APP_BIN)
        .arg("--definitely-not-a-flag")
        .output()
        .expect("run maestro-app with bad flag");

    assert_eq!(out.status.code(), Some(2), "bad usage should exit 2");
    assert!(out.stdout.is_empty(), "stdout should be empty on bad usage");

    let value = parse_single_json(&out.stderr);
    assert_eq!(value["ok"], serde_json::json!(false));
    assert_eq!(value["error_kind"], serde_json::json!("bad_usage"));
}

// ============================================================================================
// 3. Pre-serve daemon failure path
// ============================================================================================

#[test]
fn unusable_daemon_binary_fails_before_serving_and_creates_no_socket() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    // An EXPLICIT `--daemon` path that EXISTS but is not an executable. `resolve_binary` accepts the
    // explicit path because it exists (so the test never silently falls back to the real workspace
    // `pty-daemon` next to the test exe), then the spawn/exec fails -> a structured failure before
    // any socket is bound. This deterministically exercises the pre-serve failure contract.
    let bogus = ws.dir.path().join("not-an-executable");
    std::fs::write(&bogus, b"this is not a binary\n").expect("write bogus daemon");

    let out = Command::new(APP_BIN)
        .arg("launch")
        .arg("--socket")
        .arg(&ws.socket)
        .arg("--base")
        .arg(&ws.base)
        .arg("--daemon")
        .arg(&bogus)
        .arg("--no-run-renderer")
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app with unusable daemon");

    assert_ne!(out.status.code(), Some(0), "unusable daemon should fail");
    assert!(out.stdout.is_empty(), "stdout should be empty on failure");

    let value = parse_single_json(&out.stderr);
    assert_eq!(value["ok"], serde_json::json!(false));

    assert!(
        !ws.socket.exists(),
        "no socket should be created on a pre-serve failure"
    );
}

// ============================================================================================
// 4. Successful headless launch path
// ============================================================================================

#[test]
fn headless_launch_succeeds_emits_success_json_and_removes_socket() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    let out = headless_launch(&ws).output().expect("run headless launch");

    assert_eq!(out.status.code(), Some(0), "headless launch should exit 0");
    assert_stderr_quiet(&out.stderr);

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["daemon_started"], serde_json::json!(true));
    assert_eq!(value["daemon_kept"], serde_json::json!(false));
    assert_eq!(value["renderer_started"], serde_json::json!(false));

    assert!(
        !ws.socket.exists(),
        "the app-spawned daemon's socket should be removed after exit"
    );
}

// ============================================================================================
// 4b. Successful headless launch with --log-dir captures daemon logs
// ============================================================================================

#[test]
fn headless_launch_with_log_dir_creates_daemon_log_files_and_reports_log_dir() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let log_dir = ws.dir.path().join("logs");

    let out = headless_launch(&ws)
        .arg("--log-dir")
        .arg(&log_dir)
        .output()
        .expect("run headless launch with --log-dir");

    assert_eq!(
        out.status.code(),
        Some(0),
        "headless launch with --log-dir should exit 0"
    );
    assert_stderr_quiet(&out.stderr);

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["daemon_started"], serde_json::json!(true));
    assert_eq!(
        value["log_dir"],
        serde_json::json!(log_dir.to_string_lossy()),
        "success JSON must report the supplied --log-dir path"
    );

    // The app spawned the daemon, so its stdout/stderr log files must have been created under the
    // log dir. (The fake daemon writes no content, so we only assert existence — not flaky.)
    assert!(
        log_dir.join("pty-daemon.stdout.log").exists(),
        "daemon stdout log file should be created under --log-dir"
    );
    assert!(
        log_dir.join("pty-daemon.stderr.log").exists(),
        "daemon stderr log file should be created under --log-dir"
    );

    // Socket cleanup behavior is unchanged by --log-dir.
    assert!(
        !ws.socket.exists(),
        "the app-spawned daemon's socket should still be removed after exit"
    );
}

// ============================================================================================
// 4c. Dashboard command (headless, read-only, no daemon)
// ============================================================================================

#[test]
fn dashboard_empty_base_emits_success_json_and_creates_no_socket() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    let out = Command::new(APP_BIN)
        .arg("dashboard")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app dashboard");

    assert_eq!(out.status.code(), Some(0), "dashboard should exit 0");
    assert!(out.stderr.is_empty(), "stderr should be empty on success");

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["command"], serde_json::json!("dashboard"));
    assert_eq!(
        value["base"],
        serde_json::json!(ws.base.to_string_lossy()),
        "dashboard must report the resolved --base"
    );
    // An empty base yields empty projection buckets.
    assert_eq!(value["snapshot"]["projects"], serde_json::json!([]));
    assert_eq!(
        value["snapshot"]["unassigned_windows"],
        serde_json::json!([])
    );
    // The default path runs no daemon reconcile.
    assert_eq!(
        value["session_reconcile"],
        serde_json::json!(false),
        "default dashboard must report session_reconcile:false"
    );
    assert_eq!(
        value["socket_path"],
        serde_json::Value::Null,
        "default dashboard must report null socket_path"
    );

    // The dashboard command connects to / spawns no daemon, so the workspace socket stays absent.
    assert!(
        !ws.socket.exists(),
        "dashboard must not create a daemon socket"
    );
    assert!(
        !can_connect(&ws.socket),
        "dashboard must not start a daemon"
    );
}

#[test]
fn settings_show_emits_effective_defaults_and_creates_no_socket() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    let out = Command::new(APP_BIN)
        .arg("settings")
        .arg("show")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings show");

    assert_eq!(out.status.code(), Some(0), "settings show should exit 0");
    assert!(out.stderr.is_empty(), "stderr should be empty on success");

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["source"], serde_json::json!("defaults"));
    assert_eq!(
        value["base_dir"],
        serde_json::json!(ws.base.to_string_lossy()),
        "settings show must echo the resolved --base"
    );

    assert_eq!(
        value["chrome"]["top_tab_bar_default"],
        serde_json::json!(true)
    );
    assert_eq!(
        value["chrome"]["dashboard_status_default"],
        serde_json::json!(true)
    );
    assert_eq!(
        value["chrome"]["dashboard_panel_default"],
        serde_json::json!(false)
    );
    assert_eq!(
        value["chrome"]["picker_overlay_default"],
        serde_json::json!(false)
    );

    assert_eq!(
        value["workspace"]["default_policy"],
        serde_json::json!("scratch_cwd")
    );
    assert_eq!(
        value["workspace"]["worktree_requires_consent"],
        serde_json::json!(true)
    );
    assert_eq!(
        value["workspace"]["repo_write_requires_consent"],
        serde_json::json!(true)
    );

    assert_eq!(
        value["safety"]["private_dev_socket_by_default"],
        serde_json::json!(true)
    );
    assert_eq!(
        value["safety"]["destructive_worktree_cleanup_requires_confirm"],
        serde_json::json!(true)
    );
    assert_eq!(
        value["safety"]["repo_write_requires_explicit_consent"],
        serde_json::json!(true)
    );

    assert_eq!(
        value["appearance"]["theme"],
        serde_json::json!("built_in_dark")
    );
    assert_eq!(value["appearance"]["font_size_px"], serde_json::json!(16));

    // The settings command connects to / spawns no daemon, so the workspace socket stays absent.
    assert!(
        !ws.socket.exists(),
        "settings show must not create a daemon socket"
    );
    assert!(
        !can_connect(&ws.socket),
        "settings show must not start a daemon"
    );
}

/// `command-palette --list --base <dir>` prints the deterministic action catalog as one JSON value,
/// exits 0, and — being strictly read-only — connects to no daemon and creates no socket or settings
/// file under the temp base.
#[test]
fn command_palette_list_emits_catalog_and_creates_no_side_effects() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    let out = Command::new(APP_BIN)
        .arg("command-palette")
        .arg("--list")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app command-palette --list");

    assert_eq!(out.status.code(), Some(0), "command-palette should exit 0");
    assert!(out.stderr.is_empty(), "stderr should be empty on success");

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["command"], serde_json::json!("command-palette"));
    assert_eq!(
        value["base"],
        serde_json::json!(ws.base.to_string_lossy()),
        "command-palette must echo the resolved --base"
    );

    let actions = value["actions"].as_array().expect("actions is an array");
    assert!(!actions.is_empty(), "catalog must not be empty");
    assert_eq!(
        value["action_count"]
            .as_u64()
            .expect("action_count is a number") as usize,
        actions.len(),
        "action_count must equal actions.len()"
    );

    let ids: Vec<&str> = actions
        .iter()
        .map(|a| a["id"].as_str().expect("action id is a string"))
        .collect();
    for required in [
        "command_palette.list",
        "settings.show_panel",
        "attach.settings_panel",
    ] {
        assert!(
            ids.contains(&required),
            "catalog missing required id {required}"
        );
    }
    // The first action is stable (deterministic order).
    assert_eq!(ids.first(), Some(&"command_palette.list"));

    // Unfiltered output carries NO query metadata (backward-additive only when --query is present).
    assert!(
        value.get("query").is_none(),
        "unfiltered output must not include query metadata"
    );
    assert!(
        value.get("query_terms").is_none(),
        "unfiltered output must not include query_terms metadata"
    );

    // Without --preview, the previewed metadata block must be absent (backward-additive only).
    assert!(
        value.get("preview").is_none(),
        "unpreviewed output must not include preview metadata"
    );

    // Strictly read-only: no daemon socket, no daemon, and no settings file written under the base.
    assert!(
        !ws.socket.exists(),
        "command-palette must not create a daemon socket"
    );
    assert!(
        !can_connect(&ws.socket),
        "command-palette must not start a daemon"
    );
    assert!(
        !ws.base.join("settings").exists(),
        "command-palette must not create a settings directory/file"
    );
}

/// `command-palette --list --query settings --base <dir>` filters the fixed catalog to the matching
/// actions, includes the normalized `query`/`query_terms` metadata, and — like the unfiltered form —
/// connects to no daemon and creates no socket or settings file under the temp base.
#[test]
fn command_palette_query_filters_catalog_and_creates_no_side_effects() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    let out = Command::new(APP_BIN)
        .arg("command-palette")
        .arg("--list")
        .arg("--query")
        .arg("settings")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app command-palette --list --query settings");

    assert_eq!(out.status.code(), Some(0), "command-palette should exit 0");
    assert!(out.stderr.is_empty(), "stderr should be empty on success");

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["command"], serde_json::json!("command-palette"));

    // Query metadata is present and normalized.
    assert_eq!(value["query"], serde_json::json!("settings"));
    assert_eq!(value["query_terms"], serde_json::json!(["settings"]));

    let actions = value["actions"].as_array().expect("actions is an array");
    assert!(
        !actions.is_empty(),
        "settings query must match some actions"
    );
    assert_eq!(
        value["action_count"]
            .as_u64()
            .expect("action_count is a number") as usize,
        actions.len(),
        "action_count must equal actions.len()"
    );

    let ids: Vec<&str> = actions
        .iter()
        .map(|a| a["id"].as_str().expect("action id is a string"))
        .collect();
    for required in [
        "settings.show",
        "settings.show_panel",
        "attach.settings_panel",
    ] {
        assert!(
            ids.contains(&required),
            "filtered catalog missing expected settings id {required}"
        );
    }
    // An unrelated action must NOT survive the settings filter.
    assert!(
        !ids.contains(&"worktree.list"),
        "filtered catalog must exclude non-matching actions"
    );

    // Strictly read-only: no daemon socket, no daemon, and no settings file written under the base.
    assert!(
        !ws.socket.exists(),
        "command-palette --query must not create a daemon socket"
    );
    assert!(
        !can_connect(&ws.socket),
        "command-palette --query must not start a daemon"
    );
    assert!(
        !ws.base.join("settings").exists(),
        "command-palette --query must not create a settings directory/file"
    );
}

/// `command-palette --list --query settings --preview --base <dir>` adds the compact, bounded
/// `preview` block (title, normalized query, row_count, rows) derived from the SAME filtered action
/// list — staying strictly read-only (no daemon, socket, or settings file under the temp base).
#[test]
fn command_palette_preview_emits_preview_rows_and_creates_no_side_effects() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    let out = Command::new(APP_BIN)
        .arg("command-palette")
        .arg("--list")
        .arg("--query")
        .arg("settings")
        .arg("--preview")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app command-palette --list --query settings --preview");

    assert_eq!(out.status.code(), Some(0), "command-palette should exit 0");
    assert!(out.stderr.is_empty(), "stderr should be empty on success");

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["command"], serde_json::json!("command-palette"));

    // Query metadata still present and normalized alongside the preview.
    assert_eq!(value["query"], serde_json::json!("settings"));

    let actions = value["actions"].as_array().expect("actions is an array");
    assert!(
        !actions.is_empty(),
        "settings query must match some actions"
    );

    // The preview block is present and mirrors the filtered action list.
    let preview = value
        .get("preview")
        .expect("previewed output must include preview metadata");
    assert_eq!(preview["title"], serde_json::json!("Command Palette"));
    assert_eq!(
        preview["query"],
        serde_json::json!("settings"),
        "preview.query mirrors the normalized --query"
    );

    let rows = preview["rows"]
        .as_array()
        .expect("preview.rows is an array");
    assert!(!rows.is_empty(), "preview must include rows for a match");
    assert_eq!(
        preview["row_count"]
            .as_u64()
            .expect("preview.row_count is a number") as usize,
        rows.len(),
        "preview.row_count must equal preview.rows.len()"
    );
    assert_eq!(
        rows.len(),
        actions.len(),
        "preview rows are derived one-to-one from the returned actions"
    );

    // Each row carries the display-ready fields.
    let first = &rows[0];
    for field in ["id", "label", "category", "summary", "command"] {
        assert!(
            first.get(field).and_then(|v| v.as_str()).is_some(),
            "preview row missing field {field}"
        );
    }

    // Strictly read-only: no daemon socket, no daemon, and no settings file written under the base.
    assert!(
        !ws.socket.exists(),
        "command-palette --preview must not create a daemon socket"
    );
    assert!(
        !can_connect(&ws.socket),
        "command-palette --preview must not start a daemon"
    );
    assert!(
        !ws.base.join("settings").exists(),
        "command-palette --preview must not create a settings directory/file"
    );
}

/// `command-palette --describe <action-id> --base <dir>` resolves exactly one catalog action by its
/// stable id and prints the action plus a NON-executing execution plan, staying strictly read-only
/// (no daemon, socket, or settings file under the temp base).
#[test]
fn command_palette_describe_emits_action_detail_and_creates_no_side_effects() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    let out = Command::new(APP_BIN)
        .arg("command-palette")
        .arg("--describe")
        .arg("attach.settings_panel")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app command-palette --describe attach.settings_panel");

    assert_eq!(out.status.code(), Some(0), "command-palette should exit 0");
    assert!(out.stderr.is_empty(), "stderr should be empty on success");

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["command"], serde_json::json!("command-palette"));
    assert_eq!(
        value["base"],
        serde_json::json!(ws.base.to_string_lossy()),
        "command-palette --describe must echo the resolved --base"
    );

    // The resolved action mirrors the catalog entry.
    let action = value.get("action").expect("describe output has action");
    assert_eq!(action["id"], serde_json::json!("attach.settings_panel"));
    assert_eq!(
        action["title"],
        serde_json::json!("Attach tab with settings panel")
    );

    // The execution plan is non-executing and placeholder-aware.
    let execution = value
        .get("execution")
        .expect("describe output has execution plan");
    assert_eq!(execution["execution_supported"], serde_json::json!(false));
    assert_eq!(execution["requires_context"], serde_json::json!(true));
    assert_eq!(execution["can_execute_now"], serde_json::json!(false));
    assert_eq!(
        execution["placeholders"],
        serde_json::json!(["<window-id>", "<tab-id>"])
    );
    assert_eq!(
        execution["command"],
        serde_json::json!("attach-tab --window-id <window-id> --tab-id <tab-id> --settings-panel")
    );
    assert!(
        execution["note"].as_str().is_some(),
        "execution plan carries a stable note"
    );

    // Describe is NOT a list/query/preview shape: those keys must be absent.
    for absent in ["actions", "action_count", "query", "query_terms", "preview"] {
        assert!(
            value.get(absent).is_none(),
            "describe output must not include list-mode key {absent}"
        );
    }

    // Strictly read-only: no daemon socket, no daemon, and no settings file written under the base.
    assert!(
        !ws.socket.exists(),
        "command-palette --describe must not create a daemon socket"
    );
    assert!(
        !can_connect(&ws.socket),
        "command-palette --describe must not start a daemon"
    );
    assert!(
        !ws.base.join("settings").exists(),
        "command-palette --describe must not create a settings directory/file"
    );
}

/// `command-palette --describe <unknown-id>` stamps a structured `command-palette` failure JSON on
/// stderr (stage `unknown_action`) and exits non-zero, while remaining side-effect-free.
#[test]
fn command_palette_describe_unknown_id_fails_and_creates_no_side_effects() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    let out = Command::new(APP_BIN)
        .arg("command-palette")
        .arg("--describe")
        .arg("no.such.action")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app command-palette --describe no.such.action");

    assert_eq!(
        out.status.code(),
        Some(1),
        "unknown action id should exit 1"
    );
    assert!(
        out.stdout.is_empty(),
        "no JSON should be printed to stdout on failure"
    );

    let value = parse_single_json(&out.stderr);
    assert_eq!(value["command"], serde_json::json!("command-palette"));
    assert_eq!(value["stage"], serde_json::json!("unknown_action"));
    assert!(
        value["message"]
            .as_str()
            .expect("failure message is a string")
            .contains("no.such.action"),
        "failure message names the unknown id"
    );

    assert!(
        !ws.socket.exists(),
        "failed describe must not create a daemon socket"
    );
    assert!(
        !ws.base.join("settings").exists(),
        "failed describe must not create a settings directory/file"
    );
}

/// `settings show --panel-lines --base <dir>` emits the compact `SettingsPanelLines` DTO (title,
/// summary, stable category lines), exits 0, and — like normal `settings show` — connects to no
/// daemon and writes no settings file.
#[test]
fn settings_show_panel_lines_emits_panel_dto_and_creates_no_socket() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    let out = Command::new(APP_BIN)
        .arg("settings")
        .arg("show")
        .arg("--panel-lines")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings show --panel-lines");

    assert_eq!(
        out.status.code(),
        Some(0),
        "settings show --panel-lines should exit 0"
    );
    assert!(out.stderr.is_empty(), "stderr should be empty on success");

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["title"], serde_json::json!("Settings"));
    assert!(
        value["summary"].as_str().unwrap().contains("theme="),
        "panel summary must describe appearance"
    );

    let lines = value["lines"].as_array().expect("panel lines array");
    assert_eq!(
        value["line_count"].as_u64().unwrap() as usize,
        lines.len(),
        "line_count must mirror lines length"
    );
    // The DTO must not carry the raw EffectiveSettings JSON shape.
    assert!(value.get("chrome").is_none());
    assert!(value.get("appearance").is_none());

    let joined: Vec<String> = lines
        .iter()
        .map(|l| l.as_str().unwrap().to_string())
        .collect();
    assert!(joined.iter().any(|l| l == "source: defaults"));
    assert!(joined.iter().any(|l| l == "theme: built_in_dark"));
    assert!(joined
        .iter()
        .any(|l| l == "shell.default_argv: (unset; $SHELL/sh fallback)"));
    // Every panel line is ASCII so it renders safely as a fixed row.
    for line in &joined {
        assert!(line.is_ascii(), "panel line must be ASCII: {line:?}");
    }

    // Backward-additive structured rows: present, one per line, old fields still here.
    let rows = value["rows"].as_array().expect("panel rows array");
    assert_eq!(rows.len(), lines.len(), "one row per visible line");
    let first = &rows[0];
    assert_eq!(first["id"], serde_json::json!("source"));
    assert_eq!(first["category"], serde_json::json!("source"));
    assert_eq!(first["editable"], serde_json::json!(false));
    assert!(
        first.get("setting_key").is_none(),
        "report-only row omits setting_key"
    );
    let theme_row = rows
        .iter()
        .find(|r| r["id"] == serde_json::json!("theme"))
        .expect("theme row present");
    assert_eq!(
        theme_row["setting_key"],
        serde_json::json!("appearance.theme")
    );
    assert_eq!(theme_row["editable"], serde_json::json!(true));

    let settings_file = ws.base.join("settings").join("settings.json");
    assert!(
        !settings_file.exists(),
        "settings show --panel-lines must not write a settings file"
    );
    assert!(
        !ws.socket.exists(),
        "settings show --panel-lines must not create a daemon socket"
    );
    assert!(
        !can_connect(&ws.socket),
        "settings show --panel-lines must not start a daemon"
    );
}

#[test]
fn settings_set_persists_and_show_merges_override() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    let set_out = Command::new(APP_BIN)
        .arg("settings")
        .arg("set")
        .arg("appearance.font_size_px")
        .arg("18")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings set");

    assert_eq!(
        set_out.status.code(),
        Some(0),
        "settings set should exit 0; stderr: {}",
        String::from_utf8_lossy(&set_out.stderr)
    );
    assert!(
        set_out.stderr.is_empty(),
        "stderr should be empty on success"
    );

    let set_value = parse_single_json(&set_out.stdout);
    assert_eq!(set_value["ok"], serde_json::json!(true));
    assert_eq!(set_value["command"], serde_json::json!("settings"));
    assert_eq!(set_value["action"], serde_json::json!("set"));
    assert_eq!(
        set_value["key"],
        serde_json::json!("appearance.font_size_px")
    );
    assert_eq!(set_value["value"], serde_json::json!(18));
    assert_eq!(set_value["changed"], serde_json::json!(true));
    assert_eq!(
        set_value["base_dir"],
        serde_json::json!(ws.base.to_string_lossy())
    );
    assert_eq!(
        set_value["settings"]["appearance"]["font_size_px"],
        serde_json::json!(18)
    );

    let settings_file = ws.base.join("settings").join("settings.json");
    assert!(
        settings_file.exists(),
        "settings set must persist settings.json"
    );

    let show_out = Command::new(APP_BIN)
        .arg("settings")
        .arg("show")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings show");

    assert_eq!(
        show_out.status.code(),
        Some(0),
        "settings show should exit 0"
    );
    let show_value = parse_single_json(&show_out.stdout);
    assert_eq!(
        show_value["appearance"]["font_size_px"],
        serde_json::json!(18),
        "settings show must merge the persisted override"
    );
    assert_eq!(
        show_value["source"],
        serde_json::json!("defaults+overrides"),
        "settings show must report overrides as the source"
    );

    assert!(
        !ws.socket.exists(),
        "settings set/show must not create a daemon socket"
    );
    assert!(
        !can_connect(&ws.socket),
        "settings set/show must not start a daemon"
    );
}

/// `settings set appearance.theme high_contrast_dark --base <dir>` exits 0 with the theme as a JSON
/// string value, a following `settings show` merges it as `defaults+overrides`, and neither command
/// touches a daemon socket.
#[test]
fn settings_set_theme_persists_and_show_merges_override() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    let set_out = Command::new(APP_BIN)
        .arg("settings")
        .arg("set")
        .arg("appearance.theme")
        .arg("high_contrast_dark")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings set appearance.theme");

    assert_eq!(
        set_out.status.code(),
        Some(0),
        "settings set theme should exit 0; stderr: {}",
        String::from_utf8_lossy(&set_out.stderr)
    );
    assert!(
        set_out.stderr.is_empty(),
        "stderr should be empty on success"
    );

    let set_value = parse_single_json(&set_out.stdout);
    assert_eq!(set_value["ok"], serde_json::json!(true));
    assert_eq!(set_value["key"], serde_json::json!("appearance.theme"));
    assert_eq!(set_value["value"], serde_json::json!("high_contrast_dark"));
    assert_eq!(set_value["changed"], serde_json::json!(true));
    assert_eq!(
        set_value["settings"]["appearance"]["theme"],
        serde_json::json!("high_contrast_dark")
    );
    // The unchanged font size carries the default.
    assert_eq!(
        set_value["settings"]["appearance"]["font_size_px"],
        serde_json::json!(16)
    );

    let show_out = Command::new(APP_BIN)
        .arg("settings")
        .arg("show")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings show");

    assert_eq!(
        show_out.status.code(),
        Some(0),
        "settings show should exit 0"
    );
    let show_value = parse_single_json(&show_out.stdout);
    assert_eq!(
        show_value["appearance"]["theme"],
        serde_json::json!("high_contrast_dark"),
        "settings show must merge the persisted theme override"
    );
    assert_eq!(
        show_value["source"],
        serde_json::json!("defaults+overrides"),
        "settings show must report overrides as the source"
    );

    assert!(
        !ws.socket.exists(),
        "settings set/show theme must not create a daemon socket"
    );
    assert!(
        !can_connect(&ws.socket),
        "settings set/show theme must not start a daemon"
    );
}

/// `settings set appearance.font_size_px 18` then `settings reset appearance.font_size_px` clears the
/// font override: the reset exits 0 with `action:"reset"` + `value:16`, and a following `settings
/// show` reports `appearance.font_size_px:16`. Reset touches no daemon socket.
#[test]
fn settings_reset_font_size_restores_default_and_show_reports_it() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    let set_out = Command::new(APP_BIN)
        .arg("settings")
        .arg("set")
        .arg("appearance.font_size_px")
        .arg("18")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings set");
    assert_eq!(set_out.status.code(), Some(0), "settings set should exit 0");

    let reset_out = Command::new(APP_BIN)
        .arg("settings")
        .arg("reset")
        .arg("appearance.font_size_px")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings reset");
    assert_eq!(
        reset_out.status.code(),
        Some(0),
        "settings reset should exit 0; stderr: {}",
        String::from_utf8_lossy(&reset_out.stderr)
    );
    assert!(
        reset_out.stderr.is_empty(),
        "stderr should be empty on success"
    );
    let reset_value = parse_single_json(&reset_out.stdout);
    assert_eq!(reset_value["ok"], serde_json::json!(true));
    assert_eq!(reset_value["command"], serde_json::json!("settings"));
    assert_eq!(reset_value["action"], serde_json::json!("reset"));
    assert_eq!(
        reset_value["key"],
        serde_json::json!("appearance.font_size_px")
    );
    assert_eq!(reset_value["value"], serde_json::json!(16));
    assert_eq!(reset_value["changed"], serde_json::json!(true));

    let show_out = Command::new(APP_BIN)
        .arg("settings")
        .arg("show")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings show");
    assert_eq!(
        show_out.status.code(),
        Some(0),
        "settings show should exit 0"
    );
    let show_value = parse_single_json(&show_out.stdout);
    assert_eq!(
        show_value["appearance"]["font_size_px"],
        serde_json::json!(16),
        "settings show must report the reset font size"
    );

    assert!(
        !ws.socket.exists(),
        "settings reset must not create a daemon socket"
    );
    assert!(
        !can_connect(&ws.socket),
        "settings reset must not start a daemon"
    );
}

/// `settings reset --all` after overrides across appearance/chrome/shell removes the settings file in
/// one step (`key:"*"`, `changed:true`), a following `settings show` reports built-in defaults across
/// every family, and a repeat `reset --all` on the now-absent file reports `changed:false`. Touches no
/// daemon socket.
#[test]
fn settings_reset_all_restores_defaults_and_show_reports_them() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    for args in [
        &["settings", "set", "appearance.font_size_px", "22"][..],
        &["settings", "set", "appearance.theme", "high_contrast_dark"][..],
        &["settings", "set", "chrome.top_tab_bar_default", "false"][..],
    ] {
        let out = Command::new(APP_BIN)
            .args(args)
            .arg("--base")
            .arg(&ws.base)
            .stdin(Stdio::null())
            .output()
            .expect("run maestro-app settings set");
        assert_eq!(out.status.code(), Some(0), "settings set should exit 0");
    }
    let settings_file = ws.base.join("settings").join("settings.json");
    assert!(settings_file.exists(), "overrides should persist a file");

    let reset_out = Command::new(APP_BIN)
        .arg("settings")
        .arg("reset")
        .arg("--all")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings reset --all");
    assert_eq!(
        reset_out.status.code(),
        Some(0),
        "settings reset --all should exit 0; stderr: {}",
        String::from_utf8_lossy(&reset_out.stderr)
    );
    assert!(
        reset_out.stderr.is_empty(),
        "stderr should be empty on success"
    );
    let reset_value = parse_single_json(&reset_out.stdout);
    assert_eq!(reset_value["ok"], serde_json::json!(true));
    assert_eq!(reset_value["command"], serde_json::json!("settings"));
    assert_eq!(reset_value["action"], serde_json::json!("reset"));
    assert_eq!(reset_value["key"], serde_json::json!("*"));
    assert_eq!(reset_value["changed"], serde_json::json!(true));
    assert!(
        !settings_file.exists(),
        "reset --all removes the settings file"
    );

    let show_out = Command::new(APP_BIN)
        .arg("settings")
        .arg("show")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings show");
    assert_eq!(
        show_out.status.code(),
        Some(0),
        "settings show should exit 0"
    );
    let show_value = parse_single_json(&show_out.stdout);
    assert_eq!(show_value["source"], serde_json::json!("defaults"));
    assert_eq!(
        show_value["appearance"]["font_size_px"],
        serde_json::json!(16)
    );
    assert_eq!(
        show_value["appearance"]["theme"],
        serde_json::json!("built_in_dark")
    );
    assert_eq!(
        show_value["chrome"]["top_tab_bar_default"],
        serde_json::json!(true)
    );

    // Repeat reset --all on the now-absent file is a no-op.
    let repeat_out = Command::new(APP_BIN)
        .arg("settings")
        .arg("reset")
        .arg("--all")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings reset --all (repeat)");
    assert_eq!(repeat_out.status.code(), Some(0));
    let repeat_value = parse_single_json(&repeat_out.stdout);
    assert_eq!(repeat_value["key"], serde_json::json!("*"));
    assert_eq!(repeat_value["changed"], serde_json::json!(false));

    assert!(
        !ws.socket.exists(),
        "settings reset --all must not create a daemon socket"
    );
    assert!(
        !can_connect(&ws.socket),
        "settings reset --all must not start a daemon"
    );
}

/// `settings set appearance.theme high_contrast_dark` then `settings reset appearance.theme` restores
/// the built-in theme: the reset exits 0 with `value:"built_in_dark"`, and a following `settings show`
/// reports `appearance.theme:"built_in_dark"`. Reset touches no daemon socket.
#[test]
fn settings_reset_theme_restores_default_and_show_reports_it() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    let set_out = Command::new(APP_BIN)
        .arg("settings")
        .arg("set")
        .arg("appearance.theme")
        .arg("high_contrast_dark")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings set appearance.theme");
    assert_eq!(set_out.status.code(), Some(0), "settings set should exit 0");

    let reset_out = Command::new(APP_BIN)
        .arg("settings")
        .arg("reset")
        .arg("appearance.theme")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings reset appearance.theme");
    assert_eq!(
        reset_out.status.code(),
        Some(0),
        "settings reset should exit 0; stderr: {}",
        String::from_utf8_lossy(&reset_out.stderr)
    );
    let reset_value = parse_single_json(&reset_out.stdout);
    assert_eq!(reset_value["action"], serde_json::json!("reset"));
    assert_eq!(reset_value["key"], serde_json::json!("appearance.theme"));
    assert_eq!(reset_value["value"], serde_json::json!("built_in_dark"));
    assert_eq!(reset_value["changed"], serde_json::json!(true));

    let show_out = Command::new(APP_BIN)
        .arg("settings")
        .arg("show")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings show");
    assert_eq!(
        show_out.status.code(),
        Some(0),
        "settings show should exit 0"
    );
    let show_value = parse_single_json(&show_out.stdout);
    assert_eq!(
        show_value["appearance"]["theme"],
        serde_json::json!("built_in_dark"),
        "settings show must report the reset theme"
    );

    assert!(
        !ws.socket.exists(),
        "settings reset must not create a daemon socket"
    );
    assert!(
        !can_connect(&ws.socket),
        "settings reset theme must not start a daemon"
    );
}

#[test]
fn dashboard_projects_records_written_through_store_helpers() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    // Write durable records through the real maestro-shell store helpers, exactly as the dashboard
    // service will load them. A Project + its Workspace + an AgentTask + a Session + a WindowLayout
    // whose tab points at the session, so the window associates under the project.
    use maestro_shell::paths::{AppPaths, RecordKind};
    use maestro_shell::policy::WorkspacePolicy;
    use maestro_shell::records::{
        AgentTask, AgentTaskState, Attention, AttentionSource, AttentionState, LaunchSpec, Project,
        SessionKind, SessionRecord, SessionStatus, TabRecord, WindowLayout, Workspace as WsRecord,
        WorkspaceConsent,
    };
    use maestro_shell::store;

    let paths = AppPaths::with_base(&ws.base);
    let project = Project {
        project_id: "p1".into(),
        name: "One".into(),
        root: "/repos/p1".into(),
        default_workspace_policy: WorkspacePolicy::ScratchCwd,
        created_at_ms: 1,
        last_active_at_ms: 100,
        icon: None,
        accent_color: None,
        launch_defaults: None,
        directories: Vec::new(),
        system: false,
        hidden: false,
        window_order: Vec::new(),
    };
    store::write_record(
        &paths,
        RecordKind::Project,
        &project.project_id,
        1,
        &project,
    )
    .expect("write project");
    let workspace = WsRecord {
        workspace_id: "ws-1".into(),
        project_id: "p1".into(),
        root: "/repos/p1".into(),
        policy: WorkspacePolicy::ScratchCwd,
        consent: WorkspaceConsent::default(),
    };
    store::write_record(
        &paths,
        RecordKind::Workspace,
        &workspace.workspace_id,
        1,
        &workspace,
    )
    .expect("write workspace");
    let task = AgentTask {
        agent_task_id: "t-1".into(),
        project_id: "p1".into(),
        goal: "goal".into(),
        state: AgentTaskState::Running,
        current_session_id: Some("s1".into()),
        session_history: vec![],
        created_at_ms: 1,
        updated_at_ms: 1,
        result_summary: None,
    };
    store::write_record(&paths, RecordKind::AgentTask, &task.agent_task_id, 1, &task)
        .expect("write task");
    let session = SessionRecord {
        session_id: "s1".into(),
        workspace_id: "ws-1".into(),
        kind: SessionKind::Agent,
        launch: LaunchSpec::KnownSafe {
            launch_spec_id: "ls-1".into(),
            params: vec![],
        },
        cwd_resolved: "/tmp".into(),
        agent_task_id: None,
        created_at_ms: 1,
        last_attached_at_ms: 1,
        last_known_generation: None,
        status: SessionStatus::Live,
    };
    store::write_record(
        &paths,
        RecordKind::Session,
        &session.session_id,
        1,
        &session,
    )
    .expect("write session");
    let window = WindowLayout {
        window_id: "w1".into(),
        name: None,
        tabs: vec![TabRecord {
            tab_id: "tab1".into(),
            session_id: "s1".into(),
            index: 0,
            title: "title".into(),
            pinned: false,
            attention: AttentionState {
                attention: Attention::None,
                unseen: false,
                since_ms: 1,
                source: AttentionSource::Process,
            },
            split_from: None,
            pane_rect: None,
            stashed_from: None,
            stashed: false,
        }],
    };
    store::write_record(
        &paths,
        RecordKind::WindowLayout,
        &window.window_id,
        1,
        &window,
    )
    .expect("write window");

    let out = Command::new(APP_BIN)
        .arg("dashboard")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app dashboard with records");

    assert_eq!(out.status.code(), Some(0), "dashboard should exit 0");
    assert!(out.stderr.is_empty(), "stderr should be empty on success");

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    let projects = value["snapshot"]["projects"]
        .as_array()
        .expect("projects array");
    assert_eq!(projects.len(), 1, "the written project must be projected");
    assert_eq!(projects[0]["project_id"], serde_json::json!("p1"));
    assert_eq!(
        projects[0]["workspaces"][0]["workspace_id"],
        serde_json::json!("ws-1")
    );
    assert_eq!(
        projects[0]["tasks"][0]["agent_task_id"],
        serde_json::json!("t-1")
    );
    assert_eq!(
        projects[0]["windows"][0]["window_id"],
        serde_json::json!("w1")
    );
    assert_eq!(
        projects[0]["windows"][0]["tabs"][0]["session_id"],
        serde_json::json!("s1")
    );

    assert!(
        !ws.socket.exists(),
        "dashboard must not create a daemon socket"
    );
}

#[test]
fn dashboard_unknown_flag_exits_two_with_bad_usage_json() {
    maybe_run_fake_daemon();
    let out = Command::new(APP_BIN)
        .arg("dashboard")
        .arg("--definitely-not-a-flag")
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app dashboard with bad flag");

    assert_eq!(
        out.status.code(),
        Some(2),
        "a bad dashboard flag should exit 2"
    );
    assert!(out.stdout.is_empty(), "stdout should be empty on bad usage");

    let value = parse_single_json(&out.stderr);
    assert_eq!(value["ok"], serde_json::json!(false));
    assert_eq!(value["command"], serde_json::json!("dashboard"));
    assert_eq!(value["error_kind"], serde_json::json!("bad_usage"));
}

#[test]
fn dashboard_socket_without_reconcile_exits_two_bad_usage() {
    maybe_run_fake_daemon();
    let out = Command::new(APP_BIN)
        .arg("dashboard")
        .arg("--socket")
        .arg("/run/does-not-matter.sock")
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app dashboard --socket without reconcile");

    assert_eq!(
        out.status.code(),
        Some(2),
        "--socket without --with-session-reconcile should exit 2"
    );
    assert!(out.stdout.is_empty(), "stdout should be empty on bad usage");

    let value = parse_single_json(&out.stderr);
    assert_eq!(value["ok"], serde_json::json!(false));
    assert_eq!(value["command"], serde_json::json!("dashboard"));
    assert_eq!(value["error_kind"], serde_json::json!("bad_usage"));
}

/// A loopback stub daemon for the dashboard reconcile wire: bind `socket`, accept ONE connection,
/// read the single request line (asserting it is `list_sessions`), then answer
/// `{"ev":"sessions","ids":[...]}`. Mirrors `ShellRuntime::reconcile_sessions`' handshake without a
/// real `pty-daemon`. The join handle carries back the request line so the test can assert it.
fn spawn_sessions_stub(socket: PathBuf, ids: Vec<String>) -> std::thread::JoinHandle<String> {
    let listener = UnixListener::bind(&socket).expect("bind sessions stub");
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept on sessions stub");
        let mut reader = BufReader::new(stream.try_clone().expect("clone stub stream"));
        let request = read_line(&mut reader).unwrap_or_default();
        let ids_json = serde_json::to_string(&ids).expect("encode ids");
        let resp = format!("{{\"ev\":\"sessions\",\"ids\":{ids_json}}}\n");
        stream
            .write_all(resp.as_bytes())
            .expect("write sessions reply");
        stream.flush().expect("flush sessions reply");
        request
    })
}

/// A PERSISTENT loopback stub daemon for the `attach-tab` reconcile wire. Unlike
/// [`spawn_sessions_stub`] (single-shot), this binds `socket` and serves connections in a loop until
/// the socket is removed (test teardown). It is needed because `attach-tab` first probes the socket
/// via `ensure_daemon` (a throwaway connection) and THEN opens a second connection for the
/// `list_sessions` reconcile — a single-accept stub would be consumed by the probe. Every connection
/// whose first line is `list_sessions` is answered with `{"ev":"sessions","ids":[...]}`; any other
/// first line (e.g. the connectivity probe, which sends nothing) is closed. The thread is detached
/// and exits when `accept` errors after the socket file is gone.
fn spawn_persistent_sessions_stub(socket: PathBuf, ids: Vec<String>) {
    let listener = UnixListener::bind(&socket).expect("bind persistent sessions stub");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => break,
            };
            let reader = match stream.try_clone() {
                Ok(s) => s,
                Err(_) => continue,
            };
            let mut reader = BufReader::new(reader);
            let request = read_line(&mut reader).unwrap_or_default();
            if request.contains("list_sessions") {
                let ids_json = serde_json::to_string(&ids).expect("encode ids");
                let resp = format!("{{\"ev\":\"sessions\",\"ids\":{ids_json}}}\n");
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
            // Other connections (the connectivity probe) just drop.
        }
    });
}

/// Write a `SessionRecord` plus a one-tab `WindowLayout` pointing at it, so the session projects
/// into a window tab and its reconciled status is visible in the dashboard JSON.
fn write_session_with_window(base: &Path, session_id: &str, window_id: &str, tab_id: &str) {
    use maestro_shell::paths::{AppPaths, RecordKind};
    use maestro_shell::records::{
        Attention, AttentionSource, AttentionState, LaunchSpec, SessionKind, SessionRecord,
        SessionStatus, TabRecord, WindowLayout,
    };
    use maestro_shell::store;

    // sessions.workspace_id → workspaces (→ projects): seed the parent chain first.
    seed_workspace(base, "ws-1", "p-1");

    let paths = AppPaths::with_base(base);
    let session = SessionRecord {
        session_id: session_id.into(),
        workspace_id: "ws-1".into(),
        kind: SessionKind::Agent,
        launch: LaunchSpec::KnownSafe {
            launch_spec_id: "ls-1".into(),
            params: vec![],
        },
        cwd_resolved: "/tmp".into(),
        agent_task_id: None,
        created_at_ms: 1,
        last_attached_at_ms: 1,
        last_known_generation: None,
        status: SessionStatus::Unknown,
    };
    store::write_record(&paths, RecordKind::Session, session_id, 1, &session)
        .expect("write session");
    let window = WindowLayout {
        window_id: window_id.into(),
        name: None,
        tabs: vec![TabRecord {
            tab_id: tab_id.into(),
            session_id: session_id.into(),
            index: 0,
            title: "title".into(),
            pinned: false,
            attention: AttentionState {
                attention: Attention::None,
                unseen: false,
                since_ms: 1,
                source: AttentionSource::Process,
            },
            split_from: None,
            pane_rect: None,
            stashed_from: None,
            stashed: false,
        }],
    };
    store::write_record(&paths, RecordKind::WindowLayout, window_id, 1, &window)
        .expect("write window");
}

/// Write a live session plus a TWO-tab window: tab `t1` (index 0, session `s-live`, plain) and a
/// second tab `t2` (index 1, session `s-other`, persisted attention `activity` + `unseen`). Tabs are
/// written out of index order so the strip's index-sort is exercised. Used to prove `attach-tab`
/// surfaces the FULL window (not just the selected tab) and persisted `needs_attention`.
fn write_two_tab_window_with_attention(base: &Path) {
    use maestro_shell::paths::{AppPaths, RecordKind};
    use maestro_shell::records::{
        Attention, AttentionSource, AttentionState, LaunchSpec, SessionKind, SessionRecord,
        SessionStatus, TabRecord, WindowLayout,
    };
    use maestro_shell::store;

    // sessions.workspace_id → workspaces (→ projects): seed the parent chain first.
    seed_workspace(base, "ws-1", "p-1");

    let paths = AppPaths::with_base(base);
    let mk_session = |id: &str| SessionRecord {
        session_id: id.into(),
        workspace_id: "ws-1".into(),
        kind: SessionKind::Agent,
        launch: LaunchSpec::KnownSafe {
            launch_spec_id: "ls-1".into(),
            params: vec![],
        },
        cwd_resolved: "/tmp".into(),
        agent_task_id: None,
        created_at_ms: 1,
        last_attached_at_ms: 1,
        last_known_generation: None,
        status: SessionStatus::Unknown,
    };
    for id in ["s-live", "s-other"] {
        store::write_record(&paths, RecordKind::Session, id, 1, &mk_session(id))
            .expect("write session");
    }
    let window = WindowLayout {
        window_id: "w1".into(),
        name: None,
        // Written index-1-then-index-0 so the strip must sort by persisted index.
        tabs: vec![
            TabRecord {
                tab_id: "t2".into(),
                session_id: "s-other".into(),
                index: 1,
                title: "second".into(),
                pinned: true,
                attention: AttentionState {
                    attention: Attention::Activity,
                    unseen: true,
                    since_ms: 1,
                    source: AttentionSource::Process,
                },
                split_from: None,
                pane_rect: None,
                stashed_from: None,
                stashed: false,
            },
            TabRecord {
                tab_id: "t1".into(),
                session_id: "s-live".into(),
                index: 0,
                title: "first".into(),
                pinned: false,
                attention: AttentionState {
                    attention: Attention::None,
                    unseen: false,
                    since_ms: 1,
                    source: AttentionSource::Process,
                },
                split_from: None,
                pane_rect: None,
                stashed_from: None,
                stashed: false,
            },
        ],
    };
    store::write_record(&paths, RecordKind::WindowLayout, "w1", 1, &window).expect("write window");
}

/// Collect every projected tab `(session_id -> session_status)` across projects and unassigned
/// windows in a dashboard success JSON, for status assertions.
fn tab_statuses(value: &serde_json::Value) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let mut visit = |windows: &serde_json::Value| {
        if let Some(arr) = windows.as_array() {
            for w in arr {
                if let Some(tabs) = w["tabs"].as_array() {
                    for t in tabs {
                        if let (Some(sid), Some(status)) =
                            (t["session_id"].as_str(), t["session_status"].as_str())
                        {
                            out.insert(sid.to_string(), status.to_string());
                        }
                    }
                }
            }
        }
    };
    if let Some(projects) = value["snapshot"]["projects"].as_array() {
        for p in projects {
            visit(&p["windows"]);
        }
    }
    visit(&value["snapshot"]["unassigned_windows"]);
    out
}

/// The opt-in reconcile path against a loopback stub daemon: the app must send `list_sessions`,
/// report `session_reconcile:true` and the `socket_path`, project a recorded id the daemon reports
/// live as `live`, a recorded id the daemon omits as `exited`, and surface an unrecorded live id in
/// `recovered_sessions`.
#[test]
fn dashboard_with_reconcile_projects_live_exited_and_recovered() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    // s-live: recorded + reported live -> "live". s-dead: recorded + omitted -> "exited".
    write_session_with_window(&ws.base, "s-live", "w-live", "t-live");
    write_session_with_window(&ws.base, "s-dead", "w-dead", "t-dead");
    // "ghost" is reported live but has no record -> recovered_sessions.
    let stub = spawn_sessions_stub(ws.socket.clone(), vec!["s-live".into(), "ghost".into()]);

    let out = Command::new(APP_BIN)
        .arg("dashboard")
        .arg("--with-session-reconcile")
        .arg("--socket")
        .arg(&ws.socket)
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app dashboard --with-session-reconcile");

    let request = stub.join().expect("sessions stub thread");
    assert!(
        request.contains("list_sessions"),
        "opt-in path must send ListSessions, got: {request}"
    );

    assert_eq!(
        out.status.code(),
        Some(0),
        "reconcile dashboard should exit 0"
    );
    assert!(out.stderr.is_empty(), "stderr should be empty on success");

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["session_reconcile"], serde_json::json!(true));
    assert_eq!(
        value["socket_path"],
        serde_json::json!(ws.socket.display().to_string())
    );

    let statuses = tab_statuses(&value);
    assert_eq!(statuses.get("s-live").map(String::as_str), Some("live"));
    assert_eq!(statuses.get("s-dead").map(String::as_str), Some("exited"));

    let recovered: Vec<&str> = value["snapshot"]["recovered_sessions"]
        .as_array()
        .expect("recovered_sessions array")
        .iter()
        .filter_map(|r| r["session_id"].as_str())
        .collect();
    assert!(
        recovered.contains(&"ghost"),
        "unrecorded live id must surface in recovered_sessions, got: {recovered:?}"
    );
}

/// Opt-in reconcile against a socket no daemon is serving: connect fails, so the command emits one
/// `dashboard_reconcile_failed` JSON on stderr, exits non-zero, and never creates the socket.
#[test]
fn dashboard_reconcile_missing_daemon_fails_with_dashboard_reconcile_failed() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    assert!(
        !ws.socket.exists(),
        "precondition: no daemon serving the socket"
    );

    let out = Command::new(APP_BIN)
        .arg("dashboard")
        .arg("--with-session-reconcile")
        .arg("--socket")
        .arg(&ws.socket)
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app dashboard --with-session-reconcile against missing daemon");

    assert_ne!(
        out.status.code(),
        Some(0),
        "reconcile against a missing daemon must not exit 0"
    );
    assert!(
        out.stdout.is_empty(),
        "stdout should be empty on reconcile failure"
    );

    let value = parse_single_json(&out.stderr);
    assert_eq!(value["ok"], serde_json::json!(false));
    assert_eq!(value["command"], serde_json::json!("dashboard"));
    assert_eq!(
        value["error_kind"],
        serde_json::json!("dashboard_reconcile_failed")
    );
    assert!(
        !ws.socket.exists(),
        "a failed reconcile must not create the socket"
    );
}

// ============================================================================================
// 4d. Agent-task headless commands (agent-start / agent-resume)
// ============================================================================================

/// Kill a fake daemon whose PID was recorded to `pidfile`, then remove its `socket`. The agent
/// commands KEEP a spawned daemon alive on success, so each agent smoke must clean it up itself.
fn kill_kept_daemon(pidfile: &Path, socket: &Path) {
    if let Ok(text) = std::fs::read_to_string(pidfile) {
        if let Ok(pid) = text.trim().parse::<i32>() {
            // SIGKILL the kept daemon (a re-exec of this test binary in fake-daemon mode).
            let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status();
        }
    }
    let _ = std::fs::remove_file(socket);
}

#[test]
fn agent_start_succeeds_creates_running_task_and_keeps_daemon() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    // FK chain: agent-start creates the AgentTask (project p-1) and a SessionRecord under workspace
    // ws-1; seed both parents so the writes satisfy the SQLite foreign keys.
    seed_workspace(&ws.base, "ws-1", "p-1");
    let pidfile = ws.dir.path().join("daemon.pid");
    let cwd = ws.dir.path().join("work");
    std::fs::create_dir_all(&cwd).expect("cwd");
    let wrapper = write_fake_daemon_wrapper_with_pidfile(ws.dir.path(), Some(&pidfile));

    let out = Command::new(APP_BIN)
        .arg("agent-start")
        .arg("--agent-task-id")
        .arg("t-start")
        .arg("--project-id")
        .arg("p-1")
        .arg("--goal")
        .arg("do the thing")
        .arg("--session-id")
        .arg("s-start")
        .arg("--workspace-id")
        .arg("ws-1")
        .arg("--cwd")
        .arg(&cwd)
        .arg("--socket")
        .arg(&ws.socket)
        .arg("--base")
        .arg(&ws.base)
        .arg("--daemon")
        .arg(&wrapper)
        .arg("--")
        .arg("/bin/cat")
        .stdin(Stdio::null())
        .output()
        .expect("run agent-start");

    // Always clean up the intentionally-kept daemon, even if assertions below fail.
    let status = out.status.code();
    let stdout = out.stdout.clone();
    let stderr = out.stderr.clone();

    // The daemon is kept; verify it is still serving BEFORE we kill it.
    let still_serving = can_connect(&ws.socket);
    kill_kept_daemon(&pidfile, &ws.socket);

    assert_eq!(
        status,
        Some(0),
        "agent-start should exit 0; stderr: {stderr:?}"
    );
    assert!(stderr.is_empty(), "stderr should be empty on success");
    assert!(
        still_serving,
        "a daemon spawned on success must be kept serving"
    );

    let value = parse_single_json(&stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["command"], serde_json::json!("agent-start"));
    assert_eq!(value["agent_task_id"], serde_json::json!("t-start"));
    assert_eq!(value["agent_task_state"], serde_json::json!("running"));
    assert_eq!(value["session_id"], serde_json::json!("s-start"));
    assert_eq!(value["session_status"], serde_json::json!("live"));
    assert_eq!(value["daemon_started"], serde_json::json!(true));
    assert_eq!(value["daemon_kept"], serde_json::json!(true));

    // The task record was persisted Running, and the session is an Agent session carrying the FK.
    use maestro_shell::paths::{AppPaths, RecordKind};
    use maestro_shell::records::{AgentTask, AgentTaskState, SessionKind, SessionRecord};
    let paths = AppPaths::with_base(&ws.base);
    let task = load_record::<AgentTask>(&paths, RecordKind::AgentTask, "t-start");
    assert_eq!(task.state, AgentTaskState::Running);
    assert_eq!(task.current_session_id.as_deref(), Some("s-start"));
    let session = load_record::<SessionRecord>(&paths, RecordKind::Session, "s-start");
    assert_eq!(session.kind, SessionKind::Agent);
    assert_eq!(session.agent_task_id.as_deref(), Some("t-start"));
}

/// Read exactly one durable record by id through the real store, asserting it loaded cleanly.
fn load_record<T: serde::de::DeserializeOwned>(
    paths: &maestro_shell::paths::AppPaths,
    kind: maestro_shell::paths::RecordKind,
    id: &str,
) -> T {
    use maestro_shell::store::{self, LoadOutcome};
    match store::load_one::<T>(paths, kind, id).expect("load_one") {
        Some(LoadOutcome::Loaded(record)) => record,
        _ => panic!("expected one loaded record for {id}"),
    }
}

#[test]
fn agent_resume_attaches_new_session_and_pushes_history() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let pidfile = ws.dir.path().join("daemon.pid");
    let cwd = ws.dir.path().join("work");
    std::fs::create_dir_all(&cwd).expect("cwd");
    let wrapper = write_fake_daemon_wrapper_with_pidfile(ws.dir.path(), Some(&pidfile));

    // FK chain: the task's project p-1 must exist (agent_tasks.project_id → projects), and the resume
    // writes a SessionRecord under workspace ws-1 (sessions.workspace_id → workspaces). Seed both.
    seed_workspace(&ws.base, "ws-1", "p-1");

    // Pre-write an existing Running task whose current session is an older one.
    use maestro_shell::paths::{AppPaths, RecordKind};
    use maestro_shell::records::{AgentTask, AgentTaskState, SessionKind, SessionRecord};
    use maestro_shell::store;
    let paths = AppPaths::with_base(&ws.base);
    let task = AgentTask {
        agent_task_id: "t-resume".into(),
        project_id: "p-1".into(),
        goal: "goal".into(),
        state: AgentTaskState::Running,
        current_session_id: Some("s-old".into()),
        session_history: vec![],
        created_at_ms: 1,
        updated_at_ms: 1,
        result_summary: None,
    };
    store::write_record(&paths, RecordKind::AgentTask, &task.agent_task_id, 1, &task)
        .expect("seed task");

    let out = Command::new(APP_BIN)
        .arg("agent-resume")
        .arg("--agent-task-id")
        .arg("t-resume")
        .arg("--session-id")
        .arg("s-new")
        .arg("--workspace-id")
        .arg("ws-1")
        .arg("--cwd")
        .arg(&cwd)
        .arg("--socket")
        .arg(&ws.socket)
        .arg("--base")
        .arg(&ws.base)
        .arg("--daemon")
        .arg(&wrapper)
        .arg("--")
        .arg("/bin/cat")
        .stdin(Stdio::null())
        .output()
        .expect("run agent-resume");

    let status = out.status.code();
    let stdout = out.stdout.clone();
    let stderr = out.stderr.clone();
    kill_kept_daemon(&pidfile, &ws.socket);

    assert_eq!(
        status,
        Some(0),
        "agent-resume should exit 0; stderr: {stderr:?}"
    );
    assert!(stderr.is_empty(), "stderr should be empty on success");

    let value = parse_single_json(&stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["command"], serde_json::json!("agent-resume"));
    assert_eq!(value["agent_task_id"], serde_json::json!("t-resume"));
    assert_eq!(value["session_id"], serde_json::json!("s-new"));
    assert_eq!(value["session_status"], serde_json::json!("live"));
    assert_eq!(value["daemon_kept"], serde_json::json!(true));

    // The prior current session id was pushed into history; the new session is now current.
    let reloaded = load_record::<AgentTask>(&paths, RecordKind::AgentTask, "t-resume");
    assert_eq!(reloaded.current_session_id.as_deref(), Some("s-new"));
    assert!(
        reloaded.session_history.contains(&"s-old".to_string()),
        "prior session id must be pushed into session_history, got {:?}",
        reloaded.session_history
    );
    let session = load_record::<SessionRecord>(&paths, RecordKind::Session, "s-new");
    assert_eq!(session.kind, SessionKind::Agent);
    assert_eq!(session.agent_task_id.as_deref(), Some("t-resume"));
}

#[test]
fn agent_start_bad_usage_exits_two_with_command_stamped_json() {
    maybe_run_fake_daemon();
    // Missing the required `-- <argv>` is a parse-time usage error: exit 2, stamped command.
    let out = Command::new(APP_BIN)
        .arg("agent-start")
        .arg("--agent-task-id")
        .arg("t-1")
        .stdin(Stdio::null())
        .output()
        .expect("run agent-start with bad usage");

    assert_eq!(
        out.status.code(),
        Some(2),
        "bad agent-start usage should exit 2"
    );
    assert!(out.stdout.is_empty(), "stdout should be empty on bad usage");

    let value = parse_single_json(&out.stderr);
    assert_eq!(value["ok"], serde_json::json!(false));
    assert_eq!(value["command"], serde_json::json!("agent-start"));
    assert_eq!(value["error_kind"], serde_json::json!("bad_usage"));
}

#[test]
fn agent_resume_missing_task_fails_and_cleans_owned_socket() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let cwd = ws.dir.path().join("work");
    std::fs::create_dir_all(&cwd).expect("cwd");
    // No pidfile: the daemon is spawned but the resume of a NON-EXISTENT task fails AFTER spawn, so
    // the un-kept SpawnedDaemon drop must kill it and remove the owned socket.
    let wrapper = write_fake_daemon_wrapper(ws.dir.path());

    let out = Command::new(APP_BIN)
        .arg("agent-resume")
        .arg("--agent-task-id")
        .arg("does-not-exist")
        .arg("--session-id")
        .arg("s-x")
        .arg("--workspace-id")
        .arg("ws-1")
        .arg("--cwd")
        .arg(&cwd)
        .arg("--socket")
        .arg(&ws.socket)
        .arg("--base")
        .arg(&ws.base)
        .arg("--daemon")
        .arg(&wrapper)
        .arg("--")
        .arg("/bin/cat")
        .stdin(Stdio::null())
        .output()
        .expect("run agent-resume on missing task");

    assert_ne!(
        out.status.code(),
        Some(0),
        "resuming a missing task should fail"
    );
    assert!(out.stdout.is_empty(), "stdout should be empty on failure");

    let value = parse_single_json(&out.stderr);
    assert_eq!(value["ok"], serde_json::json!(false));
    assert_eq!(value["command"], serde_json::json!("agent-resume"));
    assert_eq!(value["error_kind"], serde_json::json!("agent_task_failed"));

    assert!(
        !ws.socket.exists(),
        "a failure-after-spawn must remove the owned socket"
    );
    assert!(
        !can_connect(&ws.socket),
        "no daemon should remain after a failure-after-spawn"
    );
}

// ============================================================================================
// 5. Failure-after-spawn cleanup regression
// ============================================================================================

#[test]
fn failure_after_spawn_removes_socket_and_leaves_no_daemon() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    // `--session-id ../bad` is rejected by the session store AFTER the daemon is spawned and
    // connectable, exercising the post-spawn `?` error path (owned-socket cleanup via Drop).
    let out = headless_launch(&ws)
        .arg("--session-id")
        .arg("../bad")
        .output()
        .expect("run failing headless launch");

    assert_ne!(out.status.code(), Some(0), "bad session id should fail");
    assert!(out.stdout.is_empty(), "stdout should be empty on failure");

    let value = parse_single_json(&out.stderr);
    assert_eq!(value["ok"], serde_json::json!(false));

    assert!(
        !ws.socket.exists(),
        "the owned socket should be removed after a failure-after-spawn"
    );
    assert!(
        !can_connect(&ws.socket),
        "no daemon should remain serving the socket after a failure-after-spawn"
    );
}

// ============================================================================================
// 6. Reused-daemon safety
// ============================================================================================

/// A pre-started fake daemon serving a socket, killed (and socket removed) on drop so the test
/// never leaks a process or a stale socket.
struct PreStartedDaemon {
    child: Child,
    socket: PathBuf,
}

impl Drop for PreStartedDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

fn prestart_legacy_daemon(
    ws: &Workspace,
    retained_session_id: &str,
    request_log: &Path,
) -> PreStartedDaemon {
    let test_bin = std::env::current_exe().expect("current test exe");
    let child = Command::new(&test_bin)
        .env(FAKE_DAEMON_ENV, &ws.socket)
        .env(FAKE_DAEMON_LEGACY_SESSION_ENV, retained_session_id)
        .env(FAKE_DAEMON_REQUEST_LOG_ENV, request_log)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn protocol-v1 fake daemon");
    let guard = PreStartedDaemon {
        child,
        socket: ws.socket.clone(),
    };
    wait_until_connectable(&ws.socket);
    guard
}

fn packaged_headless_launch(ws: &Workspace) -> Command {
    seed_adhoc_launch_chain(&ws.base);
    let mut cmd = Command::new(APP_BIN);
    cmd.arg("launch")
        .arg("--top-tab-bar")
        .arg("--no-dashboard-panel")
        .arg("--new-tab-default-shell")
        .arg("--record-window")
        .arg("--fresh-window")
        .arg("--title")
        .arg("Hydra")
        .arg("--socket")
        .arg(&ws.socket)
        .arg("--base")
        .arg(&ws.base)
        // The path is resolved but never spawned because the retained fixture already owns socket.
        .arg("--daemon")
        .arg(std::env::current_exe().expect("current test exe"))
        .arg("--no-run-renderer")
        .stdin(Stdio::null());
    cmd
}

fn product_headless_launch(ws: &Workspace, daemon_wrapper: &Path) -> Command {
    let mut cmd = Command::new(APP_BIN);
    cmd.arg("launch")
        .arg("--top-tab-bar")
        .arg("--no-dashboard-panel")
        .arg("--new-tab-default-shell")
        .arg("--product-startup")
        .arg("--title")
        .arg("Hydra")
        .arg("--socket")
        .arg(&ws.socket)
        .arg("--base")
        .arg(&ws.base)
        .arg("--daemon")
        .arg(daemon_wrapper)
        .arg("--keep-daemon")
        .arg("--no-run-renderer")
        .env("HOME", ws.dir.path())
        .env("HYDRA_NO_UPDATE_CHECK", "1")
        .stdin(Stdio::null());
    cmd
}

#[test]
fn keep_daemon_survives_injected_post_session_setup_failure() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let pidfile = ws.dir.path().join("post-session-daemon.pid");
    let request_log = ws.dir.path().join("post-session-requests.log");
    let omit_list_file = ws.dir.path().join("omit-retained-from-live-list");
    let wrapper =
        write_stateful_fake_daemon_wrapper(ws.dir.path(), &pidfile, &request_log, &omit_list_file);

    let output = product_headless_launch(&ws, &wrapper)
        .env("HYDRA_TEST_FAIL_AFTER_SESSION_PROOF", "1")
        .output()
        .expect("run injected post-session failure");
    let failure = parse_single_json(&output.stderr);
    let daemon_pid_recorded = pidfile.is_file();
    let sessions = maestro_shell::DaemonClient::connect(&ws.socket)
        .and_then(|mut client| client.list_sessions())
        .expect("kept daemon remains connectable after app failure");
    let transcript = std::fs::read_to_string(&request_log).unwrap_or_default();

    // Collect all proof before cleanup so a failed assertion never leaks the intentionally kept
    // fake daemon.
    kill_kept_daemon(&pidfile, &ws.socket);

    assert!(
        !output.status.success(),
        "fault injection must fail the app"
    );
    assert_eq!(failure["ok"], serde_json::json!(false));
    assert_eq!(
        failure["error_kind"],
        serde_json::json!("post_session_setup_failed")
    );
    assert!(daemon_pid_recorded);
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].0,
        maestro_app::SYSTEM_TERMINAL_SESSION_ID,
        "the proven product session survives with the daemon"
    );
    assert!(transcript.contains(r#""op":"start_session""#));
}

#[test]
fn product_startup_zero_state_relaunch_and_daemon_recovery_keep_one_owned_session() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let pidfile = ws.dir.path().join("product-daemon.pid");
    let request_log = ws.dir.path().join("product-daemon-requests.log");
    let omit_list_file = ws.dir.path().join("omit-retained-from-live-list");
    let wrapper =
        write_stateful_fake_daemon_wrapper(ws.dir.path(), &pidfile, &request_log, &omit_list_file);

    let first = product_headless_launch(&ws, &wrapper)
        .output()
        .expect("run zero-state product startup");
    let second = product_headless_launch(&ws, &wrapper)
        .output()
        .expect("run product relaunch");

    let paths = maestro_shell::paths::AppPaths::with_base(&ws.base);
    let initial_daemon_sessions = maestro_shell::DaemonClient::connect(&ws.socket)
        .and_then(|mut client| client.list_sessions())
        .expect("list retained daemon sessions");

    // Model a shell that exited while the daemon still retains its final grid. Current daemons
    // omit this latch from their live-only list, but exact Attach must still reopen it without a
    // second StartSession.
    let mut exited_session =
        match maestro_shell::store::load_one::<maestro_shell::records::SessionRecord>(
            &paths,
            maestro_shell::paths::RecordKind::Session,
            maestro_app::SYSTEM_TERMINAL_SESSION_ID,
        )
        .expect("load stable session before exited relaunch")
        {
            Some(maestro_shell::store::LoadOutcome::Loaded(session)) => session,
            other => panic!("expected current stable session, got {other:?}"),
        };
    exited_session.status = maestro_shell::records::SessionStatus::Exited;
    maestro_shell::store::write_record(
        &paths,
        maestro_shell::paths::RecordKind::Session,
        maestro_app::SYSTEM_TERMINAL_SESSION_ID,
        exited_session.last_attached_at_ms.saturating_add(1),
        &exited_session,
    )
    .expect("mark stable session exited");
    std::fs::write(&omit_list_file, b"omit exited latch").expect("create live-list marker");
    let third = product_headless_launch(&ws, &wrapper)
        .output()
        .expect("run exited retained product relaunch");

    let retained_transcript = std::fs::read_to_string(&request_log).unwrap_or_default();
    kill_kept_daemon(&pidfile, &ws.socket);
    std::fs::remove_file(&omit_list_file).expect("restore normal live-list behavior");

    // Now model a daemon restart: durable metadata still says Exited, but the retained latch is
    // genuinely gone. Exact Attach returns the authoritative miss, after which product startup may
    // safely recreate this same stable id (never an ad-hoc or second identity).
    let fourth = product_headless_launch(&ws, &wrapper)
        .output()
        .expect("run exited product startup after daemon restart");
    let recovered_daemon_sessions = maestro_shell::DaemonClient::connect(&ws.socket)
        .and_then(|mut client| client.list_sessions())
        .expect("list recreated stable daemon session");

    let projects = maestro_shell::ProjectService::new(&paths)
        .list()
        .expect("load projects");
    let workspaces: Vec<maestro_shell::records::Workspace> =
        maestro_shell::store::load_all(&paths, maestro_shell::paths::RecordKind::Workspace)
            .expect("load workspaces")
            .into_iter()
            .filter_map(|record| match record {
                maestro_shell::store::LoadOutcome::Loaded(record) => Some(record),
                _ => None,
            })
            .collect();
    let sessions: Vec<maestro_shell::records::SessionRecord> =
        maestro_shell::store::load_all(&paths, maestro_shell::paths::RecordKind::Session)
            .expect("load sessions")
            .into_iter()
            .filter_map(|record| match record {
                maestro_shell::store::LoadOutcome::Loaded(record) => Some(record),
                _ => None,
            })
            .collect();
    let windows: Vec<maestro_shell::records::WindowLayout> =
        maestro_shell::store::load_all(&paths, maestro_shell::paths::RecordKind::WindowLayout)
            .expect("load windows")
            .into_iter()
            .filter_map(|record| match record {
                maestro_shell::store::LoadOutcome::Loaded(record) => Some(record),
                _ => None,
            })
            .collect();
    let owners = maestro_shell::store::window_project_owners(&paths).expect("load owners");
    let transcript = std::fs::read_to_string(&request_log).unwrap_or_default();

    // Collect all evidence while the kept daemon is live, then clean it before assertions so a
    // failed assertion never leaves a fake process behind.
    kill_kept_daemon(&pidfile, &ws.socket);

    assert_eq!(first.status.code(), Some(0), "first launch: {first:?}");
    assert_eq!(second.status.code(), Some(0), "second launch: {second:?}");
    assert_eq!(third.status.code(), Some(0), "third launch: {third:?}");
    assert_eq!(fourth.status.code(), Some(0), "fourth launch: {fourth:?}");
    let first_json = parse_single_json(&first.stdout);
    let second_json = parse_single_json(&second.stdout);
    let third_json = parse_single_json(&third.stdout);
    let fourth_json = parse_single_json(&fourth.stdout);
    for value in [&first_json, &second_json, &third_json, &fourth_json] {
        assert_eq!(value["ok"], serde_json::json!(true));
        assert_eq!(
            value["session_id"],
            serde_json::json!(maestro_app::SYSTEM_TERMINAL_SESSION_ID)
        );
        assert_eq!(value["window_recorded"], serde_json::json!(true));
        assert_eq!(
            value["window_id"],
            serde_json::json!(maestro_app::SYSTEM_TERMINAL_WINDOW_ID)
        );
        assert_eq!(
            value["tab_id"],
            serde_json::json!(maestro_app::SYSTEM_TERMINAL_TAB_ID)
        );
    }
    assert_eq!(first_json["daemon_started"], serde_json::json!(true));
    assert_eq!(second_json["daemon_started"], serde_json::json!(false));
    assert_eq!(third_json["daemon_started"], serde_json::json!(false));
    assert_eq!(third_json["status"], serde_json::json!("exited"));
    assert_eq!(fourth_json["daemon_started"], serde_json::json!(true));
    assert_eq!(fourth_json["status"], serde_json::json!("live"));

    assert_eq!(projects.len(), 1);
    assert_eq!(
        projects[0].project_id,
        maestro_app::SYSTEM_TERMINAL_PROJECT_ID
    );
    assert!(projects[0].system);
    assert_eq!(
        projects[0].window_order,
        vec![maestro_app::SYSTEM_TERMINAL_WINDOW_ID]
    );
    assert_eq!(workspaces.len(), 1);
    assert_eq!(
        workspaces[0].workspace_id,
        maestro_app::SYSTEM_TERMINAL_WORKSPACE_ID
    );
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].session_id,
        maestro_app::SYSTEM_TERMINAL_SESSION_ID
    );
    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0].window_id, maestro_app::SYSTEM_TERMINAL_WINDOW_ID);
    assert_eq!(windows[0].tabs.len(), 1);
    assert_eq!(
        windows[0].tabs[0].tab_id,
        maestro_app::SYSTEM_TERMINAL_TAB_ID
    );
    assert_eq!(
        windows[0].tabs[0].session_id,
        maestro_app::SYSTEM_TERMINAL_SESSION_ID
    );
    assert_eq!(
        owners,
        vec![(
            maestro_app::SYSTEM_TERMINAL_WINDOW_ID.to_string(),
            Some(maestro_app::SYSTEM_TERMINAL_PROJECT_ID.to_string())
        )]
    );
    assert_eq!(initial_daemon_sessions.len(), 1, "no orphan daemon session");
    assert_eq!(
        initial_daemon_sessions[0].0,
        maestro_app::SYSTEM_TERMINAL_SESSION_ID
    );
    assert_eq!(
        recovered_daemon_sessions.len(),
        1,
        "daemon restart must recreate only the exact stable session"
    );
    assert_eq!(
        recovered_daemon_sessions[0].0,
        maestro_app::SYSTEM_TERMINAL_SESSION_ID
    );
    assert_eq!(
        retained_transcript
            .lines()
            .filter(|line| line.contains(r#""op":"start_session""#))
            .count(),
        1,
        "live/exited retained relaunches must attach without another StartSession: {retained_transcript}"
    );
    assert_eq!(
        transcript
            .lines()
            .filter(|line| line.contains(r#""op":"start_session""#))
            .count(),
        2,
        "only genuine daemon loss may recreate the stable session: {transcript}"
    );
    assert!(
        !transcript.contains(maestro_app::DEFAULT_SESSION_ID),
        "generic ad-hoc session leaked into product startup: {transcript}"
    );
}

#[test]
fn product_startup_exact_attaches_unsafe_target_then_uses_fixed_recovery_without_replay() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let pidfile = ws.dir.path().join("product-topology-daemon.pid");
    let request_log = ws.dir.path().join("product-topology-requests.log");
    let omit_list_file = ws.dir.path().join("omit-retained-from-list");
    let wrapper =
        write_stateful_fake_daemon_wrapper(ws.dir.path(), &pidfile, &request_log, &omit_list_file);

    let first = product_headless_launch(&ws, &wrapper)
        .output()
        .expect("run zero-state product startup");
    assert_eq!(first.status.code(), Some(0), "first launch: {first:?}");

    let paths = maestro_shell::paths::AppPaths::with_base(&ws.base);
    let missing_cwd = ws.dir.path().join("deleted-product-cwd");
    let mut stable = match maestro_shell::store::load_one::<maestro_shell::records::SessionRecord>(
        &paths,
        maestro_shell::paths::RecordKind::Session,
        maestro_app::SYSTEM_TERMINAL_SESSION_ID,
    )
    .expect("load stable product session")
    {
        Some(maestro_shell::store::LoadOutcome::Loaded(session)) => session,
        other => panic!("expected stable session, got {other:?}"),
    };
    stable.cwd_resolved = missing_cwd.to_string_lossy().into_owned();
    maestro_shell::store::write_record(
        &paths,
        maestro_shell::paths::RecordKind::Session,
        maestro_app::SYSTEM_TERMINAL_SESSION_ID,
        stable.last_attached_at_ms.saturating_add(1),
        &stable,
    )
    .expect("persist unavailable stable cwd");

    // An unavailable persisted cwd cannot block exact mutation-free attach to the retained stable
    // PTY. This also pins the fixed stable Shell+OptOut recovery exception.
    let second = product_headless_launch(&ws, &wrapper)
        .output()
        .expect("reattach stable product session with unavailable cwd");
    assert_eq!(second.status.code(), Some(0), "second launch: {second:?}");

    const SIBLING_SESSION_ID: &str = "visible-sibling-session";
    const SIBLING_WINDOW_ID: &str = "visible-sibling-window";
    const SIBLING_TAB_ID: &str = "visible-sibling-tab";
    let mut sibling = stable.clone();
    sibling.session_id = SIBLING_SESSION_ID.into();
    sibling.status = maestro_shell::records::SessionStatus::Unknown;
    sibling.last_known_generation = None;
    sibling.cwd_resolved = missing_cwd.to_string_lossy().into_owned();
    sibling.launch = maestro_shell::records::LaunchSpec::AdHocRedacted {
        // This is intentionally canonicalizable into a KnownSafe agent recipe by the generic
        // migration. Product startup must skip that rewrite or it would launder restart authority.
        argv: vec!["claude".into(), "--resume".into(), "secret-session".into()],
        redacted: false,
        restart_requires_user: true,
    };
    maestro_shell::store::write_record(
        &paths,
        maestro_shell::paths::RecordKind::Session,
        SIBLING_SESSION_ID,
        sibling.last_attached_at_ms.saturating_add(2),
        &sibling,
    )
    .expect("persist visible sibling session");
    let windows = maestro_shell::WindowLayoutService::new(&paths);
    windows
        .create_empty(SIBLING_WINDOW_ID, 10)
        .expect("create sibling window");
    windows
        .open_tab(
            SIBLING_WINDOW_ID,
            SIBLING_TAB_ID,
            SIBLING_SESSION_ID,
            "Visible sibling",
            false,
            maestro_shell::records::AttentionState::default(),
            11,
        )
        .expect("open sibling tab");
    maestro_shell::store::set_window_project(
        &paths,
        SIBLING_WINDOW_ID,
        maestro_app::SYSTEM_TERMINAL_PROJECT_ID,
    )
    .expect("own sibling window");
    maestro_shell::ProjectService::new(&paths)
        .reorder_windows(
            maestro_app::SYSTEM_TERMINAL_PROJECT_ID,
            &[
                maestro_app::SYSTEM_TERMINAL_WINDOW_ID.to_string(),
                SIBLING_WINDOW_ID.to_string(),
            ],
            12,
        )
        .expect("order sibling window");
    windows
        .set_tab_stashed(
            maestro_app::SYSTEM_TERMINAL_WINDOW_ID,
            maestro_app::SYSTEM_TERMINAL_TAB_ID,
            true,
            13,
        )
        .expect("stash stable product pane");

    // Seed the arbitrary AdHoc pane directly in the fake daemon. Product startup did not authorize
    // this command; it is merely retained state that exact Attach is always allowed to reopen.
    maestro_shell::DaemonClient::connect(&ws.socket)
        .and_then(|mut client| {
            client.start_and_attach(
                maestro_protocol::SessionId(SIBLING_SESSION_ID.into()),
                ws.dir.path().to_string_lossy().as_ref(),
                "sh",
                &[],
                80,
                24,
            )
        })
        .expect("seed retained unsafe sibling in fake daemon");
    std::fs::write(&omit_list_file, b"omit retained ids").expect("hide live-list membership");
    let before_retained_attach = std::fs::read_to_string(&request_log).unwrap_or_default();

    // Unknown status, an unavailable cwd, and omitted live-list membership cannot suppress the
    // required exact Attach. No StartSession or ListSessions belongs in this reopen decision.
    let third = product_headless_launch(&ws, &wrapper)
        .output()
        .expect("exact-attach retained unsafe sibling");
    assert_eq!(third.status.code(), Some(0), "third launch: {third:?}");
    let after_retained_attach = std::fs::read_to_string(&request_log).unwrap_or_default();
    let retained_delta = after_retained_attach
        .strip_prefix(&before_retained_attach)
        .expect("request log remains append-only");
    assert!(retained_delta.contains(SIBLING_SESSION_ID));
    assert!(retained_delta.contains(r#""op":"attach""#));
    assert!(!retained_delta.contains(r#""op":"start_session""#));
    assert!(!retained_delta.contains(r#""op":"list_sessions""#));

    // Restart the daemon so the arbitrary AdHoc target is authoritatively absent. Product startup
    // must exact-Attach it first, never replay it, then create/start the one fixed hidden recovery
    // shell. The selected user record remains byte-for-byte AdHoc authority.
    kill_kept_daemon(&pidfile, &ws.socket);
    std::fs::remove_file(&omit_list_file).expect("restore live-list response");
    let fourth = product_headless_launch(&ws, &wrapper)
        .output()
        .expect("fall back from missing unsafe sibling");
    assert_eq!(fourth.status.code(), Some(0), "fourth launch: {fourth:?}");

    // The real visible pane remains canonical on every launch, so it is probed again first; the
    // retained fixed recovery target is then exact-attached without another StartSession.
    let fifth = product_headless_launch(&ws, &wrapper)
        .output()
        .expect("reuse fixed retained recovery target");
    assert_eq!(fifth.status.code(), Some(0), "fifth launch: {fifth:?}");

    // With every real pane hidden/stashed, startup still remains available through direct recovery
    // projection. Neither the system project's hidden bit nor the stable pane's stash is revived.
    let projects = maestro_shell::ProjectService::new(&paths);
    let mut system = projects
        .load(maestro_app::SYSTEM_TERMINAL_PROJECT_ID)
        .expect("load system project")
        .expect("system project exists");
    system.hidden = true;
    maestro_shell::store::write_record(
        &paths,
        maestro_shell::paths::RecordKind::Project,
        maestro_app::SYSTEM_TERMINAL_PROJECT_ID,
        30,
        &system,
    )
    .expect("hide system project");
    let sixth = product_headless_launch(&ws, &wrapper)
        .output()
        .expect("all-hidden availability fallback");

    let daemon_sessions = maestro_shell::DaemonClient::connect(&ws.socket)
        .and_then(|mut client| client.list_sessions())
        .expect("list retained product sessions");
    let transcript = std::fs::read_to_string(&request_log).unwrap_or_default();
    let stable_layout = windows
        .load(maestro_app::SYSTEM_TERMINAL_WINDOW_ID)
        .expect("load stable layout")
        .expect("stable layout exists");
    let all_layouts: Vec<maestro_shell::records::WindowLayout> =
        maestro_shell::store::load_all(&paths, maestro_shell::paths::RecordKind::WindowLayout)
            .expect("load product windows")
            .into_iter()
            .filter_map(|outcome| match outcome {
                maestro_shell::store::LoadOutcome::Loaded(layout) => Some(layout),
                _ => None,
            })
            .collect();
    let referenced_ids: HashSet<String> = all_layouts
        .iter()
        .flat_map(|layout| layout.tabs.iter().map(|tab| tab.session_id.clone()))
        .collect();
    let persisted_sibling =
        match maestro_shell::store::load_one::<maestro_shell::records::SessionRecord>(
            &paths,
            maestro_shell::paths::RecordKind::Session,
            SIBLING_SESSION_ID,
        )
        .expect("load preserved unsafe sibling")
        {
            Some(maestro_shell::store::LoadOutcome::Loaded(session)) => session,
            other => panic!("expected preserved sibling, got {other:?}"),
        };
    let recovery_project = projects
        .load("system-product-recovery")
        .expect("load recovery project")
        .expect("recovery project exists");
    kill_kept_daemon(&pidfile, &ws.socket);

    let second_json = parse_single_json(&second.stdout);
    let third_json = parse_single_json(&third.stdout);
    let fourth_json = parse_single_json(&fourth.stdout);
    let fifth_json = parse_single_json(&fifth.stdout);
    let sixth_json = parse_single_json(&sixth.stdout);
    assert_eq!(
        second_json["session_id"],
        serde_json::json!(maestro_app::SYSTEM_TERMINAL_SESSION_ID)
    );
    assert_eq!(
        third_json["session_id"],
        serde_json::json!(SIBLING_SESSION_ID)
    );
    assert_eq!(
        third_json["window_id"],
        serde_json::json!(SIBLING_WINDOW_ID)
    );
    assert_eq!(third_json["tab_id"], serde_json::json!(SIBLING_TAB_ID));
    for value in [&fourth_json, &fifth_json, &sixth_json] {
        assert_eq!(value["ok"], serde_json::json!(true));
        assert_eq!(
            value["session_id"],
            serde_json::json!("system-product-recovery-session")
        );
        assert_eq!(
            value["window_id"],
            serde_json::json!("system-product-recovery-window")
        );
        assert_eq!(
            value["tab_id"],
            serde_json::json!("system-product-recovery-pane")
        );
    }
    assert!(
        stable_layout
            .tabs
            .iter()
            .find(|tab| tab.tab_id == maestro_app::SYSTEM_TERMINAL_TAB_ID)
            .expect("stable pane")
            .stashed
    );
    assert!(
        projects
            .load(maestro_app::SYSTEM_TERMINAL_PROJECT_ID)
            .unwrap()
            .unwrap()
            .hidden
    );
    assert!(recovery_project.hidden);
    assert!(recovery_project.system);
    assert_eq!(all_layouts.len(), 3, "one fixed recovery window only");
    assert_eq!(daemon_sessions.len(), 1);
    assert_eq!(daemon_sessions[0].0, "system-product-recovery-session");
    assert!(daemon_sessions
        .iter()
        .all(|id| referenced_ids.contains(&id.0)));
    let starts: Vec<&str> = transcript
        .lines()
        .filter(|line| line.contains(r#""op":"start_session""#))
        .collect();
    assert_eq!(
        starts.len(),
        3,
        "stable + explicit fixture + recovery: {transcript}"
    );
    assert!(starts
        .iter()
        .any(|line| line.contains(maestro_app::SYSTEM_TERMINAL_SESSION_ID)));
    assert_eq!(
        starts
            .iter()
            .filter(|line| line.contains(SIBLING_SESSION_ID))
            .count(),
        1,
        "only the explicit fixture seeding may start the unsafe target: {transcript}"
    );
    assert!(starts
        .iter()
        .any(|line| line.contains("system-product-recovery-session")));
    assert!(matches!(
        persisted_sibling.launch,
        maestro_shell::records::LaunchSpec::AdHocRedacted {
            restart_requires_user: true,
            ..
        }
    ));
    assert_eq!(
        persisted_sibling.cwd_resolved,
        missing_cwd.to_string_lossy()
    );
    assert!(!transcript.contains(maestro_app::DEFAULT_SESSION_ID));
}

fn seed_retained_upgrade_window(ws: &Workspace) -> serde_json::Value {
    let session_id = maestro_app::DEFAULT_SESSION_ID;
    write_session_with_window(&ws.base, session_id, "main", "kept-primary");
    let paths = maestro_shell::AppPaths::with_base(&ws.base);
    maestro_shell::store::set_window_project(&paths, "main", "p-1")
        .expect("seed retained window owner");
    maestro_shell::ProjectService::new(&paths)
        .reorder_windows("p-1", &["main".to_string()], 1)
        .expect("seed retained window order");
    let opened = run_window(
        &ws.base,
        &[
            "open-tab",
            "--window-id",
            "main",
            "--tab-id",
            "kept-secondary",
            "--session-id",
            session_id,
            "--title",
            "Kept secondary",
        ],
    );
    assert_eq!(opened.status.code(), Some(0), "seed second retained tab");
    let shown = run_window(&ws.base, &["show", "--window-id", "main"]);
    assert_eq!(shown.status.code(), Some(0), "show seeded retained window");
    parse_single_json(&shown.stdout)
}

fn assert_no_daemon_mutation(request_log: &Path) {
    let transcript = std::fs::read_to_string(request_log).unwrap_or_default();
    assert!(
        !transcript.contains("start_session")
            && !transcript.contains("kill_session")
            && !transcript.contains(r#""op":"kill""#),
        "attach-only upgrade emitted a daemon mutation: {transcript}"
    );
}

#[test]
fn reused_daemon_is_not_killed_and_its_socket_is_left_intact() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    // Pre-start a fake daemon ourselves by re-execing THIS test binary in fake-daemon mode on the
    // socket, so the app must REUSE it (not spawn its own).
    let test_bin = std::env::current_exe().expect("current test exe");
    let child = Command::new(&test_bin)
        .env(FAKE_DAEMON_ENV, &ws.socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn pre-started fake daemon");
    let mut guard = PreStartedDaemon {
        child,
        socket: ws.socket.clone(),
    };
    wait_until_connectable(&ws.socket);

    let out = headless_launch(&ws).output().expect("run reused launch");

    assert_eq!(out.status.code(), Some(0), "reused launch should exit 0");
    assert_stderr_quiet(&out.stderr);

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(
        value["daemon_started"],
        serde_json::json!(false),
        "an already-serving daemon must be reused, not re-spawned"
    );

    // The app must NOT remove a socket it did not own; the pre-started daemon is still serving it.
    assert!(
        ws.socket.exists(),
        "a reused daemon's socket must be left in place"
    );
    assert!(
        can_connect(&ws.socket),
        "the pre-started daemon must still be serving its socket after the reused launch"
    );

    // Prove the pre-started daemon is still alive (the app never killed it).
    assert!(
        guard.child.try_wait().expect("try_wait").is_none(),
        "the reused daemon process must still be running"
    );

    // Force one more accept-able connection to confirm liveness beyond the stale-socket check.
    let mut probe = UnixStream::connect(&ws.socket).expect("connect to reused daemon");
    let _ = probe.write_all(b"\n");
}

#[test]
fn packaged_launch_reuses_retained_v1_target_attach_only() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let before = seed_retained_upgrade_window(&ws);
    let request_log = ws.dir.path().join("legacy-requests.log");
    let mut daemon = prestart_legacy_daemon(&ws, maestro_app::DEFAULT_SESSION_ID, &request_log);

    let out = packaged_headless_launch(&ws)
        .output()
        .expect("run packaged-shaped v1 upgrade launch");
    assert_eq!(
        out.status.code(),
        Some(0),
        "attach-only launch should open; stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let unexpected: Vec<&str> = stderr
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter(|line| !line.starts_with("hydra-dashboard launch "))
        // A fresh test base may bootstrap the built-in Terminal project before launch. This is
        // orthogonal to retained attach and is the only additional success diagnostic permitted.
        .filter(|line| !line.starts_with("seed: project=\"system-terminal\" "))
        // Canonicalizing the current built-in model restart recipes is also an intentional,
        // bounded launch diagnostic. Match its complete shape (including a numeric count) rather
        // than allowing arbitrary launch stderr.
        .filter(|line| !is_restart_recipe_canonicalization_diagnostic(line))
        .collect();
    assert!(
        unexpected.is_empty(),
        "unexpected attach-only launch diagnostics: {unexpected:?}"
    );
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["daemon_started"], serde_json::json!(false));
    assert_eq!(
        value["session_id"],
        serde_json::json!(maestro_app::DEFAULT_SESSION_ID)
    );
    assert_eq!(value["status"], serde_json::json!("unknown"));
    assert_eq!(value["generation"], serde_json::json!(null));
    assert_eq!(value["window_recorded"], serde_json::json!(false));

    let shown = run_window(&ws.base, &["show", "--window-id", "main"]);
    assert_eq!(shown.status.code(), Some(0));
    assert_eq!(
        parse_single_json(&shown.stdout),
        before,
        "packaged --fresh-window must be inert in attach-only upgrade mode"
    );
    assert_no_daemon_mutation(&request_log);
    assert!(can_connect(&ws.socket));
    assert!(daemon.child.try_wait().unwrap().is_none());
}

#[test]
fn retained_v1_missing_target_fails_closed() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let before = seed_retained_upgrade_window(&ws);
    let request_log = ws.dir.path().join("legacy-missing-requests.log");
    let mut daemon = prestart_legacy_daemon(&ws, "some-other-session", &request_log);

    let out = packaged_headless_launch(&ws)
        .output()
        .expect("run missing-target v1 upgrade launch");
    assert_ne!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
    let value = parse_single_json(&out.stderr);
    assert_eq!(
        value["error_kind"],
        serde_json::json!("session_start_failed")
    );

    let shown = run_window(&ws.base, &["show", "--window-id", "main"]);
    assert_eq!(parse_single_json(&shown.stdout), before);
    assert_no_daemon_mutation(&request_log);
    assert!(can_connect(&ws.socket));
    assert!(daemon.child.try_wait().unwrap().is_none());
}

#[test]
fn retained_v1_explicit_command_never_falls_back() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let before = seed_retained_upgrade_window(&ws);
    let request_log = ws.dir.path().join("legacy-explicit-requests.log");
    let mut daemon = prestart_legacy_daemon(&ws, maestro_app::DEFAULT_SESSION_ID, &request_log);

    let out = packaged_headless_launch(&ws)
        .arg("--")
        .arg("printf")
        .arg("must-not-run")
        .output()
        .expect("run explicit-command v1 upgrade launch");
    assert_ne!(out.status.code(), Some(0));
    assert!(out.stdout.is_empty());
    let value = parse_single_json(&out.stderr);
    assert_eq!(
        value["error_kind"],
        serde_json::json!("session_start_failed")
    );

    let shown = run_window(&ws.base, &["show", "--window-id", "main"]);
    assert_eq!(parse_single_json(&shown.stdout), before);
    assert_no_daemon_mutation(&request_log);
    assert!(can_connect(&ws.socket));
    assert!(daemon.child.try_wait().unwrap().is_none());
}

// ============================================================================================
// 8. window create / show / open-tab / view (headless, daemon-free)
// ============================================================================================

/// Run a `maestro-app window <subcommand> ...` against `base`, capturing the full process output.
fn run_window(base: &Path, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(APP_BIN);
    cmd.arg("window");
    for a in args {
        cmd.arg(a);
    }
    cmd.arg("--base")
        .arg(base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app window")
}

#[test]
fn window_create_writes_layout_file_and_emits_empty_tabs() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let out = run_window(&ws.base, &["create", "--window-id", "w1"]);

    assert_eq!(out.status.code(), Some(0), "window create should exit 0");
    assert!(out.stderr.is_empty(), "stderr should be empty on success");

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["command"], serde_json::json!("window create"));
    assert_eq!(value["window_id"], serde_json::json!("w1"));
    assert_eq!(value["tabs"], serde_json::json!([]));
    assert_eq!(
        value["base"],
        serde_json::json!(ws.base.to_string_lossy().into_owned())
    );

    // The store persists the layout durably (SQLite-backed; no per-window JSON file anymore). Prove it
    // round-trips by reading it back through `window show`, which reports the empty-tab window.
    let show = run_window(&ws.base, &["show", "--window-id", "w1"]);
    assert_eq!(show.status.code(), Some(0), "window show should exit 0");
    let shown = parse_single_json(&show.stdout);
    assert_eq!(shown["window_id"], serde_json::json!("w1"));
    assert_eq!(shown["tabs"], serde_json::json!([]));

    // It is local-only: the workspace daemon socket is never created.
    assert!(
        !ws.socket.exists(),
        "window create must not create a daemon socket"
    );
}

#[test]
fn window_open_tab_then_show_returns_the_persisted_tab() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    assert_eq!(
        run_window(&ws.base, &["create", "--window-id", "w1"])
            .status
            .code(),
        Some(0)
    );

    let out = run_window(
        &ws.base,
        &[
            "open-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--session-id",
            "s1",
            "--title",
            "First",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "open-tab should exit 0");
    assert!(out.stderr.is_empty());
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["command"], serde_json::json!("window open-tab"));
    assert_eq!(value["tabs"].as_array().map(|a| a.len()), Some(1));
    let tab = &value["tabs"][0];
    assert_eq!(tab["tab_id"], serde_json::json!("t1"));
    assert_eq!(tab["session_id"], serde_json::json!("s1"));
    assert_eq!(tab["title"], serde_json::json!("First"));
    assert_eq!(tab["index"], serde_json::json!(0));
    assert_eq!(tab["pinned"], serde_json::json!(false));
    // The default attention object is present with snake_case strings.
    assert_eq!(tab["attention"]["attention"], serde_json::json!("none"));
    assert_eq!(tab["attention"]["source"], serde_json::json!("process"));

    // `show` returns the SAME persisted tab.
    let out = run_window(&ws.base, &["show", "--window-id", "w1"]);
    assert_eq!(out.status.code(), Some(0));
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["command"], serde_json::json!("window show"));
    assert_eq!(value["tabs"][0]["tab_id"], serde_json::json!("t1"));
    assert_eq!(value["tabs"][0]["session_id"], serde_json::json!("s1"));

    assert!(
        !ws.socket.exists(),
        "window open-tab/show must not create a daemon socket"
    );
}

#[test]
fn window_view_joins_session_and_agent_task_fields() {
    use maestro_shell::paths::{AppPaths, RecordKind};
    use maestro_shell::records::{AgentTask, AgentTaskState, SessionStatus};
    use maestro_shell::store;

    maybe_run_fake_daemon();
    let ws = Workspace::new();

    // A session + one-tab window pointing at it (status persisted as Live below). This also seeds the
    // project p-1 → workspace ws-1 chain the session and task both need.
    write_session_with_window(&ws.base, "s1", "w1", "t1");

    // An agent task whose current session is this tab's session, so the view joins task fields.
    // Written BEFORE the live-session rewrite: the session's agent_task_id points at it
    // (sessions.agent_task_id → agent_tasks), so the task row must exist first.
    let paths = AppPaths::with_base(&ws.base);
    let task = AgentTask {
        agent_task_id: "task-1".into(),
        project_id: "p-1".into(),
        goal: "do the thing".into(),
        state: AgentTaskState::Running,
        current_session_id: Some("s1".into()),
        session_history: vec!["s1".into()],
        created_at_ms: 1,
        updated_at_ms: 1,
        result_summary: None,
    };
    store::write_record(&paths, RecordKind::AgentTask, "task-1", 1, &task)
        .expect("write agent task");

    // Overwrite the session status to Live so the view's join reports it.
    {
        use maestro_shell::records::{LaunchSpec, SessionKind, SessionRecord};
        let session = SessionRecord {
            session_id: "s1".into(),
            workspace_id: "ws-1".into(),
            kind: SessionKind::Agent,
            launch: LaunchSpec::KnownSafe {
                launch_spec_id: "ls-1".into(),
                params: vec![],
            },
            cwd_resolved: "/tmp".into(),
            agent_task_id: Some("task-1".into()),
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status: SessionStatus::Live,
        };
        store::write_record(&paths, RecordKind::Session, "s1", 1, &session)
            .expect("rewrite live session");
    }

    let out = run_window(&ws.base, &["view", "--window-id", "w1"]);
    assert_eq!(out.status.code(), Some(0), "window view should exit 0");
    assert!(out.stderr.is_empty());
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["command"], serde_json::json!("window view"));
    assert_eq!(value["window_id"], serde_json::json!("w1"));
    let tab = &value["tabs"][0];
    assert_eq!(tab["session_id"], serde_json::json!("s1"));
    assert_eq!(tab["session_status"], serde_json::json!("live"));
    assert_eq!(tab["agent_task_id"], serde_json::json!("task-1"));
    assert_eq!(tab["agent_task_state"], serde_json::json!("running"));
    assert!(tab["needs_attention"].is_boolean());
    assert_eq!(tab["session_record_missing"], serde_json::json!(false));

    assert!(
        !ws.socket.exists(),
        "window view must not create a daemon socket"
    );
}

#[test]
fn window_open_tab_on_missing_window_fails_with_window_failed() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    // No `create` first: open-tab on a non-existent window is a service failure (not a parse error).
    let out = run_window(
        &ws.base,
        &[
            "open-tab",
            "--window-id",
            "ghost",
            "--tab-id",
            "t1",
            "--session-id",
            "s1",
            "--title",
            "First",
        ],
    );
    assert_eq!(out.status.code(), Some(1), "missing window should exit 1");
    assert!(out.stdout.is_empty(), "stdout empty on failure");
    let value = parse_single_json(&out.stderr);
    assert_eq!(value["ok"], serde_json::json!(false));
    assert_eq!(value["command"], serde_json::json!("window open-tab"));
    assert_eq!(value["error_kind"], serde_json::json!("window_failed"));
}

#[test]
fn window_bad_usage_exits_two_with_single_bad_usage_json() {
    maybe_run_fake_daemon();
    // Missing required --window-id is a parse error: exit 2, one bad_usage JSON on stderr.
    let out = Command::new(APP_BIN)
        .arg("window")
        .arg("create")
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app window create with no flags");
    assert_eq!(out.status.code(), Some(2), "bad usage should exit 2");
    assert!(out.stdout.is_empty(), "stdout empty on bad usage");
    let value = parse_single_json(&out.stderr);
    assert_eq!(value["ok"], serde_json::json!(false));
    assert_eq!(value["command"], serde_json::json!("window create"));
    assert_eq!(value["error_kind"], serde_json::json!("bad_usage"));
}

// ============================================================================================
// 9. window mutations: close-tab / rename-tab / pin-tab / reorder-tabs / attention
// ============================================================================================

/// Create window `w1` with three tabs `t1`/`t2`/`t3` (sessions `s1`/`s2`/`s3`) via the existing
/// `create` + `open-tab` commands. Asserts each step exits 0 so a mutation test starts from a known
/// 3-tab layout. Returns nothing; the layout is persisted under `base`.
fn seed_three_tab_window(base: &Path) {
    assert_eq!(
        run_window(base, &["create", "--window-id", "w1"])
            .status
            .code(),
        Some(0),
        "seed create"
    );
    for (tab, session, title) in [
        ("t1", "s1", "First"),
        ("t2", "s2", "Second"),
        ("t3", "s3", "Third"),
    ] {
        let out = run_window(
            base,
            &[
                "open-tab",
                "--window-id",
                "w1",
                "--tab-id",
                tab,
                "--session-id",
                session,
                "--title",
                title,
            ],
        );
        assert_eq!(out.status.code(), Some(0), "seed open-tab {tab}");
    }
}

/// The ordered `(tab_id, index)` pairs from a window success/show JSON value.
fn tab_order(value: &serde_json::Value) -> Vec<(String, u64)> {
    value["tabs"]
        .as_array()
        .expect("tabs array")
        .iter()
        .map(|t| {
            (
                t["tab_id"].as_str().expect("tab_id").to_string(),
                t["index"].as_u64().expect("index"),
            )
        })
        .collect()
}

#[test]
fn window_close_tab_removes_tab_and_compacts_indices() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    seed_three_tab_window(&ws.base);

    let out = run_window(
        &ws.base,
        &["close-tab", "--window-id", "w1", "--tab-id", "t2"],
    );
    assert_eq!(out.status.code(), Some(0), "close-tab should exit 0");
    assert!(out.stderr.is_empty());
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["command"], serde_json::json!("window close-tab"));
    // t2 is gone and indices are compacted: t1@0, t3@1.
    assert_eq!(
        tab_order(&value),
        vec![("t1".to_string(), 0), ("t3".to_string(), 1)]
    );

    assert!(
        !ws.socket.exists(),
        "window close-tab must not create a daemon socket"
    );
}

#[test]
fn window_rename_tab_changes_title_only() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    seed_three_tab_window(&ws.base);

    let out = run_window(
        &ws.base,
        &[
            "rename-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t2",
            "--title",
            "Renamed",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "rename-tab should exit 0");
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["command"], serde_json::json!("window rename-tab"));
    // Order preserved, only t2's title changed.
    assert_eq!(
        tab_order(&value),
        vec![
            ("t1".to_string(), 0),
            ("t2".to_string(), 1),
            ("t3".to_string(), 2)
        ]
    );
    assert_eq!(value["tabs"][1]["title"], serde_json::json!("Renamed"));
    assert_eq!(value["tabs"][0]["title"], serde_json::json!("First"));
    assert_eq!(value["tabs"][2]["title"], serde_json::json!("Third"));

    assert!(!ws.socket.exists());
}

#[test]
fn window_pin_tab_changes_pinned_only() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    seed_three_tab_window(&ws.base);

    let out = run_window(
        &ws.base,
        &[
            "pin-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t2",
            "--pinned",
            "true",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "pin-tab should exit 0");
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["command"], serde_json::json!("window pin-tab"));
    assert_eq!(
        tab_order(&value),
        vec![
            ("t1".to_string(), 0),
            ("t2".to_string(), 1),
            ("t3".to_string(), 2)
        ]
    );
    assert_eq!(value["tabs"][1]["pinned"], serde_json::json!(true));
    assert_eq!(value["tabs"][0]["pinned"], serde_json::json!(false));
    assert_eq!(value["tabs"][2]["pinned"], serde_json::json!(false));

    assert!(!ws.socket.exists());
}

#[test]
fn window_reorder_tabs_changes_order_and_indices() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    seed_three_tab_window(&ws.base);

    let out = run_window(
        &ws.base,
        &["reorder-tabs", "--window-id", "w1", "--order", "t3,t1,t2"],
    );
    assert_eq!(out.status.code(), Some(0), "reorder-tabs should exit 0");
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["command"], serde_json::json!("window reorder-tabs"));
    assert_eq!(
        tab_order(&value),
        vec![
            ("t3".to_string(), 0),
            ("t1".to_string(), 1),
            ("t2".to_string(), 2)
        ]
    );

    assert!(!ws.socket.exists());
}

#[test]
fn window_attention_sets_attention_object() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    seed_three_tab_window(&ws.base);

    let out = run_window(
        &ws.base,
        &[
            "attention",
            "--window-id",
            "w1",
            "--tab-id",
            "t2",
            "--attention",
            "needs_input",
            "--unseen",
            "true",
            "--source",
            "agent",
            "--since-ms",
            "12345",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "attention should exit 0");
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["command"], serde_json::json!("window attention"));
    // Order preserved; only t2's attention object changed.
    assert_eq!(
        tab_order(&value),
        vec![
            ("t1".to_string(), 0),
            ("t2".to_string(), 1),
            ("t3".to_string(), 2)
        ]
    );
    let att = &value["tabs"][1]["attention"];
    assert_eq!(att["attention"], serde_json::json!("needs_input"));
    assert_eq!(att["unseen"], serde_json::json!(true));
    assert_eq!(att["source"], serde_json::json!("agent"));
    assert_eq!(att["since_ms"], serde_json::json!(12345));
    // Untouched tab keeps the default attention object.
    assert_eq!(
        value["tabs"][0]["attention"]["attention"],
        serde_json::json!("none")
    );

    assert!(!ws.socket.exists());
}

/// `window attention-clear` resets a tab's persisted unseen non-`none` attention to the
/// seen/none user-cleared state, and a following no-render tab-strip projection drops the
/// persisted attention indicator for that tab (no task-derived attention exists here).
#[test]
fn window_attention_clear_resets_persisted_attention() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    // t2 (index 1, session s-other) starts at `activity` + `unseen:true`.
    write_two_tab_window_with_attention(&ws.base);

    let out = run_window(
        &ws.base,
        &["attention-clear", "--window-id", "w1", "--tab-id", "t2"],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "attention-clear should exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value = parse_single_json(&out.stdout);
    assert_eq!(
        value["command"],
        serde_json::json!("window attention-clear")
    );
    // Both tabs are still present (no tab dropped/reordered by the clear).
    let tabs = value["tabs"].as_array().expect("tabs array");
    assert_eq!(tabs.len(), 2);
    let t2 = tabs
        .iter()
        .find(|t| t["tab_id"] == serde_json::json!("t2"))
        .expect("t2 present");
    // t2's attention is cleared to none / unseen:false / source:user.
    let att = &t2["attention"];
    assert_eq!(att["attention"], serde_json::json!("none"));
    assert_eq!(att["unseen"], serde_json::json!(false));
    assert_eq!(att["source"], serde_json::json!("user"));
    // The untouched tab keeps its persisted attention object.
    let t1 = tabs
        .iter()
        .find(|t| t["tab_id"] == serde_json::json!("t1"))
        .expect("t1 present");
    assert_eq!(t1["attention"]["attention"], serde_json::json!("none"));

    // A following no-render tab-strip projection has a null persisted attention indicator for
    // t2, since its persisted attention is now `none` and no task-derived attention exists.
    let view = run_window(&ws.base, &["view", "--window-id", "w1"]);
    assert_eq!(view.status.code(), Some(0), "window view should exit 0");
    let vjson = parse_single_json(&view.stdout);
    let t2 = vjson["tabs"]
        .as_array()
        .expect("tabs array")
        .iter()
        .find(|t| t["tab_id"] == serde_json::json!("t2"))
        .expect("t2 present in view");
    assert_eq!(t2["attention"]["attention"], serde_json::json!("none"));
    assert_eq!(t2["needs_attention"], serde_json::json!(false));

    assert!(!ws.socket.exists());
}

#[test]
fn window_reorder_invalid_fails_and_leaves_layout_unchanged() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    seed_three_tab_window(&ws.base);

    // An order missing t3 is not an exact permutation: the service rejects it as window_failed.
    let out = run_window(
        &ws.base,
        &["reorder-tabs", "--window-id", "w1", "--order", "t1,t2"],
    );
    assert_eq!(out.status.code(), Some(1), "invalid reorder should exit 1");
    assert!(out.stdout.is_empty(), "stdout empty on failure");
    let value = parse_single_json(&out.stderr);
    assert_eq!(value["ok"], serde_json::json!(false));
    assert_eq!(value["command"], serde_json::json!("window reorder-tabs"));
    assert_eq!(value["error_kind"], serde_json::json!("window_failed"));

    // The persisted layout is unchanged: t1/t2/t3 in original order.
    let show = run_window(&ws.base, &["show", "--window-id", "w1"]);
    assert_eq!(show.status.code(), Some(0));
    let shown = parse_single_json(&show.stdout);
    assert_eq!(
        tab_order(&shown),
        vec![
            ("t1".to_string(), 0),
            ("t2".to_string(), 1),
            ("t3".to_string(), 2)
        ]
    );

    assert!(!ws.socket.exists());
}

#[test]
fn window_mutation_bad_usage_exits_two() {
    maybe_run_fake_daemon();
    // pin-tab with an invalid --pinned value is a parse error: exit 2, one bad_usage JSON stamped
    // with the attempted subcommand on stderr.
    let out = Command::new(APP_BIN)
        .arg("window")
        .arg("pin-tab")
        .arg("--window-id")
        .arg("w1")
        .arg("--tab-id")
        .arg("t1")
        .arg("--pinned")
        .arg("maybe")
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app window pin-tab with bad --pinned");
    assert_eq!(out.status.code(), Some(2), "bad usage should exit 2");
    assert!(out.stdout.is_empty(), "stdout empty on bad usage");
    let value = parse_single_json(&out.stderr);
    assert_eq!(value["ok"], serde_json::json!(false));
    assert_eq!(value["command"], serde_json::json!("window pin-tab"));
    assert_eq!(value["error_kind"], serde_json::json!("bad_usage"));
}

// ============================================================================================
// 10. launch --record-window: opt-in window/tab layout recording
// ============================================================================================

#[test]
fn launch_record_window_defaults_record_session_into_main_window() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    let out = headless_launch(&ws)
        .arg("--record-window")
        .arg("--session-id")
        .arg("rec-sess")
        .output()
        .expect("run headless launch --record-window");

    assert_eq!(out.status.code(), Some(0), "recorded launch should exit 0");
    assert_stderr_quiet(&out.stderr);

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["window_recorded"], serde_json::json!(true));
    assert_eq!(value["window_id"], serde_json::json!("main"));
    assert_eq!(value["tab_id"], serde_json::json!("rec-sess"));

    // The layout is persisted under the default window id (SQLite-backed; no per-window JSON file).
    // Persistence is proven below by reading it back through `window show`.

    // `window show` reflects exactly one tab pointing at the launched session id.
    let show = run_window(&ws.base, &["show", "--window-id", "main"]);
    assert_eq!(show.status.code(), Some(0), "window show should exit 0");
    let layout = parse_single_json(&show.stdout);
    let tabs = layout["tabs"].as_array().expect("tabs array");
    assert_eq!(tabs.len(), 1, "exactly one recorded tab");
    assert_eq!(tabs[0]["tab_id"], serde_json::json!("rec-sess"));
    assert_eq!(tabs[0]["session_id"], serde_json::json!("rec-sess"));
    assert_eq!(tabs[0]["title"], serde_json::json!("rec-sess"));
    assert_eq!(tabs[0]["pinned"], serde_json::json!(false));
}

#[test]
fn launch_record_window_unrecorded_default_reports_false_and_nulls() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    let out = headless_launch(&ws)
        .arg("--session-id")
        .arg("plain-sess")
        .output()
        .expect("run plain headless launch");

    assert_eq!(out.status.code(), Some(0), "plain launch should exit 0");
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["window_recorded"], serde_json::json!(false));
    assert_eq!(value["window_id"], serde_json::json!(null));
    assert_eq!(value["tab_id"], serde_json::json!(null));

    // A normal launch records nothing.
    assert!(
        !ws.base.join("windows").join("main.json").exists(),
        "plain launch must not create a window layout record"
    );
}

#[test]
fn launch_record_window_explicit_ids_title_and_pinned_are_persisted() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    let out = headless_launch(&ws)
        .arg("--session-id")
        .arg("s-explicit")
        .arg("--record-window")
        .arg("--window-id")
        .arg("work")
        .arg("--tab-id")
        .arg("tab-7")
        .arg("--tab-title")
        .arg("Build Log")
        .arg("--tab-pinned")
        .arg("true")
        .output()
        .expect("run headless launch with explicit record flags");

    assert_eq!(out.status.code(), Some(0), "recorded launch should exit 0");
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["window_recorded"], serde_json::json!(true));
    assert_eq!(value["window_id"], serde_json::json!("work"));
    assert_eq!(value["tab_id"], serde_json::json!("tab-7"));

    let show = run_window(&ws.base, &["show", "--window-id", "work"]);
    let layout = parse_single_json(&show.stdout);
    let tabs = layout["tabs"].as_array().expect("tabs array");
    assert_eq!(tabs.len(), 1);
    assert_eq!(tabs[0]["tab_id"], serde_json::json!("tab-7"));
    assert_eq!(tabs[0]["session_id"], serde_json::json!("s-explicit"));
    assert_eq!(tabs[0]["title"], serde_json::json!("Build Log"));
    assert_eq!(tabs[0]["pinned"], serde_json::json!(true));
}

#[test]
fn launch_record_window_existing_tab_is_left_unchanged() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    // First recording creates the tab with a known title/pinned via explicit flags.
    let first = headless_launch(&ws)
        .arg("--session-id")
        .arg("s-dup")
        .arg("--record-window")
        .arg("--window-id")
        .arg("main")
        .arg("--tab-id")
        .arg("tab-dup")
        .arg("--tab-title")
        .arg("Original")
        .arg("--tab-pinned")
        .arg("true")
        .output()
        .expect("first recorded launch");
    assert_eq!(first.status.code(), Some(0), "first launch should exit 0");

    // Second launch reuses the same window/tab id but with different title/pinned. It must NOT fail
    // just because the tab exists, and must NOT mutate the pre-existing tab.
    let second = headless_launch(&ws)
        .arg("--session-id")
        .arg("s-dup-2")
        .arg("--record-window")
        .arg("--window-id")
        .arg("main")
        .arg("--tab-id")
        .arg("tab-dup")
        .arg("--tab-title")
        .arg("Changed")
        .arg("--tab-pinned")
        .arg("false")
        .output()
        .expect("second recorded launch");
    assert_eq!(
        second.status.code(),
        Some(0),
        "second launch should not fail only because the tab already exists"
    );
    let value = parse_single_json(&second.stdout);
    assert_eq!(value["window_recorded"], serde_json::json!(true));
    assert_eq!(value["tab_id"], serde_json::json!("tab-dup"));

    // The persisted tab is unchanged from the first recording: same single tab, original
    // title/pinned/session id.
    let show = run_window(&ws.base, &["show", "--window-id", "main"]);
    let layout = parse_single_json(&show.stdout);
    let tabs = layout["tabs"].as_array().expect("tabs array");
    assert_eq!(tabs.len(), 1, "no duplicate tab is added");
    assert_eq!(tabs[0]["tab_id"], serde_json::json!("tab-dup"));
    assert_eq!(tabs[0]["session_id"], serde_json::json!("s-dup"));
    assert_eq!(tabs[0]["title"], serde_json::json!("Original"));
    assert_eq!(tabs[0]["pinned"], serde_json::json!(true));
}

#[test]
fn launch_record_window_failure_before_session_creates_no_layout() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let missing_cwd = ws.dir.path().join("does-not-exist");

    // A bad --cwd fails BEFORE the session is started, so recording is never reached.
    let out = headless_launch(&ws)
        .arg("--session-id")
        .arg("never")
        .arg("--cwd")
        .arg(&missing_cwd)
        .arg("--record-window")
        .output()
        .expect("run headless launch with bad cwd");

    assert_ne!(
        out.status.code(),
        Some(0),
        "a pre-session failure should not exit 0"
    );
    assert!(out.stdout.is_empty(), "stdout empty on launch failure");

    // No window layout record was created for a session that never launched.
    assert!(
        !ws.base.join("windows").join("main.json").exists(),
        "a pre-session failure must not create a window layout record"
    );
}

// ============================================================================================
// 11. agent-start --record-window: opt-in window/tab layout recording for agent tasks
// ============================================================================================

/// Run `agent-start` against the fake-daemon wrapper, returning the spawned command's output.
/// The daemon is kept on success, so callers must clean it up via `kill_kept_daemon`.
struct AgentStartRun {
    status: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_agent_start_record(ws: &Workspace, extra: &[&str], cwd: &Path) -> AgentStartRun {
    // FK chain for the agent session: the command creates the AgentTask (project_id p-1) and writes a
    // SessionRecord under workspace ws-1, so both the project and the workspace must exist first
    // (agent_tasks.project_id → projects, sessions.workspace_id → workspaces).
    seed_workspace(&ws.base, "ws-1", "p-1");
    let pidfile = ws.dir.path().join("daemon.pid");
    let wrapper = write_fake_daemon_wrapper_with_pidfile(ws.dir.path(), Some(&pidfile));

    let mut cmd = Command::new(APP_BIN);
    cmd.arg("agent-start")
        .arg("--agent-task-id")
        .arg("t-rec")
        .arg("--project-id")
        .arg("p-1")
        .arg("--goal")
        .arg("ship the update")
        .arg("--session-id")
        .arg("s-rec")
        .arg("--workspace-id")
        .arg("ws-1")
        .arg("--cwd")
        .arg(cwd)
        .arg("--socket")
        .arg(&ws.socket)
        .arg("--base")
        .arg(&ws.base)
        .arg("--daemon")
        .arg(&wrapper);
    for a in extra {
        cmd.arg(a);
    }
    let out = cmd
        .arg("--")
        .arg("/bin/cat")
        .stdin(Stdio::null())
        .output()
        .expect("run agent-start");

    let status = out.status.code();
    let stdout = out.stdout.clone();
    let stderr = out.stderr.clone();
    // The fake daemon is kept on success; clean it up regardless of assertions.
    kill_kept_daemon(&pidfile, &ws.socket);
    AgentStartRun {
        status,
        stdout,
        stderr,
    }
}

#[test]
fn agent_start_record_window_defaults_record_task_into_main_window() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let cwd = ws.dir.path().join("work");
    std::fs::create_dir_all(&cwd).expect("cwd");

    let run = run_agent_start_record(&ws, &["--record-window"], &cwd);

    assert_eq!(run.status, Some(0), "recorded agent-start should exit 0");
    assert!(run.stderr.is_empty(), "stderr should be empty on success");

    let value = parse_single_json(&run.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["command"], serde_json::json!("agent-start"));
    assert_eq!(value["window_recorded"], serde_json::json!(true));
    assert_eq!(value["window_id"], serde_json::json!("main"));
    // Default tab id is the durable agent task id, NOT the session id.
    assert_eq!(value["tab_id"], serde_json::json!("t-rec"));

    // The layout is persisted (SQLite-backed; no per-window JSON file). Persistence is proven below
    // by reading it back through `window show`.

    // `window show` reflects one tab keyed by the task id but pointing at the live session id.
    let show = run_window(&ws.base, &["show", "--window-id", "main"]);
    assert_eq!(show.status.code(), Some(0), "window show should exit 0");
    let layout = parse_single_json(&show.stdout);
    let tabs = layout["tabs"].as_array().expect("tabs array");
    assert_eq!(tabs.len(), 1, "exactly one recorded tab");
    assert_eq!(tabs[0]["tab_id"], serde_json::json!("t-rec"));
    assert_eq!(tabs[0]["session_id"], serde_json::json!("s-rec"));
    // Default tab title is the goal.
    assert_eq!(tabs[0]["title"], serde_json::json!("ship the update"));
    assert_eq!(tabs[0]["pinned"], serde_json::json!(false));
}

#[test]
fn agent_start_record_window_explicit_ids_title_and_pinned_are_persisted() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let cwd = ws.dir.path().join("work");
    std::fs::create_dir_all(&cwd).expect("cwd");

    let run = run_agent_start_record(
        &ws,
        &[
            "--record-window",
            "--window-id",
            "work",
            "--tab-id",
            "tab-9",
            "--tab-title",
            "Agent Log",
            "--tab-pinned",
            "true",
        ],
        &cwd,
    );

    assert_eq!(run.status, Some(0), "recorded agent-start should exit 0");
    let value = parse_single_json(&run.stdout);
    assert_eq!(value["window_recorded"], serde_json::json!(true));
    assert_eq!(value["window_id"], serde_json::json!("work"));
    assert_eq!(value["tab_id"], serde_json::json!("tab-9"));

    let show = run_window(&ws.base, &["show", "--window-id", "work"]);
    let layout = parse_single_json(&show.stdout);
    let tabs = layout["tabs"].as_array().expect("tabs array");
    assert_eq!(tabs.len(), 1);
    assert_eq!(tabs[0]["tab_id"], serde_json::json!("tab-9"));
    assert_eq!(tabs[0]["session_id"], serde_json::json!("s-rec"));
    assert_eq!(tabs[0]["title"], serde_json::json!("Agent Log"));
    assert_eq!(tabs[0]["pinned"], serde_json::json!(true));
}

#[test]
fn agent_start_unrecorded_default_reports_false_and_nulls() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let cwd = ws.dir.path().join("work");
    std::fs::create_dir_all(&cwd).expect("cwd");

    let run = run_agent_start_record(&ws, &[], &cwd);

    assert_eq!(run.status, Some(0), "plain agent-start should exit 0");
    let value = parse_single_json(&run.stdout);
    assert_eq!(value["window_recorded"], serde_json::json!(false));
    assert_eq!(value["window_id"], serde_json::json!(null));
    assert_eq!(value["tab_id"], serde_json::json!(null));

    assert!(
        !ws.base.join("windows").join("main.json").exists(),
        "plain agent-start must not create a window layout record"
    );
}

#[test]
fn agent_start_record_window_failure_before_session_creates_no_layout() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    // A bad --cwd fails BEFORE the task's first session is started, so recording is never reached.
    let missing_cwd = ws.dir.path().join("does-not-exist");

    let run = run_agent_start_record(&ws, &["--record-window"], &missing_cwd);

    assert_ne!(
        run.status,
        Some(0),
        "a pre-session failure should not exit 0"
    );
    assert!(run.stdout.is_empty(), "stdout empty on agent-start failure");

    assert!(
        !ws.base.join("windows").join("main.json").exists(),
        "a pre-session failure must not create a window layout record"
    );
}

// ============================================================================================
// 12. agent-resume --record-window: opt-in tab-session retarget for resumed agent tasks
// ============================================================================================

/// Seed a Running `AgentTask` whose current session is `s-old`, then run `agent-resume` against the
/// fake daemon resuming it onto a NEW session `s-new`. `extra` carries the layout flags. The daemon
/// is kept on success, so the pidfile is cleaned via `kill_kept_daemon` regardless of assertions.
fn run_agent_resume_record(ws: &Workspace, extra: &[&str], cwd: &Path) -> AgentStartRun {
    use maestro_shell::paths::{AppPaths, RecordKind};
    use maestro_shell::records::{AgentTask, AgentTaskState};
    use maestro_shell::store;

    // FK chain: the task's project p-1 (agent_tasks.project_id → projects) and the resume's session
    // workspace ws-1 (sessions.workspace_id → workspaces) must both exist first.
    seed_workspace(&ws.base, "ws-1", "p-1");

    let paths = AppPaths::with_base(&ws.base);
    let task = AgentTask {
        agent_task_id: "t-resume".into(),
        project_id: "p-1".into(),
        goal: "resume goal".into(),
        state: AgentTaskState::Running,
        current_session_id: Some("s-old".into()),
        session_history: vec![],
        created_at_ms: 1,
        updated_at_ms: 1,
        result_summary: None,
    };
    store::write_record(&paths, RecordKind::AgentTask, &task.agent_task_id, 1, &task)
        .expect("seed task");

    let pidfile = ws.dir.path().join("daemon.pid");
    let wrapper = write_fake_daemon_wrapper_with_pidfile(ws.dir.path(), Some(&pidfile));

    let mut cmd = Command::new(APP_BIN);
    cmd.arg("agent-resume")
        .arg("--agent-task-id")
        .arg("t-resume")
        .arg("--session-id")
        .arg("s-new")
        .arg("--workspace-id")
        .arg("ws-1")
        .arg("--cwd")
        .arg(cwd)
        .arg("--socket")
        .arg(&ws.socket)
        .arg("--base")
        .arg(&ws.base)
        .arg("--daemon")
        .arg(&wrapper);
    for a in extra {
        cmd.arg(a);
    }
    let out = cmd
        .arg("--")
        .arg("/bin/cat")
        .stdin(Stdio::null())
        .output()
        .expect("run agent-resume");

    let status = out.status.code();
    let stdout = out.stdout.clone();
    let stderr = out.stderr.clone();
    kill_kept_daemon(&pidfile, &ws.socket);
    AgentStartRun {
        status,
        stdout,
        stderr,
    }
}

#[test]
fn agent_resume_record_window_absent_tab_opens_new_tab_for_new_session() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let cwd = ws.dir.path().join("work");
    std::fs::create_dir_all(&cwd).expect("cwd");

    let run = run_agent_resume_record(&ws, &["--record-window"], &cwd);

    assert_eq!(run.status, Some(0), "recorded agent-resume should exit 0");
    assert!(run.stderr.is_empty(), "stderr should be empty on success");

    let value = parse_single_json(&run.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["command"], serde_json::json!("agent-resume"));
    assert_eq!(value["window_recorded"], serde_json::json!(true));
    assert_eq!(value["window_id"], serde_json::json!("main"));
    // Default tab id is the durable agent task id.
    assert_eq!(value["tab_id"], serde_json::json!("t-resume"));

    // The newly-opened tab points at the NEW live session.
    let show = run_window(&ws.base, &["show", "--window-id", "main"]);
    assert_eq!(show.status.code(), Some(0), "window show should exit 0");
    let layout = parse_single_json(&show.stdout);
    let tabs = layout["tabs"].as_array().expect("tabs array");
    assert_eq!(tabs.len(), 1, "exactly one recorded tab");
    assert_eq!(tabs[0]["tab_id"], serde_json::json!("t-resume"));
    assert_eq!(tabs[0]["session_id"], serde_json::json!("s-new"));
    // Default tab title is the goal.
    assert_eq!(tabs[0]["title"], serde_json::json!("resume goal"));
    assert_eq!(tabs[0]["pinned"], serde_json::json!(false));
}

#[test]
fn agent_resume_record_window_existing_task_tab_is_retargeted_preserving_fields() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let cwd = ws.dir.path().join("work");
    std::fs::create_dir_all(&cwd).expect("cwd");

    // Seed a layout tab keyed by the task id that currently points at the task's PRIOR session
    // (`s-old`), with a custom title + pinned, so we can prove only `session_id` changes.
    assert_eq!(
        run_window(&ws.base, &["create", "--window-id", "main"])
            .status
            .code(),
        Some(0),
        "seed create"
    );
    assert_eq!(
        run_window(
            &ws.base,
            &[
                "open-tab",
                "--window-id",
                "main",
                "--tab-id",
                "t-resume",
                "--session-id",
                "s-old",
                "--title",
                "Kept Title",
            ],
        )
        .status
        .code(),
        Some(0),
        "seed open-tab"
    );
    assert_eq!(
        run_window(
            &ws.base,
            &[
                "pin-tab",
                "--window-id",
                "main",
                "--tab-id",
                "t-resume",
                "--pinned",
                "true",
            ],
        )
        .status
        .code(),
        Some(0),
        "seed pin-tab"
    );

    let run = run_agent_resume_record(&ws, &["--record-window"], &cwd);

    assert_eq!(run.status, Some(0), "recorded agent-resume should exit 0");
    let value = parse_single_json(&run.stdout);
    assert_eq!(value["window_recorded"], serde_json::json!(true));
    assert_eq!(value["tab_id"], serde_json::json!("t-resume"));

    let show = run_window(&ws.base, &["show", "--window-id", "main"]);
    let layout = parse_single_json(&show.stdout);
    let tabs = layout["tabs"].as_array().expect("tabs array");
    assert_eq!(
        tabs.len(),
        1,
        "still exactly one tab (retarget, not append)"
    );
    // Only the session id moved to the new live session.
    assert_eq!(tabs[0]["session_id"], serde_json::json!("s-new"));
    // Everything else is preserved.
    assert_eq!(tabs[0]["tab_id"], serde_json::json!("t-resume"));
    assert_eq!(tabs[0]["title"], serde_json::json!("Kept Title"));
    assert_eq!(tabs[0]["pinned"], serde_json::json!(true));
    assert_eq!(tabs[0]["index"], serde_json::json!(0));
}

#[test]
fn agent_resume_record_window_unrelated_tab_fails_closed_unchanged() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let cwd = ws.dir.path().join("work");
    std::fs::create_dir_all(&cwd).expect("cwd");

    // Seed a tab with the requested tab id but an UNRELATED session id — neither the new session
    // nor any session in the task's history. Retargeting it would steal an unrelated tab.
    assert_eq!(
        run_window(&ws.base, &["create", "--window-id", "main"])
            .status
            .code(),
        Some(0),
        "seed create"
    );
    assert_eq!(
        run_window(
            &ws.base,
            &[
                "open-tab",
                "--window-id",
                "main",
                "--tab-id",
                "t-resume",
                "--session-id",
                "s-unrelated",
                "--title",
                "Do Not Touch",
            ],
        )
        .status
        .code(),
        Some(0),
        "seed open-tab"
    );
    // Read the persisted layout through the record API (SQLite-backed; no per-window JSON file).
    let before = run_window(&ws.base, &["show", "--window-id", "main"]).stdout;

    let run = run_agent_resume_record(&ws, &["--record-window"], &cwd);

    assert_eq!(run.status, Some(1), "fail-closed should exit 1");
    assert!(run.stdout.is_empty(), "stdout empty on failure");
    let value = parse_single_json(&run.stderr);
    assert_eq!(value["ok"], serde_json::json!(false));
    assert_eq!(value["command"], serde_json::json!("agent-resume"));
    assert_eq!(
        value["error_kind"],
        serde_json::json!("window_record_failed")
    );

    // The persisted layout is unchanged: nothing was retargeted or appended.
    let after = run_window(&ws.base, &["show", "--window-id", "main"]).stdout;
    assert_eq!(before, after, "unrelated-tab refusal must not touch layout");
}

#[test]
fn agent_resume_unrecorded_default_reports_false_and_nulls() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let cwd = ws.dir.path().join("work");
    std::fs::create_dir_all(&cwd).expect("cwd");

    let run = run_agent_resume_record(&ws, &[], &cwd);

    assert_eq!(run.status, Some(0), "plain agent-resume should exit 0");
    let value = parse_single_json(&run.stdout);
    assert_eq!(value["window_recorded"], serde_json::json!(false));
    assert_eq!(value["window_id"], serde_json::json!(null));
    assert_eq!(value["tab_id"], serde_json::json!(null));

    assert!(
        !ws.base.join("windows").join("main.json").exists(),
        "plain agent-resume must not create a window layout record"
    );
}

#[test]
fn agent_resume_record_window_failure_before_session_creates_no_layout() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    // A bad --cwd fails BEFORE a new live session is started, so recording is never reached.
    let missing_cwd = ws.dir.path().join("does-not-exist");

    let run = run_agent_resume_record(&ws, &["--record-window"], &missing_cwd);

    assert_ne!(
        run.status,
        Some(0),
        "a pre-session failure should not exit 0"
    );
    assert!(
        run.stdout.is_empty(),
        "stdout empty on agent-resume failure"
    );

    assert!(
        !ws.base.join("windows").join("main.json").exists(),
        "a pre-session failure must not create a window layout record"
    );
}

// ============================================================================================
// attach-tab: persisted tab -> one active renderer session
// ============================================================================================

/// A missing window record fails as a pure LOCAL lookup BEFORE any daemon is spawned or socket is
/// created: `window_failed` on stderr, non-zero exit, and no socket file is ever created.
#[test]
fn attach_tab_missing_window_fails_before_daemon_spawn() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let daemon = write_fake_daemon_wrapper(ws.dir.path());

    let out = Command::new(APP_BIN)
        .arg("attach-tab")
        .arg("--window-id")
        .arg("no-such-window")
        .arg("--tab-id")
        .arg("t1")
        .arg("--no-run-renderer")
        .arg("--base")
        .arg(&ws.base)
        .arg("--socket")
        .arg(&ws.socket)
        .arg("--daemon")
        .arg(&daemon)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app attach-tab (missing window)");

    assert_ne!(out.status.code(), Some(0), "missing window must not exit 0");
    assert!(out.stdout.is_empty(), "stdout empty on failure");
    let value = parse_single_json(&out.stderr);
    assert_eq!(value["ok"], serde_json::json!(false));
    assert_eq!(value["command"], serde_json::json!("attach-tab"));
    assert_eq!(value["error_kind"], serde_json::json!("window_failed"));
    assert!(
        !ws.socket.exists(),
        "no daemon should be spawned -> no socket created"
    );
}

/// A present window but missing tab fails as a pure LOCAL lookup BEFORE any daemon spawn:
/// `tab_selection_failed` on stderr, non-zero exit, no socket created.
#[test]
fn attach_tab_missing_tab_fails_before_daemon_spawn() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let daemon = write_fake_daemon_wrapper(ws.dir.path());
    write_session_with_window(&ws.base, "s-1", "w1", "t1");

    let out = Command::new(APP_BIN)
        .arg("attach-tab")
        .arg("--window-id")
        .arg("w1")
        .arg("--tab-id")
        .arg("no-such-tab")
        .arg("--no-run-renderer")
        .arg("--base")
        .arg(&ws.base)
        .arg("--socket")
        .arg(&ws.socket)
        .arg("--daemon")
        .arg(&daemon)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app attach-tab (missing tab)");

    assert_ne!(out.status.code(), Some(0), "missing tab must not exit 0");
    assert!(out.stdout.is_empty(), "stdout empty on failure");
    let value = parse_single_json(&out.stderr);
    assert_eq!(value["ok"], serde_json::json!(false));
    assert_eq!(value["command"], serde_json::json!("attach-tab"));
    assert_eq!(
        value["error_kind"],
        serde_json::json!("tab_selection_failed")
    );
    assert!(
        !ws.socket.exists(),
        "no daemon should be spawned -> no socket created"
    );
}

/// `--no-run-renderer` against an existing layout whose session the daemon reports LIVE succeeds:
/// exit 0, the selected tab/session is echoed in the success JSON, the renderer is not started, and
/// the command neither creates a new session record nor mutates the window layout.
#[test]
fn attach_tab_no_run_succeeds_for_live_session() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    write_session_with_window(&ws.base, "s-live", "w1", "t1");
    // The persistent stub IS the daemon: it is already bound, so `ensure_daemon` reuses it.
    spawn_persistent_sessions_stub(ws.socket.clone(), vec!["s-live".into()]);

    // Snapshot the layout before the command (via the record API; SQLite-backed, no JSON file), to
    // assert it is not mutated.
    let before = run_window(&ws.base, &["show", "--window-id", "w1"]).stdout;
    let sessions_before = count_session_records(&ws.base);

    let out = Command::new(APP_BIN)
        .arg("attach-tab")
        .arg("--window-id")
        .arg("w1")
        .arg("--tab-id")
        .arg("t1")
        .arg("--no-run-renderer")
        .arg("--base")
        .arg(&ws.base)
        .arg("--socket")
        .arg(&ws.socket)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app attach-tab --no-run-renderer");

    assert_eq!(
        out.status.code(),
        Some(0),
        "no-run attach-tab for a live session should exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stderr.is_empty(), "stderr empty on success");

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["command"], serde_json::json!("attach-tab"));
    assert_eq!(value["window_id"], serde_json::json!("w1"));
    assert_eq!(value["tab_id"], serde_json::json!("t1"));
    assert_eq!(value["session_id"], serde_json::json!("s-live"));
    assert_eq!(value["renderer_started"], serde_json::json!(false));
    assert_eq!(
        value["window_title"],
        serde_json::json!("Hydra - title"),
        "default window title uses the tab title"
    );
    // Default one-window UX: the foreground/no-run dashboard status suffix defaults ON, so the
    // composed status label carries the compact read-only counts without an explicit flag.
    assert_eq!(
        value["status_label"],
        serde_json::json!(
            "Hydra · w1/t1 · s-live · [active=0 waiting=0 blocked=0 failed=0 attn=0]"
        )
    );

    // The success JSON carries the tab-strip model for the loaded window with the selected tab
    // marked active.
    let strip = &value["tab_strip"];
    assert_eq!(strip["window_id"], serde_json::json!("w1"));
    assert_eq!(strip["active_tab_id"], serde_json::json!("t1"));
    let tabs = strip["tabs"]
        .as_array()
        .expect("tab_strip.tabs is an array");
    assert_eq!(tabs.len(), 1, "single persisted tab present in the strip");
    assert_eq!(tabs[0]["tab_id"], serde_json::json!("t1"));
    assert_eq!(tabs[0]["session_id"], serde_json::json!("s-live"));
    assert_eq!(tabs[0]["active"], serde_json::json!(true));
    assert_eq!(tabs[0]["pinned"], serde_json::json!(false));
    assert_eq!(tabs[0]["needs_attention"], serde_json::json!(false));
    assert_eq!(tabs[0]["attention"]["attention"], serde_json::json!("none"));

    // No new session record, no layout mutation.
    assert_eq!(
        count_session_records(&ws.base),
        sessions_before,
        "attach-tab must not create a session record"
    );
    let after = run_window(&ws.base, &["show", "--window-id", "w1"]).stdout;
    assert_eq!(
        before, after,
        "attach-tab must not mutate the window layout"
    );
}

/// `attach-tab --command-palette --no-run-renderer` reports the read-only command-palette model in the
/// success JSON (with its preview rows) and does NOT start the renderer. Browse-only: no GUI opens.
#[test]
fn attach_tab_no_run_reports_command_palette() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    write_session_with_window(&ws.base, "s-live", "w1", "t1");
    spawn_persistent_sessions_stub(ws.socket.clone(), vec!["s-live".into()]);

    let out = Command::new(APP_BIN)
        .arg("attach-tab")
        .arg("--window-id")
        .arg("w1")
        .arg("--tab-id")
        .arg("t1")
        .arg("--command-palette")
        .arg("--no-run-renderer")
        .arg("--base")
        .arg(&ws.base)
        .arg("--socket")
        .arg(&ws.socket)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app attach-tab --command-palette --no-run-renderer");

    assert_eq!(
        out.status.code(),
        Some(0),
        "no-run attach-tab --command-palette should exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stderr.is_empty(), "stderr empty on success");

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["renderer_started"], serde_json::json!(false));

    let palette = &value["command_palette"];
    assert_eq!(palette["ok"], serde_json::json!(true));
    assert_eq!(palette["command"], serde_json::json!("command-palette"));
    // The preview is always attached for the overlay path.
    let preview = &palette["preview"];
    assert_eq!(preview["title"], serde_json::json!("Command Palette"));
    let rows = preview["rows"]
        .as_array()
        .expect("preview.rows is an array");
    assert!(!rows.is_empty(), "unfiltered palette has catalog rows");
    // No query was supplied: the palette echoes no query.
    assert!(palette["query"].is_null());
}

/// `attach-tab --command-palette --command-palette-query <text> --no-run-renderer` filters the palette
/// rows (fewer than the unfiltered catalog) and echoes the normalized query.
#[test]
fn attach_tab_no_run_command_palette_query_filters() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    write_session_with_window(&ws.base, "s-live", "w1", "t1");
    spawn_persistent_sessions_stub(ws.socket.clone(), vec!["s-live".into()]);

    let unfiltered = {
        let out = Command::new(APP_BIN)
            .arg("attach-tab")
            .arg("--window-id")
            .arg("w1")
            .arg("--tab-id")
            .arg("t1")
            .arg("--command-palette")
            .arg("--no-run-renderer")
            .arg("--base")
            .arg(&ws.base)
            .arg("--socket")
            .arg(&ws.socket)
            .stdin(Stdio::null())
            .output()
            .expect("run unfiltered command-palette attach");
        let value = parse_single_json(&out.stdout);
        value["command_palette"]["preview"]["rows"]
            .as_array()
            .expect("rows array")
            .len()
    };

    let out = Command::new(APP_BIN)
        .arg("attach-tab")
        .arg("--window-id")
        .arg("w1")
        .arg("--tab-id")
        .arg("t1")
        .arg("--command-palette")
        .arg("--command-palette-query")
        .arg("settings")
        .arg("--no-run-renderer")
        .arg("--base")
        .arg(&ws.base)
        .arg("--socket")
        .arg(&ws.socket)
        .stdin(Stdio::null())
        .output()
        .expect("run filtered command-palette attach");

    assert_eq!(out.status.code(), Some(0), "filtered query exits 0");
    let value = parse_single_json(&out.stdout);
    let palette = &value["command_palette"];
    assert_eq!(palette["query"], serde_json::json!("settings"));
    let rows = palette["preview"]["rows"]
        .as_array()
        .expect("filtered rows array");
    assert!(
        rows.len() <= unfiltered,
        "filtered rows ({}) should not exceed unfiltered ({unfiltered})",
        rows.len()
    );
    // Every surviving row should mention the query somewhere.
    for row in rows {
        let blob = format!(
            "{} {} {} {} {}",
            row["id"], row["label"], row["category"], row["summary"], row["command"]
        )
        .to_lowercase();
        assert!(
            blob.contains("settings"),
            "filtered row should match query: {row}"
        );
    }
}

/// Without `--command-palette`, the success JSON carries `command_palette: null` (backward-additive:
/// the field is always present, null when the overlay was not requested).
#[test]
fn attach_tab_no_run_command_palette_absent_is_null() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    write_session_with_window(&ws.base, "s-live", "w1", "t1");
    spawn_persistent_sessions_stub(ws.socket.clone(), vec!["s-live".into()]);

    let out = Command::new(APP_BIN)
        .arg("attach-tab")
        .arg("--window-id")
        .arg("w1")
        .arg("--tab-id")
        .arg("t1")
        .arg("--no-run-renderer")
        .arg("--base")
        .arg(&ws.base)
        .arg("--socket")
        .arg(&ws.socket)
        .stdin(Stdio::null())
        .output()
        .expect("run attach-tab without command-palette");

    assert_eq!(out.status.code(), Some(0), "exits 0");
    let value = parse_single_json(&out.stdout);
    assert!(
        value["command_palette"].is_null(),
        "command_palette is null when the flag is absent"
    );
}

/// Persist an `appearance.font_size_px` override, then run a headless `launch --no-run-renderer`:
/// the success JSON must report the persisted size on `renderer_font_size_px` even though no GUI
/// renderer is started. This proves the launch-time settings resolution reaches the success output
/// in the `--no-run-renderer` mode (and, by the same code path, every renderer mode).
#[test]
fn headless_launch_reports_persisted_renderer_font_size() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    // Persist a non-default font size through the real settings command (writes settings.json).
    let set_out = Command::new(APP_BIN)
        .arg("settings")
        .arg("set")
        .arg("appearance.font_size_px")
        .arg("18")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings set");
    assert_eq!(
        set_out.status.code(),
        Some(0),
        "settings set should exit 0; stderr: {}",
        String::from_utf8_lossy(&set_out.stderr)
    );

    let out = headless_launch(&ws).output().expect("run headless launch");
    assert_eq!(out.status.code(), Some(0), "headless launch should exit 0");
    assert_stderr_quiet(&out.stderr);

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["renderer_started"], serde_json::json!(false));
    assert_eq!(
        value["renderer_font_size_px"],
        serde_json::json!(18),
        "launch must report the persisted appearance.font_size_px in every mode"
    );
}

/// With no persisted override, a headless launch reports the historical default font size, proving
/// the field is always present and defaults correctly rather than being omitted.
#[test]
fn headless_launch_reports_default_renderer_font_size_without_override() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    let out = headless_launch(&ws).output().expect("run headless launch");
    assert_eq!(out.status.code(), Some(0), "headless launch should exit 0");

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(
        value["renderer_font_size_px"],
        serde_json::json!(16),
        "launch with no override must report the default font size"
    );
}

/// Persist an `appearance.font_size_px` override, then run `attach-tab --no-run-renderer` against a
/// live session: the success JSON must report the persisted size on `renderer_font_size_px`, proving
/// attach-tab resolves launch-time settings on the same code path and reports them headlessly.
#[test]
fn attach_tab_no_run_reports_persisted_renderer_font_size() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    write_session_with_window(&ws.base, "s-live", "w1", "t1");
    spawn_persistent_sessions_stub(ws.socket.clone(), vec!["s-live".into()]);

    // Persist a non-default font size through the real settings command.
    let set_out = Command::new(APP_BIN)
        .arg("settings")
        .arg("set")
        .arg("appearance.font_size_px")
        .arg("18")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings set");
    assert_eq!(
        set_out.status.code(),
        Some(0),
        "settings set should exit 0; stderr: {}",
        String::from_utf8_lossy(&set_out.stderr)
    );

    let out = Command::new(APP_BIN)
        .arg("attach-tab")
        .arg("--window-id")
        .arg("w1")
        .arg("--tab-id")
        .arg("t1")
        .arg("--no-run-renderer")
        .arg("--base")
        .arg(&ws.base)
        .arg("--socket")
        .arg(&ws.socket)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app attach-tab --no-run-renderer");

    assert_eq!(
        out.status.code(),
        Some(0),
        "no-run attach-tab for a live session should exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["renderer_started"], serde_json::json!(false));
    assert_eq!(
        value["renderer_font_size_px"],
        serde_json::json!(18),
        "attach-tab must report the persisted appearance.font_size_px in every mode"
    );
}

/// Assert the reported `renderer_command` argv carries `--font-size-px <px>` immediately before the
/// socket/session positionals (the detached renderer child form). Returns silently if the command is
/// empty (no renderer binary resolvable in the test environment) — the font-size resolution is proven
/// independently by the `renderer_font_size_px` field assertions.
fn assert_renderer_command_has_font_size(value: &serde_json::Value, px: &str) {
    let cmd: Vec<String> = value["renderer_command"]
        .as_array()
        .expect("renderer_command is an array")
        .iter()
        .map(|v| v.as_str().expect("argv entries are strings").to_string())
        .collect();
    if cmd.is_empty() {
        return;
    }
    let pos = cmd
        .iter()
        .position(|a| a == "--font-size-px")
        .unwrap_or_else(|| panic!("renderer_command should contain --font-size-px; got {cmd:?}"));
    assert_eq!(
        cmd.get(pos + 1).map(String::as_str),
        Some(px),
        "--font-size-px should be followed by {px}; got {cmd:?}"
    );
    // The flag+value must precede the two trailing positionals (socket, session).
    assert!(
        pos + 1 < cmd.len() - 2,
        "--font-size-px must come before the socket/session positionals; got {cmd:?}"
    );
}

/// Persisted font size plus `launch --no-run-renderer`: the reported `renderer_command` must include
/// `--font-size-px 18` so a detached renderer child would inherit the resolved app font size.
#[test]
fn headless_launch_reports_renderer_command_with_font_size() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    let set_out = Command::new(APP_BIN)
        .arg("settings")
        .arg("set")
        .arg("appearance.font_size_px")
        .arg("18")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings set");
    assert_eq!(set_out.status.code(), Some(0), "settings set should exit 0");

    let out = headless_launch(&ws).output().expect("run headless launch");
    assert_eq!(out.status.code(), Some(0), "headless launch should exit 0");

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_renderer_command_has_font_size(&value, "18");
}

/// Persisted font size plus `attach-tab --no-run-renderer`: the reported `renderer_command` must
/// include `--font-size-px 18` on the detached-child argv it would spawn.
#[test]
fn attach_tab_no_run_reports_renderer_command_with_font_size() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    write_session_with_window(&ws.base, "s-live", "w1", "t1");
    spawn_persistent_sessions_stub(ws.socket.clone(), vec!["s-live".into()]);

    let set_out = Command::new(APP_BIN)
        .arg("settings")
        .arg("set")
        .arg("appearance.font_size_px")
        .arg("18")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings set");
    assert_eq!(set_out.status.code(), Some(0), "settings set should exit 0");

    let out = Command::new(APP_BIN)
        .arg("attach-tab")
        .arg("--window-id")
        .arg("w1")
        .arg("--tab-id")
        .arg("t1")
        .arg("--no-run-renderer")
        .arg("--base")
        .arg(&ws.base)
        .arg("--socket")
        .arg(&ws.socket)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app attach-tab --no-run-renderer");
    assert_eq!(
        out.status.code(),
        Some(0),
        "no-run attach-tab for a live session should exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_renderer_command_has_font_size(&value, "18");
}

/// Assert the reported `renderer_command` argv carries `--theme <id>` before the socket/session
/// positionals (the detached renderer child form). Returns silently if the command is empty (no
/// renderer binary resolvable in the test environment) — the theme resolution is proven independently
/// by the `renderer_theme` field assertions.
fn assert_renderer_command_has_theme(value: &serde_json::Value, theme: &str) {
    let cmd: Vec<String> = value["renderer_command"]
        .as_array()
        .expect("renderer_command is an array")
        .iter()
        .map(|v| v.as_str().expect("argv entries are strings").to_string())
        .collect();
    if cmd.is_empty() {
        return;
    }
    let pos = cmd
        .iter()
        .position(|a| a == "--theme")
        .unwrap_or_else(|| panic!("renderer_command should contain --theme; got {cmd:?}"));
    assert_eq!(
        cmd.get(pos + 1).map(String::as_str),
        Some(theme),
        "--theme should be followed by {theme}; got {cmd:?}"
    );
    assert!(
        pos + 1 < cmd.len() - 2,
        "--theme must come before the socket/session positionals; got {cmd:?}"
    );
}

/// Persist an `appearance.theme` override, then run a headless `launch --no-run-renderer`: the success
/// JSON must report the persisted theme on `renderer_theme` and the reported `renderer_command` must
/// carry `--theme high_contrast_dark`. This proves the launch-time settings resolution threads the
/// theme into the success output and the detached-child argv in every mode (`--no-run-renderer` here).
#[test]
fn headless_launch_reports_persisted_renderer_theme() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    let set_out = Command::new(APP_BIN)
        .arg("settings")
        .arg("set")
        .arg("appearance.theme")
        .arg("high_contrast_dark")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings set appearance.theme");
    assert_eq!(
        set_out.status.code(),
        Some(0),
        "settings set should exit 0; stderr: {}",
        String::from_utf8_lossy(&set_out.stderr)
    );

    let out = headless_launch(&ws).output().expect("run headless launch");
    assert_eq!(out.status.code(), Some(0), "headless launch should exit 0");
    assert_stderr_quiet(&out.stderr);

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["renderer_started"], serde_json::json!(false));
    assert_eq!(
        value["renderer_theme"],
        serde_json::json!("high_contrast_dark"),
        "launch must report the persisted appearance.theme in every mode"
    );
    assert_renderer_command_has_theme(&value, "high_contrast_dark");
}

/// With no persisted override, a headless launch reports the historical default theme, proving the
/// field is always present and defaults to the built-in dark theme rather than being omitted.
#[test]
fn headless_launch_reports_default_renderer_theme_without_override() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    let out = headless_launch(&ws).output().expect("run headless launch");
    assert_eq!(out.status.code(), Some(0), "headless launch should exit 0");

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(
        value["renderer_theme"],
        serde_json::json!("built_in_dark"),
        "launch with no override must report the default theme"
    );
}

/// Persist an `appearance.theme` override, then run `attach-tab --no-run-renderer` against a live
/// session: the success JSON must report the persisted theme on `renderer_theme` and the reported
/// `renderer_command` must carry `--theme high_contrast_dark`, proving attach-tab resolves launch-time
/// settings on the same code path and reports/threads them headlessly.
#[test]
fn attach_tab_no_run_reports_persisted_renderer_theme() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    write_session_with_window(&ws.base, "s-live", "w1", "t1");
    spawn_persistent_sessions_stub(ws.socket.clone(), vec!["s-live".into()]);

    let set_out = Command::new(APP_BIN)
        .arg("settings")
        .arg("set")
        .arg("appearance.theme")
        .arg("high_contrast_dark")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings set appearance.theme");
    assert_eq!(
        set_out.status.code(),
        Some(0),
        "settings set should exit 0; stderr: {}",
        String::from_utf8_lossy(&set_out.stderr)
    );

    let out = Command::new(APP_BIN)
        .arg("attach-tab")
        .arg("--window-id")
        .arg("w1")
        .arg("--tab-id")
        .arg("t1")
        .arg("--no-run-renderer")
        .arg("--base")
        .arg(&ws.base)
        .arg("--socket")
        .arg(&ws.socket)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app attach-tab --no-run-renderer");
    assert_eq!(
        out.status.code(),
        Some(0),
        "no-run attach-tab for a live session should exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["renderer_started"], serde_json::json!(false));
    assert_eq!(
        value["renderer_theme"],
        serde_json::json!("high_contrast_dark"),
        "attach-tab must report the persisted appearance.theme in every mode"
    );
    assert_renderer_command_has_theme(&value, "high_contrast_dark");
}

/// `attach-tab --no-run-renderer` folds task/session-derived attention into the visible tab strip:
/// a tab whose session is the current session of a `WaitingOnUser` agent task surfaces
/// `needs_attention:true` even though its PERSISTED attention is `none` (so `attention` stays null
/// and no state-aware indicator is invented). This proves the read-only legacy `!` fallback path is
/// reachable from records through the joined window-view projection without opening a GUI.
#[test]
fn attach_tab_no_run_strip_reflects_task_derived_attention() {
    use maestro_shell::paths::{AppPaths, RecordKind};
    use maestro_shell::records::{AgentTask, AgentTaskState};
    use maestro_shell::store;

    maybe_run_fake_daemon();
    let ws = Workspace::new();
    // Persisted attention for t1 is `none` (the default written by this helper).
    write_session_with_window(&ws.base, "s-live", "w1", "t1");
    // A WaitingOnUser task whose current session is this tab's session -> task-derived attention.
    let paths = AppPaths::with_base(&ws.base);
    let task = AgentTask {
        agent_task_id: "task-wait".into(),
        project_id: "p-1".into(),
        goal: "needs a human".into(),
        state: AgentTaskState::WaitingOnUser,
        current_session_id: Some("s-live".into()),
        session_history: vec!["s-live".into()],
        created_at_ms: 1,
        updated_at_ms: 1,
        result_summary: None,
    };
    store::write_record(&paths, RecordKind::AgentTask, "task-wait", 1, &task)
        .expect("write waiting-on-user task");
    spawn_persistent_sessions_stub(ws.socket.clone(), vec!["s-live".into()]);

    let out = Command::new(APP_BIN)
        .arg("attach-tab")
        .arg("--window-id")
        .arg("w1")
        .arg("--tab-id")
        .arg("t1")
        .arg("--no-run-renderer")
        .arg("--base")
        .arg(&ws.base)
        .arg("--socket")
        .arg(&ws.socket)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app attach-tab --no-run-renderer (task-derived attention)");

    assert_eq!(
        out.status.code(),
        Some(0),
        "task-derived attention attach-tab should exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let value = parse_single_json(&out.stdout);
    let tabs = value["tab_strip"]["tabs"]
        .as_array()
        .expect("tab_strip.tabs is an array");
    assert_eq!(tabs.len(), 1);
    // Persisted attention is `none` (so no state-aware indicator), but the joined task projection
    // ORs task-derived attention into the boolean -> renderer renders the legacy `!` fallback.
    assert_eq!(
        tabs[0]["needs_attention"],
        serde_json::json!(true),
        "task-derived WaitingOnUser must surface needs_attention:true"
    );
    assert_eq!(
        tabs[0]["attention_indicator"],
        serde_json::Value::Null,
        "no state-aware indicator is invented for task-derived attention"
    );
    assert_eq!(tabs[0]["attention"]["attention"], serde_json::json!("none"));
}

/// `attach-tab --top-tab-bar --no-run-renderer` parses the opt-in flag and reports it back as
/// `top_tab_bar:true` in the success JSON, so the (foreground-only) native top tab-bar opt-in can
/// be inspected without a GUI. The default path reports `false` (covered by the serde unit test).
#[test]
fn attach_tab_top_tab_bar_no_run_reports_flag() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    write_session_with_window(&ws.base, "s-live", "w1", "t1");
    spawn_persistent_sessions_stub(ws.socket.clone(), vec!["s-live".into()]);

    let out = Command::new(APP_BIN)
        .arg("attach-tab")
        .arg("--window-id")
        .arg("w1")
        .arg("--tab-id")
        .arg("t1")
        .arg("--top-tab-bar")
        .arg("--no-run-renderer")
        .arg("--base")
        .arg(&ws.base)
        .arg("--socket")
        .arg(&ws.socket)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app attach-tab --top-tab-bar --no-run-renderer");

    assert_eq!(
        out.status.code(),
        Some(0),
        "no-run attach-tab with --top-tab-bar should exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["renderer_started"], serde_json::json!(false));
    assert_eq!(
        value["top_tab_bar"],
        serde_json::json!(true),
        "the opt-in top tab bar flag is reported back in the success JSON"
    );
}

/// Helper: persist one chrome default via the real `settings set` command against `ws.base`.
fn persist_chrome_default(ws: &Workspace, key: &str, value: &str) {
    let out = Command::new(APP_BIN)
        .arg("settings")
        .arg("set")
        .arg(key)
        .arg(value)
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app settings set chrome default");
    assert_eq!(
        out.status.code(),
        Some(0),
        "settings set {key} {value} should exit 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Helper: run `attach-tab --no-run-renderer` against a seeded live session, returning the success
/// JSON. `extra` carries any additional flags (e.g. an explicit `--top-tab-bar`).
fn attach_tab_no_run_value(ws: &Workspace, extra: &[&str]) -> serde_json::Value {
    let mut cmd = Command::new(APP_BIN);
    cmd.arg("attach-tab")
        .arg("--window-id")
        .arg("w1")
        .arg("--tab-id")
        .arg("t1");
    for arg in extra {
        cmd.arg(arg);
    }
    let out = cmd
        .arg("--no-run-renderer")
        .arg("--base")
        .arg(&ws.base)
        .arg("--socket")
        .arg(&ws.socket)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app attach-tab --no-run-renderer");
    assert_eq!(
        out.status.code(),
        Some(0),
        "no-run attach-tab should exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    parse_single_json(&out.stdout)
}

/// With no persisted chrome overrides, the foreground one-window defaults are ON: `attach-tab`
/// reports `top_tab_bar:true` and the bottom `status_label` carries the dashboard status suffix.
#[test]
fn attach_tab_no_run_default_chrome_is_on() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    write_session_with_window(&ws.base, "s-live", "w1", "t1");
    spawn_persistent_sessions_stub(ws.socket.clone(), vec!["s-live".into()]);

    let value = attach_tab_no_run_value(&ws, &[]);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(
        value["top_tab_bar"],
        serde_json::json!(true),
        "with no override the top tab bar default is ON"
    );
    let label = value["status_label"].as_str().expect("status_label string");
    assert!(
        label.contains("[active="),
        "with no override the dashboard status suffix is appended; got {label:?}"
    );
}

/// A persisted `chrome.top_tab_bar_default false` flips the absent-flag default OFF: `attach-tab`
/// reports `top_tab_bar:false`. Passing `--top-tab-bar` explicitly still wins over the persisted
/// default and reports `true`.
#[test]
fn attach_tab_no_run_persisted_top_tab_bar_default_off() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    write_session_with_window(&ws.base, "s-live", "w1", "t1");
    spawn_persistent_sessions_stub(ws.socket.clone(), vec!["s-live".into()]);
    persist_chrome_default(&ws, "chrome.top_tab_bar_default", "false");

    let off = attach_tab_no_run_value(&ws, &[]);
    assert_eq!(
        off["top_tab_bar"],
        serde_json::json!(false),
        "the persisted top_tab_bar default OFF is honored when the flag is absent"
    );

    let overridden = attach_tab_no_run_value(&ws, &["--top-tab-bar"]);
    assert_eq!(
        overridden["top_tab_bar"],
        serde_json::json!(true),
        "an explicit --top-tab-bar wins over the persisted default-off"
    );
}

/// A persisted `chrome.dashboard_status_default false` flips the absent-flag default OFF: the bottom
/// `status_label` no longer carries the dashboard suffix. Passing `--dashboard-status` explicitly
/// still wins and re-appends the suffix.
#[test]
fn attach_tab_no_run_persisted_dashboard_status_default_off() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    write_session_with_window(&ws.base, "s-live", "w1", "t1");
    spawn_persistent_sessions_stub(ws.socket.clone(), vec!["s-live".into()]);
    persist_chrome_default(&ws, "chrome.dashboard_status_default", "false");

    let off = attach_tab_no_run_value(&ws, &[]);
    let off_label = off["status_label"].as_str().expect("status_label string");
    assert!(
        !off_label.contains("[active="),
        "the persisted dashboard_status default OFF drops the suffix; got {off_label:?}"
    );

    let overridden = attach_tab_no_run_value(&ws, &["--dashboard-status"]);
    let on_label = overridden["status_label"]
        .as_str()
        .expect("status_label string");
    assert!(
        on_label.contains("[active="),
        "an explicit --dashboard-status wins over the persisted default-off; got {on_label:?}"
    );
}

/// `attach-tab --dashboard-panel --no-run-renderer` computes the read-only dashboard panel from the
/// same reconcile report and reports it back as `dashboard_panel.lines` in the success JSON, proving
/// the panel was built without opening a GUI. The default path reports `null` (covered by the serde
/// unit test).
#[test]
fn attach_tab_dashboard_panel_no_run_reports_computed_lines() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    write_session_with_window(&ws.base, "s-live", "w1", "t1");
    spawn_persistent_sessions_stub(ws.socket.clone(), vec!["s-live".into()]);

    let out = Command::new(APP_BIN)
        .arg("attach-tab")
        .arg("--window-id")
        .arg("w1")
        .arg("--tab-id")
        .arg("t1")
        .arg("--dashboard-panel")
        .arg("--no-run-renderer")
        .arg("--base")
        .arg(&ws.base)
        .arg("--socket")
        .arg(&ws.socket)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app attach-tab --dashboard-panel --no-run-renderer");

    assert_eq!(
        out.status.code(),
        Some(0),
        "no-run attach-tab with --dashboard-panel should exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["renderer_started"], serde_json::json!(false));
    let lines = value["dashboard_panel"]["lines"]
        .as_array()
        .expect("dashboard_panel.lines is an array in the success JSON");
    assert!(
        !lines.is_empty(),
        "the computed panel carries at least the title/summary lines"
    );
    assert_eq!(
        lines[0],
        serde_json::json!("Dashboard"),
        "the first computed panel line is the Dashboard title"
    );
}

/// A persisted `chrome.dashboard_panel_default true` flips the absent-flag default ON: a bare
/// `attach-tab --no-run-renderer` (no `--dashboard-panel`) computes and reports the panel lines.
/// Passing `--no-dashboard-panel` explicitly wins over the persisted true and drops the panel
/// (`dashboard_panel` reports `null`).
#[test]
fn attach_tab_no_run_persisted_dashboard_panel_default_on() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    write_session_with_window(&ws.base, "s-live", "w1", "t1");
    spawn_persistent_sessions_stub(ws.socket.clone(), vec!["s-live".into()]);
    persist_chrome_default(&ws, "chrome.dashboard_panel_default", "true");

    // Absent flag: the persisted default-ON builds the panel.
    let on = attach_tab_no_run_value(&ws, &[]);
    let lines = on["dashboard_panel"]["lines"]
        .as_array()
        .expect("persisted default-on builds dashboard_panel.lines");
    assert!(
        !lines.is_empty() && lines[0] == serde_json::json!("Dashboard"),
        "the persisted dashboard_panel default ON computes the panel; got {:?}",
        on["dashboard_panel"]
    );

    // Explicit --no-dashboard-panel wins over the persisted true: no panel.
    let off = attach_tab_no_run_value(&ws, &["--no-dashboard-panel"]);
    assert_eq!(
        off["dashboard_panel"],
        serde_json::Value::Null,
        "an explicit --no-dashboard-panel wins over the persisted default-on; got {:?}",
        off["dashboard_panel"]
    );
}

/// `attach-tab --settings-panel --no-run-renderer` computes the read-only settings panel from the SAME
/// effective settings the renderer font/theme use and reports it back as `settings_panel` in the
/// success JSON, proving the panel was built without opening a GUI. The DTO matches the
/// `settings show --panel-lines` shape (`title == "Settings"`, ordered category lines). The default
/// path keeps `settings_panel` null (covered by the serde unit test).
#[test]
fn attach_tab_settings_panel_no_run_reports_computed_lines() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    write_session_with_window(&ws.base, "s-live", "w1", "t1");
    spawn_persistent_sessions_stub(ws.socket.clone(), vec!["s-live".into()]);

    let value = attach_tab_no_run_value(&ws, &["--settings-panel"]);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["renderer_started"], serde_json::json!(false));

    let panel = &value["settings_panel"];
    assert_eq!(
        panel["title"],
        serde_json::json!("Settings"),
        "the settings panel title is exactly \"Settings\"; got {panel:?}"
    );
    let lines = panel["lines"]
        .as_array()
        .expect("settings_panel.lines is an array in the success JSON");
    assert!(
        !lines.is_empty(),
        "the computed settings panel carries category lines"
    );
    assert_eq!(
        panel["line_count"]
            .as_u64()
            .expect("line_count is a number") as usize,
        lines.len(),
        "line_count mirrors lines.len()"
    );
    let joined = lines
        .iter()
        .map(|l| l.as_str().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("theme:") && joined.contains("source:"),
        "settings panel lines carry appearance/source rows; got {joined:?}"
    );

    // The settings panel is the SOLE top-panel source: dashboard_panel stays null.
    assert_eq!(
        value["dashboard_panel"],
        serde_json::Value::Null,
        "dashboard_panel stays null when --settings-panel is the top-panel source; got {:?}",
        value["dashboard_panel"]
    );
}

/// The settings panel reflects persisted appearance/chrome/shell overrides: after persisting a theme
/// and a shell argv, the computed `settings_panel` lines echo those overridden values. This proves the
/// panel reuses the SAME effective settings the rest of attach-tab resolves, not a defaults snapshot.
#[test]
fn attach_tab_settings_panel_no_run_reflects_persisted_overrides() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    write_session_with_window(&ws.base, "s-live", "w1", "t1");
    spawn_persistent_sessions_stub(ws.socket.clone(), vec!["s-live".into()]);
    persist_chrome_default(&ws, "appearance.theme", "high_contrast_dark");

    let value = attach_tab_no_run_value(&ws, &["--settings-panel"]);
    let lines = value["settings_panel"]["lines"]
        .as_array()
        .expect("settings_panel.lines present");
    let joined = lines
        .iter()
        .map(|l| l.as_str().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined.contains("high_contrast_dark"),
        "the settings panel reflects the persisted theme override; got {joined:?}"
    );
    assert!(
        value["settings_panel"]["summary"]
            .as_str()
            .expect("summary string")
            .contains("overrides"),
        "the panel summary reports overrides as the source; got {:?}",
        value["settings_panel"]["summary"]
    );
}

/// Absent `--settings-panel`, the success JSON keeps `settings_panel` null while the existing
/// `dashboard_panel` behavior is unchanged. Proves the new field is backward-additive and the two
/// panels stay independent.
#[test]
fn attach_tab_no_run_settings_panel_absent_is_null() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    write_session_with_window(&ws.base, "s-live", "w1", "t1");
    spawn_persistent_sessions_stub(ws.socket.clone(), vec!["s-live".into()]);

    let value = attach_tab_no_run_value(&ws, &[]);
    assert_eq!(
        value["settings_panel"],
        serde_json::Value::Null,
        "settings_panel is null when --settings-panel is absent; got {:?}",
        value["settings_panel"]
    );
}

/// The picker overlay is FOREGROUND-IN-PROCESS ONLY: unlike `dashboard_panel`, it is never computed
/// or surfaced under `--no-run-renderer` (`RendererMode::None` always resolves it false regardless of
/// the persisted default). A persisted `chrome.picker_overlay_default true` therefore must NOT leak
/// into the no-run path — the success JSON stays valid and carries no picker field. (`settings show`
/// already proves the default persists; here we prove it cannot surface in no-run.)
#[test]
fn attach_tab_no_run_persisted_picker_overlay_default_on_does_not_surface() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    write_session_with_window(&ws.base, "s-live", "w1", "t1");
    spawn_persistent_sessions_stub(ws.socket.clone(), vec!["s-live".into()]);
    persist_chrome_default(&ws, "chrome.picker_overlay_default", "true");

    // Absent flag with the persisted default ON: no-run still succeeds and the success JSON carries
    // no picker overlay surface (None mode hardcodes picker_overlay false).
    let on = attach_tab_no_run_value(&ws, &[]);
    assert_eq!(on["ok"], serde_json::json!(true));
    assert!(
        on.get("picker").is_none() && on.get("picker_overlay").is_none(),
        "the foreground-only picker overlay default must not leak into --no-run-renderer JSON; got {on:?}"
    );

    // An explicit --no-picker-overlay is a harmless no-op under --no-run-renderer (still succeeds).
    let off = attach_tab_no_run_value(&ws, &["--no-picker-overlay"]);
    assert_eq!(
        off["ok"],
        serde_json::json!(true),
        "--no-picker-overlay is accepted as a no-op with --no-run-renderer; got {off:?}"
    );
}

/// `attach-tab --no-run-renderer` surfaces the FULL persisted window in `tab_strip`, not just the
/// selected tab: both tabs appear in persisted-index order, the selected tab is active exactly once,
/// `pinned` is preserved per tab, and a tab with persisted `unseen + non-none` attention reports
/// `needs_attention:true`.
#[test]
fn attach_tab_no_run_strip_carries_full_window() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    write_two_tab_window_with_attention(&ws.base);
    // The selected tab's session (`s-live`) must be reported live for the attach to succeed.
    spawn_persistent_sessions_stub(ws.socket.clone(), vec!["s-live".into()]);

    let out = Command::new(APP_BIN)
        .arg("attach-tab")
        .arg("--window-id")
        .arg("w1")
        .arg("--tab-id")
        .arg("t1")
        .arg("--no-run-renderer")
        .arg("--base")
        .arg(&ws.base)
        .arg("--socket")
        .arg(&ws.socket)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app attach-tab --no-run-renderer (two-tab window)");

    assert_eq!(
        out.status.code(),
        Some(0),
        "two-tab attach-tab should exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let value = parse_single_json(&out.stdout);
    let strip = &value["tab_strip"];
    assert_eq!(strip["window_id"], serde_json::json!("w1"));
    assert_eq!(strip["active_tab_id"], serde_json::json!("t1"));

    let tabs = strip["tabs"]
        .as_array()
        .expect("tab_strip.tabs is an array");
    assert_eq!(tabs.len(), 2, "both persisted tabs present in the strip");

    // Persisted-index order: t1 (index 0) before t2 (index 1), despite reverse write order.
    assert_eq!(tabs[0]["tab_id"], serde_json::json!("t1"));
    assert_eq!(tabs[0]["index"], serde_json::json!(0));
    assert_eq!(tabs[1]["tab_id"], serde_json::json!("t2"));
    assert_eq!(tabs[1]["index"], serde_json::json!(1));

    // Active exactly once: the selected t1.
    let active_count = tabs
        .iter()
        .filter(|t| t["active"] == serde_json::json!(true))
        .count();
    assert_eq!(active_count, 1, "exactly one active tab");
    assert_eq!(tabs[0]["active"], serde_json::json!(true));
    assert_eq!(tabs[1]["active"], serde_json::json!(false));

    // Pinned preserved per tab.
    assert_eq!(tabs[0]["pinned"], serde_json::json!(false));
    assert_eq!(tabs[1]["pinned"], serde_json::json!(true));

    // Persisted attention surfaces needs_attention: t1 none -> false, t2 activity+unseen -> true.
    assert_eq!(tabs[0]["needs_attention"], serde_json::json!(false));
    assert_eq!(tabs[0]["attention"]["attention"], serde_json::json!("none"));
    assert_eq!(tabs[1]["needs_attention"], serde_json::json!(true));
    assert_eq!(
        tabs[1]["attention"]["attention"],
        serde_json::json!("activity")
    );
    assert_eq!(tabs[1]["attention"]["unseen"], serde_json::json!(true));
    // Nested attention object shape is preserved (source/since_ms present).
    assert_eq!(tabs[1]["attention"]["source"], serde_json::json!("process"));
    assert!(tabs[1]["attention"]["since_ms"].is_u64());

    // State-aware indicator surfaces end-to-end: t1 (none/seen) -> null; t2 (activity+unseen) ->
    // the kind+marker object the renderer draws.
    assert_eq!(tabs[0]["attention_indicator"], serde_json::Value::Null);
    assert_eq!(
        tabs[1]["attention_indicator"]["kind"],
        serde_json::json!("activity")
    );
    assert_eq!(
        tabs[1]["attention_indicator"]["marker"],
        serde_json::json!("~")
    );
}

/// A selected tab whose session the daemon does NOT report live fails with `tab_session_not_live`
/// BEFORE any renderer launch.
#[test]
fn attach_tab_non_live_session_fails_with_typed_error() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    write_session_with_window(&ws.base, "s-ghost", "w1", "t1");
    // Daemon reports a DIFFERENT id live, so the selected session is absent from the live set.
    spawn_persistent_sessions_stub(ws.socket.clone(), vec!["some-other".into()]);

    let out = Command::new(APP_BIN)
        .arg("attach-tab")
        .arg("--window-id")
        .arg("w1")
        .arg("--tab-id")
        .arg("t1")
        .arg("--no-run-renderer")
        .arg("--base")
        .arg(&ws.base)
        .arg("--socket")
        .arg(&ws.socket)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app attach-tab (non-live session)");

    assert_ne!(
        out.status.code(),
        Some(0),
        "a non-live session must not exit 0"
    );
    assert!(out.stdout.is_empty(), "stdout empty on failure");
    let value = parse_single_json(&out.stderr);
    assert_eq!(value["ok"], serde_json::json!(false));
    assert_eq!(value["command"], serde_json::json!("attach-tab"));
    assert_eq!(
        value["error_kind"],
        serde_json::json!("tab_session_not_live")
    );
}

/// attach-tab that SPAWNS the daemon and then fails AFTER spawn must clean the owned socket.
///
/// Unlike [`attach_tab_non_live_session_fails_with_typed_error`] (a pre-started, REUSED stub that is
/// never owned and so never cleaned), this passes `--daemon <fake-wrapper>` against a socket nobody
/// is serving, forcing `ensure_daemon` to SPAWN the fake daemon. The fake answers the `list_sessions`
/// reconcile with an empty live set, so the selected session is non-live and the command fails with
/// `tab_session_not_live` — AFTER the spawn. The un-kept `SpawnedDaemon` drop must then kill the
/// daemon and remove the owned socket, exactly like `launch`'s failure-after-spawn path.
#[test]
fn attach_tab_failure_after_spawn_cleans_owned_socket() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    write_session_with_window(&ws.base, "s-missing", "w1", "t1");
    let daemon = write_fake_daemon_wrapper(ws.dir.path());

    let out = Command::new(APP_BIN)
        .arg("attach-tab")
        .arg("--window-id")
        .arg("w1")
        .arg("--tab-id")
        .arg("t1")
        .arg("--no-run-renderer")
        .arg("--base")
        .arg(&ws.base)
        .arg("--socket")
        .arg(&ws.socket)
        .arg("--daemon")
        .arg(&daemon)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app attach-tab (failure after spawn)");

    assert_ne!(
        out.status.code(),
        Some(0),
        "a non-live session must not exit 0"
    );
    assert!(out.stdout.is_empty(), "stdout empty on failure");
    let value = parse_single_json(&out.stderr);
    assert_eq!(value["ok"], serde_json::json!(false));
    assert_eq!(value["command"], serde_json::json!("attach-tab"));
    assert_eq!(
        value["error_kind"],
        serde_json::json!("tab_session_not_live")
    );

    assert!(
        !ws.socket.exists(),
        "a failure-after-spawn must remove the owned socket"
    );
    assert!(
        !can_connect(&ws.socket),
        "no daemon should remain serving the socket after a failure-after-spawn"
    );
}

/// Count the persisted `SessionRecord`s (SQLite-backed store), for "no new session record"
/// assertions. Reads through the record API rather than counting per-record JSON files (which the
/// SQLite store no longer writes).
fn count_session_records(base: &Path) -> usize {
    use maestro_shell::paths::{AppPaths, RecordKind};
    use maestro_shell::records::SessionRecord;
    let paths = AppPaths::with_base(base);
    match maestro_shell::store::load_all::<SessionRecord>(&paths, RecordKind::Session) {
        Ok(rows) => rows.len(),
        Err(_) => 0,
    }
}

// ============================================================================================
// worktree-cleanup: dry-run / confirmed-removal apply path through the real shell seam.
//
// These exercise `maestro-app worktree-cleanup` end-to-end against the REAL
// `remove_worktree_with_consent` primitive in a temp git repo: seed a Worktree-policy workspace
// with `worktree_create` consent, create a genuine `git worktree add -b maestro/<ws>/<sess>` at the
// deterministic target, then assert dry-run deletes nothing and confirmed removal deletes exactly the
// target worktree (and only when the plan is removable). No fake daemon is involved — the command
// connects to / spawns no daemon.
// ============================================================================================

/// Run `git <args>` in `cwd`, panicking with captured stderr on non-zero exit.
fn run_git(cwd: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .unwrap_or_else(|e| panic!("git {args:?} failed to spawn: {e}"));
    assert!(
        out.status.success(),
        "git {args:?} in {} failed: {}",
        cwd.display(),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Seed a Project + Worktree-policy Workspace (root = a real initialized git repo) with the given
/// `worktree_create` consent, then create a real `git worktree add -b maestro/<ws>/<sess>` at the
/// deterministic target `<base>/worktrees/<ws>/<sess>`. Returns the target path. An optional session
/// record may be seeded to drive liveness/reference refusals.
#[allow(clippy::too_many_arguments)]
fn seed_worktree_workspace(
    ws: &Workspace,
    workspace_id: &str,
    session_id: &str,
    worktree_create_consent: bool,
    session: Option<(&str, maestro_shell::records::SessionStatus, String)>,
) -> PathBuf {
    seed_worktree_workspace_with_policy(
        ws,
        workspace_id,
        session_id,
        maestro_shell::policy::WorkspacePolicy::Worktree,
        worktree_create_consent,
        session,
    )
}

/// Like [`seed_worktree_workspace`] but lets the test pick the workspace `policy`. A real matching
/// git worktree is still created at the deterministic target, so tests can prove that a
/// non-`Worktree` workspace with an otherwise-matching checkout is NOT reported as Maestro-owned.
fn seed_worktree_workspace_with_policy(
    ws: &Workspace,
    workspace_id: &str,
    session_id: &str,
    policy: maestro_shell::policy::WorkspacePolicy,
    worktree_create_consent: bool,
    session: Option<(&str, maestro_shell::records::SessionStatus, String)>,
) -> PathBuf {
    use maestro_shell::paths::{AppPaths, RecordKind};
    use maestro_shell::policy::WorkspacePolicy;
    use maestro_shell::records::{
        LaunchSpec, Project, SessionKind, SessionRecord, Workspace as WsRecord, WorkspaceConsent,
    };
    use maestro_shell::store;

    let paths = AppPaths::with_base(&ws.base);

    // A real git repo at the workspace root so `git worktree add` and `matching_worktree` work.
    let repo_root = ws.base.join("repo");
    std::fs::create_dir_all(&repo_root).expect("repo root");
    run_git(&repo_root, &["init", "-q"]);
    run_git(&repo_root, &["config", "user.email", "t@example.com"]);
    run_git(&repo_root, &["config", "user.name", "Test"]);
    std::fs::write(repo_root.join("README"), b"seed\n").expect("seed file");
    run_git(&repo_root, &["add", "README"]);
    run_git(&repo_root, &["commit", "-q", "-m", "seed"]);

    let project = Project {
        project_id: "p1".into(),
        name: "One".into(),
        root: repo_root.to_string_lossy().into_owned(),
        default_workspace_policy: WorkspacePolicy::Worktree,
        created_at_ms: 1,
        last_active_at_ms: 100,
        icon: None,
        accent_color: None,
        launch_defaults: None,
        directories: Vec::new(),
        system: false,
        hidden: false,
        window_order: Vec::new(),
    };
    store::write_record(
        &paths,
        RecordKind::Project,
        &project.project_id,
        1,
        &project,
    )
    .expect("write project");

    let workspace = WsRecord {
        workspace_id: workspace_id.into(),
        project_id: "p1".into(),
        root: repo_root.to_string_lossy().into_owned(),
        policy,
        consent: WorkspaceConsent {
            worktree_create: worktree_create_consent,
            repo_write: false,
            granted_at_ms: Some(1),
        },
    };
    store::write_record(
        &paths,
        RecordKind::Workspace,
        &workspace.workspace_id,
        1,
        &workspace,
    )
    .expect("write workspace");

    if let Some((sess_id, status, cwd)) = session {
        let record = SessionRecord {
            session_id: sess_id.into(),
            workspace_id: workspace_id.into(),
            kind: SessionKind::Agent,
            launch: LaunchSpec::KnownSafe {
                launch_spec_id: "ls-1".into(),
                params: vec![],
            },
            cwd_resolved: cwd,
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status,
        };
        store::write_record(&paths, RecordKind::Session, &record.session_id, 1, &record)
            .expect("write session");
    }

    // The deterministic target the planner/command computes: <base>/worktrees/<ws>/<sess>.
    let target = ws
        .base
        .join("worktrees")
        .join(workspace_id)
        .join(session_id);
    std::fs::create_dir_all(target.parent().expect("target parent")).expect("worktree parent");
    let branch = format!("maestro/{workspace_id}/{session_id}");
    run_git(
        &repo_root,
        &[
            "worktree",
            "add",
            "-b",
            &branch,
            target.to_str().expect("target utf8"),
        ],
    );
    assert!(target.exists(), "seeded worktree target must exist");
    target
}

fn worktree_cleanup_cmd(ws: &Workspace, workspace_id: &str, session_id: &str) -> Command {
    let mut cmd = Command::new(APP_BIN);
    cmd.arg("worktree-cleanup")
        .arg("--workspace-id")
        .arg(workspace_id)
        .arg("--session-id")
        .arg(session_id)
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null());
    cmd
}

#[test]
fn worktree_cleanup_dry_run_is_removable_and_deletes_nothing() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let target = seed_worktree_workspace(&ws, "wsA", "sessA", true, None);

    let out = worktree_cleanup_cmd(&ws, "wsA", "sessA")
        .output()
        .expect("run worktree-cleanup dry-run");

    assert_eq!(out.status.code(), Some(0), "dry-run should exit 0");
    assert!(out.stderr.is_empty(), "stderr empty on dry-run success");
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["command"], serde_json::json!("worktree-cleanup"));
    assert_eq!(value["mode"], serde_json::json!("dry_run"));
    assert_eq!(value["decision"], serde_json::json!("removable"));
    assert_eq!(value["reason"], serde_json::json!("ok"));
    assert_eq!(value["removed"], serde_json::json!(false));
    assert_eq!(
        value["branch"],
        serde_json::json!("maestro/wsA/sessA"),
        "branch is maestro/<ws>/<sess>"
    );
    assert!(target.exists(), "dry-run must not delete the worktree");
    assert!(
        !ws.socket.exists(),
        "worktree-cleanup must not create a daemon socket"
    );
}

#[test]
fn worktree_cleanup_confirmed_removes_the_worktree() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let target = seed_worktree_workspace(&ws, "wsB", "sessB", true, None);

    let out = worktree_cleanup_cmd(&ws, "wsB", "sessB")
        .arg("--confirm")
        .output()
        .expect("run worktree-cleanup --confirm");

    assert_eq!(
        out.status.code(),
        Some(0),
        "confirmed removal should exit 0"
    );
    assert!(out.stderr.is_empty(), "stderr empty on confirmed success");
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["command"], serde_json::json!("worktree-cleanup"));
    assert_eq!(value["mode"], serde_json::json!("confirmed"));
    assert_eq!(value["decision"], serde_json::json!("removed"));
    assert_eq!(value["reason"], serde_json::json!("ok"));
    assert_eq!(value["removed"], serde_json::json!(true));
    assert!(
        !target.exists(),
        "confirmed removal must delete the target worktree"
    );
    assert!(
        !ws.socket.exists(),
        "worktree-cleanup must not create a daemon socket"
    );
}

#[test]
fn worktree_cleanup_confirm_non_removable_does_not_delete() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    // Consent absent => plan is `missing_consent` (refused). The worktree still physically exists.
    let target = seed_worktree_workspace(&ws, "wsC", "sessC", false, None);

    let out = worktree_cleanup_cmd(&ws, "wsC", "sessC")
        .arg("--confirm")
        .output()
        .expect("run worktree-cleanup --confirm on non-removable");

    assert_eq!(
        out.status.code(),
        Some(1),
        "confirm on a non-removable plan exits 1"
    );
    assert!(
        out.stdout.is_empty(),
        "stdout empty when refusing to remove"
    );
    let value = parse_single_json(&out.stderr);
    assert_eq!(value["command"], serde_json::json!("worktree-cleanup"));
    assert_eq!(value["stage"], serde_json::json!("not_removable"));
    assert!(
        target.exists(),
        "a refused confirmed plan must delete nothing"
    );
}

#[test]
fn worktree_cleanup_dry_run_refuses_live_session() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    // A Live session with the same id refuses as `live_session` even though consent is present.
    let target = seed_worktree_workspace(
        &ws,
        "wsD",
        "sessD",
        true,
        Some((
            "sessD",
            maestro_shell::records::SessionStatus::Live,
            "/somewhere".into(),
        )),
    );

    let out = worktree_cleanup_cmd(&ws, "wsD", "sessD")
        .output()
        .expect("run worktree-cleanup dry-run on live session");

    assert_eq!(out.status.code(), Some(0), "dry-run still exits 0");
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["decision"], serde_json::json!("refused"));
    assert_eq!(value["reason"], serde_json::json!("live_session"));
    assert_eq!(value["removed"], serde_json::json!(false));
    assert!(target.exists(), "a refused dry-run deletes nothing");
}

/// Seed a session ROW that `load_all::<SessionRecord>` cannot deserialize — the SQLite-store analog
/// of the old corrupt/future-version session FILE that made a scan incomplete.
///
/// In the file-era store this was a JSON envelope whose `schema_version` was bumped past this build
/// (`LoadOutcome::FutureVersion`, left in place). The relational store moved the future-version guard
/// to DB-open level (a whole DB stamped future refuses to open — see
/// `store::future_version_db_is_refused_on_open`) and has no per-row future version. The remaining
/// per-row "won't load" outcome is `Quarantined` (a stored row whose shape no longer fits the record
/// — see `store::row_that_wont_deserialize_is_quarantined_and_excluded`).
///
/// So we insert a session row through the low-level `store_sqlite::upsert` (which persists whatever
/// JSON `Value` it is handed, without enum validation) carrying a bogus `status` tag. On read,
/// `load_all` rebuilds the row and `serde_json::from_value::<SessionRecord>` fails on the unknown
/// `SessionStatus`, so the session surfaces as `LoadOutcome::Quarantined` and lands in
/// `scan.non_loaded` — exactly the "session_records_unavailable" refusal the worktree-cleanup tests
/// exercise end-to-end. A parent workspace is seeded first to satisfy `sessions.workspace_id`.
fn seed_future_version_session(base: &Path, session_id: &str) {
    // Parent chain so the FK holds even though the session row itself is deliberately un-loadable.
    seed_workspace(base, "wsZ", "p-quarantine");

    let value = serde_json::json!({
        "session_id": session_id,
        "workspace_id": "wsZ",
        "kind": "agent",
        "launch": { "tier": "known_safe", "launch_spec_id": "ls-1", "params": [] },
        "cwd_resolved": "/somewhere",
        "agent_task_id": null,
        "created_at_ms": 1,
        "last_attached_at_ms": 1,
        "last_known_generation": null,
        // Not a valid SessionStatus → the row persists but fails to deserialize on read (Quarantined).
        "status": "not_a_real_status",
    });

    let arc = maestro_shell::db::conn_for(base).expect("open db");
    let conn = arc.lock().unwrap();
    maestro_shell::store_sqlite::upsert(
        &conn,
        maestro_shell::paths::RecordKind::Session,
        session_id,
        &value,
    )
    .expect("insert quarantinable session row");
}

#[test]
fn worktree_cleanup_dry_run_refuses_incomplete_session_scan() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    // Otherwise fully removable: Worktree policy + consent, no blocking loaded session.
    let target = seed_worktree_workspace(&ws, "wsE", "sessE", true, None);
    // But a future-version session record makes the scan incomplete -> must refuse.
    seed_future_version_session(&ws.base, "future-sess");

    let out = worktree_cleanup_cmd(&ws, "wsE", "sessE")
        .output()
        .expect("run worktree-cleanup dry-run with incomplete scan");

    assert_eq!(out.status.code(), Some(0), "dry-run still exits 0");
    assert!(out.stderr.is_empty(), "stderr empty on dry-run success");
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["decision"], serde_json::json!("refused"));
    assert_eq!(
        value["reason"],
        serde_json::json!("session_records_unavailable")
    );
    assert_eq!(value["removed"], serde_json::json!(false));
    assert_eq!(
        value["non_loaded_session_records"],
        serde_json::json!(1),
        "the count surfaces how many session files failed to load"
    );
    assert!(
        target.exists(),
        "an incomplete-scan refusal deletes nothing"
    );
}

#[test]
fn worktree_cleanup_confirm_refuses_incomplete_session_scan() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let target = seed_worktree_workspace(&ws, "wsF", "sessF", true, None);
    seed_future_version_session(&ws.base, "future-sess");

    let out = worktree_cleanup_cmd(&ws, "wsF", "sessF")
        .arg("--confirm")
        .output()
        .expect("run worktree-cleanup --confirm with incomplete scan");

    assert_eq!(
        out.status.code(),
        Some(1),
        "confirm on an incomplete scan exits 1"
    );
    assert!(
        out.stdout.is_empty(),
        "stdout empty when refusing to remove"
    );
    let value = parse_single_json(&out.stderr);
    assert_eq!(value["command"], serde_json::json!("worktree-cleanup"));
    assert_eq!(value["stage"], serde_json::json!("not_removable"));
    assert!(
        target.exists(),
        "an incomplete-scan confirm must delete nothing"
    );
}

fn worktree_list_cmd(ws: &Workspace, workspace_id: &str) -> Command {
    let mut cmd = Command::new(APP_BIN);
    cmd.arg("worktree-list")
        .arg("--workspace-id")
        .arg(workspace_id)
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null());
    cmd
}

#[test]
fn worktree_list_verified_removable_candidate() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    // A loaded, Exited session whose cwd does NOT reference the worktree => removable.
    let target = seed_worktree_workspace(
        &ws,
        "wsL",
        "sessL",
        true,
        Some((
            "sessL",
            maestro_shell::records::SessionStatus::Exited,
            "/elsewhere".into(),
        )),
    );

    let out = worktree_list_cmd(&ws, "wsL")
        .output()
        .expect("run worktree-list");

    assert_eq!(out.status.code(), Some(0), "listing should exit 0");
    assert!(out.stderr.is_empty(), "stderr empty on listing success");
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["command"], serde_json::json!("worktree-list"));
    assert_eq!(value["workspace_id"], serde_json::json!("wsL"));

    let candidates = value["candidates"].as_array().expect("candidates array");
    assert_eq!(candidates.len(), 1, "one loaded session candidate");
    let c = &candidates[0];
    assert_eq!(c["workspace_id"], serde_json::json!("wsL"));
    assert_eq!(c["session_id"], serde_json::json!("sessL"));
    assert_eq!(c["branch"], serde_json::json!("maestro/wsL/sessL"));
    assert_eq!(c["workspace_status"], serde_json::json!("loaded"));
    assert_eq!(c["session_status"], serde_json::json!("loaded_exited"));
    assert_eq!(c["git_status"], serde_json::json!("verified"));
    assert_eq!(
        c["ownership"],
        serde_json::json!("verified_maestro_worktree")
    );
    assert_eq!(c["cleanup_plan_decision"], serde_json::json!("removable"));
    assert_eq!(c["cleanup_plan_reason"], serde_json::json!("ok"));
    // Record-backed rows carry a display-only staleness classification.
    assert!(
        c["staleness"].is_string(),
        "record-backed candidate carries a staleness field"
    );

    let counts = &value["counts"];
    assert_eq!(counts["total"], serde_json::json!(1));
    assert_eq!(counts["verified_maestro_worktree"], serde_json::json!(1));
    assert_eq!(counts["removable"], serde_json::json!(1));
    assert_eq!(counts["refused"], serde_json::json!(0));

    assert!(target.exists(), "listing must not delete the worktree");
    assert!(
        !ws.socket.exists(),
        "worktree-list must not create a daemon socket"
    );
}

#[test]
fn worktree_list_missing_workspace_is_zero_candidates() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    // No records seeded at all: a syntactically valid id that simply is not found.
    let out = worktree_list_cmd(&ws, "nope")
        .output()
        .expect("run worktree-list on missing workspace");

    assert_eq!(
        out.status.code(),
        Some(0),
        "a not-found workspace is a zero-candidate success, not a failure"
    );
    assert!(out.stderr.is_empty(), "stderr empty on success");
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["command"], serde_json::json!("worktree-list"));
    assert_eq!(value["workspace_id"], serde_json::json!("nope"));
    assert_eq!(
        value["candidates"]
            .as_array()
            .expect("candidates array")
            .len(),
        0
    );
    assert_eq!(value["counts"]["total"], serde_json::json!(0));
    assert!(
        !ws.socket.exists(),
        "worktree-list must not create a daemon socket"
    );
}

#[test]
fn worktree_list_bad_usage_exits_two() {
    maybe_run_fake_daemon();
    // Missing required --workspace-id is a usage error.
    let out = Command::new(APP_BIN)
        .arg("worktree-list")
        .stdin(Stdio::null())
        .output()
        .expect("run worktree-list with no args");

    assert_eq!(out.status.code(), Some(2), "bad usage exits 2");
    assert!(out.stdout.is_empty(), "stdout empty on usage error");
    let value = parse_single_json(&out.stderr);
    assert_eq!(value["command"], serde_json::json!("worktree-list"));
    assert_eq!(value["stage"], serde_json::json!("bad_usage"));
    assert!(value["message"].is_string(), "bad_usage carries a message");
}

#[test]
fn worktree_list_incomplete_scan_never_removable() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    // An otherwise-removable loaded session ...
    let target = seed_worktree_workspace(
        &ws,
        "wsM",
        "sessM",
        true,
        Some((
            "sessM",
            maestro_shell::records::SessionStatus::Exited,
            "/elsewhere".into(),
        )),
    );
    // ... but a future-version session record makes the scan incomplete.
    seed_future_version_session(&ws.base, "future-sess");

    let out = worktree_list_cmd(&ws, "wsM")
        .output()
        .expect("run worktree-list with incomplete scan");

    assert_eq!(out.status.code(), Some(0), "listing still exits 0");
    let value = parse_single_json(&out.stdout);
    let candidates = value["candidates"].as_array().expect("candidates array");
    assert_eq!(candidates.len(), 1, "the loaded session is still listed");
    let c = &candidates[0];
    assert_eq!(c["cleanup_plan_decision"], serde_json::json!("refused"));
    assert_eq!(
        c["cleanup_plan_reason"],
        serde_json::json!("session_records_unavailable"),
        "an incomplete scan surfaces session_records_unavailable, never removable"
    );
    assert_eq!(value["counts"]["removable"], serde_json::json!(0));
    assert_eq!(value["counts"]["refused"], serde_json::json!(1));
    assert!(target.exists(), "listing deletes nothing");
}

#[test]
fn worktree_list_non_worktree_workspace_is_not_verified() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    // A loaded NON-Worktree (ScratchCwd) workspace whose git checkout DOES exist and would inspect
    // as a verified Maestro worktree. The authority boundary must still refuse to claim ownership.
    let target = seed_worktree_workspace_with_policy(
        &ws,
        "wsN",
        "sessN",
        maestro_shell::policy::WorkspacePolicy::ScratchCwd,
        true,
        Some((
            "sessN",
            maestro_shell::records::SessionStatus::Exited,
            "/elsewhere".into(),
        )),
    );

    let out = worktree_list_cmd(&ws, "wsN")
        .output()
        .expect("run worktree-list on non-worktree workspace");

    assert_eq!(out.status.code(), Some(0), "listing should exit 0");
    let value = parse_single_json(&out.stdout);
    let candidates = value["candidates"].as_array().expect("candidates array");
    assert_eq!(candidates.len(), 1, "the loaded session is still listed");
    let c = &candidates[0];
    assert_eq!(c["workspace_status"], serde_json::json!("non_worktree"));
    assert_eq!(
        c["workspace_reason"],
        serde_json::json!("non_worktree_policy")
    );
    // The whole point: a matching git checkout does NOT prove Maestro ownership here.
    assert_ne!(
        c["ownership"],
        serde_json::json!("verified_maestro_worktree"),
        "a non-Worktree workspace must never report verified ownership"
    );
    assert_eq!(c["ownership"], serde_json::json!("uninspectable"));
    assert_eq!(c["git_status"], serde_json::json!("unavailable"));
    assert_eq!(c["git_reason"], serde_json::json!("non_worktree_policy"));
    // The shared planner refuses the same workspace for the same reason.
    assert_eq!(c["cleanup_plan_decision"], serde_json::json!("refused"));
    assert_eq!(
        c["cleanup_plan_reason"],
        serde_json::json!("non_worktree_policy")
    );
    assert_eq!(
        value["counts"]["verified_maestro_worktree"],
        serde_json::json!(0)
    );
    assert_eq!(value["counts"]["removable"], serde_json::json!(0));
    assert_eq!(value["counts"]["refused"], serde_json::json!(1));
    assert!(target.exists(), "listing deletes nothing");
}

#[test]
fn worktree_list_all_aggregates_record_backed_workspaces() {
    use maestro_shell::paths::{AppPaths, RecordKind};
    use maestro_shell::policy::WorkspacePolicy;
    use maestro_shell::records::{
        LaunchSpec, Project, SessionKind, SessionRecord, Workspace as WsRecord, WorkspaceConsent,
    };
    use maestro_shell::store;

    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let paths = AppPaths::with_base(&ws.base);

    // One real git repo + one project, then TWO Worktree-policy workspaces under it. (The single
    // shared `seed_worktree_workspace` helper re-commits the seed file on each call, so it can't seed
    // two workspaces against one repo — this test seeds the second workspace inline.)
    let repo_root = ws.base.join("repo");
    std::fs::create_dir_all(&repo_root).expect("repo root");
    run_git(&repo_root, &["init", "-q"]);
    run_git(&repo_root, &["config", "user.email", "t@example.com"]);
    run_git(&repo_root, &["config", "user.name", "Test"]);
    std::fs::write(repo_root.join("README"), b"seed\n").expect("seed file");
    run_git(&repo_root, &["add", "README"]);
    run_git(&repo_root, &["commit", "-q", "-m", "seed"]);

    let project = Project {
        project_id: "p1".into(),
        name: "One".into(),
        root: repo_root.to_string_lossy().into_owned(),
        default_workspace_policy: WorkspacePolicy::Worktree,
        created_at_ms: 1,
        last_active_at_ms: 100,
        icon: None,
        accent_color: None,
        launch_defaults: None,
        directories: Vec::new(),
        system: false,
        hidden: false,
        window_order: Vec::new(),
    };
    store::write_record(
        &paths,
        RecordKind::Project,
        &project.project_id,
        1,
        &project,
    )
    .expect("write project");

    // Seed each (workspace record + loaded Exited session + real `git worktree add`) and return the
    // worktree target path. The session cwd points elsewhere so the planner finds each removable.
    let seed = |workspace_id: &str, session_id: &str| -> PathBuf {
        let workspace = WsRecord {
            workspace_id: workspace_id.into(),
            project_id: "p1".into(),
            root: repo_root.to_string_lossy().into_owned(),
            policy: WorkspacePolicy::Worktree,
            consent: WorkspaceConsent {
                worktree_create: true,
                repo_write: false,
                granted_at_ms: Some(1),
            },
        };
        store::write_record(
            &paths,
            RecordKind::Workspace,
            &workspace.workspace_id,
            1,
            &workspace,
        )
        .expect("write workspace");

        let record = SessionRecord {
            session_id: session_id.into(),
            workspace_id: workspace_id.into(),
            kind: SessionKind::Agent,
            launch: LaunchSpec::KnownSafe {
                launch_spec_id: "ls-1".into(),
                params: vec![],
            },
            cwd_resolved: "/elsewhere".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status: maestro_shell::records::SessionStatus::Exited,
        };
        store::write_record(&paths, RecordKind::Session, &record.session_id, 1, &record)
            .expect("write session");

        let target = ws
            .base
            .join("worktrees")
            .join(workspace_id)
            .join(session_id);
        std::fs::create_dir_all(target.parent().expect("target parent")).expect("worktree parent");
        let branch = format!("maestro/{workspace_id}/{session_id}");
        run_git(
            &repo_root,
            &[
                "worktree",
                "add",
                "-b",
                &branch,
                target.to_str().expect("target utf8"),
            ],
        );
        assert!(target.exists(), "seeded worktree target must exist");
        target
    };

    let target_a = seed("wsAllA", "sessAllA");
    let target_b = seed("wsAllB", "sessAllB");

    let out = Command::new(APP_BIN)
        .arg("worktree-list")
        .arg("--all")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run worktree-list --all");

    assert_eq!(out.status.code(), Some(0), "--all inventory exits 0");
    assert!(out.stderr.is_empty(), "stderr empty on --all success");
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["command"], serde_json::json!("worktree-list"));
    // --all omits the top-level workspace_id entirely (never null).
    assert!(
        value.get("workspace_id").is_none(),
        "--all must omit top-level workspace_id"
    );

    let candidates = value["candidates"].as_array().expect("candidates array");
    assert_eq!(candidates.len(), 2, "both workspaces' sessions are listed");
    let ids: Vec<&str> = candidates
        .iter()
        .map(|c| c["workspace_id"].as_str().expect("row workspace_id"))
        .collect();
    assert!(ids.contains(&"wsAllA"), "row carries its own workspace_id");
    assert!(ids.contains(&"wsAllB"), "row carries its own workspace_id");
    // Every record-backed --all row carries a display-only staleness classification.
    for c in candidates {
        assert!(
            c["staleness"].is_string(),
            "each --all candidate carries a staleness field"
        );
    }

    let counts = &value["counts"];
    assert_eq!(counts["total"], serde_json::json!(2), "counts aggregate");
    assert_eq!(counts["verified_maestro_worktree"], serde_json::json!(2));
    assert_eq!(counts["removable"], serde_json::json!(2));
    assert_eq!(counts["refused"], serde_json::json!(0));

    assert!(target_a.exists(), "listing must not delete a worktree");
    assert!(target_b.exists(), "listing must not delete a worktree");
    assert!(
        !ws.socket.exists(),
        "worktree-list --all must not create a daemon socket"
    );
}

#[test]
fn worktree_list_all_include_orphans_inventories_fs_without_deleting() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    // Seed ONE real record-backed Worktree workspace+session (its target lives at
    // <base>/worktrees/wsReal/sessReal and is a real git worktree, so it appears in candidates[]).
    let real_target = seed_worktree_workspace(
        &ws,
        "wsReal",
        "sessReal",
        true,
        Some((
            "sessReal",
            maestro_shell::records::SessionStatus::Exited,
            "/elsewhere".into(),
        )),
    );
    assert!(real_target.exists(), "record-backed worktree target exists");

    // Now plant ORPHAN filesystem entries under worktree_base that NO record backs:
    let wt_base = ws.base.join("worktrees");
    // (a) a malformed (non-id-shaped) workspace-segment directory.
    let malformed_dir = wt_base.join("not a valid id");
    std::fs::create_dir_all(&malformed_dir).expect("malformed dir");
    // (b) a loose file directly under worktree_base (non-directory at workspace position).
    let loose_file = wt_base.join("stray.txt");
    std::fs::write(&loose_file, b"junk\n").expect("loose file");
    // (c) an id-shaped workspace dir + id-shaped session dir with NO loaded workspace record.
    let ghost_session = wt_base.join("ghostWs").join("ghostSess");
    std::fs::create_dir_all(&ghost_session).expect("ghost session dir");

    let out = Command::new(APP_BIN)
        .arg("worktree-list")
        .arg("--all")
        .arg("--include-orphans")
        .arg("--base")
        .arg(&ws.base)
        .stdin(Stdio::null())
        .output()
        .expect("run worktree-list --all --include-orphans");

    assert_eq!(
        out.status.code(),
        Some(0),
        "orphan inventory exits 0: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stderr.is_empty(), "stderr empty on success");
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["command"], serde_json::json!("worktree-list"));

    // The record-backed candidate set is unchanged: exactly the one real worktree.
    let candidates = value["candidates"].as_array().expect("candidates array");
    assert_eq!(
        candidates.len(),
        1,
        "only the record-backed row in candidates"
    );
    assert_eq!(candidates[0]["workspace_id"], serde_json::json!("wsReal"));

    // The orphan rows live in a SEPARATE array so scripts cannot confuse them with cleanup-eligible
    // candidates. The walk surfaces every non-record-backed entry it sees at depth 1 and 2:
    //   - ghostWs            (depth-1 id-shaped dir, no workspace record)
    //   - ghostWs/ghostSess  (depth-2 id-shaped, no workspace record)
    //   - "not a valid id"   (depth-1 malformed dir)
    //   - stray.txt          (depth-1 loose file)
    //   - wsReal             (depth-1 id-shaped dir; workspace record loaded, no session segment)
    // The record-backed wsReal/sessReal target is suppressed (it's a real candidate).
    let orphans = value["orphan_candidates"]
        .as_array()
        .expect("orphan_candidates array");
    assert_eq!(orphans.len(), 5, "five non-backed fs entries surfaced");
    let orphan_paths: Vec<&str> = orphans
        .iter()
        .map(|o| o["path"].as_str().expect("orphan path"))
        .collect();
    assert!(orphan_paths.iter().any(|p| p.ends_with("not a valid id")));
    assert!(orphan_paths.iter().any(|p| p.ends_with("stray.txt")));
    assert!(orphan_paths.iter().any(|p| p.ends_with("ghostSess")));
    assert!(orphan_paths.iter().any(|p| p.ends_with("ghostWs")));
    assert!(orphan_paths.iter().any(|p| p.ends_with("wsReal")));
    assert!(
        !orphan_paths
            .iter()
            .any(|p| *p == real_target.to_str().unwrap()),
        "record-backed target must NOT appear as an orphan"
    );

    // No orphan row is ever removable.
    for o in orphans {
        assert_eq!(
            o["cleanup_plan_decision"],
            serde_json::json!("not_applicable"),
            "orphan row {} must never be removable",
            o["path"]
        );
        // Orphan rows have no loaded SessionRecord last-use signal, so they carry NO staleness.
        assert!(
            o.get("staleness").is_none(),
            "orphan row {} must not carry a staleness field",
            o["path"]
        );
    }
    // The record-backed candidate, by contrast, does carry staleness.
    assert!(
        candidates[0]["staleness"].is_string(),
        "record-backed candidate carries staleness even when orphans are included"
    );

    // Separate orphan_counts object, distinct from candidate counts.
    let oc = &value["orphan_counts"];
    assert_eq!(oc["total"], serde_json::json!(5), "total orphan rows");
    assert_eq!(oc["non_directory"], serde_json::json!(1), "the loose file");
    // Both the "not a valid id" dir and the (non-id-shaped) stray.txt file have malformed segments.
    assert_eq!(
        oc["malformed_or_wrong_depth"],
        serde_json::json!(2),
        "malformed dir + non-id-shaped loose file"
    );
    // The id-shaped rows: ghostWs, ghostWs/ghostSess, wsReal.
    assert_eq!(
        oc["id_shaped"],
        serde_json::json!(3),
        "id-shaped orphan rows"
    );

    // Nothing on disk was deleted, and no daemon socket was created.
    assert!(real_target.exists(), "listing must not delete the worktree");
    assert!(
        malformed_dir.exists(),
        "orphan inventory must not delete dirs"
    );
    assert!(
        loose_file.exists(),
        "orphan inventory must not delete files"
    );
    assert!(
        ghost_session.exists(),
        "orphan inventory must not delete dirs"
    );
    assert!(
        !ws.socket.exists(),
        "worktree-list --all --include-orphans must not create a daemon socket"
    );
}

// ============================================================================================
// 9. layout-preset save / list / restore-plan / delete (headless, daemon-free)
// ============================================================================================

/// Run a `maestro-app layout-preset <subcommand> ...` against `base`, capturing the full output.
fn run_layout_preset(base: &Path, args: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(APP_BIN);
    cmd.arg("layout-preset");
    for a in args {
        cmd.arg(a);
    }
    cmd.arg("--base")
        .arg(base)
        .stdin(Stdio::null())
        .output()
        .expect("run maestro-app layout-preset")
}

#[test]
fn layout_preset_save_list_restore_plan_delete_round_trip() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    // A one-tab window whose tab points at a (non-exited) session record, so restore-plan can mark
    // that slot reattach.
    write_session_with_window(&ws.base, "s1", "w1", "t1");
    // The saved preset carries project_id proj-x (layout_presets.project_id → projects), so that
    // project must exist first.
    seed_project(&ws.base, "proj-x");

    // save: capture the window into a named preset.
    let out = run_layout_preset(
        &ws.base,
        &[
            "save",
            "--window-id",
            "w1",
            "--name",
            "Backend + logs",
            "--preset-id",
            "p1",
            "--project-id",
            "proj-x",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "save should exit 0");
    assert!(out.stderr.is_empty(), "save stderr should be empty");
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["command"], serde_json::json!("layout-preset save"));
    assert_eq!(value["preset"]["preset_id"], serde_json::json!("p1"));
    assert_eq!(value["preset"]["name"], serde_json::json!("Backend + logs"));
    assert_eq!(value["preset"]["project_id"], serde_json::json!("proj-x"));
    assert_eq!(value["preset"]["tabs"].as_array().map(|a| a.len()), Some(1));
    assert_eq!(
        value["preset"]["tabs"][0]["session_id"],
        serde_json::json!("s1")
    );
    // Persisted durably (SQLite-backed; no per-preset JSON file). The project-scoped `list` below
    // proves the round-trip.

    // list (project-scoped) returns the saved preset.
    let out = run_layout_preset(&ws.base, &["list", "--project-id", "proj-x"]);
    assert_eq!(out.status.code(), Some(0));
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["command"], serde_json::json!("layout-preset list"));
    assert_eq!(value["count"], serde_json::json!(1));
    assert_eq!(value["presets"][0]["preset_id"], serde_json::json!("p1"));

    // restore-plan: the live-session slot is reattach.
    let out = run_layout_preset(&ws.base, &["restore-plan", "--preset-id", "p1"]);
    assert_eq!(out.status.code(), Some(0));
    let value = parse_single_json(&out.stdout);
    assert_eq!(
        value["command"],
        serde_json::json!("layout-preset restore-plan")
    );
    assert_eq!(value["slots"].as_array().map(|a| a.len()), Some(1));
    assert_eq!(value["slots"][0]["action"], serde_json::json!("reattach"));
    assert_eq!(
        value["slots"][0]["reattach_session_id"],
        serde_json::json!("s1")
    );

    // delete removes it; a second list is empty.
    let out = run_layout_preset(&ws.base, &["delete", "--preset-id", "p1"]);
    assert_eq!(out.status.code(), Some(0));
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["deleted_preset_id"], serde_json::json!("p1"));
    // Removal is proven by the empty `list` below (no per-preset JSON file to check under SQLite).

    let out = run_layout_preset(&ws.base, &["list"]);
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["count"], serde_json::json!(0));

    assert!(
        !ws.socket.exists(),
        "layout-preset commands must not create a daemon socket"
    );
}

#[test]
fn layout_preset_restore_plan_marks_unknown_session_launch_fresh() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    // A window+tab whose session record we then mark Exited, so its slot must launch fresh.
    write_session_with_window(&ws.base, "s-dead", "w1", "t1");
    {
        use maestro_shell::paths::{AppPaths, RecordKind};
        use maestro_shell::records::{LaunchSpec, SessionKind, SessionRecord, SessionStatus};
        use maestro_shell::store;
        let paths = AppPaths::with_base(&ws.base);
        let session = SessionRecord {
            session_id: "s-dead".into(),
            workspace_id: "ws-1".into(),
            kind: SessionKind::Agent,
            launch: LaunchSpec::KnownSafe {
                launch_spec_id: "ls-1".into(),
                params: vec![],
            },
            cwd_resolved: "/tmp".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status: SessionStatus::Exited,
        };
        store::write_record(&paths, RecordKind::Session, "s-dead", 2, &session)
            .expect("overwrite session as exited");
    }

    assert_eq!(
        run_layout_preset(
            &ws.base,
            &[
                "save",
                "--window-id",
                "w1",
                "--name",
                "L",
                "--preset-id",
                "p1"
            ],
        )
        .status
        .code(),
        Some(0)
    );

    let out = run_layout_preset(&ws.base, &["restore-plan", "--preset-id", "p1"]);
    assert_eq!(out.status.code(), Some(0));
    let value = parse_single_json(&out.stdout);
    assert_eq!(
        value["slots"][0]["action"],
        serde_json::json!("launch_fresh")
    );
    assert_eq!(
        value["slots"][0]["reattach_session_id"],
        serde_json::json!(null)
    );
}

#[test]
fn layout_preset_save_on_missing_window_fails_with_window_stage() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let out = run_layout_preset(
        &ws.base,
        &[
            "save",
            "--window-id",
            "nope",
            "--name",
            "L",
            "--preset-id",
            "p1",
        ],
    );
    assert_eq!(out.status.code(), Some(1), "missing window should exit 1");
    let value = parse_single_json(&out.stderr);
    assert_eq!(value["command"], serde_json::json!("layout-preset save"));
    assert_eq!(value["stage"], serde_json::json!("window"));
    assert!(!ws.base.join("layout_presets").join("p1.json").exists());
}

#[test]
fn layout_preset_restore_plan_unknown_preset_fails_not_found() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    let out = run_layout_preset(&ws.base, &["restore-plan", "--preset-id", "ghost"]);
    assert_eq!(out.status.code(), Some(1));
    let value = parse_single_json(&out.stderr);
    assert_eq!(
        value["command"],
        serde_json::json!("layout-preset restore-plan")
    );
    assert_eq!(value["stage"], serde_json::json!("not_found"));
}

#[test]
fn layout_preset_bad_usage_exits_two_with_stamped_subcommand() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();
    // `save` missing required --preset-id.
    let out = run_layout_preset(&ws.base, &["save", "--window-id", "w1", "--name", "L"]);
    assert_eq!(out.status.code(), Some(2), "bad usage should exit 2");
    let value = parse_single_json(&out.stderr);
    assert_eq!(value["command"], serde_json::json!("layout-preset save"));
    assert_eq!(value["stage"], serde_json::json!("bad_usage"));
}

/// End-to-end restore: save a one-tab window whose tab points at a STILL-LIVE session, then EXECUTE
/// `layout-preset restore` into a different target window. The slot reattaches (the session is live),
/// so the executor records a tab against that same session id under a freshly-minted tab id — without
/// relaunching. The daemon is pre-started so `ensure_daemon` REUSES it (`daemon_started=false`) and
/// never gets killed/leaked. We assert the restore JSON and that the target window layout now carries
/// the reattached session as a tab.
#[test]
fn layout_preset_restore_reattaches_live_slot_into_target_window() {
    maybe_run_fake_daemon();
    let ws = Workspace::new();

    // Source window `w1`/tab `t1` -> live session `s1` (write_session_with_window writes Unknown,
    // which is non-Exited and therefore a valid reattach target).
    write_session_with_window(&ws.base, "s1", "w1", "t1");

    // Capture the source window into a preset.
    let out = run_layout_preset(
        &ws.base,
        &[
            "save",
            "--window-id",
            "w1",
            "--name",
            "L",
            "--preset-id",
            "p1",
        ],
    );
    assert_eq!(out.status.code(), Some(0), "save should exit 0");

    // Pre-start a fake daemon on the workspace socket so the app reuses it (reattach needs no real
    // daemon work, but the executor still ensures one because a preset MAY contain launch-fresh slots).
    let test_bin = std::env::current_exe().expect("current test exe");
    let child = Command::new(&test_bin)
        .env(FAKE_DAEMON_ENV, &ws.socket)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn pre-started fake daemon");
    let _guard = PreStartedDaemon {
        child,
        socket: ws.socket.clone(),
    };
    wait_until_connectable(&ws.socket);

    // Restore the preset INTO a fresh window `w2` (created on restore).
    let out = run_layout_preset(
        &ws.base,
        &[
            "restore",
            "--preset-id",
            "p1",
            "--window-id",
            "w2",
            "--socket",
            ws.socket.to_str().expect("socket utf-8"),
        ],
    );
    assert_eq!(out.status.code(), Some(0), "restore should exit 0");
    assert!(out.stderr.is_empty(), "restore stderr should be empty");
    let value = parse_single_json(&out.stdout);
    assert_eq!(value["ok"], serde_json::json!(true));
    assert_eq!(value["command"], serde_json::json!("layout-preset restore"));
    assert_eq!(value["window_id"], serde_json::json!("w2"));
    assert_eq!(
        value["daemon_started"],
        serde_json::json!(false),
        "an already-serving daemon must be reused, not re-spawned"
    );
    assert_eq!(value["restored_count"], serde_json::json!(1));
    assert_eq!(value["slots"][0]["kind"], serde_json::json!("reattached"));
    assert_eq!(value["slots"][0]["session_id"], serde_json::json!("s1"));
    // The restored tab gets a FRESH tab id, never the capture-time `t1`.
    assert_ne!(value["slots"][0]["tab_id"], serde_json::json!("t1"));
    let restored_tab_id = value["slots"][0]["tab_id"]
        .as_str()
        .expect("tab_id string")
        .to_string();

    // The target window layout now carries exactly the reattached tab pointing at session `s1`.
    {
        use maestro_shell::paths::AppPaths;
        use maestro_shell::window_layout::WindowLayoutService;
        let paths = AppPaths::with_base(&ws.base);
        let window = WindowLayoutService::new(&paths)
            .load("w2")
            .expect("load w2")
            .expect("w2 exists after restore");
        assert_eq!(window.tabs.len(), 1, "exactly one tab restored into w2");
        assert_eq!(window.tabs[0].tab_id, restored_tab_id);
        assert_eq!(window.tabs[0].session_id, "s1");
        assert!(
            window.tabs[0].split_from.is_none(),
            "single tab is top-level"
        );
    }
}
