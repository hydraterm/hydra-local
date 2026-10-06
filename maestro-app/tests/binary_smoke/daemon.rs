use super::test_transport::{Listener as UnixListener, Stream as UnixStream};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Env var that switches THIS test binary into fake-daemon mode. Its value is the socket path to
/// bind. Set only by the wrapper script (and the reused-daemon test), never during normal test runs.
pub(super) const FAKE_DAEMON_ENV: &str = "MAESTRO_FAKE_DAEMON_SOCKET";
/// Optional stable session id that switches the fake into a protocol-v1 attach-only fixture.
pub(super) const FAKE_DAEMON_LEGACY_SESSION_ENV: &str = "MAESTRO_FAKE_DAEMON_LEGACY_SESSION";
/// Optional append-only request transcript for the protocol-v1 fixture.
pub(super) const FAKE_DAEMON_REQUEST_LOG_ENV: &str = "MAESTRO_FAKE_DAEMON_REQUEST_LOG";
/// Opt into a modern fake whose session set survives across connections. Product-startup tests use
/// this to prove that the first open starts one stable session and the second open only reattaches.
pub(super) const FAKE_DAEMON_STATEFUL_ENV: &str = "MAESTRO_FAKE_DAEMON_STATEFUL";
/// Optional marker file: while present, the stateful fixture omits retained ids from its
/// live-only ListSessions response but continues serving exact Attach requests for them.
pub(super) const FAKE_DAEMON_OMIT_LIST_FILE_ENV: &str = "MAESTRO_FAKE_DAEMON_OMIT_LIST_FILE";

/// Optional env var: a file path the fake daemon writes its own PID to once bound. The agent-command
/// smokes use it to kill the daemon they intentionally KEEP alive on success, so a kept-daemon test
/// never leaks a process. Threaded through the wrapper script alongside the socket.
pub(super) const FAKE_DAEMON_PIDFILE_ENV: &str = "MAESTRO_FAKE_DAEMON_PIDFILE";
pub(super) const FAKE_DAEMON_LEASE_ENV: &str = "MAESTRO_FAKE_DAEMON_LEASE";
/// Stable, valid protocol-v3 process identity for one re-execed fake-daemon process.
pub(super) const FAKE_DAEMON_INSTANCE_ID: &str = "77777777777747778777777777777777";

#[derive(Clone, Debug)]
enum FakeStartOperationState {
    Reserved,
    Refused,
    #[cfg(windows)]
    Retired,
    Applied {
        generation: String,
    },
}

#[derive(Clone, Debug)]
struct FakeStartOperation {
    session_id: String,
    state: FakeStartOperationState,
}

// ============================================================================================
// Fake daemon (private to this test binary)
// ============================================================================================

/// If `MAESTRO_FAKE_DAEMON_SOCKET` is set, run the fake daemon on that socket and exit WITHOUT
/// running any test body. Called as the first statement of every test so that whichever test the
/// libtest harness happens to schedule first in a re-execed process becomes the daemon.
pub(super) fn maybe_run_fake_daemon() {
    // All test bodies enter here before spawning. The runner's own captured standard pipes must
    // not leak through the fixture into later grandchildren either.
    #[cfg(windows)]
    {
        static STDIO: std::sync::OnceLock<()> = std::sync::OnceLock::new();
        STDIO.get_or_init(|| {
            super::windows_process_stdio::detach_capture_pipe_inheritance()
                .expect("isolate test runner capture handles")
        });
    }
    if let Some(socket) = std::env::var_os(FAKE_DAEMON_ENV) {
        run_fake_daemon(Path::new(&socket));
    }
}

/// Bind `socket`, then serve each accepted connection on its own thread: answer the read-only
/// protocol identity probe, read the `StartSession` and `Attach` request lines, and reply with one
/// lightweight `grid` event echoing the requested session id. No real terminal behavior — no
/// resize/scrollback/damage. Serving each connection independently lets an already-bound instance
/// be reused by a second `maestro-app` launch.
pub(super) fn run_fake_daemon(socket: &Path) -> ! {
    // The test fixture, never production startup, owns this process's lifetime. The private owner
    // marker is removed on Workspace drop; a per-process stop marker supports deliberate restarts.
    // This process exits itself, so no stale PID can authorize terminating an unrelated process.
    let lease = std::env::var_os(FAKE_DAEMON_LEASE_ENV).map(PathBuf::from);
    let instance = uuid::Uuid::new_v4().to_string();
    let stop = std::env::var_os(FAKE_DAEMON_PIDFILE_ENV)
        .map(PathBuf::from)
        .map(|p| p.with_extension("stop"));
    if lease.is_some() || stop.is_some() {
        let stop_instance = instance.clone();
        std::thread::spawn(move || loop {
            if lease.as_ref().is_some_and(|p| !p.is_file())
                || stop.as_ref().is_some_and(|p| {
                    std::fs::read_to_string(p).is_ok_and(|value| value == stop_instance)
                })
            {
                std::process::exit(0);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        });
    }
    let listener = UnixListener::bind(socket)
        .unwrap_or_else(|e| panic!("fake daemon could not bind {}: {e}", socket.display()));
    listener
        .set_nonblocking(false)
        .expect("blocking fixture listener");
    let legacy_session = std::env::var(FAKE_DAEMON_LEGACY_SESSION_ENV).ok();
    let request_log = std::env::var_os(FAKE_DAEMON_REQUEST_LOG_ENV).map(PathBuf::from);
    let stateful = std::env::var_os(FAKE_DAEMON_STATEFUL_ENV).is_some();
    let omit_list_file = std::env::var_os(FAKE_DAEMON_OMIT_LIST_FILE_ENV).map(PathBuf::from);
    let sessions = Arc::new(Mutex::new(HashMap::<String, String>::new()));
    let start_operations = Arc::new(Mutex::new(HashMap::<String, FakeStartOperation>::new()));
    let dispatch = Arc::new(Mutex::new(()));

    // Once bound, record our PID if asked, so a test that keeps this daemon alive can kill it.
    if let Some(pidfile) = std::env::var_os(FAKE_DAEMON_PIDFILE_ENV) {
        std::fs::write(Path::new(&pidfile).with_extension("instance"), instance)
            .expect("publish exact fixture instance");
        let _ = std::fs::write(&pidfile, std::process::id().to_string());
    }

    loop {
        let stream = listener.accept().map(|(stream, _)| stream);
        match stream {
            Ok(stream) => {
                // Native pipes use a fixture-level read bound. Preserve Unix's existing setup:
                // macOS setsockopt can return EINVAL after a connection-only probe already closed.
                #[cfg(windows)]
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                    .expect("fixture read timeout");
                let legacy_session = legacy_session.clone();
                let request_log = request_log.clone();
                let sessions = Arc::clone(&sessions);
                let start_operations = Arc::clone(&start_operations);
                let dispatch = Arc::clone(&dispatch);
                let omit_list_file = omit_list_file.clone();
                std::thread::spawn(move || match legacy_session {
                    Some(session_id) => {
                        serve_one_legacy(stream, &session_id, request_log.as_deref())
                    }
                    None if stateful => serve_one_stateful(
                        stream,
                        &sessions,
                        &start_operations,
                        &dispatch,
                        request_log.as_deref(),
                        omit_list_file.as_deref(),
                    ),
                    None => serve_one(stream, &start_operations, &dispatch),
                });
            }
            // accept() is bounded in the Windows test adapter. Idle time is not daemon death;
            // this retained fixture stays alive until its owning test explicitly terminates it.
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(error) => panic!("fixture listener failed: {error}"),
        }
    }
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

fn fake_start_operation_status(operation: Option<&FakeStartOperation>) -> serde_json::Value {
    match operation.map(|operation| &operation.state) {
        None => serde_json::json!({"status": "unknown"}),
        #[cfg(windows)]
        Some(FakeStartOperationState::Retired) => serde_json::json!({"status": "unknown"}),
        Some(FakeStartOperationState::Reserved) => serde_json::json!({"status": "reserved"}),
        Some(FakeStartOperationState::Refused) => serde_json::json!({"status": "refused"}),
        Some(FakeStartOperationState::Applied { generation }) => serde_json::json!({
            "status": "applied",
            "generation": generation,
            "lifecycle": "live",
        }),
    }
}

fn fake_reserve_start_operation(
    operations: &Mutex<HashMap<String, FakeStartOperation>>,
    value: &serde_json::Value,
) -> Option<serde_json::Value> {
    let id = value["id"].as_str()?;
    let operation_token = value["operation_token"].as_str()?;
    let mut operations = operations.lock().ok()?;
    let outcome = match operations.get(operation_token) {
        None => {
            operations.insert(
                operation_token.to_string(),
                FakeStartOperation {
                    session_id: id.to_string(),
                    state: FakeStartOperationState::Reserved,
                },
            );
            serde_json::json!({"status": "reserved"})
        }
        Some(operation) if operation.session_id != id => {
            serde_json::json!({"status": "refused", "reason": "token_in_use"})
        }
        Some(FakeStartOperation {
            state: FakeStartOperationState::Reserved,
            ..
        }) => serde_json::json!({"status": "already_reserved"}),
        Some(_) => serde_json::json!({"status": "refused", "reason": "already_terminal"}),
    };
    Some(serde_json::json!({
        "ev": "start_operation_reserved",
        "id": id,
        "operation_token": operation_token,
        "daemon_instance_id": FAKE_DAEMON_INSTANCE_ID,
        "outcome": outcome,
    }))
}

fn fake_lookup_start_operation(
    operations: &Mutex<HashMap<String, FakeStartOperation>>,
    value: &serde_json::Value,
) -> Option<serde_json::Value> {
    let id = value["id"].as_str()?;
    let operation_token = value["operation_token"].as_str()?;
    let operations = operations.lock().ok()?;
    let operation = operations
        .get(operation_token)
        .filter(|operation| operation.session_id == id);
    Some(serde_json::json!({
        "ev": "start_operation_status",
        "id": id,
        "operation_token": operation_token,
        "daemon_instance_id": FAKE_DAEMON_INSTANCE_ID,
        "status": fake_start_operation_status(operation),
    }))
}

fn fake_retire_start_operation(
    operations: &Mutex<HashMap<String, FakeStartOperation>>,
    value: &serde_json::Value,
) -> Option<serde_json::Value> {
    let id = value["id"].as_str()?;
    let operation_token = value["operation_token"].as_str()?;
    let expected = &value["expected"];
    let mut operations = operations.lock().ok()?;
    let current = operations
        .get(operation_token)
        .filter(|operation| operation.session_id == id)
        .cloned();
    let exact = match (&current, expected["state"].as_str()) {
        (
            Some(FakeStartOperation {
                state: FakeStartOperationState::Reserved | FakeStartOperationState::Refused,
                ..
            }),
            Some("unapplied"),
        ) => true,
        (
            Some(FakeStartOperation {
                state: FakeStartOperationState::Applied { generation },
                ..
            }),
            Some("applied"),
        ) => expected["generation"].as_str() == Some(generation.as_str()),
        _ => false,
    };
    #[cfg(windows)]
    if current.is_none() && !operations.contains_key(operation_token) {
        operations.insert(
            operation_token.to_owned(),
            FakeStartOperation {
                session_id: id.to_owned(),
                state: FakeStartOperationState::Retired,
            },
        );
    }
    let outcome = if current.is_none()
        || fake_start_operation_status(current.as_ref())["status"] == "unknown"
    {
        serde_json::json!({"status": "already_retired"})
    } else if exact {
        #[cfg(unix)]
        operations.remove(operation_token);
        #[cfg(windows)]
        {
            operations.get_mut(operation_token).unwrap().state = FakeStartOperationState::Retired;
        }
        serde_json::json!({"status": "retired"})
    } else {
        serde_json::json!({
            "status": "conflict",
            "current": fake_start_operation_status(current.as_ref()),
        })
    };
    Some(serde_json::json!({
        "ev": "start_operation_retired",
        "id": id,
        "operation_token": operation_token,
        "daemon_instance_id": FAKE_DAEMON_INSTANCE_ID,
        "outcome": outcome,
    }))
}

fn fake_mark_start_operation(
    operations: &Mutex<HashMap<String, FakeStartOperation>>,
    id: &str,
    operation_token: &str,
    state: FakeStartOperationState,
) -> bool {
    let Ok(mut operations) = operations.lock() else {
        return false;
    };
    let Some(operation) = operations.get_mut(operation_token) else {
        return false;
    };
    if operation.session_id != id || !matches!(operation.state, FakeStartOperationState::Reserved) {
        return false;
    }
    operation.state = state;
    true
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
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

/// Modern multi-connection fixture with one process-wide retained-session set. It implements only
/// the protocol surface product startup needs: identity, list, start, and attach/grid.
fn serve_one_stateful(
    mut stream: UnixStream,
    sessions: &Arc<Mutex<HashMap<String, String>>>,
    start_operations: &Arc<Mutex<HashMap<String, FakeStartOperation>>>,
    dispatch: &Mutex<()>,
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
        // Model the daemon's dispatch lock: retirement and start publication cannot interleave.
        let _dispatch = dispatch.lock().unwrap();
        if request.contains("daemon_info") {
            let _ = writeln!(
                stream,
                "{{\"ev\":\"daemon_info\",\"protocol_version\":{},\"build_version\":\"stateful-binary-smoke\",\"daemon_instance_id\":\"{}\",\"output_generation_echo\":true,\"child_environment\":true,\"generation_conditional_mutations\":true,\"attachment_aware_conditional_kill\":true,\"generation_conditional_start\":true,\"start_operation_ledger\":true,\"generation_conditional_attach\":true,\"windows_start_operation_retirement_barrier\":{}}}",
                maestro_protocol::DAEMON_PROTOCOL_VERSION,
                FAKE_DAEMON_INSTANCE_ID,
                cfg!(windows),
            );
        } else if request.contains("reserve_start_operation") {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&request) {
                if let Some(event) = fake_reserve_start_operation(start_operations, &value) {
                    let _ = writeln!(stream, "{event}");
                }
            }
        } else if request.contains("lookup_start_operation") {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&request) {
                if let Some(event) = fake_lookup_start_operation(start_operations, &value) {
                    let _ = writeln!(stream, "{event}");
                }
            }
        } else if request.contains("retire_start_operation") {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&request) {
                if let Some(event) = fake_retire_start_operation(start_operations, &value) {
                    let _ = writeln!(stream, "{event}");
                }
            }
        } else if request.contains("list_sessions") {
            let (mut ids, mut metadata): (Vec<String>, Vec<serde_json::Value>) =
                if omit_list_file.is_some_and(Path::exists) {
                    (Vec::new(), Vec::new())
                } else {
                    let sessions = sessions.lock().expect("session lock");
                    (
                        sessions.keys().cloned().collect(),
                        sessions
                            .iter()
                            .map(|(id, generation)| {
                                serde_json::json!({"id": id, "generation": generation})
                            })
                            .collect(),
                    )
                };
            ids.sort();
            metadata.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
            let _ = writeln!(
                stream,
                "{}",
                serde_json::json!({"ev": "sessions", "ids": ids, "sessions": metadata})
            );
        } else if request.contains("start_session") {
            let value: serde_json::Value = match serde_json::from_str(&request) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let Some(id) = value["id"].as_str() else {
                continue;
            };
            // A daemon generation is process-lifetime identity. Reusing one literal after this
            // fixture is killed/restarted would make an `Absent { excluded_generation: A }`
            // replacement appear to return A again, which the production client correctly treats
            // as an ambiguous protocol contradiction.
            let generation = format!("stateful-grid-{}", std::process::id());
            let existed = sessions.lock().expect("session lock").contains_key(id);
            if let Some(conditional) = value.get("conditional_start") {
                let Some(operation_token) = conditional["operation_token"].as_str() else {
                    continue;
                };
                let refused =
                    existed && conditional["precondition"]["kind"].as_str() == Some("absent");
                let operation_state = if refused {
                    FakeStartOperationState::Refused
                } else {
                    FakeStartOperationState::Applied {
                        generation: generation.clone(),
                    }
                };
                let reserved = fake_mark_start_operation(
                    start_operations,
                    id,
                    operation_token,
                    operation_state,
                );
                let outcome = if !reserved || refused {
                    serde_json::json!({
                        "status": "refused",
                        "reason": "precondition_failed",
                    })
                } else {
                    sessions
                        .lock()
                        .expect("session lock")
                        .insert(id.to_string(), generation.clone());
                    serde_json::json!({"status": "applied", "generation": generation})
                };
                let _ = writeln!(
                    stream,
                    "{}",
                    serde_json::json!({
                        "ev": "conditional_session_start",
                        "id": id,
                        "operation_token": operation_token,
                        "daemon_instance_id": FAKE_DAEMON_INSTANCE_ID,
                        "outcome": outcome,
                    })
                );
            } else {
                sessions
                    .lock()
                    .expect("session lock")
                    .insert(id.to_string(), generation);
            }
        } else if request.contains("\"op\":\"attach\"") {
            let value: serde_json::Value = match serde_json::from_str(&request) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let id = value["id"].as_str().unwrap_or_default();
            let expected = value["expected_session_generation"].as_str();
            let generation = sessions.lock().expect("session lock").get(id).cloned();
            match (generation, expected) {
                (None, Some(expected)) => {
                    let _ = writeln!(
                        stream,
                        "{}",
                        serde_json::json!({
                            "ev": "session_attach_refused",
                            "id": id,
                            "expected_generation": expected,
                            "daemon_instance_id": FAKE_DAEMON_INSTANCE_ID,
                            "reason": "missing",
                        })
                    );
                }
                (Some(generation), Some(expected)) if generation != expected => {
                    let _ = writeln!(
                        stream,
                        "{}",
                        serde_json::json!({
                            "ev": "session_attach_refused",
                            "id": id,
                            "expected_generation": expected,
                            "daemon_instance_id": FAKE_DAEMON_INSTANCE_ID,
                            "reason": "generation_mismatch",
                        })
                    );
                }
                (Some(generation), _) => {
                    let _ = writeln!(
                        stream,
                        "{}",
                        serde_json::json!({
                            "ev": "grid",
                            "id": id,
                            "output_generation": value.get("output_generation").cloned(),
                            "grid": {"generation": generation, "revision": 1},
                        })
                    );
                }
                (None, None) => {
                    let message = format!("no such session: {id}");
                    let _ = writeln!(
                        stream,
                        "{}",
                        serde_json::json!({"ev": "error", "message": message})
                    );
                }
            }
        }
        let _ = stream.flush();
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

/// Serve one connection for the stateless fake used by ordinary launch/agent command smoke tests.
/// Readiness probes use a connection of their own; a mutation connection keeps the session
/// generation it started so the following conditional Attach can be correlated exactly. An empty
/// strict list still drives attach-tab's spawned-daemon not-live failure path.
fn serve_one(
    mut stream: UnixStream,
    shared_operations: &Mutex<HashMap<String, FakeStartOperation>>,
    dispatch: &Mutex<()>,
) {
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    });
    let mut sessions = HashMap::<String, String>::new();
    let start_operations = shared_operations;
    while let Some(request) = read_line(&mut reader) {
        let _dispatch = dispatch.lock().unwrap();
        if request.is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(&request) {
            Ok(value) => value,
            Err(_) => return,
        };
        match value["op"].as_str() {
            Some("daemon_info") => {
                let _ = writeln!(
                    stream,
                    "{}",
                    serde_json::json!({
                        "ev": "daemon_info",
                        "protocol_version": maestro_protocol::DAEMON_PROTOCOL_VERSION,
                        "build_version": "binary-smoke",
                        "daemon_instance_id": FAKE_DAEMON_INSTANCE_ID,
                        "output_generation_echo": true,
                        "child_environment": true,
                        "generation_conditional_mutations": true,
                        "attachment_aware_conditional_kill": true,
                        "generation_conditional_start": true,
                        "start_operation_ledger": true,
                        "generation_conditional_attach": true,
                        "windows_start_operation_retirement_barrier": cfg!(windows),
                    })
                );
            }
            Some("reserve_start_operation") => {
                if let Some(event) = fake_reserve_start_operation(start_operations, &value) {
                    let _ = writeln!(stream, "{event}");
                }
            }
            Some("lookup_start_operation") => {
                if let Some(event) = fake_lookup_start_operation(start_operations, &value) {
                    let _ = writeln!(stream, "{event}");
                }
            }
            Some("retire_start_operation") => {
                if let Some(event) = fake_retire_start_operation(start_operations, &value) {
                    let _ = writeln!(stream, "{event}");
                }
            }
            Some("list_sessions") => {
                let _ = stream.write_all(b"{\"ev\":\"sessions\",\"ids\":[],\"sessions\":[]}\n");
            }
            Some("start_session") => {
                let id = value["id"].as_str().unwrap_or("unknown");
                let generation = "gen-fake";
                if let Some(conditional) = value.get("conditional_start") {
                    if let Some(operation_token) = conditional["operation_token"].as_str() {
                        let applied = fake_mark_start_operation(
                            start_operations,
                            id,
                            operation_token,
                            FakeStartOperationState::Applied {
                                generation: generation.to_string(),
                            },
                        );
                        let outcome = if applied {
                            sessions.insert(id.to_string(), generation.to_string());
                            serde_json::json!({"status": "applied", "generation": generation})
                        } else {
                            serde_json::json!({
                                "status": "refused",
                                "reason": "precondition_failed",
                            })
                        };
                        let _ = writeln!(
                            stream,
                            "{}",
                            serde_json::json!({
                                "ev": "conditional_session_start",
                                "id": id,
                                "operation_token": operation_token,
                                "daemon_instance_id": FAKE_DAEMON_INSTANCE_ID,
                                "outcome": outcome,
                            })
                        );
                    }
                } else {
                    sessions.insert(id.to_string(), generation.to_string());
                }
            }
            Some("attach") => {
                let id = value["id"].as_str().unwrap_or("unknown");
                let generation = value["expected_session_generation"]
                    .as_str()
                    .map(str::to_string)
                    .or_else(|| sessions.get(id).cloned())
                    .unwrap_or_else(|| "gen-fake".to_string());
                let _ = writeln!(
                    stream,
                    "{}",
                    serde_json::json!({
                        "ev": "grid",
                        "id": id,
                        "output_generation": value.get("output_generation").cloned(),
                        "grid": {"generation": generation, "revision": 1},
                    })
                );
            }
            Some("cancel_attachment_handoff") => {
                let _ = writeln!(
                    stream,
                    "{}",
                    serde_json::json!({
                        "ev": "attachment_handoff_cancelled",
                        "id": value["id"],
                        "token": value["token"],
                        "daemon_instance_id": FAKE_DAEMON_INSTANCE_ID,
                    })
                );
            }
            _ => {}
        }
        let _ = stream.flush();
    }
    let _ = stream.shutdown(std::net::Shutdown::Both);
}

pub(super) fn read_line(reader: &mut impl BufRead) -> Option<String> {
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

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn advertised_retirement_barrier_refuses_late_reserve_and_start() {
        use super::*;
        maybe_run_fake_daemon();
        let operations = Mutex::new(HashMap::new());
        let mut request = serde_json::json!({"id":"one", "operation_token":"token", "expected":{"state":"unapplied"}});
        assert_eq!(
            fake_retire_start_operation(&operations, &request).unwrap()["outcome"]["status"],
            "already_retired"
        );
        assert_eq!(
            fake_reserve_start_operation(&operations, &request).unwrap()["outcome"]["status"],
            "refused"
        );
        assert!(!fake_mark_start_operation(
            &operations,
            "one",
            "token",
            FakeStartOperationState::Applied {
                generation: "late".into()
            }
        ));

        request["operation_token"] = "applied-token".into();
        assert_eq!(
            fake_reserve_start_operation(&operations, &request).unwrap()["outcome"]["status"],
            "reserved"
        );
        assert!(fake_mark_start_operation(
            &operations,
            "one",
            "applied-token",
            FakeStartOperationState::Applied {
                generation: "exact".into()
            }
        ));
        request["expected"] = serde_json::json!({"state":"applied", "generation":"different"});
        assert_eq!(
            fake_retire_start_operation(&operations, &request).unwrap()["outcome"]["status"],
            "conflict"
        );
        request["expected"]["generation"] = "exact".into();
        assert_eq!(
            fake_retire_start_operation(&operations, &request).unwrap()["outcome"]["status"],
            "retired"
        );
        assert_eq!(
            fake_reserve_start_operation(&operations, &request).unwrap()["outcome"]["status"],
            "refused"
        );
        assert_eq!(
            fake_lookup_start_operation(&operations, &request).unwrap()["status"]["status"],
            "unknown"
        );
    }
}
