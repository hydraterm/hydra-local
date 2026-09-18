//! S4 — LIVE local PTY smoke (last step). Spawns the REAL pty-daemon, starts a real bash session, and
//! drives the S4 `TerminalBridge` against it via a real `SessionBackend` over the daemon's Unix socket:
//! attach → send `ls` as terminal_input → confirm real daemon OUTPUT frames come back as binary
//! `terminal_output` → resize → detach. Local loopback only, no network. Proves the bridge's translation
//! to the existing daemon protocol end-to-end with a real PTY.
//!
//! Run: `cargo test -p hydra-agent --test s4_live_pty_smoke`

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use hydra_agent::remote_bridge::{
    Outbound, SessionBackend, TerminalBridge, TerminalMsg, TerminalReply,
};
use hydra_agent::remote_frame::{decode, FrameKind};
use hydra_agent::remote_policy::SameAsLocalPolicy;
use hydra_agent::remote_token::TokenClaims;

// ---- minimal daemon harness (mirrors pty-daemon/tests/common) ----

fn socket_path() -> PathBuf {
    static NEXT_SOCKET: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let sequence = NEXT_SOCKET.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("hydra-s4-smoke-{pid}-{sequence}.sock"))
}

/// Locate the built pty-daemon binary. `CARGO_BIN_EXE_pty-daemon` isn't exported to a sibling crate's
/// tests, so derive it from this test binary's own location: target/<profile>/deps/<thisbin> →
/// target/<profile>/pty-daemon.
fn daemon_binary() -> PathBuf {
    let mut dir = std::env::current_exe().expect("test exe path");
    dir.pop(); // drop the test binary name
    if dir.ends_with("deps") {
        dir.pop();
    }
    let bin = dir.join("pty-daemon");
    assert!(
        bin.exists(),
        "pty-daemon not built at {bin:?} (run the daemon build first)"
    );
    bin
}

fn start_daemon(sock: &PathBuf) -> Child {
    let child = Command::new(daemon_binary())
        .arg(sock)
        .spawn()
        .expect("spawn daemon");
    let deadline = Instant::now() + Duration::from_secs(5);
    while UnixStream::connect(sock).is_err() {
        assert!(Instant::now() < deadline, "daemon never accepted");
        std::thread::sleep(Duration::from_millis(20));
    }
    child
}

struct Killer {
    child: Child,
    socket: PathBuf,
}
impl Drop for Killer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

/// A blocking control connection to the daemon: sends ClientRequest JSON lines.
struct DaemonConn {
    write: UnixStream,
}
impl DaemonConn {
    fn connect(sock: &PathBuf) -> (Self, BufReader<UnixStream>) {
        let s = UnixStream::connect(sock).expect("connect daemon");
        let read_half = s.try_clone().unwrap();
        // The read timeout must be on the CLONE we actually read from, else read_line blocks forever and
        // the wall-clock deadline never fires.
        read_half
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        (DaemonConn { write: s }, BufReader::new(read_half))
    }
    fn send(&mut self, line: &str) {
        self.write.write_all(line.as_bytes()).unwrap();
        self.write.write_all(b"\n").unwrap();
        self.write.flush().unwrap();
    }
}

/// The REAL SessionBackend: translates bridge calls into daemon ClientRequest JSON over the socket.
/// (Output is read separately from the daemon stream in the test, then handed to the bridge to frame.)
struct DaemonBackend {
    conn: DaemonConn,
    sessions: Vec<String>,
    generations: std::sync::Arc<std::sync::Mutex<std::collections::BTreeMap<String, String>>>,
    pending_resize: std::sync::Arc<std::sync::Mutex<Option<PendingResize>>>,
}

struct PendingResize {
    session_id: String,
    cols: u16,
    rows: u16,
    authority: hydra_agent::winsize_owner::DeferredResizeAuthority,
}
impl SessionBackend for DaemonBackend {
    fn list_sessions(&self) -> Vec<String> {
        self.sessions.clone()
    }
    fn attach(&mut self, id: &str, _cols: u16, _rows: u16, _raw: bool) -> Result<(), String> {
        self.conn.send(&format!(
            r#"{{"op":"attach","id":"{id}","want_raw_output":true}}"#
        ));
        Ok(())
    }
    fn attach_with_output_generation(
        &mut self,
        id: &str,
        cols: u16,
        rows: u16,
        raw: bool,
        output_generation: u64,
        deferred_resize_authority: Option<hydra_agent::winsize_owner::DeferredResizeAuthority>,
    ) -> Result<(), String> {
        self.conn.send(&format!(
            r#"{{"op":"attach","id":{},"want_raw_output":{raw},"output_generation":{output_generation}}}"#,
            json_str(id),
        ));
        let mut pending = self
            .pending_resize
            .lock()
            .map_err(|_| "pending resize cache poisoned".to_string())?;
        *pending = deferred_resize_authority.map(|authority| PendingResize {
            session_id: id.to_string(),
            cols,
            rows,
            authority,
        });
        Ok(())
    }
    fn input(&mut self, id: &str, bytes: &[u8]) -> Result<(), String> {
        let data = String::from_utf8_lossy(bytes);
        let generation = self
            .generations
            .lock()
            .map_err(|_| "generation cache poisoned".to_string())?
            .get(id)
            .cloned()
            .ok_or_else(|| "attach generation unconfirmed".to_string())?;
        self.conn.send(&format!(
            r#"{{"op":"write","id":"{id}","data":{},"expected_generation":{}}}"#,
            json_str(&data),
            json_str(&generation)
        ));
        Ok(())
    }
    fn resize(&mut self, id: &str, cols: u16, rows: u16) -> Result<(), String> {
        let generation = self
            .generations
            .lock()
            .map_err(|_| "generation cache poisoned".to_string())?
            .get(id)
            .cloned()
            .ok_or_else(|| "attach generation unconfirmed".to_string())?;
        self.conn.send(&format!(
            r#"{{"op":"resize","id":"{id}","cols":{cols},"rows":{rows},"expected_generation":{}}}"#,
            json_str(&generation)
        ));
        Ok(())
    }
    fn scrollback(&mut self, id: &str, offset_from_top: u32, count: u16) -> Result<(), String> {
        self.conn.send(&format!(
            r#"{{"op":"scrollback","id":"{id}","offset_from_top":{offset_from_top},"count":{count}}}"#
        ));
        Ok(())
    }
    fn detach(&mut self, id: &str) {
        self.conn.send(&format!(r#"{{"op":"detach","id":"{id}"}}"#));
    }
}

fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

fn read_until(reader: &mut impl BufRead, needle: &str, within: Duration) -> Option<String> {
    let deadline = Instant::now() + within;
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => return None,
            Ok(_) => {
                if line.contains(needle) {
                    return Some(line.clone());
                }
            }
            Err(_) => continue, // read timeout tick; keep trying until the deadline
        }
    }
    None
}

fn read_output_until_marker(
    reader: &mut impl BufRead,
    marker: &[u8],
    within: Duration,
) -> Option<Vec<u8>> {
    let deadline = Instant::now() + within;
    let mut decoded = Vec::new();
    let mut line = String::new();
    while Instant::now() < deadline {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => return None,
            Ok(_) => {
                let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
                    continue;
                };
                if value.get("ev").and_then(|ev| ev.as_str()) != Some("output") {
                    continue;
                }
                let Some(data) = value.get("data").and_then(|data| data.as_str()) else {
                    continue;
                };
                let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(data) else {
                    continue;
                };
                decoded.extend_from_slice(&bytes);
                if decoded.windows(marker.len()).any(|window| window == marker) {
                    return Some(decoded);
                }
            }
            Err(_) => continue,
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn process_fd_count(pid: u32) -> usize {
    std::fs::read_dir(format!("/proc/{pid}/fd"))
        .unwrap_or_else(|error| panic!("Linux QA must expose /proc/{pid}/fd: {error}"))
        .count()
}

fn claims() -> TokenClaims {
    TokenClaims {
        account_id: "acct".into(),
        device_id: "dev_a".into(),
        session_id: None, // account-scoped → same-as-local policy
        signal_session_id: None,
        target_device_id: None,
        browser_pubkey: None,
        browser_pubkey_alg: None,
        refresh_parent_sha256: None,
        iat_ms: 0,
        exp_ms: 1_000_000,
    }
}

#[test]
fn live_pty_attach_input_output_resize_detach() {
    let sock = socket_path();
    let _killer = Killer {
        child: start_daemon(&sock),
        socket: sock.clone(),
    };

    // The bridge's backend connection both STARTS the session and drives it (the daemon scopes a session
    // to its connection; a remote client over the real bridge would likewise hold one connection).
    let (mut conn, mut daemon_rx) = DaemonConn::connect(&sock);
    conn.send(r#"{"op":"start_session","id":"s1","cwd":"/tmp","command":"bash","args":["--norc","-i"],"cols":220,"rows":70}"#);
    std::thread::sleep(Duration::from_millis(300)); // let the PTY spawn
    let generations = std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::new()));
    let pending_resize = std::sync::Arc::new(std::sync::Mutex::new(None));
    let mut deferred_conn = DaemonConn {
        write: conn.write.try_clone().expect("clone daemon writer"),
    };
    let backend = DaemonBackend {
        conn,
        sessions: vec!["s1".into()],
        generations: generations.clone(),
        pending_resize: pending_resize.clone(),
    };
    let owner = std::sync::Arc::new(std::sync::Mutex::new(
        hydra_agent::winsize_owner::WinsizeOwner::new(),
    ));
    owner.lock().unwrap().set_serving(1, 0);
    let mut bridge = TerminalBridge::new(backend, SameAsLocalPolicy, claims())
        .with_winsize_owner(owner, "s4-connection");

    // session_list shows the real session
    let r = bridge.handle(TerminalMsg::SessionList {
        request_id: "q".into(),
    });
    match &r[0] {
        Outbound::Json(TerminalReply::SessionListResult { sessions, .. }) => {
            assert!(sessions.contains(&"s1".to_string()), "real session listed");
        }
        other => panic!("expected session_list_result, got {other:?}"),
    }

    // Attach the actively viewed structured pane. Mutation remains blocked until this exact Grid.
    let r = bridge.handle(TerminalMsg::AttachSession {
        request_id: "a".into(),
        session_id: "s1".into(),
        cols: 80,
        rows: 24,
        raw: false,
        viewed: true,
    });
    assert!(
        matches!(&r[0], Outbound::Json(TerminalReply::AttachOk { .. })),
        "attach_ok"
    );
    let _structured_channel = match &r[0] {
        Outbound::Json(TerminalReply::AttachOk { channel, .. }) => *channel,
        _ => unreachable!(),
    };
    // Attach itself is read-only: the exact baseline still carries the daemon's original 220×70
    // geometry. Only after this Grid supplies the PTY generation may the token-bound conditional
    // Resize publish the browser's requested 80×24.
    let initial_grid = read_until(&mut daemon_rx, "\"ev\":\"grid\"", Duration::from_secs(5))
        .expect("attach grid snapshot");
    let initial_grid_json: serde_json::Value =
        serde_json::from_str(&initial_grid).expect("initial Grid is valid JSON");
    let generation = initial_grid_json["grid"]["generation"]
        .as_str()
        .expect("initial Grid generation")
        .to_string();
    generations
        .lock()
        .unwrap()
        .insert("s1".into(), generation.clone());
    assert_eq!(initial_grid_json["grid"]["cols"], 220);
    assert_eq!(initial_grid_json["grid"]["rows"], 70);

    let pending = pending_resize
        .lock()
        .unwrap()
        .take()
        .expect("viewed structured Attach retained deferred geometry");
    assert_eq!(pending.session_id, "s1");
    assert!(pending.authority.publish_resize_if_current(|| {
        deferred_conn.send(&format!(
            r#"{{"op":"resize","id":{},"cols":{},"rows":{},"expected_generation":{}}}"#,
            json_str(&pending.session_id),
            pending.cols,
            pending.rows,
            json_str(&generation),
        ));
        true
    }));
    deferred_conn.send(r#"{"op":"snapshot","id":"s1"}"#);
    let resized_grid = read_until(&mut daemon_rx, "\"ev\":\"grid\"", Duration::from_secs(5))
        .expect("post-Grid conditional Resize snapshot");
    let resized_grid_json: serde_json::Value =
        serde_json::from_str(&resized_grid).expect("resized Grid is valid JSON");
    assert_eq!(resized_grid_json["grid"]["cols"], 80);
    assert_eq!(resized_grid_json["grid"]["rows"], 24);
    assert!(
        resized_grid.len() < 1_000_000,
        "80x24 initial Grid unexpectedly exceeded the bounded smoke-test budget"
    );

    // Reattach raw for the existing marker/output half of this smoke. Raw Attach deliberately
    // carries no deferred resize token; its exact Grid preserves the generation cache used below.
    assert!(bridge
        .handle(TerminalMsg::Detach {
            session_id: "s1".into(),
        })
        .is_empty());
    let raw_reply = bridge.handle(TerminalMsg::AttachSession {
        request_id: "raw".into(),
        session_id: "s1".into(),
        cols: 80,
        rows: 24,
        raw: true,
        viewed: true,
    });
    let channel = match &raw_reply[0] {
        Outbound::Json(TerminalReply::AttachOk { channel, .. }) => *channel,
        other => panic!("expected raw attach_ok, got {other:?}"),
    };
    let raw_grid = read_until(&mut daemon_rx, "\"ev\":\"grid\"", Duration::from_secs(5))
        .expect("raw reattach Grid");
    let raw_generation = serde_json::from_str::<serde_json::Value>(&raw_grid)
        .expect("raw Grid JSON")["grid"]["generation"]
        .as_str()
        .expect("raw Grid generation")
        .to_string();
    generations
        .lock()
        .unwrap()
        .insert("s1".into(), raw_generation);

    // send `echo HELLO_S4` as terminal_input over the bridge → reaches the real PTY
    let inp = bridge.handle_input(channel, b"echo HELLO_S4\n");
    assert!(inp.is_empty(), "input accepted");

    // the daemon streams output frames back; find one carrying our echoed marker, then frame it as a
    // terminal_output BINARY frame via the bridge — proving the agent→client output path end-to-end.
    // The daemon's Output `data` is base64-encoded PTY bytes. PTYs may chunk the echo or append the
    // prompt in the same frame, so decode the daemon data and search the actual bytes instead of
    // depending on one exact base64 spelling.
    const MARKER: &[u8] = b"HELLO_S4";
    let out_line = {
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut found: Option<String> = None;
        let mut decoded = Vec::new();
        let mut all = String::new();
        let mut line = String::new();
        while Instant::now() < deadline && found.is_none() {
            line.clear();
            match daemon_rx.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    all.push_str(&line);
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
                        if v.get("ev").and_then(|ev| ev.as_str()) == Some("output") {
                            if let Some(data) = v.get("data").and_then(|data| data.as_str()) {
                                if let Ok(bytes) =
                                    base64::engine::general_purpose::STANDARD.decode(data)
                                {
                                    decoded.extend_from_slice(&bytes);
                                }
                            }
                        }
                    }
                    if decoded.windows(MARKER.len()).any(|w| w == MARKER) {
                        found = Some(line.clone());
                    }
                }
                Err(_) => continue,
            }
        }
        found.unwrap_or_else(|| {
            let tail = &all[all.len().saturating_sub(2000)..];
            panic!("no marker in daemon output. tail:\n{tail}");
        })
    };
    let frame = bridge
        .output_frame("s1", out_line.as_bytes())
        .expect("attached → frame");
    match frame {
        Outbound::Binary(bytes) => {
            let f = decode(&bytes).unwrap();
            assert_eq!(f.kind, FrameKind::TerminalOutput);
            assert_eq!(f.channel, channel);
            // the frame carries the daemon output line verbatim (opaque pass-through).
            assert_eq!(f.payload, out_line.as_bytes());
        }
        other => panic!("expected binary terminal_output, got {other:?}"),
    }

    // resize + detach reach the daemon without error
    assert!(bridge
        .handle(TerminalMsg::Resize {
            session_id: "s1".into(),
            cols: 100,
            rows: 30,
            viewed: true,
        })
        .is_empty());
    assert!(bridge
        .handle(TerminalMsg::Detach {
            session_id: "s1".into()
        })
        .is_empty());
    assert_eq!(bridge.attach_count(), 0, "detach cleaned up the attach");

    // no terminal bytes were ever logged/sent anywhere but the DTLS-equivalent local path; nothing to
    // assert at the cloud here (the bridge has no cloud handle at all — content-blind by construction).
}

/// Process-level teardown complement to `remote_peer`'s injected liveness tests.
///
/// A half-open peer owner ultimately revokes/drops its `TerminalBridge`. That drop must close the
/// per-connection daemon request/event tasks and their Unix socket, but it must never terminate the
/// PTY independently owned by `pty-daemon`. Exercise that exact lower half repeatedly against a real
/// daemon process. On Linux, also fail if the cycles leave a growing set of process FDs behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_bridge_teardown_releases_fds_and_retains_the_daemon_pty() {
    const SESSION: &str = "remote-teardown-retained";
    const CYCLES: usize = 24;
    const MARKER: &[u8] = b"HYDRA_RETAINED_AFTER_REMOTE_TEARDOWN";

    let sock = socket_path();
    let daemon = start_daemon(&sock);
    #[cfg(target_os = "linux")]
    let daemon_pid = daemon.id();
    let _killer = Killer {
        child: daemon,
        socket: sock.clone(),
    };

    // A witness connection creates and observes the daemon-owned PTY independently of every
    // short-lived remote bridge below.
    let (mut witness, mut witness_rx) = DaemonConn::connect(&sock);
    witness.send(&format!(
        r#"{{"op":"start_session","id":"{SESSION}","cwd":"/tmp","command":"cat","args":[],"cols":80,"rows":24}}"#
    ));
    std::thread::sleep(Duration::from_millis(250));
    witness.send(&format!(
        r#"{{"op":"attach","id":"{SESSION}","want_raw_output":true}}"#
    ));
    let witness_grid = read_until(&mut witness_rx, "\"ev\":\"grid\"", Duration::from_secs(5))
        .expect("witness attach baseline");
    let witness_generation = serde_json::from_str::<serde_json::Value>(&witness_grid)
        .expect("witness Grid JSON")["grid"]["generation"]
        .as_str()
        .expect("witness Grid generation")
        .to_string();

    #[cfg(target_os = "linux")]
    let baseline_fds = (
        process_fd_count(std::process::id()),
        process_fd_count(daemon_pid),
    );

    for cycle in 0..CYCLES {
        let (backend, daemon_output) = hydra_agent::remote_daemon_backend::spawn_daemon_task(
            sock.clone(),
            vec![SESSION.to_string()],
        )
        .await
        .unwrap_or_else(|error| panic!("cycle {cycle}: connect remote daemon bridge: {error}"));
        let mut bridge = TerminalBridge::new(backend, SameAsLocalPolicy, claims());
        let reply = bridge.handle(TerminalMsg::AttachSession {
            request_id: format!("attach-{cycle}"),
            session_id: SESSION.to_string(),
            cols: 80,
            rows: 24,
            raw: true,
            viewed: true,
        });
        assert!(
            matches!(
                reply.first(),
                Some(Outbound::Json(TerminalReply::AttachOk { .. }))
            ),
            "cycle {cycle}: real daemon bridge did not attach: {reply:?}"
        );

        // This is the lower half of the production liveness exit: bridge Drop sends Detach, backend
        // Drop closes the request channel, and dropping the receiver lets the event task finish.
        drop(bridge);
        drop(daemon_output);
        tokio::task::yield_now().await;
    }

    #[cfg(target_os = "linux")]
    {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let current = (
                process_fd_count(std::process::id()),
                process_fd_count(daemon_pid),
            );
            if current.0 <= baseline_fds.0 + 2 && current.1 <= baseline_fds.1 + 2 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "remote bridge teardown leaked process FDs: agent baseline={}, after={}; daemon baseline={}, after={}",
                baseline_fds.0,
                current.0,
                baseline_fds.1,
                current.1,
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    // If remote teardown accidentally killed the retained PTY, this write cannot be echoed by the
    // still-attached witness. Seeing the marker proves process + terminal lifetime survived all cycles.
    witness.send(&format!(
        r#"{{"op":"write","id":"{SESSION}","data":"{}\n","expected_generation":{}}}"#,
        String::from_utf8_lossy(MARKER),
        json_str(&witness_generation)
    ));
    read_output_until_marker(&mut witness_rx, MARKER, Duration::from_secs(5))
        .expect("retained PTY must remain writable after remote bridge teardown");
}
