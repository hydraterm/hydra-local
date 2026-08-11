//! Tier-(a) survival smoke test: a PTY session outlives the client that started
//! it. We start the daemon binary, open a session, feed it a marker, drop the
//! connection entirely, then reconnect and assert the marker replays out of the
//! session's scrollback. This is the core property the rewrite exists to give
//! us — agents survive the UI going away.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

fn unique() -> u128 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    nanos + N.fetch_add(1, Ordering::Relaxed) as u128
}

/// Spawn the daemon binary on a unique socket path. Returns the child (kept
/// alive for the test's duration) and the socket path.
fn start_daemon() -> (Child, PathBuf) {
    let bin = env!("CARGO_BIN_EXE_pty-daemon");
    let sock = std::env::temp_dir().join(format!(
        "hydra-pty-test-{}-{}.sock",
        std::process::id(),
        unique()
    ));
    let _ = std::fs::remove_file(&sock);
    let child = Command::new(bin)
        .arg(&sock)
        .spawn()
        .expect("spawn daemon binary");
    // Wait for the listener to bind (socket file appears).
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sock.exists() {
        assert!(Instant::now() < deadline, "daemon never bound its socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    (child, sock)
}

fn connect(sock: &PathBuf) -> UnixStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match UnixStream::connect(sock) {
            Ok(s) => return s,
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("could not connect to daemon socket: {e}"),
        }
    }
}

fn send(stream: &mut UnixStream, line: &str) {
    stream.write_all(line.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    stream.flush().unwrap();
}

/// Read lines until one contains `needle` or we time out. Returns the matching
/// line. Panics on timeout.
fn read_until(reader: &mut impl BufRead, needle: &str, within: Duration) -> String {
    let deadline = Instant::now() + within;
    let mut line = String::new();
    loop {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {needle:?}"
        );
        line.clear();
        let n = reader.read_line(&mut line).unwrap();
        if n == 0 {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        if line.contains(needle) {
            return line.clone();
        }
    }
}

struct Killer(Child);
impl Drop for Killer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Reconstruct the grid's on-screen text from a rich per-cell Grid event. The
/// snapshot stores one `"text"` grapheme per cell, so a marker is no longer a
/// contiguous JSON substring; rebuild each row by concatenating its cells in
/// order so a marker that landed on one row is findable with `.contains`.
fn grid_text(grid_line: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(grid_line.trim()).expect("grid event is JSON");
    let rows = v["grid"]["rows_cells"]
        .as_array()
        .expect("rows_cells array");
    let mut out = String::new();
    for row in rows {
        for cell in row.as_array().expect("row is array") {
            out.push_str(cell["text"].as_str().expect("text is a string"));
        }
        out.push('\n');
    }
    out
}

/// Decode an Output event's base64 `data` to a lossy String, for marker search.
fn output_text(line: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(line.trim()).expect("output event is JSON");
    let data = v["data"].as_str().unwrap_or("");
    let bytes = B64.decode(data).unwrap_or_default();
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Assert the marker survives the attach restore. The marker may land either in
/// the Grid snapshot (if `cat` had already echoed it before the snapshot was
/// taken) or in the live Output frames the daemon streams immediately after the
/// snapshot (if the echo raced just behind it). Both are a valid "the bytes
/// survived" outcome, and the atomic attach boundary guarantees the marker
/// appears in exactly one of them — never lost, never doubled. Scanning both is
/// what makes this deterministic instead of racing the snapshot timing.
fn assert_grid_has_marker(reader: &mut impl BufRead, marker: &str, within: Duration) {
    let deadline = Instant::now() + within;
    let mut seen = String::new();
    let mut line = String::new();
    loop {
        assert!(
            Instant::now() < deadline,
            "restore missing marker {marker:?}; saw:\n{seen}"
        );
        line.clear();
        let n = reader.read_line(&mut line).unwrap();
        if n == 0 {
            std::thread::sleep(Duration::from_millis(10));
            continue;
        }
        if line.contains("\"ev\":\"grid\"") {
            let text = grid_text(&line);
            if text.contains(marker) {
                return;
            }
            seen.push_str(&format!("[grid]\n{text}\n"));
        } else if line.contains("\"ev\":\"output\"") {
            let text = output_text(&line);
            if text.contains(marker) {
                return;
            }
            seen.push_str(&format!("[output] {text}\n"));
        }
    }
}

#[test]
fn session_survives_client_reconnect() {
    let (child, sock) = start_daemon();
    let _killer = Killer(child);

    let session_id = "smoke-sess";
    let marker = "HYDRA_TIER_A_MARKER_4242";

    // First connection: start a `cat` session and feed it our marker. `cat` echoes
    // stdin back to stdout, so the marker lands in the PTY's scrollback.
    {
        let mut stream = connect(&sock);
        // Read half lives in its own clone so writes don't disturb buffering.
        let mut reader = BufReader::new(stream.try_clone().unwrap());

        send(
            &mut stream,
            &format!(
                r#"{{"op":"start_session","id":"{session_id}","cwd":".","command":"cat","args":[],"cols":80,"rows":24}}"#
            ),
        );
        // Give the PTY a moment to spawn before writing to it.
        std::thread::sleep(Duration::from_millis(200));
        send(
            &mut stream,
            &format!(r#"{{"op":"write","id":"{session_id}","data":"{marker}\n"}}"#),
        );

        // Attach so we observe the echoed marker on this connection too,
        // confirming the session is live before we drop the client.
        send(
            &mut stream,
            &format!(r#"{{"op":"attach","id":"{session_id}"}}"#),
        );
        assert_grid_has_marker(&mut reader, marker, Duration::from_secs(5));

        // Drop the stream/reader: client fully disconnects. The daemon (and the
        // cat process it owns) must keep running.
    }

    // The session should still be listed after the client is gone.
    {
        let mut stream = connect(&sock);
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        send(&mut stream, r#"{"op":"list_sessions"}"#);
        let sessions = read_until(&mut reader, "\"sessions\"", Duration::from_secs(5));
        assert!(
            sessions.contains(session_id),
            "session vanished after client disconnect: {sessions}"
        );
    }

    // Second connection: reattach and assert the marker replays from scrollback —
    // proving the bytes the first client wrote outlived that client.
    {
        let mut stream = connect(&sock);
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        send(
            &mut stream,
            &format!(r#"{{"op":"attach","id":"{session_id}"}}"#),
        );
        // The marker replays out of the grid restore the daemon builds from the
        // session's scrollback — proving the bytes outlived the first client.
        assert_grid_has_marker(&mut reader, marker, Duration::from_secs(5));
    }
}
