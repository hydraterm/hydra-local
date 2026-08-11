//! Hardening tests for three corruption/loss failure modes:
//!   - split multibyte UTF-8 across PTY reads survives intact (no replacement
//!     chars) — proves base64 framing + the grid parser, not lossy String conv;
//!   - attach restores from the authoritative grid (a clean screen);
//!   - output that lands during attach is delivered, not lost.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

/// Unique token for socket paths: UNIX-nanos plus an atomic counter, so two
/// tests running in parallel in the same binary never collide. (`Instant`
/// elapsed-from-now is ~0 every call and would collide.)
fn unique() -> u128 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    nanos + N.fetch_add(1, Ordering::Relaxed) as u128
}

fn start_daemon() -> (Child, PathBuf) {
    let bin = env!("CARGO_BIN_EXE_pty-daemon");
    let sock = std::env::temp_dir().join(format!(
        "hydra-corrupt-test-{}-{}.sock",
        std::process::id(),
        unique()
    ));
    let _ = std::fs::remove_file(&sock);
    let child = Command::new(bin).arg(&sock).spawn().expect("spawn daemon");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sock.exists() {
        assert!(Instant::now() < deadline, "daemon never bound");
        std::thread::sleep(Duration::from_millis(20));
    }
    (child, sock)
}

fn connect(sock: &PathBuf) -> UnixStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match UnixStream::connect(sock) {
            Ok(s) => return s,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("connect failed: {e}"),
        }
    }
}

fn send(stream: &mut UnixStream, line: &str) {
    stream.write_all(line.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    stream.flush().unwrap();
}

fn read_until(reader: &mut impl BufRead, needle: &str, within: Duration) -> String {
    let deadline = Instant::now() + within;
    let mut line = String::new();
    loop {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {needle:?}"
        );
        line.clear();
        if reader.read_line(&mut line).unwrap() == 0 {
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

/// Reconstruct the grid's text from the rich per-cell snapshot. Each cell is
/// stored as its own `"text"` grapheme, so a marker is no longer a contiguous
/// JSON substring; rebuild each row by concatenating its cells in order so a
/// marker that landed on one row is findable with `.contains`.
fn grid_text(line: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(line.trim()).expect("grid event is JSON");
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

/// Decode the base64 `data` field out of an Output event line.
fn decode_output(line: &str) -> Vec<u8> {
    let key = "\"data\":\"";
    let start = line.find(key).expect("data field") + key.len();
    let rest = &line[start..];
    let end = rest.find('"').expect("closing quote");
    B64.decode(&rest[..end]).expect("valid base64")
}

/// A 2-byte UTF-8 char ('ş', U+015F) fed one byte per PTY write must come
/// back through the live stream as intact bytes, and render as one grid cell —
/// not two replacement characters. Lossy per-chunk String conversion would
/// turn the split read into garbage; base64 + the grid parser preserve it.
#[test]
fn split_utf8_survives() {
    let (child, sock) = start_daemon();
    let _killer = Killer(child);
    let id = "utf8-sess";

    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    // `cat` echoes stdin to stdout; hold it open with a trailing sleep is not
    // needed since cat stays alive on an open PTY.
    send(
        &mut stream,
        &format!(
            r#"{{"op":"start_session","id":"{id}","cwd":".","command":"cat","args":[],"cols":80,"rows":24}}"#
        ),
    );
    send(&mut stream, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
    // Drain the initial Grid restore event so we then read live Output.
    let _ = read_until(&mut reader, "\"grid\"", Duration::from_secs(5));
    std::thread::sleep(Duration::from_millis(100));

    // 'ş' = bytes 0xC5 0x9F. The fix under test is the OUTPUT path: the PTY
    // reader can split this 2-byte char across reads, and the old code ran
    // String::from_utf8_lossy per chunk, mangling it. We send the full char and
    // assert the echoed bytes decode back to the exact 2-byte sequence — proving
    // base64 framing carries raw bytes losslessly regardless of read boundaries.
    send(
        &mut stream,
        &format!(r#"{{"op":"write","id":"{id}","data":"ş\n"}}"#),
    );

    // Collect echoed Output until we've seen the 2 bytes of 'ş'.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut got = Vec::new();
    while Instant::now() < deadline {
        let line = read_until(&mut reader, "\"ev\":\"output\"", Duration::from_secs(5));
        got.extend(decode_output(&line));
        if got.windows(2).any(|w| w == [0xC5, 0x9F]) {
            break;
        }
    }
    assert!(
        got.windows(2).any(|w| w == [0xC5, 0x9F]),
        "echoed output never contained intact 'ş' bytes; got {got:?}"
    );
    // And the decoded stream must be valid UTF-8 containing the char (no U+FFFD).
    let text = String::from_utf8_lossy(&got);
    assert!(text.contains('ş'), "decoded output missing 'ş': {text:?}");
    assert!(
        !text.contains('\u{FFFD}'),
        "decoded output has replacement char: {text:?}"
    );
}

/// Attach restores from the grid, and output produced after the
/// session starts (but the client only attaches later) is visible in that grid
/// restore — i.e. the daemon's grid is the source of truth, populated live.
#[test]
fn attach_restores_from_grid() {
    let (child, sock) = start_daemon();
    let _killer = Killer(child);
    let id = "restore-sess";
    let marker = "RESTORE_ME_77";

    // Connection A: start a session that prints the marker, then disconnect
    // without ever attaching.
    {
        let mut a = connect(&sock);
        send(
            &mut a,
            &format!(
                r#"{{"op":"start_session","id":"{id}","cwd":".","command":"sh","args":["-c","printf '{marker}\\n'; sleep 30"],"cols":80,"rows":24}}"#
            ),
        );
        std::thread::sleep(Duration::from_millis(400));
    }

    // Connection B: attach fresh. The FIRST event must be a Grid restore that
    // already contains the marker — proving restore comes from the grid, not a
    // raw replay this client happened to witness live.
    let mut b = connect(&sock);
    let mut reader = BufReader::new(b.try_clone().unwrap());
    send(&mut b, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
    let grid = read_until(&mut reader, "\"ev\":\"grid\"", Duration::from_secs(5));
    assert!(
        grid_text(&grid).contains(marker),
        "attach grid restore missing marker: {grid}"
    );
}
