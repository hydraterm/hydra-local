//! Grid-authority smoke test. Proves the daemon parses PTY output through its
//! VT engine and holds the canonical screen: we write known text, ask for a
//! grid snapshot, and assert the rendered cells contain it. Then we resize and
//! assert the grid geometry reflows. This is the property that kills the
//! grid-desync bug class — the renderer can trust this snapshot without
//! re-parsing bytes.

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

fn start_daemon() -> (Child, PathBuf) {
    let bin = env!("CARGO_BIN_EXE_pty-daemon");
    let sock = std::env::temp_dir().join(format!(
        "hydra-grid-test-{}-{}.sock",
        std::process::id(),
        unique()
    ));
    let _ = std::fs::remove_file(&sock);
    let child = Command::new(bin).arg(&sock).spawn().expect("spawn daemon");
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

/// Read lines until one contains `needle`; return it. Panics on timeout.
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

/// Pull "cols" and "rows" out of a grid event line without a JSON dep.
fn parse_usize_field(line: &str, field: &str) -> usize {
    let key = format!("\"{field}\":");
    let start = line.find(&key).expect("field present") + key.len();
    let rest = &line[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().expect("numeric field")
}

/// Reconstruct every grid row's text from the rich per-cell snapshot. The
/// snapshot stores one `"text"` grapheme per cell, so the marker is no longer a
/// contiguous substring of the JSON; we rebuild each row by concatenating its
/// cells' `text` in order and return the rows joined by newline so a marker that
/// landed on a single row is findable with `.contains`.
fn grid_text(line: &str) -> String {
    let v: serde_json::Value = serde_json::from_str(line.trim()).expect("grid event is JSON");
    let rows = v["grid"]["rows_cells"]
        .as_array()
        .expect("rows_cells array");
    let mut out = String::new();
    for row in rows {
        for cell in row.as_array().expect("row is array") {
            let text = cell["text"].as_str().expect("text is a string");
            out.push_str(text);
        }
        out.push('\n');
    }
    out
}

#[test]
fn grid_is_authoritative_and_reflows() {
    let (child, sock) = start_daemon();
    let _killer = Killer(child);

    let id = "grid-sess";
    let marker = "HELLO_GRID";

    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    // A shell that prints our marker then holds the PTY open so the session
    // stays alive to snapshot. 80x24 initial geometry.
    send(
        &mut stream,
        &format!(
            r#"{{"op":"start_session","id":"{id}","cwd":".","command":"sh","args":["-c","printf '{marker}\\n'; sleep 30"],"cols":80,"rows":24}}"#
        ),
    );
    // Let the marker print and parse into the grid.
    std::thread::sleep(Duration::from_millis(400));

    // First snapshot: the marker must appear in a rendered grid line.
    send(&mut stream, &format!(r#"{{"op":"snapshot","id":"{id}"}}"#));
    let snap1 = read_until(&mut reader, "\"grid\"", Duration::from_secs(5));
    assert!(
        grid_text(&snap1).contains(marker),
        "grid snapshot missing rendered marker: {snap1}"
    );
    assert_eq!(parse_usize_field(&snap1, "cols"), 80, "initial cols");
    assert_eq!(parse_usize_field(&snap1, "rows"), 24, "initial rows");

    // Resize, then take a second snapshot: geometry must reflow to the new size.
    send(
        &mut stream,
        &format!(r#"{{"op":"resize","id":"{id}","cols":100,"rows":30}}"#),
    );
    std::thread::sleep(Duration::from_millis(200));
    send(&mut stream, &format!(r#"{{"op":"snapshot","id":"{id}"}}"#));
    let snap2 = read_until(&mut reader, "\"grid\"", Duration::from_secs(5));
    assert_eq!(parse_usize_field(&snap2, "cols"), 100, "resized cols");
    assert_eq!(parse_usize_field(&snap2, "rows"), 30, "resized rows");
    // The marker survives reflow (it was already on screen).
    assert!(
        grid_text(&snap2).contains(marker),
        "marker lost after reflow: {snap2}"
    );
}
