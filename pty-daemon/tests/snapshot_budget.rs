//! Snapshot cell-budget contract:
//! - a grid sized to the LARGEST supported snapshot actually crosses the socket as one
//!   newline-delimited JSON line (proving the budget keeps snapshots wire-shippable);
//! - an over-budget `StartSession` is REJECTED with an explicit error (direct protocol
//!   requests are rejected, not silently clamped).

mod common;

use common::{connect, read_until, send, socket_path, start_daemon_on, Killer};
use std::io::BufReader;
use std::time::Duration;

/// The largest supported square grid. `MAX_SNAPSHOT_CELLS` is 32752; the largest square
/// that fits is 180x180 = 32400 <= budget. Kept in sync with `grid::MAX_SNAPSHOT_CELLS`;
/// if that derivation changes, update this (the over-budget test below still guards the
/// upper bound independently).
const MAX_SQUARE_SIDE: u16 = 180;

#[test]
fn largest_supported_snapshot_crosses_the_socket() {
    let sock = socket_path("snap-budget-max");
    let _ = std::fs::remove_file(&sock);
    let child = start_daemon_on(&sock);
    let _killer = Killer(child);

    let id = "big-sess";
    let mut stream = connect(&sock);
    // A big snapshot line can exceed the default BufReader capacity across reads; a
    // generously sized reader keeps read_line from stalling on a partial buffer.
    let mut reader = BufReader::with_capacity(1 << 20, stream.try_clone().unwrap());

    // Start a session at the largest supported square and hold the PTY open.
    send(
        &mut stream,
        &format!(
            r#"{{"op":"start_session","id":"{id}","cwd":".","command":"sh","args":["-c","sleep 30"],"cols":{MAX_SQUARE_SIDE},"rows":{MAX_SQUARE_SIDE}}}"#
        ),
    );
    std::thread::sleep(Duration::from_millis(400));

    send(&mut stream, &format!(r#"{{"op":"snapshot","id":"{id}"}}"#));
    // The whole grid arrives as ONE line; read_until returns it intact.
    let snap = read_until(&mut reader, "\"ev\":\"grid\"", Duration::from_secs(10));

    let v: serde_json::Value = serde_json::from_str(snap.trim()).expect("grid line is valid JSON");
    assert_eq!(v["grid"]["version"].as_u64(), Some(2));
    assert_eq!(v["grid"]["cols"].as_u64(), Some(MAX_SQUARE_SIDE as u64));
    assert_eq!(v["grid"]["rows"].as_u64(), Some(MAX_SQUARE_SIDE as u64));
    // Sanity: the grid genuinely has the full cell array (no trimming).
    let rows = v["grid"]["rows_cells"]
        .as_array()
        .expect("rows_cells array");
    assert_eq!(rows.len(), MAX_SQUARE_SIDE as usize);
    assert_eq!(
        rows[0].as_array().unwrap().len(),
        MAX_SQUARE_SIDE as usize,
        "each row carries exactly cols cells"
    );
}

#[test]
fn over_budget_start_session_is_rejected() {
    let sock = socket_path("snap-budget-reject");
    let _ = std::fs::remove_file(&sock);
    let child = start_daemon_on(&sock);
    let _killer = Killer(child);

    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    // 2000x2000 = 4e6 cells is far over the snapshot cell budget — the daemon must
    // reject it with an explicit Error rather than spawn an un-shippable grid.
    send(
        &mut stream,
        r#"{"op":"start_session","id":"too-big","cwd":".","command":"sh","args":["-c","sleep 30"],"cols":2000,"rows":2000}"#,
    );
    let err = read_until(&mut reader, "\"ev\":\"error\"", Duration::from_secs(5));
    assert!(
        err.contains("budget") || err.contains("cell"),
        "expected a snapshot-budget rejection, got: {err}"
    );

    // And the session was NOT created: a snapshot for it returns an error, not a grid.
    send(&mut stream, r#"{"op":"snapshot","id":"too-big"}"#);
    let resp = read_until(&mut reader, "\"ev\":\"error\"", Duration::from_secs(5));
    assert!(
        resp.contains("no such session"),
        "rejected session must not exist: {resp}"
    );
}
