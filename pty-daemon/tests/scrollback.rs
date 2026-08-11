//! Over-the-wire scrollback read path: a `scrollback` request is answered with a
//! `ScrollbackRows` event (NEVER a `Grid`), carrying STRUCTURED historical rows that
//! scrolled above the live screen. We print more numbered lines than the screen holds so
//! the early ones land in history, then read them back by offset and assert the reply is
//! a scrollback event whose rows contain those earlier lines as real cells.

use std::io::BufReader;
use std::time::Duration;

mod common;
use common::{connect, read_until, send, socket_path, start_daemon_on, Killer};

/// Join a wire row (array of cell objects) into its visible text, trimming trailing
/// blanks. Spacer cells contribute their (empty) text.
fn row_text(row: &serde_json::Value) -> String {
    let s: String = row
        .as_array()
        .expect("row is array")
        .iter()
        .map(|c| c["text"].as_str().unwrap_or(""))
        .collect();
    s.trim_end().to_string()
}

#[test]
fn scrollback_request_returns_structured_history_rows() {
    let sock = socket_path("scrollback");
    let _ = std::fs::remove_file(&sock);
    let child = start_daemon_on(&sock);
    let _killer = Killer(child);

    let id = "sb-sess";

    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    // A 6-row screen. Print line0..line19 (20 lines) so line0..~13 scroll into history,
    // then hold the PTY open. `seq` + printf keeps it portable.
    send(
        &mut stream,
        &format!(
            r#"{{"op":"start_session","id":"{id}","cwd":".","command":"sh","args":["-c","i=0; while [ $i -lt 20 ]; do printf 'line%d\n' $i; i=$((i+1)); done; sleep 30"],"cols":40,"rows":6}}"#
        ),
    );
    std::thread::sleep(Duration::from_millis(500));

    // Ask for a window deep in history: 10 rows above the screen top, count 6.
    send(
        &mut stream,
        &format!(r#"{{"op":"scrollback","id":"{id}","offset_from_top":10,"count":6}}"#),
    );

    // The reply MUST be a scrollback_rows event, NOT a grid.
    let line = read_until(
        &mut reader,
        "\"ev\":\"scrollback_rows\"",
        Duration::from_secs(5),
    );
    let v: serde_json::Value = serde_json::from_str(line.trim()).expect("scrollback event is JSON");

    assert_eq!(
        v["ev"].as_str(),
        Some("scrollback_rows"),
        "reply must be scrollback_rows, not grid: {line}"
    );
    assert_eq!(v["id"].as_str(), Some(id), "echoes session id: {line}");
    assert!(v["generation"].is_string(), "carries generation: {line}");
    assert!(v["revision"].is_number(), "carries revision: {line}");
    assert!(
        v["history_len"].as_u64().unwrap_or(0) >= 6,
        "history_len reflects scrolled-off lines: {line}"
    );
    assert_eq!(
        v["offset_from_top"].as_u64(),
        Some(10),
        "offset echoed (within history, not clamped): {line}"
    );

    let rows = v["rows"].as_array().expect("rows array");
    assert_eq!(rows.len(), 6, "returned the requested 6 rows: {line}");

    // Each row is exactly cols (40) wide and carries STRUCTURED cells (objects with a
    // text field) — never a raw byte blob.
    for row in rows {
        let cells = row.as_array().expect("row is array");
        assert_eq!(cells.len(), 40, "each row is cols wide: {line}");
        assert!(
            cells[0]["text"].is_string(),
            "cells are structured, not raw bytes: {line}"
        );
    }

    // The window returns 6 CONTIGUOUS earlier history rows, top-to-bottom. The exact
    // starting line index depends on how the shell laid out its prompt around our output,
    // so we assert the structural invariant (contiguous "lineN" rows ascending by one)
    // rather than a hardcoded start — that is what proves we read real, ordered history.
    let texts: Vec<String> = rows.iter().map(row_text).collect();
    let nums: Vec<usize> = texts
        .iter()
        .map(|t| {
            t.strip_prefix("line")
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| panic!("each scrollback row is a numbered line: {texts:?}"))
        })
        .collect();
    for w in nums.windows(2) {
        assert_eq!(
            w[1],
            w[0] + 1,
            "scrollback rows are contiguous and ascending top-to-bottom: {texts:?}"
        );
    }
    // And these are genuinely EARLIER lines that scrolled off (not the live bottom).
    assert!(
        *nums.last().unwrap() < 19,
        "window is above the live screen (last printed was line19): {texts:?}"
    );
}

/// A scrollback request for a session that does not exist gets an Error, not a panic or
/// silence — and certainly not a Grid.
#[test]
fn scrollback_unknown_session_errors() {
    let sock = socket_path("scrollback-missing");
    let _ = std::fs::remove_file(&sock);
    let child = start_daemon_on(&sock);
    let _killer = Killer(child);

    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    send(
        &mut stream,
        r#"{"op":"scrollback","id":"nope","offset_from_top":0,"count":4}"#,
    );

    let line = read_until(&mut reader, "\"ev\":\"error\"", Duration::from_secs(5));
    assert!(
        line.contains("\"ev\":\"error\""),
        "unknown session yields an error event: {line}"
    );
}
