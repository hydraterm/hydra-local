//! The generation + revision backbone, observed over the wire. These are the
//! guarantees a renderer relies on to know whether its screen is still a
//! contiguous view of the daemon's grid:
//!
//! 1. Every Grid snapshot and Output frame carries `generation` + `revision`.
//! 2. Revision is monotonic within a generation (output advances it, never
//!    rewinds), and Output frames sit strictly after the snapshot they follow.
//! 3. A reattach to a live session keeps the SAME generation (incrementally
//!    bridgeable), but a respawn (kill + start the same id) mints a NEW
//!    generation (the renderer must discard and re-snapshot).

mod common;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use common::{connect, read_until, send, socket_path, start_daemon_on, Killer};
use serde_json::Value;
use std::io::{BufRead, BufReader};
use std::time::{Duration, Instant};

const WITHIN: Duration = Duration::from_secs(5);

fn start_cat(stream: &mut std::os::unix::net::UnixStream, id: &str) {
    send(
        stream,
        &format!(
            r#"{{"op":"start_session","id":"{id}","cwd":".","command":"cat","args":[],"cols":80,"rows":24}}"#
        ),
    );
    std::thread::sleep(Duration::from_millis(200));
}

fn grid_event(line: &str) -> Value {
    serde_json::from_str(line.trim()).expect("grid event JSON")
}

#[test]
fn snapshot_and_output_carry_generation_and_monotonic_revision() {
    let sock = socket_path("rev-envelope");
    let _killer = Killer(start_daemon_on(&sock));

    let id = "rev-sess";
    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    start_cat(&mut stream, id);
    // Attach to get the initial snapshot, then drive output and read a frame.
    send(&mut stream, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
    let snap = grid_event(&read_until(&mut reader, "\"ev\":\"grid\"", WITHIN));
    let gen0 = snap["grid"]["generation"].clone();
    let rev0 = snap["grid"]["revision"]
        .as_u64()
        .expect("snapshot revision present");
    assert!(!gen0.is_null(), "snapshot carries a generation");

    // cat echoes our write; that produces at least one Output frame whose
    // revision is strictly greater than the snapshot's, with a matching gen.
    send(
        &mut stream,
        &format!(r#"{{"op":"write","id":"{id}","data":"hello-rev\n"}}"#),
    );
    let out = grid_event(&read_until(&mut reader, "\"ev\":\"output\"", WITHIN));
    let out_gen = out["generation"].clone();
    let out_rev = out["revision"].as_u64().expect("output revision present");
    assert_eq!(
        out_gen, gen0,
        "output generation matches snapshot generation"
    );
    assert!(
        out_rev > rev0,
        "output revision {out_rev} must advance past snapshot revision {rev0}"
    );
}

#[test]
fn reattach_keeps_generation_respawn_changes_it() {
    let sock = socket_path("rev-respawn");
    let _killer = Killer(start_daemon_on(&sock));

    let id = "respawn-sess";
    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    start_cat(&mut stream, id);
    send(&mut stream, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
    let gen_a = grid_event(&read_until(&mut reader, "\"ev\":\"grid\"", WITHIN))["grid"]
        ["generation"]
        .clone();

    // Reattach to the SAME live session: generation must be unchanged.
    send(&mut stream, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
    let gen_a2 = grid_event(&read_until(&mut reader, "\"ev\":\"grid\"", WITHIN))["grid"]
        ["generation"]
        .clone();
    assert_eq!(
        gen_a, gen_a2,
        "reattach to a live session keeps the generation"
    );

    // Respawn: kill, then start the same id again → a fresh grid → new gen.
    send(&mut stream, &format!(r#"{{"op":"kill","id":"{id}"}}"#));
    read_until(&mut reader, "\"ev\":\"session_exited\"", WITHIN);
    start_cat(&mut stream, id);
    send(&mut stream, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
    let gen_b = grid_event(&read_until(&mut reader, "\"ev\":\"grid\"", WITHIN))["grid"]
        ["generation"]
        .clone();
    assert_ne!(gen_a, gen_b, "respawn mints a new generation");
}

/// Regression for the exit-after-kill race: when a session is killed, the live
/// forwarder learns of the end via EITHER the exit broadcast OR the live-output
/// broadcast closing (the Session drop races the broadcast). If the forwarder
/// observed the output-close first it used to `break` silently, dropping
/// SessionExited and hanging any client (and the test harness) forever. Each
/// attach+kill cycle below MUST yield exactly one session_exited within the
/// deadline; we run many cycles so the race window is hit reliably.
#[test]
fn kill_always_delivers_session_exited() {
    let sock = socket_path("kill-exit");
    let _killer = Killer(start_daemon_on(&sock));

    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    for i in 0..20 {
        let id = format!("kill-sess-{i}");
        start_cat(&mut stream, &id);
        send(&mut stream, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
        // Drain the restore Grid so the next read targets the exit event.
        read_until(&mut reader, "\"ev\":\"grid\"", WITHIN);
        send(&mut stream, &format!(r#"{{"op":"kill","id":"{id}"}}"#));
        // The hard WITHIN deadline turns the old indefinite hang into a fast,
        // unambiguous failure if SessionExited is ever dropped.
        read_until(&mut reader, "\"ev\":\"session_exited\"", WITHIN);
    }
}

/// The PTY reader broadcasts every final output frame before it latches and
/// broadcasts child exit. When both broadcasts are ready together, the live
/// forwarder must drain those already-queued frames before reporting the exit;
/// otherwise the renderer can receive `SessionExited` while the command's last
/// text/title/bell is still stranded in the output receiver.
///
/// Produce enough output to keep several frames queued, put a unique marker and
/// terminal notifications at the very end, then exit immediately. Repeating the
/// cycle makes the old unbiased-select race deterministic enough to guard the
/// real socket path rather than only a synthetic channel helper.
#[test]
fn final_output_and_notifications_precede_exactly_one_exit() {
    const CYCLES: usize = 24;
    const EXIT_CODE: i64 = 23;

    let sock = socket_path("final-before-exit");
    let _killer = Killer(start_daemon_on(&sock));
    let mut stream = connect(&sock);
    stream
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("shorten quiescence timeout");
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut partial_line = String::new();

    for cycle in 0..CYCLES {
        let id = format!("final-before-exit-{cycle}");
        let marker = format!("FINAL-MARKER-{cycle}-7f9c2d");
        let title = format!("FINAL-TITLE-{cycle}-7f9c2d");
        // Wait for one input line so Attach has installed the live forwarder
        // before the burst begins. The awk burst is large enough to span many
        // PTY reads but remains far below the broadcast lag threshold.
        let script = format!(
            "stty -echo; IFS= read -r _; awk 'BEGIN {{ for (i=0; i<4096; i++) printf \"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\" }}'; printf '\\033]0;{title}\\007'; printf '\\007'; printf '{marker}\\n'; exit {EXIT_CODE}"
        );
        send(
            &mut stream,
            &serde_json::json!({
                "op": "start_session",
                "id": id,
                "cwd": ".",
                "command": "sh",
                "args": ["-c", script],
                "cols": 80,
                "rows": 24
            })
            .to_string(),
        );
        send(
            &mut stream,
            &serde_json::json!({
                "op": "attach",
                "id": id,
                "want_raw_output": true
            })
            .to_string(),
        );

        // Consume this session's restore baseline before releasing the child.
        let baseline_deadline = Instant::now() + WITHIN;
        loop {
            let line = next_wire_line(&mut reader, &mut partial_line, baseline_deadline)
                .expect("restore Grid before deadline");
            let event: Value = serde_json::from_str(line.trim()).expect("wire event JSON");
            if event["ev"] == "grid" && event["id"] == id {
                break;
            }
        }
        send(
            &mut stream,
            &serde_json::json!({"op": "write", "id": id, "data": "go\n"}).to_string(),
        );

        let deadline = Instant::now() + WITHIN;
        let mut output = Vec::new();
        let mut event_index = 0usize;
        let mut marker_at = None;
        let mut title_at = None;
        let mut bell_at = None;
        let mut exit_at = None;
        let mut exit_count = 0usize;

        while exit_at.is_none() {
            let line = next_wire_line(&mut reader, &mut partial_line, deadline)
                .expect("SessionExited before deadline");
            let event: Value = serde_json::from_str(line.trim()).expect("wire event JSON");
            if event["id"] != id {
                continue;
            }
            event_index += 1;
            match event["ev"].as_str() {
                Some("output") => {
                    let data = event["data"].as_str().expect("Output.data");
                    output.extend(B64.decode(data).expect("Output.data base64"));
                    if marker_at.is_none() && String::from_utf8_lossy(&output).contains(&marker) {
                        marker_at = Some(event_index);
                    }
                }
                Some("terminal_title") if event["title"] == title => {
                    title_at = Some(event_index);
                }
                Some("terminal_bell") => {
                    bell_at = Some(event_index);
                }
                Some("session_exited") => {
                    exit_count += 1;
                    assert_eq!(event["code"], EXIT_CODE, "wrong exit event: {event}");
                    exit_at = Some(event_index);
                }
                _ => {}
            }
        }

        // The forwarder stops after the exit. Drain a brief quiescence window
        // and count any duplicate exit that was already queued for this id.
        let quiet_deadline = Instant::now() + Duration::from_millis(100);
        while let Some(line) = next_wire_line(&mut reader, &mut partial_line, quiet_deadline) {
            let event: Value = serde_json::from_str(line.trim()).expect("wire event JSON");
            if event["id"] == id && event["ev"] == "session_exited" {
                exit_count += 1;
            }
        }

        let exit_at = exit_at.unwrap();
        assert!(
            marker_at.is_some_and(|at| at < exit_at),
            "cycle {cycle}: final marker was not delivered before exit; output tail={:?}",
            String::from_utf8_lossy(&output[output.len().saturating_sub(128)..])
        );
        assert!(
            title_at.is_some_and(|at| at < exit_at),
            "cycle {cycle}: final OSC title was not delivered before exit"
        );
        assert!(
            bell_at.is_some_and(|at| at < exit_at),
            "cycle {cycle}: final bell was not delivered before exit"
        );
        assert_eq!(
            exit_count, 1,
            "cycle {cycle}: SessionExited must be delivered exactly once"
        );

        // Native renderers are structured-only. Reattach after exit and prove the retained
        // authoritative Grid contains the final marker before the replayed exit latch; this covers
        // the actual no-raw-output recovery path in addition to the live raw ordering above.
        send(
            &mut stream,
            &serde_json::json!({
                "op": "attach",
                "id": id,
                "want_raw_output": false
            })
            .to_string(),
        );
        let late_deadline = Instant::now() + WITHIN;
        let mut late_grid = None;
        loop {
            let line = next_wire_line(&mut reader, &mut partial_line, late_deadline)
                .expect("late structured Grid + exit before deadline");
            let event: Value = serde_json::from_str(line.trim()).expect("wire event JSON");
            if event["id"] != id {
                continue;
            }
            match event["ev"].as_str() {
                Some("grid") => late_grid = Some(grid_visible_text(&event)),
                Some("session_exited") => break,
                _ => {}
            }
        }
        let late_grid = late_grid.expect("late attach sends Grid before SessionExited");
        let compact_grid: String = late_grid
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        assert!(
            compact_grid.contains(&marker),
            "cycle {cycle}: structured retained Grid omitted final marker; tail={:?}",
            &late_grid[late_grid.len().saturating_sub(160)..]
        );
    }
}

/// Attach deliberately races a child that writes once and exits immediately. Every run must expose
/// the marker either in the atomic initial Grid or in live Output before the single exit event. The
/// historical split attach/snapshot/exit-latch sequence could instead send a stale Grid followed by
/// SessionExited and discard the already-published final frame.
#[test]
fn immediate_exit_attach_never_pairs_a_stale_grid_with_exit() {
    const CYCLES: usize = 48;
    const EXIT_CODE: i64 = 19;

    let sock = socket_path("attach-exit-boundary");
    let _killer = Killer(start_daemon_on(&sock));
    let mut stream = connect(&sock);
    stream
        .set_read_timeout(Some(Duration::from_millis(50)))
        .expect("shorten quiescence timeout");
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut partial_line = String::new();

    for cycle in 0..CYCLES {
        let id = format!("attach-exit-boundary-{cycle}");
        let marker = format!("ATTACH-RACE-MARKER-{cycle}-4d81");
        let script = format!("printf '{marker}\\n'; exit {EXIT_CODE}");
        send(
            &mut stream,
            &serde_json::json!({
                "op": "start_session",
                "id": id,
                "cwd": ".",
                "command": "sh",
                "args": ["-c", script],
                "cols": 80,
                "rows": 24
            })
            .to_string(),
        );
        // No readiness barrier: this is intentionally concurrent with the one-write child.
        send(
            &mut stream,
            &serde_json::json!({
                "op": "attach",
                "id": id,
                "want_raw_output": true
            })
            .to_string(),
        );

        let deadline = Instant::now() + WITHIN;
        let mut visible = String::new();
        let mut exit_count = 0usize;
        loop {
            let line = next_wire_line(&mut reader, &mut partial_line, deadline)
                .expect("Grid/output and SessionExited before deadline");
            let event: Value = serde_json::from_str(line.trim()).expect("wire event JSON");
            if event["id"] != id {
                continue;
            }
            match event["ev"].as_str() {
                Some("grid") => visible.push_str(&grid_visible_text(&event)),
                Some("output") => {
                    let data = event["data"].as_str().expect("Output.data");
                    visible.push_str(&String::from_utf8_lossy(
                        &B64.decode(data).expect("Output.data base64"),
                    ));
                }
                Some("session_exited") => {
                    exit_count += 1;
                    assert_eq!(event["code"], EXIT_CODE);
                    break;
                }
                _ => {}
            }
        }

        assert!(
            visible.contains(&marker),
            "cycle {cycle}: stale attach baseline reached exit without final marker"
        );
        assert_eq!(exit_count, 1);
    }
}

fn grid_visible_text(event: &Value) -> String {
    let mut out = String::new();
    for row in event["grid"]["rows_cells"].as_array().into_iter().flatten() {
        for cell in row.as_array().into_iter().flatten() {
            if let Some(text) = cell["text"].as_str() {
                out.push_str(text);
            }
        }
        out.push('\n');
    }
    out
}

/// Read one complete newline-delimited wire event while preserving any partial
/// bytes appended before a socket timeout.
fn next_wire_line(
    reader: &mut impl BufRead,
    partial: &mut String,
    deadline: Instant,
) -> Option<String> {
    loop {
        if Instant::now() >= deadline {
            return None;
        }
        match reader.read_line(partial) {
            Ok(0) => std::thread::sleep(Duration::from_millis(5)),
            Ok(_) if partial.ends_with('\n') => return Some(std::mem::take(partial)),
            Ok(_) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(error) => panic!("wire read failed: {error}"),
        }
    }
}
