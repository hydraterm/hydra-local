//! Protocol-contract hardening from the daemon-renderer-contract domain, observed
//! over the wire. These complement `live_damage.rs` (which proves the happy-path
//! damage envelope) by focusing on the failure surface the contract must survive:
//!
//!   - malformed / garbage client input does NOT crash or wedge the daemon;
//!   - an out-of-order / rapid resize burst settles on the true final geometry with
//!     no resync storm (geometry is a full-Grid resync, never partial damage);
//!   - live damage frames chain `base_revision -> revision` with NO gap across a
//!     session's life (a missing-frame tripwire at the wire level);
//!   - a client that drops damage and forces a resync recovers a correct full grid
//!     (resync-after-loss recovery).
//!
//! All of this is the daemon's *observable* contract, so the tests drive the real
//! binary over a Unix socket and assert only on wire bytes — they do not inspect
//! implementation source files.

mod common;

use common::{connect, read_until, send, socket_path, start_daemon_on, Killer};
use serde_json::Value;
use std::io::BufReader;
use std::time::Duration;

const WITHIN: Duration = Duration::from_secs(5);

fn ev(line: &str) -> Value {
    serde_json::from_str(line.trim()).expect("event JSON")
}

fn start_cat(stream: &mut std::os::unix::net::UnixStream, id: &str) {
    send(
        stream,
        &format!(
            r#"{{"op":"start_session","id":"{id}","cwd":".","command":"cat","args":[],"cols":80,"rows":24}}"#
        ),
    );
    std::thread::sleep(Duration::from_millis(200));
}

/// Concatenate every cell's `text` across a grid snapshot's `rows_cells`, row by row,
/// so a marker that the shell echoed onto one row is findable with `.contains`. (Each
/// cell is its own `"text"` grapheme, so a marker is not a contiguous JSON substring.)
fn grid_text(grid: &Value) -> String {
    let rows = grid["rows_cells"].as_array().expect("rows_cells array");
    let mut out = String::new();
    for row in rows {
        for cell in row.as_array().expect("row is array") {
            out.push_str(cell["text"].as_str().expect("cell text"));
        }
        out.push('\n');
    }
    out
}

/// Malformed and hostile client lines must not crash or wedge the daemon. A peer can
/// send: non-JSON garbage, a valid JSON object with an unknown `op`, a known op with a
/// missing required field, and a known op with a wrong-typed field. After all of that
/// on the SAME connection, a well-formed request must still be served — proving the
/// daemon skips bad lines rather than tearing down the connection or the process.
#[test]
fn malformed_requests_do_not_wedge_the_daemon() {
    let sock = socket_path("drift-malformed");
    let _killer = Killer(start_daemon_on(&sock));

    let id = "malformed-sess";
    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    // A spray of bad lines, each on its own newline-framed line.
    send(&mut stream, "this is not json at all");
    send(&mut stream, "{ broken json ");
    send(&mut stream, r#"{"op":"totally_unknown_op","id":"x"}"#);
    // start_session missing the required `command` field.
    send(
        &mut stream,
        r#"{"op":"start_session","id":"x","cwd":".","args":[],"cols":80,"rows":24}"#,
    );
    // attach with a wrong-typed id (number, not string).
    send(&mut stream, r#"{"op":"attach","id":12345}"#);
    // A bare empty line.
    send(&mut stream, "");

    // The daemon must still be alive and serving on this very connection.
    start_cat(&mut stream, id);
    send(&mut stream, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
    let snap = ev(&read_until(&mut reader, "\"ev\":\"grid\"", WITHIN));
    assert_eq!(
        snap["grid"]["cols"].as_u64(),
        Some(80),
        "daemon still serves a well-formed attach after a malformed-input spray"
    );

    // And a brand-new connection must also be accepted (the listener survived).
    let mut s2 = connect(&sock);
    let mut r2 = BufReader::new(s2.try_clone().unwrap());
    send(&mut s2, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
    let snap2 = ev(&read_until(&mut r2, "\"ev\":\"grid\"", WITHIN));
    assert_eq!(
        snap2["grid"]["cols"].as_u64(),
        Some(80),
        "a fresh connection is accepted after malformed input on another connection"
    );
}

/// A rapid burst of resizes (a "resize storm") must settle on the TRUE final geometry,
/// and geometry changes must surface as full-Grid resyncs (ResyncRequired + Grid), never
/// invented partial-resize damage. We fire several resizes back-to-back, then drive one
/// write to wake the forwarder, and assert the resync grid carries the LAST requested
/// geometry — out-of-order settling, no torn intermediate geometry.
#[test]
fn resize_storm_settles_on_final_geometry_via_grid_resync() {
    let sock = socket_path("drift-resize-storm");
    let _killer = Killer(start_daemon_on(&sock));

    let id = "storm-sess";
    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    start_cat(&mut stream, id);
    send(&mut stream, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
    let snap = ev(&read_until(&mut reader, "\"ev\":\"grid\"", WITHIN));
    assert_eq!(
        snap["grid"]["cols"].as_u64(),
        Some(80),
        "started at 80 cols"
    );

    // Fire a burst of distinct geometries with no reads in between. The final one is the
    // truth the client must converge to.
    for (cols, rows) in [(90, 26), (110, 32), (70, 20), (100, 30), (120, 40)] {
        send(
            &mut stream,
            &format!(r#"{{"op":"resize","id":"{id}","cols":{cols},"rows":{rows}}}"#),
        );
    }
    std::thread::sleep(Duration::from_millis(250));
    // One write wakes the forwarder so it diffs the new geometry against its baseline.
    send(
        &mut stream,
        &format!(r#"{{"op":"write","id":"{id}","data":"settled\n"}}"#),
    );

    // The geometry change surfaces as ResyncRequired + a full Grid. Drain grids until the
    // stream goes quiet; the LAST grid must carry the final requested geometry. (The
    // daemon may coalesce the burst into one resync or emit a few; either way it must
    // converge on the true final size, never a stale intermediate.)
    read_until(&mut reader, "\"ev\":\"resync_required\"", WITHIN);
    let mut last_grid = ev(&read_until(&mut reader, "\"ev\":\"grid\"", WITHIN));
    // Keep reading any further grids within a short window; converge on the last one.
    let settle_deadline = std::time::Instant::now() + Duration::from_millis(800);
    while std::time::Instant::now() < settle_deadline {
        // Nudge once more in case a later grid is still in flight.
        match try_read_grid(&mut reader, Duration::from_millis(200)) {
            Some(g) => last_grid = g,
            None => break,
        }
    }
    assert_eq!(
        last_grid["grid"]["cols"].as_u64(),
        Some(120),
        "resize storm settled on the FINAL requested cols, not a stale intermediate"
    );
    assert_eq!(
        last_grid["grid"]["rows"].as_u64(),
        Some(40),
        "resize storm settled on the FINAL requested rows"
    );
}

/// Best-effort: read one more `grid` event within `within`, or `None` if none arrives.
/// Unlike `read_until` (which panics on timeout), this lets a settle-loop stop cleanly
/// once the grid stream goes quiet.
fn try_read_grid(reader: &mut impl std::io::BufRead, within: Duration) -> Option<Value> {
    let deadline = std::time::Instant::now() + within;
    let mut line = String::new();
    loop {
        if std::time::Instant::now() >= deadline {
            return None;
        }
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => std::thread::sleep(Duration::from_millis(10)),
            Ok(_) => {
                if line.ends_with('\n') && line.contains("\"ev\":\"grid\"") {
                    return Some(ev(&line));
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return None,
        }
    }
}

/// Missing-frame tripwire at the wire level: across a session's life, every consecutive
/// pair of damage frames must chain `frame[N].base_revision == frame[N-1].revision`, with
/// strictly increasing revisions and no gap. A gap here would mean the daemon emitted a
/// frame that bases on a revision the client never received — the exact condition that
/// forces a renderer resync. We drive several distinct writes and assert the whole chain
/// from the attach baseline forward is contiguous.
#[test]
fn damage_chain_has_no_revision_gap_across_session_life() {
    let sock = socket_path("drift-chain");
    let _killer = Killer(start_daemon_on(&sock));

    let id = "chain-life-sess";
    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    start_cat(&mut stream, id);
    // Structured-only attach so we only get Grid + Damage, no raw Output to filter.
    send(
        &mut stream,
        &format!(r#"{{"op":"attach","id":"{id}","want_raw_output":false}}"#),
    );
    let snap = ev(&read_until(&mut reader, "\"ev\":\"grid\"", WITHIN));
    let gen = snap["grid"]["generation"].clone();
    let mut held_rev = snap["grid"]["revision"]
        .as_u64()
        .expect("baseline revision");

    // Several distinct writes; each visible echo advances the grid and emits >= 1 frame.
    let writes = ["alpha\n", "bravo\n", "charlie\n", "delta\n", "echo\n"];
    for w in writes {
        send(
            &mut stream,
            &format!(r#"{{"op":"write","id":"{id}","data":"{}"}}"#, w.trim_end()),
        );
    }

    // Read damage frames until we've consumed at least as many as we wrote, checking the
    // chain as we go. `cat` may coalesce a burst, so we don't require one frame per write —
    // only that whatever frames DO arrive form an unbroken chain from the baseline.
    let mut frames_seen = 0;
    let deadline = std::time::Instant::now() + WITHIN;
    while frames_seen < writes.len() && std::time::Instant::now() < deadline {
        let Some(d) = try_read_damage(&mut reader, Duration::from_millis(500)) else {
            break;
        };
        let frame = &d["frame"];
        assert_eq!(
            frame["generation"], gen,
            "every damage frame stays in the same generation across the session"
        );
        let base = frame["base_revision"].as_u64().expect("base_revision");
        let rev = frame["revision"].as_u64().expect("revision");
        assert_eq!(
            base, held_rev,
            "damage frame must base on the revision the client currently holds (no gap)"
        );
        assert!(
            rev > base,
            "damage frame must strictly advance the revision ({rev} > {base})"
        );
        held_rev = rev;
        frames_seen += 1;
    }
    assert!(
        frames_seen > 0,
        "at least one damage frame must arrive for visible echoed output"
    );
}

/// Best-effort read of one `damage` event within `within`, or `None` on quiet.
fn try_read_damage(reader: &mut impl std::io::BufRead, within: Duration) -> Option<Value> {
    let deadline = std::time::Instant::now() + within;
    let mut line = String::new();
    loop {
        if std::time::Instant::now() >= deadline {
            return None;
        }
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => std::thread::sleep(Duration::from_millis(10)),
            Ok(_) => {
                if line.ends_with('\n') && line.contains("\"ev\":\"damage\"") {
                    return Some(ev(&line));
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(_) => return None,
        }
    }
}

/// Resync-after-loss recovery: a client that explicitly requests a fresh `Snapshot`
/// (the exact recovery action a renderer takes when it detects a damage gap or malformed
/// frame) must receive a full authoritative `Grid` that reflects all output produced so
/// far — proving the daemon's grid is the recoverable source of truth, not a stream the
/// client had to witness live. We write a marker, then re-snapshot and confirm the marker
/// is present in the recovered grid.
#[test]
fn snapshot_request_recovers_full_grid_after_simulated_loss() {
    let sock = socket_path("drift-resync-recover");
    let _killer = Killer(start_daemon_on(&sock));

    let id = "recover-sess";
    let marker = "RECOVER_ME_4242";
    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    // Use a shell that prints the marker and stays alive.
    send(
        &mut stream,
        &format!(
            r#"{{"op":"start_session","id":"{id}","cwd":".","command":"sh","args":["-c","printf '{marker}\\n'; sleep 30"],"cols":80,"rows":24}}"#
        ),
    );
    std::thread::sleep(Duration::from_millis(400));

    send(&mut stream, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
    // Drain the initial baseline grid.
    read_until(&mut reader, "\"ev\":\"grid\"", WITHIN);

    // Simulate the renderer detecting loss and forcing recovery: request a fresh Snapshot.
    // The daemon must reply with a full Grid that still contains the marker — the grid is
    // authoritative state, recoverable at any time, independent of which frames the client
    // happened to apply.
    send(&mut stream, &format!(r#"{{"op":"snapshot","id":"{id}"}}"#));
    let recovered = ev(&read_until(&mut reader, "\"ev\":\"grid\"", WITHIN));
    assert!(
        grid_text(&recovered["grid"]).contains(marker),
        "a resync Snapshot recovers the full grid including prior output: {}",
        grid_text(&recovered["grid"])
    );
}
