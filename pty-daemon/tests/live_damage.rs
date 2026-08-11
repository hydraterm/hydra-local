//! Daemon live damage emission, observed over the wire.
//!
//! The forwarder, after optionally shipping a raw `Output` frame, diffs the held
//! baseline snapshot against a fresh authoritative one and emits structured `Damage`:
//!
//! 1. live PTY output produces a `Damage` frame whose `id` is the real session, whose
//!    `base_revision` is the previously-held snapshot's revision and whose `revision`
//!    matches the grid the frame brings the client to;
//! 2. the raw `Output` bridge STILL emits for that same write (the bridge is preserved —
//!    a renderer may consume either and stay correct via the revision gates);
//! 3. a geometry change (resize) ships a full `Grid` (ResyncRequired + Grid), NEVER a
//!    partial-resize damage frame.
//!
//! These are integration tests because the socket traffic is the contract;
//! the pure NoChange / Frame / Resync decision logic is unit-tested in `grid.rs`.

mod common;

use common::{connect, read_until, send, socket_path, start_daemon_on, Killer};
use serde_json::Value;
use std::io::BufReader;
use std::time::Duration;

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

/// Start a byte-transparent PTY peer for control-sequence tests. Disabling the
/// line discipline's echo/ECHOCTL is important: otherwise ESC is rendered as
/// the printable characters `^[` before `cat` can return it to the daemon.
fn start_raw_cat(stream: &mut std::os::unix::net::UnixStream, id: &str) {
    send(
        stream,
        &format!(
            r#"{{"op":"start_session","id":"{id}","cwd":".","command":"/bin/sh","args":["-c","stty raw -echo; cat"],"cols":20,"rows":5}}"#
        ),
    );
    std::thread::sleep(Duration::from_millis(300));
}

fn ev(line: &str) -> Value {
    serde_json::from_str(line.trim()).expect("event JSON")
}

/// Live output yields BOTH an Output frame and a Damage frame for the same write, and the
/// damage frame carries the real session id with a base_revision == the prior snapshot's
/// revision and a revision strictly past it. Proves the bridge is preserved (1 + 2) and the
/// damage envelope is stamped correctly.
#[test]
fn live_output_emits_damage_with_correct_id_and_revisions() {
    let sock = socket_path("live-damage");
    let _killer = Killer(start_daemon_on(&sock));

    let id = "dmg-sess";
    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    start_cat(&mut stream, id);
    send(&mut stream, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
    let snap = ev(&read_until(&mut reader, "\"ev\":\"grid\"", WITHIN));
    let base_rev = snap["grid"]["revision"]
        .as_u64()
        .expect("restore snapshot revision");
    let gen = snap["grid"]["generation"].clone();

    // cat echoes the write; this advances the grid → one Output frame AND one Damage
    // frame. The Output bridge is preserved (we must see it), then the Damage frame.
    send(
        &mut stream,
        &format!(r#"{{"op":"write","id":"{id}","data":"hello-damage\n"}}"#),
    );

    // (2) The raw Output bridge still emits for this write.
    let out = ev(&read_until(&mut reader, "\"ev\":\"output\"", WITHIN));
    assert_eq!(out["id"].as_str(), Some(id), "output carries session id");
    let out_rev = out["revision"].as_u64().expect("output revision");
    assert!(
        out_rev > base_rev,
        "output revision {out_rev} advances past snapshot {base_rev}"
    );

    // (1) A Damage frame follows for the same change.
    let dmg = ev(&read_until(&mut reader, "\"ev\":\"damage\"", WITHIN));
    let frame = &dmg["frame"];
    assert_eq!(
        frame["id"].as_str(),
        Some(id),
        "damage frame is stamped with the REAL session id, not the placeholder"
    );
    assert_eq!(
        frame["generation"], gen,
        "damage generation matches the live generation"
    );
    let dmg_base = frame["base_revision"]
        .as_u64()
        .expect("damage base_revision");
    let dmg_rev = frame["revision"].as_u64().expect("damage revision");
    assert_eq!(
        dmg_base, base_rev,
        "first damage frame's base_revision is the restore snapshot's revision"
    );
    assert!(
        dmg_rev > dmg_base,
        "damage revision {dmg_rev} strictly advances past its base {dmg_base}"
    );
    // The frame is well-formed damage: it carries at least one op for a visible change.
    assert!(
        frame["ops"]
            .as_array()
            .map(|o| !o.is_empty())
            .unwrap_or(false),
        "an echoed character is a visible change → non-empty ops"
    );
}

/// A second write diffs against the FIRST damage frame's grid, so consecutive frames chain:
/// frame N's base_revision == frame N-1's revision. Proves the per-session baseline is
/// advanced after each emitted frame (no stale base_revision).
#[test]
fn consecutive_damage_frames_chain_base_to_prev_revision() {
    let sock = socket_path("live-damage-chain");
    let _killer = Killer(start_daemon_on(&sock));

    let id = "chain-sess";
    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    start_cat(&mut stream, id);
    send(&mut stream, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
    read_until(&mut reader, "\"ev\":\"grid\"", WITHIN);

    send(
        &mut stream,
        &format!(r#"{{"op":"write","id":"{id}","data":"one\n"}}"#),
    );
    let d1 = ev(&read_until(&mut reader, "\"ev\":\"damage\"", WITHIN));
    let rev1 = d1["frame"]["revision"].as_u64().expect("frame1 revision");

    send(
        &mut stream,
        &format!(r#"{{"op":"write","id":"{id}","data":"two\n"}}"#),
    );
    let d2 = ev(&read_until(&mut reader, "\"ev\":\"damage\"", WITHIN));
    let base2 = d2["frame"]["base_revision"]
        .as_u64()
        .expect("frame2 base_revision");
    let rev2 = d2["frame"]["revision"].as_u64().expect("frame2 revision");

    assert_eq!(
        base2, rev1,
        "the next damage frame bases on the previous frame's revision (baseline advanced)"
    );
    assert!(
        rev2 > rev1,
        "revisions are strictly increasing across frames"
    );
}

/// A geometry change ships a full Grid (ResyncRequired then Grid), NEVER a partial-resize
/// damage frame. We resize then write; the next forwarder wake sees the geometry differ
/// from the held baseline → `generate_damage` returns Resync → ResyncRequired + Grid. (3)
#[test]
fn resize_ships_full_grid_not_damage() {
    let sock = socket_path("live-damage-resize");
    let _killer = Killer(start_daemon_on(&sock));

    let id = "resize-sess";
    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    start_cat(&mut stream, id);
    send(&mut stream, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
    let snap = ev(&read_until(&mut reader, "\"ev\":\"grid\"", WITHIN));
    let cols0 = snap["grid"]["cols"].as_u64().expect("snapshot cols");
    assert_eq!(cols0, 80, "started at 80 cols");

    // Resize the PTY+grid (different geometry), then drive output so the forwarder wakes
    // and diffs the new geometry against its 80-col baseline.
    send(
        &mut stream,
        &format!(r#"{{"op":"resize","id":"{id}","cols":100,"rows":30}}"#),
    );
    std::thread::sleep(Duration::from_millis(150));
    send(
        &mut stream,
        &format!(r#"{{"op":"write","id":"{id}","data":"after-resize\n"}}"#),
    );

    // The geometry change must surface as ResyncRequired + a full Grid at the new size —
    // not an invented partial-resize damage frame.
    read_until(&mut reader, "\"ev\":\"resync_required\"", WITHIN);
    let regrid = ev(&read_until(&mut reader, "\"ev\":\"grid\"", WITHIN));
    assert_eq!(
        regrid["grid"]["cols"].as_u64(),
        Some(100),
        "resync grid carries the NEW geometry"
    );
    assert_eq!(regrid["grid"]["rows"].as_u64(), Some(30));
}

/// Read events until one matches `want`, asserting NONE of them matches `forbidden`
/// along the way. Used to prove a stream both DOES deliver one event and does NOT
/// deliver another up to that point.
fn expect_before_forbidden(
    reader: &mut impl std::io::BufRead,
    want: &str,
    forbidden: &str,
) -> String {
    use std::time::Instant;
    let deadline = Instant::now() + WITHIN;
    let mut line = String::new();
    loop {
        assert!(Instant::now() < deadline, "timed out waiting for {want:?}");
        match reader.read_line(&mut line) {
            Ok(0) => std::thread::sleep(Duration::from_millis(10)),
            Ok(_) => {
                if line.ends_with('\n') {
                    assert!(
                        !line.contains(forbidden),
                        "saw forbidden {forbidden:?} before {want:?}: {line}"
                    );
                    if line.contains(want) {
                        return line.clone();
                    }
                    line.clear();
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => panic!("read error waiting for {want:?}: {e}"),
        }
    }
}

/// Drain events for a short bounded window, asserting NONE matches `forbidden`. Returns
/// the lines seen (for diagnostics). Used to prove a forbidden event does NOT arrive even
/// AFTER an expected one — a one-shot `read_until` only proves "before", not "after".
fn drain_assert_absent(
    reader: &mut impl std::io::BufRead,
    forbidden: &str,
    window: Duration,
) -> Vec<String> {
    use std::time::Instant;
    let deadline = Instant::now() + window;
    let mut seen = Vec::new();
    let mut line = String::new();
    while Instant::now() < deadline {
        match reader.read_line(&mut line) {
            Ok(0) => std::thread::sleep(Duration::from_millis(5)),
            Ok(_) => {
                if line.ends_with('\n') {
                    assert!(
                        !line.contains(forbidden),
                        "forbidden {forbidden:?} appeared within the window: {line}"
                    );
                    seen.push(line.clone());
                    line.clear();
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => panic!("read error during drain: {e}"),
        }
    }
    seen
}

/// The raw `Output` bridge is opt-in. An attach that omits `want_raw_output`
/// (a compatibility client) still receives raw Output for live writes.
#[test]
fn omitted_want_raw_output_still_receives_output() {
    let sock = socket_path("wro-omitted");
    let _killer = Killer(start_daemon_on(&sock));

    let id = "wro-omit";
    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    start_cat(&mut stream, id);
    // No want_raw_output field → defaults to true.
    send(&mut stream, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
    read_until(&mut reader, "\"ev\":\"grid\"", WITHIN);
    send(
        &mut stream,
        &format!(r#"{{"op":"write","id":"{id}","data":"legacy\n"}}"#),
    );
    let out = ev(&read_until(&mut reader, "\"ev\":\"output\"", WITHIN));
    assert_eq!(out["id"].as_str(), Some(id));
}

/// An explicit `want_raw_output: true` still receives raw Output.
#[test]
fn want_raw_output_true_still_receives_output() {
    let sock = socket_path("wro-true");
    let _killer = Killer(start_daemon_on(&sock));

    let id = "wro-t";
    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    start_cat(&mut stream, id);
    send(
        &mut stream,
        &format!(r#"{{"op":"attach","id":"{id}","want_raw_output":true}}"#),
    );
    read_until(&mut reader, "\"ev\":\"grid\"", WITHIN);
    send(
        &mut stream,
        &format!(r#"{{"op":"write","id":"{id}","data":"raw-on\n"}}"#),
    );
    let out = ev(&read_until(&mut reader, "\"ev\":\"output\"", WITHIN));
    assert_eq!(out["id"].as_str(), Some(id));
}

/// A structured-only attach (`want_raw_output: false`) gets NO raw Output, but STILL
/// gets a Damage frame for the same live write — proving the Output send is conditional
/// while damage generation is unconditional. We read up to the Damage
/// frame and assert no Output crossed the socket before it.
#[test]
fn want_raw_output_false_gets_damage_not_output() {
    let sock = socket_path("wro-false");
    let _killer = Killer(start_daemon_on(&sock));

    let id = "wro-f";
    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    start_cat(&mut stream, id);
    send(
        &mut stream,
        &format!(r#"{{"op":"attach","id":"{id}","want_raw_output":false}}"#),
    );
    read_until(&mut reader, "\"ev\":\"grid\"", WITHIN);
    send(
        &mut stream,
        &format!(r#"{{"op":"write","id":"{id}","data":"structured-only\n"}}"#),
    );
    // The Damage frame MUST arrive, and NO Output may precede it.
    let dmg = ev(&expect_before_forbidden(
        &mut reader,
        "\"ev\":\"damage\"",
        "\"ev\":\"output\"",
    ));
    assert_eq!(
        dmg["frame"]["id"].as_str(),
        Some(id),
        "structured-only client still gets live Damage frames"
    );

    // No Output arrives after the Damage either. Drive more output, then
    // drain a short window asserting no `output` event ever crosses the socket.
    send(
        &mut stream,
        &format!(r#"{{"op":"write","id":"{id}","data":"more-structured\n"}}"#),
    );
    let seen = drain_assert_absent(&mut reader, "\"ev\":\"output\"", Duration::from_millis(600));
    assert!(
        seen.iter().any(|l| l.contains("\"ev\":\"damage\"")),
        "the post-write window should still carry Damage frames: {seen:?}"
    );
}

/// A resize on a structured-only attach produces ResyncRequired + a full Grid at
/// the new geometry, and STILL no raw Output — neither before nor after the resync.
#[test]
fn want_raw_output_false_resize_resyncs_without_output() {
    let sock = socket_path("wro-false-resize");
    let _killer = Killer(start_daemon_on(&sock));

    let id = "wro-f-resize";
    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    start_cat(&mut stream, id);
    send(
        &mut stream,
        &format!(r#"{{"op":"attach","id":"{id}","want_raw_output":false}}"#),
    );
    read_until(&mut reader, "\"ev\":\"grid\"", WITHIN);

    send(
        &mut stream,
        &format!(r#"{{"op":"resize","id":"{id}","cols":120,"rows":40}}"#),
    );
    std::thread::sleep(Duration::from_millis(150));
    send(
        &mut stream,
        &format!(r#"{{"op":"write","id":"{id}","data":"post-resize\n"}}"#),
    );

    // ResyncRequired must arrive with NO Output before it...
    expect_before_forbidden(
        &mut reader,
        "\"ev\":\"resync_required\"",
        "\"ev\":\"output\"",
    );
    // ...followed by a full Grid at the NEW geometry, still no Output before it.
    let regrid = ev(&expect_before_forbidden(
        &mut reader,
        "\"ev\":\"grid\"",
        "\"ev\":\"output\"",
    ));
    assert_eq!(regrid["grid"]["cols"].as_u64(), Some(120));
    assert_eq!(regrid["grid"]["rows"].as_u64(), Some(40));

    // And no Output in a trailing window either.
    drain_assert_absent(&mut reader, "\"ev\":\"output\"", Duration::from_millis(400));
}

/// End-to-end structured-only: attach false → baseline Grid → write → Damage →
/// applying that Damage to the held baseline reproduces the daemon's authoritative grid
/// at the advanced revision, all WITHOUT any Snapshot request or raw Output. This is the
/// equivalence guarantee observed over the wire: baseline + damage == full snapshot.
/// Apply a single damage frame's ops to a held grid, both as raw JSON `Value`s — the
/// exact transformation the renderer performs, but expressed against the wire JSON so
/// this integration test does NOT need to import the bin crate's internal types (the
/// crate is bin-only; `apply_damage_for_test` is `#[cfg(test)]`-internal and unexported).
/// Mirrors `grid::apply_damage_for_test`: `row_span` overwrites `[start, start+len)`,
/// `clear_all` fills every cell with the given cell, `scroll_up`/`scroll_down` move a
/// half-open row region (forward copy for up, reverse for down — same as the daemon's
/// `apply_scroll`). Vacated rows are left as-is; a following `row_span` repaints them.
fn apply_damage_json(held_grid: &mut Value, frame: &Value) {
    let ops = frame["ops"].as_array().expect("frame.ops is an array");
    let rows = held_grid["rows_cells"]
        .as_array_mut()
        .expect("held grid rows_cells is an array");
    for op in ops {
        match op["op"].as_str().expect("op tag") {
            "row_span" => {
                let r = op["row"].as_u64().expect("row") as usize;
                let start = op["start"].as_u64().expect("start") as usize;
                let cells = op["cells"].as_array().expect("cells");
                let row = rows[r].as_array_mut().expect("target row is an array");
                for (i, c) in cells.iter().enumerate() {
                    row[start + i] = c.clone();
                }
            }
            "clear_all" => {
                let cell = op["cell"].clone();
                for row in rows.iter_mut() {
                    for c in row.as_array_mut().expect("row is an array").iter_mut() {
                        *c = cell.clone();
                    }
                }
            }
            tag @ ("scroll_up" | "scroll_down") => {
                let top = op["top"].as_u64().expect("top") as usize;
                let bottom = op["bottom_exclusive"].as_u64().expect("bottom") as usize;
                let lines = op["lines"].as_u64().expect("lines") as usize;
                if tag == "scroll_up" {
                    for i in top..(bottom - lines) {
                        rows[i] = rows[i + lines].clone();
                    }
                } else {
                    for i in (top + lines..bottom).rev() {
                        rows[i] = rows[i - lines].clone();
                    }
                }
            }
            other => panic!("unexpected damage op: {other}"),
        }
    }

    // The frame header carries the ABSOLUTE post-frame envelope + cursor + modes. The
    // renderer's typed apply path (grid.rs::apply_damage_for_test) folds these flat onto
    // the held GridSnapshot; mirror that here so the reconstructed wire grid is compared
    // against the authoritative snapshot on the FULL header, not just cells.
    held_grid["revision"] = frame["revision"].clone();
    held_grid["base_revision"] = frame["base_revision"].clone();
    let cursor = &frame["cursor"];
    held_grid["cursor_line"] = cursor["line"].clone();
    held_grid["cursor_col"] = cursor["col"].clone();
    held_grid["cursor_visible"] = cursor["visible"].clone();
    held_grid["cursor_shape"] = cursor["shape"].clone();
    let modes = &frame["modes"];
    held_grid["alt_screen"] = modes["alt_screen"].clone();
    held_grid["app_cursor"] = modes["app_cursor"].clone();
    held_grid["bracketed_paste"] = modes["bracketed_paste"].clone();
    held_grid["focus_reporting"] = modes["focus_reporting"].clone();
}

/// Non-vacuous equivalence: the damage-reconstructed grid MUST equal the daemon's
/// authoritative snapshot at the same revision on the full header — revision, cells,
/// cursor, and modes. This is the load-bearing guarantee; it must always run, so the
/// caller is responsible for draining so the snapshot lands at the same revision. We
/// assert that equality (held.revision == authoritative.revision) unconditionally rather
/// than skipping when they differ (which would make the test vacuous).
fn assert_grid_equivalent(held: &Value, authoritative: &Value) {
    assert_eq!(
        held["revision"], authoritative["revision"],
        "reconstructed revision must equal the authoritative snapshot revision (no quiescence gap)"
    );
    assert_eq!(
        held["rows_cells"], authoritative["rows_cells"],
        "baseline + damage reconstructs the authoritative grid cell-for-cell"
    );
    for f in [
        "cursor_line",
        "cursor_col",
        "cursor_visible",
        "cursor_shape",
    ] {
        assert_eq!(held[f], authoritative[f], "cursor field {f} must match");
    }
    for f in [
        "alt_screen",
        "app_cursor",
        "bracketed_paste",
        "focus_reporting",
    ] {
        assert_eq!(held[f], authoritative[f], "mode field {f} must match");
    }
}

#[test]
fn structured_only_damage_reconstructs_grid_without_snapshot() {
    let sock = socket_path("wro-e2e");
    let _killer = Killer(start_daemon_on(&sock));

    let id = "wro-e2e";
    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    // Use the byte-transparent peer so one application write produces one terminal
    // mutation. A canonical `cat` also exposes the line discipline's echo, then `cat`'s
    // reply; those are legitimately two independently scheduled damage revisions and
    // make a single-frame equivalence test race its own second echo.
    start_raw_cat(&mut stream, id);
    send(
        &mut stream,
        &format!(r#"{{"op":"attach","id":"{id}","want_raw_output":false}}"#),
    );
    let baseline_line = read_until(&mut reader, "\"ev\":\"grid\"", WITHIN);
    let baseline_v: Value = serde_json::from_str(baseline_line.trim()).unwrap();
    // Hold the baseline grid as raw JSON — the renderer holds a typed grid; here we mutate
    // the wire form so the test needs no daemon-internal types.
    let mut held: Value = baseline_v["grid"].clone();
    let base_rev = held["revision"].as_u64().expect("baseline revision");

    // Drive a visible change.
    send(
        &mut stream,
        &format!(r#"{{"op":"write","id":"{id}","data":"R"}}"#),
    );
    // No Snapshot is requested by us; the daemon pushes Damage. Apply it to the held grid.
    let dmg_line = expect_before_forbidden(&mut reader, "\"ev\":\"damage\"", "\"ev\":\"output\"");
    let dmg_v: Value = serde_json::from_str(dmg_line.trim()).unwrap();
    let frame = &dmg_v["frame"];
    let frame_rev = frame["revision"].as_u64().expect("damage revision");
    assert!(
        frame_rev > base_rev,
        "damage advances the revision: {frame_rev} > {base_rev}"
    );
    assert_eq!(
        frame["base_revision"].as_u64().expect("base_revision"),
        base_rev,
        "damage chains from the baseline revision we hold"
    );
    apply_damage_json(&mut held, frame);

    // Now ask the daemon for its authoritative snapshot ONLY to verify equivalence (the
    // renderer would not need to in production — it lives off damage). The reconstructed
    // grid must match the daemon's full snapshot cell-for-cell at the same revision.
    send(&mut stream, &format!(r#"{{"op":"snapshot","id":"{id}"}}"#));
    let auth_line = read_until(&mut reader, "\"ev\":\"grid\"", WITHIN);
    let auth_v: Value = serde_json::from_str(auth_line.trim()).unwrap();
    let authoritative = &auth_v["grid"];

    // The raw, echo-free peer is quiescent after its one-byte reply, so the authoritative
    // snapshot is at the same revision the damage brought us to. Assert full-header
    // equivalence UNCONDITIONALLY: if revisions or content diverge the test must fail,
    // not silently pass (which would make it vacuous).
    assert_grid_equivalent(&held, authoritative);
}

/// Over-the-wire scroll: drive enough output to scroll a full 24-row grid, then prove
/// the structured damage stream (which now includes ScrollUp ops) reconstructs the
/// authoritative snapshot cell-for-cell. The renderer applies these exact frames; this
/// test exercises the daemon's scroll detection + self-verify end to end without ever
/// re-parsing raw PTY bytes (a second VT parser is forbidden).
#[test]
fn structured_scroll_damage_reconstructs_grid_without_snapshot() {
    let sock = socket_path("scroll-e2e");
    let _killer = Killer(start_daemon_on(&sock));

    let id = "scroll-e2e";
    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    // Use `cat` and drive the scroll with explicit `write`s of pre-filled then -scrolled
    // payloads. cat's PTY is in raw mode (no echo translation), so the bytes we write are
    // the bytes alacritty processes — a `\r\n`-joined block lands as clean full-width rows,
    // and a following block of more lines scrolls the viewport cleanly. We send each block
    // as ONE write so alacritty applies it atomically (like the unit-level scroll test),
    // and snapshot between blocks so each prev->next diff is a coherent shift.
    start_cat(&mut stream, id);
    send(
        &mut stream,
        &format!(r#"{{"op":"attach","id":"{id}","want_raw_output":false}}"#),
    );
    let baseline_line = read_until(&mut reader, "\"ev\":\"grid\"", WITHIN);
    let baseline_v: Value = serde_json::from_str(baseline_line.trim()).unwrap();
    let mut held: Value = baseline_v["grid"].clone();
    let mut held_rev = held["revision"].as_u64().expect("baseline revision");
    let mut saw_scroll = false;

    let drain_apply =
        |reader: &mut BufReader<_>, held: &mut Value, held_rev: &mut u64, saw: &mut bool| {
            for line in drain_assert_absent(reader, "\"ev\":\"output\"", Duration::from_millis(400))
            {
                if !line.contains("\"ev\":\"damage\"") {
                    continue;
                }
                let dmg_v: Value = serde_json::from_str(line.trim()).unwrap();
                let frame = &dmg_v["frame"];
                if frame["base_revision"].as_u64().expect("base_revision") != *held_rev {
                    continue; // not the next link in the chain we hold
                }
                if frame["ops"]
                    .as_array()
                    .expect("ops")
                    .iter()
                    .any(|o| o["op"] == "scroll_up" || o["op"] == "scroll_down")
                {
                    *saw = true;
                }
                apply_damage_json(held, frame);
                *held_rev = frame["revision"].as_u64().expect("revision");
            }
        };

    // Block 1: fill the 24-row screen with 24 lines (rows 0..23), one atomic write.
    // cat's PTY has ONLCR set, so each `\n` we write becomes `\r\n` on the terminal — we
    // must NOT pre-add `\r` ourselves or we get `\r\r\n` (a blank line between each row).
    let fill: String = (1..=24)
        .map(|i| format!("line-{i}"))
        .collect::<Vec<_>>()
        .join("\\n");
    send(
        &mut stream,
        &format!(r#"{{"op":"write","id":"{id}","data":"{fill}"}}"#),
    );
    drain_apply(&mut reader, &mut held, &mut held_rev, &mut saw_scroll);

    // Blocks 2..: each adds 5 more lines, scrolling the full screen up by 5. One atomic
    // write per block keeps the prev->next diff a single clean shift.
    for block in 0..4 {
        let start = 25 + block * 5;
        let more: String = (start..start + 5)
            .map(|i| format!("line-{i}"))
            .collect::<Vec<_>>()
            .join("\\n");
        send(
            &mut stream,
            &format!(r#"{{"op":"write","id":"{id}","data":"\n{more}"}}"#),
        );
        drain_apply(&mut reader, &mut held, &mut held_rev, &mut saw_scroll);
    }

    assert!(
        saw_scroll,
        "scrolling past a full 24-row grid must emit at least one scroll op"
    );

    // The reconstructed grid must equal the daemon's authoritative snapshot cell-for-cell.
    send(&mut stream, &format!(r#"{{"op":"snapshot","id":"{id}"}}"#));
    let auth_line = read_until(&mut reader, "\"ev\":\"grid\"", WITHIN);
    let auth_v: Value = serde_json::from_str(auth_line.trim()).unwrap();
    let authoritative = &auth_v["grid"];

    // Full-header equivalence, UNCONDITIONAL: cat is quiescent after the final block, so
    // the authoritative snapshot is at the same revision the scroll-damage stream brought
    // us to. If they diverge the test must FAIL (otherwise the equivalence is vacuous).
    let _ = held_rev;
    assert_grid_equivalent(&held, authoritative);
}

/// `clear` conventionally emits CUP + ED2 (and sometimes ED3). Pin the essential
/// ED2 path over the real socket: the daemon must ship a structured ClearAll and
/// its authoritative grid must be blank. This protects the native renderer,
/// which deliberately does not receive or parse raw PTY output.
#[test]
fn structured_clear_screen_emits_clear_all_and_blanks_grid() {
    let sock = socket_path("clear-screen-e2e");
    let _killer = Killer(start_daemon_on(&sock));

    let id = "clear-screen-e2e";
    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    start_raw_cat(&mut stream, id);
    send(
        &mut stream,
        &format!(r#"{{"op":"attach","id":"{id}","want_raw_output":false}}"#),
    );
    read_until(&mut reader, "\"ev\":\"grid\"", WITHIN);

    send(
        &mut stream,
        &format!(r#"{{"op":"write","id":"{id}","data":"hello\r\nworld"}}"#),
    );
    read_until(&mut reader, "\"ev\":\"damage\"", WITHIN);

    send(
        &mut stream,
        &format!(r#"{{"op":"write","id":"{id}","data":"\u001b[H\u001b[2J"}}"#),
    );
    let clear = ev(&read_until(&mut reader, "\"ev\":\"damage\"", WITHIN));
    assert!(
        clear["frame"]["ops"]
            .as_array()
            .expect("damage ops")
            .iter()
            .any(|op| op["op"] == "clear_all"),
        "ED2 must become a structured ClearAll frame: {clear}"
    );

    send(&mut stream, &format!(r#"{{"op":"snapshot","id":"{id}"}}"#));
    let snap = ev(&read_until(&mut reader, "\"ev\":\"grid\"", WITHIN));
    let rows = snap["grid"]["rows_cells"].as_array().expect("grid rows");
    assert!(
        rows.iter().all(|row| row
            .as_array()
            .expect("grid row")
            .iter()
            .all(|cell| cell["text"] == " ")),
        "authoritative grid must be blank after ED2"
    );
}

/// Full-screen TUIs such as htop use DECSET 1049. Entering the alternate screen
/// must toggle the mode and paint its content; leaving it must toggle back and
/// restore the untouched primary screen.
#[test]
fn structured_alt_screen_round_trip_restores_primary_grid() {
    let sock = socket_path("alt-screen-e2e");
    let _killer = Killer(start_daemon_on(&sock));

    let id = "alt-screen-e2e";
    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    start_raw_cat(&mut stream, id);
    send(
        &mut stream,
        &format!(r#"{{"op":"attach","id":"{id}","want_raw_output":false}}"#),
    );
    read_until(&mut reader, "\"ev\":\"grid\"", WITHIN);

    send(
        &mut stream,
        &format!(r#"{{"op":"write","id":"{id}","data":"primary"}}"#),
    );
    read_until(&mut reader, "\"ev\":\"damage\"", WITHIN);

    send(
        &mut stream,
        &format!(r#"{{"op":"write","id":"{id}","data":"\u001b[?1049h\u001b[Hdashboard"}}"#),
    );
    let enter = ev(&read_until(&mut reader, "\"ev\":\"damage\"", WITHIN));
    assert_eq!(enter["frame"]["modes"]["alt_screen"], true);

    send(
        &mut stream,
        &format!(r#"{{"op":"write","id":"{id}","data":"\u001b[?1049l"}}"#),
    );
    let leave = ev(&read_until(&mut reader, "\"ev\":\"damage\"", WITHIN));
    assert_eq!(leave["frame"]["modes"]["alt_screen"], false);

    send(&mut stream, &format!(r#"{{"op":"snapshot","id":"{id}"}}"#));
    let snap = ev(&read_until(&mut reader, "\"ev\":\"grid\"", WITHIN));
    let first_row: String = snap["grid"]["rows_cells"][0]
        .as_array()
        .expect("first row")
        .iter()
        .filter_map(|cell| cell["text"].as_str())
        .collect();
    assert!(!snap["grid"]["alt_screen"].as_bool().unwrap());
    assert!(
        first_row.starts_with("primary"),
        "leaving alt screen must restore primary content: {first_row:?}"
    );
}
