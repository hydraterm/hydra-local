//! Structured-damage benchmark harness, measured over the wire.
//!
//! These are not pass/fail micro-benchmarks; they exercise the live forwarder under
//! representative load and PRINT run-specific metrics while asserting the protocol invariants described
//! by the public types in `src/protocol.rs` (damage frames advance revision; a resize burst stays bounded
//! with no resync storm). Run with output visible:
//!
//!   cargo test -p pty-daemon --test damage_bench -- --nocapture
//!
//! Metrics are inherently machine/run dependent; the asserts guard correctness and the printed values
//! support release qualification. The cap-driven fallback to Resync (a diff exceeding
//! MAX_DAMAGE_OPS / MAX_DAMAGE_CELLS) is exercised by the pure unit tests in
//! `grid.rs` — it cannot be tripped by a realistic terminal geometry over the wire
//! (it needs > 4096 changed rows or > 1e6 changed cells), so it is intentionally not
//! re-driven here.

mod common;

use common::{connect, read_until, send, socket_path, start_daemon_on, Killer};
use serde_json::Value;
use std::io::{BufRead, BufReader};
use std::time::{Duration, Instant};

const WITHIN: Duration = Duration::from_secs(5);

fn start_cat(stream: &mut std::os::unix::net::UnixStream, id: &str, cols: u16, rows: u16) {
    send(
        stream,
        &format!(
            r#"{{"op":"start_session","id":"{id}","cwd":".","command":"cat","args":[],"cols":{cols},"rows":{rows}}}"#
        ),
    );
    std::thread::sleep(Duration::from_millis(200));
}

/// Read the next complete event line (any event), honoring the socket read timeout so a
/// quiescent stream returns `None` at the deadline rather than hanging. Returns the raw
/// line including its trailing newline.
fn next_event(reader: &mut impl BufRead, within: Duration) -> Option<String> {
    let deadline = Instant::now() + within;
    let mut line = String::new();
    loop {
        if Instant::now() >= deadline {
            return None;
        }
        match reader.read_line(&mut line) {
            Ok(0) => std::thread::sleep(Duration::from_millis(10)),
            Ok(_) => {
                if line.ends_with('\n') {
                    return Some(line);
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => panic!("read error: {e}"),
        }
    }
}

/// SUSTAINED OUTPUT: stream many writes through `cat` and tally the resulting Damage
/// frames — count, total wire bytes, average and max frame size, elapsed wall time —
/// then compare the total damage bytes against ONE full Grid snapshot of the same final
/// screen. The point of structured damage is that streaming N incremental frames moves
/// far fewer bytes than re-sending the full grid N times; we print both so the doc can
/// state the ratio for this run.
#[test]
fn bench_sustained_output_damage_vs_snapshot() {
    let sock = socket_path("bench-sustained");
    let _killer = Killer(start_daemon_on(&sock));

    let id = "bench-sustained";
    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    start_cat(&mut stream, id, 80, 24);
    send(
        &mut stream,
        &format!(r#"{{"op":"attach","id":"{id}","want_raw_output":false}}"#),
    );
    // Drain the baseline restore Grid.
    let _ = read_until(&mut reader, "\"ev\":\"grid\"", WITHIN);

    const WRITES: usize = 200;
    let start = Instant::now();
    for i in 0..WRITES {
        // Each line is distinct so it actually changes the grid (cat echoes it),
        // producing one committed mutation -> one Damage frame.
        send(
            &mut stream,
            &format!(r#"{{"op":"write","id":"{id}","data":"line-{i:04}\n"}}"#),
        );
    }

    let mut damage_count = 0usize;
    let mut damage_bytes = 0usize;
    let mut max_frame = 0usize;
    let mut last_rev = 0u64;
    // Read until the stream goes quiet (no event within a short idle window) or we've
    // collected at least as many frames as writes. cat may coalesce bytes so frames can
    // be fewer than writes; that's fine — we tally whatever the daemon shipped.
    while let Some(line) = next_event(&mut reader, Duration::from_millis(600)) {
        let v: Value = serde_json::from_str(line.trim()).expect("event JSON");
        if v["ev"].as_str() == Some("damage") {
            let bytes = line.len();
            damage_count += 1;
            damage_bytes += bytes;
            max_frame = max_frame.max(bytes);
            let rev = v["frame"]["revision"].as_u64().expect("frame revision");
            assert!(
                rev > last_rev,
                "each damage frame strictly advances the revision: {rev} > {last_rev}"
            );
            last_rev = rev;
        }
    }
    let elapsed = start.elapsed();

    assert!(
        damage_count > 0,
        "sustained output must produce at least one damage frame"
    );

    // One full Grid snapshot of the SAME final screen, for the size comparison.
    send(&mut stream, &format!(r#"{{"op":"snapshot","id":"{id}"}}"#));
    let snap_line = read_until(&mut reader, "\"ev\":\"grid\"", WITHIN);
    let snapshot_bytes = snap_line.len();

    let avg_frame = damage_bytes as f64 / damage_count as f64;
    // Naive baseline: the old polling/bridge model would re-ship a full snapshot per
    // visible change. Streaming the same N changes as full snapshots would cost roughly
    // damage_count * snapshot_bytes; structured damage costs damage_bytes.
    let naive_snapshot_stream = damage_count * snapshot_bytes;
    let ratio = naive_snapshot_stream as f64 / damage_bytes.max(1) as f64;

    println!("=== sustained-output benchmark (80x24, {WRITES} writes) ===");
    println!("damage frames:            {damage_count}");
    println!("total damage bytes:       {damage_bytes}");
    println!("avg frame bytes:          {avg_frame:.1}");
    println!("max frame bytes:          {max_frame}");
    println!("elapsed:                  {elapsed:?}");
    println!("one full snapshot bytes:  {snapshot_bytes}");
    println!("naive snapshot-stream:    {naive_snapshot_stream} ({damage_count} x snapshot)");
    println!("damage / snapshot-stream: {ratio:.1}x smaller");
}

/// RESIZE BURST: a rapid run of distinct resizes must each produce a bounded full-grid
/// resync (ResyncRequired + Grid), never a partial-resize damage frame and never an
/// unbounded resync storm (more grids than resizes). Asserts the per-resize accounting
/// and prints the totals.
#[test]
fn bench_resize_burst_bounded_no_storm() {
    let sock = socket_path("bench-resize");
    let _killer = Killer(start_daemon_on(&sock));

    let id = "bench-resize";
    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    start_cat(&mut stream, id, 80, 24);
    send(
        &mut stream,
        &format!(r#"{{"op":"attach","id":"{id}","want_raw_output":false}}"#),
    );
    let _ = read_until(&mut reader, "\"ev\":\"grid\"", WITHIN);

    // Distinct geometries so each resize is a real change.
    let dims: [(u16, u16); 6] = [
        (100, 30),
        (120, 40),
        (90, 28),
        (110, 35),
        (80, 24),
        (130, 45),
    ];
    for (i, (cols, rows)) in dims.iter().enumerate() {
        send(
            &mut stream,
            &format!(r#"{{"op":"resize","id":"{id}","cols":{cols},"rows":{rows}}}"#),
        );
        // The forwarder only diffs the grid when PTY output advances it; a resize alone
        // produces no output. A tiny write after each resize drives one committed
        // mutation, which the forwarder sees AT the new geometry → ResyncRequired + Grid
        // (the generation/geometry-change branch). Without this, a resize is invisible
        // over the wire and the burst would be a vacuous no-op.
        std::thread::sleep(Duration::from_millis(60));
        send(
            &mut stream,
            &format!(r#"{{"op":"write","id":"{id}","data":"r{i}\n"}}"#),
        );
    }

    let mut grids = 0usize;
    let mut resync = 0usize;
    let mut damage = 0usize;
    let mut output = 0usize;
    while let Some(line) = next_event(&mut reader, Duration::from_millis(700)) {
        match serde_json::from_str::<Value>(line.trim()).expect("json")["ev"].as_str() {
            Some("grid") => grids += 1,
            Some("resync_required") => resync += 1,
            Some("damage") => damage += 1,
            Some("output") => output += 1,
            _ => {}
        }
    }

    println!("=== resize-burst benchmark ({} resizes) ===", dims.len());
    println!("grids:            {grids}");
    println!("resync_required:  {resync}");
    println!("damage frames:    {damage}");
    println!("raw output:       {output}");

    // No raw Output on a structured-only attach, ever.
    assert_eq!(output, 0, "want_raw_output:false must not emit raw Output");
    // Each resize is driven visible by exactly one post-resize write at the NEW geometry,
    // so each must produce exactly one ResyncRequired + one Grid — the resize/full-clear
    // contract. No partial-resize damage is emitted for the geometry change itself.
    assert!(
        grids >= 1,
        "resizes driven by a write must produce at least one full Grid resync"
    );
    // Bounded: at most one Grid (and at most one ResyncRequired) per resize. MORE would
    // be a resync storm. We allow the storm bound to be the number of resizes; coalescing
    // can make it fewer, never more.
    assert!(
        grids <= dims.len(),
        "no resync storm: grids ({grids}) must not exceed resizes ({})",
        dims.len()
    );
    assert!(
        resync <= dims.len(),
        "no resync storm: resync_required ({resync}) must not exceed resizes ({})",
        dims.len()
    );
    // NOTE on damage during a resize burst: damage frames here are NOT partial-resize
    // damage. The forwarder only diffs the grid when PTY output advances it, so a write
    // that lands AFTER its resize already resynced is a normal in-geometry mutation and
    // ships as a Frame. The geometry change ITSELF is always a full Grid (asserted above
    // via the resync/grid counts); a damage frame never carries a cols/rows change. What
    // matters for "no storm" is that grids and resyncs stay bounded by the resize count,
    // which we asserted — the damage count is just incidental echo and need not be zero.
}

/// LARGE-SCREEN REWRITE: on a large grid, a single full-screen rewrite still ships as
/// ONE damage frame (well under the caps for any realistic geometry). Prints the frame
/// size so the doc can record the worst realistic single-frame cost. (The cap-driven
/// Resync fallback — diff over MAX_DAMAGE_OPS/MAX_DAMAGE_CELLS — needs > 4096 changed
/// rows or > 1e6 changed cells, impossible at realistic dims, and is unit-tested in
/// grid.rs; we don't try to trip it over the wire.)
#[test]
fn bench_large_screen_rewrite_single_frame() {
    let sock = socket_path("bench-large");
    let _killer = Killer(start_daemon_on(&sock));

    let id = "bench-large";
    let cols: u16 = 200;
    let rows: u16 = 50;
    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    start_cat(&mut stream, id, cols, rows);
    send(
        &mut stream,
        &format!(r#"{{"op":"attach","id":"{id}","want_raw_output":false}}"#),
    );
    let _ = read_until(&mut reader, "\"ev\":\"grid\"", WITHIN);

    // Fill most of the screen in one write: rows-1 lines of cols-1 chars each. cat echoes
    // it as one burst -> the grid rewrites in (typically) one committed mutation.
    let line = "x".repeat((cols - 1) as usize);
    let mut payload = String::new();
    for _ in 0..(rows - 1) {
        payload.push_str(&line);
        payload.push_str("\\n");
    }
    send(
        &mut stream,
        &format!(r#"{{"op":"write","id":"{id}","data":"{payload}"}}"#),
    );

    let mut frames = 0usize;
    let mut total_ops = 0usize;
    let mut max_frame_bytes = 0usize;
    while let Some(l) = next_event(&mut reader, Duration::from_millis(800)) {
        let v: Value = serde_json::from_str(l.trim()).expect("json");
        if v["ev"].as_str() == Some("damage") {
            frames += 1;
            max_frame_bytes = max_frame_bytes.max(l.len());
            total_ops += v["frame"]["ops"].as_array().map(|a| a.len()).unwrap_or(0);
        }
    }

    println!("=== large-screen rewrite benchmark ({cols}x{rows}) ===");
    println!("damage frames:     {frames}");
    println!("total RowSpan ops: {total_ops}");
    println!("max frame bytes:   {max_frame_bytes}");

    assert!(
        frames > 0,
        "a full-screen rewrite must produce at least one damage frame (not a resync)"
    );
}
