//! Coverage for two daemon-side guarantees the renderer relies on:
//!
//! 1. **Late attachment** — a client that attaches *after* the child already
//!    exited must still learn it ended. The exit broadcast only reaches
//!    forwarders that subscribed before EOF, so this exercises the persisted
//!    exit latch + the attach-path replay of SessionExited.
//!
//! 2. **Atomic resync under queue saturation** — when a client falls behind and
//!    the broadcast lags, the daemon must stop forwarding raw output and ship
//!    exactly one ResyncRequired followed by a fresh authoritative Grid baseline,
//!    so the renderer rebaselines rather than painting across lost bytes.
//!
//! Both run under the harness's hard read deadline, so a dropped event surfaces
//! as a fast failure, never an indefinite hang.

mod common;

use std::fs;
use std::io::{BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use common::*;
use serde_json::Value;

const WITHIN: Duration = Duration::from_secs(5);
const SATURATION_PRODUCER_WITHIN: Duration = Duration::from_secs(60);
const SATURATION_TAIL_WITHIN: Duration = Duration::from_secs(60);

struct RemoveFileOnDrop(PathBuf);

impl Drop for RemoveFileOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Attach to a session whose child has ALREADY exited. The daemon must replay
/// the restore Grid and then SessionExited from the latch — the late attacher
/// missed the live exit broadcast entirely.
#[test]
fn late_attach_after_exit_still_receives_session_exited() {
    let sock = socket_path("late-attach");
    let _k = Killer(start_daemon_on(&sock));
    let id = "late-sess";

    let mut s = connect(&sock);
    let mut reader = BufReader::new(s.try_clone().unwrap());

    // A child that exits quickly on its own.
    send(
        &mut s,
        &format!(
            r#"{{"op":"start_session","id":"{id}","cwd":".","command":"sh","args":["-c","exit 3"],"cols":80,"rows":24}}"#
        ),
    );
    // Give the child time to exit and the reader thread to latch the exit BEFORE
    // we attach, so this genuinely tests the late-attach (latch) path and not the
    // live broadcast path.
    std::thread::sleep(Duration::from_millis(400));

    send(&mut s, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
    // The restore Grid comes first (guaranteed baseline), then SessionExited.
    let _grid = read_until(&mut reader, "\"ev\":\"grid\"", WITHIN);
    let exited = read_until(&mut reader, "\"ev\":\"session_exited\"", WITHIN);
    assert!(
        exited.contains(id),
        "late attach must report the exit for {id}: {exited}"
    );
    assert!(
        exited.contains("\"code\":3"),
        "late attach must carry the real exit code 3: {exited}"
    );
}

/// Saturate a slow client's view so the broadcast lags, and assert the daemon
/// makes the resync ATOMIC: a ResyncRequired followed by a fresh Grid baseline.
/// We attach, then flood megabytes of output from the child while NOT reading,
/// so the per-client queue and the broadcast both fill and lag. Then we drain
/// and require the resync envelope to appear before normal output resumes.
#[test]
fn queue_saturation_triggers_atomic_resync_baseline() {
    let sock = socket_path("resync-sat");
    let flood_complete = sock.with_extension("flood-complete");
    assert!(
        !flood_complete.exists(),
        "unique flood-completion marker already exists: {}",
        flood_complete.display()
    );
    let _flood_complete_cleanup = RemoveFileOnDrop(flood_complete.clone());
    let flood_complete_arg = flood_complete
        .to_str()
        .expect("flood-completion marker path must be UTF-8");
    let _k = Killer(start_daemon_on(&sock));
    let id = "sat-sess";
    let title = "SATURATION-TAIL-TITLE-2f61";
    let marker = "SATURATION-TAIL-MARKER-2f61";

    let mut s = connect(&sock);
    // Keep the kernel socket buffer from absorbing a platform-dependent fraction of the flood
    // while this intentionally slow client is not reading. The daemon's bounded queues, not host
    // autotuning, must determine whether this test reaches the Lagged recovery path.
    let requested_recv_buffer: libc::c_int = 16 * 1024;
    let set_recv_buffer = unsafe {
        libc::setsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&requested_recv_buffer as *const libc::c_int).cast(),
            std::mem::size_of_val(&requested_recv_buffer) as libc::socklen_t,
        )
    };
    assert_eq!(set_recv_buffer, 0, "set slow-client socket receive buffer");
    // Bound reads so a quiet stretch returns instead of blocking; the harness
    // read_until honors this too.
    let read_clone = s.try_clone().unwrap();
    read_clone
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let mut reader = BufReader::new(read_clone);

    // A child that emits a large burst of output quickly: `yes` piped through
    // head produces ~8M lines (~72 MiB) with no input needed. Keep raw output enabled for this
    // saturation test so the outbound byte queue must retain bytes proportional to the PTY flood.
    // With structured-only damage, repeated identical rows may legitimately coalesce to one
    // current Grid/Damage state and never fill the queue, which does not exercise lag recovery.
    // The volume must exceed capacity in FRAMES, and frame size is the PTY read granularity —
    // Linux master reads return up to the full 8 KiB buffer, so a smaller flood
    // that saturates macOS (~1 KiB reads) fits entirely in the 1024-frame
    // broadcast + 4096 out-queue there. 72 MiB / 8 KiB ≈ 9000 frames leaves a
    // deterministic margin over both queues even if a frame yields only one outbound event.
    send(
        &mut s,
        &serde_json::json!({
            "op": "start_session",
            "id": id,
            "cwd": ".",
            "command": "sh",
            "args": [
                "-c",
                format!(
                    "IFS= read -r _; yes ABCDEFGH | head -n 8000000; : > \"$1\"; IFS= read -r _; printf '\\033]0;{title}\\007'; printf '\\007'; printf '{marker}\\n'; exit 29"
                ),
                "hydra-saturation",
                flood_complete_arg
            ],
            // Queue saturation depends on frame count, not viewport size. A compact viewport keeps
            // each intentional resync Grid small enough that this correctness gate does not spend
            // a minute serializing thousands of redundant full-screen baselines.
            "cols": 40,
            "rows": 8
        })
        .to_string(),
    );
    send(
        &mut s,
        &format!(r#"{{"op":"attach","id":"{id}","want_raw_output":true}}"#),
    );

    // Prove the live notification receiver exists before the flood starts. Title/bell are
    // intentionally one-shot live effects rather than Grid state, so a child that races through
    // its whole script before Attach is not required to replay them. Blocking the child on stdin,
    // consuming the initial attach Grid, and only then releasing it makes this a deterministic
    // test of the post-attach saturation path rather than a scheduler-speed race.
    let initial_grid = read_until(&mut reader, "\"ev\":\"grid\"", WITHIN);
    assert!(initial_grid.contains(id));
    send(
        &mut s,
        &serde_json::json!({"op": "write", "id": id, "data": "\n"}).to_string(),
    );

    // Stay deliberately unread until the child has completed the entire fixed flood. A fixed sleep
    // races slow or loaded runners: draining can begin before enough 8 KiB PTY frames exist to lap
    // the broadcast. The out-of-band file is written only after all ~72 MiB have been accepted by
    // the PTY, and the second stdin barrier keeps the one-shot title/bell/exit tail out of the flood.
    let producer_deadline = Instant::now() + SATURATION_PRODUCER_WITHIN;
    while !flood_complete.exists() {
        assert!(
            Instant::now() < producer_deadline,
            "timed out waiting for the saturation producer completion marker: {}",
            flood_complete.display()
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    fs::remove_file(&flood_complete).expect("remove saturation producer completion marker");

    // Drain through ONE collector. Sequential `read_until` calls silently discard unmatched
    // events, which can turn an ordering failure into a misleading later timeout. Record the
    // resync envelope and controlled live tail in their actual wire order, stopping on exit. Keep
    // the child at its second stdin barrier until the atomic recovery Grid has actually reached
    // this client; only then can the title, bell, marker, and exit enter the live stream.
    let deadline = Instant::now() + SATURATION_TAIL_WITHIN;
    let mut line = String::new();
    let mut order = 0_usize;
    let mut waiting_for_resync_grid = false;
    let mut tail_released = false;
    let mut resync_grid_order = None;
    let mut title_order = None;
    let mut bell_order = None;
    let (exit_order, exited) = loop {
        assert!(
            Instant::now() < deadline,
            "timed out collecting the saturation tail: order={order} waiting_grid={waiting_for_resync_grid} tail_released={tail_released} resync_grid={resync_grid_order:?} title={title_order:?} bell={bell_order:?} partial_bytes={}",
            line.len()
        );
        match reader.read_line(&mut line) {
            Ok(0) => std::thread::sleep(Duration::from_millis(10)),
            Ok(_) if line.ends_with('\n') => {
                if line.contains("\"ev\":\"resync_required\"") && line.contains(id) {
                    waiting_for_resync_grid = true;
                    order += 1;
                } else if line.contains("\"ev\":\"grid\"")
                    && line.contains(id)
                    && waiting_for_resync_grid
                {
                    waiting_for_resync_grid = false;
                    resync_grid_order.get_or_insert(order);
                    order += 1;
                    if !tail_released {
                        send(
                            &mut s,
                            &serde_json::json!({"op": "write", "id": id, "data": "\n"}).to_string(),
                        );
                        tail_released = true;
                    }
                } else if line.contains("\"ev\":\"terminal_title\"") && line.contains(title) {
                    title_order.get_or_insert(order);
                    order += 1;
                } else if line.contains("\"ev\":\"terminal_bell\"") && line.contains(id) {
                    bell_order.get_or_insert(order);
                    order += 1;
                } else if line.contains("\"ev\":\"session_exited\"") && line.contains(id) {
                    let exited = line.clone();
                    break (order, exited);
                }
                line.clear();
            }
            Ok(_) => {}
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(error) => panic!("read error while collecting saturation tail: {error}"),
        }
    };

    let resync_grid_order = resync_grid_order.expect("missing atomic ResyncRequired -> Grid pair");
    let title_order = title_order.expect("attached tail title was not delivered before exit");
    let bell_order = bell_order.expect("attached tail bell was not delivered before exit");
    assert!(
        resync_grid_order < title_order && title_order < bell_order && bell_order < exit_order,
        "wrong saturation tail order: grid={resync_grid_order} title={title_order} bell={bell_order} exit={exit_order}"
    );
    assert!(exited.contains("\"code\":29"), "wrong exit event: {exited}");

    // Reattach after exit and verify the authoritative final Grid retained the tail marker. This
    // avoids depending on raw Output for recovery and proves the resync/exit path did not truncate
    // final content.
    send(
        &mut s,
        &format!(r#"{{"op":"attach","id":"{id}","want_raw_output":false}}"#),
    );
    let final_grid = read_until(&mut reader, "\"ev\":\"grid\"", WITHIN);
    let event: Value = serde_json::from_str(final_grid.trim()).expect("final Grid JSON");
    let visible: String = event["grid"]["rows_cells"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|row| row.as_array().into_iter().flatten())
        .filter_map(|cell| cell["text"].as_str())
        .collect();
    assert!(
        visible.contains(marker),
        "final resync Grid omitted tail marker: {visible:?}"
    );
}
