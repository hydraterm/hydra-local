//! Lifecycle, attach-identity and socket-guard hardening.

mod common;

use std::io::BufReader;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use common::*;

fn decode_output(line: &str) -> Vec<u8> {
    let key = "\"data\":\"";
    let start = line.find(key).expect("data field") + key.len();
    let rest = &line[start..];
    let end = rest.find('"').expect("closing quote");
    B64.decode(&rest[..end]).expect("valid base64")
}

/// A child that exits on its own fires SessionExited with its code.
#[test]
fn child_exit_emits_session_exited() {
    let sock = socket_path("life-exit");
    let _k = Killer(start_daemon_on(&sock));
    let id = "exit-sess";

    let mut s = connect(&sock);
    let mut reader = BufReader::new(s.try_clone().unwrap());
    // sh that exits 7 after a beat so attach lands before exit.
    send(
        &mut s,
        &format!(
            r#"{{"op":"start_session","id":"{id}","cwd":".","command":"sh","args":["-c","sleep 0.3; exit 7"],"cols":80,"rows":24}}"#
        ),
    );
    send(&mut s, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
    let exited = read_until(
        &mut reader,
        "\"ev\":\"session_exited\"",
        Duration::from_secs(5),
    );
    assert!(
        exited.contains(id),
        "exit event for wrong session: {exited}"
    );
    assert!(
        exited.contains("\"code\":7"),
        "expected exit code 7: {exited}"
    );
}

/// Kill terminates a long-running child and fires SessionExited; the
/// session then leaves the list.
#[test]
fn kill_terminates_child() {
    let sock = socket_path("life-kill");
    let _k = Killer(start_daemon_on(&sock));
    let id = "kill-sess";

    let mut s = connect(&sock);
    let mut reader = BufReader::new(s.try_clone().unwrap());
    send(
        &mut s,
        &format!(
            r#"{{"op":"start_session","id":"{id}","cwd":".","command":"sleep","args":["300"],"cols":80,"rows":24}}"#
        ),
    );
    send(&mut s, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
    // Drain the grid restore so we're streaming.
    let _ = read_until(&mut reader, "\"ev\":\"grid\"", Duration::from_secs(5));

    send(&mut s, &format!(r#"{{"op":"kill","id":"{id}"}}"#));
    let exited = read_until(
        &mut reader,
        "\"ev\":\"session_exited\"",
        Duration::from_secs(5),
    );
    assert!(exited.contains(id), "kill didn't report exit: {exited}");

    // Session should be gone from the list.
    send(&mut s, r#"{"op":"list_sessions"}"#);
    let sessions = read_until(&mut reader, "\"ev\":\"sessions\"", Duration::from_secs(5));
    assert!(
        !sessions.contains(id),
        "killed session still listed: {sessions}"
    );
}

/// Attaching twice on one connection must not double output. We attach,
/// then attach again (which should replace the first forwarder), then echo a
/// marker through `cat` and assert the marker's bytes appear exactly once.
///
/// `stty -echo` first so the PTY line discipline doesn't echo our input — then
/// `cat` is the sole producer of the marker, and the marker lands in the output
/// stream exactly once per *live forwarder*. A leaked/duplicated forwarder (the
/// duplicated-forwarder regression would surface it twice; correct dedup keeps it at one.
#[test]
fn repeat_attach_does_not_duplicate() {
    let sock = socket_path("life-dup");
    let _k = Killer(start_daemon_on(&sock));
    let id = "dup-sess";
    let marker = "ZZmarkerZZ";

    let mut s = connect(&sock);
    let read_clone = s.try_clone().unwrap();
    // A read timeout bounds the collection window: once output stops, read_line
    // returns a WouldBlock/timeout error instead of blocking forever (fixes the
    // hang where the daemon never closes the connection).
    read_clone
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let mut reader = BufReader::new(read_clone);
    send(
        &mut s,
        &format!(
            r#"{{"op":"start_session","id":"{id}","cwd":".","command":"sh","args":["-c","stty -echo; cat"],"cols":80,"rows":24}}"#
        ),
    );
    // Two attaches back-to-back. The second must replace, not add, a forwarder.
    send(&mut s, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
    send(&mut s, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
    // Drain both grid restores (one per attach).
    let _ = read_until(&mut reader, "\"ev\":\"grid\"", Duration::from_secs(5));
    let _ = read_until(&mut reader, "\"ev\":\"grid\"", Duration::from_secs(5));
    // Let `stty -echo` take effect before we write the marker, else the line
    // discipline echoes it back and inflates the count independent of forwarders.
    std::thread::sleep(Duration::from_millis(300));

    // Echo the marker once.
    send(
        &mut s,
        &format!(r#"{{"op":"write","id":"{id}","data":"{marker}\n"}}"#),
    );

    // Collect output until reads quiesce (timeout) past a hard deadline, then
    // count marker occurrences across the concatenated decoded byte stream.
    let mut all = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    use std::io::BufRead;
    loop {
        if std::time::Instant::now() >= deadline {
            break;
        }
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF: daemon closed
            Ok(_) => {
                if line.contains("\"ev\":\"output\"") {
                    all.extend(decode_output(&line));
                }
            }
            // Timed-out read with no more data → collection window is done.
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&all);
    let count = text.matches(marker).count();
    assert_eq!(
        count, 1,
        "marker should appear exactly once (duplication regression); got {count} in {text:?}"
    );
}

/// A second daemon on a live socket must refuse, not clobber. We start
/// daemon A, then start B on the same socket and assert B exits non-zero while
/// A still answers.
#[test]
fn second_daemon_refuses_live_socket() {
    let sock = socket_path("life-second");
    let _a = Killer(start_daemon_on(&sock));

    // B targets the same socket. It should refuse and exit non-zero.
    let bin = env!("CARGO_BIN_EXE_pty-daemon");
    let out = std::process::Command::new(bin)
        .arg(&sock)
        .output()
        .expect("run second daemon");
    assert!(
        !out.status.success(),
        "second daemon should have refused, but exited 0; stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // A must still be answering.
    let mut s = connect(&sock);
    let mut reader = BufReader::new(s.try_clone().unwrap());
    send(&mut s, r#"{"op":"list_sessions"}"#);
    let _ = read_until(&mut reader, "\"ev\":\"sessions\"", Duration::from_secs(5));
}

/// Send `sig` to `pid` via libc::kill.
fn send_signal(pid: u32, sig: i32) {
    // SAFETY: kill is always safe to call; an invalid pid just returns -1/ESRCH.
    let rc = unsafe { libc::kill(pid as libc::pid_t, sig) };
    assert_eq!(rc, 0, "failed to deliver signal {sig} to pid {pid}");
}

/// Wait up to `within` for the daemon child to exit; return its ExitStatus.
fn wait_for_daemon_exit(
    child: &mut std::process::Child,
    within: Duration,
) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + within;
    loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => return status,
            None => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "daemon did not exit after the termination signal"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

/// Targeted: the SIGTERM path runs graceful shutdown (kills+reaps the owned
/// child) and the daemon exits CLEANLY (status 0). A clean exit code is the
/// observable proof that `Daemon::shutdown` ran and reported every child reaped
/// — `main` returns Ok only when `report.all_reaped()`.
#[test]
fn sigterm_runs_graceful_shutdown_and_exits_clean() {
    let sock = socket_path("life-sigterm");
    // NOTE: not wrapped in Killer — this test owns the child's termination via the
    // signal under test, and asserts on its exit status directly.
    let mut child = start_daemon_on(&sock);

    // Give the daemon a live child to reap on shutdown.
    let id = "term-sess";
    let mut s = connect(&sock);
    let mut reader = BufReader::new(s.try_clone().unwrap());
    send(
        &mut s,
        &format!(
            r#"{{"op":"start_session","id":"{id}","cwd":".","command":"sleep","args":["300"],"cols":80,"rows":24}}"#
        ),
    );
    send(&mut s, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
    let _ = read_until(&mut reader, "\"ev\":\"grid\"", Duration::from_secs(5));

    // Deliver SIGTERM; the daemon must shut down gracefully and exit 0.
    send_signal(child.id(), libc::SIGTERM);
    let status = wait_for_daemon_exit(&mut child, Duration::from_secs(10));
    assert!(
        status.success(),
        "daemon should exit cleanly after SIGTERM (all children reaped); status: {status:?}"
    );

    // The daemon removed its own socket on the way out (graceful-exit cleanup).
    assert!(
        !sock.exists(),
        "graceful shutdown should remove the daemon's socket file"
    );
}

/// Targeted: SIGINT takes the same graceful path as SIGTERM. Covers the other
/// signal arm of the select so neither is silently unhandled.
#[test]
fn sigint_runs_graceful_shutdown_and_exits_clean() {
    let sock = socket_path("life-sigint");
    let mut child = start_daemon_on(&sock);

    let id = "int-sess";
    let mut s = connect(&sock);
    let mut reader = BufReader::new(s.try_clone().unwrap());
    send(
        &mut s,
        &format!(
            r#"{{"op":"start_session","id":"{id}","cwd":".","command":"sleep","args":["300"],"cols":80,"rows":24}}"#
        ),
    );
    send(&mut s, &format!(r#"{{"op":"attach","id":"{id}"}}"#));
    let _ = read_until(&mut reader, "\"ev\":\"grid\"", Duration::from_secs(5));

    send_signal(child.id(), libc::SIGINT);
    let status = wait_for_daemon_exit(&mut child, Duration::from_secs(10));
    assert!(
        status.success(),
        "daemon should exit cleanly after SIGINT; status: {status:?}"
    );
}
