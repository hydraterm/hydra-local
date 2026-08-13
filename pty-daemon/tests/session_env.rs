//! Session environment baseline: a session spawned by a daemon that was
//! itself launched from a THIN environment must still get a usable terminal env.
//! We start the daemon binary with a stripped env (no TERM, empty PATH), open a
//! session whose command prints diagnostics, attach for raw output, and assert:
//!   - `command -v ls` resolves (PATH baseline took effect),
//!   - both `ls` and `/bin/ls` run,
//!   - `TERM` is `xterm-256color` (TERM baseline took effect).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
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

/// Spawn the daemon with a deliberately thin environment: clear everything, then
/// add back only what the daemon itself needs to run (HOME, and TMPDIR so any
/// tempdir lookups resolve), an EMPTY PATH, no TERM, and an inherited NO_COLOR.
/// The session-spawn baseline must repair PATH/TERM and remove the color opt-out
/// for the child.
fn start_daemon_thin_env() -> (Child, PathBuf) {
    let bin = env!("CARGO_BIN_EXE_pty-daemon");
    let sock = std::env::temp_dir().join(format!(
        "hydra-session-env-{}-{}.sock",
        std::process::id(),
        unique()
    ));
    let _ = std::fs::remove_file(&sock);
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let tmp = std::env::temp_dir();
    let child = Command::new(bin)
        .arg(&sock)
        .env_clear()
        .env("HOME", home)
        .env("TMPDIR", tmp)
        .env("PATH", "") // empty -> baseline must fill it
        .env("NO_COLOR", "1")
        // intentionally no TERM
        .spawn()
        .expect("spawn daemon binary");
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
            Ok(s) => {
                s.set_read_timeout(Some(Duration::from_millis(250)))
                    .expect("set read timeout");
                return s;
            }
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("could not connect to daemon socket: {e}"),
        }
    }
}

fn send(stream: &mut UnixStream, line: &str) {
    stream.write_all(line.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    stream.flush().unwrap();
}

fn send_value(stream: &mut UnixStream, value: serde_json::Value) {
    send(stream, &serde_json::to_string(&value).unwrap());
}

/// Decode an Output event or an attach Grid snapshot and append its visible text. Reading Grid as
/// well as Output makes short-lived diagnostic commands deterministic: their final screen remains
/// available even when they exit before the attach forwarder starts.
fn append_output(line: &str, acc: &mut String) -> bool {
    let v: serde_json::Value = match serde_json::from_str(line.trim()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if v["ev"].as_str() == Some("grid") {
        if let Some(rows) = v["grid"]["rows_cells"].as_array() {
            for row in rows {
                if let Some(cells) = row.as_array() {
                    for cell in cells {
                        if let Some(text) = cell["text"].as_str() {
                            acc.push_str(text);
                        }
                    }
                }
                acc.push('\n');
            }
            return true;
        }
        return false;
    }
    if v["ev"].as_str() != Some("output") {
        return false;
    }
    let data = v["data"].as_str().unwrap_or("");
    let bytes = B64.decode(data).unwrap_or_default();
    acc.push_str(&String::from_utf8_lossy(&bytes));
    true
}

/// Accumulate raw Output text until it contains `needle` or we time out.
fn collect_output_until(reader: &mut impl BufRead, needle: &str, within: Duration) -> String {
    let deadline = Instant::now() + within;
    let mut acc = String::new();
    let mut line = String::new();
    loop {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {needle:?}; collected so far:\n{acc}"
        );
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => std::thread::sleep(Duration::from_millis(10)),
            Ok(_) => {
                if line.ends_with('\n') {
                    append_output(&line, &mut acc);
                    if acc.contains(needle) {
                        return acc;
                    }
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => panic!("read error: {e}"),
        }
    }
}

fn wait_for_session_exit(
    stream: &mut UnixStream,
    reader: &mut impl BufRead,
    session_id: &str,
    within: Duration,
) {
    let deadline = Instant::now() + within;
    let mut line = String::new();
    loop {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for session {session_id:?} to exit"
        );
        send_value(stream, serde_json::json!({"op":"list_sessions"}));
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => std::thread::sleep(Duration::from_millis(10)),
            Ok(_) => {
                let Ok(value) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
                    continue;
                };
                if value["ev"].as_str() == Some("sessions") {
                    let live = value["ids"]
                        .as_array()
                        .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(session_id)));
                    if !live {
                        return;
                    }
                }
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut => {}
            Err(error) => panic!("read error: {error}"),
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

#[test]
fn session_env_baseline_repairs_path_and_term() {
    let (child, sock) = start_daemon_thin_env();
    let _killer = Killer(child);

    let session_id = "env-baseline-sess";

    // The session runs a small diagnostic via /bin/sh (absolute path, so it
    // resolves regardless of PATH), then prints greppable markers. A trailing
    // DONE marker bounds the wait. `ls`/`command -v ls` must succeed only if the
    // PATH baseline reached the child.
    let script = concat!(
        "command -v ls >/dev/null 2>&1 && echo CV_OK || echo CV_FAIL; ",
        "/bin/ls / >/dev/null 2>&1 && echo BINLS_OK || echo BINLS_FAIL; ",
        "ls / >/dev/null 2>&1 && echo LS_OK || echo LS_FAIL; ",
        "echo TERMIS=$TERM; ",
        "echo COLORIS=$COLORTERM; ",
        "if env | /usr/bin/grep -q '^NO_COLOR='; then echo NOCOLOR_LEAKED; else echo NOCOLOR_CLEAN; fi; ",
        // Keep the PTY open briefly after the final marker. Otherwise the shell
        // exits and closes the PTY immediately, and the EOF can race ahead of the
        // attach forwarder flushing the last Output event — leaving us with all
        // diagnostics but a missing ENV_DIAG_DONE. The sleep lets the marker land
        // before the session ends; we stop reading as soon as we see it.
        "echo ENV_DIAG_DONE; sleep 1"
    );

    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    // Attach first (want_raw_output) so we capture the command's output as it is
    // produced, then start the session.
    send(
        &mut stream,
        &format!(
            r#"{{"op":"start_session","id":"{session_id}","cwd":".","command":"/bin/sh","args":["-c","{script}"],"cols":80,"rows":24}}"#
        ),
    );
    send(
        &mut stream,
        &format!(r#"{{"op":"attach","id":"{session_id}","want_raw_output":true}}"#),
    );

    let out = collect_output_until(&mut reader, "ENV_DIAG_DONE", Duration::from_secs(10));

    assert!(
        out.contains("CV_OK"),
        "`command -v ls` failed under thin daemon env -- PATH baseline not applied:\n{out}"
    );
    assert!(out.contains("BINLS_OK"), "`/bin/ls` failed:\n{out}");
    assert!(
        out.contains("LS_OK"),
        "`ls` failed under thin daemon env -- PATH baseline not applied:\n{out}"
    );
    assert!(
        out.contains("TERMIS=xterm-256color"),
        "TERM was not set to the baseline:\n{out}"
    );
    assert!(
        out.contains("COLORIS=truecolor"),
        "COLORTERM was not set to the baseline:\n{out}"
    );
    assert!(
        out.contains("NOCOLOR_CLEAN"),
        "NO_COLOR leaked from the daemon into the terminal session:\n{out}"
    );
}

#[test]
fn typed_child_environment_overrides_daemon_environment_and_restart() {
    let raw_root = PathBuf::from("/tmp").join(format!(
        "hydra-child-environment-{}-{}",
        std::process::id(),
        unique()
    ));
    std::fs::create_dir_all(&raw_root).expect("create isolated environment root");
    let root = std::fs::canonicalize(&raw_root).expect("canonicalize isolated environment root");
    let ambient_home = root.join("ambient-home");
    let first_home = root.join("first-home");
    let restarted_home = root.join("restarted-home");
    for path in [&ambient_home, &first_home, &restarted_home] {
        std::fs::create_dir_all(path).expect("create isolated HOME fixture");
    }

    let bin = env!("CARGO_BIN_EXE_pty-daemon");
    let sock = root.join("daemon.sock");
    let child = Command::new(bin)
        .arg(&sock)
        .env_clear()
        .env("HOME", &ambient_home)
        .env("SHELL", "/bin/false")
        .env("PATH", "/usr/bin:/bin")
        .env("ZDOTDIR", "/attacker/zdotdir")
        .env("BASH_ENV", "/attacker/bash-env")
        .env("ENV", "/attacker/sh-env")
        .env("XDG_CONFIG_HOME", "/attacker/config")
        .env("XDG_DATA_HOME", "/attacker/data")
        .env("XDG_STATE_HOME", "/attacker/state")
        .env("XDG_CACHE_HOME", "/attacker/cache")
        .spawn()
        .expect("spawn daemon with deliberately wrong ambient account environment");
    let killer = Killer(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sock.exists() {
        assert!(Instant::now() < deadline, "daemon never bound its socket");
        std::thread::sleep(Duration::from_millis(20));
    }

    let mut stream = connect(&sock);
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let first_id = "typed-child-env";
    let first_home_marker = format!("HOME={}", first_home.display());
    send_value(
        &mut stream,
        serde_json::json!({
            "op": "start_session",
            "id": first_id,
            "cwd": first_home,
            "command": "/usr/bin/env",
            "args": [],
            "child_environment": {"home": first_home, "shell": "/bin/sh"},
            "cols": 80,
            "rows": 24
        }),
    );
    send_value(
        &mut stream,
        serde_json::json!({"op":"attach", "id":first_id, "want_raw_output":true}),
    );
    let output = collect_output_until(&mut reader, "SHELL=/bin/sh", Duration::from_secs(10));
    assert!(
        output.contains(&first_home_marker),
        "typed HOME did not reach child: {output}"
    );
    for key in [
        "ZDOTDIR=",
        "BASH_ENV=",
        "ENV=",
        "XDG_CONFIG_HOME=",
        "XDG_DATA_HOME=",
        "XDG_STATE_HOME=",
        "XDG_CACHE_HOME=",
    ] {
        assert!(
            !output.contains(key),
            "headless child inherited {key}: {output}"
        );
    }
    wait_for_session_exit(&mut stream, &mut reader, first_id, Duration::from_secs(10));

    let restart_home_marker = format!("HOME={}", restarted_home.display());
    send_value(
        &mut stream,
        serde_json::json!({
            "op": "start_session",
            "id": first_id,
            "cwd": restarted_home,
            "command": "/usr/bin/env",
            "args": [],
            "child_environment": {"home": restarted_home, "shell": "/bin/sh"},
            "cols": 80,
            "rows": 24,
            "restart_exited": true
        }),
    );
    send_value(
        &mut stream,
        serde_json::json!({"op":"attach", "id":first_id, "want_raw_output":true}),
    );
    let output = collect_output_until(&mut reader, "SHELL=/bin/sh", Duration::from_secs(10));
    assert!(
        output.contains(&restart_home_marker),
        "typed HOME did not reach restarted child: {output}"
    );

    let legacy_id = "legacy-child-env";
    let ambient_home_marker = format!("HOME={}", ambient_home.display());
    send_value(
        &mut stream,
        serde_json::json!({
            "op": "start_session",
            "id": legacy_id,
            "cwd": ambient_home,
            "command": "/usr/bin/env",
            "args": [],
            "cols": 80,
            "rows": 24
        }),
    );
    send_value(
        &mut stream,
        serde_json::json!({"op":"attach", "id":legacy_id, "want_raw_output":true}),
    );
    let output = collect_output_until(&mut reader, &ambient_home_marker, Duration::from_secs(10));
    assert!(
        output.contains(&ambient_home_marker),
        "legacy request must retain daemon HOME: {output}"
    );
    // `collect_output_until` returns as soon as it sees daemon HOME, so variables
    // emitted later by `/usr/bin/env` are not guaranteed to be captured. BASH_ENV
    // and ENV appear in the captured prefix on both supported platforms; retaining
    // them proves that a legacy request did not receive the headless-only scrub.
    assert!(
        output.contains("BASH_ENV=/attacker/bash-env") && output.contains("ENV=/attacker/sh-env"),
        "desktop/legacy request must retain its established ambient environment: {output}"
    );
    assert!(
        !output.contains(&format!("HOME={}", first_home.display()))
            && !output.contains(&format!("HOME={}", restarted_home.display())),
        "legacy request must not inherit a typed headless HOME: {output}"
    );

    drop(stream);
    drop(killer);
    std::fs::remove_dir_all(&root).expect("remove isolated environment fixture");
}
