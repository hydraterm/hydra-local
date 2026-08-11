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

/// Decode an Output event's base64 `data` and append the text to `acc`. Returns
/// true if the line was an output event we decoded.
fn append_output(line: &str, acc: &mut String) -> bool {
    let v: serde_json::Value = match serde_json::from_str(line.trim()) {
        Ok(v) => v,
        Err(_) => return false,
    };
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
