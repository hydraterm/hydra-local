//! Shared harness for daemon integration tests: spawn the binary on a unique
//! socket, connect, send newline-JSON, read until a needle.

use std::io::{BufRead, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// Unique token for socket paths: UNIX-nanos plus an atomic counter, so two
/// tests running in parallel in the same binary never collide.
pub fn unique() -> u128 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    nanos + N.fetch_add(1, Ordering::Relaxed) as u128
}

pub fn socket_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "hydra-{tag}-{}-{:x}.sock",
        std::process::id(),
        unique()
    ))
}

/// Spawn the daemon binary on `sock`, waiting until it binds. Caller owns the
/// child (wrap in `Killer`).
pub fn start_daemon_on(sock: &PathBuf) -> Child {
    let bin = env!("CARGO_BIN_EXE_pty-daemon");
    let child = Command::new(bin).arg(sock).spawn().expect("spawn daemon");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sock.exists() {
        assert!(Instant::now() < deadline, "daemon never bound its socket");
        std::thread::sleep(Duration::from_millis(20));
    }
    // The socket file can exist a hair before accept() is ready; confirm we can
    // actually connect before handing back.
    let deadline = Instant::now() + Duration::from_secs(5);
    while UnixStream::connect(sock).is_err() {
        assert!(Instant::now() < deadline, "daemon socket never accepted");
        std::thread::sleep(Duration::from_millis(20));
    }
    child
}

pub fn connect(sock: &PathBuf) -> UnixStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match UnixStream::connect(sock) {
            Ok(s) => {
                // Every test socket gets a real read timeout so a blocking
                // read_line can never hang a test indefinitely — it returns a
                // WouldBlock/TimedOut error periodically, letting read_until's
                // wall-clock deadline actually fire. Without this the deadline
                // check between reads is never reached when no bytes arrive.
                s.set_read_timeout(Some(Duration::from_millis(250)))
                    .expect("set socket read timeout");
                return s;
            }
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => panic!("connect failed: {e}"),
        }
    }
}

pub fn send(stream: &mut UnixStream, line: &str) {
    stream.write_all(line.as_bytes()).unwrap();
    stream.write_all(b"\n").unwrap();
    stream.flush().unwrap();
}

/// Read lines until one contains `needle`; return it. Panics on timeout. Relies
/// on the socket read timeout set in `connect`, so a partial/blocked read returns
/// an error periodically and the wall-clock deadline below is always honored — no
/// test can hang indefinitely here.
pub fn read_until(reader: &mut impl BufRead, needle: &str, within: Duration) -> String {
    let deadline = Instant::now() + within;
    // `line` accumulates across timeout retries: a read timeout can fire after
    // read_line has already appended a partial line, so we must NOT clear it until
    // a complete (newline-terminated) line has been consumed — clearing mid-line
    // would drop bytes and desync the JSON framing.
    let mut line = String::new();
    loop {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {needle:?}"
        );
        match reader.read_line(&mut line) {
            // EOF: the daemon closed the connection. Keep spinning until the
            // deadline so a transient is reported as a timeout, not a false EOF.
            Ok(0) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(_) => {
                // read_line stops at '\n'. If we have a full line, test it and
                // reset; if the buffer doesn't end in '\n' yet (rare with line
                // framing) keep accumulating.
                if line.ends_with('\n') {
                    if line.contains(needle) {
                        return line.clone();
                    }
                    line.clear();
                }
            }
            // The socket read timeout fired. Any bytes already appended to `line`
            // are preserved for the next iteration. WouldBlock/TimedOut are the
            // expected idle case; anything else is a real I/O fault.
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => panic!("read error while waiting for {needle:?}: {e}"),
        }
    }
}

/// Kills the daemon child on drop so a panicking test doesn't leak processes.
pub struct Killer(pub Child);
impl Drop for Killer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
