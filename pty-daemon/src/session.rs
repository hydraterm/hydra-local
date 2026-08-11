//! A Session owns one agent process via a PTY, plus a bounded scrollback ring
//! used to replay the screen when a UI client reattaches. The session lives in
//! the daemon, so it survives the UI quitting — that's tier-(a) persistence.

use crate::grid::{
    clamp_to_snapshot_budget, normalize_dims, GridSnapshot, ScrollbackRead, TermGrid,
    TerminalNotification,
};
use crate::ids::{ChannelId, SessionId};
use crate::revision::Revision;
use anyhow::Result;
use portable_pty::{native_pty_system, ChildKiller, CommandBuilder, MasterPty, PtySize};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

/// Max bytes of scrollback retained per session for replay-on-reattach. Bounded
/// so a long-running agent can't grow memory without limit. ~1 MiB is plenty
/// to repaint a screen plus recent history; deeper history is the agent's own
/// concern (it resumes via --continue on a cold start).
const SCROLLBACK_CAP: usize = 1024 * 1024;

/// One broadcast unit of live output: the raw bytes plus the grid revision they
/// produced. The revision lets an attaching client discard any frame already
/// folded into its restore snapshot — closing the snapshot/live-stream race
/// without relying on the harmless-double assumption. `revision` is the value
/// AFTER this chunk was applied to the grid.
#[derive(Clone)]
pub struct OutputFrame {
    pub revision: Revision,
    pub bytes: Vec<u8>,
    pub notifications: Vec<TerminalNotification>,
}

/// Snapshot taken atomically with a fresh output subscription: the grid state
/// plus the receiver positioned exactly at the boundary. Any frame the receiver
/// yields with `revision <= snapshot.revision` is already in `snapshot` and must
/// be dropped by the client.
pub struct AttachState {
    pub snapshot: GridSnapshot,
    pub output_rx: broadcast::Receiver<OutputFrame>,
    pub exit_rx: broadcast::Receiver<Option<i32>>,
    pub already_exited: Option<Option<i32>>,
}

/// A detached, cloneable handle onto a session's authoritative grid. The forwarder
/// task holds one so it can take a fresh baseline snapshot when its broadcast lags
/// — without reaching back through the daemon lock. Taking the snapshot here uses
/// the same grid mutex the reader thread advances under, so the captured revision
/// is a consistent boundary, exactly like attach.
#[derive(Clone)]
pub struct GridHandle {
    grid: Arc<Mutex<TermGrid>>,
    /// The session's exit latch, shared so the forwarder can recover the exit
    /// code if the live-output broadcast closes before the exit broadcast is
    /// delivered (a race on session teardown — see the forwarder's output-closed
    /// arm in main.rs). `None` = still running; `Some(code)` = exited.
    exited: Arc<Mutex<Option<Option<i32>>>>,
}

impl GridHandle {
    /// Fresh authoritative snapshot of the current screen.
    pub fn snapshot(&self) -> GridSnapshot {
        self.grid.lock().unwrap().snapshot()
    }

    /// The persisted exit state, if the child has exited. Lets the forwarder
    /// emit SessionExited even when it learns of the end via the output channel
    /// closing rather than the exit broadcast.
    pub fn exit_state(&self) -> Option<Option<i32>> {
        *self.exited.lock().unwrap()
    }
}

/// A detached, cloneable handle onto a session's PTY write/resize surface.
///
/// Input (`Write`) and `Resize` requests do potentially BLOCKING IO: a write
/// can stall on a full kernel PTY buffer if the child isn't draining, and
/// `resize` issues an ioctl. Performing that work while the global daemon
/// `Mutex` is held would let one wedged session block every unrelated request
/// (`ListSessions`, `StartSession`, another session's `Write`). So the request
/// handlers clone this handle out from under the daemon lock (cheap `Arc`
/// clones), release the daemon lock, and only then touch the PTY.
///
/// Ordering is preserved per session: every write for a given session takes the
/// same `writer` mutex, so concurrent writes serialize in lock-acquisition order
/// exactly as they did when serialized by the daemon lock. The `writer`/`master`
/// mutexes are leaf locks held only across the syscall — never across the daemon
/// lock or any `.await` — so they cannot reintroduce cross-session coupling.
#[derive(Clone)]
pub struct PtyHandle {
    /// The PTY master write end. `write_all` + `flush` can block on a full PTY
    /// buffer; this mutex serializes writes per session without the daemon lock.
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    /// The PTY master, for resize ioctls. Wrapped in a `Mutex` because
    /// `MasterPty` is `Send` but not `Sync`, so it can't be shared via `Arc`
    /// alone; the lock is held only across the resize ioctl.
    master: Arc<Mutex<Box<dyn MasterPty + Send>>>,
    /// The authoritative grid, kept in lockstep with the PTY size on resize.
    grid: Arc<Mutex<TermGrid>>,
}

impl PtyHandle {
    /// Forward input bytes to the child via the PTY master. Blocking IO, run
    /// OFF the daemon lock. Writes serialize per session on `writer`.
    pub fn write_input(&self, data: &[u8]) -> Result<()> {
        let mut w = self.writer.lock().unwrap();
        w.write_all(data)?;
        w.flush()?;
        Ok(())
    }

    /// Clone of the per-session writer lock. Test-only: a test holds this guard
    /// to STAND IN for an in-progress blocking `write_input` (which holds exactly
    /// this lock for the duration of the syscall), then asserts the daemon lock
    /// is still free — the required cross-session isolation property. We can't reproduce a truly
    /// blocked PTY write on macOS (portable-pty buffers the master write so it
    /// never blocks, even at 80 MB), so we prove the locking discipline directly.
    #[cfg(test)]
    pub fn writer_lock_for_test(&self) -> Arc<Mutex<Box<dyn Write + Send>>> {
        self.writer.clone()
    }

    /// Resize the PTY and keep the authoritative grid in lockstep. Off the
    /// daemon lock; the resize ioctl can block, and we don't want it to stall
    /// unrelated sessions.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        // Normalize once, then clamp to the snapshot cell budget so the
        // resulting grid is always wire-shippable as one line (`MAX_LINE_BYTES`).
        // Resize CLAMPS (preserving aspect ratio) rather than rejecting, so a
        // window drag never errors. The SAME clamped pair sizes the PTY and the
        // grid, so they can never disagree about geometry.
        let (cols, rows) = normalize_dims(cols, rows);
        let (cols, rows) = clamp_to_snapshot_budget(cols, rows);
        self.master.lock().unwrap().resize(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })?;
        self.grid.lock().unwrap().resize(cols, rows);
        Ok(())
    }
}

pub struct Session {
    pub id: SessionId,
    /// Original working directory used to spawn this session. Exposed as metadata for dashboard labels; never
    /// affects PTY authority after spawn.
    pub cwd: String,
    /// Channels this session participates in (Option X: sessions own subs).
    pub subscriptions: Vec<ChannelId>,
    /// The PTY master, behind a shared lock so `PtyHandle` can issue resize
    /// ioctls off the daemon lock. `Send` but not `Sync`, hence the `Mutex`.
    master: Arc<Mutex<Box<dyn MasterPty + Send>>>,
    /// The PTY write end, behind a shared lock so `PtyHandle` can forward input
    /// off the daemon lock while preserving per-session write ordering.
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    /// Ring of recent raw output bytes, for replay on reattach.
    scrollback: Arc<Mutex<VecDeque<u8>>>,
    /// The authoritative parsed grid. The PTY reader feeds every chunk here, so
    /// the daemon (not the renderer) is the single source of screen truth.
    grid: Arc<Mutex<TermGrid>>,
    /// Live output fan-out. Each attached client subscribes; the PTY reader
    /// thread broadcasts every chunk. Lagging clients drop old frames rather
    /// than back-pressure the agent.
    pub output_tx: broadcast::Sender<OutputFrame>,
    /// Fires once when the child process exits, carrying its exit code (None if
    /// unknown / signalled). Forwarders subscribe so they can emit SessionExited
    /// and stop. Sent by the reader thread when it reaches EOF.
    pub exit_tx: broadcast::Sender<Option<i32>>,
    /// Persisted exit state, set once by the reader thread on EOF. The broadcast
    /// above only reaches forwarders that subscribed *before* the child exited; a
    /// client that attaches afterward would wait forever on it. This latch lets
    /// the Attach path detect an already-exited session and emit SessionExited
    /// synchronously. `None` = still running; `Some(code)` = exited with `code`.
    exited: Arc<Mutex<Option<Option<i32>>>>,
    /// Handle to terminate the child explicitly (Kill). Cloned from the child;
    /// the child itself is owned by the reader thread so it can reap the exit
    /// code on EOF.
    /// Shared with the reader/reaper so checking the exit latch and signalling the numeric child
    /// pid are serialized with the final `try_wait` + latch publication. Retained exited Sessions
    /// can live in the daemon map for a long time; without this seam a late Kill/Shutdown could
    /// signal a recycled pid in the tiny window after waitpid reaped it but before the latch set.
    killer: Arc<Mutex<ChildKillerState>>,
}

struct ChildKillerState {
    killer: Box<dyn ChildKiller + Send + Sync>,
    /// False once waitpid has reaped the child or the wait backend returned an ambiguous hard
    /// error. In either case a cloned numeric-pid killer is no longer safe to invoke.
    signal_safe: bool,
}

impl ChildKillerState {
    fn kill_if_safe(&mut self, already_exited: bool) -> bool {
        if !self.signal_safe || already_exited {
            return false;
        }
        let _ = self.killer.kill();
        true
    }
}

/// Delay between non-blocking child-reap probes after the PTY has closed.
///
/// PTY EOF usually arrives immediately before process exit, so start with a short delay for prompt
/// `SessionExited` delivery. EOF does not *prove* exit, though: a child can close or redirect all
/// of its PTY file descriptors and continue running indefinitely. Capping an exponential backoff
/// keeps that case from polling `waitpid` every 2 ms forever while still leaving `kill_child` free
/// to acquire the lifecycle lock and signal the live child.
const CHILD_REAP_POLL_INITIAL: std::time::Duration = std::time::Duration::from_millis(2);
const CHILD_REAP_POLL_MAX: std::time::Duration = std::time::Duration::from_millis(250);

#[derive(Debug)]
struct ChildReapBackoff {
    next: std::time::Duration,
}

impl ChildReapBackoff {
    fn new() -> Self {
        Self {
            next: CHILD_REAP_POLL_INITIAL,
        }
    }

    fn next_delay(&mut self) -> std::time::Duration {
        let delay = self.next;
        self.next = self.next.saturating_mul(2).min(CHILD_REAP_POLL_MAX);
        delay
    }
}

/// A sane default `PATH` for a spawned shell when the daemon inherited none.
/// Covers Homebrew (Apple Silicon + Intel) and the standard Unix locations so
/// `ls`, `command -v ls`, etc. resolve even from a thin daemon env.
#[cfg(target_os = "macos")]
const DEFAULT_PATH: &str = "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

/// A sane default `PATH` for a spawned shell when the daemon inherited none.
/// Standard FHS locations, matching what a systemd user session would provide.
#[cfg(not(target_os = "macos"))]
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin";

/// Build the environment overrides for a child attached to Hydra's xterm-compatible
/// PTY. TERM describes the emulator on the far side of the PTY, not the process which
/// happened to launch the daemon, so inherited values such as `dumb`, `Apple_Terminal`,
/// or `screen` are not truthful here and must not leak into the child. PATH remains a
/// fallback only; a user's real non-empty PATH is preserved.
fn terminal_env_overrides<G>(get: G) -> Vec<(&'static str, &'static str)>
where
    G: Fn(&str) -> Option<String>,
{
    let missing = |k: &str| get(k).map(|v| v.is_empty()).unwrap_or(true);
    let mut adds = vec![("TERM", "xterm-256color")];
    if missing("PATH") {
        adds.push(("PATH", DEFAULT_PATH));
    }
    adds.push(("COLORTERM", "truecolor"));
    adds
}

/// Variables which explicitly disable color must not leak from the process that
/// launched Hydra into applications running inside its terminal. In particular,
/// Codex sets `NO_COLOR=1` for its own command output; inheriting that value made
/// full-screen programs such as htop monochrome even though the PTY truthfully
/// advertises xterm-256color support.
const TERMINAL_ENV_REMOVALS: &[&str] = &["NO_COLOR"];

impl Session {
    pub fn spawn(
        id: SessionId,
        cwd: &str,
        command: &str,
        args: &[String],
        cols: u16,
        rows: u16,
    ) -> Result<Self> {
        // Normalize ONCE, here at the boundary, so the PTY and the authoritative
        // grid are sized from one identical pair. Previously the PTY got
        // the raw client cols/rows while TermGrid clamped internally — a client
        // asking for 5000 cols opened a 5000-col PTY backing a 2000-col grid, and
        // the two authorities drifted.
        let (cols, rows) = normalize_dims(cols, rows);

        let pty_system = native_pty_system();
        let pair = pty_system.openpty(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        })?;

        let mut cmd = CommandBuilder::new(command);
        cmd.args(args);
        cmd.cwd(cwd);
        // Give the child a sane terminal environment even when the daemon itself
        // was launched from a thin env (launchd, `env -i`, a stripped shell). The
        // base env is inherited from the daemon process; we only fill in the few
        // vars a terminal needs when they are absent or empty. We never overwrite
        // a user-provided non-empty value.
        let env_adds =
            terminal_env_overrides(|k| cmd.get_env(k).and_then(|v| v.to_str()).map(str::to_owned));
        for key in TERMINAL_ENV_REMOVALS {
            cmd.env_remove(key);
        }
        for (k, v) in env_adds {
            cmd.env(k, v);
        }
        // The child must not be killed when its PTY handle drops; the daemon
        // owns lifetime explicitly via Kill. We keep the child (to reap its exit
        // code) and a cloned killer (to terminate it on demand).
        let mut child = pair.slave.spawn_command(cmd)?;
        let killer = Arc::new(Mutex::new(ChildKillerState {
            killer: child.clone_killer(),
            signal_safe: true,
        }));
        drop(pair.slave);

        let writer = Arc::new(Mutex::new(pair.master.take_writer()?));
        let mut reader = pair.master.try_clone_reader()?;

        let scrollback = Arc::new(Mutex::new(VecDeque::with_capacity(SCROLLBACK_CAP)));
        let grid = Arc::new(Mutex::new(TermGrid::new(cols, rows)));
        let (output_tx, _rx) = broadcast::channel::<OutputFrame>(1024);
        let (exit_tx, _exit_rx) = broadcast::channel::<Option<i32>>(8);
        let exited = Arc::new(Mutex::new(None));

        // PTY reader: pump output into the grid (authority) + scrollback ring +
        // broadcast to any attached clients. Runs on a blocking thread (PTY
        // read is blocking). On EOF it reaps the child to learn the exit code
        // and signals exit so forwarders can emit SessionExited.
        {
            let scrollback = scrollback.clone();
            let grid = grid.clone();
            let reply_writer = writer.clone();
            let output_tx = output_tx.clone();
            let exit_tx = exit_tx.clone();
            let exited = exited.clone();
            let killer = killer.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            let chunk = &buf[..n];
                            // Make replay scrollback visible before the corresponding live frame.
                            // A client that reacts to Output by requesting scrollback must never
                            // observe a ring that trails the frame it just received.
                            {
                                let mut sb = scrollback.lock().unwrap();
                                sb.extend(chunk.iter().copied());
                                while sb.len() > SCROLLBACK_CAP {
                                    sb.pop_front();
                                }
                            }
                            // Apply to the grid and read the resulting revision
                            // under one lock, so the (revision, bytes) frame is
                            // consistent with the grid state an attaching client
                            // snapshots. Attach takes the snapshot under the same
                            // lock, giving a precise boundary between "in the
                            // snapshot" and "in the live stream".
                            let replies = {
                                let mut g = grid.lock().unwrap();
                                g.advance(chunk);
                                let revision = g.revision();
                                let (replies, notifications) = g.take_terminal_effects();
                                // Publish while the authoritative grid lock is still held. Attach
                                // subscribes and snapshots under this same lock, so a notification
                                // can never be folded into the snapshot revision before its frame is
                                // published. `broadcast::send` is synchronous and non-blocking.
                                let _ = output_tx.send(OutputFrame {
                                    revision,
                                    bytes: chunk.to_vec(),
                                    notifications,
                                });
                                replies
                            };
                            if !replies.is_empty() {
                                let mut w = reply_writer.lock().unwrap();
                                for reply in replies {
                                    let _ = w.write_all(&reply);
                                }
                                let _ = w.flush();
                            }
                        }
                        Err(_) => break,
                    }
                }
                // PTY closed → the child has exited (or is about to). Reap it for
                // the exit code, latch it for late attachers, then notify any
                // live forwarders. Order matters: set the latch BEFORE the
                // broadcast so a client that attaches in the race window either
                // sees the latch or receives the broadcast — never neither.
                // Reap and publish the latch while holding the same lifecycle lock used by
                // `kill_child`. `try_wait` avoids holding that lock across a blocking wait: a
                // concurrent explicit Kill can still acquire it between polls while the child is
                // alive. Once try_wait reaps the child, the latch is set before the lock is
                // released, so no later caller can signal a recycled numeric pid.
                let mut reap_backoff = ChildReapBackoff::new();
                let code = loop {
                    let mut fallback_error = None;
                    let reaped = {
                        let mut killer_guard = killer.lock().unwrap();
                        match child.try_wait() {
                            Ok(Some(status)) => {
                                let code = Some(status.exit_code() as i32);
                                *exited.lock().unwrap() = Some(code);
                                killer_guard.signal_safe = false;
                                Some(code)
                            }
                            Ok(None) => None,
                            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => None,
                            Err(error) => {
                                // We can no longer prove that the numeric pid still names our child.
                                // Disable future signals before releasing the lifecycle lock. A
                                // blocking wait below may be slow, but Kill/Shutdown can still make
                                // bounded progress (they skip the unsafe signal and time out) rather
                                // than deadlocking behind this lock or signalling an unrelated pid.
                                killer_guard.signal_safe = false;
                                fallback_error = Some(error);
                                None
                            }
                        }
                    };
                    if let Some(code) = reaped {
                        break code;
                    }
                    if let Some(error) = fallback_error {
                        eprintln!(
                            "pty-daemon: child try_wait failed; numeric killer disabled, falling back to wait: {error}"
                        );
                        let code = child.wait().ok().map(|status| status.exit_code() as i32);
                        let mut killer_guard = killer.lock().unwrap();
                        *exited.lock().unwrap() = Some(code);
                        killer_guard.signal_safe = false;
                        break code;
                    }
                    std::thread::sleep(reap_backoff.next_delay());
                };
                let _ = exit_tx.send(code);
            });
        }

        Ok(Session {
            id,
            cwd: cwd.to_string(),
            subscriptions: Vec::new(),
            master: Arc::new(Mutex::new(pair.master)),
            writer,
            scrollback,
            grid,
            output_tx,
            exit_tx,
            exited,
            killer,
        })
    }

    /// Raw recent output bytes. Unused on every live path: attach restores from the
    /// authoritative grid (raw bytes can begin mid-escape / mid-utf8 and corrupt the
    /// restore), and *structured* scrollback reads historical rows straight from
    /// the grid via `scrollback()` below — not from this byte ring. Kept only as a raw
    /// debugging tap; hence `dead_code`.
    #[allow(dead_code)]
    pub fn scrollback_snapshot(&self) -> Vec<u8> {
        let sb = self.scrollback.lock().unwrap();
        sb.iter().copied().collect()
    }

    /// Authoritative grid snapshot: the rendered screen the daemon holds. A
    /// renderer paints this directly rather than re-parsing the byte stream.
    pub fn grid_snapshot(&self) -> GridSnapshot {
        self.grid.lock().unwrap().snapshot()
    }

    /// Lightweight generation metadata for `ListSessions`. This avoids cloning the full grid while
    /// giving reconciliation enough identity to distinguish a new same-id lifetime from an ended
    /// one.
    pub fn generation(&self) -> String {
        self.grid.lock().unwrap().generation().to_string()
    }

    /// Return generation metadata only when this session is still live at the end of the read.
    /// Read generation first and the exit latch second: if the reader publishes exit while we are
    /// reading the grid, the final latch check excludes the session. An exit after this method
    /// returns simply means the read-only live snapshot was truthful at its observation boundary
    /// and the next reconciliation pass will observe the later exit.
    pub fn live_generation(&self) -> Option<String> {
        let generation = self.generation();
        self.exit_state().is_none().then_some(generation)
    }

    /// Read-only scrollback window: structured historical rows above the live
    /// screen. Does not touch the live grid's `display_offset`.
    pub fn scrollback(&self, offset_from_top: u32, count: u16) -> ScrollbackRead {
        self.grid.lock().unwrap().scrollback(offset_from_top, count)
    }

    /// A cloneable handle the forwarder keeps to re-baseline on lag.
    pub fn grid_handle(&self) -> GridHandle {
        GridHandle {
            grid: self.grid.clone(),
            exited: self.exited.clone(),
        }
    }

    /// Atomically subscribe to live output and lifecycle, snapshot the grid, and
    /// inspect the persisted exit latch at the same revision boundary. All happen
    /// while we hold the grid lock; the reader thread takes that same lock to
    /// advance the grid and publish the revision-stamped frame. So the snapshot's
    /// revision and every frame's revision are drawn from one lock-serialized
    /// counter. Result:
    /// - no frame is lost: `subscribe` runs before we release the lock, so any
    ///   frame the reader sends afterward reaches this receiver, and
    /// - no frame is double-counted: a frame already folded into the snapshot
    ///   carries `frame.revision <= snapshot.revision`, so the forwarder drops it.
    ///
    /// - an already-exited latch implies the snapshot is final, because exit is
    ///   latched only after the reader has published every frame, and
    /// - a still-live latch is paired with an exit subscription created before it
    ///   was inspected, so a later exit cannot be missed.
    ///
    /// This replaces the old split `attach_state` / `subscribe_exit` / `exit_state`
    /// dance, whose gaps could pair a stale snapshot with an already-exited latch.
    pub fn attach_state(&self) -> AttachState {
        let g = self.grid.lock().unwrap();
        let output_rx = self.output_tx.subscribe();
        let exit_rx = self.exit_tx.subscribe();
        let snapshot = g.snapshot();
        let already_exited = *self.exited.lock().unwrap();
        AttachState {
            snapshot,
            output_rx,
            exit_rx,
            already_exited,
        }
    }

    /// Persisted exit state for late attachers: `None` while running, otherwise
    /// `Some(code)` where `code` is the child's exit code (or `None` if unknown).
    /// Read under the same latch the reader thread writes before broadcasting, so
    /// an attacher that takes it before subscribing can rely on: latch-set ⇒ the
    /// session has exited; latch-clear ⇒ a later broadcast still reaches it.
    pub fn exit_state(&self) -> Option<Option<i32>> {
        *self.exited.lock().unwrap()
    }

    /// Terminate the child process. The reader thread will then hit EOF, reap
    /// the exit code, and fire the exit signal.
    pub fn kill_child(&self) {
        let mut lifecycle = self.killer.lock().unwrap();
        let already_exited = self.exited.lock().unwrap().is_some();
        lifecycle.kill_if_safe(already_exited);
    }

    /// Kill the child and block until the reader thread has reaped it, so no
    /// zombie is left behind. "Reaped" is observable: the reader thread sets the
    /// `exited` latch ONLY after `child.wait()` returns, so a set latch proves the
    /// kernel process-table entry was collected. Bounded by `timeout`; returns
    /// `true` if the child was confirmed reaped, `false` if it didn't within the
    /// budget (so a caller draining many sessions doesn't hang on one stuck child).
    ///
    /// Used by the daemon shutdown path to terminate owned children
    /// deterministically rather than orphaning them when the daemon exits.
    pub fn kill_and_wait(&self, timeout: std::time::Duration) -> bool {
        self.kill_child();
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if self.exit_state().is_some() {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
    }

    /// A cheap cloneable handle for the blocking PTY write/resize surface.
    /// The request handlers clone this out from under the daemon lock, release
    /// the lock, then do the IO — so a wedged PTY can't block unrelated sessions.
    pub fn pty_handle(&self) -> PtyHandle {
        PtyHandle {
            writer: self.writer.clone(),
            master: self.master.clone(),
            grid: self.grid.clone(),
        }
    }
}

#[cfg(test)]
mod child_killer_lifecycle_tests {
    use super::{ChildKillerState, ChildReapBackoff, CHILD_REAP_POLL_INITIAL, CHILD_REAP_POLL_MAX};
    use portable_pty::ChildKiller;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[derive(Debug)]
    struct CountingKiller(Arc<AtomicUsize>);

    impl ChildKiller for CountingKiller {
        fn kill(&mut self) -> std::io::Result<()> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn clone_killer(&self) -> Box<dyn ChildKiller + Send + Sync> {
            Box::new(Self(self.0.clone()))
        }
    }

    #[test]
    fn latched_or_reap_uncertain_child_is_never_signalled() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut lifecycle = ChildKillerState {
            killer: Box::new(CountingKiller(calls.clone())),
            signal_safe: true,
        };

        assert!(!lifecycle.kill_if_safe(true), "latched exit skips kill");
        lifecycle.signal_safe = false;
        assert!(
            !lifecycle.kill_if_safe(false),
            "reaped/ambiguous pid skips kill"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn live_owned_child_is_signalled_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut lifecycle = ChildKillerState {
            killer: Box::new(CountingKiller(calls.clone())),
            signal_safe: true,
        };

        assert!(lifecycle.kill_if_safe(false));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn eof_reap_polling_backs_off_from_prompt_probe_to_idle_cap() {
        let mut backoff = ChildReapBackoff::new();
        let delays: Vec<_> = (0..10).map(|_| backoff.next_delay()).collect();

        assert_eq!(
            delays,
            [2, 4, 8, 16, 32, 64, 128, 250, 250, 250].map(Duration::from_millis)
        );
        assert_eq!(delays[0], CHILD_REAP_POLL_INITIAL);
        assert_eq!(*delays.last().unwrap(), CHILD_REAP_POLL_MAX);
    }

    /// Deterministic proxy for the idle-CPU regression: a PTY-closed child that stays alive for a
    /// minute used to cause about 30,000 `try_wait` calls. The capped schedule permits at most 250
    /// probes without relying on wall-clock timing or a noisy process-wide CPU measurement.
    #[test]
    fn pty_closed_live_child_has_a_bounded_idle_reap_probe_budget() {
        let mut backoff = ChildReapBackoff::new();
        let mut elapsed = Duration::ZERO;
        let mut probes = 0;

        while elapsed < Duration::from_secs(60) {
            elapsed += backoff.next_delay();
            probes += 1;
        }

        assert!(
            probes <= 250,
            "one idle minute must not exceed 250 reap probes; got {probes}"
        );
        assert_eq!(backoff.next_delay(), CHILD_REAP_POLL_MAX);
    }
}

#[cfg(test)]
mod env_baseline_tests {
    use super::{terminal_env_overrides, DEFAULT_PATH, TERMINAL_ENV_REMOVALS};
    use std::collections::HashMap;

    /// Seed a fake env with `initial`, compute the baseline additions, apply them
    /// on top, and return the resulting map — mirroring what `spawn` does to the
    /// CommandBuilder.
    fn run(initial: &[(&str, &str)]) -> HashMap<String, String> {
        let base: HashMap<String, String> = initial
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let mut out = base.clone();
        for key in TERMINAL_ENV_REMOVALS {
            out.remove(*key);
        }
        for (k, v) in terminal_env_overrides(|k| base.get(k).cloned()) {
            out.insert(k.to_string(), v.to_string());
        }
        out
    }

    #[test]
    fn fills_all_when_env_is_empty() {
        let env = run(&[]);
        assert_eq!(env.get("TERM").unwrap(), "xterm-256color");
        assert_eq!(env.get("PATH").unwrap(), DEFAULT_PATH);
        assert_eq!(env.get("COLORTERM").unwrap(), "truecolor");
    }

    #[test]
    fn terminal_identity_is_canonical_but_path_is_preserved() {
        let env = run(&[
            ("TERM", "screen-256color"),
            ("PATH", "/custom/bin"),
            ("COLORTERM", "24bit"),
        ]);
        assert_eq!(env.get("TERM").unwrap(), "xterm-256color");
        assert_eq!(env.get("PATH").unwrap(), "/custom/bin");
        assert_eq!(env.get("COLORTERM").unwrap(), "truecolor");
    }

    #[test]
    fn repairs_incapable_nonempty_term() {
        let env = run(&[("TERM", "dumb"), ("COLORTERM", "0")]);
        assert_eq!(env.get("TERM").unwrap(), "xterm-256color");
        assert_eq!(env.get("COLORTERM").unwrap(), "truecolor");
    }

    #[test]
    fn treats_empty_string_as_missing() {
        let env = run(&[("TERM", ""), ("PATH", ""), ("COLORTERM", "")]);
        assert_eq!(env.get("TERM").unwrap(), "xterm-256color");
        assert_eq!(env.get("PATH").unwrap(), DEFAULT_PATH);
        assert_eq!(env.get("COLORTERM").unwrap(), "truecolor");
    }

    #[test]
    fn fills_only_the_missing_one() {
        let env = run(&[("PATH", "/opt/mybin")]);
        assert_eq!(env.get("PATH").unwrap(), "/opt/mybin");
        assert_eq!(env.get("TERM").unwrap(), "xterm-256color");
        assert_eq!(env.get("COLORTERM").unwrap(), "truecolor");
    }

    #[test]
    fn removes_inherited_no_color_opt_out() {
        let env = run(&[("NO_COLOR", "1"), ("PATH", "/opt/mybin")]);
        assert!(!env.contains_key("NO_COLOR"));
        assert_eq!(env.get("TERM").unwrap(), "xterm-256color");
        assert_eq!(env.get("COLORTERM").unwrap(), "truecolor");
    }
}
