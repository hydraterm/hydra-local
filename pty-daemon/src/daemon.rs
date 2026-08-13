//! The Daemon owns every Session and Channel. It is the single authority for
//! process lifetime (tier-(a) persistence) and the routing point between PTY
//! output and channels. A UI client attaches over a socket; the daemon outlives
//! the client.

use crate::channel::Channel;
use crate::ids::{ChannelId, SessionId};
use crate::protocol::{now_millis, ChannelEvent, ChannelEventKind, SessionInfo};
use crate::session::Session;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Ceiling on concurrently live sessions. Each session is a child process plus
/// a VT grid (~`cols * (rows + history)` cells); an unbounded client could
/// exhaust process/file-descriptor/memory limits by spawning without end. A
/// reattach to an existing id never counts against this (it's a no-op).
const MAX_SESSIONS: usize = 64;
/// Channels retain replay and broadcast state, so they require an independent
/// ceiling rather than inheriting the session limit accidentally.
const MAX_CHANNELS: usize = 64;
const MAX_CHANNEL_ID_BYTES: usize = 512;

#[derive(Default)]
pub struct Daemon {
    sessions: HashMap<SessionId, Session>,
    channels: HashMap<ChannelId, Channel>,
}

/// Outcome of `Daemon::shutdown`: how many owned children were confirmed reaped
/// before state was cleared, and the ids of any that did NOT confirm within the
/// per-child timeout. `all_reaped()` is the clean-exit predicate; a non-empty
/// `unconfirmed` is a degraded shutdown the caller can log or exit non-zero on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShutdownReport {
    /// Sessions that existed when shutdown began.
    pub total: usize,
    /// Children whose reaping was confirmed via the exit latch within the budget.
    pub reaped: usize,
    /// Ids of children that did not confirm reaped before the timeout. Their
    /// sessions were still dropped (PTYs closed); they just weren't confirmed.
    pub unconfirmed: Vec<SessionId>,
}

impl ShutdownReport {
    /// True when every child that existed at shutdown confirmed it was reaped.
    pub fn all_reaped(&self) -> bool {
        self.unconfirmed.is_empty()
    }
}

pub type SharedDaemon = Arc<Mutex<Daemon>>;

impl Daemon {
    pub fn shared() -> SharedDaemon {
        Arc::new(Mutex::new(Daemon::default()))
    }

    #[expect(
        dead_code,
        reason = "used by channel fan-out path once wired (channels commit)"
    )]
    pub fn has_session(&self, id: &SessionId) -> bool {
        self.sessions.contains_key(id)
    }

    pub fn start_session(
        &mut self,
        id: SessionId,
        cwd: &str,
        command: &str,
        args: &[String],
        cols: u16,
        rows: u16,
    ) -> Result<()> {
        self.start_session_with_environment(id, cwd, command, args, None, cols, rows)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn start_session_with_environment(
        &mut self,
        id: SessionId,
        cwd: &str,
        command: &str,
        args: &[String],
        child_environment: Option<&maestro_protocol::ChildEnvironment>,
        cols: u16,
        rows: u16,
    ) -> Result<()> {
        self.start_session_with_restart_and_environment(
            id,
            cwd,
            command,
            args,
            child_environment,
            cols,
            rows,
            false,
        )
    }

    /// Start a genuinely new id, reattach to a live same-id session, or (only with explicit
    /// authority) replace an exited retained same-id session. Ordinary focus/startup callers use
    /// [`start_session`](Self::start_session), whose safe default preserves an exited final grid.
    #[allow(clippy::too_many_arguments)]
    pub fn start_session_with_restart(
        &mut self,
        id: SessionId,
        cwd: &str,
        command: &str,
        args: &[String],
        cols: u16,
        rows: u16,
        restart_exited: bool,
    ) -> Result<()> {
        self.start_session_with_restart_and_environment(
            id,
            cwd,
            command,
            args,
            None,
            cols,
            rows,
            restart_exited,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn start_session_with_restart_and_environment(
        &mut self,
        id: SessionId,
        cwd: &str,
        command: &str,
        args: &[String],
        child_environment: Option<&maestro_protocol::ChildEnvironment>,
        cols: u16,
        rows: u16,
        restart_exited: bool,
    ) -> Result<()> {
        // Reattach semantics: a live same-id session is never respawned. An exited same-id entry is
        // replaced only by an explicit restart request; an ordinary StartSession preserves its
        // final grid, scrollback, and exit latch even if the durable status update is still racing.
        // When restart is explicit, the old entry remains installed until replacement spawn
        // succeeds, so invalid cwd/argv/exec never destroys the retained terminal.
        let replacing_exited_same_id = match self.sessions.get(&id) {
            Some(existing) if existing.exit_state().is_none() => return Ok(()),
            Some(_) if !restart_exited => {
                return Err(anyhow!(
                    "session {id} has exited and is retained; explicit restart authority is required"
                ));
            }
            Some(_) => true,
            None => false,
        };
        // Validate client-supplied spawn inputs at this trust boundary. An empty
        // command would spawn nothing useful; a command carrying a NUL can't be
        // passed to execvp and would surface as an opaque OS error. cwd, if set,
        // must be a real directory — otherwise the spawn fails deep inside
        // portable-pty with a confusing message instead of a clear one here.
        if command.is_empty() {
            return Err(anyhow!("command must not be empty"));
        }
        if command.contains('\0') || args.iter().any(|a| a.contains('\0')) {
            return Err(anyhow!("command and args must not contain NUL bytes"));
        }
        validate_child_environment(child_environment)?;
        if !cwd.is_empty() && !std::path::Path::new(cwd).is_dir() {
            return Err(anyhow!("cwd is not a directory: {cwd}"));
        }
        // Reject a grid whose worst-case JSON snapshot could not cross the socket as a
        // single newline-delimited line (`MAX_LINE_BYTES`). A direct protocol request
        // gets an explicit error (the native UI computes a compliant size before
        // sending; a misbehaving direct client learns its request is out of bounds
        // rather than silently getting a clamped grid). Checked on the SAME normalized
        // dims spawn will use, so the accepted grid is always wire-shippable.
        let (n_cols, n_rows) = crate::grid::normalize_dims(cols, rows);
        if !crate::grid::fits_snapshot_budget(n_cols, n_rows) {
            return Err(anyhow!(
                "grid {n_cols}x{n_rows} exceeds the snapshot cell budget ({} cells); \
                 request a smaller size",
                crate::grid::MAX_SNAPSHOT_CELLS
            ));
        }

        // A same-id replacement does not consume another map slot. A genuinely new id at capacity
        // may use one retained exited snapshot's slot, but never evict that snapshot before spawn:
        // if spawn fails, every retained terminal remains untouched.
        let needs_capacity_eviction =
            !replacing_exited_same_id && self.sessions.len() >= MAX_SESSIONS;
        if needs_capacity_eviction
            && !self
                .sessions
                .values()
                .any(|session| session.exit_state().is_some())
        {
            return Err(anyhow!(
                "session limit reached ({MAX_SESSIONS}); kill a session before starting another"
            ));
        }

        let session = Session::spawn(
            id.clone(),
            cwd,
            command,
            args,
            child_environment,
            cols,
            rows,
        )?;

        if needs_capacity_eviction {
            // The preflight above proved at least one candidate while the daemon mutex was held.
            // Reader threads may only add more exit latches; they cannot remove map entries. Evict
            // exactly one snapshot (the one slot required), preserving all other final output.
            let exited_id = self
                .sessions
                .iter()
                .find_map(|(candidate_id, candidate)| {
                    candidate
                        .exit_state()
                        .is_some()
                        .then(|| candidate_id.clone())
                })
                .expect("capacity eviction candidate remains installed under daemon lock");
            self.sessions.remove(&exited_id);
        }

        // HashMap::insert drops the old exited same-id Session only now, after the replacement PTY
        // exists. A live same-id entry returned above and can never reach this point.
        self.sessions.insert(id, session);
        Ok(())
    }

    pub fn session(&self, id: &SessionId) -> Result<&Session> {
        self.sessions
            .get(id)
            .ok_or_else(|| anyhow!("no such session: {id}"))
    }

    pub fn kill_session(&mut self, id: &SessionId) {
        // Terminate the child explicitly first — dropping the Session closes the
        // PTY, but a child sitting in its own read loop may not exit on PTY
        // close alone. kill_child guarantees it goes away.
        if let Some(s) = self.sessions.get(id) {
            s.kill_child();
        }
        self.sessions.remove(id);
    }

    #[cfg(test)]
    pub fn session_ids(&self) -> Vec<SessionId> {
        self.sessions
            .iter()
            .filter(|(_, session)| session.exit_state().is_none())
            .map(|(id, _)| id.clone())
            .collect()
    }

    pub fn session_infos(&self) -> Vec<SessionInfo> {
        self.sessions
            .values()
            .filter_map(|s| {
                s.live_generation().map(|generation| SessionInfo {
                    id: s.id.clone(),
                    cwd: if s.cwd.is_empty() {
                        None
                    } else {
                        Some(s.cwd.clone())
                    },
                    generation: Some(generation),
                })
            })
            .collect()
    }

    /// Drop every session whose child has already exited, returning its slot to
    /// the MAX_SESSIONS budget. A naturally-ended session (user typed `exit`,
    /// agent finished) is never killed by anyone, so without an explicit reap it
    /// would occupy capacity forever. Dropping the Session here closes its PTY
    /// and frees its grid/scrollback buffers.
    #[cfg(test)]
    pub fn reap_exited_sessions(&mut self) {
        self.sessions.retain(|_, s| s.exit_state().is_none());
    }

    /// Terminate and reap every owned child, then drop all sessions. Without
    /// this, daemon exit just drops the session map: the PTY masters close, but a
    /// child sitting in its own loop may linger as an orphan/zombie rather than
    /// being collected. `shutdown` kills each child and waits for the reader
    /// thread to `wait()` it (observable via the exit latch). Per-child wait is
    /// bounded so one stuck child can't wedge the whole shutdown.
    ///
    /// Returns a `ShutdownReport` recording how many children confirmed reaped vs.
    /// timed out, so the caller can distinguish a clean shutdown from a degraded
    /// one (and log/exit accordingly) rather than silently assuming every child
    /// was collected. State is cleared regardless — a child that didn't confirm
    /// is still dropped (its PTY closes); we just report that it was unconfirmed
    /// instead of overstating "all reaped".
    pub fn shutdown(&mut self) -> ShutdownReport {
        const PER_CHILD_REAP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
        self.shutdown_with_timeout(PER_CHILD_REAP_TIMEOUT)
    }

    /// `shutdown` with an explicit per-child reap budget. Split out so a test can
    /// force the timeout branch deterministically (a `Duration::ZERO` budget makes
    /// every still-running child report unconfirmed) without waiting on a real
    /// stuck child.
    fn shutdown_with_timeout(&mut self, per_child: std::time::Duration) -> ShutdownReport {
        let total = self.sessions.len();
        let mut reaped = 0usize;
        let mut unconfirmed: Vec<SessionId> = Vec::new();
        for (id, session) in self.sessions.iter() {
            if session.kill_and_wait(per_child) {
                reaped += 1;
            } else {
                unconfirmed.push(id.clone());
            }
        }
        self.sessions.clear();
        self.channels.clear();
        ShutdownReport {
            total,
            reaped,
            unconfirmed,
        }
    }

    pub fn open_channel(&mut self, id: ChannelId) -> Result<()> {
        if id.0.is_empty()
            || id.0.len() > MAX_CHANNEL_ID_BYTES
            || id.0.chars().any(char::is_control)
        {
            return Err(anyhow!(
                "channel id must be non-empty, control-free, and at most {MAX_CHANNEL_ID_BYTES} bytes"
            ));
        }
        if self.channels.contains_key(&id) {
            return Ok(());
        }
        if self.channels.len() >= MAX_CHANNELS {
            return Err(anyhow!(
                "channel limit reached ({MAX_CHANNELS}); reuse or close a channel before opening another"
            ));
        }
        self.channels.insert(id.clone(), Channel::new(id));
        Ok(())
    }

    pub fn join_channel(&mut self, channel: &ChannelId, session: &SessionId) -> Result<()> {
        if !self.sessions.contains_key(session) {
            return Err(anyhow!("no such session: {session}"));
        }
        let ch = self
            .channels
            .get_mut(channel)
            .ok_or_else(|| anyhow!("no such channel: {channel}"))?;
        ch.join(session.clone());
        if let Some(s) = self.sessions.get_mut(session) {
            if !s.subscriptions.contains(channel) {
                s.subscriptions.push(channel.clone());
            }
        }
        Ok(())
    }

    pub fn publish(&mut self, event: ChannelEvent) -> Result<()> {
        let ch = self
            .channels
            .get_mut(&event.channel)
            .ok_or_else(|| anyhow!("no such channel: {}", event.channel))?;
        let sender = event
            .from
            .as_ref()
            .ok_or_else(|| anyhow!("channel publish requires a sender session"))?;
        if !self.sessions.contains_key(sender) {
            return Err(anyhow!("no such sender session: {sender}"));
        }
        if !ch.members.contains(sender) {
            return Err(anyhow!(
                "sender session {sender} is not a member of channel {}",
                event.channel
            ));
        }
        ch.publish(event)
    }

    /// Helper: fan a session's raw output onto every channel it belongs to as an
    /// Output event. Takes `&[u8]` — the PTY emits raw bytes, and a chunk boundary can
    /// split a multibyte grapheme, so the fan-out surface must NOT be `&str` (that would
    /// re-introduce the UTF-8-split corruption the rest of the daemon avoids).
    ///
    /// The wire event still carries `text: String`; the lossy conversion here is the
    /// ONE remaining boundary defect. Before this can be wired into the per-session pump,
    /// `ChannelEventKind::Output { text }` must become a raw-byte field so split graphemes
    /// survive end to end. Until then this helper is dead code and the lossy step is
    /// explicitly flagged rather than hidden behind a `&str` signature.
    #[expect(dead_code, reason = "reserved for raw-byte channel fan-out")]
    pub fn fan_output_to_channels(&mut self, id: &SessionId, bytes: &[u8]) {
        let subs = match self.sessions.get(id) {
            Some(s) => s.subscriptions.clone(),
            None => return,
        };
        // BOUNDARY DEFECT (see doc comment): lossy until the channel wire event carries
        // base64 raw bytes. Kept lossy-not-panicking so a split grapheme never aborts.
        let text = String::from_utf8_lossy(bytes).into_owned();
        for channel in subs {
            if let Some(ch) = self.channels.get_mut(&channel) {
                let _ = ch.publish(ChannelEvent {
                    channel: channel.clone(),
                    from: Some(id.clone()),
                    kind: ChannelEventKind::Output { text: text.clone() },
                    ts: now_millis(),
                });
            }
        }
    }
}

fn validate_child_environment(
    environment: Option<&maestro_protocol::ChildEnvironment>,
) -> Result<()> {
    let Some(environment) = environment else {
        return Ok(());
    };
    let home = std::path::Path::new(&environment.home);
    let shell = std::path::Path::new(&environment.shell);
    let normalized_absolute = |path: &std::path::Path| {
        path.is_absolute()
            && path.components().all(|component| {
                matches!(
                    component,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
    };
    if environment.home.is_empty()
        || environment.shell.is_empty()
        || environment.home.len() > 4096
        || environment.shell.len() > 4096
        || environment.home.contains(['\0', '\n', '\r'])
        || environment.shell.contains(['\0', '\n', '\r'])
        || !normalized_absolute(home)
        || !normalized_absolute(shell)
        || home == std::path::Path::new("/")
        || !home.is_dir()
    {
        return Err(anyhow!("headless child environment is invalid"));
    }
    let metadata =
        std::fs::metadata(shell).map_err(|_| anyhow!("headless child environment is invalid"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if !metadata.is_file()
            || metadata.permissions().mode() & 0o111 == 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err(anyhow!("headless child environment is invalid"));
        }
    }
    #[cfg(not(unix))]
    if !metadata.is_file() {
        return Err(anyhow!("headless child environment is invalid"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn sid(s: &str) -> SessionId {
        SessionId(s.to_string())
    }

    /// Spin until the session's child has exited (or we time out). Spawning a
    /// child + reaching EOF on its PTY is inherently async, so we poll the
    /// persisted exit_state rather than sleeping a fixed amount.
    fn wait_for_exit(d: &Daemon, id: &SessionId) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Some(s) = d.sessions.get(id) {
                if s.exit_state().is_some() {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("session {id} did not record an exit within the timeout");
    }

    /// An in-flight PTY write for one session must NOT hold
    /// the global daemon lock, so unrelated requests stay responsive.
    ///
    /// We can't reproduce a truly blocked PTY write on macOS (portable-pty
    /// buffers the master write so it never blocks even at 80 MB), so we prove
    /// the locking discipline directly: a worker thread holds the per-session
    /// `writer` lock (exactly what the real `PtyHandle::write_input` holds for
    /// the duration of the syscall), and meanwhile the daemon lock must remain
    /// acquirable. Keeping the writer inside `Session` *behind the daemon lock*
    /// would let a blocking write freeze every other request; this test would
    /// hang on that design.
    #[test]
    fn in_flight_write_does_not_hold_daemon_lock() {
        let shared = Daemon::shared();
        // Borrow a tiny current-thread runtime to drive the async daemon Mutex,
        // matching how the real request handlers `.lock().await`.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        // Spawn a long-lived session and grab its PTY write handle.
        let handle = rt.block_on(async {
            let mut d = shared.lock().await;
            d.start_session(sid("writer"), ".", "sleep", &["30".to_string()], 80, 24)
                .expect("spawn session");
            d.session(&sid("writer")).unwrap().pty_handle()
        });

        // Simulate an in-progress blocking write: hold the writer lock on a
        // worker thread for a full second. A barrier makes sure the main thread
        // only probes once the lock is actually held.
        let writer_lock = handle.writer_lock_for_test();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let b2 = barrier.clone();
        let writer = std::thread::spawn(move || {
            let _guard = writer_lock.lock().unwrap();
            b2.wait();
            std::thread::sleep(Duration::from_secs(1));
        });
        barrier.wait();

        // While the "write" is in flight, an unrelated request (ListSessions →
        // session_ids) must acquire the daemon lock and return promptly. If the
        // daemon lock were held across the write, this would block ~1s.
        let started = Instant::now();
        let ids = rt.block_on(async {
            let d = shared.lock().await;
            d.session_ids()
        });
        let elapsed = started.elapsed();

        assert!(
            ids.contains(&sid("writer")),
            "the session should be listed: {ids:?}"
        );
        assert!(
            elapsed < Duration::from_millis(300),
            "acquiring the daemon lock took {elapsed:?} while a write was in flight — \
             the daemon lock is being held across PTY IO"
        );

        writer.join().unwrap();
        rt.block_on(async { shared.lock().await.kill_session(&sid("writer")) });
    }

    #[test]
    fn exited_session_releases_capacity() {
        let mut d = Daemon::default();

        // A child that exits on its own the instant it starts. Nobody calls
        // kill_session for it, so only the reap path can reclaim its slot.
        d.start_session(sid("ephemeral"), ".", "true", &[], 80, 24)
            .expect("spawn the short-lived session");
        assert_eq!(d.sessions.len(), 1, "session is in the map while/after run");

        wait_for_exit(&d, &sid("ephemeral"));

        // Starting another session below capacity preserves the final snapshot for inspection.
        d.start_session(sid("live"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn the long-lived session");
        assert!(
            d.sessions.contains_key(&sid("ephemeral")),
            "an unrelated start must preserve retained final output below capacity"
        );

        // The explicit reap path still releases capacity and keeps live children.
        d.reap_exited_sessions();

        assert!(
            !d.sessions.contains_key(&sid("ephemeral")),
            "the exited session must be reaped, freeing its capacity slot"
        );
        assert!(
            d.sessions.contains_key(&sid("live")),
            "the still-running session must survive the reap"
        );

        d.kill_session(&sid("live"));
    }

    #[test]
    fn exit_latched_session_is_not_listed_live_but_remains_late_attachable() {
        let mut d = Daemon::default();
        let id = sid("latched-exit");
        d.start_session(id.clone(), ".", "true", &[], 80, 24)
            .expect("spawn the short-lived session");
        wait_for_exit(&d, &id);

        assert!(
            !d.session_ids().contains(&id),
            "ListSessions ids must exclude an exit-latched process"
        );
        assert!(
            d.session_infos().iter().all(|info| info.id != id),
            "ListSessions metadata must use the same live-only predicate"
        );

        // Filtering is deliberately non-destructive. Attach still finds the Session, can send its
        // authoritative restore Grid, and then uses this persisted latch to replay SessionExited to
        // a client that subscribed after the one-shot broadcast. The full wire ordering remains
        // covered by tests/resync_and_late_attach.rs.
        let retained = d.session(&id).expect("latched Session remains in the map");
        let attach = retained.attach_state();
        assert_eq!(attach.snapshot.rows, 24);
        assert!(
            retained.exit_state().is_some(),
            "late attach observes the exit latch"
        );
        assert!(
            d.sessions.contains_key(&id),
            "live-list filtering must not reap/remove retained late-attach state"
        );
    }

    #[test]
    fn live_same_id_start_is_noop() {
        let mut d = Daemon::default();

        // A long-lived child. A second StartSession with the same id is a
        // reattach (the UI reconnected) and must NOT respawn it.
        d.start_session(sid("agent"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn the long-lived session");
        assert!(
            d.sessions
                .get(&sid("agent"))
                .expect("session present")
                .exit_state()
                .is_none(),
            "freshly spawned session must be alive"
        );

        // Reattach: same id, still alive. Returns Ok, leaves the live session
        // untouched (no respawn), and never grows the map.
        d.start_session(sid("agent"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("reattach to a live session is Ok");
        assert_eq!(d.sessions.len(), 1, "reattach must not add a session");
        assert!(
            d.sessions
                .get(&sid("agent"))
                .expect("live session still present")
                .exit_state()
                .is_none(),
            "the live session must survive the reattach unchanged"
        );

        d.kill_session(&sid("agent"));
    }

    #[test]
    fn exited_same_id_start_is_an_explicit_new_generation() {
        let mut d = Daemon::default();
        let id = sid("restart-ended");
        d.start_session(id.clone(), ".", "true", &[], 80, 24)
            .expect("spawn short-lived session");
        wait_for_exit(&d, &id);
        let ended_generation = d
            .session(&id)
            .expect("retained ended session")
            .attach_state()
            .snapshot
            .generation;

        d.start_session_with_restart(id.clone(), ".", "sleep", &["30".to_string()], 80, 24, true)
            .expect("same-id start explicitly restarts an ended session");

        let restarted = d.session(&id).expect("new session generation");
        assert!(restarted.exit_state().is_none());
        assert_ne!(
            restarted.attach_state().snapshot.generation,
            ended_generation,
            "restart must not reuse the ended generation"
        );
        d.kill_session(&id);
    }

    #[test]
    fn failed_same_id_restart_preserves_the_retained_final_snapshot() {
        let mut d = Daemon::default();
        let id = sid("restart-failure-retains-final-output");
        d.start_session(id.clone(), ".", "true", &[], 80, 24)
            .expect("spawn short-lived session");
        wait_for_exit(&d, &id);
        let ended_generation = d
            .session(&id)
            .expect("retained ended session")
            .attach_state()
            .snapshot
            .generation;

        let error = d
            .start_session_with_restart(
                id.clone(),
                ".",
                "/definitely/not/a/hydra/executable",
                &[],
                80,
                24,
                true,
            )
            .expect_err("replacement spawn must fail");
        assert!(!error.to_string().is_empty());

        let retained = d
            .session(&id)
            .expect("old snapshot survives failed restart");
        assert!(retained.exit_state().is_some());
        assert_eq!(
            retained.attach_state().snapshot.generation,
            ended_generation,
            "failed replacement must not discard or replace the ended generation"
        );
    }

    #[test]
    fn invalid_child_environment_is_rejected_before_exited_snapshot_replacement() {
        let mut daemon = Daemon::default();
        let id = sid("invalid-child-environment-retains-snapshot");
        daemon
            .start_session(id.clone(), ".", "true", &[], 80, 24)
            .expect("spawn short-lived session");
        wait_for_exit(&daemon, &id);
        let ended_generation = daemon
            .session(&id)
            .expect("retained ended session")
            .attach_state()
            .snapshot
            .generation;
        let environment = maestro_protocol::ChildEnvironment {
            home: "/definitely/not/a/hydra/home".into(),
            shell: "/bin/sh".into(),
        };

        let error = daemon
            .start_session_with_restart_and_environment(
                id.clone(),
                ".",
                "/bin/sh",
                &[],
                Some(&environment),
                80,
                24,
                true,
            )
            .expect_err("invalid typed environment must fail before spawn");
        assert_eq!(error.to_string(), "headless child environment is invalid");
        let retained = daemon.session(&id).expect("old snapshot remains installed");
        assert!(retained.exit_state().is_some());
        assert_eq!(
            retained.attach_state().snapshot.generation,
            ended_generation,
            "validation failure must not evict the retained final grid"
        );
    }

    /// Targeted: killed session reaps its child without leaving a zombie. The
    /// reader thread sets the exit latch ONLY after `child.wait()` returns, so a
    /// set latch proves the kernel process-table entry was collected (no zombie).
    /// `kill_and_wait` blocks until that latch is set.
    #[test]
    fn killed_session_reaps_child_without_zombie() {
        let mut d = Daemon::default();
        d.start_session(sid("victim"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn a long-lived session");
        assert!(
            d.sessions
                .get(&sid("victim"))
                .unwrap()
                .exit_state()
                .is_none(),
            "precondition: the child is alive (not yet reaped)"
        );

        // Kill and confirm the reader thread reaped it (latch set) within budget.
        let reaped = d
            .sessions
            .get(&sid("victim"))
            .unwrap()
            .kill_and_wait(Duration::from_secs(5));
        assert!(
            reaped,
            "the killed child must be reaped (exit latch set) — a zombie would leave it None"
        );
        assert!(
            d.sessions
                .get(&sid("victim"))
                .unwrap()
                .exit_state()
                .is_some(),
            "exit_state must be Some after the child is reaped"
        );

        d.kill_session(&sid("victim"));
    }

    /// Targeted: a killed session is removed from MAX_SESSIONS capacity
    /// accounting. (Companion to `exited_session_releases_capacity`, which covers
    /// the natural-exit path; this covers the explicit-kill path.)
    #[test]
    fn killed_session_releases_capacity() {
        let mut d = Daemon::default();
        d.start_session(sid("k"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn");
        assert_eq!(d.sessions.len(), 1);

        d.kill_session(&sid("k"));
        assert_eq!(
            d.sessions.len(),
            0,
            "kill_session must drop the session, freeing its capacity slot"
        );
        assert!(!d.sessions.contains_key(&sid("k")));
    }

    /// Targeted: client detach must NOT kill a live session. Detach is a
    /// client-forwarder concern handled in main.rs (it aborts the forwarder task);
    /// the daemon's Session is untouched. We assert the structural invariant at the
    /// daemon level: nothing in the detach path removes or kills the session, so a
    /// session that no one kill_session's stays alive and listed.
    #[test]
    fn detach_does_not_kill_live_session() {
        let mut d = Daemon::default();
        d.start_session(sid("persist"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn");

        // The daemon exposes no detach mutation — detach lives entirely in the
        // client handler and only aborts that client's forwarder. So after any
        // number of client attach/detach cycles (which never call into Daemon to
        // mutate session lifetime), the session remains alive and listed.
        assert!(d.sessions.contains_key(&sid("persist")));
        assert!(
            d.sessions
                .get(&sid("persist"))
                .unwrap()
                .exit_state()
                .is_none(),
            "a detach must never cause the session's child to exit"
        );
        assert!(
            d.session_ids().contains(&sid("persist")),
            "the live session stays listed across detach"
        );

        d.kill_session(&sid("persist"));
    }

    /// Targeted: a successful shutdown reports every child reaped. Each child's
    /// reaping is confirmed via its exit latch inside `kill_and_wait`, so a report
    /// of `all_reaped()` with `reaped == total` means every process-table entry
    /// was collected (no orphans/zombies), and state is cleared.
    #[test]
    fn successful_shutdown_reports_all_children_reaped() {
        let mut d = Daemon::default();
        d.start_session(sid("a"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn a");
        d.start_session(sid("b"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn b");
        d.start_session(sid("c"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn c");
        assert_eq!(d.sessions.len(), 3, "three live children before shutdown");

        let report = d.shutdown();

        assert!(
            report.all_reaped(),
            "every child must confirm reaped: {report:?}"
        );
        assert_eq!(report.total, 3, "report counts all pre-shutdown sessions");
        assert_eq!(report.reaped, 3, "all three confirmed reaped");
        assert!(report.unconfirmed.is_empty(), "no unconfirmed children");
        assert_eq!(
            d.sessions.len(),
            0,
            "shutdown must drop every session after reaping its child"
        );
        assert!(d.channels.is_empty(), "shutdown clears channels too");
    }

    /// Targeted: shutdown REPORTS timeout/failure when a child doesn't confirm
    /// reaped within the budget — it must not overstate "all reaped". We force the
    /// branch deterministically with a zero per-child budget: kill_and_wait checks
    /// the exit latch once and, since the reader thread cannot have run `wait()`
    /// in zero time, reports the child unconfirmed. State is still cleared.
    #[test]
    fn shutdown_reports_unconfirmed_when_child_does_not_confirm_in_time() {
        let mut d = Daemon::default();
        d.start_session(sid("slow"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn");
        d.start_session(sid("slow2"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn");

        // Zero budget: no child can confirm reaped, so every one is unconfirmed.
        let report = d.shutdown_with_timeout(std::time::Duration::ZERO);

        assert!(
            !report.all_reaped(),
            "a zero-timeout shutdown must NOT claim all reaped: {report:?}"
        );
        assert_eq!(report.total, 2);
        assert_eq!(report.reaped, 0, "no child confirmed within a zero budget");
        assert_eq!(
            report.unconfirmed.len(),
            2,
            "both children reported unconfirmed"
        );
        assert_eq!(
            d.sessions.len(),
            0,
            "state is cleared even on a degraded shutdown (PTYs still closed)"
        );
    }

    #[test]
    fn shutdown_report_all_reaped_predicate() {
        // Empty/clean report is trivially all-reaped; a non-empty unconfirmed is not.
        let clean = ShutdownReport {
            total: 2,
            reaped: 2,
            unconfirmed: vec![],
        };
        assert!(clean.all_reaped());
        let degraded = ShutdownReport {
            total: 2,
            reaped: 1,
            unconfirmed: vec![sid("x")],
        };
        assert!(!degraded.all_reaped());
    }

    #[test]
    fn channel_registry_rejects_invalid_ids_and_stops_at_its_ceiling() {
        let mut d = Daemon::default();

        for index in 0..MAX_CHANNELS {
            d.open_channel(ChannelId(format!("channel-{index}")))
                .expect("channel below the limit opens");
        }
        assert_eq!(d.channels.len(), MAX_CHANNELS);

        d.open_channel(ChannelId("channel-0".into()))
            .expect("existing channel remains reusable at capacity");
        assert_eq!(d.channels.len(), MAX_CHANNELS);

        let error = d
            .open_channel(ChannelId("one-too-many".into()))
            .expect_err("new channel over the limit must fail");
        assert!(error.to_string().contains("channel limit reached"));
        assert_eq!(d.channels.len(), MAX_CHANNELS);

        for invalid in [
            ChannelId(String::new()),
            ChannelId("control\ncharacter".into()),
            ChannelId("x".repeat(MAX_CHANNEL_ID_BYTES + 1)),
        ] {
            let mut empty = Daemon::default();
            assert!(empty.open_channel(invalid).is_err());
            assert!(empty.channels.is_empty());
        }
    }

    #[test]
    fn channel_event_sender_must_exist_and_belong_to_the_target_channel() {
        let mut d = Daemon::default();
        let channel = ChannelId("members-only".into());
        let sender = sid("sender");
        d.open_channel(channel.clone()).unwrap();
        d.start_session(sender.clone(), ".", "sleep", &["30".to_string()], 80, 24)
            .expect("spawn sender session");

        let event_from = |from: Option<SessionId>, ts| ChannelEvent {
            channel: channel.clone(),
            from,
            kind: ChannelEventKind::ChatMsg {
                text: "bounded message".into(),
            },
            ts,
        };

        let missing = d
            .publish(event_from(Some(sid("missing")), 1))
            .expect_err("unknown sender cannot be impersonated");
        assert!(missing.to_string().contains("no such sender session"));

        let non_member = d
            .publish(event_from(Some(sender.clone()), 2))
            .expect_err("existing non-member cannot publish as a member");
        assert!(non_member.to_string().contains("is not a member"));

        d.join_channel(&channel, &sender).unwrap();
        d.publish(event_from(Some(sender.clone()), 3))
            .expect("a real member may publish under its own id");
        assert_eq!(d.channels[&channel].replay().len(), 1);

        let anonymous = d
            .publish(event_from(None, 4))
            .expect_err("socket callers cannot publish without a member identity");
        assert!(anonymous.to_string().contains("requires a sender session"));
        assert_eq!(d.channels[&channel].replay().len(), 1);

        d.kill_session(&sender);
    }

    #[test]
    fn ordinary_same_id_start_preserves_exit_and_explicit_restart_respawns() {
        let mut d = Daemon::default();

        // A child that exits the instant it starts. Nobody kills it, so its dead
        // Session lingers in the map under id "slot".
        d.start_session(sid("slot"), ".", "true", &[], 80, 24)
            .expect("spawn the short-lived session");
        wait_for_exit(&d, &sid("slot"));
        assert!(
            d.sessions
                .get(&sid("slot"))
                .expect("dead session lingers")
                .exit_state()
                .is_some(),
            "the child has exited and its corpse still occupies the id"
        );

        // Ordinary StartSession is what window focus/startup uses. Even if the durable Exited
        // status has not landed yet, it must preserve the retained final grid rather than infer
        // restart authority merely from a same-id command.
        let error = d
            .start_session(sid("slot"), ".", "sleep", &["30".to_string()], 80, 24)
            .expect_err("ordinary same-id start must refuse ambiguous restart authority");
        assert!(
            error.to_string().contains("explicit restart authority"),
            "refusal explains how the retained session can be replaced"
        );
        assert!(
            d.sessions
                .get(&sid("slot"))
                .expect("retained session present")
                .exit_state()
                .is_some(),
            "focus/startup must leave the exited retained generation intact"
        );

        // A future explicit Restart action carries the separate authority bit and replaces the
        // corpse only after the new child has spawned successfully.
        d.start_session_with_restart(sid("slot"), ".", "sleep", &["30".to_string()], 80, 24, true)
            .expect("explicit restart respawns a fresh session");
        assert!(
            d.sessions
                .get(&sid("slot"))
                .expect("respawned session present")
                .exit_state()
                .is_none(),
            "the dead session must be replaced by a live one, not left as a corpse"
        );

        // Targeted: the respawn must not retain a stale PTY/process handle from
        // the corpse. The corpse's PTY master/writer were dropped when its Session
        // was replaced in the map (HashMap::insert drops the old value), so the
        // new session must expose a working, distinct PTY surface. A successful
        // write through the new handle proves the writer is the fresh child's, not
        // the dead one's (whose PTY is closed → write would error).
        let handle = d.sessions.get(&sid("slot")).unwrap().pty_handle();
        handle
            .write_input(b"")
            .expect("respawned session's PTY writer is live, not the corpse's closed one");

        d.kill_session(&sid("slot"));
    }
}
