//! Socket lifecycle hardening for the daemon's Unix listener.
//!
//! Binding a Unix-domain socket whose path already exists is a hazard: blindly
//! unlinking it would orphan a *live* daemon's sessions (split-brain), while
//! refusing on any existing file would wedge restart after a crash leaves a
//! *stale* socket behind. This module decides which case we're in, safely.
//!
//! The rules, in order:
//!   1. If nothing exists at the path, bind is clear.
//!   2. If a path exists but is NOT a socket, or is owned by another user, or is
//!      reachable by group/other (an insecure path that can spawn commands as
//!      us), REFUSE — never unlink someone else's file, and never inherit an
//!      insecure socket.
//!   3. If our own socket exists, PROBE it with a bounded `connect`: a wedged
//!      peer must not hang startup, so the probe has a timeout.
//!        - someone answers (or the connect blocks past the timeout) => a daemon
//!          is (presumed) live => REFUSE to start a second instance.
//!        - connect is *refused*/*not-found* => the socket is stale => UNLINK and
//!          let the caller rebind.
//!        - any other connect error (permission, etc.) => REFUSE, do NOT unlink.
//!
//! The decision is a pure function over a `SocketProbe` so it is unit-testable
//! without a real daemon; the I/O lives in thin wrappers.

use std::io;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// How long a liveness probe may block before we treat the peer as live. A wedged
/// daemon (bound but not accepting) must not hang our startup, so the probe is
/// bounded; if it can't be classified in time we err toward "live" and refuse,
/// since unlinking a possibly-live socket is the unsafe direction.
const PROBE_TIMEOUT: Duration = Duration::from_millis(500);

/// The daemon's own effective UID, matching the socket filename and peer policy.
fn self_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() as u32 }
}

/// What we observed about a pre-existing path, distilled to the facts the
/// decision needs. Kept as plain data so the policy is a pure function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketProbe {
    /// Nothing exists at the path; bind is clear.
    Vacant,
    /// A path exists but it is not a socket (a regular file/dir/etc.). Refuse —
    /// it is not ours to remove and binding would fail anyway.
    NotASocket,
    /// A socket owned by a different UID. Refuse; never unlink another user's
    /// socket.
    WrongOwner { owner: u32 },
    /// Our socket, but reachable by group or other (mode has bits below 0700).
    /// A connection can spawn commands as us, so an insecure path is refused.
    InsecurePerms { mode: u32 },
    /// Our socket, secure perms, and a peer answered the probe (or the probe
    /// timed out, which we treat as "presumed live"). Refuse: a daemon is live.
    Live,
    /// Our socket, secure perms, but the probe was refused/not-found: no daemon
    /// is listening. Safe to unlink and rebind.
    Stale,
    /// Our socket, secure perms, but the probe failed for some other reason
    /// (e.g. permission denied on connect). Ambiguous — refuse rather than
    /// unlink, since we cannot prove no daemon is live.
    ProbeError,
}

/// The action the caller must take before binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketDecision {
    /// Proceed to bind directly.
    Bind,
    /// Unlink the stale socket, then bind.
    UnlinkThenBind,
    /// Do not bind; report this as the reason.
    Refuse(RefuseReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefuseReason {
    /// A live daemon already owns the path.
    AlreadyRunning,
    /// The existing path is not a socket.
    NotASocket,
    /// The socket is owned by another user.
    WrongOwner,
    /// The socket is reachable by group/other.
    InsecurePerms,
    /// The liveness probe failed ambiguously; refuse rather than risk a clobber.
    ProbeAmbiguous,
}

impl RefuseReason {
    pub fn as_str(self) -> &'static str {
        match self {
            RefuseReason::AlreadyRunning => "a pty-daemon is already listening; refusing to start a second instance",
            RefuseReason::NotASocket => "path exists but is not a socket; refusing to remove it",
            RefuseReason::WrongOwner => "socket is owned by another user; refusing to remove or reuse it",
            RefuseReason::InsecurePerms => "socket path is group/world reachable; refusing to reuse an insecure socket",
            RefuseReason::ProbeAmbiguous => "could not determine whether a daemon is live; refusing rather than risk clobbering a live socket",
        }
    }
}

/// Pure policy: map an observation to the action. No I/O; fully unit-testable.
pub fn decide(probe: SocketProbe) -> SocketDecision {
    match probe {
        SocketProbe::Vacant => SocketDecision::Bind,
        SocketProbe::Stale => SocketDecision::UnlinkThenBind,
        SocketProbe::Live => SocketDecision::Refuse(RefuseReason::AlreadyRunning),
        SocketProbe::NotASocket => SocketDecision::Refuse(RefuseReason::NotASocket),
        SocketProbe::WrongOwner { .. } => SocketDecision::Refuse(RefuseReason::WrongOwner),
        SocketProbe::InsecurePerms { .. } => SocketDecision::Refuse(RefuseReason::InsecurePerms),
        SocketProbe::ProbeError => SocketDecision::Refuse(RefuseReason::ProbeAmbiguous),
    }
}

/// Classify a connect error: only an explicitly-refused or vanished endpoint
/// proves no daemon is listening (=> stale, safe to unlink). Every other error
/// is ambiguous and must NOT trigger an unlink.
fn classify_connect_error(err: &io::Error) -> SocketProbe {
    match err.kind() {
        // Nobody is accepting on this socket: the canonical "stale socket left by
        // a crashed daemon" signal.
        io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound => SocketProbe::Stale,
        // PermissionDenied or anything else: we can't prove the socket is dead,
        // so do not unlink it.
        _ => SocketProbe::ProbeError,
    }
}

/// Connect to `path` with a bounded timeout, on a background thread so a wedged
/// peer (bound but never accepting, so `connect` blocks) cannot hang startup.
/// Returns the classified probe result.
fn probe_liveness(path: &Path) -> SocketProbe {
    let path = path.to_path_buf();
    let (tx, rx) = std::sync::mpsc::channel();
    // The probe runs on its own thread; if it never returns (wedged peer), we
    // abandon it after the timeout. The thread is detached and will finish (or
    // not) on its own — it holds only the socket fd, which the OS reclaims.
    std::thread::spawn(move || {
        let result = match UnixStream::connect(&path) {
            Ok(_stream) => SocketProbe::Live,
            Err(e) => classify_connect_error(&e),
        };
        let _ = tx.send(result);
    });
    match rx.recv_timeout(PROBE_TIMEOUT) {
        Ok(result) => result,
        // The connect neither succeeded nor failed within the budget: the peer is
        // bound but not accepting. Treat as live and refuse — unlinking a
        // possibly-live socket is the unsafe direction.
        Err(_) => SocketProbe::Live,
    }
}

/// Inspect a path that already exists and produce a `SocketProbe`. Combines the
/// metadata security checks (is-socket, owner, perms) with the bounded liveness
/// probe. `path` is assumed to exist (the caller checks first).
fn probe_existing(path: &Path) -> io::Result<SocketProbe> {
    // `symlink_metadata` so a symlink at the path is seen as a non-socket rather
    // than followed — a planted symlink must not let us unlink or trust a target.
    let meta = std::fs::symlink_metadata(path)?;
    let file_type = meta.file_type();
    use std::os::unix::fs::FileTypeExt;
    if !file_type.is_socket() {
        return Ok(SocketProbe::NotASocket);
    }
    let owner = meta.uid();
    if owner != self_uid() {
        return Ok(SocketProbe::WrongOwner { owner });
    }
    // Reject any access below 0700: a socket that group/other can reach is a
    // local-RCE gap because connecting spawns commands as us.
    let mode = meta.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Ok(SocketProbe::InsecurePerms { mode });
    }
    Ok(probe_liveness(path))
}

/// Prepare `path` for binding: probe an existing path, apply the policy, and
/// perform the unlink when (and only when) the socket is proven stale. Returns
/// `Ok(())` when the caller may proceed to `bind`, or an error describing why
/// startup must abort. Never unlinks a live, foreign, or ambiguous socket.
pub fn prepare_socket_path(path: &Path) -> io::Result<()> {
    // `try_exists` distinguishes "absent" from "exists but stat failed"; a stat
    // failure (e.g. permission on the parent dir) is a real error, not "vacant".
    let probe = if path.try_exists()? {
        probe_existing(path)?
    } else {
        SocketProbe::Vacant
    };
    match decide(probe) {
        SocketDecision::Bind => Ok(()),
        SocketDecision::UnlinkThenBind => {
            std::fs::remove_file(path)?;
            Ok(())
        }
        SocketDecision::Refuse(reason) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("{} (path {})", reason.as_str(), path.display()),
        )),
    }
}

/// Restores the process umask to a saved value when dropped, so the temporary
/// restrictive umask we set around `bind` cannot leak past it — even if `bind`
/// returns an error and we unwind. The umask is process-global, so this RAII
/// guard keeps the window where it's tightened as small and exception-safe as
/// possible.
struct UmaskGuard {
    previous: libc::mode_t,
}

impl UmaskGuard {
    /// Set `new` as the process umask, remembering the prior value for restore.
    fn set(new: libc::mode_t) -> Self {
        // SAFETY: umask always succeeds and returns the previous mask; it has no
        // preconditions. It is not thread-safe against a concurrent umask/open in
        // another thread, but socket bind happens once at startup before any
        // worker threads touch the filesystem, so there is no racing creator.
        let previous = unsafe { libc::umask(new) };
        UmaskGuard { previous }
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: same as `set`; restore the mask we saved.
        unsafe {
            libc::umask(self.previous);
        }
    }
}

/// The umask used while binding: deny ALL group/other bits so the socket inode
/// is created 0700-or-tighter from birth, closing the window where a permissive
/// process umask would leave it momentarily group/world-reachable before the
/// post-bind chmod runs.
const BIND_UMASK: libc::mode_t = 0o077;

/// Bind a Unix socket securely: set a restrictive umask (077) around `bind` so
/// the socket is never momentarily group/world reachable, restore the umask
/// afterward (success OR failure, via the RAII guard), then chmod 0600 as
/// verification/cleanup so the final mode is exact and independent of the
/// inherited umask.
///
/// `bind` is injected so this stays decoupled from tokio (and unit-testable with
/// a std listener): it is called once, with the umask already tightened.
pub fn bind_secure<L, F>(path: &Path, bind: F) -> io::Result<L>
where
    F: FnOnce(&Path) -> io::Result<L>,
{
    let listener = {
        // The guard restores the prior umask on drop — i.e. as soon as `bind`
        // returns, whether it succeeded or errored — so the tightened mask never
        // outlives this block.
        let _umask = UmaskGuard::set(BIND_UMASK);
        bind(path)?
    };
    // Post-bind chmod 0600 as belt-and-suspenders: the umask already prevents a
    // loose inode, but this pins the exact final mode (e.g. strips the owner
    // execute bit a socket never needs) regardless of platform bind behavior.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    // --- Pure policy (decide) ---

    #[test]
    fn stale_socket_decision_unlinks() {
        assert_eq!(decide(SocketProbe::Stale), SocketDecision::UnlinkThenBind);
    }

    #[test]
    fn live_socket_is_never_unlinked() {
        // The whole point: a live daemon's socket must never be removed by a
        // second daemon. Live => Refuse(AlreadyRunning), and crucially NOT
        // UnlinkThenBind.
        let d = decide(SocketProbe::Live);
        assert_eq!(d, SocketDecision::Refuse(RefuseReason::AlreadyRunning));
        assert_ne!(d, SocketDecision::UnlinkThenBind);
    }

    #[test]
    fn wrong_owner_is_refused_not_unlinked() {
        let d = decide(SocketProbe::WrongOwner { owner: 4242 });
        assert_eq!(d, SocketDecision::Refuse(RefuseReason::WrongOwner));
        assert_ne!(d, SocketDecision::UnlinkThenBind);
    }

    #[test]
    fn insecure_perms_is_refused_not_unlinked() {
        let d = decide(SocketProbe::InsecurePerms { mode: 0o666 });
        assert_eq!(d, SocketDecision::Refuse(RefuseReason::InsecurePerms));
        assert_ne!(d, SocketDecision::UnlinkThenBind);
    }

    #[test]
    fn not_a_socket_is_refused_not_unlinked() {
        let d = decide(SocketProbe::NotASocket);
        assert_eq!(d, SocketDecision::Refuse(RefuseReason::NotASocket));
        assert_ne!(d, SocketDecision::UnlinkThenBind);
    }

    #[test]
    fn probe_error_is_refused_not_unlinked() {
        // An ambiguous probe (e.g. PermissionDenied on connect) must refuse, not
        // unlink: we cannot prove the socket is dead.
        let d = decide(SocketProbe::ProbeError);
        assert_eq!(d, SocketDecision::Refuse(RefuseReason::ProbeAmbiguous));
        assert_ne!(d, SocketDecision::UnlinkThenBind);
    }

    #[test]
    fn vacant_path_binds_directly() {
        assert_eq!(decide(SocketProbe::Vacant), SocketDecision::Bind);
    }

    // --- connect-error classification ---

    #[test]
    fn connection_refused_classifies_as_stale() {
        let e = io::Error::from(io::ErrorKind::ConnectionRefused);
        assert_eq!(classify_connect_error(&e), SocketProbe::Stale);
    }

    #[test]
    fn not_found_classifies_as_stale() {
        let e = io::Error::from(io::ErrorKind::NotFound);
        assert_eq!(classify_connect_error(&e), SocketProbe::Stale);
    }

    #[test]
    fn permission_denied_classifies_as_probe_error_not_stale() {
        // The critical safety case: a foreign/locked socket whose connect is
        // denied must NOT look stale (which would unlink it).
        let e = io::Error::from(io::ErrorKind::PermissionDenied);
        assert_eq!(classify_connect_error(&e), SocketProbe::ProbeError);
        assert_ne!(classify_connect_error(&e), SocketProbe::Stale);
    }

    // --- end-to-end over real filesystem paths ---

    fn temp_path(name: &str) -> std::path::PathBuf {
        // Unix socket paths must fit in `sockaddr_un.sun_path` (~104 bytes on
        // macOS), so keep this SHORT: a small dir + a compact base36-ish nonce.
        // `/tmp` is short and writable on the platforms we target.
        use std::sync::atomic::{AtomicU64, Ordering};
        static NONCE: AtomicU64 = AtomicU64::new(0);
        let n = NONCE.fetch_add(1, Ordering::Relaxed);
        let mut p = std::path::PathBuf::from("/tmp");
        p.push(format!("hydra-{}-{}-{}.sock", std::process::id(), name, n));
        p
    }

    #[test]
    fn vacant_path_prepares_clean() {
        let p = temp_path("vacant");
        assert!(!p.exists());
        prepare_socket_path(&p).expect("vacant path prepares for bind");
        // No file should have been created by the probe.
        assert!(!p.exists());
    }

    #[test]
    fn stale_socket_is_removed_only_when_no_live_daemon_responds() {
        // Bind a listener, then DROP it. On Unix, dropping a UnixListener leaves
        // the socket FILE on disk but nothing is accepting — the canonical stale
        // socket. prepare_socket_path must classify it stale and unlink it.
        let p = temp_path("stale");
        {
            let listener = UnixListener::bind(&p).expect("bind");
            // Tighten perms so the security check passes (mkstemp dir is 0700 on
            // most systems, but the socket inherits umask; force 0600).
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
            drop(listener); // nothing accepts now; file remains
        }
        assert!(p.exists(), "stale socket file remains on disk");
        prepare_socket_path(&p).expect("stale socket prepares (after unlink)");
        assert!(!p.exists(), "stale socket must be unlinked");
    }

    #[test]
    fn live_daemon_socket_is_never_unlinked_by_a_second_daemon() {
        // A real listener that IS accepting: a second daemon must refuse and
        // must leave the socket file intact.
        let p = temp_path("live");
        let listener = UnixListener::bind(&p).expect("bind");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        // Accept in the background so the probe's connect succeeds (=> Live).
        let accept_thread = std::thread::spawn(move || {
            // Accept one connection (the probe), then return so the test ends.
            let _ = listener.accept();
            listener
        });

        let err = prepare_socket_path(&p).expect_err("must refuse a live daemon");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(p.exists(), "live socket must NOT be unlinked");

        let listener = accept_thread.join().unwrap();
        drop(listener);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn insecure_perms_socket_is_refused() {
        // A socket reachable by group/other is refused (and not unlinked).
        let p = temp_path("insecure");
        let listener = UnixListener::bind(&p).expect("bind");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();

        let err = prepare_socket_path(&p).expect_err("insecure perms must be refused");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(
            err.to_string().contains("insecure"),
            "reason names the insecure path: {err}"
        );
        assert!(p.exists(), "refused socket must not be unlinked");

        drop(listener);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn non_socket_path_is_refused() {
        // A regular file at the socket path must be refused, never removed.
        let p = temp_path("regular");
        std::fs::write(&p, b"not a socket").expect("write file");
        let err = prepare_socket_path(&p).expect_err("regular file must be refused");
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert!(p.exists(), "refused regular file must not be removed");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn probe_does_not_wedge_when_peer_never_accepts() {
        // A socket that is bound but NOT accepting (no accept() call) makes
        // connect block; the bounded probe must still return within the timeout
        // budget and refuse (presumed live), rather than hang forever.
        let p = temp_path("wedged");
        let listener = UnixListener::bind(&p).expect("bind");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        // Never call accept(). The listen backlog lets connect() complete the
        // handshake on most platforms, so this also covers the "answers" path;
        // either way prepare_socket_path must return promptly and not hang.
        let start = std::time::Instant::now();
        let result = prepare_socket_path(&p);
        let elapsed = start.elapsed();
        assert!(
            elapsed < PROBE_TIMEOUT * 4,
            "probe must not wedge startup; took {elapsed:?}"
        );
        // Bound-but-not-accepting is treated as live => refuse, socket intact.
        assert!(result.is_err(), "a bound socket is treated as live");
        assert!(p.exists(), "must not unlink a possibly-live socket");

        drop(listener);
        let _ = std::fs::remove_file(&p);
    }

    // --- bind_secure / umask hardening ---

    // umask is process-global, so these tests must not run concurrently with each
    // other (or anything that reads/sets umask). Serialize them through one mutex.
    static UMASK_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Read the current umask without permanently changing it (umask has no pure
    /// getter: set a value, capture the prior, then restore the prior).
    fn current_umask() -> libc::mode_t {
        // SAFETY: umask is always safe; we immediately restore the value we read.
        unsafe {
            let prev = libc::umask(0o022);
            libc::umask(prev);
            prev
        }
    }

    #[test]
    fn bound_socket_is_never_group_world_reachable_under_permissive_umask() {
        let _serialize = UMASK_TEST_LOCK.lock().unwrap();
        // Simulate a hostile-permissive process umask (000 => nothing masked, so
        // a naive bind would create a 0777-ish inode).
        let saved = unsafe { libc::umask(0o000) };

        let p = temp_path("secure-bind");
        let listener =
            bind_secure(&p, |path| UnixListener::bind(path)).expect("secure bind succeeds");

        let mode = std::fs::symlink_metadata(&p).unwrap().mode() & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "socket must have no group/other bits after secure setup; mode was {mode:o}"
        );
        assert_eq!(mode, 0o600, "final mode pinned to 0600; was {mode:o}");

        drop(listener);
        let _ = std::fs::remove_file(&p);
        unsafe {
            libc::umask(saved);
        }
    }

    #[test]
    fn umask_is_restored_after_successful_bind() {
        let _serialize = UMASK_TEST_LOCK.lock().unwrap();
        let saved = unsafe { libc::umask(0o022) }; // set a known umask
        assert_eq!(current_umask(), 0o022, "precondition: umask is 022");

        let p = temp_path("umask-ok");
        let listener =
            bind_secure(&p, |path| UnixListener::bind(path)).expect("secure bind succeeds");
        assert_eq!(
            current_umask(),
            0o022,
            "umask must be restored to its prior value after a successful bind"
        );

        drop(listener);
        let _ = std::fs::remove_file(&p);
        unsafe {
            libc::umask(saved);
        }
    }

    #[test]
    fn umask_is_restored_after_failed_bind() {
        let _serialize = UMASK_TEST_LOCK.lock().unwrap();
        let saved = unsafe { libc::umask(0o022) };
        assert_eq!(current_umask(), 0o022, "precondition: umask is 022");

        // Force the bind closure to fail; the umask guard must still restore.
        let p = temp_path("umask-fail");
        let result: io::Result<UnixListener> =
            bind_secure(&p, |_path| Err(io::Error::other("synthetic bind failure")));
        assert!(result.is_err(), "bind closure forced to fail");
        assert_eq!(
            current_umask(),
            0o022,
            "umask must be restored even when bind fails (RAII guard runs on unwind)"
        );

        let _ = std::fs::remove_file(&p);
        unsafe {
            libc::umask(saved);
        }
    }
}
