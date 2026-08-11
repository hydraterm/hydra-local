//! Lifecycle-support helpers for the maestro-app harness: path defaults, binary resolution, session
//! argv, the renderer command shape, child-process log paths, renderer-mode policy, the
//! spawned-daemon keep policy, and owned-socket cleanup.
//!
//! Everything here is PURE over injected env/filesystem/socket lookups so the lifecycle decisions are
//! unit-testable without real process IO. Extracted from `lib.rs`; crate-root paths
//! (`maestro_app::<Item>` / `crate::<Item>`) are preserved by explicit re-exports in `lib.rs`.

use std::path::{Path, PathBuf};

/// The filename of the PRIVATE dev socket the harness uses when `--socket` is not given. It is
/// deliberately DIFFERENT from the daemon's per-user default socket filename so the harness can
/// never disturb a user's real daemon by
/// default.
pub const DEV_SOCKET_FILENAME: &str = "maestro-app-dev.sock";

/// The local binaries this harness needs to locate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinaryKind {
    Daemon,
    Renderer,
}

impl BinaryKind {
    /// The on-disk file name (no extension; these are unix dev binaries).
    pub fn file_name(self) -> &'static str {
        match self {
            BinaryKind::Daemon => "pty-daemon",
            BinaryKind::Renderer => "maestro-renderer",
        }
    }

    /// The environment variable that, if set, overrides the path for this binary.
    pub fn env_var(self) -> &'static str {
        match self {
            BinaryKind::Daemon => "MAESTRO_PTY_DAEMON_BIN",
            BinaryKind::Renderer => "MAESTRO_RENDERER_BIN",
        }
    }
}

/// The private dev socket path under `runtime_base` (typically `XDG_RUNTIME_DIR`/`TMPDIR`/`/tmp`).
/// Distinct filename from the daemon default, so this never aliases a user's real daemon socket.
pub fn dev_socket_path(runtime_base: &Path) -> PathBuf {
    runtime_base.join(DEV_SOCKET_FILENAME)
}

/// Choose the runtime base directory for the dev socket, mirroring the daemon's own precedence
/// (`XDG_RUNTIME_DIR`, then `TMPDIR`, then `/tmp`) but skipping empty values. Pure over an injected
/// env lookup.
pub fn runtime_base_dir(get_env: impl Fn(&str) -> Option<String>) -> PathBuf {
    for key in ["XDG_RUNTIME_DIR", "TMPDIR"] {
        if let Some(v) = get_env(key) {
            if !v.is_empty() {
                return PathBuf::from(v);
            }
        }
    }
    PathBuf::from("/tmp")
}

/// A dev-safe app-support base for `maestro-shell` records when `--base` is omitted.
///
/// Resolution: the platform app-support dir + a SEPARATE "-dev" base (so the harness never
/// writes into the production records directory) — macOS
/// `$HOME/Library/Application Support/Maestro-dev`, elsewhere `$XDG_DATA_HOME/maestro-dev`
/// (falling back to `$HOME/.local/share/maestro-dev`) — else `<runtime_base>/maestro-app-dev-base`
/// when `$HOME` is unset. Crucially this is NEVER a repo root, satisfying the "do not write
/// Maestro metadata into repo roots" rule.
pub fn default_base_dir(get_env: impl Fn(&str) -> Option<String>, runtime_base: &Path) -> PathBuf {
    #[cfg(not(target_os = "macos"))]
    if let Some(data) = get_env("XDG_DATA_HOME") {
        if !data.is_empty() && Path::new(&data).is_absolute() {
            return PathBuf::from(data).join("maestro-dev");
        }
    }
    if let Some(home) = get_env("HOME") {
        if !home.is_empty() {
            #[cfg(target_os = "macos")]
            return PathBuf::from(home)
                .join("Library")
                .join("Application Support")
                .join("Maestro-dev");
            #[cfg(not(target_os = "macos"))]
            return PathBuf::from(home)
                .join(".local")
                .join("share")
                .join("maestro-dev");
        }
    }
    runtime_base.join("maestro-app-dev-base")
}

/// How a required binary path was resolved, for the report/debug surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BinarySource {
    Explicit,
    Env,
    SiblingOfExe,
    CargoTarget,
}

/// Resolve a required binary's path, in precedence order:
/// 1. an explicit caller-supplied path (`--daemon` / `--renderer`);
/// 2. the env override (`MAESTRO_PTY_DAEMON_BIN` / `MAESTRO_RENDERER_BIN`);
/// 3. a sibling binary next to the current executable (`current_exe`'s directory);
/// 4. obvious Cargo dev/release locations under the repo (`<repo>/target/{debug,release}`),
///    derived from the current exe path.
///
/// Required binaries are deliberately never resolved through `PATH`; packaged launchers pin the
/// verified local binaries as one compatible installation.
///
/// `exists` is injected (real impl: `Path::exists`) so resolution is unit-testable without a real
/// filesystem layout. Returns the first CANDIDATE that exists, with how it was found; `None` if no
/// candidate exists (the caller turns that into a typed `binary_not_found` error).
pub fn resolve_binary(
    kind: BinaryKind,
    explicit: Option<&Path>,
    get_env: impl Fn(&str) -> Option<String>,
    current_exe: Option<&Path>,
    exists: impl Fn(&Path) -> bool,
) -> Option<(PathBuf, BinarySource)> {
    if let Some(p) = explicit {
        if exists(p) {
            return Some((p.to_path_buf(), BinarySource::Explicit));
        }
    }

    if let Some(v) = get_env(kind.env_var()) {
        if !v.is_empty() {
            let p = PathBuf::from(v);
            if exists(&p) {
                return Some((p, BinarySource::Env));
            }
        }
    }

    if let Some(exe) = current_exe {
        if let Some(dir) = exe.parent() {
            let sibling = dir.join(kind.file_name());
            if exists(&sibling) {
                return Some((sibling, BinarySource::SiblingOfExe));
            }

            // Cargo target fallback: the exe usually lives at <repo>/target/<profile>/maestro-app.
            // Probe both target profiles next to that profile dir.
            if let Some(target_dir) = dir.parent() {
                for profile in ["debug", "release"] {
                    let cand = target_dir.join(profile).join(kind.file_name());
                    if exists(&cand) {
                        return Some((cand, BinarySource::CargoTarget));
                    }
                }
            }
        }
    }

    None
}

/// The session argv to actually run: the user's `-- argv` if given, else a conservative shell
/// fallback derived from `$SHELL` (an interactive login shell), else `/bin/sh`.
pub fn session_argv(user_argv: &[String], get_env: impl Fn(&str) -> Option<String>) -> Vec<String> {
    if !user_argv.is_empty() {
        return user_argv.to_vec();
    }
    match get_env("SHELL") {
        Some(sh) if !sh.is_empty() => vec![sh, "-l".to_string()],
        _ => vec!["/bin/sh".to_string()],
    }
}

/// The session argv to actually run, layering the persisted `shell.default_argv` override between an
/// explicit user argv and the environment fallback:
///
/// 1. if `explicit_argv` is non-empty, return it unchanged — an explicit `launch -- <cmd>` always wins;
/// 2. else if `settings_shell_default_argv` is `Some(non-empty)`, return that configured argv;
/// 3. else fall back to [`session_argv`]`(&[], get_env)` (`$SHELL -l`, then `/bin/sh`).
///
/// The configured argv is trusted to already be validated (non-empty, all strings, non-empty command
/// name) by the settings-write path; a defensively-empty slice is ignored so it can never select an
/// empty command. Pure: the only effect is choosing which argv vector to return.
pub fn effective_session_argv(
    explicit_argv: &[String],
    settings_shell_default_argv: Option<&[String]>,
    get_env: impl Fn(&str) -> Option<String>,
) -> Vec<String> {
    if !explicit_argv.is_empty() {
        return explicit_argv.to_vec();
    }
    if let Some(argv) = settings_shell_default_argv {
        if !argv.is_empty() {
            return argv.to_vec();
        }
    }
    session_argv(&[], get_env)
}

/// The exact `maestro-renderer` argv for a session.
///
/// `font_size_px`/`theme` are `None` -> those flags are omitted; with both `None` this is the
/// historical bare form `maestro-renderer <socket> <session>` (renderer keeps its built-in
/// defaults). `Some(px)` -> `--font-size-px <px>` and `Some(id)` -> `--theme <id>`, so a detached
/// child renders at the same resolved `appearance.font_size_px` / `appearance.theme` the in-process
/// foreground renderer already uses. Both flags precede the positionals (font-size first) to match
/// the renderer CLI parser. Settings are resolved by the caller, not here.
pub fn renderer_command(
    renderer_bin: &Path,
    socket_path: &Path,
    session_id: &str,
    font_size_px: Option<u32>,
    theme: Option<&str>,
) -> Vec<String> {
    let mut argv = vec![renderer_bin.to_string_lossy().into_owned()];
    if let Some(px) = font_size_px {
        argv.push("--font-size-px".to_string());
        argv.push(px.to_string());
    }
    if let Some(id) = theme {
        argv.push("--theme".to_string());
        argv.push(id.to_string());
    }
    argv.push(socket_path.to_string_lossy().into_owned());
    argv.push(session_id.to_string());
    argv
}

/// Which child process a captured log file belongs to. Determines the file-name stem under a
/// `--log-dir` directory; the stream ([`ChildLogStream`]) determines the suffix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildLogKind {
    Daemon,
    Renderer,
}

impl ChildLogKind {
    /// The deterministic file-name stem for this child's log files (`pty-daemon` / `maestro-renderer`).
    pub fn file_stem(self) -> &'static str {
        match self {
            ChildLogKind::Daemon => "pty-daemon",
            ChildLogKind::Renderer => "maestro-renderer",
        }
    }
}

/// Which child stream a captured log file holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildLogStream {
    Stdout,
    Stderr,
}

impl ChildLogStream {
    /// The deterministic file-name suffix for this stream (`stdout` / `stderr`).
    pub fn suffix(self) -> &'static str {
        match self {
            ChildLogStream::Stdout => "stdout",
            ChildLogStream::Stderr => "stderr",
        }
    }
}

/// The deterministic absolute path of a child stream's log file under a `--log-dir` directory.
///
/// Names are `<stem>.<stream>.log`, e.g. `pty-daemon.stdout.log`, `pty-daemon.stderr.log`,
/// `maestro-renderer.stdout.log`, `maestro-renderer.stderr.log`. Pure: it only joins names, it does
/// not touch the filesystem.
pub fn child_log_path(log_dir: &Path, kind: ChildLogKind, stream: ChildLogStream) -> PathBuf {
    log_dir.join(format!("{}.{}.log", kind.file_stem(), stream.suffix()))
}

/// Which lifecycle mode a successful launch runs in. Derived purely from the parsed flags, so the
/// decision is unit-testable without any process IO.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RendererMode {
    /// Renderer launched; the app waits for it to exit, then cleans up a daemon it spawned (unless
    /// `--keep-daemon`).
    Foreground,
    /// Renderer launched fire-and-forget; the app does not wait and leaves a spawned daemon alive.
    Detached,
    /// No renderer (`--no-run-renderer`); a daemon this process spawned is cleaned up unless
    /// `--keep-daemon`.
    None,
}

impl RendererMode {
    /// Derive the mode from the two relevant flags. (`parse_launch` already rejects the
    /// `no_run_renderer && detach_renderer` combination, so this just reads the surviving state.)
    pub fn from_flags(no_run_renderer: bool, detach_renderer: bool) -> Self {
        if no_run_renderer {
            RendererMode::None
        } else if detach_renderer {
            RendererMode::Detached
        } else {
            RendererMode::Foreground
        }
    }
}

/// Whether this mode HARD-REQUIRES the `maestro-renderer` binary to exist before launch.
///
/// Pure policy:
/// - `Detached` spawns a separate `maestro-renderer` child process (a winit event loop cannot be
///   detached from this process/main thread), so the binary MUST resolve — its absence is fatal.
/// - `Foreground` now runs the renderer IN-PROCESS via `maestro_renderer::run_renderer`, so the
///   binary is not needed to open the window; a resolved path is used only to report
///   `renderer_command`, and its absence is non-fatal.
/// - `None` (`--no-run-renderer`) opens no GUI at all, so the binary is likewise optional and only
///   reported when available.
pub fn renderer_binary_required(mode: RendererMode) -> bool {
    matches!(mode, RendererMode::Detached)
}

/// Whether a daemon THIS process spawned should be left running after the launch completes.
///
/// Pure policy, the single source of truth for both the foreground and headless paths:
/// - if we did NOT spawn the daemon (reused an existing one), we NEVER touch it -> always kept;
/// - if `--keep-daemon` is set, a spawned daemon is kept;
/// - in `Detached` mode the spawned daemon is always kept (the renderer outlives us);
/// - in `Foreground` and `None` modes a spawned daemon is cleaned up (returns false).
pub fn should_keep_spawned_daemon(
    daemon_spawned: bool,
    mode: RendererMode,
    keep_daemon: bool,
) -> bool {
    if !daemon_spawned {
        return true; // reused daemon — out of bounds, leave it alone
    }
    if keep_daemon {
        return true;
    }
    matches!(mode, RendererMode::Detached)
}

/// Whether the daemon socket path should be cleaned up after the launch completes.
///
/// Pure policy, derived from the same lifecycle facts as [`should_keep_spawned_daemon`]:
/// - we only ever clean up a socket whose daemon THIS process spawned (`daemon_started`);
/// - we only clean up when that spawned daemon was NOT kept (`!daemon_kept`) — i.e. we just
///   stopped it, so the socket file is now stale.
///
/// This is intentionally the structural inverse of "keep": a reused daemon (`daemon_started ==
/// false`) is never ours to clean up, and a kept daemon (`--keep-daemon`/`--detach-renderer`) is
/// still serving on its socket so the file must stay. The actual filesystem removal additionally
/// refuses to delete a socket that still accepts connections (see [`cleanup_owned_socket`]).
pub fn should_cleanup_owned_socket(daemon_started: bool, daemon_kept: bool) -> bool {
    daemon_started && !daemon_kept
}

/// The outcome of attempting to clean up a now-stale owned socket file. Returned so callers can
/// surface it in the structured output/log without the helper performing IO of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketCleanup {
    /// The stale socket file was removed.
    Removed,
    /// Nothing to remove — the path was already absent.
    Absent,
    /// The socket still accepts connections, so it was deliberately left in place.
    StillLive,
    /// Removal was attempted but failed (e.g. a permission error). Non-fatal.
    RemoveFailed,
}

/// Remove a now-stale owned daemon socket file, conservatively.
///
/// Behavior, in order:
/// 1. if `can_connect(path)` still succeeds, the daemon is alive on this socket — do NOT remove it,
///    return [`SocketCleanup::StillLive`];
/// 2. if the path does not exist, treat cleanup as already done — [`SocketCleanup::Absent`];
/// 3. otherwise attempt `remove(path)`; map success to [`SocketCleanup::Removed`] and any error to
///    [`SocketCleanup::RemoveFailed`] (cleanup failure is never fatal to the launch).
///
/// `can_connect`, `exists`, and `remove` are injected so the decision is unit-testable without a
/// real socket. The caller is responsible for having already decided this socket is eligible (see
/// [`should_cleanup_owned_socket`]); this function only enforces the never-remove-a-live-socket and
/// absent-is-success invariants.
pub fn cleanup_owned_socket(
    path: &Path,
    can_connect: impl Fn(&Path) -> bool,
    exists: impl Fn(&Path) -> bool,
    remove: impl Fn(&Path) -> std::io::Result<()>,
) -> SocketCleanup {
    if can_connect(path) {
        return SocketCleanup::StillLive;
    }
    if !exists(path) {
        return SocketCleanup::Absent;
    }
    match remove(path) {
        Ok(()) => SocketCleanup::Removed,
        Err(_) => SocketCleanup::RemoveFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|x| x.to_string()).collect()
    }

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    // ---- socket / base paths ----------------------------------------------------------------

    #[test]
    fn dev_socket_filename_differs_from_real_daemon_default() {
        // Guard: the harness must never default onto the user's real daemon socket.
        assert_ne!(
            DEV_SOCKET_FILENAME,
            maestro_protocol::daemon_socket_filename(1000),
            "dev socket must not alias the real daemon socket"
        );
        let p = dev_socket_path(Path::new("/run/u"));
        assert_eq!(p, PathBuf::from("/run/u/maestro-app-dev.sock"));
    }

    #[test]
    fn runtime_base_precedence_and_empty_skip() {
        assert_eq!(
            runtime_base_dir(env_of(&[("XDG_RUNTIME_DIR", "/run/user/1")])),
            PathBuf::from("/run/user/1")
        );
        // Empty XDG falls through to TMPDIR.
        assert_eq!(
            runtime_base_dir(env_of(&[("XDG_RUNTIME_DIR", ""), ("TMPDIR", "/var/tmp")])),
            PathBuf::from("/var/tmp")
        );
        // Neither set -> /tmp.
        assert_eq!(runtime_base_dir(env_of(&[])), PathBuf::from("/tmp"));
    }

    #[test]
    fn default_base_uses_home_dev_dir_and_is_not_a_repo_root() {
        let base = default_base_dir(env_of(&[("HOME", "/example/home")]), Path::new("/tmp"));
        #[cfg(target_os = "macos")]
        assert_eq!(
            base,
            PathBuf::from("/example/home/Library/Application Support/Maestro-dev")
        );
        #[cfg(not(target_os = "macos"))]
        assert_eq!(
            base,
            PathBuf::from("/example/home/.local/share/maestro-dev")
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn default_base_prefers_xdg_data_home_off_macos() {
        let base = default_base_dir(
            env_of(&[("XDG_DATA_HOME", "/data/xdg"), ("HOME", "/home/me")]),
            Path::new("/tmp"),
        );
        assert_eq!(base, PathBuf::from("/data/xdg/maestro-dev"));
    }

    #[test]
    fn default_base_falls_back_under_runtime_when_no_home() {
        let base = default_base_dir(env_of(&[]), Path::new("/var/tmp"));
        assert_eq!(base, PathBuf::from("/var/tmp/maestro-app-dev-base"));
    }

    // ---- binary resolution ------------------------------------------------------------------

    #[test]
    fn explicit_binary_wins_when_it_exists() {
        let got = resolve_binary(
            BinaryKind::Daemon,
            Some(Path::new("/explicit/pty-daemon")),
            env_of(&[]),
            None,
            |p| p == Path::new("/explicit/pty-daemon"),
        );
        assert_eq!(
            got,
            Some((
                PathBuf::from("/explicit/pty-daemon"),
                BinarySource::Explicit
            ))
        );
    }

    #[test]
    fn env_override_used_when_no_explicit() {
        let got = resolve_binary(
            BinaryKind::Renderer,
            None,
            env_of(&[("MAESTRO_RENDERER_BIN", "/env/maestro-renderer")]),
            None,
            |p| p == Path::new("/env/maestro-renderer"),
        );
        assert_eq!(
            got,
            Some((PathBuf::from("/env/maestro-renderer"), BinarySource::Env))
        );
    }

    #[test]
    fn sibling_of_exe_resolved() {
        let got = resolve_binary(
            BinaryKind::Daemon,
            None,
            env_of(&[]),
            Some(Path::new("/repo/target/release/maestro-app")),
            |p| p == Path::new("/repo/target/release/pty-daemon"),
        );
        assert_eq!(
            got,
            Some((
                PathBuf::from("/repo/target/release/pty-daemon"),
                BinarySource::SiblingOfExe
            ))
        );
    }

    #[test]
    fn cargo_target_fallback_probes_debug_and_release() {
        // Exe in release dir, but the daemon only exists under debug -> CargoTarget find.
        let got = resolve_binary(
            BinaryKind::Daemon,
            None,
            env_of(&[]),
            Some(Path::new("/repo/target/release/maestro-app")),
            |p| p == Path::new("/repo/target/debug/pty-daemon"),
        );
        assert_eq!(
            got,
            Some((
                PathBuf::from("/repo/target/debug/pty-daemon"),
                BinarySource::CargoTarget
            ))
        );
    }

    #[test]
    fn unresolved_binary_is_none() {
        let got = resolve_binary(
            BinaryKind::Renderer,
            Some(Path::new("/nope")),
            env_of(&[]),
            Some(Path::new("/repo/target/release/maestro-app")),
            |_| false,
        );
        assert_eq!(got, None);
    }

    // ---- session argv -----------------------------------------------------------------------

    #[test]
    fn session_argv_prefers_user_argv() {
        let got = session_argv(&argv(&["htop"]), env_of(&[("SHELL", "/bin/zsh")]));
        assert_eq!(got, argv(&["htop"]));
    }

    #[test]
    fn session_argv_uses_shell_login_fallback() {
        let got = session_argv(&[], env_of(&[("SHELL", "/bin/zsh")]));
        assert_eq!(got, argv(&["/bin/zsh", "-l"]));
    }

    #[test]
    fn session_argv_falls_back_to_sh_without_shell() {
        let got = session_argv(&[], env_of(&[]));
        assert_eq!(got, argv(&["/bin/sh"]));
    }

    #[test]
    fn effective_session_argv_explicit_wins_over_configured_default() {
        let configured = argv(&["/bin/zsh", "-l"]);
        let got = effective_session_argv(
            &argv(&["htop"]),
            Some(&configured),
            env_of(&[("SHELL", "/bin/bash")]),
        );
        assert_eq!(got, argv(&["htop"]));
    }

    #[test]
    fn effective_session_argv_configured_default_wins_over_shell_env() {
        let configured = argv(&["/bin/zsh", "-l"]);
        let got = effective_session_argv(&[], Some(&configured), env_of(&[("SHELL", "/bin/bash")]));
        assert_eq!(got, argv(&["/bin/zsh", "-l"]));
    }

    #[test]
    fn effective_session_argv_absent_default_falls_back_to_shell_env() {
        let got = effective_session_argv(&[], None, env_of(&[("SHELL", "/bin/bash")]));
        assert_eq!(got, argv(&["/bin/bash", "-l"]));
    }

    #[test]
    fn effective_session_argv_absent_default_no_shell_falls_back_to_sh() {
        let got = effective_session_argv(&[], None, env_of(&[]));
        assert_eq!(got, argv(&["/bin/sh"]));
    }

    #[test]
    fn effective_session_argv_empty_configured_default_is_ignored() {
        let empty: Vec<String> = Vec::new();
        let got = effective_session_argv(&[], Some(&empty), env_of(&[("SHELL", "/bin/bash")]));
        assert_eq!(got, argv(&["/bin/bash", "-l"]));
    }

    // ---- renderer command -------------------------------------------------------------------

    #[test]
    fn renderer_command_is_socket_then_session_id() {
        let got = renderer_command(
            Path::new("/bin/maestro-renderer"),
            Path::new("/tmp/d.sock"),
            "sid",
            None,
            None,
        );
        assert_eq!(got, argv(&["/bin/maestro-renderer", "/tmp/d.sock", "sid"]));
    }

    #[test]
    fn renderer_command_inserts_font_size_flag_before_positionals() {
        let got = renderer_command(
            Path::new("/bin/maestro-renderer"),
            Path::new("/tmp/d.sock"),
            "sid",
            Some(18),
            None,
        );
        assert_eq!(
            got,
            argv(&[
                "/bin/maestro-renderer",
                "--font-size-px",
                "18",
                "/tmp/d.sock",
                "sid",
            ])
        );
    }

    #[test]
    fn renderer_command_inserts_font_size_and_theme_before_positionals() {
        let got = renderer_command(
            Path::new("/bin/maestro-renderer"),
            Path::new("/tmp/d.sock"),
            "sid",
            Some(18),
            Some("high_contrast_dark"),
        );
        assert_eq!(
            got,
            argv(&[
                "/bin/maestro-renderer",
                "--font-size-px",
                "18",
                "--theme",
                "high_contrast_dark",
                "/tmp/d.sock",
                "sid",
            ])
        );
    }

    #[test]
    fn renderer_command_inserts_theme_only_before_positionals() {
        let got = renderer_command(
            Path::new("/bin/maestro-renderer"),
            Path::new("/tmp/d.sock"),
            "sid",
            None,
            Some("built_in_dark"),
        );
        assert_eq!(
            got,
            argv(&[
                "/bin/maestro-renderer",
                "--theme",
                "built_in_dark",
                "/tmp/d.sock",
                "sid",
            ])
        );
    }

    // ---- child log paths --------------------------------------------------------------------

    #[test]
    fn child_log_paths_are_deterministic() {
        let dir = Path::new("/tmp/logs");
        assert_eq!(
            child_log_path(dir, ChildLogKind::Daemon, ChildLogStream::Stdout),
            PathBuf::from("/tmp/logs/pty-daemon.stdout.log")
        );
        assert_eq!(
            child_log_path(dir, ChildLogKind::Daemon, ChildLogStream::Stderr),
            PathBuf::from("/tmp/logs/pty-daemon.stderr.log")
        );
        assert_eq!(
            child_log_path(dir, ChildLogKind::Renderer, ChildLogStream::Stdout),
            PathBuf::from("/tmp/logs/maestro-renderer.stdout.log")
        );
        assert_eq!(
            child_log_path(dir, ChildLogKind::Renderer, ChildLogStream::Stderr),
            PathBuf::from("/tmp/logs/maestro-renderer.stderr.log")
        );
    }

    // ---- renderer mode + binary requirement -------------------------------------------------

    #[test]
    fn renderer_mode_from_flags() {
        assert_eq!(
            RendererMode::from_flags(false, false),
            RendererMode::Foreground
        );
        assert_eq!(
            RendererMode::from_flags(false, true),
            RendererMode::Detached
        );
        assert_eq!(RendererMode::from_flags(true, false), RendererMode::None);
    }

    #[test]
    fn renderer_binary_required_only_in_detach_mode() {
        // Detached spawns a child renderer process, so the binary MUST exist.
        assert!(renderer_binary_required(RendererMode::Detached));
        // Foreground runs the renderer in-process via the library — no binary needed to open the
        // window; it is only used to report `renderer_command` when available.
        assert!(!renderer_binary_required(RendererMode::Foreground));
        // None opens no GUI, so the binary is likewise optional.
        assert!(!renderer_binary_required(RendererMode::None));
    }

    #[test]
    fn foreground_default_does_not_require_a_renderer_binary() {
        // The default `launch` (no flags) is Foreground, and Foreground must NOT require a renderer
        // binary before the window can run — that is the whole point of the in-process path.
        let mode = RendererMode::from_flags(false, false);
        assert_eq!(mode, RendererMode::Foreground);
        assert!(!renderer_binary_required(mode));
    }

    #[test]
    fn detach_requires_a_renderer_binary() {
        // `--detach-renderer` is Detached, which still resolves and spawns the child binary, so a
        // missing binary is a hard failure (main.rs returns `binary_not_found`).
        let mode = RendererMode::from_flags(false, true);
        assert_eq!(mode, RendererMode::Detached);
        assert!(renderer_binary_required(mode));
    }

    #[test]
    fn no_run_renderer_does_not_require_a_renderer_binary() {
        // `--no-run-renderer` is None: no GUI, no renderer run, no binary requirement.
        let mode = RendererMode::from_flags(true, false);
        assert_eq!(mode, RendererMode::None);
        assert!(!renderer_binary_required(mode));
    }

    // ---- spawned-daemon keep policy ---------------------------------------------------------

    #[test]
    fn reused_daemon_is_never_killed() {
        // daemon_spawned = false -> kept regardless of mode / keep flag.
        for mode in [
            RendererMode::Foreground,
            RendererMode::Detached,
            RendererMode::None,
        ] {
            assert!(should_keep_spawned_daemon(false, mode, false));
            assert!(should_keep_spawned_daemon(false, mode, true));
        }
    }

    #[test]
    fn spawned_daemon_cleanup_policy() {
        // Foreground / None: spawned daemon cleaned up by default...
        assert!(!should_keep_spawned_daemon(
            true,
            RendererMode::Foreground,
            false
        ));
        assert!(!should_keep_spawned_daemon(true, RendererMode::None, false));
        // ...but kept with --keep-daemon...
        assert!(should_keep_spawned_daemon(
            true,
            RendererMode::Foreground,
            true
        ));
        assert!(should_keep_spawned_daemon(true, RendererMode::None, true));
        // ...and Detached always keeps the spawned daemon (renderer outlives us).
        assert!(should_keep_spawned_daemon(
            true,
            RendererMode::Detached,
            false
        ));
        assert!(should_keep_spawned_daemon(
            true,
            RendererMode::Detached,
            true
        ));
    }

    // ---- owned-socket cleanup policy --------------------------------------------------------

    #[test]
    fn cleanup_policy_only_for_spawned_and_stopped() {
        // Spawned + not kept (we just stopped it) -> the socket is ours to clean up.
        assert!(should_cleanup_owned_socket(true, false));
        // Spawned + kept (--keep-daemon / --detach-renderer) -> still serving, leave it.
        assert!(!should_cleanup_owned_socket(true, true));
        // Reused daemon -> never ours.
        assert!(!should_cleanup_owned_socket(false, false));
        assert!(!should_cleanup_owned_socket(false, true));
    }

    /// A removal recorder so tests can assert whether `remove` was actually invoked.
    fn never_connect(_: &Path) -> bool {
        false
    }
    fn always_connect(_: &Path) -> bool {
        true
    }

    #[test]
    fn cleanup_removes_stale_non_connectable_socket() {
        let removed = std::cell::Cell::new(false);
        let got = cleanup_owned_socket(
            Path::new("/tmp/x.sock"),
            never_connect,
            |_| true, // exists
            |_| {
                removed.set(true);
                Ok(())
            },
        );
        assert_eq!(got, SocketCleanup::Removed);
        assert!(removed.get(), "remove must be called for a stale socket");
    }

    #[test]
    fn cleanup_absent_socket_is_ok_without_remove() {
        let removed = std::cell::Cell::new(false);
        let got = cleanup_owned_socket(
            Path::new("/tmp/x.sock"),
            never_connect,
            |_| false, // absent
            |_| {
                removed.set(true);
                Ok(())
            },
        );
        assert_eq!(got, SocketCleanup::Absent);
        assert!(
            !removed.get(),
            "remove must NOT be called when path is absent"
        );
    }

    #[test]
    fn cleanup_never_removes_a_live_socket() {
        let removed = std::cell::Cell::new(false);
        let got = cleanup_owned_socket(
            Path::new("/tmp/x.sock"),
            always_connect,
            |_| true,
            |_| {
                removed.set(true);
                Ok(())
            },
        );
        assert_eq!(got, SocketCleanup::StillLive);
        assert!(
            !removed.get(),
            "a connectable socket must never be removed (no panic, no delete)"
        );
    }

    #[test]
    fn cleanup_remove_failure_is_non_fatal() {
        let got = cleanup_owned_socket(
            Path::new("/tmp/x.sock"),
            never_connect,
            |_| true,
            |_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "nope",
                ))
            },
        );
        assert_eq!(got, SocketCleanup::RemoveFailed);
    }

    #[test]
    fn cleanup_skipped_entirely_for_reused_keep_and_detach() {
        // These map to should_cleanup_owned_socket == false, so cleanup_owned_socket is never
        // reached. Assert the policy gate the way main.rs uses it.
        // reused daemon:
        assert!(!should_cleanup_owned_socket(false, true));
        // --keep-daemon (spawned, kept):
        assert!(!should_cleanup_owned_socket(true, true));
        // --detach-renderer (spawned, kept): daemon_kept is true in Detached mode.
        assert!(should_keep_spawned_daemon(
            true,
            RendererMode::Detached,
            false
        ));
        assert!(!should_cleanup_owned_socket(true, true));
    }
}
