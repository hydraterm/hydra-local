//! App startup uses one probe deadline. Replacement requires explicit foreground confirmation.
use super::{
    child_log_stdio, ChildLogKind, DaemonClientError, LaunchFailure, ReusedDaemonProtocol,
    SpawnedDaemon, DAEMON_CONNECT_POLL, DAEMON_CONNECT_TIMEOUT,
};
use std::path::Path;
use std::process::{Command as ProcCommand, Stdio};
use std::time::{Duration, Instant};

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod recovery;

type StartupResult = Result<
    (
        Option<SpawnedDaemon>,
        ReusedDaemonProtocol,
        Option<maestro_shell::DaemonClient>,
    ),
    LaunchFailure,
>;

pub(super) fn ensure_daemon(
    socket_path: &Path,
    daemon_bin: &Path,
    log_dir: Option<&Path>,
) -> StartupResult {
    ensure_daemon_before(
        socket_path,
        daemon_bin,
        log_dir,
        Instant::now() + DAEMON_CONNECT_TIMEOUT,
    )
}

fn ensure_daemon_before(
    socket_path: &Path,
    daemon_bin: &Path,
    log_dir: Option<&Path>,
    deadline: Instant,
) -> StartupResult {
    ensure_daemon_impl(socket_path, daemon_bin, log_dir, deadline, None)
}

/// Foreground-only composition supplies the explicit native confirmation. Headless callers retain
/// ensure_daemon's non-destructive behavior and unchanged structured failures.
pub(super) fn ensure_daemon_with_confirmation(
    socket_path: &Path,
    daemon_bin: &Path,
    log_dir: Option<&Path>,
    deadline: Instant,
    confirm: &mut dyn FnMut(&LaunchFailure) -> bool,
) -> StartupResult {
    ensure_daemon_impl(socket_path, daemon_bin, log_dir, deadline, Some(confirm))
}

fn ensure_daemon_impl(
    socket_path: &Path,
    daemon_bin: &Path,
    log_dir: Option<&Path>,
    deadline: Instant,
    confirm: Option<&mut dyn FnMut(&LaunchFailure) -> bool>,
) -> StartupResult {
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let _ = &confirm;
    let retained = match maestro_shell::DaemonClient::connect_before(socket_path, deadline) {
        Ok(client) => Some(client),
        Err(DaemonClientError::DaemonUnavailable { source, .. })
            if matches!(
                source.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            None
        }
        Err(error) => {
            return Err(LaunchFailure::new(
                "daemon_probe_failed",
                format!("could not probe retained daemon: {error}; retained sessions and socket were left untouched"),
            ));
        }
    };
    if let Some(mut client) = retained {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        let recovery = confirm
            .as_ref()
            .map(|_| recovery::RetainedRecovery::capture(&client, socket_path));
        let (protocol_version, build_version) = match client.daemon_info_before(deadline) {
            Ok(info) => info,
            Err(error) => {
                // Legacy daemons predate the additive identity request but speak
                // the existing session/grid protocol. Reuse them so Hydra keeps
                // its tmux-like promise: an app upgrade must not strand or kill
                // live PTYs. New-only features become available after the user
                // naturally drains and restarts that daemon.
                // Keep the CLI's stdout/stderr JSON contract intact. Reuse is the safe action and
                // is intentionally silent here; printing a warning before a structured failure
                // makes machine consumers unable to parse the result.
                if matches!(error, DaemonClientError::DaemonError { .. }) {
                    return Ok((None, ReusedDaemonProtocol::Legacy, Some(client)));
                }
                let failure = LaunchFailure::new(
                    "daemon_probe_failed",
                    format!(
                        "retained daemon did not return an aligned compatibility identity reply: {error}; its sessions were left untouched. Open the original Hydra version to access them"
                    ),
                );
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                if let (Some(recovery), Some(confirm)) = (recovery, confirm) {
                    return recover_or_refuse(
                        socket_path,
                        daemon_bin,
                        log_dir,
                        recovery,
                        failure,
                        confirm,
                    );
                }
                return Err(failure);
            }
        };
        if protocol_version > maestro_protocol::DAEMON_PROTOCOL_VERSION {
            let failure = LaunchFailure::new(
                "stale_daemon",
                format!(
                    "retained daemon protocol {protocol_version} (build {build_version}) is newer than supported protocol {}; its live sessions were left untouched",
                    maestro_protocol::DAEMON_PROTOCOL_VERSION
                ),
            );
            #[cfg(any(target_os = "macos", target_os = "linux"))]
            if let (Some(recovery), Some(confirm)) = (recovery, confirm) {
                return recover_or_refuse(
                    socket_path,
                    daemon_bin,
                    log_dir,
                    recovery,
                    failure,
                    confirm,
                );
            }
            return Err(failure);
        }
        // Older retained daemons remain attach-compatible so an app upgrade never strands or kills
        // their PTYs. ShellRuntime separately requires the exact current mutation protocol before
        // StartSession, making this an attach-only reuse rather than silently applying unsafe old
        // start/reap semantics.
        let retained_client =
            (protocol_version < maestro_protocol::DAEMON_PROTOCOL_VERSION).then_some(client);
        return Ok((
            None,
            ReusedDaemonProtocol::Version(protocol_version),
            retained_client,
        ));
    }

    // Isolate the daemon's streams from ours: its tracing logs must never land on the app's
    // stdout/stderr, which carry only the structured JSON contract. The daemon is a background
    // server with no console role here, so by default null is the right sink; with `--log-dir` its
    // stdout/stderr are captured to deterministic files there instead. stdin is always null.
    let (stdout, stderr) = child_log_stdio(log_dir, ChildLogKind::Daemon)?;
    let child = ProcCommand::new(daemon_bin)
        .arg(socket_path)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .spawn()
        .map_err(|e| {
            LaunchFailure::new(
                "daemon_spawn_failed",
                format!("failed to spawn pty-daemon: {e}"),
            )
        })?;
    let mut spawned = SpawnedDaemon {
        child,
        socket_path: socket_path.to_path_buf(),
        conditional_start_peer: None,
        keep: false,
    };

    while Instant::now() < deadline {
        // If the daemon process died before binding, fail fast instead of waiting out the timeout.
        if let Ok(Some(exit)) = spawned.child.try_wait() {
            return Err(LaunchFailure::new(
                "daemon_spawn_failed",
                format!("pty-daemon exited before accepting connections (status {exit})"),
            ));
        }
        let probe_deadline = deadline.min(Instant::now() + Duration::from_millis(250));
        if let Ok(mut client) =
            maestro_shell::DaemonClient::connect_before(socket_path, probe_deadline)
        {
            if let Ok(identity) = client.conditional_start_peer_identity_before(probe_deadline) {
                #[cfg(target_os = "linux")]
                if identity.server_pid() != Some(spawned.child.id()) {
                    return Err(LaunchFailure::new(
                        "daemon_spawn_failed",
                        "spawned daemon readiness connected to a different kernel peer PID",
                    ));
                }
                spawned.conditional_start_peer = Some(identity);
                return Ok((Some(spawned), ReusedDaemonProtocol::NotReused, None));
            }
        }
        std::thread::sleep(
            DAEMON_CONNECT_POLL.min(deadline.saturating_duration_since(Instant::now())),
        );
    }

    Err(LaunchFailure::new(
        "daemon_unreachable",
        format!(
            "pty-daemon did not accept connections at {} within {:?}",
            socket_path.display(),
            DAEMON_CONNECT_TIMEOUT
        ),
    ))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn recover_or_refuse(
    socket_path: &Path,
    daemon_bin: &Path,
    log_dir: Option<&Path>,
    recovery: std::io::Result<recovery::RetainedRecovery>,
    mut failure: LaunchFailure,
    confirm: &mut dyn FnMut(&LaunchFailure) -> bool,
) -> StartupResult {
    let recovery = match recovery {
        Ok(recovery) => recovery,
        Err(error) => {
            failure
                .message
                .push_str(&format!("\nSafe restart is unavailable: {error}"));
            return Err(failure);
        }
    };
    require_replacement_executable(daemon_bin)?;
    if !confirm(&failure) {
        return Err(failure);
    }
    // The bundle can be moved, removed or lose execute access while the dialog is open.
    // This is a fail-fast check, not an atomic guarantee that the subsequent spawn will succeed.
    require_replacement_executable(daemon_bin)?;
    recovery
        .stop_confirmed(Instant::now() + DAEMON_CONNECT_TIMEOUT)
        .map_err(|error| {
            LaunchFailure::new(
                "daemon_recovery_failed",
                format!("Could not safely restart the terminal service: {error}"),
            )
        })?;
    // A concurrent replacement is subject to the normal identity/retention rules, never killed.
    // Recovery gets no recursive confirmation or automatic retry against a new process.
    ensure_daemon(socket_path, daemon_bin, log_dir)
        .map_err(|error| LaunchFailure::new("daemon_recovery_failed", error.message))
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn require_replacement_executable(daemon_bin: &Path) -> Result<(), LaunchFailure> {
    if crate::launch_preflight::is_executable_file(daemon_bin) {
        return Ok(());
    }
    Err(LaunchFailure::new(
        "daemon_recovery_failed",
        "Restart is unavailable because this Hydra copy's replacement pty-daemon is missing or is not an executable file. The retained terminal service was left running. Reinstall or restore this Hydra app, then try again.",
    ))
}

pub(super) fn restart_unusable_retained_daemon(
    client: &maestro_shell::DaemonClient,
    socket_path: &Path,
    daemon_bin: &Path,
    log_dir: Option<&Path>,
    failure: LaunchFailure,
    confirm: &mut dyn FnMut(&LaunchFailure) -> bool,
) -> StartupResult {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    return recover_or_refuse(
        socket_path,
        daemon_bin,
        log_dir,
        recovery::RetainedRecovery::capture(client, socket_path),
        failure,
        confirm,
    );
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (client, socket_path, daemon_bin, log_dir, confirm);
        Err(failure)
    }
}

#[cfg(test)]
mod tests;
