//! Linux systemd user-unit generator + service planner — the Linux counterpart of `launchd.rs` +
//! the macOS planners in `service.rs`. PURE generation: turns resolved options into the
//! `hydra-agent.service` unit text and into `ServicePlan`s over the same `ServiceAction`
//! vocabulary the executor already runs. It NEVER writes files, calls `systemctl`, expands `~`,
//! or reads the environment — the caller resolves absolute paths and passes them in.
//!
//! Service contract (same as the launchd plist):
//!   <binary> supervise --attach-daemon-only --sock <socket> [--sessions s1[,s2...]]
//! identity (cloud_base/device_id/account) auto-loads from device.json — never passed here,
//! never a secret. The desktop-attached agent retains the established user-manager environment;
//! `MAESTRO_APP_SUPPORT_DIR` is set explicitly so the remote peer reads the same base the desktop
//! app publishes to. The standalone headless daemon instead pins `HOME` to the separately
//! validated passwd home so SSH logout/user-manager inheritance cannot redirect shell startup.

use std::path::{Path, PathBuf};

use crate::service::{ServiceAction, ServicePaths, ServicePlan};

/// Options for the systemd user unit. All paths are ABSOLUTE + already resolved by the caller
/// (no `~`, no env lookups in this module).
#[derive(Debug, Clone)]
pub struct SystemdUnitOptions {
    /// Unit name WITHOUT the `.service` suffix, e.g. `hydra-agent`.
    pub unit_name: String,
    /// Absolute path to the installed `hydra-agent` binary.
    pub binary_path: String,
    /// Public build identity embedded in the unit so same-path binary upgrades invalidate the
    /// exact-definition comparison and restart once.
    pub build_stamp: String,
    /// The independently retained pty-daemon Unix socket the agent attaches to.
    pub socket_path: String,
    /// Never follow a desktop-published daemon endpoint; bind connectivity to `socket_path` exactly.
    pub fixed_external_daemon: bool,
    /// Sessions to ensure exist (empty = browser-created on demand, same as launchd E4).
    pub sessions: Vec<String>,
    /// Absolute log directory (e.g. `~/.local/state/hydra-agent/logs` resolved by the caller).
    pub log_dir: String,
    /// Trusted effective-account home. Emitted only for fixed headless mode;
    /// ordinary desktop service definitions preserve their existing bytes.
    pub home_dir: String,
    /// The desktop app support directory the remote peer must read (daemon endpoint + kill switch).
    pub maestro_app_support_dir: String,
}

/// Exact independent PTY owner for a headless Linux server. This unit has no relationship that can
/// propagate an agent stop/restart into the daemon: retained PTYs live for the daemon process lifetime.
#[derive(Debug, Clone)]
pub struct HeadlessDaemonUnitOptions {
    /// Absolute path to the packaged `pty-daemon` binary.
    pub binary_path: String,
    /// Absolute owner-only Unix socket shared with the attach-only agent service.
    pub socket_path: String,
    /// Absolute log directory under the effective account's trusted state root.
    pub log_dir: String,
    /// Canonical passwd-derived home for every child shell/provider process.
    pub home_dir: String,
    /// Validated passwd-derived executable shell used by headless child processes.
    pub shell_path: String,
}

/// Quote one command-line argument for a systemd `ExecStart=` line. Always double-quotes so
/// spaces survive, C-style-escapes backslash/double-quote, and doubles `%` (a unit-file
/// specifier) so a literal percent can't expand into something else.
fn unit_escape_arg(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '%' => out.push_str("%%"),
            _ => out.push(ch),
        }
    }
    out.push('"');
    out
}

/// Escape a value for an `Environment="KEY=value"` / `StandardOutput=append:...` style setting
/// (specifier `%` doubling only; the caller controls the surrounding quoting).
fn unit_escape_value(s: &str) -> String {
    s.replace('%', "%%")
}

fn decode_canonical_unit_arg(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    if bytes.len() < 2 || bytes.first() != Some(&b'"') || bytes.last() != Some(&b'"') {
        return Err("systemd value is not one quoted argument".to_string());
    }
    let mut out = String::new();
    let mut chars = value[1..value.len() - 1].chars().peekable();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => match chars.next() {
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                _ => return Err("systemd value has a non-canonical escape".to_string()),
            },
            '%' => {
                if chars.next() != Some('%') {
                    return Err("systemd value has an unescaped specifier".to_string());
                }
                out.push('%');
            }
            ch if ch.is_control() => {
                return Err("systemd value contains a control character".to_string())
            }
            ch => out.push(ch),
        }
    }
    if unit_escape_arg(&out) != value {
        return Err("systemd value is not canonically encoded".to_string());
    }
    Ok(out)
}

fn canonical_absolute_runtime_path(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && value.len() <= 4096
        && path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

/// Parse only Hydra's exact standalone daemon unit family, capturing setup-time HOME/SHELL for
/// ordinary convergence or explicit destructive removal after a later `chsh`. The historical
/// SHELL is accepted only when it remains a safe executable; no captured value is executed by this
/// parser. The caller separately proves the package binary, socket, FragmentPath, MainPID, argv,
/// and that `expected_home` is either the current trusted home or the home derived from that loaded
/// FragmentPath during removal.
pub fn parse_headless_daemon_unit_for_removal(
    definition: &str,
    expected_binary: &str,
    expected_socket: &str,
    expected_home: &Path,
) -> Result<HeadlessDaemonUnitOptions, String> {
    let lines = definition.lines().collect::<Vec<_>>();
    if lines.len() != 16
        || lines
            .get(9)
            .is_none_or(|line| !line.starts_with("Environment="))
        || lines
            .get(10)
            .is_none_or(|line| !line.starts_with("Environment="))
    {
        return Err("retained daemon definition is not the reviewed unit shape".to_string());
    }
    let home_entry = decode_canonical_unit_arg(
        lines[9]
            .strip_prefix("Environment=")
            .ok_or_else(|| "retained daemon HOME entry is missing".to_string())?,
    )?;
    let shell_entry = decode_canonical_unit_arg(
        lines[10]
            .strip_prefix("Environment=")
            .ok_or_else(|| "retained daemon SHELL entry is missing".to_string())?,
    )?;
    let home = home_entry
        .strip_prefix("HOME=")
        .ok_or_else(|| "retained daemon HOME entry is invalid".to_string())?;
    let shell = shell_entry
        .strip_prefix("SHELL=")
        .ok_or_else(|| "retained daemon SHELL entry is invalid".to_string())?;
    let shell_is_safe = crate::agent_dir::validate_login_shell(Path::new(shell))
        .map(|validated| validated == shell)
        .unwrap_or(false);
    if !canonical_absolute_runtime_path(home)
        || !canonical_absolute_runtime_path(shell)
        || Path::new(home) == Path::new("/")
        || Path::new(home) != expected_home
        || !shell_is_safe
    {
        return Err("retained daemon account paths are invalid or no longer current".to_string());
    }
    let options = HeadlessDaemonUnitOptions {
        binary_path: expected_binary.to_string(),
        socket_path: expected_socket.to_string(),
        log_dir: expected_home
            .join(".local/state/hydra-agent/logs")
            .to_str()
            .ok_or_else(|| "retained daemon log path is not UTF-8".to_string())?
            .to_string(),
        home_dir: home.to_string(),
        shell_path: shell.to_string(),
    };
    if generate_headless_daemon_unit(&options) != definition {
        return Err(
            "retained daemon definition is not the reviewed server package unit".to_string(),
        );
    }
    Ok(options)
}

/// The `ExecStart=` command line invoking `supervise`, mirroring the launchd ProgramArguments.
fn exec_start(opts: &SystemdUnitOptions) -> String {
    let mut args = vec![
        opts.binary_path.clone(),
        "supervise".to_string(),
        "--attach-daemon-only".to_string(),
    ];
    if opts.fixed_external_daemon {
        args.push("--fixed-daemon-only".to_string());
    }
    args.extend(["--sock".to_string(), opts.socket_path.clone()]);
    // Same E4 rule as launchd: only emit `--sessions s1,s2` when explicitly configured.
    if !opts.sessions.is_empty() {
        args.push("--sessions".to_string());
        args.push(opts.sessions.join(","));
    }
    args.iter()
        .map(|a| unit_escape_arg(a))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Generate the full systemd user unit. Deterministic for fixed options. No secrets.
pub fn generate_systemd_unit(opts: &SystemdUnitOptions) -> String {
    let out_log = unit_escape_value(&format!(
        "{}/agent.out.log",
        opts.log_dir.trim_end_matches('/')
    ));
    let err_log = unit_escape_value(&format!(
        "{}/agent.err.log",
        opts.log_dir.trim_end_matches('/')
    ));
    let maestro_support_env = if opts.maestro_app_support_dir.is_empty() {
        String::new()
    } else {
        format!(
            "Environment=\"MAESTRO_APP_SUPPORT_DIR={}\"\n",
            unit_escape_value(&opts.maestro_app_support_dir)
        )
    };
    let build_stamp_env = if opts.build_stamp.is_empty() {
        String::new()
    } else {
        format!(
            "Environment={}\n",
            unit_escape_arg(&format!("HYDRA_AGENT_BUILD_STAMP={}", opts.build_stamp))
        )
    };
    let fixed_home_env = if opts.fixed_external_daemon {
        format!(
            "Environment={}\n",
            unit_escape_arg(&format!("HOME={}", opts.home_dir))
        )
    } else {
        String::new()
    };
    format!(
        r#"[Unit]
Description=Hydra desktop agent (attaches to retained pty-daemon + supervises remote peer)

[Service]
Type=simple
ExecStart={exec_start}
Restart=on-failure
RestartSec=10
Environment="RUST_LOG=hydra_agent=info"
{fixed_home_env}{maestro_support_env}{build_stamp_env}StandardOutput=append:{out_log}
StandardError=append:{err_log}

[Install]
WantedBy=default.target
"#,
        exec_start = exec_start(opts),
        maestro_support_env = maestro_support_env,
        fixed_home_env = fixed_home_env,
        out_log = out_log,
        err_log = err_log,
    )
}

/// Generate the standalone headless PTY owner. Deliberately no `PartOf=`, `BindsTo=`, `Requires=`, or
/// agent reference: connectivity can be replaced without terminating shells. `Restart=on-failure` does not
/// pretend to serialize processes across a deliberate stop/reboot.
pub fn generate_headless_daemon_unit(opts: &HeadlessDaemonUnitOptions) -> String {
    let exec_start = [opts.binary_path.as_str(), opts.socket_path.as_str()]
        .into_iter()
        .map(unit_escape_arg)
        .collect::<Vec<_>>()
        .join(" ");
    let out_log = unit_escape_value(&format!(
        "{}/daemon.out.log",
        opts.log_dir.trim_end_matches('/')
    ));
    let err_log = unit_escape_value(&format!(
        "{}/daemon.err.log",
        opts.log_dir.trim_end_matches('/')
    ));
    format!(
        r#"[Unit]
Description=Hydra retained terminal daemon (headless server)

[Service]
Type=simple
ExecStart={exec_start}
Restart=on-failure
RestartSec=10
Environment="RUST_LOG=pty_daemon=info"
Environment={home_env}
Environment={shell_env}
StandardOutput=append:{out_log}
StandardError=append:{err_log}

[Install]
WantedBy=default.target
"#,
        home_env = unit_escape_arg(&format!("HOME={}", opts.home_dir)),
        shell_env = unit_escape_arg(&format!("SHELL={}", opts.shell_path)),
    )
}

/// Resolve the default Linux user-service paths. `unit_dir` reuses `ServicePaths.launch_agents_dir`
/// as "the directory the service definition lives in": `~/.config/systemd/user` (or
/// `$XDG_CONFIG_HOME/systemd/user`). Logs go under `~/.local/state/hydra-agent/logs` (or
/// `$XDG_STATE_HOME/hydra-agent/logs`). The caller resolves the XDG bases and passes plain dirs
/// in, keeping this pure; `uid` is unused by systemd user targets but kept so the struct stays
/// shared with the macOS planners.
pub fn default_linux_paths(
    config_home: &Path,
    state_home: &Path,
    agent_dir: &Path,
    unit_name: &str,
) -> ServicePaths {
    ServicePaths {
        launch_agents_dir: config_home.join("systemd").join("user"),
        log_dir: state_home.join("hydra-agent").join("logs"),
        agent_dir: agent_dir.to_path_buf(),
        label: unit_name.to_string(),
        uid: String::new(),
    }
}

/// `<unit_dir>/<unit_name>.service`.
pub fn unit_path(paths: &ServicePaths) -> PathBuf {
    paths
        .launch_agents_dir
        .join(format!("{}.service", paths.label))
}

fn service_arg(paths: &ServicePaths) -> String {
    format!("{}.service", paths.label)
}

fn systemctl_user(args: &[&str]) -> ServiceAction {
    ServiceAction::RunCommand {
        program: crate::headless::SYSTEMCTL_PATH.to_string(),
        args: std::iter::once("--user".to_string())
            .chain(args.iter().map(|s| s.to_string()))
            .collect(),
    }
}

fn systemctl_user_best_effort(args: &[&str]) -> ServiceAction {
    ServiceAction::RunCommandBestEffort {
        program: crate::headless::SYSTEMCTL_PATH.to_string(),
        args: std::iter::once("--user".to_string())
            .chain(args.iter().map(|s| s.to_string()))
            .collect(),
    }
}

/// Plan an install: create dirs, write the unit, reload, enable at login, and (re)start now.
/// The systemd-specific `restart` convergence step makes a re-install pick up a changed unit.
pub fn plan_install(paths: &ServicePaths, unit: &SystemdUnitOptions) -> ServicePlan {
    let unit_contents = generate_systemd_unit(unit);
    let unit_file = unit_path(paths);
    let svc = service_arg(paths);
    ServicePlan {
        title: "install hydra desktop agent (systemd user service)".to_string(),
        actions: vec![
            ServiceAction::CreateDir(paths.launch_agents_dir.clone()),
            ServiceAction::CreatePrivateDir(
                paths
                    .log_dir
                    .parent()
                    .expect("Hydra log directory has an application-owned parent")
                    .to_path_buf(),
            ),
            ServiceAction::CreatePrivateDir(paths.log_dir.clone()),
            ServiceAction::WriteFile {
                path: unit_file,
                contents: unit_contents,
            },
            systemctl_user(&["daemon-reload"]),
            systemctl_user(&["enable", &svc]),
            systemctl_user(&["restart", &svc]),
        ],
    }
}

/// Install the independent daemon without an unconditional restart. Callers must refuse an unexpected existing
/// definition before applying this plan. `enable --now` starts an absent/inactive unit but leaves an already-running
/// exact daemon—and therefore its PTYs—untouched.
pub fn plan_headless_daemon_install(
    paths: &ServicePaths,
    unit: &HeadlessDaemonUnitOptions,
) -> ServicePlan {
    let unit_contents = generate_headless_daemon_unit(unit);
    let unit_file = unit_path(paths);
    let svc = service_arg(paths);
    ServicePlan {
        title: "install Hydra retained terminal daemon (systemd user service)".to_string(),
        actions: vec![
            ServiceAction::CreateDir(paths.launch_agents_dir.clone()),
            ServiceAction::CreatePrivateDir(
                paths
                    .log_dir
                    .parent()
                    .expect("Hydra log directory has an application-owned parent")
                    .to_path_buf(),
            ),
            ServiceAction::CreatePrivateDir(paths.log_dir.clone()),
            ServiceAction::WriteFile {
                path: unit_file,
                contents: unit_contents,
            },
            systemctl_user(&["daemon-reload"]),
            systemctl_user(&["enable", "--now", &svc]),
        ],
    }
}

/// Plan only the systemd half of an uninstall. Identity authority and stable
/// keys are never raw plan actions; the journaled lifecycle engine owns their
/// exact, ordered removal. The `forget` bit remains temporarily for caller API
/// compatibility and cannot change this plan.
pub fn plan_uninstall(paths: &ServicePaths, _forget: bool) -> ServicePlan {
    let svc = service_arg(paths);
    let actions = vec![
        // Missing/inactive is already the desired state. Continue to remove a stale unit and
        // reload the manager even when systemctl reports that there was nothing to stop.
        systemctl_user_best_effort(&["disable", "--now", &svc]),
        ServiceAction::RemoveFile(unit_path(paths)),
        systemctl_user(&["daemon-reload"]),
    ];
    ServicePlan {
        title: "uninstall hydra desktop agent service".to_string(),
        actions,
    }
}

/// First destructive phase for the independent headless PTY owner. This stop is deliberately
/// strict: if systemd cannot stop the reviewed daemon, callers retain its unit bytes and provenance.
pub fn plan_headless_daemon_stop(paths: &ServicePaths) -> ServicePlan {
    let svc = service_arg(paths);
    ServicePlan {
        title: "stop Hydra retained terminal daemon (all server sessions end)".to_string(),
        actions: vec![systemctl_user(&["disable", "--now", &svc])],
    }
}

/// Second destructive phase, called only after MainPID and socket absence have been proved. Keeping
/// definition removal separate prevents a stuck live daemon from losing its reviewed provenance.
pub fn plan_headless_daemon_definition_remove(paths: &ServicePaths) -> ServicePlan {
    ServicePlan {
        title: "remove stopped Hydra retained terminal daemon definition".to_string(),
        actions: vec![
            ServiceAction::RemoveFile(unit_path(paths)),
            systemctl_user(&["daemon-reload"]),
        ],
    }
}

/// Start an existing user unit without replacing a healthy process. `enable --now`
/// is idempotent and also repairs a definition that was present but not enabled for
/// the next login.
pub fn plan_start(paths: &ServicePaths) -> ServicePlan {
    ServicePlan {
        title: "start hydra desktop agent (systemd user service)".to_string(),
        actions: vec![systemctl_user(&["enable", "--now", &service_arg(paths)])],
    }
}

/// Plan a status check: read-only inspects only.
pub fn plan_status(paths: &ServicePaths) -> ServicePlan {
    ServicePlan {
        title: "hydra desktop agent service status".to_string(),
        actions: vec![
            ServiceAction::Inspect(format!("unit exists? {}", unit_path(paths).display())),
            ServiceAction::Inspect(format!("systemctl --user status {}", service_arg(paths))),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::launchd::DEFAULT_CLOUD_PUBKEY;
    use crate::service::{is_mutating, ActionRunner, SystemRunner};

    fn opts() -> SystemdUnitOptions {
        SystemdUnitOptions {
            unit_name: "hydra-agent".to_string(),
            binary_path: "/usr/local/bin/hydra-agent".to_string(),
            build_stamp: "git-test@1700000000000".to_string(),
            socket_path: "/tmp/hydra-maestro-4242.sock".to_string(),
            fixed_external_daemon: false,
            sessions: vec!["s1".to_string()],
            log_dir: "/home/test/home/.local/state/hydra-agent/logs".to_string(),
            home_dir: "/home/test/home".to_string(),
            maestro_app_support_dir: "/home/test/home/.local/share/maestro".to_string(),
        }
    }

    fn paths() -> ServicePaths {
        default_linux_paths(
            Path::new("/home/test/home/.config"),
            Path::new("/home/test/home/.local/state"),
            Path::new("/home/test/home/.local/share/hydra-agent"),
            "hydra-agent",
        )
    }

    fn daemon_opts() -> HeadlessDaemonUnitOptions {
        HeadlessDaemonUnitOptions {
            binary_path: "/opt/hydra/bin/pty-daemon".to_string(),
            socket_path: "/tmp/hydra-maestro-4242.sock".to_string(),
            log_dir: "/home/test/home/.local/state/hydra-agent/logs".to_string(),
            home_dir: "/home/test/home".to_string(),
            shell_path: "/bin/bash".to_string(),
        }
    }

    #[test]
    fn golden_unit_for_fixed_options() {
        let unit = generate_systemd_unit(&opts());
        let expected = r#"[Unit]
Description=Hydra desktop agent (attaches to retained pty-daemon + supervises remote peer)

[Service]
Type=simple
ExecStart="/usr/local/bin/hydra-agent" "supervise" "--attach-daemon-only" "--sock" "/tmp/hydra-maestro-4242.sock" "--sessions" "s1"
Restart=on-failure
RestartSec=10
Environment="RUST_LOG=hydra_agent=info"
Environment="MAESTRO_APP_SUPPORT_DIR=/home/test/home/.local/share/maestro"
Environment="HYDRA_AGENT_BUILD_STAMP=git-test@1700000000000"
StandardOutput=append:/home/test/home/.local/state/hydra-agent/logs/agent.out.log
StandardError=append:/home/test/home/.local/state/hydra-agent/logs/agent.err.log

[Install]
WantedBy=default.target
"#;
        assert_eq!(unit, expected);
    }

    #[test]
    fn golden_headless_daemon_unit_is_independent_and_content_blind() {
        let unit = generate_headless_daemon_unit(&daemon_opts());
        let expected = r#"[Unit]
Description=Hydra retained terminal daemon (headless server)

[Service]
Type=simple
ExecStart="/opt/hydra/bin/pty-daemon" "/tmp/hydra-maestro-4242.sock"
Restart=on-failure
RestartSec=10
Environment="RUST_LOG=pty_daemon=info"
Environment="HOME=/home/test/home"
Environment="SHELL=/bin/bash"
StandardOutput=append:/home/test/home/.local/state/hydra-agent/logs/daemon.out.log
StandardError=append:/home/test/home/.local/state/hydra-agent/logs/daemon.err.log

[Install]
WantedBy=default.target
"#;
        assert_eq!(unit, expected);
        for forbidden in [
            "hydra-agent.service",
            "PartOf=",
            "BindsTo=",
            "Requires=",
            "token",
            "password",
            "private",
            "--cloud",
        ] {
            assert!(
                !unit.contains(forbidden),
                "daemon unit contains {forbidden:?}"
            );
        }
    }

    #[test]
    fn historical_safe_shell_is_accepted_but_daemon_unit_drift_is_rejected() {
        let options = daemon_opts();
        let unit = generate_headless_daemon_unit(&options);
        let parsed = parse_headless_daemon_unit_for_removal(
            &unit,
            &options.binary_path,
            &options.socket_path,
            Path::new(&options.home_dir),
        )
        .expect("a safe setup-time shell remains reviewable after chsh");
        assert_eq!(parsed.shell_path, options.shell_path);

        let drifts = [
            unit.replacen(&options.binary_path, "/opt/hydra/bin/other-daemon", 1),
            unit.replacen(&options.socket_path, "/tmp/other.sock", 1),
            unit.replacen(&options.home_dir, "/home/test/other", 1),
            unit.replacen(&options.log_dir, "/home/test/home/other-logs", 1),
            unit.replacen("SHELL=/bin/bash", "SHELL=/definitely/missing-shell", 1),
            unit.replacen(
                "RestartSec=10\n",
                "RestartSec=10\nPartOf=hydra-agent.service\n",
                1,
            ),
            unit.replacen(
                "Environment=\"HOME=/home/test/home\"",
                "Environment=HOME=/home/test/home",
                1,
            ),
        ];
        for drift in drifts {
            assert!(
                parse_headless_daemon_unit_for_removal(
                    &drift,
                    &options.binary_path,
                    &options.socket_path,
                    Path::new(&options.home_dir),
                )
                .is_err(),
                "one-at-a-time unit drift must fail closed: {drift}"
            );
        }
    }

    #[test]
    fn headless_daemon_removal_is_explicit_and_never_targets_the_agent_unit() {
        let mut daemon_paths = paths();
        daemon_paths.label = "hydra-pty-daemon".to_string();
        let stop = plan_headless_daemon_stop(&daemon_paths);
        let remove = plan_headless_daemon_definition_remove(&daemon_paths);
        let rendered = format!(
            "{}\n{}",
            crate::service::render_plan(&stop),
            crate::service::render_plan(&remove)
        );
        assert!(rendered.contains("hydra-pty-daemon.service"));
        assert!(rendered.contains("all server sessions end"));
        assert!(!rendered.contains("hydra-agent.service"));
        assert!(matches!(
            stop.actions.as_slice(),
            [ServiceAction::RunCommand { program, args }]
                if program == crate::headless::SYSTEMCTL_PATH
                    && args == &["--user", "disable", "--now", "hydra-pty-daemon.service"]
        ));
    }

    #[test]
    fn daemon_stop_failure_cannot_remove_its_reviewed_definition() {
        struct FailingStopRunner {
            removed: bool,
        }
        impl ActionRunner for FailingStopRunner {
            fn create_dir(&mut self, _path: &Path) -> std::io::Result<()> {
                Ok(())
            }
            fn write_file(&mut self, _path: &Path, _contents: &str) -> std::io::Result<()> {
                Ok(())
            }
            fn remove_file(&mut self, _path: &Path) -> std::io::Result<()> {
                self.removed = true;
                Ok(())
            }
            fn run_command(&mut self, _program: &str, _args: &[String]) -> std::io::Result<()> {
                Err(std::io::Error::other("synthetic stop failure"))
            }
            fn inspect(&mut self, what: &str) -> String {
                what.to_string()
            }
        }

        let mut daemon_paths = paths();
        daemon_paths.label = "hydra-pty-daemon".to_string();
        let mut runner = FailingStopRunner { removed: false };
        assert!(crate::service::execute_plan(
            &plan_headless_daemon_stop(&daemon_paths),
            &mut runner
        )
        .is_err());
        assert!(
            !runner.removed,
            "a failed stop cannot delete unit provenance"
        );
    }

    #[test]
    fn fixed_headless_agent_unit_cannot_follow_a_desktop_endpoint() {
        let mut options = opts();
        options.fixed_external_daemon = true;
        let unit = generate_systemd_unit(&options);
        assert_eq!(unit.matches("\"--fixed-daemon-only\"").count(), 1);
        assert_eq!(
            unit.matches("Environment=\"HOME=/home/test/home\"").count(),
            1
        );
        assert!(unit
            .contains("\"supervise\" \"--attach-daemon-only\" \"--fixed-daemon-only\" \"--sock\""));
    }

    #[test]
    fn escapes_spaces_percent_and_quotes_in_paths() {
        let mut o = opts();
        o.binary_path = "/opt/My App/hydra \"agent\" 100%".to_string();
        let unit = generate_systemd_unit(&o);
        assert!(unit.contains(r#""/opt/My App/hydra \"agent\" 100%%""#));
        // a literal single % must never survive unescaped in ExecStart
        assert!(!unit.contains("100%\""));
    }

    #[test]
    fn service_definition_contains_no_runtime_trust_tuple() {
        let rendered = generate_systemd_unit(&opts());
        for forbidden in [
            "--environment",
            "--expected-cloud",
            "--cloud-pubkey",
            "--allowed-origin",
            crate::launchd::DEFAULT_CLOUD_BASE,
            crate::launchd::DEFAULT_ALLOWED_ORIGIN,
            crate::launchd::DEFAULT_CLOUD_PUBKEY,
        ] {
            assert!(!rendered.contains(forbidden));
        }
    }

    #[test]
    fn empty_sessions_omits_the_sessions_flag() {
        let mut o = opts();
        o.sessions = vec![];
        let unit = generate_systemd_unit(&o);
        assert!(!unit.contains("--sessions"));
        assert!(unit.contains(r#""supervise""#));
    }

    #[test]
    fn empty_app_support_dir_omits_the_env_line() {
        let mut o = opts();
        o.maestro_app_support_dir = String::new();
        let unit = generate_systemd_unit(&o);
        assert!(!unit.contains("MAESTRO_APP_SUPPORT_DIR"));
        assert!(unit.contains("RUST_LOG=hydra_agent=info"));
    }

    #[test]
    fn contains_no_secrets() {
        let unit = generate_systemd_unit(&opts()).to_lowercase();
        for bad in [
            "token",
            "secret",
            "private",
            "device-key",
            "bearer",
            "password",
        ] {
            assert!(!unit.contains(bad), "unit must not contain {bad:?}");
        }
        assert!(!generate_systemd_unit(&opts()).contains(DEFAULT_CLOUD_PUBKEY));
    }

    #[test]
    fn default_paths_follow_xdg_layout() {
        let p = paths();
        assert_eq!(
            unit_path(&p),
            PathBuf::from("/home/test/home/.config/systemd/user/hydra-agent.service")
        );
        assert_eq!(
            p.log_dir,
            PathBuf::from("/home/test/home/.local/state/hydra-agent/logs")
        );
    }

    #[test]
    fn install_plan_writes_unit_then_reloads_enables_restarts() {
        let p = paths();
        let plan = plan_install(&p, &opts());
        assert!(plan
            .actions
            .contains(&ServiceAction::CreateDir(p.launch_agents_dir.clone())));
        assert!(plan.actions.contains(&ServiceAction::CreatePrivateDir(
            p.log_dir.parent().unwrap().to_path_buf()
        )));
        assert!(plan
            .actions
            .contains(&ServiceAction::CreatePrivateDir(p.log_dir.clone())));
        let write = plan.actions.iter().find_map(|a| match a {
            ServiceAction::WriteFile { path, contents } => Some((path.clone(), contents.clone())),
            _ => None,
        });
        let (path, contents) = write.expect("a WriteFile action");
        assert_eq!(path, unit_path(&p));
        assert!(contents.contains("[Service]"));
        assert!(contents.contains("supervise"));
        let cmds: Vec<String> = plan
            .actions
            .iter()
            .filter_map(|a| match a {
                ServiceAction::RunCommand { program, args } => {
                    Some(format!("{program} {}", args.join(" ")))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            cmds,
            vec![
                "/bin/systemctl --user daemon-reload",
                "/bin/systemctl --user enable hydra-agent.service",
                "/bin/systemctl --user restart hydra-agent.service",
            ]
        );
    }

    #[test]
    fn headless_daemon_install_never_restarts_a_healthy_daemon() {
        let mut p = paths();
        p.label = "hydra-pty-daemon".to_string();
        let plan = plan_headless_daemon_install(&p, &daemon_opts());
        let commands = plan
            .actions
            .iter()
            .filter_map(|action| match action {
                ServiceAction::RunCommand { program, args } => {
                    Some(format!("{program} {}", args.join(" ")))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            commands,
            vec![
                "/bin/systemctl --user daemon-reload",
                "/bin/systemctl --user enable --now hydra-pty-daemon.service",
            ]
        );
        assert!(!commands.iter().any(|command| command.contains("restart")));
    }

    #[cfg(unix)]
    #[test]
    fn existing_state_and_log_dirs_are_observe_only_while_shared_container_stays_unchanged() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let fixture = tempfile::tempdir().unwrap();
        for mode in [0o770, 0o775, 0o750] {
            let root = fixture.path().join(format!("mode-{mode:o}"));
            let config_home = root.join(".config");
            let state_home = root.join(".local/state");
            let p = default_linux_paths(
                &config_home,
                &state_home,
                &root.join(".local/share/hydra-agent"),
                "hydra-agent",
            );
            let state_dir = p.log_dir.parent().unwrap().to_path_buf();
            std::fs::create_dir_all(&p.launch_agents_dir).unwrap();
            std::fs::set_permissions(&p.launch_agents_dir, std::fs::Permissions::from_mode(0o755))
                .unwrap();
            std::fs::create_dir_all(&p.log_dir).unwrap();
            std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(mode)).unwrap();
            std::fs::set_permissions(&p.log_dir, std::fs::Permissions::from_mode(mode)).unwrap();
            let old_log = p.log_dir.join("agent.out.log");
            std::fs::write(&old_log, b"existing log").unwrap();
            std::fs::set_permissions(&old_log, std::fs::Permissions::from_mode(0o664)).unwrap();
            let state_before = std::fs::symlink_metadata(&state_dir).unwrap();
            let log_before = std::fs::symlink_metadata(&p.log_dir).unwrap();

            let plan = plan_install(&p, &opts());
            let mut runner = SystemRunner;
            let mut private_result = Ok(());
            for action in &plan.actions {
                match action {
                    ServiceAction::CreateDir(path) => runner.create_dir(path).unwrap(),
                    ServiceAction::CreatePrivateDir(path) => {
                        if let Err(error) = runner.create_private_dir(path) {
                            private_result = Err(error);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            assert_eq!(private_result.is_ok(), mode == 0o750);

            assert_eq!(
                std::fs::symlink_metadata(&p.launch_agents_dir)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o755,
                "shared systemd container must not be chmod'd"
            );
            for (directory, before) in [(&state_dir, &state_before), (&p.log_dir, &log_before)] {
                let after = std::fs::symlink_metadata(directory).unwrap();
                assert_eq!(
                    after.permissions().mode() & 0o777,
                    mode,
                    "existing private state/log directory mode must not be rewritten"
                );
                assert_eq!(after.dev(), before.dev());
                assert_eq!(after.ino(), before.ino());
            }
            assert_eq!(std::fs::read(&old_log).unwrap(), b"existing log");
            assert_eq!(
                std::fs::symlink_metadata(old_log)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o664,
                "directory migration must not rewrite existing log metadata"
            );
        }
    }

    #[test]
    fn uninstall_plan_disables_removes_and_reloads() {
        let p = paths();
        let plan = plan_uninstall(&p, false);
        assert!(plan.actions.iter().any(|a| matches!(
            a,
            ServiceAction::RunCommandBestEffort { program, args }
                if program == crate::headless::SYSTEMCTL_PATH && args.contains(&"disable".to_string())
        )));
        assert!(plan
            .actions
            .contains(&ServiceAction::RemoveFile(unit_path(&p))));
        // default uninstall KEEPS identity
        assert!(!plan.actions.iter().any(|a| matches!(
            a,
            ServiceAction::RemoveFile(path)
                if path.ends_with("device.json") || path.ends_with("device-key")
        )));
    }

    #[test]
    fn forget_uninstall_cannot_add_identity_deletion_to_raw_plan() {
        let p = paths();
        let plan = plan_uninstall(&p, true);
        assert!(!plan.actions.iter().any(|action| matches!(
            action,
            ServiceAction::RemoveFile(path)
                if path.ends_with("device.json") || path.ends_with("device-key")
        )));
    }

    #[test]
    fn forget_uninstall_raw_plan_starts_with_service_manager_only() {
        let p = paths();
        let plan = plan_uninstall(&p, true);
        assert!(matches!(
            plan.actions.first(),
            Some(ServiceAction::RunCommandBestEffort { program, .. }) if program == crate::headless::SYSTEMCTL_PATH
        ));
    }

    #[test]
    fn status_plan_is_read_only() {
        let plan = plan_status(&paths());
        assert!(!is_mutating(&plan));
    }

    #[test]
    fn start_plan_is_non_disruptive_and_repairs_login_enablement() {
        assert_eq!(
            plan_start(&paths()).actions,
            vec![ServiceAction::RunCommand {
                program: crate::headless::SYSTEMCTL_PATH.to_string(),
                args: vec![
                    "--user".to_string(),
                    "enable".to_string(),
                    "--now".to_string(),
                    "hydra-agent.service".to_string(),
                ],
            }]
        );
    }
}
