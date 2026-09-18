//! hydra-agent — Hydra desktop enrollment, service, and remote-transport agent.
//!
//! The product path enrolls a desktop, supervises its service/daemon attachment, and connects through
//! outbound signaling plus authenticated WebRTC DataChannels. A PTY over a network is RCE by design,
//! so the agent exposes no retired LAN listener or pairing path.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;

fn main() -> Result<()> {
    // DB-write log net: attribute every store mutation this process makes to "hydra-agent" (the shared store has two
    // writers — this + the desktop app — so every db-write.jsonl line is attributable to which side wrote it).
    maestro_shell::write_trace::set_writer_tag("hydra-agent");
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = std::env::args().collect();
    hydra_agent::release_trust::reject_runtime_overrides(&args)?;
    let cmd = args.get(1).map(String::as_str).unwrap_or("version");
    let dir = match flag(&args, "--dir") {
        Some(path) => PathBuf::from(path),
        None => hydra_agent::agent_dir::default_agent_dir()
            .context("resolve private Hydra agent directory")?,
    };

    match cmd {
        "version" => {
            println!("hydra-agent {}", hydra_agent::build_stamp());
            Ok(())
        }
        "release-binding" => {
            if args.len() != 2 {
                bail!("release-binding accepts no arguments");
            }
            println!("{}", hydra_agent::release_trust::binding_json());
            Ok(())
        }
        // The extension owns its state root. Public launchers cannot redirect
        // enrollment or service authority with `--dir` (or any other argv).
        "extension" => {
            let private_dir = hydra_agent::agent_dir::default_agent_dir()
                .context("resolve private Hydra agent directory")?;
            run_extension_cmd(&args, &private_dir)
        }
        "enroll" => bail!(
            "the enrollment argv interface is unavailable; send a bounded remote_desktop_lifecycle_v1 enroll request to `hydra-agent extension` on stdin"
        ),
        "self-revoke" => run_self_revoke(&dir),
        "remove-remote" => run_remove_remote_cmd(&args, &dir),
        "remote" => run_headless_setup_cmd(&args, &dir),
        "headless" => {
            if args.get(2).map(String::as_str) == Some("remove-daemon") {
                run_headless_daemon_remove_cmd(&args, &dir)
            } else if args.get(2).map(String::as_str) == Some("transfer-owner") {
                run_headless_owner_transfer_cmd(&args, &dir)
            } else {
                run_headless_setup_cmd(&args, &dir)
            }
        }
        #[cfg(feature = "webrtc")]
        "remote-peer" => run_remote_peer_cmd(&args),
        "supervise" => run_supervise_cmd(&args, &dir),
        "service" => run_service_cmd(&args, &dir),
        "health" => run_health_cmd(&args, &dir),
        other => bail!(
            "unknown command {other:?}; use version | release-binding | extension | remote | headless | self-revoke | remove-remote | remote-peer | supervise | service | health"
        ),
    }
}

/// The retained daemon is intentionally outside ordinary agent update/removal. Destroy it only through this
/// long, explicit command after connectivity/enrollment are already absent; every live PTY ends when systemd
/// stops the daemon.
fn run_headless_daemon_remove_cmd(args: &[String], dir: &std::path::Path) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (args, dir);
        bail!("headless server daemon removal is supported only on Linux")
    }
    #[cfg(target_os = "linux")]
    {
        use hydra_agent::service::{execute_plan, SystemRunner};

        if !hydra_agent::headless::daemon_remove_argv_is_valid(args) {
            bail!(
                "removing the retained daemon ends every server session; use `hydraterms headless remove-daemon --apply --confirm-session-loss`"
            )
        }
        let uid = hydra_agent::agent_dir::trusted_uid();
        if uid == 0 {
            bail!("Hydra server daemon removal must run as its non-root session owner")
        }
        if dir != hydra_agent::agent_dir::default_agent_dir()?.as_path() {
            bail!("headless server removal uses only the fixed effective-account state directory")
        }
        hydra_agent::headless::require_linux_user_manager()?;
        let binary = std::env::current_exe()
            .context("resolve packaged Hydra server agent")?
            .canonicalize()
            .context("resolve packaged Hydra server agent path")?;
        hydra_agent::headless::validate_package_binary(&binary, "hydra-agent")?;
        let daemon_binary = binary
            .parent()
            .ok_or_else(|| anyhow::anyhow!("packaged Hydra server agent has no binary directory"))?
            .join("pty-daemon");
        hydra_agent::headless::validate_package_binary(&daemon_binary, "pty-daemon")?;

        let _setup_lock = hydra_agent::headless::SetupLock::acquire(dir)?;
        if hydra_agent::device_identity::load_record(dir)?.is_some() {
            bail!("remove remote connectivity first with `hydraterms remove-remote --apply`")
        }
        let agent_state = systemd_user_unit_state("hydra-agent")?;
        if !systemd_unit_state_proves_absent(&agent_state) {
            bail!("remove the Hydra connectivity service before destroying retained sessions")
        }

        let socket = hydra_agent::headless::daemon_socket_path(uid);
        let state = systemd_user_unit_state(hydra_agent::headless::DAEMON_UNIT_NAME)?;
        let Some(unit_path) = state.fragment_path.clone() else {
            if systemd_unit_state_proves_absent(&state)
                && std::fs::symlink_metadata(&socket)
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
            {
                println!("Hydra retained terminal daemon is already absent.");
                return Ok(());
            }
            bail!("retained terminal daemon state is ambiguous; no process was stopped")
        };
        let home = headless_unit_home_from_fragment(&unit_path)?;
        let daemon_paths = hydra_agent::systemd::default_linux_paths(
            &home.join(".config"),
            &home.join(".local/state"),
            dir,
            hydra_agent::headless::DAEMON_UNIT_NAME,
        );
        if hydra_agent::systemd::unit_path(&daemon_paths) != unit_path {
            bail!(
                "systemd retained-daemon FragmentPath is outside the reviewed account unit location"
            )
        }
        hydra_agent::service::validate_existing_service_definition_for_home(&unit_path, &home)
            .context("validate Hydra retained-daemon unit")?;
        let definition =
            std::fs::read_to_string(&unit_path).context("read Hydra retained-daemon unit")?;
        hydra_agent::systemd::parse_headless_daemon_unit_for_removal(
            &definition,
            daemon_binary
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("packaged daemon path is not UTF-8"))?,
            socket
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("retained socket path is not UTF-8"))?,
            &home,
        )
        .map_err(anyhow::Error::msg)?;
        if !systemd_unit_state_uses_loaded_fragment(&state, &unit_path) {
            bail!("systemd retained-daemon definition is not the exact loaded reviewed unit")
        }
        match (state.active_state.as_str(), state.main_pid) {
            ("active", Some(pid)) => {
                let expected_arguments = vec![
                    daemon_binary.as_os_str().as_encoded_bytes().to_vec(),
                    socket.as_os_str().as_encoded_bytes().to_vec(),
                ];
                if manager_process_arguments(pid)? != expected_arguments {
                    bail!("the active retained daemon is not the reviewed package invocation")
                }
            }
            ("inactive" | "failed", None) => {
                if std::fs::symlink_metadata(&socket).is_ok() {
                    bail!(
                        "an unattributed process owns the retained-daemon socket; nothing was stopped"
                    )
                }
            }
            _ => bail!("retained terminal daemon is transitioning or has ambiguous process state"),
        }

        let mut runner = SystemRunner;
        execute_plan(
            &hydra_agent::systemd::plan_headless_daemon_stop(&daemon_paths),
            &mut runner,
        )
        .context("stop retained terminal daemon")?;
        wait_for_headless_daemon_stopped(&unit_path, &socket, std::time::Duration::from_secs(10))?;
        execute_plan(
            &hydra_agent::systemd::plan_headless_daemon_definition_remove(&daemon_paths),
            &mut runner,
        )
        .context("remove stopped retained-daemon definition")?;
        let final_state = systemd_user_unit_state(hydra_agent::headless::DAEMON_UNIT_NAME)?;
        if !systemd_unit_state_proves_absent(&final_state)
            || !std::fs::symlink_metadata(&unit_path)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
            || !std::fs::symlink_metadata(&socket)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            bail!("retained terminal daemon removal could not prove complete absence")
        }
        println!("Hydra retained terminal daemon removed; all server sessions have ended.");
        Ok(())
    }
}

/// Retire the old headless cloud owner only after the ordinary destructive
/// daemon path has ended every retained PTY and a fresh setup-lock-bound
/// readback proves that no daemon definition, process authority, or socket can
/// survive into the replacement owner. Ordinary `remove-remote` deliberately
/// never reaches this path.
fn run_headless_owner_transfer_cmd(args: &[String], dir: &std::path::Path) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (args, dir);
        bail!("headless server ownership transfer is supported only on Linux")
    }
    #[cfg(target_os = "linux")]
    {
        if !hydra_agent::headless::owner_transfer_argv_is_valid(args) {
            bail!(
                "transferring headless ownership ends every server session and retires the old cloud boundary; use `hydraterms headless transfer-owner --apply --confirm-session-loss --confirm-cloud-ownership-transfer`"
            )
        }

        // Reuse the exact reviewed daemon-removal state machine first. It
        // refuses active enrollment/connectivity, validates the fixed package
        // invocation, stops the sole daemon, removes its unit, and proves the
        // process/socket/definition absent.
        let removal_args = vec![
            args[0].clone(),
            "headless".to_string(),
            "remove-daemon".to_string(),
            "--apply".to_string(),
            "--confirm-session-loss".to_string(),
        ];
        run_headless_daemon_remove_cmd(&removal_args, dir)?;

        // Close the small interval between the completed removal command and
        // the ownership transaction. A competing supported setup must take
        // this same lock. Freshly re-prove the complete daemon absence while
        // retaining it through the final owner deletion.
        let _setup_lock = hydra_agent::headless::SetupLock::acquire(dir)?;
        let uid = hydra_agent::agent_dir::trusted_uid();
        let home = hydra_agent::agent_dir::trusted_home_dir()
            .context("resolve effective OS account home")?;
        let daemon_paths = hydra_agent::systemd::default_linux_paths(
            &home.join(".config"),
            &home.join(".local/state"),
            dir,
            hydra_agent::headless::DAEMON_UNIT_NAME,
        );
        let unit_path = hydra_agent::systemd::unit_path(&daemon_paths);
        let socket = hydra_agent::headless::daemon_socket_path(uid);
        let state = systemd_user_unit_state(hydra_agent::headless::DAEMON_UNIT_NAME)?;
        if !systemd_unit_state_proves_absent(&state)
            || !std::fs::symlink_metadata(&unit_path)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
            || !std::fs::symlink_metadata(&socket)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            bail!("retained terminal daemon reappeared before ownership transfer")
        }

        let (locks, descriptor) = acquire_lifecycle_context_with_owner_transfer(
            dir,
            Some(hydra_agent::lifecycle_cleanup::CleanupIntent::FullForget),
            true,
        )
        .context("capture exact retired headless ownership")?;
        begin_destructive_cleanup_with_owner_transfer(
            dir,
            hydra_agent::lifecycle_cleanup::CleanupIntent::FullForget,
            &descriptor,
            &locks,
            true,
        )?;
        for name in ["device.json", "device-key", "device-owner.json"] {
            if !std::fs::symlink_metadata(dir.join(name))
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
            {
                bail!("headless ownership transfer left local authority behind")
            }
        }
        println!(
            "Hydra headless ownership transferred; all prior sessions and cloud authority are absent."
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn wait_for_headless_daemon_stopped(
    unit_path: &std::path::Path,
    socket: &std::path::Path,
    within: std::time::Duration,
) -> Result<()> {
    let deadline = std::time::Instant::now() + within;
    loop {
        let state = systemd_user_unit_state(hydra_agent::headless::DAEMON_UNIT_NAME)?;
        let socket_absent = std::fs::symlink_metadata(socket)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound);
        if systemd_unit_state_uses_loaded_fragment(&state, unit_path)
            && state.main_pid.is_none()
            && matches!(state.active_state.as_str(), "inactive" | "failed")
            && socket_absent
        {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!("retained terminal daemon did not stop; its reviewed unit was preserved")
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

#[cfg(target_os = "linux")]
fn headless_unit_home_from_fragment(path: &std::path::Path) -> Result<PathBuf> {
    if !hydra_agent::agent_dir::is_canonically_encoded_absolute_path(path)
        || path.file_name().and_then(|value| value.to_str()) != Some("hydra-pty-daemon.service")
    {
        bail!("systemd retained-daemon FragmentPath is invalid")
    }
    let user = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("unit path has no parent"))?;
    let systemd = user
        .parent()
        .ok_or_else(|| anyhow::anyhow!("unit path has no systemd root"))?;
    let config = systemd
        .parent()
        .ok_or_else(|| anyhow::anyhow!("unit path has no config root"))?;
    let home = config
        .parent()
        .ok_or_else(|| anyhow::anyhow!("unit path has no account root"))?;
    if user.file_name().and_then(|value| value.to_str()) != Some("user")
        || systemd.file_name().and_then(|value| value.to_str()) != Some("systemd")
        || config.file_name().and_then(|value| value.to_str()) != Some(".config")
        || home == std::path::Path::new("/")
    {
        bail!("systemd retained-daemon FragmentPath is outside the reviewed account unit location")
    }
    Ok(home.to_path_buf())
}

/// First-class headless Linux enrollment. The public package exposes this as `hydraterms remote`; the
/// implementation spelling remains `hydra-agent headless setup`. Both accept NO enrollment material in argv.
fn run_headless_setup_cmd(args: &[String], dir: &std::path::Path) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (args, dir);
        bail!("headless server enrollment is supported only on Linux")
    }
    #[cfg(target_os = "linux")]
    {
        use hydra_agent::service::{execute_plan, ServicePlan, SystemRunner};

        if !hydra_agent::headless::setup_argv_is_valid(args) {
            bail!(
                "usage: hydraterms remote\nThe enrollment code is requested privately and must not be placed in the command"
            )
        }
        for name in ["HYDRA_ENROLLMENT_CODE", "HYDRA_REMOTE_CODE"] {
            if std::env::var_os(name).is_some() {
                bail!("enrollment-code environment variables are refused; use the hidden prompt")
            }
        }
        let uid = hydra_agent::agent_dir::trusted_uid();
        if uid == 0 {
            bail!(
                "Hydra server access must run as the non-root Unix account that will own its terminal sessions"
            )
        }
        if dir != hydra_agent::agent_dir::default_agent_dir()?.as_path() {
            bail!("headless server setup uses only the fixed effective-account state directory")
        }
        hydra_agent::headless::require_interactive_prompt()?;
        hydra_agent::headless::require_linux_user_manager_and_linger(uid)?;
        hydra_agent::headless::require_process_inventory_tool()?;
        let trust = hydra_agent::release_trust::active().validate()?;
        let binary = std::env::current_exe()
            .context("resolve packaged Hydra server agent")?
            .canonicalize()
            .context("resolve packaged Hydra server agent path")?;
        hydra_agent::headless::validate_package_binary(&binary, "hydra-agent")?;
        let daemon_binary = binary
            .parent()
            .ok_or_else(|| anyhow::anyhow!("packaged Hydra server agent has no binary directory"))?
            .join("pty-daemon");
        hydra_agent::headless::validate_package_binary(&daemon_binary, "pty-daemon")?;

        let _setup_lock = hydra_agent::headless::SetupLock::acquire(dir)?;
        let account = hydra_agent::agent_dir::trusted_session_account()
            .context("validate effective Unix account home and login shell")?;
        let home = account.home;
        let shell = account.shell;
        let socket = hydra_agent::headless::daemon_socket_path(uid);
        let daemon_paths = hydra_agent::systemd::default_linux_paths(
            &home.join(".config"),
            &home.join(".local/state"),
            dir,
            hydra_agent::headless::DAEMON_UNIT_NAME,
        );
        let daemon_options = hydra_agent::systemd::HeadlessDaemonUnitOptions {
            binary_path: daemon_binary
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("packaged daemon path is not UTF-8"))?
                .to_string(),
            socket_path: socket
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("retained socket path is not UTF-8"))?
                .to_string(),
            log_dir: daemon_paths
                .log_dir
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("retained daemon log path is not UTF-8"))?
                .to_string(),
            home_dir: home
                .to_str()
                .ok_or_else(|| anyhow::anyhow!("effective account home is not UTF-8"))?
                .to_string(),
            shell_path: shell,
        };
        let daemon_install =
            hydra_agent::systemd::plan_headless_daemon_install(&daemon_paths, &daemon_options);
        let daemon_unit_path = hydra_agent::systemd::unit_path(&daemon_paths);
        let daemon_manager_state = require_expected_systemd_fragment(
            hydra_agent::headless::DAEMON_UNIT_NAME,
            &daemon_unit_path,
        )?;
        let daemon_plan: ServicePlan = match std::fs::symlink_metadata(&daemon_unit_path) {
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && systemd_unit_state_proves_absent(&daemon_manager_state) =>
            {
                daemon_install
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => bail!(
                "systemd retained a loaded or transitioning Hydra daemon after its reviewed unit file disappeared; no service definition was replaced"
            ),
            Err(error) => return Err(error).context("inspect Hydra retained-daemon unit"),
            Ok(_) => {
                hydra_agent::service::validate_existing_service_definition(&daemon_unit_path)
                    .context("validate Hydra retained-daemon unit")?;
                let actual = std::fs::read_to_string(&daemon_unit_path)
                    .context("read Hydra retained-daemon unit")?;
                hydra_agent::systemd::parse_headless_daemon_unit_for_removal(
                    &actual,
                    daemon_options.binary_path.as_str(),
                    daemon_options.socket_path.as_str(),
                    &home,
                )
                .map_err(anyhow::Error::msg)
                .context(
                    "an existing hydra-pty-daemon.service differs from this reviewed package; refusing to replace a possible live PTY owner",
                )?;
                hydra_agent::systemd::plan_start(&daemon_paths)
            }
        };
        let mut runner = SystemRunner;
        execute_plan(&daemon_plan, &mut runner).context("start retained terminal daemon")?;
        wait_for_headless_daemon_ready(
            &daemon_paths,
            &daemon_binary,
            &socket,
            std::time::Duration::from_secs(10),
        )?;

        // Capture all existing enrollment/service provenance only after the exact daemon is ready. A previous
        // interrupted setup may have left the attach-only supervisor waiting for this socket; it can now recover
        // and answer the existing request-bound readiness proof instead of being misclassified as ambiguous.
        let (lifecycle_locks, mut descriptor) =
            acquire_lifecycle_context(dir, None).context("capture headless remote lifecycle")?;
        descriptor.require_unambiguous()?;
        hydra_agent::remote_access::remove_retired_authority(dir)?;
        let enrolled_before = hydra_agent::device_identity::load_record(dir)?;
        if let Some(record) = enrolled_before.as_ref() {
            trust.validate_enrollment(record)?;
            hydra_agent::device_identity::preserve_owner_marker(dir)?;
        } else {
            descriptor =
                prepare_connectivity_closed_for_enrollment(dir, &descriptor, &lifecycle_locks)
                    .context("retire previous remote connectivity before server enrollment")?;
            let hostname = hostname_fallback();
            let label = hydra_agent::headless::server_device_label(hostname.as_deref());
            let code = hydra_agent::headless::read_enrollment_code()?;
            hydra_agent::device_identity::enroll_with_code_with_diagnostics(
                dir,
                trust.cloud_base,
                code.as_str(),
                &label,
                &lifecycle_locks,
                None,
            )
            .context("server enrollment was rejected")?;
            // `code` is cleared by Drop immediately after this branch.
        }

        let activation = (|| -> Result<()> {
            let prior_state = extension_service_activation_prior_state(&descriptor)?;
            ensure_extension_service(dir, prior_state, &descriptor, &lifecycle_locks)
                .context("start headless connectivity service")?;
            wait_for_headless_daemon_ready(
                &daemon_paths,
                &daemon_binary,
                &socket,
                std::time::Duration::from_secs(2),
            )?;
            let current = recapture_lifecycle_descriptor_under_locks(dir, &lifecycle_locks)?;
            if !extension_service_is_open(dir, &current)? {
                bail!(
                    "Hydra server enrollment is present but the remote service did not become ready; rerun `hydraterms remote` to resume"
                )
            }
            Ok(())
        })();
        activation?;
        println!("Hydra server is ready. Open {}", trust.allowed_origin);
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn wait_for_headless_daemon_ready(
    paths: &hydra_agent::service::ServicePaths,
    daemon_binary: &std::path::Path,
    socket: &std::path::Path,
    timeout: std::time::Duration,
) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let state = systemd_user_unit_state(&paths.label)?;
        let expected_fragment = hydra_agent::systemd::unit_path(paths);
        if state.fragment_path.as_deref() != Some(expected_fragment.as_path())
            || state.load_state != "loaded"
            || state.unit_file_state != "enabled"
        {
            bail!("the retained terminal daemon is not loaded from the reviewed enabled unit")
        }
        if state.active_state == "active" {
            let manager_pid = state.main_pid.ok_or_else(|| {
                anyhow::anyhow!("the active retained terminal daemon has no MainPID")
            })?;
            let expected_arguments = vec![
                daemon_binary.as_os_str().as_encoded_bytes().to_vec(),
                socket.as_os_str().as_encoded_bytes().to_vec(),
            ];
            if manager_process_arguments(manager_pid)? != expected_arguments {
                bail!(
                    "the retained terminal daemon process differs from the reviewed package invocation"
                )
            }
            if let Ok(mut client) = maestro_shell::DaemonClient::connect(socket) {
                let protocol_ready = client.daemon_capabilities().is_ok_and(
                    |(
                        version,
                        _,
                        _,
                        child_environment,
                        generation_conditional_mutations,
                        attachment_aware_conditional_kill,
                        generation_conditional_start,
                        start_operation_ledger,
                        // Optional input-operation capabilities are not headless readiness gates.
                        ..,
                        generation_conditional_attach,
                        daemon_instance_id,
                    )| {
                        version == maestro_protocol::DAEMON_PROTOCOL_VERSION
                            && child_environment
                            && generation_conditional_mutations
                            && attachment_aware_conditional_kill
                            && generation_conditional_start
                            && start_operation_ledger
                            && generation_conditional_attach
                            && daemon_instance_id.is_some()
                    },
                ) && client.list_sessions().is_ok();
                if client.server_pid() == Some(manager_pid) && protocol_ready {
                    return Ok(());
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            bail!("the retained terminal daemon did not become ready")
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

fn run_extension_cmd(args: &[String], dir: &std::path::Path) -> Result<()> {
    validate_extension_argv(args)?;
    use std::io::BufReader;
    let diagnostic_deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(24))
        .unwrap_or_else(std::time::Instant::now);

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();

    // Phase 1: no lifecycle frame can be decoded until the public hello has
    // negotiated the exact public capability contract.
    let host_hello_frame = hydra_agent::extension::read_frame(&mut reader)
        .map_err(|_| anyhow::anyhow!("extension hello refused"))?;
    let host_hello = hydra_agent::extension::decode_host_hello(&host_hello_frame)
        .map_err(|_| anyhow::anyhow!("extension hello refused"))?;
    hydra_agent::extension::write_frame(&mut writer, &hydra_agent::extension::extension_hello())
        .map_err(|_| anyhow::anyhow!("extension hello response failed"))?;
    let exchange = hydra_agent::extension::LifecycleExchange::negotiate(&host_hello)
        .map_err(|_| anyhow::anyhow!("extension negotiation refused"))?;

    // Phase 2: exactly one bounded request and one public typed response.
    let request_frame = hydra_agent::extension::read_frame(&mut reader)
        .map_err(|_| anyhow::anyhow!("extension request refused"))?;
    let request = exchange
        .decode_request(&request_frame)
        .map_err(|_| anyhow::anyhow!("extension request refused"))?;
    hydra_agent::extension::require_eof(&mut reader)
        .map_err(|_| anyhow::anyhow!("extension request refused"))?;
    let response = execute_extension_request(
        request,
        dir,
        exchange.supports_filesystem_mode_migration(),
        exchange.supports_enrollment_failure(),
        diagnostic_deadline,
    );
    hydra_agent::extension::write_frame(&mut writer, &response)
        .map_err(|_| anyhow::anyhow!("extension response failed"))
}

fn validate_extension_argv(args: &[String]) -> Result<()> {
    if args.len() != 2 || args.get(1).map(String::as_str) != Some("extension") {
        bail!("extension accepts no runtime arguments; requests are read from stdin")
    }
    Ok(())
}

fn commit_filesystem_ack_before_lifecycle<T>(
    commit_acknowledgement: impl FnOnce() -> std::io::Result<()>,
    continue_lifecycle: impl FnOnce() -> T,
) -> std::io::Result<T> {
    commit_acknowledgement()?;
    Ok(continue_lifecycle())
}

fn lifecycle_preflight_error_response(
    request_id: maestro_extension_api::RemoteDesktopRequestId,
    error: &anyhow::Error,
) -> maestro_extension_api::RemoteDesktopExtensionResponse {
    use maestro_extension_api::RemoteDesktopErrorCode as Code;

    let lock_contended = error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(hydra_agent::service::is_lifecycle_lock_contention)
    });
    if lock_contended {
        extension_error(
            request_id,
            Code::Busy,
            "remote desktop lifecycle is unavailable",
            true,
        )
    } else {
        extension_error(
            request_id,
            Code::Internal,
            "remote desktop lifecycle could not be verified",
            false,
        )
    }
}

fn execute_extension_request(
    request: maestro_extension_api::RemoteDesktopHostRequest,
    dir: &std::path::Path,
    supports_filesystem_mode_migration: bool,
    supports_enrollment_failure: bool,
    diagnostic_deadline: std::time::Instant,
) -> maestro_extension_api::RemoteDesktopExtensionResponse {
    use maestro_extension_api::{
        RemoteDesktopErrorCode as Code, RemoteDesktopHostRequest as Request,
    };

    let request_id = request.request_id();
    if !extension_request_uses_lifecycle_preflight(&request) {
        return hydra_agent::viewport_control::request(dir, &request).unwrap_or_else(|_| {
            extension_error(
                request_id,
                Code::ViewportUnavailable,
                "remote viewport service is unavailable",
                true,
            )
        });
    }
    // The legacy Linux 0.2.8 leaf is intentionally unsafe for LifecycleLock. Status and every
    // ordinary lifecycle request must therefore probe before establishing the root or taking that
    // lock. Only the exact ID-only Apply request may enter the receipt-backed migration path.
    let mut pending_filesystem_acknowledgement = None;
    match &request {
        Request::ApplyFilesystemModeMigration { notice_id, .. } => {
            return match hydra_agent::authority_migration::apply(
                notice_id,
                verify_legacy_authority_migration_service,
            ) {
                Ok(notice) => {
                    maestro_extension_api::RemoteDesktopExtensionResponse::FilesystemModeMigration {
                        request_id,
                        notice,
                        status: None,
                    }
                }
                Err(failure) => match failure.notice().cloned() {
                    Some(notice) => {
                        maestro_extension_api::RemoteDesktopExtensionResponse::FilesystemModeMigration {
                            request_id,
                            notice,
                            status: None,
                        }
                    }
                    None => extension_error(
                        request_id,
                        Code::Internal,
                        "filesystem security migration could not start",
                        false,
                    ),
                },
            };
        }
        Request::AcknowledgeFilesystemModeMigration { notice_id, .. } => {
            // The receipt binds the exact legacy unit inode and bytes. Remove it at the mode-
            // migration acknowledgement boundary before lifecycle_status is allowed to replace
            // that unit. A crash after this unlink leaves service convergence fail-closed and
            // retryable on the next Status; retaining the receipt across replacement would instead
            // leave an intentionally stale binding that no retry could satisfy.
            let prepared = match hydra_agent::authority_migration::prepare_acknowledgement(
                notice_id,
                verify_legacy_authority_migration_service,
            ) {
                Ok(prepared) => prepared,
                Err(_) => {
                    return extension_error(
                        request_id,
                        Code::Internal,
                        "filesystem security acknowledgement was refused",
                        false,
                    );
                }
            };
            pending_filesystem_acknowledgement = Some(prepared);
        }
        _ => {
            if let Some(response) = migration_probe_response(
                request_id,
                supports_filesystem_mode_migration,
                hydra_agent::authority_migration::probe(verify_legacy_authority_migration_service),
            ) {
                return response;
            }
        }
    }
    let requested_cleanup = match &request {
        Request::RemoveEnrollment { .. } => {
            Some(hydra_agent::lifecycle_cleanup::CleanupIntent::Remove)
        }
        _ => None,
    };
    let lifecycle_context = match pending_filesystem_acknowledgement {
        Some(prepared) => match commit_filesystem_ack_before_lifecycle(
            || prepared.commit(),
            || acquire_lifecycle_context(dir, requested_cleanup),
        ) {
            Ok(context) => context,
            Err(_) => {
                return extension_error(
                    request_id,
                    Code::Internal,
                    "filesystem security acknowledgement was refused",
                    false,
                );
            }
        },
        None => acquire_lifecycle_context(dir, requested_cleanup),
    };
    let (lifecycle_locks, descriptor) = match lifecycle_context {
        Ok(context) => context,
        Err(error) => return lifecycle_preflight_error_response(request_id, &error),
    };

    let result: std::result::Result<_, LifecycleFailure> = match request {
        Request::Status { request_id } => lifecycle_status(dir, &descriptor, &lifecycle_locks)
            .map(
                |status| maestro_extension_api::RemoteDesktopExtensionResponse::Status {
                    request_id,
                    status,
                },
            )
            .map_err(|_| LifecycleFailure::internal()),
        Request::Enroll { request_id, code } => extension_enroll(
            dir,
            code.as_str(),
            &descriptor,
            &lifecycle_locks,
            supports_enrollment_failure,
            diagnostic_deadline,
        )
            .and_then(|()| {
                recaptured_lifecycle_status(dir, &lifecycle_locks)
                    .map(
                        |status| maestro_extension_api::RemoteDesktopExtensionResponse::Enrolled {
                            request_id,
                            status,
                        },
                    )
                    .map_err(|_| LifecycleFailure::internal())
            }),
        Request::SetRemoteOpen { request_id, open } => {
            extension_set_remote_open(dir, open, &descriptor, &lifecycle_locks).and_then(|()| {
                recaptured_lifecycle_status(dir, &lifecycle_locks)
                    .map(|status| {
                        maestro_extension_api::RemoteDesktopExtensionResponse::RemoteOpenSet {
                            request_id,
                            status,
                        }
                    })
                    .map_err(|_| LifecycleFailure::internal())
            })
        }
        Request::RemoveEnrollment { request_id } => extension_remove_enrollment(
            dir,
            &descriptor,
            &lifecycle_locks,
        )
            .map_err(|_| LifecycleFailure::remote_unavailable())
            .and_then(|()| {
                lifecycle_status(dir, &descriptor, &lifecycle_locks)
                    .map(|status| {
                        maestro_extension_api::RemoteDesktopExtensionResponse::EnrollmentRemoved {
                            request_id,
                            status,
                        }
                    })
                    .map_err(|_| LifecycleFailure::internal())
            }),
        Request::AcknowledgeFilesystemModeMigration { request_id, .. } => {
            lifecycle_status(dir, &descriptor, &lifecycle_locks)
                .map_err(|_| LifecycleFailure::internal())
                .map(|status| {
                    maestro_extension_api::RemoteDesktopExtensionResponse::FilesystemModeMigrationAcknowledged {
                        request_id,
                        status,
                    }
                })
        }
        Request::ApplyFilesystemModeMigration { .. } => {
            unreachable!("filesystem migration requests return before lifecycle preflight")
        }
        Request::SnapshotViewports { .. } | Request::ReclaimViewport { .. } => unreachable!(
            "typed viewport requests return through the live private control socket above"
        ),
    };

    result.unwrap_or_else(|failure| {
        extension_error(request_id, failure.code, failure.message, failure.retryable)
    })
}

#[cfg(target_os = "linux")]
fn verify_legacy_authority_migration_service(
    trusted_home: &std::path::Path,
    authority_root: &std::path::Path,
) -> std::io::Result<()> {
    let result = (|| -> Result<()> {
        let paths = hydra_agent::systemd::default_linux_paths(
            &trusted_home.join(".config"),
            &trusted_home.join(".local/state"),
            authority_root,
            "hydra-agent",
        );
        let service_file = hydra_agent::systemd::unit_path(&paths);
        let manager = systemd_user_unit_state("hydra-agent")?;
        let bytes = hydra_agent::service::read_legacy_028_service_candidate_for_home(
            &service_file,
            trusted_home,
        )?
        .ok_or_else(|| anyhow::anyhow!("published 0.2.8 service definition is absent"))?;
        verify_legacy_authority_migration_service_evidence(
            trusted_home,
            authority_root,
            manager.fragment_path.as_deref(),
            &bytes,
        )
    })();
    result.map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("Hydra 0.2.8 service provenance is unverified: {error:#}"),
        )
    })
}

#[cfg(any(target_os = "linux", test))]
fn verify_legacy_authority_migration_service_evidence(
    trusted_home: &std::path::Path,
    authority_root: &std::path::Path,
    observed_fragment_path: Option<&std::path::Path>,
    service_definition: &[u8],
) -> Result<()> {
    let paths = hydra_agent::systemd::default_linux_paths(
        &trusted_home.join(".config"),
        &trusted_home.join(".local/state"),
        authority_root,
        "hydra-agent",
    );
    let expected_service_file = hydra_agent::systemd::unit_path(&paths);
    if observed_fragment_path != Some(expected_service_file.as_path()) {
        bail!("systemd FragmentPath is not the fixed published 0.2.8 unit");
    }
    let parsed = parse_full_systemd_service_definition(service_definition)?;
    if parsed.invocation.agent_dir.as_deref() != Some(authority_root)
        || parsed.invocation.legacy_trust.is_none()
        || parsed.binary_path != "/opt/hydra/bin/hydra-agent"
        || parsed.app_support_dir
            != trusted_home
                .join(".local/share/maestro-dev")
                .to_string_lossy()
        || parsed.log_dir
            != trusted_home
                .join(".local/state/hydra-agent/logs")
                .to_string_lossy()
    {
        bail!("installed service is not the exact published 0.2.8 authority owner");
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_legacy_authority_migration_service(
    _trusted_home: &std::path::Path,
    _authority_root: &std::path::Path,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Linux 0.2.8 authority migration is unavailable on this platform",
    ))
}

fn migration_probe_response(
    request_id: maestro_extension_api::RemoteDesktopRequestId,
    supports_filesystem_mode_migration: bool,
    probe: std::io::Result<Option<maestro_extension_api::FilesystemModeMigrationNotice>>,
) -> Option<maestro_extension_api::RemoteDesktopExtensionResponse> {
    use maestro_extension_api::{RemoteDesktopErrorCode as Code, RemoteDesktopExtensionResponse};

    match probe {
        Ok(None) => None,
        Ok(Some(notice)) if supports_filesystem_mode_migration => {
            Some(RemoteDesktopExtensionResponse::FilesystemModeMigration {
                request_id,
                notice,
                status: None,
            })
        }
        Ok(Some(_)) => Some(extension_error(
            request_id,
            Code::Internal,
            "filesystem security requires a compatible Hydra desktop",
            false,
        )),
        Err(_) => Some(extension_error(
            request_id,
            Code::Internal,
            "filesystem security state could not be verified",
            false,
        )),
    }
}

fn extension_request_uses_lifecycle_preflight(
    request: &maestro_extension_api::RemoteDesktopHostRequest,
) -> bool {
    !matches!(
        request,
        maestro_extension_api::RemoteDesktopHostRequest::SnapshotViewports { .. }
            | maestro_extension_api::RemoteDesktopHostRequest::ReclaimViewport { .. }
    )
}

/// The exact production preflight for every lifecycle request. This must run
/// before legacy-source discovery because that discovery canonicalizes the
/// root while building the deterministic multi-root lock set.
fn establish_extension_canonical_root(dir: &std::path::Path) -> Result<PathBuf> {
    hydra_agent::agent_dir::ensure_owned_safe_authority_directory(dir)
        .context("create or validate remote desktop state directory")?;
    std::fs::canonicalize(dir).context("resolve remote desktop state directory")
}

fn acquire_lifecycle_context(
    dir: &std::path::Path,
    requested_intent: Option<hydra_agent::lifecycle_cleanup::CleanupIntent>,
) -> Result<(hydra_agent::service::LifecycleLockSet, LifecycleDescriptor)> {
    acquire_lifecycle_context_with_owner_transfer(dir, requested_intent, false)
}

fn acquire_lifecycle_context_with_owner_transfer(
    dir: &std::path::Path,
    requested_intent: Option<hydra_agent::lifecycle_cleanup::CleanupIntent>,
    allow_owner_transfer_resume: bool,
) -> Result<(hydra_agent::service::LifecycleLockSet, LifecycleDescriptor)> {
    establish_extension_canonical_root(dir)?;

    // Recovery evidence, not ambient discovery, owns the exact lock set after
    // the first destructive step. Resume it before examining current service
    // files because some of those files may already be durably absent.
    if let Some(expected) = hydra_agent::lifecycle_cleanup::load(dir)? {
        if expected.retires_owner_marker() && !allow_owner_transfer_resume {
            bail!(
                "pending headless ownership transfer must be resumed with the exact `hydraterms headless transfer-owner --apply --confirm-session-loss --confirm-cloud-ownership-transfer` command"
            )
        }
        if allow_owner_transfer_resume
            && (!expected.retires_owner_marker()
                || requested_intent
                    != Some(hydra_agent::lifecycle_cleanup::CleanupIntent::FullForget))
        {
            bail!("headless ownership-transfer resume is not bound to its exact lifecycle state")
        }
        let roots = expected.lock_roots()?;
        let locks = hydra_agent::service::LifecycleLockSet::acquire(roots)?;
        let mut readback = hydra_agent::lifecycle_cleanup::load(dir)?
            .ok_or_else(|| anyhow::anyhow!("pending lifecycle journal disappeared"))?;
        if readback != expected {
            bail!("pending lifecycle journal changed while its locks were acquired");
        }
        if let Some(requested) = requested_intent {
            if requested != readback.intent() {
                if hydra_agent::lifecycle_cleanup::may_supersede(readback.intent(), requested)
                    && readback.intent() == hydra_agent::lifecycle_cleanup::CleanupIntent::Remove
                    && requested == hydra_agent::lifecycle_cleanup::CleanupIntent::FullForget
                {
                    readback = hydra_agent::lifecycle_cleanup::supersede_remove_with_full_forget(
                        dir, &locks,
                    )?;
                } else {
                    bail!(
                        "pending {:?} lifecycle cleanup cannot be replaced by {:?}",
                        readback.intent(),
                        requested
                    );
                }
            }
        }
        drive_destructive_cleanup(dir, readback, &locks)?;
        drop(locks);
    }

    let legacy_source = extension_proven_legacy_agent_dir(dir)?;
    let candidate_roots =
        hydra_agent::enrollment_migration::adoption_lock_roots(dir, legacy_source.as_deref())?;
    let locks = hydra_agent::service::LifecycleLockSet::acquire(candidate_roots)?;
    let recaptured_legacy_source = extension_proven_legacy_agent_dir(dir)?;
    let recaptured_roots = hydra_agent::enrollment_migration::adoption_lock_roots(
        dir,
        recaptured_legacy_source.as_deref(),
    )?;
    if recaptured_roots != locks.roots().map(std::path::Path::to_path_buf).collect() {
        bail!("remote desktop lifecycle changed while it was being locked");
    }
    let canonical_lock = locks.lock_for(dir)?;
    hydra_agent::enrollment_migration::adopt_proven_legacy_xdg_enrollment(
        dir,
        recaptured_legacy_source.as_deref(),
        &locks,
    )?;
    let descriptor = capture_lifecycle_descriptor(dir, canonical_lock)?;
    let _ = retry_one_provider_revocation(dir, &locks)?;
    Ok((locks, descriptor))
}

#[derive(Clone, Copy)]
struct LifecycleFailure {
    code: maestro_extension_api::RemoteDesktopErrorCode,
    message: &'static str,
    retryable: bool,
}

impl LifecycleFailure {
    fn internal() -> Self {
        Self {
            code: maestro_extension_api::RemoteDesktopErrorCode::Internal,
            message: "remote desktop operation failed",
            retryable: false,
        }
    }

    fn remote_unavailable() -> Self {
        Self {
            code: maestro_extension_api::RemoteDesktopErrorCode::RemoteUnavailable,
            message: "remote desktop service is unavailable",
            retryable: true,
        }
    }

    fn re_enrollment_required(message: &'static str) -> Self {
        Self {
            code: maestro_extension_api::RemoteDesktopErrorCode::RemoteUnavailable,
            message,
            retryable: false,
        }
    }
}

fn extension_error(
    request_id: maestro_extension_api::RemoteDesktopRequestId,
    code: maestro_extension_api::RemoteDesktopErrorCode,
    message: &'static str,
    retryable: bool,
) -> maestro_extension_api::RemoteDesktopExtensionResponse {
    let error = maestro_extension_api::RemoteDesktopResponseError::new(code, message, retryable)
        .expect("fixed private lifecycle errors satisfy the public bound");
    maestro_extension_api::RemoteDesktopExtensionResponse::Error { request_id, error }
}

fn extension_enroll(
    dir: &std::path::Path,
    enrollment_code: &str,
    descriptor: &LifecycleDescriptor,
    lifecycle_locks: &hydra_agent::service::LifecycleLockSet,
    supports_enrollment_failure: bool,
    diagnostic_deadline: std::time::Instant,
) -> std::result::Result<(), LifecycleFailure> {
    use maestro_extension_api::RemoteDesktopErrorCode as Code;

    // Refuse ambiguous service/process provenance before consuming the one-time
    // enrollment code or creating any local authority. The descriptor was
    // captured under the same lifecycle lock set held through this request.
    descriptor
        .require_unambiguous()
        .map_err(|_| LifecycleFailure::internal())?;
    hydra_agent::remote_access::remove_retired_authority(dir)
        .map_err(|_| LifecycleFailure::internal())?;
    if hydra_agent::device_identity::load_record(dir)
        .map_err(|_| LifecycleFailure::internal())?
        .is_some()
    {
        return Err(LifecycleFailure {
            code: Code::AlreadyEnrolled,
            message: "this desktop is already enrolled",
            retryable: false,
        });
    }
    let descriptor = prepare_connectivity_closed_for_enrollment(dir, descriptor, lifecycle_locks)
        .map_err(|_| LifecycleFailure::internal())?;
    let trust = hydra_agent::release_trust::active()
        .validate()
        .map_err(|_| LifecycleFailure::internal())?;
    hydra_agent::device_identity::enroll_with_code_with_diagnostics(
        dir,
        trust.cloud_base,
        enrollment_code,
        &default_device_label(),
        lifecycle_locks,
        Some(diagnostic_deadline),
    )
    .map_err(|failure| enrollment_lifecycle_failure(failure.kind(), supports_enrollment_failure))?;

    if ensure_extension_service(
        dir,
        ServiceActivationPriorState::Closed,
        &descriptor,
        lifecycle_locks,
    )
    .is_err()
    {
        // The code was consumed. First run the journaled provider/service/local
        // cleanup. If that path fails, durably queue the exact provider target
        // and cut the replaceable local record directly under the same lock.
        // Never discard a cleanup failure or leave the new enrollment live.
        let (failure, activation_outcome) = failed_activation_cleanup_result(
            fail_closed_failed_enrollment_activation(dir, lifecycle_locks),
        );
        hydra_agent::device_identity::record_enrollment_activation_terminal(
            dir,
            lifecycle_locks,
            activation_outcome,
            Some(diagnostic_deadline),
        );
        return Err(failure);
    }
    hydra_agent::device_identity::record_enrollment_activation_terminal(
        dir,
        lifecycle_locks,
        hydra_agent::device_identity::EnrollmentActivationOutcome::Ready,
        Some(diagnostic_deadline),
    );
    Ok(())
}

/// A fresh enrollment must never be activated through a connectivity process
/// that cached the previous account/device at process start. If an otherwise
/// exact old service is still present or open after its enrollment record was
/// removed, retire only that connectivity service and its remote peer through
/// the normal journaled Remove path. The independently owned PTY daemon and its
/// sessions are outside that cleanup proof and remain running.
fn prepare_connectivity_closed_for_enrollment(
    dir: &std::path::Path,
    descriptor: &LifecycleDescriptor,
    lifecycle_locks: &hydra_agent::service::LifecycleLockSet,
) -> Result<LifecycleDescriptor> {
    lifecycle_locks.require_agent_dir(dir)?;
    if hydra_agent::device_identity::load_record(dir)?.is_some() {
        bail!("active enrollment must be removed before fresh enrollment");
    }
    converge_connectivity_closed_for_enrollment(descriptor, || {
        begin_destructive_cleanup(
            dir,
            hydra_agent::lifecycle_cleanup::CleanupIntent::Remove,
            descriptor,
            lifecycle_locks,
        )?;
        recapture_lifecycle_descriptor_under_locks(dir, lifecycle_locks)
    })
}

fn converge_connectivity_closed_for_enrollment(
    descriptor: &LifecycleDescriptor,
    close_connectivity: impl FnOnce() -> Result<LifecycleDescriptor>,
) -> Result<LifecycleDescriptor> {
    descriptor.require_unambiguous()?;
    let current = match descriptor.activation_state {
        ServiceActivationPriorState::Closed => descriptor.clone(),
        // An exact but dormant service definition (launchd unloaded on macOS,
        // or an enabled/inactive systemd unit on Linux) is intentionally not
        // classified as Closed: a manager could still activate it. Once the
        // descriptor's provenance is otherwise unambiguous, retire that state
        // through the same exact journaled Remove proof as a live service.
        ServiceActivationPriorState::ProvenOpen | ServiceActivationPriorState::Ambiguous => {
            close_connectivity()
                .context("stop the previous remote connectivity service and peer")?
        }
    };
    current.require_unambiguous()?;
    if current.activation_state != ServiceActivationPriorState::Closed {
        bail!("remote connectivity remained open after retirement");
    }
    Ok(current)
}

fn failed_activation_cleanup_result(
    cleanup: Result<()>,
) -> (
    LifecycleFailure,
    hydra_agent::device_identity::EnrollmentActivationOutcome,
) {
    match cleanup {
        Ok(()) => (
            LifecycleFailure::remote_unavailable(),
            hydra_agent::device_identity::EnrollmentActivationOutcome::FailedClosed,
        ),
        Err(_) => (
            LifecycleFailure::internal(),
            hydra_agent::device_identity::EnrollmentActivationOutcome::CleanupIncomplete,
        ),
    }
}

fn enrollment_lifecycle_failure(
    kind: hydra_agent::device_identity::EnrollmentFailureKind,
    supports_enrollment_failure: bool,
) -> LifecycleFailure {
    use hydra_agent::device_identity::EnrollmentFailureKind as Kind;
    use maestro_extension_api::RemoteDesktopErrorCode as Code;

    if !supports_enrollment_failure {
        return match kind {
            Kind::CodeInvalid | Kind::AuthorityStale => LifecycleFailure {
                code: Code::EnrollmentRejected,
                message: "enrollment was rejected",
                retryable: false,
            },
            Kind::TemporarilyUnavailable => LifecycleFailure {
                code: Code::Busy,
                message: "enrollment service is temporarily unavailable",
                retryable: true,
            },
            Kind::Incompatible => LifecycleFailure {
                code: Code::InvalidRequest,
                message: "enrollment components are incompatible",
                retryable: false,
            },
            Kind::OwnerMismatch | Kind::LocalFailure | Kind::OutcomeUnconfirmed => {
                LifecycleFailure::internal()
            }
        };
    }

    let (code, message, retryable) = match kind {
        Kind::CodeInvalid => (
            Code::EnrollmentCodeInvalid,
            "enrollment code is invalid, expired, or already used",
            false,
        ),
        Kind::OwnerMismatch => (
            Code::EnrollmentOwnerMismatch,
            "the enrollment service refused this account binding",
            false,
        ),
        Kind::AuthorityStale => (
            Code::EnrollmentAuthorityStale,
            "the authorization for this code is no longer current",
            false,
        ),
        Kind::Incompatible => (
            Code::EnrollmentIncompatible,
            "enrollment components are incompatible",
            false,
        ),
        Kind::TemporarilyUnavailable => (
            Code::EnrollmentTemporarilyUnavailable,
            "enrollment service is temporarily unavailable",
            true,
        ),
        Kind::LocalFailure => (
            Code::EnrollmentLocalFailure,
            "local enrollment safety checks could not complete",
            false,
        ),
        Kind::OutcomeUnconfirmed => (
            Code::EnrollmentOutcomeUnconfirmed,
            "the enrollment outcome could not be confirmed",
            false,
        ),
    };
    LifecycleFailure {
        code,
        message,
        retryable,
    }
}

fn finish_failed_enrollment_activation<Cleanup, Present, Fallback>(
    journaled_cleanup: Cleanup,
    mut local_authority_present: Present,
    fallback_cut: Fallback,
) -> Result<()>
where
    Cleanup: FnOnce() -> Result<()>,
    Present: FnMut() -> Result<bool>,
    Fallback: FnOnce() -> Result<()>,
{
    let mut failures = Vec::new();
    if let Err(error) = journaled_cleanup() {
        failures.push(format!("journaled activation cleanup failed: {error:#}"));
    }
    match local_authority_present() {
        Ok(false) if failures.is_empty() => return Ok(()),
        Ok(false) => {}
        Ok(true) => failures.push("local enrollment authority remained after cleanup".to_string()),
        Err(error) => failures.push(format!(
            "local enrollment authority could not be checked after cleanup: {error:#}"
        )),
    }

    if let Err(error) = fallback_cut() {
        failures.push(format!("fail-closed fallback reported: {error:#}"));
    }
    match local_authority_present() {
        Ok(false) => {}
        Ok(true) => failures
            .push("failed service activation left local enrollment authority present".to_string()),
        Err(error) => failures.push(format!(
            "local enrollment authority absence could not be proved: {error:#}"
        )),
    }
    bail!(
        "failed enrollment activation was not a clean journaled rollback: {}",
        failures.join("; ")
    )
}

fn fail_closed_failed_enrollment_activation(
    dir: &std::path::Path,
    lifecycle_locks: &hydra_agent::service::LifecycleLockSet,
) -> Result<()> {
    let record = hydra_agent::device_identity::load_record(dir)?
        .ok_or_else(|| anyhow::anyhow!("failed activation has no enrollment record to clean"))?;
    let target = hydra_agent::lifecycle_cleanup::RevocationTarget::new(
        record.cloud_base.clone(),
        record.account_id.clone(),
        record.device_id.clone(),
    )?;
    let canonical_lock = lifecycle_locks.lock_for(dir)?;
    finish_failed_enrollment_activation(
        || {
            let current = recapture_lifecycle_descriptor_under_locks(dir, lifecycle_locks)?;
            extension_remove_enrollment(dir, &current, lifecycle_locks)
        },
        || Ok(hydra_agent::device_identity::load_record(dir)?.is_some()),
        || {
            // Provider handoff and the local authority cut are independent:
            // attempt both even when either one fails, then report the full
            // result only after local record absence is checked above.
            let queued =
                hydra_agent::lifecycle_cleanup::enqueue_revocation(dir, &target, canonical_lock);
            let removed = hydra_agent::device_identity::remove_record(dir);
            match (queued, removed) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(queue_error), Ok(())) => {
                    Err(queue_error.context("queue provider cleanup before fallback authority cut"))
                }
                (Ok(()), Err(remove_error)) => {
                    Err(remove_error.context("remove local enrollment in fail-closed fallback"))
                }
                (Err(queue_error), Err(remove_error)) => bail!(
                    "provider cleanup queue failed: {queue_error:#}; local enrollment cut failed: {remove_error:#}"
                ),
            }
        },
    )
}

fn extension_set_remote_open(
    dir: &std::path::Path,
    open: bool,
    descriptor: &LifecycleDescriptor,
    lifecycle_locks: &hydra_agent::service::LifecycleLockSet,
) -> std::result::Result<(), LifecycleFailure> {
    if !open {
        let retired_cleanup = hydra_agent::remote_access::remove_retired_authority(dir);
        let close = close_remote_fail_closed(
            || close_extension_service(descriptor),
            || {
                begin_destructive_cleanup(
                    dir,
                    hydra_agent::lifecycle_cleanup::CleanupIntent::Remove,
                    descriptor,
                    lifecycle_locks,
                )
                .map(|_| ())
            },
        );
        return match close {
            Ok(CloseRemoteOutcome::Closed) => {
                retired_cleanup.map_err(|_| LifecycleFailure::remote_unavailable())
            }
            Ok(CloseRemoteOutcome::EnrollmentRevoked) => {
                Err(LifecycleFailure::re_enrollment_required(
                    "Remote could not be closed cleanly, so this desktop enrollment was removed to cut access. Add the desktop again before reopening Remote.",
                ))
            }
            Err(_) => Err(LifecycleFailure::internal()),
        };
    }
    if hydra_agent::device_identity::load_record(dir)
        .map_err(|_| LifecycleFailure::internal())?
        .is_none()
    {
        return Err(LifecycleFailure {
            code: maestro_extension_api::RemoteDesktopErrorCode::NotEnrolled,
            message: "this desktop is not enrolled",
            retryable: false,
        });
    }
    // Open exists only as the exact reviewed service. There is no persistent
    // positive grant to replay after Close.
    hydra_agent::remote_access::remove_retired_authority(dir)
        .map_err(|_| LifecycleFailure::internal())?;
    let prior_state =
        require_pre_mutation_manager_state(|| extension_service_activation_prior_state(descriptor))
            .map_err(|_| LifecycleFailure::remote_unavailable())?;
    if ensure_extension_service(dir, prior_state, descriptor, lifecycle_locks).is_err() {
        if hydra_agent::device_identity::load_record(dir)
            .ok()
            .flatten()
            .is_none()
        {
            return Err(LifecycleFailure::re_enrollment_required(
                "Remote could not be opened safely, so this desktop enrollment was removed. Add the desktop again before retrying.",
            ));
        }
        return Err(LifecycleFailure::remote_unavailable());
    }
    Ok(())
}

fn lifecycle_status(
    dir: &std::path::Path,
    descriptor: &LifecycleDescriptor,
    lifecycle_locks: &hydra_agent::service::LifecycleLockSet,
) -> Result<maestro_extension_api::RemoteDesktopStatus> {
    let record = hydra_agent::device_identity::load_record(dir)?;
    lifecycle_status_with_convergence(record, descriptor.activation_state, || {
        upgrade_running_extension_service_if_needed(dir, descriptor, lifecycle_locks)
    })
}

fn recapture_lifecycle_descriptor_under_locks(
    dir: &std::path::Path,
    lifecycle_locks: &hydra_agent::service::LifecycleLockSet,
) -> Result<LifecycleDescriptor> {
    let canonical_lock = lifecycle_locks.lock_for(dir)?;
    let descriptor = capture_lifecycle_descriptor(dir, canonical_lock)?;
    let locked_roots = lifecycle_locks
        .roots()
        .map(std::path::Path::to_path_buf)
        .collect::<std::collections::BTreeSet<_>>();
    if !descriptor.peer_roots.is_subset(&locked_roots) {
        bail!("post-mutation lifecycle introduced an unlocked enrollment root");
    }
    descriptor.require_unambiguous()?;
    Ok(descriptor)
}

fn recaptured_lifecycle_status(
    dir: &std::path::Path,
    lifecycle_locks: &hydra_agent::service::LifecycleLockSet,
) -> Result<maestro_extension_api::RemoteDesktopStatus> {
    with_recaptured_lifecycle_state(
        || recapture_lifecycle_descriptor_under_locks(dir, lifecycle_locks),
        |descriptor| lifecycle_status(dir, descriptor, lifecycle_locks),
    )
}

fn with_recaptured_lifecycle_state<Descriptor, Output>(
    recapture: impl FnOnce() -> Result<Descriptor>,
    use_current: impl FnOnce(&Descriptor) -> Result<Output>,
) -> Result<Output> {
    let current = recapture()?;
    use_current(&current)
}

fn lifecycle_status_with_convergence(
    record: Option<hydra_agent::device_identity::DeviceRecord>,
    activation_state: ServiceActivationPriorState,
    converge_service: impl FnOnce() -> Result<()>,
) -> Result<maestro_extension_api::RemoteDesktopStatus> {
    if let Some(record) = record.as_ref() {
        hydra_agent::release_trust::active().validate_enrollment(record)?;
        converge_service()?;
    }
    let remote_open = if record.is_some() {
        match activation_state {
            ServiceActivationPriorState::ProvenOpen => true,
            ServiceActivationPriorState::Closed => false,
            ServiceActivationPriorState::Ambiguous => {
                bail!("remote desktop lifecycle state is incomplete or unreadable")
            }
        }
    } else {
        false
    };
    lifecycle_status_from_record(record, remote_open)
}

/// Upgrade an already-running installed service to this exact private binary,
/// but never turn a previously closed desktop back on merely because the app
/// was launched or Status was requested. A stale definition plus a live
/// manager is durable evidence that Remote was open before the package update.
/// The attach-only ownership guard in `ensure_extension_service` protects
/// retained PTYs while the supervisor is replaced.
fn upgrade_running_extension_service_if_needed(
    dir: &std::path::Path,
    descriptor: &LifecycleDescriptor,
    lifecycle_locks: &hydra_agent::service::LifecycleLockSet,
) -> Result<()> {
    descriptor.require_unambiguous()?;
    let (paths, install, socket, binding) = extension_service_install_plan(dir, descriptor)?;
    let exact_definition = service_definition_matches(&install);
    let manager_pid = platform_service_manager_pid(&paths)?;
    let exact_live_readiness = manager_pid.is_some()
        && wait_for_platform_service_ready_for(
            &paths,
            &socket,
            &hydra_agent::build_stamp(),
            &binding,
            std::time::Duration::from_millis(250),
        )
        .is_ok();
    converge_service_upgrade_if_needed(exact_definition, manager_pid, exact_live_readiness, || {
        ensure_extension_service(
            dir,
            ServiceActivationPriorState::ProvenOpen,
            descriptor,
            lifecycle_locks,
        )
        .context("upgrade running remote service")
    })
}

fn converge_service_upgrade_if_needed(
    exact_definition: bool,
    manager_pid: Option<u32>,
    exact_live_readiness: bool,
    ensure_current_service: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if service_upgrade_needed(exact_definition, manager_pid, exact_live_readiness) {
        ensure_current_service()?;
    }
    Ok(())
}

fn service_upgrade_needed(
    exact_definition: bool,
    manager_pid: Option<u32>,
    exact_live_readiness: bool,
) -> bool {
    manager_pid.is_some() && (!exact_definition || !exact_live_readiness)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServiceActivationPriorState {
    Closed,
    ProvenOpen,
    Ambiguous,
}

fn extension_service_activation_prior_state(
    descriptor: &LifecycleDescriptor,
) -> Result<ServiceActivationPriorState> {
    Ok(descriptor.activation_state)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CloseRemoteOutcome {
    Closed,
    EnrollmentRevoked,
}

/// Explicit Close is fail-closed. If service-manager cleanup cannot prove the
/// connectivity process absent, remove the local enrollment first so every
/// supervisor tick/live peer check loses authority. The durable owner marker
/// and app-owned PTY daemon remain untouched.
fn close_remote_fail_closed(
    close_service: impl FnOnce() -> Result<()>,
    revoke_enrollment: impl FnOnce() -> Result<()>,
) -> Result<CloseRemoteOutcome> {
    match close_service() {
        Ok(()) => Ok(CloseRemoteOutcome::Closed),
        Err(close_error) => match revoke_enrollment() {
            Ok(()) => Ok(CloseRemoteOutcome::EnrollmentRevoked),
            Err(revoke_error) => bail!(
                "remote service close was unproved: {close_error:#}; local enrollment revocation also failed: {revoke_error:#}"
            ),
        },
    }
}

#[cfg(test)]
fn effective_remote_open(
    enrolled: bool,
    exact_service_ready: impl FnOnce() -> Result<bool>,
) -> bool {
    enrolled && exact_service_ready().unwrap_or(false)
}

fn lifecycle_status_from_record(
    record: Option<hydra_agent::device_identity::DeviceRecord>,
    remote_open: bool,
) -> Result<maestro_extension_api::RemoteDesktopStatus> {
    let enrollment_id = record
        .as_ref()
        .map(|record| maestro_extension_api::RemoteDesktopId::new(record.device_id.clone()))
        .transpose()?;
    let account_id = record
        .as_ref()
        .map(|record| maestro_extension_api::RemoteDesktopId::new(record.account_id.clone()))
        .transpose()?;
    Ok(maestro_extension_api::RemoteDesktopStatus::new(
        enrollment_id,
        account_id,
        remote_open,
        0,
        None,
    )?)
}

fn extension_remove_enrollment(
    dir: &std::path::Path,
    descriptor: &LifecycleDescriptor,
    lifecycle_locks: &hydra_agent::service::LifecycleLockSet,
) -> Result<()> {
    begin_destructive_cleanup(
        dir,
        hydra_agent::lifecycle_cleanup::CleanupIntent::Remove,
        descriptor,
        lifecycle_locks,
    )
    .map(|_| ())
    .context("remove local enrollment and remote service")
}

/// Remove the credential that authorizes fresh and live peer checks before attempting service-manager cleanup.
/// A manager failure may leave an inert process to be retried, but it cannot preserve local enrollment authority.
#[cfg(test)]
fn remove_local_authority_before_cleanup<T>(
    remove_local_authority: impl FnOnce() -> Result<T>,
    cleanup_service: impl FnOnce() -> Result<()>,
) -> Result<T> {
    let removed = remove_local_authority()?;
    cleanup_service()?;
    Ok(removed)
}

/// Retired-file cleanup is not an authority gate. Attempt it and service
/// cleanup independently after effective enrollment is already gone, then
/// surface every incomplete cleanup to the caller.
#[cfg(test)]
fn cleanup_retired_authority_then_service(
    cleanup_retired_authority: impl FnOnce() -> Result<()>,
    cleanup_service: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let mut errors = Vec::new();
    if let Err(error) = cleanup_retired_authority() {
        errors.push(format!("retired authority cleanup: {error}"));
    }
    if let Err(error) = cleanup_service() {
        errors.push(format!("service cleanup: {error}"));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        bail!(errors.join("; "))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProviderRetryDisposition {
    NothingQueued,
    Completed,
    Retained,
}

fn desired_cleanup_unit(
    dir: &std::path::Path,
    descriptor: &LifecycleDescriptor,
) -> Result<hydra_agent::lifecycle_cleanup::DesiredUnit> {
    if descriptor.canonical_root != dir || descriptor.desired_paths.agent_dir != dir {
        bail!("lifecycle descriptor is bound to another enrollment root");
    }
    let home =
        hydra_agent::agent_dir::trusted_home_dir().context("resolve effective OS account home")?;
    let binary = std::env::current_exe().context("resolve installed Hydra agent binary")?;
    if !binary.is_absolute() || !binary.is_file() {
        bail!("installed Hydra agent binary is unavailable");
    }
    let app_support_dir = extension_maestro_app_support_dir(&home);
    let (socket, fixed_external_daemon) =
        extension_daemon_target(&home, dir, &binary, &app_support_dir)?;
    let plan = platform_plan_install(
        &descriptor.desired_paths,
        PlatformInstallOptions {
            home: &home,
            app_support_dir: &app_support_dir,
            label: &descriptor.desired_paths.label,
            binary_path: binary.to_string_lossy().into_owned(),
            socket_path: socket.to_string_lossy().into_owned(),
            fixed_external_daemon,
            sessions: Vec::new(),
        },
    );
    let (path, contents) = plan
        .actions
        .iter()
        .find_map(|action| match action {
            hydra_agent::service::ServiceAction::WriteFile { path, contents } => {
                Some((path, contents))
            }
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("reviewed service plan has no definition"))?;
    hydra_agent::lifecycle_cleanup::DesiredUnit::from_bytes(path, contents.as_bytes())
}

fn capture_destructive_cleanup(
    dir: &std::path::Path,
    intent: hydra_agent::lifecycle_cleanup::CleanupIntent,
    descriptor: &LifecycleDescriptor,
    locks: &hydra_agent::service::LifecycleLockSet,
    transfer_owner: bool,
) -> Result<hydra_agent::lifecycle_cleanup::CleanupTombstone> {
    use hydra_agent::lifecycle_cleanup::{
        AuthorityEvidence, CleanupIntent, ExactFileEvidence, LifecycleFileKind, ManagerEvidence,
        ObservedUnit, PriorActivation, UnitRole,
    };

    if !matches!(intent, CleanupIntent::Remove | CleanupIntent::FullForget) {
        bail!("only destructive authority cleanup is journaled by this path");
    }
    if transfer_owner && intent != CleanupIntent::FullForget {
        bail!("durable owner transfer requires FullForget");
    }
    descriptor.require_unambiguous()?;
    locks.require_agent_dir(dir)?;

    let record_state = hydra_agent::device_identity::load_record(dir);
    if matches!(record_state, Ok(Some(_))) {
        hydra_agent::device_identity::preserve_owner_marker(dir)?;
    }

    let mut deletions = Vec::new();
    let record_evidence = ExactFileEvidence::capture(
        dir,
        &hydra_agent::device_identity::record_path(dir),
        LifecycleFileKind::CanonicalRecord,
        locks,
    )?;
    let authority = match (&record_state, record_evidence.as_ref()) {
        (Ok(Some(_)), Some(evidence)) => {
            AuthorityEvidence::target_from_exact_record(evidence, locks)?
        }
        (Ok(None), None) => AuthorityEvidence::NoActiveRecord,
        (Err(_), Some(evidence)) if intent == CleanupIntent::Remove => {
            let canonical_lock = locks.lock_for(dir)?;
            let corrupt = hydra_agent::enrollment_migration::snapshot_corrupt_canonical_for_remove(
                dir,
                canonical_lock,
            )?
            .ok_or_else(|| anyhow::anyhow!("corrupt enrollment evidence disappeared"))?;
            if evidence.path() != hydra_agent::device_identity::record_path(dir) {
                bail!("corrupt enrollment evidence is not canonical");
            }
            AuthorityEvidence::unavailable_corrupt(corrupt.owner_bytes(), corrupt.record_bytes())?
        }
        (Err(_), Some(_)) => bail!("FullForget refuses an unreadable enrollment record"),
        (Ok(Some(_)), None) | (Err(_), None) | (Ok(None), Some(_)) => {
            bail!("enrollment record changed during destructive capture")
        }
    };
    if let Some(evidence) = record_evidence {
        deletions.push(evidence);
    }

    let marker_path = dir.join("legacy-xdg-enrollment-adoption.v1.json");
    if let Some(marker) =
        ExactFileEvidence::capture(dir, &marker_path, LifecycleFileKind::AdoptionMarker, locks)?
    {
        deletions.push(marker);
        let source = descriptor
            .verified_marker_source
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("adoption marker has no verified source"))?;
        for (name, kind) in [
            ("device.json", LifecycleFileKind::LegacyRecord),
            ("device-key", LifecycleFileKind::LegacyAdoptedKey),
        ] {
            if let Some(evidence) =
                ExactFileEvidence::capture(source, &source.join(name), kind, locks)?
            {
                deletions.push(evidence);
            }
        }
    }
    if intent == CleanupIntent::FullForget {
        for (path, kind) in [
            (
                hydra_agent::device_identity::enrollment_diagnostics_temporary_path(dir),
                LifecycleFileKind::EnrollmentDiagnosticsTemporary,
            ),
            (
                hydra_agent::device_identity::enrollment_diagnostics_path(dir),
                LifecycleFileKind::EnrollmentDiagnostics,
            ),
        ] {
            if let Some(diagnostics) = ExactFileEvidence::capture(dir, &path, kind, locks)? {
                deletions.push(diagnostics);
            }
        }
        if let Some(key) = ExactFileEvidence::capture(
            dir,
            &dir.join("device-key"),
            LifecycleFileKind::CanonicalStableKey,
            locks,
        )? {
            deletions.push(key);
        }
        if transfer_owner {
            if let Some(owner) = ExactFileEvidence::capture(
                dir,
                &dir.join("device-owner.json"),
                LifecycleFileKind::CanonicalOwnerMarker,
                locks,
            )? {
                deletions.push(owner);
            }
        }
    }

    // Readiness files are ephemeral, but a destructive transaction must still
    // bind every file that is present at capture time and every historical
    // readiness root. Recovery later uses these persisted roots even when the
    // current service descriptor has shrunk after partial cleanup.
    for root in &descriptor.peer_roots {
        for (path, kind) in [
            (
                hydra_agent::service_readiness::service_readiness_path(root),
                LifecycleFileKind::ServiceReadiness,
            ),
            (
                hydra_agent::service_readiness::service_readiness_request_path(root),
                LifecycleFileKind::ServiceReadinessRequest,
            ),
        ] {
            if let Some(evidence) = ExactFileEvidence::capture(root, &path, kind, locks)? {
                deletions.push(evidence);
            }
        }
    }

    let desired = desired_cleanup_unit(dir, descriptor)?;
    let desired_bytes = desired.bytes()?;
    let mut units = Vec::new();
    for installed in &descriptor.installed {
        let mut roles = std::collections::BTreeSet::from([UnitRole::HistoricalInstalled]);
        if installed.path == descriptor.effective_service_file() && descriptor.running.is_some() {
            roles.insert(UnitRole::LoadedEffective);
        }
        if installed.path == desired.path()
            && installed.bytes.as_slice() == desired_bytes.as_slice()
        {
            roles.insert(UnitRole::DesiredCurrent);
        }
        units.push(ObservedUnit::from_bytes(
            &installed.path,
            &installed.bytes,
            roles,
        )?);
        let exact = ExactFileEvidence::capture(
            dir,
            &installed.path,
            LifecycleFileKind::ServiceDefinition,
            locks,
        )?
        .ok_or_else(|| anyhow::anyhow!("captured service definition disappeared"))?;
        deletions.push(exact);
    }
    let manager = descriptor
        .running
        .as_ref()
        .map(|running| {
            let agent_root = running.invocation.agent_dir.as_deref().unwrap_or(dir);
            let binding = running
                .runtime_binding_stamp
                .clone()
                .ok_or_else(|| anyhow::anyhow!("running service has no trusted binding"))?;
            ManagerEvidence::new(
                agent_root,
                &running.invocation.socket_path,
                running.runtime_build_stamp.clone(),
                binding,
            )
        })
        .transpose()?;
    let prior = match descriptor.activation_state {
        ServiceActivationPriorState::ProvenOpen => PriorActivation::ProvenOpen,
        ServiceActivationPriorState::Closed => PriorActivation::ProvenClosed,
        ServiceActivationPriorState::Ambiguous => PriorActivation::Ambiguous,
    };
    hydra_agent::lifecycle_cleanup::CleanupTombstone::new(
        intent,
        prior,
        authority,
        dir,
        &descriptor.peer_roots,
        &descriptor.peer_roots,
        units,
        deletions,
        desired,
        manager,
        locks,
    )
}

fn retry_one_provider_revocation(
    dir: &std::path::Path,
    locks: &hydra_agent::service::LifecycleLockSet,
) -> Result<ProviderRetryDisposition> {
    retry_one_provider_revocation_with(
        dir,
        locks,
        hydra_agent::device_identity::load_key,
        |target, key| {
            hydra_agent::heartbeat::send_self_revoke_blocking(
                target.cloud_base(),
                target.device_id(),
                key,
            )
            .map_err(anyhow::Error::msg)
        },
    )
}

fn retry_one_provider_revocation_with<Key>(
    dir: &std::path::Path,
    locks: &hydra_agent::service::LifecycleLockSet,
    load_key: impl FnOnce(&std::path::Path) -> Result<Option<Key>>,
    send: impl FnOnce(&hydra_agent::lifecycle_cleanup::RevocationTarget, &Key) -> Result<u16>,
) -> Result<ProviderRetryDisposition> {
    use hydra_agent::lifecycle_cleanup::ProviderTerminalOutcome;

    let target = match hydra_agent::lifecycle_cleanup::load_revocation_outbox(dir)?
        .targets()
        .next()
        .cloned()
    {
        Some(target) => target,
        None => return Ok(ProviderRetryDisposition::NothingQueued),
    };
    if hydra_agent::lifecycle_cleanup::load(dir)?
        .as_ref()
        .is_some_and(|pending| pending.provider_terminal_target() == Some(&target))
    {
        let lock = locks.lock_for(dir)?;
        hydra_agent::lifecycle_cleanup::complete_revocation(dir, target.device_id(), lock)?;
        return Ok(ProviderRetryDisposition::Completed);
    }
    let Some(key) = load_key(dir)? else {
        return Ok(ProviderRetryDisposition::Retained);
    };
    let outcome = match send(&target, &key) {
        Ok(code) if (200..300).contains(&code) => ProviderTerminalOutcome::Revoked,
        Ok(404) => ProviderTerminalOutcome::AlreadyAbsent,
        Ok(_) | Err(_) => return Ok(ProviderRetryDisposition::Retained),
    };
    if let Some(pending) = hydra_agent::lifecycle_cleanup::load(dir)? {
        if pending.intent() == hydra_agent::lifecycle_cleanup::CleanupIntent::FullForget
            && pending.revocation_target() == Some(&target)
        {
            hydra_agent::lifecycle_cleanup::record_full_forget_provider_terminal(
                dir, &target, outcome, locks,
            )?;
        }
    }
    let lock = locks.lock_for(dir)?;
    hydra_agent::lifecycle_cleanup::complete_revocation(dir, target.device_id(), lock)?;
    Ok(ProviderRetryDisposition::Completed)
}

fn execute_cleanup_kind(
    dir: &std::path::Path,
    mut pending: hydra_agent::lifecycle_cleanup::CleanupTombstone,
    kind: hydra_agent::lifecycle_cleanup::LifecycleFileKind,
    locks: &hydra_agent::service::LifecycleLockSet,
) -> Result<hydra_agent::lifecycle_cleanup::CleanupTombstone> {
    let paths = pending
        .deletion_targets()
        .filter(|planned| planned.evidence().kind() == kind && !planned.is_proven_absent())
        .map(|planned| planned.evidence().path())
        .collect::<Vec<_>>();
    for path in paths {
        pending =
            hydra_agent::lifecycle_cleanup::execute_planned_deletion(dir, &pending, &path, locks)?;
    }
    Ok(pending)
}

fn pending_service_paths(
    dir: &std::path::Path,
    pending: &hydra_agent::lifecycle_cleanup::CleanupTombstone,
) -> Result<hydra_agent::service::ServicePaths> {
    let home =
        hydra_agent::agent_dir::trusted_home_dir().context("resolve effective OS account home")?;
    let paths = extension_platform_service_paths(
        &home,
        dir,
        default_service_label(),
        &hydra_agent::agent_dir::trusted_uid().to_string(),
    );
    if platform_service_file(&paths) != pending.desired_unit().path() {
        bail!("pending lifecycle desired service path is not the fixed current path");
    }
    Ok(paths)
}

fn service_definition_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};

    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A dormant service-manager state is safe to retire only when the definition
/// still present on disk is the exact attach-only unit captured by this Remove
/// journal. This is deliberately separate from the ordinary manager probe:
/// loaded/inactive is never generic absence, but it is a recoverable
/// post-`disable --now` crash state for this one exact transaction.
fn pending_remove_binds_dormant_definition(
    pending: &hydra_agent::lifecycle_cleanup::CleanupTombstone,
    installed: &InstalledServiceDescriptor,
    default_agent_root: &std::path::Path,
    platform_state_is_exact_dormant: bool,
    peer_inventory: &std::collections::BTreeSet<u32>,
) -> Result<bool> {
    use hydra_agent::lifecycle_cleanup::{CleanupIntent, LifecycleFileKind};

    if pending.intent() != CleanupIntent::Remove
        || !platform_state_is_exact_dormant
        || !peer_inventory.is_empty()
        || pending.canonical_root() != default_agent_root
    {
        return Ok(false);
    }
    let Some(invocation) = installed.invocation.as_ref() else {
        return Ok(false);
    };
    if !invocation.attach_daemon_only {
        return Ok(false);
    }
    let agent_root = invocation
        .agent_dir
        .as_deref()
        .unwrap_or(default_agent_root);
    if !pending.peer_roots()?.contains(agent_root) {
        return Ok(false);
    }

    let digest = service_definition_sha256(&installed.bytes);
    let observed = pending
        .observed_units()
        .any(|unit| unit.path() == installed.path && unit.sha256() == digest);
    let deletion = pending.deletion_targets().any(|target| {
        !target.is_proven_absent()
            && target.evidence().kind() == LifecycleFileKind::ServiceDefinition
            && target.evidence().path() == installed.path
            && target.evidence().sha256() == digest
    });
    Ok(observed && deletion)
}

#[cfg(any(target_os = "linux", test))]
fn dormant_systemd_pending_shape_is_safe(
    state: &SystemdUnitState,
    installed_path: &std::path::Path,
) -> bool {
    state.drop_in_paths_empty
        && state.fragment_path.as_deref() == Some(installed_path)
        && state.load_state == "loaded"
        && state.active_state == "inactive"
        && matches!(state.unit_file_state.as_str(), "enabled" | "disabled")
        && state.main_pid.is_none()
}

#[cfg(target_os = "linux")]
fn pending_remove_dormant_service_is_safe(
    paths: &hydra_agent::service::ServicePaths,
    pending: &hydra_agent::lifecycle_cleanup::CleanupTombstone,
) -> Result<bool> {
    if pending.intent() != hydra_agent::lifecycle_cleanup::CleanupIntent::Remove {
        return Ok(false);
    }
    let roots = pending.peer_roots()?;
    let first_state = systemd_user_unit_state(&paths.label)?;
    let Some(first_path) = first_state.fragment_path.as_deref() else {
        return Ok(false);
    };
    let Some(first_installed) = installed_linux_service_descriptor(first_path)? else {
        return Ok(false);
    };
    let first_peers = remote_peer_inventory(&roots)?;
    if !pending_remove_binds_dormant_definition(
        pending,
        &first_installed,
        &paths.agent_dir,
        dormant_systemd_pending_shape_is_safe(&first_state, &first_installed.path),
        &first_peers,
    )? {
        return Ok(false);
    }

    // Pin the no-manager state, exact parsed definition, and empty relevant
    // peer inventory across a second complete observation before mutation.
    let second_state = systemd_user_unit_state(&paths.label)?;
    let second_installed = second_state
        .fragment_path
        .as_deref()
        .map(installed_linux_service_descriptor)
        .transpose()?
        .flatten();
    let second_peers = remote_peer_inventory(&roots)?;
    let Some(second_installed) = second_installed else {
        return Ok(false);
    };
    Ok(first_state == second_state
        && first_installed == second_installed
        && first_peers == second_peers
        && pending_remove_binds_dormant_definition(
            pending,
            &second_installed,
            &paths.agent_dir,
            dormant_systemd_pending_shape_is_safe(&second_state, &second_installed.path),
            &second_peers,
        )?)
}

#[cfg(target_os = "macos")]
fn pending_remove_dormant_service_is_safe(
    paths: &hydra_agent::service::ServicePaths,
    pending: &hydra_agent::lifecycle_cleanup::CleanupTombstone,
) -> Result<bool> {
    if pending.intent() != hydra_agent::lifecycle_cleanup::CleanupIntent::Remove {
        return Ok(false);
    }
    let service_file = platform_service_file(paths);
    let roots = pending.peer_roots()?;
    let first_state = launchd_job_state(paths)?;
    let Some(first_installed) = installed_macos_service_descriptor(&service_file)? else {
        return Ok(false);
    };
    let first_peers = remote_peer_inventory(&roots)?;
    if !pending_remove_binds_dormant_definition(
        pending,
        &first_installed,
        &paths.agent_dir,
        dormant_launchd_pending_shape_is_safe(
            &first_state,
            &service_file,
            first_installed
                .invocation
                .as_ref()
                .is_some_and(|invocation| invocation.attach_daemon_only),
            first_peers.len(),
        ),
        &first_peers,
    )? {
        return Ok(false);
    }

    let second_state = launchd_job_state(paths)?;
    let second_installed = installed_macos_service_descriptor(&service_file)?;
    let second_peers = remote_peer_inventory(&roots)?;
    let Some(second_installed) = second_installed else {
        return Ok(false);
    };
    Ok(first_state == second_state
        && first_installed == second_installed
        && first_peers == second_peers
        && pending_remove_binds_dormant_definition(
            pending,
            &second_installed,
            &paths.agent_dir,
            dormant_launchd_pending_shape_is_safe(
                &second_state,
                &service_file,
                second_installed
                    .invocation
                    .as_ref()
                    .is_some_and(|invocation| invocation.attach_daemon_only),
                second_peers.len(),
            ),
            &second_peers,
        )?)
}

fn pending_service_manager_pid(
    paths: &hydra_agent::service::ServicePaths,
    pending: &hydra_agent::lifecycle_cleanup::CleanupTombstone,
) -> Result<Option<u32>> {
    match platform_service_manager_pid(paths) {
        Ok(manager_pid) => Ok(manager_pid),
        Err(error) if pending_remove_dormant_service_is_safe(paths, pending)? => {
            let _ = error;
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn guard_pending_disruptive_service_change(
    paths: &hydra_agent::service::ServicePaths,
    pending: &hydra_agent::lifecycle_cleanup::CleanupTombstone,
    action: &str,
) -> Result<()> {
    match guard_disruptive_service_change(paths, action) {
        Ok(()) => Ok(()),
        Err(error) if pending_remove_dormant_service_is_safe(paths, pending)? => {
            let _ = error;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn capture_pending_service_peer(
    paths: &hydra_agent::service::ServicePaths,
    pending: &hydra_agent::lifecycle_cleanup::CleanupTombstone,
    peer_roots: &std::collections::BTreeSet<PathBuf>,
    peer_inventory: &std::collections::BTreeSet<u32>,
) -> Result<Option<u32>> {
    let Some(manager_pid) = pending_service_manager_pid(paths, pending)? else {
        if pending_service_manager_pid(paths, pending)?.is_none() {
            return Ok(None);
        }
        bail!("remote service manager appeared during cleanup recovery preflight");
    };
    let expected = pending
        .manager()
        .ok_or_else(|| anyhow::anyhow!("an uncaptured service manager appeared during cleanup"))?;
    let invocation = parse_supervisor_invocation(&manager_process_arguments(manager_pid)?)
        .context("read exact running supervisor invocation during cleanup recovery")?;
    if !invocation.attach_daemon_only {
        bail!("running service owns the retained PTY daemon; refusing lifecycle cleanup");
    }
    let actual_root = invocation.agent_dir.as_deref().unwrap_or(&paths.agent_dir);
    if actual_root != expected.agent_root() || invocation.socket_path != expected.socket_path() {
        bail!("running service identity differs from the captured cleanup manager");
    }
    let runtime = manager_runtime_environment(manager_pid)?;
    if runtime.build_stamp != expected.build_stamp()
        || runtime.binding_stamp.as_deref() != Some(expected.binding_stamp())
    {
        bail!("running service build or binding differs from captured cleanup evidence");
    }
    if !peer_roots.contains(actual_root) {
        bail!("running service root is outside the captured cleanup roots");
    }
    let record = capture_platform_service_ready_in_dir_for(
        paths,
        actual_root,
        &invocation.socket_path,
        expected.build_stamp(),
        expected.binding_stamp(),
        std::time::Duration::from_secs(5),
    )
    .context("capture exact service readiness during cleanup recovery")?;
    if record.supervisor_pid != manager_pid
        || pending_service_manager_pid(paths, pending)? != Some(manager_pid)
        || !process_is_live_exact(record.peer_pid)?
        || !peer_inventory.contains(&record.peer_pid)
    {
        bail!("running service changed during cleanup recovery preflight");
    }
    Ok(Some(record.peer_pid))
}

fn stop_pending_service_with_proof(
    dir: &std::path::Path,
    pending: &hydra_agent::lifecycle_cleanup::CleanupTombstone,
) -> Result<()> {
    let paths = pending_service_paths(dir, pending)?;
    let peer_roots = pending.peer_roots()?;
    guard_pending_disruptive_service_change(
        &paths,
        pending,
        "finish pending remote-service cleanup",
    )?;
    let peer_inventory = remote_peer_inventory(&peer_roots)?;
    let _captured = capture_pending_service_peer(&paths, pending, &peer_roots, &peer_inventory)?;

    // Stop/disable the manager first, but leave every service definition for
    // the journal's exact inode+digest deletion primitive below. This avoids a
    // generic uninstall deleting bytes that changed after capture.
    let plan = platform_plan_uninstall(&paths, false);
    let stop_plan = hydra_agent::service::ServicePlan {
        title: "stop pending Hydra remote service without deleting evidence".to_string(),
        actions: plan
            .actions
            .into_iter()
            .filter(|action| !matches!(action, hydra_agent::service::ServiceAction::RemoveFile(_)))
            .collect(),
    };
    let mut runner = hydra_agent::service::SystemRunner;
    let (_, mut errors) = hydra_agent::service::execute_cleanup_plan(&stop_plan, &mut runner);
    match pending_service_manager_pid(&paths, pending) {
        Ok(None) => {}
        Ok(Some(_)) => errors.push("remote service manager is still running".to_string()),
        Err(error) => errors.push(format!("verify pending remote service stopped: {error}")),
    }
    if let Err(error) = prove_peer_inventory_stopped(&peer_inventory) {
        errors.push(format!("verify captured remote-peer retirement: {error}"));
    }
    match remote_peer_inventory(&peer_roots)
        .and_then(|peers| validate_closed_peer_inventory(&peers))
    {
        Ok(()) => {}
        Err(error) => errors.push(format!(
            "verify pending remote-peer roots are empty: {error}"
        )),
    }
    if errors.is_empty() {
        Ok(())
    } else {
        bail!(errors.join("; "))
    }
}

#[cfg(target_os = "linux")]
fn reload_service_manager_after_exact_definition_cleanup() -> Result<()> {
    let args = vec!["--user".to_string(), "daemon-reload".to_string()];
    let output =
        hydra_agent::service::manager_output_bounded(hydra_agent::headless::SYSTEMCTL_PATH, &args)
            .context("reload user service manager after exact definition cleanup")?;
    if output.status.success() {
        Ok(())
    } else {
        bail!(
            "systemctl --user daemon-reload failed after exact definition cleanup: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
    }
}

#[cfg(not(target_os = "linux"))]
fn reload_service_manager_after_exact_definition_cleanup() -> Result<()> {
    Ok(())
}

fn prove_pending_connectivity_postconditions(
    dir: &std::path::Path,
    pending: &hydra_agent::lifecycle_cleanup::CleanupTombstone,
) -> Result<()> {
    let paths = pending_service_paths(dir, pending)?;
    if platform_service_manager_pid(&paths)?.is_some() {
        bail!("pending cleanup left the remote service manager running");
    }
    let peers = remote_peer_inventory(&pending.peer_roots()?)?;
    validate_closed_peer_inventory(&peers)?;
    Ok(())
}

fn prove_pending_filesystem_postconditions(
    pending: &hydra_agent::lifecycle_cleanup::CleanupTombstone,
    locks: &hydra_agent::service::LifecycleLockSet,
) -> Result<()> {
    pending.prove_service_definitions_retired(locks)?;
    for root in pending.readiness_roots()? {
        for path in [
            hydra_agent::service_readiness::service_readiness_path(&root),
            hydra_agent::service_readiness::service_readiness_request_path(&root),
        ] {
            match std::fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Ok(_) => bail!("pending cleanup left service readiness evidence behind"),
                Err(error) => return Err(error).context("prove service readiness absence"),
            }
        }
    }
    Ok(())
}

fn execute_pending_local_cleanup_with<Stop, Reload, ConnectivityProof>(
    dir: &std::path::Path,
    mut pending: hydra_agent::lifecycle_cleanup::CleanupTombstone,
    locks: &hydra_agent::service::LifecycleLockSet,
    stop: Stop,
    reload: Reload,
    connectivity_proof: ConnectivityProof,
) -> Result<hydra_agent::lifecycle_cleanup::CleanupTombstone>
where
    Stop: FnOnce(&std::path::Path, &hydra_agent::lifecycle_cleanup::CleanupTombstone) -> Result<()>,
    Reload: FnOnce() -> Result<()>,
    ConnectivityProof:
        FnOnce(&std::path::Path, &hydra_agent::lifecycle_cleanup::CleanupTombstone) -> Result<()>,
{
    use hydra_agent::lifecycle_cleanup::LifecycleFileKind;
    // The persisted transaction, not a newly discovered descriptor, owns the
    // service/peer/readiness roots after the first destructive step.
    let mut captured_service_definitions = 0usize;
    let mut every_service_definition_retired = true;
    for target in pending
        .deletion_targets()
        .filter(|target| target.evidence().kind() == LifecycleFileKind::ServiceDefinition)
    {
        captured_service_definitions += 1;
        every_service_definition_retired &= target.is_proven_absent();
    }
    let resumable_remove_after_definition_unlink = pending.intent()
        == hydra_agent::lifecycle_cleanup::CleanupIntent::Remove
        && captured_service_definitions > 0
        && every_service_definition_retired;
    if !resumable_remove_after_definition_unlink {
        stop(dir, &pending)?;
    }
    // If every captured definition is already durably absent, this journal
    // could only have reached that state after the ordered stop+peer proof in
    // an earlier attempt. Resume at daemon-reload: probing the still-cached
    // inactive systemd fragment as if it were a new manager would otherwise
    // make the unlink->reload crash window unrecoverable.
    pending = execute_cleanup_kind(dir, pending, LifecycleFileKind::ServiceDefinition, locks)?;
    reload()?;
    pending = execute_cleanup_kind(dir, pending, LifecycleFileKind::ServiceReadiness, locks)?;
    pending = execute_cleanup_kind(
        dir,
        pending,
        LifecycleFileKind::ServiceReadinessRequest,
        locks,
    )?;
    for root in pending.readiness_roots()? {
        hydra_agent::service_readiness::remove_all_service_readiness(&root)
            .with_context(|| format!("remove readiness under captured root {}", root.display()))?;
    }
    connectivity_proof(dir, &pending)?;
    prove_pending_filesystem_postconditions(&pending, locks)?;
    Ok(pending)
}

fn execute_pending_local_cleanup(
    dir: &std::path::Path,
    pending: hydra_agent::lifecycle_cleanup::CleanupTombstone,
    locks: &hydra_agent::service::LifecycleLockSet,
) -> Result<hydra_agent::lifecycle_cleanup::CleanupTombstone> {
    execute_pending_local_cleanup_with(
        dir,
        pending,
        locks,
        stop_pending_service_with_proof,
        reload_service_manager_after_exact_definition_cleanup,
        prove_pending_connectivity_postconditions,
    )
}

fn drive_destructive_cleanup_with<LocalCleanup, ProviderRetry>(
    dir: &std::path::Path,
    mut pending: hydra_agent::lifecycle_cleanup::CleanupTombstone,
    locks: &hydra_agent::service::LifecycleLockSet,
    local_cleanup: LocalCleanup,
    provider_retry: ProviderRetry,
) -> Result<()>
where
    LocalCleanup: FnOnce(
        &std::path::Path,
        hydra_agent::lifecycle_cleanup::CleanupTombstone,
        &hydra_agent::service::LifecycleLockSet,
    ) -> Result<hydra_agent::lifecycle_cleanup::CleanupTombstone>,
    ProviderRetry: FnOnce(
        &std::path::Path,
        &hydra_agent::service::LifecycleLockSet,
    ) -> Result<ProviderRetryDisposition>,
{
    use hydra_agent::lifecycle_cleanup::{CleanupIntent, LifecycleFileKind};

    if !matches!(
        pending.intent(),
        CleanupIntent::Remove | CleanupIntent::FullForget
    ) {
        bail!("unsupported pending lifecycle intent");
    }
    if pending.lock_roots()? != locks.roots().map(std::path::Path::to_path_buf).collect() {
        bail!("pending lifecycle journal is not bound to this exact lock set");
    }

    if let Some(target) = pending.revocation_target().cloned() {
        pending = hydra_agent::lifecycle_cleanup::handoff_revocation(dir, &target, locks)?;
    }
    // The durable provider handoff precedes the first authority cut. A crash
    // after this point can always recover the exact old provider target.
    pending = execute_cleanup_kind(dir, pending, LifecycleFileKind::CanonicalRecord, locks)?;
    pending = local_cleanup(dir, pending, locks)?;

    pending = execute_cleanup_kind(dir, pending, LifecycleFileKind::LegacyRecord, locks)?;
    pending = execute_cleanup_kind(dir, pending, LifecycleFileKind::LegacyAdoptedKey, locks)?;
    let _locally_complete =
        execute_cleanup_kind(dir, pending, LifecycleFileKind::AdoptionMarker, locks)?;

    let _ = provider_retry(dir, locks)?;
    pending = hydra_agent::lifecycle_cleanup::load(dir)?
        .ok_or_else(|| anyhow::anyhow!("destructive lifecycle journal disappeared"))?;

    if pending.intent() == CleanupIntent::FullForget {
        pending = execute_cleanup_kind(
            dir,
            pending,
            LifecycleFileKind::EnrollmentDiagnosticsTemporary,
            locks,
        )?;
        pending = execute_cleanup_kind(
            dir,
            pending,
            LifecycleFileKind::EnrollmentDiagnostics,
            locks,
        )?;
        if !hydra_agent::lifecycle_cleanup::full_forget_key_deletion_ready(dir, locks)? {
            bail!("provider cleanup is pending; stable device key was retained");
        }
        pending = execute_cleanup_kind(dir, pending, LifecycleFileKind::CanonicalStableKey, locks)?;
        pending =
            execute_cleanup_kind(dir, pending, LifecycleFileKind::CanonicalOwnerMarker, locks)?;
    }
    hydra_agent::lifecycle_cleanup::clear(dir, &pending, locks)
}

fn drive_destructive_cleanup(
    dir: &std::path::Path,
    pending: hydra_agent::lifecycle_cleanup::CleanupTombstone,
    locks: &hydra_agent::service::LifecycleLockSet,
) -> Result<()> {
    drive_destructive_cleanup_with(
        dir,
        pending,
        locks,
        execute_pending_local_cleanup,
        retry_one_provider_revocation,
    )
}

fn begin_destructive_cleanup(
    dir: &std::path::Path,
    intent: hydra_agent::lifecycle_cleanup::CleanupIntent,
    descriptor: &LifecycleDescriptor,
    locks: &hydra_agent::service::LifecycleLockSet,
) -> Result<bool> {
    begin_destructive_cleanup_with_owner_transfer(dir, intent, descriptor, locks, false)
}

fn begin_destructive_cleanup_with_owner_transfer(
    dir: &std::path::Path,
    intent: hydra_agent::lifecycle_cleanup::CleanupIntent,
    descriptor: &LifecycleDescriptor,
    locks: &hydra_agent::service::LifecycleLockSet,
    transfer_owner: bool,
) -> Result<bool> {
    let proposed = capture_destructive_cleanup(dir, intent, descriptor, locks, transfer_owner)?;
    let had_enrollment = !matches!(
        proposed.authority(),
        hydra_agent::lifecycle_cleanup::AuthorityEvidence::NoActiveRecord
    );
    let pending = match hydra_agent::lifecycle_cleanup::load(dir)? {
        Some(existing) if existing.intent() == intent => {
            hydra_agent::lifecycle_cleanup::store(dir, &proposed, locks)?
        }
        Some(existing)
            if hydra_agent::lifecycle_cleanup::may_supersede(existing.intent(), intent) =>
        {
            hydra_agent::lifecycle_cleanup::supersede(dir, &proposed, locks)?
        }
        Some(existing) => bail!(
            "pending {:?} lifecycle cleanup cannot be replaced by {:?}",
            existing.intent(),
            intent
        ),
        None => hydra_agent::lifecycle_cleanup::store(dir, &proposed, locks)?,
    };
    drive_destructive_cleanup(dir, pending, locks)?;
    Ok(had_enrollment)
}

/// `service uninstall --forget --apply` is a destructive authority change, not
/// merely a service-manager operation. Remove the effective local enrollment
/// before running any guard that can fail while inspecting a legacy manager.
/// The dry-run path must remain observational and call neither closure.
#[cfg(test)]
fn prepare_forget_before_service_guard(
    apply: bool,
    forget: bool,
    remove_local_authority: impl FnOnce() -> Result<()>,
    guard: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if !apply {
        return Ok(());
    }
    if forget {
        remove_local_authority()?;
    }
    guard()
}

/// Resolve only agent-owned/default lifecycle inputs. None of these values are
/// accepted in the public extension argv, and release trust comes exclusively
/// from the compiled private tuple.
fn extension_service_install_plan(
    dir: &std::path::Path,
    descriptor: &LifecycleDescriptor,
) -> Result<(
    hydra_agent::service::ServicePaths,
    hydra_agent::service::ServicePlan,
    PathBuf,
    String,
)> {
    let home =
        hydra_agent::agent_dir::trusted_home_dir().context("resolve effective OS account home")?;
    let label = default_service_label();
    if descriptor.canonical_root != dir || descriptor.desired_paths.agent_dir != dir {
        bail!("lifecycle descriptor is bound to a different enrollment root");
    }
    // Observation and convergence are deliberately separate. A historical
    // systemd FragmentPath remains in `observed_paths` so destructive cleanup
    // can retire it exactly, but every new install is written only to the
    // fixed effective-account location.
    let paths = descriptor.desired_paths.clone();
    let binary = std::env::current_exe().context("resolve installed Hydra agent binary")?;
    if !binary.is_absolute() || !binary.is_file() {
        bail!("installed Hydra agent binary is unavailable");
    }
    let app_support_dir = extension_maestro_app_support_dir(&home);
    let (socket, fixed_external_daemon) =
        extension_daemon_target(&home, dir, &binary, &app_support_dir)?;
    hydra_agent::release_trust::active().validate()?;
    hydra_agent::supervise::validate_enrollment_binding(dir).map_err(anyhow::Error::msg)?;
    let binding = hydra_agent::supervise::service_binding_stamp();
    let install = platform_plan_install(
        &paths,
        PlatformInstallOptions {
            home: &home,
            app_support_dir: &app_support_dir,
            label,
            binary_path: binary.to_string_lossy().into_owned(),
            socket_path: socket.to_string_lossy().into_owned(),
            fixed_external_daemon,
            sessions: Vec::new(),
        },
    );
    Ok((paths, install, socket, binding))
}

fn execute_replacing_service_plan(
    paths: &hydra_agent::service::ServicePaths,
    binding: &str,
    peer_roots: &std::collections::BTreeSet<PathBuf>,
    plan: &hydra_agent::service::ServicePlan,
    runner: &mut dyn hydra_agent::service::ActionRunner,
) -> Result<Vec<String>> {
    let peer_inventory = remote_peer_inventory(peer_roots)?;
    let _captured = capture_running_service_peer(paths, binding, peer_roots, &peer_inventory)?;
    let execution = hydra_agent::service::execute_plan(plan, runner)
        .map_err(anyhow::Error::new)
        .context("execute disruptive remote-service plan");
    let retirement = prove_peer_inventory_stopped(&peer_inventory)
        .context("prove replaced remote-peer retired")
        .map(|_| ());
    match (execution, retirement) {
        (Ok(log), Ok(())) => Ok(log),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(execution_error), Err(retirement_error)) => bail!(
            "{execution_error:#}; replaced remote-peer retirement also failed: {retirement_error:#}"
        ),
    }
}

fn uninstall_extension_service_with_proof(
    paths: &hydra_agent::service::ServicePaths,
    binding: &str,
    peer_roots: &std::collections::BTreeSet<PathBuf>,
    runner: &mut dyn hydra_agent::service::ActionRunner,
) -> Result<()> {
    // Capture happens before the first service-manager or filesystem mutation.
    // The app-owned daemon has no PID in this proof and is never signalled.
    let peer_inventory = remote_peer_inventory(peer_roots)?;
    let _captured = capture_running_service_peer(paths, binding, peer_roots, &peer_inventory)?;
    let (_, mut errors) =
        hydra_agent::service::execute_cleanup_plan(&platform_plan_uninstall(paths, false), runner);
    if let Err(error) =
        hydra_agent::service_readiness::remove_all_service_readiness(&paths.agent_dir)
    {
        errors.push(format!("remove service readiness: {error}"));
    }
    match service_definition_entry_exists(&platform_service_file(paths)) {
        Ok(false) => {}
        Ok(true) => errors.push("service definition still exists".to_string()),
        Err(error) => errors.push(format!("verify service definition removal: {error}")),
    }
    match platform_service_manager_pid(paths) {
        Ok(None) => {}
        Ok(Some(_)) => errors.push("remote service manager is still running".to_string()),
        Err(error) => errors.push(format!("verify remote service manager stopped: {error}")),
    }
    if let Err(error) = prove_peer_inventory_stopped(&peer_inventory) {
        errors.push(format!("verify inventoried remote-peers stopped: {error}"));
    }
    match remote_peer_inventory(peer_roots).and_then(|peers| validate_closed_peer_inventory(&peers))
    {
        Ok(()) => {}
        Err(error) => errors.push(format!(
            "verify zero remote-peer processes after Close: {error}"
        )),
    }
    if errors.is_empty() {
        Ok(())
    } else {
        bail!(errors.join("; "))
    }
}

fn close_extension_service(descriptor: &LifecycleDescriptor) -> Result<()> {
    let paths = descriptor.observed_paths.clone();
    let binding = descriptor
        .running
        .as_ref()
        .and_then(|running| running.runtime_binding_stamp.clone())
        .unwrap_or_else(hydra_agent::supervise::service_binding_stamp);
    let peer_roots = descriptor.peer_roots.clone();
    guard_disruptive_service_change(&paths, "close the remote service")?;
    let mut runner = hydra_agent::service::SystemRunner;
    uninstall_extension_service_with_proof(&paths, &binding, &peer_roots, &mut runner)
}

fn ensure_extension_service(
    dir: &std::path::Path,
    prior_state: ServiceActivationPriorState,
    descriptor: &LifecycleDescriptor,
    lifecycle_locks: &hydra_agent::service::LifecycleLockSet,
) -> Result<()> {
    use hydra_agent::service::{execute_plan, SystemRunner};

    descriptor.require_unambiguous()?;
    let (paths, install, socket, binding) = extension_service_install_plan(dir, descriptor)?;
    let peer_roots = descriptor.peer_roots.clone();
    let exact_definition_installed = service_definition_matches(&install);
    let first_plan = if exact_definition_installed {
        platform_plan_start(&paths)
    } else {
        install.clone()
    };
    // This guard precedes every mutation. Refusal therefore leaves the old
    // service, enrollment, and daemon-owned PTYs exactly as they were; there is
    // nothing to roll back and no authority may be revoked as a side effect of
    // observing an unsafe legacy owner.
    require_pre_mutation_service_guard(|| {
        guard_disruptive_service_change(&paths, "ensure the remote service")
    })?;
    let mut runner = SystemRunner;
    let first = if exact_definition_installed {
        execute_plan(&first_plan, &mut runner).map_err(anyhow::Error::new)
    } else {
        execute_replacing_service_plan(&paths, &binding, &peer_roots, &first_plan, &mut runner)
    };
    match first {
        Ok(_) => {}
        Err(first_error) if exact_definition_installed => {
            if let Err(guard_error) =
                guard_disruptive_service_change(&paths, "repair the remote service")
            {
                return fail_extension_service_activation(
                    anyhow::anyhow!(
                        "start reviewed remote service failed: {first_error}; repair safety guard failed: {guard_error:#}"
                    ),
                    || {
                        rollback_extension_service(
                            dir,
                            prior_state,
                            descriptor,
                            &paths,
                            &peer_roots,
                            lifecycle_locks,
                            &mut runner,
                        )
                    },
                );
            }
            if let Err(error) =
                execute_replacing_service_plan(&paths, &binding, &peer_roots, &install, &mut runner)
            {
                return fail_extension_service_activation(
                    error.context("install reviewed remote service"),
                    || {
                        rollback_extension_service(
                            dir,
                            prior_state,
                            descriptor,
                            &paths,
                            &peer_roots,
                            lifecycle_locks,
                            &mut runner,
                        )
                    },
                );
            }
        }
        Err(error) => {
            return fail_extension_service_activation(
                error.context("install reviewed remote service"),
                || {
                    rollback_extension_service(
                        dir,
                        prior_state,
                        descriptor,
                        &paths,
                        &peer_roots,
                        lifecycle_locks,
                        &mut runner,
                    )
                },
            );
        }
    }

    let first_ready = capture_platform_service_ready_for(
        &paths,
        &socket,
        &hydra_agent::build_stamp(),
        &binding,
        std::time::Duration::from_secs(10),
    );
    let final_readiness = match first_ready {
        Err(first_error) if exact_definition_installed => {
            if let Err(guard_error) =
                guard_disruptive_service_change(&paths, "reload an unready remote service")
            {
                return fail_extension_service_activation(
                    anyhow::anyhow!(
                        "remote service did not become ready: {first_error:#}; reload safety guard failed: {guard_error:#}"
                    ),
                    || {
                        rollback_extension_service(
                            dir,
                            prior_state,
                            descriptor,
                            &paths,
                            &peer_roots,
                            lifecycle_locks,
                            &mut runner,
                        )
                    },
                );
            }
            if let Err(error) =
                execute_replacing_service_plan(&paths, &binding, &peer_roots, &install, &mut runner)
            {
                return fail_extension_service_activation(
                    error.context("reload reviewed remote service"),
                    || {
                        rollback_extension_service(
                            dir,
                            prior_state,
                            descriptor,
                            &paths,
                            &peer_roots,
                            lifecycle_locks,
                            &mut runner,
                        )
                    },
                );
            }
            capture_platform_service_ready_for(
                &paths,
                &socket,
                &hydra_agent::build_stamp(),
                &binding,
                std::time::Duration::from_secs(10),
            )
        }
        other => other,
    };
    let final_readiness = final_readiness.and_then(|readiness| {
        prove_single_ready_service_peer(&paths, &peer_roots, &readiness)?;
        Ok(())
    });
    let definition_matches = service_definition_matches(&install);
    finalize_extension_service_activation(final_readiness, definition_matches, || {
        rollback_extension_service(
            dir,
            prior_state,
            descriptor,
            &paths,
            &peer_roots,
            lifecycle_locks,
            &mut runner,
        )
    })
}

/// The initial owner/session guard runs before any service-manager mutation.
/// Refusal is observational: it cannot revoke an otherwise valid closed
/// enrollment. Destructive fail-closed revocation belongs only to rollback
/// after an Open mutation began and service absence can no longer be proved.
fn require_pre_mutation_service_guard(guard: impl FnOnce() -> Result<()>) -> Result<()> {
    guard().context("initial remote-service safety guard refused Open")
}

fn require_pre_mutation_manager_state<T>(probe: impl FnOnce() -> Result<T>) -> Result<T> {
    probe().context("read remote-service state before Open")
}

fn finalize_extension_service_activation(
    readiness: Result<()>,
    definition_matches: bool,
    rollback: impl FnOnce() -> Result<()>,
) -> Result<()> {
    if let Err(error) = readiness {
        return fail_extension_service_activation(
            error.context("reviewed remote service did not become ready"),
            rollback,
        );
    }
    if !definition_matches {
        return fail_extension_service_activation(
            anyhow::anyhow!("remote service definition changed during lifecycle convergence"),
            rollback,
        );
    }
    Ok(())
}

fn fail_extension_service_activation<T>(
    activation_error: anyhow::Error,
    rollback: impl FnOnce() -> Result<()>,
) -> Result<T> {
    match rollback() {
        Ok(()) => Err(activation_error),
        Err(rollback_error) => {
            bail!("{activation_error:#}; failed to prove a closed rollback: {rollback_error:#}")
        }
    }
}

#[cfg(target_os = "linux")]
fn extension_service_is_open(
    dir: &std::path::Path,
    descriptor: &LifecycleDescriptor,
) -> Result<bool> {
    descriptor.require_unambiguous()?;
    let (paths, install, socket, binding) = extension_service_install_plan(dir, descriptor)?;
    let peer_roots = descriptor.peer_roots.clone();
    if !service_definition_matches(&install) || platform_service_manager_pid(&paths)?.is_none() {
        return Ok(false);
    }
    let readiness = capture_platform_service_ready_for(
        &paths,
        &socket,
        &hydra_agent::build_stamp(),
        &binding,
        std::time::Duration::from_millis(1_250),
    );
    Ok(readiness
        .and_then(|record| prove_single_ready_service_peer(&paths, &peer_roots, &record))
        .is_ok())
}

fn rollback_extension_service(
    dir: &std::path::Path,
    prior_state: ServiceActivationPriorState,
    descriptor: &LifecycleDescriptor,
    paths: &hydra_agent::service::ServicePaths,
    peer_roots: &std::collections::BTreeSet<PathBuf>,
    lifecycle_locks: &hydra_agent::service::LifecycleLockSet,
    runner: &mut dyn hydra_agent::service::ActionRunner,
) -> Result<()> {
    let retirement = uninstall_extension_service_with_proof(
        paths,
        &hydra_agent::supervise::service_binding_stamp(),
        peer_roots,
        runner,
    );
    finish_extension_service_rollback(
        Vec::new(),
        service_definition_entry_exists(&platform_service_file(paths)),
        platform_service_manager_pid(paths),
        retirement,
        prior_state,
        || {
            begin_destructive_cleanup(
                dir,
                hydra_agent::lifecycle_cleanup::CleanupIntent::Remove,
                descriptor,
                lifecycle_locks,
            )
            .map(|_| ())
        },
    )
}

fn service_definition_entry_exists(path: &std::path::Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("read service definition metadata"),
    }
}

/// A failed activation always leaves the independently owned PTY daemon
/// untouched. An already-open package upgrade preserves enrollment because it
/// cannot create new authority. A previously closed Open must either prove the
/// service absent or revoke enrollment, so a failed request cannot silently
/// leave Remote open.
fn finish_extension_service_rollback(
    mut errors: Vec<String>,
    definition_exists: Result<bool>,
    manager_pid: Result<Option<u32>>,
    peer_retirement: Result<()>,
    prior_state: ServiceActivationPriorState,
    revoke_local_authority: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let mut absence_proved = true;
    match definition_exists {
        Ok(false) => {}
        Ok(true) => {
            absence_proved = false;
            errors.push("service definition still exists after rollback".to_string());
        }
        Err(error) => {
            absence_proved = false;
            errors.push(format!("verify service definition removal: {error}"));
        }
    }
    match manager_pid {
        Ok(None) => {}
        Ok(Some(_)) => {
            absence_proved = false;
            errors.push("remote service is still running after rollback".to_string());
        }
        Err(error) => {
            absence_proved = false;
            errors.push(format!("verify remote service stopped: {error}"));
        }
    }
    if let Err(error) = peer_retirement {
        absence_proved = false;
        errors.push(format!("verify exact remote-peer retirement: {error}"));
    }
    if !absence_proved && prior_state != ServiceActivationPriorState::ProvenOpen {
        if let Err(error) = revoke_local_authority() {
            errors.push(format!(
                "revoke enrollment after unproved closed-state activation rollback: {error}"
            ));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        bail!(errors.join("; "))
    }
}

/// Atomically stop the persistent connectivity service and revoke the local
/// enrollment under the same lifecycle lock used by `service ensure`. All
/// cleanup steps are attempted; success is reported only after exact local
/// postconditions are verified.
fn run_remove_remote_cmd(args: &[String], dir: &std::path::Path) -> Result<()> {
    if !args.iter().any(|arg| arg == "--apply") {
        bail!("remove-remote modifies this desktop; re-run with --apply");
    }
    let (locks, descriptor) = acquire_lifecycle_context(
        dir,
        Some(hydra_agent::lifecycle_cleanup::CleanupIntent::Remove),
    )
    .context("capture deterministic remote lifecycle")?;
    begin_destructive_cleanup(
        dir,
        hydra_agent::lifecycle_cleanup::CleanupIntent::Remove,
        &descriptor,
        &locks,
    )?;
    println!("remove-remote: service stopped and local enrollment cleared");
    Ok(())
}

/// `supervise` — the local persistent process model (Slice C, child processes): start/monitor pty-daemon +
/// ensure the default session(s) + start/monitor remote-peer. `--dry-run` prints the plan and exits without
/// starting anything. Identity loads from device.json (no `--account`/`--device-id`).
fn run_supervise_cmd(args: &[String], dir: &std::path::Path) -> Result<()> {
    use hydra_agent::supervise::{dry_run_plan, run, SuperviseOptions};

    let explicit_sock = flag(args, "--sock")
        .unwrap_or_else(|| default_daemon_socket().to_string_lossy().into_owned());
    let attach_daemon_only = supervise_standalone_flag(args, "--attach-daemon-only");
    let fixed_external_daemon = supervise_standalone_flag(args, "--fixed-daemon-only");
    if fixed_external_daemon && !attach_daemon_only {
        bail!("--fixed-daemon-only requires --attach-daemon-only")
    }
    // If the desktop app publishes a live daemon (via MAESTRO_APP_SUPPORT_DIR/daemon/endpoint.json), attach to it:
    // use that socket AND don't run our own pty-daemon (own_daemon=false), so the browser sees the desktop's live
    // projects/sessions. Otherwise supervise owns a standalone daemon on --sock (own_daemon=true), as before.
    let resolved = if fixed_external_daemon {
        daemon_socket_resolution(PathBuf::from(&explicit_sock), None)
    } else {
        resolve_desktop_daemon_sock_with_source(PathBuf::from(&explicit_sock))
    };
    // Ownership is about WHERE the choice came from, never whether two path strings happen to be
    // equal. A desktop can publish the exact same path as --sock; that is still attach mode.
    // Product-installed services are explicitly attach-only. PTY ownership is
    // independent from the replaceable connectivity agent so an agent upgrade,
    // crash, uninstall, or service-manager restart can never kill retained PTYs.
    // Direct operator/dev `supervise` keeps the legacy inferred behavior.
    let own_daemon = supervisor_owns_daemon(attach_daemon_only, resolved.from_published_endpoint);
    let socket_path = resolved.path.to_string_lossy().into_owned();
    hydra_agent::release_trust::active().validate()?;
    // E4: default to NO pre-seeded sessions — the browser creates them on demand. `--sessions s1,s2`
    // still seeds explicitly (operator/test/back-compat).
    let sessions: Vec<String> = flag(args, "--sessions")
        .map(|s| {
            s.split(',')
                .filter(|x| !x.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    // default the pty-daemon binary to a sibling of this executable; the agent binary to the current exe.
    let self_exe = std::env::current_exe().ok();
    let pty_daemon_bin = flag(args, "--pty-daemon-bin").unwrap_or_else(|| {
        self_exe
            .as_ref()
            .and_then(|p| p.parent())
            .map(|d| d.join("pty-daemon").to_string_lossy().into_owned())
            .unwrap_or_else(|| "pty-daemon".to_string())
    });
    let hydra_agent_bin = flag(args, "--hydra-agent-bin").unwrap_or_else(|| {
        self_exe
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| "hydra-agent".to_string())
    });

    let opts = SuperviseOptions {
        agent_dir: dir.to_path_buf(),
        socket_path,
        sessions,
        pty_daemon_bin,
        hydra_agent_bin,
        own_daemon,
        fixed_external_daemon,
    };

    if args.iter().any(|a| a == "--dry-run") {
        print!("{}", dry_run_plan(&opts));
        return Ok(());
    }
    let home =
        hydra_agent::agent_dir::trusted_home_dir().context("resolve effective OS account home")?;
    run(&opts, &home.to_string_lossy())
}

/// `health` — a content-blind, READ-ONLY readiness readout for the remote path. Reports enrolled identity,
/// daemon-socket reachability, supervise/remote-peer presence, and launchd-plist presence — never any secret.
/// Exits non-zero on NOT READY so it's scriptable. Mutates nothing.
fn run_health_cmd(args: &[String], dir: &std::path::Path) -> Result<()> {
    use hydra_agent::health::{assess, gather, render, Verdict};

    let socket_path = flag(args, "--sock")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(default_daemon_socket);

    // Persistent-install signal: the launchd plist on macOS, the systemd user unit on Linux.
    // Best-effort: missing HOME/uid → no service file.
    let plist_present = {
        let home = std::env::var("HOME").ok().map(std::path::PathBuf::from);
        let uid = current_uid_string();
        match (home, uid) {
            (Some(home), Some(uid)) => {
                let paths = platform_service_paths(&home, dir, health_service_label(), &uid);
                platform_service_file(&paths).exists()
            }
            _ => false,
        }
    };

    // content-blind process detection via `pgrep -f <pattern>` (matches the full argv, like the triage script).
    let proc_matches = |pattern: &str| {
        std::process::Command::new("pgrep")
            .arg("-f")
            .arg(pattern)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    };

    let facts = gather(dir, &socket_path, plist_present, now_ms(), proc_matches);
    let report = assess(&facts);
    print!("{}", render(&report));
    if report.verdict == Verdict::NotReady {
        std::process::exit(1);
    }
    Ok(())
}

/// The daemon's default socket path when `--sock` is omitted — the SAME per-user resolution the
/// daemon and the desktop app use (`XDG_RUNTIME_DIR` → `TMPDIR` → `/tmp` + the shared filename),
/// via `maestro_shell::default_socket_path`. Keeping every component on one resolver means a
/// fresh install talks to itself out of the box in the user's own runtime dir (no permissions
/// needed beyond the user's), instead of one side defaulting to a world-shared `/tmp` name.
fn default_daemon_socket() -> PathBuf {
    maestro_shell::default_socket_path(&|k: &str| std::env::var(k).ok())
}

/// The service name whose installed definition `health` looks for. macOS deployments install
/// under the canonical `com.hydra.agent` launchd label; Linux uses the `hydra-agent` systemd unit.
#[cfg(target_os = "macos")]
fn health_service_label() -> &'static str {
    "com.hydra.agent"
}

#[cfg(not(target_os = "macos"))]
fn health_service_label() -> &'static str {
    "hydra-agent"
}

/// The current uid as a string (for the launchd service target), or None. `id -u` avoids a libc dependency;
/// content-blind (a uid number only).
fn current_uid_string() -> Option<String> {
    std::process::Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

const SERVICE_USAGE: &str = "usage: hydra-agent service <install|ensure|start|uninstall|status> [--dry-run|--apply] [opts]\n  install/ensure: --binary-path <path> [--sessions s1,s2] [--sock <path>] [--app-support-dir <absolute-path>] [--label <l>]\n  cloud, browser-origin, and verifier trust are compiled into the private agent and have no runtime flags\n  ensure: replace a stale definition, otherwise non-disruptively start, then verify readiness\n  start: starts an installed service without replacing a healthy process\n  uninstall: [--forget]   status: (read-only)";

/// `service` command group. The safe path previews plans with --dry-run; the mutating executor is gated
/// behind an explicit --apply:
///   hydra-agent service install --dry-run --binary-path <path> [--sessions s1,s2]
///                              [--sock <path>] [--log-dir <path>] [--label <label>]
///   hydra-agent service install --apply --binary-path <path> [...]
/// The dry-run path writes nothing; --apply writes the plist and runs launchctl.
fn run_service_cmd(args: &[String], dir: &std::path::Path) -> Result<()> {
    use hydra_agent::service::{
        execute_plan, human_summary, is_mutating, render_plan, ServicePlan, SystemRunner,
    };

    let sub = args.get(2).map(String::as_str).unwrap_or("");
    let dry_run = args.iter().any(|a| a == "--dry-run");
    let label = flag(args, "--label").unwrap_or_else(|| default_service_label().to_string());
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    let uid = flag(args, "--uid").unwrap_or_else(|| {
        // SAFETY: getuid() is always available + has no failure mode.
        unsafe { libc_getuid() }.to_string()
    });
    let paths = platform_service_paths(&home, dir, &label, &uid);
    let apply = args.iter().any(|a| a == "--apply");
    let forget = sub == "uninstall" && args.iter().any(|a| a == "--forget");
    if apply && dry_run {
        bail!("--apply and --dry-run are mutually exclusive");
    }
    if apply && forget {
        if flag(args, "--label").is_some() || flag(args, "--uid").is_some() {
            bail!("service uninstall --forget uses only the fixed production service identity");
        }
        let (locks, descriptor) = acquire_lifecycle_context(
            dir,
            Some(hydra_agent::lifecycle_cleanup::CleanupIntent::FullForget),
        )
        .context("capture deterministic remote lifecycle")?;
        begin_destructive_cleanup(
            dir,
            hydra_agent::lifecycle_cleanup::CleanupIntent::FullForget,
            &descriptor,
            &locks,
        )?;
        println!("service uninstall --forget: remote authority and stable key removed");
        return Ok(());
    }
    // Re-read and execute the whole convergence decision while holding one
    // cross-process lock. Multiple app windows therefore cannot race each other
    // or reinstall the service during Remove Remote.
    let _lifecycle_lock = if apply && sub != "status" {
        Some(
            hydra_agent::service::LifecycleLock::acquire(dir)
                .context("locking Hydra agent lifecycle")?,
        )
    } else {
        None
    };
    if apply
        && matches!(sub, "ensure" | "install" | "start")
        && hydra_agent::device_identity::is_enrolled(dir).is_none()
    {
        bail!("Hydra agent is not enrolled; refusing to install or start its service");
    }

    // D1: build the PLAN only; never execute. A mutating plan without --dry-run fails clearly (D2 will add
    // a human-gated executor).
    let mut ensure_fallback_install: Option<ServicePlan> = None;
    let mut ensure_used_start = false;
    let mut ensure_expected_socket: Option<PathBuf> = None;
    let mut ensure_expected_binding: Option<String> = None;
    let plan: ServicePlan = match sub {
        "install" | "ensure" => {
            let binary_path = flag(args, "--binary-path")
                .ok_or_else(|| anyhow::anyhow!("service install requires --binary-path <path>"))?;
            if binary_path.contains("target/debug") || binary_path.contains("target/release") {
                eprintln!(
                    "note: {binary_path} is a repo build path (dev-only). A real install should use an \
                     installed binary (e.g. /usr/local/bin/hydra-agent)."
                );
            }
            // E4: the installed service defaults to NO pre-seeded sessions (browser-created on demand);
            // `--sessions` still seeds explicitly into the generated service definition.
            let sessions: Vec<String> = flag(args, "--sessions")
                .map(|s| {
                    s.split(',')
                        .filter(|x| !x.is_empty())
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default();
            let socket_path = flag(args, "--sock")
                .unwrap_or_else(|| default_daemon_socket().to_string_lossy().into_owned());
            // Retain the exact socket for both readiness (`ensure`) and the
            // retained-session safety guard (`install` and `ensure`).
            ensure_expected_socket = Some(PathBuf::from(&socket_path));
            hydra_agent::release_trust::active().validate()?;
            if apply {
                hydra_agent::supervise::validate_enrollment_binding(dir)
                    .map_err(anyhow::Error::msg)?;
            }
            ensure_expected_binding = Some(hydra_agent::supervise::service_binding_stamp());
            let app_support_dir = service_app_support_dir(args, &home)?;
            let install = platform_plan_install(
                &paths,
                PlatformInstallOptions {
                    home: &home,
                    app_support_dir: &app_support_dir,
                    label: &label,
                    binary_path,
                    socket_path,
                    fixed_external_daemon: false,
                    sessions,
                },
            );
            if sub == "ensure" {
                ensure_fallback_install = Some(install.clone());
                if service_definition_matches(&install) {
                    ensure_used_start = true;
                    platform_plan_start(&paths)
                } else {
                    install
                }
            } else {
                install
            }
        }
        "start" => platform_plan_start(&paths),
        "uninstall" => platform_plan_uninstall(&paths, forget),
        "status" => platform_plan_status(&paths),
        _ => bail!(SERVICE_USAGE),
    };

    // --apply REALLY executes (writes the plist, runs launchctl, removes files). Human-gated: it must be
    // requested explicitly; without it, a mutating plan stays a dry-run print and never touches the machine.
    if apply && is_mutating(&plan) {
        eprint!("{}", human_summary(&plan));
        let mut runner = SystemRunner;
        if matches!(sub, "install" | "ensure" | "uninstall") {
            guard_disruptive_service_change(&paths, sub)?;
        }
        let mut log = match execute_plan(&plan, &mut runner) {
            Ok(log) => log,
            Err(start_error) if sub == "ensure" && ensure_used_start => {
                let install = ensure_fallback_install
                    .as_ref()
                    .expect("ensure start always retains its install fallback");
                guard_disruptive_service_change(&paths, "repair an unstartable service")?;
                eprintln!(
                    "service ensure: installed definition was not startable ({start_error}); replacing it"
                );
                execute_plan(install, &mut runner)
                    .context("applying fallback service install plan")?
            }
            Err(error) => return Err(error).context("applying service plan"),
        };
        if sub == "ensure" {
            let readiness = wait_for_platform_service_ready(
                &paths,
                ensure_expected_socket
                    .as_deref()
                    .expect("service ensure records its exact socket"),
                &hydra_agent::build_stamp(),
                ensure_expected_binding
                    .as_deref()
                    .expect("service ensure records its exact cloud binding"),
            );
            if let Err(first_error) = readiness {
                // The file may already contain the new definition while the
                // service manager still caches/runs the old one after a prior
                // interrupted install. Perform exactly one guarded reload and
                // then require the same exact readiness proof again.
                if ensure_used_start {
                    let install = ensure_fallback_install
                        .as_ref()
                        .expect("ensure start always retains its install fallback");
                    let socket = ensure_expected_socket
                        .as_deref()
                        .expect("service ensure records its exact socket");
                    guard_disruptive_service_change(&paths, "repair stale service-manager state")?;
                    eprintln!(
                        "service ensure: start did not reach exact readiness ({first_error}); reloading once"
                    );
                    log.extend(
                        execute_plan(install, &mut runner)
                            .context("reloading stale service-manager definition")?,
                    );
                    wait_for_platform_service_ready(
                        &paths,
                        socket,
                        &hydra_agent::build_stamp(),
                        ensure_expected_binding
                            .as_deref()
                            .expect("service ensure records its exact cloud binding"),
                    )
                    .context("service remained unready after one guarded reload")?;
                } else {
                    return Err(first_error);
                }
            }
        }
        for line in log {
            println!("  ✓ {line}");
        }
        return Ok(());
    }
    if !dry_run && is_mutating(&plan) {
        bail!(
            "this would modify your machine (write a launchd plist + run launchctl). Re-run with --dry-run \
             to preview, or --apply to actually install/uninstall."
        );
    }
    print!("{}", render_plan(&plan));
    Ok(())
}

fn service_definition_matches(plan: &hydra_agent::service::ServicePlan) -> bool {
    let Some((path, expected)) = plan.actions.iter().find_map(|action| match action {
        hydra_agent::service::ServiceAction::WriteFile { path, contents } => Some((path, contents)),
        _ => None,
    }) else {
        return false;
    };
    std::fs::read_to_string(path)
        .map(|actual| actual == *expected)
        .unwrap_or(false)
}

fn validated_build_stamp(value: &str) -> Result<String> {
    let (git, built) = value
        .strip_prefix("git=")
        .and_then(|value| value.split_once(" built="))
        .ok_or_else(|| anyhow::anyhow!("service build stamp has an invalid shape"))?;
    if git.is_empty()
        || git.len() > 96
        || !git
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || built.is_empty()
        || built.len() > 24
        || !built.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("service build stamp is not a bounded canonical value");
    }
    Ok(value.to_string())
}

#[cfg(test)]
fn exactly_one_between<'a>(text: &'a str, prefix: &str, suffix: &str) -> Result<&'a str> {
    let mut matches = text.match_indices(prefix);
    let (prefix_offset, _) = matches
        .next()
        .ok_or_else(|| anyhow::anyhow!("service definition omits its build stamp"))?;
    if matches.next().is_some() {
        bail!("service definition contains more than one build stamp");
    }
    let value = &text[prefix_offset + prefix.len()..];
    let end = value
        .find(suffix)
        .ok_or_else(|| anyhow::anyhow!("service definition build stamp is unterminated"))?;
    Ok(&value[..end])
}

#[cfg(test)]
fn parse_launchd_build_stamp(definition: &str) -> Result<String> {
    validated_build_stamp(exactly_one_between(
        definition,
        "<key>HYDRA_AGENT_BUILD_STAMP</key>\n    <string>",
        "</string>",
    )?)
}

#[cfg(test)]
fn parse_systemd_build_stamp(definition: &str) -> Result<String> {
    validated_build_stamp(exactly_one_between(
        definition,
        "Environment=\"HYDRA_AGENT_BUILD_STAMP=",
        "\"",
    )?)
}

fn installed_service_definition(path: &std::path::Path) -> Result<String> {
    let bytes = read_owned_service_definition(path)?
        .ok_or_else(|| anyhow::anyhow!("installed Hydra service definition is absent"))?;
    if bytes.is_empty() {
        bail!("installed Hydra service definition is empty");
    }
    String::from_utf8(bytes).context("installed Hydra service definition is not UTF-8")
}

#[cfg(target_os = "macos")]
fn installed_service_build_stamp(paths: &hydra_agent::service::ServicePaths) -> Result<String> {
    let definition = installed_service_definition(&platform_service_file(paths))?;
    Ok(parse_full_launchd_service_definition(definition.as_bytes())?.build_stamp)
}

#[cfg(not(target_os = "macos"))]
fn installed_service_build_stamp(paths: &hydra_agent::service::ServicePaths) -> Result<String> {
    let definition = installed_service_definition(&platform_service_file(paths))?;
    Ok(parse_full_systemd_service_definition(definition.as_bytes())?.build_stamp)
}

fn wait_for_platform_service_ready(
    paths: &hydra_agent::service::ServicePaths,
    expected_socket_path: &std::path::Path,
    expected_build_stamp: &str,
    expected_binding_stamp: &str,
) -> Result<()> {
    capture_platform_service_ready_for(
        paths,
        expected_socket_path,
        expected_build_stamp,
        expected_binding_stamp,
        std::time::Duration::from_secs(10),
    )
    .map(|_| ())
}

fn wait_for_platform_service_ready_for(
    paths: &hydra_agent::service::ServicePaths,
    expected_socket_path: &std::path::Path,
    expected_build_stamp: &str,
    expected_binding_stamp: &str,
    timeout: std::time::Duration,
) -> Result<()> {
    capture_platform_service_ready_for(
        paths,
        expected_socket_path,
        expected_build_stamp,
        expected_binding_stamp,
        timeout,
    )
    .map(|_| ())
}

/// Ask the exact live service manager for a fresh, request-bound readiness
/// answer and retain the remote-peer PID in memory. Callers that are about to
/// replace or remove the service use that PID to prove the old connectivity
/// child did not escape its manager. The readiness files are still removed
/// before this function returns; the returned record is the proof artifact.
fn capture_platform_service_ready_for(
    paths: &hydra_agent::service::ServicePaths,
    expected_socket_path: &std::path::Path,
    expected_build_stamp: &str,
    expected_binding_stamp: &str,
    timeout: std::time::Duration,
) -> Result<hydra_agent::service_readiness::ServiceReadinessRecord> {
    capture_platform_service_ready_in_dir_for(
        paths,
        &paths.agent_dir,
        expected_socket_path,
        expected_build_stamp,
        expected_binding_stamp,
        timeout,
    )
}

fn capture_platform_service_ready_in_dir_for(
    paths: &hydra_agent::service::ServicePaths,
    readiness_agent_dir: &std::path::Path,
    expected_socket_path: &std::path::Path,
    expected_build_stamp: &str,
    expected_binding_stamp: &str,
    timeout: std::time::Duration,
) -> Result<hydra_agent::service_readiness::ServiceReadinessRecord> {
    let deadline = std::time::Instant::now() + timeout;
    let mut manager_tracker = PlatformServiceReadinessTracker::default();
    loop {
        let Some(expected_manager_pid) =
            platform_service_manager_pid_for_readiness(paths, &mut manager_tracker)?
        else {
            if std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
            continue;
        };
        let request = hydra_agent::service_readiness::ServiceReadinessRequest::new(
            expected_manager_pid,
            expected_socket_path.to_path_buf(),
            expected_build_stamp.to_string(),
            expected_binding_stamp.to_string(),
            now_ms(),
        );
        hydra_agent::service_readiness::remove_all_service_readiness(readiness_agent_dir)
            .context("clearing stale local service readiness")?;
        hydra_agent::service_readiness::write_service_readiness_request(
            readiness_agent_dir,
            &request,
        )
        .context("requesting local service readiness")?;
        let mut progress = hydra_agent::service_readiness::ServiceReadinessProgress::default();
        while std::time::Instant::now() < deadline {
            let manager_pid =
                platform_service_manager_pid_for_readiness(paths, &mut manager_tracker)?;
            if manager_pid.is_some_and(|pid| pid != expected_manager_pid) {
                // Every supported platform tracker pins one manager
                // generation. A replacement may not inherit the predecessor's
                // request even when it appears within the original deadline.
                bail!("remote service manager changed during readiness");
            }
            if manager_pid == Some(expected_manager_pid) {
                // launchd can expose the new manager before the supervisor's
                // startup cleanup runs. That cleanup deliberately withdraws
                // stale request/answer bytes, so restore this same immutable
                // request only when neither it nor its exact answer exists.
                // The original deadline is never extended.
                hydra_agent::service_readiness::restore_service_readiness_request_if_empty(
                    readiness_agent_dir,
                    &request,
                )
                .context("restoring local service readiness request")?;
            }
            let record =
                hydra_agent::service_readiness::load_service_readiness(readiness_agent_dir)
                    .context("reading local service readiness")?;
            let live = match (manager_pid, record.as_ref()) {
                (Some(manager_pid), Some(record)) => {
                    process_is_live_non_zombie(record.peer_pid)
                        && daemon_socket_is_usable(expected_socket_path)
                        && record.supervisor_pid == manager_pid
                }
                _ => false,
            };
            if progress.observe(record.as_ref(), &request, expected_manager_pid, live) {
                let accepted =
                    record.expect("accepted readiness progress always has an exact record");
                hydra_agent::service_readiness::remove_all_service_readiness(readiness_agent_dir)
                    .context("cleaning completed local readiness handshake")?;
                return Ok(accepted);
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        break;
    }
    let _ = hydra_agent::service_readiness::remove_all_service_readiness(readiness_agent_dir);
    bail!(
        "Hydra agent service started, but its exact remote peer and retained daemon did not become locally ready"
    )
}

/// Snapshot the exact connectivity child owned by the current service manager.
/// A manager that is absent twice has no child to retire. A live manager must
/// answer one fresh readiness request using its installed build definition and
/// current socket, and must remain the same manager through the final read.
fn supervisor_readiness_agent_dir<'a>(
    canonical_agent_dir: &'a std::path::Path,
    invocation: &'a RunningSupervisorInvocation,
) -> &'a std::path::Path {
    invocation
        .agent_dir
        .as_deref()
        .unwrap_or(canonical_agent_dir)
}

fn capture_running_service_peer(
    paths: &hydra_agent::service::ServicePaths,
    expected_binding_stamp: &str,
    peer_roots: &std::collections::BTreeSet<PathBuf>,
    peer_inventory: &std::collections::BTreeSet<u32>,
) -> Result<Option<u32>> {
    let Some(manager_pid) = platform_service_manager_pid(paths)? else {
        // Close the absent -> starting race without waiting ten seconds on the
        // ordinary already-closed path.
        if platform_service_manager_pid(paths)?.is_none() {
            return Ok(None);
        }
        bail!("remote service manager appeared during its retirement preflight");
    };
    let invocation = parse_supervisor_invocation(&manager_process_arguments(manager_pid)?)
        .context("read exact running supervisor invocation before service mutation")?;
    if !invocation.attach_daemon_only {
        bail!("running service owns the retained PTY daemon; refusing lifecycle mutation");
    }
    let installed_build_stamp = installed_service_build_stamp(paths)?;
    let readiness_agent_dir = supervisor_readiness_agent_dir(&paths.agent_dir, &invocation);
    if !peer_roots.contains(readiness_agent_dir) {
        bail!("running service readiness directory is outside its proven enrollment roots");
    }
    let record = capture_platform_service_ready_in_dir_for(
        paths,
        readiness_agent_dir,
        &invocation.socket_path,
        &installed_build_stamp,
        expected_binding_stamp,
        std::time::Duration::from_secs(5),
    )
    .context("capture fresh exact service readiness before mutation")?;
    if record.supervisor_pid != manager_pid {
        bail!("remote service manager changed during its retirement preflight");
    }
    if platform_service_manager_pid(paths)? != Some(manager_pid) {
        bail!("remote service manager changed after its readiness answer");
    }
    if !process_is_live_exact(record.peer_pid)
        .context("recheck captured remote-peer before service mutation")?
    {
        bail!("captured remote-peer exited before service mutation");
    }
    if !peer_inventory.contains(&record.peer_pid) {
        bail!("fresh readiness peer is absent from the stable pre-mutation inventory");
    }
    Ok(Some(record.peer_pid))
}

fn daemon_socket_is_usable(path: &std::path::Path) -> bool {
    let Ok(mut client) = maestro_shell::DaemonClient::connect(path) else {
        return false;
    };
    client.list_sessions().is_ok()
}

fn classify_process_ps(
    success: bool,
    exit_code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<bool> {
    if success {
        let states = stdout
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        if states.len() != 1 || states[0].is_empty() {
            bail!("process liveness output was missing or ambiguous");
        }
        return Ok(states[0][0] != b'Z');
    }
    // Both BSD ps (macOS) and procps ps (Linux) return 1 with no output when
    // the exact PID no longer exists. Any diagnostic, signal termination, or
    // different status is an unreadable proof rather than absence.
    if exit_code == Some(1)
        && stdout.iter().all(|byte| byte.is_ascii_whitespace())
        && stderr.iter().all(|byte| byte.is_ascii_whitespace())
    {
        return Ok(false);
    }
    bail!("process liveness probe failed ambiguously")
}

fn process_is_live_exact(pid: u32) -> Result<bool> {
    if pid == 0 {
        bail!("process liveness probe received PID zero");
    }
    let output = std::process::Command::new(hydra_agent::headless::PS_PATH)
        .args(["-o", "stat=", "-p", &pid.to_string()])
        .output()
        .context("running exact process liveness probe")?;
    classify_process_ps(
        output.status.success(),
        output.status.code(),
        &output.stdout,
        &output.stderr,
    )
}

fn process_is_live_non_zombie(pid: u32) -> bool {
    process_is_live_exact(pid).unwrap_or(false)
}

#[cfg(test)]
fn prove_exact_peer_stopped_with(
    peer_pid: u32,
    attempts: usize,
    mut process_is_live: impl FnMut(u32) -> Result<bool>,
    mut pause: impl FnMut(),
) -> Result<()> {
    if attempts == 0 {
        bail!("exact peer-exit proof has no observations");
    }
    for attempt in 0..attempts {
        if !process_is_live(peer_pid)
            .with_context(|| format!("read exact remote-peer PID {peer_pid}"))?
        {
            return Ok(());
        }
        if attempt + 1 < attempts {
            pause();
        }
    }
    bail!("exact remote-peer PID {peer_pid} survived service retirement")
}

fn prove_peer_inventory_stopped_with(
    peer_pids: &std::collections::BTreeSet<u32>,
    attempts: usize,
    mut process_is_live: impl FnMut(u32) -> Result<bool>,
    mut pause: impl FnMut(),
) -> Result<()> {
    if attempts == 0 {
        bail!("remote-peer inventory exit proof has no observations");
    }
    let mut remaining = peer_pids.clone();
    for attempt in 0..attempts {
        let observed = remaining.iter().copied().collect::<Vec<_>>();
        for pid in observed {
            if !process_is_live(pid)
                .with_context(|| format!("read inventoried remote-peer PID {pid}"))?
            {
                remaining.remove(&pid);
            }
        }
        if remaining.is_empty() {
            return Ok(());
        }
        if attempt + 1 < attempts {
            pause();
        }
    }
    bail!(
        "{} inventoried remote-peer process(es) survived service retirement",
        remaining.len()
    )
}

fn prove_peer_inventory_stopped(peer_pids: &std::collections::BTreeSet<u32>) -> Result<()> {
    prove_peer_inventory_stopped_with(peer_pids, 41, process_is_live_exact, || {
        std::thread::sleep(std::time::Duration::from_millis(125))
    })
}

fn validate_closed_peer_inventory(peers: &std::collections::BTreeSet<u32>) -> Result<()> {
    if peers.is_empty() {
        Ok(())
    } else {
        bail!(
            "Close left {} same-account remote-peer process(es) for this enrollment root",
            peers.len()
        )
    }
}

fn validate_single_peer_inventory(
    peers: &std::collections::BTreeSet<u32>,
    expected_peer_pid: u32,
) -> Result<()> {
    if peers.len() == 1 && peers.contains(&expected_peer_pid) {
        Ok(())
    } else {
        bail!(
            "remote service inventory is not the one exact newly-qualified peer (found {})",
            peers.len()
        )
    }
}

fn prove_single_ready_service_peer(
    paths: &hydra_agent::service::ServicePaths,
    peer_roots: &std::collections::BTreeSet<PathBuf>,
    readiness: &hydra_agent::service_readiness::ServiceReadinessRecord,
) -> Result<()> {
    if platform_service_manager_pid(paths)? != Some(readiness.supervisor_pid) {
        bail!("qualified service manager changed before final inventory proof");
    }
    if !process_is_live_exact(readiness.peer_pid).context("read newly-qualified remote-peer PID")? {
        bail!("newly-qualified remote-peer is no longer live");
    }
    validate_single_peer_inventory(&remote_peer_inventory(peer_roots)?, readiness.peer_pid)
}

fn supervise_standalone_flag(args: &[String], wanted: &str) -> bool {
    let mut index = 2;
    while index < args.len() {
        let argument = args[index].as_str();
        if argument == wanted {
            return true;
        }
        index += if matches!(
            argument,
            "--dir"
                | "--sock"
                | "--environment"
                | "--expected-cloud"
                | "--cloud-pubkey"
                | "--allowed-origin"
                | "--sessions"
                | "--pty-daemon-bin"
                | "--hydra-agent-bin"
        ) {
            2
        } else {
            1
        };
    }
    false
}

fn legacy_manager_change_is_safe(session_count: Result<usize, ()>) -> bool {
    matches!(session_count, Ok(0))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LegacySupervisorTrust {
    environment: String,
    expected_cloud: String,
    cloud_pubkey: String,
    allowed_origin: String,
}

impl LegacySupervisorTrust {
    fn binding_stamp(&self) -> String {
        use sha2::{Digest as _, Sha256};
        let mut digest = Sha256::new();
        for value in [
            "hydra.remote-service-binding.v1",
            self.environment.as_str(),
            self.expected_cloud.as_str(),
            self.cloud_pubkey.as_str(),
            self.allowed_origin.as_str(),
        ] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        digest
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RunningSupervisorInvocation {
    attach_daemon_only: bool,
    fixed_external_daemon: bool,
    agent_dir: Option<PathBuf>,
    socket_path: PathBuf,
    legacy_trust: Option<LegacySupervisorTrust>,
}

fn parse_supervisor_invocation(arguments: &[Vec<u8>]) -> Result<RunningSupervisorInvocation> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    if arguments.get(1).map(Vec::as_slice) != Some(b"supervise") {
        bail!("manager process is not a Hydra supervisor invocation");
    }
    let mut attach_daemon_only = false;
    let mut fixed_external_daemon = false;
    let mut agent_dir = None;
    let mut socket_path = None;
    let mut legacy_trust = std::collections::BTreeMap::<&'static str, String>::new();
    let mut index = 2;
    while index < arguments.len() {
        match arguments[index].as_slice() {
            b"--attach-daemon-only" => {
                attach_daemon_only = true;
                index += 1;
            }
            b"--fixed-daemon-only" => {
                fixed_external_daemon = true;
                index += 1;
            }
            flag @ (b"--dir" | b"--sock" | b"--environment" | b"--expected-cloud"
            | b"--cloud-pubkey" | b"--allowed-origin" | b"--sessions"
            | b"--pty-daemon-bin" | b"--hydra-agent-bin") => {
                let value = arguments.get(index + 1).ok_or_else(|| {
                    anyhow::anyhow!(
                        "manager supervisor argument {:?} has no value",
                        String::from_utf8_lossy(flag)
                    )
                })?;
                if flag == b"--dir" {
                    if agent_dir.is_some() {
                        bail!("manager supervisor has more than one --dir value");
                    }
                    agent_dir = Some(PathBuf::from(OsString::from_vec(value.clone())));
                } else if flag == b"--sock" {
                    if socket_path.is_some() {
                        bail!("manager supervisor has more than one --sock value");
                    }
                    socket_path = Some(PathBuf::from(OsString::from_vec(value.clone())));
                } else if let Some(name) = match flag {
                    b"--environment" => Some("environment"),
                    b"--expected-cloud" => Some("expected_cloud"),
                    b"--cloud-pubkey" => Some("cloud_pubkey"),
                    b"--allowed-origin" => Some("allowed_origin"),
                    _ => None,
                } {
                    let value = std::str::from_utf8(value)
                        .context("manager supervisor trust value is not UTF-8")?;
                    if value.is_empty()
                        || value.len() > 4096
                        || value.chars().any(char::is_control)
                        || legacy_trust.insert(name, value.to_string()).is_some()
                    {
                        bail!("manager supervisor trust tuple is invalid");
                    }
                }
                index += 2;
            }
            unknown => bail!(
                "manager supervisor has an unknown argument {:?}",
                String::from_utf8_lossy(unknown)
            ),
        }
    }
    let socket_path = socket_path
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| anyhow::anyhow!("manager supervisor has no provable --sock value"))?;
    let legacy_trust = if legacy_trust.is_empty() {
        None
    } else if legacy_trust.len() == 4 {
        Some(LegacySupervisorTrust {
            environment: legacy_trust.remove("environment").unwrap(),
            expected_cloud: legacy_trust.remove("expected_cloud").unwrap(),
            cloud_pubkey: legacy_trust.remove("cloud_pubkey").unwrap(),
            allowed_origin: legacy_trust.remove("allowed_origin").unwrap(),
        })
    } else {
        bail!("manager supervisor has a partial legacy trust tuple");
    };
    if fixed_external_daemon && !attach_daemon_only {
        bail!("fixed-daemon supervisor mode is not attach-only");
    }
    Ok(RunningSupervisorInvocation {
        attach_daemon_only,
        fixed_external_daemon,
        agent_dir,
        socket_path,
        legacy_trust,
    })
}

#[cfg(any(not(target_os = "macos"), test))]
fn parse_nul_arguments(bytes: &[u8]) -> Vec<Vec<u8>> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .map(<[u8]>::to_vec)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagerProcessSnapshot {
    arguments: Vec<Vec<u8>>,
    environment: Vec<u8>,
}

#[cfg(target_os = "macos")]
fn parse_macos_procargs2_snapshot(bytes: &[u8]) -> Result<ManagerProcessSnapshot> {
    let argc_bytes: [u8; std::mem::size_of::<libc::c_int>()] = bytes
        .get(..std::mem::size_of::<libc::c_int>())
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("macOS process arguments omitted argc"))?;
    let argc = libc::c_int::from_ne_bytes(argc_bytes);
    if argc <= 0 {
        bail!("macOS process arguments reported invalid argc");
    }
    let mut cursor = std::mem::size_of::<libc::c_int>();
    let executable_end = bytes[cursor..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|offset| cursor + offset)
        .ok_or_else(|| anyhow::anyhow!("macOS process arguments omitted executable terminator"))?;
    cursor = executable_end + 1;
    while bytes.get(cursor) == Some(&0) {
        cursor += 1;
    }
    let mut arguments = Vec::with_capacity(argc as usize);
    for _ in 0..argc {
        let end = bytes[cursor..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| cursor + offset)
            .ok_or_else(|| anyhow::anyhow!("macOS process arguments ended before argc"))?;
        arguments.push(bytes[cursor..end].to_vec());
        cursor = end + 1;
    }
    let environment = bytes[cursor..]
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .flat_map(|entry| entry.iter().copied().chain(std::iter::once(0)))
        .collect();
    Ok(ManagerProcessSnapshot {
        arguments,
        environment,
    })
}

#[cfg(all(target_os = "macos", test))]
fn parse_macos_procargs2(bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    Ok(parse_macos_procargs2_snapshot(bytes)?.arguments)
}

#[cfg(target_os = "macos")]
fn manager_process_snapshot(pid: u32) -> Result<ManagerProcessSnapshot> {
    let mut argmax: libc::c_int = 0;
    let mut argmax_size = std::mem::size_of_val(&argmax);
    let mut argmax_mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    // SAFETY: all pointers reference initialized local storage with the exact
    // lengths supplied to sysctl; no new value is written.
    let argmax_result = unsafe {
        libc::sysctl(
            argmax_mib.as_mut_ptr(),
            argmax_mib.len() as libc::c_uint,
            (&mut argmax as *mut libc::c_int).cast(),
            &mut argmax_size,
            std::ptr::null_mut(),
            0,
        )
    };
    if argmax_result != 0 || argmax <= 0 || argmax as usize > MAX_PROCESS_INVENTORY_BYTES {
        return Err(std::io::Error::last_os_error())
            .context("querying macOS process argument capacity");
    }
    let mut bytes = vec![0u8; argmax as usize];
    let mut size = bytes.len();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
    // SAFETY: `bytes` owns `size` writable bytes and sysctl updates `size` to
    // the number actually written. The queried process belongs to this user.
    let result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            bytes.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error())
            .context("reading the installed Hydra agent process arguments");
    }
    bytes.truncate(size);
    parse_macos_procargs2_snapshot(&bytes)
}

#[cfg(not(target_os = "macos"))]
fn manager_process_snapshot(pid: u32) -> Result<ManagerProcessSnapshot> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let read_bounded = |name: &str| -> Result<Vec<u8>> {
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = options
            .open(format!("/proc/{pid}/{name}"))
            .with_context(|| format!("open installed Hydra agent process {name}"))?;
        let mut bytes = Vec::new();
        file.take((MAX_PROCESS_INVENTORY_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .with_context(|| format!("read installed Hydra agent process {name}"))?;
        if bytes.len() > MAX_PROCESS_INVENTORY_BYTES {
            bail!("installed Hydra agent process {name} exceeded its size limit");
        }
        Ok(bytes)
    };
    let arguments = parse_nul_arguments(&read_bounded("cmdline")?);
    if arguments.is_empty() {
        bail!("installed Hydra agent process arguments were empty");
    }
    Ok(ManagerProcessSnapshot {
        arguments,
        environment: read_bounded("environ")?,
    })
}

fn manager_process_arguments(pid: u32) -> Result<Vec<Vec<u8>>> {
    Ok(manager_process_snapshot(pid)?.arguments)
}

const MAX_PROCESS_INVENTORY_BYTES: usize = 1024 * 1024;
const MAX_REMOTE_PEER_PROCESSES: usize = 32;

const MAX_PROCESS_INVENTORY_ENTRIES: usize = 16 * 1024;
const MAX_PROCESS_COMMAND_BYTES: usize = 4 * 1024;

fn take_process_inventory_field<'a>(line: &'a str, label: &str) -> Result<(&'a str, &'a str)> {
    // `ps` aligns columns with ordinary spaces. Do not normalize tabs, CR, or
    // other control characters into separators: hostile/control-bearing input
    // must fail rather than being trimmed into an apparently valid record.
    let line = line.trim_start_matches(' ');
    let boundary = line.find(' ').unwrap_or(line.len());
    let (field, rest) = line.split_at(boundary);
    if field.is_empty() {
        bail!("process inventory omits {label}");
    }
    Ok((field, rest))
}

fn parse_process_inventory(text: &str) -> Result<Vec<(u32, u32, String)>> {
    if text.len() > MAX_PROCESS_INVENTORY_BYTES {
        bail!("process inventory exceeds its byte bound");
    }
    let mut processes = Vec::new();
    // `split('\n')`, rather than `lines()`, deliberately preserves a trailing
    // CR so the command control-character check below can reject it.
    for line in text.split('\n') {
        if line.is_empty() || line.bytes().all(|byte| byte == b' ') {
            continue;
        }
        if processes.len() == MAX_PROCESS_INVENTORY_ENTRIES {
            bail!("process inventory exceeds its entry bound");
        }
        let (pid, rest) = take_process_inventory_field(line, "PID")?;
        let pid = pid
            .parse::<u32>()
            .ok()
            .filter(|value| *value > 0)
            .ok_or_else(|| anyhow::anyhow!("process inventory contains an invalid PID"))?;
        let (uid, rest) = take_process_inventory_field(rest, "UID")?;
        let uid = uid
            .parse::<u32>()
            .ok()
            .ok_or_else(|| anyhow::anyhow!("process inventory contains an invalid UID"))?;
        let command = rest.trim_matches(' ');
        if command.is_empty() {
            bail!("process inventory omits a command");
        }
        if command.len() > MAX_PROCESS_COMMAND_BYTES {
            bail!("process inventory command exceeds its byte bound");
        }
        if command.chars().any(char::is_control) {
            bail!("process inventory command contains a control character");
        }
        processes.push((pid, uid, command.to_string()));
    }
    Ok(processes)
}

fn remote_peer_agent_dir(arguments: &[Vec<u8>]) -> Result<Option<PathBuf>> {
    if arguments.get(1).map(Vec::as_slice) != Some(b"remote-peer") {
        return Ok(None);
    }
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt as _;

    let mut agent_dir = None;
    let mut seen_flags = std::collections::BTreeSet::new();
    let mut index = 2;
    while index < arguments.len() {
        let flag = arguments[index].as_slice();
        if flag == b"--headless-server" {
            if !seen_flags.insert(flag.to_vec()) {
                bail!("remote-peer process repeats argument --headless-server");
            }
            index += 1;
            continue;
        }
        if !matches!(
            flag,
            b"--dir"
                | b"--sock"
                | b"--sessions"
                // Finite predecessor-only composition fields. They are read
                // solely to inventory and retire an already-running 0.2.8
                // peer; current authority never consumes them.
                | b"--environment"
                | b"--expected-cloud"
                | b"--cloud-pubkey"
                | b"--allowed-origin"
        ) {
            bail!(
                "remote-peer process has an unknown argument {:?}",
                String::from_utf8_lossy(flag)
            );
        }
        if !seen_flags.insert(flag.to_vec()) {
            bail!(
                "remote-peer process repeats argument {:?}",
                String::from_utf8_lossy(flag)
            );
        }
        let value = arguments.get(index + 1).ok_or_else(|| {
            anyhow::anyhow!(
                "remote-peer argument {:?} has no value",
                String::from_utf8_lossy(flag)
            )
        })?;
        if flag == b"--dir" {
            if agent_dir.is_some() {
                bail!("remote-peer process has more than one --dir value");
            }
            let path = PathBuf::from(OsString::from_vec(value.clone()));
            if !hydra_agent::agent_dir::is_canonically_encoded_absolute_path(&path) {
                bail!("remote-peer process has a non-canonical --dir value");
            }
            agent_dir = Some(path);
        }
        index += 2;
    }
    agent_dir
        .map(Some)
        .ok_or_else(|| anyhow::anyhow!("remote-peer process omits --dir"))
}

fn remote_peer_inventory_once(
    agent_dirs: &std::collections::BTreeSet<PathBuf>,
) -> Result<std::collections::BTreeSet<u32>> {
    if agent_dirs.is_empty() || agent_dirs.len() > 5 {
        bail!("remote-peer inventory root set is empty or exceeds its reviewed bound");
    }
    let args = vec!["-axo".to_string(), "pid=,uid=,comm=".to_string()];
    let output =
        hydra_agent::service::manager_output_bounded(hydra_agent::headless::PS_PATH, &args)
            .context("enumerate same-account processes")?;
    if !output.status.success()
        || !output.stderr.iter().all(|byte| byte.is_ascii_whitespace())
        || output.stdout.len() > MAX_PROCESS_INVENTORY_BYTES
    {
        bail!("same-account process inventory was unavailable or unbounded");
    }
    let text = std::str::from_utf8(&output.stdout)
        .context("same-account process inventory was not UTF-8")?;
    let expected_uid = hydra_agent::agent_dir::trusted_uid();
    let mut peers = std::collections::BTreeSet::new();
    for (pid, uid, command) in parse_process_inventory(text)? {
        if uid != expected_uid
            || std::path::Path::new(&command)
                .file_name()
                .and_then(|value| value.to_str())
                != Some("hydra-agent")
        {
            continue;
        }
        let arguments = match manager_process_arguments(pid) {
            Ok(arguments) => arguments,
            Err(first_error) => match process_is_live_exact(pid) {
                Ok(false) => continue,
                Ok(true) => manager_process_arguments(pid).with_context(|| {
                    format!("read live hydra-agent process {pid} arguments after {first_error}")
                })?,
                Err(probe_error) => bail!(
                    "hydra-agent process {pid} arguments and liveness were unreadable: {first_error}; {probe_error}"
                ),
            },
        };
        if remote_peer_agent_dir(&arguments)?
            .as_ref()
            .is_some_and(|agent_dir| agent_dirs.contains(agent_dir))
        {
            peers.insert(pid);
            if peers.len() > MAX_REMOTE_PEER_PROCESSES {
                bail!("remote-peer process inventory exceeds the reviewed bound");
            }
        }
    }
    Ok(peers)
}

fn remote_peer_inventory(
    agent_dirs: &std::collections::BTreeSet<PathBuf>,
) -> Result<std::collections::BTreeSet<u32>> {
    let first = remote_peer_inventory_once(agent_dirs)?;
    std::thread::sleep(std::time::Duration::from_millis(50));
    let second = remote_peer_inventory_once(agent_dirs)?;
    if first != second {
        bail!("remote-peer process inventory changed between stable reads");
    }
    Ok(second)
}

const MAX_INSTALLED_SERVICE_DEFINITION_BYTES: usize = 128 * 1024;
#[cfg(any(target_os = "linux", test))]
const MAX_SYSTEMD_FRAGMENT_PATH_BYTES: usize = 16 * 1024;
const MAX_MANAGER_ENVIRONMENT_BYTES: usize = 128 * 1024;

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct SystemdUnitState {
    fragment_path: Option<PathBuf>,
    drop_in_paths_empty: bool,
    load_state: String,
    active_state: String,
    unit_file_state: String,
    main_pid: Option<u32>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SystemdReadinessObservation {
    Absent,
    LoadedWithoutManager,
    Transitional(u32),
    Running(u32),
}

#[cfg(any(target_os = "linux", test))]
impl SystemdUnitState {
    /// Operational and destructive callers may distinguish only a structurally
    /// absent unit from one exact active manager. A loaded inactive, failed, or
    /// transitioning unit is not absence: systemd may still start, restart, or
    /// finish stopping its process after this observation.
    fn exact_running_or_absent(&self) -> Result<Option<u32>> {
        if systemd_unit_state_proves_absent(self) {
            return Ok(None);
        }
        if self.drop_in_paths_empty
            && self.fragment_path.is_some()
            && self.load_state == "loaded"
            && self.active_state == "active"
        {
            return self
                .main_pid
                .map(Some)
                .ok_or_else(|| anyhow::anyhow!("active systemd Hydra unit has no manager PID"));
        }
        bail!("systemd Hydra unit is not exact active or structurally absent")
    }

    /// Readiness alone may wait through the documented loaded startup states,
    /// but a transition PID is never a qualified Hydra supervisor. The exact
    /// FragmentPath is part of this observation so an old or transient unit
    /// cannot answer readiness for the current definition.
    fn readiness_observation(
        &self,
        expected_fragment: &std::path::Path,
    ) -> Result<SystemdReadinessObservation> {
        if systemd_unit_state_proves_absent(self) {
            return Ok(SystemdReadinessObservation::Absent);
        }
        if !self.drop_in_paths_empty
            || self.fragment_path.as_deref() != Some(expected_fragment)
            || self.load_state != "loaded"
        {
            bail!("systemd readiness is not bound to the exact loaded Hydra unit")
        }
        match (self.active_state.as_str(), self.main_pid) {
            ("active", Some(pid)) => Ok(SystemdReadinessObservation::Running(pid)),
            ("activating" | "reloading", Some(pid)) => {
                Ok(SystemdReadinessObservation::Transitional(pid))
            }
            ("activating" | "reloading" | "inactive" | "failed", None) => {
                Ok(SystemdReadinessObservation::LoadedWithoutManager)
            }
            ("deactivating", _) => {
                bail!("systemd Hydra unit began stopping during readiness")
            }
            ("active", None) => bail!("active systemd Hydra unit has no manager PID"),
            ("inactive" | "failed", Some(_)) => {
                bail!("inactive systemd Hydra unit still carries a manager PID")
            }
            _ => bail!("systemd Hydra unit has an unreviewed readiness state"),
        }
    }
}

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct LaunchdJobState {
    loaded: bool,
    state: Option<String>,
    pid: Option<u32>,
    definition_path: Option<PathBuf>,
}

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LaunchdReadinessObservation {
    Absent,
    LoadedWithoutManager,
    XpcProxy(u32),
    Running(u32),
}

#[cfg(any(target_os = "macos", test))]
impl LaunchdJobState {
    /// Only an exact top-level `running` state names a supervisor. launchd's
    /// `xpcproxy` PID is preserved in this snapshot for readiness continuity,
    /// but it is never promoted to a Hydra manager PID.
    fn qualified_running_pid(&self) -> Option<u32> {
        (self.loaded && self.state.as_deref() == Some("running"))
            .then_some(self.pid)
            .flatten()
    }

    /// Mutation and absence proofs may distinguish only an unloaded target
    /// from one exact running manager. Every loaded non-running state is an
    /// ambiguous service-manager transition and must fail closed.
    fn exact_running_or_absent(&self) -> Result<Option<u32>> {
        if !self.loaded {
            if self.state.is_none() && self.pid.is_none() {
                return Ok(None);
            }
            bail!("unloaded launchd job carries lifecycle fields");
        }
        match (self.state.as_deref(), self.pid) {
            (Some("running"), Some(pid)) => Ok(Some(pid)),
            (Some(_), _) => bail!("launchd Hydra job is loaded without an exact running manager"),
            (None, _) => bail!("loaded launchd job omits state"),
        }
    }

    fn readiness_observation(&self) -> Result<LaunchdReadinessObservation> {
        if !self.loaded {
            if self.state.is_none() && self.pid.is_none() {
                return Ok(LaunchdReadinessObservation::Absent);
            }
            bail!("unloaded launchd job carries lifecycle fields");
        }
        match (self.state.as_deref(), self.pid) {
            (Some("running"), Some(pid)) => Ok(LaunchdReadinessObservation::Running(pid)),
            (Some("xpcproxy"), Some(pid)) => Ok(LaunchdReadinessObservation::XpcProxy(pid)),
            (Some("not running" | "spawn scheduled" | "spawning" | "waiting"), None) => {
                Ok(LaunchdReadinessObservation::LoadedWithoutManager)
            }
            (Some(_), _) => bail!("launchd job state and PID disagree"),
            (None, _) => bail!("loaded launchd job omits state"),
        }
    }
}

/// Readiness alone may wait through launchd's loaded startup states. Once the
/// xpcproxy trampoline exposes PID P, only `running` with that same P can be
/// admitted during this fixed-deadline attempt. Intermediate no-PID states do
/// not erase the pin, and a different proxy/manager remains unqualified.
#[cfg(any(target_os = "macos", test))]
#[derive(Default)]
struct LaunchdReadinessTracker {
    xpcproxy_pid: Option<u32>,
    manager_pid: Option<u32>,
    poisoned: bool,
}

#[cfg(any(target_os = "macos", test))]
impl LaunchdReadinessTracker {
    fn observe(&mut self, state: &LaunchdJobState) -> Result<Option<u32>> {
        if self.poisoned {
            bail!("launchd readiness continuity was already violated");
        }
        match state.readiness_observation()? {
            LaunchdReadinessObservation::Absent => {
                if self.xpcproxy_pid.is_some() || self.manager_pid.is_some() {
                    self.poisoned = true;
                    bail!("launchd job unloaded after its readiness generation began");
                }
                Ok(None)
            }
            LaunchdReadinessObservation::LoadedWithoutManager => {
                if self.manager_pid.is_some() {
                    self.poisoned = true;
                    bail!("launchd manager disappeared during readiness");
                }
                Ok(None)
            }
            LaunchdReadinessObservation::XpcProxy(pid) => {
                match self.xpcproxy_pid {
                    Some(expected) if expected != pid => {
                        self.poisoned = true;
                        bail!("launchd xpcproxy PID changed during readiness")
                    }
                    Some(_) => {}
                    None => self.xpcproxy_pid = Some(pid),
                }
                Ok(None)
            }
            LaunchdReadinessObservation::Running(pid) => {
                if self.xpcproxy_pid.is_some_and(|expected| expected != pid)
                    || self.manager_pid.is_some_and(|expected| expected != pid)
                {
                    self.poisoned = true;
                    bail!("launchd manager PID changed during readiness")
                }
                self.manager_pid = Some(pid);
                Ok(Some(pid))
            }
        }
    }
}

/// Systemd readiness pins the first positive transition or active manager PID.
/// Losing that PID, changing it, or unloading the unit poisons the attempt, so
/// PID reuse cannot let a replacement process answer the predecessor request.
#[cfg(any(target_os = "linux", test))]
#[derive(Default)]
struct SystemdReadinessTracker {
    manager_pid: Option<u32>,
    poisoned: bool,
}

#[cfg(any(target_os = "linux", test))]
impl SystemdReadinessTracker {
    fn observe(
        &mut self,
        state: &SystemdUnitState,
        expected_fragment: &std::path::Path,
    ) -> Result<Option<u32>> {
        if self.poisoned {
            bail!("systemd readiness continuity was already violated");
        }
        match state.readiness_observation(expected_fragment)? {
            SystemdReadinessObservation::Absent => {
                if self.manager_pid.is_some() {
                    self.poisoned = true;
                    bail!("systemd unit unloaded after its readiness generation began");
                }
                Ok(None)
            }
            SystemdReadinessObservation::LoadedWithoutManager => {
                if self.manager_pid.is_some() {
                    self.poisoned = true;
                    bail!("systemd manager disappeared during readiness");
                }
                Ok(None)
            }
            SystemdReadinessObservation::Transitional(pid) => {
                if self.manager_pid.is_some_and(|expected| expected != pid) {
                    self.poisoned = true;
                    bail!("systemd transition PID changed during readiness");
                }
                self.manager_pid = Some(pid);
                Ok(None)
            }
            SystemdReadinessObservation::Running(pid) => {
                if self.manager_pid.is_some_and(|expected| expected != pid) {
                    self.poisoned = true;
                    bail!("systemd manager PID changed during readiness");
                }
                self.manager_pid = Some(pid);
                Ok(Some(pid))
            }
        }
    }
}

#[derive(Default)]
struct PlatformServiceReadinessTracker {
    #[cfg(target_os = "macos")]
    launchd: LaunchdReadinessTracker,
    #[cfg(target_os = "linux")]
    systemd: SystemdReadinessTracker,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct InstalledServiceDescriptor {
    path: PathBuf,
    bytes: Vec<u8>,
    invocation: Option<RunningSupervisorInvocation>,
    build_stamp: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct RunningServiceDescriptor {
    manager_pid: u32,
    invocation: RunningSupervisorInvocation,
    runtime_build_stamp: String,
    runtime_binding_stamp: Option<String>,
}

#[derive(Clone, Debug)]
struct LifecycleDescriptor {
    canonical_root: PathBuf,
    verified_marker_source: Option<PathBuf>,
    /// Fixed current install target. Never derived from ambient XDG or a
    /// historical loaded FragmentPath.
    desired_paths: hydra_agent::service::ServicePaths,
    /// Exact manager/readiness observation path. On Linux this can describe a
    /// verified historical FragmentPath and is cleanup evidence only.
    observed_paths: hydra_agent::service::ServicePaths,
    installed: Vec<InstalledServiceDescriptor>,
    running: Option<RunningServiceDescriptor>,
    peer_roots: std::collections::BTreeSet<PathBuf>,
    activation_state: ServiceActivationPriorState,
    issues: Vec<String>,
}

impl LifecycleDescriptor {
    fn require_unambiguous(&self) -> Result<()> {
        if self.issues.is_empty() {
            Ok(())
        } else {
            bail!(
                "remote lifecycle provenance is ambiguous: {}",
                self.issues.join("; ")
            )
        }
    }

    fn effective_service_file(&self) -> PathBuf {
        platform_service_file(&self.observed_paths)
    }
}

fn valid_peer_root(path: &std::path::Path) -> bool {
    hydra_agent::agent_dir::is_canonically_encoded_absolute_path(path)
        && path.file_name().and_then(|name| name.to_str()) == Some("hydra-agent")
}

fn add_descriptor_peer_root(
    roots: &mut std::collections::BTreeSet<PathBuf>,
    issues: &mut Vec<String>,
    source: &str,
    path: Option<&std::path::Path>,
) {
    let Some(path) = path else { return };
    if valid_peer_root(path) {
        roots.insert(path.to_path_buf());
    } else {
        issues.push(format!("{source} names an invalid enrollment root"));
    }
}

#[cfg(target_os = "linux")]
fn paths_for_exact_service_file(
    fixed: &hydra_agent::service::ServicePaths,
    file: &std::path::Path,
) -> Result<hydra_agent::service::ServicePaths> {
    if !hydra_agent::agent_dir::is_canonically_encoded_absolute_path(file)
        || file.file_name().and_then(|name| name.to_str())
            != Some(format!("{}.service", fixed.label).as_str())
    {
        bail!("verified service fragment path is invalid");
    }
    let mut paths = fixed.clone();
    paths.launch_agents_dir = file
        .parent()
        .ok_or_else(|| anyhow::anyhow!("verified service fragment has no parent"))?
        .to_path_buf();
    if platform_service_file(&paths) != file {
        bail!("verified service fragment cannot be represented exactly");
    }
    Ok(paths)
}

fn capture_descriptor_runtime_proof(
    paths: &hydra_agent::service::ServicePaths,
    running: Option<&RunningServiceDescriptor>,
    peer_roots: &std::collections::BTreeSet<PathBuf>,
    proven_open_semantics: bool,
    proven_closed_semantics: bool,
    issues: &mut Vec<String>,
) -> (
    std::collections::BTreeSet<u32>,
    Option<hydra_agent::service_readiness::ServiceReadinessRecord>,
    ServiceActivationPriorState,
) {
    let captured_peers = match remote_peer_inventory(peer_roots) {
        Ok(peers) => peers,
        Err(error) => {
            issues.push(format!("remote-peer inventory is unreadable: {error:#}"));
            std::collections::BTreeSet::new()
        }
    };
    let readiness = running.and_then(|running| {
        let Some(binding) = running.runtime_binding_stamp.as_deref() else {
            issues.push("running service binding cannot be derived".to_string());
            return None;
        };
        let readiness_root = supervisor_readiness_agent_dir(&paths.agent_dir, &running.invocation);
        match capture_platform_service_ready_in_dir_for(
            paths,
            readiness_root,
            &running.invocation.socket_path,
            &running.runtime_build_stamp,
            binding,
            std::time::Duration::from_millis(1_250),
        ) {
            Ok(record)
                if record.supervisor_pid == running.manager_pid
                    && captured_peers.contains(&record.peer_pid) =>
            {
                Some(record)
            }
            Ok(_) => {
                issues
                    .push("running service readiness disagrees with its process inventory".into());
                None
            }
            Err(error) => {
                issues.push(format!("running service readiness is unproved: {error:#}"));
                None
            }
        }
    });
    let activation_state = if !issues.is_empty() {
        ServiceActivationPriorState::Ambiguous
    } else if proven_open_semantics {
        let (Some(running), Some(readiness)) = (running, readiness.as_ref()) else {
            return (
                captured_peers,
                readiness,
                ServiceActivationPriorState::Ambiguous,
            );
        };
        if captured_peers.len() == 1
            && captured_peers.contains(&readiness.peer_pid)
            && readiness.supervisor_pid == running.manager_pid
        {
            ServiceActivationPriorState::ProvenOpen
        } else {
            ServiceActivationPriorState::Ambiguous
        }
    } else if running.is_none() && captured_peers.is_empty() && proven_closed_semantics {
        ServiceActivationPriorState::Closed
    } else {
        ServiceActivationPriorState::Ambiguous
    };
    (captured_peers, readiness, activation_state)
}

#[cfg(target_os = "linux")]
fn capture_lifecycle_descriptor(
    canonical_root: &std::path::Path,
    lifecycle_lock: &hydra_agent::service::LifecycleLock,
) -> Result<LifecycleDescriptor> {
    let home =
        hydra_agent::agent_dir::trusted_home_dir().context("resolve effective OS account home")?;
    let label = default_service_label();
    let fixed_paths = extension_platform_service_paths(
        &home,
        canonical_root,
        label,
        &hydra_agent::agent_dir::trusted_uid().to_string(),
    );
    let fixed_service_file = platform_service_file(&fixed_paths);
    let mut issues = Vec::new();
    let mut unit_paths = std::collections::BTreeSet::from([fixed_service_file.clone()]);
    let systemd = match systemd_user_unit_state(label) {
        Ok(state) => Some(state),
        Err(error) => {
            issues.push(format!("systemd unit state is unreadable: {error:#}"));
            None
        }
    };
    if let Some(fragment) = systemd
        .as_ref()
        .and_then(|state| state.fragment_path.as_ref())
    {
        unit_paths.insert(fragment.clone());
    }

    let mut installed = Vec::new();
    for path in unit_paths.iter() {
        match installed_linux_service_descriptor(path) {
            Ok(Some(descriptor)) => installed.push(descriptor),
            Ok(None) => {}
            Err(error) => issues.push(format!(
                "service definition {} is unverified: {error:#}",
                path.display()
            )),
        }
    }
    if let Some(fragment) = systemd
        .as_ref()
        .and_then(|state| state.fragment_path.as_ref())
    {
        if !installed
            .iter()
            .any(|definition| definition.path == *fragment)
        {
            issues.push("systemd FragmentPath disappeared or became unreadable".to_string());
        }
    }
    if unit_paths.len() > 1 && installed.len() > 1 {
        issues.push("more than one Hydra systemd definition exists".to_string());
    }

    let paths = systemd
        .as_ref()
        .and_then(|state| state.fragment_path.as_ref())
        .and_then(|fragment| {
            installed
                .iter()
                .any(|definition| definition.path == *fragment)
                .then(|| paths_for_exact_service_file(&fixed_paths, fragment))
        })
        .transpose()?
        .unwrap_or_else(|| fixed_paths.clone());

    let manager_pid = systemd.as_ref().and_then(|state| state.main_pid);
    if let Some(state) = systemd.as_ref() {
        let active_with_pid = matches!(
            state.active_state.as_str(),
            "active" | "activating" | "reloading" | "deactivating"
        );
        if (state.main_pid.is_some() && !active_with_pid)
            || (state.main_pid.is_none() && state.active_state == "active")
            || (state.fragment_path.is_some() && state.load_state == "not-found")
            || (state.fragment_path.is_none() && state.load_state == "loaded")
        {
            issues.push("systemd unit state has contradictory lifecycle fields".to_string());
        }
    }
    let running = if let Some(manager_pid) = manager_pid {
        match manager_process_snapshot(manager_pid).and_then(|snapshot| {
            let invocation = parse_supervisor_invocation(&snapshot.arguments)?;
            let runtime = parse_manager_runtime_environment(&snapshot.environment)?;
            if platform_service_manager_pid(&paths)? != Some(manager_pid) {
                bail!("service manager changed during descriptor capture");
            }
            let runtime_binding_stamp = runtime
                .binding_stamp
                .or_else(|| {
                    invocation
                        .legacy_trust
                        .as_ref()
                        .map(|trust| trust.binding_stamp())
                })
                .or_else(|| {
                    (runtime.build_stamp == hydra_agent::build_stamp())
                        .then(hydra_agent::supervise::service_binding_stamp)
                });
            Ok(RunningServiceDescriptor {
                manager_pid,
                invocation,
                runtime_build_stamp: runtime.build_stamp,
                runtime_binding_stamp,
            })
        }) {
            Ok(running) => Some(running),
            Err(error) => {
                issues.push(format!("running service is unverified: {error:#}"));
                None
            }
        }
    } else {
        None
    };

    let verified_marker_source =
        match hydra_agent::enrollment_migration::verified_completed_legacy_source(
            canonical_root,
            lifecycle_lock,
        ) {
            Ok(source) => source,
            Err(error) => {
                issues.push(format!("legacy adoption marker is unverified: {error:#}"));
                None
            }
        };
    let mut peer_roots = std::collections::BTreeSet::from([canonical_root.to_path_buf()]);
    add_descriptor_peer_root(
        &mut peer_roots,
        &mut issues,
        "legacy adoption marker",
        verified_marker_source.as_deref(),
    );
    add_descriptor_peer_root(
        &mut peer_roots,
        &mut issues,
        "running service",
        running
            .as_ref()
            .and_then(|running| running.invocation.agent_dir.as_deref()),
    );
    for definition in &installed {
        add_descriptor_peer_root(
            &mut peer_roots,
            &mut issues,
            "installed service",
            definition
                .invocation
                .as_ref()
                .and_then(|invocation| invocation.agent_dir.as_deref()),
        );
    }
    if peer_roots.len() > 5 {
        issues.push("lifecycle descriptor exceeds its peer-root bound".to_string());
    }
    let proven_open_semantics = systemd.as_ref().is_some_and(|state| {
        state.main_pid.is_some() && state.load_state == "loaded" && state.active_state == "active"
    });
    let proven_closed_semantics = systemd.as_ref().is_some_and(|state| {
        state.main_pid.is_none()
            && state.active_state == "inactive"
            && ((state.fragment_path.is_none() && state.load_state == "not-found")
                || matches!(state.unit_file_state.as_str(), "" | "disabled" | "masked"))
    });
    let (_, _, activation_state) = capture_descriptor_runtime_proof(
        &paths,
        running.as_ref(),
        &peer_roots,
        proven_open_semantics,
        proven_closed_semantics,
        &mut issues,
    );
    Ok(LifecycleDescriptor {
        canonical_root: canonical_root.to_path_buf(),
        verified_marker_source,
        desired_paths: fixed_paths,
        observed_paths: paths,
        installed,
        running,
        peer_roots,
        activation_state,
        issues,
    })
}

#[cfg(target_os = "macos")]
fn capture_lifecycle_descriptor(
    canonical_root: &std::path::Path,
    lifecycle_lock: &hydra_agent::service::LifecycleLock,
) -> Result<LifecycleDescriptor> {
    let home =
        hydra_agent::agent_dir::trusted_home_dir().context("resolve effective OS account home")?;
    let paths = extension_platform_service_paths(
        &home,
        canonical_root,
        default_service_label(),
        &hydra_agent::agent_dir::trusted_uid().to_string(),
    );
    let fixed_service_file = platform_service_file(&paths);
    let mut issues = Vec::new();
    let launchd = match launchd_job_state(&paths) {
        Ok(state) => Some(state),
        Err(error) => {
            issues.push(format!("launchd unit state is unreadable: {error:#}"));
            None
        }
    };
    let installed = match installed_macos_service_descriptor(&fixed_service_file) {
        Ok(Some(descriptor)) => vec![descriptor],
        Ok(None) => Vec::new(),
        Err(error) => {
            issues.push(format!("launchd definition is unverified: {error:#}"));
            Vec::new()
        }
    };
    let running = match launchd
        .as_ref()
        .and_then(LaunchdJobState::qualified_running_pid)
    {
        Some(manager_pid) => match manager_process_snapshot(manager_pid).and_then(|snapshot| {
            let invocation = parse_supervisor_invocation(&snapshot.arguments)?;
            let runtime = parse_manager_runtime_environment(&snapshot.environment)?;
            if platform_service_manager_pid(&paths)? != Some(manager_pid) {
                bail!("launchd manager changed during descriptor capture");
            }
            let runtime_binding_stamp = runtime
                .binding_stamp
                .or_else(|| {
                    invocation
                        .legacy_trust
                        .as_ref()
                        .map(|trust| trust.binding_stamp())
                })
                .or_else(|| {
                    (runtime.build_stamp == hydra_agent::build_stamp())
                        .then(hydra_agent::supervise::service_binding_stamp)
                });
            Ok(RunningServiceDescriptor {
                manager_pid,
                invocation,
                runtime_build_stamp: runtime.build_stamp,
                runtime_binding_stamp,
            })
        }) {
            Ok(running) => Some(running),
            Err(error) => {
                issues.push(format!("running launchd service is unverified: {error:#}"));
                None
            }
        },
        None => None,
    };
    let verified_marker_source =
        match hydra_agent::enrollment_migration::verified_completed_legacy_source(
            canonical_root,
            lifecycle_lock,
        ) {
            Ok(source) => source,
            Err(error) => {
                issues.push(format!("legacy adoption marker is unverified: {error:#}"));
                None
            }
        };
    let mut peer_roots = std::collections::BTreeSet::from([canonical_root.to_path_buf()]);
    add_descriptor_peer_root(
        &mut peer_roots,
        &mut issues,
        "legacy adoption marker",
        verified_marker_source.as_deref(),
    );
    add_descriptor_peer_root(
        &mut peer_roots,
        &mut issues,
        "running service",
        running
            .as_ref()
            .and_then(|running| running.invocation.agent_dir.as_deref()),
    );
    let (_, _, activation_state) = capture_descriptor_runtime_proof(
        &paths,
        running.as_ref(),
        &peer_roots,
        launchd
            .as_ref()
            .is_some_and(|state| state.qualified_running_pid().is_some()),
        launchd.as_ref().is_some_and(|state| !state.loaded) && installed.is_empty(),
        &mut issues,
    );
    Ok(LifecycleDescriptor {
        canonical_root: canonical_root.to_path_buf(),
        verified_marker_source,
        desired_paths: paths.clone(),
        observed_paths: paths,
        installed,
        running,
        peer_roots,
        activation_state,
        issues,
    })
}

/// Recover the historical enrollment root only from Hydra-owned service
/// provenance. The ambient process environment is intentionally absent from
/// this decision: public code may inherit or choose XDG values, but it cannot
/// use them to redirect private account authority.
#[cfg(target_os = "linux")]
fn extension_proven_legacy_agent_dir(
    canonical_agent_dir: &std::path::Path,
) -> Result<Option<PathBuf>> {
    let home =
        hydra_agent::agent_dir::trusted_home_dir().context("resolve effective OS account home")?;
    let paths = extension_platform_service_paths(
        &home,
        canonical_agent_dir,
        default_service_label(),
        &hydra_agent::agent_dir::trusted_uid().to_string(),
    );

    let running = platform_service_manager_pid(&paths)?
        .map(manager_process_arguments)
        .transpose()?
        .map(|arguments| parse_supervisor_invocation(&arguments))
        .transpose()?
        .and_then(|invocation| invocation.agent_dir);
    let fixed_service_file = platform_service_file(&paths);
    let installed = installed_systemd_supervisor_invocation(&fixed_service_file)?
        .and_then(|invocation| invocation.agent_dir);
    // Historical builds installed the user unit under the then-current
    // XDG_CONFIG_HOME. Query the already-loaded systemd manager for the exact
    // fragment it owns instead of consulting today's ambient XDG value.
    let fragment = match systemd_user_fragment_path(default_service_label())? {
        Some(path) => required_systemd_fragment_invocation(&path)?.agent_dir,
        None => None,
    };
    reconcile_proven_legacy_agent_dir_candidates(
        canonical_agent_dir,
        [running, installed, fragment],
    )
}

#[cfg(not(target_os = "linux"))]
fn extension_proven_legacy_agent_dir(
    _canonical_agent_dir: &std::path::Path,
) -> Result<Option<PathBuf>> {
    Ok(None)
}

#[cfg(test)]
fn reconcile_proven_legacy_agent_dirs(
    canonical_agent_dir: &std::path::Path,
    running: Option<PathBuf>,
    installed: Option<PathBuf>,
) -> Result<Option<PathBuf>> {
    reconcile_proven_legacy_agent_dir_candidates(canonical_agent_dir, [running, installed])
}

#[cfg(any(target_os = "linux", test))]
fn reconcile_proven_legacy_agent_dir_candidates<const N: usize>(
    canonical_agent_dir: &std::path::Path,
    candidates: [Option<PathBuf>; N],
) -> Result<Option<PathBuf>> {
    let mut legacy = None;
    for candidate in candidates.into_iter().flatten() {
        if !hydra_agent::agent_dir::is_canonically_encoded_absolute_path(&candidate)
            || candidate.file_name().and_then(|name| name.to_str()) != Some("hydra-agent")
        {
            bail!("installed Hydra service contains an invalid enrollment directory");
        }
        if candidate == canonical_agent_dir {
            continue;
        }
        if legacy
            .as_ref()
            .is_some_and(|existing| existing != &candidate)
        {
            bail!(
                "running and installed Hydra services disagree on the legacy enrollment directory"
            );
        }
        legacy = Some(candidate);
    }
    Ok(legacy)
}

#[cfg(test)]
fn peer_inventory_roots(
    canonical_agent_dir: &std::path::Path,
    proven_legacy_agent_dir: Option<&std::path::Path>,
) -> Result<std::collections::BTreeSet<PathBuf>> {
    if !hydra_agent::agent_dir::is_canonically_encoded_absolute_path(canonical_agent_dir)
        || canonical_agent_dir
            .file_name()
            .and_then(|name| name.to_str())
            != Some("hydra-agent")
    {
        bail!("canonical remote-peer inventory root is invalid");
    }
    let mut roots = std::collections::BTreeSet::from([canonical_agent_dir.to_path_buf()]);
    if let Some(legacy) = proven_legacy_agent_dir {
        if !hydra_agent::agent_dir::is_canonically_encoded_absolute_path(legacy)
            || legacy.file_name().and_then(|name| name.to_str()) != Some("hydra-agent")
        {
            bail!("legacy remote-peer inventory root is invalid");
        }
        roots.insert(legacy.to_path_buf());
    }
    Ok(roots)
}

#[cfg(target_os = "linux")]
fn systemd_user_fragment_path(label: &str) -> Result<Option<PathBuf>> {
    Ok(systemd_user_unit_state(label)?.fragment_path)
}

#[cfg(target_os = "linux")]
fn systemd_user_unit_state(label: &str) -> Result<SystemdUnitState> {
    let args = vec![
        "--user".to_string(),
        "show".to_string(),
        "--no-pager".to_string(),
        "--property=FragmentPath".to_string(),
        "--property=DropInPaths".to_string(),
        "--property=LoadState".to_string(),
        "--property=ActiveState".to_string(),
        "--property=UnitFileState".to_string(),
        "--property=MainPID".to_string(),
        format!("{label}.service"),
    ];
    let output =
        hydra_agent::service::manager_output_bounded(hydra_agent::headless::SYSTEMCTL_PATH, &args)
            .context("querying systemd Hydra agent unit state")?;
    if output.stdout.len() > MAX_SYSTEMD_FRAGMENT_PATH_BYTES
        || output.stderr.len() > MAX_SYSTEMD_FRAGMENT_PATH_BYTES
    {
        bail!("systemd Hydra agent state response exceeded its size limit");
    }
    if !output.status.success() {
        if manager_absence(&String::from_utf8_lossy(&output.stderr)) {
            return Ok(SystemdUnitState {
                fragment_path: None,
                drop_in_paths_empty: true,
                load_state: "not-found".to_string(),
                active_state: "inactive".to_string(),
                unit_file_state: String::new(),
                main_pid: None,
            });
        }
        bail!(
            "systemctl unit-state query failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let state = parse_systemd_unit_state(&output.stdout)?;
    let expected_name = format!("{label}.service");
    if state.fragment_path.as_ref().is_some_and(|path| {
        path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str())
    }) {
        bail!("systemd FragmentPath names an unexpected service definition");
    }
    Ok(state)
}

#[cfg(target_os = "linux")]
fn require_expected_systemd_fragment(
    label: &str,
    expected: &std::path::Path,
) -> Result<SystemdUnitState> {
    let state = systemd_user_unit_state(label)?;
    validate_expected_systemd_fragment(&state, expected)?;
    Ok(state)
}

#[cfg(any(target_os = "linux", test))]
fn systemd_unit_state_proves_absent(state: &SystemdUnitState) -> bool {
    state.fragment_path.is_none()
        && state.drop_in_paths_empty
        && state.load_state == "not-found"
        && state.active_state == "inactive"
        && state.unit_file_state.is_empty()
        && state.main_pid.is_none()
}

#[cfg(any(target_os = "linux", test))]
fn systemd_unit_state_uses_loaded_fragment(
    state: &SystemdUnitState,
    expected: &std::path::Path,
) -> bool {
    state.fragment_path.as_deref() == Some(expected)
        && state.drop_in_paths_empty
        && state.load_state == "loaded"
}

#[cfg(any(target_os = "linux", test))]
fn validate_expected_systemd_fragment(
    state: &SystemdUnitState,
    expected: &std::path::Path,
) -> Result<()> {
    if !state.drop_in_paths_empty {
        bail!("systemd Hydra retained-daemon has unreviewed drop-in composition")
    }
    match state.fragment_path.as_deref() {
        Some(actual) if actual == expected => Ok(()),
        Some(_) => bail!(
            "the Hydra retained-daemon unit is loaded from a previous Unix account HOME; restore that HOME and remove remote connectivity plus the retained daemon before rerunning setup"
        ),
        None if state.active_state == "active" || state.load_state == "loaded" => {
            bail!("systemd reports a loaded Hydra retained-daemon without a reviewed FragmentPath")
        }
        None => Ok(()),
    }
}

#[cfg(any(target_os = "linux", test))]
fn parse_systemd_unit_state(output: &[u8]) -> Result<SystemdUnitState> {
    if output.len() > MAX_SYSTEMD_FRAGMENT_PATH_BYTES {
        bail!("systemd unit state exceeded its size limit");
    }
    let text = std::str::from_utf8(output).context("systemd unit state is not UTF-8")?;
    let mut fields = std::collections::BTreeMap::new();
    for line in text.lines() {
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("systemd unit state has an invalid line"))?;
        if !matches!(
            name,
            "FragmentPath"
                | "DropInPaths"
                | "LoadState"
                | "ActiveState"
                | "UnitFileState"
                | "MainPID"
        ) || fields.insert(name, value).is_some()
        {
            bail!("systemd unit state has duplicate or unexpected fields");
        }
    }
    for required in [
        "FragmentPath",
        "DropInPaths",
        "LoadState",
        "ActiveState",
        "UnitFileState",
        "MainPID",
    ] {
        if !fields.contains_key(required) {
            bail!("systemd unit state omitted {required}");
        }
    }
    let bounded_state = |name: &str, allow_empty: bool| -> Result<String> {
        let value = *fields.get(name).expect("required field checked");
        if (!allow_empty && value.is_empty())
            || value.len() > 64
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            bail!("systemd {name} is not a bounded canonical value");
        }
        Ok(value.to_string())
    };
    let fragment_path = parse_systemd_fragment_path(
        fields
            .get("FragmentPath")
            .expect("required field checked")
            .as_bytes(),
    )?;
    let drop_in_paths_empty = fields
        .get("DropInPaths")
        .expect("required field checked")
        .is_empty();
    if !drop_in_paths_empty {
        bail!("systemd Hydra unit has unreviewed drop-in composition");
    }
    let main_pid = fields
        .get("MainPID")
        .expect("required field checked")
        .parse::<u32>()
        .context("systemd MainPID is invalid")?;
    Ok(SystemdUnitState {
        fragment_path,
        drop_in_paths_empty,
        load_state: bounded_state("LoadState", false)?,
        active_state: bounded_state("ActiveState", false)?,
        unit_file_state: bounded_state("UnitFileState", true)?,
        main_pid: (main_pid > 0).then_some(main_pid),
    })
}

#[cfg(any(target_os = "linux", test))]
fn parse_systemd_fragment_path(output: &[u8]) -> Result<Option<PathBuf>> {
    if output.len() > MAX_SYSTEMD_FRAGMENT_PATH_BYTES {
        bail!("systemd FragmentPath exceeded its size limit");
    }
    let value = std::str::from_utf8(output)
        .context("systemd FragmentPath is not UTF-8")?
        .trim_end_matches('\n');
    if value.is_empty() {
        return Ok(None);
    }
    if value.contains('\n') || value.contains('\r') || value.chars().any(char::is_control) {
        bail!("systemd FragmentPath has an invalid line shape");
    }
    let path = PathBuf::from(value);
    if !hydra_agent::agent_dir::is_canonically_encoded_absolute_path(&path) {
        bail!("systemd FragmentPath is not an absolute normalized path");
    }
    Ok(Some(path))
}

#[cfg(any(target_os = "linux", test))]
fn installed_systemd_supervisor_invocation(
    path: &std::path::Path,
) -> Result<Option<RunningSupervisorInvocation>> {
    let home = hydra_agent::agent_dir::trusted_home_dir()
        .context("resolve effective OS account home for service provenance")?;
    installed_systemd_supervisor_invocation_for_home(path, &home)
}

#[cfg(any(target_os = "linux", test))]
fn installed_systemd_supervisor_invocation_for_home(
    path: &std::path::Path,
    trusted_home: &std::path::Path,
) -> Result<Option<RunningSupervisorInvocation>> {
    let Some(definition) = read_owned_service_definition_for_home(path, trusted_home)? else {
        return Ok(None);
    };
    let parsed = parse_full_systemd_service_definition(&definition)?;
    require_fixed_systemd_home(&parsed, trusted_home)?;
    Ok(Some(parsed.invocation))
}

#[cfg(target_os = "linux")]
fn installed_linux_service_descriptor(
    path: &std::path::Path,
) -> Result<Option<InstalledServiceDescriptor>> {
    let Some(bytes) = read_owned_service_definition(path)? else {
        return Ok(None);
    };
    if bytes.is_empty() {
        bail!("installed Hydra service definition is empty");
    }
    let parsed = parse_full_systemd_service_definition(&bytes)?;
    let trusted_home = hydra_agent::agent_dir::trusted_home_dir()
        .context("resolve effective OS account home for service provenance")?;
    require_fixed_systemd_home(&parsed, &trusted_home)?;
    Ok(Some(InstalledServiceDescriptor {
        path: path.to_path_buf(),
        bytes,
        invocation: Some(parsed.invocation),
        build_stamp: parsed.build_stamp,
    }))
}

#[cfg(target_os = "macos")]
fn installed_macos_service_descriptor(
    path: &std::path::Path,
) -> Result<Option<InstalledServiceDescriptor>> {
    let Some(bytes) = read_owned_service_definition(path)? else {
        return Ok(None);
    };
    if bytes.is_empty() {
        bail!("installed Hydra service definition is empty");
    }
    let parsed = parse_full_launchd_service_definition(&bytes)?;
    Ok(Some(InstalledServiceDescriptor {
        path: path.to_path_buf(),
        bytes,
        invocation: Some(parsed.invocation),
        build_stamp: parsed.build_stamp,
    }))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ManagerRuntimeEnvironment {
    build_stamp: String,
    binding_stamp: Option<String>,
}

fn parse_manager_runtime_environment(bytes: &[u8]) -> Result<ManagerRuntimeEnvironment> {
    if bytes.len() > MAX_MANAGER_ENVIRONMENT_BYTES {
        bail!("manager environment exceeded its size limit");
    }
    let mut stamp = None;
    let mut binding = None;
    for entry in bytes
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        if let Some(value) = entry.strip_prefix(b"HYDRA_AGENT_BUILD_STAMP=") {
            if stamp.is_some() {
                bail!("manager environment contains duplicate build stamps");
            }
            stamp = Some(
                std::str::from_utf8(value)
                    .context("manager build stamp is not UTF-8")?
                    .to_string(),
            );
        } else if let Some(value) = entry.strip_prefix(b"HYDRA_AGENT_SERVICE_BINDING=") {
            if binding.is_some() {
                bail!("manager environment contains duplicate service bindings");
            }
            let value =
                std::str::from_utf8(value).context("manager service binding is not UTF-8")?;
            if value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                bail!("manager service binding is not canonical SHA-256");
            }
            binding = Some(value.to_string());
        }
    }
    let build_stamp = validated_build_stamp(
        stamp
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("manager environment omits its build stamp"))?,
    )?;
    Ok(ManagerRuntimeEnvironment {
        build_stamp,
        binding_stamp: binding,
    })
}

fn manager_runtime_environment(pid: u32) -> Result<ManagerRuntimeEnvironment> {
    let snapshot = manager_process_snapshot(pid)?;
    parse_manager_runtime_environment(&snapshot.environment)
}

#[cfg(any(target_os = "linux", test))]
fn required_systemd_fragment_invocation(
    path: &std::path::Path,
) -> Result<RunningSupervisorInvocation> {
    installed_systemd_supervisor_invocation(path)?
        .ok_or_else(|| anyhow::anyhow!("systemd FragmentPath disappeared before readback"))
}

fn read_owned_service_definition(path: &std::path::Path) -> Result<Option<Vec<u8>>> {
    let home = hydra_agent::agent_dir::trusted_home_dir()
        .context("resolve effective OS account home for service definition")?;
    read_owned_service_definition_for_home(path, &home)
}

fn read_owned_service_definition_for_home(
    path: &std::path::Path,
    trusted_home: &std::path::Path,
) -> Result<Option<Vec<u8>>> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    hydra_agent::service::validate_existing_service_definition_for_home(path, trusted_home)
        .context("validate historical Hydra service definition without mutation")?;
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("open installed Hydra service definition"),
    };
    let metadata = file
        .metadata()
        .context("inspect installed Hydra service definition")?;
    if !metadata.file_type().is_file()
        || metadata.uid() != hydra_agent::agent_dir::trusted_uid()
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.len() > MAX_INSTALLED_SERVICE_DEFINITION_BYTES as u64
    {
        bail!("installed Hydra service definition has unsafe type, owner, mode, links, or size");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((MAX_INSTALLED_SERVICE_DEFINITION_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .context("read installed Hydra service definition")?;
    if bytes.len() > MAX_INSTALLED_SERVICE_DEFINITION_BYTES {
        bail!("installed Hydra service definition exceeds its size limit");
    }
    Ok(Some(bytes))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct ParsedServiceDefinition {
    invocation: RunningSupervisorInvocation,
    build_stamp: String,
    binary_path: String,
    app_support_dir: String,
    log_dir: String,
    fixed_home_dir: Option<String>,
}

#[cfg(any(target_os = "linux", test))]
fn require_fixed_systemd_home(
    parsed: &ParsedServiceDefinition,
    trusted_home: &std::path::Path,
) -> Result<()> {
    let expected = trusted_home.to_string_lossy();
    match (
        parsed.invocation.fixed_external_daemon,
        parsed.fixed_home_dir.as_deref(),
    ) {
        (true, Some(actual)) if actual == expected => Ok(()),
        (false, None) => Ok(()),
        (true, _) => bail!("fixed Hydra service HOME differs from the effective Unix account"),
        (false, Some(_)) => bail!("desktop Hydra service unexpectedly overrides HOME"),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedGeneratedSupervisorArguments {
    invocation: RunningSupervisorInvocation,
    binary_path: String,
    sessions: Vec<String>,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GeneratedServicePlatform {
    Linux,
    #[cfg(any(target_os = "macos", test))]
    Macos,
}

#[cfg(target_arch = "x86_64")]
const LEGACY_028_LINUX_BUILD_STAMP: &str = "git=36d69db built=1786095258338";
#[cfg(target_arch = "aarch64")]
const LEGACY_028_LINUX_ARM64_BUILD_STAMP: &str = "git=36d69db built=1786095205145";
#[cfg(any(target_os = "macos", test))]
const LEGACY_028_MACOS_BUILD_STAMP: &str = "git=36d69db built=1786095177153";
const LEGACY_028_ENVIRONMENT: &str = "production";
const LEGACY_028_CLOUD_BASE: &str = "https://api.hydraterms.com";
const LEGACY_028_CLOUD_PUBKEY: &str = "eKNpAYrE3JwA1btPJMtqQZ5ePDX6k/hPjBxZnTmoanM=";
const LEGACY_028_ALLOWED_ORIGIN: &str = "https://app.hydraterms.com";

#[cfg(any(target_os = "linux", test))]
fn parse_full_systemd_service_definition(bytes: &[u8]) -> Result<ParsedServiceDefinition> {
    let text =
        std::str::from_utf8(bytes).context("installed Hydra service definition is not UTF-8")?;
    if !text.ends_with('\n') {
        bail!("installed Hydra systemd definition has no final newline");
    }
    let lines = text.lines().collect::<Vec<_>>();
    let mut index = 0usize;
    require_exact_definition_line(&lines, &mut index, "[Unit]", "systemd")?;
    require_exact_definition_line(
        &lines,
        &mut index,
        "Description=Hydra desktop agent (attaches to retained pty-daemon + supervises remote peer)",
        "systemd",
    )?;
    require_exact_definition_line(&lines, &mut index, "", "systemd")?;
    require_exact_definition_line(&lines, &mut index, "[Service]", "systemd")?;
    require_exact_definition_line(&lines, &mut index, "Type=simple", "systemd")?;
    let exec_line = *lines
        .get(index)
        .ok_or_else(|| anyhow::anyhow!("installed Hydra systemd definition omits ExecStart"))?;
    index += 1;
    let exec_value = exec_line.strip_prefix("ExecStart=").ok_or_else(|| {
        anyhow::anyhow!("installed Hydra systemd definition has an invalid ExecStart line")
    })?;
    let arguments = parse_generated_systemd_exec_start(exec_line.as_bytes())?;
    if canonical_systemd_arguments(&arguments)? != exec_value {
        bail!("installed Hydra systemd ExecStart is not canonically encoded");
    }
    let parsed_arguments = parse_exact_generated_supervisor_arguments(&arguments)?;
    require_exact_definition_line(&lines, &mut index, "Restart=on-failure", "systemd")?;
    require_exact_definition_line(&lines, &mut index, "RestartSec=10", "systemd")?;
    require_exact_definition_line(
        &lines,
        &mut index,
        "Environment=\"RUST_LOG=hydra_agent=info\"",
        "systemd",
    )?;
    let fixed_home_dir = if parsed_arguments.invocation.fixed_external_daemon {
        let home = *lines.get(index).ok_or_else(|| {
            anyhow::anyhow!("installed fixed Hydra systemd definition omits HOME")
        })?;
        let home_value = home
            .strip_prefix("Environment=\"HOME=")
            .and_then(|value| value.strip_suffix('"'))
            .ok_or_else(|| anyhow::anyhow!("installed fixed Hydra systemd HOME is invalid"))?;
        let home_value = decode_canonical_systemd_value(home_value, "fixed HOME")?;
        let _ = require_absolute_normalized_path(&home_value, "fixed HOME", None)?;
        index += 1;
        Some(home_value)
    } else {
        None
    };
    let support = *lines.get(index).ok_or_else(|| {
        anyhow::anyhow!("installed Hydra systemd definition omits its app-support environment")
    })?;
    let support_value = support
        .strip_prefix("Environment=\"MAESTRO_APP_SUPPORT_DIR=")
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| {
            anyhow::anyhow!("installed Hydra systemd app-support environment is invalid")
        })?;
    let support_value = decode_canonical_systemd_value(support_value, "app-support path")?;
    let _ = require_absolute_normalized_path(&support_value, "app-support path", None)?;
    index += 1;
    let stamp_line = *lines.get(index).ok_or_else(|| {
        anyhow::anyhow!("installed Hydra systemd definition omits its build stamp")
    })?;
    let stamp = stamp_line
        .strip_prefix("Environment=\"HYDRA_AGENT_BUILD_STAMP=")
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| anyhow::anyhow!("installed Hydra systemd build stamp line is invalid"))?;
    let build_stamp = validated_build_stamp(stamp)?;
    index += 1;
    let out_line = *lines
        .get(index)
        .ok_or_else(|| anyhow::anyhow!("installed Hydra systemd definition omits stdout"))?;
    let out_path = out_line
        .strip_prefix("StandardOutput=append:")
        .ok_or_else(|| anyhow::anyhow!("installed Hydra systemd stdout path is invalid"))?;
    let out_path = decode_canonical_systemd_value(out_path, "stdout path")?;
    let out_path =
        require_absolute_normalized_path(&out_path, "stdout path", Some("agent.out.log"))?;
    let log_dir = out_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("installed Hydra systemd stdout path has no parent"))?
        .to_string_lossy()
        .into_owned();
    index += 1;
    let err_line = *lines
        .get(index)
        .ok_or_else(|| anyhow::anyhow!("installed Hydra systemd definition omits stderr"))?;
    let err_path = err_line
        .strip_prefix("StandardError=append:")
        .ok_or_else(|| anyhow::anyhow!("installed Hydra systemd stderr path is invalid"))?;
    let err_path = decode_canonical_systemd_value(err_path, "stderr path")?;
    let err_path =
        require_absolute_normalized_path(&err_path, "stderr path", Some("agent.err.log"))?;
    if err_path.parent() != Some(std::path::Path::new(&log_dir)) {
        bail!("installed Hydra systemd stdout/stderr directories differ");
    }
    index += 1;
    require_exact_definition_line(&lines, &mut index, "", "systemd")?;
    require_exact_definition_line(&lines, &mut index, "[Install]", "systemd")?;
    require_exact_definition_line(&lines, &mut index, "WantedBy=default.target", "systemd")?;
    if index != lines.len() {
        bail!("installed Hydra systemd definition contains extra directives");
    }
    validate_generated_service_generation(
        &parsed_arguments.invocation,
        &build_stamp,
        GeneratedServicePlatform::Linux,
    )?;
    let regenerated = render_allowlisted_systemd_definition(
        &arguments,
        fixed_home_dir.as_deref(),
        &support_value,
        &build_stamp,
        &log_dir,
    )?;
    if regenerated.as_bytes() != bytes {
        bail!("installed Hydra systemd definition is not the exact allowlisted encoding");
    }
    Ok(ParsedServiceDefinition {
        binary_path: parsed_arguments.binary_path,
        invocation: parsed_arguments.invocation,
        build_stamp,
        fixed_home_dir,
        app_support_dir: support_value,
        log_dir,
    })
}

#[cfg(any(target_os = "macos", test))]
fn parse_full_launchd_service_definition(bytes: &[u8]) -> Result<ParsedServiceDefinition> {
    let text =
        std::str::from_utf8(bytes).context("installed Hydra service definition is not UTF-8")?;
    if !text.ends_with('\n') {
        bail!("installed Hydra launchd definition has no final newline");
    }
    let lines = text.lines().collect::<Vec<_>>();
    let mut index = 0usize;
    for expected in [
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">",
        "<plist version=\"1.0\">",
        "<dict>",
        "  <key>Label</key>",
    ] {
        require_exact_definition_line(&lines, &mut index, expected, "launchd")?;
    }
    let label = parse_exact_xml_string_line(
        lines
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("installed Hydra launchd definition omits Label"))?,
        "  ",
        "Label",
    )?;
    if label != "com.hydra.agent" {
        bail!("installed Hydra launchd Label differs from the durable identity");
    }
    index += 1;
    for expected in [
        "  <key>AssociatedBundleIdentifiers</key>",
        "  <array>",
        "    <string>com.hydraterms.hydra</string>",
        "  </array>",
        "  <key>ProgramArguments</key>",
        "  <array>",
    ] {
        require_exact_definition_line(&lines, &mut index, expected, "launchd")?;
    }
    let mut arguments = Vec::new();
    while lines.get(index).copied() != Some("  </array>") {
        if arguments.len() >= 32 {
            bail!("installed Hydra launchd definition has too many ProgramArguments");
        }
        let line = lines.get(index).ok_or_else(|| {
            anyhow::anyhow!("installed Hydra launchd ProgramArguments array is unterminated")
        })?;
        arguments.push(parse_exact_xml_string_line(line, "    ", "ProgramArguments")?.into_bytes());
        index += 1;
    }
    require_exact_definition_line(&lines, &mut index, "  </array>", "launchd")?;
    let parsed_arguments = parse_exact_generated_supervisor_arguments(&arguments)?;
    for expected in [
        "  <key>RunAtLoad</key>",
        "  <true/>",
        "  <key>KeepAlive</key>",
        "  <dict>",
        "    <key>SuccessfulExit</key>",
        "    <false/>",
        "  </dict>",
        "  <key>ThrottleInterval</key>",
        "  <integer>10</integer>",
        "  <key>EnvironmentVariables</key>",
        "  <dict>",
        "    <key>HOME</key>",
    ] {
        require_exact_definition_line(&lines, &mut index, expected, "launchd")?;
    }
    let home_dir = parse_exact_xml_string_line(
        lines
            .get(index)
            .ok_or_else(|| anyhow::anyhow!("installed Hydra launchd definition omits HOME"))?,
        "    ",
        "HOME",
    )?;
    let _ = require_absolute_normalized_path(&home_dir, "launchd HOME", None)?;
    index += 1;
    require_exact_definition_line(
        &lines,
        &mut index,
        "    <key>MAESTRO_APP_SUPPORT_DIR</key>",
        "launchd",
    )?;
    let support_dir = parse_exact_xml_string_line(
        lines.get(index).ok_or_else(|| {
            anyhow::anyhow!("installed Hydra launchd definition omits app-support directory")
        })?,
        "    ",
        "app-support path",
    )?;
    let _ = require_absolute_normalized_path(&support_dir, "launchd app-support path", None)?;
    index += 1;
    require_exact_definition_line(
        &lines,
        &mut index,
        "    <key>HYDRA_AGENT_BUILD_STAMP</key>",
        "launchd",
    )?;
    let build_stamp = validated_build_stamp(&parse_exact_xml_string_line(
        lines.get(index).ok_or_else(|| {
            anyhow::anyhow!("installed Hydra launchd definition omits build stamp")
        })?,
        "    ",
        "build stamp",
    )?)?;
    index += 1;
    for expected in [
        "    <key>RUST_LOG</key>",
        "    <string>hydra_agent=info</string>",
        "  </dict>",
        "  <key>StandardOutPath</key>",
    ] {
        require_exact_definition_line(&lines, &mut index, expected, "launchd")?;
    }
    let out_path = parse_exact_xml_string_line(
        lines.get(index).ok_or_else(|| {
            anyhow::anyhow!("installed Hydra launchd definition omits stdout path")
        })?,
        "  ",
        "stdout path",
    )?;
    let out_path =
        require_absolute_normalized_path(&out_path, "launchd stdout path", Some("agent.out.log"))?;
    let log_dir = out_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("installed Hydra launchd stdout path has no parent"))?
        .to_string_lossy()
        .into_owned();
    index += 1;
    require_exact_definition_line(
        &lines,
        &mut index,
        "  <key>StandardErrorPath</key>",
        "launchd",
    )?;
    let err_path = parse_exact_xml_string_line(
        lines.get(index).ok_or_else(|| {
            anyhow::anyhow!("installed Hydra launchd definition omits stderr path")
        })?,
        "  ",
        "stderr path",
    )?;
    let err_path =
        require_absolute_normalized_path(&err_path, "launchd stderr path", Some("agent.err.log"))?;
    if err_path.parent() != Some(std::path::Path::new(&log_dir)) {
        bail!("installed Hydra launchd stdout/stderr directories differ");
    }
    index += 1;
    for expected in [
        "  <key>ProcessType</key>",
        "  <string>Background</string>",
        "</dict>",
        "</plist>",
    ] {
        require_exact_definition_line(&lines, &mut index, expected, "launchd")?;
    }
    if index != lines.len() {
        bail!("installed Hydra launchd definition contains extra keys");
    }
    validate_generated_service_generation(
        &parsed_arguments.invocation,
        &build_stamp,
        GeneratedServicePlatform::Macos,
    )?;
    let regenerated = render_allowlisted_launchd_definition(
        &arguments,
        &home_dir,
        &support_dir,
        &build_stamp,
        &log_dir,
    )?;
    if regenerated.as_bytes() != bytes {
        bail!("installed Hydra launchd definition is not the exact allowlisted encoding");
    }
    Ok(ParsedServiceDefinition {
        binary_path: parsed_arguments.binary_path,
        invocation: parsed_arguments.invocation,
        build_stamp,
        fixed_home_dir: None,
        app_support_dir: support_dir,
        log_dir,
    })
}

#[cfg(any(target_os = "macos", test))]
fn parse_exact_xml_string_line(line: &str, indent: &str, name: &str) -> Result<String> {
    let prefix = format!("{indent}<string>");
    let encoded = line
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix("</string>"))
        .ok_or_else(|| anyhow::anyhow!("installed Hydra launchd {name} has an invalid shape"))?;
    if encoded.len() > 8192 {
        bail!("installed Hydra launchd {name} exceeded its size limit");
    }
    let mut decoded = String::with_capacity(encoded.len());
    let mut remaining = encoded;
    while let Some(offset) = remaining.find('&') {
        decoded.push_str(&remaining[..offset]);
        remaining = &remaining[offset..];
        let (entity, value) = if let Some(rest) = remaining.strip_prefix("&amp;") {
            (rest, '&')
        } else if let Some(rest) = remaining.strip_prefix("&lt;") {
            (rest, '<')
        } else if let Some(rest) = remaining.strip_prefix("&gt;") {
            (rest, '>')
        } else if let Some(rest) = remaining.strip_prefix("&quot;") {
            (rest, '"')
        } else if let Some(rest) = remaining.strip_prefix("&apos;") {
            (rest, '\'')
        } else {
            bail!("installed Hydra launchd {name} uses an unreviewed XML entity");
        };
        decoded.push(value);
        remaining = entity;
    }
    decoded.push_str(remaining);
    if decoded.chars().any(char::is_control) || canonical_xml_value(&decoded) != encoded {
        bail!("installed Hydra launchd {name} is not canonically encoded");
    }
    Ok(decoded)
}

#[cfg(any(target_os = "macos", test))]
fn canonical_xml_value(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            character => output.push(character),
        }
    }
    output
}

#[cfg(any(target_os = "macos", test))]
fn render_allowlisted_launchd_definition(
    arguments: &[Vec<u8>],
    home_dir: &str,
    app_support_dir: &str,
    build_stamp: &str,
    log_dir: &str,
) -> Result<String> {
    let mut rendered_arguments = Vec::with_capacity(arguments.len());
    for argument in arguments {
        let argument = std::str::from_utf8(argument)
            .context("installed Hydra launchd argument is not UTF-8")?;
        rendered_arguments.push(format!(
            "    <string>{}</string>",
            canonical_xml_value(argument)
        ));
    }
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key>\n  <string>com.hydra.agent</string>\n  <key>AssociatedBundleIdentifiers</key>\n  <array>\n    <string>com.hydraterms.hydra</string>\n  </array>\n  <key>ProgramArguments</key>\n  <array>\n{}\n  </array>\n  <key>RunAtLoad</key>\n  <true/>\n  <key>KeepAlive</key>\n  <dict>\n    <key>SuccessfulExit</key>\n    <false/>\n  </dict>\n  <key>ThrottleInterval</key>\n  <integer>10</integer>\n  <key>EnvironmentVariables</key>\n  <dict>\n    <key>HOME</key>\n    <string>{}</string>\n    <key>MAESTRO_APP_SUPPORT_DIR</key>\n    <string>{}</string>\n    <key>HYDRA_AGENT_BUILD_STAMP</key>\n    <string>{}</string>\n    <key>RUST_LOG</key>\n    <string>hydra_agent=info</string>\n  </dict>\n  <key>StandardOutPath</key>\n  <string>{}/agent.out.log</string>\n  <key>StandardErrorPath</key>\n  <string>{}/agent.err.log</string>\n  <key>ProcessType</key>\n  <string>Background</string>\n</dict>\n</plist>\n",
        rendered_arguments.join("\n"),
        canonical_xml_value(home_dir),
        canonical_xml_value(app_support_dir),
        canonical_xml_value(build_stamp),
        canonical_xml_value(log_dir),
        canonical_xml_value(log_dir),
    ))
}

fn require_exact_definition_line(
    lines: &[&str],
    index: &mut usize,
    expected: &str,
    kind: &str,
) -> Result<()> {
    if lines.get(*index).copied() != Some(expected) {
        bail!("installed Hydra {kind} definition differs from the allowlisted shape");
    }
    *index += 1;
    Ok(())
}

fn require_absolute_normalized_path(
    value: &str,
    name: &str,
    expected_basename: Option<&str>,
) -> Result<PathBuf> {
    if value.is_empty()
        || value.len() > 4096
        || value.chars().any(char::is_control)
        || value.contains('\0')
    {
        bail!("installed Hydra {name} is not a bounded path");
    }
    let path = PathBuf::from(value);
    if !hydra_agent::agent_dir::is_canonically_encoded_absolute_path(&path) {
        bail!("installed Hydra {name} is not an absolute normalized path");
    }
    if expected_basename.is_some()
        && path.file_name().and_then(|name| name.to_str()) != expected_basename
    {
        bail!("installed Hydra {name} has the wrong basename");
    }
    Ok(path)
}

#[cfg(any(target_os = "linux", test))]
fn decode_canonical_systemd_value(value: &str, name: &str) -> Result<String> {
    if value.is_empty()
        || value.len() > 8192
        || value
            .chars()
            .any(|character| character.is_control() || matches!(character, '"' | '\\'))
    {
        bail!("installed Hydra systemd {name} is outside the reviewed value grammar");
    }
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if bytes.get(index + 1) != Some(&b'%') {
                bail!("installed Hydra systemd {name} uses an unreviewed specifier");
            }
            decoded.push(b'%');
            index += 2;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    let decoded = String::from_utf8(decoded)
        .with_context(|| format!("installed Hydra systemd {name} is not UTF-8"))?;
    if canonical_systemd_value(&decoded)? != value {
        bail!("installed Hydra systemd {name} is not canonically encoded");
    }
    Ok(decoded)
}

#[cfg(any(target_os = "linux", test))]
fn canonical_systemd_value(value: &str) -> Result<String> {
    if value
        .chars()
        .any(|character| character.is_control() || matches!(character, '"' | '\\'))
    {
        bail!("installed Hydra systemd value cannot be encoded safely");
    }
    Ok(value.replace('%', "%%"))
}

#[cfg(any(target_os = "linux", test))]
fn render_allowlisted_systemd_definition(
    arguments: &[Vec<u8>],
    fixed_home_dir: Option<&str>,
    app_support_dir: &str,
    build_stamp: &str,
    log_dir: &str,
) -> Result<String> {
    let out_log = canonical_systemd_value(&format!("{log_dir}/agent.out.log"))?;
    let err_log = canonical_systemd_value(&format!("{log_dir}/agent.err.log"))?;
    let support = canonical_systemd_value(app_support_dir)?;
    let fixed_home = fixed_home_dir
        .map(canonical_systemd_value)
        .transpose()?
        .map(|home| format!("Environment=\"HOME={home}\"\n"))
        .unwrap_or_default();
    Ok(format!(
        "[Unit]\nDescription=Hydra desktop agent (attaches to retained pty-daemon + supervises remote peer)\n\n[Service]\nType=simple\nExecStart={}\nRestart=on-failure\nRestartSec=10\nEnvironment=\"RUST_LOG=hydra_agent=info\"\n{}Environment=\"MAESTRO_APP_SUPPORT_DIR={}\"\nEnvironment=\"HYDRA_AGENT_BUILD_STAMP={}\"\nStandardOutput=append:{}\nStandardError=append:{}\n\n[Install]\nWantedBy=default.target\n",
        canonical_systemd_arguments(arguments)?,
        fixed_home,
        support,
        build_stamp,
        out_log,
        err_log,
    ))
}

#[cfg(any(target_os = "linux", test))]
fn canonical_systemd_arguments(arguments: &[Vec<u8>]) -> Result<String> {
    let mut encoded = Vec::with_capacity(arguments.len());
    for argument in arguments {
        let value = std::str::from_utf8(argument)
            .context("installed Hydra systemd argument is not UTF-8")?;
        let mut output = String::with_capacity(value.len() + 2);
        output.push('"');
        for character in value.chars() {
            match character {
                '\\' => output.push_str("\\\\"),
                '"' => output.push_str("\\\""),
                '%' => output.push_str("%%"),
                character if character.is_control() => {
                    bail!("installed Hydra systemd argument contains a control character")
                }
                character => output.push(character),
            }
        }
        output.push('"');
        encoded.push(output);
    }
    Ok(encoded.join(" "))
}

fn parse_exact_generated_supervisor_arguments(
    arguments: &[Vec<u8>],
) -> Result<ParsedGeneratedSupervisorArguments> {
    let binary = arguments
        .first()
        .ok_or_else(|| anyhow::anyhow!("installed Hydra supervisor has no binary"))?;
    let binary_path = std::str::from_utf8(binary)
        .context("installed Hydra supervisor binary is not UTF-8")?
        .to_string();
    let _ =
        require_absolute_normalized_path(&binary_path, "supervisor binary", Some("hydra-agent"))?;
    if arguments.get(1).map(Vec::as_slice) != Some(b"supervise")
        || arguments.get(2).map(Vec::as_slice) != Some(b"--attach-daemon-only")
    {
        bail!("installed Hydra supervisor prefix is not exact");
    }
    let fixed_external_daemon = arguments.get(3).map(Vec::as_slice) == Some(b"--fixed-daemon-only");
    let mut index = if fixed_external_daemon { 4 } else { 3 };
    let legacy = arguments.get(index).map(Vec::as_slice) == Some(b"--dir");
    if legacy {
        let agent_dir = arguments
            .get(index + 1)
            .ok_or_else(|| anyhow::anyhow!("installed Hydra supervisor directory is absent"))?;
        let agent_dir = std::str::from_utf8(agent_dir)
            .context("installed Hydra supervisor directory is not UTF-8")?;
        let _ = require_absolute_normalized_path(
            agent_dir,
            "supervisor enrollment directory",
            Some("hydra-agent"),
        )?;
        index += 2;
    }
    if arguments.get(index).map(Vec::as_slice) != Some(b"--sock") {
        bail!("installed Hydra supervisor socket argument is not exact");
    }
    let socket = arguments
        .get(index + 1)
        .ok_or_else(|| anyhow::anyhow!("installed Hydra supervisor socket is absent"))?;
    let socket =
        std::str::from_utf8(socket).context("installed Hydra supervisor socket is not UTF-8")?;
    let _ = require_absolute_normalized_path(socket, "supervisor socket", None)?;
    index += 2;
    if legacy {
        for expected in [
            b"--environment".as_slice(),
            b"--expected-cloud".as_slice(),
            b"--cloud-pubkey".as_slice(),
            b"--allowed-origin".as_slice(),
        ] {
            if arguments.get(index).map(Vec::as_slice) != Some(expected)
                || arguments.get(index + 1).is_none()
            {
                bail!("installed Hydra supervisor legacy trust tuple is not exact");
            }
            index += 2;
        }
    }
    let mut sessions = Vec::new();
    if arguments.get(index).map(Vec::as_slice) == Some(b"--sessions") {
        let raw_sessions = arguments
            .get(index + 1)
            .ok_or_else(|| anyhow::anyhow!("installed Hydra supervisor sessions are absent"))?;
        if raw_sessions.is_empty()
            || raw_sessions.len() > 4096
            || raw_sessions
                .split(|byte| *byte == b',')
                .any(<[u8]>::is_empty)
            || raw_sessions.iter().any(u8::is_ascii_control)
        {
            bail!("installed Hydra supervisor sessions are not bounded");
        }
        let sessions_value = std::str::from_utf8(raw_sessions)
            .context("installed Hydra supervisor sessions are not UTF-8")?;
        let parsed_sessions = sessions_value
            .split(',')
            .map(str::to_string)
            .collect::<Vec<_>>();
        if parsed_sessions.iter().any(|session| session.len() > 512) {
            bail!("installed Hydra supervisor session identifier exceeded its bound");
        }
        sessions = parsed_sessions;
        index += 2;
    }
    if index != arguments.len() {
        bail!("installed Hydra supervisor has extra or reordered arguments");
    }
    let invocation = parse_supervisor_invocation(arguments)?;
    if !invocation.attach_daemon_only
        || invocation.fixed_external_daemon != fixed_external_daemon
        || legacy != (invocation.agent_dir.is_some() && invocation.legacy_trust.is_some())
    {
        bail!("installed Hydra supervisor current/legacy shape is inconsistent");
    }
    Ok(ParsedGeneratedSupervisorArguments {
        invocation,
        binary_path,
        sessions,
    })
}

fn validate_generated_service_generation(
    invocation: &RunningSupervisorInvocation,
    build_stamp: &str,
    platform: GeneratedServicePlatform,
) -> Result<()> {
    if let Some(trust) = invocation.legacy_trust.as_ref() {
        let expected_build_stamp = match platform {
            #[cfg(any(target_os = "macos", test))]
            GeneratedServicePlatform::Macos => LEGACY_028_MACOS_BUILD_STAMP,
            GeneratedServicePlatform::Linux => {
                #[cfg(target_arch = "aarch64")]
                {
                    LEGACY_028_LINUX_ARM64_BUILD_STAMP
                }
                #[cfg(target_arch = "x86_64")]
                {
                    LEGACY_028_LINUX_BUILD_STAMP
                }
                #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
                {
                    bail!("published Hydra 0.2.8 has no legacy service on this architecture")
                }
            }
        };
        if invocation.agent_dir.is_none()
            || build_stamp != expected_build_stamp
            || trust.environment != LEGACY_028_ENVIRONMENT
            || trust.expected_cloud != LEGACY_028_CLOUD_BASE
            || trust.cloud_pubkey != LEGACY_028_CLOUD_PUBKEY
            || trust.allowed_origin != LEGACY_028_ALLOWED_ORIGIN
        {
            bail!("installed Hydra service is not the exact published 0.2.8 legacy generation");
        }
    } else if invocation.agent_dir.is_some() {
        bail!("installed Hydra current service carries a legacy enrollment directory");
    }
    Ok(())
}

/// Parse the exact quoted argument subset emitted by `systemd::exec_start`.
/// Refusing broader shell/systemd syntax is deliberate: an arbitrary unit is
/// not structural provenance for private enrollment state.
#[cfg(any(target_os = "linux", test))]
fn parse_generated_systemd_exec_start(definition: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut exec_start = None;
    for raw_line in definition.split(|byte| *byte == b'\n') {
        let line = trim_ascii(raw_line);
        if let Some(value) = line.strip_prefix(b"ExecStart=") {
            if exec_start.replace(value).is_some() {
                bail!("installed Hydra service has more than one ExecStart");
            }
        }
    }
    let value =
        exec_start.ok_or_else(|| anyhow::anyhow!("installed Hydra service has no ExecStart"))?;
    let mut arguments = Vec::new();
    let mut cursor = 0usize;
    while cursor < value.len() {
        while value.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if cursor == value.len() {
            break;
        }
        if value[cursor] != b'"' {
            bail!("installed Hydra service ExecStart is outside the reviewed quoted form");
        }
        cursor += 1;
        let mut argument = Vec::new();
        let mut closed = false;
        while cursor < value.len() {
            match value[cursor] {
                b'"' => {
                    cursor += 1;
                    closed = true;
                    break;
                }
                b'\\' => {
                    let escaped = *value.get(cursor + 1).ok_or_else(|| {
                        anyhow::anyhow!("installed Hydra service ends inside an escape")
                    })?;
                    if !matches!(escaped, b'\\' | b'"') {
                        bail!("installed Hydra service uses an unreviewed escape");
                    }
                    argument.push(escaped);
                    cursor += 2;
                }
                b'%' => {
                    if value.get(cursor + 1) != Some(&b'%') {
                        bail!("installed Hydra service uses an unreviewed systemd specifier");
                    }
                    argument.push(b'%');
                    cursor += 2;
                }
                byte if byte == 0 || byte.is_ascii_control() => {
                    bail!("installed Hydra service argument contains a control byte")
                }
                byte => {
                    argument.push(byte);
                    cursor += 1;
                }
            }
        }
        if !closed
            || value
                .get(cursor)
                .is_some_and(|byte| !byte.is_ascii_whitespace())
        {
            bail!("installed Hydra service ExecStart has invalid argument boundaries");
        }
        arguments.push(argument);
    }
    if arguments.is_empty() {
        bail!("installed Hydra service ExecStart is empty");
    }
    Ok(arguments)
}

#[cfg(any(target_os = "linux", test))]
fn trim_ascii(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

/// A pre-attach-only service may own the retained PTY daemon. Never stop,
/// replace, or reload such a manager while it could be holding sessions. A new
/// attach-only supervisor is independently replaceable and does not need the
/// daemon probe. When manager argv cannot be proven, use the conservative
/// legacy path.
fn guard_disruptive_service_change(
    paths: &hydra_agent::service::ServicePaths,
    action: &str,
) -> Result<()> {
    let manager_pid = match platform_service_manager_pid(paths) {
        Ok(manager_pid) => manager_pid,
        #[cfg(target_os = "macos")]
        Err(error) if dormant_attach_only_launchd_replacement_is_safe(paths)? => {
            // A verified generated attach-only definition cannot own the PTY daemon even if
            // launchd races from this stable dormant observation into a fresh manager before the
            // following bootout. No remote-peer may survive either observation. Treat this one
            // narrow state as safe-to-replace, not as general launchd absence.
            let _ = error;
            None
        }
        Err(error) => return Err(error),
    };
    let Some(manager_pid) = manager_pid else {
        return Ok(());
    };
    let invocation = parse_supervisor_invocation(&manager_process_arguments(manager_pid)?)
        .with_context(|| {
            format!(
                "refusing to {action}: the running Hydra agent ownership and socket could not be proven"
            )
        })?;
    if invocation.attach_daemon_only {
        return Ok(());
    }
    let sessions = {
        let mut client = maestro_shell::DaemonClient::connect(&invocation.socket_path)
            .with_context(|| {
                format!(
                    "refusing to {action}: the legacy Hydra agent may own the retained daemon, and session safety could not be verified"
                )
            })?;
        client.list_sessions().with_context(|| {
            format!(
                "refusing to {action}: the legacy Hydra agent may own the retained daemon, and session safety could not be verified"
            )
        })?
    };
    if !legacy_manager_change_is_safe(Ok(sessions.len())) {
        bail!(
            "refusing to {action}: the legacy Hydra agent may own the retained daemon and {} retained session(s) are still live; close or migrate those sessions first",
            sessions.len()
        );
    }
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn dormant_launchd_replacement_shape_is_safe(
    state: &LaunchdJobState,
    installed_attach_only: bool,
    remote_peer_count: usize,
) -> bool {
    state.loaded
        && state.state.as_deref() == Some("not running")
        && state.pid.is_none()
        && installed_attach_only
        && remote_peer_count == 0
}

#[cfg(any(target_os = "macos", test))]
fn dormant_launchd_pending_shape_is_safe(
    state: &LaunchdJobState,
    installed_path: &std::path::Path,
    installed_attach_only: bool,
    remote_peer_count: usize,
) -> bool {
    state.definition_path.as_deref() == Some(installed_path)
        && dormant_launchd_replacement_shape_is_safe(
            state,
            installed_attach_only,
            remote_peer_count,
        )
}

/// Prove the one recoverable macOS upgrade state that has no manager PID but still has a loaded
/// launchd definition. The definition must be Hydra's exact generated, owner-safe attach-only
/// shape; the state and process inventory must remain stable across a second observation. Other
/// dormant/transitional states stay ambiguous and are never booted out by enrollment convergence.
#[cfg(target_os = "macos")]
fn dormant_attach_only_launchd_replacement_is_safe(
    paths: &hydra_agent::service::ServicePaths,
) -> Result<bool> {
    let first_state = launchd_job_state(paths)?;
    let Some(installed) = installed_macos_service_descriptor(&platform_service_file(paths))? else {
        return Ok(false);
    };
    let Some(invocation) = installed.invocation.as_ref() else {
        return Ok(false);
    };
    let mut peer_roots = std::collections::BTreeSet::from([paths.agent_dir.clone()]);
    if let Some(agent_dir) = invocation.agent_dir.as_ref() {
        if !valid_peer_root(agent_dir) {
            return Ok(false);
        }
        peer_roots.insert(agent_dir.clone());
    }
    let first_peers = remote_peer_inventory(&peer_roots)?;
    if !dormant_launchd_replacement_shape_is_safe(
        &first_state,
        invocation.attach_daemon_only,
        first_peers.len(),
    ) {
        return Ok(false);
    }

    let second_state = launchd_job_state(paths)?;
    if second_state != first_state {
        return Ok(false);
    }
    let second_peers = remote_peer_inventory(&peer_roots)?;
    Ok(dormant_launchd_replacement_shape_is_safe(
        &second_state,
        invocation.attach_daemon_only,
        second_peers.len(),
    ))
}

fn manager_absence(stderr: &str) -> bool {
    let detail = stderr.to_ascii_lowercase();
    detail.contains("could not find service")
        || detail.contains("no such process")
        || detail.contains("not loaded")
        || detail.contains("not-found")
        || (detail.contains("unit") && detail.contains("does not exist"))
        || detail.contains("could not be found")
}

#[cfg(target_os = "macos")]
fn platform_service_manager_pid(paths: &hydra_agent::service::ServicePaths) -> Result<Option<u32>> {
    launchd_job_state(paths)?.exact_running_or_absent()
}

#[cfg(target_os = "macos")]
fn platform_service_manager_pid_for_readiness(
    paths: &hydra_agent::service::ServicePaths,
    tracker: &mut PlatformServiceReadinessTracker,
) -> Result<Option<u32>> {
    tracker.launchd.observe(&launchd_job_state(paths)?)
}

#[cfg(target_os = "macos")]
fn launchd_job_state(paths: &hydra_agent::service::ServicePaths) -> Result<LaunchdJobState> {
    let args = vec!["print".to_string(), paths.service_target()];
    let output = hydra_agent::service::manager_output_bounded("launchctl", &args)
        .context("querying launchd Hydra agent job")?;
    if output.stdout.len() > MAX_PROCESS_INVENTORY_BYTES
        || output.stderr.len() > MAX_PROCESS_INVENTORY_BYTES
    {
        bail!("launchctl Hydra job response exceeded its size limit");
    }
    if output.status.success() {
        return parse_launchctl_job_state(&output.stdout);
    }
    if manager_absence(&String::from_utf8_lossy(&output.stderr)) {
        return Ok(LaunchdJobState {
            loaded: false,
            state: None,
            pid: None,
            definition_path: None,
        });
    }
    bail!(
        "launchctl print failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

#[cfg(any(target_os = "macos", test))]
fn parse_launchctl_job_state(output: &[u8]) -> Result<LaunchdJobState> {
    if output.len() > MAX_PROCESS_INVENTORY_BYTES {
        bail!("launchctl Hydra job response exceeded its size limit");
    }
    let output = std::str::from_utf8(output).context("launchctl job response is not UTF-8")?;
    let mut state = None;
    let mut pid = None;
    let mut definition_path = None;
    // `launchctl print` nests coalition and transaction dictionaries beneath
    // the job and repeats keys such as `state` and `pid` there. Only exact
    // one-tab job fields describe the service manager itself.
    for line in output.lines() {
        if let Some(value) = line.strip_prefix("\tstate = ") {
            if state.is_some() {
                bail!("launchctl job has ambiguous state");
            }
            // This allowlist is the reviewed launchd contract. `xpcproxy` is
            // the PID-bearing trampoline between bootstrap and the exact
            // `running` manager; readiness may observe it, but mutation and
            // absence proofs cannot treat its PID as a Hydra supervisor. A
            // syntactically tidy unknown state cannot prove manager absence.
            if !matches!(
                value,
                "running" | "not running" | "spawn scheduled" | "spawning" | "xpcproxy" | "waiting"
            ) {
                bail!("launchctl job has an unrecognized state");
            }
            state = Some(value.to_string());
        }
        if let Some(value) = line.strip_prefix("\tpid = ") {
            if pid.is_some() {
                bail!("launchctl job has more than one PID");
            }
            let parsed = value
                .parse::<u32>()
                .context("launchctl job PID is invalid")?;
            if parsed == 0 {
                bail!("launchctl job PID is zero");
            }
            pid = Some(parsed);
        }
        if let Some(value) = line.strip_prefix("\tpath = ") {
            if definition_path.is_some() {
                bail!("launchctl job has more than one definition path");
            }
            let path = PathBuf::from(value);
            if !hydra_agent::agent_dir::is_canonically_encoded_absolute_path(&path) {
                bail!("launchctl job definition path is not absolute and normalized");
            }
            definition_path = Some(path);
        }
    }
    let state = state.ok_or_else(|| anyhow::anyhow!("launchctl job response omits state"))?;
    if matches!(state.as_str(), "running" | "xpcproxy") != pid.is_some() {
        bail!("launchctl job state and PID disagree");
    }
    Ok(LaunchdJobState {
        loaded: true,
        state: Some(state),
        pid,
        definition_path,
    })
}

#[cfg(test)]
fn launchctl_running_pid(output: &str) -> Option<u32> {
    parse_launchctl_job_state(output.as_bytes())
        .ok()?
        .qualified_running_pid()
}

#[cfg(not(target_os = "macos"))]
fn platform_service_manager_pid(paths: &hydra_agent::service::ServicePaths) -> Result<Option<u32>> {
    systemd_user_unit_state(&paths.label)?.exact_running_or_absent()
}

#[cfg(not(target_os = "macos"))]
fn platform_service_manager_pid_for_readiness(
    paths: &hydra_agent::service::ServicePaths,
    tracker: &mut PlatformServiceReadinessTracker,
) -> Result<Option<u32>> {
    let state = systemd_user_unit_state(&paths.label)?;
    tracker
        .systemd
        .observe(&state, &platform_service_file(paths))
}

/// Resolve the exact desktop data root observed by the persistent agent. The app supplies its
/// active base; operator installs keep the platform default. Relative overrides are rejected
/// because launchd/systemd services have no trustworthy working directory.
fn service_app_support_dir(args: &[String], home: &std::path::Path) -> Result<PathBuf> {
    let path = flag(args, "--app-support-dir")
        .map(PathBuf::from)
        .unwrap_or_else(|| platform_maestro_app_support_dir(home));
    if !path.is_absolute() {
        bail!("--app-support-dir must be an absolute path");
    }
    Ok(path)
}

// getuid via the C library — only used to default the launchctl `gui/<uid>` target. Overridable via --uid
// (tests inject one), so no real syscall is exercised in unit tests.
extern "C" {
    #[link_name = "getuid"]
    fn libc_getuid() -> u32;
}

// ---- platform boundary: launchd (macOS) vs systemd user service (Linux) ----
//
// The planners share the ServiceAction/ServicePlan vocabulary and the executor; only how a
// "service definition" is expressed differs (plist + launchctl vs unit + systemctl). Both
// generator modules compile on every platform (they are pure), so their tests always run;
// these cfg-gated helpers pick which one the CLI drives on this machine.

#[cfg(target_os = "macos")]
fn default_service_label() -> &'static str {
    "com.hydra.agent"
}

#[cfg(not(target_os = "macos"))]
fn default_service_label() -> &'static str {
    "hydra-agent"
}

#[cfg(target_os = "macos")]
fn platform_service_paths(
    home: &std::path::Path,
    agent_dir: &std::path::Path,
    label: &str,
    uid: &str,
) -> hydra_agent::service::ServicePaths {
    hydra_agent::service::default_macos_paths(home, agent_dir, label, uid)
}

#[cfg(not(target_os = "macos"))]
fn platform_service_paths(
    home: &std::path::Path,
    agent_dir: &std::path::Path,
    label: &str,
    _uid: &str,
) -> hydra_agent::service::ServicePaths {
    hydra_agent::systemd::default_linux_paths(
        &xdg_dir(home, "XDG_CONFIG_HOME", ".config"),
        &xdg_dir(home, "XDG_STATE_HOME", ".local/state"),
        agent_dir,
        label,
    )
}

/// `$<var>` when set to an absolute path, else `<home>/<fallback>` — the XDG base-dir rule.
#[cfg(not(target_os = "macos"))]
fn xdg_dir(home: &std::path::Path, var: &str, fallback: &str) -> PathBuf {
    if let Some(dir) = std::env::var_os(var) {
        let p = PathBuf::from(dir);
        if p.is_absolute() {
            return p;
        }
    }
    home.join(fallback)
}

/// The desktop app-support base the installed service should read (daemon endpoint + kill
/// switch). Mirrors the dev-mode base the desktop app currently publishes to on each platform.
#[cfg(target_os = "macos")]
fn platform_maestro_app_support_dir(home: &std::path::Path) -> PathBuf {
    home.join("Library")
        .join("Application Support")
        .join("Maestro-dev")
}

#[cfg(not(target_os = "macos"))]
fn platform_maestro_app_support_dir(home: &std::path::Path) -> PathBuf {
    xdg_dir(home, "XDG_DATA_HOME", ".local/share").join("maestro-dev")
}

#[cfg(target_os = "macos")]
fn extension_maestro_app_support_dir(home: &std::path::Path) -> PathBuf {
    home.join("Library")
        .join("Application Support")
        .join("Maestro-dev")
}

#[cfg(not(target_os = "macos"))]
fn extension_maestro_app_support_dir(home: &std::path::Path) -> PathBuf {
    home.join(".local/share/maestro-dev")
}

/// Extension-owned service paths ignore XDG/HOME process variables. The
/// effective account home was resolved through the OS account database.
#[cfg(target_os = "macos")]
fn extension_platform_service_paths(
    home: &std::path::Path,
    agent_dir: &std::path::Path,
    label: &str,
    uid: &str,
) -> hydra_agent::service::ServicePaths {
    hydra_agent::service::default_macos_paths(home, agent_dir, label, uid)
}

#[cfg(not(target_os = "macos"))]
fn extension_platform_service_paths(
    home: &std::path::Path,
    agent_dir: &std::path::Path,
    label: &str,
    _uid: &str,
) -> hydra_agent::service::ServicePaths {
    hydra_agent::systemd::default_linux_paths(
        &home.join(".config"),
        &home.join(".local/state"),
        agent_dir,
        label,
    )
}

fn reviewed_daemon_socket(app_support_dir: &std::path::Path) -> PathBuf {
    let fallback = maestro_shell::default_socket_path(&|_: &str| None);
    let paths = maestro_shell::AppPaths::with_base(app_support_dir.to_path_buf());
    match maestro_shell::load_endpoint(&paths) {
        Ok(Some(endpoint)) => {
            let path = PathBuf::from(endpoint.socket_path);
            if path.is_absolute() && path.exists() {
                path
            } else {
                fallback
            }
        }
        _ => fallback,
    }
}

/// Resolve the agent's daemon authority. A reviewed standalone daemon unit is the durable headless marker:
/// when it exists, connectivity is pinned to that unit's exact socket and must never follow desktop state.
fn extension_daemon_target(
    home: &std::path::Path,
    agent_dir: &std::path::Path,
    agent_binary: &std::path::Path,
    app_support_dir: &std::path::Path,
) -> Result<(PathBuf, bool)> {
    #[cfg(target_os = "linux")]
    {
        let uid = hydra_agent::agent_dir::trusted_uid();
        let socket = hydra_agent::headless::daemon_socket_path(uid);
        let daemon_paths = hydra_agent::systemd::default_linux_paths(
            &home.join(".config"),
            &home.join(".local/state"),
            agent_dir,
            hydra_agent::headless::DAEMON_UNIT_NAME,
        );
        let unit_path = hydra_agent::systemd::unit_path(&daemon_paths);
        let daemon_manager_state =
            require_expected_systemd_fragment(hydra_agent::headless::DAEMON_UNIT_NAME, &unit_path)?;
        match std::fs::symlink_metadata(&unit_path) {
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && systemd_unit_state_proves_absent(&daemon_manager_state) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => bail!(
                "systemd retained a loaded or transitioning Hydra daemon after its reviewed unit file disappeared; refusing desktop fallback"
            ),
            Err(error) => return Err(error).context("inspect Hydra retained-daemon unit"),
            Ok(_) => {
                hydra_agent::service::validate_existing_service_definition(&unit_path)
                    .context("validate Hydra retained-daemon unit")?;
                let daemon_binary = agent_binary
                    .parent()
                    .ok_or_else(|| {
                        anyhow::anyhow!("installed Hydra agent has no binary directory")
                    })?
                    .join("pty-daemon");
                hydra_agent::headless::validate_package_binary(&daemon_binary, "pty-daemon")?;
                let binary = daemon_binary
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("installed daemon path is not UTF-8"))?;
                let socket_text = socket
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("retained daemon socket is not UTF-8"))?;
                let actual = std::fs::read_to_string(&unit_path)
                    .context("read Hydra retained-daemon unit")?;
                hydra_agent::systemd::parse_headless_daemon_unit_for_removal(
                    &actual,
                    binary,
                    socket_text,
                    home,
                )
                .map_err(anyhow::Error::msg)
                .context("hydra-pty-daemon.service differs from the reviewed headless package")?;
                return Ok((socket, true));
            }
        }
    }
    let _ = (home, agent_dir, agent_binary);
    Ok((reviewed_daemon_socket(app_support_dir), false))
}

struct PlatformInstallOptions<'a> {
    home: &'a std::path::Path,
    app_support_dir: &'a std::path::Path,
    label: &'a str,
    binary_path: String,
    socket_path: String,
    fixed_external_daemon: bool,
    sessions: Vec<String>,
}

#[cfg(target_os = "macos")]
fn platform_plan_install(
    paths: &hydra_agent::service::ServicePaths,
    opts: PlatformInstallOptions<'_>,
) -> hydra_agent::service::ServicePlan {
    let _ = opts.fixed_external_daemon;
    let plist = hydra_agent::launchd::LaunchdPlistOptions {
        label: opts.label.to_string(),
        binary_path: opts.binary_path,
        build_stamp: hydra_agent::build_stamp(),
        socket_path: opts.socket_path,
        sessions: opts.sessions,
        log_dir: paths.log_dir.to_string_lossy().into_owned(),
        // Emit HOME in the plist so the installed agent can locate device.json under launchd (which strips
        // HOME); without it remote-peer dies "requires --cloud".
        home_dir: opts.home.to_string_lossy().into_owned(),
        maestro_app_support_dir: opts.app_support_dir.to_string_lossy().into_owned(),
    };
    hydra_agent::service::plan_install(paths, &plist)
}

#[cfg(not(target_os = "macos"))]
fn platform_plan_install(
    paths: &hydra_agent::service::ServicePaths,
    opts: PlatformInstallOptions<'_>,
) -> hydra_agent::service::ServicePlan {
    let unit = hydra_agent::systemd::SystemdUnitOptions {
        unit_name: opts.label.to_string(),
        binary_path: opts.binary_path,
        build_stamp: hydra_agent::build_stamp(),
        socket_path: opts.socket_path,
        fixed_external_daemon: opts.fixed_external_daemon,
        sessions: opts.sessions,
        log_dir: paths.log_dir.to_string_lossy().into_owned(),
        home_dir: opts.home.to_string_lossy().into_owned(),
        maestro_app_support_dir: opts.app_support_dir.to_string_lossy().into_owned(),
    };
    hydra_agent::systemd::plan_install(paths, &unit)
}

#[cfg(target_os = "macos")]
fn platform_plan_uninstall(
    paths: &hydra_agent::service::ServicePaths,
    forget: bool,
) -> hydra_agent::service::ServicePlan {
    hydra_agent::service::plan_uninstall(paths, forget)
}

#[cfg(target_os = "macos")]
fn platform_plan_start(
    paths: &hydra_agent::service::ServicePaths,
) -> hydra_agent::service::ServicePlan {
    hydra_agent::service::plan_start(paths)
}

#[cfg(not(target_os = "macos"))]
fn platform_plan_start(
    paths: &hydra_agent::service::ServicePaths,
) -> hydra_agent::service::ServicePlan {
    hydra_agent::systemd::plan_start(paths)
}

#[cfg(not(target_os = "macos"))]
fn platform_plan_uninstall(
    paths: &hydra_agent::service::ServicePaths,
    forget: bool,
) -> hydra_agent::service::ServicePlan {
    hydra_agent::systemd::plan_uninstall(paths, forget)
}

#[cfg(target_os = "macos")]
fn platform_plan_status(
    paths: &hydra_agent::service::ServicePaths,
) -> hydra_agent::service::ServicePlan {
    hydra_agent::service::plan_status(paths)
}

#[cfg(not(target_os = "macos"))]
fn platform_plan_status(
    paths: &hydra_agent::service::ServicePaths,
) -> hydra_agent::service::ServicePlan {
    hydra_agent::systemd::plan_status(paths)
}

/// Where the persistent-install service definition lives on this platform (health's
/// "installed?" fact): the launchd plist on macOS, the systemd user unit elsewhere.
#[cfg(target_os = "macos")]
fn platform_service_file(paths: &hydra_agent::service::ServicePaths) -> PathBuf {
    paths.plist_path()
}

#[cfg(not(target_os = "macos"))]
fn platform_service_file(paths: &hydra_agent::service::ServicePaths) -> PathBuf {
    hydra_agent::systemd::unit_path(paths)
}

/// S3c-wiring: the dial-out WebRTC peer. Polls S3a signaling, answers offers, runs the control channel +
/// terminal bridge against the local daemon. NO public listener. (webrtc feature.)
#[cfg(feature = "webrtc")]
fn run_remote_peer_cmd(args: &[String]) -> Result<()> {
    use hydra_agent::remote_peer::{run_remote_peer, PeerConfig};

    let sock = PathBuf::from(
        flag(args, "--sock")
            .ok_or_else(|| anyhow::anyhow!("remote-peer requires --sock <daemon.sock>"))?,
    );
    // CRITICAL: connect to the SAME daemon the desktop app is using, else the agent talks to a different (empty)
    // daemon and the browser sees no sessions/projects. When MAESTRO_APP_SUPPORT_DIR is set, the desktop app
    // publishes its live daemon socket to `<base>/daemon/endpoint.json`; prefer that over the fixed `--sock`. Falls
    // back to `--sock` when no endpoint is published (standalone daemon).
    let headless_server = supervise_standalone_flag(args, "--headless-server");
    let headless_runtime_home = if headless_server {
        let account = hydra_agent::agent_dir::trusted_session_account()
            .context("validate effective Unix account for headless connectivity")?;
        require_headless_runtime_home(std::env::var_os("HOME").as_deref(), &account.home)?;
        Some(account.home)
    } else {
        None
    };
    let sock = if headless_server {
        sock
    } else {
        resolve_desktop_daemon_sock(sock)
    };
    let dir = match flag(args, "--dir") {
        Some(path) => PathBuf::from(path),
        None => hydra_agent::agent_dir::default_agent_dir()
            .context("resolve private Hydra agent directory")?,
    };
    let record = hydra_agent::device_identity::load_record(&dir)?
        .ok_or_else(|| anyhow::anyhow!("remote-peer requires an enrolled device"))?;
    let trust = hydra_agent::release_trust::active().validate()?;
    trust.validate_enrollment(&record)?;
    hydra_agent::device_identity::require_passkey_for_remote_authority(&record)?;
    let cloud_base = trust.cloud_base.to_string();
    let device_id = record.device_id.clone();
    let auth = record.account_id.clone();
    let cloud_pubkey = trust.verifying_key()?;
    let allowed_origins = vec![trust.allowed_origin.to_string()];
    let seed_sessions: Vec<String> = flag(args, "--sessions")
        .map(|s| {
            s.split(',')
                .filter(|x| !x.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();

    // the enrolled device PRIVATE key signs presence heartbeats. Best-effort: only present after `enroll`
    // (a key file exists); absent in unenrolled/dev runs → no heartbeats (presence stays "Last seen …").
    let device_key = hydra_agent::device_identity::load_or_create_key(&dir).ok();
    let expected_record_cloud = cloud_base.trim_end_matches('/').to_string();
    let expected_desktop_id = device_id.clone();
    let expected_account_id = auth.clone();

    let cfg = PeerConfig {
        sock,
        headless_server,
        cloud_base,
        auth,
        device_id,
        enrolled_account_id: Some(expected_account_id.clone()),
        cloud_pubkey,
        allowed_origins,
        device_key,
        seed_sessions,
        agent_dir: dir.clone(),
    };
    // webrtc-rs / rustls 0.23 needs a process-level crypto provider installed before any DTLS handshake,
    // or the connection panics mid-handshake (no DataChannel). Install the ring provider once at startup.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rt = tokio::runtime::Runtime::new()?;
    // LIVE REVOKE: the `revoked(account, device)` closure is checked on the 2s tick + every inbound message. CRITICAL:
    // the `device` arg is the BROWSER's device id (the token authorizes the connecting browser), NOT this desktop's.
    // So we must NOT compare it against our own device.json id (they're always different → that bug refused EVERY
    // browser as "revoked"). The agent's live-revoke authority is whether THIS DESKTOP is still enrolled: if the
    // desktop's device.json is gone (cloud revoked us → heartbeat cleared it, or "Remove Remote"), the agent stops
    // serving anyone. The BROWSER device's own revocation was already vetted by the cloud when it minted the token
    // (the agent can't re-check that without a cloud round-trip on the hot path). Read-only disk check.
    let revoke_dir = dir.clone();
    let expected_headless_home = headless_runtime_home.clone();
    rt.block_on(run_remote_peer(
        cfg,
        move |account: &str, _browser_device: &str, _token_iat_ms: u64| {
            // Revoked ⇔ this DESKTOP is no longer enrolled (device.json absent). Do NOT key off the browser device id.
            // (Browser/account revocation is delivered live via the cloud poll — composed in run_remote_peer.)
            let headless_home_changed = expected_headless_home.as_ref().is_some_and(|expected| {
                hydra_agent::agent_dir::trusted_session_account()
                    .map(|current| current.home != *expected)
                    .unwrap_or(true)
            });
            headless_home_changed
                || account != expected_account_id
                || hydra_agent::device_identity::enrollment_binding_is_revoked(
                    &revoke_dir,
                    account,
                    &expected_desktop_id,
                    &expected_record_cloud,
                )
        },
    ))?;
    Ok(())
}

#[cfg(feature = "webrtc")]
fn require_headless_runtime_home(
    runtime_home: Option<&std::ffi::OsStr>,
    trusted_home: &std::path::Path,
) -> Result<()> {
    if runtime_home == Some(trusted_home.as_os_str()) {
        return Ok(());
    }
    bail!(
        "the Unix account HOME changed after Hydra server setup; restore the original account HOME, remove remote connectivity and the retained daemon, then rerun `hydraterms remote`"
    )
}

/// SELF-REVOKE this desktop ("Remove Remote"): tell the cloud to revoke THIS device (device-signature auth) so the
/// browser's account device list drops it, then clear the local enrollment. Idempotent + best-effort on the cloud
/// call — the LOCAL removal always happens (the desktop must become un-enrolled even if offline). Reads the enrolled
/// device id + cloud base from device.json; a no-op with a clear message if not enrolled.
fn run_self_revoke(dir: &std::path::Path) -> Result<()> {
    let (locks, descriptor) = acquire_lifecycle_context(
        dir,
        Some(hydra_agent::lifecycle_cleanup::CleanupIntent::Remove),
    )
    .context("capture deterministic remote lifecycle")?;
    let had_enrollment = begin_destructive_cleanup(
        dir,
        hydra_agent::lifecycle_cleanup::CleanupIntent::Remove,
        &descriptor,
        &locks,
    )?;
    if had_enrollment {
        println!("self-revoke: local enrollment cleared and remote service stopped");
    } else {
        println!("self-revoke: not enrolled; remote service stopped");
    }
    Ok(())
}

fn hostname_fallback() -> Option<String> {
    let mut bytes = [0u8; 256];
    if unsafe { libc::gethostname(bytes.as_mut_ptr().cast(), bytes.len()) } != 0 {
        return None;
    }
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8(bytes[..end].to_vec())
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn default_device_label() -> String {
    hostname_fallback().unwrap_or_else(|| "desktop".to_string())
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// Resolve the daemon socket to the ONE the desktop app is actually using. The desktop app publishes its live
/// daemon socket as the singleton daemon endpoint record in its app-support store; prefer a live endpoint (so the
/// agent shares the desktop's daemon and can see/control the same sessions/projects) over the `--sock` fallback.
///
/// Dev packaging runs the local app from the `Maestro-dev` base, while launchd/standalone agents often start without
/// `MAESTRO_APP_SUPPORT_DIR`. In that case, probe the common local bases and use the first endpoint whose socket still
/// exists. This avoids the remote silently creating a separate daemon on the default socket path.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DaemonSocketResolution {
    path: PathBuf,
    from_published_endpoint: bool,
}

fn supervisor_owns_daemon(attach_daemon_only: bool, from_published_endpoint: bool) -> bool {
    !attach_daemon_only && !from_published_endpoint
}

fn daemon_socket_resolution(
    explicit: PathBuf,
    published: Option<PathBuf>,
) -> DaemonSocketResolution {
    match published {
        Some(path) => DaemonSocketResolution {
            path,
            from_published_endpoint: true,
        },
        None => DaemonSocketResolution {
            path: explicit,
            from_published_endpoint: false,
        },
    }
}

fn resolve_desktop_daemon_sock_with_source(explicit: PathBuf) -> DaemonSocketResolution {
    fn live_endpoint_from_base(base: PathBuf) -> Option<PathBuf> {
        if base.as_os_str().is_empty() {
            return None;
        }
        let paths = maestro_shell::AppPaths::with_base(base);
        match maestro_shell::load_endpoint(&paths) {
            Ok(Some(ep)) if !ep.socket_path.trim().is_empty() => {
                let published = PathBuf::from(ep.socket_path);
                if published.exists() {
                    Some(published)
                } else {
                    eprintln!(
                        "[hydra-agent] ignoring stale desktop daemon endpoint (socket missing): {}",
                        published.display()
                    );
                    None
                }
            }
            Ok(_) => None,
            Err(e) => {
                eprintln!("[hydra-agent] could not read desktop daemon endpoint: {e}");
                None
            }
        }
    }

    let mut bases: Vec<PathBuf> = Vec::new();
    if let Some(base) = std::env::var_os("MAESTRO_APP_SUPPORT_DIR") {
        bases.push(PathBuf::from(base));
    }
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        #[cfg(target_os = "macos")]
        {
            let support = home.join("Library").join("Application Support");
            bases.push(support.join("Maestro-dev"));
            bases.push(support.join("Maestro"));
        }
        #[cfg(not(target_os = "macos"))]
        {
            let data = xdg_dir(&home, "XDG_DATA_HOME", ".local/share");
            bases.push(data.join("maestro-dev"));
            bases.push(data.join("maestro"));
        }
    }

    for base in bases {
        if let Some(published) = live_endpoint_from_base(base) {
            if published != explicit {
                eprintln!(
                    "[hydra-agent] using desktop daemon socket from endpoint store: {}",
                    published.display()
                );
            }
            return daemon_socket_resolution(explicit, Some(published));
        }
    }

    daemon_socket_resolution(explicit, None)
}

fn resolve_desktop_daemon_sock(explicit: PathBuf) -> PathBuf {
    resolve_desktop_daemon_sock_with_source(explicit).path
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod cli_contract_tests {
    use super::{
        capture_destructive_cleanup, classify_process_ps, cleanup_retired_authority_then_service,
        close_remote_fail_closed, commit_filesystem_ack_before_lifecycle,
        converge_connectivity_closed_for_enrollment, converge_service_upgrade_if_needed,
        daemon_socket_resolution, dormant_launchd_pending_shape_is_safe,
        dormant_launchd_replacement_shape_is_safe, drive_destructive_cleanup_with,
        effective_remote_open, enrollment_lifecycle_failure, establish_extension_canonical_root,
        execute_extension_request, execute_pending_local_cleanup_with,
        extension_request_uses_lifecycle_preflight, failed_activation_cleanup_result,
        finalize_extension_service_activation, finish_extension_service_rollback,
        finish_failed_enrollment_activation, installed_systemd_supervisor_invocation,
        installed_systemd_supervisor_invocation_for_home, launchctl_running_pid,
        legacy_manager_change_is_safe, lifecycle_preflight_error_response,
        lifecycle_status_with_convergence, migration_probe_response,
        parse_generated_systemd_exec_start, parse_launchctl_job_state, parse_launchd_build_stamp,
        parse_manager_runtime_environment, parse_nul_arguments, parse_process_inventory,
        parse_supervisor_invocation, parse_systemd_build_stamp, parse_systemd_fragment_path,
        parse_systemd_unit_state, peer_inventory_roots, prepare_connectivity_closed_for_enrollment,
        prepare_forget_before_service_guard, process_is_live_exact, prove_exact_peer_stopped_with,
        prove_peer_inventory_stopped_with, read_owned_service_definition,
        read_owned_service_definition_for_home, reconcile_proven_legacy_agent_dir_candidates,
        reconcile_proven_legacy_agent_dirs, remote_peer_agent_dir,
        remove_local_authority_before_cleanup, require_pre_mutation_manager_state,
        require_pre_mutation_service_guard, required_systemd_fragment_invocation,
        retry_one_provider_revocation_with, run_service_cmd, service_app_support_dir,
        service_definition_entry_exists, service_upgrade_needed, supervise_standalone_flag,
        supervisor_owns_daemon, supervisor_readiness_agent_dir, systemd_unit_state_proves_absent,
        systemd_unit_state_uses_loaded_fragment, validate_closed_peer_inventory,
        validate_expected_systemd_fragment, validate_extension_argv,
        validate_single_peer_inventory, with_recaptured_lifecycle_state, CloseRemoteOutcome,
        LaunchdJobState, LaunchdReadinessTracker, ProviderRetryDisposition,
        ServiceActivationPriorState, SystemdReadinessTracker, SystemdUnitState,
        MAX_PROCESS_COMMAND_BYTES, MAX_PROCESS_INVENTORY_BYTES, MAX_PROCESS_INVENTORY_ENTRIES,
        SERVICE_USAGE,
    };
    #[cfg(target_os = "macos")]
    use super::{parse_macos_procargs2, parse_macos_procargs2_snapshot};

    const INSTALL_BINARY: &str = "/usr/local/bin/hydra-agent";

    #[cfg(unix)]
    fn secure_authority_test_dir(prefix: &str) -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt as _;

        let shared = std::fs::canonicalize("/tmp").unwrap();
        let root = tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in(shared)
            .unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    #[cfg(unix)]
    fn inert_lifecycle_descriptor(root: &std::path::Path) -> super::LifecycleDescriptor {
        let home = hydra_agent::agent_dir::trusted_home_dir().unwrap();
        let paths = super::extension_platform_service_paths(
            &home,
            root,
            super::default_service_label(),
            &hydra_agent::agent_dir::trusted_uid().to_string(),
        );
        super::LifecycleDescriptor {
            canonical_root: root.to_path_buf(),
            verified_marker_source: None,
            desired_paths: paths.clone(),
            observed_paths: paths,
            installed: Vec::new(),
            running: None,
            peer_roots: std::collections::BTreeSet::from([root.to_path_buf()]),
            activation_state: ServiceActivationPriorState::Closed,
            issues: Vec::new(),
        }
    }

    fn dormant_launchctl_job_fixture(state: &str) -> String {
        format!(
            "gui/501/com.hydra.agent = {{\n\
             \tactive count = 0\n\
             \tpath = /Users/test/Library/LaunchAgents/com.hydra.agent.plist\n\
             \tstate = {state}\n\
             \tlast exit code = 0\n\
             \tresource coalition = {{\n\
             \t\tpath = /foreign/nested.plist\n\
             \t\tstate = active\n\
             \t\tpid = 991\n\
             \t}}\n\
             \tjetsam coalition = {{\n\
             \t\tstate = active\n\
             \t}}\n\
             }}"
        )
    }

    #[cfg(unix)]
    fn queued_full_forget_fixture(
        label: &str,
        device_id: &str,
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        hydra_agent::service::LifecycleLockSet,
        hydra_agent::lifecycle_cleanup::RevocationTarget,
    ) {
        use hydra_agent::lifecycle_cleanup::{
            AuthorityEvidence, CleanupIntent, CleanupTombstone, DesiredUnit, ExactFileEvidence,
            LifecycleFileKind, PriorActivation,
        };

        let fixture = secure_authority_test_dir(&format!("hydra-provider-retry-{label}-"));
        let root = fixture.path().join("hydra-agent");
        hydra_agent::agent_dir::ensure_owned_safe_authority_directory(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let locks = hydra_agent::service::LifecycleLockSet::acquire([root.clone()]).unwrap();
        let record = hydra_agent::device_identity::DeviceRecord {
            device_id: device_id.to_string(),
            account_id: format!("acct_synthetic_{label}"),
            cloud_base: hydra_agent::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        hydra_agent::device_identity::save_record(&root, &record).unwrap();
        hydra_agent::device_identity::load_or_create_key(&root).unwrap();
        let record_evidence = ExactFileEvidence::capture(
            &root,
            &root.join("device.json"),
            LifecycleFileKind::CanonicalRecord,
            &locks,
        )
        .unwrap()
        .unwrap();
        let authority =
            AuthorityEvidence::target_from_exact_record(&record_evidence, &locks).unwrap();
        let key_evidence = ExactFileEvidence::capture(
            &root,
            &root.join("device-key"),
            LifecycleFileKind::CanonicalStableKey,
            &locks,
        )
        .unwrap()
        .unwrap();
        #[cfg(target_os = "macos")]
        let unit = root.join("synthetic-service/com.hydra.agent.plist");
        #[cfg(not(target_os = "macos"))]
        let unit = root.join("synthetic-service/hydra-agent.service");
        let pending = CleanupTombstone::new(
            CleanupIntent::FullForget,
            PriorActivation::ProvenClosed,
            authority,
            &root,
            &std::collections::BTreeSet::from([root.clone()]),
            &std::collections::BTreeSet::from([root.clone()]),
            [],
            [record_evidence, key_evidence],
            DesiredUnit::from_bytes(&unit, b"synthetic desired service definition").unwrap(),
            None,
            &locks,
        )
        .unwrap();
        let stored = hydra_agent::lifecycle_cleanup::store(&root, &pending, &locks).unwrap();
        let target = stored.revocation_target().unwrap().clone();
        hydra_agent::lifecycle_cleanup::handoff_revocation(&root, &target, &locks).unwrap();
        (fixture, root, locks, target)
    }

    fn published_028_linux_build_stamp() -> &'static str {
        #[cfg(target_arch = "aarch64")]
        {
            super::LEGACY_028_LINUX_ARM64_BUILD_STAMP
        }
        #[cfg(target_arch = "x86_64")]
        {
            super::LEGACY_028_LINUX_BUILD_STAMP
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            panic!("published 0.2.8 did not target this architecture")
        }
    }

    fn published_028_systemd_definition(agent_dir: &std::path::Path) -> String {
        let arguments = [
            "/opt/hydra/bin/hydra-agent".to_string(),
            "supervise".to_string(),
            "--attach-daemon-only".to_string(),
            "--dir".to_string(),
            agent_dir.to_string_lossy().into_owned(),
            "--sock".to_string(),
            "/run/user/1000/hydra-maestro-1000.sock".to_string(),
            "--environment".to_string(),
            super::LEGACY_028_ENVIRONMENT.to_string(),
            "--expected-cloud".to_string(),
            super::LEGACY_028_CLOUD_BASE.to_string(),
            "--cloud-pubkey".to_string(),
            super::LEGACY_028_CLOUD_PUBKEY.to_string(),
            "--allowed-origin".to_string(),
            super::LEGACY_028_ALLOWED_ORIGIN.to_string(),
        ]
        .into_iter()
        .map(String::into_bytes)
        .collect::<Vec<_>>();
        super::render_allowlisted_systemd_definition(
            &arguments,
            None,
            "/home/test/home/.local/share/maestro-dev",
            published_028_linux_build_stamp(),
            "/home/test/home/.local/state/hydra-agent/logs",
        )
        .unwrap()
    }

    fn current_systemd_definition() -> String {
        hydra_agent::systemd::generate_systemd_unit(&hydra_agent::systemd::SystemdUnitOptions {
            unit_name: "hydra-agent".to_string(),
            binary_path: "/opt/hydra/bin/hydra-agent".to_string(),
            build_stamp: "git=current123 built=1786200000000".to_string(),
            socket_path: "/run/user/1000/hydra-maestro-1000.sock".to_string(),
            fixed_external_daemon: false,
            sessions: vec!["session-1".to_string()],
            log_dir: "/home/test/home/.local/state/hydra-agent/logs".to_string(),
            home_dir: "/home/test/home".to_string(),
            maestro_app_support_dir: "/home/test/home/.local/share/maestro-dev".to_string(),
        })
    }

    fn fixed_headless_systemd_definition() -> String {
        hydra_agent::systemd::generate_systemd_unit(&hydra_agent::systemd::SystemdUnitOptions {
            unit_name: "hydra-agent".to_string(),
            binary_path: "/opt/hydra/bin/hydra-agent".to_string(),
            build_stamp: "git=current123 built=1786200000000".to_string(),
            socket_path: "/tmp/hydra-maestro-1000.sock".to_string(),
            fixed_external_daemon: true,
            sessions: Vec::new(),
            log_dir: "/home/test/home/.local/state/hydra-agent/logs".to_string(),
            home_dir: "/home/test/home".to_string(),
            maestro_app_support_dir: "/home/test/home/.local/share/maestro-dev".to_string(),
        })
    }

    fn published_028_launchd_definition(agent_dir: &std::path::Path) -> String {
        let arguments = [
            "/Applications/Hydra.app/Contents/MacOS/hydra-agent".to_string(),
            "supervise".to_string(),
            "--attach-daemon-only".to_string(),
            "--dir".to_string(),
            agent_dir.to_string_lossy().into_owned(),
            "--sock".to_string(),
            "/private/tmp/synthetic/hydra-maestro-501.sock".to_string(),
            "--environment".to_string(),
            super::LEGACY_028_ENVIRONMENT.to_string(),
            "--expected-cloud".to_string(),
            super::LEGACY_028_CLOUD_BASE.to_string(),
            "--cloud-pubkey".to_string(),
            super::LEGACY_028_CLOUD_PUBKEY.to_string(),
            "--allowed-origin".to_string(),
            super::LEGACY_028_ALLOWED_ORIGIN.to_string(),
        ]
        .into_iter()
        .map(String::into_bytes)
        .collect::<Vec<_>>();
        super::render_allowlisted_launchd_definition(
            &arguments,
            "/Users/test/home",
            "/Users/test/home/Library/Application Support/Maestro-dev",
            super::LEGACY_028_MACOS_BUILD_STAMP,
            "/Users/test/home/Library/Logs/Hydra",
        )
        .unwrap()
    }

    fn current_launchd_definition() -> String {
        hydra_agent::launchd::generate_launchd_plist(&hydra_agent::launchd::LaunchdPlistOptions {
            label: "com.hydra.agent".to_string(),
            binary_path: "/Applications/Hydra.app/Contents/MacOS/hydra-agent".to_string(),
            build_stamp: "git=current123 built=1786200000000".to_string(),
            socket_path: "/private/tmp/synthetic/hydra-maestro-501.sock".to_string(),
            sessions: vec!["session-1".to_string()],
            log_dir: "/Users/test/home/Library/Logs/Hydra".to_string(),
            home_dir: "/Users/test/home".to_string(),
            maestro_app_support_dir: "/Users/test/home/Library/Application Support/Maestro-dev"
                .to_string(),
        })
    }

    fn extension_command() -> String {
        "hydra-agent extension < one-bounded-request-on-stdin".to_string()
    }

    fn service_commands() -> [String; 4] {
        [
            format!("hydra-agent service install --dry-run --binary-path {INSTALL_BINARY}"),
            format!("hydra-agent service install --apply --binary-path {INSTALL_BINARY}"),
            "hydra-agent service status".to_string(),
            "hydra-agent service uninstall".to_string(),
        ]
    }

    #[test]
    fn extension_cli_has_no_secret_or_trust_argv() {
        let allowed = ["hydra-agent", "extension"].map(str::to_string);
        assert!(validate_extension_argv(&allowed).is_ok());
        for forbidden in [
            "--dir",
            "--code",
            "--cloud",
            "--cloud-pubkey",
            "--allowed-origin",
        ] {
            let args = ["hydra-agent", "extension", forbidden, "value"].map(str::to_string);
            assert!(validate_extension_argv(&args).is_err());
        }
    }

    #[test]
    fn service_state_is_the_only_positive_remote_gate() {
        assert!(!effective_remote_open(false, || Ok(true)));
        assert!(!effective_remote_open(true, || Ok(false)));
        assert!(!effective_remote_open(true, || anyhow::bail!("unready")));
        assert!(effective_remote_open(true, || Ok(true)));
    }

    #[test]
    fn close_then_restore_retired_gate_bytes_stays_closed() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-retired-gate-replay-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let retired = hydra_agent::remote_access::retired_authority_path(&dir);
        let bytes = br#"{"record":{"enabled":true},"signature":"retired"}"#;
        std::fs::write(&retired, bytes).unwrap();
        hydra_agent::remote_access::remove_retired_authority(&dir).unwrap();
        std::fs::write(&retired, bytes).unwrap();

        assert!(!effective_remote_open(true, || Ok(false)));
        assert_eq!(std::fs::read(&retired).unwrap(), bytes);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn service_readiness_failure_rolls_back_closed() {
        let rolled_back = std::cell::Cell::new(false);
        let result = finalize_extension_service_activation(
            Err(anyhow::anyhow!("readiness refused")),
            true,
            || {
                rolled_back.set(true);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(rolled_back.get());
    }

    #[test]
    fn installed_definition_build_stamp_parsers_are_exact_and_bounded() {
        let stamp = "git=0123abcd-dirty built=1786000000000";
        let launchd = format!(
            "<dict>\n    <key>HYDRA_AGENT_BUILD_STAMP</key>\n    <string>{stamp}</string>\n</dict>"
        );
        let systemd = format!("Environment=\"HYDRA_AGENT_BUILD_STAMP={stamp}\"\n");
        assert_eq!(parse_launchd_build_stamp(&launchd).unwrap(), stamp);
        assert_eq!(parse_systemd_build_stamp(&systemd).unwrap(), stamp);
        assert!(parse_launchd_build_stamp(&format!("{launchd}\n{launchd}")).is_err());
        assert!(parse_systemd_build_stamp(
            "Environment=\"HYDRA_AGENT_BUILD_STAMP=../../attacker\""
        )
        .is_err());
    }

    #[test]
    fn exact_process_probe_rejects_ambiguous_output() {
        assert!(classify_process_ps(true, Some(0), b"S+\n", b"").unwrap());
        assert!(!classify_process_ps(true, Some(0), b"Z\n", b"").unwrap());
        assert!(!classify_process_ps(false, Some(1), b"", b"").unwrap());
        assert!(classify_process_ps(true, Some(0), b"", b"").is_err());
        assert!(classify_process_ps(true, Some(0), b"S\nR\n", b"").is_err());
        assert!(classify_process_ps(false, Some(1), b"", b"permission denied").is_err());
        assert!(classify_process_ps(false, Some(2), b"", b"").is_err());
    }

    #[test]
    fn process_inventory_and_predecessor_remote_peer_argv_are_structural() {
        assert_eq!(
            parse_process_inventory(
                "  41  501 /Applications/Hydra Terms.app/Contents/MacOS/hydra-agent\n  42  501 /bin/sh\n  1105876  1000 Hydra Web Process\n"
            )
            .unwrap(),
            vec![
                (
                    41,
                    501,
                    "/Applications/Hydra Terms.app/Contents/MacOS/hydra-agent".to_string()
                ),
                (42, 501, "/bin/sh".to_string()),
                (1105876, 1000, "Hydra Web Process".to_string()),
            ]
        );
        for malformed in [
            "0 1000 hydra-agent",
            "pid 1000 hydra-agent",
            "1 uid hydra-agent",
            "1 1000",
            "1 1000    ",
            "1",
            "1 1000 hydra\tagent",
            "1 1000 hydra-agent\t",
            "1 1000 hydra-agent\r",
            "1 1000 hydra\0agent",
            "\t",
            "   \r",
        ] {
            assert!(parse_process_inventory(malformed).is_err(), "{malformed:?}");
        }
        assert!(parse_process_inventory(&format!(
            "1 1000 {}",
            "x".repeat(MAX_PROCESS_COMMAND_BYTES + 1)
        ))
        .is_err());
        assert!(
            parse_process_inventory(&"1 1000 x\n".repeat(MAX_PROCESS_INVENTORY_ENTRIES + 1))
                .is_err()
        );
        assert!(parse_process_inventory(&"x".repeat(MAX_PROCESS_INVENTORY_BYTES + 1)).is_err());
        let predecessor = parse_nul_arguments(
            b"/opt/hydra/hydra-agent\0remote-peer\0--dir\0/home/test/.local/share/hydra-agent\0--sock\0/run/user/501/hydra.sock\0--environment\0production\0--expected-cloud\0https://api.example.invalid\0--cloud-pubkey\0synthetic\0--allowed-origin\0https://app.example.invalid\0--sessions\0one,two\0",
        );
        assert_eq!(
            remote_peer_agent_dir(&predecessor).unwrap(),
            Some(std::path::PathBuf::from(
                "/home/test/.local/share/hydra-agent"
            ))
        );
        let headless = parse_nul_arguments(
            b"/usr/bin/hydra-agent\0remote-peer\0--dir\0/home/test/.local/share/hydra-agent\0--sock\0/tmp/hydra-maestro-1000.sock\0--headless-server\0",
        );
        assert_eq!(
            remote_peer_agent_dir(&headless).unwrap(),
            Some(std::path::PathBuf::from(
                "/home/test/.local/share/hydra-agent"
            ))
        );
        let duplicate_headless = parse_nul_arguments(
            b"hydra-agent\0remote-peer\0--dir\0/one\0--sock\0/socket\0--headless-server\0--headless-server\0",
        );
        assert!(remote_peer_agent_dir(&duplicate_headless).is_err());
        let duplicate = parse_nul_arguments(
            b"hydra-agent\0remote-peer\0--dir\0/one\0--dir\0/two\0--sock\0/socket\0",
        );
        assert!(remote_peer_agent_dir(&duplicate).is_err());
        let unknown =
            parse_nul_arguments(b"hydra-agent\0remote-peer\0--dir\0/one\0--attacker\0/value\0");
        assert!(remote_peer_agent_dir(&unknown).is_err());
    }

    #[test]
    fn failed_enrollment_activation_requires_proved_local_authority_absence() {
        let fallback_calls = std::cell::Cell::new(0);
        finish_failed_enrollment_activation(
            || Ok(()),
            || Ok(false),
            || {
                fallback_calls.set(fallback_calls.get() + 1);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(fallback_calls.get(), 0);

        let present = std::cell::Cell::new(true);
        let fallback_calls = std::cell::Cell::new(0);
        let result = finish_failed_enrollment_activation(
            || anyhow::bail!("journal refused"),
            || Ok(present.get()),
            || {
                fallback_calls.set(fallback_calls.get() + 1);
                present.set(false);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(fallback_calls.get(), 1);
        assert!(!present.get());

        let present = std::cell::Cell::new(true);
        let fallback_calls = std::cell::Cell::new(0);
        let result = finish_failed_enrollment_activation(
            || Ok(()),
            || Ok(present.get()),
            || {
                fallback_calls.set(fallback_calls.get() + 1);
                present.set(false);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(fallback_calls.get(), 1);
        assert!(!present.get());

        let present = std::cell::Cell::new(true);
        let result = finish_failed_enrollment_activation(
            || anyhow::bail!("journal refused"),
            || Ok(present.get()),
            || {
                present.set(false);
                anyhow::bail!("provider handoff refused")
            },
        );
        assert!(result.is_err());
        assert!(!present.get(), "fallback error may not skip the local cut");

        let result = finish_failed_enrollment_activation(
            || anyhow::bail!("journal refused"),
            || Ok(true),
            || Ok(()),
        );
        assert!(result.is_err(), "final authority presence must fail closed");
    }

    #[test]
    fn post_mutation_status_uses_recaptured_open_and_closed_state() {
        let record = hydra_agent::device_identity::DeviceRecord {
            device_id: "dev_synthetic_recapture".to_string(),
            account_id: "acct_synthetic_recapture".to_string(),
            cloud_base: hydra_agent::release_trust::active().cloud_base.to_string(),
            passkey: None,
        };
        let stale_before_open = ServiceActivationPriorState::Closed;
        let after_open = with_recaptured_lifecycle_state(
            || Ok(ServiceActivationPriorState::ProvenOpen),
            |current| lifecycle_status_with_convergence(Some(record.clone()), *current, || Ok(())),
        )
        .unwrap();
        assert_eq!(stale_before_open, ServiceActivationPriorState::Closed);
        assert!(after_open.remote_open());

        let stale_before_close = ServiceActivationPriorState::ProvenOpen;
        let after_close = with_recaptured_lifecycle_state(
            || Ok(ServiceActivationPriorState::Closed),
            |current| lifecycle_status_with_convergence(Some(record), *current, || Ok(())),
        )
        .unwrap();
        assert_eq!(stale_before_close, ServiceActivationPriorState::ProvenOpen);
        assert!(!after_close.remote_open());
    }

    #[cfg(unix)]
    #[test]
    fn fresh_enrollment_retires_open_or_dormant_connectivity_and_requires_closed_readback() {
        let root = secure_authority_test_dir("hydra-reenrollment-connectivity-");
        let closed = inert_lifecycle_descriptor(root.path());

        let close_calls = std::cell::Cell::new(0);
        let already_closed = converge_connectivity_closed_for_enrollment(&closed, || {
            close_calls.set(close_calls.get() + 1);
            Ok(closed.clone())
        })
        .unwrap();
        assert_eq!(
            already_closed.activation_state,
            ServiceActivationPriorState::Closed
        );
        assert_eq!(close_calls.get(), 0);

        let mut proven_open = closed.clone();
        proven_open.activation_state = ServiceActivationPriorState::ProvenOpen;
        let retired = converge_connectivity_closed_for_enrollment(&proven_open, || {
            close_calls.set(close_calls.get() + 1);
            Ok(closed.clone())
        })
        .unwrap();
        assert_eq!(
            retired.activation_state,
            ServiceActivationPriorState::Closed
        );
        assert_eq!(close_calls.get(), 1);

        assert!(
            converge_connectivity_closed_for_enrollment(&proven_open, || {
                Ok(proven_open.clone())
            })
            .is_err()
        );

        let mut ambiguous = closed.clone();
        ambiguous.activation_state = ServiceActivationPriorState::Ambiguous;
        let ambiguous_close_calls = std::cell::Cell::new(0);
        let retired = converge_connectivity_closed_for_enrollment(&ambiguous, || {
            ambiguous_close_calls.set(ambiguous_close_calls.get() + 1);
            Ok(closed.clone())
        })
        .unwrap();
        assert_eq!(
            retired.activation_state,
            ServiceActivationPriorState::Closed
        );
        assert_eq!(ambiguous_close_calls.get(), 1);

        assert!(converge_connectivity_closed_for_enrollment(&ambiguous, || {
            Ok(ambiguous.clone())
        })
        .is_err());
        assert!(converge_connectivity_closed_for_enrollment(&ambiguous, || {
            Err(anyhow::anyhow!("dormant connectivity cleanup failed"))
        })
        .is_err());

        let mut unverified = ambiguous;
        unverified
            .issues
            .push("unverified connectivity provenance".to_string());
        let unverified_close_called = std::cell::Cell::new(false);
        assert!(
            converge_connectivity_closed_for_enrollment(&unverified, || {
                unverified_close_called.set(true);
                Ok(closed.clone())
            })
            .is_err()
        );
        assert!(!unverified_close_called.get());
    }

    #[cfg(unix)]
    #[test]
    fn fresh_enrollment_never_retires_connectivity_for_an_active_record() {
        let root = secure_authority_test_dir("hydra-active-enrollment-connectivity-");
        let descriptor = inert_lifecycle_descriptor(root.path());
        let key = hydra_agent::device_identity::load_or_create_key(root.path()).unwrap();
        let record = hydra_agent::device_identity::DeviceRecord {
            device_id: "dev_active_rebind_guard".into(),
            account_id: "acct_active_rebind_guard".into(),
            cloud_base: hydra_agent::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        hydra_agent::device_identity::save_record(root.path(), &record).unwrap();
        let locks =
            hydra_agent::service::LifecycleLockSet::acquire([root.path().to_path_buf()]).unwrap();

        assert!(
            prepare_connectivity_closed_for_enrollment(root.path(), &descriptor, &locks,).is_err()
        );
        let retained = hydra_agent::device_identity::load_record(root.path())
            .unwrap()
            .unwrap();
        assert_eq!(retained.device_id, record.device_id);
        assert_eq!(retained.account_id, record.account_id);
        assert_eq!(retained.cloud_base, record.cloud_base);
        assert!(retained.passkey.is_none());
        assert_eq!(
            hydra_agent::device_identity::load_key(root.path())
                .unwrap()
                .unwrap()
                .to_bytes(),
            key.to_bytes()
        );
        assert!(root.path().join("device-owner.json").is_file());
        assert!(hydra_agent::lifecycle_cleanup::load(root.path())
            .unwrap()
            .is_none());
    }

    #[cfg(unix)]
    #[test]
    fn pending_remove_crash_window_accepts_only_journal_bound_attach_only_dormant_definition() {
        use hydra_agent::lifecycle_cleanup::{
            AuthorityEvidence, CleanupIntent, CleanupTombstone, DesiredUnit, ExactFileEvidence,
            LifecycleFileKind, ManagerEvidence, ObservedUnit, PriorActivation, UnitRole,
        };
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = secure_authority_test_dir("hydra-dormant-remove-proof-");
        let base = std::fs::canonicalize(fixture.path()).unwrap();
        let root = base.join("canonical/hydra-agent");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(
            root.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let locks = hydra_agent::service::LifecycleLockSet::acquire([root.clone()]).unwrap();

        let record = hydra_agent::device_identity::DeviceRecord {
            device_id: "dev_dormant_remove_proof".into(),
            account_id: "acct_dormant_remove_proof".into(),
            cloud_base: hydra_agent::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        hydra_agent::device_identity::save_record(&root, &record).unwrap();
        let record_evidence = ExactFileEvidence::capture(
            &root,
            &root.join("device.json"),
            LifecycleFileKind::CanonicalRecord,
            &locks,
        )
        .unwrap()
        .unwrap();
        let authority =
            AuthorityEvidence::target_from_exact_record(&record_evidence, &locks).unwrap();

        let service_dir = base.join("service");
        std::fs::create_dir(&service_dir).unwrap();
        std::fs::set_permissions(&service_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        #[cfg(target_os = "macos")]
        let (service_file, service_bytes, parsed) = {
            let bytes = current_launchd_definition().into_bytes();
            let parsed = super::parse_full_launchd_service_definition(&bytes).unwrap();
            (service_dir.join("com.hydra.agent.plist"), bytes, parsed)
        };
        #[cfg(target_os = "linux")]
        let (service_file, service_bytes, parsed) = {
            let bytes = current_systemd_definition().into_bytes();
            let parsed = super::parse_full_systemd_service_definition(&bytes).unwrap();
            (service_dir.join("hydra-agent.service"), bytes, parsed)
        };
        std::fs::write(&service_file, &service_bytes).unwrap();
        std::fs::set_permissions(&service_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let service_evidence = ExactFileEvidence::capture(
            &root,
            &service_file,
            LifecycleFileKind::ServiceDefinition,
            &locks,
        )
        .unwrap()
        .unwrap();
        let installed = super::InstalledServiceDescriptor {
            path: service_file.clone(),
            bytes: service_bytes.clone(),
            invocation: Some(parsed.invocation.clone()),
            build_stamp: parsed.build_stamp.clone(),
        };
        let manager = ManagerEvidence::new(
            &root,
            &parsed.invocation.socket_path,
            parsed.build_stamp,
            "a".repeat(64),
        )
        .unwrap();
        #[cfg(target_os = "macos")]
        let desired = base.join("desired/com.hydra.agent.plist");
        #[cfg(target_os = "linux")]
        let desired = base.join("desired/hydra-agent.service");
        let roots = std::collections::BTreeSet::from([root.clone()]);
        let pending = CleanupTombstone::new(
            CleanupIntent::Remove,
            PriorActivation::ProvenOpen,
            authority,
            &root,
            &roots,
            &roots,
            [ObservedUnit::from_bytes(
                &service_file,
                &service_bytes,
                [UnitRole::HistoricalInstalled, UnitRole::LoadedEffective],
            )
            .unwrap()],
            [record_evidence, service_evidence],
            DesiredUnit::from_bytes(&desired, b"synthetic desired service definition").unwrap(),
            Some(manager),
            &locks,
        )
        .unwrap();
        let stored = hydra_agent::lifecycle_cleanup::store(&root, &pending, &locks).unwrap();
        let target = stored.revocation_target().unwrap().clone();
        let handed =
            hydra_agent::lifecycle_cleanup::handoff_revocation(&root, &target, &locks).unwrap();
        let record_cut = hydra_agent::lifecycle_cleanup::execute_planned_deletion(
            &root,
            &handed,
            &root.join("device.json"),
            &locks,
        )
        .unwrap();
        assert!(!root.join("device.json").exists());
        assert!(service_file.exists());

        let no_peers = std::collections::BTreeSet::new();
        assert!(super::pending_remove_binds_dormant_definition(
            &record_cut,
            &installed,
            &root,
            true,
            &no_peers,
        )
        .unwrap());

        let peers = std::collections::BTreeSet::from([4242]);
        assert!(!super::pending_remove_binds_dormant_definition(
            &record_cut,
            &installed,
            &root,
            true,
            &peers,
        )
        .unwrap());
        assert!(!super::pending_remove_binds_dormant_definition(
            &record_cut,
            &installed,
            &root,
            false,
            &no_peers,
        )
        .unwrap());

        let mut daemon_owning = installed.clone();
        daemon_owning
            .invocation
            .as_mut()
            .unwrap()
            .attach_daemon_only = false;
        assert!(!super::pending_remove_binds_dormant_definition(
            &record_cut,
            &daemon_owning,
            &root,
            true,
            &no_peers,
        )
        .unwrap());

        let mut changed = installed.clone();
        changed.bytes.push(b'\n');
        assert!(!super::pending_remove_binds_dormant_definition(
            &record_cut,
            &changed,
            &root,
            true,
            &no_peers,
        )
        .unwrap());

        let mut foreign_root = installed;
        foreign_root.invocation.as_mut().unwrap().agent_dir =
            Some(base.join("foreign/hydra-agent"));
        assert!(!super::pending_remove_binds_dormant_definition(
            &record_cut,
            &foreign_root,
            &root,
            true,
            &no_peers,
        )
        .unwrap());

        // Model the immediately following crash window too: stop already
        // succeeded, the exact unit unlink was journaled, but systemd had not
        // yet been reloaded. Recovery must resume at reload and must not try to
        // rediscover or stop a manager from the now-absent definition.
        let definition_cut = hydra_agent::lifecycle_cleanup::execute_planned_deletion(
            &root,
            &record_cut,
            &service_file,
            &locks,
        )
        .unwrap();
        let stop_called = std::cell::Cell::new(false);
        let reload_called = std::cell::Cell::new(false);
        let connectivity_proved = std::cell::Cell::new(false);
        let resumed = execute_pending_local_cleanup_with(
            &root,
            definition_cut,
            &locks,
            |_dir, _pending| {
                stop_called.set(true);
                anyhow::bail!("a durably retired definition must resume after stop")
            },
            || {
                reload_called.set(true);
                Ok(())
            },
            |_dir, _pending| {
                connectivity_proved.set(true);
                Ok(())
            },
        )
        .unwrap();
        assert!(!stop_called.get());
        assert!(reload_called.get());
        assert!(connectivity_proved.get());
        assert!(resumed
            .deletion_targets()
            .filter(|target| { target.evidence().kind() == LifecycleFileKind::ServiceDefinition })
            .all(hydra_agent::lifecycle_cleanup::PlannedDeletion::is_proven_absent));
    }

    #[test]
    fn installed_xdg_predecessor_uses_old_readiness_root_then_one_canonical_peer() {
        // This is the exact source identity of the published 0.2.8 cohort. Its
        // service_readiness.rs digest is byte-identical to this build
        // (9738fc1f03ff008255a567ff32e3f9b9350492a63ff892b2ed8654e83c2cd6ee),
        // and its generated Linux unit carries this git value plus the exact
        // historical XDG --dir and retired trust argv represented below.
        const PUBLISHED_028_SOURCE: &str = "36d69db";
        let canonical = std::path::Path::new("/home/test/.local/share/hydra-agent");
        let legacy = std::path::Path::new("/home/test/.xdg-data/hydra-agent");
        let roots = peer_inventory_roots(canonical, Some(legacy)).unwrap();
        assert_eq!(
            roots,
            std::collections::BTreeSet::from([canonical.to_path_buf(), legacy.to_path_buf(),])
        );

        let predecessor = parse_supervisor_invocation(&parse_nul_arguments(
            b"/opt/hydra/hydra-agent\0supervise\0--attach-daemon-only\0--dir\0/home/test/.xdg-data/hydra-agent\0--sock\0/run/user/501/hydra.sock\0--environment\0production\0--expected-cloud\0https://api.example.invalid\0--cloud-pubkey\0synthetic\0--allowed-origin\0https://app.example.invalid\0",
        ))
        .unwrap();
        assert_eq!(
            supervisor_readiness_agent_dir(canonical, &predecessor),
            legacy
        );
        let predecessor_stamp = format!("git={PUBLISHED_028_SOURCE} built=1786200000");
        assert_eq!(
            parse_systemd_build_stamp(&format!(
                "Environment=\"HYDRA_AGENT_BUILD_STAMP={predecessor_stamp}\"\n"
            ))
            .unwrap(),
            predecessor_stamp
        );

        let old_peer = 91;
        let new_peer = 92;
        prove_peer_inventory_stopped_with(
            &std::collections::BTreeSet::from([old_peer]),
            1,
            |_| Ok(false),
            || {},
        )
        .unwrap();
        validate_single_peer_inventory(&std::collections::BTreeSet::from([new_peer]), new_peer)
            .unwrap();
        validate_closed_peer_inventory(&std::collections::BTreeSet::new()).unwrap();
    }

    #[test]
    fn exact_peer_retirement_is_fail_closed_for_survival_or_unreadable_state() {
        let observations = std::cell::RefCell::new(vec![true, true, false].into_iter());
        prove_exact_peer_stopped_with(
            41,
            3,
            |_| Ok(observations.borrow_mut().next().unwrap()),
            || {},
        )
        .unwrap();
        assert!(prove_exact_peer_stopped_with(42, 2, |_| Ok(true), || {}).is_err());
        assert!(prove_exact_peer_stopped_with(
            43,
            2,
            |_| anyhow::bail!("liveness unreadable"),
            || {},
        )
        .is_err());
    }

    #[test]
    fn close_rejects_absent_manager_orphan_and_upgrade_rejects_prior_orphan_plus_current() {
        let absent_manager_orphan = std::collections::BTreeSet::from([71]);
        assert!(validate_closed_peer_inventory(&absent_manager_orphan).is_err());
        assert!(
            prove_peer_inventory_stopped_with(&absent_manager_orphan, 2, |_| Ok(true), || {},)
                .is_err()
        );

        let prior_orphan = 81;
        let current_manager_child = 82;
        let new_peer = 83;
        let before = std::collections::BTreeSet::from([prior_orphan, current_manager_child]);
        let after = std::collections::BTreeSet::from([prior_orphan, new_peer]);
        assert!(prove_peer_inventory_stopped_with(
            &before,
            2,
            |pid| Ok(pid == prior_orphan),
            || {},
        )
        .is_err());
        assert!(validate_single_peer_inventory(&after, new_peer).is_err());
        assert!(validate_single_peer_inventory(
            &std::collections::BTreeSet::from([new_peer]),
            new_peer,
        )
        .is_ok());
    }

    #[test]
    fn platform_process_seam_distinguishes_exited_child_from_surviving_orphan() {
        let mut exited = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .unwrap();
        let exited_pid = exited.id();
        exited.wait().unwrap();
        prove_exact_peer_stopped_with(exited_pid, 1, process_is_live_exact, || {}).unwrap();

        let mut orphan = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .spawn()
            .unwrap();
        let orphan_pid = orphan.id();
        assert!(process_is_live_exact(orphan_pid).unwrap());
        assert!(
            prove_exact_peer_stopped_with(orphan_pid, 2, process_is_live_exact, || {}).is_err()
        );
        orphan.kill().unwrap();
        orphan.wait().unwrap();
        prove_exact_peer_stopped_with(orphan_pid, 1, process_is_live_exact, || {}).unwrap();
    }

    #[test]
    fn installed_predecessor_to_new_proof_retires_old_and_requires_one_new_peer() {
        let mut old = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .spawn()
            .unwrap();
        let mut new = std::process::Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .spawn()
            .unwrap();
        let old_pid = old.id();
        let new_pid = new.id();
        old.kill().unwrap();
        old.wait().unwrap();
        prove_exact_peer_stopped_with(old_pid, 1, process_is_live_exact, || {}).unwrap();
        assert!(process_is_live_exact(new_pid).unwrap());
        validate_single_peer_inventory(&std::collections::BTreeSet::from([new_pid]), new_pid)
            .unwrap();
        new.kill().unwrap();
        new.wait().unwrap();
    }

    #[test]
    fn closed_activation_revokes_when_exact_peer_retirement_is_unproved() {
        let revoked = std::cell::Cell::new(false);
        let result = finish_extension_service_rollback(
            Vec::new(),
            Ok(false),
            Ok(None),
            Err(anyhow::anyhow!("captured peer survived")),
            ServiceActivationPriorState::Closed,
            || {
                revoked.set(true);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(revoked.get());
    }

    #[test]
    fn failed_upgrade_reports_unproved_close_without_revoking_enrollment() {
        let revoked = std::cell::Cell::new(false);
        let result = finish_extension_service_rollback(
            vec!["manager cleanup failed".to_string()],
            Err(anyhow::anyhow!("definition metadata unreadable")),
            Ok(Some(41)),
            Ok(()),
            ServiceActivationPriorState::ProvenOpen,
            || {
                revoked.set(true);
                Ok(())
            },
        );

        let error = result.unwrap_err().to_string();
        assert!(error.contains("manager cleanup failed"));
        assert!(error.contains("definition metadata unreadable"));
        assert!(error.contains("still running"));
        assert!(!error.contains("revoke"));
        assert!(
            !revoked.get(),
            "an already-open upgrade keeps its enrollment"
        );
    }

    #[test]
    fn failed_upgrade_keeps_enrollment_when_definition_and_pid_absence_are_proved() {
        let revoked = std::cell::Cell::new(false);
        let result = finish_extension_service_rollback(
            vec!["readiness cleanup reported an error".to_string()],
            Ok(false),
            Ok(None),
            Ok(()),
            ServiceActivationPriorState::ProvenOpen,
            || {
                revoked.set(true);
                Ok(())
            },
        );

        assert!(result.is_err(), "cleanup errors remain visible");
        assert!(!revoked.get());
    }

    #[test]
    fn pre_mutation_open_guard_refusal_preserves_closed_enrollment() {
        let dir = secure_authority_test_dir("hydra-pre-mutation-guard-");
        let record = hydra_agent::device_identity::DeviceRecord {
            device_id: "dev_synthetic_guard".into(),
            account_id: "acct_synthetic_guard".into(),
            cloud_base: hydra_agent::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        hydra_agent::device_identity::save_record(dir.path(), &record).unwrap();
        let result = require_pre_mutation_service_guard(|| {
            anyhow::bail!("legacy owner has retained sessions")
        });
        assert!(result.is_err());
        assert!(
            hydra_agent::device_identity::load_record(dir.path())
                .unwrap()
                .is_some(),
            "an observational guard may not revoke enrollment"
        );
    }

    #[test]
    fn pre_mutation_manager_probe_failure_preserves_closed_enrollment() {
        let dir = secure_authority_test_dir("hydra-pre-mutation-manager-probe-");
        let record = hydra_agent::device_identity::DeviceRecord {
            device_id: "dev_synthetic_manager_probe".into(),
            account_id: "acct_synthetic_manager_probe".into(),
            cloud_base: hydra_agent::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        hydra_agent::device_identity::save_record(dir.path(), &record).unwrap();

        let result: anyhow::Result<ServiceActivationPriorState> =
            require_pre_mutation_manager_state(|| anyhow::bail!("manager metadata denied"));

        assert!(result.is_err());
        assert!(
            hydra_agent::device_identity::load_record(dir.path())
                .unwrap()
                .is_some(),
            "a pre-mutation manager probe may not revoke enrollment"
        );
    }

    #[test]
    fn failed_closed_open_revokes_only_when_post_mutation_absence_is_unproved() {
        for (definition_exists, manager_pid, should_revoke) in [
            (false, None, false),
            (true, None, true),
            (false, Some(7), true),
            (true, Some(7), true),
        ] {
            let revoked = std::cell::Cell::new(false);
            let result = finish_extension_service_rollback(
                Vec::new(),
                Ok(definition_exists),
                Ok(manager_pid),
                Ok(()),
                ServiceActivationPriorState::Closed,
                || {
                    revoked.set(true);
                    Ok(())
                },
            );
            assert_eq!(revoked.get(), should_revoke);
            assert_eq!(result.is_ok(), !should_revoke);
        }

        let revoked = std::cell::Cell::new(false);
        assert!(finish_extension_service_rollback(
            Vec::new(),
            Err(anyhow::anyhow!("metadata denied")),
            Ok(None),
            Ok(()),
            ServiceActivationPriorState::Closed,
            || {
                revoked.set(true);
                Ok(())
            },
        )
        .is_err());
        assert!(
            revoked.get(),
            "probe errors cannot establish service absence"
        );
    }

    #[test]
    fn explicit_close_revokes_on_guard_partial_cleanup_or_manager_read_failure() {
        for failure in [
            "legacy-session guard refused",
            "partial uninstall",
            "manager state unreadable",
        ] {
            let revoked = std::cell::Cell::new(false);
            let result = close_remote_fail_closed(
                || anyhow::bail!(failure),
                || {
                    revoked.set(true);
                    Ok(())
                },
            )
            .unwrap();
            assert_eq!(result, CloseRemoteOutcome::EnrollmentRevoked);
            assert!(revoked.get(), "{failure}");
        }
    }

    #[test]
    fn explicit_close_local_revocation_cuts_an_existing_peer_binding() {
        let dir = secure_authority_test_dir("hydra-close-live-binding-");
        let record = hydra_agent::device_identity::DeviceRecord {
            device_id: "dev_synthetic_close".into(),
            account_id: "acct_synthetic_close".into(),
            cloud_base: hydra_agent::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        hydra_agent::device_identity::save_record(dir.path(), &record).unwrap();
        assert!(
            !hydra_agent::device_identity::enrollment_binding_is_revoked(
                dir.path(),
                &record.account_id,
                &record.device_id,
                &record.cloud_base,
            )
        );

        let result = close_remote_fail_closed(
            || anyhow::bail!("service state unreadable"),
            || {
                hydra_agent::device_identity::preserve_owner_marker(dir.path())?;
                hydra_agent::device_identity::remove_record(dir.path())
            },
        )
        .unwrap();
        assert_eq!(result, CloseRemoteOutcome::EnrollmentRevoked);
        assert!(hydra_agent::device_identity::enrollment_binding_is_revoked(
            dir.path(),
            &record.account_id,
            &record.device_id,
            &record.cloud_base,
        ));
        assert!(dir.path().join("device-owner.json").is_file());
    }

    #[cfg(unix)]
    #[test]
    fn provider_retry_classifier_is_exact_bounded_and_terminal_receipted() {
        use hydra_agent::lifecycle_cleanup::ProviderTerminalOutcome;

        for (label, status, expected) in [
            ("ok-200", 200, ProviderTerminalOutcome::Revoked),
            ("ok-204", 204, ProviderTerminalOutcome::Revoked),
            ("ok-299", 299, ProviderTerminalOutcome::Revoked),
            ("absent-404", 404, ProviderTerminalOutcome::AlreadyAbsent),
        ] {
            let (_fixture, root, locks, target) =
                queued_full_forget_fixture(label, &format!("dev_synthetic_{label}"));
            let calls = std::cell::Cell::new(0usize);
            let disposition = retry_one_provider_revocation_with(
                &root,
                &locks,
                |_| Ok(Some(())),
                |sent_target, &()| {
                    calls.set(calls.get() + 1);
                    assert_eq!(sent_target, &target);
                    Ok(status)
                },
            )
            .unwrap();
            assert_eq!(disposition, ProviderRetryDisposition::Completed);
            assert_eq!(calls.get(), 1);
            let pending = hydra_agent::lifecycle_cleanup::load(&root)
                .unwrap()
                .unwrap();
            assert_eq!(pending.provider_terminal_target(), Some(&target));
            assert_eq!(pending.provider_terminal_outcome(), Some(expected));
            assert!(
                hydra_agent::lifecycle_cleanup::load_revocation_outbox(&root)
                    .unwrap()
                    .targets()
                    .next()
                    .is_none()
            );
        }

        for (label, response) in [
            ("refused-400", Ok(400)),
            ("failed-500", Ok(500)),
            ("network", Err(anyhow::anyhow!("synthetic network failure"))),
        ] {
            let (_fixture, root, locks, target) =
                queued_full_forget_fixture(label, &format!("dev_synthetic_{label}"));
            let calls = std::cell::Cell::new(0usize);
            let disposition = retry_one_provider_revocation_with(
                &root,
                &locks,
                |_| Ok(Some(())),
                |sent_target, &()| {
                    calls.set(calls.get() + 1);
                    assert_eq!(sent_target, &target);
                    response
                },
            )
            .unwrap();
            assert_eq!(disposition, ProviderRetryDisposition::Retained);
            assert_eq!(calls.get(), 1);
            let pending = hydra_agent::lifecycle_cleanup::load(&root)
                .unwrap()
                .unwrap();
            assert_eq!(pending.provider_terminal_target(), None);
            assert!(
                hydra_agent::lifecycle_cleanup::load_revocation_outbox(&root)
                    .unwrap()
                    .targets()
                    .any(|queued| queued == &target)
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn provider_retry_never_recreates_a_missing_key_and_processes_one_target() {
        let (_fixture, root, locks, target) =
            queued_full_forget_fixture("bounded", "dev_b_provider_retry");
        std::fs::remove_file(root.join("device-key")).unwrap();
        let second = hydra_agent::lifecycle_cleanup::RevocationTarget::new(
            hydra_agent::release_trust::CLOUD_BASE.into(),
            "acct_synthetic_second".into(),
            "dev_a_provider_retry".into(),
        )
        .unwrap();
        hydra_agent::lifecycle_cleanup::enqueue_revocation(
            &root,
            &second,
            locks.lock_for(&root).unwrap(),
        )
        .unwrap();
        let send_calls = std::cell::Cell::new(0usize);
        assert_eq!(
            retry_one_provider_revocation_with::<()>(
                &root,
                &locks,
                |_| Ok(None),
                |_target, &()| {
                    send_calls.set(send_calls.get() + 1);
                    Ok(200)
                },
            )
            .unwrap(),
            ProviderRetryDisposition::Retained
        );
        assert_eq!(send_calls.get(), 0);
        assert!(!root.join("device-key").exists());
        assert_eq!(
            hydra_agent::lifecycle_cleanup::load_revocation_outbox(&root)
                .unwrap()
                .targets()
                .count(),
            2
        );

        let sent = std::cell::RefCell::new(Vec::new());
        assert_eq!(
            retry_one_provider_revocation_with(
                &root,
                &locks,
                |_| Ok(Some(())),
                |sent_target, &()| {
                    sent.borrow_mut().push(sent_target.device_id().to_string());
                    Ok(200)
                },
            )
            .unwrap(),
            ProviderRetryDisposition::Completed
        );
        assert_eq!(sent.borrow().as_slice(), [second.device_id()]);
        let remaining = hydra_agent::lifecycle_cleanup::load_revocation_outbox(&root)
            .unwrap()
            .targets()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(remaining, vec![target]);
    }

    #[cfg(unix)]
    #[test]
    fn production_driver_recovers_key_unlink_before_proof_without_requeue() {
        use hydra_agent::lifecycle_cleanup::{
            AuthorityEvidence, CleanupIntent, CleanupTombstone, DesiredUnit, ExactFileEvidence,
            LifecycleFileKind, PriorActivation, ProviderTerminalOutcome,
        };

        let fixture = secure_authority_test_dir("hydra-full-forget-crash-");
        let root = std::fs::canonicalize(fixture.path())
            .unwrap()
            .join("hydra-agent");
        hydra_agent::agent_dir::ensure_owned_safe_authority_directory(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let locks = hydra_agent::service::LifecycleLockSet::acquire([root.clone()]).unwrap();
        let record = hydra_agent::device_identity::DeviceRecord {
            device_id: "dev_synthetic_full_forget_crash".into(),
            account_id: "acct_synthetic_full_forget_crash".into(),
            cloud_base: hydra_agent::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        hydra_agent::device_identity::save_record(&root, &record).unwrap();
        hydra_agent::device_identity::load_or_create_key(&root).unwrap();
        let record_evidence = ExactFileEvidence::capture(
            &root,
            &root.join("device.json"),
            LifecycleFileKind::CanonicalRecord,
            &locks,
        )
        .unwrap()
        .unwrap();
        let authority =
            AuthorityEvidence::target_from_exact_record(&record_evidence, &locks).unwrap();
        let key_evidence = ExactFileEvidence::capture(
            &root,
            &root.join("device-key"),
            LifecycleFileKind::CanonicalStableKey,
            &locks,
        )
        .unwrap()
        .unwrap();
        #[cfg(target_os = "macos")]
        let unit = root.join("service/com.hydra.agent.plist");
        #[cfg(not(target_os = "macos"))]
        let unit = root.join("service/hydra-agent.service");
        let pending = CleanupTombstone::new(
            CleanupIntent::FullForget,
            PriorActivation::ProvenClosed,
            authority,
            &root,
            &std::collections::BTreeSet::from([root.clone()]),
            &std::collections::BTreeSet::from([root.clone()]),
            [],
            [record_evidence, key_evidence],
            DesiredUnit::from_bytes(&unit, b"synthetic desired service definition").unwrap(),
            None,
            &locks,
        )
        .unwrap();
        let stored = hydra_agent::lifecycle_cleanup::store(&root, &pending, &locks).unwrap();
        let target = stored.revocation_target().unwrap().clone();
        hydra_agent::lifecycle_cleanup::handoff_revocation(&root, &target, &locks).unwrap();
        hydra_agent::lifecycle_cleanup::record_full_forget_provider_terminal(
            &root,
            &target,
            ProviderTerminalOutcome::Revoked,
            &locks,
        )
        .unwrap();
        hydra_agent::lifecycle_cleanup::complete_revocation(
            &root,
            target.device_id(),
            locks.lock_for(&root).unwrap(),
        )
        .unwrap();

        // Exact crash state: unlink and durably sync the stable key, but do not
        // publish the deletion proof into the lifecycle journal.
        std::fs::remove_file(root.join("device-key")).unwrap();
        std::fs::File::open(&root).unwrap().sync_all().unwrap();
        let crashed = hydra_agent::lifecycle_cleanup::load(&root)
            .unwrap()
            .unwrap();
        assert_eq!(crashed.provider_terminal_target(), Some(&target));

        drive_destructive_cleanup_with(
            &root,
            crashed,
            &locks,
            |_dir, pending, _locks| Ok(pending),
            super::retry_one_provider_revocation,
        )
        .unwrap();

        assert!(hydra_agent::lifecycle_cleanup::load(&root)
            .unwrap()
            .is_none());
        assert!(
            hydra_agent::lifecycle_cleanup::load_revocation_outbox(&root)
                .unwrap()
                .targets()
                .next()
                .is_none()
        );
        assert!(!root.join("device-key").exists());
        assert!(!root.join("device.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn production_full_forget_capture_is_nonmutating_and_binds_both_diagnostics() {
        use hydra_agent::lifecycle_cleanup::{CleanupIntent, LifecycleFileKind};
        use std::os::unix::fs::{symlink, MetadataExt as _, PermissionsExt as _};

        let fixture = |label: &str| {
            let fixture = secure_authority_test_dir(&format!("hydra-capture-diagnostics-{label}-"));
            let root = fixture.path().join("hydra-agent");
            hydra_agent::agent_dir::ensure_owned_safe_authority_directory(&root).unwrap();
            let root = std::fs::canonicalize(root).unwrap();
            let locks = hydra_agent::service::LifecycleLockSet::acquire([root.clone()]).unwrap();
            let descriptor = inert_lifecycle_descriptor(&root);
            (fixture, root, locks, descriptor)
        };

        let (_fixture, root, locks, descriptor) = fixture("safe");
        let diagnostics = hydra_agent::device_identity::enrollment_diagnostics_path(&root);
        let temporary = hydra_agent::device_identity::enrollment_diagnostics_temporary_path(&root);
        let diagnostic_bytes = br#"{"version":1,"events":[]}"#;
        let temporary_bytes = b"crash-before-rename";
        std::fs::write(&diagnostics, diagnostic_bytes).unwrap();
        std::fs::write(&temporary, temporary_bytes).unwrap();
        std::fs::set_permissions(&diagnostics, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).unwrap();
        let diagnostic_before = std::fs::metadata(&diagnostics).unwrap();
        let temporary_before = std::fs::metadata(&temporary).unwrap();
        let captured = capture_destructive_cleanup(
            &root,
            CleanupIntent::FullForget,
            &descriptor,
            &locks,
            false,
        )
        .unwrap();
        assert!(captured.deletion_targets().any(|target| {
            target.evidence().kind() == LifecycleFileKind::EnrollmentDiagnostics
                && target.evidence().path() == diagnostics
        }));
        assert!(captured.deletion_targets().any(|target| {
            target.evidence().kind() == LifecycleFileKind::EnrollmentDiagnosticsTemporary
                && target.evidence().path() == temporary
        }));
        let diagnostic_after = std::fs::metadata(&diagnostics).unwrap();
        let temporary_after = std::fs::metadata(&temporary).unwrap();
        assert_eq!(
            (diagnostic_after.dev(), diagnostic_after.ino()),
            (diagnostic_before.dev(), diagnostic_before.ino())
        );
        assert_eq!(
            (temporary_after.dev(), temporary_after.ino()),
            (temporary_before.dev(), temporary_before.ino())
        );
        assert_eq!(std::fs::read(&diagnostics).unwrap(), diagnostic_bytes);
        assert_eq!(std::fs::read(&temporary).unwrap(), temporary_bytes);

        let (_fixture, root, locks, descriptor) = fixture("symlink");
        let temporary = hydra_agent::device_identity::enrollment_diagnostics_temporary_path(&root);
        let target = root.join("diagnostic-symlink-target");
        std::fs::write(&target, b"symlink-sentinel").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &temporary).unwrap();
        let before = std::fs::symlink_metadata(&temporary).unwrap();
        assert!(capture_destructive_cleanup(
            &root,
            CleanupIntent::FullForget,
            &descriptor,
            &locks,
            false,
        )
        .is_err());
        let after = std::fs::symlink_metadata(&temporary).unwrap();
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
        assert_eq!(std::fs::read(&target).unwrap(), b"symlink-sentinel");

        let (_fixture, root, locks, descriptor) = fixture("hardlink");
        let temporary = hydra_agent::device_identity::enrollment_diagnostics_temporary_path(&root);
        std::fs::write(&temporary, b"hardlink-sentinel").unwrap();
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).unwrap();
        let second = root.join("diagnostic-second-link");
        std::fs::hard_link(&temporary, &second).unwrap();
        let before = std::fs::metadata(&temporary).unwrap();
        assert!(capture_destructive_cleanup(
            &root,
            CleanupIntent::FullForget,
            &descriptor,
            &locks,
            false,
        )
        .is_err());
        let after = std::fs::metadata(&temporary).unwrap();
        assert_eq!(
            (after.dev(), after.ino(), after.nlink()),
            (before.dev(), before.ino(), 2)
        );
        assert_eq!(std::fs::read(&temporary).unwrap(), b"hardlink-sentinel");

        let (_fixture, root, locks, descriptor) = fixture("mode");
        let temporary = hydra_agent::device_identity::enrollment_diagnostics_temporary_path(&root);
        std::fs::write(&temporary, b"mode-sentinel").unwrap();
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o400)).unwrap();
        let before = std::fs::metadata(&temporary).unwrap();
        assert!(capture_destructive_cleanup(
            &root,
            CleanupIntent::FullForget,
            &descriptor,
            &locks,
            false,
        )
        .is_err());
        let after = std::fs::metadata(&temporary).unwrap();
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
        assert_eq!(after.permissions().mode() & 0o7777, 0o400);

        for (label, path_for) in [
            (
                "oversized-canonical",
                hydra_agent::device_identity::enrollment_diagnostics_path
                    as fn(&std::path::Path) -> std::path::PathBuf,
            ),
            (
                "oversized-temporary",
                hydra_agent::device_identity::enrollment_diagnostics_temporary_path
                    as fn(&std::path::Path) -> std::path::PathBuf,
            ),
        ] {
            let (_fixture, root, locks, descriptor) = fixture(label);
            let path = path_for(&root);
            let bytes =
                vec![b'x'; hydra_agent::device_identity::MAX_ENROLLMENT_DIAGNOSTICS_BYTES + 1];
            std::fs::write(&path, &bytes).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let before = std::fs::metadata(&path).unwrap();
            assert!(capture_destructive_cleanup(
                &root,
                CleanupIntent::FullForget,
                &descriptor,
                &locks,
                false,
            )
            .is_err());
            let after = std::fs::metadata(&path).unwrap();
            assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
    }

    #[cfg(unix)]
    #[test]
    fn initial_full_forget_deletes_captured_diagnostic_temp_and_ring_only_after_handoff() {
        use hydra_agent::lifecycle_cleanup::{
            AuthorityEvidence, CleanupIntent, CleanupTombstone, DesiredUnit, ExactFileEvidence,
            LifecycleFileKind, PriorActivation, ProviderTerminalOutcome,
        };
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = secure_authority_test_dir("hydra-full-forget-diagnostics-");
        let root = fixture.path().join("hydra-agent");
        hydra_agent::agent_dir::ensure_owned_safe_authority_directory(&root).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        let locks = hydra_agent::service::LifecycleLockSet::acquire([root.clone()]).unwrap();
        let record = hydra_agent::device_identity::DeviceRecord {
            device_id: "dev_full_forget_diagnostics".into(),
            account_id: "acct_full_forget_diagnostics".into(),
            cloud_base: hydra_agent::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        hydra_agent::device_identity::save_record(&root, &record).unwrap();
        hydra_agent::device_identity::load_or_create_key(&root).unwrap();
        let diagnostics = hydra_agent::device_identity::enrollment_diagnostics_path(&root);
        let diagnostics_temporary =
            hydra_agent::device_identity::enrollment_diagnostics_temporary_path(&root);
        std::fs::write(&diagnostics, br#"{"version":1,"events":[]}"#).unwrap();
        std::fs::write(&diagnostics_temporary, b"crash-before-rename").unwrap();
        std::fs::set_permissions(&diagnostics, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(
            &diagnostics_temporary,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        let capture = |path: &std::path::Path, kind| {
            ExactFileEvidence::capture(&root, path, kind, &locks)
                .unwrap()
                .unwrap()
        };
        let record_evidence = capture(
            &root.join("device.json"),
            LifecycleFileKind::CanonicalRecord,
        );
        let authority =
            AuthorityEvidence::target_from_exact_record(&record_evidence, &locks).unwrap();
        let key_evidence = capture(
            &root.join("device-key"),
            LifecycleFileKind::CanonicalStableKey,
        );
        let temporary_evidence = capture(
            &diagnostics_temporary,
            LifecycleFileKind::EnrollmentDiagnosticsTemporary,
        );
        let diagnostics_evidence = capture(&diagnostics, LifecycleFileKind::EnrollmentDiagnostics);
        #[cfg(target_os = "macos")]
        let unit = root.join("synthetic/com.hydra.agent.plist");
        #[cfg(not(target_os = "macos"))]
        let unit = root.join("synthetic/hydra-agent.service");
        let roots = std::collections::BTreeSet::from([root.clone()]);
        let pending = CleanupTombstone::new(
            CleanupIntent::FullForget,
            PriorActivation::ProvenClosed,
            authority,
            &root,
            &roots,
            &roots,
            [],
            [
                record_evidence,
                temporary_evidence,
                diagnostics_evidence,
                key_evidence,
            ],
            DesiredUnit::from_bytes(&unit, b"synthetic desired service definition").unwrap(),
            None,
            &locks,
        )
        .unwrap();
        let stored = hydra_agent::lifecycle_cleanup::store(&root, &pending, &locks).unwrap();
        let target = stored.revocation_target().unwrap().clone();
        hydra_agent::lifecycle_cleanup::handoff_revocation(&root, &target, &locks).unwrap();
        hydra_agent::lifecycle_cleanup::record_full_forget_provider_terminal(
            &root,
            &target,
            ProviderTerminalOutcome::Revoked,
            &locks,
        )
        .unwrap();
        hydra_agent::lifecycle_cleanup::complete_revocation(
            &root,
            target.device_id(),
            locks.lock_for(&root).unwrap(),
        )
        .unwrap();

        drive_destructive_cleanup_with(
            &root,
            hydra_agent::lifecycle_cleanup::load(&root)
                .unwrap()
                .unwrap(),
            &locks,
            |dir, pending, locks| {
                assert!(diagnostics.exists());
                assert!(diagnostics_temporary.exists());
                hydra_agent::lifecycle_cleanup::execute_planned_deletion(
                    dir,
                    &pending,
                    &dir.join("device.json"),
                    locks,
                )
            },
            |_dir, _locks| {
                assert!(diagnostics.exists());
                assert!(diagnostics_temporary.exists());
                assert!(root.join("device-key").exists());
                Ok(ProviderRetryDisposition::NothingQueued)
            },
        )
        .unwrap();
        assert!(!diagnostics_temporary.exists());
        assert!(!diagnostics.exists());
        assert!(!root.join("device-key").exists());
    }

    #[cfg(unix)]
    #[test]
    fn production_pending_remove_accepts_dormant_launchd_and_uses_persisted_roots() {
        use hydra_agent::lifecycle_cleanup::{
            AuthorityEvidence, CleanupIntent, CleanupTombstone, DesiredUnit, ExactFileEvidence,
            LifecycleFileKind, ObservedUnit, PriorActivation, UnitRole,
        };
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = secure_authority_test_dir("hydra-pending-root-recovery-");
        let base = std::fs::canonicalize(fixture.path()).unwrap();
        let canonical = base.join("canonical/hydra-agent");
        let historical = base.join("historical/hydra-agent");
        for root in [&canonical, &historical] {
            std::fs::create_dir_all(root).unwrap();
            std::fs::set_permissions(
                root.parent().unwrap(),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let canonical = std::fs::canonicalize(canonical).unwrap();
        let historical = std::fs::canonicalize(historical).unwrap();
        let locks = hydra_agent::service::LifecycleLockSet::acquire([
            canonical.clone(),
            historical.clone(),
        ])
        .unwrap();
        let record = hydra_agent::device_identity::DeviceRecord {
            device_id: "dev_synthetic_historical_cleanup".into(),
            account_id: "acct_synthetic_historical_cleanup".into(),
            cloud_base: hydra_agent::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        hydra_agent::device_identity::save_record(&canonical, &record).unwrap();
        let record_evidence = ExactFileEvidence::capture(
            &canonical,
            &canonical.join("device.json"),
            LifecycleFileKind::CanonicalRecord,
            &locks,
        )
        .unwrap()
        .unwrap();
        let authority =
            AuthorityEvidence::target_from_exact_record(&record_evidence, &locks).unwrap();

        let service_dir = base.join("historical-service");
        std::fs::create_dir(&service_dir).unwrap();
        std::fs::set_permissions(&service_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        #[cfg(target_os = "macos")]
        let service_file = service_dir.join("com.hydra.agent.plist");
        #[cfg(not(target_os = "macos"))]
        let service_file = service_dir.join("hydra-agent.service");
        let service_bytes = b"synthetic historical service definition";
        std::fs::write(&service_file, service_bytes).unwrap();
        std::fs::set_permissions(&service_file, std::fs::Permissions::from_mode(0o644)).unwrap();
        let service_evidence = ExactFileEvidence::capture(
            &canonical,
            &service_file,
            LifecycleFileKind::ServiceDefinition,
            &locks,
        )
        .unwrap()
        .unwrap();

        let readiness = hydra_agent::service_readiness::service_readiness_path(&historical);
        let request = hydra_agent::service_readiness::service_readiness_request_path(&historical);
        for (path, bytes) in [
            (&readiness, b"synthetic readiness".as_slice()),
            (&request, b"synthetic request".as_slice()),
        ] {
            std::fs::write(path, bytes).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let readiness_evidence = ExactFileEvidence::capture(
            &historical,
            &readiness,
            LifecycleFileKind::ServiceReadiness,
            &locks,
        )
        .unwrap()
        .unwrap();
        let request_evidence = ExactFileEvidence::capture(
            &historical,
            &request,
            LifecycleFileKind::ServiceReadinessRequest,
            &locks,
        )
        .unwrap()
        .unwrap();
        #[cfg(target_os = "macos")]
        let desired = base.join("current-service/com.hydra.agent.plist");
        #[cfg(not(target_os = "macos"))]
        let desired = base.join("current-service/hydra-agent.service");
        let roots = std::collections::BTreeSet::from([canonical.clone(), historical.clone()]);
        let pending = CleanupTombstone::new(
            CleanupIntent::Remove,
            PriorActivation::ProvenClosed,
            authority,
            &canonical,
            &roots,
            &roots,
            [ObservedUnit::from_bytes(
                &service_file,
                service_bytes,
                [UnitRole::HistoricalInstalled],
            )
            .unwrap()],
            [
                record_evidence,
                service_evidence,
                readiness_evidence,
                request_evidence,
            ],
            DesiredUnit::from_bytes(&desired, b"synthetic desired service definition").unwrap(),
            None,
            &locks,
        )
        .unwrap();
        let stored = hydra_agent::lifecycle_cleanup::store(&canonical, &pending, &locks).unwrap();
        let target = stored.revocation_target().unwrap().clone();
        let handed =
            hydra_agent::lifecycle_cleanup::handoff_revocation(&canonical, &target, &locks)
                .unwrap();
        let record_cut = hydra_agent::lifecycle_cleanup::execute_planned_deletion(
            &canonical,
            &handed,
            &canonical.join("device.json"),
            &locks,
        )
        .unwrap();
        let dormant_launchd_observed = std::cell::Cell::new(false);

        drive_destructive_cleanup_with(
            &canonical,
            record_cut,
            &locks,
            |dir, pending, locks| {
                execute_pending_local_cleanup_with(
                    dir,
                    pending,
                    locks,
                    |_dir, _pending| {
                        let output = dormant_launchctl_job_fixture("spawn scheduled");
                        let state = parse_launchctl_job_state(output.as_bytes())?;
                        assert!(state.loaded);
                        assert_eq!(state.state.as_deref(), Some("spawn scheduled"));
                        assert_eq!(state.pid, None);
                        dormant_launchd_observed.set(true);
                        Ok(())
                    },
                    || Ok(()),
                    |_dir, _pending| Ok(()),
                )
            },
            |_dir, _locks| Ok(super::ProviderRetryDisposition::Retained),
        )
        .unwrap();

        assert!(dormant_launchd_observed.get());
        assert!(!service_file.exists());
        assert!(!readiness.exists());
        assert!(!request.exists());
        assert!(hydra_agent::lifecycle_cleanup::load(&canonical)
            .unwrap()
            .is_none());
        assert!(
            hydra_agent::lifecycle_cleanup::load_revocation_outbox(&canonical)
                .unwrap()
                .targets()
                .any(|queued| queued == &target)
        );
    }

    #[test]
    fn failed_open_aggregates_all_rollback_errors() {
        let result = finalize_extension_service_activation(
            Err(anyhow::anyhow!("readiness refused")),
            true,
            || {
                finish_extension_service_rollback(
                    vec![
                        "manager cleanup failed".to_string(),
                        "readiness cleanup failed".to_string(),
                    ],
                    Err(anyhow::anyhow!("definition probe failed")),
                    Err(anyhow::anyhow!("PID probe failed")),
                    Err(anyhow::anyhow!("peer PID probe failed")),
                    ServiceActivationPriorState::Closed,
                    || anyhow::bail!("enrollment revocation failed"),
                )
            },
        );
        let error = result.unwrap_err().to_string();
        assert!(error.contains("readiness refused"));
        assert!(error.contains("manager cleanup failed"));
        assert!(error.contains("readiness cleanup failed"));
        assert!(error.contains("definition probe failed"));
        assert!(error.contains("PID probe failed"));
        assert!(error.contains("enrollment revocation failed"));
    }

    #[test]
    fn service_forget_apply_removes_effective_authority_before_guard_failure() {
        let order = std::cell::RefCell::new(Vec::new());
        let authority_present = std::cell::Cell::new(true);
        let result = prepare_forget_before_service_guard(
            true,
            true,
            || {
                order.borrow_mut().push("remove-authority");
                authority_present.set(false);
                Ok(())
            },
            || {
                order.borrow_mut().push("guard");
                assert!(!authority_present.get());
                anyhow::bail!("legacy session guard refused")
            },
        );

        assert!(result.is_err());
        assert_eq!(*order.borrow(), ["remove-authority", "guard"]);
        assert!(!authority_present.get());
    }

    #[test]
    fn service_forget_dry_run_is_nonmutating() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-forget-dry-run-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let record = b"exact enrolled record bytes";
        let key = b"exact retained key bytes";
        std::fs::write(dir.join("device.json"), record).unwrap();
        std::fs::write(dir.join("device-key"), key).unwrap();
        let args = [
            "hydra-agent",
            "service",
            "uninstall",
            "--forget",
            "--dry-run",
        ]
        .map(str::to_string);

        run_service_cmd(&args, &dir).unwrap();

        assert_eq!(std::fs::read(dir.join("device.json")).unwrap(), record);
        assert_eq!(std::fs::read(dir.join("device-key")).unwrap(), key);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn service_apply_and_dry_run_are_mutually_exclusive_and_nonmutating() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-forget-mixed-mode-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let record = b"exact enrolled record bytes";
        let key = b"exact retained key bytes";
        std::fs::write(dir.join("device.json"), record).unwrap();
        std::fs::write(dir.join("device-key"), key).unwrap();
        let args = [
            "hydra-agent",
            "service",
            "uninstall",
            "--forget",
            "--apply",
            "--dry-run",
        ]
        .map(str::to_string);

        let error = run_service_cmd(&args, &dir).unwrap_err().to_string();

        assert!(error.contains("mutually exclusive"));
        assert_eq!(std::fs::read(dir.join("device.json")).unwrap(), record);
        assert_eq!(std::fs::read(dir.join("device-key")).unwrap(), key);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn dangling_service_definition_is_treated_as_present() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-dangling-service-link-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let link = dir.join("hydra-agent.service");
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.join("missing-target"), &link).unwrap();
        assert!(service_definition_entry_exists(&link).unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn package_upgrade_only_converges_a_service_that_was_already_running() {
        assert!(service_upgrade_needed(false, Some(41), false));
        assert!(
            service_upgrade_needed(true, Some(41), false),
            "an exact definition can still point at an old live build"
        );
        assert!(!service_upgrade_needed(true, Some(41), true));
        assert!(!service_upgrade_needed(false, None, false));
        assert!(!service_upgrade_needed(true, None, false));
    }

    #[test]
    fn remove_clears_local_authority_before_cleanup_failure() {
        let order = std::cell::RefCell::new(Vec::new());
        let result: anyhow::Result<()> = remove_local_authority_before_cleanup(
            || {
                order.borrow_mut().push("local-authority");
                Ok(())
            },
            || {
                order.borrow_mut().push("service-cleanup");
                anyhow::bail!("manager unavailable")
            },
        );
        assert!(result.is_err());
        assert_eq!(*order.borrow(), ["local-authority", "service-cleanup"]);
    }

    #[test]
    fn remove_does_not_touch_service_when_local_authority_removal_fails() {
        let cleanup_ran = std::cell::Cell::new(false);
        let result: anyhow::Result<()> = remove_local_authority_before_cleanup(
            || anyhow::bail!("local authority could not be removed"),
            || {
                cleanup_ran.set(true);
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(!cleanup_ran.get());
    }

    #[test]
    fn retired_cleanup_failure_cannot_block_effective_close_or_service_cleanup() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-remove-order-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let effective = dir.join("device.json");
        std::fs::write(&effective, b"effective authority").unwrap();
        let service_cleanup_ran = std::cell::Cell::new(false);

        let result: anyhow::Result<()> = remove_local_authority_before_cleanup(
            || {
                std::fs::remove_file(&effective)?;
                Ok(())
            },
            || {
                cleanup_retired_authority_then_service(
                    || anyhow::bail!("retired inert file is unreadable"),
                    || {
                        service_cleanup_ran.set(true);
                        Ok(())
                    },
                )
            },
        );

        assert!(
            result.is_err(),
            "incomplete retired cleanup remains visible"
        );
        assert!(!effective.exists(), "the effective gate is already closed");
        assert!(
            service_cleanup_ran.get(),
            "retired-file failure cannot prevent service cleanup"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn private_extension_negotiates_lifecycle_and_typed_viewport_capabilities() {
        use maestro_extension_api::{
            negotiate, Capability, ExtensionHello, KnownCapability, RemoteDesktopExtensionResponse,
            RemoteDesktopHostRequest, RemoteDesktopRequestId,
        };

        let host = ExtensionHello::host([
            Capability::remote_desktop_lifecycle_v1(),
            Capability::external_viewport_lease_v1(),
            Capability::filesystem_mode_migration_v1(),
            Capability::enrollment_failure_v1(),
        ])
        .unwrap();
        let negotiated = negotiate(&host, &hydra_agent::extension::extension_hello()).unwrap();
        assert!(negotiated.supports(KnownCapability::RemoteDesktopLifecycleV1));
        assert!(negotiated.supports(KnownCapability::ExternalViewportLeaseV1));
        assert!(negotiated.supports(KnownCapability::FilesystemModeMigrationV1));
        assert!(negotiated.supports(KnownCapability::EnrollmentFailureV1));

        #[cfg(unix)]
        let dir = std::path::PathBuf::from("/dev/null/hydra-viewport-must-not-lock");
        #[cfg(not(unix))]
        let dir = std::env::temp_dir().join("hydra-private-viewport-refusal");
        let response = execute_extension_request(
            RemoteDesktopHostRequest::SnapshotViewports {
                request_id: RemoteDesktopRequestId::new(77).unwrap(),
            },
            &dir,
            true,
            true,
            std::time::Instant::now() + std::time::Duration::from_secs(24),
        );
        assert!(matches!(
            response,
            RemoteDesktopExtensionResponse::Error { error, .. }
                if error.code() == maestro_extension_api::RemoteDesktopErrorCode::ViewportUnavailable
        ));
        assert!(
            !dir.exists(),
            "viewport request must precede lifecycle lock and enrollment migration"
        );
    }

    #[test]
    fn predecessor_host_receives_only_legacy_enrollment_failures() {
        use hydra_agent::device_identity::EnrollmentFailureKind as Kind;
        use maestro_extension_api::RemoteDesktopErrorCode as Code;

        for kind in [Kind::CodeInvalid, Kind::AuthorityStale] {
            let failure = enrollment_lifecycle_failure(kind, false);
            assert_eq!(failure.code, Code::EnrollmentRejected);
            assert!(!failure.retryable);
        }
        assert_eq!(
            enrollment_lifecycle_failure(Kind::TemporarilyUnavailable, false).code,
            Code::Busy
        );
        assert_eq!(
            enrollment_lifecycle_failure(Kind::Incompatible, false).code,
            Code::InvalidRequest
        );
        for kind in [
            Kind::OwnerMismatch,
            Kind::LocalFailure,
            Kind::OutcomeUnconfirmed,
        ] {
            assert_eq!(
                enrollment_lifecycle_failure(kind, false).code,
                Code::Internal
            );
        }
        assert_eq!(
            enrollment_lifecycle_failure(Kind::OutcomeUnconfirmed, true).code,
            Code::EnrollmentOutcomeUnconfirmed
        );
        let owner_mismatch = enrollment_lifecycle_failure(Kind::OwnerMismatch, true);
        assert_eq!(owner_mismatch.code, Code::EnrollmentOwnerMismatch);
        assert_eq!(
            owner_mismatch.message,
            "the enrollment service refused this account binding"
        );
    }

    #[test]
    fn activation_cleanup_diagnostic_distinguishes_proven_closed_from_incomplete() {
        use hydra_agent::device_identity::EnrollmentActivationOutcome as Outcome;
        use maestro_extension_api::RemoteDesktopErrorCode as Code;

        let (failure, outcome) = failed_activation_cleanup_result(Ok(()));
        assert_eq!(failure.code, Code::RemoteUnavailable);
        assert!(failure.retryable);
        assert_eq!(outcome, Outcome::FailedClosed);

        let (failure, outcome) =
            failed_activation_cleanup_result(Err(anyhow::anyhow!("injected cleanup failure")));
        assert_eq!(failure.code, Code::Internal);
        assert!(!failure.retryable);
        assert_eq!(outcome, Outcome::CleanupIncomplete);
    }

    #[test]
    fn extension_ack_boundary_commits_before_lifecycle_and_leaves_status_retryable() {
        let fixture = tempfile::tempdir().unwrap();
        let receipt = fixture.path().join("migration-receipt");
        let current_service = fixture.path().join("current-service");
        std::fs::write(&receipt, b"applied receipt").unwrap();
        let events = std::cell::RefCell::new(Vec::new());

        let first: std::io::Result<Result<(), std::io::Error>> =
            commit_filesystem_ack_before_lifecycle(
                || {
                    events.borrow_mut().push("commit");
                    std::fs::remove_file(&receipt)
                },
                || {
                    events.borrow_mut().push("lifecycle");
                    assert!(!receipt.exists());
                    Err(std::io::Error::other(
                        "synthetic crash before service convergence",
                    ))
                },
            );
        assert!(first.unwrap().is_err());
        assert_eq!(*events.borrow(), ["commit", "lifecycle"]);
        assert!(!receipt.exists());

        // The next ordinary Status runs the same production convergence path with no
        // acknowledgement latch to replay.
        let record = hydra_agent::device_identity::DeviceRecord {
            device_id: "desktop-status-retry".to_string(),
            account_id: "account-status-retry".to_string(),
            cloud_base: hydra_agent::release_trust::active().cloud_base.to_string(),
            passkey: None,
        };
        let status = lifecycle_status_with_convergence(
            Some(record),
            ServiceActivationPriorState::ProvenOpen,
            || {
                converge_service_upgrade_if_needed(false, Some(4242), false, || {
                    events.borrow_mut().push("status-service-convergence");
                    std::fs::write(&current_service, b"current exact service")?;
                    Ok(())
                })
            },
        )
        .unwrap();
        assert!(status.remote_open());
        assert_eq!(
            std::fs::read(&current_service).unwrap(),
            b"current exact service"
        );
        assert_eq!(
            *events.borrow(),
            ["commit", "lifecycle", "status-service-convergence"]
        );

        std::fs::write(&receipt, b"applied receipt").unwrap();
        let lifecycle_ran = std::cell::Cell::new(false);
        let failed_commit: std::io::Result<()> = commit_filesystem_ack_before_lifecycle(
            || Err(std::io::Error::other("synthetic commit failure")),
            || lifecycle_ran.set(true),
        );
        assert!(failed_commit.is_err());
        assert!(!lifecycle_ran.get());
        assert!(receipt.exists());
    }

    #[cfg(unix)]
    #[test]
    fn legacy_shape_status_returns_notice_before_strict_lifecycle_lock_and_old_host_gets_only_error(
    ) {
        use maestro_extension_api::{
            FilesystemMode, FilesystemModeChange, FilesystemModeMigrationNotice,
            FilesystemModeMigrationNoticeId, FilesystemModeMigrationPhase,
            RemoteDesktopExtensionResponse, RemoteDesktopRequestId,
        };
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = secure_authority_test_dir("hydra-absent-canonical-preflight-");
        let home = std::fs::canonicalize(fixture.path()).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        let local = home.join(".local");
        let share = local.join("share");
        let leaf = share.join("hydra-agent");
        std::fs::create_dir_all(&leaf).unwrap();
        for path in [&local, &share, &leaf] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o775)).unwrap();
        }
        assert!(
            hydra_agent::agent_dir::ensure_owned_safe_authority_directory(&leaf).is_err(),
            "ordinary lifecycle validation must reject the legacy leaf"
        );
        let notice = FilesystemModeMigrationNotice::new(
            FilesystemModeMigrationNoticeId::new("a".repeat(64)).unwrap(),
            FilesystemModeMigrationPhase::ReadyToApply,
            [
                FilesystemModeChange::new(
                    local.to_str().unwrap(),
                    FilesystemMode::LegacyPublicGroupWritable,
                    FilesystemMode::PublicRead,
                )
                .unwrap(),
                FilesystemModeChange::new(
                    share.to_str().unwrap(),
                    FilesystemMode::LegacyPublicGroupWritable,
                    FilesystemMode::PublicRead,
                )
                .unwrap(),
                FilesystemModeChange::new(
                    leaf.to_str().unwrap(),
                    FilesystemMode::LegacyPublicGroupWritable,
                    FilesystemMode::OwnerOnly,
                )
                .unwrap(),
            ],
            None,
        )
        .unwrap();
        let request_id = RemoteDesktopRequestId::new(301).unwrap();

        let response = migration_probe_response(request_id, true, Ok(Some(notice.clone())))
            .expect("pending migration short-circuits lifecycle preflight");
        assert!(matches!(
            response,
            RemoteDesktopExtensionResponse::FilesystemModeMigration {
                notice: returned,
                status: None,
                ..
            } if returned == notice
        ));
        for path in [&local, &share, &leaf] {
            assert_eq!(
                std::fs::symlink_metadata(path)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o775,
                "Status must not repair the legacy shape"
            );
        }

        let old_host = migration_probe_response(request_id, false, Ok(Some(notice))).unwrap();
        assert!(matches!(
            old_host,
            RemoteDesktopExtensionResponse::Error { .. }
        ));
        let encoded = serde_json::to_string(&old_host).unwrap();
        assert!(!encoded.contains("filesystem_mode_migration"));
        assert!(!encoded.contains(".local/share/hydra-agent"));
    }

    #[cfg(unix)]
    #[test]
    fn status_and_enroll_route_absent_root_through_safe_canonical_preflight() {
        use maestro_extension_api::{
            EnrollmentCode, RemoteDesktopHostRequest, RemoteDesktopRequestId,
        };
        use std::os::unix::fs::{symlink, MetadataExt as _, PermissionsExt as _};

        const CHILD: &str = "HYDRA_TEST_ABSENT_CANONICAL_ROOT_UMASK_0002";
        const SENTINEL: &str = "HYDRA_TEST_ABSENT_CANONICAL_ROOT_SENTINEL";
        if std::env::var_os(CHILD).is_none() {
            let parent_fixture = secure_authority_test_dir("hydra-absent-child-handshake-");
            let sentinel = parent_fixture.path().join("child-ran.txt");
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "cli_contract_tests::status_and_enroll_route_absent_root_through_safe_canonical_preflight",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .env(SENTINEL, &sentinel)
                .status()
                .expect("spawn isolated umask proof");
            assert!(status.success(), "isolated umask proof failed: {status}");
            assert_eq!(
                std::fs::read(sentinel).unwrap(),
                b"absent-root-production-preflight-ran\n"
            );
            return;
        }

        // Process-global umask changes are safe only in this isolated child.
        unsafe { libc::umask(0o002) };
        let fixture = secure_authority_test_dir("hydra-absent-canonical-preflight-");
        let fixture_root = std::fs::canonicalize(fixture.path()).unwrap();
        let requests = [
            RemoteDesktopHostRequest::Status {
                request_id: RemoteDesktopRequestId::new(901).unwrap(),
            },
            RemoteDesktopHostRequest::Enroll {
                request_id: RemoteDesktopRequestId::new(902).unwrap(),
                code: EnrollmentCode::new("A2B3C4D5").unwrap(),
            },
        ];

        for (index, request) in requests.iter().enumerate() {
            assert!(
                extension_request_uses_lifecycle_preflight(request),
                "Status and Enroll must route through the production preflight"
            );
            let profile = fixture_root.join(format!("profile-{index}"));
            std::fs::create_dir(&profile).unwrap();
            std::fs::set_permissions(&profile, std::fs::Permissions::from_mode(0o700)).unwrap();
            let root = profile.join("hydra-agent");
            assert!(!root.exists(), "the canonical root must begin absent");
            let canonical = establish_extension_canonical_root(&root).unwrap();
            assert_eq!(canonical, std::fs::canonicalize(&root).unwrap());
            let metadata = std::fs::symlink_metadata(&root).unwrap();
            assert!(metadata.file_type().is_dir());
            assert_eq!(metadata.uid(), hydra_agent::agent_dir::trusted_uid());
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);

            let candidates =
                hydra_agent::enrollment_migration::adoption_lock_roots(&root, None).unwrap();
            assert_eq!(
                candidates,
                std::collections::BTreeSet::from([canonical.clone()]),
                "a fresh profile has only its canonical lifecycle root"
            );
            let locks = hydra_agent::service::LifecycleLockSet::acquire(candidates).unwrap();
            assert_eq!(
                locks
                    .roots()
                    .map(std::path::Path::to_path_buf)
                    .collect::<Vec<_>>(),
                vec![canonical]
            );
            let lock_metadata = std::fs::symlink_metadata(root.join("lifecycle.lock")).unwrap();
            assert_eq!(lock_metadata.permissions().mode() & 0o777, 0o600);
            assert_eq!(lock_metadata.uid(), hydra_agent::agent_dir::trusted_uid());
        }

        for legacy_mode in [0o770, 0o775] {
            let legacy_root = fixture_root.join(format!("legacy-{legacy_mode:o}/hydra-agent"));
            std::fs::create_dir_all(&legacy_root).unwrap();
            std::fs::set_permissions(
                legacy_root.parent().unwrap(),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            std::fs::set_permissions(&legacy_root, std::fs::Permissions::from_mode(legacy_mode))
                .unwrap();
            let legacy_key = legacy_root.join("device-key");
            std::fs::write(&legacy_key, b"synthetic-owner-only-key").unwrap();
            std::fs::set_permissions(&legacy_key, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(
                establish_extension_canonical_root(&legacy_root).is_err(),
                "an arbitrary historical root cannot authorize permission migration"
            );
            assert_eq!(
                std::fs::symlink_metadata(&legacy_root)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                legacy_mode,
                "lifecycle preflight must not chmod an unreceipted historical root"
            );
            assert_eq!(
                std::fs::symlink_metadata(legacy_key)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }

        let unsafe_root = fixture_root.join("unsafe/hydra-agent");
        std::fs::create_dir_all(&unsafe_root).unwrap();
        std::fs::set_permissions(
            unsafe_root.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(&unsafe_root, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(establish_extension_canonical_root(&unsafe_root).is_err());
        assert!(!unsafe_root.join("lifecycle.lock").exists());

        let target = fixture_root.join("safe-target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
        let symlink_root = fixture_root.join("symlink-root");
        symlink(&target, &symlink_root).unwrap();
        assert!(establish_extension_canonical_root(&symlink_root).is_err());
        assert!(!target.join("lifecycle.lock").exists());

        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let sentinel = std::path::PathBuf::from(std::env::var_os(SENTINEL).unwrap());
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(sentinel)
            .unwrap();
        file.write_all(b"absent-root-production-preflight-ran\n")
            .unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn browser_setup_service_commands_match_cli_contract() {
        assert_eq!(
            service_commands(),
            [
                "hydra-agent service install --dry-run --binary-path /usr/local/bin/hydra-agent",
                "hydra-agent service install --apply --binary-path /usr/local/bin/hydra-agent",
                "hydra-agent service status",
                "hydra-agent service uninstall",
            ]
        );
    }

    #[test]
    fn browser_setup_contract_keeps_preview_before_apply_and_no_secrets() {
        let commands = service_commands();
        let preview = commands
            .iter()
            .position(|c| c.contains("--dry-run"))
            .expect("preview command");
        let apply = commands
            .iter()
            .position(|c| c.contains("--apply"))
            .expect("apply command");
        assert!(preview < apply);

        let all = std::iter::once(extension_command())
            .chain(commands)
            .collect::<Vec<_>>()
            .join("\n")
            .to_lowercase();
        for bad in [
            "token",
            "secret",
            "signature",
            "private",
            "cookie",
            "password",
            "bearer",
        ] {
            assert!(
                !all.contains(bad),
                "CLI contract copy must not contain {bad:?}"
            );
        }
    }

    #[test]
    fn service_usage_mentions_apply_and_current_binary_path_flag() {
        assert!(SERVICE_USAGE.contains("[--dry-run|--apply]"));
        assert!(SERVICE_USAGE.contains("--binary-path <path>"));
        assert!(SERVICE_USAGE.contains("--app-support-dir <absolute-path>"));
        assert!(!SERVICE_USAGE.contains("--binary <path>"));
    }

    #[test]
    fn service_app_support_override_is_exact_and_absolute() {
        let args = vec![
            "hydra-agent".to_string(),
            "service".to_string(),
            "install".to_string(),
            "--app-support-dir".to_string(),
            "/tmp/Hydra QA/base".to_string(),
        ];
        assert_eq!(
            service_app_support_dir(&args, std::path::Path::new("/home/test")).unwrap(),
            std::path::PathBuf::from("/tmp/Hydra QA/base")
        );
    }

    #[test]
    fn service_app_support_override_rejects_relative_paths() {
        let args = vec![
            "hydra-agent".to_string(),
            "service".to_string(),
            "install".to_string(),
            "--app-support-dir".to_string(),
            "relative/base".to_string(),
        ];
        assert!(service_app_support_dir(&args, std::path::Path::new("/home/test")).is_err());
    }

    #[test]
    fn same_path_published_endpoint_is_still_attach_mode() {
        let socket = std::path::PathBuf::from("/run/user/1/hydra.sock");
        let resolved = daemon_socket_resolution(socket.clone(), Some(socket.clone()));
        assert_eq!(resolved.path, socket);
        assert!(resolved.from_published_endpoint);
    }

    #[test]
    fn fallback_socket_is_owned_only_when_no_endpoint_was_published() {
        let socket = std::path::PathBuf::from("/run/user/1/hydra.sock");
        let resolved = daemon_socket_resolution(socket.clone(), None);
        assert_eq!(resolved.path, socket);
        assert!(!resolved.from_published_endpoint);
    }

    #[test]
    fn installed_attach_only_service_never_owns_the_pty_daemon() {
        assert!(!supervisor_owns_daemon(true, false));
        assert!(!supervisor_owns_daemon(true, true));
        assert!(supervisor_owns_daemon(false, false));
        assert!(!supervisor_owns_daemon(false, true));
    }

    #[test]
    fn launchctl_readiness_requires_running_state_and_numeric_pid() {
        assert_eq!(
            launchctl_running_pid("gui/501/com.hydra.agent = {\n\tstate = running\n\tpid = 123\n}"),
            Some(123)
        );
        assert_eq!(
            launchctl_running_pid("gui/501/com.hydra.agent = {\n\tstate = waiting\n\tpid = 123\n}"),
            None
        );
        assert_eq!(
            launchctl_running_pid(
                "gui/501/com.hydra.agent = {\n\tstate = running\n\tlast exit code = 1\n}"
            ),
            None
        );
        assert_eq!(
            launchctl_running_pid(
                "gui/501/com.hydra.agent = {\n\tstate = running\n\tpid = not-a-pid\n}"
            ),
            None
        );
    }

    #[test]
    fn launchctl_job_state_accepts_reviewed_top_level_states_and_ignores_nested_fields() {
        for expected in ["not running", "spawn scheduled", "spawning", "waiting"] {
            let output = dormant_launchctl_job_fixture(expected);
            let state = parse_launchctl_job_state(output.as_bytes()).unwrap();
            assert!(state.loaded);
            assert_eq!(state.state.as_deref(), Some(expected));
            assert_eq!(state.pid, None);
            assert_eq!(
                state.definition_path.as_deref(),
                Some(std::path::Path::new(
                    "/Users/test/Library/LaunchAgents/com.hydra.agent.plist"
                ))
            );
        }
    }

    #[test]
    fn launchctl_spawning_transition_is_loaded_without_a_manager_pid() {
        let output = dormant_launchctl_job_fixture("spawning");
        let state = parse_launchctl_job_state(output.as_bytes()).unwrap();
        assert!(state.loaded);
        assert_eq!(state.state.as_deref(), Some("spawning"));
        assert_eq!(state.pid, None);
        assert_eq!(launchctl_running_pid(&output), None);
    }

    #[test]
    fn launchctl_xpcproxy_transition_preserves_but_never_qualifies_its_pid() {
        let output = "gui/501/com.hydra.agent = {\n\tstate = xpcproxy\n\tpid = 123\n}";
        let state = parse_launchctl_job_state(output.as_bytes()).unwrap();

        assert!(state.loaded);
        assert_eq!(state.state.as_deref(), Some("xpcproxy"));
        assert_eq!(state.pid, Some(123));
        assert_eq!(state.qualified_running_pid(), None);
        assert!(state.exact_running_or_absent().is_err());
        assert_eq!(launchctl_running_pid(output), None);
    }

    #[test]
    fn launchctl_readiness_tracks_one_exact_xpcproxy_to_running_pid() {
        let mut tracker = LaunchdReadinessTracker::default();
        for transition in ["spawn scheduled", "spawning"] {
            let state =
                parse_launchctl_job_state(dormant_launchctl_job_fixture(transition).as_bytes())
                    .unwrap();
            assert_eq!(tracker.observe(&state).unwrap(), None);
        }
        let proxy = parse_launchctl_job_state(
            b"gui/501/com.hydra.agent = {\n\tstate = xpcproxy\n\tpid = 123\n}",
        )
        .unwrap();
        assert_eq!(tracker.observe(&proxy).unwrap(), None);

        // A loaded no-PID observation cannot erase the proxy continuity pin.
        let waiting =
            parse_launchctl_job_state(dormant_launchctl_job_fixture("waiting").as_bytes()).unwrap();
        assert_eq!(tracker.observe(&waiting).unwrap(), None);

        let running = parse_launchctl_job_state(
            b"gui/501/com.hydra.agent = {\n\tstate = running\n\tpid = 123\n}",
        )
        .unwrap();
        assert_eq!(tracker.observe(&running).unwrap(), Some(123));
    }

    #[test]
    fn launchctl_readiness_accepts_direct_running_without_a_proxy_observation() {
        let mut tracker = LaunchdReadinessTracker::default();
        let running = parse_launchctl_job_state(
            b"gui/501/com.hydra.agent = {\n\tstate = running\n\tpid = 123\n}",
        )
        .unwrap();

        assert_eq!(tracker.observe(&running).unwrap(), Some(123));
    }

    #[test]
    fn launchctl_direct_manager_generation_loss_poison_is_persistent() {
        let running = parse_launchctl_job_state(
            b"gui/501/com.hydra.agent = {\n\tstate = running\n\tpid = 123\n}",
        )
        .unwrap();
        let replacement = parse_launchctl_job_state(
            b"gui/501/com.hydra.agent = {\n\tstate = running\n\tpid = 124\n}",
        )
        .unwrap();
        let waiting =
            parse_launchctl_job_state(dormant_launchctl_job_fixture("waiting").as_bytes()).unwrap();
        let absent = LaunchdJobState {
            loaded: false,
            state: None,
            pid: None,
            definition_path: None,
        };

        let mut changed = LaunchdReadinessTracker::default();
        assert_eq!(changed.observe(&running).unwrap(), Some(123));
        assert!(changed.observe(&replacement).is_err());
        assert!(changed.observe(&running).is_err());

        let mut dormant = LaunchdReadinessTracker::default();
        assert_eq!(dormant.observe(&running).unwrap(), Some(123));
        assert!(dormant.observe(&waiting).is_err());
        assert!(dormant.observe(&running).is_err());

        let mut unloaded = LaunchdReadinessTracker::default();
        assert_eq!(unloaded.observe(&running).unwrap(), Some(123));
        assert!(unloaded.observe(&absent).is_err());
        assert!(unloaded.observe(&running).is_err());
    }

    #[test]
    fn launchctl_readiness_fails_closed_on_proxy_or_manager_pid_change() {
        let proxy = parse_launchctl_job_state(
            b"gui/501/com.hydra.agent = {\n\tstate = xpcproxy\n\tpid = 123\n}",
        )
        .unwrap();
        let replacement_proxy = parse_launchctl_job_state(
            b"gui/501/com.hydra.agent = {\n\tstate = xpcproxy\n\tpid = 124\n}",
        )
        .unwrap();
        let replacement_running = parse_launchctl_job_state(
            b"gui/501/com.hydra.agent = {\n\tstate = running\n\tpid = 124\n}",
        )
        .unwrap();

        let mut proxy_change = LaunchdReadinessTracker::default();
        assert_eq!(proxy_change.observe(&proxy).unwrap(), None);
        assert!(proxy_change.observe(&replacement_proxy).is_err());
        assert!(proxy_change.observe(&proxy).is_err());

        let mut manager_change = LaunchdReadinessTracker::default();
        assert_eq!(manager_change.observe(&proxy).unwrap(), None);
        let intermediate =
            parse_launchctl_job_state(dormant_launchctl_job_fixture("spawning").as_bytes())
                .unwrap();
        assert_eq!(manager_change.observe(&intermediate).unwrap(), None);
        assert!(manager_change.observe(&replacement_running).is_err());
        assert!(manager_change.observe(&proxy).is_err());
    }

    #[test]
    fn launchctl_readiness_fails_closed_when_proxy_generation_unloads() {
        let absent = LaunchdJobState {
            loaded: false,
            state: None,
            pid: None,
            definition_path: None,
        };
        let proxy = parse_launchctl_job_state(
            b"gui/501/com.hydra.agent = {\n\tstate = xpcproxy\n\tpid = 123\n}",
        )
        .unwrap();
        let running = parse_launchctl_job_state(
            b"gui/501/com.hydra.agent = {\n\tstate = running\n\tpid = 123\n}",
        )
        .unwrap();

        let mut tracker = LaunchdReadinessTracker::default();
        assert_eq!(tracker.observe(&absent).unwrap(), None);
        assert_eq!(tracker.observe(&proxy).unwrap(), None);
        assert!(tracker.observe(&absent).is_err());
        assert!(tracker.observe(&running).is_err());
    }

    #[test]
    fn launchctl_readiness_never_qualifies_transitions_within_a_fixed_poll_budget() {
        let mut tracker = LaunchdReadinessTracker::default();
        let proxy = parse_launchctl_job_state(
            b"gui/501/com.hydra.agent = {\n\tstate = xpcproxy\n\tpid = 123\n}",
        )
        .unwrap();
        let spawning =
            parse_launchctl_job_state(dormant_launchctl_job_fixture("spawning").as_bytes())
                .unwrap();

        // Mirrors a bounded readiness deadline: exhausting the caller's fixed
        // poll budget never turns a loaded transition into a manager.
        for state in [&proxy, &spawning, &spawning, &spawning] {
            assert_eq!(tracker.observe(state).unwrap(), None);
        }
        assert_eq!(tracker.xpcproxy_pid, Some(123));
        assert!(!tracker.poisoned);
    }

    #[test]
    fn launchctl_cleanup_classification_refuses_every_loaded_non_running_state() {
        let absent = LaunchdJobState {
            loaded: false,
            state: None,
            pid: None,
            definition_path: None,
        };
        assert_eq!(absent.exact_running_or_absent().unwrap(), None);

        let running = parse_launchctl_job_state(
            b"gui/501/com.hydra.agent = {\n\tstate = running\n\tpid = 123\n}",
        )
        .unwrap();
        assert_eq!(running.exact_running_or_absent().unwrap(), Some(123));

        for transition in ["not running", "spawn scheduled", "spawning", "waiting"] {
            let state =
                parse_launchctl_job_state(dormant_launchctl_job_fixture(transition).as_bytes())
                    .unwrap();
            assert!(
                state.exact_running_or_absent().is_err(),
                "loaded {transition:?} must not prove manager absence"
            );
        }
        let proxy = parse_launchctl_job_state(
            b"gui/501/com.hydra.agent = {\n\tstate = xpcproxy\n\tpid = 123\n}",
        )
        .unwrap();
        assert!(proxy.exact_running_or_absent().is_err());
    }

    #[test]
    fn launchctl_job_state_rejects_noncanonical_ambiguous_or_pid_mismatched_states() {
        for output in [
            "gui/501/com.hydra.agent = {\n\tstate = waiting\n\tpid = 123\n}",
            "gui/501/com.hydra.agent = {\n\tstate = running\n}",
            "gui/501/com.hydra.agent = {\n\tstate = not running\n\tpid = 123\n}",
            "gui/501/com.hydra.agent = {\n\tstate = spawn scheduled\n\tpid = 123\n}",
            "gui/501/com.hydra.agent = {\n\tstate = spawning\n\tpid = 123\n}",
            "gui/501/com.hydra.agent = {\n\tstate = xpcproxy\n}",
            "gui/501/com.hydra.agent = {\n\tstate = xpcproxy\n\tpid = 0\n}",
            "gui/501/com.hydra.agent = {\n\tstate = xpcproxy\n\tpid = 123\n\tpid = 124\n}",
            "gui/501/com.hydra.agent = {\n\tstate = running pending\n}",
            "gui/501/com.hydra.agent = {\n\tstate = unknown active\n}",
            "gui/501/com.hydra.agent = {\n\tstate = active\n}",
            "gui/501/com.hydra.agent = {\n\tstate = exited\n}",
            "gui/501/com.hydra.agent = {\n\tstate = not\trunning\n}",
            "gui/501/com.hydra.agent = {\n\tstate = spawn  scheduled\n}",
            "gui/501/com.hydra.agent = {\n\tstate = Not running\n}",
            "gui/501/com.hydra.agent = {\n\tstate = not running \n}",
            "gui/501/com.hydra.agent = {\n\tstate = not running\0\n}",
            "gui/501/com.hydra.agent = {\n\tstate = not running\n\tstate = not running\n}",
            "gui/501/com.hydra.agent = {\n\tstate = running\n\tpid = 123\n\tpid = 124\n}",
            "gui/501/com.hydra.agent = {\n\tstate = running\n\tpid = 0\n}",
            "gui/501/com.hydra.agent = {\n\tstate = running\n\tpid = not-a-pid\n}",
            "gui/501/com.hydra.agent = {\n\tpid = 123\n}",
            "gui/501/com.hydra.agent = {\n\tpath = relative/com.hydra.agent.plist\n\tstate = not running\n}",
            "gui/501/com.hydra.agent = {\n\tpath = /Users/test/../foreign/com.hydra.agent.plist\n\tstate = not running\n}",
            "gui/501/com.hydra.agent = {\n\tpath = /one/com.hydra.agent.plist\n\tpath = /two/com.hydra.agent.plist\n\tstate = not running\n}",
            "gui/501/com.hydra.agent = {\n\tresource coalition = {\n\t\tstate = running\n\t\tpid = 123\n\t}\n}",
        ] {
            assert!(
                parse_launchctl_job_state(output.as_bytes()).is_err(),
                "unexpectedly accepted {output:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_preflight_reports_only_exact_lock_contention_as_busy() {
        use maestro_extension_api::{
            RemoteDesktopErrorCode, RemoteDesktopExtensionResponse, RemoteDesktopRequestId,
        };

        let fixture = secure_authority_test_dir("hydra-lifecycle-error-classifier-");
        let root = fixture.path().join("hydra-agent");
        let held = hydra_agent::service::LifecycleLock::acquire(&root).unwrap();
        let contention = hydra_agent::service::LifecycleLock::acquire(&root)
            .err()
            .expect("held lifecycle lock must report contention");
        assert!(hydra_agent::service::is_lifecycle_lock_contention(
            &contention
        ));

        let parser_failure = parse_launchctl_job_state(
            b"gui/501/com.hydra.agent = {\n\tstate = spawn  scheduled\n}",
        )
        .unwrap_err();
        let unrelated_would_block = std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "synthetic metadata would block",
        );
        let cases = [
            (
                lifecycle_preflight_error_response(
                    RemoteDesktopRequestId::new(931).unwrap(),
                    &anyhow::Error::new(contention),
                ),
                RemoteDesktopErrorCode::Busy,
                true,
            ),
            (
                lifecycle_preflight_error_response(
                    RemoteDesktopRequestId::new(932).unwrap(),
                    &parser_failure,
                ),
                RemoteDesktopErrorCode::Internal,
                false,
            ),
            (
                lifecycle_preflight_error_response(
                    RemoteDesktopRequestId::new(933).unwrap(),
                    &anyhow::Error::new(unrelated_would_block),
                ),
                RemoteDesktopErrorCode::Internal,
                false,
            ),
        ];

        for (response, expected_code, expected_retryable) in cases {
            let RemoteDesktopExtensionResponse::Error { error, .. } = response else {
                panic!("lifecycle preflight failure returned a non-error response");
            };
            assert_eq!(error.code(), expected_code);
            assert_eq!(error.retryable(), expected_retryable);
            assert!(!error.message().contains("launchctl"));
            assert!(!error.message().contains("synthetic"));
        }
        drop(held);
    }

    #[test]
    fn supervisor_ownership_and_socket_are_parsed_structurally() {
        let invocation = parse_supervisor_invocation(&parse_nul_arguments(
            b"/opt/hydra/hydra-agent\0supervise\0--attach-daemon-only\0--dir\0/legacy/data/hydra-agent\0--sock\0/old/h.sock\0--sessions\0s1\0",
        ))
        .unwrap();
        assert!(invocation.attach_daemon_only);
        assert_eq!(
            invocation.agent_dir.as_deref(),
            Some(std::path::Path::new("/legacy/data/hydra-agent"))
        );
        assert_eq!(invocation.socket_path, std::path::Path::new("/old/h.sock"));

        let fixed = parse_supervisor_invocation(&parse_nul_arguments(
            b"/opt/hydra/hydra-agent\0supervise\0--attach-daemon-only\0--fixed-daemon-only\0--sock\0/tmp/hydra.sock\0",
        ))
        .unwrap();
        assert!(fixed.attach_daemon_only);
        assert!(fixed.fixed_external_daemon);
        assert_eq!(fixed.socket_path, std::path::Path::new("/tmp/hydra.sock"));
        assert!(parse_supervisor_invocation(&parse_nul_arguments(
            b"/opt/hydra/hydra-agent\0supervise\0--fixed-daemon-only\0--sock\0/tmp/hydra.sock\0",
        ))
        .is_err());

        let value_not_flag = parse_supervisor_invocation(&parse_nul_arguments(
            b"/opt/hydra/hydra-agent\0supervise\0--sessions\0--attach-daemon-only\0--sock\0/owned/h.sock\0",
        ))
        .unwrap();
        assert!(!value_not_flag.attach_daemon_only);
        assert_eq!(value_not_flag.agent_dir, None);
        assert_eq!(
            value_not_flag.socket_path,
            std::path::Path::new("/owned/h.sock")
        );

        assert!(parse_supervisor_invocation(&parse_nul_arguments(
            b"/opt/hydra/hydra-agent\0supervise\0--attach-daemon-only-ish\0--sock\0/x\0"
        ))
        .is_err());
        assert!(parse_supervisor_invocation(&parse_nul_arguments(
            b"/opt/hydra/hydra-agent\0supervise\0--attach-daemon-only\0"
        ))
        .is_err());
        assert!(parse_supervisor_invocation(&parse_nul_arguments(
            b"/opt/hydra/hydra-agent\0supervise\0--dir\0/a/hydra-agent\0--dir\0/b/hydra-agent\0--sock\0/x\0"
        ))
        .is_err());
    }

    #[test]
    fn installed_systemd_definition_yields_exact_legacy_dir_without_ambient_xdg() {
        let definition = br#"[Service]
ExecStart="/opt/Hydra Agent/hydra-agent" "supervise" "--attach-daemon-only" "--dir" "/legacy data/hydra-agent" "--sock" "/run/user/1000/hydra%%socket.sock"
"#;
        let arguments = parse_generated_systemd_exec_start(definition).unwrap();
        let invocation = parse_supervisor_invocation(&arguments).unwrap();
        assert_eq!(
            invocation.agent_dir.as_deref(),
            Some(std::path::Path::new("/legacy data/hydra-agent"))
        );
        assert_eq!(
            invocation.socket_path,
            std::path::Path::new("/run/user/1000/hydra%socket.sock")
        );
    }

    #[cfg(unix)]
    #[test]
    fn stopped_manager_legacy_units_are_refused_without_permission_mutation() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let fixture = secure_authority_test_dir("hydra-observe-only-service-");
        let home = fixture.path().join("home");
        let config = home.join(".config");
        let systemd = config.join("systemd");
        let unit_dir = systemd.join("user");
        let legacy = home.join("legacy/hydra-agent");
        std::fs::create_dir(&home).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();

        for (directory_mode, unit_mode) in [(0o770, 0o660), (0o775, 0o664)] {
            std::fs::create_dir_all(&unit_dir).unwrap();
            for directory in [&config, &systemd, &unit_dir] {
                std::fs::set_permissions(
                    directory,
                    std::fs::Permissions::from_mode(directory_mode),
                )
                .unwrap();
            }
            let unit = unit_dir.join("hydra-agent.service");
            let definition = published_028_systemd_definition(&legacy);
            std::fs::write(&unit, definition.as_bytes()).unwrap();
            std::fs::set_permissions(&unit, std::fs::Permissions::from_mode(unit_mode)).unwrap();
            let unit_before = std::fs::symlink_metadata(&unit).unwrap();
            let ancestry_before = [&config, &systemd, &unit_dir]
                .map(|directory| std::fs::symlink_metadata(directory).unwrap());

            assert!(
                read_owned_service_definition_for_home(&unit, &home).is_err(),
                "group-writable historical units must fail closed"
            );
            assert!(
                installed_systemd_supervisor_invocation_for_home(&unit, &home).is_err(),
                "unsafe metadata cannot establish installed provenance"
            );
            let after = std::fs::symlink_metadata(&unit).unwrap();
            assert_eq!(after.dev(), unit_before.dev());
            assert_eq!(after.ino(), unit_before.ino());
            assert_eq!(
                after.permissions().mode() & 0o777,
                unit_mode,
                "validation must not chmod the historical unit"
            );
            assert_eq!(std::fs::read(&unit).unwrap(), definition.as_bytes());
            for (directory, before) in [&config, &systemd, &unit_dir]
                .into_iter()
                .zip(ancestry_before.iter())
            {
                let metadata = std::fs::symlink_metadata(directory).unwrap();
                assert_eq!(metadata.dev(), before.dev());
                assert_eq!(metadata.ino(), before.ino());
                assert_eq!(
                    metadata.permissions().mode() & 0o777,
                    directory_mode,
                    "validation must not chmod shared systemd ancestry"
                );
            }
            std::fs::remove_file(unit).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn malformed_legacy_mode_unit_is_refused_and_left_byte_exact() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let fixture = secure_authority_test_dir("hydra-malformed-service-");
        let home = fixture.path().join("home");
        let unit_dir = home.join(".config/systemd/user");
        std::fs::create_dir(&home).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir_all(&unit_dir).unwrap();
        for directory in [
            home.join(".config"),
            home.join(".config/systemd"),
            unit_dir.clone(),
        ] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let unit = unit_dir.join("hydra-agent.service");
        let malformed = b"[Service]\nExecStart=/bin/sh -c 'untrusted'\n";
        std::fs::write(&unit, malformed).unwrap();
        std::fs::set_permissions(&unit, std::fs::Permissions::from_mode(0o664)).unwrap();
        let before = std::fs::symlink_metadata(&unit).unwrap();

        assert!(installed_systemd_supervisor_invocation_for_home(&unit, &home).is_err());
        assert_eq!(std::fs::read(&unit).unwrap(), malformed);
        let after = std::fs::symlink_metadata(unit).unwrap();
        assert_eq!(after.dev(), before.dev());
        assert_eq!(after.ino(), before.ino());
        assert_eq!(after.permissions().mode() & 0o777, 0o664);
    }

    #[test]
    fn historical_systemd_fragment_recovers_old_xdg_config_service() {
        let root = tempfile::tempdir().unwrap();
        let fragment = root
            .path()
            .join("historical-xdg/systemd/user/hydra-agent.service");
        std::fs::create_dir_all(fragment.parent().unwrap()).unwrap();
        std::fs::write(
            &fragment,
            published_028_systemd_definition(std::path::Path::new("/historical/data/hydra-agent")),
        )
        .unwrap();
        let mut fragment_output = fragment.as_os_str().as_encoded_bytes().to_vec();
        fragment_output.push(b'\n');
        let parsed = parse_systemd_fragment_path(&fragment_output)
            .unwrap()
            .unwrap();
        let fragment_dir = installed_systemd_supervisor_invocation(&parsed)
            .unwrap()
            .unwrap()
            .agent_dir;
        assert_eq!(
            reconcile_proven_legacy_agent_dir_candidates(
                std::path::Path::new("/home/test/home/.local/share/hydra-agent"),
                [None, None, fragment_dir],
            )
            .unwrap(),
            Some(std::path::PathBuf::from("/historical/data/hydra-agent"))
        );
    }

    #[test]
    fn systemd_fragment_path_parser_is_bounded_and_unambiguous() {
        assert_eq!(parse_systemd_fragment_path(b"\n").unwrap(), None);
        assert_eq!(
            parse_systemd_fragment_path(
                b"/home/test/home/.config/systemd/user/hydra-agent.service\n"
            )
            .unwrap(),
            Some(std::path::PathBuf::from(
                "/home/test/home/.config/systemd/user/hydra-agent.service"
            ))
        );
        for invalid in [
            b"relative/hydra-agent.service\n".as_slice(),
            b"/home/test/home/../other/hydra-agent.service\n".as_slice(),
            b"/one/hydra-agent.service\n/two/hydra-agent.service\n".as_slice(),
            b"/home/test/home/\thydra-agent.service\n".as_slice(),
        ] {
            assert!(parse_systemd_fragment_path(invalid).is_err());
        }
        assert!(parse_systemd_fragment_path(&vec![
            b'a';
            super::MAX_SYSTEMD_FRAGMENT_PATH_BYTES + 1
        ])
        .is_err());

        let missing = tempfile::tempdir()
            .unwrap()
            .path()
            .join("hydra-agent.service");
        assert!(required_systemd_fragment_invocation(&missing).is_err());
    }

    #[test]
    fn systemd_descriptor_state_is_named_bounded_and_exact() {
        let state = parse_systemd_unit_state(
            b"FragmentPath=/old/config/systemd/user/hydra-agent.service\nDropInPaths=\nLoadState=loaded\nActiveState=failed\nUnitFileState=enabled\nMainPID=0\n",
        )
        .unwrap();
        assert_eq!(
            state.fragment_path,
            Some(std::path::PathBuf::from(
                "/old/config/systemd/user/hydra-agent.service"
            ))
        );
        assert_eq!(state.load_state, "loaded");
        assert_eq!(state.active_state, "failed");
        assert_eq!(state.unit_file_state, "enabled");
        assert_eq!(state.main_pid, None);
        for invalid in [
            b"FragmentPath=\nDropInPaths=\nLoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\n".as_slice(),
            b"FragmentPath=/one/hydra-agent.service\nFragmentPath=/two/hydra-agent.service\nDropInPaths=\nLoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\nMainPID=0\n".as_slice(),
            b"FragmentPath=\nDropInPaths=\nLoadState=loaded\nLoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\nMainPID=0\n".as_slice(),
            b"FragmentPath=\nDropInPaths=\nLoadState=loaded\nActiveState=inactive\nUnitFileState=disabled\nMainPID=not-a-pid\n".as_slice(),
            b"FragmentPath=/home/test/.config/systemd/user/hydra-agent.service\nDropInPaths=/home/test/.config/systemd/user/hydra-agent.service.d/override.conf\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\nMainPID=42\n".as_slice(),
        ] {
            assert!(parse_systemd_unit_state(invalid).is_err());
        }
    }

    fn systemd_service_state(active_state: &str, main_pid: Option<u32>) -> SystemdUnitState {
        SystemdUnitState {
            fragment_path: Some("/home/test/.config/systemd/user/hydra-agent.service".into()),
            drop_in_paths_empty: true,
            load_state: "loaded".into(),
            active_state: active_state.into(),
            unit_file_state: "enabled".into(),
            main_pid,
        }
    }

    fn absent_systemd_service_state() -> SystemdUnitState {
        SystemdUnitState {
            fragment_path: None,
            drop_in_paths_empty: true,
            load_state: "not-found".into(),
            active_state: "inactive".into(),
            unit_file_state: String::new(),
            main_pid: None,
        }
    }

    #[test]
    fn systemd_cleanup_classification_refuses_every_loaded_non_active_state() {
        assert_eq!(
            absent_systemd_service_state()
                .exact_running_or_absent()
                .unwrap(),
            None
        );
        assert_eq!(
            systemd_service_state("active", Some(42))
                .exact_running_or_absent()
                .unwrap(),
            Some(42)
        );

        for (state, pid) in [
            ("activating", None),
            ("activating", Some(42)),
            ("reloading", None),
            ("reloading", Some(42)),
            ("deactivating", None),
            ("deactivating", Some(42)),
            ("inactive", None),
            ("failed", None),
            ("active", None),
        ] {
            assert!(
                systemd_service_state(state, pid)
                    .exact_running_or_absent()
                    .is_err(),
                "loaded systemd state {state:?}/{pid:?} must not prove absence"
            );
        }
    }

    #[test]
    fn pending_remove_systemd_dormant_exception_is_exact_and_does_not_weaken_generic_absence() {
        let path = std::path::Path::new("/home/test/.config/systemd/user/hydra-agent.service");
        let mut dormant = systemd_service_state("inactive", None);
        assert!(dormant.exact_running_or_absent().is_err());
        assert!(super::dormant_systemd_pending_shape_is_safe(&dormant, path));

        dormant.unit_file_state = "disabled".into();
        assert!(super::dormant_systemd_pending_shape_is_safe(&dormant, path));

        let mut unsafe_states = Vec::new();
        let mut wrong_fragment = dormant.clone();
        wrong_fragment.fragment_path = Some("/foreign/hydra-agent.service".into());
        unsafe_states.push(wrong_fragment);
        let mut drop_in = dormant.clone();
        drop_in.drop_in_paths_empty = false;
        unsafe_states.push(drop_in);
        let mut failed = dormant.clone();
        failed.active_state = "failed".into();
        unsafe_states.push(failed);
        let mut running = dormant.clone();
        running.active_state = "active".into();
        running.main_pid = Some(42);
        unsafe_states.push(running);
        let mut unexpected_unit_state = dormant.clone();
        unexpected_unit_state.unit_file_state = "static".into();
        unsafe_states.push(unexpected_unit_state);
        let mut missing_pid_but_active = dormant;
        missing_pid_but_active.active_state = "active".into();
        unsafe_states.push(missing_pid_but_active);

        for state in unsafe_states {
            assert!(!super::dormant_systemd_pending_shape_is_safe(&state, path));
        }
    }

    #[test]
    fn systemd_readiness_tracks_one_exact_transition_generation() {
        let expected = std::path::Path::new("/home/test/.config/systemd/user/hydra-agent.service");
        let mut tracker = SystemdReadinessTracker::default();
        assert_eq!(
            tracker
                .observe(&absent_systemd_service_state(), expected)
                .unwrap(),
            None
        );
        assert_eq!(
            tracker
                .observe(&systemd_service_state("activating", None), expected)
                .unwrap(),
            None
        );
        assert_eq!(
            tracker
                .observe(&systemd_service_state("activating", Some(42)), expected)
                .unwrap(),
            None
        );
        assert_eq!(
            tracker
                .observe(&systemd_service_state("reloading", Some(42)), expected)
                .unwrap(),
            None
        );
        assert_eq!(
            tracker
                .observe(&systemd_service_state("active", Some(42)), expected)
                .unwrap(),
            Some(42)
        );

        let mut direct = SystemdReadinessTracker::default();
        assert_eq!(
            direct
                .observe(&systemd_service_state("active", Some(42)), expected)
                .unwrap(),
            Some(42)
        );
    }

    #[test]
    fn systemd_readiness_poison_survives_pid_change_or_generation_loss() {
        let expected = std::path::Path::new("/home/test/.config/systemd/user/hydra-agent.service");

        let mut mismatch = SystemdReadinessTracker::default();
        assert_eq!(
            mismatch
                .observe(&systemd_service_state("activating", Some(42)), expected)
                .unwrap(),
            None
        );
        assert!(mismatch
            .observe(&systemd_service_state("active", Some(43)), expected)
            .is_err());
        assert!(mismatch
            .observe(&systemd_service_state("active", Some(42)), expected)
            .is_err());

        let mut lost = SystemdReadinessTracker::default();
        assert_eq!(
            lost.observe(&systemd_service_state("active", Some(42)), expected)
                .unwrap(),
            Some(42)
        );
        assert!(lost
            .observe(&systemd_service_state("activating", None), expected)
            .is_err());
        assert!(lost
            .observe(&systemd_service_state("active", Some(42)), expected)
            .is_err());

        let mut unloaded = SystemdReadinessTracker::default();
        assert_eq!(
            unloaded
                .observe(&systemd_service_state("activating", Some(42)), expected)
                .unwrap(),
            None
        );
        assert!(unloaded
            .observe(&absent_systemd_service_state(), expected)
            .is_err());
        assert!(unloaded
            .observe(&systemd_service_state("active", Some(42)), expected)
            .is_err());
    }

    #[test]
    fn systemd_readiness_rejects_wrong_fragment_or_stopping_state() {
        let expected = std::path::Path::new("/home/test/.config/systemd/user/hydra-agent.service");
        let mut wrong_fragment = systemd_service_state("active", Some(42));
        wrong_fragment.fragment_path = Some("/old/hydra-agent.service".into());
        assert!(SystemdReadinessTracker::default()
            .observe(&wrong_fragment, expected)
            .is_err());
        assert!(SystemdReadinessTracker::default()
            .observe(&systemd_service_state("deactivating", Some(42)), expected)
            .is_err());
    }

    #[test]
    fn retained_daemon_loaded_fragment_must_match_before_any_service_action() {
        let expected =
            std::path::Path::new("/home/test/.config/systemd/user/hydra-pty-daemon.service");
        let exact = SystemdUnitState {
            fragment_path: Some(expected.to_path_buf()),
            drop_in_paths_empty: true,
            load_state: "loaded".into(),
            active_state: "active".into(),
            unit_file_state: "enabled".into(),
            main_pid: Some(42),
        };
        validate_expected_systemd_fragment(&exact, expected).unwrap();
        assert!(systemd_unit_state_uses_loaded_fragment(&exact, expected));

        let mut contradictory_loaded_definition = exact.clone();
        contradictory_loaded_definition.load_state = "not-found".into();
        assert!(!systemd_unit_state_uses_loaded_fragment(
            &contradictory_loaded_definition,
            expected
        ));

        let mut moved = exact.clone();
        moved.fragment_path =
            Some("/old/home/.config/systemd/user/hydra-pty-daemon.service".into());
        assert!(validate_expected_systemd_fragment(&moved, expected).is_err());

        let mut composed = exact.clone();
        composed.drop_in_paths_empty = false;
        assert!(validate_expected_systemd_fragment(&composed, expected).is_err());

        let mut unattributed = exact.clone();
        unattributed.fragment_path = None;
        assert!(validate_expected_systemd_fragment(&unattributed, expected).is_err());

        let absent = SystemdUnitState {
            fragment_path: None,
            drop_in_paths_empty: true,
            load_state: "not-found".into(),
            active_state: "inactive".into(),
            unit_file_state: String::new(),
            main_pid: None,
        };
        validate_expected_systemd_fragment(&absent, expected).unwrap();
        assert!(systemd_unit_state_proves_absent(&absent));

        let mut loaded_file_disappeared = exact.clone();
        loaded_file_disappeared.fragment_path = Some(expected.to_path_buf());
        assert!(!systemd_unit_state_proves_absent(&loaded_file_disappeared));

        let mut transitioning_without_pid = absent.clone();
        transitioning_without_pid.load_state = "loaded".into();
        transitioning_without_pid.active_state = "activating".into();
        assert!(!systemd_unit_state_proves_absent(
            &transitioning_without_pid
        ));

        let mut disabled_but_unproven = absent;
        disabled_but_unproven.unit_file_state = "disabled".into();
        assert!(!systemd_unit_state_proves_absent(&disabled_but_unproven));
    }

    #[test]
    fn exact_028_runtime_stamp_and_retired_binding_are_separate_from_disk() {
        let invocation = parse_supervisor_invocation(&parse_nul_arguments(
            b"/opt/hydra/hydra-agent\0supervise\0--attach-daemon-only\0--dir\0/home/test/.xdg-data/hydra-agent\0--sock\0/run/user/501/hydra.sock\0--environment\0production\0--expected-cloud\0https://api.hydraterms.com\0--cloud-pubkey\0eKNpAYrE3JwA1btPJMtqQZ5ePDX6k/hPjBxZnTmoanM=\0--allowed-origin\0https://app.hydraterms.com\0",
        ))
        .unwrap();
        let trust = invocation.legacy_trust.unwrap();
        assert_eq!(
            trust.binding_stamp(),
            "a19a9392b66ddab6be6139d56f915e6b832c7b9a79dd437bbeb2936b10c56984"
        );
        let runtime = parse_manager_runtime_environment(
            b"HOME=/home/test/home\0HYDRA_AGENT_BUILD_STAMP=git=36d69db built=1786200000\0",
        )
        .unwrap();
        assert_eq!(runtime.build_stamp, "git=36d69db built=1786200000");
        assert_eq!(runtime.binding_stamp, None);
        assert!(parse_manager_runtime_environment(
            b"HYDRA_AGENT_BUILD_STAMP=git=36d69db built=1786200000\0HYDRA_AGENT_BUILD_STAMP=git=new built=2\0"
        )
        .is_err());
    }

    #[test]
    fn full_service_parsers_accept_only_current_or_exact_published_028_generations() {
        let current_systemd = current_systemd_definition();
        assert!(!current_systemd.contains("Environment=\"HOME="));
        let current = super::parse_full_systemd_service_definition(current_systemd.as_bytes())
            .expect("current generated systemd unit must be accepted");
        assert_eq!(current.invocation.agent_dir, None);
        assert_eq!(current.invocation.legacy_trust, None);

        let fixed_systemd = fixed_headless_systemd_definition();
        let fixed = super::parse_full_systemd_service_definition(fixed_systemd.as_bytes())
            .expect("fixed generated systemd unit must be accepted");
        assert!(fixed.invocation.fixed_external_daemon);
        assert_eq!(fixed.fixed_home_dir.as_deref(), Some("/home/test/home"));
        super::require_fixed_systemd_home(&fixed, std::path::Path::new("/home/test/home")).unwrap();
        assert!(super::require_fixed_systemd_home(
            &fixed,
            std::path::Path::new("/home/test/another-account")
        )
        .is_err());

        let legacy_dir = std::path::Path::new("/home/test/home/.local/share/hydra-agent");
        let legacy_systemd = published_028_systemd_definition(legacy_dir);
        let legacy = super::parse_full_systemd_service_definition(legacy_systemd.as_bytes())
            .expect("exact published 0.2.8 systemd unit must be accepted");
        assert_eq!(legacy.invocation.agent_dir.as_deref(), Some(legacy_dir));
        assert_eq!(legacy.build_stamp, published_028_linux_build_stamp());
        assert_eq!(
            legacy.invocation.legacy_trust.unwrap().binding_stamp(),
            "a19a9392b66ddab6be6139d56f915e6b832c7b9a79dd437bbeb2936b10c56984"
        );

        let current_launchd = current_launchd_definition();
        let current = super::parse_full_launchd_service_definition(current_launchd.as_bytes())
            .expect("current generated launchd plist must be accepted");
        assert_eq!(current.invocation.agent_dir, None);
        assert_eq!(current.invocation.legacy_trust, None);

        let legacy_dir = std::path::Path::new("/Users/test/home/.local/share/hydra-agent");
        let legacy_launchd = published_028_launchd_definition(legacy_dir);
        let legacy = super::parse_full_launchd_service_definition(legacy_launchd.as_bytes())
            .expect("exact published 0.2.8 launchd plist must be accepted");
        assert_eq!(legacy.invocation.agent_dir.as_deref(), Some(legacy_dir));
        assert_eq!(legacy.build_stamp, super::LEGACY_028_MACOS_BUILD_STAMP);
        assert_eq!(
            legacy.invocation.legacy_trust.unwrap().binding_stamp(),
            "a19a9392b66ddab6be6139d56f915e6b832c7b9a79dd437bbeb2936b10c56984"
        );
    }

    #[test]
    fn authority_migration_accepts_only_the_exact_fixed_028_service_owner() {
        let home = std::path::PathBuf::from("/home/test/home");
        let authority_root = home.join(".local/share/hydra-agent");
        let service = home.join(".config/systemd/user/hydra-agent.service");
        let definition = published_028_systemd_definition(&authority_root);
        super::verify_legacy_authority_migration_service_evidence(
            &home,
            &authority_root,
            Some(&service),
            definition.as_bytes(),
        )
        .unwrap();

        for fragment in [
            None,
            Some(std::path::Path::new(
                "/home/test/home/.config/systemd/user/other.service",
            )),
            Some(std::path::Path::new(
                "/home/test/home/custom/systemd/user/hydra-agent.service",
            )),
        ] {
            assert!(super::verify_legacy_authority_migration_service_evidence(
                &home,
                &authority_root,
                fragment,
                definition.as_bytes(),
            )
            .is_err());
        }

        assert!(super::verify_legacy_authority_migration_service_evidence(
            &home,
            &authority_root,
            Some(&service),
            current_systemd_definition().as_bytes(),
        )
        .is_err());

        let other_root = home.join(".local/share/other-agent");
        assert!(super::verify_legacy_authority_migration_service_evidence(
            &home,
            &authority_root,
            Some(&service),
            published_028_systemd_definition(&other_root).as_bytes(),
        )
        .is_err());

        let wrong_build =
            definition.replacen(published_028_linux_build_stamp(), "git=ffffffff built=1", 1);
        assert!(super::verify_legacy_authority_migration_service_evidence(
            &home,
            &authority_root,
            Some(&service),
            wrong_build.as_bytes(),
        )
        .is_err());

        let wrong_trust = definition.replacen(
            super::LEGACY_028_ALLOWED_ORIGIN,
            "https://invalid.example",
            1,
        );
        assert!(super::verify_legacy_authority_migration_service_evidence(
            &home,
            &authority_root,
            Some(&service),
            wrong_trust.as_bytes(),
        )
        .is_err());

        for valid_but_wrong_owner in [
            definition.replacen(
                "/opt/hydra/bin/hydra-agent",
                "/opt/other/bin/hydra-agent",
                1,
            ),
            definition.replacen(
                "/home/test/home/.local/share/maestro-dev",
                "/home/test/home/.local/share/other-dev",
                1,
            ),
            definition.replace(
                "/home/test/home/.local/state/hydra-agent/logs",
                "/home/test/home/.local/state/other/logs",
            ),
        ] {
            assert!(
                super::parse_full_systemd_service_definition(valid_but_wrong_owner.as_bytes())
                    .is_ok()
            );
            assert!(super::verify_legacy_authority_migration_service_evidence(
                &home,
                &authority_root,
                Some(&service),
                valid_but_wrong_owner.as_bytes(),
            )
            .is_err());
        }
    }

    #[test]
    fn full_systemd_parser_rejects_extra_directives_hooks_and_noncanonical_paths() {
        let current = current_systemd_definition();
        let fixed = fixed_headless_systemd_definition();
        let legacy = published_028_systemd_definition(std::path::Path::new(
            "/home/test/home/.local/share/hydra-agent",
        ));
        let mutations = [
            current.replacen("Type=simple\n", "Type=simple\nExecStartPre=/bin/true\n", 1),
            current.replacen(
                "Environment=\"RUST_LOG=hydra_agent=info\"\n",
                "Environment=\"RUST_LOG=hydra_agent=info\"\nEnvironment=\"LD_PRELOAD=/tmp/injected.so\"\n",
                1,
            ),
            current.replacen(
                "Environment=\"RUST_LOG=hydra_agent=info\"\n",
                "Environment=\"RUST_LOG=hydra_agent=info\"\nEnvironment=\"HOME=/home/test/home\"\n",
                1,
            ),
            fixed.replacen("Environment=\"HOME=/home/test/home\"\n", "", 1),
            fixed.replacen(
                "Environment=\"HOME=/home/test/home\"",
                "Environment=\"HOME=relative/home\"",
                1,
            ),
            current.replacen(
                "/home/test/home/.local/share/maestro-dev",
                "relative/maestro-dev",
                1,
            ),
            current.replacen(
                "/run/user/1000/hydra-maestro-1000.sock",
                "/run/user/1000//hydra-maestro-1000.sock",
                1,
            ),
            current.replacen(
                "/opt/hydra/bin/hydra-agent",
                "/opt/hydra/bin/not-hydra",
                1,
            ),
            current.replacen(
                "StandardOutput=append:/home/test/home",
                "StandardOutput=append:%h/synthetic",
                1,
            ),
            legacy.replacen(published_028_linux_build_stamp(), "git=36d69db built=1", 1),
            legacy.replacen(
                super::LEGACY_028_CLOUD_BASE,
                "https://attacker.invalid",
                1,
            ),
        ];
        for mutation in mutations {
            assert!(
                super::parse_full_systemd_service_definition(mutation.as_bytes()).is_err(),
                "mutated systemd definition unexpectedly became provenance: {mutation}"
            );
        }
    }

    #[test]
    fn full_launchd_parser_rejects_extra_keys_arguments_and_noncanonical_paths() {
        let current = current_launchd_definition();
        let legacy = published_028_launchd_definition(std::path::Path::new(
            "/Users/test/home/.local/share/hydra-agent",
        ));
        let mutations = [
            current.replacen(
                "  <key>RunAtLoad</key>\n",
                "  <key>UnreviewedHook</key>\n  <string>/bin/true</string>\n  <key>RunAtLoad</key>\n",
                1,
            ),
            current.replacen(
                "  </array>\n  <key>RunAtLoad</key>",
                "    <string>--attacker</string>\n  </array>\n  <key>RunAtLoad</key>",
                1,
            ),
            current.replacen(
                "    <key>RUST_LOG</key>\n",
                "    <key>LD_PRELOAD</key>\n    <string>/tmp/injected.so</string>\n    <key>RUST_LOG</key>\n",
                1,
            ),
            current.replacen(
                "/private/tmp/synthetic/hydra-maestro-501.sock",
                "/private/tmp/synthetic/./hydra-maestro-501.sock",
                1,
            ),
            current.replacen(
                "/Applications/Hydra.app/Contents/MacOS/hydra-agent",
                "/Applications/Hydra.app/Contents/MacOS/not-hydra",
                1,
            ),
            current.replacen("com.hydra.agent", "com.attacker.agent", 1),
            legacy.replacen(super::LEGACY_028_MACOS_BUILD_STAMP, "git=36d69db built=1", 1),
            legacy.replacen(
                super::LEGACY_028_ALLOWED_ORIGIN,
                "https://attacker.invalid",
                1,
            ),
        ];
        for mutation in mutations {
            assert!(
                super::parse_full_launchd_service_definition(mutation.as_bytes()).is_err(),
                "mutated launchd definition unexpectedly became provenance: {mutation}"
            );
        }
    }

    #[test]
    fn service_provenance_paths_reject_semantically_normal_but_noncanonical_text() {
        for value in [
            "/opt/hydra//bin/hydra-agent",
            "/opt/hydra/./bin/hydra-agent",
            "/opt/hydra/bin/hydra-agent/",
            "opt/hydra/bin/hydra-agent",
        ] {
            assert!(super::require_absolute_normalized_path(
                value,
                "test path",
                Some("hydra-agent")
            )
            .is_err());
        }
        assert!(super::require_absolute_normalized_path(
            "/opt/hydra/bin/hydra-agent",
            "test path",
            Some("hydra-agent")
        )
        .is_ok());
    }

    #[test]
    fn installed_systemd_parser_rejects_shell_and_specifier_ambiguity() {
        for definition in [
            b"[Service]\nExecStart=/bin/hydra-agent supervise --sock /tmp/x\n".as_slice(),
            b"[Service]\nExecStart=\"/bin/hydra-agent\" \"supervise\" \"--sock\" \"/tmp/%h/x\"\n".as_slice(),
            b"[Service]\nExecStart=\"/bin/hydra-agent\" \"supervise\" \"--sock\" \"/tmp/x\"\nExecStart=\"/bin/other\"\n".as_slice(),
        ] {
            assert!(parse_generated_systemd_exec_start(definition).is_err());
        }
    }

    #[cfg(unix)]
    #[test]
    fn installed_service_provenance_rejects_unsafe_mode_and_symlink() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let unit = root.path().join("hydra-agent.service");
        std::fs::write(
            &unit,
            b"[Service]\nExecStart=\"/opt/hydra-agent\" \"supervise\" \"--sock\" \"/tmp/h.sock\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&unit, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_owned_service_definition(&unit).is_err());

        let target = root.path().join("target.service");
        std::fs::write(&target, b"safe bytes").unwrap();
        std::fs::remove_file(&unit).unwrap();
        std::os::unix::fs::symlink(&target, &unit).unwrap();
        assert!(read_owned_service_definition(&unit).is_err());
    }

    #[test]
    fn running_and_installed_legacy_provenance_must_agree() {
        let canonical = std::path::Path::new("/home/test/home/.local/share/hydra-agent");
        let legacy = std::path::PathBuf::from("/mnt/legacy/hydra-agent");
        assert_eq!(
            reconcile_proven_legacy_agent_dirs(
                canonical,
                Some(legacy.clone()),
                Some(legacy.clone())
            )
            .unwrap(),
            Some(legacy)
        );
        assert!(reconcile_proven_legacy_agent_dirs(
            canonical,
            Some("/mnt/a/hydra-agent".into()),
            Some("/mnt/b/hydra-agent".into())
        )
        .is_err());
        assert_eq!(
            reconcile_proven_legacy_agent_dirs(canonical, Some(canonical.to_path_buf()), None)
                .unwrap(),
            None
        );
    }

    #[test]
    fn live_supervise_flag_scanner_skips_values_that_look_like_flags() {
        let args = [
            "hydra-agent",
            "supervise",
            "--sessions",
            "--attach-daemon-only",
            "--sock",
            "/owned/h.sock",
        ]
        .map(str::to_string);
        assert!(!supervise_standalone_flag(&args, "--attach-daemon-only"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_procargs_parser_preserves_nul_delimited_socket_with_spaces() {
        let raw_args = [
            b"/Applications/Hydra.app/Contents/Resources/bin/hydra-agent".as_slice(),
            b"supervise".as_slice(),
            b"--sock".as_slice(),
            b"/tmp/Hydra socket.sock".as_slice(),
        ];
        let mut bytes = (raw_args.len() as libc::c_int).to_ne_bytes().to_vec();
        bytes.extend_from_slice(raw_args[0]);
        bytes.extend_from_slice(&[0, 0]);
        for argument in raw_args {
            bytes.extend_from_slice(argument);
            bytes.push(0);
        }
        bytes.extend_from_slice(b"HYDRA_AGENT_BUILD_STAMP=git=36d69db built=1786200000\0");
        assert_eq!(
            parse_macos_procargs2(&bytes).unwrap(),
            raw_args
                .iter()
                .map(|argument| argument.to_vec())
                .collect::<Vec<_>>()
        );
        let snapshot = parse_macos_procargs2_snapshot(&bytes).unwrap();
        assert_eq!(
            parse_manager_runtime_environment(&snapshot.environment)
                .unwrap()
                .build_stamp,
            "git=36d69db built=1786200000"
        );
    }

    #[test]
    fn legacy_manager_can_change_only_after_proving_zero_sessions() {
        assert!(legacy_manager_change_is_safe(Ok(0)));
        assert!(!legacy_manager_change_is_safe(Ok(1)));
        assert!(!legacy_manager_change_is_safe(Err(())));
    }

    #[test]
    fn dormant_launchd_replacement_requires_exact_attach_only_shape_and_no_peer() {
        let not_running =
            parse_launchctl_job_state(dormant_launchctl_job_fixture("not running").as_bytes())
                .unwrap();
        let installed =
            std::path::Path::new("/Users/test/Library/LaunchAgents/com.hydra.agent.plist");
        assert!(dormant_launchd_replacement_shape_is_safe(
            &not_running,
            true,
            0
        ));
        assert!(dormant_launchd_pending_shape_is_safe(
            &not_running,
            installed,
            true,
            0,
        ));
        assert!(!dormant_launchd_pending_shape_is_safe(
            &not_running,
            std::path::Path::new("/Users/test/Library/LaunchAgents/foreign.plist"),
            true,
            0,
        ));
        assert!(!dormant_launchd_replacement_shape_is_safe(
            &not_running,
            false,
            0
        ));
        assert!(!dormant_launchd_replacement_shape_is_safe(
            &not_running,
            true,
            1
        ));

        for state in ["spawn scheduled", "spawning", "waiting"] {
            let transitional =
                parse_launchctl_job_state(dormant_launchctl_job_fixture(state).as_bytes()).unwrap();
            assert!(!dormant_launchd_replacement_shape_is_safe(
                &transitional,
                true,
                0
            ));
        }
        assert!(!dormant_launchd_replacement_shape_is_safe(
            &super::LaunchdJobState {
                loaded: false,
                state: None,
                pid: None,
                definition_path: None,
            },
            true,
            0,
        ));
    }
}
