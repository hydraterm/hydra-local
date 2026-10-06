// Native adapter for main's existing service/lifecycle boundary. No Unix environment is invented.
type WindowsProcess = std::sync::Arc<hydra_agent::windows_service::ProcessWitness>;
static WINDOWS_PROCESSES: std::sync::OnceLock<
    std::sync::Mutex<std::collections::BTreeMap<u32, WindowsProcess>>,
> = std::sync::OnceLock::new();
fn retain_windows_process(
    process: hydra_agent::windows_service::ProcessWitness,
) -> Result<WindowsProcess> {
    let mut records = WINDOWS_PROCESSES
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| anyhow::anyhow!("Windows witness lock poisoned"))?;
    if let Some(prior) = records.get(&process.pid) {
        if !prior.matches_live(&process)? {
            bail!("Windows process identity changed during lifecycle operation");
        }
        return Ok(prior.clone());
    }
    if records.len() >= 256 {
        bail!("Windows process witness bound exceeded");
    }
    let process = std::sync::Arc::new(process);
    records.insert(process.pid, process.clone());
    Ok(process)
}
fn windows_process(pid: u32) -> Result<WindowsProcess> {
    if let Some(process) = WINDOWS_PROCESSES
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| anyhow::anyhow!("Windows witness lock poisoned"))?
        .get(&pid)
        .cloned()
    {
        return Ok(process);
    }
    retain_windows_process(hydra_agent::windows_service::ProcessWitness::open(pid)?)
}
fn process_is_live_exact(pid: u32) -> Result<bool> {
    match windows_process(pid) {
        Ok(process) => process.is_live(),
        Err(error) if error.is::<hydra_agent::windows_service::ProcessAlreadyExited>() => Ok(false),
        Err(error)
            if error
                .downcast_ref::<windows::core::Error>()
                .is_some_and(|e| {
                    e.code()
                        == windows::core::HRESULT::from_win32(
                            windows::Win32::Foundation::ERROR_INVALID_PARAMETER.0,
                        )
                }) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}
fn manager_process_snapshot(pid: u32) -> Result<ManagerProcessSnapshot> {
    let snapshot = windows_process(pid)?.snapshot()?;
    Ok(ManagerProcessSnapshot {
        arguments: snapshot
            .arguments
            .into_iter()
            .map(String::into_bytes)
            .collect(),
        environment: Vec::new(),
    })
}
fn manager_runtime_environment(pid: u32) -> Result<ManagerRuntimeEnvironment> {
    // Actual process argv carries public stamps checked at supervisor startup. Fresh readiness
    // independently binds that live process to these values; there is no fabricated environment.
    let snapshot = windows_process(pid)?.snapshot()?;
    let unique = |wanted: &str| -> Result<String> {
        let matches = snapshot
            .arguments
            .windows(2)
            .filter(|pair| pair[0] == wanted)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            bail!("Windows supervisor metadata is missing or ambiguous");
        }
        Ok(matches[0][1].clone())
    };
    let binding = unique("--service-binding-stamp")?;
    if binding.len() != 64
        || !binding
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        bail!("Windows runtime binding is invalid");
    }
    Ok(ManagerRuntimeEnvironment {
        build_stamp: validated_build_stamp(&unique("--service-build-stamp")?)?,
        binding_stamp: Some(binding),
    })
}
fn remote_peer_inventory_once(
    roots: &std::collections::BTreeSet<PathBuf>,
) -> Result<std::collections::BTreeSet<u32>> {
    if roots.is_empty() || roots.len() > 5 {
        bail!("remote-peer inventory roots are invalid");
    }
    let mut peers = std::collections::BTreeSet::new();
    for process in hydra_agent::windows_service::agent_processes()? {
        let Some(snapshot) = process.snapshot_if_live()? else {
            continue;
        };
        let arguments = snapshot
            .arguments
            .into_iter()
            .map(String::into_bytes)
            .collect::<Vec<_>>();
        if remote_peer_agent_dir(&arguments)?
            .as_ref()
            .is_some_and(|root| roots.contains(root))
        {
            peers.insert(retain_windows_process(process)?.pid);
            if peers.len() > MAX_REMOTE_PEER_PROCESSES {
                bail!("remote-peer inventory exceeds bound");
            }
        }
    }
    Ok(peers)
}
fn platform_service_paths(
    _home: &std::path::Path,
    dir: &std::path::Path,
    _label: &str,
    _uid: &str,
) -> hydra_agent::service::ServicePaths {
    hydra_agent::windows_service::default_paths(dir, "")
}
fn windows_health_process_presence(
    dir: &std::path::Path,
    socket: &std::path::Path,
) -> Result<(bool, bool, bool)> {
    let sid = hydra_agent::windows_service::current_user_sid()?;
    let paths = hydra_agent::windows_service::default_paths(dir, &sid);
    let installed = match hydra_agent::windows_service::read_definition(&paths)? {
        Some(definition) if definition.user_sid == sid && definition.agent_dir == dir => true,
        Some(_) => bail!("health service definition has another authority root or principal"),
        None => false,
    };
    let default_root = hydra_agent::agent_dir::default_agent_dir()?;
    let (mut supervisor, mut peer) = (false, false);
    for process in hydra_agent::windows_service::agent_processes()? {
        let Some(snapshot) = process.snapshot_if_live()? else {
            continue;
        };
        let arguments = snapshot
            .arguments
            .into_iter()
            .map(String::into_bytes)
            .collect::<Vec<_>>();
        let (is_supervisor, is_peer) =
            windows_health_invocation(&arguments, dir, socket, &default_root)?;
        if process.is_live()? {
            supervisor |= is_supervisor;
            peer |= is_peer;
        }
    }
    Ok((installed, supervisor, peer))
}
fn windows_health_invocation(
    arguments: &[Vec<u8>],
    dir: &std::path::Path,
    socket: &std::path::Path,
    default_root: &std::path::Path,
) -> Result<(bool, bool)> {
    if arguments.get(1).map(Vec::as_slice) == Some(b"supervise") {
        let invocation = parse_supervisor_invocation(arguments)?;
        return Ok((
            invocation.agent_dir.as_deref().unwrap_or(default_root) == dir
                && invocation.socket_path == socket,
            false,
        ));
    }
    let Some(peer_root) = remote_peer_agent_dir(arguments)? else {
        return Ok((false, false));
    };
    let mut sockets = arguments.windows(2).filter(|pair| pair[0] == b"--sock");
    let peer_socket = sockets
        .next()
        .map(|pair| process_argument_path(&pair[1]))
        .transpose()?;
    if sockets.next().is_some() {
        bail!("health peer has ambiguous socket arguments");
    }
    Ok((
        false,
        peer_root == dir && peer_socket.as_deref() == Some(socket),
    ))
}
#[cfg(test)]
mod windows_health_tests {
    use super::*;
    #[test]
    fn health_uses_exact_native_root_socket_and_command() {
        let root = std::path::Path::new(r"C:\Fixture\agent");
        let socket = std::path::Path::new(r"\\.\pipe\Hydra.Maestro.health-fixture");
        let args = |command: &str| {
            [
                "hydra-agent.exe",
                command,
                "--dir",
                root.to_str().unwrap(),
                "--sock",
                socket.to_str().unwrap(),
            ]
            .into_iter()
            .map(|s| s.as_bytes().to_vec())
            .collect::<Vec<_>>()
        };
        assert_eq!(
            windows_health_invocation(&args("supervise"), root, socket, root).unwrap(),
            (true, false)
        );
        assert_eq!(
            windows_health_invocation(&args("remote-peer"), root, socket, root).unwrap(),
            (false, true)
        );
        assert_eq!(
            windows_health_invocation(&args("windows-service-manager"), root, socket, root)
                .unwrap(),
            (false, false)
        );
        assert_eq!(
            windows_health_invocation(
                &args("remote-peer"),
                std::path::Path::new(r"C:\Other"),
                socket,
                root
            )
            .unwrap(),
            (false, false)
        );
        let mut duplicate = args("remote-peer");
        duplicate.extend([
            b"--sock".to_vec(),
            socket.to_str().unwrap().as_bytes().to_vec(),
        ]);
        assert!(windows_health_invocation(&duplicate, root, socket, root).is_err());
    }
}
fn extension_platform_service_paths(
    home: &std::path::Path,
    dir: &std::path::Path,
    label: &str,
    uid: &str,
) -> hydra_agent::service::ServicePaths {
    platform_service_paths(home, dir, label, uid)
}
fn platform_maestro_app_support_dir(_home: &std::path::Path) -> Result<PathBuf> {
    hydra_agent::windows_service::local_app_support_dir()
}
fn extension_maestro_app_support_dir(home: &std::path::Path) -> Result<PathBuf> {
    platform_maestro_app_support_dir(home)
}
fn platform_service_file(paths: &hydra_agent::service::ServicePaths) -> PathBuf {
    hydra_agent::windows_service::definition_path(paths)
}
fn platform_plan_install(
    paths: &hydra_agent::service::ServicePaths,
    opts: PlatformInstallOptions<'_>,
) -> Result<hydra_agent::service::ServicePlan> {
    if opts.fixed_external_daemon {
        bail!("Windows desktop task cannot install a Linux headless manager");
    }
    hydra_agent::windows_service::plan_install(
        paths,
        &hydra_agent::windows_service::WindowsServiceOptions {
            binary_path: std::path::Path::new(&opts.binary_path)
                .with_file_name("hydra-agent-service.exe")
                .to_string_lossy()
                .into_owned(),
            build_stamp: hydra_agent::build_stamp(),
            binding_stamp: hydra_agent::supervise::service_binding_stamp(),
            user_sid: hydra_agent::windows_service::current_user_sid()?,
            agent_dir: paths.agent_dir.clone(),
            app_support_dir: opts.app_support_dir.into(),
            socket_path: opts.socket_path,
            sessions: opts.sessions,
        },
    )
}
fn platform_plan_start(
    paths: &hydra_agent::service::ServicePaths,
) -> hydra_agent::service::ServicePlan {
    hydra_agent::windows_service::plan_start(paths, &std::env::current_exe().unwrap_or_default())
}
fn platform_plan_uninstall(
    paths: &hydra_agent::service::ServicePaths,
    _forget: bool,
) -> hydra_agent::service::ServicePlan {
    hydra_agent::windows_service::plan_uninstall(
        paths,
        &std::env::current_exe().unwrap_or_default(),
    )
}
fn platform_plan_status(
    paths: &hydra_agent::service::ServicePaths,
) -> hydra_agent::service::ServicePlan {
    hydra_agent::windows_service::plan_status(paths, &std::env::current_exe().unwrap_or_default())
}
fn platform_service_manager_pid(paths: &hydra_agent::service::ServicePaths) -> Result<Option<u32>> {
    let state = hydra_agent::windows_service::query(paths)?;
    let process = hydra_agent::windows_service::supervisor_for_state(&state)?
        .map(retain_windows_process)
        .transpose()?;
    if hydra_agent::windows_service::query(paths)? != state {
        bail!("Windows task changed during process binding");
    }
    Ok(process.map(|p| p.pid))
}
fn platform_service_manager_pid_for_readiness(
    paths: &hydra_agent::service::ServicePaths,
    tracker: &mut PlatformServiceReadinessTracker,
) -> Result<Option<u32>> {
    let state = hydra_agent::windows_service::query(paths)?;
    if state.absent()
        || state.dormant()
        || state.state == windows::Win32::System::TaskScheduler::TASK_STATE_QUEUED.0
    {
        return Ok(None);
    }
    let Some(process) = hydra_agent::windows_service::supervisor_for_state(&state)? else {
        return Ok(None);
    };
    let process = retain_windows_process(process)?;
    if let Some(prior) = &tracker.windows {
        if !prior.matches_live(&process)? {
            bail!("Windows supervisor changed during readiness");
        }
    }
    tracker.windows = Some(process.clone());
    Ok(Some(process.pid))
}
fn read_owned_service_definition_for_home(
    path: &std::path::Path,
    _home: &std::path::Path,
) -> Result<Option<Vec<u8>>> {
    use std::io::Read as _;
    if !path.try_exists()? {
        return Ok(None);
    }
    let parent = maestro_shell::WindowsPrivateDirectory::open(
        path.parent().context("Windows definition has no parent")?,
    )?;
    let mut file = parent.open_file(
        path.file_name().context("Windows definition has no name")?,
        false,
    )?;
    let identity = maestro_shell::WindowsPrivateDirectory::validate_file(&file)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take((MAX_INSTALLED_SERVICE_DEFINITION_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_INSTALLED_SERVICE_DEFINITION_BYTES
        || maestro_shell::WindowsPrivateDirectory::validate_file(&file)? != identity
    {
        bail!("Windows definition changed or exceeds bound");
    }
    Ok(Some(bytes))
}
fn installed_windows_service_descriptor(
    path: &std::path::Path,
) -> Result<Option<InstalledServiceDescriptor>> {
    let Some(bytes) = read_owned_service_definition(path)? else {
        return Ok(None);
    };
    let options = hydra_agent::windows_service::parse_task_xml(std::str::from_utf8(&bytes)?)?;
    if options.user_sid != hydra_agent::windows_service::current_user_sid()? {
        bail!("Windows task has another principal");
    }
    let mut args = vec![options.binary_path.as_bytes().to_vec()];
    args.extend(options.arguments().into_iter().map(String::into_bytes));
    Ok(Some(InstalledServiceDescriptor {
        path: path.into(),
        bytes,
        invocation: Some(parse_supervisor_invocation(&args)?),
        build_stamp: options.build_stamp,
    }))
}
fn installed_service_build_stamp(paths: &hydra_agent::service::ServicePaths) -> Result<String> {
    Ok(
        installed_windows_service_descriptor(&platform_service_file(paths))?
            .context("Windows task definition is absent")?
            .build_stamp,
    )
}
fn dormant_windows_replacement_is_safe(paths: &hydra_agent::service::ServicePaths) -> Result<bool> {
    let first = hydra_agent::windows_service::query(paths)?;
    let roots = std::collections::BTreeSet::from([paths.agent_dir.clone()]);
    if !first.dormant() || !remote_peer_inventory(&roots)?.is_empty() {
        return Ok(false);
    }
    let Some(installed) = hydra_agent::windows_service::read_definition(paths)? else {
        return Ok(false);
    };
    Ok(first.definition.as_ref() == Some(&installed)
        && hydra_agent::windows_service::query(paths)? == first
        && remote_peer_inventory(&roots)?.is_empty())
}
fn pending_remove_dormant_service_is_safe(
    paths: &hydra_agent::service::ServicePaths,
    pending: &hydra_agent::lifecycle_cleanup::CleanupTombstone,
) -> Result<bool> {
    let first = hydra_agent::windows_service::query(paths)?;
    let Some(installed) = installed_windows_service_descriptor(&platform_service_file(paths))?
    else {
        return Ok(false);
    };
    if hydra_agent::windows_service::read_definition(paths)?.as_ref() != first.definition.as_ref() {
        return Ok(false);
    }
    let roots = pending.peer_roots()?;
    let peers = remote_peer_inventory(&roots)?;
    if !pending_remove_binds_dormant_definition(
        pending,
        &installed,
        &paths.agent_dir,
        first.dormant(),
        &peers,
    )? {
        return Ok(false);
    }
    Ok(hydra_agent::windows_service::query(paths)? == first
        && installed_windows_service_descriptor(&platform_service_file(paths))?.as_ref()
            == Some(&installed)
        && remote_peer_inventory(&roots)? == peers)
}
fn capture_lifecycle_descriptor(
    root: &std::path::Path,
    lock: &hydra_agent::service::LifecycleLock,
) -> Result<LifecycleDescriptor> {
    let paths = hydra_agent::windows_service::default_paths(
        root,
        &hydra_agent::windows_service::current_user_sid()?,
    );
    let mut issues = Vec::new();
    let state = match hydra_agent::windows_service::query(&paths) {
        Ok(state) => Some(state),
        Err(error) => {
            issues.push(format!("Windows task is unreadable: {error:#}"));
            None
        }
    };
    let installed = match installed_windows_service_descriptor(&platform_service_file(&paths)) {
        Ok(value) => value.into_iter().collect::<Vec<_>>(),
        Err(error) => {
            issues.push(format!("Windows definition is unverified: {error:#}"));
            vec![]
        }
    };
    let running = if state
        .as_ref()
        .is_some_and(|s| s.state == windows::Win32::System::TaskScheduler::TASK_STATE_RUNNING.0)
    {
        match platform_service_manager_pid(&paths).and_then(|pid| {
            let pid = pid.context("Windows task lost its supervisor")?;
            let invocation = parse_supervisor_invocation(&manager_process_arguments(pid)?)?;
            let runtime = manager_runtime_environment(pid)?;
            Ok(RunningServiceDescriptor {
                manager_pid: pid,
                invocation,
                runtime_build_stamp: runtime.build_stamp,
                runtime_binding_stamp: runtime.binding_stamp,
            })
        }) {
            Ok(value) => Some(value),
            Err(error) => {
                issues.push(format!("Windows supervisor is unverified: {error:#}"));
                None
            }
        }
    } else {
        None
    };
    let verified_marker_source =
        hydra_agent::enrollment_migration::verified_completed_legacy_source(root, lock)?;
    let mut peer_roots = std::collections::BTreeSet::from([root.to_path_buf()]);
    add_descriptor_peer_root(
        &mut peer_roots,
        &mut issues,
        "legacy adoption marker",
        verified_marker_source.as_deref(),
    );
    // A stopped attach-only task is recoverably closed only when the loaded task and the
    // SID/ACL-verified installed definition agree across a second observation. A missing PID
    // alone is never a closure proof; the shared proof additionally requires an empty exact-peer
    // inventory across all provenance roots and no inspection issues.
    let proven_closed = match state.as_ref() {
        Some(state) if state.absent() && installed.is_empty() => {
            hydra_agent::windows_service::query(&paths)? == *state
        }
        Some(state) if state.dormant() && installed.len() == 1 => {
            hydra_agent::windows_service::read_definition(&paths)?.as_ref()
                == state.definition.as_ref()
                && installed_windows_service_descriptor(&platform_service_file(&paths))?.as_ref()
                    == installed.first()
                && hydra_agent::windows_service::query(&paths)? == *state
        }
        _ => false,
    };
    let (_, _, activation_state) = capture_descriptor_runtime_proof(
        &paths,
        running.as_ref(),
        &peer_roots,
        running.is_some(),
        proven_closed,
        &mut issues,
    );
    Ok(LifecycleDescriptor {
        canonical_root: root.into(),
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
