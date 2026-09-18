//! Service install/uninstall/status PLANNER (Slice D1 — dry-run only; no real machine writes here). Produces
//! a pure `ServicePlan` (a list of typed `ServiceAction`s) that describes EXACTLY what a real install/
//! uninstall/status would do — write the launchd plist, run `launchctl`, remove files — without executing
//! any of it. Slice D2 will add an executor that runs a plan only when human-approved. All paths are
//! injectable (`ServicePaths`) so tests use temp dirs and never touch the real `~/Library`.
//!
//! `launchd.rs` stays focused on plist GENERATION; this module owns paths/actions/rollback semantics. No
//! secrets ever appear in a plan (the plist carries only the non-secret cloud verify key). Identity authority
//! is never deleted by this raw planner; the journaled lifecycle engine owns that operation.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static SERVICE_WRITE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct LifecycleLockContention;

impl std::fmt::Display for LifecycleLockContention {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Hydra lifecycle is already being changed")
    }
}

impl std::error::Error for LifecycleLockContention {}

/// Distinguish the lock's explicit nonblocking contention result from an
/// unrelated I/O error that happens to use `WouldBlock`.
pub fn is_lifecycle_lock_contention(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::WouldBlock
        && error
            .get_ref()
            .is_some_and(|source| source.is::<LifecycleLockContention>())
}

/// Cross-process serialization for service/enrollment lifecycle transitions.
/// Every desktop window and CLI invocation uses the same per-agent-dir lock, so
/// ensure cannot reinstall a job halfway through Remove Remote.
pub struct LifecycleLock {
    root: PathBuf,
    #[cfg(unix)]
    file: std::fs::File,
    #[cfg(unix)]
    root_dir: std::fs::File,
    #[cfg(unix)]
    root_device: u64,
    #[cfg(unix)]
    root_inode: u64,
}

/// Deterministic lock ownership for canonical plus verified historical agent
/// roots. Candidate discovery happens before this call; callers must recapture
/// provenance after acquisition and retry if the root set changed.
pub struct LifecycleLockSet {
    locks: Vec<LifecycleLock>,
}

impl LifecycleLock {
    pub fn acquire(agent_dir: &Path) -> std::io::Result<Self> {
        #[cfg(unix)]
        let root = {
            // Request an owner-private mode explicitly so a caller's ambient
            // umask cannot create a group-writable authority root. Existing
            // 0755 roots remain compatible, but an existing writable root is
            // rejected before the lock file (or any lifecycle journal) is
            // created inside it.
            crate::agent_dir::ensure_owned_safe_authority_directory(agent_dir)?;
            std::fs::canonicalize(agent_dir)?
        };
        #[cfg(not(unix))]
        let root = {
            std::fs::create_dir_all(agent_dir)?;
            std::fs::canonicalize(agent_dir)?
        };
        let path = root.join("lifecycle.lock");
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;
            use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
            let mut root_options = std::fs::OpenOptions::new();
            root_options
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
            let root_dir = root_options.open(&root)?;
            let root_metadata = root_dir.metadata()?;
            let named_root = std::fs::symlink_metadata(&root)?;
            if !root_metadata.file_type().is_dir()
                || root_metadata.uid() != crate::agent_dir::trusted_uid()
                || root_metadata.permissions().mode() & 0o022 != 0
                || named_root.dev() != root_metadata.dev()
                || named_root.ino() != root_metadata.ino()
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Hydra lifecycle root changed before lock acquisition",
                ));
            }
            let root_device = root_metadata.dev();
            let root_inode = root_metadata.ino();
            let file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path)?;
            let metadata = file.metadata()?;
            if !metadata.file_type().is_file()
                || metadata.uid() != crate::agent_dir::trusted_uid()
                || metadata.nlink() != 1
                || metadata.permissions().mode() & 0o777 != 0o600
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Hydra lifecycle lock file has unsafe metadata",
                ));
            }
            // SAFETY: flock only borrows this valid open descriptor; the RAII
            // object owns it until unlock/drop.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                let error = std::io::Error::last_os_error();
                return if error
                    .raw_os_error()
                    .is_some_and(|code| code == libc::EWOULDBLOCK || code == libc::EAGAIN)
                {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        LifecycleLockContention,
                    ))
                } else {
                    Err(error)
                };
            }
            let value = Self {
                root,
                file,
                root_dir,
                root_device,
                root_inode,
            };
            value.revalidate_root()?;
            Ok(value)
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            Ok(Self { root })
        }
    }

    /// Prove that a lifecycle mutation uses the same state root whose lock is
    /// held. Passing a lock acquired for another profile is not serialization.
    pub fn require_agent_dir(&self, agent_dir: &Path) -> std::io::Result<()> {
        if !crate::agent_dir::is_canonically_encoded_absolute_path(agent_dir) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "lifecycle agent directory is not canonically encoded",
            ));
        }
        let candidate = std::fs::canonicalize(agent_dir)?;
        if candidate != self.root {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "lifecycle lock belongs to a different agent directory",
            ));
        }
        #[cfg(unix)]
        {
            self.revalidate_root()
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }

    #[cfg(unix)]
    fn revalidate_root(&self) -> std::io::Result<()> {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let opened = self.root_dir.metadata()?;
        let named = std::fs::symlink_metadata(&self.root)?;
        if !opened.file_type().is_dir()
            || opened.uid() != crate::agent_dir::trusted_uid()
            || opened.permissions().mode() & 0o022 != 0
            || opened.dev() != self.root_device
            || opened.ino() != self.root_inode
            || named.dev() != self.root_device
            || named.ino() != self.root_inode
        {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Hydra lifecycle root was replaced while its lock was held",
            ))
        } else {
            Ok(())
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl LifecycleLockSet {
    pub fn acquire(agent_dirs: impl IntoIterator<Item = PathBuf>) -> std::io::Result<Self> {
        let mut roots = agent_dirs
            .into_iter()
            .map(|root| {
                if !crate::agent_dir::is_canonically_encoded_absolute_path(&root) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "lifecycle lock root is not canonically encoded",
                    ));
                }
                std::fs::canonicalize(root)
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        roots.sort();
        roots.dedup();
        if roots.is_empty() || roots.len() > 5 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "lifecycle lock root set is empty or exceeds its bound",
            ));
        }
        let mut locks = Vec::with_capacity(roots.len());
        for root in roots {
            // LOCK_NB ensures a competing holder cannot deadlock a multi-root
            // acquisition. Dropping `locks` releases every earlier root when
            // a later one reports Busy.
            locks.push(LifecycleLock::acquire(&root)?);
        }
        Ok(Self { locks })
    }

    pub fn require_agent_dir(&self, agent_dir: &Path) -> std::io::Result<()> {
        if self
            .locks
            .iter()
            .any(|lock| lock.require_agent_dir(agent_dir).is_ok())
        {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "lifecycle lock set does not own this agent directory",
            ))
        }
    }

    pub fn lock_for(&self, agent_dir: &Path) -> std::io::Result<&LifecycleLock> {
        self.locks
            .iter()
            .find(|lock| lock.require_agent_dir(agent_dir).is_ok())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "lifecycle lock set does not own this agent directory",
                )
            })
    }

    pub fn roots(&self) -> impl Iterator<Item = &Path> {
        self.locks.iter().map(|lock| lock.root())
    }

    /// Prove that the caller holds exactly the canonical root set captured by
    /// a durable lifecycle transaction. A subset is insufficient: otherwise a
    /// retry could mutate one root while a historical peer root is unlocked.
    pub fn require_exact_roots(
        &self,
        expected: &std::collections::BTreeSet<PathBuf>,
    ) -> std::io::Result<()> {
        #[cfg(unix)]
        for lock in &self.locks {
            lock.revalidate_root()?;
        }
        let actual = self
            .roots()
            .map(Path::to_path_buf)
            .collect::<std::collections::BTreeSet<_>>();
        if &actual == expected {
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "lifecycle lock set differs from the transaction's captured root set",
            ))
        }
    }
}

#[cfg(unix)]
impl Drop for LifecycleLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd as _;
        // SAFETY: same owned live descriptor acquired above. Drop still closes
        // the descriptor even if an advisory unlock unexpectedly fails.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

use crate::launchd::{generate_launchd_plist, LaunchdPlistOptions};

/// One step of a service plan. Tests assert on these (not on rendered shell text).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceAction {
    /// Create or validate a shared service-manager container such as
    /// `LaunchAgents` or `systemd/user`. Existing group/world-writable shapes
    /// are rejected and never chmod'd.
    CreateDir(PathBuf),
    /// Create or validate an application-owned state/log directory. This is
    /// the only action allowed to tighten the exact 0.2.8 0770/0775 legacy
    /// shapes; it is never used for a shared service-manager container.
    CreatePrivateDir(PathBuf),
    /// Write a file (the plist) — contents included so tests can inspect it.
    WriteFile { path: PathBuf, contents: String },
    /// Remove a service definition or other non-authority plan output.
    RemoveFile(PathBuf),
    /// Run a command (launchctl bootstrap/bootout/kickstart/print). Not executed in D1.
    RunCommand { program: String, args: Vec<String> },
    /// Run a convergence command whose non-zero exit is harmless (for example, unloading a
    /// service that is not currently loaded). Spawn failures are still fatal; only the command's
    /// exit status is tolerated by the real runner. This lets install/uninstall plans be
    /// idempotent without hiding failures from the commands that establish the final state.
    RunCommandBestEffort { program: String, args: Vec<String> },
    /// A read-only check (does the plist exist? what does launchctl print?) — for `status`.
    Inspect(String),
}

/// A plan = the ordered actions + a short human title.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePlan {
    pub title: String,
    pub actions: Vec<ServiceAction>,
}

/// Injectable filesystem paths. The CLI fills these from `$HOME`/the agent dir; tests pass temp dirs.
#[derive(Debug, Clone)]
pub struct ServicePaths {
    /// `~/Library/LaunchAgents` (the dir the plist lives in).
    pub launch_agents_dir: PathBuf,
    /// `~/Library/Logs/Hydra` (StandardOut/ErrPath dir).
    pub log_dir: PathBuf,
    /// The agent data dir holding the replaceable enrollment credential and durable ownership marker.
    pub agent_dir: PathBuf,
    /// launchd label, e.g. `com.hydra.agent`.
    pub label: String,
    /// The numeric login UID (for `launchctl bootstrap gui/<uid>`); the CLI resolves it, tests inject one.
    pub uid: String,
}

impl ServicePaths {
    pub fn plist_path(&self) -> PathBuf {
        self.launch_agents_dir.join(format!("{}.plist", self.label))
    }
    /// Exact launchd target for this user service. Kept here so status/readiness
    /// probes and lifecycle planners cannot silently construct different labels.
    pub fn service_target(&self) -> String {
        format!("gui/{}/{}", self.uid, self.label)
    }
}

/// Plan an install: create dirs, write the plist, then load it via launchctl. The plist content comes from
/// `launchd.rs` (single source of truth) using the same log dir. `bootstrap` is the only strict manager
/// command after the write: `RunAtLoad` starts the new job, and an immediate force-kickstart could kill
/// launchd's still-starting xpcproxy trampoline.
pub fn plan_install(paths: &ServicePaths, plist: &LaunchdPlistOptions) -> ServicePlan {
    let plist_contents = generate_launchd_plist(plist);
    let plist_path = paths.plist_path();
    ServicePlan {
        title: "install hydra desktop agent (launchd user service)".to_string(),
        actions: vec![
            // Converge from both "not installed" and "already loaded". bootout returns non-zero
            // when the label is absent, which is expected on first install; bootstrap below
            // remains strict so the final loaded state is never falsely reported healthy.
            ServiceAction::RunCommandBestEffort {
                program: "launchctl".to_string(),
                args: vec!["bootout".to_string(), paths.service_target()],
            },
            ServiceAction::CreateDir(paths.launch_agents_dir.clone()),
            ServiceAction::CreatePrivateDir(paths.log_dir.clone()),
            ServiceAction::WriteFile {
                path: plist_path.clone(),
                contents: plist_contents,
            },
            // load it for the current GUI session.
            ServiceAction::RunCommand {
                program: "launchctl".to_string(),
                args: vec![
                    "bootstrap".to_string(),
                    format!("gui/{}", paths.uid),
                    plist_path.to_string_lossy().into_owned(),
                ],
            },
        ],
    }
}

/// Plan only the launchd half of an uninstall. The `forget` bit is retained at
/// this API boundary while callers migrate, but cannot add identity deletion:
/// exact authority/key removal belongs exclusively to the journaled lifecycle
/// engine.
pub fn plan_uninstall(paths: &ServicePaths, _forget: bool) -> ServicePlan {
    let actions = vec![
        ServiceAction::RunCommandBestEffort {
            program: "launchctl".to_string(),
            args: vec!["bootout".to_string(), paths.service_target()],
        },
        ServiceAction::RemoveFile(paths.plist_path()),
    ];
    ServicePlan {
        title: "uninstall hydra desktop agent service".to_string(),
        actions,
    }
}

/// Start an already-installed job without replacing a healthy running process. If the job was
/// never bootstrapped this strict plan fails, allowing the desktop to fall back to `install`.
pub fn plan_start(paths: &ServicePaths) -> ServicePlan {
    ServicePlan {
        title: "start hydra desktop agent (launchd user service)".to_string(),
        actions: vec![ServiceAction::RunCommand {
            program: "launchctl".to_string(),
            args: vec!["kickstart".to_string(), paths.service_target()],
        }],
    }
}

/// Plan a status check: read-only inspects only (no writes, no launchctl mutations).
pub fn plan_status(paths: &ServicePaths) -> ServicePlan {
    ServicePlan {
        title: "hydra desktop agent service status".to_string(),
        actions: vec![
            ServiceAction::Inspect(format!("plist exists? {}", paths.plist_path().display())),
            ServiceAction::Inspect(format!("launchctl print {}", paths.service_target())),
        ],
    }
}

/// Render a plan as human-readable dry-run text. Deterministic; carries no secrets.
pub fn render_plan(plan: &ServicePlan) -> String {
    let mut out = format!("{} — DRY RUN (nothing was changed):\n", plan.title);
    for (i, a) in plan.actions.iter().enumerate() {
        let n = i + 1;
        match a {
            ServiceAction::CreateDir(p) => {
                out.push_str(&format!("  {n}. would create dir: {}\n", p.display()))
            }
            ServiceAction::CreatePrivateDir(p) => {
                out.push_str(&format!("  {n}. would create app dir: {}\n", p.display()))
            }
            ServiceAction::WriteFile { path, contents } => {
                out.push_str(&format!(
                    "  {n}. would write: {} ({} bytes)\n",
                    path.display(),
                    contents.len()
                ));
            }
            ServiceAction::RemoveFile(p) => {
                out.push_str(&format!("  {n}. would remove: {}\n", p.display()))
            }
            ServiceAction::RunCommand { program, args } => {
                out.push_str(&format!(
                    "  {n}. would run: {} {}\n",
                    program,
                    args.join(" ")
                ));
            }
            ServiceAction::RunCommandBestEffort { program, args } => {
                out.push_str(&format!(
                    "  {n}. would run (ignore absent-state exit): {} {}\n",
                    program,
                    args.join(" ")
                ));
            }
            ServiceAction::Inspect(s) => out.push_str(&format!("  {n}. would check: {s}\n")),
        }
    }
    out
}

/// Does any plan action mutate the machine (so the CLI can require `--dry-run` until D2)?
pub fn is_mutating(plan: &ServicePlan) -> bool {
    plan.actions.iter().any(|a| {
        matches!(
            a,
            ServiceAction::CreateDir(_)
                | ServiceAction::CreatePrivateDir(_)
                | ServiceAction::WriteFile { .. }
                | ServiceAction::RemoveFile(_)
                | ServiceAction::RunCommand { .. }
                | ServiceAction::RunCommandBestEffort { .. }
        )
    })
}

/// Resolve the default macOS user-agent paths from `$HOME`/agent dir. The CLI calls this; tests inject paths
/// directly (so they never touch the real `~/Library`).
pub fn default_macos_paths(home: &Path, agent_dir: &Path, label: &str, uid: &str) -> ServicePaths {
    ServicePaths {
        launch_agents_dir: home.join("Library/LaunchAgents"),
        log_dir: home.join("Library/Logs/Hydra"),
        agent_dir: agent_dir.to_path_buf(),
        label: label.to_string(),
        uid: uid.to_string(),
    }
}

// ---- executor (Slice D2 — real ops behind --apply; the runner is injectable so tests use a fake) ----

/// Performs the real side effects of a `ServiceAction`. Injectable so tests record commands + write to a
/// temp root instead of touching the real `~/Library` / running `launchctl`.
pub trait ActionRunner {
    fn create_dir(&mut self, path: &Path) -> std::io::Result<()>;
    fn create_private_dir(&mut self, path: &Path) -> std::io::Result<()> {
        self.create_dir(path)
    }
    fn write_file(&mut self, path: &Path, contents: &str) -> std::io::Result<()>;
    fn remove_file(&mut self, path: &Path) -> std::io::Result<()>;
    /// Run a command; Err on spawn failure OR a nonzero exit.
    fn run_command(&mut self, program: &str, args: &[String]) -> std::io::Result<()>;
    /// Run an idempotent convergence command. A missing executable and every unclassified
    /// manager error remain fatal; only an explicitly recognized already-absent service is OK.
    fn run_command_best_effort(&mut self, program: &str, args: &[String]) -> std::io::Result<()> {
        self.run_command(program, args)
    }
    /// Read-only check (status). Returns a human line; never mutates.
    fn inspect(&mut self, what: &str) -> String;
}

/// Apply every action in a plan via the runner, in order. Stops + returns on the first error (so a failed
/// launchctl/write aborts the rest — no half-applied state past the failure point). NEVER called without an
/// explicit `--apply` at the CLI.
pub fn execute_plan(
    plan: &ServicePlan,
    runner: &mut dyn ActionRunner,
) -> std::io::Result<Vec<String>> {
    let mut log = Vec::new();
    for action in &plan.actions {
        match action {
            ServiceAction::CreateDir(p) => {
                runner.create_dir(p)?;
                log.push(format!("created dir {}", p.display()));
            }
            ServiceAction::CreatePrivateDir(p) => {
                runner.create_private_dir(p)?;
                log.push(format!("created app dir {}", p.display()));
            }
            ServiceAction::WriteFile { path, contents } => {
                runner.write_file(path, contents)?;
                log.push(format!(
                    "wrote {} ({} bytes)",
                    path.display(),
                    contents.len()
                ));
            }
            ServiceAction::RemoveFile(p) => {
                runner.remove_file(p)?;
                log.push(format!("removed {}", p.display()));
            }
            ServiceAction::RunCommand { program, args } => {
                runner.run_command(program, args)?;
                log.push(format!("ran {} {}", program, args.join(" ")));
            }
            ServiceAction::RunCommandBestEffort { program, args } => {
                runner.run_command_best_effort(program, args)?;
                log.push(format!(
                    "converged {} {} (absent state accepted)",
                    program,
                    args.join(" ")
                ));
            }
            ServiceAction::Inspect(what) => log.push(runner.inspect(what)),
        }
    }
    Ok(log)
}

/// Apply every action while collecting failures instead of stopping at the
/// first one. Reserved for destructive cleanup, where stopping a service,
/// removing its definition, and clearing local identity must all be attempted
/// before reporting an honest aggregate result.
pub fn execute_cleanup_plan(
    plan: &ServicePlan,
    runner: &mut dyn ActionRunner,
) -> (Vec<String>, Vec<String>) {
    let mut log = Vec::new();
    let mut errors = Vec::new();
    for action in &plan.actions {
        let result = match action {
            ServiceAction::CreateDir(path) => runner.create_dir(path),
            ServiceAction::CreatePrivateDir(path) => runner.create_private_dir(path),
            ServiceAction::WriteFile { path, contents } => runner.write_file(path, contents),
            ServiceAction::RemoveFile(path) => runner.remove_file(path),
            ServiceAction::RunCommand { program, args } => runner.run_command(program, args),
            ServiceAction::RunCommandBestEffort { program, args } => {
                runner.run_command_best_effort(program, args)
            }
            ServiceAction::Inspect(what) => {
                log.push(runner.inspect(what));
                continue;
            }
        };
        match result {
            Ok(()) => log.push(format!("completed cleanup action: {action:?}")),
            Err(error) => errors.push(format!("{action:?}: {error}")),
        }
    }
    (log, errors)
}

/// A concise human summary printed BEFORE `--apply` executes, so the user sees what is about to change.
/// No secrets.
pub fn human_summary(plan: &ServicePlan) -> String {
    let mut out = format!("Applying: {}\n", plan.title);
    for a in &plan.actions {
        match a {
            ServiceAction::WriteFile { path, .. } => {
                out.push_str(&format!("  • write {}\n", path.display()))
            }
            ServiceAction::RunCommand { program, args } => {
                out.push_str(&format!("  • run {} {}\n", program, args.join(" ")));
            }
            ServiceAction::RunCommandBestEffort { program, args } => {
                out.push_str(&format!(
                    "  • converge {} {} (absent state is OK)\n",
                    program,
                    args.join(" ")
                ));
            }
            ServiceAction::RemoveFile(p) => out.push_str(&format!("  • remove {}\n", p.display())),
            ServiceAction::CreateDir(p) => out.push_str(&format!("  • mkdir {}\n", p.display())),
            ServiceAction::CreatePrivateDir(p) => {
                out.push_str(&format!("  • mkdir app dir {}\n", p.display()))
            }
            ServiceAction::Inspect(_) => {}
        }
    }
    out
}

/// The real runner: filesystem + `launchctl`. Used only via the `--apply` CLI path.
pub struct SystemRunner;

const MANAGER_COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const MANAGER_STREAM_OUTPUT_LIMIT_BYTES: usize = 1024 * 1024;

pub fn manager_output_bounded(
    program: &str,
    args: &[String],
) -> std::io::Result<std::process::Output> {
    manager_output_bounded_with_limits(
        program,
        args,
        MANAGER_COMMAND_TIMEOUT,
        MANAGER_STREAM_OUTPUT_LIMIT_BYTES,
    )
}

#[cfg(unix)]
fn manager_output_bounded_with_limits(
    program: &str,
    args: &[String],
    timeout: std::time::Duration,
    stream_limit: usize,
) -> std::io::Result<std::process::Output> {
    use std::os::fd::AsRawFd as _;
    use std::process::Stdio;
    use std::time::Instant;

    fn set_nonblocking(fd: std::os::fd::RawFd) -> std::io::Result<()> {
        // SAFETY: `fd` is borrowed from a live child pipe. `fcntl` does not take
        // ownership and the returned flags are applied back to that same fd.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    fn drain<R: std::io::Read>(
        stream: &mut Option<R>,
        bytes: &mut Vec<u8>,
        limit: usize,
        label: &str,
    ) -> std::io::Result<bool> {
        let Some(reader) = stream.as_mut() else {
            return Ok(false);
        };
        let mut progressed = false;
        let mut buffer = [0_u8; 16 * 1024];
        loop {
            let remaining_with_sentinel = limit.saturating_sub(bytes.len()).saturating_add(1);
            let read_len = remaining_with_sentinel.min(buffer.len());
            match reader.read(&mut buffer[..read_len]) {
                Ok(0) => {
                    *stream = None;
                    return Ok(true);
                }
                Ok(count) => {
                    progressed = true;
                    bytes.extend_from_slice(&buffer[..count]);
                    if bytes.len() > limit {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("{label} exceeded the lifecycle command output limit"),
                        ));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(progressed);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }

    fn kill_group_and_reap(child: &mut std::process::Child) {
        // SAFETY: the child is placed in a process group whose id is its pid
        // before exec. Negative pid targets that exact group. The direct kill is
        // retained as a fallback, and `wait` always reaps the direct child.
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
        let _ = child.kill();
        let _ = child.wait();
    }

    let mut command = std::process::Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    use std::os::unix::process::CommandExt as _;
    command.process_group(0);
    let mut child = command.spawn()?;
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let configure_pipes = stdout
        .as_ref()
        .ok_or_else(|| std::io::Error::other("manager stdout pipe is unavailable"))
        .and_then(|pipe| set_nonblocking(pipe.as_raw_fd()))
        .and_then(|()| {
            stderr
                .as_ref()
                .ok_or_else(|| std::io::Error::other("manager stderr pipe is unavailable"))
        })
        .and_then(|pipe| set_nonblocking(pipe.as_raw_fd()));
    if let Err(error) = configure_pipes {
        kill_group_and_reap(&mut child);
        return Err(error);
    }

    let deadline = Instant::now() + timeout;
    let mut status = None;
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    loop {
        let stdout_progress = match drain(
            &mut stdout,
            &mut stdout_bytes,
            stream_limit,
            "manager stdout",
        ) {
            Ok(progressed) => progressed,
            Err(error) => {
                kill_group_and_reap(&mut child);
                return Err(error);
            }
        };
        let stderr_progress = match drain(
            &mut stderr,
            &mut stderr_bytes,
            stream_limit,
            "manager stderr",
        ) {
            Ok(progressed) => progressed,
            Err(error) => {
                kill_group_and_reap(&mut child);
                return Err(error);
            }
        };
        if status.is_none() {
            match child.try_wait() {
                Ok(candidate) => status = candidate,
                Err(error) => {
                    kill_group_and_reap(&mut child);
                    return Err(error);
                }
            }
        }
        if let Some(status) = status {
            if stdout.is_none() && stderr.is_none() {
                return Ok(std::process::Output {
                    status,
                    stdout: stdout_bytes,
                    stderr: stderr_bytes,
                });
            }
        }
        if Instant::now() >= deadline {
            // The lifecycle lock holder must not return while the manager or a
            // descendant holding either output pipe remains able to mutate
            // service state.
            kill_group_and_reap(&mut child);
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("{program} exceeded the 5s lifecycle command limit"),
            ));
        }
        if !(stdout_progress || stderr_progress) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

#[cfg(not(unix))]
fn manager_output_bounded_with_limits(
    program: &str,
    args: &[String],
    _timeout: std::time::Duration,
    _stream_limit: usize,
) -> std::io::Result<std::process::Output> {
    std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()
}

impl ActionRunner for SystemRunner {
    fn create_dir(&mut self, path: &Path) -> std::io::Result<()> {
        ensure_owned_safe_shared_service_directory(path)
    }
    fn create_private_dir(&mut self, path: &Path) -> std::io::Result<()> {
        crate::agent_dir::ensure_owned_safe_private_service_directory(path)
    }
    fn write_file(&mut self, path: &Path, contents: &str) -> std::io::Result<()> {
        atomic_write(path, contents)
    }
    fn remove_file(&mut self, path: &Path) -> std::io::Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()), // remove-if-exists
            Err(e) => Err(e),
        }
    }
    fn run_command(&mut self, program: &str, args: &[String]) -> std::io::Result<()> {
        let output = manager_output_bounded(program, args)?;
        if output.status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other(format!(
                "{program} {} exited with {}: {}",
                args.join(" "),
                output.status,
                String::from_utf8_lossy(&output.stderr)
                    .trim()
                    .lines()
                    .last()
                    .unwrap_or("unknown manager error")
            )))
        }
    }
    fn run_command_best_effort(&mut self, program: &str, args: &[String]) -> std::io::Result<()> {
        let output = manager_output_bounded(program, args)?;
        if output.status.success()
            || absent_service_exit(program, args, &String::from_utf8_lossy(&output.stderr))
        {
            return Ok(());
        }
        let detail = String::from_utf8_lossy(&output.stderr);
        Err(std::io::Error::other(format!(
            "{program} {} exited with {}: {}",
            args.join(" "),
            output.status,
            detail
                .trim()
                .lines()
                .last()
                .unwrap_or("unknown manager error")
        )))
    }
    fn inspect(&mut self, what: &str) -> String {
        format!("checked: {what}")
    }
}

/// Service managers use a non-zero exit for the desired "already absent" state. Accept only the
/// documented command shapes and narrow, content-blind absence markers; permission, domain/DBus,
/// malformed-unit, and every unknown error remain fatal.
fn absent_service_exit(program: &str, args: &[String], stderr: &str) -> bool {
    let command_allows_absence = match program {
        "launchctl" => args.first().map(String::as_str) == Some("bootout"),
        "systemctl" | "/bin/systemctl" => {
            args.iter().any(|arg| arg == "disable") && args.iter().any(|arg| arg == "--now")
        }
        _ => false,
    };
    if !command_allows_absence {
        return false;
    }
    let detail = stderr.to_ascii_lowercase();
    [
        "no such process",
        "could not find service",
        "service not found",
        "unit not loaded",
        "not-found",
    ]
    .iter()
    .any(|marker| detail.contains(marker))
        // systemd includes the unit name between these words, for example:
        // `Unit file hydra-agent.service does not exist.`
        || (detail.contains("unit file") && detail.contains("does not exist"))
}

/// Write `contents` to `path` atomically: write a temp file in the SAME dir, then rename over the target so
/// a crash mid-write can't leave a half-written plist.
pub fn atomic_write(path: &Path, contents: &str) -> std::io::Result<()> {
    let home = crate::agent_dir::trusted_home_dir()?;
    atomic_write_for_home(path, contents, &home)
}

fn atomic_write_for_home(path: &Path, contents: &str, trusted_home: &Path) -> std::io::Result<()> {
    use std::io::Write as _;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    // Inspect an existing unit/plist before the generic shared-parent check.
    // This validation is deliberately observe-only: no existing service file
    // or shared service-manager directory is chmod'd on this path.
    validate_existing_service_definition_for_home(path, trusted_home)?;
    ensure_owned_safe_shared_service_directory_for_home(dir, trusted_home)?;
    let tmp = dir.join(format!(
        ".{}.tmp.{}.{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("svc"),
        std::process::id(),
        SERVICE_WRITE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let _existing = open_existing_service_file(path)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options
                .mode(0o644)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let mut file = options.open(&tmp)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            // `OpenOptionsExt::mode` is filtered by the ambient umask. This is
            // a newly-created, O_NOFOLLOW, owner-verified temp inode, so set
            // its reviewed public service-definition mode on the open file
            // before any bytes are written. Existing files and directories
            // are never chmod'd by this writer.
            file.set_permissions(std::fs::Permissions::from_mode(0o644))?;
        }
        validate_service_file(&file, "temporary service definition", Some(0o644))?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        validate_service_file(&file, "temporary service definition", Some(0o644))?;
        drop(file);
        std::fs::rename(&tmp, path)?;
        std::fs::File::open(dir)?.sync_all()?;

        let mut readback = open_existing_service_file(path)?.ok_or_else(|| {
            std::io::Error::other("service definition vanished after durable publication")
        })?;
        validate_service_file(&readback, "service definition", Some(0o644))?;
        let mut actual = Vec::new();
        use std::io::Read as _;
        readback.read_to_end(&mut actual)?;
        if actual != contents.as_bytes() {
            return Err(std::io::Error::other(
                "service definition readback differs after publication",
            ));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Create or validate a shared service-manager directory. The policy never
/// chmods an existing shared container. Historical group-writable ancestry
/// and all unsafe custom-XDG/macOS containers fail closed; entirely absent
/// components are created deterministically with owner-private modes.
pub fn ensure_owned_safe_shared_service_directory(path: &Path) -> std::io::Result<()> {
    let home = crate::agent_dir::trusted_home_dir()?;
    ensure_owned_safe_shared_service_directory_for_home(path, &home)
}

fn ensure_owned_safe_shared_service_directory_for_home(
    path: &Path,
    trusted_home: &Path,
) -> std::io::Result<()> {
    let config = trusted_home.join(".config");
    let systemd = config.join("systemd");
    let unit_dir = systemd.join("user");
    if path != systemd && path != unit_dir {
        return crate::agent_dir::ensure_owned_safe_directory(path);
    }

    crate::agent_dir::require_owned_safe_directory(trusted_home)?;
    crate::agent_dir::ensure_owned_safe_directory(&config)?;
    for component in [&systemd, &unit_dir] {
        if component == &unit_dir && path == systemd {
            break;
        }
        match std::fs::symlink_metadata(component) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                crate::agent_dir::ensure_owned_safe_directory(component)?;
            }
            Err(error) => return Err(error),
            Ok(_) => crate::agent_dir::require_owned_safe_directory(component)?,
        }
    }
    crate::agent_dir::require_owned_safe_directory(path)
}

fn open_existing_service_file(path: &Path) -> std::io::Result<Option<std::fs::File>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    validate_service_file(&file, "existing service definition", None)?;
    Ok(Some(file))
}

/// Observe and validate an existing service definition before a caller reads
/// its bytes. Unsafe ownership, links, modes, or ancestry fail closed without
/// changing the file or any shared parent directory.
pub fn validate_existing_service_definition(path: &Path) -> std::io::Result<()> {
    let home = crate::agent_dir::trusted_home_dir()?;
    validate_existing_service_definition_for_home(path, &home)
}

/// Testable core of the observe-only validation. Production callers always
/// pass the effective account home resolved through the OS account database.
#[doc(hidden)]
pub fn validate_existing_service_definition_for_home(
    path: &Path,
    trusted_home: &Path,
) -> std::io::Result<()> {
    validate_existing_service_definition_for_home_and_uid(
        path,
        trusted_home,
        crate::agent_dir::trusted_uid(),
    )
}

/// Observe the one fixed Linux 0.2.8 systemd location without repairing it.
///
/// The published 0.2.8 writer let the ambient umask shape newly-created
/// `~/.config/systemd/user` ancestry and the unit itself.  Consequently the
/// affected authority cohort can carry owner-owned 0770/0775 directories and
/// a 0660/0664 unit.  The ordinary service reader quite deliberately rejects
/// those modes.  This migration-only reader admits them solely so the caller
/// can parse and prove the exact published unit bytes before offering the
/// explicit filesystem migration.  It never creates, removes, renames, or
/// chmods any path.
#[doc(hidden)]
#[cfg(unix)]
pub fn read_legacy_028_service_candidate_for_home(
    path: &Path,
    trusted_home: &Path,
) -> std::io::Result<Option<Vec<u8>>> {
    read_legacy_028_service_candidate_for_home_and_uid(
        path,
        trusted_home,
        crate::agent_dir::trusted_uid(),
    )
}

#[cfg(unix)]
#[derive(Clone)]
struct LegacyDirectoryBinding {
    path: PathBuf,
    device: u64,
    inode: u64,
    mode: u32,
}

#[cfg(unix)]
fn read_legacy_028_service_candidate_for_home_and_uid(
    path: &Path,
    trusted_home: &Path,
    expected_uid: u32,
) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    if !crate::agent_dir::is_canonically_encoded_absolute_path(trusted_home)
        || path != trusted_home.join(".config/systemd/user/hydra-agent.service")
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "legacy service candidate is outside its fixed effective-account path",
        ));
    }
    crate::agent_dir::require_rename_safe_ancestry(trusted_home)?;
    let home_metadata = std::fs::symlink_metadata(trusted_home)?;
    if !home_metadata.file_type().is_dir()
        || home_metadata.uid() != expected_uid
        || home_metadata.permissions().mode() & 0o7022 != 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "trusted home has unsafe metadata",
        ));
    }

    let directory_paths = [
        trusted_home.join(".config"),
        trusted_home.join(".config/systemd"),
        trusted_home.join(".config/systemd/user"),
    ];
    let mut directories = Vec::with_capacity(directory_paths.len());
    for directory in directory_paths {
        let metadata = std::fs::symlink_metadata(&directory)?;
        let mode = metadata.permissions().mode() & 0o7777;
        let ordinary_safe = mode & 0o7022 == 0;
        let exact_legacy = matches!(mode, 0o770 | 0o775);
        if !metadata.file_type().is_dir()
            || metadata.uid() != expected_uid
            || (!ordinary_safe && !exact_legacy)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "legacy service directory has unsafe metadata",
            ));
        }
        directories.push(LegacyDirectoryBinding {
            path: directory,
            device: metadata.dev(),
            inode: metadata.ino(),
            mode,
        });
    }

    let named_before = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options.open(path)?;
    let opened_before = file.metadata()?;
    let mode = opened_before.permissions().mode() & 0o7777;
    let ordinary_safe = mode & 0o7022 == 0;
    let exact_legacy = matches!(mode, 0o660 | 0o664);
    if !opened_before.file_type().is_file()
        || !named_before.file_type().is_file()
        || opened_before.uid() != expected_uid
        || opened_before.nlink() != 1
        || opened_before.dev() != named_before.dev()
        || opened_before.ino() != named_before.ino()
        || (!ordinary_safe && !exact_legacy)
        || opened_before.len() > 128 * 1024
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "legacy service candidate has unsafe metadata",
        ));
    }

    let mut bytes = Vec::with_capacity(opened_before.len() as usize);
    (&file).take(128 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 128 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "legacy service candidate exceeds its size limit",
        ));
    }

    let opened_after = file.metadata()?;
    let named_after = std::fs::symlink_metadata(path)?;
    if opened_after.dev() != opened_before.dev()
        || opened_after.ino() != opened_before.ino()
        || opened_after.uid() != expected_uid
        || opened_after.nlink() != 1
        || opened_after.permissions().mode() & 0o7777 != mode
        || opened_after.len() != opened_before.len()
        || named_after.dev() != opened_before.dev()
        || named_after.ino() != opened_before.ino()
        || read_service_file_bounded(&file)? != bytes
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "legacy service candidate changed while it was read",
        ));
    }
    for binding in directories {
        let metadata = std::fs::symlink_metadata(&binding.path)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != expected_uid
            || metadata.dev() != binding.device
            || metadata.ino() != binding.inode
            || metadata.permissions().mode() & 0o7777 != binding.mode
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "legacy service ancestry changed while it was read",
            ));
        }
    }
    Ok(Some(bytes))
}

fn validate_existing_service_definition_for_home_and_uid(
    path: &Path,
    trusted_home: &Path,
    expected_uid: u32,
) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "service definition has no parent directory",
        )
    })?;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let named_before = std::fs::symlink_metadata(path)?;
        let opened_before = file.metadata()?;
        let mode = opened_before.permissions().mode() & 0o777;
        if opened_before.uid() != expected_uid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "existing service definition has an unexpected owner",
            ));
        }
        // Permission repair for ~/.config ancestry and legacy 0660/0664 unit
        // files is deliberately prohibited here. Safe definitions continue;
        // group-writable or otherwise unproven shapes fail without mutation.
        validate_service_file(&file, "existing service definition", None)?;
        let before_bytes = read_service_file_bounded(&file)?;
        ensure_owned_safe_shared_service_directory_for_home(parent, trusted_home)?;
        revalidate_named_open_service_file(
            path,
            &file,
            &named_before,
            expected_uid,
            mode,
            &before_bytes,
        )?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        validate_service_file(&file, "existing service definition", None)
    }
}

#[cfg(unix)]
fn read_service_file_bounded(file: &std::fs::File) -> std::io::Result<Vec<u8>> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    const MAX_BYTES: usize = 128 * 1024;
    let metadata = file.metadata()?;
    if metadata.len() > MAX_BYTES as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "service definition exceeds its size limit",
        ));
    }
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    reader
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "service definition exceeds its size limit",
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn revalidate_named_open_service_file(
    path: &Path,
    file: &std::fs::File,
    named_before: &std::fs::Metadata,
    expected_uid: u32,
    expected_mode: u32,
    expected_bytes: &[u8],
) -> std::io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let opened = file.metadata()?;
    let named = std::fs::symlink_metadata(path)?;
    if !opened.file_type().is_file()
        || opened.uid() != expected_uid
        || opened.nlink() != 1
        || opened.permissions().mode() & 0o777 != expected_mode
        || opened.dev() != named_before.dev()
        || opened.ino() != named_before.ino()
        || named.dev() != opened.dev()
        || named.ino() != opened.ino()
        || read_service_file_bounded(file)? != expected_bytes
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "service definition changed while its ancestry was validated",
        ));
    }
    Ok(())
}

fn validate_service_file(
    file: &std::fs::File,
    label: &str,
    exact_mode: Option<u32>,
) -> std::io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{label} is not a regular file"),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let mode = metadata.permissions().mode() & 0o777;
        if metadata.uid() != crate::agent_dir::trusted_uid()
            || metadata.nlink() != 1
            || mode & 0o022 != 0
            || exact_mode.is_some_and(|expected| mode != expected)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("{label} has unsafe metadata"),
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = (label, exact_mode);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn test_systemd_ancestry(trusted_home: &Path) -> [PathBuf; 3] {
        let config = trusted_home.join(".config");
        let systemd = config.join("systemd");
        let unit_dir = systemd.join("user");
        [config, systemd, unit_dir]
    }

    #[cfg(unix)]
    fn secure_tempdir(prefix: &str) -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt as _;

        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let root = tempfile::Builder::new()
            .prefix(prefix)
            .tempdir_in(base)
            .unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    fn paths() -> ServicePaths {
        // temp-dir based — never the real ~/Library.
        let base = std::env::temp_dir().join(format!("svc-test-{}", std::process::id()));
        ServicePaths {
            launch_agents_dir: base.join("LaunchAgents"),
            log_dir: base.join("Logs/Hydra"),
            agent_dir: base.join("agent"),
            label: "com.hydra.agent".to_string(),
            uid: "501".to_string(),
        }
    }
    fn plist_opts(p: &ServicePaths) -> LaunchdPlistOptions {
        LaunchdPlistOptions {
            label: p.label.clone(),
            binary_path: "/usr/local/bin/hydra-agent".to_string(),
            build_stamp: "git-test@1700000000000".to_string(),
            socket_path: "/tmp/hydra-maestro-4242.sock".to_string(),
            sessions: vec!["s1".to_string()],
            log_dir: p.log_dir.to_string_lossy().into_owned(),
            home_dir: "/Users/test/home".to_string(),
            maestro_app_support_dir: "/Users/test/Library/Application Support/Maestro-dev"
                .to_string(),
        }
    }

    #[test]
    fn install_plan_creates_dirs_and_writes_the_plist() {
        let p = paths();
        let plan = plan_install(&p, &plist_opts(&p));
        // creates both dirs
        assert!(plan
            .actions
            .contains(&ServiceAction::CreateDir(p.launch_agents_dir.clone())));
        assert!(plan
            .actions
            .contains(&ServiceAction::CreatePrivateDir(p.log_dir.clone())));
        // writes the plist at LaunchAgents/<label>.plist with real plist content
        let write = plan.actions.iter().find_map(|a| match a {
            ServiceAction::WriteFile { path, contents } => Some((path.clone(), contents.clone())),
            _ => None,
        });
        let (path, contents) = write.expect("a WriteFile action");
        assert_eq!(path, p.plist_path());
        assert!(contents.contains("<key>Label</key>"));
        assert!(contents.contains("supervise")); // the plist invokes supervise
    }

    #[test]
    fn install_plan_is_deterministic_and_bootstraps_without_kickstart() {
        let p = paths();
        let plan = plan_install(&p, &plist_opts(&p));
        assert_eq!(plan, plan_install(&p, &plist_opts(&p)));
        let plist = plan.actions.iter().find_map(|action| match action {
            ServiceAction::WriteFile { contents, .. } => Some(contents),
            _ => None,
        });
        assert!(plist
            .expect("install plan must publish one launchd plist")
            .contains("  <key>RunAtLoad</key>\n  <true/>\n"));
        let manager_actions = plan
            .actions
            .iter()
            .filter(|action| {
                matches!(
                    action,
                    ServiceAction::RunCommand { .. } | ServiceAction::RunCommandBestEffort { .. }
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            manager_actions,
            vec![
                ServiceAction::RunCommandBestEffort {
                    program: "launchctl".to_string(),
                    args: vec!["bootout".to_string(), p.service_target()],
                },
                ServiceAction::RunCommand {
                    program: "launchctl".to_string(),
                    args: vec![
                        "bootstrap".to_string(),
                        format!("gui/{}", p.uid),
                        p.plist_path().to_string_lossy().into_owned(),
                    ],
                },
            ]
        );
        assert!(!manager_actions.iter().any(|action| match action {
            ServiceAction::RunCommand { args, .. }
            | ServiceAction::RunCommandBestEffort { args, .. } =>
                args.iter().any(|arg| arg == "kickstart" || arg == "-k"),
            _ => false,
        }));
        // D1 must NOT have run anything: the temp dirs/files do not exist after planning.
        assert!(!p.plist_path().exists());
        assert!(!p.launch_agents_dir.exists());
    }

    #[test]
    fn uninstall_plan_removes_exactly_the_plist_and_unloads() {
        let p = paths();
        let plan = plan_uninstall(&p, false);
        assert!(plan.actions.iter().any(|a| matches!(a, ServiceAction::RunCommandBestEffort { program, args } if program == "launchctl" && args.first().map(String::as_str) == Some("bootout"))));
        assert!(plan
            .actions
            .contains(&ServiceAction::RemoveFile(p.plist_path())));
        // default uninstall KEEPS identity (no device.json / device-key removal)
        assert!(!plan.actions.iter().any(|a| matches!(a, ServiceAction::RemoveFile(path) if path.ends_with("device.json") || path.ends_with("device-key"))));
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
            Some(ServiceAction::RunCommandBestEffort { program, .. }) if program == "launchctl"
        ));
    }

    #[test]
    fn status_plan_is_read_only() {
        let p = paths();
        let plan = plan_status(&p);
        assert!(!is_mutating(&plan)); // only Inspect actions
        assert!(plan
            .actions
            .iter()
            .all(|a| matches!(a, ServiceAction::Inspect(_))));
    }

    #[test]
    fn start_plan_uses_one_bounded_non_killing_kickstart() {
        let p = paths();
        let plan = plan_start(&p);
        assert_eq!(
            plan.actions,
            vec![ServiceAction::RunCommand {
                program: "launchctl".to_string(),
                args: vec!["kickstart".to_string(), p.service_target()],
            }]
        );
        assert_eq!(MANAGER_COMMAND_TIMEOUT, std::time::Duration::from_secs(5));
    }

    #[test]
    fn rendered_dry_run_has_no_secrets() {
        let p = paths();
        for plan in [
            plan_install(&p, &plist_opts(&p)),
            plan_uninstall(&p, true),
            plan_status(&p),
        ] {
            let text = render_plan(&plan).to_lowercase();
            for bad in ["token", "secret", "private", "bearer", "password"] {
                assert!(!text.contains(bad), "dry-run text must not contain {bad:?}");
            }
            // The lifecycle engine, not a rendered raw plan, handles identity material.
            assert!(!text.contains("begin"), "no key material");
        }
        // the public cloud-pubkey appears in the install plist write (allowed + expected)
        assert!(render_plan(&plan_install(&p, &plist_opts(&p))).contains("would write"));
    }

    // ---- executor tests (fake runner — records commands, writes to a temp root; no real launchctl) ----

    /// A fresh temp root per test so executor runs don't collide.
    fn tmp_paths(tag: &str) -> ServicePaths {
        let base = std::env::temp_dir().join(format!("svc-exec-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        ServicePaths {
            launch_agents_dir: base.join("LaunchAgents"),
            log_dir: base.join("Logs/Hydra"),
            agent_dir: base.join("agent"),
            label: "com.hydra.agent".to_string(),
            uid: "501".to_string(),
        }
    }

    /// Fake runner: does real fs ops (so install/uninstall round-trips can be checked on temp dirs) but
    /// RECORDS commands instead of running launchctl. Optionally fails one program to test abort.
    #[derive(Default)]
    struct FakeRunner {
        commands: Vec<String>,
        fail_program: Option<String>,
        fail_args_prefix: Option<Vec<String>>,
    }
    impl ActionRunner for FakeRunner {
        fn create_dir(&mut self, path: &Path) -> std::io::Result<()> {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                let mut builder = std::fs::DirBuilder::new();
                builder.recursive(true).mode(0o700);
                builder.create(path)
            }
            #[cfg(not(unix))]
            {
                std::fs::create_dir_all(path)
            }
        }
        fn write_file(&mut self, path: &Path, contents: &str) -> std::io::Result<()> {
            atomic_write(path, contents)
        }
        fn remove_file(&mut self, path: &Path) -> std::io::Result<()> {
            match std::fs::remove_file(path) {
                Ok(()) | Err(_) => Ok(()), // remove-if-exists
            }
        }
        fn run_command(&mut self, program: &str, args: &[String]) -> std::io::Result<()> {
            self.commands.push(format!("{program} {}", args.join(" ")));
            if self.fail_program.as_deref() == Some(program)
                && self
                    .fail_args_prefix
                    .as_ref()
                    .is_none_or(|prefix| args.starts_with(prefix))
            {
                return Err(std::io::Error::other("forced command failure"));
            }
            Ok(())
        }
        fn run_command_best_effort(
            &mut self,
            program: &str,
            args: &[String],
        ) -> std::io::Result<()> {
            self.commands.push(format!("{program} {}", args.join(" ")));
            // Match SystemRunner semantics: a non-zero absent-state result is tolerated. Fake a
            // spawn failure with a distinct sentinel so that path remains testable.
            if self.fail_program.as_deref() == Some("<spawn-failure>") {
                return Err(std::io::Error::other("forced spawn failure"));
            }
            Ok(())
        }
        fn inspect(&mut self, what: &str) -> String {
            format!("checked: {what}")
        }
    }

    #[test]
    fn execute_install_writes_plist_and_records_launchctl_no_real_run() {
        let p = tmp_paths("install");
        let mut r = FakeRunner::default();
        execute_plan(&plan_install(&p, &plist_opts(&p)), &mut r).unwrap();
        // dirs + plist really exist now (in the TEMP root, not ~/Library)
        assert!(p.launch_agents_dir.exists());
        assert!(p.log_dir.exists());
        let plist = std::fs::read_to_string(p.plist_path()).unwrap();
        assert!(plist.contains("<key>Label</key>"));
        assert!(plist.contains("supervise"));
        // launchctl was RECORDED, not really run. RunAtLoad makes bootstrap the
        // only strict install command; no force-kickstart may race its trampoline.
        assert_eq!(
            r.commands,
            vec![
                format!("launchctl bootout {}", p.service_target()),
                format!(
                    "launchctl bootstrap gui/{} {}",
                    p.uid,
                    p.plist_path().display()
                ),
            ]
        );
        let _ = std::fs::remove_dir_all(p.launch_agents_dir.parent().unwrap());
    }

    #[test]
    fn execute_start_records_one_non_killing_kickstart_no_real_run() {
        let p = tmp_paths("start");
        let mut r = FakeRunner::default();
        execute_plan(&plan_start(&p), &mut r).unwrap();
        assert_eq!(
            r.commands,
            vec![format!("launchctl kickstart {}", p.service_target())]
        );
    }

    #[test]
    fn execute_uninstall_removes_plist_and_records_bootout() {
        let p = tmp_paths("uninstall");
        let mut r = FakeRunner::default();
        execute_plan(&plan_install(&p, &plist_opts(&p)), &mut r).unwrap();
        assert!(p.plist_path().exists());
        let mut r2 = FakeRunner::default();
        execute_plan(&plan_uninstall(&p, false), &mut r2).unwrap();
        assert!(!p.plist_path().exists()); // plist gone
        assert!(r2
            .commands
            .iter()
            .any(|c| c.starts_with("launchctl bootout")));
        let _ = std::fs::remove_dir_all(p.launch_agents_dir.parent().unwrap());
    }

    #[test]
    fn execute_forget_raw_plan_preserves_identity_files() {
        let p = tmp_paths("forget");
        std::fs::create_dir_all(&p.agent_dir).unwrap();
        std::fs::write(p.agent_dir.join("device.json"), "{}").unwrap();
        std::fs::write(p.agent_dir.join("device-key"), "seed").unwrap();
        std::fs::write(p.agent_dir.join("device-owner.json"), "owner").unwrap();
        let mut r = FakeRunner::default();
        execute_plan(&plan_uninstall(&p, true), &mut r).unwrap();
        assert!(p.agent_dir.join("device.json").exists());
        assert!(p.agent_dir.join("device-key").exists());
        assert!(p.agent_dir.join("device-owner.json").exists());
        let _ = std::fs::remove_dir_all(p.agent_dir.parent().unwrap());
    }

    #[test]
    fn forget_manager_failure_does_not_touch_identity() {
        let p = tmp_paths("forget-manager-failure");
        std::fs::create_dir_all(&p.agent_dir).unwrap();
        let record = p.agent_dir.join("device.json");
        let key = p.agent_dir.join("device-key");
        std::fs::write(&record, "{}").unwrap();
        std::fs::write(&key, "seed").unwrap();
        let mut runner = FakeRunner {
            fail_program: Some("<spawn-failure>".to_string()),
            ..FakeRunner::default()
        };

        assert!(execute_plan(&plan_uninstall(&p, true), &mut runner).is_err());
        assert!(
            record.exists(),
            "raw launchd failure cannot mutate authority"
        );
        assert!(
            key.exists(),
            "raw launchd failure cannot mutate the stable key"
        );
        let _ = std::fs::remove_dir_all(p.agent_dir.parent().unwrap());
    }

    #[test]
    fn systemd_forget_manager_failure_does_not_touch_identity() {
        let p = tmp_paths("systemd-forget-manager-failure");
        std::fs::create_dir_all(&p.agent_dir).unwrap();
        let record = p.agent_dir.join("device.json");
        let key = p.agent_dir.join("device-key");
        std::fs::write(&record, "{}").unwrap();
        std::fs::write(&key, "seed").unwrap();
        let mut runner = FakeRunner {
            fail_program: Some(crate::headless::SYSTEMCTL_PATH.to_string()),
            fail_args_prefix: Some(vec!["--user".to_string(), "daemon-reload".to_string()]),
            ..FakeRunner::default()
        };

        assert!(execute_plan(&crate::systemd::plan_uninstall(&p, true), &mut runner).is_err());
        assert!(record.exists());
        assert!(key.exists());
        assert!(runner
            .commands
            .iter()
            .any(|command| command == "/bin/systemctl --user daemon-reload"));
        let _ = std::fs::remove_dir_all(p.agent_dir.parent().unwrap());
    }

    #[test]
    fn execute_removing_missing_file_is_ok() {
        let p = tmp_paths("missing");
        let mut r = FakeRunner::default();
        // uninstall with nothing installed → no error (remove-if-exists)
        assert!(execute_plan(&plan_uninstall(&p, false), &mut r).is_ok());
    }

    #[test]
    fn execute_install_fails_closed_on_bootstrap_failure() {
        let p = tmp_paths("fail");
        let mut r = FakeRunner {
            commands: vec![],
            fail_program: Some("launchctl".to_string()),
            fail_args_prefix: Some(vec!["bootstrap".to_string()]),
        };
        let err = execute_plan(&plan_install(&p, &plist_opts(&p)), &mut r).unwrap_err();
        assert!(err.to_string().contains("forced command failure"));
        // The best-effort bootout ran first; strict bootstrap failed and no later action ran.
        assert_eq!(r.commands.len(), 2);
        assert!(r.commands[0].starts_with("launchctl bootout"));
        assert!(r.commands[1].starts_with("launchctl bootstrap"));
        let _ = std::fs::remove_dir_all(p.launch_agents_dir.parent().unwrap());
    }

    #[test]
    fn execute_start_fails_closed_on_kickstart_failure() {
        let p = tmp_paths("start-fail");
        let mut r = FakeRunner {
            fail_program: Some("launchctl".to_string()),
            fail_args_prefix: Some(vec!["kickstart".to_string()]),
            ..FakeRunner::default()
        };
        let error = execute_plan(&plan_start(&p), &mut r).unwrap_err();
        assert!(error.to_string().contains("forced command failure"));
        assert_eq!(
            r.commands,
            vec![format!("launchctl kickstart {}", p.service_target())]
        );
    }

    #[test]
    fn reinstall_converges_from_an_already_loaded_service() {
        let p = tmp_paths("reinstall");
        let plan = plan_install(&p, &plist_opts(&p));
        assert!(matches!(
            plan.actions.first(),
            Some(ServiceAction::RunCommandBestEffort { program, args })
                if program == "launchctl" && args.first().map(String::as_str) == Some("bootout")
        ));
        let mut r = FakeRunner {
            fail_program: Some("launchctl".to_string()),
            fail_args_prefix: Some(vec!["bootout".to_string()]),
            ..FakeRunner::default()
        };
        execute_plan(&plan, &mut r).unwrap();
        assert_eq!(
            r.commands,
            vec![
                format!("launchctl bootout {}", p.service_target()),
                format!(
                    "launchctl bootstrap gui/{} {}",
                    p.uid,
                    p.plist_path().display()
                ),
            ]
        );
        let _ = std::fs::remove_dir_all(p.launch_agents_dir.parent().unwrap());
    }

    #[test]
    fn best_effort_spawn_failure_is_still_fatal() {
        let p = tmp_paths("spawn-fail");
        let mut r = FakeRunner {
            fail_program: Some("<spawn-failure>".to_string()),
            ..FakeRunner::default()
        };
        let err = execute_plan(&plan_uninstall(&p, false), &mut r).unwrap_err();
        assert!(err.to_string().contains("forced spawn failure"));
    }

    #[test]
    fn absent_service_classification_is_narrow_and_fail_closed() {
        let bootout = vec!["bootout".to_string(), "gui/501/com.hydra.agent".to_string()];
        assert!(absent_service_exit(
            "launchctl",
            &bootout,
            "Boot-out failed: 3: No such process"
        ));
        assert!(!absent_service_exit(
            "launchctl",
            &bootout,
            "Boot-out failed: 1: Operation not permitted"
        ));
        assert!(!absent_service_exit(
            "launchctl",
            &["bootstrap".to_string()],
            "No such process"
        ));

        let disable = vec![
            "--user".to_string(),
            "disable".to_string(),
            "--now".to_string(),
            "hydra-agent.service".to_string(),
        ];
        assert!(absent_service_exit(
            "systemctl",
            &disable,
            "Failed to disable unit: Unit file hydra-agent.service does not exist."
        ));
        assert!(!absent_service_exit(
            "systemctl",
            &disable,
            "Failed to connect to bus: Permission denied"
        ));
        assert!(!absent_service_exit("sh", &disable, "service not found"));
    }

    #[cfg(unix)]
    fn sh_args(script: String) -> Vec<String> {
        vec!["-c".to_string(), script]
    }

    #[cfg(unix)]
    fn process_exists(pid: i32) -> bool {
        // SAFETY: signal 0 performs an existence/permission probe only.
        if unsafe { libc::kill(pid, 0) } == 0 {
            return true;
        }
        std::io::Error::last_os_error().kind() == std::io::ErrorKind::PermissionDenied
    }

    #[cfg(unix)]
    #[test]
    fn manager_output_drains_more_than_pipe_capacity_from_both_streams() {
        let stdout_chunk = "O".repeat(1024);
        let stderr_chunk = "E".repeat(1024);
        let script = format!(
            "(i=0; while [ \"$i\" -lt 256 ]; do printf '%s' '{stdout_chunk}'; i=$((i + 1)); done) & \
             (i=0; while [ \"$i\" -lt 256 ]; do printf '%s' '{stderr_chunk}' >&2; i=$((i + 1)); done) & wait"
        );

        let output = manager_output_bounded_with_limits(
            "/bin/sh",
            &sh_args(script),
            std::time::Duration::from_secs(3),
            512 * 1024,
        )
        .unwrap();

        assert!(output.status.success());
        assert_eq!(output.stdout.len(), 256 * 1024);
        assert_eq!(output.stderr.len(), 256 * 1024);
        assert!(output.stdout.iter().all(|byte| *byte == b'O'));
        assert!(output.stderr.iter().all(|byte| *byte == b'E'));
    }

    #[cfg(unix)]
    #[test]
    fn manager_output_preserves_exit_status_and_exact_output() {
        let output = manager_output_bounded_with_limits(
            "/bin/sh",
            &sh_args("printf 'stdout'; printf 'stderr' >&2; exit 7".to_string()),
            std::time::Duration::from_secs(1),
            1024,
        )
        .unwrap();

        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"stdout");
        assert_eq!(output.stderr, b"stderr");
    }

    #[cfg(unix)]
    #[test]
    fn manager_output_cap_fails_closed_without_waiting_for_a_blocked_writer() {
        let chunk = "X".repeat(1024);
        let script =
            format!("i=0; while [ \"$i\" -lt 128 ]; do printf '%s' '{chunk}'; i=$((i + 1)); done");
        let started = std::time::Instant::now();
        let error = manager_output_bounded_with_limits(
            "/bin/sh",
            &sh_args(script),
            std::time::Duration::from_secs(2),
            16 * 1024,
        )
        .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("output limit"));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[cfg(unix)]
    #[test]
    fn manager_timeout_kills_and_reaps_the_whole_process_group() {
        let fixture = secure_tempdir("hydra-manager-timeout-");
        let pids_path = fixture.path().join("pids");
        let script = format!(
            "(sleep 30) & background=$!; printf '%s %s' \"$$\" \"$background\" > '{}'; wait",
            pids_path.display()
        );
        let error = manager_output_bounded_with_limits(
            "/bin/sh",
            &sh_args(script),
            std::time::Duration::from_millis(500),
            1024,
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);

        let pids = std::fs::read_to_string(&pids_path)
            .expect("manager and descendant pids must be captured before the timeout");
        let pids = pids
            .split_whitespace()
            .map(|pid| pid.parse::<i32>().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(pids.len(), 2);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while pids.iter().any(|pid| process_exists(*pid)) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert!(
            pids.iter().all(|pid| !process_exists(*pid)),
            "timed-out manager process group left a live process: {pids:?}"
        );
    }

    #[test]
    fn manager_command_public_limits_remain_fixed() {
        assert_eq!(MANAGER_COMMAND_TIMEOUT, std::time::Duration::from_secs(5));
        assert_eq!(MANAGER_STREAM_OUTPUT_LIMIT_BYTES, 1024 * 1024);
    }

    #[test]
    fn atomic_write_leaves_only_the_final_file() {
        let dir = std::env::temp_dir().join(format!("svc-atomic-{}", std::process::id()));
        crate::agent_dir::ensure_owned_safe_directory(&dir).unwrap();
        let target = dir.join("com.hydra.agent.plist");
        atomic_write(&target, "hello plist").unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "hello plist");
        // no leftover temp files
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "atomic_write left a temp file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn human_summary_has_no_secrets() {
        let p = tmp_paths("summary");
        let s = human_summary(&plan_install(&p, &plist_opts(&p))).to_lowercase();
        for bad in ["token", "secret", "private", "bearer", "password"] {
            assert!(!s.contains(bad));
        }
        assert!(s.contains("applying"));
    }

    #[test]
    fn cleanup_attempts_later_actions_after_a_manager_failure() {
        let p = tmp_paths("cleanup-continues");
        std::fs::create_dir_all(&p.launch_agents_dir).unwrap();
        std::fs::write(p.plist_path(), "old definition").unwrap();
        let mut runner = FakeRunner {
            fail_program: Some("<spawn-failure>".to_string()),
            ..FakeRunner::default()
        };
        let (_log, errors) = execute_cleanup_plan(&plan_uninstall(&p, false), &mut runner);
        assert_eq!(errors.len(), 1);
        assert!(
            !p.plist_path().exists(),
            "definition removal must still run"
        );
        let _ = std::fs::remove_dir_all(p.launch_agents_dir.parent().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_lock_returns_busy_without_hanging_and_recovers_after_release() {
        let root = secure_tempdir("hydra-lifecycle-lock-");
        let dir = root.path().join("hydra-agent");
        let first = LifecycleLock::acquire(&dir).unwrap();
        let busy = LifecycleLock::acquire(&dir)
            .err()
            .expect("second lifecycle lock should be busy");
        assert_eq!(busy.kind(), std::io::ErrorKind::WouldBlock);
        assert!(is_lifecycle_lock_contention(&busy));
        assert!(!is_lifecycle_lock_contention(&std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "synthetic non-lock I/O refusal",
        )));
        drop(first);
        let next = LifecycleLock::acquire(&dir).unwrap();
        drop(next);
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_lock_set_sorts_deduplicates_and_releases_partial_acquisition_on_busy() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = secure_tempdir("hydra-lifecycle-lock-set-");
        let first = root.path().join("a/hydra-agent");
        let second = root.path().join("b/hydra-agent");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        for directory in [
            first.parent().unwrap(),
            second.parent().unwrap(),
            &first,
            &second,
        ] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let held_second = LifecycleLock::acquire(&second).unwrap();

        let busy = LifecycleLockSet::acquire(vec![second.clone(), first.clone(), first.clone()])
            .err()
            .expect("held second root must make the set busy");
        assert_eq!(busy.kind(), std::io::ErrorKind::WouldBlock);
        let first_after_partial = LifecycleLock::acquire(&first)
            .expect("failed set must release its earlier first-root lock");
        drop(first_after_partial);
        drop(held_second);

        let set =
            LifecycleLockSet::acquire(vec![second.clone(), first.clone(), first.clone()]).unwrap();
        assert_eq!(
            set.roots().map(Path::to_path_buf).collect::<Vec<_>>(),
            vec![
                std::fs::canonicalize(&first).unwrap(),
                std::fs::canonicalize(&second).unwrap(),
            ]
        );
        assert!(set.require_agent_dir(&first).is_ok());
        assert!(set.require_agent_dir(&second).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_lock_rejects_a_safe_same_uid_root_replacement() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = secure_tempdir("hydra-lifecycle-lock-replace-");
        let root = std::fs::canonicalize(root.path()).unwrap();
        let agent = root.join("hydra-agent");
        std::fs::create_dir(&agent).unwrap();
        std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let lock = LifecycleLock::acquire(&agent).unwrap();

        let displaced = root.join("hydra-agent-displaced");
        std::fs::rename(&agent, &displaced).unwrap();
        std::fs::create_dir(&agent).unwrap();
        std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o700)).unwrap();

        let error = lock.require_agent_dir(&agent).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("replaced"));
        drop(lock);
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_lock_set_rejects_noncanonical_textual_root_aliases() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(root.path()).unwrap();
        let agent = root.join("hydra-agent");
        std::fs::create_dir(&agent).unwrap();
        std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let aliases = [
            PathBuf::from(format!("{}/", agent.display())),
            PathBuf::from(format!("{}/./", agent.display())),
            PathBuf::from(format!("{}//", agent.display())),
            root.join("hydra-agent/../hydra-agent"),
        ];
        for alias in aliases {
            let error = LifecycleLockSet::acquire(vec![alias])
                .err()
                .expect("textual alias must fail before canonicalization");
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        }
        assert!(!agent.join("lifecycle.lock").exists());
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_lock_rejects_symlink_permissive_and_hardlinked_files() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let root = tempfile::tempdir().unwrap();
        let agent = root.path().join("hydra-agent");
        std::fs::create_dir(&agent).unwrap();
        std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let lock_path = agent.join("lifecycle.lock");
        let outside = root.path().join("outside");
        std::fs::write(&outside, b"").unwrap();
        symlink(&outside, &lock_path).unwrap();
        assert!(LifecycleLock::acquire(&agent).is_err());

        std::fs::remove_file(&lock_path).unwrap();
        std::fs::write(&lock_path, b"").unwrap();
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(LifecycleLock::acquire(&agent).is_err());

        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&lock_path, agent.join("lock-alias")).unwrap();
        assert!(LifecycleLock::acquire(&agent).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn lifecycle_lock_rejects_unsupported_group_writable_root_before_creating_lock_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let agent = root.path().join("hydra-agent");
        std::fs::create_dir(&agent).unwrap();
        std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o760)).unwrap();

        let error = LifecycleLock::acquire(&agent)
            .err()
            .expect("group-writable lifecycle authority must be rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            !agent.join("lifecycle.lock").exists(),
            "unsafe authority root must be rejected before lock-file mutation"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ambient_umask_0002_production_publishers_create_deterministic_modes() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        const CHILD: &str = "HYDRA_TEST_PRODUCTION_PUBLISHERS_UMASK_0002";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "service::tests::ambient_umask_0002_production_publishers_create_deterministic_modes",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .expect("spawn isolated production publisher umask proof");
            assert!(status.success(), "isolated umask proof failed: {status}");
            return;
        }

        // Process-global umask changes are safe only in this isolated child.
        unsafe { libc::umask(0o002) };
        let fixture = secure_tempdir("hydra-production-publishers-");
        let state = fixture.path().join("state");
        std::fs::create_dir(&state).unwrap();
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let agent = state.join("hydra-agent");
        assert!(!agent.exists());

        let lock = LifecycleLock::acquire(&agent).unwrap();
        drop(lock);
        let _key = crate::device_identity::load_or_create_key(&agent).unwrap();
        let record = crate::device_identity::DeviceRecord {
            device_id: "dev_synthetic_umask".into(),
            account_id: "acct_synthetic_umask".into(),
            cloud_base: "https://example.invalid".into(),
            passkey: None,
        };
        crate::device_identity::save_record(&agent, &record).unwrap();
        let loaded = crate::device_identity::load_record(&agent)
            .unwrap()
            .expect("saved synthetic enrollment");
        assert_eq!(loaded.device_id, record.device_id);
        assert_eq!(loaded.account_id, record.account_id);
        assert_eq!(loaded.cloud_base, record.cloud_base);
        assert_eq!(loaded.passkey, record.passkey);

        let request = crate::service_readiness::ServiceReadinessRequest::new(
            101,
            fixture.path().join("hydra.sock"),
            "git=synthetic built=1".to_string(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            1_000,
        );
        crate::service_readiness::write_service_readiness_request(&agent, &request).unwrap();
        assert_eq!(
            crate::service_readiness::load_service_readiness_request(&agent).unwrap(),
            Some(request)
        );

        let service_dir = fixture.path().join("config/systemd/user");
        let service_file = service_dir.join("hydra-agent.service");
        let mut runner = SystemRunner;
        runner.create_dir(&service_dir).unwrap();
        runner
            .write_file(&service_file, "[Unit]\nDescription=Hydra\n")
            .unwrap();

        for directory in [&agent, &service_dir] {
            let metadata = std::fs::symlink_metadata(directory).unwrap();
            assert_eq!(metadata.uid(), crate::agent_dir::trusted_uid());
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        }
        for file in [
            agent.join("lifecycle.lock"),
            agent.join("device-key"),
            agent.join("device.json"),
            agent.join("device-owner.json"),
            agent.join("service-readiness.lock"),
            agent.join(crate::service_readiness::SERVICE_READINESS_REQUEST_FILE),
        ] {
            let metadata = std::fs::symlink_metadata(&file).unwrap();
            assert_eq!(metadata.uid(), crate::agent_dir::trusted_uid());
            assert_eq!(
                metadata.permissions().mode() & 0o777,
                0o600,
                "unexpected private mode for {}",
                file.display()
            );
        }
        let service_metadata = std::fs::symlink_metadata(&service_file).unwrap();
        assert_eq!(service_metadata.uid(), crate::agent_dir::trusted_uid());
        assert_eq!(service_metadata.permissions().mode() & 0o777, 0o644);
        assert_eq!(
            std::fs::read_to_string(service_file).unwrap(),
            "[Unit]\nDescription=Hydra\n"
        );
    }

    #[cfg(unix)]
    #[test]
    fn ambient_umask_0077_service_and_plist_publish_are_deterministic() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        const CHILD: &str = "HYDRA_TEST_SERVICE_PUBLISH_UMASK_0077";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "service::tests::ambient_umask_0077_service_and_plist_publish_are_deterministic",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .expect("spawn isolated restrictive-umask publisher proof");
            assert!(status.success(), "isolated umask proof failed: {status}");
            return;
        }

        // Process-global umask changes are safe only in this isolated child.
        unsafe { libc::umask(0o077) };
        let fixture = tempfile::tempdir().unwrap();
        let mut runner = SystemRunner;
        for (directory, name, contents) in [
            (
                fixture.path().join("config/systemd/user"),
                "hydra-agent.service",
                "[Unit]\nDescription=Hydra\n",
            ),
            (
                fixture.path().join("Library/LaunchAgents"),
                "com.hydra.agent.plist",
                "<?xml version=\"1.0\"?><plist></plist>\n",
            ),
        ] {
            runner.create_dir(&directory).unwrap();
            let target = directory.join(name);
            runner.write_file(&target, contents).unwrap();
            let directory_metadata = std::fs::symlink_metadata(&directory).unwrap();
            assert_eq!(directory_metadata.uid(), crate::agent_dir::trusted_uid());
            assert_eq!(directory_metadata.permissions().mode() & 0o777, 0o700);
            let metadata = std::fs::symlink_metadata(&target).unwrap();
            assert_eq!(metadata.uid(), crate::agent_dir::trusted_uid());
            assert_eq!(metadata.permissions().mode() & 0o777, 0o644);
            assert_eq!(std::fs::read_to_string(target).unwrap(), contents);
        }
    }

    #[cfg(unix)]
    #[test]
    fn legacy_0660_and_0664_service_predecessors_fail_without_mutation() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let fixture = tempfile::tempdir().unwrap();
        for mode in [0o660, 0o664] {
            for (directory, name) in [
                (
                    fixture.path().join(format!("{mode:o}/config/systemd/user")),
                    "hydra-agent.service",
                ),
                (
                    fixture
                        .path()
                        .join(format!("{mode:o}/Library/LaunchAgents")),
                    "com.hydra.agent.plist",
                ),
            ] {
                std::fs::create_dir_all(&directory).unwrap();
                std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))
                    .unwrap();
                let target = directory.join(name);
                std::fs::write(&target, b"untrusted historical definition").unwrap();
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)).unwrap();

                let before = std::fs::symlink_metadata(&target).unwrap();
                assert!(atomic_write(&target, "reviewed replacement\n").is_err());
                let after = std::fs::symlink_metadata(&target).unwrap();
                assert_eq!(after.ino(), before.ino());
                assert_eq!(after.permissions().mode() & 0o777, mode);
                assert_eq!(
                    std::fs::read(&target).unwrap(),
                    b"untrusted historical definition"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn already_safe_service_definition_modes_are_accepted_without_rewrite() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let fixture = tempfile::tempdir().unwrap();
        let directory = fixture.path().join("config/systemd/user");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        for mode in [0o600, 0o640, 0o644] {
            let target = directory.join("hydra-agent.service");
            std::fs::write(&target, format!("safe-{mode:o}")).unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(mode)).unwrap();
            let before = std::fs::symlink_metadata(&target).unwrap();

            validate_existing_service_definition(&target).unwrap();

            let after = std::fs::symlink_metadata(&target).unwrap();
            assert_eq!(after.dev(), before.dev());
            assert_eq!(after.ino(), before.ino());
            assert_eq!(after.permissions().mode() & 0o777, mode);
            std::fs::remove_file(target).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn pre_provenance_service_mode_validation_is_observe_only_and_refuses() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let fixture = tempfile::tempdir().unwrap();
        for (relative_directory, file_name) in [
            ("config/systemd/user", "hydra-agent.service"),
            ("Library/LaunchAgents", "com.hydra.agent.plist"),
        ] {
            let directory = fixture.path().join(relative_directory);
            std::fs::create_dir_all(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
            for legacy_mode in [0o660, 0o664] {
                let target = directory.join(file_name);
                let bytes =
                    format!("synthetic historical definition {legacy_mode:o}\n").into_bytes();
                std::fs::write(&target, &bytes).unwrap();
                std::fs::set_permissions(&target, std::fs::Permissions::from_mode(legacy_mode))
                    .unwrap();
                let before = std::fs::symlink_metadata(&target).unwrap();

                assert!(
                    validate_existing_service_definition_for_home(&target, fixture.path()).is_err()
                );

                let after = std::fs::symlink_metadata(&target).unwrap();
                assert_eq!(after.dev(), before.dev());
                assert_eq!(after.ino(), before.ino());
                assert_eq!(after.permissions().mode() & 0o777, legacy_mode);
                assert_eq!(std::fs::read(&target).unwrap(), bytes);
                std::fs::remove_file(target).unwrap();
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn default_systemd_group_writable_ancestry_is_refused_without_mutation() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let fixture = tempfile::tempdir().unwrap();
        let home = fixture.path().join("home");
        let config = home.join(".config");
        let systemd = config.join("systemd");
        let unit_dir = systemd.join("user");
        std::fs::create_dir(&home).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();

        let cases = [
            [0o770, 0o770, 0o770],
            [0o750, 0o770, 0o750],
            [0o755, 0o755, 0o775],
        ];
        for legacy_modes in cases {
            std::fs::create_dir_all(&unit_dir).unwrap();
            for (directory, mode) in [&config, &systemd, &unit_dir].into_iter().zip(legacy_modes) {
                std::fs::set_permissions(directory, std::fs::Permissions::from_mode(mode)).unwrap();
            }
            let ancestry_before = [&config, &systemd, &unit_dir]
                .map(|directory| std::fs::symlink_metadata(directory).unwrap());
            let unit = unit_dir.join("hydra-agent.service");
            let bytes = b"already-safe unit from a prior interrupted normalization\n";
            std::fs::write(&unit, bytes).unwrap();
            std::fs::set_permissions(&unit, std::fs::Permissions::from_mode(0o644)).unwrap();
            let before = std::fs::symlink_metadata(&unit).unwrap();

            assert!(validate_existing_service_definition_for_home(&unit, &home).is_err());

            let after = std::fs::symlink_metadata(&unit).unwrap();
            assert_eq!(after.dev(), before.dev());
            assert_eq!(after.ino(), before.ino());
            assert_eq!(after.permissions().mode() & 0o777, 0o644);
            assert_eq!(std::fs::read(&unit).unwrap(), bytes);
            for ((directory, before), legacy_mode) in [&config, &systemd, &unit_dir]
                .into_iter()
                .zip(ancestry_before.iter())
                .zip(legacy_modes)
            {
                let after = std::fs::symlink_metadata(directory).unwrap();
                let actual = after.permissions().mode() & 0o777;
                assert_eq!(actual, legacy_mode);
                assert_eq!(after.dev(), before.dev());
                assert_eq!(after.ino(), before.ino());
            }
            std::fs::remove_file(unit).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn default_systemd_install_creates_absent_ancestry_but_never_chmods_unproven_legacy_dirs() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let fixture = tempfile::tempdir().unwrap();

        let fresh_home = fixture.path().join("fresh-home");
        std::fs::create_dir(&fresh_home).unwrap();
        std::fs::set_permissions(&fresh_home, std::fs::Permissions::from_mode(0o700)).unwrap();
        let fresh_unit_dir = fresh_home.join(".config/systemd/user");
        ensure_owned_safe_shared_service_directory_for_home(&fresh_unit_dir, &fresh_home).unwrap();
        for directory in test_systemd_ancestry(&fresh_home) {
            let metadata = std::fs::symlink_metadata(directory).unwrap();
            assert_eq!(metadata.uid(), crate::agent_dir::trusted_uid());
            assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        }

        for (name, legacy_component) in [("legacy-config", 0usize), ("legacy-systemd", 1usize)] {
            let home = fixture.path().join(name);
            let ancestry = test_systemd_ancestry(&home);
            std::fs::create_dir(&home).unwrap();
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::create_dir_all(&ancestry[2]).unwrap();
            for directory in &ancestry {
                std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
            std::fs::set_permissions(
                &ancestry[legacy_component],
                std::fs::Permissions::from_mode(0o775),
            )
            .unwrap();
            let before = ancestry
                .each_ref()
                .map(|directory| std::fs::symlink_metadata(directory).unwrap());

            let error = ensure_owned_safe_shared_service_directory_for_home(&ancestry[2], &home)
                .expect_err("unproven group-writable service ancestry must fail closed");
            assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
            assert!(!ancestry[2].join("hydra-agent.service").exists());
            for (directory, before) in ancestry.iter().zip(before.iter()) {
                let after = std::fs::symlink_metadata(directory).unwrap();
                assert_eq!(after.dev(), before.dev());
                assert_eq!(after.ino(), before.ino());
                assert_eq!(
                    after.permissions().mode() & 0o777,
                    before.permissions().mode() & 0o777,
                    "an absent unit cannot authorize shared-ancestry chmod"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn existing_fixed_unit_does_not_authorize_shared_ancestry_or_mode_changes() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let fixture = tempfile::tempdir().unwrap();
        let home = fixture.path().join("home");
        let ancestry = test_systemd_ancestry(&home);
        std::fs::create_dir(&home).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::create_dir_all(&ancestry[2]).unwrap();
        for directory in &ancestry {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o775)).unwrap();
        }
        let unit = ancestry[2].join("hydra-agent.service");
        std::fs::write(&unit, b"historical fixed unit").unwrap();
        std::fs::set_permissions(&unit, std::fs::Permissions::from_mode(0o664)).unwrap();
        let ancestry_before = ancestry
            .each_ref()
            .map(|directory| std::fs::symlink_metadata(directory).unwrap());
        let unit_before = std::fs::symlink_metadata(&unit).unwrap();

        assert!(atomic_write_for_home(&unit, "reviewed replacement\n", &home).is_err());

        for (directory, before) in ancestry.iter().zip(ancestry_before.iter()) {
            let after = std::fs::symlink_metadata(directory).unwrap();
            assert_eq!(after.dev(), before.dev());
            assert_eq!(after.ino(), before.ino());
            assert_eq!(
                after.permissions().mode() & 0o777,
                before.permissions().mode() & 0o777
            );
        }
        let unit_after = std::fs::symlink_metadata(&unit).unwrap();
        assert_eq!(unit_after.ino(), unit_before.ino());
        assert_eq!(std::fs::read(&unit).unwrap(), b"historical fixed unit");
        assert_eq!(unit_after.permissions().mode() & 0o777, 0o664);
    }

    #[cfg(unix)]
    #[test]
    fn default_systemd_ancestry_validation_rejects_unsafe_shapes_without_mutation() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let fixture = tempfile::tempdir().unwrap();

        let world_home = fixture.path().join("world-home");
        let world_config = world_home.join(".config");
        let world_unit_dir = world_config.join("systemd/user");
        std::fs::create_dir_all(&world_unit_dir).unwrap();
        std::fs::set_permissions(&world_home, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&world_config, std::fs::Permissions::from_mode(0o777)).unwrap();
        let world_unit = world_unit_dir.join("hydra-agent.service");
        std::fs::write(&world_unit, b"malformed historical unit").unwrap();
        std::fs::set_permissions(&world_unit, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(validate_existing_service_definition_for_home(&world_unit, &world_home).is_err());
        assert_eq!(
            std::fs::symlink_metadata(&world_unit)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o664
        );

        let symlink_home = fixture.path().join("symlink-home");
        let real_config = fixture.path().join("real-config");
        let real_unit_dir = real_config.join("systemd/user");
        std::fs::create_dir_all(&real_unit_dir).unwrap();
        std::fs::create_dir(&symlink_home).unwrap();
        std::fs::set_permissions(&symlink_home, std::fs::Permissions::from_mode(0o700)).unwrap();
        symlink(&real_config, symlink_home.join(".config")).unwrap();
        let symlink_unit = symlink_home.join(".config/systemd/user/hydra-agent.service");
        std::fs::write(&symlink_unit, b"malformed").unwrap();
        std::fs::set_permissions(&symlink_unit, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(
            validate_existing_service_definition_for_home(&symlink_unit, &symlink_home).is_err()
        );

        let wrong_home = fixture.path().join("wrong-owner-home");
        let wrong_unit_dir = wrong_home.join(".config/systemd/user");
        std::fs::create_dir_all(&wrong_unit_dir).unwrap();
        std::fs::set_permissions(&wrong_home, std::fs::Permissions::from_mode(0o700)).unwrap();
        let wrong_unit = wrong_unit_dir.join("hydra-agent.service");
        std::fs::write(&wrong_unit, b"malformed").unwrap();
        std::fs::set_permissions(&wrong_unit, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(validate_existing_service_definition_for_home_and_uid(
            &wrong_unit,
            &wrong_home,
            crate::agent_dir::trusted_uid().wrapping_add(1),
        )
        .is_err());
        assert_eq!(
            std::fs::symlink_metadata(wrong_unit)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o664
        );
    }

    #[cfg(unix)]
    #[test]
    fn legacy_service_validation_rejects_symlink_hardlink_0666_and_unsafe_parent() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let fixture = tempfile::tempdir().unwrap();

        let symlink_dir = fixture.path().join("symlink/systemd/user");
        std::fs::create_dir_all(&symlink_dir).unwrap();
        std::fs::set_permissions(&symlink_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let outside = fixture.path().join("outside");
        std::fs::write(&outside, b"outside").unwrap();
        let symlink_path = symlink_dir.join("hydra-agent.service");
        symlink(&outside, &symlink_path).unwrap();
        assert!(atomic_write(&symlink_path, "replacement").is_err());
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside");

        let hardlink_dir = fixture.path().join("hardlink/systemd/user");
        std::fs::create_dir_all(&hardlink_dir).unwrap();
        std::fs::set_permissions(&hardlink_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let hardlink_path = hardlink_dir.join("hydra-agent.service");
        std::fs::write(&hardlink_path, b"historical").unwrap();
        std::fs::set_permissions(&hardlink_path, std::fs::Permissions::from_mode(0o664)).unwrap();
        std::fs::hard_link(&hardlink_path, hardlink_dir.join("alias")).unwrap();
        assert!(atomic_write(&hardlink_path, "replacement").is_err());

        let unknown_dir = fixture.path().join("unknown");
        std::fs::create_dir(&unknown_dir).unwrap();
        std::fs::set_permissions(&unknown_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let unknown_path = unknown_dir.join("hydra-agent.service");
        std::fs::write(&unknown_path, b"historical").unwrap();
        std::fs::set_permissions(&unknown_path, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(atomic_write(&unknown_path, "replacement").is_err());

        let world_dir = fixture.path().join("world/systemd/user");
        std::fs::create_dir_all(&world_dir).unwrap();
        std::fs::set_permissions(&world_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let world_path = world_dir.join("hydra-agent.service");
        std::fs::write(&world_path, b"historical").unwrap();
        std::fs::set_permissions(&world_path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(validate_existing_service_definition(&world_path).is_err());
        assert_eq!(
            std::fs::symlink_metadata(&world_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o666
        );

        let unsafe_dir = fixture.path().join("unsafe/systemd/user");
        std::fs::create_dir_all(&unsafe_dir).unwrap();
        std::fs::set_permissions(&unsafe_dir, std::fs::Permissions::from_mode(0o775)).unwrap();
        let unsafe_path = unsafe_dir.join("hydra-agent.service");
        std::fs::write(&unsafe_path, b"historical").unwrap();
        std::fs::set_permissions(&unsafe_path, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(atomic_write(&unsafe_path, "replacement").is_err());
        assert_eq!(std::fs::read(&unsafe_path).unwrap(), b"historical");
        assert_eq!(
            std::fs::symlink_metadata(&unsafe_dir)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o775,
            "custom shared ancestry must never be chmod'd"
        );
    }
}
