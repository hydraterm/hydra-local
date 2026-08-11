//! Native macOS bundle entrypoint for Hydra.
//!
//! Finder and LaunchServices inspect `CFBundleExecutable` to select a native slice. A shell script
//! at that path hides the architectures of the real app and can make an Apple Silicon launch run
//! the x86_64 slice under Rosetta. This small Mach-O launcher keeps the package policy outside the
//! product binary while preserving the historical launcher argv, log, socket, and self-test rules.

use std::env;
use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const APP_BINARY: &str = "maestro-app";
const DAEMON_BINARY: &str = "pty-daemon";
const SELF_TEST_SOCKET_ENV: &str = "HYDRA_SELF_TEST_SOCKET";
const SELF_TEST_BASE_ENV: &str = "HYDRA_SELF_TEST_BASE";
const LOG_DIR_MODE: u32 = 0o700;
const LOG_FILE_MODE: u32 = 0o600;
const MAX_LAUNCH_LOG_FILES: usize = 10;

const FIXED_LAUNCH_ARGS: &[&str] = &[
    "launch",
    "--top-tab-bar",
    "--no-dashboard-panel",
    "--new-tab-default-shell",
    "--product-startup",
    "--title",
    "Hydra",
];

#[derive(Debug, PartialEq, Eq)]
struct LaunchPlan {
    app_binary: PathBuf,
    daemon_binary: PathBuf,
    socket_path: PathBuf,
    self_test_base: Option<PathBuf>,
    keep_daemon: bool,
    forwarded_args: Vec<OsString>,
}

impl LaunchPlan {
    fn command_args(&self) -> Vec<OsString> {
        let mut args = FIXED_LAUNCH_ARGS
            .iter()
            .map(OsString::from)
            .collect::<Vec<_>>();
        args.push(OsString::from("--socket"));
        args.push(self.socket_path.as_os_str().to_owned());
        args.push(OsString::from("--daemon"));
        args.push(self.daemon_binary.as_os_str().to_owned());
        if let Some(base) = self.self_test_base.as_ref() {
            args.push(OsString::from("--base"));
            args.push(base.as_os_str().to_owned());
        }
        if self.keep_daemon {
            args.push(OsString::from("--keep-daemon"));
        }
        args.extend(self.forwarded_args.iter().cloned());
        args
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Hydra launcher failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> io::Result<()> {
    let current_exe = env::current_exe()?;
    let forwarded_args = env::args_os().skip(1).collect();
    let plan = build_launch_plan(
        &current_exe,
        |key| env::var_os(key),
        unsafe { libc::geteuid() },
        forwarded_args,
    )?;

    let mut log = open_log_file(|key| env::var_os(key))?;
    writeln!(
        log,
        "=== Hydra launch {} ===",
        local_timestamp("%a %b %e %T %Z %Y")?
    )?;
    writeln!(
        log,
        "hydra-launcher architecture={} translated={}",
        launcher_architecture(),
        process_is_translated()
    )?;
    log.flush()?;

    let stdout = log.try_clone()?;
    let error = Command::new(&plan.app_binary)
        .args(plan.command_args())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(log))
        .exec();
    Err(error)
}

fn build_launch_plan(
    current_exe: &Path,
    get_env: impl Fn(&str) -> Option<OsString>,
    effective_uid: u32,
    forwarded_args: Vec<OsString>,
) -> io::Result<LaunchPlan> {
    let macos_dir = current_exe.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "launcher has no parent directory",
        )
    })?;
    let contents_dir = macos_dir.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "launcher is not inside an application Contents directory",
        )
    })?;
    let bin_dir = contents_dir.join("Resources").join("bin");

    let self_test_socket = non_empty_env(&get_env, SELF_TEST_SOCKET_ENV).map(PathBuf::from);
    let self_test_base = non_empty_env(&get_env, SELF_TEST_BASE_ENV).map(PathBuf::from);
    if self_test_socket.is_some() != self_test_base.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HYDRA_SELF_TEST_SOCKET and HYDRA_SELF_TEST_BASE must be set together",
        ));
    }
    let socket_path = self_test_socket.clone().unwrap_or_else(|| {
        runtime_dir(&get_env).join(maestro_protocol::daemon_socket_filename(effective_uid))
    });

    Ok(LaunchPlan {
        app_binary: bin_dir.join(APP_BINARY),
        daemon_binary: bin_dir.join(DAEMON_BINARY),
        socket_path,
        self_test_base,
        keep_daemon: self_test_socket.is_none(),
        forwarded_args,
    })
}

fn runtime_dir(get_env: &impl Fn(&str) -> Option<OsString>) -> PathBuf {
    non_empty_env(get_env, "XDG_RUNTIME_DIR")
        .or_else(|| non_empty_env(get_env, "TMPDIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"))
}

fn non_empty_env(get_env: &impl Fn(&str) -> Option<OsString>, key: &str) -> Option<OsString> {
    get_env(key).filter(|value| !value.is_empty())
}

fn open_log_file(get_env: impl Fn(&str) -> Option<OsString>) -> io::Result<File> {
    let home = non_empty_env(&get_env, "HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
    let timestamp = local_timestamp("%Y%m%d-%H%M%S")?;
    open_log_file_at(&home, &timestamp)
}

fn open_log_file_at(home: &Path, timestamp: &str) -> io::Result<File> {
    let log_dir = home.join("Library").join("Logs").join("Hydra");
    let mut builder = DirBuilder::new();
    builder.recursive(true).mode(LOG_DIR_MODE);
    builder.create(&log_dir)?;

    let directory = fs::symlink_metadata(&log_dir)?;
    if !directory.file_type().is_dir() || directory.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Hydra log directory is not a current-user-owned directory",
        ));
    }
    fs::set_permissions(&log_dir, fs::Permissions::from_mode(LOG_DIR_MODE))?;

    let log_path = log_dir.join(format!("Hydra-{timestamp}.log"));
    let mut options = OpenOptions::new();
    options
        .create(true)
        .append(true)
        .mode(LOG_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(&log_path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Hydra launch log is not a current-user-owned regular file",
        ));
    }
    file.set_permissions(fs::Permissions::from_mode(LOG_FILE_MODE))?;

    if let Err(error) = prune_managed_logs(&log_dir, &log_path) {
        let _ = writeln!(file, "Hydra log retention warning: {error}");
    }
    Ok(file)
}

fn prune_managed_logs(log_dir: &Path, current: &Path) -> io::Result<()> {
    let mut managed = Vec::new();
    for entry in fs::read_dir(log_dir)? {
        let entry = entry?;
        if !is_managed_log_name(&entry.file_name()) || !entry.file_type()?.is_file() {
            continue;
        }
        let metadata = entry.metadata()?;
        if metadata.uid() == unsafe { libc::geteuid() } && metadata.nlink() == 1 {
            managed.push(entry.path());
        }
    }
    managed.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
    while managed.len() > MAX_LAUNCH_LOG_FILES {
        let Some(index) = managed.iter().position(|path| path != current) else {
            break;
        };
        let oldest = managed.remove(index);
        fs::remove_file(oldest)?;
    }
    Ok(())
}

fn is_managed_log_name(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let bytes = name.as_bytes();
    bytes.len() == 25
        && bytes.starts_with(b"Hydra-")
        && bytes[6..14].iter().all(u8::is_ascii_digit)
        && bytes[14] == b'-'
        && bytes[15..21].iter().all(u8::is_ascii_digit)
        && &bytes[21..] == b".log"
}

fn local_timestamp(format: &str) -> io::Result<String> {
    let format = std::ffi::CString::new(format)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid time format"))?;
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    if now == -1 {
        return Err(io::Error::last_os_error());
    }

    let mut local = std::mem::MaybeUninit::<libc::tm>::uninit();
    if unsafe { libc::localtime_r(&now, local.as_mut_ptr()) }.is_null() {
        return Err(io::Error::last_os_error());
    }
    let local = unsafe { local.assume_init() };
    let mut buffer = [0 as libc::c_char; 128];
    let written =
        unsafe { libc::strftime(buffer.as_mut_ptr(), buffer.len(), format.as_ptr(), &local) };
    if written == 0 {
        return Err(io::Error::other("could not format local time"));
    }
    let bytes = buffer[..written]
        .iter()
        .map(|byte| *byte as u8)
        .collect::<Vec<_>>();
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "formatted time is not UTF-8"))
}

fn launcher_architecture() -> &'static str {
    match env::consts::ARCH {
        "aarch64" => "arm64",
        architecture => architecture,
    }
}

#[cfg(target_os = "macos")]
fn process_is_translated() -> bool {
    let mut translated: libc::c_int = 0;
    let mut size = std::mem::size_of_val(&translated);
    let status = unsafe {
        libc::sysctlbyname(
            c"sysctl.proc_translated".as_ptr(),
            (&mut translated as *mut libc::c_int).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    status == 0 && translated == 1
}

#[cfg(not(target_os = "macos"))]
fn process_is_translated() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::ffi::OsStr;
    use std::io::Read;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEST_HOME: AtomicU64 = AtomicU64::new(0);

    struct TestHome(PathBuf);

    impl TestHome {
        fn new(label: &str) -> Self {
            let sequence = NEXT_TEST_HOME.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "hydra-launcher-{label}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestHome {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn env_lookup(values: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let values = values
            .iter()
            .map(|(key, value)| ((*key).to_string(), OsString::from(value)))
            .collect::<HashMap<_, _>>();
        move |key| values.get(key).cloned()
    }

    #[test]
    fn normal_bundle_launch_preserves_paths_socket_policy_and_args() {
        let plan = build_launch_plan(
            Path::new("/Applications/Hydra.app/Contents/MacOS/Hydra"),
            env_lookup(&[("TMPDIR", "/private/tmp/user/")]),
            501,
            vec![OsString::from("--example")],
        )
        .expect("launch plan");

        assert_eq!(
            plan.app_binary,
            PathBuf::from("/Applications/Hydra.app/Contents/Resources/bin/maestro-app")
        );
        assert_eq!(
            plan.daemon_binary,
            PathBuf::from("/Applications/Hydra.app/Contents/Resources/bin/pty-daemon")
        );
        assert_eq!(
            plan.socket_path,
            PathBuf::from("/private/tmp/user/hydra-maestro-501.sock")
        );
        assert!(plan.keep_daemon);
        assert_eq!(plan.self_test_base, None);
        assert_eq!(
            plan.command_args(),
            FIXED_LAUNCH_ARGS
                .iter()
                .map(OsString::from)
                .chain([
                    OsString::from("--socket"),
                    OsString::from("/private/tmp/user/hydra-maestro-501.sock"),
                    OsString::from("--daemon"),
                    OsString::from("/Applications/Hydra.app/Contents/Resources/bin/pty-daemon"),
                    OsString::from("--keep-daemon"),
                    OsString::from("--example"),
                ])
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn self_test_socket_is_isolated_and_does_not_keep_daemon() {
        let plan = build_launch_plan(
            Path::new("/tmp/Hydra.app/Contents/MacOS/Hydra"),
            env_lookup(&[
                ("HYDRA_SELF_TEST_SOCKET", "/tmp/package-self-test.sock"),
                ("HYDRA_SELF_TEST_BASE", "/tmp/package-self-test-base"),
                ("XDG_RUNTIME_DIR", "/ignored"),
            ]),
            42,
            vec![OsString::from("--no-run-renderer")],
        )
        .expect("launch plan");

        assert_eq!(
            plan.socket_path,
            PathBuf::from("/tmp/package-self-test.sock")
        );
        assert!(!plan.keep_daemon);
        assert_eq!(
            plan.self_test_base,
            Some(PathBuf::from("/tmp/package-self-test-base"))
        );
        assert!(!plan
            .command_args()
            .iter()
            .any(|arg| arg == OsStr::new("--keep-daemon")));
        assert_eq!(
            plan.command_args().last(),
            Some(&OsString::from("--no-run-renderer"))
        );
        assert!(plan.command_args().windows(2).any(|args| {
            args == [
                OsString::from("--base"),
                OsString::from("/tmp/package-self-test-base"),
            ]
        }));
    }

    #[test]
    fn self_test_socket_and_base_are_an_atomic_pair() {
        for values in [
            vec![(SELF_TEST_SOCKET_ENV, "/tmp/self-test.sock")],
            vec![(SELF_TEST_BASE_ENV, "/tmp/self-test-base")],
        ] {
            let error = build_launch_plan(
                Path::new("/tmp/Hydra.app/Contents/MacOS/Hydra"),
                env_lookup(&values),
                42,
                Vec::new(),
            )
            .expect_err("partial self-test isolation must fail closed");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn runtime_directory_matches_shell_launcher_precedence() {
        assert_eq!(
            runtime_dir(&env_lookup(&[
                ("XDG_RUNTIME_DIR", "/run/user/501"),
                ("TMPDIR", "/private/tmp")
            ])),
            PathBuf::from("/run/user/501")
        );
        assert_eq!(
            runtime_dir(&env_lookup(&[
                ("XDG_RUNTIME_DIR", ""),
                ("TMPDIR", "/private/tmp")
            ])),
            PathBuf::from("/private/tmp")
        );
        assert_eq!(runtime_dir(&env_lookup(&[])), PathBuf::from("/tmp"));
    }

    #[test]
    fn launch_logs_are_private_even_when_existing_modes_are_permissive() {
        let home = TestHome::new("private-log");
        let log_dir = home.path().join("Library/Logs/Hydra");
        fs::create_dir_all(&log_dir).unwrap();
        fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o777)).unwrap();
        let path = log_dir.join("Hydra-20260811-120000.log");
        fs::write(&path, b"existing\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();

        drop(open_log_file_at(home.path(), "20260811-120000").unwrap());

        assert_eq!(fs::metadata(&log_dir).unwrap().mode() & 0o777, LOG_DIR_MODE);
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, LOG_FILE_MODE);
    }

    #[test]
    fn launch_log_retention_removes_only_old_exact_managed_files() {
        use std::os::unix::fs::symlink;

        let home = TestHome::new("retention");
        let log_dir = home.path().join("Library/Logs/Hydra");
        fs::create_dir_all(&log_dir).unwrap();
        for second in 0..12 {
            fs::write(
                log_dir.join(format!("Hydra-20260811-1200{second:02}.log")),
                b"old\n",
            )
            .unwrap();
        }
        fs::write(log_dir.join("notes.log"), b"keep\n").unwrap();
        fs::write(log_dir.join("Hydra-not-a-timestamp.log"), b"keep\n").unwrap();
        fs::create_dir(log_dir.join("Hydra-20200101-000000.log")).unwrap();
        symlink(
            log_dir.join("notes.log"),
            log_dir.join("Hydra-20200101-000001.log"),
        )
        .unwrap();

        drop(open_log_file_at(home.path(), "20260811-120012").unwrap());

        let managed_regular = fs::read_dir(&log_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                is_managed_log_name(&entry.file_name())
                    && entry.file_type().is_ok_and(|kind| kind.is_file())
            })
            .count();
        assert_eq!(managed_regular, MAX_LAUNCH_LOG_FILES);
        assert!(log_dir.join("Hydra-20260811-120003.log").exists());
        assert!(!log_dir.join("Hydra-20260811-120002.log").exists());
        assert!(log_dir.join("Hydra-20260811-120012.log").exists());
        assert!(log_dir.join("notes.log").exists());
        assert!(log_dir.join("Hydra-not-a-timestamp.log").exists());
        assert!(log_dir.join("Hydra-20200101-000000.log").is_dir());
        assert!(log_dir.join("Hydra-20200101-000001.log").is_symlink());
    }

    #[test]
    fn same_second_launch_reopens_and_appends_to_one_private_log() {
        let home = TestHome::new("same-second");
        let mut first = open_log_file_at(home.path(), "20260811-120000").unwrap();
        writeln!(first, "first").unwrap();
        drop(first);
        let mut second = open_log_file_at(home.path(), "20260811-120000").unwrap();
        writeln!(second, "second").unwrap();
        drop(second);

        let path = home
            .path()
            .join("Library/Logs/Hydra/Hydra-20260811-120000.log");
        let mut body = String::new();
        File::open(&path)
            .unwrap()
            .read_to_string(&mut body)
            .unwrap();
        assert_eq!(body, "first\nsecond\n");
        assert_eq!(fs::metadata(path).unwrap().mode() & 0o777, LOG_FILE_MODE);
    }
}
