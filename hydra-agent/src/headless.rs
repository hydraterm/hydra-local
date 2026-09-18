//! Headless Linux server setup primitives.
//!
//! The product command is intentionally `hydraterms remote` with no code in argv. The short-lived,
//! account-authorized enrollment code is read by the system password prompt over the controlling TTY and
//! retained only in an owner-owned byte buffer that is cleared on drop. Cloud/origin/verifier authority stays
//! compiled into `hydra-agent`; this module has no runtime trust override.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

pub const DAEMON_UNIT_NAME: &str = "hydra-pty-daemon";
// Ubuntu 22.04 and Debian package these tools under /bin. On merged-/usr systems
// /bin remains the compatibility path, so these fixed spellings cover both layouts.
pub const ASK_PASSWORD_PATH: &str = "/bin/systemd-ask-password";
pub const SYSTEMCTL_PATH: &str = "/bin/systemctl";
pub const LOGINCTL_PATH: &str = "/bin/loginctl";
pub const PS_PATH: &str = "/bin/ps";

/// Serialize the headless-only daemon preflight with enrollment/service convergence. The existing lifecycle
/// lock is acquired later by the established desktop lifecycle engine; using a distinct lock avoids recursive
/// flock acquisition while still preventing two `hydraterms remote` invocations from consuming two codes.
pub struct SetupLock {
    #[cfg(unix)]
    file: std::fs::File,
}

impl SetupLock {
    pub fn acquire(agent_dir: &Path) -> Result<Self> {
        crate::agent_dir::ensure_owned_safe_authority_directory(agent_dir)
            .context("create or validate Hydra server authority directory")?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;
            use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
            let path = agent_dir.join("headless-setup.lock");
            let file = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path)
                .context("open Hydra server setup lock")?;
            let metadata = file.metadata().context("inspect Hydra server setup lock")?;
            if !metadata.file_type().is_file()
                || metadata.uid() != crate::agent_dir::trusted_uid()
                || metadata.nlink() != 1
                || metadata.permissions().mode() & 0o777 != 0o600
            {
                bail!("Hydra server setup lock has unsafe ownership or permissions")
            }
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                let error = std::io::Error::last_os_error();
                if error
                    .raw_os_error()
                    .is_some_and(|code| code == libc::EWOULDBLOCK || code == libc::EAGAIN)
                {
                    bail!("another Hydra server setup is already running")
                }
                return Err(error).context("lock Hydra server setup");
            }
            Ok(Self { file })
        }
        #[cfg(not(unix))]
        Ok(Self {})
    }
}

#[cfg(unix)]
impl Drop for SetupLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd as _;
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

/// Owner-held enrollment material. Deliberately omits `Debug`, `Display`, and serialization traits.
pub struct EnrollmentCode(Zeroizing<Vec<u8>>);

impl EnrollmentCode {
    pub fn as_str(&self) -> &str {
        // Construction accepts only the ASCII alphabet above.
        std::str::from_utf8(&self.0).expect("validated enrollment code is ASCII")
    }
}

/// Parse exactly the current eight-character, ambiguity-free link-code alphabet. Lowercase paste is
/// normalized locally; no rejected input is ever reflected into an error.
pub fn parse_enrollment_code(mut bytes: Vec<u8>) -> Result<EnrollmentCode> {
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    for byte in &mut bytes {
        *byte = byte.to_ascii_uppercase();
    }
    if bytes.len() != maestro_extension_api::ENROLLMENT_CODE_LENGTH
        || !bytes.iter().all(|byte| {
            maestro_extension_api::ENROLLMENT_CODE_ALPHABET
                .as_bytes()
                .contains(byte)
        })
    {
        bytes.zeroize();
        bail!("invalid enrollment code; use the current eight-character code shown by Hydra")
    }
    Ok(EnrollmentCode(Zeroizing::new(bytes)))
}

/// Read the code through systemd's password UI. The answer is returned on a private pipe, never argv,
/// environment, shell history, a unit definition, or a journal line. `systemd-ask-password` owns terminal echo
/// restoration on its success, cancellation, and timeout paths; setup requires a real controlling TTY before
/// this is called.
pub fn read_enrollment_code() -> Result<EnrollmentCode> {
    #[cfg(not(target_os = "linux"))]
    {
        bail!("headless server enrollment is supported only on Linux")
    }
    #[cfg(target_os = "linux")]
    {
        require_interactive_prompt()?;
        invoke_password_prompt(Path::new(ASK_PASSWORD_PATH))
    }
}

#[cfg(target_os = "linux")]
fn invoke_password_prompt(prompt_path: &Path) -> Result<EnrollmentCode> {
    invoke_password_prompt_with_timeout(prompt_path, 300)
}

#[cfg(target_os = "linux")]
fn invoke_password_prompt_with_timeout(
    prompt_path: &Path,
    timeout_seconds: u64,
) -> Result<EnrollmentCode> {
    let controlling_tty = open_controlling_tty()?;
    let output = std::process::Command::new(prompt_path)
        .arg(format!("--timeout={timeout_seconds}"))
        .arg("--echo=no")
        .arg("Hydra enrollment code:")
        .env_clear()
        // `Command::output` otherwise closes fd 0. Pass the exact controlling TTY
        // reopened at prompt time rather than trusting a redirected inherited fd.
        .stdin(std::process::Stdio::from(controlling_tty))
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .output()
        .context("open hidden enrollment prompt")?;
    let mut answer = output.stdout;
    if !output.status.success() {
        answer.zeroize();
        bail!("enrollment prompt was cancelled or expired")
    }
    if answer.len() > 16 {
        answer.fill(0);
        bail!("enrollment prompt returned an invalid response")
    }
    parse_enrollment_code(answer)
}

/// Accept only the two product spellings and never an argv-carried code or setup override.
pub fn setup_argv_is_valid(args: &[String]) -> bool {
    (args.get(1).map(String::as_str) == Some("remote") && args.len() == 2)
        || (args.get(1).map(String::as_str) == Some("headless")
            && args.get(2).map(String::as_str) == Some("setup")
            && args.len() == 3)
}

/// The retained daemon owns every headless PTY, so its removal deliberately has no short alias and accepts
/// exactly two independent destructive acknowledgements. The executable spelling itself is packaging-owned.
pub fn daemon_remove_argv_is_valid(args: &[String]) -> bool {
    args.len() == 5
        && args.get(1).map(String::as_str) == Some("headless")
        && args.get(2).map(String::as_str) == Some("remove-daemon")
        && args.get(3).map(String::as_str) == Some("--apply")
        && args.get(4).map(String::as_str) == Some("--confirm-session-loss")
}

/// Optional full local-identity reset. Ordinary Remove followed by a fresh-code
/// enrollment can rebind an account without ending retained PTYs; this longer
/// legacy-named operation instead destroys the daemon sessions and stable key,
/// so it requires an additional exact acknowledgement beyond session loss.
pub fn owner_transfer_argv_is_valid(args: &[String]) -> bool {
    args.len() == 6
        && args.get(1).map(String::as_str) == Some("headless")
        && args.get(2).map(String::as_str) == Some("transfer-owner")
        && args.get(3).map(String::as_str) == Some("--apply")
        && args.get(4).map(String::as_str) == Some("--confirm-session-loss")
        && args.get(5).map(String::as_str) == Some("--confirm-cloud-ownership-transfer")
}

pub fn require_interactive_prompt() -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        bail!("headless server enrollment is supported only on Linux")
    }
    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
            bail!("headless enrollment requires an interactive TTY; reconnect with `ssh -t`")
        }
        open_controlling_tty()?;
        validate_root_owned_tool(Path::new(ASK_PASSWORD_PATH), "system password prompt")
    }
}

#[cfg(target_os = "linux")]
fn open_controlling_tty() -> Result<std::fs::File> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{FileTypeExt as _, OpenOptionsExt as _};

    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/dev/tty")
        .map_err(|_| {
            anyhow::anyhow!(
                "headless enrollment requires a controlling TTY; reconnect with `ssh -t`"
            )
        })?;
    let metadata = tty.metadata().map_err(|_| {
        anyhow::anyhow!("headless enrollment requires a controlling TTY; reconnect with `ssh -t`")
    })?;
    if !metadata.file_type().is_char_device() || unsafe { libc::isatty(tty.as_raw_fd()) } != 1 {
        bail!("headless enrollment requires a controlling TTY; reconnect with `ssh -t`")
    }
    Ok(tty)
}

/// One explicit socket shared by the two user services. `/tmp` is deliberate for the first headless slice:
/// it is also the reviewed no-desktop-endpoint fallback used by the existing attach-only agent. The daemon
/// itself refuses live/foreign/ambiguous paths and publishes the final socket owner-only (0600).
pub fn daemon_socket_path(uid: u32) -> PathBuf {
    PathBuf::from("/tmp").join(maestro_protocol::daemon_socket_filename(uid))
}

pub fn server_device_label(hostname: Option<&str>) -> String {
    let hostname = hostname
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("Linux");
    let mut label = format!("{hostname} (server)");
    label.retain(|ch| {
        let value = ch as u32;
        value >= 0x20 && value != 0x7f
    });
    if label.len() > 64 {
        let mut boundary = 64;
        while !label.is_char_boundary(boundary) {
            boundary -= 1;
        }
        label.truncate(boundary);
    }
    label
}

pub fn linger_is_enabled(output: &[u8]) -> Result<bool> {
    if output.len() > 16 {
        bail!("login manager returned an invalid lingering state")
    }
    match std::str::from_utf8(output)
        .context("login manager returned non-UTF-8 lingering state")?
        .trim()
    {
        "yes" => Ok(true),
        "no" => Ok(false),
        _ => bail!("login manager returned an unknown lingering state"),
    }
}

/// Require the persistent user manager before consuming a single-use code. Hydra never invokes sudo or enables
/// lingering on the user's behalf; that is an explicit administrator decision.
pub fn require_linux_user_manager() -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        bail!("headless server enrollment is supported only on Linux")
    }
    #[cfg(target_os = "linux")]
    {
        let manager = crate::service::manager_output_bounded(
            SYSTEMCTL_PATH,
            &[
                "--user".into(),
                "show".into(),
                "default.target".into(),
                "--property=LoadState".into(),
                "--value".into(),
            ],
        )
        .context("query systemd user manager")?;
        if !manager.status.success() || manager.stdout.len() > 32 || manager.stdout != b"loaded\n" {
            bail!("a running systemd user manager is required; reconnect with a normal SSH login and try again")
        }
        Ok(())
    }
}

/// The lifecycle inventory is part of the fail-closed replacement/removal proof. Validate the
/// exact procps binary before enrollment so an absent or PATH-shadowed `ps` cannot consume a code
/// and then strand setup between identity and service activation.
pub fn require_process_inventory_tool() -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        bail!("headless server enrollment is supported only on Linux")
    }
    #[cfg(target_os = "linux")]
    validate_root_owned_tool(Path::new(PS_PATH), "process inventory tool")
}

/// Setup additionally requires lingering before it consumes a single-use code. Removal needs only the live
/// manager and therefore remains possible after an administrator has already disabled lingering.
pub fn require_linux_user_manager_and_linger(uid: u32) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = uid;
        bail!("headless server enrollment is supported only on Linux")
    }
    #[cfg(target_os = "linux")]
    {
        require_linux_user_manager()?;
        let linger = crate::service::manager_output_bounded(
            LOGINCTL_PATH,
            &[
                "show-user".into(),
                uid.to_string(),
                "--property=Linger".into(),
                "--value".into(),
            ],
        )
        .context("query user lingering")?;
        if !linger.status.success() || !linger_is_enabled(&linger.stdout)? {
            bail!(
                "Hydra server access must survive SSH logout. Ask an administrator to run `sudo loginctl enable-linger \"$USER\"`, then run `hydraterms remote` again"
            )
        }
        Ok(())
    }
}

/// Require a fixed package binary rather than accepting an ambient PATH program or caller-selected executable.
/// Root-owned release files and owner-built qualification files are accepted; writable or linked inodes fail.
pub fn validate_package_binary(path: &Path, expected_name: &str) -> Result<()> {
    if !crate::agent_dir::is_canonically_encoded_absolute_path(path)
        || path.file_name().and_then(|name| name.to_str()) != Some(expected_name)
    {
        bail!("Hydra server package has an invalid binary path")
    }
    let metadata =
        std::fs::symlink_metadata(path).context("inspect Hydra server package binary")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let uid = crate::agent_dir::trusted_uid();
        if !metadata.file_type().is_file()
            || (metadata.uid() != 0 && metadata.uid() != uid)
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o111 == 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            bail!("Hydra server package binary has unsafe ownership or permissions")
        }
    }
    #[cfg(not(unix))]
    if !metadata.file_type().is_file() {
        bail!("Hydra server package binary is not a regular file")
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_root_owned_tool(path: &Path, label: &str) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).with_context(|| format!("inspect {label}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
            || metadata.permissions().mode() & 0o111 == 0
        {
            bail!("{label} is unavailable or unsafe")
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    const PROMPT_FIXTURE_ENV: &str = "HYDRA_HEADLESS_PROMPT_FIXTURE";

    #[cfg(target_os = "linux")]
    const NON_TTY_FIXTURE_ENV: &str = "HYDRA_HEADLESS_NON_TTY_FIXTURE";

    #[cfg(target_os = "linux")]
    const PROMPT_FIXTURE_OUTCOME_ENV: &str = "HYDRA_HEADLESS_PROMPT_FIXTURE_OUTCOME";

    #[cfg(target_os = "linux")]
    const REAL_PROMPT_FIXTURE_ENV: &str = "HYDRA_HEADLESS_REAL_PROMPT_FIXTURE";

    #[cfg(target_os = "linux")]
    fn prompt_fixture(script: &str) -> (tempfile::TempDir, PathBuf) {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("systemd-ask-password-fixture");
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        (root, path)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn __hydra_prompt_stdin_fixture_child() {
        use std::os::fd::AsRawFd as _;

        let Some(prompt_path) = std::env::var_os(PROMPT_FIXTURE_ENV) else {
            return;
        };
        assert_ne!(unsafe { libc::setsid() }, -1);
        assert_eq!(
            unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY, 0) },
            0
        );
        assert_eq!(unsafe { libc::isatty(libc::STDIN_FILENO) }, 1);
        let controlling_tty = std::fs::File::open("/dev/tty").unwrap();
        assert_eq!(unsafe { libc::isatty(controlling_tty.as_raw_fd()) }, 1);

        let result = invoke_password_prompt(Path::new(&prompt_path));
        match std::env::var(PROMPT_FIXTURE_OUTCOME_ENV).as_deref() {
            Ok("success") => assert_eq!(result.unwrap().as_str(), "ABCDE234"),
            Ok("failure") => {
                let error = match result {
                    Ok(_) => panic!("a failed prompt fixture returned enrollment material"),
                    Err(error) => error,
                };
                assert_eq!(
                    error.to_string(),
                    "enrollment prompt was cancelled or expired"
                );
                assert!(!error.to_string().contains("ABCDE234"));
            }
            outcome => panic!("unknown prompt fixture outcome: {outcome:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn __hydra_real_prompt_fixture_child() {
        use std::os::fd::AsRawFd as _;

        let Some(outcome) = std::env::var_os(REAL_PROMPT_FIXTURE_ENV) else {
            return;
        };
        assert_ne!(unsafe { libc::setsid() }, -1);
        assert_eq!(
            unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCSCTTY, 0) },
            0
        );
        let controlling_tty = std::fs::File::open("/dev/tty").unwrap();
        assert_eq!(unsafe { libc::isatty(controlling_tty.as_raw_fd()) }, 1);
        eprintln!("real-prompt-ready");
        let result = invoke_password_prompt_with_timeout(Path::new(ASK_PASSWORD_PATH), 1);
        match outcome.to_str() {
            Some("success") => assert_eq!(result.unwrap().as_str(), "ABCDE234"),
            Some("cancel" | "timeout") => {
                let error = match result {
                    Ok(_) => panic!("the real cancelled prompt returned enrollment material"),
                    Err(error) => error,
                };
                assert_eq!(
                    error.to_string(),
                    "enrollment prompt was cancelled or expired"
                );
            }
            outcome => panic!("unknown real prompt fixture outcome: {outcome:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    fn terminal_flags(fd: std::os::fd::RawFd) -> libc::tcflag_t {
        let mut termios = std::mem::MaybeUninit::<libc::termios>::uninit();
        assert_eq!(unsafe { libc::tcgetattr(fd, termios.as_mut_ptr()) }, 0);
        unsafe { termios.assume_init() }.c_lflag
    }

    #[cfg(target_os = "linux")]
    fn read_pty_until(fd: std::os::fd::RawFd, expected: &[u8]) -> Vec<u8> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut transcript = Vec::new();
        while !transcript
            .windows(expected.len())
            .any(|window| window == expected)
        {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for PTY fixture marker; transcript={}",
                String::from_utf8_lossy(&transcript)
            );
            let mut poll = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let polled = unsafe { libc::poll(&mut poll, 1, 100) };
            assert!(
                polled >= 0,
                "poll PTY fixture: {}",
                std::io::Error::last_os_error()
            );
            if polled == 0 {
                continue;
            }
            let mut chunk = [0_u8; 256];
            let read = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
            assert!(
                read > 0,
                "read PTY fixture: {}",
                std::io::Error::last_os_error()
            );
            transcript.extend_from_slice(&chunk[..read as usize]);
        }
        transcript
    }

    #[cfg(target_os = "linux")]
    fn drain_pty(fd: std::os::fd::RawFd, transcript: &mut Vec<u8>) {
        loop {
            let mut poll = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let polled = unsafe { libc::poll(&mut poll, 1, 50) };
            assert!(
                polled >= 0,
                "poll PTY fixture: {}",
                std::io::Error::last_os_error()
            );
            if polled == 0 || poll.revents & libc::POLLIN == 0 {
                break;
            }
            let mut chunk = [0_u8; 256];
            let read = unsafe { libc::read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
            if read <= 0 {
                break;
            }
            transcript.extend_from_slice(&chunk[..read as usize]);
        }
    }

    #[cfg(target_os = "linux")]
    fn run_prompt_fixture(prompt_path: &Path, outcome: &str, input: &[u8]) -> (Vec<u8>, Vec<u8>) {
        use std::io::Write as _;
        use std::os::fd::{AsRawFd as _, FromRawFd as _};

        let mut master_fd = -1;
        let mut slave_fd = -1;
        let opened = unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(opened, 0, "open a credential-free test pseudo-terminal");
        let mut master = unsafe { std::fs::File::from_raw_fd(master_fd) };
        let slave = unsafe { std::fs::File::from_raw_fd(slave_fd) };
        let original_flags = terminal_flags(slave.as_raw_fd());

        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("__hydra_prompt_stdin_fixture_child")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(PROMPT_FIXTURE_ENV, prompt_path)
            .env(PROMPT_FIXTURE_OUTCOME_ENV, outcome)
            .stdin(slave.try_clone().unwrap())
            .stdout(std::process::Stdio::piped())
            .stderr(slave.try_clone().unwrap())
            .spawn()
            .unwrap();
        let mut transcript = read_pty_until(master.as_raw_fd(), b"fixture-ready");
        master.write_all(input).unwrap();
        let output = child.wait_with_output().unwrap();
        drain_pty(master.as_raw_fd(), &mut transcript);
        assert!(
            output.status.success(),
            "TTY inheritance fixture failed: stdout={} transcript={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&transcript)
        );
        assert_eq!(
            terminal_flags(slave.as_raw_fd()) & (libc::ECHO | libc::ICANON),
            original_flags & (libc::ECHO | libc::ICANON),
            "the prompt helper must restore terminal echo and canonical mode"
        );
        (output.stdout, transcript)
    }

    #[cfg(target_os = "linux")]
    fn run_real_prompt_fixture(outcome: &str, input: Option<&[u8]>) -> Vec<u8> {
        use std::io::Write as _;
        use std::os::fd::{AsRawFd as _, FromRawFd as _};

        assert!(Path::new(ASK_PASSWORD_PATH).is_file());
        let mut master_fd = -1;
        let mut slave_fd = -1;
        let opened = unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(opened, 0, "open a real-prompt test pseudo-terminal");
        let mut master = unsafe { std::fs::File::from_raw_fd(master_fd) };
        let slave = unsafe { std::fs::File::from_raw_fd(slave_fd) };
        let original_flags = terminal_flags(slave.as_raw_fd());
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("__hydra_real_prompt_fixture_child")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(REAL_PROMPT_FIXTURE_ENV, outcome)
            .stdin(slave.try_clone().unwrap())
            .stdout(std::process::Stdio::piped())
            .stderr(slave.try_clone().unwrap())
            .spawn()
            .unwrap();
        let mut transcript = read_pty_until(master.as_raw_fd(), b"real-prompt-ready");
        if !transcript
            .windows(b"Hydra enrollment code".len())
            .any(|window| window == b"Hydra enrollment code")
        {
            transcript.extend(read_pty_until(master.as_raw_fd(), b"Hydra enrollment code"));
        }
        if let Some(input) = input {
            master.write_all(input).unwrap();
        }
        let output = child.wait_with_output().unwrap();
        drain_pty(master.as_raw_fd(), &mut transcript);
        assert!(
            output.status.success(),
            "real prompt fixture failed: stdout={} transcript={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&transcript)
        );
        assert_eq!(
            terminal_flags(slave.as_raw_fd()) & (libc::ECHO | libc::ICANON),
            original_flags & (libc::ECHO | libc::ICANON),
            "systemd-ask-password must restore terminal echo and canonical mode"
        );
        transcript
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn real_prompt_success_eot_cancellation_and_timeout_are_private_and_restore_modes() {
        let succeeded = run_real_prompt_fixture("success", Some(b"abcde234\n"));
        let cancelled = run_real_prompt_fixture("cancel", Some(b"\x04"));
        let timed_out = run_real_prompt_fixture("timeout", None);
        for transcript in [succeeded, cancelled, timed_out] {
            assert!(!transcript.windows(8).any(|window| window == b"ABCDE234"));
            assert!(!transcript.windows(8).any(|window| window == b"abcde234"));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn enrollment_prompt_passes_the_controlling_tty_but_captures_only_the_answer() {
        let (_root, prompt_path) = prompt_fixture(
            r#"#!/bin/sh
set -eu
[ -t 0 ]
[ -t 2 ]
[ "$#" -eq 3 ]
[ "$1" = "--timeout=300" ]
[ "$2" = "--echo=no" ]
[ "$3" = "Hydra enrollment code:" ]
[ "${HYDRA_HEADLESS_PROMPT_FIXTURE+x}" != x ]
[ "${HYDRA_HEADLESS_PROMPT_FIXTURE_OUTCOME+x}" != x ]
saved=$(/bin/stty -g </dev/tty)
trap '/bin/stty "$saved" </dev/tty' 0 1 2 15
/bin/stty -echo </dev/tty
printf '%s\n' 'fixture-ready' >&2
IFS= read -r probe </dev/tty
[ "$probe" = "abcde234" ]
printf '%s\n' "$probe"
"#,
        );
        let (output, transcript) = run_prompt_fixture(&prompt_path, "success", b"abcde234\n");
        assert!(!output.windows(8).any(|window| window == b"abcde234"));
        assert!(!output.windows(8).any(|window| window == b"ABCDE234"));
        assert!(!transcript.windows(8).any(|window| window == b"abcde234"));
        assert!(!transcript.windows(8).any(|window| window == b"ABCDE234"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn __hydra_non_tty_fixture_child() {
        match std::env::var(NON_TTY_FIXTURE_ENV).as_deref() {
            Ok("redirected") => {
                let error = require_interactive_prompt().unwrap_err();
                assert_eq!(
                    error.to_string(),
                    "headless enrollment requires an interactive TTY; reconnect with `ssh -t`"
                );
            }
            Ok("no-controlling-tty") => {
                assert_eq!(unsafe { libc::isatty(libc::STDIN_FILENO) }, 1);
                assert_ne!(unsafe { libc::setsid() }, -1);
                let error = require_interactive_prompt().unwrap_err();
                assert_eq!(
                    error.to_string(),
                    "headless enrollment requires a controlling TTY; reconnect with `ssh -t`"
                );
            }
            Err(_) => (),
            outcome => panic!("unknown non-TTY fixture outcome: {outcome:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn enrollment_prompt_fails_closed_before_invoking_a_helper_without_a_tty() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("__hydra_non_tty_fixture_child")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(NON_TTY_FIXTURE_ENV, "redirected")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "non-TTY rejection fixture failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn enrollment_prompt_rejects_a_tty_fd_without_a_controlling_terminal() {
        use std::os::fd::FromRawFd as _;

        let mut master_fd = -1;
        let mut slave_fd = -1;
        let opened = unsafe {
            libc::openpty(
                &mut master_fd,
                &mut slave_fd,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert_eq!(opened, 0, "open a non-controlling test pseudo-terminal");
        let master = unsafe { std::fs::File::from_raw_fd(master_fd) };
        let slave = unsafe { std::fs::File::from_raw_fd(slave_fd) };
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("__hydra_non_tty_fixture_child")
            .arg("--nocapture")
            .arg("--test-threads=1")
            .env(NON_TTY_FIXTURE_ENV, "no-controlling-tty")
            .stdin(slave)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .unwrap();
        drop(master);
        assert!(
            output.status.success(),
            "controlling-TTY rejection fixture failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn enrollment_prompt_nonzero_result_is_generic_private_and_restores_the_tty() {
        let (_root, prompt_path) = prompt_fixture(
            r#"#!/bin/sh
set -eu
[ -t 0 ]
[ -t 2 ]
[ "$#" -eq 3 ]
[ "$1" = "--timeout=300" ]
[ "$2" = "--echo=no" ]
[ "$3" = "Hydra enrollment code:" ]
saved=$(/bin/stty -g </dev/tty)
trap '/bin/stty "$saved" </dev/tty' 0 1 2 15
/bin/stty -echo </dev/tty
printf '%s\n' 'fixture-ready' >&2
IFS= read -r probe </dev/tty
[ "$probe" = "abcde234" ]
printf '%s\n' "$probe"
exit 1
"#,
        );
        let (output, transcript) = run_prompt_fixture(&prompt_path, "failure", b"abcde234\n");
        assert!(!output.windows(8).any(|window| window == b"abcde234"));
        assert!(!output.windows(8).any(|window| window == b"ABCDE234"));
        assert!(!transcript.windows(8).any(|window| window == b"abcde234"));
        assert!(!transcript.windows(8).any(|window| window == b"ABCDE234"));
    }

    #[test]
    fn enrollment_code_is_exact_normalized_and_never_debuggable() {
        let code = parse_enrollment_code(b"abcde234\r\n".to_vec()).unwrap();
        assert_eq!(code.as_str(), "ABCDE234");
        assert_eq!(
            parse_enrollment_code(b"a2b3c4d5\r\n".to_vec())
                .unwrap()
                .as_str(),
            "A2B3C4D5"
        );
        assert!(parse_enrollment_code(b"ABCD0101".to_vec()).is_ok());
        for rejected in [b'I', b'L', b'O', b'U'] {
            assert!(parse_enrollment_code(vec![rejected; 8]).is_err());
        }
        assert!(parse_enrollment_code(b"ABCD-I23".to_vec()).is_err());
        assert!(parse_enrollment_code(b"TOO-LONG-CODE".to_vec()).is_err());

        for byte in 0_u8..=u8::MAX {
            let normalized = byte.to_ascii_uppercase();
            let expected = maestro_extension_api::ENROLLMENT_CODE_ALPHABET
                .as_bytes()
                .contains(&normalized);
            assert_eq!(
                parse_enrollment_code(vec![byte; maestro_extension_api::ENROLLMENT_CODE_LENGTH])
                    .is_ok(),
                expected,
                "byte {byte} drifted from the shared enrollment grammar"
            );
        }
    }

    #[test]
    fn setup_argv_never_accepts_enrollment_material() {
        assert!(setup_argv_is_valid(&["hydraterms".into(), "remote".into()]));
        assert!(setup_argv_is_valid(&[
            "hydra-agent".into(),
            "headless".into(),
            "setup".into()
        ]));
        assert!(!setup_argv_is_valid(&[
            "hydraterms".into(),
            "remote".into(),
            "ABCDEFGH".into()
        ]));
        assert!(!setup_argv_is_valid(&[
            "hydra-agent".into(),
            "headless".into(),
            "setup".into(),
            "--code".into(),
            "ABCDEFGH".into()
        ]));
    }

    #[test]
    fn daemon_removal_requires_both_exact_destructive_acknowledgements() {
        let args = |values: &[&str]| {
            values
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
        };
        assert!(daemon_remove_argv_is_valid(&args(&[
            "hydraterms",
            "headless",
            "remove-daemon",
            "--apply",
            "--confirm-session-loss",
        ])));
        assert!(!daemon_remove_argv_is_valid(&args(&[
            "hydraterms",
            "headless",
            "remove-daemon",
            "--apply",
        ])));
        assert!(!daemon_remove_argv_is_valid(&args(&[
            "hydraterms",
            "headless",
            "remove-daemon",
            "--confirm-session-loss",
            "--apply",
        ])));
    }

    #[test]
    fn owner_transfer_requires_all_exact_destructive_acknowledgements() {
        let args = |values: &[&str]| {
            values
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
        };
        assert!(owner_transfer_argv_is_valid(&args(&[
            "hydraterms",
            "headless",
            "transfer-owner",
            "--apply",
            "--confirm-session-loss",
            "--confirm-cloud-ownership-transfer",
        ])));
        assert!(!owner_transfer_argv_is_valid(&args(&[
            "hydraterms",
            "headless",
            "transfer-owner",
            "--apply",
            "--confirm-session-loss",
        ])));
        assert!(!owner_transfer_argv_is_valid(&args(&[
            "hydraterms",
            "headless",
            "transfer-owner",
            "--apply",
            "--confirm-cloud-ownership-transfer",
            "--confirm-session-loss",
        ])));
    }

    #[test]
    fn daemon_socket_matches_the_existing_no_desktop_fallback() {
        assert_eq!(
            daemon_socket_path(1001),
            PathBuf::from("/tmp/hydra-maestro-1001.sock")
        );
    }

    #[test]
    fn systemd_tools_use_the_unmerged_and_merged_usr_compatible_paths() {
        assert_eq!(ASK_PASSWORD_PATH, "/bin/systemd-ask-password");
        assert_eq!(SYSTEMCTL_PATH, "/bin/systemctl");
        assert_eq!(LOGINCTL_PATH, "/bin/loginctl");
    }

    #[test]
    fn server_label_is_bounded_scrubbed_and_explicit() {
        assert_eq!(server_device_label(Some("box\nname")), "boxname (server)");
        assert_eq!(server_device_label(None), "Linux (server)");
        assert!(server_device_label(Some(&"x".repeat(100))).len() <= 64);
    }

    #[test]
    fn lingering_readback_is_closed_and_bounded() {
        assert!(linger_is_enabled(b"yes\n").unwrap());
        assert!(!linger_is_enabled(b"no\n").unwrap());
        assert!(linger_is_enabled(b"enabled\n").is_err());
        assert!(linger_is_enabled(&[b'x'; 17]).is_err());
    }
}
