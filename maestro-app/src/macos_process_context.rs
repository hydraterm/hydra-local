//! Re-enter a directly invoked macOS app with process-owned XPC state removed before exec.
//!
//! The native bundle launcher already does this for ordinary launches. Direct CLI invocation can
//! inherit a retained GUI/daemon's XPC context instead. libxpc initializes before Rust main, so
//! unsetting the variables in-place is insufficient even before the first pasteboard operation.

use std::ffi::OsString;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

const INTERNAL_KEYS: [&str; 2] = ["XPC_FLAGS", "XPC_SERVICE_NAME"];

pub(crate) fn ensure_clean_start() -> io::Result<()> {
    if !requires_reexec(|key| std::env::var_os(key)) {
        return Ok(());
    }
    // exec replaces only this process, retaining its PID, cwd, standard streams and arguments.
    // No daemon, store, window or worker has been created by the app at this entrypoint yet.
    // The replacement has neither key, so it proceeds without another exec or a marker variable.
    let mut command = clean_reexec_command(&std::env::current_exe()?, std::env::args_os());
    Err(command.exec())
}

fn requires_reexec(get_env: impl Fn(&str) -> Option<OsString>) -> bool {
    INTERNAL_KEYS.iter().any(|key| get_env(key).is_some())
}

fn clean_reexec_command(executable: &Path, mut args: impl Iterator<Item = OsString>) -> Command {
    let mut command = Command::new(executable);
    if let Some(arg0) = args.next() {
        command.arg0(arg0);
    }
    command.args(args);
    for key in INTERNAL_KEYS {
        command.env_remove(key);
    }
    command
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn clean_start_needs_no_exec_and_either_internal_key_requires_one() {
        assert!(!requires_reexec(|_| None));
        for selected in INTERNAL_KEYS {
            for value in [OsString::new(), OsString::from("fixture")] {
                assert!(requires_reexec(
                    |key| (key == selected).then(|| value.clone())
                ));
            }
        }
    }

    #[test]
    fn reexec_command_keeps_native_arguments_and_only_removes_internal_environment() {
        let args = vec![
            OsString::from("hydra custom argv0"),
            OsString::from("argument with spaces"),
            OsString::from_vec(vec![b'n', 0xff]),
        ];
        let command =
            clean_reexec_command(Path::new("/fixture/maestro-app"), args.clone().into_iter());
        assert_eq!(command.get_program(), "/fixture/maestro-app");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            args[1..].iter().collect::<Vec<_>>()
        );
        assert_eq!(command.get_envs().count(), 2);
        assert!(command
            .get_envs()
            .all(|(key, value)| INTERNAL_KEYS.iter().any(|name| key == *name) && value.is_none()));
        assert_eq!(command.get_current_dir(), None);
    }

    #[test]
    fn actual_reexec_keeps_pid_and_user_settings_without_looping() {
        const PROBE: &str = "HYDRA_TEST_GUI_REEXEC";
        if std::env::var_os(PROBE).is_some() {
            ensure_clean_start().unwrap();
            assert!(!requires_reexec(|key| std::env::var_os(key)));
            assert_eq!(std::env::args_os().next().unwrap(), "hydra reexec fixture");
            assert_eq!(std::env::current_dir().unwrap(), Path::new("/"));
            assert_eq!(std::env::var("HOME").unwrap(), "/fixture/home");
            assert_eq!(std::env::var("PATH").unwrap(), "/fixture/user-bin");
            assert_eq!(
                std::env::var("HTTPS_PROXY").unwrap(),
                "http://proxy.invalid:8080"
            );
            assert_eq!(
                std::env::var("CODEX_HOME").unwrap(),
                "/fixture/provider-config"
            );
            println!("clean-reexec-pid={}", std::process::id());
            return;
        }
        let qualified = concat!(
            module_path!(),
            "::actual_reexec_keeps_pid_and_user_settings_without_looping"
        );
        let test_name = qualified.split_once("::").unwrap().1;
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg0("hydra reexec fixture")
            .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
            .env(PROBE, "1")
            .env("XPC_FLAGS", "0x2")
            .env(
                "XPC_SERVICE_NAME",
                "application.com.hydraterms.hydra.fixture",
            )
            .env("HTTPS_PROXY", "http://proxy.invalid:8080")
            .env("CODEX_HOME", "/fixture/provider-config")
            .env("HOME", "/fixture/home")
            .env("PATH", "/fixture/user-bin")
            .current_dir("/")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("clean startup re-exec did not finish within ten seconds");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout).unwrap();
        assert!(
            stdout.contains(&format!("clean-reexec-pid={pid}")),
            "{stdout}"
        );
        assert!(stdout.contains("1 passed; 0 failed"), "{stdout}");
    }
}
