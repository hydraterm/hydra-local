//! Focused native adapters without compiling the Unix daemon-fixture unit-test modules.
#![cfg(windows)]

use maestro_app::{
    default_base_dir, effective_session_argv, resolve_binary, runtime_base_dir, session_argv,
    BinaryKind, BinarySource,
};
use std::path::{Path, PathBuf};

#[test]
fn bundled_binary_names_have_native_suffixes() {
    assert_eq!(BinaryKind::Daemon.file_name(), "pty-daemon.exe");
    assert_eq!(BinaryKind::Renderer.file_name(), "maestro-renderer.exe");
    let exe = Path::new(r"C:\Hydra\maestro-app.exe");
    let daemon = PathBuf::from(r"C:\Hydra\pty-daemon.exe");
    assert_eq!(
        resolve_binary(
            BinaryKind::Daemon,
            None,
            |_| None,
            Some(exe),
            |p| p == daemon
        ),
        Some((daemon, BinarySource::SiblingOfExe))
    );
}

#[test]
fn windows_data_and_runtime_defaults_do_not_use_posix_paths() {
    let runtime = runtime_base_dir(|key| (key == "TEMP").then(|| r"C:\Temp".into()));
    assert_eq!(runtime, PathBuf::from(r"C:\Temp"));
    assert_eq!(
        default_base_dir(
            |key| (key == "LOCALAPPDATA").then(|| r"C:\Fixture\fixture\AppData\Local".into()),
            &runtime
        ),
        PathBuf::from(r"C:\Fixture\fixture\AppData\Local\Hydra")
    );
    assert_eq!(
        default_base_dir(
            |key| (key == "MAESTRO_APP_SUPPORT_DIR").then(|| r"C:\Fixture\Profile".into()),
            &runtime
        ),
        PathBuf::from(r"C:\Fixture\Profile")
    );
}

#[test]
fn missing_shell_does_not_guess_a_bare_command_or_posix_fallback() {
    assert!(session_argv(&[], |_| None).is_empty());
}

#[test]
fn powershell_is_selected_as_native_argv_without_login_shell_flags() {
    let root = tempfile::tempdir().unwrap();
    let command = root.path().join("pwsh.exe");
    std::fs::write(&command, b"fixture, never executed").unwrap();
    let path = root.path().to_str().unwrap().to_owned();
    assert_eq!(
        session_argv(&[], |key| (key == "PATH").then(|| path.clone())),
        vec![command.to_str().unwrap().to_owned()]
    );
}

#[test]
fn native_explicit_and_configured_argv_remain_literal() {
    let configured = vec![r"C:\Tools\pwsh.exe".into(), "-NoLogo".into()];
    let explicit = vec![r"C:\Tools\provider.cmd".into(), "a & b".into()];
    assert_eq!(
        effective_session_argv(&explicit, Some(&configured), |_| None),
        explicit
    );
    assert_eq!(
        effective_session_argv(&[], Some(&configured), |_| None),
        configured
    );
}
