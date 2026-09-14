//! Canonical provider execution through the desktop user's interactive login shell.
//!
//! This module is intentionally below `maestro-local-services`: durable KnownSafe restart
//! authority and ordinary App launches must derive byte-identical argv without accepting caller-
//! supplied live command bytes. Environment and executable lookup are injectable for tests.

use std::ffi::CString;
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::LaunchSpec;

/// Provider CLIs are resolved in the same interactive login-shell environment as terminal users.
pub const LOGIN_SHELL_COMMAND_FLAGS: &str = "-lic";

const LOGIN_SHELL_PROVIDERS: &[&str] = &[
    "claude", "codex", "copilot", "agy", "kimi", "kiro-cli", "agent", "amp", "devin", "droid",
    "gemini", "opencode",
];

/// Launch-specific environment access preserves the old platform semantics: SHELL must be valid
/// UTF-8 or it is ignored, while HOME stays lossless until an absolute argv string is required.
pub trait LaunchEnvLookup {
    fn shell_utf8(&self) -> Option<String>;
    fn home_os(&self) -> Option<OsString>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessLaunchEnv;

impl LaunchEnvLookup for ProcessLaunchEnv {
    fn shell_utf8(&self) -> Option<String> {
        std::env::var("SHELL").ok()
    }

    fn home_os(&self) -> Option<OsString> {
        std::env::var_os("HOME")
    }
}

/// Resolve the user's configured login shell without consulting process-global state directly.
pub fn login_shell_program(env: &impl LaunchEnvLookup) -> String {
    env.shell_utf8()
        .filter(|shell| !shell.trim().is_empty())
        .unwrap_or_else(|| {
            if cfg!(target_os = "macos") {
                "/bin/zsh".to_string()
            } else {
                "/bin/sh".to_string()
            }
        })
}

/// Minimal single-quote escaping used to embed exact argv in one login-shell command string.
pub fn shell_quote_login_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }
    format!("'{}'", arg.replace('\'', "'\\''"))
}

fn is_executable_file(path: &Path) -> bool {
    if !path.metadata().map(|meta| meta.is_file()).unwrap_or(false) {
        return false;
    }
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `path` is a live NUL-terminated C string and `access` does not retain it.
    unsafe { libc::access(path.as_ptr(), libc::X_OK) == 0 }
}

/// Build the exact login-shell argv used by both fresh App launches and durable KnownSafe replay.
/// OpenCode's documented per-user installation path is preferred only when it exists and is
/// executable for the current user; every other command is resolved by the login shell's PATH.
pub fn login_shell_argv(argv: &[String], env: &impl LaunchEnvLookup) -> Vec<String> {
    login_shell_argv_with(argv, &login_shell_program(env), env, is_executable_file)
}

/// Explicit-program test seam used by preflight/parity tests. The executable predicate is injected
/// so tests never need to mutate permissions or the real HOME.
pub fn login_shell_argv_with(
    argv: &[String],
    login_shell: &str,
    env: &impl LaunchEnvLookup,
    executable: impl Fn(&Path) -> bool,
) -> Vec<String> {
    let mut resolved = argv.to_vec();
    if resolved
        .first()
        .is_some_and(|command| command == "opencode")
    {
        let candidate = env
            .home_os()
            .filter(|home| !home.is_empty())
            .map(PathBuf::from)
            .map(|home| home.join(".opencode/bin/opencode"));
        if let Some(candidate) = candidate
            .filter(|candidate| executable(candidate))
            .and_then(|candidate| candidate.to_str().map(str::to_string))
        {
            resolved[0] = candidate;
        }
    }
    let command = resolved
        .iter()
        .map(|arg| shell_quote_login_arg(arg))
        .collect::<Vec<_>>()
        .join(" ");
    // XPC_FLAGS and XPC_SERVICE_NAME are libxpc's process-internal state, not terminal/user
    // preferences. A retained macOS daemon can pass its "reentrancy avoided" state (0x2) and its
    // owning service name to new shells. In a fresh executable that disables system-service
    // lookups, including DNS and browser launching: a provider inheriting XPC_SERVICE_NAME fails
    // every hostname with "nodename nor servname provided" while the same lookup succeeds outside
    // the app. Clear both after shell startup too: the login shell may itself inherit that state.
    // Do not change the user's HOME, provider config, sandbox, network policy, or approval choices.
    let process_context_reset = if cfg!(target_os = "macos") {
        "unset XPC_FLAGS XPC_SERVICE_NAME; "
    } else {
        ""
    };
    vec![
        login_shell.to_string(),
        LOGIN_SHELL_COMMAND_FLAGS.to_string(),
        format!(
            "{process_context_reset}unset NO_COLOR; export TERM=xterm-256color COLORTERM=truecolor CLICOLOR=1 FORCE_COLOR=1; {command}"
        ),
    ]
}

/// Derive execution only for the closed set of KnownSafe provider identities. This function does
/// not itself grant restart authority; callers that replace an existing row must additionally prove
/// an exact provider-conversation recipe.
pub fn known_safe_provider_login_shell_argv(
    launch: &LaunchSpec,
    env: &impl LaunchEnvLookup,
) -> Option<Vec<String>> {
    let LaunchSpec::KnownSafe {
        launch_spec_id,
        params,
    } = launch
    else {
        return None;
    };
    if !LOGIN_SHELL_PROVIDERS.contains(&launch_spec_id.as_str()) {
        return None;
    }
    let mut argv = Vec::with_capacity(1 + params.len());
    argv.push(launch_spec_id.clone());
    argv.extend(params.iter().cloned());
    Some(login_shell_argv(&argv, env))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::os::unix::ffi::OsStringExt;

    struct MapLaunchEnv {
        shell: Option<String>,
        home: Option<OsString>,
    }

    impl LaunchEnvLookup for MapLaunchEnv {
        fn shell_utf8(&self) -> Option<String> {
            self.shell.clone()
        }

        fn home_os(&self) -> Option<OsString> {
            self.home.clone()
        }
    }

    fn env(values: BTreeMap<&'static str, &'static str>) -> MapLaunchEnv {
        MapLaunchEnv {
            shell: values.get("SHELL").map(|value| (*value).to_string()),
            home: values.get("HOME").map(|value| OsString::from(*value)),
        }
    }

    #[test]
    fn exact_login_shell_bytes_quote_and_reassert_color() {
        let argv = login_shell_argv_with(
            &["codex".into(), "a'b".into(), String::new()],
            "/bin/test-shell",
            &env(BTreeMap::new()),
            |_| false,
        );
        assert_eq!(argv[0], "/bin/test-shell");
        assert_eq!(argv[1], LOGIN_SHELL_COMMAND_FLAGS);
        assert!(argv[2].contains("unset NO_COLOR"));
        assert!(argv[2].contains("FORCE_COLOR=1"));
        assert!(argv[2].contains("'a'\\''b' ''"));
    }

    #[test]
    fn opencode_home_path_uses_injected_executable_proof() {
        let argv = login_shell_argv_with(
            &["opencode".into(), "--session".into(), "exact".into()],
            "/bin/test-shell",
            &env(BTreeMap::from([("HOME", "/home/test")])),
            |path| path == Path::new("/home/test/.opencode/bin/opencode"),
        );
        assert!(argv[2].contains("'/home/test/.opencode/bin/opencode'"));
    }

    #[test]
    fn every_known_provider_uses_one_identical_quoted_login_shell_shape() {
        for provider in LOGIN_SHELL_PROVIDERS {
            let launch = LaunchSpec::KnownSafe {
                launch_spec_id: (*provider).to_string(),
                params: vec!["space value".into(), "quote'value".into(), String::new()],
            };
            let argv = known_safe_provider_login_shell_argv(
                &launch,
                &env(BTreeMap::from([("SHELL", "/bin/reviewed-shell")])),
            )
            .unwrap_or_else(|| panic!("closed provider {provider} must derive execution"));
            assert_eq!(argv[0], "/bin/reviewed-shell", "provider={provider}");
            assert_eq!(argv[1], LOGIN_SHELL_COMMAND_FLAGS, "provider={provider}");
            assert!(argv[2].contains("'space value'"), "provider={provider}");
            assert!(argv[2].contains("'quote'\\''value'"), "provider={provider}");
            assert!(argv[2].ends_with(" ''"), "provider={provider}");
        }
    }

    #[test]
    fn login_shell_selection_handles_set_empty_and_unset_values() {
        assert_eq!(
            login_shell_program(&env(BTreeMap::from([("SHELL", "/bin/custom")]))),
            "/bin/custom"
        );
        let platform_default = if cfg!(target_os = "macos") {
            "/bin/zsh"
        } else {
            "/bin/sh"
        };
        assert_eq!(
            login_shell_program(&env(BTreeMap::from([("SHELL", "")]))),
            platform_default
        );
        assert_eq!(login_shell_program(&env(BTreeMap::new())), platform_default);
    }

    #[test]
    fn non_executable_opencode_home_path_falls_back_to_login_shell_path_lookup() {
        let argv = login_shell_argv_with(
            &["opencode".into(), "--session".into(), "exact".into()],
            "/bin/test-shell",
            &env(BTreeMap::from([("HOME", "/home/test")])),
            |_| false,
        );
        assert!(argv[2].contains("'opencode' '--session' 'exact'"));
        assert!(!argv[2].contains("/home/test/.opencode/bin/opencode"));
    }

    #[test]
    fn non_utf8_launch_environment_never_invents_replacement_character_paths() {
        let non_utf8 = OsString::from_vec(vec![b'/', b't', b'm', b'p', 0xff]);
        let launch_env = MapLaunchEnv {
            // Production obtains SHELL through `std::env::var`, so non-UTF8 is represented as None.
            shell: None,
            home: Some(non_utf8),
        };
        let platform_default = if cfg!(target_os = "macos") {
            "/bin/zsh"
        } else {
            "/bin/sh"
        };
        assert_eq!(login_shell_program(&launch_env), platform_default);
        let argv =
            login_shell_argv_with(&["opencode".into()], platform_default, &launch_env, |_| {
                true
            });
        assert!(argv[2].contains("'opencode'"));
        assert!(!argv[2].contains('\u{fffd}'));
    }

    #[test]
    fn provider_shell_resets_only_macos_internal_xpc_state() {
        for provider in LOGIN_SHELL_PROVIDERS {
            let argv = login_shell_argv_with(
                &[(*provider).to_string()],
                "/bin/test-shell",
                &env(BTreeMap::new()),
                |_| false,
            );
            assert_eq!(
                argv[2].starts_with("unset XPC_FLAGS XPC_SERVICE_NAME; "),
                cfg!(target_os = "macos"),
                "provider={provider}"
            );
            assert!(argv[2].ends_with(&format!("'{provider}'")));
            assert!(!argv[2].contains("unset HOME"));
            assert!(!argv[2].contains("unset CODEX_HOME"));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launched_child_drops_xpc_flags_without_changing_user_environment() {
        let argv = login_shell_argv_with(
            &[
                "/bin/sh".into(),
                "-c".into(),
                "test -z \"${XPC_FLAGS+x}\" && test -z \"${XPC_SERVICE_NAME+x}\" && test \"$HYDRA_TEST_USER_SETTING\" = kept".into(),
            ],
            "/bin/sh",
            &env(BTreeMap::new()),
            |_| false,
        );
        let status = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .env("XPC_FLAGS", "0x2")
            .env("XPC_SERVICE_NAME", "application.com.hydraterms.hydra.1.2")
            .env("HYDRA_TEST_USER_SETTING", "kept")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("launch the ordinary login-shell path");
        assert!(status.success());
    }
}
