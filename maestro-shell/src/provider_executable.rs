//! One provider lookup policy shared by preflight and retained-session launch fallbacks.
//!
//! Order: explicit HYDRA_PROVIDER_*_EXECUTABLE absolute locator; OpenCode's established native
//! ~/.opencode/bin/opencode preference; fixed command spellings in the interactive login shell;
//! then ~/.local/bin and ~/.nix-profile/bin. Cursor also accepts its documented cursor-agent
//! spelling. Other renamed/versioned wrappers require the explicit mapping below. No globbing,
//! candidate execution, provider-history reads, or shell evaluation of configured paths occurs.
//! For manual installation diagnostics the supported CLIs expose `<absolute launcher> --version`;
//! discovery itself never runs a version probe or arbitrary wrapper to infer provider identity.
//! Sources: https://docs.cursor.com/en/cli/installation and
//! https://nix.dev/manual/nix/2.25/package-management/profiles .
//!
//! The selected path is lexical, not canonicalized: stable symlinks may follow normal upgrades.
//! Replayable prepared recipes persist it as BoundProvider. FreshProvider records only audit a
//! selected fresh launch without an assigned conversation; they never grant replay authority.
//! Shell-only aliases without an absolute selection retain the non-replayable AdHoc recipe.

#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::{Command, Stdio};
#[cfg(unix)]
use std::time::{Duration, Instant};

use crate::launch_environment::is_executable_file;
#[cfg(unix)]
use crate::launch_environment::LOGIN_SHELL_COMMAND_FLAGS;
use crate::provider_launch_selection::LaunchEnvLookup;
use crate::provider_launch_selection::ProviderExecutable;

impl ProviderExecutable {
    pub fn remains_executable_for(&self, provider: &str) -> bool {
        self.path_for(provider).is_some_and(is_executable_file)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderResolution {
    Executable(ProviderExecutable),
    /// A login-shell alias/function remains a shell command; never pretend it is an absolute file.
    ShellCommand,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderLookupError {
    Unavailable,
    TimedOut,
}

/// Fixed provider command spellings. A wrapper using one of these names is an ordinary executable;
/// arbitrary renamed/versioned wrappers require an explicit absolute-path mapping, never a glob.
pub fn provider_executable_names(provider: &str) -> Option<&'static [&'static str]> {
    Some(match provider {
        "claude" => &["claude"],
        "codex" => &["codex"],
        "gemini" => &["gemini"],
        "opencode" => &["opencode"],
        "copilot" => &["copilot"],
        "agy" => &["agy"],
        "kimi" => &["kimi"],
        "kiro-cli" => &["kiro-cli"],
        // Cursor documents both the original cursor-agent launcher and current agent command.
        "agent" => &["agent", "cursor-agent"],
        "amp" => &["amp"],
        "devin" => &["devin"],
        "droid" => &["droid"],
        _ => return None,
    })
}

pub fn provider_executable_override_variable(provider: &str) -> Option<&'static str> {
    Some(match provider {
        "claude" => "HYDRA_PROVIDER_CLAUDE_EXECUTABLE",
        "codex" => "HYDRA_PROVIDER_CODEX_EXECUTABLE",
        "gemini" => "HYDRA_PROVIDER_GEMINI_EXECUTABLE",
        "opencode" => "HYDRA_PROVIDER_OPENCODE_EXECUTABLE",
        "copilot" => "HYDRA_PROVIDER_COPILOT_EXECUTABLE",
        "agy" => "HYDRA_PROVIDER_ANTIGRAVITY_EXECUTABLE",
        "kimi" => "HYDRA_PROVIDER_KIMI_EXECUTABLE",
        "kiro-cli" => "HYDRA_PROVIDER_KIRO_EXECUTABLE",
        "agent" => "HYDRA_PROVIDER_CURSOR_EXECUTABLE",
        "amp" => "HYDRA_PROVIDER_AMP_EXECUTABLE",
        "devin" => "HYDRA_PROVIDER_DEVIN_EXECUTABLE",
        "droid" => "HYDRA_PROVIDER_FACTORY_EXECUTABLE",
        _ => return None,
    })
}

#[cfg(windows)]
#[path = "provider_executable_windows.rs"]
mod windows;
#[cfg(windows)]
pub use windows::resolve_provider_executable;

/// Conventional stable launch roots, not physical version directories. Nix's documented profile
/// symlink follows upgrades; keep it lexical rather than pinning a /nix/store generation.
#[cfg(unix)]
pub(crate) fn provider_fallback(
    provider: &str,
    env: &impl LaunchEnvLookup,
    executable: impl Fn(&Path) -> bool,
) -> Option<PathBuf> {
    let names = provider_executable_names(provider)?;
    let mut candidates = Vec::new();
    if let Some(home) = env
        .home_os()
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
    {
        if provider == "opencode" {
            candidates.push(home.join(".opencode/bin/opencode"));
        }
        for root in [".local/bin", ".nix-profile/bin"] {
            for name in names {
                candidates.push(home.join(root).join(name));
            }
        }
    }
    candidates
        .into_iter()
        .find(|path| path.to_str().is_some() && executable(path))
}

#[cfg(unix)]
pub fn resolve_provider_executable(
    provider: &str,
    cwd: &Path,
    env: &impl LaunchEnvLookup,
) -> Result<Option<ProviderResolution>, ProviderLookupError> {
    let Some(names) = provider_executable_names(provider) else {
        return Ok(None);
    };
    if let Some(path) = env.configured_provider_path(provider) {
        // Operator configuration is data, never shell syntax; missing/invalid overrides do not
        // silently select a different executable from PATH or a conventional root.
        return Ok(
            (path.is_absolute() && path.to_str().is_some() && is_executable_file(&path)).then(
                || ProviderResolution::Executable(ProviderExecutable::new(provider.into(), path)),
            ),
        );
    }
    let cwd = if cwd.is_absolute() {
        cwd.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| ProviderLookupError::Unavailable)?
            .join(cwd)
    };
    let selected =
        |path| ProviderResolution::Executable(ProviderExecutable::new(provider.to_owned(), path));
    let fallback = provider_fallback(provider, env, is_executable_file);
    // Keep OpenCode's existing preferred native installation, without preferring conventional
    // fallback roots over another provider's user-selected login-shell PATH.
    if provider == "opencode" {
        if let Some(path) = fallback.as_ref().filter(|path| {
            env.home_os()
                .is_some_and(|home| PathBuf::from(home).join(".opencode/bin/opencode") == **path)
        }) {
            return Ok(Some(selected(path.clone())));
        }
    }
    const MARKER: &[u8] = b"\x1eHYDRA_PROVIDER\x1f";
    const END: &[u8] = b"\x1eHYDRA_PROVIDER_END\x1f";
    let mut command = Command::new(crate::login_shell_program(env));
    let lookup = names
        .iter()
        .map(|name| format!("command -v {name}"))
        .collect::<Vec<_>>()
        .join(" || ");
    command.args([
        LOGIN_SHELL_COMMAND_FLAGS,
        &format!("printf '\\036HYDRA_PROVIDER\\037'; {lookup}; hydra_status=$?; printf '\\036HYDRA_PROVIDER_END\\037'; exit \"$hydra_status\""),
    ]);
    command
        .current_dir(&cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(home) = env.home_os() {
        command.env("HOME", home);
    }
    if let Some(path) = env.path_os() {
        command.env("PATH", path);
    }
    let mut child = command
        .spawn()
        .map_err(|_| ProviderLookupError::Unavailable)?;
    let mut output = child
        .stdout
        .take()
        .ok_or(ProviderLookupError::Unavailable)?;
    // Drain noisy shell startup without blocking on inherited stdout in a background child. The
    // existing preflight deadline applies to this owned lookup only, never to a provider session.
    let fd = output.as_raw_fd();
    // SAFETY: this is our live owned pipe descriptor; these fcntl operations take no pointers.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        let _ = child.kill();
        let _ = child.wait();
        return Err(ProviderLookupError::Unavailable);
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut bytes = Vec::new();
    let status = loop {
        if drain_available(&mut output, &mut bytes, deadline).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ProviderLookupError::Unavailable);
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                drain_available(&mut output, &mut bytes, deadline)
                    .map_err(|_| ProviderLookupError::Unavailable)?;
                break status;
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(if result.is_err() {
                    ProviderLookupError::Unavailable
                } else {
                    ProviderLookupError::TimedOut
                });
            }
        }
    };
    if !status.success() {
        return Ok(fallback.map(selected));
    }
    // A shell startup file can exit successfully without running our lookup. Only a complete,
    // nonempty command-v response proves discovery; process exit status alone does not.
    let Some(marker) = bytes.windows(MARKER.len()).rposition(|part| part == MARKER) else {
        return Err(ProviderLookupError::Unavailable);
    };
    let result = &bytes[marker + MARKER.len()..];
    let Some(end) = result.windows(END.len()).position(|part| part == END) else {
        return Err(ProviderLookupError::Unavailable);
    };
    let Ok(value) = std::str::from_utf8(&result[..end]) else {
        return Ok(Some(ProviderResolution::ShellCommand));
    };
    let value = value.strip_suffix('\n').unwrap_or(value);
    if value.is_empty() {
        return Err(ProviderLookupError::Unavailable);
    }
    // A bare name can be a shell function even when an unrelated same-name file exists in cwd.
    // Do not reinterpret that ambiguous shell result as a filesystem selection.
    if !value.contains('/') {
        return Ok(Some(ProviderResolution::ShellCommand));
    }
    let path = Path::new(value);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    Ok(Some(if is_executable_file(&path) {
        selected(path)
    } else {
        ProviderResolution::ShellCommand
    }))
}

#[cfg(unix)]
fn drain_available(
    output: &mut impl Read,
    bytes: &mut Vec<u8>,
    deadline: Instant,
) -> std::io::Result<()> {
    let mut chunk = [0; 4096];
    loop {
        match output.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                bytes.extend_from_slice(&chunk[..n]);
                if bytes.len() > 16384 {
                    bytes.drain(..bytes.len() - 16384);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Ok(());
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::SelectedProviderLaunchEnv;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt;

    struct Fixture {
        root: tempfile::TempDir,
        shell: PathBuf,
        path: OsString,
        configured: Option<PathBuf>,
    }
    impl LaunchEnvLookup for Fixture {
        fn shell_utf8(&self) -> Option<String> {
            Some(self.shell.to_str().unwrap().to_owned())
        }
        fn home_os(&self) -> Option<OsString> {
            Some(self.root.path().as_os_str().to_owned())
        }
        fn path_os(&self) -> Option<OsString> {
            Some(self.path.clone())
        }
        fn configured_provider_path(&self, provider: &str) -> Option<PathBuf> {
            (provider == "claude")
                .then(|| self.configured.clone())
                .flatten()
        }
    }
    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let shell = root.path().join("login-shell");
            Self::write(
                &shell,
                "#!/bin/sh\n[ \"$1\" = '-lic' ] || exit 97\nexec /bin/sh -c \"$2\"\n",
            );
            Self {
                root,
                shell,
                path: "/usr/bin:/bin".into(),
                configured: None,
            }
        }
        fn write(path: &Path, contents: &str) {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        fn provider(&self, relative: &str, marker: &str) -> PathBuf {
            let path = self.root.path().join(relative);
            Self::write(
                &path,
                &format!("#!/bin/sh\nprintf '%s\\n' '{marker}' \"$@\"\n"),
            );
            path
        }
        fn resolve(&self, provider: &str) -> Option<ProviderResolution> {
            resolve_provider_executable(provider, self.root.path(), self).unwrap()
        }
        fn run(&self, argv: &[String]) -> String {
            let output = Command::new(&argv[0])
                .args(&argv[1..])
                .current_dir(self.root.path())
                .env_clear()
                .env("HOME", self.root.path())
                .env("PATH", &self.path)
                .env("HYDRA_OWNED_ENV", "preserved")
                .output()
                .unwrap();
            assert!(output.status.success());
            String::from_utf8(output.stdout).unwrap()
        }
    }

    #[test]
    fn explicit_versioned_wrapper_is_data_and_missing_override_does_not_fall_back() {
        let mut fixture = Fixture::new();
        let marker = fixture.root.path().join("unexpected-discovery-execution");
        let path = fixture
            .root
            .path()
            .join("wrapper v2 ' $(touch should-not-run)");
        Fixture::write(
            &path,
            &format!(
                "#!/bin/sh\ntouch '{}'\nprintf 'wrapper-v2'\n",
                marker.display()
            ),
        );
        fixture.configured = Some(path.clone());
        let Some(ProviderResolution::Executable(selected)) = fixture.resolve("claude") else {
            panic!("explicit absolute wrapper was missed")
        };
        assert_eq!(selected.path_for("claude"), Some(path.as_path()));
        assert!(
            !marker.exists(),
            "discovery must never execute candidate wrappers"
        );
        fixture.provider(".local/bin/claude", "wrong-fallback");
        for invalid in [
            PathBuf::from("relative/wrapper"),
            fixture.root.path().join("absent"),
        ] {
            fixture.configured = Some(invalid);
            assert!(fixture.resolve("claude").is_none());
        }
    }

    #[test]
    fn stable_nix_profile_and_documented_cursor_alias_are_discoverable() {
        let fixture = Fixture::new();
        let wrapped = fixture.provider(".nix-profile/bin/claude", "nix-wrapper");
        let Some(ProviderResolution::Executable(selected)) = fixture.resolve("claude") else {
            panic!("stable Nix profile launcher was missed")
        };
        assert_eq!(selected.path_for("claude"), Some(wrapped.as_path()));
        let cursor = fixture.provider(".local/bin/cursor-agent", "cursor");
        let Some(ProviderResolution::Executable(selected)) = fixture.resolve("agent") else {
            panic!("documented Cursor CLI alias was missed")
        };
        assert_eq!(selected.path_for("agent"), Some(cursor.as_path()));
    }

    #[test]
    fn successful_shell_exit_without_probe_envelope_is_not_provider_resolution() {
        for script in [
            "#!/bin/sh\nexit 0\n",
            "#!/bin/sh\nprintf 'startup banner\\n'\nexit 0\n",
            "#!/bin/sh\nprintf '\\036HYDRA_PROVIDER\\037claude\\n'\nexit 0\n",
            "#!/bin/sh\nprintf 'claude\\n\\036HYDRA_PROVIDER_END\\037'\nexit 0\n",
            "#!/bin/sh\nprintf '\\036HYDRA_PROVIDER\\037\\036HYDRA_PROVIDER_END\\037'\nexit 0\n",
        ] {
            let fixture = Fixture::new();
            Fixture::write(&fixture.shell, script);
            assert_eq!(
                resolve_provider_executable("claude", fixture.root.path(), &fixture),
                Err(ProviderLookupError::Unavailable),
                "shell exit status alone cannot prove command discovery"
            );
        }
    }

    #[test]
    fn valid_shell_alias_still_resolves() {
        let fixture = Fixture::new();
        Fixture::write(
            &fixture.shell,
            "#!/bin/sh\nexec /bin/sh -c 'alias claude=\"printf alias\"; eval \"$1\"' sh \"$2\"\n",
        );
        assert_eq!(
            fixture.resolve("claude"),
            Some(ProviderResolution::ShellCommand)
        );
    }

    #[test]
    fn complete_probe_preserves_non_utf8_shell_command_fallback() {
        let fixture = Fixture::new();
        // A framed non-UTF8 command path is not a missing lookup result. Keep its existing shell
        // fallback; this payload fixture does not claim a native non-UTF8 filesystem launch.
        Fixture::write(
            &fixture.shell,
            "#!/bin/sh\nprintf '\\036HYDRA_PROVIDER\\037/qa/\\377/claude\\n\\036HYDRA_PROVIDER_END\\037'\n",
        );
        assert_eq!(
            fixture.resolve("claude"),
            Some(ProviderResolution::ShellCommand)
        );
    }

    #[test]
    fn known_roots_are_generic_executable_only_and_opencode_keeps_its_preference() {
        let mut fixture = Fixture::new();
        for provider in ["claude", "codex", "kimi"] {
            let path = fixture.provider(&format!(".local/bin/{provider}"), "owned");
            let Some(ProviderResolution::Executable(selected)) = fixture.resolve(provider) else {
                panic!("known root missed")
            };
            assert_eq!(selected.path_for(provider), Some(path.as_path()));
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert!(fixture.resolve(provider).is_none());
        }
        let native = fixture.provider(".opencode/bin/opencode", "native");
        fixture.provider("other/opencode", "path");
        fixture.path = fixture.root.path().join("other").into_os_string();
        let Some(ProviderResolution::Executable(selected)) = fixture.resolve("opencode") else {
            panic!("native OpenCode missed")
        };
        assert_eq!(selected.path_for("opencode"), Some(native.as_path()));
        assert!(fixture.resolve("claude-wrapper").is_none());
    }

    #[test]
    fn selected_current_launch_survives_path_drift_but_later_resume_resolves_again() {
        let mut fixture = Fixture::new();
        let first = fixture.provider("path-a/claude", "A");
        fixture.provider("path-b/claude", "B");
        fixture.provider(".local/bin/claude", "fallback");
        fixture.path = fixture.root.path().join("path-a").into_os_string();
        let Some(ProviderResolution::Executable(selected)) = fixture.resolve("claude") else {
            panic!("PATH executable missed")
        };
        assert_eq!(selected.path_for("claude"), Some(first.as_path()));
        // Drift occurs after preflight but BEFORE sealing wire argv, not merely after spawn.
        fixture.path = fixture.root.path().join("path-b").into_os_string();
        let source = vec![
            "claude".into(),
            "--resume".into(),
            "owned-conversation".into(),
        ];
        let env = SelectedProviderLaunchEnv {
            env: &fixture,
            selected: Some(&selected),
        };
        let wire = crate::login_shell_argv(&source, &env);
        assert_eq!(fixture.run(&wire), "A\n--resume\nowned-conversation\n");
        let resume = crate::LaunchSpec::KnownSafe {
            launch_spec_id: "claude".into(),
            params: source[1..].to_vec(),
        };
        let resume_wire = crate::known_safe_provider_login_shell_argv(&resume, &fixture).unwrap();
        assert_eq!(
            fixture.run(&resume_wire),
            "B\n--resume\nowned-conversation\n"
        );
        fixture.path = "/usr/bin:/bin".into();
        assert_eq!(
            fixture.run(&crate::known_safe_provider_login_shell_argv(&resume, &fixture).unwrap()),
            "fallback\n--resume\nowned-conversation\n"
        );
        assert_eq!(source[0], "claude");
    }

    #[test]
    fn shell_functions_and_explicit_custom_paths_keep_existing_behavior() {
        let fixture = Fixture::new();
        fixture.provider("claude", "unrelated-cwd-executable");
        Fixture::write(&fixture.shell, "#!/bin/sh\nexec /bin/sh -c 'claude() { printf \"function:%s\\n\" \"$HYDRA_OWNED_ENV\"; }; eval \"$1\"' sh \"$2\"\n");
        assert_eq!(
            fixture.resolve("claude"),
            Some(ProviderResolution::ShellCommand)
        );
        assert_eq!(
            fixture.run(&crate::login_shell_argv(&["claude".into()], &fixture)),
            "function:preserved\n"
        );
        let custom = fixture.provider("custom path/claude-wrapper", "custom");
        let argv = vec![custom.to_str().unwrap().into(), "--arbitrary-option".into()];
        assert_eq!(
            fixture.run(&crate::login_shell_argv(&argv, &fixture)),
            "custom\n--arbitrary-option\n"
        );
    }
}
