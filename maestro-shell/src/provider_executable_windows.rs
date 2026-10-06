//! Native Windows provider discovery. Discovery reads paths; it never launches candidate tools.

use super::*;

pub fn resolve_provider_executable(
    provider: &str,
    cwd: &Path,
    env: &impl LaunchEnvLookup,
) -> Result<Option<ProviderResolution>, ProviderLookupError> {
    let Some(names) = provider_executable_names(provider) else {
        return Ok(None);
    };
    let selected =
        |path| ProviderResolution::Executable(ProviderExecutable::new(provider.into(), path));
    if let Some(path) = env.configured_provider_path(provider) {
        return Ok(
            (path.is_absolute() && path.to_str().is_some() && is_executable_file(&path))
                .then(|| selected(path)),
        );
    }
    let cwd = if cwd.is_absolute() {
        cwd.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| ProviderLookupError::Unavailable)?
            .join(cwd)
    };
    let home = env
        .home_os()
        .map(PathBuf::from)
        .filter(|home| home.is_absolute());
    let mut roots = Vec::new();
    if provider == "opencode" {
        if let Some(home) = home.as_ref() {
            roots.push(home.join(".opencode").join("bin"));
        }
    }
    if let Some(path) = env.path_os() {
        roots.extend(std::env::split_paths(&path).map(|path| {
            if path.is_absolute() {
                path
            } else {
                cwd.join(path)
            }
        }));
    }
    if let Some(home) = home.as_ref() {
        roots.push(home.join(".local").join("bin"));
    }
    if let Some(roaming) = env
        .roaming_app_data_os()
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| home.map(|home| home.join("AppData").join("Roaming")))
    {
        roots.push(roaming.join("npm"));
    }
    for root in roots {
        for name in names {
            // These are the native formats handled by our ConPTY command adapter. Do not
            // canonicalize: updater-owned stable links must remain stable replay locators.
            for extension in ["exe", "com", "cmd", "bat"] {
                let path = root.join(format!("{name}.{extension}"));
                if path.to_str().is_some() && is_executable_file(&path) {
                    return Ok(Some(selected(path)));
                }
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    struct Env {
        home: PathBuf,
        path: OsString,
        configured: Option<PathBuf>,
        roaming: Option<OsString>,
    }
    impl LaunchEnvLookup for Env {
        fn shell_utf8(&self) -> Option<String> {
            Some("cmd.exe".into())
        }
        fn home_os(&self) -> Option<OsString> {
            Some(self.home.clone().into())
        }
        fn path_os(&self) -> Option<OsString> {
            Some(self.path.clone())
        }
        fn configured_provider_path(&self, _: &str) -> Option<PathBuf> {
            self.configured.clone()
        }
        fn roaming_app_data_os(&self) -> Option<OsString> {
            self.roaming.clone()
        }
    }
    #[test]
    fn redirected_roaming_npm_root_and_absent_appdata_fallback() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let roaming = root.path().join("redirected roaming 日本語");
        let fallback = home.join("AppData").join("Roaming").join("npm");
        let redirected = roaming.join("npm");
        let preferred = root.path().join("preferred path");
        for directory in [&fallback, &redirected, &preferred] {
            std::fs::create_dir_all(directory).unwrap();
            std::fs::write(directory.join("codex.cmd"), "@exit /b 99").unwrap();
        }
        let mut env = Env {
            home,
            path: root.path().join("empty-path").into_os_string(),
            configured: None,
            roaming: Some(roaming.into_os_string()),
        };
        let resolve = |env: &Env| {
            let Some(ProviderResolution::Executable(selected)) =
                resolve_provider_executable("codex", root.path(), env).unwrap()
            else {
                panic!("npm shim missing")
            };
            selected.path_for("codex").unwrap().to_path_buf()
        };
        assert_eq!(resolve(&env), redirected.join("codex.cmd"));
        let selected_env = crate::SelectedProviderLaunchEnv {
            env: &env,
            selected: None,
        };
        assert_eq!(selected_env.roaming_app_data_os(), env.roaming);
        assert_eq!(
            crate::login_shell_argv(&["codex".into(), "two words".into()], &selected_env),
            vec![
                redirected.join("codex.cmd").to_str().unwrap().to_owned(),
                "two words".into()
            ]
        );
        env.path = preferred.clone().into_os_string();
        assert_eq!(resolve(&env), preferred.join("codex.cmd"));
        env.path = root.path().join("empty-path").into_os_string();
        std::fs::remove_file(redirected.join("codex.cmd")).unwrap();
        assert!(
            resolve_provider_executable("codex", root.path(), &env)
                .unwrap()
                .is_none(),
            "an explicit redirected APPDATA must not silently select another npm installation"
        );
        env.roaming = None;
        assert_eq!(resolve(&env), fallback.join("codex.cmd"));
        env.roaming = Some("relative-roaming".into());
        assert_eq!(resolve(&env), fallback.join("codex.cmd"));
    }

    #[test]
    fn windows_provider_discovery_and_wire_keep_native_argv() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("tools with spaces");
        std::fs::create_dir(&bin).unwrap();
        let launcher = bin.join("codex.cmd");
        std::fs::write(&launcher, "@exit /b 99").unwrap();
        let mut env = Env {
            home: root.path().into(),
            path: bin.into(),
            configured: None,
            roaming: None,
        };
        let Some(ProviderResolution::Executable(selected)) =
            resolve_provider_executable("codex", root.path(), &env).unwrap()
        else {
            panic!("npm shim missing")
        };
        assert_eq!(selected.path_for("codex"), Some(launcher.as_path()));
        let source = vec![
            "codex".into(),
            "two words".into(),
            "%LITERAL% & a'b".into(),
            "".into(),
        ];
        let wire = crate::login_shell_argv(
            &source,
            &crate::SelectedProviderLaunchEnv {
                env: &env,
                selected: Some(&selected),
            },
        );
        assert_eq!(wire[0], launcher.to_str().unwrap());
        assert_eq!(wire[1..], source[1..]);
        env.configured = Some(root.path().join("missing.exe"));
        assert!(resolve_provider_executable("codex", root.path(), &env)
            .unwrap()
            .is_none());
        env.configured = Some(launcher.clone());
        assert!(matches!(
            resolve_provider_executable("codex", root.path(), &env).unwrap(),
            Some(ProviderResolution::Executable(_))
        ));
        std::fs::remove_file(launcher).unwrap();
        assert!(!selected.remains_executable_for("codex"));
    }
}
