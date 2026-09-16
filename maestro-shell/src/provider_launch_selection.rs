//! Platform-neutral, current-attempt provider selection. Resolving and validating an executable
//! remain platform operations; this carrier never changes a durable provider/conversation recipe.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// Launch-specific environment access preserves the old platform semantics: SHELL must be valid
/// UTF-8 or it is ignored, while HOME stays lossless until an absolute argv string is required.
pub trait LaunchEnvLookup {
    fn shell_utf8(&self) -> Option<String>;
    fn home_os(&self) -> Option<OsString>;
    fn path_os(&self) -> Option<OsString> {
        None
    }
    fn selected_provider_path(&self, _provider: &str) -> Option<PathBuf> {
        None
    }
}

/// An executable selected for this launch attempt, not a durable provider/conversation recipe.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderExecutable {
    provider: String,
    path: PathBuf,
}

impl std::fmt::Debug for ProviderExecutable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderExecutable")
            .field("provider", &self.provider)
            .finish_non_exhaustive()
    }
}

impl ProviderExecutable {
    pub(crate) fn new(provider: String, path: PathBuf) -> Self {
        Self { provider, path }
    }

    pub fn path_for(&self, provider: &str) -> Option<&Path> {
        (self.provider == provider).then_some(self.path.as_path())
    }
}

/// Preserve user environment while binding an already-selected executable to one provider only.
pub struct SelectedProviderLaunchEnv<'a, E> {
    pub env: &'a E,
    pub selected: Option<&'a ProviderExecutable>,
}

impl<E: LaunchEnvLookup> LaunchEnvLookup for SelectedProviderLaunchEnv<'_, E> {
    fn shell_utf8(&self) -> Option<String> {
        self.env.shell_utf8()
    }
    fn home_os(&self) -> Option<OsString> {
        self.env.home_os()
    }
    fn path_os(&self) -> Option<OsString> {
        self.env.path_os()
    }
    fn selected_provider_path(&self, provider: &str) -> Option<PathBuf> {
        self.selected
            .and_then(|selected| selected.path_for(provider).map(Path::to_path_buf))
            .or_else(|| self.env.selected_provider_path(provider))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        path: OsString,
    }

    impl LaunchEnvLookup for Fixture {
        fn shell_utf8(&self) -> Option<String> {
            Some("configured-shell".into())
        }
        fn home_os(&self) -> Option<OsString> {
            Some(self.path.clone())
        }
        fn path_os(&self) -> Option<OsString> {
            Some(self.path.clone())
        }
        fn selected_provider_path(&self, provider: &str) -> Option<PathBuf> {
            Some(PathBuf::from("underlying").join(provider))
        }
    }

    #[test]
    fn selection_is_provider_bound_and_does_not_replace_other_environment_values() {
        let path = PathBuf::from("owned fixture").join("λ cli #%.exe");
        let selected = ProviderExecutable::new("codex".into(), path.clone());
        let fixture = Fixture {
            path: "home".into(),
        };
        let env = SelectedProviderLaunchEnv {
            env: &fixture,
            selected: Some(&selected),
        };
        assert_eq!(selected.path_for("codex"), Some(path.as_path()));
        assert_eq!(selected.path_for("claude"), None);
        assert_eq!(env.selected_provider_path("codex"), Some(path));
        assert_eq!(
            env.selected_provider_path("claude"),
            fixture.selected_provider_path("claude")
        );
        assert_eq!(env.shell_utf8(), fixture.shell_utf8());
        assert_eq!(env.home_os(), fixture.home_os());
        assert_eq!(env.path_os(), fixture.path_os());
        assert_eq!(selected, selected.clone());
        assert_eq!(
            format!("{selected:?}"),
            "ProviderExecutable { provider: \"codex\", .. }"
        );
    }

    #[test]
    fn absent_selection_delegates_without_resolving_or_mutating_the_underlying_environment() {
        let fixture = Fixture {
            path: "home".into(),
        };
        let env = SelectedProviderLaunchEnv {
            env: &fixture,
            selected: None,
        };
        for provider in ["codex", "claude", "custom-wrapper"] {
            assert_eq!(
                env.selected_provider_path(provider),
                fixture.selected_provider_path(provider)
            );
        }
        assert_eq!(env.home_os(), fixture.home_os());
        assert_eq!(env.path_os(), fixture.path_os());
    }

    #[test]
    fn unimplemented_optional_lookups_keep_the_existing_none_defaults() {
        struct Minimal;
        impl LaunchEnvLookup for Minimal {
            fn shell_utf8(&self) -> Option<String> {
                None
            }
            fn home_os(&self) -> Option<OsString> {
                None
            }
        }
        let env = SelectedProviderLaunchEnv {
            env: &Minimal,
            selected: None,
        };
        assert_eq!(env.shell_utf8(), None);
        assert_eq!(env.home_os(), None);
        assert_eq!(env.path_os(), None);
        assert_eq!(env.selected_provider_path("codex"), None);
    }

    #[test]
    fn platform_native_paths_remain_lossless_through_selection_and_delegation() {
        #[cfg(unix)]
        let path = {
            use std::os::unix::ffi::OsStringExt;
            OsString::from_vec(b"/owned/invalid-\xff".to_vec())
        };
        #[cfg(windows)]
        let path = {
            use std::os::windows::ffi::OsStringExt;
            OsString::from_wide(&[0x43, 0x3a, 0x5c, 0xd800])
        };
        let selected = ProviderExecutable::new("codex".into(), PathBuf::from(&path));
        let fixture = Fixture { path: path.clone() };
        let env = SelectedProviderLaunchEnv {
            env: &fixture,
            selected: Some(&selected),
        };
        assert_eq!(env.home_os(), Some(path.clone()));
        assert_eq!(env.path_os(), Some(path.clone()));
        assert_eq!(
            env.selected_provider_path("codex"),
            Some(PathBuf::from(path))
        );
    }
}
