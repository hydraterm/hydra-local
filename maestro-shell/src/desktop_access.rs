//! Desktop protected-folder capability detection.
//!
//! macOS does not expose a public API that answers “does this process have Full Disk Access?”.
//! Reading TCC's database as a database would also be an unsupported private implementation
//! dependency. Instead, Hydra performs a capability probe using ordinary read-only filesystem APIs:
//! it opens an always-present FDA-protected file as an opaque one-byte witness and checks a small
//! set of FDA-protected user-data directories when they exist. The bytes are never parsed or
//! retained. This distinguishes a verified capability from an acknowledgement in Hydra's UI.
//!
//! Protected project paths are classified lexically before any filesystem access. This is
//! deliberate: canonicalizing a Desktop/Documents/iCloud path can itself trigger the TCC behavior
//! the caller is trying to avoid. An otherwise-unprotected path that crosses a symlink, or whose
//! components cannot be inspected, is treated as protected (fail closed).

use std::path::{Component, Path, PathBuf};

/// Stable machine-readable error code used when a protected macOS path is refused before access.
pub const FULL_DISK_ACCESS_REQUIRED_CODE: &str = "macos_full_disk_access_required";

/// The currently verified desktop protected-folder capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DesktopAccessStatus {
    /// At least one FDA-only witness was readable and every other existing witness was readable.
    Granted,
    /// An FDA-only witness exists but macOS denied access to it.
    Required,
    /// No reliable witness exists, or an I/O result was ambiguous. Callers must not infer a grant.
    Unknown,
    /// This platform has no macOS Full Disk Access boundary.
    NotApplicable,
}

/// Result of probing one known FDA-only witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DesktopAccessProbeResult {
    Accessible,
    Missing,
    PermissionDenied,
    Inconclusive,
}

/// Injectable boundary for the macOS capability probe.
pub trait DesktopAccessProbe {
    fn home_dir(&self) -> Option<PathBuf>;
    fn probe_file(&self, path: &Path) -> DesktopAccessProbeResult;
    fn probe_directory(&self, path: &Path) -> DesktopAccessProbeResult;
}

/// Reduce injected FDA-only witness results into a truthful status.
///
/// A denial always wins. A grant is reported only when at least one existing witness was readable
/// and every other existing witness was also readable. Missing witnesses are ignored; any other
/// I/O ambiguity keeps the status `Unknown`.
pub fn status_from_probe(probe: &impl DesktopAccessProbe) -> DesktopAccessStatus {
    let Some(home) = probe.home_dir() else {
        return DesktopAccessStatus::Unknown;
    };

    // This file is used only as an opaque capability witness. Hydra neither opens it as SQLite nor
    // queries TCC's private schema.
    let results = [
        probe.probe_file(
            &home
                .join("Library")
                .join("Application Support")
                .join("com.apple.TCC")
                .join("TCC.db"),
        ),
        probe.probe_directory(&home.join("Library").join("Mail")),
        probe.probe_directory(&home.join("Library").join("Messages")),
        probe.probe_directory(&home.join("Library").join("Safari")),
    ];

    if results.contains(&DesktopAccessProbeResult::PermissionDenied) {
        return DesktopAccessStatus::Required;
    }
    if results.contains(&DesktopAccessProbeResult::Inconclusive) {
        return DesktopAccessStatus::Unknown;
    }
    if results.contains(&DesktopAccessProbeResult::Accessible) {
        DesktopAccessStatus::Granted
    } else {
        DesktopAccessStatus::Unknown
    }
}

#[cfg(target_os = "macos")]
struct SystemDesktopAccessProbe;

#[cfg(target_os = "macos")]
impl DesktopAccessProbe for SystemDesktopAccessProbe {
    fn home_dir(&self) -> Option<PathBuf> {
        std::env::var_os("HOME").map(PathBuf::from)
    }

    fn probe_file(&self, path: &Path) -> DesktopAccessProbeResult {
        use std::io::Read;

        match std::fs::File::open(path) {
            Ok(mut file) => {
                let mut witness = [0_u8; 1];
                match file.read(&mut witness) {
                    Ok(0 | 1) => DesktopAccessProbeResult::Accessible,
                    Ok(_) => DesktopAccessProbeResult::Inconclusive,
                    Err(error) => probe_error(error),
                }
            }
            Err(error) => probe_error(error),
        }
    }

    fn probe_directory(&self, path: &Path) -> DesktopAccessProbeResult {
        match std::fs::read_dir(path) {
            Ok(_) => DesktopAccessProbeResult::Accessible,
            Err(error) => probe_error(error),
        }
    }
}

#[cfg(target_os = "macos")]
fn probe_error(error: std::io::Error) -> DesktopAccessProbeResult {
    match error.kind() {
        std::io::ErrorKind::NotFound => DesktopAccessProbeResult::Missing,
        std::io::ErrorKind::PermissionDenied => DesktopAccessProbeResult::PermissionDenied,
        _ if error.raw_os_error() == Some(libc::EPERM) => {
            DesktopAccessProbeResult::PermissionDenied
        }
        _ => DesktopAccessProbeResult::Inconclusive,
    }
}

/// Probe the current process's protected-folder capability.
///
/// This always performs a fresh macOS filesystem capability check. It never reads a persisted
/// acknowledgement and never reports `Granted` on platforms where the check is not applicable.
pub fn current_status() -> DesktopAccessStatus {
    #[cfg(target_os = "macos")]
    {
        status_from_probe(&SystemDesktopAccessProbe)
    }
    #[cfg(not(target_os = "macos"))]
    {
        DesktopAccessStatus::NotApplicable
    }
}

/// Filesystem-component result used by the injectable lexical-path classifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathComponentProbeResult {
    Ordinary,
    Symlink,
    Missing,
    Inconclusive,
}

/// Injectable environment/filesystem boundary for protected-path classification.
pub trait DesktopAccessPathProbe {
    fn home_dir(&self) -> Option<PathBuf>;
    fn current_dir(&self) -> Option<PathBuf>;
    fn inspect_component(&self, path: &Path) -> PathComponentProbeResult;
}

#[cfg(target_os = "macos")]
struct SystemDesktopAccessPathProbe;

#[cfg(target_os = "macos")]
impl DesktopAccessPathProbe for SystemDesktopAccessPathProbe {
    fn home_dir(&self) -> Option<PathBuf> {
        std::env::var_os("HOME").map(PathBuf::from)
    }

    fn current_dir(&self) -> Option<PathBuf> {
        std::env::current_dir().ok()
    }

    fn inspect_component(&self, path: &Path) -> PathComponentProbeResult {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => PathComponentProbeResult::Symlink,
            Ok(_) => PathComponentProbeResult::Ordinary,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                PathComponentProbeResult::Missing
            }
            Err(_) => PathComponentProbeResult::Inconclusive,
        }
    }
}

/// Return whether a project/cwd path requires macOS Full Disk Access.
///
/// Linux and other platforms return `false`. The injectable helper below contains the
/// platform-neutral classifier used by tests and by the macOS implementation.
pub fn path_requires_full_disk_access(path: &Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        path_requires_full_disk_access_with_probe(path, &SystemDesktopAccessPathProbe)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        false
    }
}

/// Injectable implementation of [`path_requires_full_disk_access`].
pub fn path_requires_full_disk_access_with_probe(
    path: &Path,
    probe: &impl DesktopAccessPathProbe,
) -> bool {
    let Some(current_dir) = probe.current_dir() else {
        return true;
    };
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else if current_dir.is_absolute() {
        current_dir.join(path)
    } else {
        return true;
    };
    // Do not normalize a parent traversal before the symlink walk. A path such as
    // `safe/link/../project` may cross `link` before returning to its parent, and proving otherwise
    // would require resolving filesystem state. Parent traversal is uncommon for the UI's absolute
    // project paths, so fail closed instead.
    if candidate
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return true;
    }
    let Some(absolute) = lexical_absolute(path, &current_dir) else {
        return true;
    };

    // Default macOS APFS volumes are case-insensitive. A differently-cased spelling still resolves
    // to the protected location, so an exact `Path::starts_with` check is not a safe boundary.
    let data_volume_root = Path::new("/System/Volumes/Data");
    if path_starts_with_ascii_case_insensitive(&absolute, Path::new("/Volumes"))
        || path_starts_with_ascii_case_insensitive(&absolute, &data_volume_root.join("Volumes"))
    {
        return true;
    }

    let Some(home) = probe.home_dir() else {
        // Without the user's home, the classifier cannot prove that an arbitrary path is outside
        // Desktop/Documents/iCloud. Refuse rather than silently miss a protected root.
        return true;
    };
    let Some(home) = lexical_absolute(&home, &current_dir) else {
        return true;
    };
    // The sealed-system-volume firmlink exposes the same home through both `/Users/<account>` and
    // `/System/Volumes/Data/Users/<account>`. Treat both spellings as one protected identity without
    // resolving either path (resolution could itself cross the TCC boundary).
    let mut home_aliases = vec![home.clone()];
    if let Some(suffix) = path_strip_prefix_ascii_case_insensitive(&home, data_volume_root) {
        home_aliases.push(Path::new("/").join(suffix));
    } else if let Some(suffix) = path_strip_prefix_ascii_case_insensitive(&home, Path::new("/")) {
        home_aliases.push(data_volume_root.join(suffix));
    }
    let mut protected = home_aliases.into_iter().flat_map(|home| {
        [
            home.join("Desktop"),
            home.join("Documents"),
            home.join("Downloads"),
            home.join("Library").join("Mobile Documents"),
            home.join("Library").join("CloudStorage"),
        ]
    });
    if protected.any(|root| path_starts_with_ascii_case_insensitive(&absolute, &root)) {
        return true;
    }

    // Never canonicalize. Walk with symlink_metadata so a link cannot redirect a lexically safe
    // cwd into a protected tree. Missing tails cannot currently be opened as a cwd; ambiguous
    // component access remains fail closed.
    let mut cursor = PathBuf::new();
    for component in absolute.components() {
        cursor.push(component.as_os_str());
        if matches!(component, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        match probe.inspect_component(&cursor) {
            PathComponentProbeResult::Ordinary => {}
            PathComponentProbeResult::Missing => return false,
            PathComponentProbeResult::Symlink | PathComponentProbeResult::Inconclusive => {
                return true
            }
        }
    }
    false
}

fn path_starts_with_ascii_case_insensitive(path: &Path, root: &Path) -> bool {
    path_strip_prefix_ascii_case_insensitive(path, root).is_some()
}

fn path_strip_prefix_ascii_case_insensitive(path: &Path, root: &Path) -> Option<PathBuf> {
    let mut path_components = path.components();
    for root_component in root.components() {
        let matches = path_components.next().is_some_and(|path_component| {
            path_component
                .as_os_str()
                .as_encoded_bytes()
                .eq_ignore_ascii_case(root_component.as_os_str().as_encoded_bytes())
        });
        if !matches {
            return None;
        }
    }
    Some(
        path_components
            .map(|component| component.as_os_str())
            .collect(),
    )
}

fn lexical_absolute(path: &Path, current_dir: &Path) -> Option<PathBuf> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else if current_dir.is_absolute() {
        current_dir.join(path)
    } else {
        return None;
    };
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = normalized.pop();
            }
            Component::Normal(value) => normalized.push(value),
        }
    }
    normalized.is_absolute().then_some(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct FakeStatusProbe {
        home: Option<PathBuf>,
        files: HashMap<PathBuf, DesktopAccessProbeResult>,
        directories: HashMap<PathBuf, DesktopAccessProbeResult>,
    }

    impl DesktopAccessProbe for FakeStatusProbe {
        fn home_dir(&self) -> Option<PathBuf> {
            self.home.clone()
        }

        fn probe_file(&self, path: &Path) -> DesktopAccessProbeResult {
            self.files
                .get(path)
                .copied()
                .unwrap_or(DesktopAccessProbeResult::Missing)
        }

        fn probe_directory(&self, path: &Path) -> DesktopAccessProbeResult {
            self.directories
                .get(path)
                .copied()
                .unwrap_or(DesktopAccessProbeResult::Missing)
        }
    }

    fn tcc_path(home: &Path) -> PathBuf {
        home.join("Library")
            .join("Application Support")
            .join("com.apple.TCC")
            .join("TCC.db")
    }

    #[test]
    fn status_granted_requires_a_successful_unambiguous_witness() {
        let home = PathBuf::from("/Users/test");
        let mut probe = FakeStatusProbe {
            home: Some(home.clone()),
            ..FakeStatusProbe::default()
        };
        probe
            .files
            .insert(tcc_path(&home), DesktopAccessProbeResult::Accessible);
        assert_eq!(status_from_probe(&probe), DesktopAccessStatus::Granted);
    }

    #[test]
    fn status_permission_denial_wins_over_other_successes() {
        let home = PathBuf::from("/Users/test");
        let mut probe = FakeStatusProbe {
            home: Some(home.clone()),
            ..FakeStatusProbe::default()
        };
        probe
            .files
            .insert(tcc_path(&home), DesktopAccessProbeResult::Accessible);
        probe.directories.insert(
            home.join("Library").join("Safari"),
            DesktopAccessProbeResult::PermissionDenied,
        );
        assert_eq!(status_from_probe(&probe), DesktopAccessStatus::Required);
    }

    #[test]
    fn status_ambiguous_or_witnessless_never_claims_granted() {
        let home = PathBuf::from("/Users/test");
        let missing = FakeStatusProbe {
            home: Some(home.clone()),
            ..FakeStatusProbe::default()
        };
        assert_eq!(status_from_probe(&missing), DesktopAccessStatus::Unknown);

        let mut ambiguous = FakeStatusProbe {
            home: Some(home.clone()),
            ..FakeStatusProbe::default()
        };
        ambiguous
            .files
            .insert(tcc_path(&home), DesktopAccessProbeResult::Accessible);
        ambiguous.directories.insert(
            home.join("Library").join("Mail"),
            DesktopAccessProbeResult::Inconclusive,
        );
        assert_eq!(status_from_probe(&ambiguous), DesktopAccessStatus::Unknown);
        assert_eq!(
            status_from_probe(&FakeStatusProbe::default()),
            DesktopAccessStatus::Unknown
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn current_status_is_not_applicable_off_macos() {
        assert_eq!(current_status(), DesktopAccessStatus::NotApplicable);
    }

    struct FakePathProbe {
        home: Option<PathBuf>,
        current: Option<PathBuf>,
        components: HashMap<PathBuf, PathComponentProbeResult>,
    }

    impl FakePathProbe {
        fn ordinary() -> Self {
            Self {
                home: Some(PathBuf::from("/Users/test")),
                current: Some(PathBuf::from("/Users/test/work")),
                components: HashMap::new(),
            }
        }
    }

    impl DesktopAccessPathProbe for FakePathProbe {
        fn home_dir(&self) -> Option<PathBuf> {
            self.home.clone()
        }

        fn current_dir(&self) -> Option<PathBuf> {
            self.current.clone()
        }

        fn inspect_component(&self, path: &Path) -> PathComponentProbeResult {
            self.components
                .get(path)
                .copied()
                .unwrap_or(PathComponentProbeResult::Ordinary)
        }
    }

    #[test]
    fn lexical_classifier_covers_all_protected_roots_without_prefix_confusion() {
        let probe = FakePathProbe::ordinary();
        for path in [
            "/Users/test/Desktop",
            "/Users/test/Desktop/project",
            "/users/TEST/desktop/project",
            "/Users/test/Documents/repo",
            "/USERS/test/documents/repo",
            "/Users/test/Downloads/repo",
            "/Users/test/Library/Mobile Documents/com~apple~CloudDocs/repo",
            "/users/test/library/mobile documents/com~apple~CloudDocs/repo",
            "/Users/test/Library/CloudStorage/provider/repo",
            "/Volumes/External/repo",
            "/volumes/External/repo",
            "/System/Volumes/Data/Users/test/Desktop/project",
            "/system/volumes/data/users/TEST/documents/project",
            "/System/Volumes/Data/Users/test/Library/CloudStorage/provider/repo",
            "/System/Volumes/Data/Volumes/External/repo",
        ] {
            assert!(
                path_requires_full_disk_access_with_probe(Path::new(path), &probe),
                "{path}"
            );
        }
        assert!(!path_requires_full_disk_access_with_probe(
            Path::new("/Users/test/Desktopish/repo"),
            &probe
        ));
        assert!(!path_requires_full_disk_access_with_probe(
            Path::new("/Users/test/work/repo"),
            &probe
        ));
        assert!(!path_requires_full_disk_access_with_probe(
            Path::new("/System/Volumes/Data/Users/test/Desktopish/repo"),
            &probe
        ));
        assert!(!path_requires_full_disk_access_with_probe(
            Path::new("/System/Volumes/Data/Users/test/work/repo"),
            &probe
        ));
    }

    #[test]
    fn data_volume_home_environment_also_protects_the_root_alias() {
        let mut probe = FakePathProbe::ordinary();
        probe.home = Some(PathBuf::from("/System/Volumes/Data/Users/test"));
        for path in [
            "/System/Volumes/Data/Users/test/Desktop/project",
            "/Users/test/Desktop/project",
            "/users/TEST/downloads/project",
        ] {
            assert!(
                path_requires_full_disk_access_with_probe(Path::new(path), &probe),
                "{path}"
            );
        }
    }

    #[test]
    fn lexical_normalization_cannot_escape_or_hide_a_protected_root() {
        let probe = FakePathProbe::ordinary();
        assert!(path_requires_full_disk_access_with_probe(
            Path::new("/Users/test/work/../Desktop/repo"),
            &probe
        ));
        assert!(path_requires_full_disk_access_with_probe(
            Path::new("../Documents/repo"),
            &probe
        ));
    }

    #[test]
    fn symlink_and_component_uncertainty_fail_closed_without_canonicalizing() {
        let mut symlink = FakePathProbe::ordinary();
        symlink.components.insert(
            PathBuf::from("/Users/test/work/link"),
            PathComponentProbeResult::Symlink,
        );
        assert!(path_requires_full_disk_access_with_probe(
            Path::new("/Users/test/work/link/repo"),
            &symlink
        ));

        let mut uncertain = FakePathProbe::ordinary();
        uncertain.components.insert(
            PathBuf::from("/Users/test/work/private"),
            PathComponentProbeResult::Inconclusive,
        );
        assert!(path_requires_full_disk_access_with_probe(
            Path::new("/Users/test/work/private/repo"),
            &uncertain
        ));

        let mut missing = FakePathProbe::ordinary();
        missing.components.insert(
            PathBuf::from("/Users/test/work/new"),
            PathComponentProbeResult::Missing,
        );
        assert!(!path_requires_full_disk_access_with_probe(
            Path::new("/Users/test/work/new/repo"),
            &missing
        ));
    }

    #[test]
    fn parent_traversal_cannot_hide_a_symlink_component() {
        let mut probe = FakePathProbe::ordinary();
        probe.components.insert(
            PathBuf::from("/Users/test/work/link"),
            PathComponentProbeResult::Symlink,
        );
        assert!(path_requires_full_disk_access_with_probe(
            Path::new("/Users/test/work/link/../repo"),
            &probe
        ));
    }

    #[test]
    fn missing_environment_context_fails_closed() {
        let mut probe = FakePathProbe::ordinary();
        probe.home = None;
        assert!(path_requires_full_disk_access_with_probe(
            Path::new("/Users/test/work/repo"),
            &probe
        ));
        probe.home = Some(PathBuf::from("/Users/test"));
        probe.current = None;
        assert!(path_requires_full_disk_access_with_probe(
            Path::new("repo"),
            &probe
        ));
    }
}
