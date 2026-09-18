use std::io;
use std::path::{Path, PathBuf};

/// Return true only when an absolute path is written in its single canonical
/// textual form. `Path::components` deliberately normalizes repeated
/// separators, `.` and trailing separators, so component-only validation is
/// insufficient for authority-bearing strings that are persisted and later
/// compared byte-for-byte.
pub fn is_canonically_encoded_absolute_path(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    if path.components().any(|component| {
        matches!(
            component,
            std::path::Component::CurDir | std::path::Component::ParentDir
        )
    }) {
        return false;
    }
    let normalized = path.components().collect::<PathBuf>();
    path.as_os_str().as_encoded_bytes() == normalized.as_os_str().as_encoded_bytes()
}

/// Effective OS account id used by the private agent lifecycle. Unlike HOME,
/// XDG variables, or argv, this cannot be substituted by the public launcher.
#[cfg(unix)]
pub fn trusted_uid() -> u32 {
    unsafe { libc::geteuid() }
}

/// Create an owner-controlled directory without consulting the caller's
/// ambient umask, or validate an existing compatible directory before any
/// authority-bearing child is created. Existing read/execute access remains
/// compatible, but group/world write access, foreign ownership, and a symlink
/// leaf fail closed rather than being silently chmod'd.
#[cfg(unix)]
pub fn ensure_owned_safe_directory(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    let existed = match std::fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(error),
    };
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(path)?;
    require_owned_safe_directory(path)?;
    if !existed {
        let parent = path.parent().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "safe directory has no parent")
        })?;
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Establish or validate the private agent authority root. Existing unsafe
/// modes are never repaired implicitly: the Linux 0.2.8 legacy authority and its exact service
/// ancestry are handled only by the explicit ten-path, receipt-backed `authority_migration` flow.
#[cfg(unix)]
pub fn ensure_owned_safe_authority_directory(path: &std::path::Path) -> io::Result<()> {
    let trusted_home = trusted_home_dir()?;
    ensure_owned_safe_authority_directory_with_home(path, &trusted_home)
}

#[cfg(unix)]
fn ensure_owned_safe_authority_directory_with_home(
    path: &Path,
    trusted_home: &Path,
) -> io::Result<()> {
    if !is_canonically_encoded_absolute_path(path) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Hydra authority directory is not a canonically encoded absolute path",
        ));
    }
    if !is_canonically_encoded_absolute_path(trusted_home) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "trusted home is not a canonically encoded absolute path",
        ));
    }
    let default = trusted_home.join(".local/share/hydra-agent");
    if path == default {
        return ensure_default_authority_directory(path, trusted_home);
    }

    // Custom/XDG-derived historical roots are accepted only when their
    // existing ancestry is already rename-resistant. They never authorize an
    // automatic chmod outside Hydra's fixed default path.
    require_rename_safe_ancestry(path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "authority directory has no parent",
        )
    })?)?;
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return ensure_owned_safe_directory(path)
        }
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    require_owned_safe_directory(path)
}

#[cfg(unix)]
fn ensure_default_authority_directory(path: &Path, trusted_home: &Path) -> io::Result<()> {
    require_rename_safe_ancestry(trusted_home)?;
    require_owned_safe_directory(trusted_home)?;
    let local = trusted_home.join(".local");
    let share = local.join("share");
    let ancestry = [&local, &share];

    let leaf = match std::fs::symlink_metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };

    if leaf.is_none() {
        for component in ancestry {
            match std::fs::symlink_metadata(component) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    ensure_owned_safe_directory(component)?;
                }
                Err(error) => return Err(error),
                Ok(_) => require_owned_safe_directory(component)?,
            }
        }
        ensure_owned_safe_directory(path)?;
        require_rename_safe_ancestry(path.parent().expect("default authority has parent"))?;
        return Ok(());
    }

    require_owned_safe_directory(path)?;
    for component in ancestry {
        require_owned_safe_directory(component)?;
    }
    require_rename_safe_ancestry(path.parent().expect("default authority has parent"))
}

/// Prove that no ancestor can be renamed by an unrelated group/world user.
/// Sticky shared roots (for example `/tmp`) are accepted because the kernel
/// prevents another UID from replacing a victim-owned child there. This is a
/// validation primitive only; it never changes ancestry permissions.
#[cfg(unix)]
pub fn require_rename_safe_ancestry(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if !is_canonically_encoded_absolute_path(path) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Hydra authority ancestry is not a canonically encoded absolute path",
        ));
    }
    let mut lexical = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => lexical.push(Path::new("/")),
            std::path::Component::Normal(name) => lexical.push(name),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Hydra authority ancestry contains a non-lexical component",
                ));
            }
        }
        let metadata = std::fs::symlink_metadata(&lexical)?;
        let mode = metadata.permissions().mode();
        let owner = metadata.uid();
        if !metadata.file_type().is_dir()
            || (owner != 0 && owner != trusted_uid())
            || (mode & 0o022 != 0 && mode & 0o1000 == 0)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Hydra authority ancestry permits path substitution",
            ));
        }
    }
    Ok(())
}

/// Test-only seam for exercising the fixed `~/.local/share/hydra-agent`
/// migration against a synthetic trusted home. Production always derives this
/// value from the effective account database and cannot inject it.
#[cfg(all(test, unix))]
pub(crate) fn ensure_owned_safe_authority_directory_for_test_home(
    path: &Path,
    trusted_home: &Path,
) -> io::Result<()> {
    ensure_owned_safe_authority_directory_with_home(path, trusted_home)
}

/// Build a synthetic authority root beneath the kernel-protected shared
/// temporary directory. macOS's per-user TMPDIR can contain group-writable,
/// non-sticky ancestors; production correctly rejects that ancestry, so tests
/// that need a valid authority root must not inherit it accidentally.
#[cfg(all(test, unix))]
pub fn secure_authority_test_dir(prefix: &str) -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt as _;

    let shared = std::fs::canonicalize("/tmp").expect("resolve protected test temp root");
    let root = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(shared)
        .expect("create protected authority fixture");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
        .expect("make authority fixture owner-private");
    root
}

/// Establish an application-owned service directory when absent, or validate
/// an existing one without changing its inode, bytes, ownership, or mode.
/// Ordinary callers never repair an existing service/state/log path. The only
/// exception is the separately invoked, receipt-backed Linux 0.2.8 ten-path
/// migration, which binds and updates its exact default state/log ancestry.
#[cfg(unix)]
pub fn ensure_owned_safe_private_service_directory(path: &std::path::Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return ensure_owned_safe_directory(path)
        }
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    require_owned_safe_directory(path)
}

#[cfg(unix)]
pub fn require_owned_safe_directory(path: &std::path::Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != trusted_uid()
        || metadata.permissions().mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Hydra authority directory has unsafe metadata",
        ));
    }
    Ok(())
}

#[cfg(unix)]
struct TrustedAccountPaths {
    home: PathBuf,
    login_shell: Option<PathBuf>,
}

/// One atomic effective-account snapshot for headless session creation. Fetching passwd once avoids
/// mixing HOME from one NSS generation with SHELL from another during an account update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedSessionAccount {
    pub home: PathBuf,
    pub shell: String,
}

#[cfg(unix)]
fn trusted_account_paths() -> io::Result<TrustedAccountPaths> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStringExt as _;

    let uid = trusted_uid();
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut capacity = if suggested > 0 {
        suggested as usize
    } else {
        16 * 1024
    }
    .clamp(1024, 1024 * 1024);

    loop {
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0u8; capacity];
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                &mut entry,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && capacity < 1024 * 1024 {
            capacity = (capacity * 2).min(1024 * 1024);
            continue;
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status));
        }
        if result.is_null() || entry.pw_dir.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "effective OS account has no home directory",
            ));
        }
        let home_bytes = unsafe { CStr::from_ptr(entry.pw_dir) }.to_bytes();
        let home = PathBuf::from(std::ffi::OsString::from_vec(home_bytes.to_vec()));
        if !home.is_absolute() || home == std::path::Path::new("/") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "effective OS account home is not a private absolute path",
            ));
        }
        let login_shell = if entry.pw_shell.is_null() {
            None
        } else {
            let bytes = unsafe { CStr::from_ptr(entry.pw_shell) }.to_bytes();
            (!bytes.is_empty()).then(|| PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec())))
        };
        return Ok(TrustedAccountPaths { home, login_shell });
    }
}

/// Resolve the effective user's home through the OS account database. The
/// optional extension deliberately ignores HOME/XDG overrides because they
/// would redirect enrollment and service authority into launcher-chosen state.
#[cfg(unix)]
pub fn trusted_home_dir() -> io::Result<PathBuf> {
    Ok(trusted_account_paths()?.home)
}

/// Resolve the effective account's configured login shell without consulting
/// the caller-controlled `SHELL` environment variable. An empty passwd shell
/// has the traditional `/bin/sh` meaning. A non-empty configured shell must be
/// an absolute, executable, non-writable regular file owned by root or the
/// effective account. A missing or unsafe configured executable falls back to
/// the separately validated platform shell rather than being executed.
#[cfg(unix)]
pub fn trusted_login_shell() -> io::Result<String> {
    let account = trusted_account_paths()?;
    validated_login_shell_or_fallback(account.login_shell.as_deref(), Path::new("/bin/sh"))
}

#[cfg(unix)]
pub fn trusted_session_account() -> io::Result<TrustedSessionAccount> {
    let account = trusted_account_paths()?;
    validate_trusted_session_home(&account.home)?;
    let shell =
        validated_login_shell_or_fallback(account.login_shell.as_deref(), Path::new("/bin/sh"))?;
    Ok(TrustedSessionAccount {
        home: account.home,
        shell,
    })
}

#[cfg(unix)]
fn validate_trusted_session_home(home: &Path) -> io::Result<()> {
    let home_text = home.to_str().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "effective OS account home is not UTF-8",
        )
    })?;
    if home_text.chars().any(char::is_control)
        || !is_canonically_encoded_absolute_path(home)
        || home == Path::new("/")
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "effective OS account home is not a private canonical UTF-8 path",
        ));
    }
    require_rename_safe_ancestry(home)?;
    require_owned_safe_directory(home)
}

#[cfg(unix)]
fn validated_login_shell_or_fallback(
    configured: Option<&Path>,
    fallback: &Path,
) -> io::Result<String> {
    match configured {
        Some(shell) => validate_login_shell(shell).or_else(|_| validate_login_shell(fallback)),
        None => validate_login_shell(fallback),
    }
}

#[cfg(unix)]
pub(crate) fn validate_login_shell(shell: &Path) -> io::Result<String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let shell_text = shell
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "login shell is not UTF-8"))?;
    if shell_text.chars().any(char::is_control) || !is_canonically_encoded_absolute_path(shell) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "effective OS account login shell is not a canonical absolute path",
        ));
    }
    require_safe_login_shell_route(shell)?;
    let canonical = std::fs::canonicalize(shell)?;
    if !is_canonically_encoded_absolute_path(&canonical) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "effective OS account login shell target is not canonical",
        ));
    }
    require_rename_safe_ancestry(canonical.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "effective OS account login shell has no parent",
        )
    })?)?;
    let metadata = std::fs::metadata(&canonical)?;
    let mode = metadata.permissions().mode();
    if !metadata.file_type().is_file()
        || (metadata.uid() != 0 && metadata.uid() != trusted_uid())
        || mode & 0o111 == 0
        || mode & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "effective OS account login shell has unsafe metadata",
        ));
    }
    Ok(shell_text.to_owned())
}

/// Validate the account-database spelling as well as its resolved target. This
/// permits conventional root-owned aliases such as `/bin -> /usr/bin`, while
/// refusing a shell reached through a path component another Unix account can
/// replace between validation and daemon exec.
#[cfg(unix)]
fn require_safe_login_shell_route(shell: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let mut lexical = PathBuf::new();
    let mut components = shell.components().peekable();
    while let Some(component) = components.next() {
        match component {
            std::path::Component::RootDir => lexical.push(Path::new("/")),
            std::path::Component::Normal(name) => lexical.push(name),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "effective OS account login shell route is not lexical",
                ));
            }
        }
        let metadata = std::fs::symlink_metadata(&lexical)?;
        let owner_is_trusted = metadata.uid() == 0 || metadata.uid() == trusted_uid();
        let is_leaf = components.peek().is_none();
        let safe_kind = if is_leaf {
            metadata.file_type().is_file() || metadata.file_type().is_symlink()
        } else if metadata.file_type().is_dir() {
            let mode = metadata.permissions().mode();
            mode & 0o022 == 0 || mode & 0o1000 != 0
        } else {
            metadata.file_type().is_symlink()
        };
        if !owner_is_trusted || !safe_kind {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "effective OS account login shell route has unsafe metadata",
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn trusted_uid() -> u32 {
    0
}

#[cfg(not(unix))]
pub fn ensure_owned_safe_directory(path: &std::path::Path) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    require_owned_safe_directory(path)
}

#[cfg(not(unix))]
pub fn ensure_owned_safe_authority_directory(path: &std::path::Path) -> io::Result<()> {
    ensure_owned_safe_directory(path)
}

#[cfg(not(unix))]
pub fn ensure_owned_safe_private_service_directory(path: &std::path::Path) -> io::Result<()> {
    ensure_owned_safe_directory(path)
}

#[cfg(not(unix))]
pub fn require_owned_safe_directory(path: &std::path::Path) -> io::Result<()> {
    if std::fs::metadata(path)?.is_dir() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Hydra authority path is not a directory",
        ))
    }
}

#[cfg(not(unix))]
pub fn trusted_home_dir() -> io::Result<PathBuf> {
    dirs::home_dir().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "effective OS account has no home directory",
        )
    })
}

#[cfg(not(unix))]
pub fn trusted_session_account() -> io::Result<TrustedSessionAccount> {
    Ok(TrustedSessionAccount {
        home: trusted_home_dir()?,
        shell: String::new(),
    })
}

/// Default per-user directory for private identity and lifecycle state.
pub fn default_agent_dir() -> io::Result<PathBuf> {
    Ok(trusted_home_dir()?.join(".local/share/hydra-agent"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_paths_are_absolute_and_do_not_consult_process_home() {
        let home = trusted_home_dir().unwrap();
        let dir = default_agent_dir().unwrap();
        assert!(home.is_absolute());
        assert_eq!(dir, home.join(".local/share/hydra-agent"));
    }

    #[cfg(unix)]
    #[test]
    fn login_shell_validation_accepts_only_safe_absolute_executables() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let fixture = secure_authority_test_dir("hydra-login-shell-");
        let shell = fixture.path().join("account-shell");
        std::fs::write(&shell, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&shell, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            validate_login_shell(&shell).unwrap(),
            shell.to_str().unwrap()
        );

        let alias = fixture.path().join("shell-alias");
        symlink(&shell, &alias).unwrap();
        assert_eq!(
            validate_login_shell(&alias).unwrap(),
            alias.to_str().unwrap(),
            "validation may resolve a safe target but preserves the account's invocation name"
        );

        assert!(validate_login_shell(Path::new("relative-shell")).is_err());
        std::fs::set_permissions(&shell, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_login_shell(&shell).is_err());
        std::fs::set_permissions(&shell, std::fs::Permissions::from_mode(0o722)).unwrap();
        assert!(validate_login_shell(&shell).is_err());
        assert!(validate_login_shell(fixture.path()).is_err());

        let control_shell = fixture.path().join("account\nshell");
        std::fs::write(&control_shell, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&control_shell, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(validate_login_shell(&control_shell).is_err());

        std::fs::set_permissions(&shell, std::fs::Permissions::from_mode(0o700)).unwrap();
        let unsafe_parent = fixture.path().join("replaceable");
        std::fs::create_dir(&unsafe_parent).unwrap();
        std::fs::set_permissions(&unsafe_parent, std::fs::Permissions::from_mode(0o777)).unwrap();
        let unsafe_alias = unsafe_parent.join("shell-alias");
        symlink(&shell, &unsafe_alias).unwrap();
        assert!(
            validate_login_shell(&unsafe_alias).is_err(),
            "a safe resolved target does not excuse a replaceable account path"
        );
    }

    #[cfg(unix)]
    #[test]
    fn invalid_account_shell_uses_a_separately_validated_fallback() {
        use std::os::unix::fs::PermissionsExt as _;

        let fixture = secure_authority_test_dir("hydra-login-shell-fallback-");
        let invalid = fixture.path().join("missing-shell");
        let fallback = fixture.path().join("fallback-shell");
        std::fs::write(&fallback, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&fallback, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert_eq!(
            validated_login_shell_or_fallback(Some(&invalid), &fallback).unwrap(),
            fallback.to_str().unwrap()
        );
        assert_eq!(
            validated_login_shell_or_fallback(None, &fallback).unwrap(),
            fallback.to_str().unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn trusted_session_home_rejects_replaceable_or_foreign_authority() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let fixture = secure_authority_test_dir("hydra-session-home-");
        let safe = fixture.path().join("safe-home");
        std::fs::create_dir(&safe).unwrap();
        std::fs::set_permissions(&safe, std::fs::Permissions::from_mode(0o750)).unwrap();
        validate_trusted_session_home(&safe).expect("owner-controlled home is accepted");

        let writable = fixture.path().join("writable-home");
        std::fs::create_dir(&writable).unwrap();
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(validate_trusted_session_home(&writable).is_err());

        let alias = fixture.path().join("home-alias");
        symlink(&safe, &alias).unwrap();
        assert!(validate_trusted_session_home(&alias).is_err());

        let control_home = fixture.path().join("account\nhome");
        std::fs::create_dir(&control_home).unwrap();
        std::fs::set_permissions(&control_home, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(validate_trusted_session_home(&control_home).is_err());

        if trusted_uid() != 0 {
            assert!(
                validate_trusted_session_home(Path::new("/usr")).is_err(),
                "a root-owned directory is not this Unix account's HOME authority"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_authority_ensure_rejects_legacy_roots_without_mutation() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        for mode in [0o770, 0o775] {
            let fixture = tempfile::tempdir().unwrap();
            let home = std::fs::canonicalize(fixture.path()).unwrap();
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
            let local = home.join(".local");
            let share = local.join("share");
            let root = share.join("hydra-agent");
            std::fs::create_dir_all(&root).unwrap();
            std::fs::set_permissions(&local, std::fs::Permissions::from_mode(mode)).unwrap();
            std::fs::set_permissions(&share, std::fs::Permissions::from_mode(mode)).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(mode)).unwrap();
            let key = root.join("device-key");
            std::fs::write(&key, b"synthetic-owner-only-key").unwrap();
            std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
            let before = std::fs::symlink_metadata(&root).unwrap();

            assert!(ensure_owned_safe_authority_directory_for_test_home(&root, &home).is_err());

            let after = std::fs::symlink_metadata(&root).unwrap();
            assert_eq!(after.dev(), before.dev());
            assert_eq!(after.ino(), before.ino());
            assert_eq!(after.uid(), trusted_uid());
            assert_eq!(after.permissions().mode() & 0o777, mode);
            assert_eq!(
                std::fs::symlink_metadata(key).unwrap().permissions().mode() & 0o777,
                0o600,
                "ordinary validation must not rewrite authority children"
            );
            assert_eq!(
                std::fs::symlink_metadata(local)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                mode
            );
            assert_eq!(
                std::fs::symlink_metadata(share)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                mode
            );
        }

        let fixture = tempfile::tempdir().unwrap();
        let fixture = std::fs::canonicalize(fixture.path()).unwrap();
        let already_safe = fixture.join("private-750");
        std::fs::create_dir(&already_safe).unwrap();
        std::fs::set_permissions(&already_safe, std::fs::Permissions::from_mode(0o750)).unwrap();
        ensure_owned_safe_private_service_directory(&already_safe).unwrap();
        assert_eq!(
            std::fs::symlink_metadata(already_safe)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o750,
            "an already non-writable private service directory remains unchanged"
        );
    }

    #[cfg(unix)]
    #[test]
    fn authority_validation_rejects_unsafe_modes_and_symlink_leaves() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let fixture_handle = tempfile::tempdir().unwrap();
        std::fs::set_permissions(
            fixture_handle.path(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let fixture = std::fs::canonicalize(fixture_handle.path()).unwrap();
        let safe = fixture.join("safe-narrow");
        std::fs::create_dir(&safe).unwrap();
        std::fs::set_permissions(&safe, std::fs::Permissions::from_mode(0o750)).unwrap();
        ensure_owned_safe_authority_directory(&safe).unwrap();
        assert_eq!(
            std::fs::symlink_metadata(&safe)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o750,
            "already-safe read/execute access remains compatible"
        );

        for (name, mode) in [("world", 0o777), ("unsupported-group-write", 0o760)] {
            let root = fixture.join(name);
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(ensure_owned_safe_authority_directory(&root).is_err());
            assert_eq!(
                std::fs::symlink_metadata(&root)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                mode,
                "custom authority roots are never auto-repaired"
            );
        }
        let target = fixture.join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o775)).unwrap();
        let alias = fixture.join("alias");
        symlink(&target, &alias).unwrap();
        assert!(ensure_owned_safe_authority_directory(&alias).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn default_authority_repair_rejects_symlinked_local_or_share_without_mutation() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        for symlink_component in ["local", "share"] {
            let fixture = tempfile::tempdir().unwrap();
            let home = std::fs::canonicalize(fixture.path()).unwrap();
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
            let outside = home.join(format!("outside-{symlink_component}"));
            std::fs::create_dir(&outside).unwrap();
            std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o775)).unwrap();
            let local = home.join(".local");
            if symlink_component == "local" {
                symlink(&outside, &local).unwrap();
            } else {
                std::fs::create_dir(&local).unwrap();
                std::fs::set_permissions(&local, std::fs::Permissions::from_mode(0o755)).unwrap();
                symlink(&outside, local.join("share")).unwrap();
            }
            let agent = local.join("share/hydra-agent");

            assert!(ensure_owned_safe_authority_directory_for_test_home(&agent, &home).is_err());
            assert_eq!(
                std::fs::symlink_metadata(&outside)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o775,
                "a symlink target must never be chmod'd"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn authority_paths_reject_every_noncanonical_textual_alias() {
        let fixture = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(fixture.path()).unwrap();
        let canonical = root.join("hydra-agent");
        let aliases = [
            PathBuf::from(format!("{}/", canonical.display())),
            PathBuf::from(format!("{}//", canonical.display())),
            PathBuf::from(format!("{}/./", canonical.display())),
            root.join("hydra-agent/../hydra-agent"),
        ];
        for alias in aliases {
            assert!(!is_canonically_encoded_absolute_path(&alias));
            assert!(ensure_owned_safe_authority_directory(&alias).is_err());
        }
        assert!(!canonical.exists());
    }

    #[cfg(unix)]
    #[test]
    fn existing_unsafe_private_service_dirs_are_rejected_without_mutation() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let fixture = tempfile::tempdir().unwrap();
        for mode in [0o770, 0o775] {
            let dir = fixture.path().join(format!("private-{mode:o}"));
            std::fs::create_dir(&dir).unwrap();
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode)).unwrap();
            let before = std::fs::symlink_metadata(&dir).unwrap();
            assert!(ensure_owned_safe_private_service_directory(&dir).is_err());
            let after = std::fs::symlink_metadata(&dir).unwrap();
            assert_eq!(after.dev(), before.dev());
            assert_eq!(after.ino(), before.ino());
            assert_eq!(after.uid(), before.uid());
            assert_eq!(after.permissions().mode() & 0o777, mode);
        }

        let shared = fixture.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(ensure_owned_safe_directory(&shared).is_err());
        assert_eq!(
            std::fs::symlink_metadata(shared)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o775
        );
    }
}
