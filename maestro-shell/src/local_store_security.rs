//! Fail-closed filesystem boundary for the SQLite-backed local store.
//!
//! The desktop app and `hydra-agent` are separate processes, but they share one app-support
//! directory.  Before either process creates a migration/schema lock or lets SQLite inspect a
//! path, this module walks the directory by descriptor, refuses user-controlled symlinks and
//! ambiguous ancestry, and pins the base to the current Unix user at `0700`.  Store files are
//! opened relative to that descriptor with `O_NOFOLLOW`, then owner/type/link/mode are checked on
//! the returned descriptor.  This narrows path races to the explicitly trusted same-UID boundary.

use std::ffi::{CString, OsStr};
use std::fs::{self, File};
use std::io;
use std::path::{Component, Path};

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

pub(crate) const OWNER_DIR_MODE: u32 = 0o700;
pub(crate) const OWNER_FILE_MODE: u32 = 0o600;

/// A verified descriptor for the current user's real app-support base.
#[derive(Debug)]
pub(crate) struct SecureAppSupport {
    dir: File,
}

impl SecureAppSupport {
    /// Walk, create where absent, and secure `base` without following a user-controlled link.
    pub(crate) fn open(base: &Path) -> io::Result<Self> {
        secure_app_support(base)
    }

    /// Open or create one direct child as an owner-only, singly-linked regular file.
    pub(crate) fn open_owner_file(&self, name: &OsStr, create_new: bool) -> io::Result<File> {
        open_owner_file_at(&self.dir, name, true, create_new)
    }

    /// Open one existing direct child without creating authority on absence.
    pub(crate) fn open_existing_owner_file(&self, name: &OsStr) -> io::Result<File> {
        open_owner_file_at(&self.dir, name, false, false)
    }

    /// Secure an existing direct child. `Ok(false)` means it does not exist.
    pub(crate) fn secure_existing_file(&self, name: &OsStr) -> io::Result<bool> {
        match self.open_existing_owner_file(name) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[cfg(unix)]
fn secure_app_support(base: &Path) -> io::Result<SecureAppSupport> {
    if !base.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "app-support base must be absolute",
        ));
    }

    let current_uid = unsafe { libc::geteuid() };
    let mut current = open_root()?;
    let mut normals = base
        .components()
        .filter_map(|component| match component {
            Component::RootDir => None,
            Component::Normal(name) => Some(Ok(name)),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                Some(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "app-support base contains a non-normal component",
                )))
            }
        })
        .peekable();

    if normals.peek().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "app-support base cannot be the filesystem root",
        ));
    }

    while let Some(component) = normals.next() {
        let name = component?;
        let is_base = normals.peek().is_none();
        let next = match open_directory_at(&current, name) {
            Ok(dir) => dir,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                mkdir_owner_at(&current, name)?;
                open_directory_at(&current, name)?
            }
            Err(error) => return Err(error),
        };
        validate_ancestor(&next, current_uid, is_base)?;
        if is_base {
            set_and_verify_mode(&next, OWNER_DIR_MODE)?;
        }
        current = next;
    }

    Ok(SecureAppSupport { dir: current })
}

#[cfg(not(unix))]
fn secure_app_support(_base: &Path) -> io::Result<SecureAppSupport> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the Hydra local store requires Unix descriptor security",
    ))
}

#[cfg(unix)]
fn open_root() -> io::Result<File> {
    let root = CString::new("/").unwrap();
    // SAFETY: `root` is a valid NUL-terminated path, and a successful descriptor is immediately
    // transferred into `File` ownership.
    let fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    file_from_fd(fd)
}

#[cfg(unix)]
fn open_directory_at(parent: &File, name: &OsStr) -> io::Result<File> {
    let name = c_name(name)?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    // SAFETY: both the directory descriptor and NUL-terminated child name are live for the call.
    let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if fd >= 0 {
        return file_from_fd(fd);
    }
    let error = io::Error::last_os_error();
    // Darwin reports `ENOTDIR` rather than `ELOOP` for `O_DIRECTORY | O_NOFOLLOW` on a symlink.
    if error.raw_os_error() != Some(libc::ELOOP) && error.raw_os_error() != Some(libc::ENOTDIR) {
        return Err(error);
    }

    // macOS exposes trusted system aliases such as `/var -> private/var`.  A root-owned link in a
    // previously validated directory is outside the unprivileged local-user threat boundary; it
    // may be followed.  Every user-owned or foreign link remains a hard refusal.
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `stat` points to writable storage and the other arguments remain live.
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful `fstatat` initialized `stat`.
    let stat = unsafe { stat.assume_init() };
    if (stat.st_mode & libc::S_IFMT) != libc::S_IFLNK {
        return Err(error);
    }
    if stat.st_uid != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "app-support ancestry contains a non-system symlink",
        ));
    }
    // SAFETY: root ownership permits following this system alias only far enough to obtain a
    // descriptor. The target is still subject to owner, mode, and ACL validation below.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    file_from_fd(fd)
}

#[cfg(unix)]
fn mkdir_owner_at(parent: &File, name: &OsStr) -> io::Result<()> {
    let name = c_name(name)?;
    // SAFETY: the parent descriptor and NUL-terminated child name are live for the call.
    let result = unsafe {
        libc::mkdirat(
            parent.as_raw_fd(),
            name.as_ptr(),
            OWNER_DIR_MODE as libc::mode_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        let error = io::Error::last_os_error();
        // A concurrent creator is classified by the subsequent no-follow open and owner check.
        if error.kind() == io::ErrorKind::AlreadyExists {
            Ok(())
        } else {
            Err(error)
        }
    }
}

#[cfg(unix)]
fn validate_ancestor(dir: &File, current_uid: u32, is_base: bool) -> io::Result<()> {
    let metadata = dir.metadata()?;
    if !metadata.file_type().is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "app-support ancestry is not a directory",
        ));
    }
    let owner = metadata.uid();
    if (owner != 0 || is_base) && owner != current_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "app-support ancestry has foreign ownership",
        ));
    }
    let mode = metadata.mode();
    let writable_by_others = mode & 0o022 != 0;
    let sticky = u64::from(mode) & u64::from(libc::S_ISVTX) != 0;
    if !is_base && writable_by_others && !sticky {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "app-support ancestry is writable by another local user without sticky protection",
        ));
    }
    #[cfg(target_os = "macos")]
    if !is_base && macos_acl_has_allow_entry(dir)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "app-support ancestry has an extended ACL allow entry",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn open_owner_file_at(
    base: &File,
    name: &OsStr,
    create: bool,
    create_new: bool,
) -> io::Result<File> {
    if Path::new(name).components().count() != 1
        || !matches!(
            Path::new(name).components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "store filename must be one normal path component",
        ));
    }
    let name = c_name(name)?;
    let access = if create { libc::O_RDWR } else { libc::O_RDONLY };
    let flags = access | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    let file = if create_new {
        open_file_at_raw(base, &name, flags | libc::O_CREAT | libc::O_EXCL)?
    } else if create {
        match open_file_at_raw(base, &name, flags) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                match open_file_at_raw(base, &name, flags | libc::O_CREAT | libc::O_EXCL) {
                    Ok(file) => file,
                    // Another cooperating process won creation. Classify the exact object it
                    // published rather than treating a harmless first-open race as startup loss.
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        open_file_at_raw(base, &name, flags)?
                    }
                    Err(error) => return Err(error),
                }
            }
            Err(error) => return Err(error),
        }
    } else {
        open_file_at_raw(base, &name, flags)?
    };
    validate_owner_file(&file, unsafe { libc::geteuid() })?;
    set_and_verify_mode(&file, OWNER_FILE_MODE)?;
    validate_owner_file(&file, unsafe { libc::geteuid() })?;
    Ok(file)
}

#[cfg(unix)]
fn open_file_at_raw(base: &File, name: &CString, flags: libc::c_int) -> io::Result<File> {
    // SAFETY: the base descriptor and NUL-terminated child name remain live, and a successful
    // descriptor is immediately transferred into `File` ownership.
    let fd = unsafe {
        libc::openat(
            base.as_raw_fd(),
            name.as_ptr(),
            flags,
            OWNER_FILE_MODE as libc::c_int,
        )
    };
    file_from_fd(fd)
}

#[cfg(not(unix))]
fn open_owner_file_at(
    _base: &File,
    _name: &OsStr,
    _create: bool,
    _create_new: bool,
) -> io::Result<File> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "the Hydra local store requires Unix descriptor security",
    ))
}

#[cfg(unix)]
fn validate_owner_file(file: &File, current_uid: u32) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "store authority is not a regular file",
        ));
    }
    if metadata.uid() != current_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "store authority has foreign ownership",
        ));
    }
    // SQLite deletes transient WAL/SHM/journal paths when their last connection closes. If that
    // happens after our no-follow open, this descriptor has zero links and no longer names store
    // authority. Report ordinary absence so optional-sidecar callers can accept the completed
    // cleanup; link counts above one remain a hard failure below.
    if metadata.nlink() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "store authority was unlinked during descriptor validation",
        ));
    }
    if metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "store authority has an unsafe hard-link count",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn set_and_verify_mode(file: &File, expected: u32) -> io::Result<()> {
    clear_and_verify_extended_acl(file)?;
    file.set_permissions(fs::Permissions::from_mode(expected))?;
    let observed = file.metadata()?.mode() & 0o7777;
    if observed != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("filesystem retained mode {observed:#o}; expected {expected:#o}"),
        ));
    }
    verify_no_extended_acl(file)?;
    Ok(())
}

#[cfg(target_os = "macos")]
type MacAcl = *mut libc::c_void;

#[cfg(target_os = "macos")]
const MAC_ACL_TYPE_EXTENDED: libc::c_int = 0x100;
#[cfg(target_os = "macos")]
const MAC_ACL_FIRST_ENTRY: libc::c_int = 0;
#[cfg(target_os = "macos")]
const MAC_ACL_NEXT_ENTRY: libc::c_int = -1;
#[cfg(target_os = "macos")]
const MAC_ACL_EXTENDED_ALLOW: libc::c_int = 1;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn acl_init(count: libc::c_int) -> MacAcl;
    fn acl_free(object: *mut libc::c_void) -> libc::c_int;
    fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> MacAcl;
    fn acl_set_fd_np(fd: libc::c_int, acl: MacAcl, acl_type: libc::c_int) -> libc::c_int;
    fn acl_get_entry(
        acl: MacAcl,
        entry_id: libc::c_int,
        entry: *mut *mut libc::c_void,
    ) -> libc::c_int;
    fn acl_get_tag_type(entry: *mut libc::c_void, tag: *mut libc::c_int) -> libc::c_int;
}

#[cfg(target_os = "macos")]
struct MacAclGuard(MacAcl);

#[cfg(target_os = "macos")]
impl Drop for MacAclGuard {
    fn drop(&mut self) {
        // SAFETY: this guard owns the ACL object returned by a libc allocation function.
        let _ = unsafe { acl_free(self.0) };
    }
}

#[cfg(target_os = "macos")]
fn clear_and_verify_extended_acl(file: &File) -> io::Result<()> {
    // SAFETY: `acl_init` returns an owned empty ACL object or null with errno set.
    let acl = unsafe { acl_init(0) };
    if acl.is_null() {
        return Err(io::Error::last_os_error());
    }
    let acl = MacAclGuard(acl);
    // SAFETY: `file` and the owned ACL object stay live for this call.
    if unsafe { acl_set_fd_np(file.as_raw_fd(), acl.0, MAC_ACL_TYPE_EXTENDED) } != 0 {
        return Err(io::Error::last_os_error());
    }
    verify_no_extended_acl(file)
}

#[cfg(target_os = "macos")]
fn verify_no_extended_acl(file: &File) -> io::Result<()> {
    if macos_acl_entry_count(file)? == 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "extended ACL entries remain after owner-only hardening",
        ))
    }
}

#[cfg(target_os = "macos")]
fn macos_acl_has_allow_entry(file: &File) -> io::Result<bool> {
    let Some(acl) = get_macos_acl(file)? else {
        return Ok(false);
    };
    let acl = acl.0;
    let mut entry = std::ptr::null_mut();
    // SAFETY: the ACL remains live and `entry` points to writable storage.
    let mut result = unsafe { acl_get_entry(acl, MAC_ACL_FIRST_ENTRY, &mut entry) };
    while result == 0 {
        let mut tag = 0;
        // SAFETY: a successful `acl_get_entry` returned a live entry from the live ACL.
        if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if tag == MAC_ACL_EXTENDED_ALLOW {
            return Ok(true);
        }
        // SAFETY: the ACL remains live and `entry` points to writable storage.
        result = unsafe { acl_get_entry(acl, MAC_ACL_NEXT_ENTRY, &mut entry) };
    }
    macos_acl_end_or_error(result).map(|()| false)
}

#[cfg(target_os = "macos")]
fn macos_acl_entry_count(file: &File) -> io::Result<usize> {
    let Some(acl) = get_macos_acl(file)? else {
        return Ok(0);
    };
    let acl = acl.0;
    let mut count = 0;
    let mut entry = std::ptr::null_mut();
    // SAFETY: the ACL remains live and `entry` points to writable storage.
    let mut result = unsafe { acl_get_entry(acl, MAC_ACL_FIRST_ENTRY, &mut entry) };
    while result == 0 {
        count += 1;
        // SAFETY: the ACL remains live and `entry` points to writable storage.
        result = unsafe { acl_get_entry(acl, MAC_ACL_NEXT_ENTRY, &mut entry) };
    }
    macos_acl_end_or_error(result).map(|()| count)
}

#[cfg(target_os = "macos")]
fn macos_acl_end_or_error(result: libc::c_int) -> io::Result<()> {
    debug_assert_eq!(result, -1);
    let error = io::Error::last_os_error();
    // Darwin's ACL iterator reports end-of-list as `-1/EINVAL` rather than the draft-POSIX
    // `0` convention used by some other implementations.
    if error.raw_os_error() == Some(libc::EINVAL) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(target_os = "macos")]
fn get_macos_acl(file: &File) -> io::Result<Option<MacAclGuard>> {
    // SAFETY: `file` stays open and libc returns an owned ACL object or null with errno set.
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), MAC_ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error);
    }
    Ok(Some(MacAclGuard(acl)))
}

#[cfg(target_os = "linux")]
const LINUX_ACCESS_ACL_XATTR: &[u8] = b"system.posix_acl_access\0";
#[cfg(target_os = "linux")]
const LINUX_DEFAULT_ACL_XATTR: &[u8] = b"system.posix_acl_default\0";

#[cfg(target_os = "linux")]
fn clear_and_verify_extended_acl(file: &File) -> io::Result<()> {
    remove_linux_acl_xattr(file, LINUX_ACCESS_ACL_XATTR)?;
    if file.metadata()?.file_type().is_dir() {
        remove_linux_acl_xattr(file, LINUX_DEFAULT_ACL_XATTR)?;
    }
    verify_no_extended_acl(file)
}

#[cfg(target_os = "linux")]
fn verify_no_extended_acl(file: &File) -> io::Result<()> {
    verify_linux_acl_xattr_absent(file, LINUX_ACCESS_ACL_XATTR)?;
    if file.metadata()?.file_type().is_dir() {
        verify_linux_acl_xattr_absent(file, LINUX_DEFAULT_ACL_XATTR)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_linux_acl_xattr(file: &File, name: &[u8]) -> io::Result<()> {
    debug_assert_eq!(name.last(), Some(&0));
    // SAFETY: `name` is statically NUL-terminated and `file` stays open.
    if unsafe { libc::fremovexattr(file.as_raw_fd(), name.as_ptr().cast()) } == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENODATA) {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(target_os = "linux")]
fn verify_linux_acl_xattr_absent(file: &File, name: &[u8]) -> io::Result<()> {
    // SAFETY: `name` is statically NUL-terminated, the zero-size query has no output buffer, and
    // `file` stays open.
    let size = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            name.as_ptr().cast(),
            std::ptr::null_mut(),
            0,
        )
    };
    if size < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENODATA) {
            return Ok(());
        }
        return Err(error);
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "POSIX ACL xattr remains after owner-only hardening",
    ))
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn clear_and_verify_extended_acl(_file: &File) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "extended-ACL hardening is implemented only for macOS and Linux",
    ))
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn verify_no_extended_acl(_file: &File) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "extended-ACL verification is implemented only for macOS and Linux",
    ))
}

#[cfg(unix)]
fn c_name(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "store path component contains NUL",
        )
    })
}

#[cfg(unix)]
fn file_from_fd(fd: libc::c_int) -> io::Result<File> {
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `fd` is a newly returned owned descriptor and is transferred exactly once.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[cfg(unix)]
    #[test]
    fn repairs_owner_controlled_base_and_file_modes() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().join("Maestro");
        fs::create_dir(&base).unwrap();
        fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).unwrap();
        let db = base.join("maestro.db");
        fs::write(&db, b"bytes").unwrap();
        fs::set_permissions(&db, fs::Permissions::from_mode(0o644)).unwrap();

        let secured = SecureAppSupport::open(&base).unwrap();
        assert!(secured
            .secure_existing_file(OsStr::new("maestro.db"))
            .unwrap());

        assert_eq!(fs::metadata(&base).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&db).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::read(&db).unwrap(), b"bytes");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_user_symlinks_in_ancestry() {
        use std::os::unix::fs::symlink;

        if unsafe { libc::geteuid() } == 0 {
            // Root-owned symlinks are deliberately trusted system aliases. A root test process
            // cannot construct the unprivileged-owner case this regression covers.
            return;
        }
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().join("real");
        fs::create_dir(&real).unwrap();
        let alias = tmp.path().join("alias");
        symlink(&real, &alias).unwrap();

        let error = SecureAppSupport::open(&alias.join("Maestro")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(fs::read_dir(&real).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_ambiguous_writable_ancestry() {
        let tmp = TempDir::new().unwrap();
        let parent = tmp.path().join("ambiguous");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();

        let error = SecureAppSupport::open(&parent.join("Maestro")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!parent.join("Maestro").exists());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_and_hardlinked_authority_without_chmod() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().unwrap();
        let base = tmp.path().join("Maestro");
        let secured = SecureAppSupport::open(&base).unwrap();
        let victim = base.join("victim");
        fs::write(&victim, b"preserve").unwrap();
        fs::set_permissions(&victim, fs::Permissions::from_mode(0o644)).unwrap();
        symlink(&victim, base.join("maestro.db")).unwrap();
        assert!(secured
            .secure_existing_file(OsStr::new("maestro.db"))
            .is_err());
        assert_eq!(fs::metadata(&victim).unwrap().mode() & 0o777, 0o644);

        fs::remove_file(base.join("maestro.db")).unwrap();
        fs::hard_link(&victim, base.join("maestro.db")).unwrap();
        let error = secured
            .secure_existing_file(OsStr::new("maestro.db"))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(fs::metadata(&victim).unwrap().mode() & 0o777, 0o644);
    }

    #[cfg(unix)]
    #[test]
    fn owner_check_refuses_a_foreign_expected_uid() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("authority");
        fs::write(&path, b"bytes").unwrap();
        let file = File::open(path).unwrap();
        let actual = file.metadata().unwrap().uid();
        let error = validate_owner_file(&file, actual.wrapping_add(1)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[cfg(unix)]
    #[test]
    fn unlinked_open_inode_is_absence_not_a_hardlink_violation() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("maestro.db-shm");
        fs::write(&path, b"sidecar").unwrap();
        let file = File::open(&path).unwrap();

        // SQLite removes WAL sidecars when the last connection closes. A concurrent validator
        // may already hold a descriptor at that instant, in which case fstat reports nlink == 0.
        // That inode is no longer path authority; it is not a multiply-linked attacker object.
        fs::remove_file(&path).unwrap();
        let error = validate_owner_file(&file, unsafe { libc::geteuid() }).unwrap_err();

        assert_eq!(file.metadata().unwrap().nlink(), 0);
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[cfg(target_os = "macos")]
    fn add_macos_acl(path: &Path, rule: &str) {
        let status = std::process::Command::new("/bin/chmod")
            .arg("+a")
            .arg(rule)
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success(), "failed to add macOS ACL fixture");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn clears_macos_acl_grants_that_numeric_modes_leave_in_place() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().join("Maestro");
        fs::create_dir(&base).unwrap();
        let db = base.join("maestro.db");
        fs::write(&db, b"bytes").unwrap();
        add_macos_acl(&base, "everyone allow read");
        add_macos_acl(&db, "everyone allow read");

        fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&db, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            macos_acl_entry_count(&File::open(&base).unwrap()).unwrap(),
            1,
            "macOS numeric chmod unexpectedly removed the directory ACL fixture"
        );
        assert_eq!(
            macos_acl_entry_count(&File::open(&db).unwrap()).unwrap(),
            1,
            "macOS numeric chmod unexpectedly removed the file ACL fixture"
        );

        let secured = SecureAppSupport::open(&base).unwrap();
        assert!(secured
            .secure_existing_file(OsStr::new("maestro.db"))
            .unwrap());

        assert_eq!(
            macos_acl_entry_count(&File::open(&base).unwrap()).unwrap(),
            0
        );
        assert_eq!(macos_acl_entry_count(&File::open(&db).unwrap()).unwrap(), 0);
        assert_eq!(fs::metadata(&base).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&db).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::read(&db).unwrap(), b"bytes");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn refuses_ancestor_acl_allow_but_accepts_protective_deny() {
        let tmp = TempDir::new().unwrap();
        let allowed_parent = tmp.path().join("allowed-parent");
        fs::create_dir(&allowed_parent).unwrap();
        add_macos_acl(&allowed_parent, "everyone allow read");
        let error = SecureAppSupport::open(&allowed_parent.join("Maestro")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!allowed_parent.join("Maestro").exists());

        let denied_parent = tmp.path().join("denied-parent");
        fs::create_dir(&denied_parent).unwrap();
        add_macos_acl(&denied_parent, "everyone deny delete");
        SecureAppSupport::open(&denied_parent.join("Maestro")).unwrap();
        assert!(denied_parent.join("Maestro").is_dir());
        assert_eq!(
            macos_acl_entry_count(&File::open(&denied_parent).unwrap()).unwrap(),
            1,
            "protective ancestry ACL must not be rewritten"
        );
    }

    #[cfg(target_os = "linux")]
    fn linux_named_user_acl(uid: u32) -> Vec<u8> {
        const ACL_UNDEFINED_ID: u32 = u32::MAX;
        let mut bytes = 2_u32.to_le_bytes().to_vec();
        for (tag, permissions, id) in [
            (0x01_u16, 0x06_u16, ACL_UNDEFINED_ID),
            (0x02_u16, 0x04_u16, uid),
            (0x04_u16, 0x00_u16, ACL_UNDEFINED_ID),
            (0x10_u16, 0x04_u16, ACL_UNDEFINED_ID),
            (0x20_u16, 0x00_u16, ACL_UNDEFINED_ID),
        ] {
            bytes.extend_from_slice(&tag.to_le_bytes());
            bytes.extend_from_slice(&permissions.to_le_bytes());
            bytes.extend_from_slice(&id.to_le_bytes());
        }
        bytes
    }

    #[cfg(target_os = "linux")]
    fn set_linux_acl_xattr(file: &File, name: &[u8], bytes: &[u8]) {
        // SAFETY: both byte slices remain live; `name` is statically NUL-terminated.
        let result = unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                name.as_ptr().cast(),
                bytes.as_ptr().cast(),
                bytes.len(),
                0,
            )
        };
        assert_eq!(
            result,
            0,
            "failed to add Linux ACL fixture: {}",
            io::Error::last_os_error()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn clears_linux_access_and_default_acls_from_base_and_authority() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().join("Maestro");
        fs::create_dir(&base).unwrap();
        let db = base.join("maestro.db");
        fs::write(&db, b"bytes").unwrap();
        let fixture = linux_named_user_acl(unsafe { libc::geteuid() }.wrapping_add(1));
        let base_file = File::open(&base).unwrap();
        let db_file = File::open(&db).unwrap();
        set_linux_acl_xattr(&base_file, LINUX_ACCESS_ACL_XATTR, &fixture);
        set_linux_acl_xattr(&base_file, LINUX_DEFAULT_ACL_XATTR, &fixture);
        set_linux_acl_xattr(&db_file, LINUX_ACCESS_ACL_XATTR, &fixture);
        assert!(verify_no_extended_acl(&base_file).is_err());
        assert!(verify_no_extended_acl(&db_file).is_err());
        drop(base_file);
        drop(db_file);

        let secured = SecureAppSupport::open(&base).unwrap();
        assert!(secured
            .secure_existing_file(OsStr::new("maestro.db"))
            .unwrap());

        verify_no_extended_acl(&File::open(&base).unwrap()).unwrap();
        verify_no_extended_acl(&File::open(&db).unwrap()).unwrap();
        assert_eq!(fs::metadata(&base).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&db).unwrap().mode() & 0o777, 0o600);
        assert_eq!(fs::read(&db).unwrap(), b"bytes");
    }
}
