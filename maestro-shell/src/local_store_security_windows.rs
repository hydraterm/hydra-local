//! Windows implementation of the existing owner-local store boundary, not a second store.
//! Directory handles deny delete sharing throughout the walk. Existing parents are inspected,
//! never re-ACL'd; only current-user Hydra directories/files receive the protected owner DACL.

use super::SecureAppSupport;
use crate::windows_identity::OwnedSid;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    LocalFree, ERROR_ALREADY_EXISTS, GENERIC_ALL, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SetSecurityInfo,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    EqualSid, GetAce, GetLengthSid, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
    IsValidAcl, IsValidSid, LookupAccountNameW, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OBJECT_INHERIT_ACE,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, GetFileInformationByHandle, GetFileType,
    GetFinalPathNameByHandleW, BY_HANDLE_FILE_INFORMATION, CREATE_NEW, DELETE, FILE_ALL_ACCESS,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK,
    FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, OPEN_ALWAYS, OPEN_EXISTING,
    READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE};

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

fn wide(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut value: Vec<_> = value.encode_wide().collect();
    if value.contains(&0) {
        return Err(invalid("store path contains NUL"));
    }
    value.push(0);
    Ok(value)
}

struct Descriptor(PSECURITY_DESCRIPTOR);

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: these descriptors come only from allocating Windows security APIs.
        unsafe { LocalFree(self.0) };
    }
}

impl Descriptor {
    fn owner_only(owner: &OwnedSid, directory: bool) -> io::Result<Self> {
        let sid = owner.to_string()?;
        // Set the owner explicitly too: an elevated token's default owner can be Administrators.
        let flags = if directory { "OICI" } else { "" };
        let text = wide(OsStr::new(&format!("O:{sid}D:P(A;{flags};FA;;;{sid})")))?;
        let mut descriptor = null_mut();
        // SAFETY: the terminated input and writable output live through this synchronous call.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0,
            bInheritHandle: 0,
        }
    }

    fn dacl(&self) -> io::Result<*mut ACL> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl = null_mut();
        // SAFETY: the descriptor allocation is retained by self; every output is live.
        if unsafe { GetSecurityDescriptorDacl(self.0, &mut present, &mut acl, &mut defaulted) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if present == 0 || acl.is_null() || unsafe { IsValidAcl(acl) } == 0 {
            return Err(denied(
                "store object has no valid discretionary access boundary",
            ));
        }
        Ok(acl)
    }
}

struct ObjectSecurity {
    descriptor: Descriptor,
    owner: PSID,
}

impl ObjectSecurity {
    fn read(file: &File) -> io::Result<Self> {
        let mut owner = null_mut();
        let mut descriptor = null_mut();
        // SAFETY: the file handle and writable outputs remain live. The API allocates the
        // returned descriptor, which owns the returned owner pointer until Descriptor::drop.
        let result = unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        if result != 0 {
            return Err(io::Error::from_raw_os_error(result as i32));
        }
        let result = Self {
            descriptor: Descriptor(descriptor),
            owner,
        };
        if result.owner.is_null() || unsafe { IsValidSid(result.owner) } == 0 {
            return Err(denied("store object has no valid Windows owner"));
        }
        Ok(result)
    }

    fn require_owner(&self, owner: &OwnedSid) -> io::Result<()> {
        if unsafe { EqualSid(self.owner, owner.as_ptr()) } == 0 {
            return Err(denied("store authority has foreign ownership"));
        }
        Ok(())
    }
}

fn file_info(file: &File, directory: bool) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: file stays open and info is writable for the complete synchronous call.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
    {
        return Err(invalid(
            "store authority is a reparse point or has the wrong file type",
        ));
    }
    if !directory {
        if info.nNumberOfLinks == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "store file was retired during validation",
            ));
        }
        if info.nNumberOfLinks != 1 {
            return Err(invalid("store authority has an unsafe hard-link count"));
        }
    }
    Ok(info)
}

fn open_directory(path: &Path, is_base: bool) -> io::Result<File> {
    let path = wide(path.as_os_str())?;
    // No FILE_SHARE_DELETE: every held ancestor stays at the name that was walked. Do not
    // request directory write/ACL access for parents that Hydra will only inspect.
    let access = READ_CONTROL | FILE_READ_ATTRIBUTES | if is_base { WRITE_DAC } else { 0 };
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful CreateFileW returns a uniquely owned non-inheritable handle.
    let file = unsafe { File::from_raw_handle(handle) };
    file_info(&file, true)?;
    Ok(file)
}

fn trusted_installer_sid() -> io::Result<OwnedSid> {
    let name = wide(OsStr::new(r"NT SERVICE\TrustedInstaller"))?;
    let mut sid_bytes = 0;
    let mut domain_chars = 0;
    let mut kind = 0;
    // Lookup is only for the fixed local Windows servicing principal, never a user-supplied name.
    unsafe {
        LookupAccountNameW(
            null(),
            name.as_ptr(),
            null_mut(),
            &mut sid_bytes,
            null_mut(),
            &mut domain_chars,
            &mut kind,
        )
    };
    if sid_bytes == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut sid = vec![0usize; (sid_bytes as usize).div_ceil(size_of::<usize>())];
    let mut domain = vec![0u16; domain_chars as usize];
    if unsafe {
        LookupAccountNameW(
            null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_bytes,
            domain.as_mut_ptr(),
            &mut domain_chars,
            &mut kind,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    OwnedSid::copy_from(
        sid.as_mut_ptr().cast(),
        "Windows servicing principal has no SID",
    )
}

struct AncestorTrust {
    current_sid: String,
    servicing_sid: Option<String>,
}

impl AncestorTrust {
    fn new(owner: &OwnedSid) -> io::Result<Self> {
        Ok(Self {
            current_sid: owner.to_string()?,
            // Absence does not stop normal user/Admin/System ancestry; an unknown owner is
            // never promoted to trusted merely because this optional lookup failed.
            servicing_sid: trusted_installer_sid().and_then(|sid| sid.to_string()).ok(),
        })
    }

    fn contains(&self, sid: PSID) -> io::Result<bool> {
        let sid = OwnedSid::copy_from(sid, "directory trustee has no SID")?.to_string()?;
        Ok(sid == self.current_sid
            || sid == "S-1-5-18"
            || sid == "S-1-5-32-544"
            || self.servicing_sid.as_ref() == Some(&sid))
    }
}

fn allowed_ace(acl: *mut ACL, index: u32) -> io::Result<Option<(u32, PSID, u8)>> {
    let mut raw = null_mut();
    if unsafe { GetAce(acl, index, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: GetAce points inside the validated, retained Windows descriptor allocation.
    let header = unsafe { &*raw.cast::<ACE_HEADER>() };
    if u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0
        || u32::from(header.AceType) == ACCESS_DENIED_ACE_TYPE
    {
        return Ok(None);
    }
    if u32::from(header.AceType) != ACCESS_ALLOWED_ACE_TYPE {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "store ancestry uses an unqualified conditional/object ACL entry",
        ));
    }
    let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    if usize::from(header.AceSize) < sid_offset + 8 {
        return Err(invalid("directory ACL entry is truncated"));
    }
    let ace = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
    let sid = unsafe { raw.cast::<u8>().add(sid_offset).cast() };
    if unsafe { GetLengthSid(sid) } as usize > usize::from(header.AceSize) - sid_offset
        || unsafe { IsValidSid(sid) } == 0
    {
        return Err(invalid("directory ACL trustee is invalid"));
    }
    Ok(Some((ace.Mask, sid, header.AceFlags)))
}

fn validate_ancestor(file: &File, trust: &AncestorTrust) -> io::Result<()> {
    let security = ObjectSecurity::read(file)?;
    if !trust.contains(security.owner)? {
        return Err(denied("store ancestry has foreign ownership"));
    }
    let acl = security.descriptor.dacl()?;
    let dangerous = DELETE
        | WRITE_DAC
        | WRITE_OWNER
        | FILE_DELETE_CHILD
        | FILE_WRITE_DATA
        | FILE_WRITE_EA
        | FILE_WRITE_ATTRIBUTES
        | GENERIC_ALL
        | GENERIC_WRITE;
    // Conservatively reject an untrusted destructive allow even if a later/conditional deny
    // might narrow it. Read/traverse and create-subdirectory-only grants do not permit takeover.
    for index in 0..u32::from(unsafe { (*acl).AceCount }) {
        if let Some((mask, sid, _)) = allowed_ace(acl, index)? {
            if mask & dangerous != 0 && !trust.contains(sid)? {
                return Err(denied(
                    "store ancestry can be changed by another local user",
                ));
            }
        }
    }
    Ok(())
}

fn protect_owner(file: &File, owner: &OwnedSid, directory: bool) -> io::Result<()> {
    file_info(file, directory)?;
    let existing = ObjectSecurity::read(file)?;
    existing.require_owner(owner)?;
    // No-op for the normal already-protected case. Failure to inspect the old ACL is not
    // acceptance: the exact current owner was proved, and repair still needs strict verification.
    if owner_acl_matches(&existing, owner, directory).unwrap_or(false) {
        return Ok(());
    }
    let repair;
    let target = if directory {
        repair = open_directory_for_repair(file)?;
        ObjectSecurity::read(&repair)?.require_owner(owner)?;
        &repair
    } else {
        file
    };
    let expected = Descriptor::owner_only(owner, directory)?;
    let acl = expected.dacl()?;
    // Directory repairs use a short-lived non-shared handle. SetSecurityInfo's documented
    // exclusive-directory behavior prevents inheritable ACEs from propagating into existing
    // children. The ordinary pinned metadata handle survives throughout; close the repair
    // handle before returning so normal migration directory enumeration remains possible.
    let status = unsafe {
        SetSecurityInfo(
            target.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl,
            null(),
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let observed = ObjectSecurity::read(file)?;
    observed.require_owner(owner)?;
    if !owner_acl_matches(&observed, owner, directory)? {
        return Err(denied("store object owner ACL verification failed"));
    }
    file_info(file, directory)?;
    Ok(())
}

fn open_directory_for_repair(file: &File) -> io::Result<File> {
    let before = file_info(file, true)?;
    let path = wide(directory_path(file)?.as_os_str())?;
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES,
            0,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful non-inheritable handle is transferred to its unique File owner.
    let repair = unsafe { File::from_raw_handle(handle) };
    let after = file_info(&repair, true)?;
    if (
        before.dwVolumeSerialNumber,
        before.nFileIndexHigh,
        before.nFileIndexLow,
    ) != (
        after.dwVolumeSerialNumber,
        after.nFileIndexHigh,
        after.nFileIndexLow,
    ) {
        return Err(invalid(
            "store directory identity changed before ACL repair",
        ));
    }
    Ok(repair)
}

fn owner_acl_matches(
    observed: &ObjectSecurity,
    owner: &OwnedSid,
    directory: bool,
) -> io::Result<bool> {
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(observed.descriptor.0, &mut control, &mut revision) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    let acl = observed.descriptor.dacl()?;
    if control & SE_DACL_PROTECTED == 0 || unsafe { (*acl).AceCount } != 1 {
        return Ok(false);
    }
    let Some((mask, sid, flags)) = allowed_ace(acl, 0)? else {
        return Ok(false);
    };
    let expected_flags = if directory {
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    } else {
        0
    };
    Ok(mask == FILE_ALL_ACCESS
        && unsafe { EqualSid(sid, owner.as_ptr()) } != 0
        && u32::from(flags) == expected_flags)
}

pub(super) fn secure_app_support(base: &Path) -> io::Result<SecureAppSupport> {
    if !base.is_absolute() {
        return Err(invalid("app-support base must be absolute"));
    }
    let mut components = base.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(invalid(
            "Windows app-support base requires a disk or UNC root",
        ));
    };
    if !matches!(
        prefix.kind(),
        Prefix::Disk(_) | Prefix::VerbatimDisk(_) | Prefix::UNC(_, _) | Prefix::VerbatimUNC(_, _)
    ) || components.next() != Some(Component::RootDir)
    {
        return Err(invalid(
            "app-support base uses a device or drive-relative path",
        ));
    }
    let names: Vec<_> = components
        .map(|component| match component {
            Component::Normal(name) => validate_filename(name).map(|()| name),
            _ => Err(invalid("app-support base contains a non-normal component")),
        })
        .collect::<io::Result<_>>()?;
    if names.is_empty() {
        return Err(invalid("app-support base cannot be the filesystem root"));
    }
    let owner = OwnedSid::current_process()?;
    let trust = AncestorTrust::new(&owner)?;
    let descriptor = Descriptor::owner_only(&owner, true)?;
    let attributes = descriptor.attributes();
    let mut current = PathBuf::from(prefix.as_os_str());
    current.push(r"\");
    let root = open_directory(&current, false)?;
    validate_ancestor(&root, &trust)?;
    let mut ancestors = vec![root];
    for (index, name) in names.iter().enumerate() {
        current.push(name);
        let is_base = index + 1 == names.len();
        let next = match open_directory(&current, is_base) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let path = wide(current.as_os_str())?;
                if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
                        return Err(error);
                    }
                }
                // An AlreadyExists race is classified by handle and owner, never overwritten.
                open_directory(&current, is_base)?
            }
            Err(error) => return Err(error),
        };
        if is_base {
            protect_owner(&next, &owner, true)?;
            return Ok(SecureAppSupport {
                dir: next,
                _ancestors: ancestors,
            });
        }
        validate_ancestor(&next, &trust)?;
        ancestors.push(next);
    }
    unreachable!("nonempty component walk returns its last directory")
}

fn validate_filename(name: &OsStr) -> io::Result<()> {
    let units: Vec<_> = name.encode_wide().collect();
    if units.is_empty()
        || units.iter().any(|unit| matches!(*unit, 0 | 47 | 58 | 92))
        || matches!(units.last(), Some(32 | 46))
        || Path::new(name).components().count() != 1
        || !matches!(
            Path::new(name).components().next(),
            Some(Component::Normal(_))
        )
    {
        return Err(invalid(
            "store filename must be one unambiguous normal component",
        ));
    }
    // Verbatim paths avoid Win32's device-name conversion. Still reject device-like names so
    // future callers cannot reinterpret an authority path through a non-verbatim API.
    let text = name.to_string_lossy();
    let stem = text
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|suffix| {
                suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9')
            })
        })
    {
        return Err(invalid("store filename cannot name a Windows device"));
    }
    Ok(())
}

fn directory_path(file: &File) -> io::Result<PathBuf> {
    let needed = unsafe { GetFinalPathNameByHandleW(file.as_raw_handle(), null_mut(), 0, 0) };
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut path = vec![0u16; needed as usize];
    let copied =
        unsafe { GetFinalPathNameByHandleW(file.as_raw_handle(), path.as_mut_ptr(), needed, 0) };
    if copied == 0 {
        return Err(io::Error::last_os_error());
    }
    if copied >= needed {
        return Err(invalid(
            "pinned store directory path changed during resolution",
        ));
    }
    path.truncate(copied as usize);
    Ok(PathBuf::from(OsString::from_wide(&path)))
}

pub(super) fn open_owner_file_at(
    base: &File,
    name: &OsStr,
    create: bool,
    create_new: bool,
) -> io::Result<File> {
    validate_filename(name)?;
    let owner = OwnedSid::current_process()?;
    file_info(base, true)?;
    ObjectSecurity::read(base)?.require_owner(&owner)?;
    let path = wide(directory_path(base)?.join(name).as_os_str())?;
    let descriptor = Descriptor::owner_only(&owner, false)?;
    let attributes = descriptor.attributes();
    let disposition = if create_new {
        CREATE_NEW
    } else if create {
        OPEN_ALWAYS
    } else {
        OPEN_EXISTING
    };
    let access = GENERIC_READ | READ_CONTROL | WRITE_DAC | if create { GENERIC_WRITE } else { 0 };
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            disposition,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: this is a uniquely owned successful CreateFileW handle; no bytes are read/written
    // before its type, link count, owner and protected ACL are established.
    let file = unsafe { File::from_raw_handle(handle) };
    protect_owner(&file, &owner, false)?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn dacl_bytes(file: &File) -> Vec<u8> {
        let security = ObjectSecurity::read(file).unwrap();
        let acl = security.descriptor.dacl().unwrap();
        // SAFETY: dacl() validated this retained allocation and AclSize describes its byte span.
        unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), usize::from((*acl).AclSize)) }
            .to_vec()
    }

    #[test]
    fn base_acl_repair_does_not_rewrite_parent_or_existing_child_acls() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("existing");
        std::fs::create_dir(&base).unwrap();
        let child = base.join("preserved.db");
        std::fs::write(&child, b"unchanged").unwrap();
        let owner = OwnedSid::current_process().unwrap();
        let parent = open_directory(temp.path(), false).unwrap();
        let before_parent = dacl_bytes(&parent);
        let before_child = dacl_bytes(&File::open(&child).unwrap());
        let before_base = open_directory(&base, false).unwrap();
        assert!(
            !owner_acl_matches(&ObjectSecurity::read(&before_base).unwrap(), &owner, true).unwrap()
        );
        let secured = SecureAppSupport::open(&base).unwrap();
        assert!(
            owner_acl_matches(&ObjectSecurity::read(&secured.dir).unwrap(), &owner, true).unwrap()
        );
        assert!(before_parent == dacl_bytes(&parent), "parent ACL changed");
        assert!(
            before_child == dacl_bytes(&File::open(&child).unwrap()),
            "existing child ACL changed"
        );
        assert_eq!(std::fs::read(&child).unwrap(), b"unchanged");
        // The short-lived exclusive repair handle must not prevent ordinary directory reads.
        assert_eq!(std::fs::read_dir(&base).unwrap().count(), 1);
    }

    #[test]
    fn cooperating_first_opens_share_the_same_owner_boundary() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("concurrent").join("state");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let joins: Vec<_> = (0..4)
            .map(|index| {
                let base = base.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let secured = SecureAppSupport::open(&base).unwrap();
                    secured
                        .open_owner_file(OsStr::new(&format!("worker-{index}.db")), true)
                        .unwrap();
                })
            })
            .collect();
        for join in joins {
            join.join().unwrap();
        }
        assert_eq!(std::fs::read_dir(base).unwrap().count(), 4);
    }

    #[test]
    fn creates_and_reopens_owner_files_without_truncating_content() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("例 Hydra").join("state");
        let secured = SecureAppSupport::open(&base).unwrap();
        let name = OsStr::new("receipt.db");
        secured
            .open_owner_file(name, true)
            .unwrap()
            .write_all(b"preserve existing")
            .unwrap();
        assert_eq!(
            secured.open_owner_file(name, true).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        let mut contents = String::new();
        secured
            .open_owner_file(name, false)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(contents, "preserve existing");
        assert!(!secured
            .secure_existing_file(OsStr::new("absent.db"))
            .unwrap());
        assert!(!base.join("absent.db").exists());
    }

    #[test]
    fn refuses_hardlinked_authority_and_pins_parent_names() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("state");
        let secured = SecureAppSupport::open(&base).unwrap();
        std::fs::write(base.join("original.db"), b"unchanged").unwrap();
        std::fs::hard_link(base.join("original.db"), base.join("alias.db")).unwrap();
        let before_acl = dacl_bytes(&File::open(base.join("original.db")).unwrap());
        assert!(secured
            .open_existing_owner_file(OsStr::new("alias.db"))
            .is_err());
        assert_eq!(
            std::fs::read(base.join("original.db")).unwrap(),
            b"unchanged"
        );
        assert!(before_acl == dacl_bytes(&File::open(base.join("original.db")).unwrap()));
        assert!(std::fs::rename(&base, temp.path().join("replacement")).is_err());
        drop(secured);
        std::fs::rename(&base, temp.path().join("replacement")).unwrap();
    }

    #[test]
    fn refuses_ambiguous_authority_names_and_relative_bases() {
        for name in [
            "", ".", "..", "../other", r"a\b", "a:b", "file.", "file ", "NUL", "COM1.txt",
        ] {
            assert!(
                validate_filename(OsStr::new(name)).is_err(),
                "accepted {name:?}"
            );
        }
        assert!(validate_filename(OsStr::new("maestro.db-wal")).is_ok());
        assert!(SecureAppSupport::open(Path::new(r"C:relative")).is_err());
        assert!(SecureAppSupport::open(Path::new(r"C:\")).is_err());
    }
}
