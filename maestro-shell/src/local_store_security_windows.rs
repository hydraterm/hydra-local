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
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TYPE_DISK, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA,
    OPEN_ALWAYS, OPEN_EXISTING, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
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
    // request directory write/ACL access for parents that Hydra will only inspect. Metadata-only
    // handles do not participate in Windows sharing checks: FILE_LIST_DIRECTORY (FILE_READ_DATA)
    // is required for omission of FILE_SHARE_DELETE to actually pin the directory name.
    let access = READ_CONTROL
        | FILE_READ_ATTRIBUTES
        | FILE_LIST_DIRECTORY
        | if is_base { WRITE_DAC } else { 0 };
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
    allowed_ace_with_inheritance(acl, index, false)
}

fn allowed_ace_with_inheritance(
    acl: *mut ACL,
    index: u32,
    include_inherit_only: bool,
) -> io::Result<Option<(u32, PSID, u8)>> {
    let mut raw = null_mut();
    if unsafe { GetAce(acl, index, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: GetAce points inside the validated, retained Windows descriptor allocation.
    let header = unsafe { &*raw.cast::<ACE_HEADER>() };
    if (!include_inherit_only && u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0)
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

fn ancestor_takeover_mask(pinned_volume_root: bool) -> u32 {
    let takeover = WRITE_DAC | WRITE_OWNER | FILE_DELETE_CHILD | GENERIC_ALL | GENERIC_WRITE;
    if pinned_volume_root {
        takeover
    } else {
        takeover | DELETE | FILE_WRITE_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES
    }
}

fn validate_ancestor(file: &File, trust: &AncestorTrust) -> io::Result<()> {
    validate_ancestor_mask(file, trust, ancestor_takeover_mask(false))
}

fn validate_ancestor_mask(file: &File, trust: &AncestorTrust, dangerous: u32) -> io::Result<()> {
    let security = ObjectSecurity::read(file)?;
    if !trust.contains(security.owner)? {
        return Err(denied("store ancestry has foreign ownership"));
    }
    let acl = security.descriptor.dacl()?;
    // Conservatively reject an untrusted destructive allow even if a later/conditional deny
    // might narrow it. Read/traverse and create-subdirectory-only grants do not permit takeover.
    for index in 0..u32::from(unsafe { (*acl).AceCount }) {
        if let Some((mask, sid, _)) = allowed_ace(acl, index)? {
            // OWNER RIGHTS denotes the object's owner, whose ancestry trust was proved above.
            let owner_rights =
                OwnedSid::copy_from(sid, "directory trustee has no SID")?.to_string()? == "S-1-3-4";
            if mask & dangerous != 0 && !owner_rights && !trust.contains(sid)? {
                return Err(denied(
                    "store ancestry can be changed by another local user",
                ));
            }
        }
    }
    Ok(())
}

fn local_drive_root(path: &Path) -> Option<u8> {
    let mut components = path.components();
    let Component::Prefix(prefix) = components.next()? else {
        return None;
    };
    let drive = match prefix.kind() {
        Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive.to_ascii_uppercase(),
        _ => return None,
    };
    (components.next() == Some(Component::RootDir) && components.next().is_none()).then_some(drive)
}

fn is_same_local_volume_root(requested: &Path, resolved: &Path) -> bool {
    matches!((local_drive_root(requested), local_drive_root(resolved)),
        (Some(requested), Some(resolved)) if requested == resolved)
}

/// A volume root has no replaceable parent entry. Its data/attribute grants cannot redirect this
/// walk while a validated existing child keeps it nonempty. Keep this exception out of ordinary
/// ancestry: FILE_WRITE_DATA/ATTRIBUTES can set a reparse point on an empty directory (MS-FSA
/// FSCTL_SET_REPARSE_POINT processing), and a syntactic drive root can actually be a SUBST directory or a remote share.
fn pin_volume_root_child(
    root: &File,
    root_path: &Path,
    first_name: &OsStr,
    trust: &AncestorTrust,
) -> io::Result<File> {
    if !is_same_local_volume_root(root_path, &directory_path(root)?) {
        return Err(denied("store root is not a verified local volume root"));
    }
    // No creation, repair or store access before this proof. An absent child remains unsupported
    // under a broad root ACL. No delete sharing pins the child throughout the secured-store life.
    let child = open_directory(&root_path.join(first_name), false)?;
    validate_ancestor(&child, trust)?;
    file_info(root, true)?;
    validate_ancestor_mask(root, trust, ancestor_takeover_mask(true))?;
    file_info(root, true)?;
    Ok(child)
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
    let expected = Descriptor::owner_only(owner, directory)?;
    let acl = expected.dacl()?;
    if directory {
        set_directory_dacl_without_propagation(file, &expected)?;
    } else {
        let status = unsafe {
            SetSecurityInfo(
                file.as_raw_handle(),
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
    }
    let observed = ObjectSecurity::read(file)?;
    observed.require_owner(owner)?;
    if !owner_acl_matches(&observed, owner, directory)? {
        return Err(denied("store object owner ACL verification failed"));
    }
    file_info(file, directory)?;
    Ok(())
}

fn set_directory_dacl_without_propagation(file: &File, descriptor: &Descriptor) -> io::Result<()> {
    // SetSecurityInfo walks existing children to propagate inheritable ACEs. A metadata-only
    // "exclusive" reopen does not suppress that walk, and a truly exclusive read handle would
    // conflict with our pinned read handle. Set only this already-proved object's DACL through
    // the documented native object-security operation instead. Future children still inherit the
    // owner ACE; existing children retain byte-identical ACLs and are secured individually when
    // their own authority is opened. The caller always verifies owner, protected DACL and type.
    // https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetsecurityobject
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtSetSecurityObject(
            handle: windows_sys::Win32::Foundation::HANDLE,
            information: u32,
            descriptor: PSECURITY_DESCRIPTOR,
        ) -> i32;
        fn RtlNtStatusToDosError(status: i32) -> u32;
    }
    // SAFETY: the uniquely owned handle and complete self-relative descriptor remain alive for
    // this synchronous call. WRITE_DAC was requested at open; no owner/SACL change is requested.
    let status = unsafe {
        NtSetSecurityObject(
            file.as_raw_handle(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor.0,
        )
    };
    if status < 0 {
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ));
    }
    Ok(())
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

/// Prove privacy, not equality with the template used to create new objects. A normal private
/// Windows profile may inherit owner/System/Admin ACEs or split the owner's grants. Harmless
/// metadata/traverse grants are not content exposure. Denies cannot broaden an allow; conditional
/// and object-specific allow entries remain unsupported rather than being guessed about.
fn private_acl_is_safe(
    observed: &ObjectSecurity,
    owner: &OwnedSid,
    directory: bool,
) -> io::Result<bool> {
    use windows_sys::Win32::Foundation::GENERIC_EXECUTE;
    use windows_sys::Win32::Storage::FileSystem::{FILE_EXECUTE, SYNCHRONIZE};
    let acl = observed.descriptor.dacl()?;
    for index in 0..u32::from(unsafe { (*acl).AceCount }) {
        let Some((mask, sid, flags)) = allowed_ace_with_inheritance(acl, index, directory)? else {
            continue;
        };
        let sid_text = OwnedSid::copy_from(sid, "private ACL trustee is invalid")?.to_string()?;
        let trusted = unsafe { EqualSid(sid, owner.as_ptr()) } != 0
            || matches!(sid_text.as_str(), "S-1-5-18" | "S-1-5-32-544" | "S-1-3-4")
            // CREATOR OWNER is only a descendant-owner placeholder, never current-object
            // authority. Each opened child must independently prove its actual owner SID.
            || (directory && u32::from(flags) & INHERIT_ONLY_ACE != 0 && sid_text == "S-1-3-0");
        if trusted {
            continue;
        }
        let metadata = READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
        let harmless = if directory {
            metadata | FILE_EXECUTE | GENERIC_EXECUTE
        } else {
            metadata
        };
        if mask & !harmless != 0 {
            return Ok(false);
        }
        // An inherit-only grant does not expose this directory, but an inheritable file-execute
        // grant is not merely directory traversal. New authority still always receives an
        // explicit protected descriptor, independent of this compatibility inspection.
        if directory && u32::from(flags) & OBJECT_INHERIT_ACE != 0 && mask & !metadata != 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(super) fn secure_app_support(base: &Path) -> io::Result<SecureAppSupport> {
    open_app_support(base, true, true)
}

pub(super) fn private_authority(base: &Path, create: bool) -> io::Result<SecureAppSupport> {
    open_app_support(base, create, false)
}

fn open_app_support(base: &Path, create: bool, repair: bool) -> io::Result<SecureAppSupport> {
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
    let pinned_root_child = match validate_ancestor(&root, &trust) {
        Ok(()) => None,
        Err(original) => match pin_volume_root_child(&root, &current, names[0], &trust) {
            Ok(child) => Some(child),
            Err(_) => return Err(original),
        },
    };
    let mut ancestors = vec![root];
    // Retain the nonempty proof even while later components are opened/revalidated separately.
    if let Some(child) = pinned_root_child {
        ancestors.push(child);
    }
    for (index, name) in names.iter().enumerate() {
        current.push(name);
        let is_base = index + 1 == names.len();
        let next = match open_directory(&current, is_base && repair) {
            Ok(file) => file,
            Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                let path = wide(current.as_os_str())?;
                if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } == 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
                        return Err(error);
                    }
                }
                // An AlreadyExists race is classified by handle and owner, never overwritten.
                open_directory(&current, is_base && repair)?
            }
            Err(error) => return Err(error),
        };
        if is_base {
            if repair {
                protect_owner(&next, &owner, true)?;
            } else {
                require_private(&next, true)?;
            }
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

pub(super) fn directory_path(file: &File) -> io::Result<PathBuf> {
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

pub(super) fn require_private(file: &File, directory: bool) -> io::Result<(u64, u64)> {
    let info = file_info(file, directory)?;
    let owner = OwnedSid::current_process()?;
    let observed = ObjectSecurity::read(file)?;
    observed.require_owner(&owner)?;
    if !private_acl_is_safe(&observed, &owner, directory)? {
        return Err(denied(
            "private authority grants content or mutation access to an untrusted principal",
        ));
    }
    Ok((
        u64::from(info.dwVolumeSerialNumber),
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

pub(super) fn open_private_file_at(
    base: &File,
    name: &OsStr,
    create_new: bool,
) -> io::Result<File> {
    validate_filename(name)?;
    require_private(base, true)?;
    let owner = OwnedSid::current_process()?;
    let descriptor = Descriptor::owner_only(&owner, false)?;
    let attributes = descriptor.attributes();
    let path = wide(directory_path(base)?.join(name).as_os_str())?;
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | READ_CONTROL | if create_new { GENERIC_WRITE } else { 0 },
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            if create_new {
                CREATE_NEW
            } else {
                OPEN_EXISTING
            },
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_handle(handle) };
    // Observe only: never adopt a previously exposed key by repairing its ACL.
    require_private(&file, false)?;
    Ok(file)
}

pub(super) fn publish_private_at(
    base: &File,
    name: &OsStr,
    bytes: &[u8],
    replace: bool,
) -> io::Result<()> {
    publish_private_with_hook(base, name, bytes, replace, |_, _| Ok(()))
}

fn publish_private_with_hook(
    base: &File,
    name: &OsStr,
    bytes: &[u8],
    replace: bool,
    before_rename: impl FnOnce(&File, &OsStr) -> io::Result<()>,
) -> io::Result<()> {
    use std::io::Write as _;
    validate_filename(name)?;
    require_private(base, true)?;
    let existing = match open_private_file_at(base, name, false) {
        Ok(file) if replace => Some(file),
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "private authority already exists",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };
    let mut temporary = OsString::from(".");
    temporary.push(name);
    temporary.push(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let mut file = open_private_file_at(base, &temporary, true)?;
    let identity = require_private(&file, false)?;
    let mut moved = false;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        before_rename(&file, &temporary)?;
        if let Some(existing) = &existing {
            let named = open_private_file_at(base, name, false)?;
            if require_private(&named, false)? != require_private(existing, false)? {
                return Err(denied("private publication target changed"));
            }
        }
        // Rename this exact opened object into the pinned parent. Never resolve the temporary
        // source pathname again: another same-user writer may have replaced that directory entry.
        rename_private_file_at(base, &file, name, replace)?;
        moved = true;
        let published = open_private_file_at(base, name, false)?;
        if require_private(&published, false)? != identity {
            return Err(denied("private publication identity changed"));
        }
        // The read-only verification handle deliberately does not demand mutation access.
        // Flush through our original writable source handle after publication has been recorded,
        // so a failed flush cannot route cleanup into deleting an already-published file.
        file.sync_all()
    })();
    if result.is_err() && !moved {
        // Retire our exact temporary handle, not whichever file might now occupy its old name.
        let _ = remove_private_file(&file);
    }
    result
}

fn rename_private_file_at(base: &File, file: &File, name: &OsStr, replace: bool) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        FileRenameInfoEx, ReOpenFile, SetFileInformationByHandle, FILE_RENAME_INFO,
    };
    validate_filename(name)?;
    require_private(base, true)?;
    let identity = require_private(file, false)?;
    // ReOpenFile adds DELETE on the same object, without reopening its mutable pathname.
    let handle = unsafe {
        ReOpenFile(
            file.as_raw_handle(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL | DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let source = unsafe { File::from_raw_handle(handle) };
    if require_private(&source, false)? != identity {
        return Err(denied("private rename source changed"));
    }
    // Use the Win32 absolute destination form. The complete parent walk is retained without
    // delete sharing, so its name cannot be swapped while this source-handle rename is in flight.
    let destination = directory_path(base)?.join(name);
    let name: Vec<u16> = destination.as_os_str().encode_wide().collect();
    let filename_bytes = name
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or_else(|| invalid("private filename is too long"))?;
    let buffer_bytes = size_of::<FILE_RENAME_INFO>()
        .checked_add(filename_bytes)
        .ok_or_else(|| invalid("private rename buffer is too long"))?;
    let length =
        u32::try_from(buffer_bytes).map_err(|_| invalid("private rename buffer is too long"))?;
    // usize storage satisfies FILE_RENAME_INFO's native pointer alignment; reserve the complete
    // header plus variable UTF-16 tail (including zero padding for the optional terminator).
    let mut buffer = vec![0usize; buffer_bytes.div_ceil(size_of::<usize>())];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        // Documented FileRenameInformationEx flags: REPLACE_IF_EXISTS | POSIX_SEMANTICS.
        // POSIX replacement keeps already-open reader handles valid. No-clobber uses no flags.
        (*info).Anonymous.Flags = if replace { 0x1 | 0x2 } else { 0 };
        (*info).RootDirectory = null_mut();
        (*info).FileNameLength =
            u32::try_from(filename_bytes).map_err(|_| invalid("private filename is too long"))?;
        std::ptr::copy_nonoverlapping(name.as_ptr(), (*info).FileName.as_mut_ptr(), name.len());
        if SetFileInformationByHandle(
            source.as_raw_handle(),
            FileRenameInfoEx,
            info.cast(),
            length,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    // The caller records successful publication before flushing the still-owned writable file.
    // File flushing does not claim Unix parent-directory fsync / durable-absence equivalence.
    Ok(())
}

pub(super) fn remove_private_file(file: &File) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, ReOpenFile, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };
    require_private(file, false)?;
    let handle = unsafe {
        ReOpenFile(
            file.as_raw_handle(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL | DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let deleting = unsafe { File::from_raw_handle(handle) };
    require_private(&deleting, false)?;
    deleting.sync_all()?;
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    if unsafe {
        SetFileInformationByHandle(
            deleting.as_raw_handle(),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    deleting.sync_all()
}

pub(super) fn remove_private_file_at(base: &File, file: &File) -> io::Result<()> {
    require_private(base, true)?;
    let name = directory_path(file)?;
    if name.parent() != Some(directory_path(base)?.as_path()) {
        return Err(denied(
            "private file does not belong to the pinned directory",
        ));
    }
    remove_private_file(file)
}

pub(super) fn remove_empty_private_directory_at(base: &File, name: &OsStr) -> io::Result<bool> {
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
    };
    validate_filename(name)?;
    require_private(base, true)?;
    let path = directory_path(base)?.join(name);
    let encoded = wide(path.as_os_str())?;
    // The parent stays pinned. This separately held child permits DELETE access and is never
    // re-opened by name for mutation; regular-file/reparse targets fail before disposition.
    let handle = unsafe {
        CreateFileW(
            encoded.as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(error)
        };
    }
    let child = unsafe { File::from_raw_handle(handle) };
    require_private(&child, true)?;
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    if unsafe {
        SetFileInformationByHandle(
            child.as_raw_handle(),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::DirectoryNotEmpty {
            Ok(false)
        } else {
            Err(error)
        };
    }
    drop(child);
    require_private(base, true)?;
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error),
        Ok(_) => Err(denied(
            "private directory remained or was replaced after removal",
        )),
    }
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

    #[test]
    fn root_policy_accepts_modify_but_never_child_or_acl_takeover() {
        let modify = 0x0013_01bf;
        assert_eq!(modify & ancestor_takeover_mask(true), 0);
        assert_ne!(modify & ancestor_takeover_mask(false), 0);
        for right in [
            WRITE_DAC,
            WRITE_OWNER,
            FILE_DELETE_CHILD,
            GENERIC_ALL,
            GENERIC_WRITE,
        ] {
            assert_ne!(right & ancestor_takeover_mask(true), 0);
            assert_ne!(right & ancestor_takeover_mask(false), 0);
        }
        for right in [
            DELETE,
            FILE_WRITE_DATA,
            FILE_WRITE_EA,
            FILE_WRITE_ATTRIBUTES,
        ] {
            assert_ne!(right & ancestor_takeover_mask(false), 0);
        }
        assert_eq!(0x0012_00a9 & ancestor_takeover_mask(false), 0); // read/traverse
        assert_eq!(4 & ancestor_takeover_mask(false), 0); // create-subdirectory only
    }

    #[test]
    fn root_proof_rejects_subst_targets_unc_and_nonroot_paths() {
        assert!(is_same_local_volume_root(
            Path::new(r"C:\"),
            Path::new(r"\\?\C:\")
        ));
        assert!(is_same_local_volume_root(
            Path::new(r"c:\"),
            Path::new(r"\\?\C:\")
        ));
        for resolved in [
            r"\\?\C:\mapped",
            r"\\?\D:\",
            r"\\server\share\",
            r"\\?\UNC\server\share\",
        ] {
            assert!(!is_same_local_volume_root(
                Path::new(r"C:\"),
                Path::new(resolved)
            ));
        }
        assert!(!is_same_local_volume_root(
            Path::new(r"C:\folder"),
            Path::new(r"C:\folder")
        ));
    }

    #[test]
    fn ordinary_directory_cannot_supply_volume_root_child_proof() {
        let temp = tempfile::tempdir().unwrap();
        let child = temp.path().join("child");
        std::fs::create_dir(&child).unwrap();
        let owner = OwnedSid::current_process().unwrap();
        let trust = AncestorTrust::new(&owner).unwrap();
        let directory = open_directory(temp.path(), false).unwrap();
        assert!(
            pin_volume_root_child(&directory, temp.path(), OsStr::new("child"), &trust).is_err()
        );
    }

    fn dacl_bytes(file: &File) -> Vec<u8> {
        // GetSecurityInfo synthesizes INHERITED_ACE flags against the current parent ACL even
        // when the stored child descriptor has not changed. Compare the raw object descriptor,
        // not that inheritance projection. The same byte-identity assertions must detect actual
        // descendant writes (the former SetSecurityInfo repair reduced three child ACEs to one).
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtQuerySecurityObject(
                handle: windows_sys::Win32::Foundation::HANDLE,
                information: u32,
                descriptor: PSECURITY_DESCRIPTOR,
                length: u32,
                needed: *mut u32,
            ) -> i32;
        }
        let mut needed = 0;
        unsafe {
            NtQuerySecurityObject(
                file.as_raw_handle(),
                DACL_SECURITY_INFORMATION,
                null_mut(),
                0,
                &mut needed,
            );
        }
        assert!(needed > 0);
        let mut descriptor = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
        let status = unsafe {
            NtQuerySecurityObject(
                file.as_raw_handle(),
                DACL_SECURITY_INFORMATION,
                descriptor.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        };
        assert!(
            status >= 0,
            "raw security descriptor query failed: {status:#x}"
        );
        let mut acl = null_mut();
        let mut present = 0;
        let mut defaulted = 0;
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(
                    descriptor.as_mut_ptr().cast(),
                    &mut present,
                    &mut acl,
                    &mut defaulted,
                )
            },
            0
        );
        assert_ne!(present, 0);
        assert!(!acl.is_null());
        assert_ne!(unsafe { IsValidAcl(acl) }, 0);
        // SAFETY: the validated ACL is inside the retained descriptor and has a bounded AclSize.
        unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), usize::from((*acl).AclSize)) }
            .to_vec()
    }

    fn set_test_acl(path: &Path, directory: bool, text: &str) {
        let text = wide(OsStr::new(text)).unwrap();
        let mut descriptor = null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            },
            0
        );
        let descriptor = Descriptor(descriptor);
        let path = wide(path.as_os_str()).unwrap();
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                READ_CONTROL | WRITE_DAC,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT
                    | if directory {
                        FILE_FLAG_BACKUP_SEMANTICS
                    } else {
                        0
                    },
                null_mut(),
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE);
        let file = unsafe { File::from_raw_handle(handle) };
        assert_eq!(
            unsafe {
                SetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    descriptor.dacl().unwrap(),
                    null(),
                )
            },
            0
        );
    }

    #[test]
    fn private_authority_accepts_safe_inherited_and_split_acl_without_repair() {
        use super::super::WindowsPrivateDirectory as Directory;
        let temp = tempfile::tempdir().unwrap();
        let sid = OwnedSid::current_process().unwrap().to_string().unwrap();
        set_test_acl(
            temp.path(),
            true,
            &format!("D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"),
        );
        let base = temp.path().join("inherited");
        std::fs::create_dir(&base).unwrap();
        let raw = open_directory(&base, false).unwrap();
        let before = dacl_bytes(&raw);
        let private = Directory::open(&base).unwrap();
        private
            .publish(OsStr::new("key"), b"stable", false)
            .unwrap();
        assert_eq!(dacl_bytes(&raw), before);
        // Multiple owner grants and safe metadata/traversal rights for others are not exposure.
        set_test_acl(&base, true, &format!("D:P(A;;FR;;;{sid})(A;;FW;;;{sid})(A;;FX;;;{sid})(A;;SDWDWO;;;{sid})(A;;0x1200a0;;;WD)(A;OIIO;FR;;;{sid})(D;;WD;;;AN)"));
        let before = dacl_bytes(&raw);
        assert!(Directory::open(&base).is_ok());
        assert_eq!(before, dacl_bytes(&raw));
    }

    #[test]
    fn private_authority_reads_owner_read_only_file_without_requesting_write_access() {
        use super::super::WindowsPrivateDirectory as Directory;
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("identity");
        let directory = Directory::ensure(&base).unwrap();
        let name = OsStr::new("device-key");
        directory.publish(name, b"stable", false).unwrap();
        let sid = OwnedSid::current_process().unwrap().to_string().unwrap();
        set_test_acl(
            &base.join(name),
            false,
            &format!("D:P(A;;FR;;;{sid})(A;;0x120080;;;WD)"),
        );
        let mut file = directory.open_file(name, false).unwrap();
        let before = dacl_bytes(&file);
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"stable");
        assert_eq!(before, dacl_bytes(&file));
    }

    #[test]
    fn private_authority_publication_renames_the_handle_not_a_substituted_source_name() {
        let temp = tempfile::tempdir().unwrap();
        let base_path = temp.path().join("identity");
        let base = private_authority(&base_path, true).unwrap();
        let target = OsStr::new("device-key");
        let mut substituted = None;
        publish_private_with_hook(
            &base.dir,
            target,
            b"original",
            false,
            |original, temporary| {
                let moved = base_path.join("held-original");
                std::fs::rename(base_path.join(temporary), &moved)?;
                let mut impostor = open_private_file_at(&base.dir, temporary, true)?;
                impostor.write_all(b"impostor")?;
                impostor.sync_all()?;
                assert_ne!(
                    require_private(original, false)?,
                    require_private(&impostor, false)?
                );
                substituted = Some(temporary.to_os_string());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(std::fs::read(base_path.join(target)).unwrap(), b"original");
        assert_eq!(
            std::fs::read(base_path.join(substituted.unwrap())).unwrap(),
            b"impostor"
        );
        assert!(!base_path.join("held-original").exists());
    }

    #[test]
    fn private_authority_concurrent_no_replace_has_one_complete_winner() {
        use super::super::WindowsPrivateDirectory as Directory;
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("identity");
        let _root = Directory::ensure(&base).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = [b"first".as_slice(), b"second".as_slice()]
            .into_iter()
            .map(|bytes| {
                let base = base.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let directory = Directory::open(&base).unwrap();
                    barrier.wait();
                    (
                        bytes,
                        directory.publish(OsStr::new("device-key"), bytes, false),
                    )
                })
            })
            .collect();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(
            results.iter().filter(|(_, result)| result.is_ok()).count(),
            1
        );
        let winner = results.iter().find(|(_, result)| result.is_ok()).unwrap().0;
        let loser = results.iter().find(|(_, result)| result.is_err()).unwrap();
        assert_eq!(
            loser.1.as_ref().unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(base.join("device-key")).unwrap(), winner);
    }

    #[test]
    fn private_authority_observes_exposed_directory_without_repair() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("identity");
        std::fs::create_dir(&base).unwrap();
        let sid = OwnedSid::current_process().unwrap().to_string().unwrap();
        set_test_acl(
            &base,
            true,
            &format!("D:P(A;OICI;FA;;;{sid})(A;OICI;FR;;;WD)"),
        );
        let directory = open_directory(&base, false).unwrap();
        let before = dacl_bytes(&directory);
        assert!(private_authority(&base, false).is_err());
        assert!(private_authority(&base, true).is_err());
        assert_eq!(before, dacl_bytes(&directory));
        assert_eq!(std::fs::read_dir(&base).unwrap().count(), 0);
    }

    #[test]
    fn private_authority_publication_preserves_winner_and_has_real_identity() {
        use super::super::WindowsPrivateDirectory as Directory;
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("identity");
        let directory = Directory::ensure(&base).unwrap();
        let name = OsStr::new("device-key");
        directory.publish(name, b"first", false).unwrap();
        let first = directory.open_file(name, false).unwrap();
        let first_identity = Directory::validate_file(&first).unwrap();
        assert_ne!(first_identity.file_index, 0);
        assert_eq!(
            directory.publish(name, b"loser", false).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert_eq!(std::fs::read(base.join(name)).unwrap(), b"first");
        directory.publish(name, b"second", true).unwrap();
        let second = directory.open_file(name, false).unwrap();
        assert_ne!(Directory::validate_file(&second).unwrap(), first_identity);
        assert_eq!(std::fs::read(base.join(name)).unwrap(), b"second");
        drop(first);
        directory.remove_opened_file(second).unwrap();
        assert!(!base.join(name).exists());
    }

    #[test]
    fn private_authority_rejects_foreign_file_access_and_hardlinks_without_repair() {
        use super::super::WindowsPrivateDirectory as Directory;
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("identity");
        let directory = Directory::ensure(&base).unwrap();
        let exposed = base.join("unprotected");
        std::fs::write(&exposed, b"preserve").unwrap();
        // Safe inherited owner access is accepted, but an actual foreign read grant is not.
        directory
            .open_file(OsStr::new("unprotected"), false)
            .unwrap();
        let sid = OwnedSid::current_process().unwrap().to_string().unwrap();
        set_test_acl(&exposed, false, &format!("D:P(A;;FA;;;{sid})(A;;FR;;;WD)"));
        let file = File::open(&exposed).unwrap();
        let before = dacl_bytes(&file);
        assert!(directory
            .open_file(OsStr::new("unprotected"), false)
            .is_err());
        assert_eq!(before, dacl_bytes(&file));
        assert_eq!(std::fs::read(&exposed).unwrap(), b"preserve");
        directory
            .publish(OsStr::new("original"), b"private", false)
            .unwrap();
        std::fs::hard_link(base.join("original"), base.join("alias")).unwrap();
        assert!(directory.open_file(OsStr::new("alias"), false).is_err());
        assert!(directory
            .publish(OsStr::new("original"), b"replacement", true)
            .is_err());
        assert_eq!(std::fs::read(base.join("original")).unwrap(), b"private");
    }

    #[test]
    fn private_authority_checks_foreign_inherit_only_grants_on_directories() {
        use super::super::WindowsPrivateDirectory as Directory;
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("identity");
        let directory = Directory::ensure(&base).unwrap();
        let sid = OwnedSid::current_process().unwrap().to_string().unwrap();
        set_test_acl(
            &base,
            true,
            &format!("D:P(A;OICI;FA;;;{sid})(A;OIIO;FR;;;WD)"),
        );
        assert!(Directory::open(&base).is_err());
        assert!(directory
            .publish(OsStr::new("record"), b"must-not-publish", false)
            .is_err());
        assert!(!base.join("record").exists());
    }

    #[test]
    fn private_authority_accepts_owner_aliases_but_not_creator_group_or_effective_creator_owner() {
        use super::super::WindowsPrivateDirectory as Directory;
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("identity");
        let directory = Directory::ensure(&base).unwrap();
        let sid = OwnedSid::current_process().unwrap().to_string().unwrap();
        set_test_acl(
            &base,
            true,
            &format!("D:P(A;;FA;;;{sid})(A;;FA;;;S-1-3-4)(A;OICIIO;FA;;;CO)"),
        );
        assert!(Directory::open(&base).is_ok());
        // Reopening a nested authority also revalidates this directory as ancestry.
        let nested = Directory::ensure(&base.join("nested")).unwrap();
        nested
            .publish(OsStr::new("record"), b"private", false)
            .unwrap();
        drop(nested);
        for acl in [
            format!("D:P(A;;FA;;;{sid})(A;OICIIO;FA;;;CG)"),
            format!("D:P(A;;FA;;;{sid})(A;;FA;;;CO)"),
        ] {
            set_test_acl(&base, true, &acl);
            let raw = open_directory(&base, false).unwrap();
            let before = dacl_bytes(&raw);
            let observed = ObjectSecurity::read(&raw).unwrap();
            let dacl = observed.descriptor.dacl().unwrap();
            // Windows may materialize CREATOR OWNER into the current owner's SID when applying
            // this DACL. Judge the actual stored trustees, not the input template spelling.
            let mut foreign = false;
            for index in 0..u32::from(unsafe { (*dacl).AceCount }) {
                if let Some((_, trustee, flags)) =
                    allowed_ace_with_inheritance(dacl, index, true).unwrap()
                {
                    let trustee = OwnedSid::copy_from(trustee, "test ACL trustee")
                        .unwrap()
                        .to_string()
                        .unwrap();
                    let inherited_owner =
                        trustee == "S-1-3-0" && u32::from(flags) & INHERIT_ONLY_ACE != 0;
                    foreign |= trustee != sid && trustee != "S-1-3-4" && !inherited_owner;
                }
            }
            assert_eq!(Directory::open(&base).is_err(), foreign);
            assert_eq!(directory.identity().is_err(), foreign);
            assert_eq!(before, dacl_bytes(&raw));
        }
    }

    #[test]
    fn private_authority_removes_only_empty_real_child_directories() {
        use super::super::WindowsPrivateDirectory as Directory;
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("identity");
        let directory = Directory::ensure(&base).unwrap();
        let name = OsStr::new("recovery");
        assert!(!directory.remove_empty_child(name).unwrap());
        let child = Directory::ensure(&base.join(name)).unwrap();
        child
            .publish(OsStr::new("journal"), b"retain", false)
            .unwrap();
        drop(child);
        assert!(!directory.remove_empty_child(name).unwrap());
        assert_eq!(
            std::fs::read(base.join(name).join("journal")).unwrap(),
            b"retain"
        );
        let child = Directory::open(&base.join(name)).unwrap();
        let journal = child.open_file(OsStr::new("journal"), false).unwrap();
        child.remove_opened_file(journal).unwrap();
        drop(child);
        assert!(directory.remove_empty_child(name).unwrap());
        assert!(!base.join(name).exists());
        directory.publish(name, b"not-a-directory", false).unwrap();
        assert!(directory.remove_empty_child(name).is_err());
        assert_eq!(std::fs::read(base.join(name)).unwrap(), b"not-a-directory");
    }

    #[test]
    fn private_authority_lock_contends_and_pins_its_root() {
        use super::super::WindowsPrivateDirectory as Directory;
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("identity");
        let directory = Directory::ensure(&base).unwrap();
        let name = OsStr::new("lifecycle.lock");
        let lock = directory.try_lock(name).unwrap();
        assert_eq!(
            directory.try_lock(name).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert!(std::fs::remove_file(base.join(name)).is_err());
        assert!(std::fs::rename(&base, temp.path().join("moved")).is_err());
        drop(lock);
        directory.try_lock(name).unwrap();
    }

    #[test]
    fn private_authority_cannot_delete_another_directorys_file() {
        use super::super::WindowsPrivateDirectory as Directory;
        let temp = tempfile::tempdir().unwrap();
        let first = Directory::ensure(&temp.path().join("first")).unwrap();
        let second_path = temp.path().join("second");
        let second = Directory::ensure(&second_path).unwrap();
        second
            .publish(OsStr::new("record"), b"preserve", false)
            .unwrap();
        let file = second.open_file(OsStr::new("record"), false).unwrap();
        assert!(first.remove_opened_file(file).is_err());
        assert_eq!(
            std::fs::read(second_path.join("record")).unwrap(),
            b"preserve"
        );
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
