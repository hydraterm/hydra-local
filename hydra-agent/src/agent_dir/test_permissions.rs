//! Native permission fixtures. Never used by production authority checks.
use std::{io, path::Path};

pub(crate) fn set_mode(path: impl AsRef<Path>, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }
    #[cfg(windows)]
    {
        set_windows_mode(path.as_ref(), mode)
    }
}

#[cfg(windows)]
fn set_windows_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::{
        os::windows::ffi::OsStrExt,
        ptr::{null, null_mut},
    };
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                GetNamedSecurityInfoW, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
            },
            GetSecurityDescriptorDacl, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION,
        },
    };
    struct Local(*mut std::ffi::c_void);
    impl Drop for Local {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    assert!(
        matches!(mode, 0o600 | 0o644 | 0o700),
        "unmapped fixture mode {mode:o}"
    );
    let path_wide: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut owner = null_mut();
    let mut owner_descriptor = null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            path_wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut owner_descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _owner_descriptor = Local(owner_descriptor);
    let mut owner_text = null_mut();
    if unsafe { ConvertSidToStringSidW(owner, &mut owner_text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _owner_text = Local(owner_text.cast());
    let mut len = 0;
    while unsafe { *owner_text.add(len) } != 0 {
        len += 1;
    }
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(owner_text, len) })
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let flags = if path.is_dir() { "OICI" } else { "" };
    let exposure = if mode == 0o644 { "(A;;FR;;;WD)" } else { "" };
    let text: Vec<_> = format!("D:P(A;{flags};FA;;;{sid}){exposure}")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = null_mut();
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
    let _descriptor = Local(descriptor);
    let mut acl = null_mut();
    let mut present = 0;
    let mut defaulted = 0;
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    assert_ne!(present, 0);
    assert!(!acl.is_null());
    let status = unsafe {
        SetNamedSecurityInfoW(
            path_wide.as_ptr(),
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
    Ok(())
}
