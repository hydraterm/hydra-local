//! Current-user descriptor ownership for the preserved private ConPTY pipe factory.
//! The shared Session's Windows backend uses this exact private-pipe descriptor.

use crate::windows_job::{owned_handle, raw_handle};
use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    CopySid, GetLengthSid, GetTokenInformation, TokenUser, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Aligned owned storage for one copied SID. Keeping a copy means no pointer escapes the token
/// information buffer returned by Windows.
struct OwnedSid {
    words: Vec<usize>,
    byte_len: u32,
}

impl OwnedSid {
    fn copy_from(sid: PSID, missing_message: &'static str) -> io::Result<Self> {
        if sid.is_null() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, missing_message));
        }
        let sid_len = unsafe { GetLengthSid(sid) };
        if sid_len == 0 {
            return Err(io::Error::last_os_error());
        }
        let sid_word_count = (sid_len as usize)
            .checked_add(size_of::<usize>() - 1)
            .and_then(|bytes| bytes.checked_div(size_of::<usize>()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SID size overflow"))?;
        let mut words = vec![0usize; sid_word_count];
        if unsafe { CopySid(sid_len, words.as_mut_ptr().cast(), sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            words,
            byte_len: sid_len,
        })
    }

    fn from_token(token: HANDLE) -> io::Result<Self> {
        let mut needed = 0u32;
        // The first call intentionally supplies no buffer and obtains the exact byte count.
        unsafe {
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed);
        }
        if needed < size_of::<TOKEN_USER>() as u32 {
            return Err(io::Error::last_os_error());
        }

        let word_count = (needed as usize)
            .checked_add(size_of::<usize>() - 1)
            .and_then(|bytes| bytes.checked_div(size_of::<usize>()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "token SID size overflow"))?;
        let mut token_words = vec![0usize; word_count];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                token_words.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }

        // `token_words` has pointer alignment, and GetTokenInformation wrote a TOKEN_USER at its
        // beginning. Its SID pointer remains valid until this temporary buffer is dropped.
        let user = unsafe { &*(token_words.as_ptr().cast::<TOKEN_USER>()) };
        Self::copy_from(user.User.Sid, "Windows token did not contain a user SID")
    }

    fn current_process() -> io::Result<Self> {
        let mut token = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = unsafe { owned_handle(token, "current-process token")? };
        Self::from_token(raw_handle(&token))
    }

    fn as_ptr(&self) -> PSID {
        self.words.as_ptr() as *mut c_void
    }

    fn to_string(&self) -> io::Result<String> {
        debug_assert!(self.byte_len > 0);
        let mut raw = null_mut();
        if unsafe { ConvertSidToStringSidW(self.as_ptr(), &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let raw = LocalWideString(raw);
        let mut len = 0usize;
        // ConvertSidToStringSidW returns a NUL-terminated LocalAlloc buffer.
        while unsafe { *raw.0.add(len) } != 0 {
            len = len.checked_add(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "SID string length overflow")
            })?;
        }
        String::from_utf16(unsafe { std::slice::from_raw_parts(raw.0, len) }).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows returned a non-Unicode SID string",
            )
        })
    }
}
struct LocalWideString(*mut u16);

impl Drop for LocalWideString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0.cast());
            }
        }
    }
}

struct LocalSecurityDescriptor(*mut c_void);

impl LocalSecurityDescriptor {
    fn for_user(sid: &str) -> io::Result<Self> {
        // Preserve the final backend's protected, current-user-only private-pipe DACL.
        let sddl = format!("D:P(A;;GA;;;{sid})");
        let encoded: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                encoded.as_ptr(),
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
}

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

/// Owns the protected current-user-only descriptor behind a Win32
/// `SECURITY_ATTRIBUTES` value. The descriptor allocation remains live for every syscall that
/// receives [`as_ptr`](Self::as_ptr); Windows copies it into the newly-created kernel object.
///
/// This is the preserved ConPTY private-pipe constructor, available to the later listener
/// integration without creating a second descriptor policy.
pub(super) struct CurrentUserSecurityAttributes {
    _descriptor: LocalSecurityDescriptor,
    attributes: SECURITY_ATTRIBUTES,
}

impl CurrentUserSecurityAttributes {
    pub(super) fn new() -> io::Result<Self> {
        let sid = OwnedSid::current_process()?.to_string()?;
        Self::for_sid(&sid)
    }

    fn for_sid(sid: &str) -> io::Result<Self> {
        let descriptor = LocalSecurityDescriptor::for_user(sid)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        Ok(Self {
            _descriptor: descriptor,
            attributes,
        })
    }

    pub(super) fn as_ptr(&mut self) -> *mut SECURITY_ATTRIBUTES {
        &mut self.attributes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_private_pipe::{private_pipe, PipeDirection};
    use windows_sys::Win32::Foundation::GENERIC_ALL;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{
        EqualSid, GetAce, GetSecurityDescriptorControl, ACCESS_ALLOWED_ACE,
        DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;

    #[test]
    fn created_pipe_keeps_one_protected_current_user_allow_ace() -> io::Result<()> {
        let (server, _client) =
            private_pipe(PipeDirection::HydraReads).map_err(io::Error::other)?;
        let mut dacl = null_mut();
        let mut descriptor = null_mut();
        let status = unsafe {
            GetSecurityInfo(
                raw_handle(&server),
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let descriptor = LocalSecurityDescriptor(descriptor);
        assert!(!descriptor.0.is_null());
        assert!(!dacl.is_null(), "private pipe must not have a NULL DACL");
        let mut control = 0;
        let mut revision = 0;
        if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
            return Err(io::Error::last_os_error());
        }
        assert_ne!(control & SE_DACL_PROTECTED, 0);
        assert_eq!(unsafe { (*dacl).AceCount }, 1);
        let mut ace = null_mut();
        if unsafe { GetAce(dacl, 0, &mut ace) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // ACCESS_ALLOWED_ACE_TYPE is zero in the Win32 ACE header ABI.
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        assert_eq!(allowed.Header.AceType, 0);
        assert!(
            allowed.Mask & GENERIC_ALL != 0 || allowed.Mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS
        );
        let current = OwnedSid::current_process()?;
        let ace_sid = (&allowed.SidStart as *const u32).cast_mut().cast();
        assert_ne!(unsafe { EqualSid(ace_sid, current.as_ptr()) }, 0);
        Ok(())
    }
}
