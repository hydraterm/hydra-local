//! Owned Windows user SID used by the shared local-store handle boundary.

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::{LocalFree, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    CopySid, GetLengthSid, GetTokenInformation, TokenUser, PSID, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

pub(crate) struct OwnedSid {
    words: Vec<usize>,
    byte_len: u32,
}

impl OwnedSid {
    pub(crate) fn copy_from(sid: PSID, missing_message: &'static str) -> io::Result<Self> {
        if sid.is_null() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, missing_message));
        }
        let sid_len = unsafe { GetLengthSid(sid) };
        if sid_len == 0 {
            return Err(io::Error::last_os_error());
        }
        let word_count = (sid_len as usize)
            .checked_add(size_of::<usize>() - 1)
            .and_then(|bytes| bytes.checked_div(size_of::<usize>()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SID size overflow"))?;
        let mut words = vec![0usize; word_count];
        if unsafe { CopySid(sid_len, words.as_mut_ptr().cast(), sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            words,
            byte_len: sid_len,
        })
    }

    pub(crate) fn from_token(token: HANDLE) -> io::Result<Self> {
        let mut needed = 0u32;
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
        let mut words = vec![0usize; word_count];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                words.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let user = unsafe { &*(words.as_ptr().cast::<TOKEN_USER>()) };
        Self::copy_from(user.User.Sid, "Windows token did not contain a user SID")
    }

    pub(crate) fn current_process() -> io::Result<Self> {
        let token = open_process_token(unsafe { GetCurrentProcess() })?;
        Self::from_token(raw_handle(&token))
    }

    pub(crate) fn as_ptr(&self) -> PSID {
        self.words.as_ptr() as *mut c_void
    }

    pub(crate) fn to_string(&self) -> io::Result<String> {
        debug_assert!(self.byte_len > 0);
        let mut raw = null_mut();
        if unsafe { ConvertSidToStringSidW(self.as_ptr(), &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let raw = LocalWideString(raw);
        let mut len = 0usize;
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

fn open_process_token(process: HANDLE) -> io::Result<OwnedHandle> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    owned_handle(token, "OpenProcessToken")
}

fn raw_handle(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle() as HANDLE
}

fn owned_handle(handle: HANDLE, operation: &'static str) -> io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::other(format!(
            "{operation} returned an invalid Windows handle"
        )));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}
