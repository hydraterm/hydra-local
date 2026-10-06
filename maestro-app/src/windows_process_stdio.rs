//! Keep caller-owned capture pipes out of independently retained child processes.
//!
//! Rust 1.88 Command uses CreateProcessW with bInheritHandles=TRUE. Replacing a child's
//! standard streams with NUL does not exclude unrelated inheritable handles already in this
//! process. Clear only the inheritance bit on our standard pipes before spawning anything.
//! The handles remain open and usable; explicit Stdio::inherit duplicates them when requested.

use std::io;
use windows_sys::Win32::Foundation::{
    SetHandleInformation, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{GetFileType, FILE_TYPE_PIPE};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};

/// Call at the single-threaded app entrypoint, before any child launch or background work.
pub(crate) fn detach_capture_pipe_inheritance() -> io::Result<()> {
    for stream in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: GetStdHandle returns a borrowed process handle; we neither close nor replace it.
        let handle = unsafe { GetStdHandle(stream) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            continue;
        }
        // Consoles, files and GUI startup without standard handles retain their original setup.
        if unsafe { GetFileType(handle) } != FILE_TYPE_PIPE {
            continue;
        }
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}
