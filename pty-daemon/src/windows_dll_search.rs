//! Daemon-only process-wide DLL search policy; not part of reusable pipe transport.
use std::io;
use windows_sys::Win32::System::LibraryLoader::{
    SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

/// Restrict all later name-only DLL loads in this daemon to Windows' protected system directory.
///
/// The Windows terminal backend links the documented ConPTY exports directly. This process-wide
/// restriction remains defense in depth for any future or transitive name-only load: standard DLL
/// search order must not execute a sidecar from the application directory, current directory, or
/// PATH. This standalone authority does not support application-local plugins or DLL sidecars.
pub fn restrict_dll_search_to_system32() -> io::Result<()> {
    if unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
