//! Prefer the app-local Microsoft ConPTY runtime when packaged, without changing the OS.
//! The inbox APIs remain available for unbundled developer builds. All operations on one
//! HPCON use the same API; a loaded module stays resident through asynchronous close.

use anyhow::{anyhow, bail, Context, Result};
use std::ffi::CStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::{FreeLibrary, HANDLE, HMODULE};
use windows_sys::Win32::System::Console::{
    ClosePseudoConsole, CreatePseudoConsole, ResizePseudoConsole, COORD, HPCON,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

type Create = unsafe extern "system" fn(COORD, HANDLE, HANDLE, u32, *mut HPCON) -> i32;
type Resize = unsafe extern "system" fn(HPCON, COORD) -> i32;
type Close = unsafe extern "system" fn(HPCON);

pub(super) struct Api {
    create: Create,
    resize: Resize,
    close: Close,
    flags: u32,
}

impl Api {
    pub(super) unsafe fn create(
        &self,
        size: COORD,
        input: HANDLE,
        output: HANDLE,
        hpc: *mut HPCON,
    ) -> i32 {
        unsafe { (self.create)(size, input, output, self.flags, hpc) }
    }

    pub(super) unsafe fn resize(&self, hpc: HPCON, size: COORD) -> i32 {
        unsafe { (self.resize)(hpc, size) }
    }

    pub(super) unsafe fn close(&self, hpc: HPCON) {
        unsafe { (self.close)(hpc) }
    }
}

pub(super) fn api() -> Result<&'static Api> {
    static API: OnceLock<std::result::Result<Api, String>> = OnceLock::new();
    API.get_or_init(|| {
        let result = std::env::current_exe()
            .context("locate daemon for app-local ConPTY")
            .and_then(|exe| load_for_executable(&exe));
        result.map_err(|error| format!("{error:#}"))
    })
    .as_ref()
    .map_err(|error| anyhow!(error.clone()))
}

fn load_for_executable(executable: &Path) -> Result<Api> {
    let directory = executable
        .parent()
        .filter(|parent| parent.is_absolute())
        .context("daemon has no absolute package directory")?
        .join("conpty");
    let dll = directory.join("conpty.dll");
    match std::fs::metadata(&dll) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("hydra-conpty runtime=inbox (app-local runtime not packaged)");
            return Ok(Api {
                create: CreatePseudoConsole,
                resize: ResizePseudoConsole,
                close: ClosePseudoConsole,
                flags: 0,
            });
        }
        Err(error) => return Err(error).context("inspect app-local ConPTY runtime"),
        Ok(metadata) if !metadata.is_file() => bail!("app-local conpty.dll is not a file"),
        Ok(_) => {}
    }
    if !directory.join("OpenConsole.exe").is_file() {
        bail!("app-local ConPTY is incomplete: OpenConsole.exe is missing; reinstall the complete package");
    }
    let wide: Vec<u16> = dll.as_os_str().encode_wide().chain(Some(0)).collect();
    // Never search the terminal's cwd or PATH for executable code. Microsoft ships these
    // two files together; the loader may resolve only this DLL's directory and System32.
    let module = unsafe {
        LoadLibraryExW(
            wide.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    };
    if module.is_null() {
        return Err(std::io::Error::last_os_error()).context("load app-local conpty.dll");
    }
    let module = LoadedModule(module);
    let api = unsafe {
        Api {
            create: std::mem::transmute::<unsafe extern "system" fn() -> isize, Create>(
                module.symbol(c"ConptyCreatePseudoConsole")?,
            ),
            resize: std::mem::transmute::<unsafe extern "system" fn() -> isize, Resize>(
                module.symbol(c"ConptyResizePseudoConsole")?,
            ),
            close: std::mem::transmute::<unsafe extern "system" fn() -> isize, Close>(
                module.symbol(c"ConptyClosePseudoConsole")?,
            ),
            // Microsoft's PSEUDOCONSOLE_GLYPH_WIDTH_WCSWIDTH: matches Hydra's scalar
            // width model, including zero-width combining marks (not legacy console cells).
            flags: 0x10,
        }
    };
    // The singleton API and control threads may outlive every session. Do not unload their code.
    std::mem::forget(module);
    eprintln!("hydra-conpty runtime=app-local glyph-width=wcswidth");
    Ok(api)
}

struct LoadedModule(HMODULE);

impl LoadedModule {
    unsafe fn symbol(&self, name: &CStr) -> Result<unsafe extern "system" fn() -> isize> {
        unsafe { GetProcAddress(self.0, name.as_ptr().cast()) }
            .with_context(|| format!("app-local ConPTY missing export {}", name.to_string_lossy()))
    }
}

impl Drop for LoadedModule {
    fn drop(&mut self) {
        unsafe { FreeLibrary(self.0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_package_uses_inbox_without_searching_the_working_directory() {
        let exe = std::env::temp_dir()
            .join(format!("hydra-conpty-absent-{}", uuid::Uuid::new_v4()))
            .join("pty-daemon.exe");
        let selected = load_for_executable(&exe).unwrap();
        assert_eq!(selected.flags, 0);
        assert_eq!(selected.create as usize, CreatePseudoConsole as usize);
    }

    #[test]
    fn incomplete_package_is_not_silently_downgraded() {
        let root =
            std::env::temp_dir().join(format!("hydra-conpty-partial-{}", uuid::Uuid::new_v4()));
        let runtime = root.join("conpty");
        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::write(runtime.join("conpty.dll"), b"synthetic incomplete package").unwrap();
        let result = load_for_executable(&root.join("pty-daemon.exe"));
        std::fs::remove_dir_all(&root).unwrap();
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("OpenConsole.exe"));
    }
}
