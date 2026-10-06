//! Windows GUI launcher. No console flash, shell quoting, service or elevation.
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use windows_sys::Win32::System::Registry::{
    RegGetValueW, HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONERROR, MB_OK};

const CREATE_NO_WINDOW: u32 = 0x08000000;
const LOG_LIMIT: usize = 2 * 1024 * 1024;
const LOG_COUNT: usize = 10;
#[cfg(test)]
#[path = "windows/capture_tests.rs"]
mod capture_tests;
#[path = "windows/process_stdio.rs"]
mod process_stdio;
const CHANNEL: &str = if cfg!(feature = "windows-local-qa") {
    "local-desktop-qa"
} else {
    "development"
};

pub(crate) fn main() {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    if arguments == [OsString::from("--package-info")] {
        println!(
            "{{\"platform\":\"windows\",\"channel\":\"{CHANNEL}\",\"version\":\"{}\"}}",
            env!("CARGO_PKG_VERSION")
        );
        return;
    }
    if let Err(error) =
        process_stdio::detach_capture_pipe_inheritance().and_then(|()| run(arguments))
    {
        let message = wide(&format!("Hydra could not start.\n\n{error}"));
        let title = wide("Hydra — startup problem");
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONERROR,
            )
        };
        std::process::exit(1);
    }
}

fn run(arguments: Vec<OsString>) -> io::Result<()> {
    let exe = std::env::current_exe()?;
    let bin = exe
        .parent()
        .ok_or_else(|| invalid("Launcher directory is unavailable"))?;
    validate_package(bin)?;
    if !webview_runtime_present() {
        return Err(invalid("Microsoft Edge WebView2 Runtime is missing. Install the Evergreen Runtime from https://developer.microsoft.com/microsoft-edge/webview2/ and reopen Hydra. No projects or sessions were changed."));
    }
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or_else(|| invalid("Windows Local AppData is unavailable"))?;
    let base = local.join(if cfg!(feature = "windows-local-qa") {
        "Hydra-LocalDesktopQA"
    } else {
        "Hydra"
    });
    let mut pipe = maestro_shell::windows_default_pipe_name()?.into_os_string();
    if cfg!(feature = "windows-local-qa") {
        pipe.push(".local-desktop-qa");
    }
    let (path, file) = open_launch_log(&base.join("logs"))?;
    let log = Arc::new(Mutex::new(BoundedLog { file, written: 0 }));
    let command = launch_command(bin, &base, &pipe, &arguments);
    let status = run_logged_gui(command, log)?;
    if status.success() {
        Ok(())
    } else {
        Err(invalid(format!(
            "The application exited with {status}. Details: {}",
            path.display()
        )))
    }
}

fn run_logged_gui(
    mut command: Command,
    log: Arc<Mutex<BoundedLog>>,
) -> io::Result<std::process::ExitStatus> {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            invalid(format!(
                "Cannot launch the packaged application: {error}. Reinstall the complete package."
            ))
        })?;
    let output = drain(child.stdout.take().expect("piped stdout"), Arc::clone(&log));
    let errors = drain(child.stderr.take().expect("piped stderr"), log);
    let status = child.wait()?;
    // Only the GUI child is waited; the independent retained daemon is not killed or waited.
    for thread in [output, errors] {
        let _ = thread.join();
    }
    Ok(status)
}

fn launch_command(bin: &Path, base: &Path, pipe: &OsStr, extra: &[OsString]) -> Command {
    let mut command = Command::new(bin.join("maestro-app.exe"));
    command
        .args([
            "launch",
            "--top-tab-bar",
            "--no-dashboard-panel",
            "--new-tab-default-shell",
            "--product-startup",
            "--keep-daemon",
            "--title",
            "Hydra",
        ])
        .arg("--base")
        .arg(base)
        .arg("--socket")
        .arg(pipe)
        .arg("--daemon")
        .arg(bin.join("pty-daemon.exe"))
        .args(extra)
        .current_dir(base.parent().expect("app-support parent"))
        .creation_flags(CREATE_NO_WINDOW);
    command
}

fn validate_package(bin: &Path) -> io::Result<()> {
    for relative in [
        "maestro-app.exe",
        "pty-daemon.exe",
        "conpty/conpty.dll",
        "conpty/OpenConsole.exe",
        "../dashboard-ui/index.html",
    ] {
        let path = bin.join(relative);
        if !path.is_file() || path.metadata()?.len() == 0 {
            return Err(invalid(format!("The package is incomplete ({relative}). Reinstall the complete Hydra package; existing projects and retained sessions are unchanged.")));
        }
    }
    Ok(())
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(Some(0)).collect()
}
fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}

// Microsoft's documented Evergreen Runtime identity, not the Edge browser or preview channel.
fn webview_runtime_present() -> bool {
    const USER: &str =
        r"Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";
    const MACHINE: &str =
        r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";
    [(HKEY_CURRENT_USER, USER), (HKEY_LOCAL_MACHINE, MACHINE)]
        .into_iter()
        .filter_map(|(hive, key)| registry_version(hive, key))
        .any(|version| usable_version(&version))
}

fn registry_version(hive: HKEY, key: &str) -> Option<String> {
    let mut buffer = [0u16; 256];
    let mut bytes = std::mem::size_of_val(&buffer) as u32;
    let status = unsafe {
        RegGetValueW(
            hive,
            wide(key).as_ptr(),
            wide("pv").as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if status != 0
        || bytes == 0
        || bytes as usize > std::mem::size_of_val(&buffer)
        || bytes % 2 != 0
    {
        return None;
    }
    let used = &buffer[..bytes as usize / 2];
    String::from_utf16(used.strip_suffix(&[0]).unwrap_or(used)).ok()
}

fn usable_version(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').map(str::parse::<u32>).collect();
    parts.len() == 4
        && parts.iter().all(Result::is_ok)
        && parts
            .iter()
            .any(|part| part.as_ref().is_ok_and(|v| *v != 0))
}

fn open_launch_log(directory: &Path) -> io::Result<(PathBuf, File)> {
    fs::create_dir_all(directory)?;
    let mut old: Vec<_> = fs::read_dir(directory)?
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("windows-launch-") && name.ends_with(".log"))
        })
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .collect();
    old.sort_by_key(|entry| entry.file_name());
    let remove = old.len().saturating_sub(LOG_COUNT - 1);
    for entry in old.into_iter().take(remove) {
        let _ = fs::remove_file(entry.path());
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let path = directory.join(format!("windows-launch-{stamp}-{}.log", std::process::id()));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    Ok((path, file))
}

struct BoundedLog {
    file: File,
    written: usize,
}
impl BoundedLog {
    fn append(&mut self, bytes: &[u8]) -> io::Result<()> {
        let count = bytes.len().min(LOG_LIMIT.saturating_sub(self.written));
        self.file.write_all(&bytes[..count])?;
        self.written += count;
        Ok(())
    }
}
fn drain(
    mut input: impl Read + Send + 'static,
    log: Arc<Mutex<BoundedLog>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buffer = [0; 8192];
        while let Ok(count) = input.read(&mut buffer) {
            if count == 0 {
                break;
            }
            if let Ok(mut log) = log.lock() {
                let _ = log.append(&buffer[..count]);
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn evergreen_version_requires_four_numeric_components_not_all_zero() {
        for valid in ["130.0.2849.68", "0.0.0.1"] {
            assert!(usable_version(valid));
        }
        for invalid in [
            "",
            "0.0.0.0",
            "1.2.3",
            "0.2.3.4.5",
            "1.2.3.preview",
            "0.2.3.4\0",
        ] {
            assert!(!usable_version(invalid));
        }
    }
    #[test]
    fn launcher_keeps_literal_paths_and_retained_daemon() {
        let bin = Path::new(r"C:\Hydra ü test\bin");
        let base = Path::new(r"C:\User space\Hydra-LocalDesktopQA");
        let pipe = OsStr::new(r"\\.\pipe\Hydra.Maestro.test.local-desktop-qa");
        let command = launch_command(bin, base, pipe, &[]);
        assert_eq!(command.get_program(), bin.join("maestro-app.exe"));
        let args: Vec<_> = command.get_args().collect();
        assert!(args.contains(&OsStr::new("--keep-daemon")));
        for (flag, value) in [("--base", base.as_os_str()), ("--socket", pipe)] {
            let index = args.iter().position(|arg| *arg == flag).unwrap();
            assert_eq!(args[index + 1], value);
        }
    }
    #[test]
    fn bounded_log_discards_excess_but_drains_input() {
        let root =
            std::env::temp_dir().join(format!("hydra-launcher-log-test-{}", std::process::id()));
        let (path, file) = open_launch_log(&root).unwrap();
        let log = Arc::new(Mutex::new(BoundedLog { file, written: 0 }));
        drain(io::Cursor::new(vec![b'x'; LOG_LIMIT + 32768]), log.clone())
            .join()
            .unwrap();
        drop(log);
        assert_eq!(fs::metadata(&path).unwrap().len(), LOG_LIMIT as u64);
        fs::remove_file(path).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
