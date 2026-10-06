//! Fixed platform HTTP executable for bounded metadata requests. Never consult PATH.
use std::process::Command;

pub(crate) fn curl_command() -> Option<Command> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        Some(Command::new("/usr/bin/curl"))
    }
    #[cfg(windows)]
    {
        use std::os::windows::{ffi::OsStringExt, process::CommandExt};
        use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
        let mut buffer = [0u16; 32768];
        let count = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
        if count == 0 || count as usize >= buffer.len() {
            return None;
        }
        let executable =
            std::path::PathBuf::from(std::ffi::OsString::from_wide(&buffer[..count as usize]))
                .join("curl.exe");
        if !executable.is_absolute() || !executable.is_file() {
            return None;
        }
        let mut command = Command::new(executable);
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW, including background refresh.
        Some(command)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        None
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn windows_inbox_curl_does_not_follow_path_or_systemroot_environment() {
        let mut command = curl_command().expect("Windows 11 system curl");
        let executable = std::path::Path::new(command.get_program());
        assert!(executable.is_absolute());
        assert_eq!(executable.file_name().unwrap(), "curl.exe");
        assert!(executable
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .eq_ignore_ascii_case("System32"));
        let output = command
            .args(["-q", "--version"])
            .env("PATH", r"C:\missing-hydra-fixture")
            .env("SystemRoot", r"C:\missing-hydra-fixture")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(output.stdout.starts_with(b"curl "));
    }
}
