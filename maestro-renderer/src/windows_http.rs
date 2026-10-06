//! Native browser dispatch: one literal HTTP(S) document, never a command line.
use windows_sys::Win32::System::Com::{
    CoInitializeEx, CoUninitialize, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE,
};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub struct HttpOpen {
    target: Vec<u16>,
}

impl HttpOpen {
    pub fn prepare(url: &str) -> Option<Self> {
        maestro_protocol::is_safe_terminal_http_url(url).then(|| Self {
            target: url.encode_utf16().chain(Some(0)).collect(),
        })
    }

    /// Call on a dedicated worker; the OS may synchronously activate a browser association.
    pub fn open(self) -> bool {
        unsafe {
            let initialized = CoInitializeEx(
                std::ptr::null(),
                (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
            );
            if initialized < 0 {
                return false;
            }
            let result = ShellExecuteW(
                std::ptr::null_mut(),
                windows_sys::w!("open"),
                self.target.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                SW_SHOWNORMAL,
            ) as isize;
            CoUninitialize();
            result > 32
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_document_is_literal_unicode_not_a_shell_command() {
        let url = "https://example.test/日本語?q=%25PATH%25&other=$(calc)";
        let prepared = HttpOpen::prepare(url).unwrap();
        assert_eq!(
            prepared.target,
            url.encode_utf16().chain(Some(0)).collect::<Vec<_>>()
        );
        for invalid in [
            "https://example.test/?q=%PATH%",
            "file:///C:/test.exe",
            "javascript:alert(1)",
            "https://example.test/\0extra",
            "https://example.test/\nextra",
        ] {
            assert!(HttpOpen::prepare(invalid).is_none());
        }
    }
}
