//! winit implementation of [`HostServices`] (macOS path).
//!
//! Wraps the `Arc<winit::window::Window>` the winit event loop owns and forwards each neutral
//! window-service call to the exact winit call `App` made before this boundary existed, with the
//! same arguments — so macOS runtime behavior is byte-identical. The cursor mapping is 1:1 with the
//! winit `CursorIcon` variants `App` used. `winit` types are confined to this adapter; the trait and
//! [`HostCursorIcon`] stay neutral.

#![cfg(not(target_os = "linux"))]

#[cfg(target_os = "windows")]
use std::cell::Cell;
use std::sync::Arc;

use winit::window::{CursorIcon, UserAttentionType, Window};

use crate::host_services::{HostCursorIcon, HostServices};

/// winit-backed [`HostServices`], holding the same `Arc<Window>` used for surface creation.
pub struct WinitHostServices {
    window: Arc<Window>,
    #[cfg(target_os = "windows")]
    last_visible_size: Cell<(u32, u32)>,
}

impl WinitHostServices {
    pub fn new(window: Arc<Window>) -> Self {
        Self {
            #[cfg(target_os = "windows")]
            last_visible_size: Cell::new(window.inner_size().into()),
            window,
        }
    }
}

// Windows reports a zero client area on minimize. That is visibility, not a request to
// shrink every retained ConPTY to one cell (which destroys its visible buffer contents).
#[cfg(any(target_os = "windows", test))]
fn retained_window_size(previous: (u32, u32), observed: (u32, u32)) -> (u32, u32) {
    if observed.0 == 0 || observed.1 == 0 {
        previous
    } else {
        observed
    }
}

impl HostServices for WinitHostServices {
    fn request_redraw(&self) {
        self.window.request_redraw();
    }

    fn inner_size(&self) -> (u32, u32) {
        let s = self.window.inner_size();
        #[cfg(target_os = "windows")]
        {
            let size = retained_window_size(self.last_visible_size.get(), (s.width, s.height));
            self.last_visible_size.set(size);
            size
        }
        #[cfg(not(target_os = "windows"))]
        {
            (s.width, s.height)
        }
    }

    fn scale_factor(&self) -> f64 {
        self.window.scale_factor()
    }

    fn set_cursor(&self, icon: HostCursorIcon) {
        self.window.set_cursor(match icon {
            HostCursorIcon::Default => CursorIcon::Default,
            HostCursorIcon::Pointer => CursorIcon::Pointer,
            HostCursorIcon::Grab => CursorIcon::Grab,
            HostCursorIcon::Grabbing => CursorIcon::Grabbing,
            HostCursorIcon::ColResize => CursorIcon::ColResize,
            HostCursorIcon::RowResize => CursorIcon::RowResize,
        });
    }

    fn set_title(&self, title: &str) {
        self.window.set_title(title);
    }

    fn request_attention(&self) {
        self.window
            .request_user_attention(Some(UserAttentionType::Informational));
    }

    fn set_ime_allowed(&self, allowed: bool) {
        self.window.set_ime_allowed(allowed);
    }

    fn open_http_url(&self, url: &str) -> bool {
        crate::host_services::start_native_http_open(url)
    }

    fn terminal_surface_scope(&self) -> crate::host_services::TerminalSurfaceScope {
        // macOS renders the terminal into the FULL window surface; the sidebar WebView overlays its left, so
        // the terminal reserves the sidebar width itself. Unchanged behavior.
        crate::host_services::TerminalSurfaceScope::FullWindowWithChrome
    }
}

#[cfg(test)]
mod tests {
    use super::retained_window_size;

    #[test]
    fn minimized_client_area_preserves_geometry_until_real_restore() {
        let visible = (1900, 1300);
        for minimized in [(0, 0), (1900, 0), (0, 1300)] {
            assert_eq!(retained_window_size(visible, minimized), visible);
        }
        assert_eq!(retained_window_size(visible, (3840, 2000)), (3840, 2000));
        assert_eq!(retained_window_size(visible, (1, 1)), (1, 1));
    }
}
