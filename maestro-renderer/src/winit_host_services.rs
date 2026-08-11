//! winit implementation of [`HostServices`] (macOS path).
//!
//! Wraps the `Arc<winit::window::Window>` the winit event loop owns and forwards each neutral
//! window-service call to the exact winit call `App` made before this boundary existed, with the
//! same arguments — so macOS runtime behavior is byte-identical. The cursor mapping is 1:1 with the
//! winit `CursorIcon` variants `App` used. `winit` types are confined to this adapter; the trait and
//! [`HostCursorIcon`] stay neutral.

#![cfg(not(target_os = "linux"))]

use std::sync::Arc;

use winit::window::{CursorIcon, UserAttentionType, Window};

use crate::host_services::{HostCursorIcon, HostServices};

/// winit-backed [`HostServices`], holding the same `Arc<Window>` used for surface creation.
pub struct WinitHostServices {
    window: Arc<Window>,
}

impl WinitHostServices {
    pub fn new(window: Arc<Window>) -> Self {
        Self { window }
    }
}

impl HostServices for WinitHostServices {
    fn request_redraw(&self) {
        self.window.request_redraw();
    }

    fn inner_size(&self) -> (u32, u32) {
        let s = self.window.inner_size();
        (s.width, s.height)
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

    fn terminal_surface_scope(&self) -> crate::host_services::TerminalSurfaceScope {
        // macOS renders the terminal into the FULL window surface; the sidebar WebView overlays its left, so
        // the terminal reserves the sidebar width itself. Unchanged behavior.
        crate::host_services::TerminalSurfaceScope::FullWindowWithChrome
    }
}
