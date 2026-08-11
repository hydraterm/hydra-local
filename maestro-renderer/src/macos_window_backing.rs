//! Opaque AppKit backing beneath macOS's full-window WGPU surface.
//!
//! WGPU replaces winit's content-view layer with a `CAMetalLayer`. During a live width resize,
//! AppKit can expose newly allocated content pixels before the next Metal drawable is presented.
//! `NSWindow` otherwise supplies its dynamic system background there, which is light in the default
//! appearance. The backing is not a terminal geometry or presentation owner; it is only the final
//! opaque fill under the WGPU layer and child WKWebViews.

use crate::theme::{self, RendererTheme};
use objc2_app_kit::{NSColor, NSView};
use std::fmt;
use wgpu::rwh::{HasWindowHandle, RawWindowHandle};
use winit::window::Window;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ApplyError {
    WindowHandleUnavailable,
    UnexpectedWindowHandle,
    DetachedContentView,
}

impl fmt::Display for ApplyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::WindowHandleUnavailable => "native window handle unavailable",
            Self::UnexpectedWindowHandle => "native window handle is not AppKit",
            Self::DetachedContentView => "AppKit content view is detached from its NSWindow",
        };
        formatter.write_str(message)
    }
}

fn backing_rgba(selected_theme: Option<RendererTheme>) -> [u8; 4] {
    let palette = selected_theme.map_or_else(theme::default_palette, theme::palette);
    let [red, green, blue] = palette.background;
    [red, green, blue, u8::MAX]
}

/// Apply the active terminal theme's opaque background to the native parent beneath WGPU.
///
/// This must run on AppKit's main thread. Both call sites are in winit's owner-loop callbacks
/// (`ApplicationHandler::resumed` and the live-theme `UserEvent` handler), so the raw `NSView`
/// supplied by winit remains alive and main-thread confined for the full call.
pub(crate) fn apply(
    window: &Window,
    selected_theme: Option<RendererTheme>,
) -> Result<(), ApplyError> {
    let handle = window
        .window_handle()
        .map_err(|_| ApplyError::WindowHandleUnavailable)?;
    let RawWindowHandle::AppKit(handle) = handle.as_raw() else {
        return Err(ApplyError::UnexpectedWindowHandle);
    };

    // SAFETY: raw-window-handle's AppKit contract identifies this pointer as the live NSView owned
    // by `window`. The caller runs on winit's AppKit main thread and keeps `window` borrowed until
    // every Objective-C message below has returned.
    let content_view = unsafe { handle.ns_view.cast::<NSView>().as_ref() };
    let native_window = content_view
        .window()
        .ok_or(ApplyError::DetachedContentView)?;
    let [red, green, blue, alpha] = backing_rgba(selected_theme);
    let color = NSColor::colorWithSRGBRed_green_blue_alpha(
        f64::from(red) / 255.0,
        f64::from(green) / 255.0,
        f64::from(blue) / 255.0,
        f64::from(alpha) / 255.0,
    );

    native_window.setOpaque(true);
    native_window.setBackgroundColor(Some(&color));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::backing_rgba;
    use crate::theme::{self, RendererTheme};

    #[test]
    fn backing_is_opaque_and_matches_every_terminal_theme() {
        for selected_theme in [
            None,
            Some(RendererTheme::BuiltInDark),
            Some(RendererTheme::HighContrastDark),
        ] {
            let rgba = backing_rgba(selected_theme);
            let expected = selected_theme.map_or_else(theme::default_palette, theme::palette);
            assert_eq!(&rgba[..3], expected.background.as_slice());
            assert_eq!(rgba[3], u8::MAX);
        }
    }

    #[test]
    fn built_in_backing_never_falls_back_to_the_appkit_light_default() {
        assert_eq!(backing_rgba(None), [0x05, 0x06, 0x07, 0xff]);
        assert_eq!(
            backing_rgba(Some(RendererTheme::HighContrastDark)),
            [0x00, 0x00, 0x00, 0xff]
        );
    }
}
