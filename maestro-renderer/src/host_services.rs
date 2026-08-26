//! Platform-neutral window-service boundary for the renderer's `App`.
//!
//! `App` drives a small set of outbound window operations — request a redraw, read the surface
//! size and scale, set the cursor shape/title, raise the informational bell, and toggle IME — that
//! on macOS are winit `Window` calls and on Linux are Tao/GTK calls. This trait is the neutral seam
//! between `App` and whichever host owns the window, so `App` never names a toolkit type for these
//! services. Each platform supplies an adapter that implements this trait (winit on macOS, Tao/GTK
//! on Linux); the trait and the cursor enum here MUST stay free of any windowing-toolkit type.
//!
//! Scope note: this covers only `App`'s direct window-SERVICE calls. Surface creation still hands
//! the raw platform window to the GPU renderer, and the `Renderer`'s own internal scale-factor read
//! is handled separately (cfg-gated inside `Renderer`); neither is routed through this trait.

/// Neutral cursor shape the host maps to its toolkit's cursor. Exactly the set `App` uses today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostCursorIcon {
    Default,
    Pointer,
    Grab,
    Grabbing,
    ColResize,
    RowResize,
}

/// What the WGPU surface `App` renders into actually SPANS, relative to the React dashboard chrome. This is
/// the SINGLE source of truth for whether the terminal must reserve the sidebar width and top-bar height
/// itself:
///
/// * `FullWindowWithChrome` (macOS): the surface is the whole window; the sidebar WebView is a child laid over
///   the LEFT of the same surface, so the terminal grid MUST inset right by the sidebar width — for the draw
///   origin AND every geometry that keys off it (column count, hit-testing, cursor/selection coords, PTY resize
///   dims, mouse-report coords).
/// * `TerminalSlot` (Linux GTK host): the surface is ALREADY only the terminal slot's GTK-owned child surface —
///   React chrome is hosted by separate GTK widgets outside it. The terminal grid must NOT inset again on
///   either axis; its origin is `(0, 0)` and the whole surface belongs to the terminal. Insetting here
///   double-applies the host layout and shifts draw, input, and PTY geometry away from each other.
///
/// The renderer reads this once (via the host) and threads it through the same reservation value, so draw,
/// input, and geometry can never diverge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalSurfaceScope {
    FullWindowWithChrome,
    TerminalSlot,
}

/// Outbound window-service operations `App` performs on its host window. Implemented per platform by
/// a thin adapter over the native window handle. No method here returns or takes a toolkit type.
pub trait HostServices {
    /// Ask the host to schedule a redraw (coalesced by the host/event loop).
    fn request_redraw(&self);
    /// Current inner (client-area) size in physical pixels, as `(width, height)`.
    fn inner_size(&self) -> (u32, u32);
    /// Current display scale factor (physical pixels per logical pixel).
    fn scale_factor(&self) -> f64;
    /// Set the pointer cursor shape.
    fn set_cursor(&self, icon: HostCursorIcon);
    /// Set the window title.
    fn set_title(&self, title: &str);
    /// Raise an informational user-attention request (the terminal bell).
    fn request_attention(&self);
    /// Allow or disallow IME composition for this window.
    fn set_ime_allowed(&self, allowed: bool);
    /// Open one already-proven absolute HTTP(S) URL with the platform's fixed
    /// native opener.  The default is inert for test/non-shipping hosts.
    fn open_http_url(&self, _url: &str) -> bool {
        false
    }
    /// What the WGPU surface spans relative to React chrome. Governs whether the terminal reserves the React
    /// sidebar/top-bar insets itself (`FullWindowWithChrome`) or not (`TerminalSlot`, where the host layout
    /// already owns those bounds). macOS returns `FullWindowWithChrome`; the Linux GTK host returns
    /// `TerminalSlot`.
    fn terminal_surface_scope(&self) -> TerminalSurfaceScope;
    /// Linux/Wayland presentation guard. The native terminal is a synchronized child
    /// `wl_subsurface`; a full-window WebKit overlay may place it below the parent surface. Mesa's
    /// swapchain acquire can block the GTK owner thread while that child is occluded, so the Linux
    /// host can reject a frame before WGPU is touched. Other hosts retain the historical behavior.
    #[cfg(target_os = "linux")]
    fn try_begin_terminal_frame(&self) -> bool {
        true
    }
    /// Linux/Wayland surface-configuration guard. When the terminal child is occluded, retain only
    /// the newest nonzero allocation and apply it after the parent has committed the reveal.
    /// Other Linux backends retain the historical immediate resize behavior.
    #[cfg(target_os = "linux")]
    fn try_begin_terminal_surface_resize(&self, _width: u32, _height: u32) -> bool {
        true
    }
}

/// Spawn macOS's fixed native opener off the owner thread. No shell is involved,
/// no executable is resolved through `PATH`, and terminal-controlled URL content
/// is neither logged nor inherited as process stdio. Linux uses GIO directly in
/// its GTK host adapter instead of the shell-dispatching `xdg-open` program.
pub(crate) fn start_native_http_open(url: &str) -> bool {
    #[cfg(not(target_os = "macos"))]
    {
        let _ = url;
        return false;
    }
    #[cfg(target_os = "macos")]
    {
        let Some(mut command) = native_http_open_command(url) else {
            return false;
        };
        std::thread::Builder::new()
            .name("hydra-open-http".to_owned())
            .spawn(move || {
                let _ = command.status();
            })
            .is_ok()
    }
}

#[cfg(target_os = "macos")]
fn native_http_open_command(url: &str) -> Option<std::process::Command> {
    if !maestro_protocol::is_safe_terminal_http_url(url) {
        return None;
    }
    let mut command = std::process::Command::new("/usr/bin/open");
    use std::process::Stdio;
    command
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Some(command)
}

#[cfg(all(test, target_os = "macos"))]
mod terminal_link_opener_tests {
    use super::native_http_open_command;

    #[test]
    fn native_opener_is_absolute_shell_free_and_refuses_other_schemes() {
        let command = native_http_open_command("https://example.test/path").unwrap();
        assert_eq!(command.get_program(), "/usr/bin/open");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            vec![std::ffi::OsStr::new("https://example.test/path")]
        );
        assert!(native_http_open_command("file:///tmp/no").is_none());
        assert!(native_http_open_command("https://bad.test/\nnext").is_none());
    }
}

/// Native terminal clipboard operations supplied by the Linux GTK host. Kept separate from
/// [`HostServices`] because reads are asynchronous and menu activation returns through
/// [`HostEvent`](crate::host_event::HostEvent); macOS retains its existing synchronous arboard
/// path byte-for-byte. No GTK/GDK/Tao type crosses this boundary.
#[cfg(target_os = "linux")]
pub trait TerminalClipboardHostServices {
    /// Request text without blocking the UI. Completion returns as a typed host event carrying
    /// the same `request_id`; empty/non-text/unavailable clipboard content returns `None`.
    fn request_text(&self, request_id: u64);
    /// Claim the desktop clipboard with UTF-8 text. Returns whether a native backend accepted it.
    fn set_text(&self, text: &str) -> bool;
    /// Open the native Copy/Paste menu at the most recently recorded real right-button event.
    /// `can_copy` controls the Copy item's sensitivity. Returns false when no valid trigger exists.
    fn show_context_menu(&self, can_copy: bool) -> bool;
}

/// Outbound operations `App` performs on the dashboard WebView + its GTK sidebar container when the HOST owns
/// them (the Linux GTK DashboardHost). On macOS `App` owns the child WebView directly, so it does NOT use this
/// (it keeps its existing `react_webview` path, byte-identical); on Linux the WebView lives in
/// `LinuxDashboardHost`, so `App` delegates here instead of no-op'ing. Neutral: no `wry`/`gtk` type appears.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub trait ChromeHostServices {
    /// Run `script` in every relevant dashboard surface. Linux evaluates it in the sidebar and either
    /// evaluates or safely remembers it for the lazy overlay. `kind` is host-owned metadata; the
    /// overlay must never infer authority or lifecycle from user-controlled serialized script text.
    /// macOS keeps its direct WebView evaluation behavior and ignores the classification.
    fn evaluate_dashboard_script(&self, script: &str, kind: crate::ReactChromeScriptKind);
    /// Set the GTK sidebar container's physical width (logical px) and trigger a relayout so the terminal slot
    /// grows/shrinks into the freed/consumed space. Drives collapse/expand. `None`-op on hosts without a
    /// resizable sidebar container.
    fn set_sidebar_width(&self, width_logical_px: u32);
    /// Return keyboard/IME focus from dashboard chrome to the native terminal widget.
    fn focus_terminal(&self);
    /// Show/hide the host-owned full-window dashboard overlay. On Linux this owns GTK/WebKit stacking
    /// and focus restoration; the terminal present target remains renderer-owned and PTYs are untouched.
    fn set_overlay_visible(&self, visible: bool);
    /// Open a native folder picker (GTK FileChooserNative / portal) and relay the chosen path (or cancel) back
    /// into the dashboard via `evaluate_dashboard_script`, keyed by `request_id`. Content-blind: a path only.
    fn pick_folder(&self, request_id: &str);
}
