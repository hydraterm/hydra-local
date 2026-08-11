//! Platform-neutral windowing events the renderer's `App` consumes.
//!
//! The `App` event loop must not depend on a specific windowing toolkit. Both platforms translate their native
//! events into [`HostEvent`] through a small adapter, and `App` acts only on [`HostEvent`]:
//!
//! ```text
//!   macOS:  winit WindowEvent → WinitHostAdapter  → HostEvent → App
//!   Linux:  Tao/GTK events    → LinuxHostAdapter  → HostEvent → App
//! ```
//!
//! Rules this model encodes:
//! * It carries ONLY the semantic events `App` actually uses (below). Native events `App` ignores are dropped
//!   by the adapter, never mistranslated.
//! * No `winit`/`tao`/`gtk` type appears here, so no toolkit type leaks past the platform adapters.
//! * The macOS winit adapter must preserve the exact event ORDER and MEANING of the current winit path — this
//!   is a mechanical re-expression of `App::window_event`, not a behavior change.
//!
//! The keyboard model mirrors exactly the winit keyboard surface `App` reads today (logical key + text +
//! location + state); `physical_key`/`KeyCode` are unused by `App`, so they are intentionally absent.

/// The neutral named (non-character) keys `App` acts on. Exactly the `winit::keyboard::NamedKey` variants the
/// renderer reads today — extend only when `App` starts handling a new named key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostNamedKey {
    ArrowUp,
    ArrowDown,
    ArrowLeft,
    ArrowRight,
    Backspace,
    Enter,
    Escape,
    Space,
    Tab,
    Home,
    End,
    Insert,
    Delete,
    PageUp,
    PageDown,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
}

/// A neutral logical key: a named key, a produced character string, or an unmapped key `App` doesn't act on.
/// Mirrors `winit::keyboard::Key` for the subset the renderer uses (`Named` + `Character`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostKey {
    Named(HostNamedKey),
    Character(String),
    /// A key the renderer does not special-case (still may carry `text` for PTY encoding).
    Other,
}

/// Neutral keyboard modifier state (the four the renderer checks). Mirrors `winit`'s `ModifiersState` reads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HostModifiers {
    pub control: bool,
    pub alt: bool,
    pub shift: bool,
    pub super_key: bool,
}

/// Neutral key location (winit `KeyLocation`): only Standard vs Numpad matters to the renderer's encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKeyLocation {
    Standard,
    Numpad,
    // The neutral event contract also represents the locations emitted by macOS/winit. GDK folds
    // these into `Standard`, so the variants are intentionally not constructed on Linux.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    Left,
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    Right,
}

/// A neutral key event: the renderer acts on key-DOWN, reads the logical key, any produced `text`, and location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyEvent {
    pub key: HostKey,
    /// The text this key produces, if any (used for PTY encoding of printable input).
    pub text: Option<String>,
    /// The text the key produces with NO modifiers applied — winit's `key_without_modifiers()` on macOS.
    /// This is what recovers `b` from Option-b (whose `text` is the composed glyph `∫`) so Alt-as-Meta
    /// ESC-prefixes the intended base key. `None` when the platform cannot supply it (Alt-as-Meta then
    /// falls through to the OS text path, matching prior behavior). Kept OUT of the `key` field because
    /// `key` mirrors the composed logical key exactly.
    pub base_text: Option<String>,
    pub location: HostKeyLocation,
    pub pressed: bool,
    pub repeat: bool,
}

/// Neutral pointer buttons the renderer distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPointerButton {
    Left,
    Middle,
    Right,
    Other,
}

/// Neutral scroll delta (winit `MouseScrollDelta`): line-based or pixel-based.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HostScrollDelta {
    Lines { x: f32, y: f32 },
    Pixels { x: f64, y: f64 },
}

/// Neutral IME event. The renderer only acts on `Commit`; preedit/enable/disable are display-only no-ops today
/// but are represented so the adapter never silently drops them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostIme {
    Commit(String),
    Preedit(String),
    // GTK supplies commit/preedit callbacks but no enabled/disabled callbacks. Keep the neutral
    // contract aligned with winit without treating the Linux adapter's smaller surface as dead code.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    Enabled,
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    Disabled,
}

/// Clipboard events that must return from an asynchronous native host operation to the
/// renderer owner loop. Text never crosses the dashboard IPC boundary: GTK delivers it
/// directly to `App`, which applies the existing paste sanitizer and writes to the PTY.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(target_os = "linux")]
pub enum HostClipboardEvent {
    /// Result of one native clipboard text request. `None` means empty/non-text/unavailable.
    Text {
        request_id: u64,
        text: Option<String>,
    },
    /// The native terminal context menu's Copy item was activated.
    CopyRequested,
    /// The native terminal context menu's Paste item was activated.
    PasteRequested,
    /// The native menu closed (activation, Escape, or click-away). The App retains its right-release
    /// guard until a matching terminal release or a later right press, preventing a TUI orphan release.
    ContextMenuClosed,
}

/// The platform-neutral event set the renderer's `App` handles. One variant per semantic event `App` acts on
/// today (mapped 1:1 from the current winit `WindowEvent` arms). Physical pixels unless noted.
#[derive(Debug, Clone, PartialEq)]
pub enum HostEvent {
    /// The window/terminal surface was resized to (width, height) physical pixels.
    Resized { width: u32, height: u32 },
    /// The DPI/buffer scale changed.
    ScaleFactorChanged { scale: f64 },
    /// A repaint was requested.
    RedrawRequested,
    /// The window was asked to close.
    CloseRequested,
    /// Keyboard focus entered (`true`) or left (`false`) the window.
    Focused(bool),
    /// A keyboard key event.
    Keyboard(HostKeyEvent),
    /// Modifier state changed.
    ModifiersChanged(HostModifiers),
    /// An IME event.
    Ime(HostIme),
    /// An asynchronous native clipboard result or terminal context-menu action.
    #[cfg(target_os = "linux")]
    Clipboard(HostClipboardEvent),
    /// Pointer moved to (x, y) physical pixels.
    CursorMoved { x: f64, y: f64 },
    /// Pointer left the window.
    CursorLeft,
    /// A pointer button changed.
    MouseInput {
        button: HostPointerButton,
        pressed: bool,
    },
    /// Scroll wheel / touchpad scroll.
    MouseWheel { delta: HostScrollDelta },
}
