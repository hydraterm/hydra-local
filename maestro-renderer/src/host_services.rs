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
    /// Consume a captured ownership ticket after exact viewport publication. A newer user
    /// interaction, modal or window activation must make the ticket ineffective.
    fn finish_dialog_focus(&self, _ticket: u64) {}
    /// Show/hide the host-owned full-window dashboard overlay. On Linux this owns GTK/WebKit stacking
    /// and focus restoration; the terminal present target remains renderer-owned and PTYs are untouched.
    fn set_overlay_visible(&self, visible: bool);
    /// Open a native folder picker (GTK FileChooserNative / portal) and relay the chosen path (or cancel) back
    /// into the dashboard via `evaluate_dashboard_script`, keyed by `request_id`. Content-blind: a path only.
    fn pick_folder(&self, request_id: &str);
}

/// Window-local input ownership, not a timer or a launch-success signal.
#[cfg(any(target_os = "linux", test))]
#[derive(Default)]
pub(crate) struct DialogFocusEpoch(std::cell::Cell<u64>);

#[cfg(any(target_os = "linux", test))]
impl DialogFocusEpoch {
    pub(crate) fn changed(&self) {
        self.0.set(self.0.get().saturating_add(1));
    }

    pub(crate) fn capture(&self, dialog_owns_focus: bool) -> Option<u64> {
        (dialog_owns_focus && self.0.get() != u64::MAX).then(|| self.0.get())
    }

    pub(crate) fn capture_persistent_action(
        &self,
        json: &str,
        owns_focus: bool,
        is_sidebar: bool,
    ) -> Option<u64> {
        #[derive(serde::Deserialize)]
        struct IntentKind {
            #[serde(rename = "type")]
            kind: String,
        }
        let explicit_action = serde_json::from_str::<IntentKind>(json).is_ok_and(|intent| {
            matches!(intent.kind.as_str(), "focusWindow" | "focusSessionOrPane")
                || (is_sidebar && intent.kind == "reviveSession")
        });
        self.capture(owns_focus && explicit_action)
    }

    pub(crate) fn can_finish(&self, ticket: u64, window_active: bool, modal_visible: bool) -> bool {
        window_active && !modal_visible && self.capture(true) == Some(ticket)
    }
}

/// Finish a native modal close without letting document restoration precede native focus.
/// Dropping an overlay restores its interactivity but must not request opener focus.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn restore_dialog_underlay(
    restore_opener: bool,
    restore_native: impl FnOnce(),
    focus_opener: impl FnOnce(),
    restore_documents: impl FnOnce(bool),
) {
    restore_native();
    if restore_opener {
        focus_opener();
    }
    restore_documents(restore_opener);
}

/// One close owns one opener restoration; accepting it must not consume the launch focus epoch.
#[cfg(any(target_os = "linux", test))]
pub(crate) mod dialog_opener {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Pending {
        pub token: u64,
        pub input_epoch: u64,
        pub target: usize,
        pub generation: u64,
        pub dispatched: bool,
    }

    impl Pending {
        pub fn accept(
            &mut self,
            token: u64,
            target: usize,
            generation: u64,
            epoch: Option<u64>,
            owns_focus: bool,
        ) -> bool {
            if self.dispatched
                || self.token != token
                || self.target != target
                || self.generation != generation
                || epoch != Some(self.input_epoch)
                || !owns_focus
            {
                return false;
            }
            self.dispatched = true;
            true
        }
    }

    /// None means ordinary dashboard IPC; malformed reserved messages must never reach App.
    pub fn parse_ready(json: &str) -> Option<Result<u64, ()>> {
        let value: serde_json::Value = serde_json::from_str(json).ok()?;
        if value.get("type").and_then(serde_json::Value::as_str)
            != Some("__hydraPersistentFocusReady")
        {
            return None;
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Ready {
            #[serde(rename = "type")]
            _kind: String,
            token: String,
        }
        Some((|| {
            if json.len() > 192 {
                return Err(());
            }
            let ready: Ready = serde_json::from_value(value).map_err(|_| ())?;
            if ready.token.is_empty()
                || ready.token.starts_with('0')
                || ready.token.len() > 20
                || !ready.token.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(());
            }
            ready.token.parse().map_err(|_| ())
        })())
    }
}

/// Opt-in focus diagnostics contain only closed categories and boolean state, never page content.
#[cfg(any(target_os = "linux", test))]
pub(crate) mod dialog_focus_trace {
    pub const SNAPSHOT_FUNCTION: &str = r#"function(requested, attempted, root, saved, prior, current, focused) {
      function tag(node) {
        if (!node) return "none";
        switch (node.tagName) {
          case "BODY": return "body";
          case "BUTTON": return "button";
          case "INPUT": return "input";
          default: return "other";
        }
      }
      return {
        root_present: Boolean(root), saved_present: Boolean(saved),
        firewall_present: Boolean(window.__HYDRA_NATIVE_MODAL_UNDERLAY_FIREWALL__),
        firewall_active: Boolean(window.__HYDRA_NATIVE_MODAL_UNDERLAY_FIREWALL__ && window.__HYDRA_NATIVE_MODAL_UNDERLAY_FIREWALL__.active),
        prior_present: Boolean(prior), prior_tag: tag(prior), current_tag: tag(current),
        document_focused: Boolean(focused), current_is_prior: Boolean(prior && current === prior),
        current_unchanged: !current || current === document.body || current === root || current === prior,
        inert: Boolean(root && root.inert), prior_connected: Boolean(prior && prior.isConnected),
        prior_focusable: Boolean(prior && typeof prior.focus === "function"),
        restore_requested: Boolean(requested), attempted_focus: Boolean(attempted),
        active_is_prior_after: Boolean(prior && document.activeElement === prior)
      };
    }"#;

    pub fn saved_snapshot_script() -> String {
        format!(
            "(function () {{ var saved = window.__HYDRA_NATIVE_MODAL_UNDERLAY_STATE__; \
             return ({SNAPSHOT_FUNCTION})(false, false, document.documentElement, saved, \
             saved && saved.activeElement, document.activeElement, document.hasFocus()); }})();"
        )
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub enum Tag {
        None,
        Body,
        Button,
        Input,
        Other,
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct Snapshot {
        root_present: bool,
        saved_present: bool,
        firewall_present: bool,
        firewall_active: bool,
        prior_present: bool,
        prior_tag: Tag,
        current_tag: Tag,
        document_focused: bool,
        current_is_prior: bool,
        current_unchanged: bool,
        inert: bool,
        prior_connected: bool,
        prior_focusable: bool,
        restore_requested: bool,
        attempted_focus: bool,
        active_is_prior_after: bool,
    }

    /// Explicit field formatting ensures no raw callback payload or arbitrary string reaches logs.
    pub fn summary(json: &str) -> Option<String> {
        if json.len() > 2048 {
            return None;
        }
        let s: Snapshot = serde_json::from_str(json).ok()?;
        Some(format!(
            "root={} saved={} firewall={} firewall_active={} prior={} prior_tag={:?} current_tag={:?} \
             document_focused={} current_is_prior={} unchanged={} inert={} connected={} \
             focusable={} requested={} attempted={} active_is_prior_after={}",
            s.root_present,
            s.saved_present,
            s.firewall_present,
            s.firewall_active,
            s.prior_present,
            s.prior_tag,
            s.current_tag,
            s.document_focused,
            s.current_is_prior,
            s.current_unchanged,
            s.inert,
            s.prior_connected,
            s.prior_focusable,
            s.restore_requested,
            s.attempted_focus,
            s.active_is_prior_after,
        ))
    }
}

#[cfg(test)]
mod dialog_restore_tests {
    use super::restore_dialog_underlay;
    use std::cell::Cell;

    #[test]
    fn sidebar_revival_focus_requires_explicit_intent_and_current_native_owner() {
        let epoch = super::DialogFocusEpoch::default();
        let json = r#"{"type":"reviveSession","session_id":"fixture"}"#;
        let ticket = epoch.capture_persistent_action(json, true, true).unwrap();
        assert!(epoch.capture_persistent_action(json, false, true).is_none());
        assert!(epoch.capture_persistent_action(json, true, false).is_none());
        assert!(epoch.can_finish(ticket, true, false));
        epoch.changed();
        assert!(!epoch.can_finish(ticket, true, false));
        for json in [
            "{}",
            "not json",
            r#"{"type":"focusPane"}"#,
            r#"{"type":"reviveWindow"}"#,
            r#"{"type":"createProject"}"#,
            r#"{"type":"__hydraPersistentFocusReady","token":"1"}"#,
        ] {
            assert!(epoch.capture_persistent_action(json, true, true).is_none());
        }
    }

    #[test]
    fn persistent_navigation_requires_owned_surface_and_current_publication_epoch() {
        for sidebar in [false, true] {
            for kind in ["focusWindow", "focusSessionOrPane"] {
                let epoch = super::DialogFocusEpoch::default();
                let json = format!(r#"{{"type":"{kind}"}}"#);
                let ticket = epoch
                    .capture_persistent_action(&json, true, sidebar)
                    .unwrap();
                assert!(epoch
                    .capture_persistent_action(&json, false, sidebar)
                    .is_none());
                assert!(!epoch.can_finish(ticket, false, false), "inactive window");
                assert!(!epoch.can_finish(ticket, true, true), "new modal");
                assert!(epoch.can_finish(ticket, true, false));
                epoch.changed();
                assert!(!epoch.can_finish(ticket, true, false), "new native input");
                assert_eq!(
                    epoch.capture_persistent_action(&json, true, sidebar),
                    Some(ticket + 1)
                );
            }
        }
    }

    #[test]
    fn dialog_opener_ready_requires_exact_owned_identity_and_only_dispatches_once() {
        use super::{dialog_opener::Pending, DialogFocusEpoch};
        let epoch = DialogFocusEpoch::default();
        let ticket = epoch.capture(true).unwrap();
        let mut pending = Pending {
            token: 4,
            input_epoch: ticket,
            target: 0,
            generation: 2,
            dispatched: false,
        };
        for (token, target, generation, owner) in [
            (3, 0, 2, true),
            (4, 1, 2, true),
            (4, 0, 1, true),
            (4, 0, 2, false),
        ] {
            assert!(!pending.accept(token, target, generation, epoch.capture(true), owner));
            assert!(
                !pending.dispatched,
                "a stale ACK must not consume the current opener"
            );
        }
        assert!(pending.accept(4, 0, 2, epoch.capture(true), true));
        assert!(
            epoch.can_finish(ticket, true, false),
            "opener restore must preserve a pending Create/Split launch ticket"
        );
        assert!(!pending.accept(4, 0, 2, epoch.capture(true), true));
    }

    #[test]
    fn dialog_opener_newer_input_or_terminal_publication_revokes_old_epoch() {
        use super::{dialog_opener::Pending, DialogFocusEpoch};
        let epoch = DialogFocusEpoch::default();
        let mut pending = Pending {
            token: 4,
            input_epoch: epoch.capture(true).unwrap(),
            target: 0,
            generation: 2,
            dispatched: false,
        };
        // Native key/press, deactivation and successful terminal publication advance this epoch.
        epoch.changed();
        assert!(!pending.accept(4, 0, 2, epoch.capture(true), true));
    }

    #[test]
    fn dialog_opener_private_ack_is_closed_bounded_and_has_no_caller_selected_origin() {
        use super::dialog_opener::parse_ready;
        assert_eq!(
            parse_ready(r#"{"type":"__hydraPersistentFocusReady","token":"4"}"#),
            Some(Ok(4))
        );
        for json in [
            r#"{"type":"__hydraPersistentFocusReady","token":4}"#,
            r#"{"type":"__hydraPersistentFocusReady","token":"04"}"#,
            r#"{"type":"__hydraPersistentFocusReady","token":"0"}"#,
            r#"{"type":"__hydraPersistentFocusReady","token":"18446744073709551616"}"#,
            r#"{"type":"__hydraPersistentFocusReady","token":"4","surface":"sidebar"}"#,
            r#"{"type":"__hydraPersistentFocusReady","token":"4","generation":0}"#,
        ] {
            assert_eq!(parse_ready(json), Some(Err(())));
        }
        let oversized = format!(
            r#"{{"type":"__hydraPersistentFocusReady","token":"{}"}}"#,
            "1".repeat(193)
        );
        assert_eq!(parse_ready(&oversized), Some(Err(())));
        assert_eq!(parse_ready(r#"{"type":"openProjectDialog"}"#), None);
    }

    #[test]
    fn dialog_restore_native_focus_precedes_guarded_document_restore() {
        let interactive = Cell::new(false);
        let focused = Cell::new(false);
        let restored_opener = Cell::new(false);
        restore_dialog_underlay(
            true,
            || interactive.set(true),
            || {
                assert!(
                    interactive.get(),
                    "parent bands must reopen before native focus"
                );
                focused.set(true);
            },
            |restore_focus| {
                // The real document guard declines while document.hasFocus() is false and
                // discards its saved opener. A later native focus cannot repair that loss.
                restored_opener.set(restore_focus && focused.get());
            },
        );
        assert!(
            restored_opener.get(),
            "Cancel must not lose its DOM opener before GTK focus"
        );
    }

    #[test]
    fn dialog_restore_teardown_restores_state_without_requesting_focus() {
        let interactive = Cell::new(false);
        let restored_document = Cell::new(false);
        restore_dialog_underlay(
            false,
            || interactive.set(true),
            || panic!("teardown must not focus the old opener"),
            |restore_focus| {
                assert!(interactive.get());
                assert!(!restore_focus);
                restored_document.set(true);
            },
        );
        assert!(restored_document.get());
    }

    #[test]
    fn dialog_focus_trace_accepts_only_bounded_closed_metadata() {
        use super::dialog_focus_trace::summary;
        assert!(super::dialog_focus_trace::saved_snapshot_script().contains("saved.activeElement"));
        let valid = serde_json::json!({
            "root_present": true, "saved_present": true, "firewall_present": true,
            "firewall_active": false,
            "prior_present": true, "prior_tag": "button", "current_tag": "body",
            "document_focused": true, "current_is_prior": false, "current_unchanged": true,
            "inert": false, "prior_connected": true, "prior_focusable": true,
            "restore_requested": true, "attempted_focus": true, "active_is_prior_after": true
        });
        assert!(summary(&valid.to_string())
            .unwrap()
            .contains("prior_tag=Button"));
        assert!(summary(&valid.to_string())
            .unwrap()
            .contains("firewall_active=false"));
        for invalid in ["", "null", "[]", "{", &" ".repeat(2049)] {
            assert!(summary(invalid).is_none());
        }
        let mut unknown = valid.clone();
        unknown["value"] = serde_json::json!("must-not-be-logged");
        assert!(summary(&unknown.to_string()).is_none());
        let mut arbitrary_tag = valid.clone();
        arbitrary_tag["prior_tag"] = serde_json::json!("must-not-be-logged");
        assert!(summary(&arbitrary_tag.to_string()).is_none());
        let mut wrong_type = valid;
        wrong_type["document_focused"] = serde_json::json!("true");
        assert!(summary(&wrong_type.to_string()).is_none());
    }
}
