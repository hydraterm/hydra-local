//! Tao/GTK implementation of [`HostServices`](crate::host_services::HostServices) (Linux path).
//!
//! The macOS adapter (`winit_host_services.rs`) wraps the winit `Window`. On Linux the window is owned by the
//! Tao/GTK [`LinuxDashboardHost`](super::window_host::LinuxDashboardHost), and the GEOMETRY AUTHORITY is the
//! realized GTK terminal-slot widget — NOT Tao's top-level. So this adapter forwards each neutral
//! window-service call to the matching GTK call on the terminal slot / top-level window:
//!
//! * `request_redraw`   → `queue_draw()` on the terminal slot (coalesced by GTK's frame clock).
//! * `inner_size`       → the terminal slot's realized allocation × its scale factor (physical pixels).
//! * `scale_factor`     → the terminal slot's realized GTK scale factor (the buffer-scale authority).
//! * `set_cursor`       → a `gdk::Cursor` on the terminal slot's `GdkWindow`.
//! * `set_title`        → the top-level `gtk::ApplicationWindow` title.
//! * `request_attention`→ the top-level window urgency hint (the GTK equivalent of the bell attention).
//! * `set_ime_allowed`  → focus in/out the terminal slot's GTK IM context (best-effort composition toggle).
//!
//! GTK objects are `glib::Object` handles (reference-counted, cheap to clone, `!Send`) so the host clones the
//! terminal slot, the top-level window, and the IM context into here; App runs on the GTK main thread, so the
//! `!Send` handles never cross a thread. No `gtk`/`tao` type leaks past this module — App consumes only the
//! neutral [`HostCursorIcon`](crate::host_services::HostCursorIcon) / trait.

#![cfg(target_os = "linux")]

use std::cell::RefCell;

use gtk::gdk;
use gtk::prelude::*;

use crate::host_services::{HostCursorIcon, HostServices};
use crate::linux_host::present_target::TerminalPresentTarget;
use std::rc::Rc;

/// GTK-backed [`HostServices`]. Holds the realized terminal-slot widget (geometry + cursor authority), the
/// top-level window (title + urgency), and the terminal IM context (composition toggle). All are cheap,
/// reference-counted GTK handles cloned from the [`LinuxDashboardHost`](super::window_host::LinuxDashboardHost).
pub struct LinuxHostServices {
    /// The GTK terminal-slot widget — the single geometry/scale AUTHORITY and the cursor/redraw target.
    terminal_slot: gtk::DrawingArea,
    /// The Tao top-level's GTK window, used for title and urgency (attention) only.
    top_level: gtk::ApplicationWindow,
    /// The terminal slot's IM context; `set_ime_allowed` focuses it in/out (best-effort GTK composition toggle).
    im_context: gtk::IMMulticontext,
    /// Remembers the last cursor icon so a redundant `set_cursor` does not rebuild a `gdk::Cursor` every frame.
    last_cursor: RefCell<Option<HostCursorIcon>>,
    /// Shared native presentation gate. On Wayland it prevents WGPU acquire/configure while the
    /// terminal child is below the parent overlay; on X11 it is an always-open no-op.
    present_target: Rc<TerminalPresentTarget>,
}

impl LinuxHostServices {
    pub fn new(
        terminal_slot: gtk::DrawingArea,
        top_level: gtk::ApplicationWindow,
        im_context: gtk::IMMulticontext,
        present_target: Rc<TerminalPresentTarget>,
    ) -> Self {
        Self {
            terminal_slot,
            top_level,
            im_context,
            last_cursor: RefCell::new(None),
            present_target,
        }
    }

    /// Map a neutral [`HostCursorIcon`] to a GDK cursor NAME (CSS cursor names GTK understands on both X11 and
    /// Wayland). 1:1 with the winit `CursorIcon` variants the winit adapter maps.
    fn gdk_cursor_name(icon: HostCursorIcon) -> &'static str {
        match icon {
            HostCursorIcon::Default => "default",
            HostCursorIcon::Pointer => "pointer",
            HostCursorIcon::Grab => "grab",
            HostCursorIcon::Grabbing => "grabbing",
            HostCursorIcon::ColResize => "col-resize",
            HostCursorIcon::RowResize => "row-resize",
        }
    }
}

impl HostServices for LinuxHostServices {
    fn request_redraw(&self) {
        // GTK coalesces queued draws through its frame clock, matching winit's `request_redraw` coalescing.
        self.terminal_slot.queue_draw();
    }

    fn inner_size(&self) -> (u32, u32) {
        // GEOMETRY AUTHORITY: the terminal slot's realized allocation (logical) × its GTK scale = physical
        // pixels, exactly what the WGPU surface is configured to. Never Tao's top-level size.
        let scale = self.terminal_slot.scale_factor().max(1) as u32;
        let w = (self.terminal_slot.allocated_width().max(0) as u32) * scale;
        let h = (self.terminal_slot.allocated_height().max(0) as u32) * scale;
        (w.max(1), h.max(1))
    }

    fn scale_factor(&self) -> f64 {
        // The realized GTK terminal-widget scale is the buffer-scale authority (Wayland/X11 alike).
        self.terminal_slot.scale_factor().max(1) as f64
    }

    fn set_cursor(&self, icon: HostCursorIcon) {
        if *self.last_cursor.borrow() == Some(icon) {
            return;
        }
        // The terminal slot has its own GdkWindow (it is `set_has_window(true)`), so the cursor applies to the
        // terminal region only. If the slot is not yet realized we log rather than silently drop.
        let Some(gdk_window) = self.terminal_slot.window() else {
            eprintln!("linux-host set_cursor skipped: terminal slot has no realized GdkWindow yet");
            return;
        };
        let display = gdk_window.display();
        let name = Self::gdk_cursor_name(icon);
        match gdk::Cursor::from_name(&display, name) {
            Some(cursor) => {
                gdk_window.set_cursor(Some(&cursor));
                *self.last_cursor.borrow_mut() = Some(icon);
            }
            None => eprintln!("linux-host set_cursor: GDK has no cursor named {name:?}"),
        }
    }

    fn set_title(&self, title: &str) {
        self.top_level.set_title(title);
    }

    fn request_attention(&self) {
        // GTK urgency hint is the terminal-bell attention equivalent (winit's Informational UserAttention).
        // Match winit's contract: a request while Hydra already owns focus has no effect. Without this guard,
        // GTK/X11 can leave WM_HINTS urgent until a focus transition that may never occur.
        if !self.top_level.is_active() {
            self.top_level.set_urgency_hint(true);
        }
    }

    fn set_ime_allowed(&self, allowed: bool) {
        // Best-effort GTK composition toggle: focus the terminal IM context in/out. GTK has no exact analogue
        // of winit's `set_ime_allowed`; focus in/out is the documented way to start/stop composition routing.
        if allowed {
            self.im_context.focus_in();
        } else {
            self.im_context.focus_out();
        }
    }

    fn terminal_surface_scope(&self) -> crate::host_services::TerminalSurfaceScope {
        // The Linux GTK host's WGPU surface is the terminal SLOT's own GTK-owned child surface; the sidebar is
        // a separate GTK widget outside it. So the terminal must NOT reserve the sidebar width again — grid
        // origin 0, full surface is the terminal. This is what fixes the ~sidebar-width right-shift of the grid.
        crate::host_services::TerminalSurfaceScope::TerminalSlot
    }

    fn try_begin_terminal_frame(&self) -> bool {
        self.present_target.try_begin_frame()
    }

    fn try_begin_terminal_surface_resize(&self, width: u32, height: u32) -> bool {
        self.present_target.try_begin_surface_resize(width, height)
    }
}
