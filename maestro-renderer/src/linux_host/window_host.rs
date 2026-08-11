//! The Tao/GTK top-level window hosting the React sidebar/topbar and native terminal slot.
//!
//! This owns the Linux window and event loop (winit stays the macOS path). A noninteractive GTK allocator gives
//! the WebKitGTK sidebar and terminal column exact sibling rectangles; the terminal slot's realized
//! `size_allocate` is the AUTHORITATIVE geometry the WGPU renderer follows. X11 and Wayland share this same
//! layout/policy code — only the native present-target creation (see
//! [`super::present_target`]) differs by backend.
//!
//! Lifecycle:
//! * [`LinuxDashboardHost::new`] builds the layout, mounts the dashboard WebView, realizes the top-level, and
//!   creates the terminal [`TerminalPresentTarget`]. The caller (`run_renderer` Linux entry) then reads
//!   [`present_target`](LinuxDashboardHost::present_target) + [`geometry`](LinuxDashboardHost::geometry) to
//!   build the WGPU [`Renderer`](crate::render::Renderer) and reads [`host_services`] to build the neutral
//!   [`HostServices`](crate::host_services::HostServices), attaching both to the renderer `App`.
//! * [`LinuxDashboardHost::run`] wires every GTK terminal-slot input signal + `size_allocate` to the neutral
//!   [`HostEvent`] feed (`on_event`, which is `App::handle_host_event`) and runs the Tao event loop.
//!
//! The dashboard WebView is presentation-only: it owns no terminal/PTY/daemon lifecycle. If its web process
//! dies, the bundled dashboard URL is reloaded while the WGPU terminal keeps running.

#![cfg(target_os = "linux")]

use std::cell::{Cell, RefCell};
use std::os::raw::c_int;
use std::rc::Rc;
use std::sync::{Arc, OnceLock};

use glib::translate::ToGlibPtr;
use gtk::prelude::*;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoop};
use tao::platform::unix::WindowExtUnix;
use tao::window::WindowBuilder;

use super::clipboard::GtkTerminalClipboardHost;
use super::event_bridge::{
    cursor_moved_event, host_button, host_modifiers, host_scroll, ime_commit_event,
    ime_preedit_event, key_host_event, route_terminal_key, HostEvent,
};
use super::overlay::LinuxOverlayHost;
use super::persistent_surface::{
    ChromeServing, PersistentChromeSurface, PersistentInputGate, PersistentMount,
};
use super::present_target::TerminalPresentTarget;
use super::recovery::{WebKitRecoveryEvent, WebKitSurface};
use super::sidebar_layout::SidebarLayout;
use super::wake::{
    FlushWake, HostEventSender, LinuxLoopEvent, LinuxUserEventSender, RendererRedrawWake,
};
use crate::host_services::{ChromeHostServices, HostServices, TerminalClipboardHostServices};
use crate::linux_host::chrome_services::LinuxChromeServices;
use crate::linux_host::host_services::LinuxHostServices;
use crate::{RendererEvent, UserEvent};

/// Default sidebar width in logical pixels when the caller supplies no React chrome width.
const DEFAULT_SIDEBAR_WIDTH: i32 = 420;

/// Errors constructing or running the Linux dashboard host.
#[derive(Debug)]
pub enum LinuxHostError {
    /// Xlib could not enable process-wide thread safety before GTK opened the X11 display.
    XlibThreadInit,
    /// `gtk::init` failed (no display / no GTK).
    GtkInit,
    /// Tao failed to build the top-level window or event loop.
    WindowBuild(String),
    /// Tao did not expose the GTK hierarchy wry/present-target need.
    NoGtkHierarchy,
    /// Creating the terminal present target failed.
    PresentTarget(super::present_target::PresentTargetError),
    /// The Tao owner loop's `run_return` ended with a NONZERO exit code — an abnormal end such as
    /// a display-server disconnect (tao reports 1), not a user close. Code 0 (CloseRequested /
    /// normal exit) never produces this.
    EventLoopExit(i32),
}

impl std::fmt::Display for LinuxHostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinuxHostError::XlibThreadInit => {
                write!(f, "XInitThreads failed before GTK initialization")
            }
            LinuxHostError::GtkInit => write!(f, "gtk::init failed"),
            LinuxHostError::WindowBuild(e) => write!(f, "tao window build failed: {e}"),
            LinuxHostError::NoGtkHierarchy => write!(f, "tao exposed no GTK hierarchy"),
            LinuxHostError::PresentTarget(e) => write!(f, "present target: {e}"),
            LinuxHostError::EventLoopExit(code) => {
                write!(f, "tao event loop ended abnormally with exit code {code}")
            }
        }
    }
}

/// Enable Xlib's process-wide locking before GTK/GDK can make the first Xlib call.
///
/// The Linux host passes GDK's Xlib `Display` to WGPU's Vulkan X11 surface, so GTK's
/// owner thread and the driver's presentation machinery share one Xlib/XCB event
/// connection. Xlib requires `XInitThreads` to be the first Xlib call in that process.
/// Tao also initializes Xlib for its own connection, but `LinuxDashboardHost::new`
/// historically called `gtk::init` first, which made Tao's later initialization too
/// late for GDK's connection.
///
/// Calling this on Wayland is harmless and keeps startup backend-independent. GTK work
/// remains confined to the owner thread; this only makes the shared Xlib connection safe.
fn initialize_xlib_threads() -> Result<(), LinuxHostError> {
    static INITIALIZED: OnceLock<bool> = OnceLock::new();

    #[link(name = "X11")]
    extern "C" {
        fn XInitThreads() -> c_int;
    }

    let initialized = *INITIALIZED.get_or_init(|| unsafe { XInitThreads() != 0 });
    xlib_thread_init_result(initialized)
}

fn xlib_thread_init_result(initialized: bool) -> Result<(), LinuxHostError> {
    if initialized {
        Ok(())
    } else {
        Err(LinuxHostError::XlibThreadInit)
    }
}

/// Classify the Tao `run_return` exit code: 0 (CloseRequested / normal end) is a clean return;
/// any nonzero code (e.g. 1 on display-server disconnect) propagates as an error so the caller
/// (`run_renderer_impl` → maestro-app) can report the abnormal end instead of treating it as a
/// user close. Pure so the classification is unit-testable without a display.
fn run_result_for_exit_code(exit_code: i32) -> Result<(), LinuxHostError> {
    if exit_code == 0 {
        Ok(())
    } else {
        Err(LinuxHostError::EventLoopExit(exit_code))
    }
}

/// Who owns the pixels of the GTK terminal slot when GTK asks it to draw.
///
/// Wayland gives WGPU a distinct `wl_subsurface`, so GTK may paint the dark parent fallback while
/// the child buffer catches up. X11 gives WGPU the DrawingArea's own XID; Cairo-painting that same
/// drawable would erase the last presented terminal frame. An X11 GTK expose therefore queues a
/// typed owner-loop redraw and leaves the XID's pixels exclusively to WGPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalSlotDrawPolicy {
    PaintParentFallback,
    RequestWgpuRedraw,
}

fn terminal_slot_draw_policy(display_type_name: &str) -> TerminalSlotDrawPolicy {
    if display_type_name.to_ascii_lowercase().contains("x11") {
        TerminalSlotDrawPolicy::RequestWgpuRedraw
    } else {
        TerminalSlotDrawPolicy::PaintParentFallback
    }
}

/// Canonical native geometry for the terminal present target. Width and height are physical pixels;
/// the origin remains in the GTK top-level's logical coordinate space, matching
/// [`TerminalPresentTarget::update_geometry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TerminalSlotGeometry {
    slot_x: i32,
    slot_y: i32,
    width: u32,
    height: u32,
    scale: i32,
}

/// Side effects required to move from one canonical terminal allocation to the next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TerminalGeometryTransition {
    update_present_target: bool,
    emit_scale_factor_changed: bool,
    emit_resized: bool,
}

#[derive(Default)]
struct TerminalGeometryTracker {
    last_applied: Cell<Option<TerminalSlotGeometry>>,
}

impl TerminalGeometryTracker {
    fn transition_to(&self, current: TerminalSlotGeometry) -> TerminalGeometryTransition {
        terminal_geometry_transition(self.last_applied.get(), current)
    }

    fn commit(&self, current: TerminalSlotGeometry) {
        self.last_applied.set(Some(current));
    }
}

fn terminal_geometry_transition(
    previous: Option<TerminalSlotGeometry>,
    current: TerminalSlotGeometry,
) -> TerminalGeometryTransition {
    let Some(previous) = previous else {
        return TerminalGeometryTransition {
            update_present_target: true,
            emit_scale_factor_changed: true,
            emit_resized: true,
        };
    };

    let scale_changed = previous.scale != current.scale;
    TerminalGeometryTransition {
        update_present_target: previous != current,
        emit_scale_factor_changed: scale_changed,
        // A scale transition must preserve the established ScaleFactorChanged → Resized ordering
        // even when rounding happens to leave the physical dimensions unchanged.
        emit_resized: scale_changed
            || previous.width != current.width
            || previous.height != current.height,
    }
}

impl std::error::Error for LinuxHostError {}

/// A snapshot of the terminal slot's realized geometry — the single source of truth the WGPU renderer follows.
/// Produced from the GTK terminal-slot widget's `size_allocate` + realized scale, never from Tao's top-level
/// size. All values are physical pixels except `scale`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostGeometry {
    /// Terminal slot origin X within the top-level's coordinate space (parent-surface relative).
    pub slot_x: i32,
    /// Terminal slot origin Y within the top-level's coordinate space.
    pub slot_y: i32,
    /// Terminal content width in physical pixels.
    pub width: u32,
    /// Terminal content height in physical pixels.
    pub height: u32,
    /// Authoritative buffer scale from the realized GTK terminal widget.
    pub scale: i32,
}

/// The Linux DashboardHost: owns the Tao/GTK window, the sidebar/topbar dashboard WebViews, and the terminal
/// present target. Presentation-only with respect to the terminal: it never owns terminal or PTY lifecycle —
/// it hosts the surface the existing renderer draws into and routes input/geometry to it.
pub struct LinuxDashboardHost {
    /// The Tao top-level window (owns the GTK `ApplicationWindow`). Moved into the event loop by `run`.
    window: tao::window::Window,
    /// The Tao event loop — the OWNER loop, typed over [`LinuxLoopEvent`] so both wake sources
    /// (client/bridge `UserEvent`s and GTK-signal `HostEvent`s) arrive as `Event::UserEvent` and
    /// wake GTK even while fully idle. Taken by `run`.
    event_loop: Option<EventLoop<LinuxLoopEvent>>,
    /// A proxy onto `event_loop`: cloned out through [`user_event_sender`](Self::user_event_sender)
    /// as the platform-neutral wake path for the client reader thread and the command bridge, and
    /// into [`wire_events`](Self::wire_events) as the direct GTK HostEvent transport.
    wake_proxy: tao::event_loop::EventLoopProxy<LinuxLoopEvent>,
    /// Shared level-triggered redraw gate. The client/bridge sender owns clones; the owner loop
    /// acknowledges a delivered redraw before handling it so sustained Grid/Damage traffic can
    /// never grow an unbounded Tao FIFO.
    renderer_redraw_wake: Arc<RendererRedrawWake>,
    /// The host-authoritative noninteractive allocator: `[ sidebar | terminal_column ]`.
    _root: SidebarLayout,
    /// The right vertical container: `[ topbar ; terminal_slot ]`.
    _terminal_column: gtk::Box,
    /// GTK stacking container whose base child is `_root` and whose hidden overlay child hosts the
    /// lazily-created full-window React overlay.
    _composition: gtk::Overlay,
    /// The left sidebar band that hosts the dashboard WebView.
    _sidebar: gtk::Box,
    /// Fixed-height topbar band above the terminal slot.
    _topbar: gtk::Box,
    /// The GTK terminal slot — the geometry AUTHORITY and the input target. `set_has_window(true)` so it has
    /// its own `GdkWindow` (a valid X11 child XID / cursor target).
    terminal_slot: gtk::DrawingArea,
    /// Independently recoverable persistent dashboard surfaces. Each owns its WebView and exact
    /// generation tracker; both are presentation-only and retain their GTK allocation on failure.
    sidebar_surface: Option<PersistentChromeSurface>,
    topbar_surface: Option<PersistentChromeSurface>,
    /// The neutral [`ChromeHostServices`] over the host-owned WebView + GTK sidebar. Attached to `App` so
    /// App's dashboard-script / sidebar-width / folder-pick calls delegate here. `None` if no WebView mounted.
    chrome_host: Option<Rc<dyn ChromeHostServices>>,
    /// Direct owner-loop recovery target for the lazy overlay. Also retained by `chrome_host`.
    overlay_host: Option<Rc<LinuxOverlayHost>>,
    /// Shared WRY context/process pool. Declared after the WebView/service owners so it drops last.
    _web_context: Option<Rc<RefCell<wry::WebContext>>>,
    /// The terminal IM context for composition + neutral IME commit/preedit routing.
    im_context: gtk::IMMulticontext,
    /// Native asynchronous GTK clipboard + terminal Copy/Paste menu. It owns no terminal/session
    /// state; callbacks return typed events through `wake_proxy` to the App owner loop.
    clipboard_host: Rc<GtkTerminalClipboardHost>,
    /// The native child present target (Wayland subsurface / X11 child XID) the WGPU renderer presents into.
    /// Held for the renderer's lifetime; its geometry is updated from `size_allocate`.
    present_target: Rc<TerminalPresentTarget>,
    /// Persistent GTK frame-clock acknowledgement for Wayland terminal reveals. The signal sends
    /// one generation-bound owner-loop event after parent paint; Drop disconnects it explicitly.
    terminal_reveal_frame_clock: Option<(gtk::gdk::FrameClock, glib::SignalHandlerId)>,
}

impl LinuxDashboardHost {
    /// Build the Tao/GTK top-level, mount the dashboard sidebar/topbar (from `react_chrome`, if any), realize
    /// the top-level, and create the terminal present target (Wayland subsurface / X11 child XID) positioned
    /// at the terminal slot.
    ///
    /// GTK layout, realization and `size_allocate` establish the native child geometry before
    /// WGPU creates its present target.
    pub fn new(
        window_title: &str,
        react_chrome: Option<crate::RendererReactChrome>,
        events: Option<std::sync::mpsc::Sender<RendererEvent>>,
    ) -> Result<Self, LinuxHostError> {
        // MUST precede gtk::init: GTK opens the GDK Xlib connection, which is later
        // shared with WGPU/Vulkan on X11.
        initialize_xlib_threads()?;
        eprintln!("linux-host XInitThreads completed before GTK initialization");
        gtk::init().map_err(|_| LinuxHostError::GtkInit)?;

        let sidebar_width = react_chrome
            .as_ref()
            .map(|c| c.width_logical_px as i32)
            .filter(|w| *w > 0)
            .unwrap_or(DEFAULT_SIDEBAR_WIDTH);
        let has_sidebar = react_chrome.is_some();
        // Derive the custom-protocol serving parameters from the `file://…/index.html?chrome=…` URL the caller
        // supplies. On Linux we do NOT load the page over `file://`: wry's WebKitGTK IPC handler reads
        // `webview.uri().unwrap()` (wry mod.rs:648) and a `file://` URL fails `http::Uri` parsing → panic. So we
        // serve the SAME bundled dashboard-ui assets over a `hydra://localhost/…` custom protocol whose URL
        // parses cleanly. `chrome_serving` carries the asset ROOT dir + the `hydra://` URL to load/reload.
        let chrome_serving = react_chrome
            .as_ref()
            .and_then(|c| ChromeServing::from_file_url(&c.url));
        let topbar_serving = react_chrome
            .as_ref()
            .and_then(|c| ChromeServing::from_file_url(&c.top_url))
            .filter(|topbar| {
                let shared = chrome_serving
                    .as_ref()
                    .is_some_and(|sidebar| topbar.shares_asset_root(sidebar));
                if !shared {
                    eprintln!(
                        "linux-host dashboard topbar rejected: asset root differs from sidebar"
                    );
                }
                shared
            });
        let overlay_serving = react_chrome
            .as_ref()
            .and_then(|c| ChromeServing::from_file_url(&c.overlay_url));
        let topbar_height = match react_chrome.as_ref() {
            Some(chrome) => match i32::try_from(chrome.top_height_logical_px) {
                Ok(height) if height > 0 => height,
                Ok(_) => 0,
                Err(_) => {
                    eprintln!(
                        "linux-host dashboard topbar rejected: logical height exceeds GTK range"
                    );
                    0
                }
            },
            None => 0,
        };
        let has_topbar = topbar_height > 0 && topbar_serving.is_some();
        // The sidebar registers the private scheme once. Topbar and lazy overlay are related views
        // in this same context/process pool and reuse that exact protocol handler.
        let web_context = chrome_serving
            .as_ref()
            .map(|_| Rc::new(RefCell::new(wry::WebContext::new(None))));

        // Typed over `LinuxLoopEvent`: this loop is the OWNER loop, and its proxy (below) is the
        // wake path that replaces the old non-blocking winit pump — a proxy send wakes the GLib
        // main context directly, so daemon updates and queued GTK HostEvents reach App while the
        // window is completely idle.
        let event_loop =
            tao::event_loop::EventLoopBuilder::<LinuxLoopEvent>::with_user_event().build();
        let wake_proxy = event_loop.create_proxy();
        let renderer_redraw_wake = Arc::new(RendererRedrawWake::default());
        let window = WindowBuilder::new()
            .with_title(window_title)
            .with_inner_size(tao::dpi::LogicalSize::new(1280.0, 800.0))
            .build(&event_loop)
            .map_err(|e| LinuxHostError::WindowBuild(e.to_string()))?;

        // Product composition: full-height fixed sidebar on the left; a right column with the
        // fixed logical-height topbar above the expanding terminal slot. The terminal DrawingArea
        // remains the one geometry authority. The lazy overlay covers this entire base composition.
        let terminal_column = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let composition = gtk::Overlay::new();
        let overlay_layer = gtk::EventBox::new();
        let overlay_content = gtk::Box::new(gtk::Orientation::Vertical, 0);
        overlay_layer.set_halign(gtk::Align::Fill);
        overlay_layer.set_valign(gtk::Align::Fill);
        overlay_layer.set_hexpand(true);
        overlay_layer.set_vexpand(true);
        overlay_layer.set_no_show_all(true);
        overlay_content.set_hexpand(true);
        overlay_content.set_vexpand(true);
        overlay_layer.add(&overlay_content);
        overlay_content.show();
        let sidebar = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let topbar = gtk::Box::new(gtk::Orientation::Vertical, 0);
        let terminal_slot = gtk::DrawingArea::new();
        // Allocate the proven direct sidebar/terminal children without introducing another native GdkWindow.
        // This matters on X11: the terminal DrawingArea XID must remain an immediate child of the top-level so
        // the existing top-level-relative WGPU geometry remains correct. SidebarLayout still ignores stale
        // WebKit natural requisitions and gives each child its exact rectangle.
        let root = SidebarLayout::new(
            has_sidebar.then_some(&sidebar),
            &terminal_column,
            sidebar_width as u32,
        );
        let clipboard_host = Rc::new(GtkTerminalClipboardHost::new(
            &terminal_slot.display(),
            wake_proxy.clone(),
        ));
        terminal_slot.set_has_window(true);
        sidebar.set_vexpand(true);
        root.set_hexpand(true);
        root.set_vexpand(true);
        terminal_column.set_hexpand(true);
        terminal_column.set_vexpand(true);
        topbar.set_size_request(-1, topbar_height);
        topbar.set_hexpand(true);
        topbar.set_vexpand(false);
        terminal_slot.set_hexpand(true);
        terminal_slot.set_vexpand(true);
        terminal_slot.set_can_focus(true);
        // The terminal slot is the input target: the WGPU child is input-transparent, so key/pointer/scroll/
        // focus events for the terminal must reach THIS widget.
        terminal_slot.add_events(
            gtk::gdk::EventMask::BUTTON_PRESS_MASK
                | gtk::gdk::EventMask::BUTTON_RELEASE_MASK
                | gtk::gdk::EventMask::POINTER_MOTION_MASK
                | gtk::gdk::EventMask::SCROLL_MASK
                | gtk::gdk::EventMask::SMOOTH_SCROLL_MASK
                | gtk::gdk::EventMask::KEY_PRESS_MASK
                | gtk::gdk::EventMask::KEY_RELEASE_MASK
                | gtk::gdk::EventMask::FOCUS_CHANGE_MASK
                | gtk::gdk::EventMask::LEAVE_NOTIFY_MASK,
        );

        // --- Slot background painting: avoid a white PARENT flash during a resize ---
        // When GTK grows/shrinks these slots, the WebKit (sidebar) / WGPU (terminal) child buffer can arrive
        // one compositor frame after GTK reallocates. If GTK clears the exposed parent slot to its default
        // (white) that frame flashes white. The sidebar therefore paints the dashboard canvas (#101419), and
        // Wayland paints the terminal parent with WGPU's clear color (~near-black rgb 7,8,11) while its separate
        // subsurface catches up. X11 is different: WGPU owns the DrawingArea's own XID, so GTK must leave those
        // pixels alone and request a WGPU present instead. We deliberately do NOT paint the outer/root container
        // a global color because that would leave a visible border around the child surfaces.
        terminal_slot.set_app_paintable(true);
        let terminal_draw_policy =
            terminal_slot_draw_policy(terminal_slot.display().type_().name());
        if terminal_draw_policy == TerminalSlotDrawPolicy::RequestWgpuRedraw {
            // GTK3 normally wraps a native widget's draw signal in an automatic offscreen
            // begin/end-draw frame and copies that buffer back to its GdkWindow. On X11 that
            // GdkWindow is the exact XID WGPU presents into, so even an otherwise empty Cairo
            // callback could overwrite the last terminal frame. Disable GTK double buffering for
            // this native X11-only widget before realization; Tao uses the same GTK primitive for
            // externally rendered X11 windows. Wayland deliberately keeps its normal GTK buffer
            // because WGPU owns a separate wl_subsurface there.
            unsafe {
                let terminal_widget = terminal_slot.upcast_ref::<gtk::Widget>();
                gtk::ffi::gtk_widget_set_double_buffered(terminal_widget.to_glib_none().0, 0);
            }
        }
        let terminal_draw_proxy = wake_proxy.clone();
        let terminal_present_trace =
            std::env::var("HYDRA_LINUX_PRESENT_TRACE").as_deref() == Ok("1");
        terminal_slot.connect_draw(move |_, cr| {
            match terminal_draw_policy {
                TerminalSlotDrawPolicy::PaintParentFallback => {
                    // Wayland: sRGB equivalent of the renderer's dark background / WGPU clear
                    // (rgb 7,8,11 / 255). WGPU owns a distinct wl_subsurface, so this paints only
                    // the parent exposed while the child buffer catches up.
                    cr.set_source_rgb(7.0 / 255.0, 8.0 / 255.0, 11.0 / 255.0);
                    let _ = cr.paint();
                }
                TerminalSlotDrawPolicy::RequestWgpuRedraw => {
                    // X11: WGPU presents into this DrawingArea's own XID. Cairo must never paint
                    // that drawable; doing so erases the terminal frame. Queue the real WGPU draw
                    // through the typed owner loop after GTK's expose instead. Sends during teardown
                    // are harmless because a closed event loop returns the event as an error.
                    let _ = terminal_draw_proxy
                        .send_event(LinuxLoopEvent::Host(HostEvent::RedrawRequested));
                    if terminal_present_trace {
                        eprintln!("linux-host x11 GTK draw queued WGPU redraw");
                    }
                }
            }
            // Stop GTK's default background handler on both backends. Wayland was painted above;
            // X11's pixels are intentionally left to WGPU alone.
            glib::Propagation::Stop
        });
        // WebKit bands paint a dark parent ground so a buffer swap/resize never exposes GTK white. Keep this
        // provider local to the host-owned widgets: SidebarLayout has no internal separator and must not alter
        // unrelated GTK widgets on the same screen. The terminal DrawingArea fallback above owns its pixels.
        sidebar.set_widget_name("hydra-dashboard-slot");
        topbar.set_widget_name("hydra-dashboard-topbar-slot");
        let surface_css = gtk::CssProvider::new();
        if surface_css
            .load_from_data(
                b"#hydra-dashboard-slot { background-color: #101419; }\
                  #hydra-dashboard-topbar-slot { background-color: #101116; }",
            )
            .is_ok()
        {
            sidebar
                .style_context()
                .add_provider(&surface_css, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);
            topbar
                .style_context()
                .add_provider(&surface_css, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);
        }

        if has_topbar {
            terminal_column.pack_start(&topbar, false, false, 0);
        }
        terminal_column.pack_start(&terminal_slot, true, true, 0);
        composition.add(&root);
        composition.add_overlay(&overlay_layer);
        composition.set_overlay_pass_through(&overlay_layer, false);
        window
            .default_vbox()
            .ok_or(LinuxHostError::NoGtkHierarchy)?
            .pack_start(&composition, true, true, 0);
        root.show_all();
        composition.show();

        eprintln!(
            "linux-host dashboard has_sidebar={has_sidebar} has_topbar={has_topbar} sidebar_width={sidebar_width} topbar_height={topbar_height} source_bytes={} bundled={} serve_url_bytes={}",
            react_chrome.as_ref().map(|c| c.url.len()).unwrap_or(0),
            chrome_serving.is_some(),
            chrome_serving.as_ref().map(|s| s.url.len()).unwrap_or(0),
        );
        // One native modal spans three independent WebKit documents. All persistent IPC handlers
        // and the overlay owner share this gate so accessibility actions cannot mutate the
        // sidebar/topbar behind a visible modal even if WebKit exposes a stale remote action.
        let persistent_input_gate = Rc::new(PersistentInputGate::default());
        // The sidebar is the primary view and registers the private asset protocol exactly once.
        // The topbar is a related view in the same WebContext/process pool; both use the shared
        // persistent-surface security and recovery implementation.
        let sidebar_surface = match (
            react_chrome.as_ref(),
            chrome_serving.as_ref(),
            web_context.as_ref(),
        ) {
            (Some(chrome), Some(serving), Some(context)) => Some(PersistentChromeSurface::mount(
                &sidebar,
                WebKitSurface::Sidebar,
                serving,
                chrome.initialization_script.clone(),
                context,
                PersistentMount::Primary,
                events.clone(),
                wake_proxy.clone(),
                persistent_input_gate.clone(),
            )),
            _ => None,
        };
        let sidebar_webview = sidebar_surface
            .as_ref()
            .and_then(PersistentChromeSurface::webview);
        let topbar_surface = match (
            react_chrome.as_ref(),
            topbar_serving.as_ref(),
            web_context.as_ref(),
            sidebar_webview.as_ref(),
        ) {
            (Some(chrome), Some(serving), Some(context), Some(sidebar_webview)) if has_topbar => {
                Some(PersistentChromeSurface::mount(
                    &topbar,
                    WebKitSurface::Topbar,
                    serving,
                    chrome.initialization_script.clone(),
                    context,
                    PersistentMount::Related(sidebar_webview),
                    events.clone(),
                    wake_proxy.clone(),
                    persistent_input_gate.clone(),
                ))
            }
            _ => None,
        };
        let topbar_webview = topbar_surface
            .as_ref()
            .and_then(PersistentChromeSurface::webview);

        // The terminal IM context routes composition/commit for the terminal slot.
        let im_context = gtk::IMMulticontext::new();

        // Realize the top-level so its GdkWindow (and Wayland wl_surface / X11 XID) exists before we parent the
        // present target onto it. Drain GTK so allocations settle before parenting the surface.
        window.gtk_window().show_all();
        while gtk::events_pending() {
            gtk::main_iteration_do(false);
        }
        root.queue_resize();
        while gtk::events_pending() {
            gtk::main_iteration_do(false);
        }

        // Terminal-slot geometry (AUTHORITATIVE): origin relative to the top-level, and its realized scale.
        let (slot_x, slot_y) = terminal_slot
            .translate_coordinates(window.gtk_window(), 0, 0)
            .unwrap_or((
                if has_sidebar { sidebar_width } else { 0 },
                if has_topbar { topbar_height } else { 0 },
            ));
        let scale = terminal_slot.scale_factor().max(1);

        let parent_gdk_window = window
            .gtk_window()
            .window()
            .ok_or(LinuxHostError::NoGtkHierarchy)?;
        let slot_gdk_window = terminal_slot
            .window()
            .ok_or(LinuxHostError::NoGtkHierarchy)?;

        eprintln!(
            "linux-host terminal-slot geometry slot_x={slot_x} slot_y={slot_y} scale={scale} slot_alloc={}x{} sidebar_alloc_w={}",
            terminal_slot.allocated_width(),
            terminal_slot.allocated_height(),
            sidebar.allocated_width(),
        );
        let present_target = Rc::new(
            TerminalPresentTarget::new(&slot_gdk_window, &parent_gdk_window, slot_x, slot_y, scale)
                .map_err(LinuxHostError::PresentTarget)?,
        );
        // Wayland `wl_subsurface.place_above` is synchronized parent state: issuing it does not
        // mean the compositor has observed the reveal. Keep WGPU gated until the GTK parent
        // reaches AFTER_PAINT, then send the generation through Tao so App resumes on a later
        // owner-loop turn. X11 shares this hook but its presentation gate is disabled, so it
        // never emits an event and retains the qualified immediate behavior.
        let terminal_reveal_clock = window
            .gtk_window()
            .frame_clock()
            .ok_or(LinuxHostError::NoGtkHierarchy)?;
        let reveal_target = present_target.clone();
        let reveal_proxy = wake_proxy.clone();
        let terminal_reveal_signal = terminal_reveal_clock.connect_after_paint(move |_| {
            let Some(generation) = reveal_target.parent_paint_observed() else {
                return;
            };
            let _ = reveal_proxy.send_event(LinuxLoopEvent::TerminalRevealReady { generation });
        });
        let terminal_reveal_frame_clock = Some((terminal_reveal_clock, terminal_reveal_signal));

        // Build the lazy overlay owner only after the proven terminal present target exists. The WebView is
        // NOT created here; LinuxOverlayHost creates it on the first visibility request. Its initialization
        // flag is scoped to this page so macOS's eager overlay and the Linux sidebar emit no new readiness IPC.
        let overlay_host = match (
            sidebar_webview.as_ref(),
            web_context.as_ref(),
            overlay_serving.as_ref(),
            react_chrome.as_ref(),
        ) {
            (Some(sidebar_webview), Some(context), Some(serving), Some(chrome)) => {
                let overlay_initialization_script = format!(
                    "window.__HYDRA_LAZY_OVERLAY_HOST__ = true;\n{}",
                    chrome.initialization_script
                );
                let mut underlay_containers = vec![sidebar.clone().upcast::<gtk::Widget>()];
                if topbar_webview.is_some() {
                    underlay_containers.push(topbar.clone().upcast::<gtk::Widget>());
                }
                match LinuxOverlayHost::new(
                    overlay_layer.clone(),
                    overlay_content.clone(),
                    terminal_slot.clone(),
                    window.gtk_window().clone(),
                    present_target.clone(),
                    context.clone(),
                    sidebar_webview.clone(),
                    topbar_webview.clone(),
                    underlay_containers,
                    serving.url.clone(),
                    overlay_initialization_script,
                    events.clone(),
                    wake_proxy.clone(),
                    persistent_input_gate.clone(),
                ) {
                    Ok(host) => Some(Rc::new(host)),
                    Err(err) => {
                        eprintln!(
                            "linux-host dashboard overlay unavailable; terminal remains active: {err}"
                        );
                        None
                    }
                }
            }
            _ => None,
        };

        // Build the neutral ChromeHostServices over the sidebar and optional lazy overlay. App delegates
        // script/model delivery, physical sidebar width, overlay visibility, and native folder picking here.
        let chrome_host: Option<Rc<dyn ChromeHostServices>> = sidebar_webview.as_ref().map(|wv| {
            let svc: Rc<dyn ChromeHostServices> = Rc::new(LinuxChromeServices::new(
                wv.clone(),
                topbar_webview.clone(),
                root.clone(),
                terminal_slot.clone(),
                window.gtk_window().clone(),
                overlay_host.clone(),
            ));
            svc
        });

        Ok(Self {
            window,
            event_loop: Some(event_loop),
            wake_proxy,
            renderer_redraw_wake,
            _root: root,
            _terminal_column: terminal_column,
            _composition: composition,
            _sidebar: sidebar,
            _topbar: topbar,
            terminal_slot,
            sidebar_surface,
            topbar_surface,
            chrome_host,
            overlay_host,
            _web_context: web_context,
            im_context,
            clipboard_host,
            present_target,
            terminal_reveal_frame_clock,
        })
    }

    /// The native child present target the WGPU renderer presents into. Used by the caller to build the
    /// `Renderer` via [`Renderer::new_for_linux_host`](crate::render::Renderer::new_for_linux_host).
    pub fn present_target(&self) -> &TerminalPresentTarget {
        &self.present_target
    }

    /// The current authoritative terminal-slot geometry (physical pixels + realized scale).
    pub fn geometry(&self) -> HostGeometry {
        let scale = self.terminal_slot.scale_factor().max(1);
        let (slot_x, slot_y) = self
            .terminal_slot
            .translate_coordinates(self.window.gtk_window(), 0, 0)
            .unwrap_or((0, 0));
        HostGeometry {
            slot_x,
            slot_y,
            width: (self.terminal_slot.allocated_width().max(1) * scale) as u32,
            height: (self.terminal_slot.allocated_height().max(1) * scale) as u32,
            scale,
        }
    }

    /// Build the neutral [`HostServices`] over this host's GTK terminal slot + top-level + IM context. The
    /// caller attaches it to the renderer `App` (`app.host`), so App's outbound window-service calls
    /// (redraw/size/scale/cursor/title/attention/IME) route through GTK — never a toolkit type in App.
    pub fn host_services(&self) -> Box<dyn HostServices> {
        Box::new(LinuxHostServices::new(
            self.terminal_slot.clone(),
            self.window.gtk_window().clone(),
            self.im_context.clone(),
            self.present_target.clone(),
        ))
    }

    /// The neutral [`ChromeHostServices`] over the host-owned dashboard WebView + GTK sidebar, if the WebView
    /// mounted. The caller attaches it to `App.chrome_host` so App's dashboard-script / sidebar-width /
    /// folder-pick calls delegate to the host WebView instead of no-op'ing (macOS owns its WebView directly).
    pub fn chrome_host(&self) -> Option<Rc<dyn ChromeHostServices>> {
        self.chrome_host.clone()
    }

    /// Native GTK clipboard service for App's Linux-only asynchronous paste/copy path.
    pub fn clipboard_host(&self) -> Rc<dyn TerminalClipboardHostServices> {
        self.clipboard_host.clone()
    }

    /// The platform-neutral owner-loop wake path (see [`super::wake`]): a boxed
    /// [`UserEventSender`](crate::UserEventSender) over this host's Tao proxy. `client::spawn`'s
    /// reader thread and the command bridge send through it; typed events remain exact FIFO while
    /// redundant payloadless redraws share one pending wake. The first send wakes the GLib main
    /// context directly, so the newest shared paint state reaches
    /// [`crate::App::handle_user_event`] even while the window is completely idle. Clone-fan-out
    /// via `clone_sender` shares the same redraw gate.
    pub fn user_event_sender(&self) -> Box<dyn crate::UserEventSender> {
        Box::new(LinuxUserEventSender::new(
            self.wake_proxy.clone(),
            self.renderer_redraw_wake.clone(),
        ))
    }

    /// Handle one WebKit signal on the Tao owner loop. Signal callbacks never call `load_uri`,
    /// show/hide/focus, or evaluate script for recovery; they only enqueue this typed event.
    fn handle_webkit_recovery(&self, event: WebKitRecoveryEvent) -> Option<UserEvent> {
        let surface = event.surface();
        let persistent_page_started = match &event {
            WebKitRecoveryEvent::PageStarted {
                surface: surface @ (WebKitSurface::Sidebar | WebKitSurface::Topbar),
                generation: Some(generation),
                bundled: true,
            } => Some((*surface, *generation)),
            _ => None,
        };
        let persistent_page_finished = match &event {
            WebKitRecoveryEvent::PageFinished {
                surface: surface @ (WebKitSurface::Sidebar | WebKitSurface::Topbar),
                generation: Some(generation),
                bundled: true,
            } => Some((*surface, *generation)),
            _ => None,
        };
        let persistent_failure = match &event {
            WebKitRecoveryEvent::Failure {
                surface: surface @ (WebKitSurface::Sidebar | WebKitSurface::Topbar),
                generation: Some(generation),
                ..
            } => Some((*surface, *generation)),
            _ => None,
        };
        // Invalidate before PersistentChromeSurface may dispatch `load_uri`. Waiting for the later
        // PageStarted proxy event would leave a window where an outgoing suppression callback can
        // certify the replacement process/document.
        let current_persistent_failure =
            persistent_failure.filter(|(surface, generation)| match surface {
                WebKitSurface::Sidebar => self
                    .sidebar_surface
                    .as_ref()
                    .is_some_and(|owner| owner.failure_is_current(Some(*generation))),
                WebKitSurface::Topbar => self
                    .topbar_surface
                    .as_ref()
                    .is_some_and(|owner| owner.failure_is_current(Some(*generation))),
                WebKitSurface::Overlay => false,
            });
        if let Some((surface, generation)) = current_persistent_failure {
            if let Some(overlay) = self.overlay_host.as_ref() {
                overlay.persistent_document_started(surface, generation);
            }
        }
        let result = match surface {
            WebKitSurface::Sidebar => self
                .sidebar_surface
                .as_ref()
                .and_then(|surface| surface.handle_recovery_event(event)),
            WebKitSurface::Topbar => self
                .topbar_surface
                .as_ref()
                .and_then(|surface| surface.handle_recovery_event(event)),
            WebKitSurface::Overlay => {
                if let Some(overlay) = self.overlay_host.as_ref() {
                    overlay.handle_recovery_event(event);
                }
                None
            }
        };
        if let Some((surface, generation)) = persistent_page_started {
            if let Some(overlay) = self.overlay_host.as_ref() {
                overlay.persistent_document_started(surface, generation);
            }
        }
        if let Some((surface, generation)) = persistent_page_finished.filter(|_| result.is_some()) {
            if let Some(overlay) = self.overlay_host.as_ref() {
                overlay.persistent_document_finished(surface, generation);
            }
        }
        result
    }

    /// Close every independent recovery lifecycle before the Tao loop can accept late callbacks.
    fn shut_down_webkit_recovery(&self) {
        if let Some(sidebar) = self.sidebar_surface.as_ref() {
            sidebar.shut_down_recovery();
        }
        if let Some(topbar) = self.topbar_surface.as_ref() {
            topbar.shut_down_recovery();
        }
        if let Some(overlay) = self.overlay_host.as_ref() {
            overlay.shut_down_recovery();
        }
    }

    /// Wire every terminal-slot GTK input signal + `size_allocate` to DIRECT owner-loop delivery:
    /// each emitted [`HostEvent`] is sent as [`LinuxLoopEvent::Host`] through the Tao proxy (see
    /// [`HostEventSender`]), and the loop hands it to `App::handle_host_event`. GTK signal
    /// callbacks only SEND — they never touch `App` — so the driver loop is the single `&mut App`
    /// owner. The send itself is the wake, so an event whose GTK handler returns
    /// `Propagation::Stop` (an IME-consumed keystroke: its commit/preedit arrives via the IM
    /// context, never via top-level propagation) reaches the loop on its own — there is no
    /// passive queue that could hold it awaiting unrelated activity.
    ///
    /// Keyboard/pointer/IME come from these terminal-slot signals (the WGPU child is
    /// input-transparent); `size_allocate` is the geometry authority (updates the present target
    /// + emits `ScaleFactorChanged`/`Resized`, in that order).
    // Tao returns the full owned loop event when a closed loop rejects a send. Keeping that exact
    // type is required for the typed owner-loop boundary; boxing it here would change the contract.
    #[allow(clippy::result_large_err)]
    pub fn wire_events(&self) {
        // The one direct HostEvent transport all signal closures share (via the sink Rc below).
        let host_sender = {
            let wake_proxy = self.wake_proxy.clone();
            HostEventSender::new(move |message| {
                wake_proxy
                    .send_event(message)
                    .map_err(|tao::event_loop::EventLoopClosed(returned)| returned)
            })
        };
        // Adapt the sender to the `FnMut(HostEvent)` sink shape the wiring below uses.
        let sink: Rc<RefCell<dyn FnMut(HostEvent)>> =
            Rc::new(RefCell::new(move |ev: HostEvent| host_sender.send(ev)));

        let terminal_slot = self.terminal_slot.clone();
        let im_context = self.im_context.clone();
        let clipboard_host = self.clipboard_host.clone();
        let present_target = self.present_target.clone();
        let gtk_window = self.window.gtk_window().clone();

        // Track the last modifier mask so we emit ModifiersChanged before a key event only on a real change,
        // mirroring the winit ModifiersChanged/KeyboardInput ordering the App expects.
        let last_modifiers = Rc::new(RefCell::new(crate::host_event::HostModifiers::default()));
        // GTK does not label key auto-repeat. Track hardware keycodes from press to release so
        // paste shortcuts can consume repeats without issuing repeated clipboard reads/writes.
        let pressed_keys = Rc::new(RefCell::new(std::collections::HashSet::<u16>::new()));

        // GTK does not clear an X11 urgency hint automatically when the window is activated. Clear it at the
        // top-level focus boundary so a bell raised while Hydra is in the background is acknowledged whether
        // focus returns through the terminal slot or through the dashboard WebView. This deliberately emits no
        // HostEvent: terminal focus reporting remains owned by the terminal-slot handlers below.
        gtk_window.connect_focus_in_event(|window, _| {
            window.set_urgency_hint(false);
            glib::Propagation::Proceed
        });

        // --- IME: preedit + commit → neutral HostEvent::Ime ---
        {
            let sink = sink.clone();
            im_context.connect_commit(move |_, text| {
                (sink.borrow_mut())(ime_commit_event(text));
            });
        }
        {
            let sink = sink.clone();
            let im = im_context.clone();
            im_context.connect_preedit_changed(move |_| {
                let (text, _attrs, _cursor) = im.preedit_string();
                (sink.borrow_mut())(ime_preedit_event(text.as_str()));
            });
        }

        // --- Pointer focus: clicking the terminal grabs GTK focus so keys/IME route to the slot ---
        {
            let sink = sink.clone();
            let im = im_context.clone();
            let mods = last_modifiers.clone();
            let clipboard_host = clipboard_host.clone();
            terminal_slot.connect_button_press_event(move |widget, event| {
                widget.grab_focus();
                emit_modifiers_if_changed(&sink, &mods, event.state());
                // A click can arrive without a preceding motion event (touchpad tap, restored
                // window, synthetic accessibility action). Deliver its exact position first so
                // pane hit-testing/context-menu policy never uses stale cursor coordinates.
                let (x, y) = event.position();
                (sink.borrow_mut())(cursor_moved_event(x, y, widget.scale_factor().max(1)));
                // Keep the REAL GDK right-button event (Wayland seat serial + time) inside the
                // GTK adapter. If App chooses the local menu policy, it asks this service to popup
                // with this trigger; no native event type crosses the neutral HostEvent boundary.
                if event.button() == 3 {
                    clipboard_host.record_context_trigger(event);
                }
                (sink.borrow_mut())(HostEvent::MouseInput {
                    button: host_button(event.button()),
                    pressed: true,
                });
                let _ = im;
                glib::Propagation::Proceed
            });
        }
        {
            let sink = sink.clone();
            terminal_slot.connect_button_release_event(move |_, event| {
                (sink.borrow_mut())(HostEvent::MouseInput {
                    button: host_button(event.button()),
                    pressed: false,
                });
                glib::Propagation::Proceed
            });
        }
        {
            let sink = sink.clone();
            let mods = last_modifiers.clone();
            terminal_slot.connect_motion_notify_event(move |widget, event| {
                emit_modifiers_if_changed(&sink, &mods, event.state());
                let (x, y) = event.position();
                (sink.borrow_mut())(cursor_moved_event(x, y, widget.scale_factor().max(1)));
                glib::Propagation::Proceed
            });
        }
        {
            let sink = sink.clone();
            terminal_slot.connect_leave_notify_event(move |_, _| {
                (sink.borrow_mut())(HostEvent::CursorLeft);
                glib::Propagation::Proceed
            });
        }
        {
            let sink = sink.clone();
            terminal_slot.connect_scroll_event(move |_, event| {
                (sink.borrow_mut())(HostEvent::MouseWheel {
                    delta: host_scroll(event),
                });
                glib::Propagation::Proceed
            });
        }

        // --- Focus in/out → HostEvent::Focused + IM focus routing ---
        {
            let sink = sink.clone();
            let im = im_context.clone();
            terminal_slot.connect_focus_in_event(move |_, _| {
                im.focus_in();
                (sink.borrow_mut())(HostEvent::Focused(true));
                glib::Propagation::Proceed
            });
        }
        {
            let sink = sink.clone();
            let im = im_context.clone();
            let pressed_keys = pressed_keys.clone();
            terminal_slot.connect_focus_out_event(move |_, _| {
                pressed_keys.borrow_mut().clear();
                im.focus_out();
                (sink.borrow_mut())(HostEvent::Focused(false));
                glib::Propagation::Proceed
            });
        }

        // --- Keyboard: press/release. IM gets first refusal (composition); non-composed keys become neutral
        //     key events. text/base_text come from the keyval unicode in the bridge. ---
        {
            let sink = sink.clone();
            let im = im_context.clone();
            let mods = last_modifiers.clone();
            let pressed_keys = pressed_keys.clone();
            terminal_slot.connect_key_press_event(move |_, event| {
                emit_modifiers_if_changed(&sink, &mods, event.state());
                let repeat =
                    key_press_is_repeat(&mut pressed_keys.borrow_mut(), event.hardware_keycode());
                // Let the IM context consume composition keystrokes (dead keys, CJK); it will emit `commit`
                // which we already route as HostEvent::Ime. Every terminal-owned key stops GTK propagation:
                // allowing a forwarded Left arrow to proceed makes GTK move focus into the sidebar WebView.
                let (forwarded, propagation) = route_terminal_key(
                    key_host_event(event, true, repeat),
                    im.filter_keypress(event),
                );
                if let Some(forwarded) = forwarded {
                    (sink.borrow_mut())(forwarded);
                }
                propagation
            });
        }
        {
            let sink = sink.clone();
            let im = im_context.clone();
            let pressed_keys = pressed_keys.clone();
            terminal_slot.connect_key_release_event(move |_, event| {
                key_released(&mut pressed_keys.borrow_mut(), event.hardware_keycode());
                let (forwarded, propagation) = route_terminal_key(
                    key_host_event(event, false, false),
                    im.filter_keypress(event),
                );
                if let Some(forwarded) = forwarded {
                    (sink.borrow_mut())(forwarded);
                }
                propagation
            });
        }

        // --- size_allocate: the GEOMETRY AUTHORITY. Update the present target + emit ScaleFactorChanged then
        //     Resized so the renderer reconfigures the WGPU surface to the terminal slot's physical size. ---
        {
            let sink = sink.clone();
            let present_target = present_target.clone();
            let gtk_window = gtk_window.clone();
            let geometry_tracker = TerminalGeometryTracker::default();
            terminal_slot.connect_size_allocate(move |widget, alloc| {
                let scale = widget.scale_factor().max(1);
                let (slot_x, slot_y) = widget
                    .translate_coordinates(&gtk_window, 0, 0)
                    .unwrap_or((0, 0));
                let width = (alloc.width().max(1) * scale) as u32;
                let height = (alloc.height().max(1) * scale) as u32;
                let geometry = TerminalSlotGeometry {
                    slot_x,
                    slot_y,
                    width,
                    height,
                    scale,
                };
                let transition = geometry_tracker.transition_to(geometry);
                if std::env::var("HYDRA_LINUX_GEOMETRY_TRACE").as_deref() == Ok("1") {
                    eprintln!(
                        "linux-host geometry allocation slot_x={slot_x} slot_y={slot_y} width={width} height={height} scale={scale}"
                    );
                }
                if !transition.update_present_target {
                    return;
                }
                // Reposition + rescale the native child to the slot. WGPU's next present is the child commit.
                if let Err(e) = present_target.update_geometry(slot_x, slot_y, width, height, scale)
                {
                    eprintln!("linux-host present target geometry update failed: {e}");
                    // Keep the last successfully applied geometry and retry this complete transition
                    // on the next allocation. Reconfiguring WGPU after the native target failed to
                    // move/resize would publish mismatched child and renderer geometry.
                    return;
                }
                geometry_tracker.commit(geometry);
                // Emit a scale change first (only when it actually changed) so the renderer's scale-dependent
                // metrics update before the Resized reconfigure — matching the winit event ordering.
                if transition.emit_scale_factor_changed {
                    (sink.borrow_mut())(HostEvent::ScaleFactorChanged {
                        scale: scale as f64,
                    });
                }
                if transition.emit_resized {
                    (sink.borrow_mut())(HostEvent::Resized { width, height });
                }
            });
        }

        // Kick one allocation so the first frame is sized correctly without waiting for a user resize.
        self._root.queue_resize();
        while gtk::events_pending() {
            gtk::main_iteration_do(false);
        }
        // Focus the terminal on start so keyboard input flows immediately.
        terminal_slot.grab_focus();
    }

    /// Run the Tao/GTK OWNER event loop (Linux driver). The loop owns the window and — being typed
    /// over [`LinuxLoopEvent`] — both wake paths: a proxy send wakes the blocked GLib main context
    /// and arrives here as `Event::UserEvent`, either a client/bridge `UserEvent` delivered into
    /// `app.handle_user_event` or a GTK-signal `HostEvent` delivered into `app.handle_host_event`.
    /// There is no secondary winit loop, no pump, and no passive event queue: daemon grid updates,
    /// redraws, title, bell, clipboard, and GTK input (including IME commits whose keystroke never
    /// propagated to the top level) reach App while the window is completely idle. GTK signals
    /// only SEND, so this loop is the single `&mut App` owner.
    ///
    /// RedrawRequested from Tao is unreliable for a Wayland subsurface, so App also
    /// presents inline from the Resized/size_allocate path; we still forward Tao's RedrawRequested
    /// when it fires.
    ///
    /// Runs via `run_return`, NOT tao's diverging `run` (which ends in `process::exit`): after
    /// CloseRequested this returns normally, so App (the WGPU renderer) and then the host's
    /// GTK/WebKit/present-target handles drop in order, the renderer entry returns to
    /// `maestro-app`, and its daemon ownership/retention policy runs unchanged. Proxy sends after
    /// the return see loop closure nonfatally.
    ///
    /// `app` must already have its Linux renderer + host + IME attached (see the `run_renderer`
    /// Linux entry). Blocks until the window closes.
    pub fn run(mut self, mut app: crate::App) -> Result<(), LinuxHostError> {
        use tao::platform::run_return::EventLoopExtRunReturn;

        let mut tao_event_loop = match self.event_loop.take() {
            Some(el) => el,
            None => return Ok(()),
        };
        // Ownership of the one-shot GLib flush-deadline wake (see [`FlushWake`]): armed ONLY
        // while a trailing resize/refit flush is pending, cancelled when superseded/cleared and
        // at teardown, cleared by its own callback when it fires. Shared (`Rc<RefCell>`) between
        // this loop closure and each armed timer callback — all on the GTK main thread. With
        // `run_return` the process outlives the loop, so an unowned source could otherwise
        // survive host teardown and fire against the process-global GLib context.
        let flush_wake: Rc<RefCell<FlushWake<glib::SourceId>>> =
            Rc::new(RefCell::new(FlushWake::new()));
        let cancel_source = |source: glib::SourceId| source.remove();

        // The Tao loop blocks in the GLib main context until GTK activity or a proxy wake. On each
        // pass we pump GTK (so terminal-slot signals fire and SEND their HostEvents through the
        // proxy) and hand the delivered event to App. `run_return` accepts a non-'static closure,
        // so `app` and the host (`self`) stay owned by this frame for ordered teardown below.
        let exit_code = tao_event_loop.run_return(|event, _, control_flow| {
            *control_flow = ControlFlow::Wait;
            if matches!(event, Event::LoopDestroyed) {
                // Teardown pass: nothing to deliver, and no flush source may survive the loop.
                self.shut_down_webkit_recovery();
                flush_wake.borrow_mut().cancel_armed(cancel_source);
                return;
            }
            // Tao's Linux loop executes one `gtk::main_iteration_do(blocking)` after every state
            // transition. Do not manually drain the same process-global context here: WebKit,
            // native dialogs and frame-clock sources can continuously replenish it, starving
            // Tao's event phases (including compositor responsiveness) before this callback can
            // return. Initialization still drains GTK explicitly before the owner loop starts so
            // the first terminal allocation is authoritative.
            match event {
                // A client/bridge wake delivered by the owner loop itself — Redraw/Bell/Title/
                // clipboard/RendererCommand events take effect with the window otherwise idle.
                Event::UserEvent(LinuxLoopEvent::Renderer(user_event)) => {
                    self.renderer_redraw_wake.acknowledge(&user_event);
                    app.handle_user_event(user_event);
                }
                // A GTK-signal HostEvent (input/geometry/IME), delivered directly — the send was
                // the wake, so no top-level Tao event is needed for it to arrive.
                Event::UserEvent(LinuxLoopEvent::Host(host_event)) => {
                    if app.handle_host_event(host_event) == crate::HostControl::Exit {
                        *control_flow = ControlFlow::Exit;
                    }
                }
                Event::UserEvent(LinuxLoopEvent::WebKitRecovery(recovery_event)) => {
                    if let Some(user_event) = self.handle_webkit_recovery(recovery_event) {
                        app.handle_user_event(user_event);
                    }
                }
                Event::UserEvent(LinuxLoopEvent::OverlayEvaluation(result)) => {
                    if let Some(overlay) = self.overlay_host.as_ref() {
                        overlay.handle_evaluation_result(result);
                    }
                }
                Event::UserEvent(LinuxLoopEvent::PersistentSuppression(result)) => {
                    if let Some(overlay) = self.overlay_host.as_ref() {
                        overlay.handle_persistent_suppression_result(result);
                    }
                }
                Event::UserEvent(LinuxLoopEvent::OverlayNativeAllocationReady(result)) => {
                    if let Some(overlay) = self.overlay_host.as_ref() {
                        overlay.handle_native_allocation_ready(result);
                    }
                }
                Event::UserEvent(LinuxLoopEvent::OverlayViewportReady(result)) => {
                    if let Some(overlay) = self.overlay_host.as_ref() {
                        overlay.handle_viewport_ready(result);
                    }
                }
                Event::UserEvent(LinuxLoopEvent::OverlayPresentationTimeout { token }) => {
                    if let Some(overlay) = self.overlay_host.as_ref() {
                        overlay.handle_presentation_timeout(token);
                    }
                }
                Event::UserEvent(LinuxLoopEvent::TerminalRevealReady { generation }) => {
                    if let Some(resume) = self.present_target.complete_reveal(generation) {
                        app.resume_linux_terminal_presentation(resume);
                    }
                }
                Event::RedrawRequested(_) => {
                    if app.handle_host_event(HostEvent::RedrawRequested) == crate::HostControl::Exit
                    {
                        *control_flow = ControlFlow::Exit;
                    }
                }
                Event::WindowEvent {
                    event: WindowEvent::CloseRequested,
                    ..
                } => {
                    // Shut down recovery before App/window close handling while the Tao proxy and
                    // process-global WebKit context can still emit callbacks.
                    self.shut_down_webkit_recovery();
                    if app.handle_host_event(HostEvent::CloseRequested) == crate::HostControl::Exit
                    {
                        *control_flow = ControlFlow::Exit;
                    }
                }
                _ => {}
            }
            if *control_flow == ControlFlow::Exit {
                // The loop is about to end (LoopDestroyed follows): no flush source may survive.
                self.shut_down_webkit_recovery();
                flush_wake.borrow_mut().cancel_armed(cancel_source);
                return;
            }
            // Deferred-flush tail — the Linux analogue of winit `about_to_wait`: flush any trailing
            // resize/refit work that is due NOW, and if some remains pending, sleep only until its
            // deadline. Tao's `WaitUntil` does NOT arm a GLib timer of its own (it just blocks on
            // the main context), so an otherwise silent window would oversleep the deadline; we arm
            // a ONE-SHOT GLib timeout purely to wake the loop — the flush itself runs in this tail
            // on that wake. [`FlushWake`] owns the source: kept while it still covers the deadline,
            // cancelled when superseded or when the pending work clears, self-clearing on fire.
            // This is not a heartbeat: no flush pending ⇒ no timer, plain `Wait`.
            let deadline = app.flush_deferred_and_next_deadline();
            if let Some(at) = deadline {
                *control_flow = ControlFlow::WaitUntil(at);
            }
            let fired_wake = flush_wake.clone();
            flush_wake.borrow_mut().reconcile(
                std::time::Instant::now(),
                deadline,
                move |duration| {
                    glib::timeout_add_local_once(duration, move || {
                        // The one-shot fired (GLib already removed it): clear the bookkeeping so
                        // the next pending deadline arms a fresh source. The wake itself is the
                        // point — the loop runs this tail again and flushes the due work.
                        fired_wake.borrow_mut().on_fired();
                    })
                },
                cancel_source,
            );
        });

        // Belt-and-braces: the loop exit paths above already cancelled the flush source, and this
        // is idempotent — but nothing may leave a live source behind once `run` returns.
        self.shut_down_webkit_recovery();
        flush_wake.borrow_mut().cancel_armed(cancel_source);
        // Normal teardown, in dependency order: App first (its WGPU renderer presents into the
        // host's child surface), then the host (WebView, present target, GTK/Tao window). The
        // event loop object drops last with this frame; any proxy send from a client/bridge
        // thread after that returns EventLoopClosed, which every sender treats as nonfatal.
        drop(app);
        drop(self);
        // Code 0 is the normal CloseRequested end; a nonzero code (e.g. display-server
        // disconnect) propagates so maestro-app can report the abnormal end.
        run_result_for_exit_code(exit_code)
    }
}

impl Drop for LinuxDashboardHost {
    fn drop(&mut self) {
        if let Some((clock, signal)) = self.terminal_reveal_frame_clock.take() {
            clock.disconnect(signal);
        }
        // Covers construction-success paths which fail before entering `run`; normal run-return
        // teardown already closes the same state before App/WebView destruction.
        self.shut_down_webkit_recovery();
    }
}

/// Emit a [`HostEvent::ModifiersChanged`] only when the GDK modifier mask differs from the last one seen, so the
/// App's `modifiers` field tracks the same way it does under winit's separate `ModifiersChanged` event.
fn emit_modifiers_if_changed(
    sink: &Rc<RefCell<dyn FnMut(HostEvent)>>,
    last: &Rc<RefCell<crate::host_event::HostModifiers>>,
    state: gtk::gdk::ModifierType,
) {
    let m = host_modifiers(state);
    if *last.borrow() != m {
        *last.borrow_mut() = m;
        (sink.borrow_mut())(HostEvent::ModifiersChanged(m));
    }
}

/// GTK/GDK exposes no cross-backend repeat flag. A keycode already held at the next press is an
/// auto-repeat; real release (or focus-out, which clears the whole set) makes the next press fresh.
fn key_press_is_repeat(
    pressed: &mut std::collections::HashSet<u16>,
    hardware_keycode: u16,
) -> bool {
    !pressed.insert(hardware_keycode)
}

fn key_released(pressed: &mut std::collections::HashSet<u16>, hardware_keycode: u16) {
    pressed.remove(&hardware_keycode);
}

#[cfg(test)]
mod key_repeat_tests {
    use std::collections::HashSet;

    use super::{key_press_is_repeat, key_released};

    #[test]
    fn held_key_repeats_until_release() {
        let mut pressed = HashSet::new();
        assert!(!key_press_is_repeat(&mut pressed, 55));
        assert!(key_press_is_repeat(&mut pressed, 55));
        assert!(key_press_is_repeat(&mut pressed, 55));
        key_released(&mut pressed, 55);
        assert!(!key_press_is_repeat(&mut pressed, 55));
    }

    #[test]
    fn different_keys_track_independently_and_focus_clear_resets_all() {
        let mut pressed = HashSet::new();
        assert!(!key_press_is_repeat(&mut pressed, 10));
        assert!(!key_press_is_repeat(&mut pressed, 20));
        assert!(key_press_is_repeat(&mut pressed, 10));
        pressed.clear();
        assert!(!key_press_is_repeat(&mut pressed, 10));
        assert!(!key_press_is_repeat(&mut pressed, 20));
    }
}

// ============================================================================
// Exit-code classification: the pure seam `run` uses to decide whether the Tao
// loop ended normally (CloseRequested → 0 → Ok) or abnormally (e.g. a display
// server disconnect → nonzero → EventLoopExit propagated to maestro-app).
// ============================================================================
#[cfg(test)]
mod run_result_tests {
    use super::{run_result_for_exit_code, LinuxHostError};

    #[test]
    fn zero_exit_code_is_a_clean_return() {
        assert!(run_result_for_exit_code(0).is_ok());
    }

    #[test]
    fn nonzero_exit_codes_propagate_with_the_code() {
        for code in [1, 2, -1] {
            match run_result_for_exit_code(code) {
                Err(LinuxHostError::EventLoopExit(reported)) => assert_eq!(reported, code),
                other => panic!("expected EventLoopExit({code}), got {other:?}"),
            }
        }
    }
}

#[cfg(test)]
mod xlib_thread_init_tests {
    use super::{xlib_thread_init_result, LinuxHostError};

    #[test]
    fn nonzero_xinitthreads_result_allows_toolkit_startup() {
        assert!(xlib_thread_init_result(true).is_ok());
    }

    #[test]
    fn failed_xinitthreads_result_stops_before_gtk_startup() {
        assert!(matches!(
            xlib_thread_init_result(false),
            Err(LinuxHostError::XlibThreadInit)
        ));
    }
}

#[cfg(test)]
mod terminal_slot_draw_policy_tests {
    use super::{terminal_slot_draw_policy, TerminalSlotDrawPolicy};

    #[test]
    fn x11_never_cairo_paints_the_wgpu_owned_xid() {
        for display in ["GdkX11Display", "x11", "VendorX11Backend"] {
            assert_eq!(
                terminal_slot_draw_policy(display),
                TerminalSlotDrawPolicy::RequestWgpuRedraw
            );
        }
    }

    #[test]
    fn wayland_keeps_the_parent_fallback_paint() {
        assert_eq!(
            terminal_slot_draw_policy("GdkWaylandDisplay"),
            TerminalSlotDrawPolicy::PaintParentFallback
        );
    }

    #[test]
    fn unknown_backend_fails_conservatively_to_parent_paint() {
        assert_eq!(
            terminal_slot_draw_policy("MockDisplay"),
            TerminalSlotDrawPolicy::PaintParentFallback
        );
    }
}

#[cfg(test)]
mod terminal_geometry_tests {
    use super::{
        terminal_geometry_transition, TerminalGeometryTracker, TerminalGeometryTransition,
        TerminalSlotGeometry,
    };

    const BASE: TerminalSlotGeometry = TerminalSlotGeometry {
        slot_x: 420,
        slot_y: 46,
        width: 860,
        height: 754,
        scale: 1,
    };

    #[test]
    fn first_allocation_updates_target_then_emits_scale_and_resize() {
        assert_eq!(
            terminal_geometry_transition(None, BASE),
            TerminalGeometryTransition {
                update_present_target: true,
                emit_scale_factor_changed: true,
                emit_resized: true,
            }
        );
    }

    #[test]
    fn exact_duplicate_allocation_is_a_complete_no_op() {
        assert_eq!(
            terminal_geometry_transition(Some(BASE), BASE),
            TerminalGeometryTransition {
                update_present_target: false,
                emit_scale_factor_changed: false,
                emit_resized: false,
            }
        );
    }

    #[test]
    fn origin_only_change_repositions_target_without_renderer_resize() {
        let moved = TerminalSlotGeometry {
            slot_x: BASE.slot_x + 40,
            slot_y: BASE.slot_y + 10,
            ..BASE
        };
        assert_eq!(
            terminal_geometry_transition(Some(BASE), moved),
            TerminalGeometryTransition {
                update_present_target: true,
                emit_scale_factor_changed: false,
                emit_resized: false,
            }
        );
    }

    #[test]
    fn dimension_change_updates_target_and_emits_only_resize() {
        for resized in [
            TerminalSlotGeometry {
                width: BASE.width + 100,
                ..BASE
            },
            TerminalSlotGeometry {
                height: BASE.height + 50,
                ..BASE
            },
        ] {
            assert_eq!(
                terminal_geometry_transition(Some(BASE), resized),
                TerminalGeometryTransition {
                    update_present_target: true,
                    emit_scale_factor_changed: false,
                    emit_resized: true,
                }
            );
        }
    }

    #[test]
    fn scale_change_preserves_scale_then_resize_contract_when_dimensions_match() {
        let scaled = TerminalSlotGeometry { scale: 2, ..BASE };
        assert_eq!(
            terminal_geometry_transition(Some(BASE), scaled),
            TerminalGeometryTransition {
                update_present_target: true,
                emit_scale_factor_changed: true,
                emit_resized: true,
            }
        );
    }

    #[test]
    fn failed_target_update_leaves_transition_pending_for_exact_retry() {
        let tracker = TerminalGeometryTracker::default();
        let first_attempt = tracker.transition_to(BASE);

        // Simulate `update_geometry` returning Err: no commit occurs.
        assert_eq!(tracker.transition_to(BASE), first_attempt);

        // Only a successful native update commits the canonical geometry.
        tracker.commit(BASE);
        assert_eq!(
            tracker.transition_to(BASE),
            TerminalGeometryTransition {
                update_present_target: false,
                emit_scale_factor_changed: false,
                emit_resized: false,
            }
        );
    }
}
