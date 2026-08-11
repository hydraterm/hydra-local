//! The native present target for the terminal slot: what the EXISTING WGPU renderer presents into on Linux.
//!
//! WGPU must never present into the top-level surface WebKit draws on. Instead we give WGPU a GTK-owned CHILD
//! surface positioned in the terminal slot of the horizontal GTK layout:
//!
//!   * **Wayland** → an input-transparent `wl_subsurface` of the Tao top-level's `wl_surface`, created via raw
//!     libwayland against GDK's own `wl_display`. Its input region is empty so pointer/keyboard fall through to
//!     the GTK terminal slot and Hydra's normal Rust input pipeline.
//!   * **X11** → a GTK-owned child window (child XID) beneath the terminal slot.
//!
//! Either way this yields a `raw-window-handle` pair that WGPU's `create_surface_unsafe` accepts (see
//! `Renderer::new_for_linux_host`). Buffer scale is applied from the realized GTK terminal-slot widget (the
//! authority), never from Tao's reported window scale.
//!
//! The Wayland FFI binds `wl_compositor`/`wl_subcompositor` from GDK's registry, creates a child
//! `wl_surface`, makes it a subsurface, sets an empty input region, desynchronizes and positions it,
//! and applies `set_buffer_scale`. It runs on GDK's OWN `wl_display` (no second Rust event queue).

use gtk::prelude::*;
use raw_window_handle::{
    RawDisplayHandle, RawWindowHandle, WaylandDisplayHandle, WaylandWindowHandle,
    XlibDisplayHandle, XlibWindowHandle,
};
use std::{cell::Cell, ffi::c_void, ptr::NonNull};

use glib::translate::ToGlibPtr;
use wayland_sys::{
    client::{wayland_client_handle, wl_display, wl_proxy},
    common::{wl_argument, wl_interface},
    ffi_dispatch,
};

/// Errors creating or updating the terminal present target.
#[derive(Debug)]
pub enum PresentTargetError {
    /// GDK returned a null `wl_display`/`wl_surface` (Wayland) or a null display/XID (X11).
    NullNativeHandle(&'static str),
    /// The core `wl_compositor`/`wl_subcompositor` (Wayland) global was not advertised.
    MissingWaylandGlobal(&'static str),
    /// The active GDK backend is neither Wayland nor X11 (unsupported).
    UnsupportedBackend(String),
    /// A raw libwayland / GDK FFI call returned a failure.
    NativeCall(&'static str),
}

impl std::fmt::Display for PresentTargetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PresentTargetError::NullNativeHandle(w) => write!(f, "null native handle: {w}"),
            PresentTargetError::MissingWaylandGlobal(g) => write!(f, "missing wayland global: {g}"),
            PresentTargetError::UnsupportedBackend(b) => write!(f, "unsupported GDK backend: {b}"),
            PresentTargetError::NativeCall(c) => write!(f, "native call failed: {c}"),
        }
    }
}

impl std::error::Error for PresentTargetError {}

// ---- core wayland.xml opcodes (stable, never renumbered) ----
const WL_REGISTRY_BIND: u32 = 0;
const WL_COMPOSITOR_CREATE_SURFACE: u32 = 0;
const WL_COMPOSITOR_CREATE_REGION: u32 = 1;
const WL_SUBCOMPOSITOR_DESTROY: u32 = 0;
const WL_SUBCOMPOSITOR_GET_SUBSURFACE: u32 = 1;
const WL_SUBSURFACE_DESTROY: u32 = 0;
const WL_SUBSURFACE_SET_POSITION: u32 = 1;
const WL_SUBSURFACE_PLACE_ABOVE: u32 = 2;
const WL_SUBSURFACE_PLACE_BELOW: u32 = 3;
const WL_SUBSURFACE_SET_DESYNC: u32 = 5;
const WL_SURFACE_DESTROY: u32 = 0;
const WL_SURFACE_SET_INPUT_REGION: u32 = 5;
const WL_SURFACE_COMMIT: u32 = 6;
const WL_SURFACE_SET_BUFFER_SCALE: u32 = 8;
const WL_REGION_DESTROY: u32 = 0;
const WL_DISPLAY_GET_REGISTRY: u32 = 1;

// Interface statics are C globals in libwayland-client.so. wayland-sys's `dlopen` feature loads libwayland's
// FUNCTIONS at runtime but not these DATA symbols, so we link libwayland-client directly (GTK already loads it).
#[link(name = "wayland-client")]
extern "C" {
    static wl_registry_interface: wl_interface;
    static wl_compositor_interface: wl_interface;
    static wl_subcompositor_interface: wl_interface;
    static wl_surface_interface: wl_interface;
    static wl_subsurface_interface: wl_interface;
    static wl_region_interface: wl_interface;
}

#[derive(Default)]
struct Globals {
    compositor_name: Option<u32>,
    compositor_version: u32,
    subcompositor_name: Option<u32>,
    subcompositor_version: u32,
}

unsafe extern "C" fn registry_global(
    data: *mut c_void,
    _registry: *mut wl_proxy,
    name: u32,
    interface: *const std::os::raw::c_char,
    version: u32,
) {
    if data.is_null() || interface.is_null() {
        return;
    }
    let globals = &mut *(data as *mut Globals);
    let iface = std::ffi::CStr::from_ptr(interface);
    match iface.to_bytes() {
        b"wl_compositor" => {
            globals.compositor_name = Some(name);
            globals.compositor_version = version;
        }
        b"wl_subcompositor" => {
            globals.subcompositor_name = Some(name);
            globals.subcompositor_version = version;
        }
        _ => {}
    }
}
unsafe extern "C" fn registry_global_remove(_d: *mut c_void, _r: *mut wl_proxy, _n: u32) {}

#[repr(C)]
struct RegistryListener {
    global: unsafe extern "C" fn(*mut c_void, *mut wl_proxy, u32, *const std::os::raw::c_char, u32),
    global_remove: unsafe extern "C" fn(*mut c_void, *mut wl_proxy, u32),
}

/// Whether releasing a client proxy also requires its protocol-level destructor request. Core
/// globals such as `wl_registry` and `wl_compositor` have only client-side proxy destruction;
/// objects such as `wl_subcompositor`, `wl_surface`, `wl_subsurface`, and `wl_region` define an
/// explicit destroy request which must be sent before the local proxy storage is released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProxyCleanup {
    LocalOnly,
    ProtocolDestroy(u32),
}

const REGISTRY_PROXY_CLEANUP: ProxyCleanup = ProxyCleanup::LocalOnly;
const COMPOSITOR_PROXY_CLEANUP: ProxyCleanup = ProxyCleanup::LocalOnly;
const SUBCOMPOSITOR_PROXY_CLEANUP: ProxyCleanup =
    ProxyCleanup::ProtocolDestroy(WL_SUBCOMPOSITOR_DESTROY);
const SURFACE_PROXY_CLEANUP: ProxyCleanup = ProxyCleanup::ProtocolDestroy(WL_SURFACE_DESTROY);
const SUBSURFACE_PROXY_CLEANUP: ProxyCleanup = ProxyCleanup::ProtocolDestroy(WL_SUBSURFACE_DESTROY);
const REGION_PROXY_CLEANUP: ProxyCleanup = ProxyCleanup::ProtocolDestroy(WL_REGION_DESTROY);

/// One owned libwayland client proxy. Drop always releases local proxy storage and, for protocol
/// objects with a destructor request, first tells the compositor to release the server-side object.
struct OwnedWaylandProxy {
    proxy: NonNull<wl_proxy>,
    cleanup: ProxyCleanup,
}

impl OwnedWaylandProxy {
    unsafe fn from_raw(proxy: *mut wl_proxy, cleanup: ProxyCleanup) -> Option<Self> {
        Some(Self {
            proxy: NonNull::new(proxy)?,
            cleanup,
        })
    }

    fn as_ptr(&self) -> *mut wl_proxy {
        self.proxy.as_ptr()
    }
}

impl Drop for OwnedWaylandProxy {
    fn drop(&mut self) {
        unsafe {
            if let ProxyCleanup::ProtocolDestroy(opcode) = self.cleanup {
                ffi_dispatch!(
                    wayland_client_handle(),
                    wl_proxy_marshal,
                    self.proxy.as_ptr(),
                    opcode
                );
            }
            ffi_dispatch!(
                wayland_client_handle(),
                wl_proxy_destroy,
                self.proxy.as_ptr()
            );
        }
    }
}

/// A registry listener whose Rust lifetime is tied to both callback storage objects. The registry
/// proxy is destroyed by this guard before either borrowed object can move or go out of scope, so a
/// later GDK display dispatch can never call the listener with dangling stack pointers.
struct RegistryListenerGuard<'a> {
    registry: OwnedWaylandProxy,
    _listener: &'a RegistryListener,
    globals: &'a mut Globals,
}

impl<'a> RegistryListenerGuard<'a> {
    unsafe fn attach(
        registry: *mut wl_proxy,
        listener: &'a RegistryListener,
        globals: &'a mut Globals,
    ) -> Result<Self, PresentTargetError> {
        let guard = Self {
            registry: OwnedWaylandProxy::from_raw(registry, REGISTRY_PROXY_CLEANUP)
                .ok_or(PresentTargetError::NativeCall("wl_display.get_registry"))?,
            _listener: listener,
            globals,
        };
        let rc = ffi_dispatch!(
            wayland_client_handle(),
            wl_proxy_add_listener,
            guard.registry.as_ptr(),
            listener as *const RegistryListener as *mut _,
            (&mut *guard.globals) as *mut Globals as *mut c_void
        );
        if rc != 0 {
            return Err(PresentTargetError::NativeCall("wl_proxy_add_listener"));
        }
        Ok(guard)
    }

    fn as_ptr(&self) -> *mut wl_proxy {
        self.registry.as_ptr()
    }

    fn globals(&self) -> &Globals {
        &*self.globals
    }
}

/// Temporary global bindings used only while constructing the child surface. Their cleanup does
/// not affect child objects already created from them.
struct BoundCompositors {
    subcompositor: OwnedWaylandProxy,
    compositor: OwnedWaylandProxy,
}

/// Bind `wl_compositor` + `wl_subcompositor` from GDK's registry (one roundtrip). Hydra owns the
/// resulting proxies on GDK's connection and needs them only while constructing the child objects.
unsafe fn bind_compositors(
    display: *mut wl_display,
) -> Result<BoundCompositors, PresentTargetError> {
    let mut get_registry_args = [wl_argument { n: 0 }];
    let registry = ffi_dispatch!(
        wayland_client_handle(),
        wl_proxy_marshal_array_constructor,
        display as *mut wl_proxy,
        WL_DISPLAY_GET_REGISTRY,
        get_registry_args.as_mut_ptr(),
        &wl_registry_interface
    );
    let listener = RegistryListener {
        global: registry_global,
        global_remove: registry_global_remove,
    };
    let mut globals = Globals::default();
    let registry = RegistryListenerGuard::attach(registry, &listener, &mut globals)?;
    if ffi_dispatch!(wayland_client_handle(), wl_display_roundtrip, display) < 0 {
        return Err(PresentTargetError::NativeCall("wl_display_roundtrip"));
    }
    let (compositor_name, compositor_version, subcompositor_name, subcompositor_version) = {
        let globals = registry.globals();
        (
            globals
                .compositor_name
                .ok_or(PresentTargetError::MissingWaylandGlobal("wl_compositor"))?,
            globals.compositor_version,
            globals
                .subcompositor_name
                .ok_or(PresentTargetError::MissingWaylandGlobal("wl_subcompositor"))?,
            globals.subcompositor_version,
        )
    };

    let compositor_iface = c"wl_compositor";
    let mut compositor_args = [
        wl_argument { u: compositor_name },
        wl_argument {
            s: compositor_iface.as_ptr(),
        },
        wl_argument {
            u: compositor_version,
        },
        wl_argument { n: 0 },
    ];
    let compositor = ffi_dispatch!(
        wayland_client_handle(),
        wl_proxy_marshal_array_constructor_versioned,
        registry.as_ptr(),
        WL_REGISTRY_BIND,
        compositor_args.as_mut_ptr(),
        &wl_compositor_interface,
        compositor_version
    );
    let compositor = OwnedWaylandProxy::from_raw(compositor, COMPOSITOR_PROXY_CLEANUP).ok_or(
        PresentTargetError::NativeCall("wl_registry.bind wl_compositor"),
    )?;
    let subcompositor_iface = c"wl_subcompositor";
    let mut subcompositor_args = [
        wl_argument {
            u: subcompositor_name,
        },
        wl_argument {
            s: subcompositor_iface.as_ptr(),
        },
        wl_argument {
            u: subcompositor_version,
        },
        wl_argument { n: 0 },
    ];
    let subcompositor = ffi_dispatch!(
        wayland_client_handle(),
        wl_proxy_marshal_array_constructor_versioned,
        registry.as_ptr(),
        WL_REGISTRY_BIND,
        subcompositor_args.as_mut_ptr(),
        &wl_subcompositor_interface,
        subcompositor_version
    );
    let subcompositor = OwnedWaylandProxy::from_raw(subcompositor, SUBCOMPOSITOR_PROXY_CLEANUP)
        .ok_or(PresentTargetError::NativeCall(
            "wl_registry.bind wl_subcompositor",
        ))?;
    Ok(BoundCompositors {
        subcompositor,
        compositor,
    })
}

/// The Wayland backend: the child `wl_surface` WGPU presents into + the `wl_subsurface` role (for reposition).
struct WaylandChild {
    wl_display: *mut wl_display,
    // Field order is cleanup order: destroy the role before the surface carrying it.
    subsurface: OwnedWaylandProxy,
    surface: OwnedWaylandProxy,
    parent_surface: *mut wl_proxy,
}

/// The X11 backend: the GDK display + the child window XID WGPU presents into.
#[derive(Clone, Copy)]
struct X11Child {
    display: *mut c_void,
    xid: std::os::raw::c_ulong,
}

enum Backend {
    Wayland(WaylandChild),
    X11(X11Child),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalStackOrder {
    AboveParent,
    BelowParent,
}

/// Tracks overlay intent independently of the native backend. The child starts above its parent,
/// so repeated requests for the already-published order are no-ops.
#[derive(Default)]
struct OverlayOcclusionState {
    occluded: Cell<bool>,
}

impl OverlayOcclusionState {
    fn transition_to(&self, occluded: bool) -> Option<TerminalStackOrder> {
        if self.occluded.replace(occluded) == occluded {
            return None;
        }
        Some(if occluded {
            TerminalStackOrder::BelowParent
        } else {
            TerminalStackOrder::AboveParent
        })
    }
}

/// Deferred renderer work released only after the parent surface has committed a terminal reveal.
/// The newest resize replaces every earlier resize while hidden; one fresh frame then paints the
/// latest shared terminal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TerminalPresentationResume {
    pub(crate) deferred_resize: Option<(u32, u32)>,
    pub(crate) redraw_required: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalPresentationPhase {
    Presenting,
    Occluded,
    RevealPending {
        generation: u64,
        parent_paint_observed: bool,
    },
}

/// Pure Wayland presentation state. X11 keeps this gate disabled because its independently
/// qualified GTK child stacking does not route WGPU through a synchronized `wl_subsurface`.
///
/// This gate is deliberately synchronous with native restacking: `occlude` closes it before
/// `place_below`, so no owner-loop event can enter WGPU after the terminal becomes hidden.
struct TerminalPresentationGate {
    enabled: bool,
    phase: Cell<TerminalPresentationPhase>,
    next_generation: Cell<u64>,
    deferred_resize: Cell<Option<(u32, u32)>>,
    redraw_required: Cell<bool>,
}

impl TerminalPresentationGate {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            phase: Cell::new(TerminalPresentationPhase::Presenting),
            next_generation: Cell::new(0),
            deferred_resize: Cell::new(None),
            redraw_required: Cell::new(false),
        }
    }

    /// Close the WGPU boundary before native stacking changes. Re-occluding a reveal-pending
    /// terminal invalidates its acknowledgement because the phase no longer carries that token.
    fn occlude(&self) {
        if !self.enabled {
            return;
        }
        if self.phase.get() != TerminalPresentationPhase::Occluded {
            self.phase.set(TerminalPresentationPhase::Occluded);
            // Even with no intervening Grid/Damage, reveal must repaint once so the renderer and
            // compositor re-establish a current visible buffer.
            self.redraw_required.set(true);
        }
    }

    /// Restacking above is synchronized Wayland parent state. Remain closed until a later parent
    /// paint is observed and its generation returns through the owner-loop proxy.
    fn begin_reveal(&self) {
        if !self.enabled {
            return;
        }
        if self.phase.get() != TerminalPresentationPhase::Occluded {
            return;
        }
        let generation = self.next_generation.get().wrapping_add(1).max(1);
        self.next_generation.set(generation);
        self.phase.set(TerminalPresentationPhase::RevealPending {
            generation,
            parent_paint_observed: false,
        });
    }

    /// Called from the GTK top-level's after-draw signal. It does not reopen WGPU there; it only
    /// emits one generation for delivery on a later Tao owner-loop turn, after GTK has returned
    /// from the parent paint/commit path.
    fn parent_paint_observed(&self) -> Option<u64> {
        let TerminalPresentationPhase::RevealPending {
            generation,
            parent_paint_observed: false,
        } = self.phase.get()
        else {
            return None;
        };
        self.phase.set(TerminalPresentationPhase::RevealPending {
            generation,
            parent_paint_observed: true,
        });
        Some(generation)
    }

    /// Reopen only for the current acknowledged generation. A stale callback from an earlier
    /// hide/recovery cycle cannot resume a newly occluded terminal.
    fn complete_reveal(&self, generation: u64) -> Option<TerminalPresentationResume> {
        if !self.enabled {
            return None;
        }
        if self.phase.get()
            != (TerminalPresentationPhase::RevealPending {
                generation,
                parent_paint_observed: true,
            })
        {
            return None;
        }
        self.phase.set(TerminalPresentationPhase::Presenting);
        Some(TerminalPresentationResume {
            deferred_resize: self.deferred_resize.take(),
            redraw_required: self.redraw_required.replace(false),
        })
    }

    fn try_begin_frame(&self) -> bool {
        if !self.enabled || self.phase.get() == TerminalPresentationPhase::Presenting {
            return true;
        }
        self.redraw_required.set(true);
        false
    }

    fn try_begin_surface_resize(&self, width: u32, height: u32) -> bool {
        if !self.enabled || self.phase.get() == TerminalPresentationPhase::Presenting {
            return true;
        }
        if width > 0 && height > 0 {
            self.deferred_resize.set(Some((width, height)));
            self.redraw_required.set(true);
        }
        false
    }
}

/// A GTK-owned child surface the WGPU renderer presents the terminal into. Holds the native child alive for the
/// renderer's lifetime and exposes the raw-window-handle pair WGPU needs. Input-transparent: it never steals
/// pointer/keyboard from the GTK terminal slot. Neither `wl_*` proxies nor X11 types leak past this module.
pub struct TerminalPresentTarget {
    backend: Backend,
    overlay_occlusion: OverlayOcclusionState,
    presentation_gate: TerminalPresentationGate,
}

impl TerminalPresentTarget {
    /// Whether this target is the native Wayland child surface. Renderer policy uses this fact to
    /// avoid applying Wayland-specific WSI workarounds to the independently qualified X11 path.
    pub(crate) fn is_wayland(&self) -> bool {
        matches!(self.backend, Backend::Wayland(_))
    }

    /// Build the child present target for the realized GTK terminal-slot `gdk_window`, positioned at
    /// (`slot_x`, `slot_y`) in the parent surface, at `buffer_scale`. Chooses Wayland subsurface or X11 child
    /// XID from the active GDK backend.
    pub fn new(
        gdk_window: &gtk::gdk::Window,
        parent_gdk_window: &gtk::gdk::Window,
        slot_x: i32,
        slot_y: i32,
        buffer_scale: i32,
    ) -> Result<Self, PresentTargetError> {
        let display = gdk_window.display();
        let backend_name = display.type_().name().to_string();
        if backend_name.to_ascii_lowercase().contains("wayland") {
            Ok(Self {
                backend: Backend::Wayland(unsafe {
                    build_wayland_child(&display, parent_gdk_window, slot_x, slot_y, buffer_scale)?
                }),
                overlay_occlusion: OverlayOcclusionState::default(),
                presentation_gate: TerminalPresentationGate::new(true),
            })
        } else if backend_name.to_ascii_lowercase().contains("x11") {
            Ok(Self {
                backend: Backend::X11(unsafe { build_x11_child(&display, gdk_window)? }),
                overlay_occlusion: OverlayOcclusionState::default(),
                presentation_gate: TerminalPresentationGate::new(false),
            })
        } else {
            Err(PresentTargetError::UnsupportedBackend(backend_name))
        }
    }

    /// The raw display + window handle pair WGPU's `create_surface_unsafe` consumes.
    pub fn raw_handles(&self) -> (RawDisplayHandle, RawWindowHandle) {
        match &self.backend {
            Backend::Wayland(c) => {
                let d = NonNull::new(c.wl_display.cast::<c_void>()).expect("wl_display non-null");
                let s =
                    NonNull::new(c.surface.as_ptr().cast::<c_void>()).expect("wl_surface non-null");
                (
                    RawDisplayHandle::Wayland(WaylandDisplayHandle::new(d)),
                    RawWindowHandle::Wayland(WaylandWindowHandle::new(s)),
                )
            }
            Backend::X11(c) => {
                let d = NonNull::new(c.display);
                (
                    RawDisplayHandle::Xlib(XlibDisplayHandle::new(d, 0)),
                    RawWindowHandle::Xlib(XlibWindowHandle::new(c.xid)),
                )
            }
        }
    }

    /// Hide/reveal the terminal present surface while a GTK/WebKit overlay covers the window.
    /// Wayland restacks the child relative to its parent; the caller queues the normal GTK redraw
    /// that publishes this parent-surface state. X11 needs no native action: qualified GTK stacking
    /// already covers the child XID. No GDK-owned parent surface is committed here.
    pub fn set_overlay_occluded(&self, occluded: bool) {
        // The Wayland gate must close BEFORE place_below. Reveal remains closed after place_above
        // until a later parent paint/commit acknowledgement returns through the owner loop.
        if occluded {
            self.presentation_gate.occlude();
        } else {
            self.presentation_gate.begin_reveal();
        }
        let Some(order) = self.overlay_occlusion.transition_to(occluded) else {
            return;
        };
        match &self.backend {
            Backend::Wayland(child) => unsafe {
                stack_wayland_subsurface_against_parent(child, order);
            },
            Backend::X11(_) => {}
        }
    }

    /// Reject a renderer frame before it reaches WGPU while the Wayland child is occluded or its
    /// reveal is waiting for the parent commit. X11 always returns true.
    pub(crate) fn try_begin_frame(&self) -> bool {
        self.presentation_gate.try_begin_frame()
    }

    /// Retain only the newest surface allocation while hidden. PTY/session geometry remains owned
    /// by the existing coalescer; this guards only WGPU `Surface::configure`.
    pub(crate) fn try_begin_surface_resize(&self, width: u32, height: u32) -> bool {
        self.presentation_gate
            .try_begin_surface_resize(width, height)
    }

    /// Record one completed GTK parent draw and return its generation exactly once.
    pub(crate) fn parent_paint_observed(&self) -> Option<u64> {
        self.presentation_gate.parent_paint_observed()
    }

    /// Complete a generation-bound reveal on the owner loop and release coalesced renderer work.
    pub(crate) fn complete_reveal(&self, generation: u64) -> Option<TerminalPresentationResume> {
        self.presentation_gate.complete_reveal(generation)
    }

    /// Reposition + rescale the child to the terminal slot's realized geometry. Wayland: move the subsurface +
    /// re-apply buffer scale (WGPU's next present supplies the child-buffer commit). X11: move/resize the child
    /// window. Called from the GTK `size_allocate` path so the terminal region always tracks the layout.
    pub fn update_geometry(
        &self,
        slot_x: i32,
        slot_y: i32,
        width: u32,
        height: u32,
        buffer_scale: i32,
    ) -> Result<(), PresentTargetError> {
        match &self.backend {
            Backend::Wayland(c) => unsafe {
                // Position is parent-surface state; do NOT commit the child here (that would publish the
                // old-sized buffer). WGPU's following present is the only child-buffer commit.
                ffi_dispatch!(
                    wayland_client_handle(),
                    wl_proxy_marshal,
                    c.subsurface.as_ptr(),
                    WL_SUBSURFACE_SET_POSITION,
                    slot_x,
                    slot_y
                );
                ffi_dispatch!(
                    wayland_client_handle(),
                    wl_proxy_marshal,
                    c.surface.as_ptr(),
                    WL_SURFACE_SET_BUFFER_SCALE,
                    buffer_scale.max(1)
                );
            },
            Backend::X11(c) => unsafe {
                gdk_x11_move_resize_child(c, slot_x, slot_y, width, height);
            },
        }
        Ok(())
    }
}

/// Queue a Wayland child stacking change relative to its parent. This is double-buffered parent
/// state; a subsequent GTK redraw/commit publishes it. Never commit GDK's parent directly.
unsafe fn stack_wayland_subsurface_against_parent(child: &WaylandChild, order: TerminalStackOrder) {
    let opcode = match order {
        TerminalStackOrder::AboveParent => WL_SUBSURFACE_PLACE_ABOVE,
        TerminalStackOrder::BelowParent => WL_SUBSURFACE_PLACE_BELOW,
    };
    ffi_dispatch!(
        wayland_client_handle(),
        wl_proxy_marshal,
        child.subsurface.as_ptr(),
        opcode,
        child.parent_surface
    );
}

/// Create the Wayland subsurface child: bind compositors on GDK's display, create a child `wl_surface`, make it
/// an input-transparent subsurface of the parent top-level, desync + position + set buffer scale, and commit.
unsafe fn build_wayland_child(
    display: &gtk::gdk::Display,
    parent_gdk_window: &gtk::gdk::Window,
    slot_x: i32,
    slot_y: i32,
    buffer_scale: i32,
) -> Result<WaylandChild, PresentTargetError> {
    let display_ptr: *mut gtk::gdk::ffi::GdkDisplay = display.to_glib_none().0;
    let parent_ptr: *mut gtk::gdk::ffi::GdkWindow = parent_gdk_window.to_glib_none().0;
    let wl_display = gdk_wayland_sys::gdk_wayland_display_get_wl_display(display_ptr.cast());
    let parent_surface = gdk_wayland_sys::gdk_wayland_window_get_wl_surface(parent_ptr.cast());
    if wl_display.is_null() {
        return Err(PresentTargetError::NullNativeHandle("wl_display"));
    }
    if parent_surface.is_null() {
        return Err(PresentTargetError::NullNativeHandle("parent wl_surface"));
    }
    let wl_display = wl_display.cast::<wl_display>();
    let parent_surface = parent_surface.cast::<wl_proxy>();
    let compositors = bind_compositors(wl_display)?;

    let mut create_surface_args = [wl_argument { n: 0 }];
    let surface = ffi_dispatch!(
        wayland_client_handle(),
        wl_proxy_marshal_array_constructor,
        compositors.compositor.as_ptr(),
        WL_COMPOSITOR_CREATE_SURFACE,
        create_surface_args.as_mut_ptr(),
        &wl_surface_interface
    );
    let surface = OwnedWaylandProxy::from_raw(surface, SURFACE_PROXY_CLEANUP).ok_or(
        PresentTargetError::NativeCall("wl_compositor.create_surface"),
    )?;
    let mut get_subsurface_args = [
        wl_argument { n: 0 },
        wl_argument {
            o: surface.as_ptr() as *const c_void,
        },
        wl_argument {
            o: parent_surface as *const c_void,
        },
    ];
    let subsurface = ffi_dispatch!(
        wayland_client_handle(),
        wl_proxy_marshal_array_constructor,
        compositors.subcompositor.as_ptr(),
        WL_SUBCOMPOSITOR_GET_SUBSURFACE,
        get_subsurface_args.as_mut_ptr(),
        &wl_subsurface_interface
    );
    let subsurface = OwnedWaylandProxy::from_raw(subsurface, SUBSURFACE_PROXY_CLEANUP).ok_or(
        PresentTargetError::NativeCall("wl_subcompositor.get_subsurface"),
    )?;
    // Input-transparent: an explicitly EMPTY input region so pointer/keyboard fall through to the GTK terminal
    // slot (Hydra's normal input pipeline). The default infinite region would swallow clicks with no listener.
    let mut create_region_args = [wl_argument { n: 0 }];
    let empty_region = ffi_dispatch!(
        wayland_client_handle(),
        wl_proxy_marshal_array_constructor,
        compositors.compositor.as_ptr(),
        WL_COMPOSITOR_CREATE_REGION,
        create_region_args.as_mut_ptr(),
        &wl_region_interface
    );
    let empty_region = OwnedWaylandProxy::from_raw(empty_region, REGION_PROXY_CLEANUP).ok_or(
        PresentTargetError::NativeCall("wl_compositor.create_region"),
    )?;
    ffi_dispatch!(
        wayland_client_handle(),
        wl_proxy_marshal,
        surface.as_ptr(),
        WL_SURFACE_SET_INPUT_REGION,
        empty_region.as_ptr()
    );
    drop(empty_region);
    // Desync so WGPU presents independently of the parent's commit cadence; position beside the sidebar; apply
    // buffer scale so a HiDPI physical buffer isn't re-scaled by the compositor.
    ffi_dispatch!(
        wayland_client_handle(),
        wl_proxy_marshal,
        subsurface.as_ptr(),
        WL_SUBSURFACE_SET_POSITION,
        slot_x,
        slot_y
    );
    ffi_dispatch!(
        wayland_client_handle(),
        wl_proxy_marshal,
        subsurface.as_ptr(),
        WL_SUBSURFACE_SET_DESYNC
    );
    ffi_dispatch!(
        wayland_client_handle(),
        wl_proxy_marshal,
        surface.as_ptr(),
        WL_SURFACE_SET_BUFFER_SCALE,
        buffer_scale.max(1)
    );
    ffi_dispatch!(
        wayland_client_handle(),
        wl_proxy_marshal,
        surface.as_ptr(),
        WL_SURFACE_COMMIT
    );
    Ok(WaylandChild {
        wl_display,
        subsurface,
        surface,
        parent_surface,
    })
}

/// Create the X11 present target: the realized GTK terminal-slot `gdk_window`'s XID + the X display. GTK gives
/// the slot its own native child window on X11, so the XID is a valid WGPU present target.
unsafe fn build_x11_child(
    display: &gtk::gdk::Display,
    gdk_window: &gtk::gdk::Window,
) -> Result<X11Child, PresentTargetError> {
    let display_ptr: *mut gtk::gdk::ffi::GdkDisplay = display.to_glib_none().0;
    let window_ptr: *mut gtk::gdk::ffi::GdkWindow = gdk_window.to_glib_none().0;
    let xdisplay = gdk_x11_sys::gdk_x11_display_get_xdisplay(display_ptr.cast());
    let xid = gdk_x11_sys::gdk_x11_window_get_xid(window_ptr.cast());
    if xdisplay.is_null() {
        return Err(PresentTargetError::NullNativeHandle("x11 display"));
    }
    if xid == 0 {
        return Err(PresentTargetError::NullNativeHandle("x11 window xid"));
    }
    Ok(X11Child {
        display: xdisplay.cast(),
        xid: xid as std::os::raw::c_ulong,
    })
}

/// Move/resize the X11 child window via Xlib. The child XID tracks the GTK terminal slot on resize.
unsafe fn gdk_x11_move_resize_child(c: &X11Child, x: i32, y: i32, width: u32, height: u32) {
    // GDK's Xlib is loaded at runtime, but these DATA/text symbols are not re-exported by gdk-x11, so we link
    // libX11 directly for them (GTK already loads libX11, so this adds no new runtime dependency).
    #[link(name = "X11")]
    extern "C" {
        fn XMoveResizeWindow(
            display: *mut c_void,
            w: std::os::raw::c_ulong,
            x: std::os::raw::c_int,
            y: std::os::raw::c_int,
            width: std::os::raw::c_uint,
            height: std::os::raw::c_uint,
        ) -> std::os::raw::c_int;
        fn XFlush(display: *mut c_void) -> std::os::raw::c_int;
    }
    XMoveResizeWindow(c.display, c.xid, x, y, width.max(1), height.max(1));
    XFlush(c.display);
}

#[cfg(test)]
mod tests {
    use super::{
        Backend, OverlayOcclusionState, ProxyCleanup, RegistryListenerGuard, TerminalPresentTarget,
        TerminalPresentationGate, TerminalPresentationPhase, TerminalStackOrder, WaylandChild,
        X11Child, COMPOSITOR_PROXY_CLEANUP, REGION_PROXY_CLEANUP, REGISTRY_PROXY_CLEANUP,
        SUBCOMPOSITOR_PROXY_CLEANUP, SUBSURFACE_PROXY_CLEANUP, SURFACE_PROXY_CLEANUP,
        WL_REGION_DESTROY, WL_SUBCOMPOSITOR_DESTROY, WL_SUBSURFACE_DESTROY, WL_SURFACE_DESTROY,
    };

    #[test]
    fn wayland_bind_and_child_proxies_have_explicit_cleanup_contracts() {
        assert_eq!(REGISTRY_PROXY_CLEANUP, ProxyCleanup::LocalOnly);
        assert_eq!(COMPOSITOR_PROXY_CLEANUP, ProxyCleanup::LocalOnly);
        assert_eq!(
            SUBCOMPOSITOR_PROXY_CLEANUP,
            ProxyCleanup::ProtocolDestroy(WL_SUBCOMPOSITOR_DESTROY)
        );
        assert_eq!(
            REGION_PROXY_CLEANUP,
            ProxyCleanup::ProtocolDestroy(WL_REGION_DESTROY)
        );
        assert_eq!(
            SUBSURFACE_PROXY_CLEANUP,
            ProxyCleanup::ProtocolDestroy(WL_SUBSURFACE_DESTROY)
        );
        assert_eq!(
            SURFACE_PROXY_CLEANUP,
            ProxyCleanup::ProtocolDestroy(WL_SURFACE_DESTROY)
        );
        assert!(std::mem::needs_drop::<RegistryListenerGuard<'static>>());
        assert!(std::mem::needs_drop::<WaylandChild>());
    }

    #[test]
    fn terminal_starts_visible_without_a_native_transition() {
        let state = OverlayOcclusionState::default();
        assert_eq!(state.transition_to(false), None);
        assert_eq!(state.transition_to(false), None);
    }

    #[test]
    fn overlay_visibility_changes_map_to_parent_relative_stack_order() {
        let state = OverlayOcclusionState::default();
        assert_eq!(
            state.transition_to(true),
            Some(TerminalStackOrder::BelowParent)
        );
        assert_eq!(state.transition_to(true), None);
        assert_eq!(
            state.transition_to(false),
            Some(TerminalStackOrder::AboveParent)
        );
        assert_eq!(state.transition_to(false), None);
    }

    #[test]
    fn x11_occlusion_tracks_state_without_touching_the_native_child() {
        // Null/zero handles make an accidental native call fail loudly. X11 deliberately leaves
        // GTK's qualified child stacking alone while retaining idempotent logical state.
        let target = TerminalPresentTarget {
            backend: Backend::X11(X11Child {
                display: std::ptr::null_mut(),
                xid: 0,
            }),
            overlay_occlusion: OverlayOcclusionState::default(),
            presentation_gate: TerminalPresentationGate::new(false),
        };

        target.set_overlay_occluded(true);
        assert!(target.overlay_occlusion.occluded.get());
        target.set_overlay_occluded(true);
        assert!(target.overlay_occlusion.occluded.get());
        target.set_overlay_occluded(false);
        assert!(!target.overlay_occlusion.occluded.get());
        assert!(target.try_begin_frame());
        assert!(target.try_begin_surface_resize(800, 600));
    }

    #[test]
    fn wayland_gate_closes_before_occlusion_and_reopens_only_after_matching_parent_paint() {
        let gate = TerminalPresentationGate::new(true);
        assert!(gate.try_begin_frame());

        gate.occlude();
        assert_eq!(gate.phase.get(), TerminalPresentationPhase::Occluded);
        assert!(!gate.try_begin_frame());
        assert!(!gate.try_begin_surface_resize(1200, 700));

        gate.begin_reveal();
        let TerminalPresentationPhase::RevealPending { generation, .. } = gate.phase.get() else {
            panic!("reveal must remain pending")
        };
        assert!(!gate.try_begin_frame());
        assert_eq!(gate.complete_reveal(generation), None);

        assert_eq!(gate.parent_paint_observed(), Some(generation));
        assert_eq!(gate.parent_paint_observed(), None);
        let resume = gate
            .complete_reveal(generation)
            .expect("matching parent paint resumes");
        assert_eq!(resume.deferred_resize, Some((1200, 700)));
        assert!(resume.redraw_required);
        assert!(gate.try_begin_frame());
        assert_eq!(gate.complete_reveal(generation), None);
    }

    #[test]
    fn hidden_resizes_coalesce_to_the_latest_nonzero_allocation() {
        let gate = TerminalPresentationGate::new(true);
        gate.occlude();
        assert!(!gate.try_begin_surface_resize(800, 500));
        assert!(!gate.try_begin_surface_resize(0, 0));
        assert!(!gate.try_begin_surface_resize(1440, 900));
        gate.begin_reveal();
        let generation = gate.parent_paint_observed().expect("pending reveal");
        let resume = gate.complete_reveal(generation).expect("current reveal");
        assert_eq!(resume.deferred_resize, Some((1440, 900)));
    }

    #[test]
    fn reocclusion_invalidates_a_stale_reveal_acknowledgement() {
        let gate = TerminalPresentationGate::new(true);
        gate.occlude();
        gate.begin_reveal();
        let stale_generation = gate.parent_paint_observed().expect("first reveal");

        gate.occlude();
        assert_eq!(gate.complete_reveal(stale_generation), None);
        assert!(!gate.try_begin_frame());

        gate.begin_reveal();
        let current_generation = gate.parent_paint_observed().expect("second reveal");
        assert_ne!(current_generation, stale_generation);
        assert!(gate.complete_reveal(current_generation).is_some());
        assert!(gate.try_begin_frame());
    }

    #[test]
    fn disabled_gate_preserves_x11_immediate_presentation() {
        let gate = TerminalPresentationGate::new(false);
        gate.occlude();
        gate.begin_reveal();
        assert!(gate.try_begin_frame());
        assert!(gate.try_begin_surface_resize(1920, 1080));
        assert_eq!(gate.parent_paint_observed(), None);
    }
}
