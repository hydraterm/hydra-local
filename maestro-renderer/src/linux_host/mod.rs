//! Linux DashboardHost adapter — a PLATFORM-GATED HOST BOUNDARY, not a renderer fork.
//!
//! # Why this module exists
//!
//! The production renderer is winit-driven and stays that way on macOS, where wry hosts the React dashboard as
//! a child NSView of the winit window and WGPU presents into the winit surface. On Linux, winit exposes no GTK
//! hierarchy, but wry's WebKitGTK backend REQUIRES one to host a WebView. So on Linux only, this adapter owns
//! the top-level window + event loop via **Tao/GTK**:
//!
//! ```text
//!   Tao GTK top-level (this adapter)
//!   └── SidebarLayout ────────── exact, noninteractive GTK allocator
//!       ├── gtk::Box ────────── WebKitGTK sidebar dashboard (wry)      [presentation-only]
//!       └── gtk::Box (vertical)
//!                 ├── topbar slot ─ related WebKitGTK dashboard view   [presentation-only]
//!                 └── terminal slot ─ native child present target:
//!                 • Wayland → input-transparent `wl_subsurface`
//!                 • X11     → GTK-owned child XID
//!                 …handed to the EXISTING WGPU renderer via a raw-window-handle.
//! ```
//!
//! WGPU never presents into the same top-level surface as WebKit on any platform; sharing that surface can let
//! one compositor overwrite the other. The dashboard WebView is presentation-only: it never
//! owns terminal or daemon lifecycle. If WebKit's process dies, the bundled dashboard source is reloaded while
//! the WGPU terminal and its PTY continue uninterrupted.
//!
//! # Hard boundaries (do not violate)
//!
//! * **No renderer fork.** The renderer's logic, terminal grid, protocol, PTY daemon, retained-session
//!   ownership, and winsize ownership are untouched. This module only creates the native window/event/surface
//!   and NORMALIZES Tao/GTK events into the renderer's platform-neutral event model.
//! * **No type leakage.** `tao::*` and `gtk::*` types stay inside `src/linux_host/`. The renderer core consumes
//!   only the neutral [`HostEvent`] / [`HostGeometry`] / present-target handle defined here.
//! * **GTK is the geometry authority.** Terminal size/position and buffer scale come from the realized GTK
//!   terminal-slot widget's `size_allocate` + scale factor, NOT from Tao's reported window size.
//! * **Input goes through the existing Rust pipeline.** The WGPU child surface is input-transparent; keyboard/
//!   mouse/IME arrive at the GTK terminal slot and are normalized into [`HostEvent`] for the renderer.
//! * **Shared X11/Wayland policy.** Both display servers share the same GTK layout/IPC/policy code; only the
//!   native presentation-target creation differs (see [`present_target`]).
//!
#![cfg(target_os = "linux")]
// `dead_code`: some public boundary types/fields (e.g. `HostGeometry` field accessors, the error variants) are
// part of the host's API surface but not read on every build path. `unused_imports`: the re-exports below are
// the module's public vocabulary; not every one is imported by name in-crate yet.
#![allow(dead_code, unused_imports)]

pub mod chrome_services;
pub mod clipboard;
pub mod event_bridge;
pub mod host_services;
pub mod overlay;
mod persistent_surface;
pub mod present_target;
pub mod recovery;
pub(crate) mod sidebar_layout;
pub mod wake;
pub mod window_host;

pub use present_target::{PresentTargetError, TerminalPresentTarget};
pub use window_host::{HostGeometry, LinuxDashboardHost, LinuxHostError};
