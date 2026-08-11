//! wgpu renderer. Two layers per frame:
//!   1. an instanced quad pipeline that paints every cell's BACKGROUND, the cursor
//!      rect, and text DECORATIONS (underline / double underline / strikethrough,
//!      and segmented approximations of dotted/dashed/curly) as solid colored
//!      rectangles, and
//!   2. glyphon (cosmic-text + wgpu) for the glyphs and the status overlay.
//!
//! It never parses PTY bytes; it paints the daemon's authoritative grid only.

use glyphon::{
    Attrs, Buffer, Cache, Color as GColor, Family, FontSystem, Metrics, Resolution, Shaping,
    SwashCache, TextArea, TextAtlas, TextBounds, TextRenderer, Viewport, Weight,
};
use std::collections::HashMap;
// Arc + winit Window back the macOS `Renderer::new(Arc<Window>)` + `window` field; on Linux the renderer is
// built via `new_for_linux_host` from a GTK-owned present target and holds no winit window, so these are unused
// there. Keep the imports (macOS needs them) and silence the Linux-only unused warning.
#[cfg_attr(target_os = "linux", allow(unused_imports))]
use std::sync::Arc;
use std::time::Instant;
use wgpu::util::DeviceExt;
#[cfg_attr(target_os = "linux", allow(unused_imports))]
use winit::window::Window;

use crate::client::CellPos;
use crate::theme;
use crate::wire::{CursorShape, GridSnapshot, UnderlineStyle};
use crate::RendererCommandPaletteOverlayLine;

/// One background/cursor rectangle instance: position + size in pixels (physical)
/// and an RGBA color. The vertex shader maps pixel space to clip space.
#[repr(C)]
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
struct QuadInstance {
    // x, y (top-left), w, h in physical pixels.
    rect: [f32; 4],
    color: [f32; 4],
}

/// Uniform: the surface size in physical pixels, used to map px -> clip space.
#[repr(C)]
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
struct ScreenUniform {
    size: [f32; 2],
    _pad: [f32; 2],
}

/// Upper bound on distinct shaped glyph buffers held at once. A terminal's live
/// working set of (text, bold, italic, wide) combinations is small (a few hundred:
/// printable ASCII × a handful of styles, plus whatever CJK/box-drawing is on
/// screen). This cap only guards against pathological input (e.g. a flood of unique
/// multi-codepoint clusters) growing the map without bound. On overflow we clear the
/// whole map rather than LRU-evict — re-shaping a fresh working set is cheap and the
/// cap is hit rarely, so the simpler policy is the right tradeoff here.
const GLYPH_CACHE_CAP: usize = 4096;

/// Selection highlight color (defined locally, NOT in theme.rs, which is being
/// tuned separately). A light, translucent overlay so underlying glyphs stay
/// legible on the dark background.
const SELECTION_RGB: (u8, u8, u8) = (110, 140, 200);
const SELECTION_ALPHA: f32 = 0.35;

/// Focused-pane indicator border color (defined locally, NOT in theme.rs, which is being
/// tuned separately — same precedent as `SELECTION_RGB`). A soft, translucent accent drawn
/// as a thin frame around the focused split pane so the active pane is obvious without
/// obscuring its content. Only painted when a split exists.
const FOCUS_INDICATOR_RGB: (u8, u8, u8) = (120, 170, 255);
const FOCUS_INDICATOR_ALPHA: f32 = 0.55;
/// Border thickness of the focused-pane indicator, in physical pixels.
const FOCUS_INDICATOR_THICKNESS_PX: f32 = 2.0;

/// Inactive-pane dim overlay color (defined locally, NOT in theme.rs — same precedent as
/// `FOCUS_INDICATOR_RGB`/`SELECTION_RGB`). A near-black translucent tint laid over every non-focused
/// split pane so the focused pane reads as the target; the alpha is low enough that the dimmed pane's
/// content stays legible. Only painted when a split exists and never over a zoomed full-window pane.
const INACTIVE_DIM_RGB: (u8, u8, u8) = (0, 0, 0);
const INACTIVE_DIM_ALPHA: f32 = 0.28;

/// Pane drag-to-swap drop-target highlight color (defined locally, same precedent as the dim/focus
/// tints). A brighter translucent tint laid over the pane the cursor currently hovers during a pane
/// drag, so the user sees which pane the dragged pane will swap with on release. Painted ONLY while a
/// pane drag is in flight and only over the hovered target pane; cleared every frame otherwise so it
/// never persists past the gesture. Reuses the focus-indicator hue so the affordance reads as "this
/// pane is the active target."
const DROP_HIGHLIGHT_RGB: (u8, u8, u8) = (120, 170, 255);
const DROP_HIGHLIGHT_ALPHA: f32 = 0.22;

/// Edge-dock drop highlight color: a warm amber wash painted over the HALF of the target pane the
/// dragged pane will dock into (left/right/top/bottom), distinct from the blue full-pane swap wash so
/// "dock beside" reads differently from "swap with". Same opt-in lifetime as
/// [`DROP_HIGHLIGHT_RGB`].
const DROP_DOCK_HIGHLIGHT_RGB: (u8, u8, u8) = (245, 180, 90);
const DROP_DOCK_HIGHLIGHT_ALPHA: f32 = 0.28;

/// The pane drag-to-swap/dock drop highlight: the screen region to wash and whether it is an edge DOCK
/// (amber, a half-pane wash) or a center SWAP (blue, the full pane). Built in `lib.rs` from the live
/// drop zone so the highlighted shape/hue matches exactly what a release commits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DropHighlight {
    pub region: crate::RendererPaneRegion,
    /// `true` = edge dock (amber); `false` = center swap (blue).
    pub dock: bool,
}

/// Cache key for a shaped per-cell glyph buffer. The dominant per-frame cost is
/// `Buffer::new` + `shape_until_scroll` once PER non-blank cell (measured ~99% of
/// frame time on dense grids). The shaped result depends ONLY on what determines
/// glyph selection + geometry: the cell text, the bold/italic font variant, and
/// whether the cell spans one or two columns (the layout width bound). It does NOT
/// depend on foreground color — color is applied later via `TextArea.default_color`
/// (glyphon resolves each glyph's `color_opt`, which we leave `None`, to that
/// fallback), so the same letter shares one shaped buffer across every color it
/// appears in. Cell metrics/scale are NOT in the key: a DPI change rescales every
/// glyph, so the whole cache is dropped on scale change (see `render`).
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct GlyphKey {
    text: String,
    bold: bool,
    italic: bool,
    wide: bool,
}

/// Device limits to REQUEST for native desktop rendering, derived from what the adapter
/// actually supports. Pure so the policy is testable without a GPU.
///
/// Why not raw `Limits::downlevel_defaults()`: that profile caps
/// `max_texture_dimension_2d` at 2048, and `Surface::configure` validates the surface
/// size against the DEVICE limit (not the adapter's). A fullscreen retina macOS surface
/// (e.g. 3456x2168 on a 14" MBP) exceeds 2048, so the green-button fullscreen transition
/// aborted with a non-unwinding validation panic inside AppKit's
/// `frame_did_change` callback — even though the adapter supported far larger textures.
///
/// Policy: start from `downlevel_defaults()` (we need nothing else beyond it, so the
/// broad-compatibility floor stays), then raise ONLY `max_texture_dimension_2d` to the
/// native-desktop default (`Limits::default()`, 8192 — larger than any current display,
/// including 6K at 6016px), clamped to the adapter's own maximum so the device request
/// can never fail. On a weak/fallback adapter that supports less than 2048 the adapter's
/// value is used as-is, which only restores the previous behavior there.
fn renderer_required_limits(adapter: wgpu::Limits) -> wgpu::Limits {
    let native_2d = wgpu::Limits::default().max_texture_dimension_2d;
    wgpu::Limits {
        max_texture_dimension_2d: native_2d.min(adapter.max_texture_dimension_2d),
        ..wgpu::Limits::downlevel_defaults()
    }
}

/// A terminal renderer does not benefit from waking a discrete GPU. More importantly,
/// on PRIME/offload Linux laptops the integrated adapter owns the desktop scanout while
/// a `HighPerformance` request selects the discrete adapter and forces every X11
/// swapchain present through the cross-GPU path. That path can block the sole GTK/Tao
/// owner thread in the NVIDIA X11 WSI. Prefer the display-class integrated adapter on
/// Linux; a discrete-only machine still resolves to its only compatible adapter.
#[cfg(target_os = "linux")]
const LINUX_RENDERER_POWER_PREFERENCE: wgpu::PowerPreference = wgpu::PowerPreference::LowPower;

/// Intel's ANV Wayland FIFO path can block the sole GTK/Tao owner thread inside
/// `wl_display_dispatch_queue` while the swapchain is configured or resized. Prefer a supported
/// non-FIFO mode only for that exact native-Wayland/Vulkan combination. Mailbox keeps vsync without
/// making an old queued frame authoritative. Every other backend retains the qualified FIFO policy.
#[cfg(any(target_os = "linux", test))]
fn linux_surface_present_mode(
    is_wayland: bool,
    vendor: u32,
    backend: wgpu::Backend,
    supported: &[wgpu::PresentMode],
) -> wgpu::PresentMode {
    const INTEL_PCI_VENDOR_ID: u32 = 0x8086;
    if is_wayland
        && vendor == INTEL_PCI_VENDOR_ID
        && backend == wgpu::Backend::Vulkan
        && supported.contains(&wgpu::PresentMode::Mailbox)
    {
        return wgpu::PresentMode::Mailbox;
    }
    wgpu::PresentMode::Fifo
}

/// The window/scale source the shared [`Renderer::finish_new`] stores. A cfg-gated adapter seam: macOS carries
/// the winit window (unchanged semantics); Linux carries only the GTK-terminal scale, since the Tao/GTK
/// DashboardHost owns the window and the renderer presents into a child surface.
enum WindowHandleForRenderer {
    #[cfg(not(target_os = "linux"))]
    Winit(Arc<Window>),
    #[cfg(target_os = "linux")]
    LinuxHost { scale: f32, is_wayland: bool },
}

impl WindowHandleForRenderer {
    #[cfg(not(target_os = "linux"))]
    fn into_winit_window(self) -> Arc<Window> {
        match self {
            WindowHandleForRenderer::Winit(w) => w,
        }
    }

    #[cfg(target_os = "linux")]
    fn linux_scale(&self) -> f32 {
        match self {
            WindowHandleForRenderer::LinuxHost { scale, .. } => *scale,
        }
    }

    #[cfg(target_os = "linux")]
    fn linux_is_wayland(&self) -> bool {
        match self {
            WindowHandleForRenderer::LinuxHost { is_wayland, .. } => *is_wayland,
        }
    }
}

pub struct Renderer {
    // macOS keeps the winit window (unchanged): WGPU's surface is created from it and it is the scale-factor
    // source. On Linux the window/event/surface are owned by the Tao/GTK DashboardHost adapter, so the renderer
    // holds no winit window — it presents into a GTK-owned child surface and reads scale from `linux_scale`
    // (fed by the realized GTK terminal widget, the geometry authority). This is a cfg-gated ADAPTER seam, not
    // a macOS redesign: the macOS field + its uses are byte-identical.
    #[cfg(not(target_os = "linux"))]
    window: Arc<Window>,
    /// Linux-only: buffer scale from the GTK terminal slot (the authority), replacing `window.scale_factor()`.
    #[cfg(target_os = "linux")]
    linux_scale: f32,
    surface: wgpu::Surface<'static>,
    device: wgpu::Device,
    queue: wgpu::Queue,
    config: wgpu::SurfaceConfiguration,
    /// The `max_texture_dimension_2d` the device was created with; `resize` refuses
    /// (logs + skips) any configure beyond it instead of letting wgpu's validation
    /// abort the process.
    max_surface_dim: u32,

    // Quad (background + cursor) pipeline.
    quad_pipeline: wgpu::RenderPipeline,
    quad_bind_group: wgpu::BindGroup,
    screen_buf: wgpu::Buffer,
    instance_buf: wgpu::Buffer,
    instance_cap: usize,
    instance_count: u32,

    // glyphon text stack.
    font_system: FontSystem,
    swash_cache: SwashCache,
    atlas: TextAtlas,
    text_renderer: TextRenderer,
    viewport: Viewport,

    // Cell metrics (logical px) and font size.
    cell_w: f32,
    cell_h: f32,
    font_size: f32,
    line_height: f32,

    // The active color theme + its resolved palette. Seeded from `RendererLaunch.theme` (or the
    // built-in dark default when `None`) and used for the full-window background clear, every cell's
    // foreground/background, the cursor color, and dim resolution. Per-instance — two windows launched
    // with different themes never share color state. `set_theme` re-resolves both in place for a live
    // theme change; `theme` is retained so an identical re-apply is a no-op.
    theme: theme::RendererTheme,
    palette: theme::Palette,

    // Shaped-glyph cache (see GlyphKey). Holds one already-shaped Buffer per unique
    // (text, bold, italic, wide) combination, reused across cells AND frames so an
    // unchanged screen re-shapes nothing. Keyed independent of color (applied per
    // TextArea) and of position (placement is per-cell). Invalidated wholesale when
    // `scale_at_shape` changes, because the cached buffers are shaped at that scale's
    // metrics. Bounded by `GLYPH_CACHE_CAP`; cleared (not LRU-evicted) when full,
    // since a terminal's working set of glyphs is small and a clear is rare.
    glyph_cache: HashMap<GlyphKey, Buffer>,
    scale_at_shape: f32,

    // Opt-in top tab bar (set by the App before each frame; default inert).
    // `top_bar` is the pure pixel layout of the app-owned tabs; `grid_origin_y` is the physical
    // pixel offset the terminal grid (and cursor/selection/glyphs) is painted down by so the reserved
    // top chrome rows are not overpainted. `grid_origin_y` covers ALL top chrome (tab bar + dashboard
    // panel), so it can be nonzero even when `top_bar` is `None` (dashboard panel only). It is `0.0`
    // only when there is no top chrome at all, keeping every existing path byte-identical.
    top_bar: Option<crate::RendererTabBarLayout>,
    grid_origin_y: f32,
    // The physical-pixel offset the terminal grid (and cursor/selection/glyphs/panes) is painted RIGHT
    // by. It includes the real LEFT dock plus any terminal-only outer padding. Mirrors `grid_origin_y`
    // on the X axis; `0.0` keeps the historical full-width path. Set independently via
    // `set_grid_origin_x` so the vertical path is never touched.
    grid_origin_x: f32,
    // Actual renderer-owned dock/sidebar width in physical pixels. Kept separate from `grid_origin_x`
    // so terminal padding never widens app chrome or moves its collapse button/rows.
    dock_width_x: f32,
    // The left-dock rows to paint inside the reserved column (in draw order), and whether the dock is in
    // its collapsed icon-rail variant. Empty `dock_rows` draws only the dock fill. Set by
    // the App each frame via `set_dock_rows` alongside `set_grid_origin_x`.
    dock_rows: Vec<crate::RendererDockRow>,
    dock_collapsed: bool,
    // The visible top tab the cursor is hovering, or `None`. Display-only chrome state set by the App
    // each frame alongside `top_bar`; it shifts a hovered INACTIVE tab's fill/label without changing
    // the active tab. Ignored when `top_bar` is `None`.
    top_bar_hover: Option<String>,

    // Opt-in read-only dashboard panel: app-owned chrome drawn BELOW the top tab bar and ABOVE the
    // grid. `dashboard_panel` is the already-fitted, control-char-free text for each reserved panel
    // row (one String per row, in draw order); `dashboard_panel_origin_y` is the physical pixel y the
    // first panel row is painted at (equal to the tab-bar height, or 0.0 when no tab bar). The App
    // computes both each frame from the same `total_chrome_rows` reservation the grid origin uses, so
    // the panel never overpaints the grid. Empty/`None` draws nothing and every existing path is
    // byte-identical. The panel has no hit testing, hover, or click handling.
    dashboard_panel: Vec<String>,
    dashboard_panel_origin_y: f32,
    // Optional private Remote extension presentation. The renderer never discovers an agent or reads
    // extension-owned files: the public host projects a negotiated, structured snapshot here. When the
    // extension is absent or incompatible the controls are not painted or hit-testable.
    remote_controls_available: bool,
    // Display-only remote-access state supplied by the negotiated optional extension.
    remote_open: bool,
    // Display-only viewport-owner summary supplied by the negotiated optional extension.
    winsize_owner_remote: bool,
    // Optional active-project accent (8-bit sRGB) for the panel's project-header band (row 0). `None`
    // keeps the neutral `DASHBOARD_PANEL_BAND` for every row.
    dashboard_panel_accent: Option<theme::Rgb>,

    // Opt-in read-only picker overlay: a foreground modal list of rows drawn OVER the grid (from
    // physical y=0, one cell-height per row). `picker_overlay` is the already-composed,
    // control-char-free text for each row in deterministic draw order; empty draws nothing and keeps
    // every existing path byte-identical. The overlay has its own dim backdrop quad; row hit-testing
    // and dismissal are owned by the App. The renderer never re-sorts rows.
    picker_overlay: Vec<String>,

    // Opt-in read-only command-palette overlay: a foreground modal list of rows drawn OVER the grid
    // (from physical y=0, one cell-height per row), mirroring the picker overlay draw style but kept
    // as a SEPARATE carrier/state so the two never alias. Each entry is the already-composed,
    // control-char-free text plus a `selected` flag for the one highlighted action row (at most one,
    // never a header/empty-state line). Empty draws nothing and keeps every existing path
    // byte-identical. Display-only: no hit testing, hover, or click handling, and the renderer never
    // re-sorts rows.
    command_palette_overlay: Vec<RendererCommandPaletteOverlayLine>,

    // Opt-in split-pane shortcut hint overlay: a small, NON-modal list of the current split controls
    // drawn OVER the grid (from physical y=0, one cell-height per row). Unlike the picker/command-palette
    // overlays this draws NO full-window dim backdrop — the grid stays visible behind it, since it is a
    // discoverability hint, not a focus-stealing modal. Each entry is already-composed, control-char-free
    // text. Empty draws nothing and keeps every existing path byte-identical. Display-only: no hit
    // testing, hover, or click handling; the renderer never re-sorts.
    shortcut_hint_overlay: Vec<RendererCommandPaletteOverlayLine>,

    // Opt-in read-only file-preview overlay: the already-composed lines of the one active
    // `RendererFilePreview` (header + bounded body + truncation marker), painted as a NON-modal band
    // anchored to the RIGHT half of the window so it reads as a preview "beside" the terminal. Like the
    // shortcut-hint overlay it draws NO full-window dim backdrop — the grid stays visible and keys keep
    // reaching the PTY. Each entry is control-char-free text. Empty draws nothing and keeps every
    // existing path byte-identical. Display-only: no hit testing, hover, or click handling.
    file_preview_overlay: Vec<RendererCommandPaletteOverlayLine>,

    // Opt-in file-path-input prompt: the single already-composed prompt row shown while the user is
    // typing a path to preview, painted as a NON-modal band anchored to the BOTTOM of the window. Like
    // the shortcut-hint overlay it draws NO full-window dim backdrop — the grid stays visible. Empty
    // draws nothing and keeps every existing path byte-identical. Display-only: no hit testing or click
    // handling; the prompt's key capture lives in the App.
    file_path_input_overlay: Vec<RendererCommandPaletteOverlayLine>,

    // Opt-in split-pane frame: the one top-level split the active tab participates in (source/child
    // pair, even cell regions, and the dividing line), computed by the App via
    // `compute_split_frame` and set each frame alongside the other chrome carriers. When `Some`, the
    // renderer paints the divider line into the grid quad scene at `divider.col`/`divider.row` (over
    // the offset grid, below the top chrome). `None` keeps every existing path byte-identical. This is
    // advisory geometry only: the active PTY viewport stays the single rendered terminal grid — no
    // second session is drawn into the regions yet.
    split_frame: Option<crate::RendererSplitFrame>,
    // Status of the inactive pane's cached sibling session, sourced from `Shared::sibling` by the App
    // and shown in the placeholder label. Defaults to `Detached` (no sibling) so the byte-identical
    // no-split path is unchanged.
    split_sibling_status: SiblingPaneStatus,
    // Cached grid snapshot of the inactive pane's sibling session, sourced from `Shared::sibling` by
    // the App and threaded in alongside `split_frame`. When `Some` (and the sibling has not exited),
    // `render` paints it clipped/offset to the inactive pane region in place of the placeholder band/
    // label. `None` keeps the placeholder, leaving the no-sibling path byte-identical.
    sibling_grid: Option<std::sync::Arc<GridSnapshot>>,
    // Extra non-active panes of a 3+-pane split layout, beyond the active pane and the rendered
    // sibling. Each carries its absolute window-grid region, its cached grid (`None` until baselined
    // or after exit), and the label fields for a pending/exited placeholder. Populated by the App
    // from `compute_split_layout` + `Shared::panes`; empty for the two-pane case, so the existing
    // active+sibling path stays byte-identical. `render` paints each entry clipped/offset to its
    // region (or a placeholder when it has no live grid).
    extra_panes: Vec<ExtraPanePaint>,
    // Dividers to draw for the extra panes (every divider of `compute_split_layout` beyond the single
    // two-pane divider the `split_frame` path already draws). Empty for the two-pane case.
    extra_dividers: Vec<crate::RendererSplitDivider>,
    // Window-grid region of the focused split pane to draw a subtle border around. `None` (no split,
    // or focus not resolvable) draws nothing, so the single-pane view stays byte-identical. Set by the
    // App from `focused_pane_region`; display-only chrome — it never changes pane geometry or routing.
    focus_indicator: Option<crate::RendererPaneRegion>,
    // Window-grid regions of every INACTIVE (non-focused) split pane to lay a subtle dim overlay over.
    // Empty (no split, or a zoomed full-window pane) draws nothing, so the single-pane and zoomed views
    // stay byte-identical. Set by the App from `inactive_pane_regions`; display-only chrome — it never
    // changes pane geometry, clipping, or input routing.
    inactive_dims: Vec<crate::RendererPaneRegion>,
    // Window-grid region of the pane currently hovered as a drop target during a pane drag-to-swap,
    // or `None` when no pane is being dragged (or the cursor is over no pane). Set by the App each
    // frame from the live drag state + cursor; `None` clears it so the highlight never outlives the
    // gesture. Display-only chrome — it never changes pane geometry, clipping, or input routing.
    drop_highlight: Option<DropHighlight>,

    // Instrumentation: when true (MAESTRO_RENDER_STATS=1), `render` measures
    // per-frame cost and prints a one-line stats summary. Off by default and on the
    // hot path it is a single bool check, so production frames pay nothing.
    stats_enabled: bool,
    frame_index: u64,
}

/// Per-frame render cost, populated only when stats are enabled. Counters answer the
/// where a frame's time goes: how many cells we touched, how many
/// cosmic-text buffers/TextAreas we built, how many quads we emitted, and the wall time
/// of the expensive sub-phases (text shaping/prepare, GPU submit+present).
#[derive(Default, Clone, Copy)]
struct FrameStats {
    nonblank_cells: u32,
    glyph_buffers_built: u32,
    text_areas: u32,
    decoration_quads: u32,
    background_quads: u32,
    /// Microseconds building + shaping per-cell glyph buffers (the suspected hot spot).
    glyph_build_us: u128,
    /// Microseconds in `TextRenderer::prepare` (atlas upload + layout).
    text_prepare_us: u128,
    /// CPU-side microseconds spent in `queue.submit` + `frame.present()` — i.e. the
    /// cost of ENQUEUING the frame's command buffer and scheduling the swapchain
    /// present. This is NOT GPU execution time: those calls return once the work is
    /// handed to the driver; the GPU renders asynchronously afterward (and present
    /// may block on vsync/swapchain availability rather than on draw work). Measuring
    /// true GPU time would require timestamp queries, which are not enabled here.
    submit_present_cpu_us: u128,
    /// Total microseconds for the whole `render` call.
    frame_total_us: u128,
}

impl Renderer {
    /// macOS/winit constructor — UNCHANGED. Builds the WGPU surface from the winit window and keeps the window
    /// for scale-factor reads. The Linux DashboardHost path uses [`Renderer::new_for_linux_host`] instead; the
    /// two share the same post-surface setup via [`Renderer::finish_new`] so no macOS semantics change.
    #[cfg(not(target_os = "linux"))]
    pub fn new(
        window: Arc<Window>,
        font_size_px: Option<u32>,
        theme: Option<crate::RendererTheme>,
    ) -> Self {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: wgpu::Backends::PRIMARY,
            ..Default::default()
        });
        // Byte-identical to the historical path: WGPU surface from the winit window.
        let surface = instance
            .create_surface(window.clone())
            .expect("create surface");
        let initial_size = window.inner_size();
        Self::finish_new(
            instance,
            surface,
            WindowHandleForRenderer::Winit(window),
            (initial_size.width, initial_size.height),
            font_size_px,
            theme,
        )
    }

    /// Linux/DashboardHost constructor: the Tao/GTK adapter owns the window and hands the renderer a GTK-owned
    /// child present target (Wayland `wl_subsurface` / X11 child XID) plus the terminal-slot geometry + scale.
    /// WGPU presents into that child surface, never the WebKit top-level. Shares [`Renderer::finish_new`] with
    /// macOS so the post-surface setup is identical.
    #[cfg(target_os = "linux")]
    pub fn new_for_linux_host(
        target: &crate::linux_host::TerminalPresentTarget,
        width: u32,
        height: u32,
        scale: f32,
        font_size_px: Option<u32>,
        theme: Option<crate::RendererTheme>,
    ) -> Self {
        let instance = wgpu::Instance::new(wgpu::InstanceDescriptor {
            backends: wgpu::Backends::PRIMARY,
            ..Default::default()
        });
        let (raw_display_handle, raw_window_handle) = target.raw_handles();
        // SAFETY: the present target keeps the native child surface (and its GDK connection) alive for the
        // renderer's lifetime, and the handles refer to it.
        let surface = unsafe {
            instance
                .create_surface_unsafe(wgpu::SurfaceTargetUnsafe::RawHandle {
                    raw_display_handle,
                    raw_window_handle,
                })
                .expect("create surface (linux host child)")
        };
        Self::finish_new(
            instance,
            surface,
            WindowHandleForRenderer::LinuxHost {
                scale,
                is_wayland: target.is_wayland(),
            },
            (width.max(1), height.max(1)),
            font_size_px,
            theme,
        )
    }

    /// Post-surface setup shared by both constructors (adapter/device/pipeline/atlas/config). Kept semantically
    /// identical to the original single `new` body so macOS behavior is unchanged; only the surface + the
    /// scale/window source differ by platform.
    fn finish_new(
        instance: wgpu::Instance,
        surface: wgpu::Surface<'static>,
        window_handle: WindowHandleForRenderer,
        initial_size: (u32, u32),
        font_size_px: Option<u32>,
        theme: Option<crate::RendererTheme>,
    ) -> Self {
        let resolved_theme = theme.unwrap_or(theme::RendererTheme::BuiltInDark);
        let palette = match theme {
            Some(t) => theme::palette(t),
            None => theme::default_palette(),
        };
        #[cfg(target_os = "linux")]
        let power_preference = LINUX_RENDERER_POWER_PREFERENCE;
        #[cfg(not(target_os = "linux"))]
        let power_preference = wgpu::PowerPreference::HighPerformance;
        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference,
            compatible_surface: Some(&surface),
            force_fallback_adapter: false,
        }))
        .expect("request adapter");
        #[cfg(target_os = "linux")]
        let adapter_info = adapter.get_info();
        #[cfg(target_os = "linux")]
        {
            let info = &adapter_info;
            eprintln!(
                "maestro-renderer: linux adapter name={:?} vendor={:#x} device={:#x} \
                 device_type={:?} backend={:?} driver={:?}",
                info.name, info.vendor, info.device, info.device_type, info.backend, info.driver
            );
        }
        let adapter_limits = adapter.limits();
        let required_limits = renderer_required_limits(adapter_limits.clone());
        let max_surface_dim = required_limits.max_texture_dimension_2d;
        // One concise startup line: the chosen surface limit is the first thing to check
        // when a fullscreen/maximize size is refused.
        eprintln!(
            "maestro-renderer: max_texture_dimension_2d adapter={} requested={}",
            adapter_limits.max_texture_dimension_2d, max_surface_dim
        );
        let (device, queue) = pollster::block_on(adapter.request_device(
            &wgpu::DeviceDescriptor {
                label: Some("maestro-device"),
                required_features: wgpu::Features::empty(),
                required_limits,
                memory_hints: wgpu::MemoryHints::Performance,
            },
            None,
        ))
        .expect("request device");

        let (init_w, init_h) = initial_size;
        let width = init_w.max(1);
        let height = init_h.max(1);
        let caps = surface.get_capabilities(&adapter);
        let format = caps
            .formats
            .iter()
            .copied()
            .find(|f| f.is_srgb())
            .unwrap_or(caps.formats[0]);
        #[cfg(target_os = "linux")]
        let present_mode = linux_surface_present_mode(
            window_handle.linux_is_wayland(),
            adapter_info.vendor,
            adapter_info.backend,
            &caps.present_modes,
        );
        #[cfg(not(target_os = "linux"))]
        let present_mode = wgpu::PresentMode::Fifo;
        #[cfg(target_os = "linux")]
        eprintln!(
            "maestro-renderer: present_mode={present_mode:?} supported={:?}",
            caps.present_modes
        );
        let config = wgpu::SurfaceConfiguration {
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
            format,
            width,
            height,
            present_mode,
            alpha_mode: caps.alpha_modes[0],
            view_formats: vec![],
            desired_maximum_frame_latency: 2,
        };
        surface.configure(&device, &config);
        #[cfg(target_os = "linux")]
        eprintln!(
            "maestro-renderer: surface configured width={} height={} present_mode={present_mode:?}",
            config.width, config.height
        );

        // --- glyphon setup ---
        let mut font_system = FontSystem::new();
        let swash_cache = SwashCache::new();
        let cache = Cache::new(&device);
        let mut atlas = TextAtlas::new(&device, &queue, &cache, format);
        let text_renderer =
            TextRenderer::new(&mut atlas, &device, wgpu::MultisampleState::default(), None);
        let viewport = Viewport::new(&device, &cache);

        // Measure monospace cell metrics with a probe buffer. The launch caller resolves the size
        // from persisted settings; `None` keeps the historical default (`DEFAULT_FONT_SIZE_PX`).
        let font_size = font_size_px.unwrap_or(crate::DEFAULT_FONT_SIZE_PX) as f32;
        let line_height = (font_size * 1.25).round();
        let (cell_w, cell_h) = measure_cell(&mut font_system, font_size, line_height);

        // --- quad pipeline ---
        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("quad-shader"),
            source: wgpu::ShaderSource::Wgsl(QUAD_WGSL.into()),
        });
        let screen_buf = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("screen-uniform"),
            contents: bytemuck::cast_slice(&[ScreenUniform {
                size: [width as f32, height as f32],
                _pad: [0.0, 0.0],
            }]),
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
        });
        let bind_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("quad-bind-layout"),
            entries: &[wgpu::BindGroupLayoutEntry {
                binding: 0,
                visibility: wgpu::ShaderStages::VERTEX,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Uniform,
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            }],
        });
        let quad_bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("quad-bind"),
            layout: &bind_layout,
            entries: &[wgpu::BindGroupEntry {
                binding: 0,
                resource: screen_buf.as_entire_binding(),
            }],
        });
        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("quad-pl"),
            bind_group_layouts: &[&bind_layout],
            push_constant_ranges: &[],
        });
        let quad_pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("quad-pipeline"),
            layout: Some(&pipeline_layout),
            vertex: wgpu::VertexState {
                module: &shader,
                entry_point: "vs_main",
                compilation_options: Default::default(),
                buffers: &[wgpu::VertexBufferLayout {
                    array_stride: std::mem::size_of::<QuadInstance>() as wgpu::BufferAddress,
                    step_mode: wgpu::VertexStepMode::Instance,
                    attributes: &[
                        wgpu::VertexAttribute {
                            offset: 0,
                            shader_location: 0,
                            format: wgpu::VertexFormat::Float32x4,
                        },
                        wgpu::VertexAttribute {
                            offset: 16,
                            shader_location: 1,
                            format: wgpu::VertexFormat::Float32x4,
                        },
                    ],
                }],
            },
            fragment: Some(wgpu::FragmentState {
                module: &shader,
                entry_point: "fs_main",
                compilation_options: Default::default(),
                targets: &[Some(wgpu::ColorTargetState {
                    format,
                    blend: Some(wgpu::BlendState::ALPHA_BLENDING),
                    write_mask: wgpu::ColorWrites::ALL,
                })],
            }),
            primitive: wgpu::PrimitiveState::default(),
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            multiview: None,
            cache: None,
        });

        let instance_cap = 4096;
        let instance_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("quad-instances"),
            size: (instance_cap * std::mem::size_of::<QuadInstance>()) as wgpu::BufferAddress,
            usage: wgpu::BufferUsages::VERTEX | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        Renderer {
            #[cfg(not(target_os = "linux"))]
            window: window_handle.into_winit_window(),
            #[cfg(target_os = "linux")]
            linux_scale: window_handle.linux_scale(),
            surface,
            device,
            queue,
            config,
            max_surface_dim,
            quad_pipeline,
            quad_bind_group,
            screen_buf,
            instance_buf,
            instance_cap,
            instance_count: 0,
            font_system,
            swash_cache,
            atlas,
            text_renderer,
            viewport,
            cell_w,
            cell_h,
            font_size,
            line_height,
            theme: resolved_theme,
            palette,
            glyph_cache: HashMap::new(),
            scale_at_shape: 0.0,
            top_bar: None,
            grid_origin_y: 0.0,
            grid_origin_x: 0.0,
            dock_width_x: 0.0,
            dock_rows: Vec::new(),
            dock_collapsed: false,
            top_bar_hover: None,
            dashboard_panel: Vec::new(),
            remote_controls_available: false,
            remote_open: false,
            winsize_owner_remote: false,
            dashboard_panel_origin_y: 0.0,
            dashboard_panel_accent: None,
            picker_overlay: Vec::new(),
            command_palette_overlay: Vec::new(),
            shortcut_hint_overlay: Vec::new(),
            file_preview_overlay: Vec::new(),
            file_path_input_overlay: Vec::new(),
            split_frame: None,
            split_sibling_status: SiblingPaneStatus::Detached,
            sibling_grid: None,
            extra_panes: Vec::new(),
            extra_dividers: Vec::new(),
            focus_indicator: None,
            inactive_dims: Vec::new(),
            drop_highlight: None,
            stats_enabled: std::env::var_os("MAESTRO_RENDER_STATS").is_some_and(|v| v == "1"),
            frame_index: 0,
        }
    }

    pub fn cell_size_logical(&self) -> (f32, f32) {
        (self.cell_w, self.cell_h)
    }

    /// The window's current DPI scale factor, so callers can convert logical cell metrics to the
    /// physical pixels the draw path uses (e.g. to size the reserved top tab-bar row). macOS reads the winit
    /// window (unchanged); Linux reads the GTK-terminal-widget scale the DashboardHost feeds in.
    #[cfg(not(target_os = "linux"))]
    pub fn window_scale_factor(&self) -> f32 {
        self.window.scale_factor() as f32
    }

    #[cfg(target_os = "linux")]
    pub fn window_scale_factor(&self) -> f32 {
        self.linux_scale
    }

    /// Set (or clear) the opt-in top tab bar AND the terminal grid origin for subsequent frames.
    /// `Some(layout)` reserves one physical cell row at the top; `None` clears the tab bar. The grid is
    /// always shifted down by `grid_origin_y` (in physical pixels) REGARDLESS of whether a tab bar is
    /// present, because top chrome can also include a surface-owned React band and dashboard-panel rows.
    /// The caller owns the contract: it passes the total effective top-chrome offset and passes `0.0`
    /// when the terminal owns the whole surface, so the grid begins at the surface top.
    /// `hovered_tab_id` is the visible tab the cursor is over (display-only): it tints a hovered INACTIVE
    /// tab and is ignored when the bar is `None`.
    pub fn set_top_bar(
        &mut self,
        layout: Option<crate::RendererTabBarLayout>,
        grid_origin_y: f32,
        hovered_tab_id: Option<String>,
    ) {
        self.top_bar = layout;
        self.grid_origin_y = grid_origin_y.max(0.0);
        self.top_bar_hover = if self.top_bar.is_some() {
            hovered_tab_id
        } else {
            None
        };
    }

    /// Set the terminal grid's LEFT origin (in physical pixels) for subsequent frames. The origin may
    /// include both app chrome and terminal-only padding; actual dock painting is controlled separately
    /// by [`Self::set_dock_width_x`]. Kept separate from `set_top_bar` so vertical geometry is untouched.
    pub fn set_grid_origin_x(&mut self, grid_origin_x: f32) {
        self.grid_origin_x = grid_origin_x.max(0.0);
    }

    /// Set the actual left-dock width in physical pixels. This controls only dock fill/rows/button and
    /// deliberately does not move terminal cells; the App supplies the combined terminal origin through
    /// [`Self::set_grid_origin_x`].
    pub fn set_dock_width_x(&mut self, dock_width_x: f32) {
        self.dock_width_x = dock_width_x.max(0.0);
    }

    /// Hand the renderer the left-dock rows (in draw order) and the collapsed flag for subsequent
    /// frames. Independent of `set_grid_origin_x`; actual chrome width comes from `set_dock_width_x`,
    /// while a larger grid origin may include terminal-only padding. An empty `rows` vec draws only the
    /// dock fill. Display-only: the renderer paints, never mutates, these rows.
    pub fn set_dock_rows(&mut self, rows: Vec<crate::RendererDockRow>, collapsed: bool) {
        self.dock_rows = rows;
        self.dock_collapsed = collapsed;
    }

    /// The configured surface size in physical pixels (`width`, `height`). Lets the App derive the
    /// drawable column count for fitting dashboard-panel lines from the same metrics the draw path
    /// uses, so what the panel fits equals what is painted.
    pub fn surface_size_physical(&self) -> (u32, u32) {
        (self.config.width, self.config.height)
    }

    /// Set (or clear) the opt-in read-only dashboard panel for subsequent frames. `lines` is the
    /// already-fitted, control-char-free text for each reserved panel row (one String per row, in
    /// draw order); `origin_y` is the physical pixel y the first panel row is painted at (the tab-bar
    /// height, or 0.0 when no tab bar). `None`/empty draws nothing and restores the byte-identical
    /// path. The origin may also include a surface-owned React top inset. The App reserves the matching
    /// space via its canonical grid origin, so the panel never overpaints the grid. The panel is
    /// display-only: no hit testing, hover, or click handling.
    pub fn set_dashboard_panel(
        &mut self,
        lines: Option<Vec<String>>,
        origin_y: f32,
        accent: Option<theme::Rgb>,
    ) {
        self.dashboard_panel = lines.unwrap_or_default();
        self.dashboard_panel_origin_y = origin_y.max(0.0);
        self.dashboard_panel_accent = accent;
    }

    /// Show or hide optional Remote presentation. Hidden is the fail-closed default for a local-only
    /// build or an absent/incompatible private extension.
    pub fn set_remote_controls_available(&mut self, available: bool) {
        self.remote_controls_available = available;
    }

    pub fn remote_controls_available(&self) -> bool {
        self.remote_controls_available
    }

    /// Update the display-only remote-access state supplied by the optional extension.
    pub fn set_remote_open(&mut self, open: bool) {
        self.remote_open = open;
    }

    /// The current remote-access UI state (for click handling: toggling flips this).
    pub fn remote_open(&self) -> bool {
        self.remote_open
    }

    /// Update the winsize-owner toggle state (drives the tab-bar button label + status dot).
    pub fn set_winsize_owner_remote(&mut self, remote: bool) {
        self.winsize_owner_remote = remote;
    }

    /// Current winsize-owner UI state (for click handling: toggling flips this).
    pub fn winsize_owner_remote(&self) -> bool {
        self.winsize_owner_remote
    }

    /// Set (or clear) the foreground read-only picker overlay for subsequent frames. `lines` is the
    /// already-composed, control-char-free text for each row in deterministic draw order. `None`/empty
    /// draws nothing and restores the byte-identical path. When non-empty the overlay is painted OVER
    /// the grid (dim backdrop + rows from physical y=0). Row hit-testing and dismissal are owned by the
    /// App; the renderer only draws and never re-sorts.
    pub fn set_picker_overlay(&mut self, lines: Option<Vec<String>>) {
        self.picker_overlay = lines.unwrap_or_default();
    }

    /// Set (or clear) the foreground read-only command-palette overlay for subsequent frames. `lines`
    /// is the already-composed, control-char-free text for each row in deterministic draw order.
    /// `None`/empty draws nothing and restores the byte-identical path. When non-empty the overlay is
    /// painted OVER the grid (dim backdrop + rows from physical y=0), reusing the picker overlay draw
    /// style but kept as a SEPARATE carrier so the two never alias. Display-only: no hit testing,
    /// dismissal, or events; the renderer only draws and never re-sorts.
    pub fn set_command_palette_overlay(
        &mut self,
        lines: Option<Vec<RendererCommandPaletteOverlayLine>>,
    ) {
        self.command_palette_overlay = lines.unwrap_or_default();
    }

    /// Set (or clear) the foreground read-only split-pane shortcut hint overlay for subsequent frames.
    /// `lines` is the already-composed, control-char-free text for each row in deterministic draw order.
    /// `None`/empty draws nothing and restores the byte-identical path. When non-empty the overlay is
    /// painted OVER the grid (one opaque band per row from physical y=0) but WITHOUT a full-window dim
    /// backdrop — it is a non-modal hint, so the grid stays visible behind it. Display-only: no hit
    /// testing, dismissal, or events; the renderer only draws and never re-sorts.
    pub fn set_shortcut_hint_overlay(
        &mut self,
        lines: Option<Vec<RendererCommandPaletteOverlayLine>>,
    ) {
        self.shortcut_hint_overlay = lines.unwrap_or_default();
    }

    /// Set (or clear) the read-only file-preview overlay for subsequent frames. `lines` is the
    /// already-composed, control-char-free text for each preview row (header + bounded body +
    /// truncation marker) in draw order, produced by the App via
    /// [`compose_file_preview_lines`](crate::compose_file_preview_lines). `None`/empty draws nothing and
    /// restores the byte-identical path. When non-empty the band is painted OVER the grid anchored to
    /// the RIGHT half of the window (one opaque row per line from physical y=0) WITHOUT a full-window
    /// dim backdrop — the grid stays visible. Display-only: no hit testing, dismissal, or events; the
    /// renderer only draws and never re-sorts.
    pub fn set_file_preview_overlay(
        &mut self,
        lines: Option<Vec<RendererCommandPaletteOverlayLine>>,
    ) {
        self.file_preview_overlay = lines.unwrap_or_default();
    }

    /// Set (or clear) the read-only file-path-input prompt band for subsequent frames. `lines` is the
    /// already-composed, control-char-free prompt row(s) produced by the App via
    /// [`file_path_input_prompt_line`](crate::file_path_input_prompt_line). `None`/empty draws nothing
    /// and restores the byte-identical path. When non-empty the band is painted OVER the grid anchored
    /// to the BOTTOM of the window (one opaque row per line) WITHOUT a full-window dim backdrop — the
    /// grid stays visible. Display-only: the prompt's key capture lives in the App; the renderer only
    /// draws and never re-sorts.
    pub fn set_file_path_input_overlay(
        &mut self,
        lines: Option<Vec<RendererCommandPaletteOverlayLine>>,
    ) {
        self.file_path_input_overlay = lines.unwrap_or_default();
    }

    /// Set (or clear) the opt-in split-pane frame for subsequent frames. `frame` is the one top-level
    /// split the active tab participates in (its source/child pair, even cell regions, and the dividing
    /// line), as computed by the App via [`compute_split_frame`](crate::compute_split_frame). When
    /// `Some`, the renderer paints the divider line into the grid quad scene at `divider.col`/
    /// `divider.row`; `None`/no-frame draws nothing and keeps every existing path byte-identical.
    /// Advisory geometry only — the active PTY viewport stays the single rendered terminal grid; no
    /// second session is drawn into the regions yet.
    pub fn set_split_frame(
        &mut self,
        frame: Option<crate::RendererSplitFrame>,
        sibling_status: SiblingPaneStatus,
    ) {
        self.split_frame = frame;
        self.split_sibling_status = sibling_status;
    }

    /// Set (or clear) the cached sibling grid painted into the inactive split pane for subsequent
    /// frames. `grid` is the App's snapshot of the inactive pane's sibling session (from
    /// `Shared::sibling`), passed only when a sibling is bound and has NOT exited. When `Some`,
    /// `render` paints it clipped/offset to the inactive pane region in place of the placeholder
    /// band/label; `None` restores the placeholder and keeps the no-sibling path byte-identical.
    pub fn set_sibling_grid(&mut self, grid: Option<std::sync::Arc<GridSnapshot>>) {
        self.sibling_grid = grid;
    }

    /// Set (or clear) the extra non-active panes of a 3+-pane split layout and their dividers for
    /// subsequent frames. `panes` are every visible pane beyond the active pane and the rendered
    /// sibling (each with its absolute region, cached grid, and placeholder label data); `dividers`
    /// are every layout divider beyond the single two-pane divider the `split_frame` path draws.
    /// Both empty for the two-pane case, so the existing active+sibling paint stays byte-identical.
    /// `render` paints each pane's cached grid clipped/offset to its region, or a pending/exited
    /// placeholder when it has no live grid.
    pub fn set_extra_panes(
        &mut self,
        panes: Vec<ExtraPanePaint>,
        dividers: Vec<crate::RendererSplitDivider>,
    ) {
        self.extra_panes = panes;
        self.extra_dividers = dividers;
    }

    /// Set (or clear) the focused-pane indicator region for subsequent frames. `region` is the
    /// window-grid region of the pane that owns current session focus (resolved by the App via
    /// `focused_pane_region`, with stale focus falling back to the active/root pane). When `Some`,
    /// `render` draws a subtle translucent border around that region so the focused split pane is
    /// obvious; `None` (no split, or focus unresolvable) draws nothing, keeping the single-pane view
    /// byte-identical. Display-only chrome — it never changes pane geometry, clipping, or input routing.
    pub fn set_focus_indicator(&mut self, region: Option<crate::RendererPaneRegion>) {
        self.focus_indicator = region;
    }

    /// Set (or clear) the inactive-pane dim regions for subsequent frames. `regions` are the window-grid
    /// regions of every non-focused split pane (resolved by the App via `inactive_pane_regions`, with
    /// stale focus falling back to the active/root pane). When non-empty, `render` lays a subtle
    /// translucent tint over each, drawn UNDER the focus indicator so the focused pane and its border
    /// stay fully readable; empty (no split, or a zoomed full-window pane) draws nothing, keeping the
    /// single-pane and zoomed views byte-identical. Display-only chrome — it never changes pane geometry,
    /// clipping, or input routing.
    pub fn set_inactive_dims(&mut self, regions: Vec<crate::RendererPaneRegion>) {
        self.inactive_dims = regions;
    }

    /// Set (or clear) the pane drag-to-swap drop-target highlight for subsequent frames. `region` is
    /// the window-grid region of the pane the cursor currently hovers during a pane drag (resolved by
    /// the App via `layout_pane_at_cell`), or `None` when no pane is being dragged or the cursor is
    /// over no pane. When `Some`, `render` lays a brighter translucent tint over that pane so the user
    /// sees the swap target; `None` draws nothing. Display-only chrome — it never changes pane
    /// geometry, clipping, or input routing.
    pub fn set_drop_highlight(&mut self, region: Option<DropHighlight>) {
        self.drop_highlight = region;
    }

    /// Swap the live color `theme` in place: re-resolve the palette so subsequent frames paint with the
    /// new colors. Color-only — cell metrics, grid geometry, scrollback, selection, and all chrome are
    /// untouched. Idempotent: re-applying the active theme is a no-op (the stored `theme` short-circuits).
    pub fn set_theme(&mut self, theme: theme::RendererTheme) {
        if self.theme == theme {
            return;
        }
        self.theme = theme;
        self.palette = theme::palette(theme);
    }

    /// Re-apply the font size in place: re-derive `line_height`, re-measure the cell, and drop the
    /// shaped-glyph cache (its buffers were shaped at the OLD metrics). Unlike `set_theme` this changes
    /// cell metrics, so the caller MUST reflow the PTY afterward (the App drives the existing
    /// window-resize path, which reads `cell_size_logical`). Idempotent: re-applying the active size is
    /// a no-op. The DPI `scale` is applied per-frame at shape time (see `render`), so this stores only
    /// the logical metric — exactly like `Renderer::new`.
    pub fn set_font_size(&mut self, px: u32) {
        let font_size = px as f32;
        if self.font_size == font_size {
            return;
        }
        self.font_size = font_size;
        self.line_height = (font_size * 1.25).round();
        let (cell_w, cell_h) = measure_cell(&mut self.font_system, font_size, self.line_height);
        self.cell_w = cell_w;
        self.cell_h = cell_h;
        // Cached buffers were shaped at the old font metrics; the per-frame scale-change guard would NOT
        // catch a pure font-size change (scale is unchanged), so clear here.
        self.glyph_cache.clear();
    }

    pub fn resize(&mut self, width: u32, height: u32) {
        if width == 0 || height == 0 {
            return;
        }
        // Defense in depth: `Surface::configure` validates against the DEVICE limit and
        // a violation is a non-unwinding abort. With `renderer_required_limits` this
        // should never trigger on a real display, but if it does, keep the previous
        // (valid) surface and log instead of crashing the terminal.
        if width > self.max_surface_dim || height > self.max_surface_dim {
            eprintln!(
                "maestro-renderer: refusing surface resize {width}x{height}: exceeds device \
                 max_texture_dimension_2d={}; keeping previous size {}x{}",
                self.max_surface_dim, self.config.width, self.config.height
            );
            return;
        }
        self.config.width = width;
        self.config.height = height;
        self.surface.configure(&self.device, &self.config);
        self.queue.write_buffer(
            &self.screen_buf,
            0,
            bytemuck::cast_slice(&[ScreenUniform {
                size: [width as f32, height as f32],
                _pad: [0.0, 0.0],
            }]),
        );
    }

    /// Paint one frame. `grid` is the latest authoritative snapshot (None ->
    /// clear to background). `overlay` is an optional status-line text. `selection`
    /// is the optional `(anchor, focus)` cell range to highlight (order independent).
    pub fn render(
        &mut self,
        grid: Option<&GridSnapshot>,
        overlay: Option<&str>,
        selection: Option<(CellPos, CellPos)>,
    ) {
        let frame_start = self.stats_enabled.then(Instant::now);
        let mut stats = FrameStats::default();

        let scale = self.window_scale_factor();
        let cw = self.cell_w * scale;
        let ch = self.cell_h * scale;
        // Physical pixel offset the terminal grid is painted down by, so the reserved top tab-bar
        // row is not overpainted. 0.0 unless the opt-in top bar is active.
        let oy = self.grid_origin_y;
        // Resolve actual app chrome separately from the terminal origin. The terminal is never allowed
        // to overpaint the dock even if a future caller sets the two out of order; any intentional
        // difference is the subtle terminal-background padding. Every grid/cursor/selection X derives
        // from this one `ox` below.
        let (dock_w, ox) = resolved_horizontal_origins(
            self.dock_width_x,
            self.grid_origin_x,
            self.config.width as f32,
        );

        // Active-pane clip: when a split frame exists, the active PTY grid is painted ONLY inside the
        // active tab's pane (offset by the pane's top-left cell, bounded by its cell extent). `None`
        // keeps the byte-identical full-grid path (offset 0, no cell bound). The sibling pane is left as
        // a placeholder (drawn after the grid). One PTY grid only — the inactive pane has no session yet.
        let active_pane = self.split_frame.as_ref().map(crate::active_pane_region);
        let (pane_col, pane_row) = active_pane.map_or((0u16, 0u16), |p| (p.col, p.row));
        let pane_off_x = pane_col as f32 * cw + ox;
        let pane_off_y = pane_row as f32 * ch;
        let active_pixel_clip = active_pane.map(|pane| pane_pixel_rect(pane, cw, ch, ox, oy));
        let active_text_clip = active_pane.map(|pane| pane_text_clip(pane, 0, cw, ch, ox, oy));

        // Inactive (sibling) pane: when a split frame is set AND a cached sibling grid is available,
        // we paint that grid clipped/offset to the inactive pane region in place of the placeholder.
        // `paint_sibling_grid`/`show_placeholder` are the mutually-exclusive decision; `sibling` is
        // `Some(region)` only when painting the grid (the sibling grid's cells are pane-local (0,0),
        // so they offset by the region's top-left). `show_placeholder` gates the band/label below.
        let (paint_sibling_grid, show_placeholder) =
            sibling_paint_decision(self.split_frame.is_some(), self.sibling_grid.is_some());
        let sibling = self
            .split_frame
            .as_ref()
            .filter(|_| paint_sibling_grid)
            .map(crate::inactive_pane_region);
        let sib_off_x = sibling.map_or(ox, |p| p.col as f32 * cw + ox);
        let sib_off_y = sibling.map_or(0.0, |p| p.row as f32 * ch);
        let sibling_pixel_clip = sibling.map(|pane| pane_pixel_rect(pane, cw, ch, ox, oy));
        let sibling_text_clip = sibling.map(|pane| pane_text_clip(pane, 0, cw, ch, ox, oy));

        // --- build background + cursor quads ---
        let mut quads: Vec<QuadInstance> = Vec::new();
        let bg = self.palette.background;
        quads.push(QuadInstance {
            rect: [
                0.0,
                0.0,
                self.config.width as f32,
                self.config.height as f32,
            ],
            color: rgba(bg, 1.0),
        });

        if let Some(g) = grid {
            for (row, cells) in g.rows_cells.iter().enumerate() {
                for (col, cell) in cells.iter().enumerate() {
                    if cell.width == 0 {
                        continue; // wide spacer
                    }
                    // Clip the active PTY grid to the active pane when a split frame is set.
                    if !cell_in_pane(col, row, active_pane) {
                        continue;
                    }
                    let (cfg, cbg) = resolved_colors(cell, &self.palette);
                    // Skip painting cells whose bg equals the global bg (cheap win).
                    let span = if cell.width == 2 { 2.0 } else { 1.0 };
                    let x = col as f32 * cw + pane_off_x;
                    let y = row as f32 * ch + oy + pane_off_y;
                    if cbg != bg {
                        if let Some(rect) =
                            clip_rect_to_pixel_bounds([x, y, cw * span, ch], active_pixel_clip)
                        {
                            quads.push(QuadInstance {
                                rect,
                                color: rgba(cbg, 1.0),
                            });
                            stats.background_quads += 1;
                        }
                    }
                    // Text decorations (underline / double / dotted / dashed / curly
                    // approximation / strikeout) drawn as fg-colored bars over the cell.
                    // Hidden cells draw none (their fg == bg anyway).
                    if !cell.hidden && (cell.underline != UnderlineStyle::None || cell.strikeout) {
                        for rect in decoration_rects(
                            cell.underline,
                            cell.strikeout,
                            x,
                            y,
                            cw * span,
                            ch,
                            scale,
                        ) {
                            if let Some(rect) = clip_rect_to_pixel_bounds(rect, active_pixel_clip) {
                                quads.push(QuadInstance {
                                    rect,
                                    color: rgba(cfg, 1.0),
                                });
                                stats.decoration_quads += 1;
                            }
                        }
                    }
                }
            }
            // cursor rect — only when inside the active pane (clipped like the grid cells).
            if g.cursor_visible
                && g.cursor_line < g.rows
                && g.cursor_col < g.cols
                && cell_in_pane(g.cursor_col, g.cursor_line, active_pane)
            {
                let x = g.cursor_col as f32 * cw + pane_off_x;
                let y = g.cursor_line as f32 * ch + oy + pane_off_y;
                let ccolor = self.palette.cursor;
                let rect = match g.cursor_shape {
                    CursorShape::Block => [x, y, cw, ch],
                    CursorShape::Underline => [x, y + ch - (2.0 * scale), cw, 2.0 * scale],
                    CursorShape::Beam => [x, y, 2.0 * scale, ch],
                };
                if let Some(rect) = clip_rect_to_pixel_bounds(rect, active_pixel_clip) {
                    quads.push(QuadInstance {
                        rect,
                        color: rgba(ccolor, 0.7),
                    });
                }
            }

            // Selection highlight: translucent rects under the text, clamped to the
            // painted grid. Row-major contiguous range (first row from anchor col to
            // row end, full intermediate rows, last row to focus col).
            if let Some((a, b)) = selection {
                let sel_color = rgba(
                    [SELECTION_RGB.0, SELECTION_RGB.1, SELECTION_RGB.2],
                    SELECTION_ALPHA,
                );
                for mut rect in selection_rects(g, a, b, cw, ch) {
                    rect[0] += pane_off_x;
                    rect[1] += oy + pane_off_y;
                    // Clip the selection to the active pane (no-op when there is no split frame).
                    if let Some(rect) =
                        clip_rect_to_pane(rect, active_pane, pane_off_x, oy + pane_off_y, cw, ch)
                    {
                        quads.push(QuadInstance {
                            rect,
                            color: sel_color,
                        });
                    }
                }
            }

            // --- split-pane divider (opt-in) ---
            // When the active tab participates in a split, paint the one dividing line into the grid
            // quad scene (over the offset grid, below the top chrome). Drawn only with a grid present so
            // the line tracks the painted viewport; the regions themselves carry no second session yet.
            if let Some(frame) = self.split_frame.as_ref() {
                // Inactive (sibling) pane placeholder: a quiet backing band over the sibling region so
                // it reads as a dormant pane (its label text is added in the glyph pass below). Drawn
                // BEFORE the divider so the divider line sits on top. Suppressed when a live sibling
                // grid is being painted into the region (`show_placeholder` is false).
                if show_placeholder {
                    let inactive = crate::inactive_pane_region(frame);
                    quads.push(QuadInstance {
                        rect: pane_pixel_rect(inactive, cw, ch, ox, oy),
                        color: rgba(SPLIT_PLACEHOLDER_BAND, 1.0),
                    });
                }
                let rect = split_divider_rect(&frame.divider, frame.axis, cw, ch, ox, oy);
                quads.push(QuadInstance {
                    rect,
                    color: rgba(SPLIT_DIVIDER_LINE, 1.0),
                });
            }
        }

        // --- sibling-pane grid backgrounds/decorations/cursor ---
        // When a split frame is set and a live sibling grid is cached, paint the sibling's grid into
        // the INACTIVE pane region (mirrors the active-grid quad pass above, but clipped/offset to the
        // sibling region). The sibling grid's cells are pane-local (0,0), so they offset by the region
        // top-left and clip to its cell extent. Drawn AFTER the active grid + divider so it sits within
        // its own region only; `sibling` is `None` (placeholder kept) when no sibling grid is available.
        if let (Some(sib_pane), Some(sib_g)) = (sibling, self.sibling_grid.as_ref()) {
            for (row, cells) in sib_g.rows_cells.iter().enumerate() {
                for (col, cell) in cells.iter().enumerate() {
                    if cell.width == 0 {
                        continue; // wide spacer
                    }
                    if !cell_in_pane(col, row, Some(sib_pane)) {
                        continue;
                    }
                    let (cfg, cbg) = resolved_colors(cell, &self.palette);
                    let span = if cell.width == 2 { 2.0 } else { 1.0 };
                    let x = col as f32 * cw + sib_off_x;
                    let y = row as f32 * ch + oy + sib_off_y;
                    if cbg != bg {
                        if let Some(rect) =
                            clip_rect_to_pixel_bounds([x, y, cw * span, ch], sibling_pixel_clip)
                        {
                            quads.push(QuadInstance {
                                rect,
                                color: rgba(cbg, 1.0),
                            });
                            stats.background_quads += 1;
                        }
                    }
                    if !cell.hidden && (cell.underline != UnderlineStyle::None || cell.strikeout) {
                        for rect in decoration_rects(
                            cell.underline,
                            cell.strikeout,
                            x,
                            y,
                            cw * span,
                            ch,
                            scale,
                        ) {
                            if let Some(rect) = clip_rect_to_pixel_bounds(rect, sibling_pixel_clip)
                            {
                                quads.push(QuadInstance {
                                    rect,
                                    color: rgba(cfg, 1.0),
                                });
                                stats.decoration_quads += 1;
                            }
                        }
                    }
                }
            }
            // Sibling cursor rect — clipped to the sibling pane just like the active cursor.
            if sib_g.cursor_visible
                && sib_g.cursor_line < sib_g.rows
                && sib_g.cursor_col < sib_g.cols
                && cell_in_pane(sib_g.cursor_col, sib_g.cursor_line, Some(sib_pane))
            {
                let x = sib_g.cursor_col as f32 * cw + sib_off_x;
                let y = sib_g.cursor_line as f32 * ch + oy + sib_off_y;
                let ccolor = self.palette.cursor;
                let rect = match sib_g.cursor_shape {
                    CursorShape::Block => [x, y, cw, ch],
                    CursorShape::Underline => [x, y + ch - (2.0 * scale), cw, 2.0 * scale],
                    CursorShape::Beam => [x, y, 2.0 * scale, ch],
                };
                if let Some(rect) = clip_rect_to_pixel_bounds(rect, sibling_pixel_clip) {
                    quads.push(QuadInstance {
                        rect,
                        color: rgba(ccolor, 0.7),
                    });
                }
            }
        }

        // --- extra non-active pane grids/backgrounds/decorations/cursors (3+-pane layout) ---
        // Each extra pane paints exactly like the sibling: its cached grid is pane-local (0,0), so it
        // offsets by the pane region's top-left and clips to its cell extent. A pane with no live grid
        // gets a placeholder backing band + label instead (drawn below). Empty for the two-pane case,
        // so this whole block is skipped and the active+sibling path stays byte-identical.
        for ep in &self.extra_panes {
            let region = ep.region;
            let off_x = region.col as f32 * cw + ox;
            // The header reserves the top row of the region (only for a real split pane that opts in
            // and is large enough), so the terminal content starts one row lower and the local clip
            // loses that row. A pane with no header keeps its full region — content at row 0.
            let header_rows = pane_header_rows_for(ep, cw, ch, oy);
            let off_y = (region.row + header_rows) as f32 * ch;
            // Region-local clip: the cached grid's cells are (0,0)-based and sized to the region MINUS
            // the header row, so we bound to the content rows (matching the sibling's
            // `cell_in_pane(.., 0,0-pane)`).
            let local = crate::RendererPaneRegion {
                col: 0,
                row: 0,
                cols: region.cols,
                rows: region.rows.saturating_sub(header_rows),
            };
            let content_pixel_clip = Some([
                off_x,
                oy + off_y,
                local.cols as f32 * cw,
                local.rows as f32 * ch,
            ]);
            match ep.grid.as_ref() {
                Some(g) => {
                    for (row, cells) in g.rows_cells.iter().enumerate() {
                        for (col, cell) in cells.iter().enumerate() {
                            if cell.width == 0 {
                                continue;
                            }
                            if !cell_in_pane(col, row, Some(local)) {
                                continue;
                            }
                            let (cfg, cbg) = resolved_colors(cell, &self.palette);
                            let span = if cell.width == 2 { 2.0 } else { 1.0 };
                            let x = col as f32 * cw + off_x;
                            let y = row as f32 * ch + oy + off_y;
                            if cbg != bg {
                                if let Some(rect) = clip_rect_to_pixel_bounds(
                                    [x, y, cw * span, ch],
                                    content_pixel_clip,
                                ) {
                                    quads.push(QuadInstance {
                                        rect,
                                        color: rgba(cbg, 1.0),
                                    });
                                    stats.background_quads += 1;
                                }
                            }
                            if !cell.hidden
                                && (cell.underline != UnderlineStyle::None || cell.strikeout)
                            {
                                for rect in decoration_rects(
                                    cell.underline,
                                    cell.strikeout,
                                    x,
                                    y,
                                    cw * span,
                                    ch,
                                    scale,
                                ) {
                                    if let Some(rect) =
                                        clip_rect_to_pixel_bounds(rect, content_pixel_clip)
                                    {
                                        quads.push(QuadInstance {
                                            rect,
                                            color: rgba(cfg, 1.0),
                                        });
                                        stats.decoration_quads += 1;
                                    }
                                }
                            }
                        }
                    }
                    // Split-pane local selection. App carries absolute window-grid cells so pointer
                    // routing, pane focus, and drawing share one coordinate space; translate only at
                    // this final paint boundary because the pane's cached grid is content-local.
                    if let Some((anchor, focus)) = ep.selection {
                        let anchor =
                            pane_local_selection_cell(anchor, region, header_rows, g.cols, g.rows);
                        let focus =
                            pane_local_selection_cell(focus, region, header_rows, g.cols, g.rows);
                        let sel_color = rgba(
                            [SELECTION_RGB.0, SELECTION_RGB.1, SELECTION_RGB.2],
                            SELECTION_ALPHA,
                        );
                        for mut rect in selection_rects(g, anchor, focus, cw, ch) {
                            rect[0] += off_x;
                            rect[1] += oy + off_y;
                            if let Some(rect) = clip_rect_to_pixel_bounds(rect, content_pixel_clip)
                            {
                                quads.push(QuadInstance {
                                    rect,
                                    color: sel_color,
                                });
                            }
                        }
                    }
                    if g.cursor_visible
                        && g.cursor_line < g.rows
                        && g.cursor_col < g.cols
                        && cell_in_pane(g.cursor_col, g.cursor_line, Some(local))
                    {
                        let x = g.cursor_col as f32 * cw + off_x;
                        let y = g.cursor_line as f32 * ch + oy + off_y;
                        let ccolor = self.palette.cursor;
                        let rect = match g.cursor_shape {
                            CursorShape::Block => [x, y, cw, ch],
                            CursorShape::Underline => [x, y + ch - (2.0 * scale), cw, 2.0 * scale],
                            CursorShape::Beam => [x, y, 2.0 * scale, ch],
                        };
                        if let Some(rect) = clip_rect_to_pixel_bounds(rect, content_pixel_clip) {
                            quads.push(QuadInstance {
                                rect,
                                color: rgba(ccolor, 0.7),
                            });
                        }
                    }
                }
                None => {
                    // No live grid (pending/exited): a quiet backing band so the pane reads as dormant;
                    // its label text is added in the glyph pass below.
                    quads.push(QuadInstance {
                        rect: pane_pixel_rect(region, cw, ch, ox, oy),
                        color: rgba(SPLIT_PLACEHOLDER_BAND, 1.0),
                    });
                }
            }
        }

        // --- extra dividers (every divider beyond the single two-pane divider) ---
        // Drawn from the layout's absolute-offset dividers, on top of the extra-pane grids/bands. Empty
        // for the two-pane case. The axis is recovered from each divider's chrome glyph.
        for divider in &self.extra_dividers {
            let rect = split_divider_rect(divider, divider_axis(divider), cw, ch, ox, oy);
            quads.push(QuadInstance {
                rect,
                color: rgba(SPLIT_DIVIDER_LINE, 1.0),
            });
        }

        // --- inactive-pane dim overlay (opt-in) ---
        // A subtle near-black translucent tint over every non-focused split pane so the focused pane
        // reads as the target. Drawn over the pane grids/placeholders/dividers but BEFORE the focus
        // indicator below, so the focused pane (never in this list) and its border stay fully readable.
        // Empty (no split, or a zoomed full-window pane) draws nothing, keeping those views unchanged.
        if !self.inactive_dims.is_empty() {
            let dim_color = rgba(
                [INACTIVE_DIM_RGB.0, INACTIVE_DIM_RGB.1, INACTIVE_DIM_RGB.2],
                INACTIVE_DIM_ALPHA,
            );
            for region in &self.inactive_dims {
                let rect = pane_pixel_rect(*region, cw, ch, ox, oy);
                if rect[2] <= 0.0 || rect[3] <= 0.0 {
                    continue;
                }
                quads.push(QuadInstance {
                    rect,
                    color: dim_color,
                });
            }
        }

        // --- pane drag-to-swap drop-target highlight (opt-in) ---
        // A brighter translucent tint over the pane the cursor hovers during a pane drag, so the user
        // sees which pane the dragged pane will swap with on release. Drawn OVER the inactive dim (a
        // dimmed target still highlights) but BEFORE the focus indicator. `None` (no drag, or cursor
        // over no pane) draws nothing, keeping every non-drag frame byte-identical.
        if let Some(highlight) = self.drop_highlight {
            let rect = pane_pixel_rect(highlight.region, cw, ch, ox, oy);
            if rect[2] > 0.0 && rect[3] > 0.0 {
                let (rgb, alpha) = if highlight.dock {
                    (DROP_DOCK_HIGHLIGHT_RGB, DROP_DOCK_HIGHLIGHT_ALPHA)
                } else {
                    (DROP_HIGHLIGHT_RGB, DROP_HIGHLIGHT_ALPHA)
                };
                quads.push(QuadInstance {
                    rect,
                    color: rgba([rgb.0, rgb.1, rgb.2], alpha),
                });
            }
        }

        // --- per-pane header band (opt-in) ---
        // A one-row band at the top of each split pane carrying the pane name (left) + arrow/close
        // glyphs (right, added in the text pass). The focused pane's band brightens. Drawn AFTER the
        // pane grids/dim/drop-highlight but BEFORE the focus border so the amber frame sits on top of
        // the band's top edge. Same `pane_header_rect` the glyph pass uses, so band and glyphs agree.
        // Empty `extra_panes` (no split) draws nothing, keeping the single-pane view byte-identical.
        for ep in &self.extra_panes {
            if pane_header_rows_for(ep, cw, ch, oy) == 0 {
                continue;
            }
            if let Some(rect) = pane_header_rect(ep.region, cw, ch, ox, oy) {
                let band = if ep.focused {
                    PANE_HEADER_BAND_FOCUSED
                } else {
                    PANE_HEADER_BAND
                };
                quads.push(QuadInstance {
                    rect,
                    color: rgba(band, 1.0),
                });
            }
        }

        // --- focused-pane indicator (opt-in) ---
        // A subtle translucent border around the focused split pane so the active pane is obvious.
        // Drawn LAST among the split chrome so the frame sits over pane grids, placeholders, and
        // dividers. `None` (no split) draws nothing, keeping the single-pane view unchanged.
        if let Some(region) = self.focus_indicator {
            let color = rgba(
                [
                    FOCUS_INDICATOR_RGB.0,
                    FOCUS_INDICATOR_RGB.1,
                    FOCUS_INDICATOR_RGB.2,
                ],
                FOCUS_INDICATOR_ALPHA,
            );
            let thickness = (FOCUS_INDICATOR_THICKNESS_PX * scale).max(1.0);
            for rect in focus_border_rects(region, cw, ch, ox, oy, thickness) {
                quads.push(QuadInstance { rect, color });
            }
        }

        // --- left dock chrome (opt-in) ---
        // A flat, full-height dark column at the window's left edge, `dock_width_x` physical pixels
        // wide. The terminal grid begins at `grid_origin_x >= dock_width_x`, leaving any difference as
        // terminal-background padding rather than falsely widening the dock. Drawn
        // AFTER the grid and BEFORE the top bar so the full-width tab band sits over the dock's top edge.
        if dock_w > 0.0 {
            quads.push(QuadInstance {
                rect: [0.0, 0.0, dock_w, self.config.height as f32],
                color: rgba(DOCK_FILL, 1.0),
            });

            // Collapse/expand toggle button: a `ch`-square in the top-right corner of the dock column,
            // aligned with the first row band. Geometry matches `dock_collapse_button_rect` in lib.rs
            // (the hit-test), so the painted button and the click target cannot drift. The `«`/`»`
            // glyph is drawn in the text pass below.
            {
                let btn_top = if self.top_bar.is_some() { ch } else { 0.0 };
                if dock_w > ch {
                    quads.push(QuadInstance {
                        rect: [dock_w - ch, btn_top, ch, ch],
                        color: rgba(DOCK_ROW_HEADER, 1.0),
                    });
                }
            }

            // Per-row styling quads: backing fill, left accent bar, status dot, count-badge pill.
            // Geometry matches the text pass below (same `dock_rows_top`/`ch`/depth-indent), so quads
            // and labels stay registered. The numeric badge GLYPH and the row label text are drawn in
            // the text pass; here we only lay the quads beneath them.
            let dock_top = if self.top_bar.is_some() { ch } else { 0.0 };
            for (i, row) in self.dock_rows.iter().enumerate() {
                let y = dock_top + ch * i as f32;
                if y >= self.config.height as f32 {
                    break;
                }
                let accent = row
                    .accent_color
                    .as_deref()
                    .and_then(crate::parse_hex_rgb)
                    .unwrap_or(DOCK_ACCENT_FALLBACK);

                // Backing fill: brightest for the active/focused row, a quiet header tint for a
                // (non-active) project row so depth-0 rows read as section headers.
                let backing = if row.active || row.focused {
                    Some(DOCK_ROW_ACTIVE)
                } else if row.depth == 0 {
                    Some(DOCK_ROW_HEADER)
                } else {
                    None
                };
                if let Some(bg) = backing {
                    quads.push(QuadInstance {
                        rect: [0.0, y, dock_w, ch],
                        color: rgba(bg, 1.0),
                    });
                }

                // Left accent bar: a 3px (scaled) vertical strip in the project accent. Brighter on the
                // active row; dimmed otherwise so the column reads as a quiet rail until selected.
                let bar_w = 3.0 * scale;
                let bar_alpha = if row.active || row.focused { 1.0 } else { 0.55 };
                quads.push(QuadInstance {
                    rect: [0.0, y, bar_w, ch],
                    color: rgba(accent, bar_alpha),
                });

                // Status dot for rows that represent a live/dormant surface (panes; and projects as a
                // roll-up via `active`). A small square centered vertically, just right of the accent
                // bar, before the (indented) label.
                let dot = if row.stashed {
                    Some(DOCK_DOT_STASHED)
                } else if row.active && row.kind != crate::DockRowKind::Window {
                    Some(DOCK_DOT_LIVE)
                } else {
                    None
                };
                if let Some(dot_rgb) = dot {
                    let d = 6.0 * scale;
                    quads.push(QuadInstance {
                        rect: [bar_w + 5.0 * scale, y + (ch - d) * 0.5, d, d],
                        color: rgba(dot_rgb, 1.0),
                    });
                }

                // Count-badge pill on the right edge of the row for rows carrying a count (projects,
                // windows). The numeric glyph is drawn over this in the text pass.
                if let Some(n) = row.count_badge {
                    let digits = if n >= 100 {
                        3
                    } else if n >= 10 {
                        2
                    } else {
                        1
                    };
                    let pill_w = (10.0 + 7.0 * digits as f32) * scale;
                    let pill_h = (ch - 6.0 * scale).max(0.0);
                    let pill_x = (dock_w - pill_w - 6.0 * scale).max(0.0);
                    quads.push(QuadInstance {
                        rect: [pill_x, y + (ch - pill_h) * 0.5, pill_w, pill_h],
                        color: rgba(DOCK_BADGE_FILL, 1.0),
                    });
                }
            }
        }

        // --- top tab bar chrome (opt-in) ---
        // Minimal native chrome: a flat band across the full window width, one cell row high, with
        // an opaque rect per visible tab. The active tab is a brighter fill; inactive tabs are a
        // quieter fill so they read as "behind" the active one. No rounded corners, borders,
        // gradients, hover, or buttons. Drawn AFTER the grid quads so the band sits
        // on top of the (offset) grid's reserved row, and BEFORE upload so it ships this frame.
        if let Some(layout) = self.top_bar.as_ref() {
            // Full-width band across the reserved top row.
            quads.push(QuadInstance {
                rect: [0.0, 0.0, self.config.width as f32, ch],
                color: rgba(TOP_BAR_BAND, 1.0),
            });
            let max_x = self.config.width as f32;
            let hovered_id = self.top_bar_hover.as_deref();
            // A 2 logical-px accent line (floored to >=1 physical px) — thick enough to read as an
            // attention cue, thin enough not to swamp the one-row band.
            let accent_thickness = decoration_thickness(scale) * 2.0;
            for item in &layout.items {
                // Clip each tab rect to the window width so nothing overflows the right edge.
                let x0 = item.x0.max(0.0);
                let x1 = item.x1.min(max_x);
                if x1 <= x0 {
                    continue;
                }
                // Hover lifts only an inactive tab; active styling always wins (decided purely in
                // `top_tab_style`). Hover never matches the active tab id here because the active tab
                // keeps active styling regardless.
                let hovered = hovered_id == Some(item.tab_id.as_str());
                let style = top_tab_style(item.active, hovered);
                quads.push(QuadInstance {
                    rect: [x0, 0.0, x1 - x0, ch],
                    color: rgba(style.fill, 1.0),
                });
                // Attention accent: a thin underline bounded INSIDE the clipped tab rect, so it never
                // overflows the tab or window. Drawn after the fill so it sits on top.
                if let Some(rect) =
                    attention_accent_rect(item.needs_attention, x0, x1, ch, accent_thickness)
                {
                    quads.push(QuadInstance {
                        rect,
                        color: rgba(TOP_ATTENTION_ACCENT, 1.0),
                    });
                }
                // Close marker backing cell: only when the tab is wide enough to host one (the helper
                // returns None otherwise), bounded fully inside the clipped tab rect. Geometry comes
                // from `tab_close_rect_for_item` — the same helper the click hit-test uses — so the
                // drawn cell and the click target stay identical.
                if let Some(rect) = tab_close_rect_for_item(item.x0, item.x1, max_x, cw, ch) {
                    quads.push(QuadInstance {
                        rect,
                        color: rgba(TOP_CLOSE_FILL, 1.0),
                    });
                }
            }
            // Overflow cue: when the strip is truncated, fill the reserved right-edge marker cell so
            // the `>` glyph (added to the text pass below) reads against a quiet backing. Bounded by
            // construction to the band and window width; drawn last so it sits over any tab fill that
            // reached the right edge.
            if let Some(rect) = overflow_marker_rect(layout.overflow, max_x, cw, ch) {
                quads.push(QuadInstance {
                    rect,
                    color: rgba(TOP_OVERFLOW_FILL, 1.0),
                });
            }
            // New-tab control backing cell: a quiet cell hosting the `+`, placed left of the overflow
            // marker when present, else flush right. Bounded by construction to the band and window;
            // drawn last so it sits over any tab fill that reached the right edge. Same `new_tab_rect`
            // the `+` glyph and the click hit-test use, so cell and click target stay identical.
            if let Some(rect) = new_tab_rect(layout.overflow, max_x, cw, ch) {
                quads.push(QuadInstance {
                    rect,
                    color: rgba(TOP_NEWTAB_FILL, 1.0),
                });
            }
            // Split control backing cells: two quiet cells hosting `>` (split-right) and `v`
            // (split-down), placed immediately left of the `+`. Bounded by construction to the band and
            // window; drawn last so they sit over any tab fill that reached this region. Same
            // `split_button_rects` the glyphs and the click hit-test use, so cells and click targets
            // stay identical.
            if let Some((right_rect, down_rect)) =
                split_button_rects(layout.overflow, max_x, cw, ch)
            {
                quads.push(QuadInstance {
                    rect: right_rect,
                    color: rgba(TOP_SPLIT_FILL, 1.0),
                });
                quads.push(QuadInstance {
                    rect: down_rect,
                    color: rgba(TOP_SPLIT_FILL, 1.0),
                });
            }
            // Swap control backing cell: a quiet cell hosting `s` (swap the active split's two
            // panes), placed immediately left of the split-right `>`. Bounded by construction to the
            // band and window. Same `swap_button_rect` the glyph and the click hit-test use, so the
            // cell and click target stay identical.
            if let Some(rect) = swap_button_rect(layout.overflow, max_x, cw, ch) {
                quads.push(QuadInstance {
                    rect,
                    color: rgba(TOP_SWAP_FILL, 1.0),
                });
            }
            // Swallow control backing cell: a quiet cell hosting `o` (the active split's pane reclaims
            // the full frame), placed immediately left of the swap `s`. Bounded by construction to the
            // band and window. Same `swallow_button_rect` the glyph and the click hit-test use, so the
            // cell and click target stay identical.
            if let Some(rect) = swallow_button_rect(layout.overflow, max_x, cw, ch) {
                quads.push(QuadInstance {
                    rect,
                    color: rgba(TOP_SWALLOW_FILL, 1.0),
                });
            }
            // Remote-access toggle: a wider text button ("Open Remote"/"Close Remote") left of the swallow cell,
            // with a status dot on its right — GREEN when remote is OPEN, dark when CLOSED. Same
            // `remote_toggle_button_rect` the label glyphs + the click hit-test use, so they can't drift.
            if self.remote_controls_available {
                if let Some(rect) = remote_toggle_button_rect(layout.overflow, max_x, cw, ch) {
                    quads.push(QuadInstance {
                        rect,
                        color: rgba(TOP_REMOTE_FILL, 1.0),
                    });
                    // status dot: a small square near the right edge of the button, vertically centered.
                    let [rx, _, rw, _] = rect;
                    let d = (ch * 0.34).min(cw * 0.5);
                    let dot_x = rx + rw - cw * 0.5 - d * 0.5;
                    let dot_color = if self.remote_open {
                        TOP_REMOTE_DOT_ON
                    } else {
                        TOP_REMOTE_DOT_OFF
                    };
                    quads.push(QuadInstance {
                        rect: [dot_x, (ch - d) * 0.5, d, d],
                        color: rgba(dot_color, 1.0),
                    });
                }
            }
            // Winsize-owner toggle: a separate text button left of the remote-access toggle. Dot is blue when
            // Remote owns PTY geometry, green when Local owns it.
            if self.remote_controls_available {
                if let Some(rect) = winsize_toggle_button_rect(layout.overflow, max_x, cw, ch) {
                    quads.push(QuadInstance {
                        rect,
                        color: rgba(TOP_WINSIZE_FILL, 1.0),
                    });
                    let [rx, _, rw, _] = rect;
                    let d = (ch * 0.34).min(cw * 0.5);
                    let dot_x = rx + rw - cw * 0.5 - d * 0.5;
                    let dot_color = if self.winsize_owner_remote {
                        TOP_WINSIZE_DOT_REMOTE
                    } else {
                        TOP_WINSIZE_DOT_LOCAL
                    };
                    quads.push(QuadInstance {
                        rect: [dot_x, (ch - d) * 0.5, d, d],
                        color: rgba(dot_color, 1.0),
                    });
                }
            }
        }

        // --- dashboard panel chrome (opt-in, read-only) ---
        // A flat band per fitted panel row, drawn below the top tab bar and above the grid. One
        // full-width quad per row so the panel text (added to the glyph pass below) reads against a
        // quiet backing. Drawn AFTER the grid quads so it sits on top of the (offset) grid's reserved
        // rows. Bounded by construction: `dashboard_panel` already holds only the drawable, fitted
        // rows, and each band is one cell row tall starting at `dashboard_panel_origin_y`.
        for i in 0..self.dashboard_panel.len() {
            let y = self.dashboard_panel_origin_y + ch * i as f32;
            // Row 0 is the branded project-header band: blend the active-project accent lightly over
            // the neutral band so the header reads as branded without drowning the text. Other rows
            // and the no-accent case keep the neutral band exactly.
            let band = match (i, self.dashboard_panel_accent) {
                (0, Some(accent)) => blend(DASHBOARD_PANEL_BAND, accent, 0.35),
                _ => DASHBOARD_PANEL_BAND,
            };
            quads.push(QuadInstance {
                rect: [0.0, y, self.config.width as f32, ch],
                color: rgba(band, 1.0),
            });
        }

        // --- picker overlay (opt-in, read-only, foreground modal) ---
        // Drawn LAST so it sits OVER the grid and all other chrome: a full-window dim backdrop quad
        // plus one opaque band per composed row (from physical y=0, one cell-height each). The rows
        // are already composed/fitted by the App; the renderer only paints them. Empty draws nothing.
        if !self.picker_overlay.is_empty() {
            quads.push(QuadInstance {
                rect: [
                    0.0,
                    0.0,
                    self.config.width as f32,
                    self.config.height as f32,
                ],
                color: rgba(PICKER_OVERLAY_BACKDROP, 0.92),
            });
            for i in 0..self.picker_overlay.len() {
                let y = ch * i as f32;
                quads.push(QuadInstance {
                    rect: [0.0, y, self.config.width as f32, ch],
                    color: rgba(PICKER_OVERLAY_ROW, 1.0),
                });
            }
        }

        // --- command-palette overlay (opt-in, read-only, foreground modal) ---
        // Mirrors the picker overlay quad draw but from the SEPARATE `command_palette_overlay`
        // carrier: a full-window dim backdrop plus one opaque band per composed row. Drawn LAST so it
        // sits OVER the grid and all other chrome. The parser forbids it alongside the picker overlay,
        // so the two are never populated at once. Empty draws nothing.
        if !self.command_palette_overlay.is_empty() {
            quads.push(QuadInstance {
                rect: [
                    0.0,
                    0.0,
                    self.config.width as f32,
                    self.config.height as f32,
                ],
                color: rgba(PICKER_OVERLAY_BACKDROP, 0.92),
            });
            for (i, line) in self.command_palette_overlay.iter().enumerate() {
                let y = ch * i as f32;
                let row_color = if line.selected {
                    COMMAND_PALETTE_OVERLAY_SELECTED_ROW
                } else {
                    PICKER_OVERLAY_ROW
                };
                quads.push(QuadInstance {
                    rect: [0.0, y, self.config.width as f32, ch],
                    color: rgba(row_color, 1.0),
                });
            }
        }

        // --- split-pane shortcut hint overlay (opt-in, read-only, NON-modal) ---
        // One opaque band per composed row from physical y=0, mirroring the picker/command-palette row
        // bands, but with NO full-window dim backdrop: the grid stays visible behind the hint. Drawn
        // LAST so the bands sit OVER the grid and other chrome. Empty draws nothing.
        if !self.shortcut_hint_overlay.is_empty() {
            for i in 0..self.shortcut_hint_overlay.len() {
                let y = ch * i as f32;
                quads.push(QuadInstance {
                    rect: [0.0, y, self.config.width as f32, ch],
                    color: rgba(PICKER_OVERLAY_ROW, 1.0),
                });
            }
        }

        // --- read-only file-preview overlay (opt-in, NON-modal, RIGHT-anchored) ---
        // One opaque band per composed row from physical y=0, anchored to the RIGHT half of the window
        // so it reads as a preview beside the terminal. No full-window dim backdrop: the grid stays
        // visible. Drawn LAST so the bands sit OVER the grid and other chrome. Empty draws nothing.
        if !self.file_preview_overlay.is_empty() {
            let x0 = (self.config.width as f32 * crate::FILE_PREVIEW_OVERLAY_LEFT_FRACTION).floor();
            let band_w = (self.config.width as f32 - x0).max(0.0);
            let band_h = ch * self.file_preview_overlay.len() as f32;
            for i in 0..self.file_preview_overlay.len() {
                let y = ch * i as f32;
                quads.push(QuadInstance {
                    rect: [x0, y, band_w, ch],
                    color: rgba(PICKER_OVERLAY_ROW, 1.0),
                });
            }
            // Stable vertical divider at the band's left edge so the preview reads as a distinct
            // right-side pane rather than text floating over the grid. Drawn after the row bands so it
            // sits on top of them along the full painted height.
            let divider_rect = file_preview_divider_rect(x0, band_h, scale);
            quads.push(QuadInstance {
                rect: divider_rect,
                color: rgba(FILE_PREVIEW_DIVIDER, 1.0),
            });
        }

        // --- file-path-input prompt band (opt-in, NON-modal, BOTTOM-anchored) ---
        // One opaque full-width band per composed row anchored to the BOTTOM of the window so it reads as
        // an input prompt. No full-window dim backdrop: the grid stays visible. Drawn LAST so the band
        // sits OVER the grid and other chrome. Empty draws nothing.
        if !self.file_path_input_overlay.is_empty() {
            let band_h = ch * self.file_path_input_overlay.len() as f32;
            let y0 = (self.config.height as f32 - band_h).max(0.0);
            for i in 0..self.file_path_input_overlay.len() {
                let y = y0 + ch * i as f32;
                quads.push(QuadInstance {
                    rect: [0.0, y, self.config.width as f32, ch],
                    color: rgba(PICKER_OVERLAY_ROW, 1.0),
                });
            }
        }

        // Upload quad instances (grow buffer if needed).
        if quads.len() > self.instance_cap {
            self.instance_cap = quads.len().next_power_of_two();
            self.instance_buf = self.device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("quad-instances"),
                size: (self.instance_cap * std::mem::size_of::<QuadInstance>())
                    as wgpu::BufferAddress,
                usage: wgpu::BufferUsages::VERTEX | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });
        }
        self.instance_count = quads.len() as u32;
        self.queue
            .write_buffer(&self.instance_buf, 0, bytemuck::cast_slice(&quads));

        // --- build glyph text buffers ---
        self.viewport.update(
            &self.queue,
            Resolution {
                width: self.config.width,
                height: self.config.height,
            },
        );

        // Glyph positioning rule (alacritty/wezterm model): the GRID dictates each
        // glyph's cell; the font only supplies the glyph SHAPE. We therefore build
        // ONE cosmic-text buffer per non-empty cell and place it via its own
        // TextArea at (col*cw, row*ch). We never let cosmic-text's flow layout pick
        // x-positions across a row — that would drift after any wide/fallback glyph
        // whose natural advance differs from cw, desyncing glyphs from the per-cell
        // backgrounds. A width-2 cell is given a 2*cw bound so a wide glyph (CJK)
        // has room; its trailing width-0 spacer is skipped (it carries no text).
        let metrics = Metrics::new(self.font_size * scale, self.line_height * scale);
        let mut overlay_buf = overlay.map(|_| Buffer::new(&mut self.font_system, metrics));

        // Drop the shaped-glyph cache when the DPI scale changes: cached buffers were
        // shaped at the old metrics and would paint at the wrong size. This is the only
        // invalidation needed — text/style/width changes can't alias because they are
        // all in the key, and color is applied per-TextArea, not baked into the buffer.
        if scale != self.scale_at_shape {
            self.glyph_cache.clear();
            self.scale_at_shape = scale;
        }

        let glyph_build_start = self.stats_enabled.then(Instant::now);
        // Pass 1 (no shaping): collect each painted cell's key + placement + color + optional
        // split-pane clip. The clip is `None` for the unsplit path, preserving its existing glyph
        // bounds exactly; split panes carry their terminal-content pixel bounds so a width-2 lead
        // cell at the pane's final column cannot paint into its neighbor.
        // (key, left_px, top_px, span_cells, fg, pane_clip) for each painted cell.
        type GlyphPlacement = (GlyphKey, f32, f32, f32, theme::Rgb, Option<[i32; 4]>);
        let mut placements: Vec<GlyphPlacement> = Vec::new();
        if let Some(g) = grid {
            for (row, cells) in g.rows_cells.iter().enumerate() {
                for (col, cell) in cells.iter().enumerate() {
                    let Some(key) = glyph_key_for(cell) else {
                        continue; // spacer / blank / hidden — background covers it
                    };
                    // Clip the active PTY glyphs to the active pane (no-op without a split frame).
                    if !cell_in_pane(col, row, active_pane) {
                        continue;
                    }
                    stats.nonblank_cells += 1;
                    let (fg, _bg) = resolved_colors(cell, &self.palette);
                    let span = if cell.width == 2 { 2.0 } else { 1.0 };
                    placements.push((
                        key,
                        col as f32 * cw + pane_off_x,
                        row as f32 * ch + oy + pane_off_y,
                        span,
                        fg,
                        active_text_clip,
                    ));
                }
            }
        }
        // Sibling-pane glyphs: collect the cached sibling grid's glyph placements into the SAME
        // `placements` list (so Pass 2 shapes and Pass 3 places them), clipped/offset to the inactive
        // pane. Only when a live sibling grid is being painted; otherwise the placeholder label stands.
        if let (Some(sib_pane), Some(sib_g)) = (sibling, self.sibling_grid.as_ref()) {
            for (row, cells) in sib_g.rows_cells.iter().enumerate() {
                for (col, cell) in cells.iter().enumerate() {
                    let Some(key) = glyph_key_for(cell) else {
                        continue; // spacer / blank / hidden — background covers it
                    };
                    if !cell_in_pane(col, row, Some(sib_pane)) {
                        continue;
                    }
                    stats.nonblank_cells += 1;
                    let (fg, _bg) = resolved_colors(cell, &self.palette);
                    let span = if cell.width == 2 { 2.0 } else { 1.0 };
                    placements.push((
                        key,
                        col as f32 * cw + sib_off_x,
                        row as f32 * ch + oy + sib_off_y,
                        span,
                        fg,
                        sibling_text_clip,
                    ));
                }
            }
        }
        // Extra non-active pane glyphs (3+-pane layout): collect each cached pane grid's glyphs into the
        // SAME `placements` list, clipped/offset to the pane's region. A pane with no live grid emits no
        // glyphs here — its placeholder label is built below. Empty for the two-pane case.
        for ep in &self.extra_panes {
            let Some(g) = ep.grid.as_ref() else {
                continue;
            };
            let region = ep.region;
            let off_x = region.col as f32 * cw + ox;
            let header_rows = pane_header_rows_for(ep, cw, ch, oy);
            let off_y = (region.row + header_rows) as f32 * ch;
            let local = crate::RendererPaneRegion {
                col: 0,
                row: 0,
                cols: region.cols,
                rows: region.rows.saturating_sub(header_rows),
            };
            let content_text_clip = Some(pane_text_clip(region, header_rows, cw, ch, ox, oy));
            for (row, cells) in g.rows_cells.iter().enumerate() {
                for (col, cell) in cells.iter().enumerate() {
                    let Some(key) = glyph_key_for(cell) else {
                        continue;
                    };
                    if !cell_in_pane(col, row, Some(local)) {
                        continue;
                    }
                    stats.nonblank_cells += 1;
                    let (fg, _bg) = resolved_colors(cell, &self.palette);
                    let span = if cell.width == 2 { 2.0 } else { 1.0 };
                    placements.push((
                        key,
                        col as f32 * cw + off_x,
                        row as f32 * ch + oy + off_y,
                        span,
                        fg,
                        content_text_clip,
                    ));
                }
            }
        }

        // Pass 2 (shape on miss only): ensure every referenced key is in the cache.
        // A cache HIT re-shapes nothing — the dominant per-frame cost vanishes for any
        // glyph already on screen. Color is intentionally absent from the shaped text
        // (Attrs carries no color), so glyphon resolves each glyph to the per-cell
        // TextArea.default_color set below.
        let base_attrs = Attrs::new().family(Family::Monospace);
        for (key, _, _, span, _, _) in &placements {
            if self.glyph_cache.contains_key(key) {
                continue;
            }
            // Enforce the bound BEFORE every insert, not once per frame: a single
            // frame can reference more than GLYPH_CACHE_CAP distinct glyphs (e.g. a
            // flood of unique clusters), and a once-per-frame check would let the map
            // grow past the cap within that frame. This keeps `len()` strictly
            // <= GLYPH_CACHE_CAP at all times. The frame still paints every glyph: a
            // post-clear miss simply re-shapes into the now-empty map.
            enforce_glyph_cache_cap(&mut self.glyph_cache, GLYPH_CACHE_CAP);
            let mut attrs = base_attrs;
            if key.bold {
                attrs = attrs.weight(Weight::BOLD);
            }
            if key.italic {
                attrs = attrs.style(glyphon::Style::Italic);
            }
            let mut buf = Buffer::new(&mut self.font_system, metrics);
            // Bound the cell to its own width so a single glyph never wraps; give a
            // little vertical slack for tall combining marks.
            buf.set_size(&mut self.font_system, Some(cw * span), Some(ch * 2.0));
            buf.set_text(&mut self.font_system, &key.text, attrs, Shaping::Advanced);
            buf.shape_until_scroll(&mut self.font_system, false);
            stats.glyph_buffers_built += 1;
            self.glyph_cache.insert(key.clone(), buf);
        }
        if let Some(t) = glyph_build_start {
            stats.glyph_build_us = t.elapsed().as_micros();
        }

        if let (Some(overlay), Some(buf)) = (overlay, overlay_buf.as_mut()) {
            buf.set_size(
                &mut self.font_system,
                Some(self.config.width as f32),
                Some(ch),
            );
            buf.set_text(
                &mut self.font_system,
                overlay,
                Attrs::new()
                    .family(Family::Monospace)
                    .color(GColor::rgb(0x9e, 0x9e, 0x9e)),
                Shaping::Basic,
            );
            buf.shape_until_scroll(&mut self.font_system, false);
        }

        // Top tab-bar labels: one shaped buffer per visible tab, bounded to its rect width so a long
        // label is clipped (not wrapped) and never overflows past the window edge. Built here (while
        // we hold `&mut font_system`) and held in a local Vec so they outlive the `text_areas`
        // borrow below. Active labels are brighter; inactive labels quieter but still readable.
        let mut tab_label_bufs: Vec<(Buffer, f32, f32, GColor)> = Vec::new();
        if let Some(layout) = self.top_bar.as_ref() {
            let max_x = self.config.width as f32;
            let hovered_id = self.top_bar_hover.as_deref();
            for item in &layout.items {
                let x0 = item.x0.max(0.0);
                let x1 = item.x1.min(max_x);
                if x1 <= x0 {
                    continue;
                }
                // If a close marker exists for this tab, clip the title to the area BEFORE it so the
                // label never draws under the `x`; otherwise the title keeps the whole tab rect. Same
                // helper the fill pass and the click hit-test use, so the label clip and the marker
                // cell agree.
                let close_rect = tab_close_rect_for_item(item.x0, item.x1, max_x, cw, ch);
                let title_right = tab_title_right(x1, close_rect);
                let title_w = (title_right - x0).max(0.0);
                let mut buf = Buffer::new(&mut self.font_system, metrics);
                buf.set_size(&mut self.font_system, Some(title_w), Some(ch));
                buf.set_text(
                    &mut self.font_system,
                    &item.label,
                    Attrs::new().family(Family::Monospace),
                    Shaping::Advanced,
                );
                buf.shape_until_scroll(&mut self.font_system, false);
                // Same pure decision as the fill quad, so fill and label never disagree.
                let hovered = hovered_id == Some(item.tab_id.as_str());
                let lc = top_tab_style(item.active, hovered).label;
                let color = GColor::rgb(lc[0], lc[1], lc[2]);
                // The title placement bound is `title_right` (before the close cell when present).
                tab_label_bufs.push((buf, x0, title_right, color));
                // Close `x` glyph, clipped to the close cell so it cannot bleed onto the title or the
                // neighbor tab. Visual only — there is no hit-test for it.
                if let Some([cx0, _, cw_rect, _]) = close_rect {
                    let mut cbuf = Buffer::new(&mut self.font_system, metrics);
                    cbuf.set_size(&mut self.font_system, Some(cw_rect), Some(ch));
                    cbuf.set_text(
                        &mut self.font_system,
                        TOP_CLOSE_GLYPH,
                        Attrs::new().family(Family::Monospace),
                        Shaping::Advanced,
                    );
                    cbuf.shape_until_scroll(&mut self.font_system, false);
                    let mk = TOP_CLOSE_MARK;
                    tab_label_bufs.push((
                        cbuf,
                        cx0,
                        cx0 + cw_rect,
                        GColor::rgb(mk[0], mk[1], mk[2]),
                    ));
                }
            }
            // Overflow `>` glyph in the reserved right-edge marker cell, clipped to that cell so it
            // never bleeds onto a tab. Same bounded rect the fill quad uses.
            if let Some([mx, _, mw, _]) = overflow_marker_rect(layout.overflow, max_x, cw, ch) {
                let mut buf = Buffer::new(&mut self.font_system, metrics);
                buf.set_size(&mut self.font_system, Some(mw), Some(ch));
                buf.set_text(
                    &mut self.font_system,
                    TOP_OVERFLOW_GLYPH,
                    Attrs::new().family(Family::Monospace),
                    Shaping::Advanced,
                );
                buf.shape_until_scroll(&mut self.font_system, false);
                let mk = TOP_OVERFLOW_MARK;
                tab_label_bufs.push((buf, mx, mx + mw, GColor::rgb(mk[0], mk[1], mk[2])));
            }
            // New-tab `+` glyph in the reserved new-tab cell, clipped to that cell so it never bleeds
            // onto a tab or the overflow marker. Same bounded rect the fill quad uses.
            if let Some([nx, _, nw, _]) = new_tab_rect(layout.overflow, max_x, cw, ch) {
                let mut buf = Buffer::new(&mut self.font_system, metrics);
                buf.set_size(&mut self.font_system, Some(nw), Some(ch));
                buf.set_text(
                    &mut self.font_system,
                    TOP_NEWTAB_GLYPH,
                    Attrs::new().family(Family::Monospace),
                    Shaping::Advanced,
                );
                buf.shape_until_scroll(&mut self.font_system, false);
                let mk = TOP_NEWTAB_MARK;
                tab_label_bufs.push((buf, nx, nx + nw, GColor::rgb(mk[0], mk[1], mk[2])));
            }
            // Split `>`/`v` glyphs in the reserved split cells (immediately left of `+`), each clipped
            // to its own cell so it never bleeds onto a neighbor. Same bounded rects the fill quads use.
            if let Some((right_rect, down_rect)) =
                split_button_rects(layout.overflow, max_x, cw, ch)
            {
                let mk = TOP_SPLIT_MARK;
                for ([sx, _, sw, _], glyph) in [
                    (right_rect, TOP_SPLIT_RIGHT_GLYPH),
                    (down_rect, TOP_SPLIT_DOWN_GLYPH),
                ] {
                    let mut buf = Buffer::new(&mut self.font_system, metrics);
                    buf.set_size(&mut self.font_system, Some(sw), Some(ch));
                    buf.set_text(
                        &mut self.font_system,
                        glyph,
                        Attrs::new().family(Family::Monospace),
                        Shaping::Advanced,
                    );
                    buf.shape_until_scroll(&mut self.font_system, false);
                    tab_label_bufs.push((buf, sx, sx + sw, GColor::rgb(mk[0], mk[1], mk[2])));
                }
            }
            // Swap `s` glyph in the reserved swap cell (immediately left of `>`), clipped to that cell
            // so it never bleeds onto a neighbor. Same bounded rect the fill quad uses.
            if let Some([sx, _, sw, _]) = swap_button_rect(layout.overflow, max_x, cw, ch) {
                let mut buf = Buffer::new(&mut self.font_system, metrics);
                buf.set_size(&mut self.font_system, Some(sw), Some(ch));
                buf.set_text(
                    &mut self.font_system,
                    TOP_SWAP_GLYPH,
                    Attrs::new().family(Family::Monospace),
                    Shaping::Advanced,
                );
                buf.shape_until_scroll(&mut self.font_system, false);
                let mk = TOP_SWAP_MARK;
                tab_label_bufs.push((buf, sx, sx + sw, GColor::rgb(mk[0], mk[1], mk[2])));
            }
            // Swallow `o` glyph in the reserved swallow cell (immediately left of `s`), clipped to that
            // cell so it never bleeds onto a neighbor. Same bounded rect the fill quad uses.
            if let Some([sx, _, sw, _]) = swallow_button_rect(layout.overflow, max_x, cw, ch) {
                let mut buf = Buffer::new(&mut self.font_system, metrics);
                buf.set_size(&mut self.font_system, Some(sw), Some(ch));
                buf.set_text(
                    &mut self.font_system,
                    TOP_SWALLOW_GLYPH,
                    Attrs::new().family(Family::Monospace),
                    Shaping::Advanced,
                );
                buf.shape_until_scroll(&mut self.font_system, false);
                let mk = TOP_SWALLOW_MARK;
                tab_label_bufs.push((buf, sx, sx + sw, GColor::rgb(mk[0], mk[1], mk[2])));
            }
            // Remote-access toggle label: "Close Remote" when currently OPEN (the action to close), "Open Remote"
            // when currently CLOSED. Left-aligned in the button; the status dot (drawn in the quad pass) sits to its
            // right. Reserve the last cell for the dot so the text doesn't overlap it.
            if self.remote_controls_available {
                if let Some([rx, _, rw, _]) =
                    remote_toggle_button_rect(layout.overflow, max_x, cw, ch)
                {
                    let mut buf = Buffer::new(&mut self.font_system, metrics);
                    let text_w = (rw - cw).max(cw); // leave a cell on the right for the dot
                    buf.set_size(&mut self.font_system, Some(text_w), Some(ch));
                    let label = if self.remote_open {
                        TOP_REMOTE_LABEL_CLOSE
                    } else {
                        TOP_REMOTE_LABEL_OPEN
                    };
                    buf.set_text(
                        &mut self.font_system,
                        label,
                        Attrs::new().family(Family::Monospace),
                        Shaping::Advanced,
                    );
                    buf.shape_until_scroll(&mut self.font_system, false);
                    let mk = TOP_REMOTE_MARK;
                    tab_label_bufs.push((
                        buf,
                        rx + cw * 0.25,
                        rx + text_w,
                        GColor::rgb(mk[0], mk[1], mk[2]),
                    ));
                }
            }
            // Winsize-owner toggle label. It shows the ACTION: "Size Local" while Remote owns, and "Size Remote"
            // while Local owns.
            if self.remote_controls_available {
                if let Some([rx, _, rw, _]) =
                    winsize_toggle_button_rect(layout.overflow, max_x, cw, ch)
                {
                    let mut buf = Buffer::new(&mut self.font_system, metrics);
                    let text_w = (rw - cw).max(cw);
                    buf.set_size(&mut self.font_system, Some(text_w), Some(ch));
                    let label = if self.winsize_owner_remote {
                        TOP_WINSIZE_LABEL_LOCAL
                    } else {
                        TOP_WINSIZE_LABEL_REMOTE
                    };
                    buf.set_text(
                        &mut self.font_system,
                        label,
                        Attrs::new().family(Family::Monospace),
                        Shaping::Advanced,
                    );
                    buf.shape_until_scroll(&mut self.font_system, false);
                    let mk = TOP_WINSIZE_MARK;
                    tab_label_bufs.push((
                        buf,
                        rx + cw * 0.25,
                        rx + text_w,
                        GColor::rgb(mk[0], mk[1], mk[2]),
                    ));
                }
            }
        }

        // Dashboard panel line buffers: one shaped buffer per fitted row, each (buffer, top_y). The
        // text is already fitted to the drawable columns and control-char-free (the App fits it via
        // `fit_panel_line`), so it is set verbatim and clipped to its band row. Built here so the
        // buffers outlive the `text_areas` borrow below.
        let panel_w = self.config.width as f32;
        let mut panel_line_bufs: Vec<(Buffer, f32)> = Vec::new();
        for (i, line) in self.dashboard_panel.iter().enumerate() {
            let top = self.dashboard_panel_origin_y + ch * i as f32;
            let mut buf = Buffer::new(&mut self.font_system, metrics);
            buf.set_size(&mut self.font_system, Some(panel_w), Some(ch));
            buf.set_text(
                &mut self.font_system,
                line,
                Attrs::new().family(Family::Monospace),
                Shaping::Advanced,
            );
            buf.shape_until_scroll(&mut self.font_system, false);
            panel_line_bufs.push((buf, top));
        }

        // Left-dock row buffers: one shaped buffer per dock row, each (buffer, top_y, left_x), plus a
        // separate right-aligned count-badge numeral buffer per badged row. Rows are stacked one
        // cell-row high starting just below the top tab band (or y=0 when no tab bar), indented by depth,
        // and shifted further right to clear the status dot. The label text leads with a disclosure
        // caret (▾/▸) on expandable project rows. Built here so the buffers outlive the `text_areas`
        // borrow below. The accent bar / dot / badge-pill QUADS were already pushed above.
        let dock_rows_top = if self.top_bar.is_some() { ch } else { 0.0 };
        let mut dock_line_bufs: Vec<(Buffer, f32, f32)> = Vec::new();
        // (buffer, top_y, pill_left_x) for right-aligned count badges.
        let mut dock_badge_bufs: Vec<(Buffer, f32, f32)> = Vec::new();
        // Collapse-button glyph: (buffer, left_x, top_y). `»` when collapsed (click to expand), `«`
        // when expanded (click to collapse). Drawn over the button quad in the dock's top-right corner.
        let mut dock_button_buf: Option<(Buffer, f32, f32)> = None;
        if dock_w > ch {
            let glyph = if self.dock_collapsed { "»" } else { "«" };
            let mut bbuf = Buffer::new(&mut self.font_system, metrics);
            bbuf.set_size(&mut self.font_system, Some(ch), Some(ch));
            bbuf.set_text(
                &mut self.font_system,
                glyph,
                Attrs::new().family(Family::Monospace),
                Shaping::Advanced,
            );
            bbuf.shape_until_scroll(&mut self.font_system, false);
            dock_button_buf = Some((bbuf, dock_w - ch, dock_rows_top));
        }
        if dock_w > 0.0 && !self.dock_rows.is_empty() {
            for (i, row) in self.dock_rows.iter().enumerate() {
                let top = dock_rows_top + ch * i as f32;
                if top >= self.config.height as f32 {
                    break;
                }
                // Per-depth indent in physical pixels; the collapsed rail centers icons so it ignores
                // depth (only project rows are emitted when collapsed). Non-collapsed rows are shifted
                // past the accent bar + status dot gutter so labels never sit under the dot.
                let indent = if self.dock_collapsed {
                    8.0 * scale
                } else {
                    (16.0 + 12.0 * row.depth as f32) * scale
                };
                // Disclosure caret only on collapsible project rows (when expanded). Filled vs hollow.
                let caret = match (self.dock_collapsed, row.expanded) {
                    (false, Some(true)) => "▾ ",
                    (false, Some(false)) => "▸ ",
                    _ => "",
                };
                let text = if self.dock_collapsed {
                    if row.icon.is_empty() {
                        row.label
                            .chars()
                            .next()
                            .map(|c| c.to_string())
                            .unwrap_or_default()
                    } else {
                        row.icon.clone()
                    }
                } else if row.icon.is_empty() {
                    format!("{caret}{}", row.label)
                } else {
                    format!("{caret}{} {}", row.icon, row.label)
                };
                let mut buf = Buffer::new(&mut self.font_system, metrics);
                buf.set_size(
                    &mut self.font_system,
                    Some((dock_w - indent).max(0.0)),
                    Some(ch),
                );
                buf.set_text(
                    &mut self.font_system,
                    &text,
                    Attrs::new().family(Family::Monospace),
                    Shaping::Advanced,
                );
                buf.shape_until_scroll(&mut self.font_system, false);
                dock_line_bufs.push((buf, top, indent));

                // Count-badge numeral, right-aligned within its pill (the pill quad was drawn above with
                // identical geometry). Skipped in the collapsed rail (no room for a numeral).
                if let (false, Some(n)) = (self.dock_collapsed, row.count_badge) {
                    let digits = if n >= 100 {
                        3
                    } else if n >= 10 {
                        2
                    } else {
                        1
                    };
                    let pill_w = (10.0 + 7.0 * digits as f32) * scale;
                    let pill_x = (dock_w - pill_w - 6.0 * scale).max(0.0);
                    let mut bbuf = Buffer::new(&mut self.font_system, metrics);
                    bbuf.set_size(&mut self.font_system, Some(pill_w), Some(ch));
                    bbuf.set_text(
                        &mut self.font_system,
                        &n.to_string(),
                        Attrs::new().family(Family::Monospace),
                        Shaping::Advanced,
                    );
                    bbuf.shape_until_scroll(&mut self.font_system, false);
                    dock_badge_bufs.push((bbuf, top, pill_x));
                }
            }
        }

        // Picker overlay row buffers: one shaped buffer per composed row, each (buffer, top_y) from
        // physical y=0. The rows are already composed/fitted and control-char-free by the App, so each
        // is set verbatim and clipped to its band row. Built here so the buffers outlive the
        // `text_areas` borrow below.
        let picker_w = self.config.width as f32;
        let mut picker_line_bufs: Vec<(Buffer, f32)> = Vec::new();
        for (i, line) in self.picker_overlay.iter().enumerate() {
            let top = ch * i as f32;
            let mut buf = Buffer::new(&mut self.font_system, metrics);
            buf.set_size(&mut self.font_system, Some(picker_w), Some(ch));
            buf.set_text(
                &mut self.font_system,
                line,
                Attrs::new().family(Family::Monospace),
                Shaping::Advanced,
            );
            buf.shape_until_scroll(&mut self.font_system, false);
            picker_line_bufs.push((buf, top));
        }

        // Command-palette overlay row buffers: mirrors the picker overlay buffers but from the
        // SEPARATE `command_palette_overlay` carrier, so the two never alias. One shaped buffer per
        // composed row, each (buffer, top_y) from physical y=0. The rows are already composed/fitted
        // and control-char-free by the App. Built here so the buffers outlive the `text_areas` borrow.
        let command_palette_w = self.config.width as f32;
        let mut command_palette_line_bufs: Vec<(Buffer, f32, bool)> = Vec::new();
        for (i, line) in self.command_palette_overlay.iter().enumerate() {
            let top = ch * i as f32;
            let mut buf = Buffer::new(&mut self.font_system, metrics);
            buf.set_size(&mut self.font_system, Some(command_palette_w), Some(ch));
            buf.set_text(
                &mut self.font_system,
                &line.text,
                Attrs::new().family(Family::Monospace),
                Shaping::Advanced,
            );
            buf.shape_until_scroll(&mut self.font_system, false);
            command_palette_line_bufs.push((buf, top, line.selected));
        }

        // Split-pane shortcut hint overlay row buffers: one shaped buffer per composed row, each
        // (buffer, top_y) from physical y=0. The rows are already composed and control-char-free by the
        // App, so each is set verbatim and clipped to its band row. Built here so the buffers outlive the
        // `text_areas` borrow below.
        let shortcut_hint_w = self.config.width as f32;
        let mut shortcut_hint_line_bufs: Vec<(Buffer, f32)> = Vec::new();
        for (i, line) in self.shortcut_hint_overlay.iter().enumerate() {
            let top = ch * i as f32;
            let mut buf = Buffer::new(&mut self.font_system, metrics);
            buf.set_size(&mut self.font_system, Some(shortcut_hint_w), Some(ch));
            buf.set_text(
                &mut self.font_system,
                &line.text,
                Attrs::new().family(Family::Monospace),
                Shaping::Advanced,
            );
            buf.shape_until_scroll(&mut self.font_system, false);
            shortcut_hint_line_bufs.push((buf, top));
        }

        // File-preview overlay row buffers: one shaped buffer per composed row, each (buffer, top_y, x0)
        // anchored to the RIGHT half of the window from physical y=0. The rows are already composed and
        // control-char-free by the App, so each is set verbatim and clipped to its band cell. Built here
        // so the buffers outlive the `text_areas` borrow below.
        let file_preview_x0 =
            (self.config.width as f32 * crate::FILE_PREVIEW_OVERLAY_LEFT_FRACTION).floor();
        let file_preview_w = (self.config.width as f32 - file_preview_x0).max(0.0);
        let mut file_preview_line_bufs: Vec<(Buffer, f32)> = Vec::new();
        for (i, line) in self.file_preview_overlay.iter().enumerate() {
            let top = ch * i as f32;
            let mut buf = Buffer::new(&mut self.font_system, metrics);
            buf.set_size(&mut self.font_system, Some(file_preview_w), Some(ch));
            buf.set_text(
                &mut self.font_system,
                &line.text,
                Attrs::new().family(Family::Monospace),
                Shaping::Advanced,
            );
            buf.shape_until_scroll(&mut self.font_system, false);
            file_preview_line_bufs.push((buf, top));
        }

        // File-path-input prompt row buffers: one shaped buffer per composed row, anchored to the
        // BOTTOM of the window. Each (buffer, top_y) is computed from the band's bottom origin. The rows
        // are already composed and control-char-free by the App. Built here so the buffers outlive the
        // `text_areas` borrow below.
        let file_path_input_w = self.config.width as f32;
        let file_path_input_band_h = ch * self.file_path_input_overlay.len() as f32;
        let file_path_input_y0 = (self.config.height as f32 - file_path_input_band_h).max(0.0);
        let mut file_path_input_line_bufs: Vec<(Buffer, f32)> = Vec::new();
        for (i, line) in self.file_path_input_overlay.iter().enumerate() {
            let top = file_path_input_y0 + ch * i as f32;
            let mut buf = Buffer::new(&mut self.font_system, metrics);
            buf.set_size(&mut self.font_system, Some(file_path_input_w), Some(ch));
            buf.set_text(
                &mut self.font_system,
                &line.text,
                Attrs::new().family(Family::Monospace),
                Shaping::Advanced,
            );
            buf.shape_until_scroll(&mut self.font_system, false);
            file_path_input_line_bufs.push((buf, top));
        }

        // Inactive split-pane placeholder label: one shaped buffer with the sibling tab id, placed at
        // the inactive pane's top-left (inset to match the overlay gutter), clipped to that pane. Built
        // here so it outlives the `text_areas` borrow. `None` when there is no split frame.
        let split_placeholder_buf: Option<(Buffer, [f32; 4])> = self
            .split_frame
            .as_ref()
            .filter(|_| show_placeholder)
            .map(|frame| {
                let inactive = crate::inactive_pane_region(frame);
                let rect = pane_pixel_rect(inactive, cw, ch, ox, oy);
                let label = split_placeholder_label(
                    crate::inactive_pane_tab_id(frame),
                    frame.inactive_session_id.as_deref(),
                    self.split_sibling_status,
                );
                let mut buf = Buffer::new(&mut self.font_system, metrics);
                buf.set_size(&mut self.font_system, Some(rect[2]), Some(ch));
                buf.set_text(
                    &mut self.font_system,
                    &label,
                    Attrs::new().family(Family::Monospace),
                    Shaping::Advanced,
                );
                buf.shape_until_scroll(&mut self.font_system, false);
                (buf, rect)
            });

        // Extra-pane placeholder labels: one shaped buffer per extra pane that has NO live grid (a
        // pending/exited pane), placed at the pane region's top-left and clipped to it. Built here so
        // they outlive the `text_areas` borrow. A pane WITH a live grid emits no label (its glyphs are
        // already collected above). Empty for the two-pane case.
        let mut extra_placeholder_bufs: Vec<(Buffer, [f32; 4])> = Vec::new();
        for ep in &self.extra_panes {
            if ep.grid.is_some() {
                continue;
            }
            // Shift the placeholder label below the reserved header row (when the pane hosts a header)
            // so it never draws under the header band.
            let mut rect = pane_pixel_rect(ep.region, cw, ch, ox, oy);
            if pane_header_rows_for(ep, cw, ch, oy) > 0 {
                let band = PANE_HEADER_ROWS as f32 * ch;
                rect[1] += band;
                rect[3] = (rect[3] - band).max(0.0);
            }
            let label =
                split_placeholder_label(&ep.tab_id, Some(ep.session_id.as_str()), ep.status);
            let mut buf = Buffer::new(&mut self.font_system, metrics);
            buf.set_size(&mut self.font_system, Some(rect[2]), Some(ch));
            buf.set_text(
                &mut self.font_system,
                &label,
                Attrs::new().family(Family::Monospace),
                Shaping::Advanced,
            );
            buf.shape_until_scroll(&mut self.font_system, false);
            extra_placeholder_bufs.push((buf, rect));
        }

        // Per-pane close `x` glyphs: one shaped buffer per split pane that earns a close cell (large
        // enough), placed in the pane's top-right corner cell and clipped to it. Built here so the
        // buffers outlive the `text_areas` borrow. The marker remains one cell wide; the lib.rs
        // click hit-test owns the wider corner button zone. Empty for the two-pane case.
        let mut pane_close_bufs: Vec<(Buffer, [f32; 4])> = Vec::new();
        for ep in &self.extra_panes {
            if !ep.show_header {
                continue;
            }
            if let Some(rect) = pane_close_rect(ep.region, cw, ch, ox, oy) {
                let close_col = pane_header_close_cell(ep.region).unwrap_or(ep.region.col);
                let glyph_x = close_col as f32 * cw + ox;
                let glyph_y = rect[1] + ((PANE_HEADER_VISUAL_ROWS - 1.0) * ch * 0.5);
                let mut buf = Buffer::new(&mut self.font_system, metrics);
                buf.set_size(&mut self.font_system, Some(cw), Some(ch));
                buf.set_text(
                    &mut self.font_system,
                    PANE_CLOSE_GLYPH,
                    Attrs::new().family(Family::Monospace),
                    Shaping::Advanced,
                );
                buf.shape_until_scroll(&mut self.font_system, false);
                pane_close_bufs.push((buf, [glyph_x, glyph_y, cw, ch]));
            }
        }

        // Per-pane header NAME + ARROW glyphs. The name (left, clipped to `pane_header_name_extent`)
        // and the move/swallow arrow cluster (right, design-only — drawn but not yet wired). Built here
        // so the buffers outlive the `text_areas` borrow. Color: name brightens when the pane is
        // focused; arrows are a quiet resting gray. The `x` glyph itself is built above (`pane_close_bufs`).
        // Same geometry helpers (`pane_header_rect`, `pane_header_name_extent`, `pane_header_button_cells`)
        // the band quad and any future hit-test use, so the glyphs cannot drift. Empty for the two-pane case.
        let mut pane_header_bufs: Vec<(Buffer, [f32; 4], GColor)> = Vec::new();
        for ep in &self.extra_panes {
            if pane_header_rows_for(ep, cw, ch, oy) == 0 {
                continue;
            }
            let region = ep.region;
            let row_y = region.row as f32 * ch + oy + ((PANE_HEADER_VISUAL_ROWS - 1.0) * ch * 0.5);
            // Name, left-aligned, clipped to the cells before the button cluster.
            if let Some((name_first, name_end)) = pane_header_name_extent(region) {
                let name_cells = name_end.saturating_sub(name_first);
                if name_cells > 0 && !ep.name.is_empty() {
                    let name_w = name_cells as f32 * cw;
                    let left = name_first as f32 * cw + ox;
                    let color = if ep.focused {
                        PANE_HEADER_NAME_FOCUSED
                    } else {
                        PANE_HEADER_NAME
                    };
                    let mut buf = Buffer::new(&mut self.font_system, metrics);
                    buf.set_size(&mut self.font_system, Some(name_w), Some(ch));
                    buf.set_text(
                        &mut self.font_system,
                        &ep.name,
                        Attrs::new().family(Family::Monospace),
                        Shaping::Advanced,
                    );
                    buf.shape_until_scroll(&mut self.font_system, false);
                    pane_header_bufs.push((
                        buf,
                        [left, row_y, name_w, ch],
                        GColor::rgb(color[0], color[1], color[2]),
                    ));
                }
            }
            // Arrow cluster (move + swallow), one glyph per cell. The trailing `x` cell from
            // `pane_header_button_cells` is skipped here (its glyph is in `pane_close_bufs`).
            let arrow_color = GColor::rgb(
                PANE_HEADER_ARROW[0],
                PANE_HEADER_ARROW[1],
                PANE_HEADER_ARROW[2],
            );
            for (cell_col, dir) in pane_header_move_arrow_cells(region) {
                if !ep.move_directions.contains(&dir) {
                    continue;
                }
                let glyph = pane_focus_direction_glyph(dir);
                let left = cell_col as f32 * cw + ox;
                let mut buf = Buffer::new(&mut self.font_system, metrics);
                buf.set_size(&mut self.font_system, Some(cw), Some(ch));
                buf.set_text(
                    &mut self.font_system,
                    glyph,
                    Attrs::new().family(Family::Monospace),
                    Shaping::Advanced,
                );
                buf.shape_until_scroll(&mut self.font_system, false);
                pane_header_bufs.push((buf, [left, row_y, cw, ch], arrow_color));
            }
            for (cell_col, dir) in pane_header_swallow_arrow_cells(region) {
                if !ep.swallow_directions.contains(&dir) {
                    continue;
                }
                let glyph = pane_swallow_direction_glyph(dir);
                let left = cell_col as f32 * cw + ox;
                let mut buf = Buffer::new(&mut self.font_system, metrics);
                buf.set_size(&mut self.font_system, Some(cw), Some(ch));
                buf.set_text(
                    &mut self.font_system,
                    glyph,
                    Attrs::new().family(Family::Monospace),
                    Shaping::Advanced,
                );
                buf.shape_until_scroll(&mut self.font_system, false);
                pane_header_bufs.push((buf, [left, row_y, cw, ch], arrow_color));
            }
            if self.winsize_owner_remote && ep.show_local_size_reclaim {
                if let Some(cell_col) = pane_header_local_size_cell(region) {
                    let left = cell_col as f32 * cw + ox;
                    let mut buf = Buffer::new(&mut self.font_system, metrics);
                    buf.set_size(&mut self.font_system, Some(cw), Some(ch));
                    buf.set_text(
                        &mut self.font_system,
                        PANE_HEADER_LOCAL_SIZE_GLYPH,
                        Attrs::new().family(Family::Monospace),
                        Shaping::Advanced,
                    );
                    buf.shape_until_scroll(&mut self.font_system, false);
                    pane_header_bufs.push((
                        buf,
                        [left, row_y, cw, ch],
                        GColor::rgb(
                            PANE_HEADER_LOCAL_SIZE[0],
                            PANE_HEADER_LOCAL_SIZE[1],
                            PANE_HEADER_LOCAL_SIZE[2],
                        ),
                    ));
                }
            }
        }

        // Pass 3: place each cell's cached buffer at its grid cell. Every key was
        // inserted in pass 2, so the lookup never misses. The per-cell foreground is
        // applied here via `default_color` (the buffers carry no color), which is what
        // lets one shaped buffer serve a glyph in any color.
        let mut text_areas: Vec<TextArea> = Vec::new();
        for (key, left, top, span, fg, pane_clip) in placements.iter() {
            let Some(buf) = self.glyph_cache.get(key) else {
                continue;
            };
            // Clip each glyph to its own cell so a slightly-overhanging fallback
            // glyph can't bleed into the neighbor cell. Split panes additionally clamp that cell
            // bound to the pane content, which matters for a width-2 lead in the last pane column.
            let Some(bounds) = cell_text_bounds(
                *left,
                *top,
                cw * *span,
                ch,
                *pane_clip,
                self.config.width,
                self.config.height,
            ) else {
                continue;
            };
            text_areas.push(TextArea {
                buffer: buf,
                left: *left,
                top: *top,
                scale: 1.0,
                bounds,
                default_color: GColor::rgb(fg[0], fg[1], fg[2]),
                custom_glyphs: &[],
            });
        }

        // Inactive split-pane placeholder label, clipped to the inactive pane rect so it never bleeds
        // into the active grid or past the window. Drawn over the placeholder backing band.
        if let Some((buf, rect)) = split_placeholder_buf.as_ref() {
            let left = rect[0] + 4.0 * scale;
            let top = rect[1] + (rect[3] - ch).max(0.0) * 0.5;
            text_areas.push(TextArea {
                buffer: buf,
                left,
                top,
                scale: 1.0,
                bounds: TextBounds {
                    left: rect[0].floor() as i32,
                    top: rect[1].floor() as i32,
                    right: ((rect[0] + rect[2]).ceil() as i32).min(self.config.width as i32),
                    bottom: ((rect[1] + rect[3]).ceil() as i32).min(self.config.height as i32),
                },
                default_color: GColor::rgb(
                    SPLIT_PLACEHOLDER_LABEL[0],
                    SPLIT_PLACEHOLDER_LABEL[1],
                    SPLIT_PLACEHOLDER_LABEL[2],
                ),
                custom_glyphs: &[],
            });
        }
        // Extra-pane placeholder labels, each clipped to its pane rect so it never bleeds into a
        // neighbor pane or past the window. Drawn over each extra pane's placeholder backing band.
        for (buf, rect) in extra_placeholder_bufs.iter() {
            let left = rect[0] + 4.0 * scale;
            let top = rect[1] + (rect[3] - ch).max(0.0) * 0.5;
            text_areas.push(TextArea {
                buffer: buf,
                left,
                top,
                scale: 1.0,
                bounds: TextBounds {
                    left: rect[0].floor() as i32,
                    top: rect[1].floor() as i32,
                    right: ((rect[0] + rect[2]).ceil() as i32).min(self.config.width as i32),
                    bottom: ((rect[1] + rect[3]).ceil() as i32).min(self.config.height as i32),
                },
                default_color: GColor::rgb(
                    SPLIT_PLACEHOLDER_LABEL[0],
                    SPLIT_PLACEHOLDER_LABEL[1],
                    SPLIT_PLACEHOLDER_LABEL[2],
                ),
                custom_glyphs: &[],
            });
        }
        // Per-pane close `x` glyph, clipped to its corner cell so it never bleeds onto the pane content.
        for (buf, rect) in pane_close_bufs.iter() {
            text_areas.push(TextArea {
                buffer: buf,
                left: rect[0],
                top: rect[1],
                scale: 1.0,
                bounds: TextBounds {
                    left: rect[0].floor() as i32,
                    top: rect[1].floor() as i32,
                    right: ((rect[0] + rect[2]).ceil() as i32).min(self.config.width as i32),
                    bottom: ((rect[1] + rect[3]).ceil() as i32).min(self.config.height as i32),
                },
                default_color: GColor::rgb(
                    PANE_CLOSE_MARK[0],
                    PANE_CLOSE_MARK[1],
                    PANE_CLOSE_MARK[2],
                ),
                custom_glyphs: &[],
            });
        }
        // Per-pane header NAME + ARROW glyphs, each clipped to its cell (the name to its extent),
        // carrying its own color. Drawn over the header band built above.
        for (buf, rect, color) in pane_header_bufs.iter() {
            text_areas.push(TextArea {
                buffer: buf,
                left: rect[0],
                top: rect[1],
                scale: 1.0,
                bounds: TextBounds {
                    left: rect[0].floor() as i32,
                    top: rect[1].floor() as i32,
                    right: ((rect[0] + rect[2]).ceil() as i32).min(self.config.width as i32),
                    bottom: ((rect[1] + rect[3]).ceil() as i32).min(self.config.height as i32),
                },
                default_color: *color,
                custom_glyphs: &[],
            });
        }
        // Optional legacy bottom overlay. The app normally suppresses this now so renderer diagnostics
        // such as generation/revision/FPS do not appear below the terminal.
        if let Some(buf) = overlay_buf.as_ref() {
            let overlay_top = (self.config.height as f32 - ch).max(0.0);
            text_areas.push(TextArea {
                buffer: buf,
                left: 4.0 * scale,
                top: overlay_top,
                scale: 1.0,
                bounds: TextBounds {
                    left: 0,
                    top: overlay_top as i32,
                    right: self.config.width as i32,
                    bottom: self.config.height as i32,
                },
                default_color: GColor::rgb(0x9e, 0x9e, 0x9e),
                custom_glyphs: &[],
            });
        }

        // Top tab-bar labels, each clipped to its tab rect (so a long title never bleeds into the
        // next tab or past the window edge). Drawn in the reserved top row band (`top = 0`).
        for (buf, x0, x1, color) in tab_label_bufs.iter() {
            text_areas.push(TextArea {
                buffer: buf,
                left: *x0,
                top: 0.0,
                scale: 1.0,
                bounds: TextBounds {
                    left: x0.floor() as i32,
                    top: 0,
                    right: (x1.ceil() as i32).min(self.config.width as i32),
                    bottom: ch.ceil() as i32,
                },
                default_color: *color,
                custom_glyphs: &[],
            });
        }

        // Dashboard panel lines, each clipped to its one-row band so text never bleeds into the grid
        // or a neighbor row. A small left inset matches the bottom overlay's gutter.
        for (buf, top) in panel_line_bufs.iter() {
            let band_bottom = (top + ch).ceil() as i32;
            text_areas.push(TextArea {
                buffer: buf,
                left: 4.0 * scale,
                top: *top,
                scale: 1.0,
                bounds: TextBounds {
                    left: 0,
                    top: top.floor() as i32,
                    right: self.config.width as i32,
                    bottom: band_bottom.min(self.config.height as i32),
                },
                default_color: GColor::rgb(
                    DASHBOARD_PANEL_TEXT[0],
                    DASHBOARD_PANEL_TEXT[1],
                    DASHBOARD_PANEL_TEXT[2],
                ),
                custom_glyphs: &[],
            });
        }

        // Left-dock rows, each clipped to its one-row band within the dock column so labels never bleed
        // into a neighbor row or past the dock's right edge into the grid. Indented by depth.
        for (buf, top, indent) in dock_line_bufs.iter() {
            let band_bottom = (top + ch).ceil() as i32;
            text_areas.push(TextArea {
                buffer: buf,
                left: *indent,
                top: *top,
                scale: 1.0,
                bounds: TextBounds {
                    left: 0,
                    top: top.floor() as i32,
                    right: dock_w.floor() as i32,
                    bottom: band_bottom.min(self.config.height as i32),
                },
                default_color: GColor::rgb(DOCK_TEXT[0], DOCK_TEXT[1], DOCK_TEXT[2]),
                custom_glyphs: &[],
            });
        }

        // Left-dock collapse-button glyph, clipped to the button square in the top-right corner.
        if let Some((buf, left, top)) = dock_button_buf.as_ref() {
            let band_bottom = (top + ch).ceil() as i32;
            text_areas.push(TextArea {
                buffer: buf,
                left: *left + 4.0 * scale,
                top: *top,
                scale: 1.0,
                bounds: TextBounds {
                    left: left.floor() as i32,
                    top: top.floor() as i32,
                    right: dock_w.floor() as i32,
                    bottom: band_bottom.min(self.config.height as i32),
                },
                default_color: GColor::rgb(DOCK_TEXT[0], DOCK_TEXT[1], DOCK_TEXT[2]),
                custom_glyphs: &[],
            });
        }

        // Left-dock count-badge numerals, clipped to their pill (drawn as a quad above) on the row's
        // right edge. Same band-clip as the labels so a numeral never bleeds into a neighbor row.
        for (buf, top, pill_x) in dock_badge_bufs.iter() {
            let band_bottom = (top + ch).ceil() as i32;
            text_areas.push(TextArea {
                buffer: buf,
                left: *pill_x + 5.0 * scale,
                top: *top,
                scale: 1.0,
                bounds: TextBounds {
                    left: pill_x.floor() as i32,
                    top: top.floor() as i32,
                    right: dock_w.floor() as i32,
                    bottom: band_bottom.min(self.config.height as i32),
                },
                default_color: GColor::rgb(DOCK_TEXT[0], DOCK_TEXT[1], DOCK_TEXT[2]),
                custom_glyphs: &[],
            });
        }

        // Picker overlay rows, each clipped to its one-row band so text never bleeds into a neighbor
        // row. Pushed LAST so the modal text draws over the grid and all other chrome. Same left inset
        // as the bottom overlay / dashboard panel.
        for (buf, top) in picker_line_bufs.iter() {
            let band_bottom = (top + ch).ceil() as i32;
            text_areas.push(TextArea {
                buffer: buf,
                left: 4.0 * scale,
                top: *top,
                scale: 1.0,
                bounds: TextBounds {
                    left: 0,
                    top: top.floor() as i32,
                    right: self.config.width as i32,
                    bottom: band_bottom.min(self.config.height as i32),
                },
                default_color: GColor::rgb(
                    PICKER_OVERLAY_TEXT[0],
                    PICKER_OVERLAY_TEXT[1],
                    PICKER_OVERLAY_TEXT[2],
                ),
                custom_glyphs: &[],
            });
        }

        // Command-palette overlay rows: mirrors the picker overlay text draw but from the separate
        // command-palette buffers, each clipped to its one-row band. Pushed LAST so the modal text
        // draws over the grid and all other chrome. Since the parser forbids `--command-palette`
        // alongside `--picker-overlay`, the two overlays are never populated at once.
        for (buf, top, selected) in command_palette_line_bufs.iter() {
            let band_bottom = (top + ch).ceil() as i32;
            let text_color = if *selected {
                COMMAND_PALETTE_OVERLAY_SELECTED_TEXT
            } else {
                PICKER_OVERLAY_TEXT
            };
            text_areas.push(TextArea {
                buffer: buf,
                left: 4.0 * scale,
                top: *top,
                scale: 1.0,
                bounds: TextBounds {
                    left: 0,
                    top: top.floor() as i32,
                    right: self.config.width as i32,
                    bottom: band_bottom.min(self.config.height as i32),
                },
                default_color: GColor::rgb(text_color[0], text_color[1], text_color[2]),
                custom_glyphs: &[],
            });
        }

        // Split-pane shortcut hint overlay rows: mirrors the picker overlay text draw, each clipped to
        // its one-row band so text never bleeds into a neighbor row. Pushed LAST so the hint text draws
        // over the grid and other chrome. Same left inset as the other overlays.
        for (buf, top) in shortcut_hint_line_bufs.iter() {
            let band_bottom = (top + ch).ceil() as i32;
            text_areas.push(TextArea {
                buffer: buf,
                left: 4.0 * scale,
                top: *top,
                scale: 1.0,
                bounds: TextBounds {
                    left: 0,
                    top: top.floor() as i32,
                    right: self.config.width as i32,
                    bottom: band_bottom.min(self.config.height as i32),
                },
                default_color: GColor::rgb(
                    PICKER_OVERLAY_TEXT[0],
                    PICKER_OVERLAY_TEXT[1],
                    PICKER_OVERLAY_TEXT[2],
                ),
                custom_glyphs: &[],
            });
        }

        // File-preview overlay text: each composed row drawn into its RIGHT-anchored band, clipped to
        // that band so text never bleeds left into the grid or down into a neighbor row. Pushed LAST so
        // the preview text draws over the grid and other chrome. Left inset matches the other overlays.
        let file_preview_left = file_preview_x0 + 4.0 * scale;
        for (buf, top) in file_preview_line_bufs.iter() {
            let band_bottom = (top + ch).ceil() as i32;
            text_areas.push(TextArea {
                buffer: buf,
                left: file_preview_left,
                top: *top,
                scale: 1.0,
                bounds: TextBounds {
                    left: file_preview_x0 as i32,
                    top: top.floor() as i32,
                    right: self.config.width as i32,
                    bottom: band_bottom.min(self.config.height as i32),
                },
                default_color: GColor::rgb(
                    PICKER_OVERLAY_TEXT[0],
                    PICKER_OVERLAY_TEXT[1],
                    PICKER_OVERLAY_TEXT[2],
                ),
                custom_glyphs: &[],
            });
        }

        // File-path-input prompt text: each composed row drawn into its BOTTOM-anchored band, clipped to
        // that band so text never bleeds into a neighbor row. Pushed LAST so the prompt text draws over
        // the grid and other chrome. Same left inset as the other overlays.
        for (buf, top) in file_path_input_line_bufs.iter() {
            let band_bottom = (top + ch).ceil() as i32;
            text_areas.push(TextArea {
                buffer: buf,
                left: 4.0 * scale,
                top: *top,
                scale: 1.0,
                bounds: TextBounds {
                    left: 0,
                    top: top.floor() as i32,
                    right: self.config.width as i32,
                    bottom: band_bottom.min(self.config.height as i32),
                },
                default_color: GColor::rgb(
                    PICKER_OVERLAY_TEXT[0],
                    PICKER_OVERLAY_TEXT[1],
                    PICKER_OVERLAY_TEXT[2],
                ),
                custom_glyphs: &[],
            });
        }

        stats.text_areas = text_areas.len() as u32;
        let prepare_start = self.stats_enabled.then(Instant::now);
        if let Err(e) = self.text_renderer.prepare(
            &self.device,
            &self.queue,
            &mut self.font_system,
            &mut self.atlas,
            &self.viewport,
            text_areas,
            &mut self.swash_cache,
        ) {
            eprintln!("maestro-renderer: text prepare failed: {e}");
        }
        if let Some(t) = prepare_start {
            stats.text_prepare_us = t.elapsed().as_micros();
        }

        // --- encode + submit ---
        let frame = match self.surface.get_current_texture() {
            Ok(f) => f,
            Err(_) => {
                self.surface.configure(&self.device, &self.config);
                match self.surface.get_current_texture() {
                    Ok(f) => f,
                    Err(e) => {
                        eprintln!("maestro-renderer: surface error: {e}");
                        return;
                    }
                }
            }
        };
        let view = frame
            .texture
            .create_view(&wgpu::TextureViewDescriptor::default());
        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("frame-encoder"),
            });
        {
            let mut pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("main-pass"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &view,
                    resolve_target: None,
                    ops: wgpu::Operations {
                        load: wgpu::LoadOp::Clear(wgpu::Color {
                            r: srgb(bg[0]),
                            g: srgb(bg[1]),
                            b: srgb(bg[2]),
                            a: 1.0,
                        }),
                        store: wgpu::StoreOp::Store,
                    },
                })],
                depth_stencil_attachment: None,
                timestamp_writes: None,
                occlusion_query_set: None,
            });
            pass.set_pipeline(&self.quad_pipeline);
            pass.set_bind_group(0, &self.quad_bind_group, &[]);
            pass.set_vertex_buffer(0, self.instance_buf.slice(..));
            pass.draw(0..6, 0..self.instance_count);

            if let Err(e) = self
                .text_renderer
                .render(&self.atlas, &self.viewport, &mut pass)
            {
                eprintln!("maestro-renderer: text render failed: {e}");
            }
        }
        let submit_start = self.stats_enabled.then(Instant::now);
        self.queue.submit(std::iter::once(encoder.finish()));
        frame.present();
        if let Some(t) = submit_start {
            stats.submit_present_cpu_us = t.elapsed().as_micros();
        }
        self.atlas.trim();

        if let Some(start) = frame_start {
            stats.frame_total_us = start.elapsed().as_micros();
            self.print_stats(&stats);
        }
        self.frame_index = self.frame_index.wrapping_add(1);
    }

    /// Emit a one-line stats summary for this frame (only when stats are enabled).
    /// Kept on its own so the hot `render` body stays readable; the early `return`
    /// in the surface-error path is the one place a frame prints nothing, which is
    /// fine — a dropped frame has no meaningful cost breakdown.
    fn print_stats(&self, s: &FrameStats) {
        eprintln!(
            "maestro-stats frame={} total={}us cells={} glyph_buffers={} text_areas={} \
             bg_quads={} deco_quads={} glyph_build={}us prepare={}us submit_present_cpu={}us",
            self.frame_index,
            s.frame_total_us,
            s.nonblank_cells,
            s.glyph_buffers_built,
            s.text_areas,
            s.background_quads,
            s.decoration_quads,
            s.glyph_build_us,
            s.text_prepare_us,
            s.submit_present_cpu_us,
        );
    }
}

/// Derive the shaped-glyph cache key for a cell, or `None` if the cell paints no
/// glyph (a wide-cell spacer, an empty/space cell whose background already covers
/// it, or a hidden cell). Pure and color-independent so it is unit-testable without
/// a GPU and so the same key (hence the same shaped buffer) is shared across colors.
fn glyph_key_for(cell: &crate::wire::Cell) -> Option<GlyphKey> {
    if cell.width == 0 || cell.text.is_empty() || cell.text == " " || cell.hidden {
        return None;
    }
    Some(GlyphKey {
        text: cell.text.clone(),
        bold: cell.bold,
        italic: cell.italic,
        wide: cell.width == 2,
    })
}

/// Keep the glyph cache strictly within `cap`: if inserting one more entry would
/// exceed it, clear the whole map first so the post-insert size never goes above
/// `cap`. Called before EACH insert (not once per frame) because a single frame can
/// reference more than `cap` distinct glyphs. Returns whether a clear happened (the
/// caller's per-frame "shaped a fresh working set" signal; also drives the unit test).
fn enforce_glyph_cache_cap(cache: &mut HashMap<GlyphKey, Buffer>, cap: usize) -> bool {
    if cache.len() >= cap {
        cache.clear();
        return true;
    }
    false
}

/// Resolve a cell's (fg, bg) RGB against the launch-time palette, honoring inverse / hidden / dim.
fn resolved_colors(cell: &crate::wire::Cell, palette: &theme::Palette) -> (theme::Rgb, theme::Rgb) {
    let mut fg = theme::resolve_with_palette(cell.fg, palette);
    let mut bg = theme::resolve_with_palette(cell.bg, palette);
    if cell.dim {
        fg = theme::apply_dim(fg);
    }
    if cell.inverse {
        std::mem::swap(&mut fg, &mut bg);
    }
    if cell.hidden {
        fg = bg; // invisible text
    }
    (fg, bg)
}

/// Thickness of a decoration line in physical pixels at a given scale: 1 logical px,
/// floored to at least 1 physical px so it never vanishes on a fractional scale.
fn decoration_thickness(scale: f32) -> f32 {
    (1.0 * scale).max(1.0)
}

/// Whether grid cell `(col, row)` falls inside `pane`'s cell extent (zero-based, `col`/`row` relative
/// to the pane's own origin). Pure so the active-pane clip is unit-tested without a window. `None` pane
/// means "no split" and every cell is in-pane.
fn cell_in_pane(col: usize, row: usize, pane: Option<crate::RendererPaneRegion>) -> bool {
    match pane {
        None => true,
        Some(p) => col < p.cols as usize && row < p.rows as usize,
    }
}

/// Clip a physical-pixel rect `[x, y, w, h]` to optional physical-pixel bounds. `None` preserves
/// the rect byte-for-byte (the no-split rendering path). A zero-area or non-overlapping result is
/// dropped. This is the shared final paint guard for split-pane cell backgrounds, decorations,
/// cursors, selections, and glyph bounds.
fn clip_rect_to_pixel_bounds(rect: [f32; 4], bounds: Option<[f32; 4]>) -> Option<[f32; 4]> {
    let Some([clip_x, clip_y, clip_w, clip_h]) = bounds else {
        return Some(rect);
    };
    let x0 = rect[0].max(clip_x);
    let y0 = rect[1].max(clip_y);
    let x1 = (rect[0] + rect[2]).min(clip_x + clip_w);
    let y1 = (rect[1] + rect[3]).min(clip_y + clip_h);
    if x1 <= x0 || y1 <= y0 {
        return None;
    }
    Some([x0, y0, x1 - x0, y1 - y0])
}

/// Glyphon requires integer [`TextBounds`]. Start from the existing per-cell bounds, intersect them
/// with the split pane's already-quantized content edges when present, then clamp the far edges to
/// the render surface. With `pane_bounds == None` this produces the exact pre-split values.
fn cell_text_bounds(
    left: f32,
    top: f32,
    width: f32,
    height: f32,
    pane_bounds: Option<[i32; 4]>,
    surface_width: u32,
    surface_height: u32,
) -> Option<TextBounds> {
    let cell_bounds = TextBounds {
        left: left.floor() as i32,
        top: top.floor() as i32,
        right: ((left + width).ceil() as i32).min(surface_width as i32),
        bottom: ((top + height).ceil() as i32).min(surface_height as i32),
    };
    // Before split clipping, even an off-surface cell was still submitted with the surface-clamped
    // far edge. Keep that exact no-split behavior; only a split intersection may intentionally drop
    // a now-empty TextArea.
    let Some([pane_left, pane_top, pane_right, pane_bottom]) = pane_bounds else {
        return Some(cell_bounds);
    };
    let bounds = TextBounds {
        left: cell_bounds.left.max(pane_left),
        top: cell_bounds.top.max(pane_top),
        right: cell_bounds.right.min(pane_right),
        bottom: cell_bounds.bottom.min(pane_bottom),
    };
    (bounds.right > bounds.left && bounds.bottom > bounds.top).then_some(bounds)
}

/// Convert a pane's absolute grid edges to glyphon's integer clipping coordinates. Every edge uses
/// the same nearest-physical-pixel rule and is computed from the absolute cell coordinate, never as
/// `left + width`. Adjacent panes therefore quantize a shared fractional edge to the identical i32:
/// one pane's `right` is exactly its neighbor's `left` (and likewise bottom/top), with no overlap or
/// gap. `header_rows` shifts only the content top; the right/bottom remain the pane's outer edges.
fn pane_text_clip(
    pane: crate::RendererPaneRegion,
    header_rows: u16,
    cw: f32,
    ch: f32,
    ox: f32,
    oy: f32,
) -> [i32; 4] {
    let col_start = pane.col as u32;
    let col_end = col_start + pane.cols as u32;
    let row_start = pane.row as u32;
    let row_end = row_start + pane.rows as u32;
    let content_row_start = row_start + header_rows.min(pane.rows) as u32;
    let edge = |cell: u32, metric: f32, origin: f32| (origin + cell as f32 * metric).round() as i32;
    [
        edge(col_start, cw, ox),
        edge(content_row_start, ch, oy),
        edge(col_end, cw, ox),
        edge(row_end, ch, oy),
    ]
}

/// Clip a physical-pixel rect `[x, y, w, h]` to the active pane's pixel bounds, returning the clipped
/// rect or `None` if it falls fully outside. `None` pane means "no split" → the rect is returned
/// unchanged. `pane_off_*` are the pane origin in pixels (already added to the rect by the caller);
/// `cw`/`ch` are the physical cell size. Pure so the selection clip is unit-testable.
fn clip_rect_to_pane(
    rect: [f32; 4],
    pane: Option<crate::RendererPaneRegion>,
    pane_off_x: f32,
    pane_off_y: f32,
    cw: f32,
    ch: f32,
) -> Option<[f32; 4]> {
    clip_rect_to_pixel_bounds(
        rect,
        pane.map(|p| {
            [
                pane_off_x,
                pane_off_y,
                p.cols as f32 * cw,
                p.rows as f32 * ch,
            ]
        }),
    )
}

/// Physical-pixel rect `[x, y, w, h]` covering a whole pane region, in grid-cell space. `oy` is the
/// grid origin offset (top chrome). Pure so the placeholder backing is unit-testable.
fn pane_pixel_rect(
    pane: crate::RendererPaneRegion,
    cw: f32,
    ch: f32,
    ox: f32,
    oy: f32,
) -> [f32; 4] {
    [
        pane.col as f32 * cw + ox,
        pane.row as f32 * ch + oy,
        pane.cols as f32 * cw,
        pane.rows as f32 * ch,
    ]
}

/// Bound the actual dock width and terminal-grid origin to one surface. The grid origin is clamped to
/// at least the dock edge so a malformed/out-of-order caller cannot paint terminal cells over chrome;
/// a larger origin intentionally leaves terminal-background padding between them. Pure so the
/// dock-vs-padding separation is regression-tested without a GPU.
fn resolved_horizontal_origins(
    dock_width_x: f32,
    grid_origin_x: f32,
    surface_width: f32,
) -> (f32, f32) {
    if !surface_width.is_finite() || surface_width <= 0.0 {
        return (0.0, 0.0);
    }
    let sanitize = |value: f32| {
        if value.is_finite() {
            value.max(0.0).min(surface_width)
        } else {
            0.0
        }
    };
    let dock = sanitize(dock_width_x);
    let grid = sanitize(grid_origin_x).max(dock);
    (dock, grid)
}

/// The four thin border rects (top, bottom, left, right) outlining a pane's pixel rect for the
/// focused-pane indicator, each `thickness` physical px wide and drawn just INSIDE the pane so the
/// frame sits over the pane's own content rather than bleeding into a neighbour. Returns an empty
/// `Vec` when the pane is too small to host the border (so a degenerate region draws nothing).
/// Pure — no GPU, no window — so the border geometry is unit-tested and provably never alters the
/// pane region it outlines.
fn focus_border_rects(
    pane: crate::RendererPaneRegion,
    cw: f32,
    ch: f32,
    ox: f32,
    oy: f32,
    thickness: f32,
) -> Vec<[f32; 4]> {
    let [x, y, w, h] = pane_pixel_rect(pane, cw, ch, ox, oy);
    if w <= 0.0 || h <= 0.0 {
        return Vec::new();
    }
    // Clamp the band so a tiny pane never has overlapping/outsized borders.
    let t = thickness.min(w).min(h);
    vec![
        [x, y, w, t],         // top
        [x, y + h - t, w, t], // bottom
        [x, y, t, h],         // left
        [x + w - t, y, t, h], // right
    ]
}

/// The inactive-pane paint decision: given whether the active tab participates in a split
/// (`has_frame`) and whether a live sibling grid is cached for the inactive pane (`has_sibling_grid`),
/// return `(paint_sibling_grid, show_placeholder)`. The two are mutually exclusive: a live sibling
/// grid replaces the placeholder; with no grid (or no split) the placeholder stands. Pure so the
/// render branch is unit-tested without a window — `render` consumes the same booleans.
fn sibling_paint_decision(has_frame: bool, has_sibling_grid: bool) -> (bool, bool) {
    let paint_sibling_grid = has_frame && has_sibling_grid;
    let show_placeholder = has_frame && !paint_sibling_grid;
    (paint_sibling_grid, show_placeholder)
}

/// Status of the inactive pane's cached sibling session, sourced from the renderer's sibling cache
/// (`Shared::sibling`) by the App and shown in the placeholder label. When a live sibling grid is
/// cached the inactive pane paints that grid instead of the placeholder; an exited pane may retain
/// and paint its final grid, while an exited/unbound pane without a grid keeps the placeholder whose
/// label carries this status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SiblingPaneStatus {
    /// No sibling bound (no split, or no resolved `inactive_session_id`). The placeholder shows id only.
    #[default]
    Detached,
    /// Sibling bound/attached but no grid cached yet (awaiting its first baseline).
    Pending,
    /// Sibling has a cached grid (attached and baselined). Still not rendered this turn.
    Attached,
    /// Sibling session process has exited.
    Exited,
}

impl SiblingPaneStatus {
    /// The short status token appended to the placeholder label, or `None` for `Detached`
    /// (so the no-sibling label stays exactly `[tab · sid]` / `[tab]`).
    fn token(self) -> Option<&'static str> {
        match self {
            SiblingPaneStatus::Detached => None,
            SiblingPaneStatus::Pending => Some("pending"),
            SiblingPaneStatus::Attached => Some("attached"),
            SiblingPaneStatus::Exited => Some("exited"),
        }
    }
}

/// One extra non-active pane to paint, beyond the active pane and the rendered sibling. `region` is
/// the absolute window-grid region (cells); `grid` is the pane's cached snapshot (`None` → paint the
/// placeholder). `tab_id`/`session_id`/`status` feed the placeholder label when there is no live grid
/// (including an exited pane whose final grid was unavailable). Pure data set by the App from
/// `compute_split_layout` + `Shared::panes`.
///
/// Generic over the grid handle `T` so the pure planning logic ([`crate::plan_extra_panes`]) is
/// unit-testable with a fake grid; the live render path uses [`ExtraPanePaint`]
/// (`T = Arc<GridSnapshot>`).
#[derive(Clone)]
pub struct ExtraPanePaintOf<T> {
    pub region: crate::RendererPaneRegion,
    pub grid: Option<T>,
    pub tab_id: String,
    pub session_id: String,
    pub status: SiblingPaneStatus,
    /// Display name for the pane header bar (left-aligned). Resolved by the App from the tab strip
    /// (`tab.name`), falling back to the tab id when the tab is not in the strip.
    pub name: String,
    /// Whether this pane currently holds input focus — drives the brighter header band + amber border.
    pub focused: bool,
    /// Whether this pane should draw a header bar. False for a single full-window pane (no split), so
    /// the unsplit view stays byte-identical (no header band, no content shift). True only when the
    /// layout actually tiles 2+ panes.
    pub show_header: bool,
    /// Whether this pane should draw the local-size reclaim glyph while Remote owns global PTY sizing.
    /// This is pane-local: once a specific pane has been reclaimed locally, its glyph disappears while
    /// other still-remote-sized panes may keep theirs.
    pub show_local_size_reclaim: bool,
    /// Feasible directional swap arrows for this pane. The renderer draws only these directions so the
    /// header never advertises a no-op edge.
    pub move_directions: Vec<crate::PaneFocusDirection>,
    /// Feasible directional swallow arrows for this pane. Mirrors the canonical three-pane swallow
    /// table; empty for layouts where swallow is currently unsupported.
    pub swallow_directions: Vec<crate::PaneSwallowDirection>,
    /// Local-selection range in ABSOLUTE window-grid coordinates when this pane owns the selection.
    /// The renderer translates it to this pane's content-local grid before painting. `None` whenever
    /// this pane does not own the current selection.
    pub selection: Option<(CellPos, CellPos)>,
}

/// The live-path extra pane: an [`ExtraPanePaintOf`] whose grid handle is the cached
/// `Arc<GridSnapshot>` the renderer paints.
pub type ExtraPanePaint = ExtraPanePaintOf<std::sync::Arc<GridSnapshot>>;

/// The inactive-pane placeholder label: the sibling tab id, its session id when resolved, and the
/// sibling cache status when bound, e.g. `[src · s-9 · attached]`. A missing session id (`None` →
/// sibling tab not in the strip, no attach target yet) drops the session segment; a `Detached` status
/// drops the status segment, so an unbound split still shows `[src]` / `[src · s-9]`. Pure so the
/// status bridge is unit-tested without a window; the renderer owns the bracket/separator glyphs.
fn split_placeholder_label(
    tab_id: &str,
    session_id: Option<&str>,
    status: SiblingPaneStatus,
) -> String {
    let mut label = match session_id {
        Some(sid) => format!("[{tab_id} \u{b7} {sid}"),
        None => format!("[{tab_id}"),
    };
    if let Some(tok) = status.token() {
        label.push_str(" \u{b7} ");
        label.push_str(tok);
    }
    label.push(']');
    label
}

/// Physical-pixel rect `[x, y, w, h]` for a split-pane divider line, in grid-cell space. Pure (no GPU
/// state) so the geometry is unit-tested directly. `cw`/`ch` are the physical cell size; `oy` the grid
/// origin offset (top chrome pushes the grid down).
///
/// - [`Right`](crate::RendererTabSplitAxis::Right): a vertical line one cell wide spanning `length`
///   rows from the top of the grid, at column `divider.col`.
/// - [`Down`](crate::RendererTabSplitAxis::Down): a horizontal line one cell tall spanning `length`
///   columns from the left, at row `divider.row`.
fn split_divider_rect(
    divider: &crate::RendererSplitDivider,
    axis: crate::RendererTabSplitAxis,
    cw: f32,
    ch: f32,
    ox: f32,
    oy: f32,
) -> [f32; 4] {
    match axis {
        crate::RendererTabSplitAxis::Right => {
            let x = divider.col as f32 * cw + ox;
            // `divider.row` is 0 for a top-level (two-pane) divider, so this stays byte-identical
            // there; a NESTED Right divider starts partway down its parent region's row offset.
            let y = divider.row as f32 * ch + oy;
            [x, y, cw, divider.length as f32 * ch]
        }
        crate::RendererTabSplitAxis::Down => {
            let y = divider.row as f32 * ch + oy;
            // `divider.col` is 0 for a top-level (two-pane) divider; a nested Down divider starts at
            // its parent region's column offset.
            let x = divider.col as f32 * cw + ox;
            [x, y, divider.length as f32 * cw, ch]
        }
    }
}

/// Width, in physical pixels, of the file-preview pane divider: a thin DPI-scaled stripe (>=1px) at
/// the band's left edge. A fixed multiple of `scale` so the line stays visible at any DPI without
/// stealing a full cell column.
const FILE_PREVIEW_DIVIDER_WIDTH: f32 = 2.0;

/// Build the file-preview pane divider rect `[x, y, w, h]` in physical pixels: a thin vertical stripe
/// at the band's left edge `x0`, spanning the full painted band height `band_h` from physical y=0.
/// Pure (no GPU state) so it can be unit-tested without a window. The width is DPI-scaled and floored
/// to at least 1px so the divider never vanishes.
fn file_preview_divider_rect(x0: f32, band_h: f32, scale: f32) -> [f32; 4] {
    let w = (FILE_PREVIEW_DIVIDER_WIDTH * scale).max(1.0);
    [x0, 0.0, w, band_h]
}

/// Infer a divider's axis from its chrome glyph: `|` is a vertical (`Right`-split) divider, anything
/// else (`-`) is a horizontal (`Down`-split) divider. The extra-pane dividers from
/// [`compute_split_layout`](crate::compute_split_layout) carry the glyph but not the axis, so the
/// paint path recovers it here. Pure.
fn divider_axis(divider: &crate::RendererSplitDivider) -> crate::RendererTabSplitAxis {
    if divider.glyph == '|' {
        crate::RendererTabSplitAxis::Right
    } else {
        crate::RendererTabSplitAxis::Down
    }
}

/// Build the DECORATION rectangles for one cell, in physical pixels, as `[x, y, w, h]`
/// quads to be painted in the cell's foreground color. Pure (no GPU state) so the
/// style→geometry mapping is unit-tested directly.
///
/// `x`/`y` are the cell's top-left; `cw`/`ch` its physical size; `scale` the DPI factor.
///
/// Supported faithfully:
///
/// - `Single`  — one bar near the baseline.
/// - `Double`  — two stacked bars.
/// - `Dotted`  — a row of short square dots along the baseline.
/// - `Dashed`  — a row of longer dashes along the baseline.
/// - strikeout — one bar through the vertical middle (independent of underline).
///
/// Approximated honestly (documented limitation): `Curly` (the wavy "spell-check"
/// underline) cannot be drawn as a smooth sine with axis-aligned quads without a
/// dedicated shader, which is out of scope for this commit. We render it as a DENSE
/// dotted bar so the cell is still visibly distinguished as curly-underlined; a true
/// wavy curl is deferred to a future decoration-shader pass.
fn decoration_rects(
    underline: UnderlineStyle,
    strikeout: bool,
    x: f32,
    y: f32,
    cw: f32,
    ch: f32,
    scale: f32,
) -> Vec<[f32; 4]> {
    let mut rects: Vec<[f32; 4]> = Vec::new();
    let t = decoration_thickness(scale);

    // Underline baseline: a hair above the very bottom so it isn't clipped by the
    // next row. Double underline stacks a second bar just above the first.
    let base_y = y + ch - 2.0 * t;
    match underline {
        UnderlineStyle::None => {}
        UnderlineStyle::Single => rects.push([x, base_y, cw, t]),
        UnderlineStyle::Double => {
            rects.push([x, base_y, cw, t]);
            rects.push([x, base_y - 2.0 * t, cw, t]);
        }
        UnderlineStyle::Dotted => {
            // Square dots ~1 thickness wide, 1 thickness gap.
            push_segments(&mut rects, x, base_y, cw, t, t.max(1.0), t.max(1.0));
        }
        UnderlineStyle::Dashed => {
            // Longer dashes (~4t) with a 2t gap.
            push_segments(&mut rects, x, base_y, cw, t, (4.0 * t).max(2.0), 2.0 * t);
        }
        UnderlineStyle::Curly => {
            // Approximation (see fn doc): a dense dotted bar stands in for the wavy
            // curl until a decoration shader exists.
            push_segments(&mut rects, x, base_y, cw, t, t.max(1.0), t.max(1.0));
        }
    }

    if strikeout {
        // Centered vertically through the cell.
        let mid_y = y + (ch - t) * 0.5;
        rects.push([x, mid_y, cw, t]);
    }

    rects
}

/// Append a row of horizontal dash segments spanning `[x, x+width)` at vertical `y`
/// with bar thickness `t`. Each `seg_len` segment is followed by a `gap` of blank
/// space; the final segment is clipped so it never overruns the cell width.
fn push_segments(
    rects: &mut Vec<[f32; 4]>,
    x: f32,
    y: f32,
    width: f32,
    t: f32,
    seg_len: f32,
    gap: f32,
) {
    let step = seg_len + gap;
    if step <= 0.0 || width <= 0.0 {
        return;
    }
    let mut sx = 0.0_f32;
    while sx < width {
        let len = seg_len.min(width - sx);
        if len > 0.0 {
            rects.push([x + sx, y, len, t]);
        }
        sx += step;
    }
}

/// Build the highlight rects (physical pixels) for the selection `[a, b]` over
/// the painted grid `g`. One rect per selected row span: the first row from the
/// anchor column to the row end, intermediate rows full width, the last row to
/// the focus column. Rows beyond the grid are clamped out. `cw`/`ch` are the
/// physical cell metrics.
fn selection_rects(g: &GridSnapshot, a: CellPos, b: CellPos, cw: f32, ch: f32) -> Vec<[f32; 4]> {
    if g.rows == 0 || g.cols == 0 {
        return Vec::new();
    }
    let (start, end) = if (a.row, a.col) <= (b.row, b.col) {
        (a, b)
    } else {
        (b, a)
    };
    let last_row = g.rows - 1;
    let r0 = start.row.min(last_row);
    let r1 = end.row.min(last_row);
    let last_col = g.cols - 1;

    let mut rects = Vec::with_capacity(r1 - r0 + 1);
    for r in r0..=r1 {
        let col_start = if r == r0 { start.col } else { 0 };
        let col_end = if r == r1 { end.col } else { last_col };
        let col_start = col_start.min(last_col);
        let col_end = col_end.min(last_col);
        let x = col_start as f32 * cw;
        let w = (col_end - col_start + 1) as f32 * cw;
        let y = r as f32 * ch;
        rects.push([x, y, w, ch]);
    }
    rects
}

/// Translate an absolute window-grid selection cell to one split pane's content-local grid.
/// Header rows belong to renderer chrome, so the content origin includes `header_rows`. Dragging
/// across a divider/neighbor is clamped at the owning pane's last cell rather than selecting text
/// from another PTY. Zero-sized grids map to `(0, 0)`; `selection_rects` then emits nothing.
fn pane_local_selection_cell(
    cell: CellPos,
    region: crate::RendererPaneRegion,
    header_rows: u16,
    grid_cols: usize,
    grid_rows: usize,
) -> CellPos {
    let content_col = region.col as usize;
    let content_row = region.row.saturating_add(header_rows) as usize;
    CellPos {
        col: cell
            .col
            .saturating_sub(content_col)
            .min(grid_cols.saturating_sub(1)),
        row: cell
            .row
            .saturating_sub(content_row)
            .min(grid_rows.saturating_sub(1)),
    }
}

#[cfg(test)]
mod split_selection_tests {
    use super::{pane_local_selection_cell, CellPos};
    use crate::RendererPaneRegion;

    #[test]
    fn absolute_cell_translates_below_split_header() {
        let region = RendererPaneRegion {
            col: 40,
            row: 7,
            cols: 30,
            rows: 20,
        };
        assert_eq!(
            pane_local_selection_cell(CellPos { col: 44, row: 12 }, region, 2, 30, 18),
            CellPos { col: 4, row: 3 }
        );
    }

    #[test]
    fn selection_drag_clamps_to_owning_pane_grid() {
        let region = RendererPaneRegion {
            col: 40,
            row: 7,
            cols: 30,
            rows: 20,
        };
        assert_eq!(
            pane_local_selection_cell(CellPos { col: 999, row: 999 }, region, 2, 30, 18),
            CellPos { col: 29, row: 17 }
        );
        assert_eq!(
            pane_local_selection_cell(CellPos { col: 0, row: 0 }, region, 2, 30, 18),
            CellPos { col: 0, row: 0 }
        );
    }
}

// --- top tab bar styling (pure, unit-testable) ---
// Local to render.rs (NOT in theme.rs, which is user-owned): a small palette for the opt-in top bar.
// Fills read as a stack — active brightest, hovered-inactive a step up from quiet inactive — so hover
// is visible without competing with the active tab. Attention is a distinct accent, not a fill swap,
// so an attention tab still reads as active/inactive/hovered underneath it.
const TOP_BAR_BAND: theme::Rgb = [0x12, 0x14, 0x18];
// Left-dock column fill: a deep, slightly cool dark so the dock reads as a distinct surface behind the
// (lighter) terminal grid to its right. Square edges only; accent bars, dots, and badges add
// hierarchy without a gradient or rounded corner here.
const DOCK_FILL: theme::Rgb = [0x0d, 0x0f, 0x13];

// Left-dock row label color: a soft off-white that reads clearly on `DOCK_FILL` without competing with
// the active-row/accent emphasis.
const DOCK_TEXT: theme::Rgb = [0xc8, 0xcd, 0xd6];

// Per-row backing fill for the ACTIVE/FOCUSED dock row: a lifted slate so the selected project/pane
// reads as raised off the dock surface. Drawn under the accent bar and label.
const DOCK_ROW_ACTIVE: theme::Rgb = [0x1c, 0x22, 0x2c];
// Subtler backing for a non-active project HEADER so depth-0 rows read as section headers even when
// not selected.
const DOCK_ROW_HEADER: theme::Rgb = [0x14, 0x18, 0x1f];
// Neutral accent bar / status fallbacks when a row has no `#rrggbb` accent.
const DOCK_ACCENT_FALLBACK: theme::Rgb = [0x3a, 0x42, 0x50];
// Status dot: live (green), stashed/dormant (muted amber).
const DOCK_DOT_LIVE: theme::Rgb = [0x4a, 0xd6, 0x6e];
const DOCK_DOT_STASHED: theme::Rgb = [0xc9, 0x9a, 0x3f];
// Count-badge pill fill behind the numeric badge on project/window rows.
const DOCK_BADGE_FILL: theme::Rgb = [0x26, 0x2d, 0x38];
const TOP_TAB_INACTIVE: theme::Rgb = [0x1c, 0x20, 0x26];
const TOP_TAB_HOVER: theme::Rgb = [0x26, 0x2c, 0x34];
const TOP_TAB_ACTIVE: theme::Rgb = [0x2e, 0x35, 0x40];
const TOP_LABEL_ACTIVE: theme::Rgb = [0xe6, 0xe6, 0xe6];
const TOP_LABEL_HOVER: theme::Rgb = [0xc8, 0xcc, 0xd2];
const TOP_LABEL_INACTIVE: theme::Rgb = [0x9a, 0xa0, 0xa8];
const TOP_ATTENTION_ACCENT: theme::Rgb = [0xe5, 0xa0, 0x3a];
// Split-pane divider line: a quiet steel color that reads against both light and dark cells without
// claiming attention. Local to render.rs (theme.rs is user-owned and untouched).
const SPLIT_DIVIDER_LINE: theme::Rgb = [0x3a, 0x40, 0x4a];
// Inactive split pane: a quiet backing band a touch darker than the active grid, with a calm label
// color, so the sibling pane reads as a dormant placeholder (no live session yet). Local to render.rs
// (theme.rs is user-owned and untouched).
const SPLIT_PLACEHOLDER_BAND: theme::Rgb = [0x0c, 0x0e, 0x12];
const SPLIT_PLACEHOLDER_LABEL: theme::Rgb = [0x7a, 0x80, 0x8a];
// Read-only dashboard panel chrome: a quiet band a half-step darker than the tab bar so the panel
// reads as a distinct surface stacked below the tabs, with calm readable text. Local to render.rs
// (theme.rs is user-owned and untouched).
const DASHBOARD_PANEL_BAND: theme::Rgb = [0x0e, 0x10, 0x14];
const DASHBOARD_PANEL_TEXT: theme::Rgb = [0xb4, 0xba, 0xc2];
// Read-only picker overlay chrome: a near-black dim backdrop (drawn at ~0.92 alpha) that quiets the
// grid behind the modal, a slightly lighter row band, and calm readable row text. Local to render.rs
// (theme.rs is user-owned and untouched).
const PICKER_OVERLAY_BACKDROP: theme::Rgb = [0x06, 0x07, 0x0a];
const PICKER_OVERLAY_ROW: theme::Rgb = [0x12, 0x15, 0x1b];
const PICKER_OVERLAY_TEXT: theme::Rgb = [0xc6, 0xcc, 0xd4];
// File-preview pane divider: a quiet steel-blue stripe at the band's left edge, brighter than the row
// band so it reads as a deliberate pane border between the grid and the preview. Local to render.rs
// (theme.rs is user-owned and untouched).
const FILE_PREVIEW_DIVIDER: theme::Rgb = [0x3a, 0x44, 0x55];
// Command-palette overlay selected-action-row highlight: a brighter row band than the unselected
// PICKER_OVERLAY_ROW plus near-white text, so the single focused action reads as selected without any
// keyboard/activation behavior. Display-only scaffolding, local to render.rs (theme.rs is user-owned
// and untouched).
const COMMAND_PALETTE_OVERLAY_SELECTED_ROW: theme::Rgb = [0x2b, 0x3a, 0x55];
const COMMAND_PALETTE_OVERLAY_SELECTED_TEXT: theme::Rgb = [0xf2, 0xf5, 0xfa];
// Overflow cue: a quiet fill behind the right-edge `>` marker cell, plus a brighter glyph color, so a
// truncated strip reads as "more tabs this way" without competing with the active tab.
const TOP_OVERFLOW_FILL: theme::Rgb = [0x22, 0x27, 0x2e];
const TOP_OVERFLOW_MARK: theme::Rgb = [0xc8, 0xcc, 0xd2];
// ASCII-only cue (no icon/glyph dependency); a single `>` aligned to the reserved right-edge cell.
const TOP_OVERFLOW_GLYPH: &str = ">";
// Close affordance: a quiet backing cell at the right inside edge of each tab plus a brighter ASCII
// `x` glyph. Local constants only; theme.rs is not touched. The width is one cell column (the live
// cell width), so the marker stays aligned with the band's character grid. The drawn rect and the
// click hit-test share one geometry helper (`tab_close_rect_for_item`) so they cannot drift.
const TOP_CLOSE_FILL: theme::Rgb = [0x2a, 0x20, 0x22];
const TOP_CLOSE_MARK: theme::Rgb = [0xc8, 0xcc, 0xd2];
// ASCII-only (no icon/glyph dependency); a single `x` aligned to the tab's right inside edge.
const TOP_CLOSE_GLYPH: &str = "x";
// A close cell only earns its space if the tab still leaves at least this many physical pixels of
// title area before it; below that the tab is "too narrow" and we draw no close marker (the title
// keeps the whole rect). Expressed as a multiple of the close cell width so it scales with DPI.
const TOP_CLOSE_MIN_TITLE_RATIO: f32 = 1.0;
// Inside gap between the close cell's right edge and the tab's right edge, as a fraction of the cell
// width (floored to >=1px). The single source of truth for the close-cell padding shared by the draw
// sites and `tab_close_rect_for_item`, so the drawn `x` and the click target stay identical.
const TOP_CLOSE_PAD_RATIO: f32 = 0.5;
// Per-pane close affordance: a brighter `×` anchored to the upper-right corner of EACH split pane
// region, so any pane can be closed (stashed) directly. The hit-test is intentionally wider than the
// glyph, but the backing is not drawn as a separate patch; it should sit naturally on the pane header.
// Local constants only; theme.rs is untouched.
const PANE_CLOSE_MARK: theme::Rgb = [0xc8, 0xcc, 0xd2];
const PANE_CLOSE_GLYPH: &str = "\u{00d7}";
// A pane only earns a close cell when its region is at least this many cells wide AND tall — below that
// the pane is too small to host a corner marker without swamping its content, so none is drawn.
const PANE_CLOSE_MIN_COLS: u16 = 3;
const PANE_CLOSE_MIN_ROWS: u16 = 3;
// Per-pane HEADER bar: a taller band at the top of
// every split pane carrying the pane NAME (left), a cluster of move/swallow arrow glyphs (right,
// rendered but not wired to events), and the `x` close marker (far right).
// The focused pane's header brightens and the focused-pane border accents amber, mirroring
// `.terminal-pane.is-focused .pane-tab`. Local constants only; theme.rs (user-owned) is untouched.
const PANE_HEADER_BAND: theme::Rgb = [0x0d, 0x0e, 0x12];
const PANE_HEADER_BAND_FOCUSED: theme::Rgb = [0x12, 0x13, 0x18];
const PANE_HEADER_NAME: theme::Rgb = [0x71, 0x71, 0x7a];
const PANE_HEADER_NAME_FOCUSED: theme::Rgb = [0xf2, 0xf4, 0xf7];
const PANE_HEADER_LOCAL_SIZE: theme::Rgb = [0xf0, 0xb8, 0x4f];
// Arrow-cluster glyph color. The
// glyphs render but emit no events yet; wiring (swap/swallow) reuses `pane_header_button_cells`.
const PANE_HEADER_ARROW: theme::Rgb = [0xa3, 0xa8, 0xb3];
// Move/swap directional arrows followed by the
// swallow arrows (span this pane to its full band). Laid out left→right just before the `x`.
const PANE_HEADER_MOVE_GLYPHS: [&str; 4] = ["\u{2190}", "\u{2193}", "\u{2191}", "\u{2192}"]; // ← ↓ ↑ →
const PANE_HEADER_SWALLOW_GLYPHS: [&str; 4] = ["\u{21e4}", "\u{2913}", "\u{2912}", "\u{21e5}"]; // ⇤ ⤓ ⤒ ⇥
const PANE_HEADER_LOCAL_SIZE_GLYPH: &str = "\u{25a3}"; // ▣
const PANE_HEADER_VISUAL_ROWS: f32 = 1.5;
const PANE_HEADER_ROWS: u16 = 2;
const PANE_HEADER_BUTTON_RIGHT_INSET_CELLS: u16 = 5;
// Mirrors `lib.rs` hit testing: the close button is a small button, not a one-cell pinhead.
// Keep the visible backing in lockstep with the real click zone.
const PANE_CLOSE_HIT_COLS: u16 = 7;
// The arrow cluster (4 move + 4 swallow = 8 glyphs) is laid out with breathing room so each glyph is
// an easy click target once wired: one-cell gaps between glyphs, a wider gap between clusters, and a
// gap before the `×`. That makes the cluster span 18 cells.
const PANE_HEADER_ARROW_CLUSTER_CELLS: u16 = 18;
// The arrow cluster only renders when the pane is wide enough to also hold a readable name and the `x`.
// Below this width the cluster is dropped (name + `x` only). Sized so the wider, spaced cluster still
// leaves several cells for the name.
const PANE_HEADER_MIN_COLS_FOR_ARROWS: u16 = 36;
// New-tab affordance: a quiet backing cell plus a brighter ASCII `+`, placed in the top band's
// right-edge region. Local constants only; theme.rs is not touched. One cell column wide so it stays
// aligned with the band grid. The drawn rect and the click hit-test share `new_tab_rect`, so the
// drawn `+` and the click target cannot drift.
const TOP_NEWTAB_FILL: theme::Rgb = [0x1e, 0x28, 0x22];
const TOP_NEWTAB_MARK: theme::Rgb = [0xc8, 0xcc, 0xd2];
// ASCII-only (no icon/glyph dependency); a single `+` aligned to the reserved new-tab cell.
const TOP_NEWTAB_GLYPH: &str = "+";
// Split affordances: two quiet backing cells plus brighter ASCII glyphs (`>` = split-right, `v` =
// split-down), placed in the top band's right-edge region IMMEDIATELY LEFT of the new-tab `+`. Local
// constants only; theme.rs is not touched. Each is one cell column wide so it stays aligned with the
// band grid. The drawn rects and the click hit-test share `split_button_rects`, so the drawn glyphs
// and the click targets cannot drift. These make splitting discoverable without the hidden chords.
const TOP_SPLIT_FILL: theme::Rgb = [0x1e, 0x24, 0x2c];
const TOP_SPLIT_MARK: theme::Rgb = [0xc8, 0xcc, 0xd2];
const TOP_SPLIT_RIGHT_GLYPH: &str = ">";
const TOP_SPLIT_DOWN_GLYPH: &str = "v";
// Swap affordance: a quiet backing cell plus a brighter ASCII `s` (swap the active split's two
// panes), placed in the top band's right-edge region IMMEDIATELY LEFT of the split-right `>`. Local
// constants only; theme.rs is not touched. One cell column wide so it stays aligned with the band
// grid. The drawn rect and the click hit-test share `swap_button_rect`, so the drawn glyph and the
// click target cannot drift. ASCII-only (no icon/glyph dependency).
const TOP_SWAP_FILL: theme::Rgb = [0x1e, 0x2c, 0x2a];
const TOP_SWAP_MARK: theme::Rgb = [0xc8, 0xcc, 0xd2];
const TOP_SWAP_GLYPH: &str = "s";
// Swallow affordance: a quiet backing cell plus a brighter ASCII `o` (the active split's pane
// reclaims the full frame, dissolving the divider without killing the sibling session), placed in the
// top band's right-edge region IMMEDIATELY LEFT of the swap `s`. Local constants only; theme.rs is
// not touched. One cell column wide so it stays aligned with the band grid. The drawn rect and the
// click hit-test share `swallow_button_rect`, so the drawn glyph and the click target cannot drift.
// ASCII-only (no icon/glyph dependency).
const TOP_SWALLOW_FILL: theme::Rgb = [0x2c, 0x28, 0x1e];
const TOP_SWALLOW_MARK: theme::Rgb = [0xc8, 0xcc, 0xd2];
const TOP_SWALLOW_GLYPH: &str = "o";
// Remote-access kill-switch toggle: a TEXT button ("Open Remote" when currently closed = the action to open;
// "Close Remote" when currently open), placed in the top band's right-edge region IMMEDIATELY LEFT of the swallow
// `o`. Unlike the single-glyph affordances this one is several cells wide (label + a trailing status dot). A small
// filled dot on the RIGHT of the button is GREEN when remote access is OPEN and dark when CLOSED, so the user can
// tell at a glance whether the machine is reachable from a browser. The drawn rect + the click hit-test share
// `remote_toggle_button_rect`, so the glyphs and the click target cannot drift.
// Backing is a distinctly brighter cell than the band (TOP_BAR_BAND = [0x12,0x14,0x18]) so the button reads as a
// real control, not blank band. Label is near-white for legibility. The status dot is GREEN when open and a clear
// RED/amber when closed (so "closed" is an unmistakable state, not the absence of a dot).
const TOP_REMOTE_FILL: theme::Rgb = [0x28, 0x30, 0x2c];
const TOP_REMOTE_MARK: theme::Rgb = [0xe8, 0xec, 0xf2];
const TOP_REMOTE_LABEL_OPEN: &str = "Open Remote"; // shown when currently CLOSED (click to open)
const TOP_REMOTE_LABEL_CLOSE: &str = "Close Remote"; // shown when currently OPEN (click to close)
const TOP_REMOTE_DOT_ON: theme::Rgb = [0x4a, 0xd6, 0x6e]; // green: reachable (same as DOCK_DOT_LIVE)
const TOP_REMOTE_DOT_OFF: theme::Rgb = [0xd6, 0x4a, 0x4a]; // red: NOT reachable (closed)
/// Width of the remote toggle button in whole tab-band cells (label chars + 1 padding + 2 for the dot area).
const TOP_REMOTE_CELLS: usize = 14;
// Winsize-owner toggle: action label + dot. "Size Remote" means clicking hands PTY geometry to the browser;
// "Size Local" means clicking hands it back to the desktop. Separate from the remote-access kill switch.
const TOP_WINSIZE_FILL: theme::Rgb = [0x26, 0x2a, 0x34];
const TOP_WINSIZE_MARK: theme::Rgb = [0xe8, 0xec, 0xf2];
const TOP_WINSIZE_LABEL_REMOTE: &str = "Size Remote";
const TOP_WINSIZE_LABEL_LOCAL: &str = "Size Local";
const TOP_WINSIZE_DOT_REMOTE: theme::Rgb = [0x6e, 0x96, 0xff];
const TOP_WINSIZE_DOT_LOCAL: theme::Rgb = [0x4a, 0xd6, 0x6e];
const TOP_WINSIZE_CELLS: usize = 13;

/// Pure: the bounded rects of the two SPLIT affordance cells (`>` split-right, `v` split-down), or
/// `None` when the geometry is degenerate or there is no room. Mirrors [`new_tab_rect`]: the draw
/// passes (fill quad + glyph) and the `lib.rs` click hit-test both call it, so the drawn cells and the
/// click targets cannot drift. The two cells are one cell column wide each and full band height
/// (`y = 0`, `h = ch`). Placement: they sit IMMEDIATELY LEFT of the reserved new-tab `+` cell, in
/// order `[split-right, split-down]` from left to right, so the right-edge order is
/// `> v +  [overflow]`. Returned ONLY when BOTH cells fit fully inside the window (`x >= 0` for the
/// leftmost). It knows nothing about sessions, windows, or app/daemon state. Returns
/// `(split_right_rect, split_down_rect)`. `None` for: non-finite/non-positive `physical_width`,
/// `cell_phys_w`, or `ch`; or no room for the new-tab cell or the two split cells.
pub(crate) fn split_button_rects(
    overflow: bool,
    physical_width: f32,
    cell_phys_w: f32,
    ch: f32,
) -> Option<([f32; 4], [f32; 4])> {
    // Anchor on the new-tab cell so the split cells always sit just left of it. If the new-tab cell
    // has no room, neither do the split cells.
    let [newtab_x, _, _, _] = new_tab_rect(overflow, physical_width, cell_phys_w, ch)?;
    let w = cell_phys_w;
    // `v` (split-down) sits immediately left of `+`; `>` (split-right) sits left of `v`.
    let down_x = newtab_x - w;
    let right_x = down_x - w;
    if right_x < 0.0 {
        return None;
    }
    Some(([right_x, 0.0, w, ch], [down_x, 0.0, w, ch]))
}

/// Pure: the bounded rect of the SWAP control (`⇄`), one cell wide, sitting immediately LEFT of the
/// split-right cell, or `None` when there is no room. Anchored on [`split_button_rects`] so the
/// right-edge order is `⇄ > v +`: swap, split-right, split-down, then the new-tab `+`, each one cell
/// wide and adjacent. If the split cells have no room (or any dim is degenerate), neither does swap.
/// The cell never starts below 0. Returns `[x, y, w, h]` in physical pixels.
pub(crate) fn swap_button_rect(
    overflow: bool,
    physical_width: f32,
    cell_phys_w: f32,
    ch: f32,
) -> Option<[f32; 4]> {
    let (right_rect, _down_rect) = split_button_rects(overflow, physical_width, cell_phys_w, ch)?;
    let [right_x, _, w, _] = right_rect;
    let swap_x = right_x - w;
    if swap_x < 0.0 {
        return None;
    }
    Some([swap_x, 0.0, w, ch])
}

/// Pure: the bounded rect of the SWALLOW control (`o`), one cell wide, sitting immediately LEFT of the
/// swap cell, or `None` when there is no room. Anchored on [`swap_button_rect`] so the right-edge order
/// is `o s > v +`: swallow, swap, split-right, split-down, then the new-tab `+`, each one cell wide and
/// adjacent. If the swap cell has no room (or any dim is degenerate), neither does swallow. The cell
/// never starts below 0. Returns `[x, y, w, h]` in physical pixels.
pub(crate) fn swallow_button_rect(
    overflow: bool,
    physical_width: f32,
    cell_phys_w: f32,
    ch: f32,
) -> Option<[f32; 4]> {
    let [swap_x, _, w, _] = swap_button_rect(overflow, physical_width, cell_phys_w, ch)?;
    let swallow_x = swap_x - w;
    if swallow_x < 0.0 {
        return None;
    }
    Some([swallow_x, 0.0, w, ch])
}

/// Pure: the bounded rect of the REMOTE-ACCESS toggle button, `TOP_REMOTE_CELLS` cells wide, sitting immediately
/// LEFT of the swallow cell, or `None` when there's no room. Anchored on [`swallow_button_rect`] so the right-edge
/// order is `[Remote toggle] o s > v +`. Returns `[x, y, w, h]` in physical pixels.
pub(crate) fn remote_toggle_button_rect(
    overflow: bool,
    physical_width: f32,
    cell_phys_w: f32,
    ch: f32,
) -> Option<[f32; 4]> {
    let [swallow_x, _, _, _] = swallow_button_rect(overflow, physical_width, cell_phys_w, ch)?;
    let w = cell_phys_w * TOP_REMOTE_CELLS as f32;
    let x = swallow_x - w;
    if x < 0.0 {
        return None;
    }
    Some([x, 0.0, w, ch])
}

/// Pure: the bounded rect of the WINSIZE-OWNER toggle, sitting immediately LEFT of the remote-access toggle.
/// Right-edge order: `[Size owner] [Remote toggle] o s > v +`.
pub(crate) fn winsize_toggle_button_rect(
    overflow: bool,
    physical_width: f32,
    cell_phys_w: f32,
    ch: f32,
) -> Option<[f32; 4]> {
    let [remote_x, _, _, _] = remote_toggle_button_rect(overflow, physical_width, cell_phys_w, ch)?;
    let w = cell_phys_w * TOP_WINSIZE_CELLS as f32;
    let x = remote_x - w;
    if x < 0.0 {
        return None;
    }
    Some([x, 0.0, w, ch])
}

/// Resolved drawing colors for one top tab, decided purely from its state. `active` always wins over
/// `hover` (a hovered active tab keeps active styling), and `hover` only lifts an INACTIVE tab. This
/// is the single source of truth for the fill quad and label color so the two cannot disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TopTabStyle {
    pub fill: theme::Rgb,
    pub label: theme::Rgb,
}

/// Pure: pick a top tab's fill + label color from `(active, hovered)`. Active takes precedence over
/// hover; hover lifts only an inactive tab; an unhovered inactive tab stays quiet.
pub(crate) fn top_tab_style(active: bool, hovered: bool) -> TopTabStyle {
    if active {
        TopTabStyle {
            fill: TOP_TAB_ACTIVE,
            label: TOP_LABEL_ACTIVE,
        }
    } else if hovered {
        TopTabStyle {
            fill: TOP_TAB_HOVER,
            label: TOP_LABEL_HOVER,
        }
    } else {
        TopTabStyle {
            fill: TOP_TAB_INACTIVE,
            label: TOP_LABEL_INACTIVE,
        }
    }
}

/// Pure: the accent rect that surfaces `needs_attention` for a tab, or `None` when the tab does not
/// need attention or its clipped rect is degenerate. A thin underline INSIDE the tab's clipped rect
/// (`[x0, x1)` already clipped to the window width), so it can never overflow the tab or the window:
/// it spans the clipped width and sits flush to the bottom of the one-cell band, `thickness` tall.
/// Returns `[x, y, w, h]` in physical pixels. Bounded by construction (`x in [x0,x1)`, `y+h == ch`).
pub(crate) fn attention_accent_rect(
    needs_attention: bool,
    x0: f32,
    x1: f32,
    ch: f32,
    thickness: f32,
) -> Option<[f32; 4]> {
    if !needs_attention {
        return None;
    }
    let w = x1 - x0;
    if w <= 0.0 || ch <= 0.0 {
        return None;
    }
    let t = thickness.clamp(1.0, ch);
    Some([x0, ch - t, w, t])
}

/// Pure: the bounded rect of the right-edge OVERFLOW marker, or `None` when the strip is not
/// overflowing or the geometry is degenerate. When `overflow` is true the visible top tab strip was
/// truncated (more tabs than fit), so we reserve exactly one cell column at the right edge of the
/// one-cell band for a `>` cue. The rect is one cell wide (or the whole bar if it is narrower than a
/// cell), flush to the right edge (`x = physical_width - w`, never negative) and full band height, so
/// it always stays inside both the band and the window width. Returns `[x, y, w, h]` in physical
/// pixels. `None` for: no overflow; non-finite/non-positive `physical_width`, `cell_phys_w`, or `ch`.
pub(crate) fn overflow_marker_rect(
    overflow: bool,
    physical_width: f32,
    cell_phys_w: f32,
    ch: f32,
) -> Option<[f32; 4]> {
    if !overflow {
        return None;
    }
    if !(physical_width.is_finite() && physical_width > 0.0) {
        return None;
    }
    if !(cell_phys_w.is_finite() && cell_phys_w > 0.0) {
        return None;
    }
    if !(ch.is_finite() && ch > 0.0) {
        return None;
    }
    // One cell wide, but never wider than the whole bar; flush to the right edge.
    let w = cell_phys_w.min(physical_width);
    let x = (physical_width - w).max(0.0);
    Some([x, 0.0, w, ch])
}

/// Pure: the bounded rect of a tab's right-anchored CLOSE affordance, or `None` when the tab's clipped
/// rect is too narrow or degenerate to host one. `x0`/`x1` are the tab rect already clipped to the
/// window (`[x0, x1)`, x1 exclusive); `close_w` is the marker cell width and `padding` an inside gap
/// from the right edge, both in physical pixels. The close rect is anchored near the right inside edge
/// (`cx1 = x1 - padding`, `cx0 = cx1 - close_w`) and is returned ONLY when it stays fully inside
/// `[x0, x1)` AND still leaves at least `close_w * TOP_CLOSE_MIN_TITLE_RATIO` of title area before it,
/// so a narrow tab keeps its whole rect for the label instead of a cramped `x`. This is the same
/// physical-pixel space the other top-bar helpers use; it knows nothing about sessions, windows, or
/// app/daemon state. Returns `[x, y, w, h]` (`y = 0`, `h = ch`). Bounded by construction:
/// `x0 <= cx0 < cx1 <= x1`.
pub(crate) fn tab_close_rect(
    x0: f32,
    x1: f32,
    ch: f32,
    close_w: f32,
    padding: f32,
) -> Option<[f32; 4]> {
    if !(x0.is_finite() && x1.is_finite() && ch.is_finite()) {
        return None;
    }
    if !(close_w.is_finite() && close_w > 0.0) {
        return None;
    }
    if !(padding.is_finite() && padding >= 0.0) {
        return None;
    }
    if ch <= 0.0 || x1 <= x0 {
        return None;
    }
    let cx1 = x1 - padding;
    let cx0 = cx1 - close_w;
    // Must sit fully inside the tab rect AND leave room for a readable title before it.
    let min_title = close_w * TOP_CLOSE_MIN_TITLE_RATIO;
    if cx0 < x0 + min_title || cx1 > x1 {
        return None;
    }
    Some([cx0, 0.0, close_w, ch])
}

/// Pure: the right edge (in physical pixels) that a tab's TITLE may draw up to, given its clipped rect
/// and optional close rect. When a close marker exists the title is clipped to the area BEFORE it
/// (`close_x0`); otherwise the title keeps the whole tab rect (`x1`). Keeping this in one place means
/// the label width and its `TextBounds.right` agree with whatever `tab_close_rect` decided, so a title
/// can never draw under the `x` or, when there is no `x`, lose space it is entitled to.
pub(crate) fn tab_title_right(x1: f32, close_rect: Option<[f32; 4]>) -> f32 {
    match close_rect {
        Some([cx0, _, _, _]) => cx0.min(x1),
        None => x1,
    }
}

/// Pure: the close rect for one top-tab item, in physical pixels, or `None` when the tab is too narrow
/// or degenerate to host one. This is the SINGLE SOURCE OF TRUTH for the close cell: both the renderer
/// draw passes (fill quad + `x` glyph) and the `lib.rs` click hit-test call it, so the drawn marker and
/// the click target cannot drift. It clips the item's raw `[x0, x1)` to the window width, derives the
/// marker cell width from `cell_phys_w` and the inside padding from `TOP_CLOSE_PAD_RATIO` (floored to
/// at least 1px), then defers all the bounding/too-narrow logic to `tab_close_rect`. It knows nothing
/// about sessions, windows, or app/daemon state — it only turns a tab rect into a pixel cell, and
/// returns `[x, y, w, h]` with `y = 0` and `h = ch`.
pub(crate) fn tab_close_rect_for_item(
    raw_x0: f32,
    raw_x1: f32,
    physical_width: f32,
    cell_phys_w: f32,
    ch: f32,
) -> Option<[f32; 4]> {
    if !(physical_width.is_finite() && physical_width > 0.0) {
        return None;
    }
    let x0 = raw_x0.max(0.0);
    let x1 = raw_x1.min(physical_width);
    if x1 <= x0 {
        return None;
    }
    let close_w = cell_phys_w;
    let padding = (cell_phys_w * TOP_CLOSE_PAD_RATIO).max(1.0);
    tab_close_rect(x0, x1, ch, close_w, padding)
}

/// Pure: the bounded pixel rect of a split pane's CLOSE button — wide enough to match the real
/// hit target and the full header height, anchored to the pane region's TOP-RIGHT corner — or `None` when the pane is too small (`< PANE_CLOSE_MIN_COLS` wide
/// or `< PANE_CLOSE_MIN_ROWS` tall) or the geometry is degenerate. This is the SINGLE SOURCE OF TRUTH
/// for the per-pane close backing; the `x` glyph stays right-aligned inside this rect, and the `lib.rs` click
/// hit-test uses the same cell span so the drawn button and the click target cannot drift. `region` is in absolute
/// window-grid cells; `oy` is the top-chrome pixel offset already applied to grid rows. Returns
/// `[x, y, w, h]` in physical pixels. It knows nothing about sessions or app/daemon state.
pub(crate) fn pane_close_rect(
    region: crate::RendererPaneRegion,
    cell_phys_w: f32,
    ch: f32,
    ox: f32,
    oy: f32,
) -> Option<[f32; 4]> {
    if !(cell_phys_w.is_finite() && cell_phys_w > 0.0 && ch.is_finite() && ch > 0.0) {
        return None;
    }
    if region.cols < PANE_CLOSE_MIN_COLS || region.rows < PANE_CLOSE_MIN_ROWS {
        return None;
    }
    let close_col = pane_header_close_cell(region)?;
    let close_cols = PANE_CLOSE_HIT_COLS.min(region.cols);
    let first_close_col = close_col
        .saturating_sub(close_cols.saturating_sub(1))
        .max(region.col);
    let x = first_close_col as f32 * cell_phys_w + ox;
    let y = region.row as f32 * ch + oy;
    Some([
        x,
        y,
        (close_col.saturating_sub(first_close_col) + 1) as f32 * cell_phys_w,
        PANE_HEADER_VISUAL_ROWS * ch,
    ])
}

/// Pure: the full-width 1.5-row visual header BAND rect at the top of a pane region, or `None` when the
/// geometry is degenerate or the pane is too small to host the close marker (same width/height gate
/// as [`pane_close_rect`], so a pane either has a full header or none). This is the SINGLE SOURCE OF
/// TRUTH for the header band quad. `oy` is the top-chrome grid offset.
pub(crate) fn pane_header_rect(
    region: crate::RendererPaneRegion,
    cell_phys_w: f32,
    ch: f32,
    ox: f32,
    oy: f32,
) -> Option<[f32; 4]> {
    if !(cell_phys_w.is_finite() && cell_phys_w > 0.0 && ch.is_finite() && ch > 0.0) {
        return None;
    }
    if region.cols < PANE_CLOSE_MIN_COLS || region.rows < PANE_CLOSE_MIN_ROWS {
        return None;
    }
    let x = region.col as f32 * cell_phys_w + ox;
    let y = region.row as f32 * ch + oy;
    Some([
        x,
        y,
        region.cols as f32 * cell_phys_w,
        PANE_HEADER_VISUAL_ROWS * ch,
    ])
}

/// The number of header rows an extra pane reserves: `PANE_HEADER_ROWS` when the pane opts into a
/// header (`show_header`, set only for real 2+-pane splits) AND its region is large enough to host one
/// (`pane_header_rect` is `Some`), else `0`. The SINGLE gate the draw loops use so the band quad,
/// the content offset/clip, and the glyph passes all agree on whether a given pane has a header.
fn pane_header_rows_for<T>(ep: &ExtraPanePaintOf<T>, cw: f32, ch: f32, oy: f32) -> u16 {
    // The header-presence gate is purely a size check (`is_some()`), independent of the X inset, so
    // pass `ox=0.0` here; the actual band/glyph rects below apply the real `ox`.
    if ep.show_header && pane_header_rect(ep.region, cw, ch, 0.0, oy).is_some() {
        PANE_HEADER_ROWS
    } else {
        0
    }
}

/// Pure: the header button GLYPH cells, right-aligned in the header band as
/// `[…name…  ←  ↓  ↑  →   ⇤  ⤓  ⤒  ⇥   ×]`. Returns `(absolute_cell_col, glyph)` pairs ordered left→right.
/// The `×` close cell is always last (the rightmost cell of the region); the 8 arrow glyphs precede
/// it ONLY when the pane is at least [`PANE_HEADER_MIN_COLS_FOR_ARROWS`] wide (otherwise just the `×`
/// is returned). This is the SINGLE SOURCE OF TRUTH for the arrow/close glyph columns so the draw
/// pass and any future hit-test reuse identical geometry. Empty when the pane is too small for even a
/// close marker (mirrors [`pane_close_rect`]'s gate).
pub(crate) fn pane_header_button_cells(
    region: crate::RendererPaneRegion,
) -> Vec<(u16, &'static str)> {
    if region.cols < PANE_CLOSE_MIN_COLS || region.rows < PANE_CLOSE_MIN_ROWS {
        return Vec::new();
    }
    let region_last_col = region.col + region.cols - 1;
    let inset = PANE_HEADER_BUTTON_RIGHT_INSET_CELLS.min(region.cols.saturating_sub(1));
    let last_col = region_last_col - inset;
    let mut cells = Vec::with_capacity(9);
    if region.cols >= PANE_HEADER_MIN_COLS_FOR_ARROWS {
        // Spaced layout reading left→right: move(4) [gap] swallow(4) [gap] ×. Computed from the close
        // cell leftward so the whole cluster spans PANE_HEADER_ARROW_CLUSTER_CELLS and hugs the right
        // edge, leaving the remaining left cells for the name. The internal one-cell gaps give each
        // glyph room to read and to become an easy click target when the move/swallow handlers are wired.
        let move_start = last_col.saturating_sub(PANE_HEADER_ARROW_CLUSTER_CELLS - 1);
        for (i, g) in PANE_HEADER_MOVE_GLYPHS.iter().enumerate() {
            cells.push((move_start + (i as u16 * 2), *g));
        }
        // Four move glyphs occupy offsets 0,2,4,6; leave two cells before the swallow cluster.
        let swallow_start = move_start + 9;
        for (i, g) in PANE_HEADER_SWALLOW_GLYPHS.iter().enumerate() {
            cells.push((swallow_start + (i as u16 * 2), *g));
        }
    }
    cells.push((last_col, PANE_CLOSE_GLYPH));
    cells
}

/// Pure: the absolute grid column of each drawn MOVE arrow glyph (`← ↓ ↑ →`) paired with the
/// directional swap it requests, derived from the SAME [`pane_header_button_cells`] geometry the draw
/// pass uses so the drawn glyph and the click hit-test cannot drift. The four glyphs are
/// [`PANE_HEADER_MOVE_GLYPHS`] in order `← ↓ ↑ →`, i.e. Left, Down, Up, Right. Empty when the pane is
/// too narrow to host the arrow cluster (mirrors [`pane_header_button_cells`]'s `PANE_HEADER_MIN_COLS_FOR_ARROWS`
/// gate, which only emits the move/swallow glyphs above that width). The swallow glyphs are intentionally
/// NOT returned here — only the move/swap arrows are wired.
pub(crate) fn pane_header_move_arrow_cells(
    region: crate::RendererPaneRegion,
) -> Vec<(u16, crate::PaneFocusDirection)> {
    use crate::PaneFocusDirection::{Down, Left, Right, Up};
    // The move cluster is the first four NON-close glyphs of `pane_header_button_cells`, emitted only
    // above `PANE_HEADER_MIN_COLS_FOR_ARROWS`. Reuse that single source of truth for the columns; the
    // directions follow `PANE_HEADER_MOVE_GLYPHS`' fixed `← ↓ ↑ →` order.
    let dirs = [Left, Down, Up, Right];
    pane_header_button_cells(region)
        .into_iter()
        .filter(|(_, g)| *g != PANE_CLOSE_GLYPH)
        .take(PANE_HEADER_MOVE_GLYPHS.len())
        .zip(dirs)
        .map(|((col, _glyph), dir)| (col, dir))
        .collect()
}

pub(crate) fn pane_focus_direction_glyph(dir: crate::PaneFocusDirection) -> &'static str {
    use crate::PaneFocusDirection::{Down, Left, Right, Up};
    match dir {
        Left => PANE_HEADER_MOVE_GLYPHS[0],
        Down => PANE_HEADER_MOVE_GLYPHS[1],
        Up => PANE_HEADER_MOVE_GLYPHS[2],
        Right => PANE_HEADER_MOVE_GLYPHS[3],
    }
}

/// Pure: the absolute grid column of each drawn SWALLOW arrow glyph (`⇤ ⤓ ⤒ ⇥`) paired with the
/// direction it requests. The display order is Left, Down, Up, Right.
/// Reuses [`pane_header_button_cells`] so draw and hit-test cannot drift.
pub(crate) fn pane_header_swallow_arrow_cells(
    region: crate::RendererPaneRegion,
) -> Vec<(u16, crate::PaneSwallowDirection)> {
    use crate::PaneSwallowDirection::{Down, Left, Right, Up};
    let dirs = [Left, Down, Up, Right];
    pane_header_button_cells(region)
        .into_iter()
        .filter(|(_, g)| *g != PANE_CLOSE_GLYPH)
        .skip(PANE_HEADER_MOVE_GLYPHS.len())
        .take(PANE_HEADER_SWALLOW_GLYPHS.len())
        .zip(dirs)
        .map(|((col, _glyph), dir)| (col, dir))
        .collect()
}

/// Pure: the absolute grid column of the local-size glyph (`▣`) shown when Remote currently owns
/// PTY geometry. It sits in the quiet gap between the move and swallow clusters, so it is visible
/// next to the arrows without stealing the close cell. Empty when the pane is too narrow to host
/// the arrow cluster, matching the draw gate for the surrounding controls.
pub(crate) fn pane_header_local_size_cell(region: crate::RendererPaneRegion) -> Option<u16> {
    if region.cols < PANE_HEADER_MIN_COLS_FOR_ARROWS {
        return None;
    }
    let move_cols = pane_header_move_arrow_cells(region);
    let swallow_cols = pane_header_swallow_arrow_cells(region);
    let last_move = move_cols.last().map(|(col, _)| *col)?;
    let first_swallow = swallow_cols.first().map(|(col, _)| *col)?;
    let cell = last_move.saturating_add(2);
    (cell < first_swallow && cell < region.col + region.cols).then_some(cell)
}

pub(crate) fn pane_swallow_direction_glyph(dir: crate::PaneSwallowDirection) -> &'static str {
    use crate::PaneSwallowDirection::{Down, Left, Right, Up};
    match dir {
        Left => PANE_HEADER_SWALLOW_GLYPHS[0],
        Down => PANE_HEADER_SWALLOW_GLYPHS[1],
        Up => PANE_HEADER_SWALLOW_GLYPHS[2],
        Right => PANE_HEADER_SWALLOW_GLYPHS[3],
    }
}

/// Pure: the absolute grid column of the drawn pane close marker, or `None` when the pane is too
/// small to draw header buttons. Hit-testing uses this instead of re-deriving the corner cell so the
/// click target follows future header-button layout changes.
pub(crate) fn pane_header_close_cell(region: crate::RendererPaneRegion) -> Option<u16> {
    pane_header_button_cells(region)
        .into_iter()
        .find_map(|(col, glyph)| (glyph == PANE_CLOSE_GLYPH).then_some(col))
}

/// Pure: the `[first_col, end_col)` half-open cell range available for the pane NAME in the header,
/// i.e. from the region's left edge up to (but not including) the leftmost button cell. Used to clip
/// the name so it never overdraws the arrow/close cluster. `None` when the pane is too small for a
/// header (no button cells), or when the buttons leave no room for a name.
pub(crate) fn pane_header_name_extent(region: crate::RendererPaneRegion) -> Option<(u16, u16)> {
    let buttons = pane_header_button_cells(region);
    let first_button_col = buttons.iter().map(|(c, _)| *c).min()?;
    if first_button_col <= region.col {
        return None;
    }
    Some((region.col, first_button_col))
}

/// Pure: the bounded rect of the right-edge NEW-TAB control cell, or `None` when there is no room or
/// the geometry is degenerate. This is the SINGLE SOURCE OF TRUTH for the `+` control: the renderer
/// draw passes (fill quad + `+` glyph) and the `lib.rs` click hit-test both call it, so the drawn cell
/// and the click target cannot drift. It is one cell column wide and full band height (`y = 0`,
/// `h = ch`). Placement: when `overflow` is true the strip reserves the right-edge OVERFLOW marker
/// cell, so the new-tab cell sits IMMEDIATELY TO ITS LEFT (`x = physical_width - 2*cell`); without
/// overflow it sits flush to the right edge (`x = physical_width - cell`). Returned ONLY when the cell
/// fits fully inside the window (`x >= 0`), so a window narrower than the reserved region(s) draws and
/// hit-tests nothing. It knows nothing about sessions, windows, or app/daemon state. `None` for:
/// non-finite/non-positive `physical_width`, `cell_phys_w`, or `ch`; or no room for the cell.
pub(crate) fn new_tab_rect(
    overflow: bool,
    physical_width: f32,
    cell_phys_w: f32,
    ch: f32,
) -> Option<[f32; 4]> {
    if !(physical_width.is_finite() && physical_width > 0.0) {
        return None;
    }
    if !(cell_phys_w.is_finite() && cell_phys_w > 0.0) {
        return None;
    }
    if !(ch.is_finite() && ch > 0.0) {
        return None;
    }
    let w = cell_phys_w;
    // Reserve the overflow marker cell first (one cell) when present; the new-tab cell goes to its
    // left. Otherwise the new-tab cell is flush right.
    let reserved_right = if overflow { cell_phys_w } else { 0.0 };
    let x = physical_width - reserved_right - w;
    // Require the cell to fit fully inside the window. A window too narrow to host the reserved
    // region(s) plus a distinct new-tab cell gets no marker (drawn nothing, hit-tested nothing).
    if x < 0.0 {
        return None;
    }
    Some([x, 0.0, w, ch])
}

/// Pure: the single-cell hit rect of a top-bar tab's visible ATTENTION MARKER glyph, or `None` when
/// the tab carries no marker or the geometry leaves no room. Unlike [`tab_close_rect_for_item`] and
/// [`new_tab_rect`] this is HIT-TEST ONLY — the marker glyph is already drawn inside the tab's label
/// buffer (one cell per char), so there is no separate draw pass to keep in sync; this helper only
/// recovers the marker's cell so a click on it can be distinguished from a plain tab-body click.
///
/// The bracketed label is `[<markers><title>]` with markers in fixed order `*` (active), `^`
/// (pinned), then the attention marker. So when `attention_marker` is set the marker glyph is at
/// char index `1 (the '[') + active as usize + pinned as usize`, and since the label is laid out one
/// `cell_phys_w` cell per char from the item's `x0`, its cell is `[x0 + idx*cell, x0 + (idx+1)*cell)`.
/// The cell is clipped to `[0, physical_width)`; if it falls entirely outside the window (a tab
/// scrolled/clipped off the left or right edge) `None` is returned so an off-screen marker is never a
/// click target. Returns `[x, 0, w, ch]`. `None` for: `attention_marker` false; non-finite/non-positive
/// `physical_width`/`cell_phys_w`/`ch`; or the marker cell clipped to nothing.
pub(crate) fn tab_attention_marker_rect(
    item: &crate::RendererTabBarItem,
    physical_width: f32,
    cell_phys_w: f32,
    ch: f32,
) -> Option<[f32; 4]> {
    if !item.attention_marker {
        return None;
    }
    if !(physical_width.is_finite() && physical_width > 0.0) {
        return None;
    }
    if !(cell_phys_w.is_finite() && cell_phys_w > 0.0) {
        return None;
    }
    if !(ch.is_finite() && ch > 0.0) {
        return None;
    }
    let idx = 1 + item.active as usize + item.pinned as usize;
    let cell_x0 = item.x0 + idx as f32 * cell_phys_w;
    let cell_x1 = cell_x0 + cell_phys_w;
    // Clip to the window; an entirely off-screen marker is not a click target.
    let x0 = cell_x0.max(0.0);
    let x1 = cell_x1.min(physical_width);
    if x1 <= x0 {
        return None;
    }
    Some([x0, 0.0, x1 - x0, ch])
}

fn rgba(c: theme::Rgb, a: f32) -> [f32; 4] {
    [srgb(c[0]) as f32, srgb(c[1]) as f32, srgb(c[2]) as f32, a]
}

/// Linearly blend `top` over `base` in 8-bit sRGB space by `t` (0.0 = base, 1.0 = top), clamped.
/// Used to tint the dashboard project-header band with the active-project accent.
fn blend(base: theme::Rgb, top: theme::Rgb, t: f32) -> theme::Rgb {
    let t = t.clamp(0.0, 1.0);
    let mix = |b: u8, o: u8| -> u8 {
        (b as f32 * (1.0 - t) + o as f32 * t)
            .round()
            .clamp(0.0, 255.0) as u8
    };
    [
        mix(base[0], top[0]),
        mix(base[1], top[1]),
        mix(base[2], top[2]),
    ]
}

/// Convert an 8-bit sRGB channel to linear float for an sRGB surface.
fn srgb(c: u8) -> f64 {
    let s = c as f64 / 255.0;
    if s <= 0.04045 {
        s / 12.92
    } else {
        ((s + 0.055) / 1.055).powf(2.4)
    }
}

/// Measure monospace advance + line height by shaping a run of 'M's.
fn measure_cell(fs: &mut FontSystem, font_size: f32, line_height: f32) -> (f32, f32) {
    let metrics = Metrics::new(font_size, line_height);
    let mut buf = Buffer::new(fs, metrics);
    buf.set_size(fs, Some(1000.0), Some(line_height * 2.0));
    buf.set_text(
        fs,
        "MMMMMMMMMM",
        Attrs::new().family(Family::Monospace),
        Shaping::Basic,
    );
    buf.shape_until_scroll(fs, false);
    let mut adv = font_size * 0.6; // fallback advance
    if let Some(run) = buf.layout_runs().next() {
        if run.glyphs.len() >= 2 {
            adv = run.glyphs[1].x - run.glyphs[0].x;
        } else if let Some(g) = run.glyphs.first() {
            adv = g.w;
        }
    }
    (adv, line_height)
}

const QUAD_WGSL: &str = r#"
struct Screen { size: vec2<f32>, pad: vec2<f32>, };
@group(0) @binding(0) var<uniform> screen: Screen;

struct VsOut {
  @builtin(position) pos: vec4<f32>,
  @location(0) color: vec4<f32>,
};

@vertex
fn vs_main(
  @builtin(vertex_index) vi: u32,
  @location(0) rect: vec4<f32>,
  @location(1) color: vec4<f32>,
) -> VsOut {
  // Two triangles (6 verts) of a unit quad.
  var corners = array<vec2<f32>, 6>(
    vec2<f32>(0.0, 0.0), vec2<f32>(1.0, 0.0), vec2<f32>(0.0, 1.0),
    vec2<f32>(0.0, 1.0), vec2<f32>(1.0, 0.0), vec2<f32>(1.0, 1.0),
  );
  let c = corners[vi];
  let px = rect.xy + c * rect.zw;            // pixel-space position
  // map pixel -> clip space (y down -> y up)
  let ndc = vec2<f32>(
    px.x / screen.size.x * 2.0 - 1.0,
    1.0 - px.y / screen.size.y * 2.0,
  );
  var out: VsOut;
  out.pos = vec4<f32>(ndc, 0.0, 1.0);
  out.color = color;
  return out;
}

@fragment
fn fs_main(in: VsOut) -> @location(0) vec4<f32> {
  return in.color;
}
"#;

#[cfg(test)]
mod color_blend_tests {
    use super::blend;

    #[test]
    fn blend_endpoints_return_base_and_top() {
        let base = [10, 20, 30];
        let top = [200, 100, 50];
        assert_eq!(blend(base, top, 0.0), base);
        assert_eq!(blend(base, top, 1.0), top);
    }

    #[test]
    fn blend_midpoint_is_rounded_average() {
        // 0.5 mix of (0,0,0) and (255,255,255) rounds to 128 per channel.
        assert_eq!(blend([0, 0, 0], [255, 255, 255], 0.5), [128, 128, 128]);
    }

    #[test]
    fn blend_clamps_t_out_of_range() {
        let base = [10, 20, 30];
        let top = [200, 100, 50];
        assert_eq!(blend(base, top, -1.0), base);
        assert_eq!(blend(base, top, 2.0), top);
    }
}

#[cfg(test)]
mod decoration_tests {
    use super::*;

    const X: f32 = 10.0;
    const Y: f32 = 20.0;
    const CW: f32 = 9.0;
    const CH: f32 = 20.0;

    fn rects(u: UnderlineStyle, strike: bool) -> Vec<[f32; 4]> {
        decoration_rects(u, strike, X, Y, CW, CH, 1.0)
    }

    #[test]
    fn none_without_strike_draws_nothing() {
        assert!(rects(UnderlineStyle::None, false).is_empty());
    }

    #[test]
    fn single_underline_is_one_full_width_bar_near_baseline() {
        let r = rects(UnderlineStyle::Single, false);
        assert_eq!(r.len(), 1, "single underline = one bar");
        let [x, y, w, h] = r[0];
        assert_eq!(x, X, "spans from cell left");
        assert_eq!(w, CW, "spans full cell width");
        assert!(h >= 1.0, "bar has positive thickness");
        assert!(
            y > Y + CH * 0.5,
            "bar sits in the lower half (near baseline)"
        );
        assert!(y + h <= Y + CH, "bar stays within the cell");
    }

    #[test]
    fn double_underline_is_two_stacked_full_width_bars() {
        let r = rects(UnderlineStyle::Double, false);
        assert_eq!(r.len(), 2, "double underline = two bars");
        // Both full width.
        assert!(r.iter().all(|q| q[0] == X && q[2] == CW));
        // The two bars are at distinct y's (stacked, not overlapping).
        assert_ne!(r[0][1], r[1][1]);
    }

    #[test]
    fn strikeout_is_one_bar_through_the_vertical_middle() {
        let r = rects(UnderlineStyle::None, true);
        assert_eq!(r.len(), 1, "strikeout alone = one bar");
        let [x, y, w, h] = r[0];
        assert_eq!((x, w), (X, CW), "full-width bar");
        // Centered: bar center near the cell's vertical middle.
        let center = y + h / 2.0;
        assert!(
            (center - (Y + CH / 2.0)).abs() <= h,
            "bar centered vertically"
        );
    }

    #[test]
    fn underline_and_strikeout_combine() {
        let r = rects(UnderlineStyle::Single, true);
        assert_eq!(r.len(), 2, "single underline + strikeout = two bars");
    }

    #[test]
    fn dashed_is_multiple_segments_within_the_cell() {
        let r = rects(UnderlineStyle::Dashed, false);
        assert!(r.len() >= 2, "dashed underline = several segments");
        // Every segment stays within the cell horizontally.
        for [x, _y, w, _h] in &r {
            assert!(*x >= X, "segment not left of cell");
            assert!(*x + *w <= X + CW + 0.01, "segment clipped to cell width");
        }
    }

    #[test]
    fn dotted_has_more_segments_than_dashed() {
        // Dots are shorter than dashes, so a cell fits more of them.
        let dotted = rects(UnderlineStyle::Dotted, false).len();
        let dashed = rects(UnderlineStyle::Dashed, false).len();
        assert!(
            dotted > dashed,
            "dotted ({dotted}) should pack more segments than dashed ({dashed})"
        );
    }

    #[test]
    fn curly_is_drawn_as_segments_documented_approximation() {
        // Curly is approximated as a dense dotted bar (see decoration_rects doc): it
        // must still draw SOMETHING so the cell is visibly distinguished.
        let r = rects(UnderlineStyle::Curly, false);
        assert!(r.len() >= 2, "curly approximation draws multiple segments");
    }

    #[test]
    fn thickness_floors_to_one_physical_pixel() {
        // On a tiny fractional scale the bar must not vanish.
        assert!(decoration_thickness(0.1) >= 1.0);
        // And it scales up with DPI.
        assert!(decoration_thickness(2.0) >= 2.0);
    }
}

#[cfg(test)]
mod top_bar_style_tests {
    use super::*;

    #[test]
    fn active_style_wins_over_hover() {
        // An active tab keeps active styling whether or not it is also hovered.
        let plain = top_tab_style(true, false);
        let hovered = top_tab_style(true, true);
        assert_eq!(plain, hovered, "hover must not alter an active tab");
        assert_eq!(plain.fill, TOP_TAB_ACTIVE);
        assert_eq!(plain.label, TOP_LABEL_ACTIVE);
    }

    #[test]
    fn hovered_inactive_differs_from_quiet_inactive() {
        let quiet = top_tab_style(false, false);
        let hovered = top_tab_style(false, true);
        assert_ne!(
            quiet, hovered,
            "a hovered inactive tab must look different from a quiet one"
        );
        assert_eq!(quiet.fill, TOP_TAB_INACTIVE);
        assert_eq!(hovered.fill, TOP_TAB_HOVER);
        // Active stays distinct from the hovered-inactive lift.
        assert_ne!(hovered.fill, TOP_TAB_ACTIVE);
    }

    #[test]
    fn attention_accent_is_bounded_inside_the_tab_rect() {
        let (x0, x1, ch) = (40.0_f32, 120.0_f32, 16.0_f32);
        let rect = attention_accent_rect(true, x0, x1, ch, 2.0).expect("attention -> a rect");
        let [x, y, w, h] = rect;
        // Spans the clipped width, flush to the bottom of the one-cell band, never overflowing it.
        assert_eq!(x, x0);
        assert_eq!(w, x1 - x0);
        assert!(x + w <= x1, "accent must not overflow the tab right edge");
        assert!(h >= 1.0 && h <= ch, "thickness clamped to [1, ch]");
        assert_eq!(y + h, ch, "accent sits flush to the band bottom");
        assert!(y >= 0.0, "accent stays inside the band");
    }

    #[test]
    fn no_attention_means_no_accent() {
        assert_eq!(attention_accent_rect(false, 0.0, 80.0, 16.0, 2.0), None);
    }

    #[test]
    fn attention_accent_none_on_degenerate_rect() {
        // Zero/negative width or band height yields no rect (nothing to draw, no overflow risk).
        assert_eq!(attention_accent_rect(true, 50.0, 50.0, 16.0, 2.0), None);
        assert_eq!(attention_accent_rect(true, 80.0, 40.0, 16.0, 2.0), None);
        assert_eq!(attention_accent_rect(true, 0.0, 80.0, 0.0, 2.0), None);
    }

    #[test]
    fn attention_thickness_clamped_to_band_height() {
        // A thickness larger than the band collapses to exactly the band height (still in-bounds).
        let rect = attention_accent_rect(true, 0.0, 80.0, 16.0, 999.0).unwrap();
        assert_eq!(rect[3], 16.0);
        assert_eq!(rect[1], 0.0, "full-height accent starts at the band top");
    }

    #[test]
    fn overflow_marker_rect_some_only_when_overflow() {
        // Overflow true + valid geometry -> a marker; overflow false -> nothing.
        let (width, cw, ch) = (200.0_f32, 8.0_f32, 16.0_f32);
        assert!(overflow_marker_rect(true, width, cw, ch).is_some());
        assert_eq!(overflow_marker_rect(false, width, cw, ch), None);
    }

    #[test]
    fn overflow_marker_rect_is_bounded_to_band_and_window() {
        let (width, cw, ch) = (200.0_f32, 8.0_f32, 16.0_f32);
        let [x, y, w, h] = overflow_marker_rect(true, width, cw, ch).expect("overflow -> a rect");
        // One cell wide, flush to the right edge, full band height, never past the window width.
        assert_eq!(w, cw);
        assert_eq!(x, width - cw);
        assert!(x >= 0.0, "marker stays inside the window left edge");
        assert!(x + w <= width, "marker must not overflow the window width");
        assert_eq!(y, 0.0, "marker fills the band from the top");
        assert_eq!(h, ch, "marker spans the one-cell band height");
    }

    #[test]
    fn overflow_marker_rect_clamps_to_bar_when_narrower_than_a_cell() {
        // A window narrower than one cell still yields a marker bounded to the whole bar (x == 0).
        let [x, _, w, _] = overflow_marker_rect(true, 5.0, 8.0, 16.0).expect("overflow -> a rect");
        assert_eq!(x, 0.0);
        assert_eq!(w, 5.0, "marker never wider than the bar");
    }

    #[test]
    fn overflow_marker_rect_none_on_degenerate_dims() {
        // Zero/negative/non-finite dimensions yield no marker (nothing to draw).
        assert_eq!(overflow_marker_rect(true, 0.0, 8.0, 16.0), None);
        assert_eq!(overflow_marker_rect(true, 200.0, 0.0, 16.0), None);
        assert_eq!(overflow_marker_rect(true, 200.0, 8.0, 0.0), None);
        assert_eq!(overflow_marker_rect(true, f32::NAN, 8.0, 16.0), None);
        assert_eq!(overflow_marker_rect(true, 200.0, -8.0, 16.0), None);
    }

    #[test]
    fn new_tab_rect_some_with_valid_geometry_bounded_to_band_and_window() {
        // No overflow: the `+` is one cell flush to the right edge, full band height, inside the window.
        let (width, cw, ch) = (200.0_f32, 8.0_f32, 16.0_f32);
        let [x, y, w, h] = new_tab_rect(false, width, cw, ch).expect("valid -> a rect");
        assert_eq!(w, cw, "new-tab control is exactly one cell wide");
        assert_eq!(x, width - cw, "flush to the right edge when not truncated");
        assert!(x >= 0.0, "stays inside the window left edge");
        assert!(x + w <= width, "must not overflow the window width");
        assert_eq!(y, 0.0, "fills the band from the top");
        assert_eq!(h, ch, "spans the one-cell band height");
    }

    #[test]
    fn new_tab_rect_does_not_overlap_overflow_marker() {
        // When truncated, the overflow marker owns the rightmost cell; the `+` sits in the cell to its
        // LEFT, so the two rects are disjoint and adjacent (no draw/hit-test collision).
        let (width, cw, ch) = (200.0_f32, 8.0_f32, 16.0_f32);
        let [mx, _, mw, _] = overflow_marker_rect(true, width, cw, ch).expect("overflow -> marker");
        let [nx, _, nw, _] = new_tab_rect(true, width, cw, ch).expect("overflow -> new-tab rect");
        assert_eq!(
            nx + nw,
            mx,
            "new-tab control ends exactly where the marker begins"
        );
        assert!(
            nx + nw <= mx,
            "new-tab control never overlaps the overflow marker"
        );
        assert_eq!(mw, cw);
        assert_eq!(nw, cw);
    }

    #[test]
    fn new_tab_rect_none_when_no_room_to_the_left_of_marker() {
        // A window only one cell wide (truncated) has no room for the `+` left of the marker.
        assert_eq!(new_tab_rect(true, 8.0, 8.0, 16.0), None);
        // Likewise when the single reserved overflow cell consumes the whole window.
        assert_eq!(new_tab_rect(true, 6.0, 8.0, 16.0), None);
    }

    #[test]
    fn new_tab_rect_none_on_degenerate_dims() {
        // Zero/negative/non-finite dimensions yield no control (nothing to draw, nothing to hit).
        assert_eq!(new_tab_rect(false, 0.0, 8.0, 16.0), None);
        assert_eq!(new_tab_rect(false, 200.0, 0.0, 16.0), None);
        assert_eq!(new_tab_rect(false, 200.0, 8.0, 0.0), None);
        assert_eq!(new_tab_rect(false, f32::NAN, 8.0, 16.0), None);
        assert_eq!(new_tab_rect(false, 200.0, -8.0, 16.0), None);
    }

    #[test]
    fn split_button_rects_sit_left_of_new_tab_in_order_right_then_down() {
        // Right-edge order is `> v +`: split-right, split-down, then the new-tab `+`, each one cell
        // wide and adjacent. The two split cells are disjoint and the `v` ends exactly where `+` begins.
        let (width, cw, ch) = (200.0_f32, 8.0_f32, 16.0_f32);
        let [nx, _, nw, _] = new_tab_rect(false, width, cw, ch).expect("new-tab rect");
        let (right, down) = split_button_rects(false, width, cw, ch).expect("split rects");
        let [rx, ry, rw, rh] = right;
        let [dx, _, dw, _] = down;
        assert_eq!(rw, cw);
        assert_eq!(dw, cw);
        assert_eq!(rh, ch);
        assert_eq!(ry, 0.0, "split cells fill the band from the top");
        assert_eq!(
            dx + dw,
            nx,
            "split-down ends exactly where the new-tab `+` begins"
        );
        assert_eq!(
            rx + rw,
            dx,
            "split-right ends exactly where split-down begins"
        );
        assert!(rx < dx, "split-right is left of split-down");
        assert_eq!(nw, cw);
    }

    #[test]
    fn split_button_rects_respect_overflow_marker_reservation() {
        // When truncated, the overflow marker owns the rightmost cell and `+` sits left of it; the two
        // split cells then sit left of `+`, still disjoint and inside the window.
        let (width, cw, ch) = (200.0_f32, 8.0_f32, 16.0_f32);
        let [nx, _, _, _] = new_tab_rect(true, width, cw, ch).expect("new-tab rect");
        let (right, down) = split_button_rects(true, width, cw, ch).expect("split rects");
        let [rx, _, rw, _] = right;
        let [dx, _, dw, _] = down;
        assert_eq!(dx + dw, nx, "split-down abuts the new-tab cell");
        assert_eq!(rx + rw, dx, "split-right abuts split-down");
        assert!(rx >= 0.0, "leftmost split cell stays inside the window");
    }

    #[test]
    fn swap_button_rect_sits_left_of_split_right_in_order_swap_right_down_newtab() {
        // Right-edge order is `⇄ > v +`: swap, split-right, split-down, then the new-tab `+`, each one
        // cell wide and adjacent. Swap abuts split-right's left edge.
        let (width, cw, ch) = (200.0_f32, 8.0_f32, 16.0_f32);
        let (right, _down) = split_button_rects(false, width, cw, ch).expect("split rects");
        let [rx, _, _, _] = right;
        let [sx, sy, sw, sh] = swap_button_rect(false, width, cw, ch).expect("swap rect");
        assert_eq!(sw, cw);
        assert_eq!(sh, ch);
        assert_eq!(sy, 0.0, "swap cell fills the band from the top");
        assert_eq!(sx + sw, rx, "swap ends exactly where split-right begins");
        assert!(sx < rx, "swap is left of split-right");
        assert!(sx >= 0.0, "swap cell stays inside the window");
    }

    #[test]
    fn swap_button_rect_none_when_no_room_or_degenerate() {
        // No room for the split cells -> no room for the swap cell either.
        assert_eq!(swap_button_rect(false, 16.0, 8.0, 16.0), None);
        // Room for `> v +` but not one more cell to their left.
        assert_eq!(swap_button_rect(false, 24.0, 8.0, 16.0), None);
        // Degenerate dims.
        assert_eq!(swap_button_rect(false, 0.0, 8.0, 16.0), None);
        assert_eq!(swap_button_rect(false, 200.0, 0.0, 16.0), None);
        assert_eq!(swap_button_rect(false, f32::NAN, 8.0, 16.0), None);
    }

    #[test]
    fn swallow_button_rect_sits_left_of_swap_in_order_swallow_swap_right_down_newtab() {
        // Right-edge order is `o s > v +`: swallow, swap, split-right, split-down, then `+`, each one
        // cell wide and adjacent. Swallow abuts swap's left edge.
        let (width, cw, ch) = (200.0_f32, 8.0_f32, 16.0_f32);
        let [swx, _, _, _] = swap_button_rect(false, width, cw, ch).expect("swap rect");
        let [ox, oy, ow, oh] = swallow_button_rect(false, width, cw, ch).expect("swallow rect");
        assert_eq!(ow, cw);
        assert_eq!(oh, ch);
        assert_eq!(oy, 0.0, "swallow cell fills the band from the top");
        assert_eq!(ox + ow, swx, "swallow ends exactly where swap begins");
        assert!(ox < swx, "swallow is left of swap");
        assert!(ox >= 0.0, "swallow cell stays inside the window");
    }

    #[test]
    fn swallow_button_rect_none_when_no_room_or_degenerate() {
        // No room for the swap cell -> no room for the swallow cell either.
        assert_eq!(swallow_button_rect(false, 24.0, 8.0, 16.0), None);
        // Room for `s > v +` but not one more cell to their left.
        assert_eq!(swallow_button_rect(false, 32.0, 8.0, 16.0), None);
        // Degenerate dims.
        assert_eq!(swallow_button_rect(false, 0.0, 8.0, 16.0), None);
        assert_eq!(swallow_button_rect(false, 200.0, 0.0, 16.0), None);
        assert_eq!(swallow_button_rect(false, f32::NAN, 8.0, 16.0), None);
    }

    #[test]
    fn remote_toggle_button_rect_sits_left_of_swallow_and_is_multi_cell() {
        // Wide window so every control fits: [Remote (14 cells)] o s > v +
        let (width, cw, ch) = (400.0_f32, 8.0_f32, 16.0_f32);
        let [ox, _, _, _] = swallow_button_rect(false, width, cw, ch).expect("swallow rect");
        let [rx, ry, rw, rh] =
            remote_toggle_button_rect(false, width, cw, ch).expect("remote rect");
        assert_eq!(
            rw,
            cw * TOP_REMOTE_CELLS as f32,
            "remote button is TOP_REMOTE_CELLS wide"
        );
        assert_eq!(rh, ch);
        assert_eq!(ry, 0.0, "remote button fills the band from the top");
        assert_eq!(
            rx + rw,
            ox,
            "remote button ends exactly where swallow begins"
        );
        assert!(rx < ox, "remote button is left of swallow");
        assert!(rx >= 0.0, "remote button stays inside the window");
    }

    #[test]
    fn remote_toggle_button_rect_none_when_no_room_or_degenerate() {
        // Room for the single-glyph controls but not for the wide remote button to their left.
        assert_eq!(remote_toggle_button_rect(false, 60.0, 8.0, 16.0), None);
        // Degenerate dims.
        assert_eq!(remote_toggle_button_rect(false, 0.0, 8.0, 16.0), None);
        assert_eq!(remote_toggle_button_rect(false, 400.0, 0.0, 16.0), None);
        assert_eq!(remote_toggle_button_rect(false, f32::NAN, 8.0, 16.0), None);
    }

    #[test]
    fn split_button_rects_none_when_no_room() {
        // No room for the new-tab cell -> no room for the split cells either.
        assert_eq!(split_button_rects(true, 8.0, 8.0, 16.0), None);
        // Room for `+` but not two more cells to its left.
        assert_eq!(split_button_rects(false, 16.0, 8.0, 16.0), None);
    }

    #[test]
    fn split_button_rects_none_on_degenerate_dims() {
        assert_eq!(split_button_rects(false, 0.0, 8.0, 16.0), None);
        assert_eq!(split_button_rects(false, 200.0, 0.0, 16.0), None);
        assert_eq!(split_button_rects(false, 200.0, 8.0, 0.0), None);
        assert_eq!(split_button_rects(false, f32::NAN, 8.0, 16.0), None);
        assert_eq!(split_button_rects(false, 200.0, -8.0, 16.0), None);
    }

    #[test]
    fn tab_close_rect_some_for_normal_tab_bounded_inside() {
        // A comfortably-wide tab gets a close rect fully inside its [x0, x1) bounds.
        let (x0, x1, ch, close_w, pad) = (10.0_f32, 130.0_f32, 16.0_f32, 8.0_f32, 4.0_f32);
        let [x, y, w, h] = tab_close_rect(x0, x1, ch, close_w, pad).expect("wide tab -> a rect");
        assert_eq!(w, close_w);
        assert_eq!(h, ch);
        assert_eq!(y, 0.0, "close cell fills the band from the top");
        assert!(x >= x0, "close rect stays inside the tab left edge");
        assert!(
            x + w <= x1,
            "close rect stays inside the tab right edge (x1 exclusive)"
        );
    }

    #[test]
    fn tab_close_rect_is_right_anchored_not_crossing_edge() {
        // Anchored near the right inside edge: right side sits exactly `pad` before x1.
        let (x0, x1, ch, close_w, pad) = (0.0_f32, 100.0_f32, 16.0_f32, 8.0_f32, 4.0_f32);
        let [x, _, w, _] = tab_close_rect(x0, x1, ch, close_w, pad).expect("wide tab -> a rect");
        assert!(
            (x + w - (x1 - pad)).abs() < 1e-3,
            "right edge is pad before x1"
        );
        assert!(
            x > (x0 + x1) / 2.0,
            "close marker sits in the right half of the tab"
        );
    }

    #[test]
    fn tab_close_rect_none_for_too_narrow_tab() {
        // A tab only as wide as the close cell leaves no title room -> no close marker.
        // (min title room is close_w * TOP_CLOSE_MIN_TITLE_RATIO before the cell.)
        assert_eq!(tab_close_rect(0.0, 8.0, 16.0, 8.0, 2.0), None);
        // Slightly wider but still under (close_w title + close_w cell + pad) -> None.
        assert_eq!(tab_close_rect(0.0, 14.0, 16.0, 8.0, 2.0), None);
    }

    #[test]
    fn tab_close_rect_none_for_degenerate_rect() {
        // Zero/inverted width, non-positive band height, and non-finite inputs yield no close rect.
        assert_eq!(tab_close_rect(50.0, 50.0, 16.0, 8.0, 2.0), None);
        assert_eq!(tab_close_rect(60.0, 10.0, 16.0, 8.0, 2.0), None);
        assert_eq!(tab_close_rect(0.0, 100.0, 0.0, 8.0, 2.0), None);
        assert_eq!(tab_close_rect(0.0, 100.0, 16.0, 0.0, 2.0), None);
        assert_eq!(tab_close_rect(f32::NAN, 100.0, 16.0, 8.0, 2.0), None);
        assert_eq!(tab_close_rect(0.0, 100.0, 16.0, 8.0, -1.0), None);
    }

    #[test]
    fn tab_title_right_leaves_room_before_close_rect() {
        // When a close rect exists, the title may only draw up to its left edge (cx0), never under it.
        let (x0, x1, ch, close_w, pad) = (10.0_f32, 130.0_f32, 16.0_f32, 8.0_f32, 4.0_f32);
        let close = tab_close_rect(x0, x1, ch, close_w, pad).expect("wide tab -> a rect");
        let right = tab_title_right(x1, Some(close));
        assert_eq!(right, close[0], "title stops at the close rect's left edge");
        assert!(
            right < x1,
            "title right is pulled in before the tab's right edge"
        );
        assert!(right > x0, "title still has room to draw");
    }

    #[test]
    fn tab_title_right_uses_full_rect_when_no_close() {
        // A too-narrow tab has no close rect, so the title keeps the whole tab rect (bounded by x1).
        let x1 = 14.0_f32;
        assert_eq!(tab_title_right(x1, None), x1);
        // Even a long title is bounded by x1 here (the placement pass clips to this right edge).
        assert!(tab_title_right(x1, None) <= x1);
    }
}

#[cfg(test)]
mod split_divider_tests {
    use super::split_divider_rect;
    use crate::{RendererSplitDivider, RendererTabSplitAxis};

    #[test]
    fn right_split_divider_is_a_vertical_line_at_its_column() {
        // Divider at col 10, spanning 10 rows; cell 8x16 physical, grid offset 16px down.
        let divider = RendererSplitDivider {
            col: 10,
            row: 0,
            length: 10,
            glyph: '|',
        };
        let rect = split_divider_rect(&divider, RendererTabSplitAxis::Right, 8.0, 16.0, 0.0, 16.0);
        // x = col * cw, y = oy, w = one cell wide, h = length rows.
        assert_eq!(rect, [80.0, 16.0, 8.0, 160.0]);
    }

    #[test]
    fn down_split_divider_is_a_horizontal_line_at_its_row() {
        // Divider at row 4, spanning 12 cols; cell 8x16 physical, grid offset 16px down.
        let divider = RendererSplitDivider {
            col: 0,
            row: 4,
            length: 12,
            glyph: '-',
        };
        let rect = split_divider_rect(&divider, RendererTabSplitAxis::Down, 8.0, 16.0, 0.0, 16.0);
        // x = 0, y = row * ch + oy, w = length cols, h = one cell tall.
        assert_eq!(rect, [0.0, 80.0, 96.0, 16.0]);
    }

    #[test]
    fn divider_rect_respects_zero_grid_offset() {
        let divider = RendererSplitDivider {
            col: 3,
            row: 0,
            length: 5,
            glyph: '|',
        };
        let rect = split_divider_rect(&divider, RendererTabSplitAxis::Right, 10.0, 20.0, 0.0, 0.0);
        assert_eq!(rect, [30.0, 0.0, 10.0, 100.0]);
    }

    #[test]
    fn nested_right_divider_starts_at_its_row_offset() {
        // A nested vertical divider that begins partway down its parent region (row 4) draws from that
        // row, not the grid top — so a mixed-axis 3-pane layout's inner divider is placed correctly.
        let divider = RendererSplitDivider {
            col: 10,
            row: 4,
            length: 6,
            glyph: '|',
        };
        let rect = split_divider_rect(&divider, RendererTabSplitAxis::Right, 8.0, 16.0, 0.0, 16.0);
        // x = col*cw, y = row*ch + oy, w = one cell, h = length rows.
        assert_eq!(rect, [80.0, 80.0, 8.0, 96.0]);
    }

    #[test]
    fn nested_down_divider_starts_at_its_col_offset() {
        // A nested horizontal divider that begins partway across its parent region (col 5) draws from
        // that column, not the grid left edge.
        let divider = RendererSplitDivider {
            col: 5,
            row: 4,
            length: 7,
            glyph: '-',
        };
        let rect = split_divider_rect(&divider, RendererTabSplitAxis::Down, 8.0, 16.0, 0.0, 16.0);
        // x = col*cw, y = row*ch + oy, w = length cols, h = one cell.
        assert_eq!(rect, [40.0, 80.0, 56.0, 16.0]);
    }

    #[test]
    fn divider_axis_is_recovered_from_the_chrome_glyph() {
        let vertical = RendererSplitDivider {
            col: 0,
            row: 0,
            length: 1,
            glyph: '|',
        };
        let horizontal = RendererSplitDivider {
            col: 0,
            row: 0,
            length: 1,
            glyph: '-',
        };
        assert_eq!(super::divider_axis(&vertical), RendererTabSplitAxis::Right);
        assert_eq!(super::divider_axis(&horizontal), RendererTabSplitAxis::Down);
    }
}

#[cfg(test)]
mod file_preview_divider_tests {
    use super::file_preview_divider_rect;

    #[test]
    fn divider_is_a_thin_vertical_stripe_at_the_band_left_edge() {
        // Band starts at x0=400, spans 5 rows of ch=16 => 80px tall; scale 1.0 => 2px wide.
        let rect = file_preview_divider_rect(400.0, 80.0, 1.0);
        // x = band left edge, y = 0 (band paints from physical top), w = 2px, h = full band height.
        assert_eq!(rect, [400.0, 0.0, 2.0, 80.0]);
    }

    #[test]
    fn divider_width_scales_with_dpi() {
        // At 2x DPI the 2px stripe doubles so it stays visible.
        let rect = file_preview_divider_rect(400.0, 80.0, 2.0);
        assert_eq!(rect, [400.0, 0.0, 4.0, 80.0]);
    }

    #[test]
    fn divider_width_never_collapses_below_one_pixel() {
        // A tiny fractional scale still yields a >=1px line rather than an invisible 0-width quad.
        let rect = file_preview_divider_rect(10.0, 32.0, 0.1);
        assert_eq!(rect, [10.0, 0.0, 1.0, 32.0]);
    }

    #[test]
    fn divider_left_edge_matches_the_band_left_edge() {
        // The divider's x and the band's x0 are the same value, so the stripe sits exactly on the
        // boundary between the grid (left) and the preview band (right) with no gap or overlap drift.
        let x0 = (1024.0_f32 * crate::FILE_PREVIEW_OVERLAY_LEFT_FRACTION).floor();
        let rect = file_preview_divider_rect(x0, 48.0, 1.0);
        assert_eq!(rect[0], x0);
    }
}

#[cfg(test)]
mod pane_clip_tests {
    use super::{
        cell_in_pane, cell_text_bounds, clip_rect_to_pane, clip_rect_to_pixel_bounds,
        focus_border_rects, pane_pixel_rect, pane_text_clip, resolved_horizontal_origins,
        sibling_paint_decision, split_placeholder_label, SiblingPaneStatus,
    };
    use crate::RendererPaneRegion;

    #[test]
    fn placeholder_label_includes_tab_and_session_identity() {
        // Detached (no sibling bound) keeps the byte-identical id-only label, no status segment.
        assert_eq!(
            split_placeholder_label("src", Some("s-9"), SiblingPaneStatus::Detached),
            "[src \u{b7} s-9]"
        );
    }

    #[test]
    fn placeholder_label_without_session_shows_tab_only() {
        // No resolved sibling session (no attach target yet) → tab id alone, no separator.
        assert_eq!(
            split_placeholder_label("bot", None, SiblingPaneStatus::Detached),
            "[bot]"
        );
    }

    #[test]
    fn placeholder_label_appends_sibling_cache_status() {
        // A bound sibling sources its status into the label as a trailing segment.
        assert_eq!(
            split_placeholder_label("src", Some("s-9"), SiblingPaneStatus::Pending),
            "[src \u{b7} s-9 \u{b7} pending]"
        );
        assert_eq!(
            split_placeholder_label("src", Some("s-9"), SiblingPaneStatus::Attached),
            "[src \u{b7} s-9 \u{b7} attached]"
        );
        assert_eq!(
            split_placeholder_label("src", Some("s-9"), SiblingPaneStatus::Exited),
            "[src \u{b7} s-9 \u{b7} exited]"
        );
        // Status still appends even with no resolved session id.
        assert_eq!(
            split_placeholder_label("bot", None, SiblingPaneStatus::Attached),
            "[bot \u{b7} attached]"
        );
    }

    // A right-split second pane: starts at col 11, 10 cols wide, 10 rows tall.
    fn right_second_pane() -> RendererPaneRegion {
        RendererPaneRegion {
            col: 11,
            row: 0,
            cols: 10,
            rows: 10,
        }
    }

    // A down-split second pane: starts at row 5, full 12 cols, 4 rows tall.
    fn down_second_pane() -> RendererPaneRegion {
        RendererPaneRegion {
            col: 0,
            row: 5,
            cols: 12,
            rows: 4,
        }
    }

    #[test]
    fn no_pane_means_every_cell_is_in_pane() {
        // None == no split → the active grid paints everywhere.
        assert!(cell_in_pane(0, 0, None));
        assert!(cell_in_pane(999, 999, None));
    }

    #[test]
    fn cells_outside_selected_pane_are_not_painted_right_split() {
        // The active grid is drawn in pane-local cell coordinates: only cells
        // [0, pane.cols) × [0, pane.rows) belong to the active pane.
        let pane = Some(right_second_pane());
        // Inside the pane footprint.
        assert!(cell_in_pane(0, 0, pane));
        assert!(cell_in_pane(9, 9, pane));
        // Past the pane's own width/height → not painted.
        assert!(!cell_in_pane(10, 0, pane));
        assert!(!cell_in_pane(0, 10, pane));
    }

    #[test]
    fn cells_outside_selected_pane_are_not_painted_down_split() {
        let pane = Some(down_second_pane());
        assert!(cell_in_pane(11, 3, pane));
        // pane is 4 rows tall in pane-local space → row 4 is outside.
        assert!(!cell_in_pane(0, 4, pane));
        // pane is 12 cols wide → col 12 is outside.
        assert!(!cell_in_pane(12, 0, pane));
    }

    #[test]
    fn pane_pixel_rect_offsets_right_split_pane() {
        // col 11 * cw(8) = 88; row 0 * ch(16) + oy(16) = 16; 10 cols * 8 = 80; 10 rows * 16 = 160.
        let rect = pane_pixel_rect(right_second_pane(), 8.0, 16.0, 0.0, 16.0);
        assert_eq!(rect, [88.0, 16.0, 80.0, 160.0]);
    }

    #[test]
    fn pane_pixel_rect_offsets_x_by_canonical_grid_origin() {
        // A canonical grid origin (dock plus any terminal padding, ox=40) shifts the pane's x right by
        // exactly ox; width/height/y are
        // untouched. col 11 * 8 + 40 = 128; the rest matches the no-inset rect above.
        let rect = pane_pixel_rect(right_second_pane(), 8.0, 16.0, 40.0, 16.0);
        assert_eq!(rect, [128.0, 16.0, 80.0, 160.0]);
    }

    #[test]
    fn dock_width_and_terminal_padding_resolve_as_distinct_bounds() {
        let (dock, grid) = resolved_horizontal_origins(460.0, 464.0, 1000.0);
        assert_eq!(dock, 460.0, "padding must not widen app chrome");
        assert_eq!(grid, 464.0, "terminal begins after the separate 4px gap");

        // Even a malformed/out-of-order caller cannot let the terminal paint over the dock.
        assert_eq!(
            resolved_horizontal_origins(460.0, 4.0, 1000.0),
            (460.0, 460.0)
        );
        assert_eq!(
            resolved_horizontal_origins(460.0, 464.0, 462.0),
            (460.0, 462.0),
            "the dock stays exact while the padded terminal origin clamps to the narrow surface"
        );
        assert_eq!(resolved_horizontal_origins(1.0, 2.0, 0.0), (0.0, 0.0));
    }

    #[test]
    fn retina_terminal_origin_projects_two_and_four_pane_draw_bounds() {
        use crate::{
            compute_split_layout, RendererTab, RendererTabSplitAxis, RendererTabStrip,
            PANE_HEADER_ROWS,
        };

        let tab =
            |id: &str, source: Option<(&str, RendererTabSplitAxis)>, active: bool| -> RendererTab {
                let (split_from_tab_id, split) = source
                    .map_or((None, None), |(source_id, axis)| {
                        (Some(source_id.to_string()), Some(axis))
                    });
                RendererTab {
                    tab_id: id.to_string(),
                    session_id: format!("sid-{id}"),
                    title: id.to_string(),
                    active,
                    pinned: false,
                    needs_attention: false,
                    attention: None,
                    split,
                    split_from_tab_id,
                    split_ratio_per_mille: None,
                    pane_rect: None,
                }
            };
        let strip = |tabs| RendererTabStrip {
            window_id: "viewport-draw".to_string(),
            tabs,
        };
        let cases = [
            (
                "two-pane",
                strip(vec![
                    tab("A", None, false),
                    tab("B", Some(("A", RendererTabSplitAxis::Right)), true),
                ]),
                2,
            ),
            (
                "canonical-four-pane",
                strip(vec![
                    tab("A", None, false),
                    tab("B", Some(("A", RendererTabSplitAxis::Right)), false),
                    tab("C", Some(("A", RendererTabSplitAxis::Down)), false),
                    tab("D", Some(("B", RendererTabSplitAxis::Down)), true),
                ]),
                4,
            ),
        ];

        // Retina projection of a 460-logical-pixel sidebar plus 4-logical-pixel terminal padding.
        let (cw, ch, ox, oy) = (20.0_f32, 40.0_f32, 928.0_f32, 92.0_f32);
        let (surface_w, surface_h) = (2400_u32, 1600_u32);
        for (label, tabs, expected_panes) in cases {
            let layout =
                compute_split_layout(&tabs, 73, 37).unwrap_or_else(|| panic!("{label}: layout"));
            assert_eq!(layout.panes.len(), expected_panes, "{label}");
            for pane in &layout.panes {
                let content =
                    crate::pane_content_region_for_layout(pane.region, layout.panes.len());
                let rect = pane_pixel_rect(pane.region, cw, ch, ox, oy);
                assert_eq!(
                    rect,
                    [
                        ox + f32::from(pane.region.col) * cw,
                        oy + f32::from(pane.region.row) * ch,
                        f32::from(pane.region.cols) * cw,
                        f32::from(pane.region.rows) * ch,
                    ],
                    "{label}: pane quad uses the canonical terminal origin",
                );
                let text_clip = pane_text_clip(pane.region, PANE_HEADER_ROWS, cw, ch, ox, oy);
                assert_eq!(
                    text_clip,
                    [
                        (ox + f32::from(content.col) * cw).round() as i32,
                        (oy + f32::from(content.row) * ch).round() as i32,
                        (ox + f32::from(content.col + content.cols) * cw).round() as i32,
                        (oy + f32::from(content.row + content.rows) * ch).round() as i32,
                    ],
                    "{label}: glyph clip and PTY content region share exact bounds",
                );

                let last_cell_bounds = cell_text_bounds(
                    ox + f32::from(content.col + content.cols - 1) * cw,
                    oy + f32::from(content.row + content.rows - 1) * ch,
                    cw,
                    ch,
                    Some(text_clip),
                    surface_w,
                    surface_h,
                )
                .expect("last pane cell remains drawable");
                assert_eq!(last_cell_bounds.right, text_clip[2]);
                assert_eq!(last_cell_bounds.bottom, text_clip[3]);
            }
        }
    }

    #[test]
    fn pane_pixel_rect_offsets_down_split_pane() {
        // col 0 → x 0; row 5 * 16 + oy 16 = 96; 12 cols * 8 = 96; 4 rows * 16 = 64.
        let rect = pane_pixel_rect(down_second_pane(), 8.0, 16.0, 0.0, 16.0);
        assert_eq!(rect, [0.0, 96.0, 96.0, 64.0]);
    }

    #[test]
    fn focus_border_rects_frame_a_pane_without_altering_its_geometry() {
        // The indicator is pure chrome: the four border bands must sit fully INSIDE the pane's own
        // pixel rect (so they never bleed into a neighbour), and the pane rect they derive from is
        // unchanged by the call. Pane rect for `right_second_pane()` is [88, 16, 80, 160].
        let pane = right_second_pane();
        let pane_rect = pane_pixel_rect(pane, 8.0, 16.0, 0.0, 16.0);
        let [px, py, pw, ph] = pane_rect;
        let t = 2.0;
        let rects = focus_border_rects(pane, 8.0, 16.0, 0.0, 16.0, t);
        assert_eq!(rects.len(), 4, "top, bottom, left, right");
        // top / bottom / left / right, each `t` thick, hugging the pane edges.
        assert_eq!(rects[0], [px, py, pw, t]); // top
        assert_eq!(rects[1], [px, py + ph - t, pw, t]); // bottom
        assert_eq!(rects[2], [px, py, t, ph]); // left
        assert_eq!(rects[3], [px + pw - t, py, t, ph]); // right
                                                        // Every band lies within the pane rect — geometry is framed, not changed.
        for r in &rects {
            assert!(r[0] >= px && r[1] >= py, "border origin inside pane");
            assert!(
                r[0] + r[2] <= px + pw + f32::EPSILON,
                "border right within pane"
            );
            assert!(
                r[1] + r[3] <= py + ph + f32::EPSILON,
                "border bottom within pane"
            );
        }
        // The pane rect itself is unchanged after planning the indicator.
        assert_eq!(pane_pixel_rect(pane, 8.0, 16.0, 0.0, 16.0), pane_rect);
    }

    #[test]
    fn focus_border_rects_degenerate_pane_draws_nothing() {
        // A zero-area pane (collapsed region) yields no border bands, so a degenerate layout draws no
        // stray chrome.
        let empty = RendererPaneRegion {
            col: 0,
            row: 0,
            cols: 0,
            rows: 0,
        };
        assert!(focus_border_rects(empty, 8.0, 16.0, 0.0, 16.0, 2.0).is_empty());
    }

    #[test]
    fn clip_rect_unchanged_without_pane() {
        let rect = [3.0, 7.0, 100.0, 200.0];
        assert_eq!(
            clip_rect_to_pane(rect, None, 0.0, 0.0, 8.0, 16.0),
            Some(rect)
        );
    }

    #[test]
    fn clip_rect_trims_to_pane_bounds() {
        // Pane footprint in pixels: x [88, 168), y [16, 176). A rect that overhangs the
        // right/bottom edges is trimmed to the pane.
        let pane = Some(right_second_pane());
        let pane_off_x = 88.0;
        let pane_off_y = 16.0;
        let rect = [120.0, 100.0, 80.0, 120.0];
        let clipped = clip_rect_to_pane(rect, pane, pane_off_x, pane_off_y, 8.0, 16.0).unwrap();
        // x stays (inside), width trimmed so x+w == max_x 168; y stays, height trimmed to max_y 176.
        assert_eq!(clipped, [120.0, 100.0, 48.0, 76.0]);
    }

    #[test]
    fn clip_rect_fully_outside_pane_is_dropped() {
        let pane = Some(right_second_pane());
        // Entirely left of the pane's min_x (88).
        let rect = [0.0, 20.0, 40.0, 40.0];
        assert_eq!(clip_rect_to_pane(rect, pane, 88.0, 16.0, 8.0, 16.0), None);
    }

    #[test]
    fn unsplit_cell_rect_and_text_bounds_remain_unchanged() {
        // `None` is the no-split path. It must preserve the existing physical quad and the exact
        // floor/ceil + surface-clamp convention used by glyphon before pane clipping was added.
        let rect = [12.25, 7.5, 17.0, 19.0];
        assert_eq!(clip_rect_to_pixel_bounds(rect, None), Some(rect));
        let bounds = cell_text_bounds(rect[0], rect[1], rect[2], rect[3], None, 28, 25)
            .expect("visible unsplit cell");
        assert_eq!(bounds.left, 12);
        assert_eq!(bounds.top, 7);
        assert_eq!(bounds.right, 28, "existing surface clamp remains");
        assert_eq!(bounds.bottom, 25, "existing surface clamp remains");

        let off_surface = cell_text_bounds(40.0, 30.0, 8.0, 16.0, None, 28, 25)
            .expect("unsplit submission remains byte-identical even past the surface");
        assert_eq!(off_surface.left, 40);
        assert_eq!(off_surface.top, 30);
        assert_eq!(off_surface.right, 28);
        assert_eq!(off_surface.bottom, 25);
    }

    #[test]
    fn wide_last_column_cell_is_clipped_for_quads_and_glyphs() {
        // Ten 8px columns occupy [88, 168). A width-2 lead starts in the legal final column at x=160,
        // but its natural 16px span reaches x=176. Both quad/decor geometry and glyph TextBounds must
        // stop exactly at x=168 rather than painting eight pixels into the neighbor pane.
        let pane_pixel_bounds = Some([88.0, 16.0, 80.0, 160.0]);
        let clipped = clip_rect_to_pixel_bounds([160.0, 16.0, 16.0, 16.0], pane_pixel_bounds)
            .expect("last column remains visible");
        assert_eq!(clipped, [160.0, 16.0, 8.0, 16.0]);

        let pane_text_bounds = Some([88, 16, 168, 176]);
        let bounds = cell_text_bounds(160.0, 16.0, 16.0, 16.0, pane_text_bounds, 400, 300)
            .expect("clipped glyph remains visible");
        assert_eq!(bounds.left, 160);
        assert_eq!(bounds.top, 16);
        assert_eq!(bounds.right, 168);
        assert_eq!(bounds.bottom, 32);
    }

    #[test]
    fn fractional_active_sibling_and_extra_text_edges_meet_exactly() {
        // These fractional metrics put both shared edges between physical pixels. The old
        // floor(left)/ceil(right) policy produced a one-pixel overlap at each edge. All pane roles now
        // derive the shared integer edge from the same absolute cell coordinate and nearest-pixel rule.
        let cw = 8.35;
        let ch = 15.25;
        let ox = 2.4;
        let oy = 3.6;
        let active = RendererPaneRegion {
            col: 0,
            row: 0,
            cols: 7,
            rows: 5,
        };
        let sibling = RendererPaneRegion {
            col: 7,
            row: 0,
            cols: 5,
            rows: 5,
        };
        let extra = RendererPaneRegion {
            col: 0,
            row: 5,
            cols: 12,
            rows: 4,
        };
        let active_clip = pane_text_clip(active, 0, cw, ch, ox, oy);
        let sibling_clip = pane_text_clip(sibling, 0, cw, ch, ox, oy);
        let extra_clip = pane_text_clip(extra, 0, cw, ch, ox, oy);
        assert_eq!(active_clip[2], sibling_clip[0], "shared vertical edge");
        assert_eq!(
            active_clip[3], extra_clip[1],
            "active/extra horizontal edge"
        );
        assert_eq!(
            sibling_clip[3], extra_clip[1],
            "sibling/extra horizontal edge"
        );

        // A wide active lead reaches through the right edge while the sibling's first glyph naturally
        // floors to the pixel before it. Their final TextBounds meet at exactly one coordinate.
        let active_last =
            cell_text_bounds(ox + 6.0 * cw, oy, 2.0 * cw, ch, Some(active_clip), 400, 300)
                .expect("active edge cell");
        let sibling_first =
            cell_text_bounds(ox + 7.0 * cw, oy, cw, ch, Some(sibling_clip), 400, 300)
                .expect("sibling edge cell");
        assert_eq!(active_last.right, sibling_first.left);

        // The same invariant holds vertically between a final active row and the extra pane below.
        let active_bottom =
            cell_text_bounds(ox, oy + 4.0 * ch, cw, 2.0 * ch, Some(active_clip), 400, 300)
                .expect("active bottom cell");
        let extra_first = cell_text_bounds(ox, oy + 5.0 * ch, cw, ch, Some(extra_clip), 400, 300)
            .expect("extra top cell");
        assert_eq!(active_bottom.bottom, extra_first.top);

        // Real extra-pane terminal content commonly starts below a one-row header. Two adjacent
        // header-bearing extras must still share one canonical horizontal clip edge.
        let extra_left = RendererPaneRegion {
            col: 0,
            row: 5,
            cols: 7,
            rows: 4,
        };
        let extra_right = RendererPaneRegion {
            col: 7,
            row: 5,
            cols: 5,
            rows: 4,
        };
        let extra_left_clip = pane_text_clip(extra_left, 1, cw, ch, ox, oy);
        let extra_right_clip = pane_text_clip(extra_right, 1, cw, ch, ox, oy);
        assert_eq!(extra_left_clip[2], extra_right_clip[0]);
        assert_eq!(extra_left_clip[1], extra_right_clip[1]);
        let content_y = oy + 6.0 * ch;
        let extra_left_last = cell_text_bounds(
            ox + 6.0 * cw,
            content_y,
            2.0 * cw,
            ch,
            Some(extra_left_clip),
            400,
            300,
        )
        .expect("left extra edge cell");
        let extra_right_first = cell_text_bounds(
            ox + 7.0 * cw,
            content_y,
            cw,
            ch,
            Some(extra_right_clip),
            400,
            300,
        )
        .expect("right extra edge cell");
        assert_eq!(extra_left_last.right, extra_right_first.left);
    }

    #[test]
    fn active_sibling_and_extra_cell_clips_share_exact_pane_edges() {
        // The render branches supply different origins (active, sibling, header-offset extra), but
        // every one reaches this same final-paint clamp. Pin each branch-shaped bound with a wide lead
        // in its last column; none may cross its own right or bottom edge.
        let cases = [
            ([0.0, 16.0, 80.0, 64.0], [72.0, 64.0, 16.0, 32.0]),
            ([88.0, 16.0, 80.0, 64.0], [160.0, 64.0, 16.0, 32.0]),
            ([0.0, 32.0, 80.0, 48.0], [72.0, 64.0, 16.0, 32.0]),
        ];
        for (pane, cell) in cases {
            let clipped = clip_rect_to_pixel_bounds(cell, Some(pane)).expect("partial cell");
            assert_eq!(clipped[0] + clipped[2], pane[0] + pane[2]);
            assert_eq!(clipped[1] + clipped[3], pane[1] + pane[3]);
        }
    }

    #[test]
    fn extra_pane_selection_is_clipped_to_content_bounds() {
        // A stale 12-column cached grid can produce a selection rect wider than its current 10-column
        // pane after resize. The final extra-pane selection guard retains only the pane-local 80px.
        let pane_content = Some([40.0, 32.0, 80.0, 48.0]);
        let stale_selection = [40.0, 32.0, 96.0, 64.0];
        assert_eq!(
            clip_rect_to_pixel_bounds(stale_selection, pane_content),
            Some([40.0, 32.0, 80.0, 48.0])
        );
    }

    #[test]
    fn sibling_grid_paints_and_replaces_placeholder_when_cached() {
        // Split present + a live sibling grid cached → paint the sibling grid, hide the placeholder.
        assert_eq!(sibling_paint_decision(true, true), (true, false));
    }

    #[test]
    fn sibling_placeholder_kept_when_no_sibling_grid() {
        // Split present but no cached sibling grid (pending/exited/unbound) → keep the placeholder.
        assert_eq!(sibling_paint_decision(true, false), (false, true));
    }

    #[test]
    fn sibling_paint_noop_without_split() {
        // No split frame → neither paints; the unsplit path is untouched even if a stale grid lingers.
        assert_eq!(sibling_paint_decision(false, false), (false, false));
        assert_eq!(sibling_paint_decision(false, true), (false, false));
    }

    #[test]
    fn sibling_grid_cells_clip_to_inactive_pane_right_split() {
        // The sibling grid is painted in pane-local coords clipped to the INACTIVE pane footprint
        // (here a 10x10 right pane), exactly like the active grid clips to the active pane.
        let inactive = Some(right_second_pane());
        assert!(cell_in_pane(0, 0, inactive));
        assert!(cell_in_pane(9, 9, inactive));
        // Sibling cells past the inactive pane's own extent never paint — no bleed into the active pane.
        assert!(!cell_in_pane(10, 0, inactive));
        assert!(!cell_in_pane(0, 10, inactive));
    }

    #[test]
    fn sibling_grid_offsets_into_inactive_pane_pixels() {
        // The sibling grid origin offset equals the inactive pane's pixel top-left, so its (0,0) cell
        // lands at the pane origin rather than the window origin (no overlap with the active pane).
        let inactive = right_second_pane();
        let rect = pane_pixel_rect(inactive, 8.0, 16.0, 0.0, 16.0);
        // col 11 * 8 = 88 (x origin); row 0 * 16 + oy 16 = 16 (y origin).
        assert_eq!(rect[0], 88.0);
        assert_eq!(rect[1], 16.0);
    }

    #[test]
    fn pane_header_rect_is_a_full_width_one_and_half_row_band_at_the_top() {
        // A 10x10 pane at col 11: the header is a full-width (10 cells) 1.5-row visual band.
        let region = crate::RendererPaneRegion {
            col: 11,
            row: 0,
            cols: 10,
            rows: 10,
        };
        let rect = super::pane_header_rect(region, 8.0, 16.0, 0.0, 16.0).expect("header rect");
        // x = 11*8 = 88; y = 0*16 + oy 16 = 16; w = 10*8 = 80; h = 1.5 rows = 24.
        assert_eq!(rect, [88.0, 16.0, 80.0, 24.0]);
    }

    #[test]
    fn pane_header_rect_none_for_a_pane_too_small() {
        // Below the close-marker size gate (cols < 3 or rows < 2) there is no header.
        let tiny = crate::RendererPaneRegion {
            col: 0,
            row: 0,
            cols: 2,
            rows: 2,
        };
        assert!(super::pane_header_rect(tiny, 8.0, 16.0, 0.0, 16.0).is_none());
    }

    #[test]
    fn pane_header_buttons_close_is_last_cell_arrows_appear_only_when_wide() {
        // A wide pane (>= 36 cols) hosts the spaced 8-arrow cluster: move arrows every other cell,
        // a wider gap, swallow arrows every other cell, then a final gap before the `x`.
        // The cluster spans 18 cells and sits five cells left of the right edge, with the `x` at col 34.
        let wide = crate::RendererPaneRegion {
            col: 0,
            row: 0,
            cols: 40,
            rows: 5,
        };
        let cells = super::pane_header_button_cells(wide);
        // 8 arrows + 1 close.
        assert_eq!(cells.len(), 9);
        // Close is inset from the last cell of the region (col 34) and is the `x` glyph.
        let (close_col, close_glyph) = *cells.last().unwrap();
        assert_eq!(close_col, 34);
        assert_eq!(close_glyph, super::PANE_CLOSE_GLYPH);
        // Spaced layout from the inset right: move at 17,19,21,23; swallow at 26,28,30,32; x at 34.
        let arrow_cols: Vec<u16> = cells[..8].iter().map(|(c, _)| *c).collect();
        assert_eq!(arrow_cols, vec![17, 19, 21, 23, 26, 28, 30, 32]);
        assert_eq!(
            super::pane_header_local_size_cell(wide),
            Some(25),
            "local-size glyph sits in the gap between move and swallow clusters"
        );
        // Internal gaps and the gap before the `x` carry no glyph.
        for gap in [18, 20, 22, 24, 25, 27, 29, 31, 33] {
            assert!(
                !arrow_cols.contains(&gap),
                "gap {gap} should carry no glyph"
            );
        }

        // A narrow pane (< 36 cols) drops the arrow cluster — only the `x` remains.
        let narrow = crate::RendererPaneRegion {
            col: 0,
            row: 0,
            cols: 10,
            rows: 5,
        };
        let cells = super::pane_header_button_cells(narrow);
        assert_eq!(cells.len(), 1);
        assert_eq!(cells[0], (4, super::PANE_CLOSE_GLYPH));
        assert_eq!(super::pane_header_local_size_cell(narrow), None);
    }

    #[test]
    fn pane_header_name_extent_stops_before_the_button_cluster() {
        // Wide pane: the name spans from the region's left edge up to the first (leftmost move) arrow.
        let wide = crate::RendererPaneRegion {
            col: 0,
            row: 0,
            cols: 40,
            rows: 5,
        };
        // First button cell is the leftmost move arrow at col 17, so the name extent is [0, 17).
        assert_eq!(super::pane_header_name_extent(wide), Some((0, 17)));

        // Narrow pane with only the inset `x` at col 4: the name spans [0, 4).
        let narrow = crate::RendererPaneRegion {
            col: 0,
            row: 0,
            cols: 10,
            rows: 5,
        };
        assert_eq!(super::pane_header_name_extent(narrow), Some((0, 4)));
    }
}

#[cfg(test)]
mod measure_cell_tests {
    use super::*;

    // `set_font_size` re-derives `line_height = (font_size * 1.25).round()` and re-measures the cell
    // with `measure_cell`. The metric is GPU-free, so prove its size-dependence directly here: a larger
    // font yields a strictly larger cell advance and a taller line height, which is exactly what makes a
    // live font-size change reflow the grid (the App's window-resize path reads the new cell size).
    #[test]
    fn larger_font_size_yields_a_strictly_larger_cell() {
        let mut fs = FontSystem::new();
        let line_height = |px: f32| (px * 1.25).round();
        let (small_w, small_h) = measure_cell(&mut fs, 12.0, line_height(12.0));
        let (large_w, large_h) = measure_cell(&mut fs, 24.0, line_height(24.0));
        assert!(
            large_w > small_w,
            "cell width should grow with font size: {small_w} -> {large_w}"
        );
        assert!(
            large_h > small_h,
            "line height should grow with font size: {small_h} -> {large_h}"
        );
    }

    #[test]
    fn same_font_size_measures_an_identical_cell() {
        // The idempotent no-op in `set_font_size` short-circuits on an unchanged size; the underlying
        // metric is deterministic, so re-measuring the same size yields the same cell.
        let mut fs = FontSystem::new();
        let lh = (16.0_f32 * 1.25).round();
        let first = measure_cell(&mut fs, 16.0, lh);
        let second = measure_cell(&mut fs, 16.0, lh);
        assert_eq!(first, second);
    }
}

#[cfg(test)]
mod glyph_cache_tests {
    use super::*;
    use crate::wire::{Cell, Color, NamedColor, UnderlineStyle};

    fn cell(text: &str) -> Cell {
        Cell {
            text: text.to_string(),
            fg: Color::Named {
                name: NamedColor::Foreground,
            },
            bg: Color::Named {
                name: NamedColor::Background,
            },
            bold: false,
            italic: false,
            underline: UnderlineStyle::None,
            inverse: false,
            strikeout: false,
            dim: false,
            hidden: false,
            width: 1,
        }
    }

    // Mirror of the render-loop insert sequence: enforce the cap BEFORE each insert,
    // exactly as pass 2 does, so the test exercises the real bound, not a paraphrase.
    fn fill_cache_with_distinct_keys(n: usize, cap: usize) -> HashMap<GlyphKey, Buffer> {
        let mut fs = FontSystem::new();
        let metrics = Metrics::new(16.0, 20.0);
        let mut cache: HashMap<GlyphKey, Buffer> = HashMap::new();
        for i in 0..n {
            let key = GlyphKey {
                text: format!("g{i}"),
                bold: false,
                italic: false,
                wide: false,
            };
            if cache.contains_key(&key) {
                continue;
            }
            enforce_glyph_cache_cap(&mut cache, cap);
            cache.insert(key, Buffer::new(&mut fs, metrics));
            assert!(
                cache.len() <= cap,
                "cache exceeded cap mid-fill: len={} cap={cap}",
                cache.len()
            );
        }
        cache
    }

    #[test]
    fn cache_is_strictly_bounded_even_when_one_frame_floods_unique_glyphs() {
        // A single frame referencing far more than `cap` distinct glyphs must never
        // grow the map past `cap` at ANY point — the bound is per-insert, not
        // once-per-frame. Insert 10x the cap of unique keys and assert the invariant
        // held throughout (the in-loop assert) and at the end.
        let cap = 8;
        let cache = fill_cache_with_distinct_keys(cap * 10, cap);
        assert!(
            cache.len() <= cap,
            "final cache size {} must be within cap {cap}",
            cache.len()
        );
        assert!(!cache.is_empty(), "the latest glyphs must still be cached");
    }

    #[test]
    fn enforce_clears_only_at_or_above_cap() {
        let mut fs = FontSystem::new();
        let metrics = Metrics::new(16.0, 20.0);
        let mut cache: HashMap<GlyphKey, Buffer> = HashMap::new();
        // Below cap: no clear.
        cache.insert(
            GlyphKey {
                text: "a".into(),
                bold: false,
                italic: false,
                wide: false,
            },
            Buffer::new(&mut fs, metrics),
        );
        assert!(
            !enforce_glyph_cache_cap(&mut cache, 4),
            "below cap → no clear"
        );
        assert_eq!(cache.len(), 1);
        // At cap: clear.
        for t in ["b", "c", "d"] {
            cache.insert(
                GlyphKey {
                    text: t.into(),
                    bold: false,
                    italic: false,
                    wide: false,
                },
                Buffer::new(&mut fs, metrics),
            );
        }
        assert_eq!(cache.len(), 4);
        assert!(enforce_glyph_cache_cap(&mut cache, 4), "at cap → clear");
        assert!(cache.is_empty(), "clear empties the whole map");
    }

    #[test]
    fn blank_spacer_and_hidden_cells_have_no_key() {
        // A space cell, an empty cell, a wide spacer (width 0), and a hidden cell all
        // paint no glyph — the background quad covers them — so they must never be
        // shaped or cached.
        assert!(glyph_key_for(&cell(" ")).is_none(), "space → no glyph");
        assert!(glyph_key_for(&cell("")).is_none(), "empty → no glyph");

        let mut spacer = cell("界");
        spacer.width = 0;
        assert!(glyph_key_for(&spacer).is_none(), "wide spacer → no glyph");

        let mut hidden = cell("x");
        hidden.hidden = true;
        assert!(glyph_key_for(&hidden).is_none(), "hidden → no glyph");
    }

    #[test]
    fn key_ignores_color_so_same_glyph_shares_one_buffer() {
        // Color is applied per-TextArea (default_color), NOT baked into the shaped
        // buffer, so two cells with the same text/style but different colors must map
        // to the SAME key — that is what collapses N colored 'a's into one shaping.
        let mut red = cell("a");
        red.fg = Color::Indexed { index: 1 };
        let mut green = cell("a");
        green.fg = Color::Indexed { index: 2 };
        assert_eq!(
            glyph_key_for(&red),
            glyph_key_for(&green),
            "same glyph in different colors must share a cache key"
        );
    }

    #[test]
    fn same_glyph_different_color_shares_key_but_keeps_distinct_fg() {
        // The headless equivalent of the `--stress styles` visual check: that mode
        // paints the SAME letters in many DIFFERENT per-cell colors. The cache key is
        // color-independent (so the letter is shaped once), but each painted cell must
        // still carry its OWN foreground — applied via the TextArea's default_color,
        // derived from `resolved_colors`. This asserts the two render-loop inputs
        // behave correctly together: shared key, independent color. If this held but
        // colors leaked, every 'A' on screen would render in one color.
        let mut red = cell("A");
        red.fg = Color::Indexed { index: 9 }; // bright red
        let mut blue = cell("A");
        blue.fg = Color::Indexed { index: 12 }; // bright blue

        assert_eq!(
            glyph_key_for(&red),
            glyph_key_for(&blue),
            "same glyph must share one shaped buffer regardless of color"
        );
        let palette = theme::default_palette();
        let (red_fg, _) = resolved_colors(&red, &palette);
        let (blue_fg, _) = resolved_colors(&blue, &palette);
        assert_ne!(
            red_fg, blue_fg,
            "each cell must keep its own foreground for per-TextArea coloring"
        );
    }

    #[test]
    fn key_distinguishes_text_bold_italic_and_width() {
        // Each input that changes glyph selection or layout geometry must change the
        // key, or a cache hit would paint the wrong shape.
        let base = glyph_key_for(&cell("a")).unwrap();

        assert_ne!(
            base,
            glyph_key_for(&cell("b")).unwrap(),
            "different text → different key"
        );

        let mut bold = cell("a");
        bold.bold = true;
        assert_ne!(base, glyph_key_for(&bold).unwrap(), "bold → different key");

        let mut italic = cell("a");
        italic.italic = true;
        assert_ne!(
            base,
            glyph_key_for(&italic).unwrap(),
            "italic → different key"
        );

        // A wide lead cell has a different layout width bound than a normal cell, so
        // even the same text at width 2 must key separately.
        let mut wide = cell("a");
        wide.width = 2;
        assert_ne!(base, glyph_key_for(&wide).unwrap(), "wide → different key");
    }

    #[test]
    fn underline_strikeout_dim_inverse_do_not_change_key() {
        // These attributes are painted as separate quads / resolved into the per-cell
        // color, not into the glyph shape, so they must NOT fragment the cache.
        let base = glyph_key_for(&cell("a")).unwrap();
        for mutate in [
            (|c: &mut Cell| c.underline = UnderlineStyle::Single) as fn(&mut Cell),
            |c: &mut Cell| c.strikeout = true,
            |c: &mut Cell| c.dim = true,
            |c: &mut Cell| c.inverse = true,
        ] {
            let mut c = cell("a");
            mutate(&mut c);
            assert_eq!(
                base,
                glyph_key_for(&c).unwrap(),
                "decoration/color-only attribute must not change the glyph key"
            );
        }
    }
}

#[cfg(test)]
mod device_limits_tests {
    #[cfg(target_os = "linux")]
    use super::LINUX_RENDERER_POWER_PREFERENCE;
    use super::{linux_surface_present_mode, renderer_required_limits};

    fn adapter_with_2d(max_texture_dimension_2d: u32) -> wgpu::Limits {
        wgpu::Limits {
            max_texture_dimension_2d,
            // A real adapter reports large values everywhere; the helper must not
            // depend on them beyond the 2d dimension.
            ..wgpu::Limits::default()
        }
    }

    #[test]
    fn fullscreen_retina_surface_fits_when_adapter_supports_it() {
        // The crash case: a 3456x2168 fullscreen surface (14" MBP retina) was refused
        // under the downlevel 2048 cap. With a capable adapter the requested limit must
        // cover both dimensions.
        for adapter_2d in [4096, 8192, 16384] {
            let req = renderer_required_limits(adapter_with_2d(adapter_2d));
            assert!(
                req.max_texture_dimension_2d >= 3456,
                "adapter max {adapter_2d}: requested {} must fit a 3456x2168 surface",
                req.max_texture_dimension_2d
            );
        }
    }

    #[test]
    fn never_requests_more_than_the_adapter_supports() {
        // Requesting above the adapter's maximum would make request_device FAIL — a
        // startup crash instead of a fullscreen crash. Clamp must hold everywhere,
        // including adapters weaker than the downlevel 2048 floor.
        for adapter_2d in [256, 1024, 2048, 4096, 8192, 16384, u32::MAX] {
            let req = renderer_required_limits(adapter_with_2d(adapter_2d));
            assert!(
                req.max_texture_dimension_2d <= adapter_2d,
                "adapter max {adapter_2d}: requested {} exceeds it",
                req.max_texture_dimension_2d
            );
        }
    }

    #[test]
    fn caps_at_native_default_instead_of_adapter_maximum() {
        // Compatibility: we take only what fullscreen rendering needs (the native
        // desktop default, 8192 — larger than any current display), not every adapter
        // maximum.
        let native = wgpu::Limits::default().max_texture_dimension_2d;
        let req = renderer_required_limits(adapter_with_2d(u32::MAX));
        assert_eq!(req.max_texture_dimension_2d, native);
    }

    #[test]
    fn everything_else_stays_at_the_downlevel_floor() {
        // Only the surface-relevant 2d texture limit is raised; all other limits keep
        // the broad-compatibility downlevel profile the renderer was built against.
        let req = renderer_required_limits(wgpu::Limits::default());
        let expected = wgpu::Limits {
            max_texture_dimension_2d: req.max_texture_dimension_2d,
            ..wgpu::Limits::downlevel_defaults()
        };
        assert_eq!(req, expected);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_terminal_renderer_prefers_the_display_class_adapter() {
        assert_eq!(
            LINUX_RENDERER_POWER_PREFERENCE,
            wgpu::PowerPreference::LowPower
        );
    }

    #[test]
    fn intel_vulkan_wayland_prefers_supported_non_fifo_presentation() {
        let supported = [
            wgpu::PresentMode::Fifo,
            wgpu::PresentMode::Immediate,
            wgpu::PresentMode::Mailbox,
        ];
        assert_eq!(
            linux_surface_present_mode(true, 0x8086, wgpu::Backend::Vulkan, &supported),
            wgpu::PresentMode::Mailbox
        );
        assert_eq!(
            linux_surface_present_mode(
                true,
                0x8086,
                wgpu::Backend::Vulkan,
                &[wgpu::PresentMode::Fifo, wgpu::PresentMode::Immediate],
            ),
            wgpu::PresentMode::Fifo
        );
    }

    #[test]
    fn fifo_remains_the_policy_outside_intel_vulkan_wayland() {
        let supported = [wgpu::PresentMode::Fifo, wgpu::PresentMode::Mailbox];
        for (is_wayland, vendor, backend) in [
            (false, 0x8086, wgpu::Backend::Vulkan),
            (true, 0x1002, wgpu::Backend::Vulkan),
            (true, 0x8086, wgpu::Backend::Gl),
        ] {
            assert_eq!(
                linux_surface_present_mode(is_wayland, vendor, backend, &supported),
                wgpu::PresentMode::Fifo
            );
        }
    }

    #[test]
    fn intel_vulkan_wayland_falls_back_to_universal_fifo_when_required() {
        assert_eq!(
            linux_surface_present_mode(
                true,
                0x8086,
                wgpu::Backend::Vulkan,
                &[wgpu::PresentMode::Fifo],
            ),
            wgpu::PresentMode::Fifo
        );
    }
}
