//! WebView2 child surfaces for the Windows winit owner. PTYs and rendering stay outside WebView2.

use std::cell::Cell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use winit::event_loop::EventLoopProxy;
use winit::window::Window;
use wry::WebViewBuilderExtWindows;

use crate::dashboard_protocol::{
    windows_dashboard_document_is_trusted as trusted_document, DashboardAssetServing,
    DASHBOARD_PROTOCOL_SCHEME,
};
use crate::host_services::ChromeHostServices;
use crate::windows_chrome_geometry::apply_changed;
use crate::{
    bounded_react_chrome_ipc_body, ReactChromeScriptKind, RendererEvent, RendererReactChrome,
    UserEvent, ViewportEventSink,
};

pub(crate) struct WindowsChromeHost {
    sidebar: wry::WebView,
    topbar: wry::WebView,
    overlay: wry::WebView,
    // Drop views before their shared context, as required by WRY's context contract.
    _context: wry::WebContext,
    window: Arc<Window>,
    width: Cell<u32>,
    top_height: u32,
    overlay_visible: Cell<bool>,
    overlay_focus_pending: Cell<bool>,
    sidebar_applied: SurfaceCache,
    topbar_applied: SurfaceCache,
    overlay_applied: SurfaceCache,
    overlay_requested_bounds: Cell<Option<PhysicalBounds>>,
}

type PhysicalBounds = (i32, i32, u32, u32);

struct SurfaceCache {
    bounds: Cell<Option<PhysicalBounds>>,
    visible: Cell<Option<bool>>,
}

impl SurfaceCache {
    fn new(visible: bool) -> Self {
        Self {
            bounds: Cell::new(None),
            visible: Cell::new(Some(visible)),
        }
    }

    fn set_bounds(&self, view: &wry::WebView, bounds: PhysicalBounds) -> Result<(), wry::Error> {
        apply_changed(&self.bounds, bounds, || {
            view.set_bounds(wry::Rect {
                position: wry::dpi::PhysicalPosition::new(bounds.0, bounds.1).into(),
                size: wry::dpi::PhysicalSize::new(bounds.2, bounds.3).into(),
            })
        })
    }

    fn set_visible(&self, view: &wry::WebView, visible: bool) -> Result<(), wry::Error> {
        apply_changed(&self.visible, visible, || view.set_visible(visible))
    }
}

impl WindowsChromeHost {
    pub(crate) fn mount(
        window: Arc<Window>,
        chrome: &RendererReactChrome,
        events: Option<ViewportEventSink>,
        proxy: Option<EventLoopProxy<UserEvent>>,
    ) -> Result<Rc<Self>, String> {
        let surface = |query, expected_url: &str| {
            DashboardAssetServing::checked_native_surface(&chrome.index_html, query, expected_url)
                .ok_or_else(|| "dashboard surface must match its bundled entrypoint".to_string())
        };
        let sidebar = surface("chrome=sidebar", &chrome.url)?;
        let topbar = surface("chrome=topbar", &chrome.top_url)?;
        let overlay = surface("chrome=overlay", &chrome.overlay_url)?;
        let data_root = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute() && path.is_dir())
            .ok_or_else(|| "Windows Local AppData is unavailable for WebView2".to_string())?;
        let data_directory = data_root.join("Hydra/WindowsFoundation/WebView2");
        std::fs::create_dir_all(&data_directory)
            .map_err(|error| format!("create WebView2 profile directory: {error}"))?;
        let mut context = wry::WebContext::new(Some(data_directory));
        let make_view =
            |context: &mut wry::WebContext, serving: DashboardAssetServing, visible: bool| {
                let canonical_url = serving.url.clone();
                let navigation_url = canonical_url.clone();
                let ipc_url = canonical_url.clone();
                let page_url = canonical_url.clone();
                let view_events = events.clone();
                let view_proxy = proxy.clone();
                wry::WebViewBuilder::new_with_web_context(context)
                    .with_custom_protocol(DASHBOARD_PROTOCOL_SCHEME.into(), move |_, request| {
                        serving.serve(request)
                    })
                    .with_https_scheme(true)
                    .with_url(&canonical_url)
                    // Presentation only: the standalone sidebar's CSS follows this
                    // WebView's native viewport, without waiting for React replay.
                    .with_initialization_script("window.__HYDRA_WINDOWS_SIDEBAR_CSS__ = true;")
                    .with_initialization_script(&chrome.initialization_script)
                    // The document keeps its opaque CSS background; unpainted resize
                    // backing composes over the opaque WGPU parent, not a white fill.
                    .with_transparent(true)
                    .with_devtools(false)
                    .with_visible(visible)
                    // WRY defaults to focused=true, even for the initially hidden overlay.
                    // Mounting chrome must not steal the fresh terminal's keyboard input.
                    .with_focused(false)
                    .with_navigation_handler(move |candidate| {
                        trusted_document(&candidate, &navigation_url)
                    })
                    .with_new_window_req_handler(|_, _| wry::NewWindowResponse::Deny)
                    .with_download_started_handler(|_, _| false)
                    .with_ipc_handler(move |request| {
                        if !trusted_document(&request.uri().to_string(), &ipc_url) {
                            eprintln!("hydra-dashboard Windows IPC rejected: untrusted document");
                            return;
                        }
                        let Some(json) = bounded_react_chrome_ipc_body(request.body()) else {
                            eprintln!("hydra-dashboard Windows IPC rejected: payload too large");
                            return;
                        };
                        if let Some(events) = view_events.as_ref() {
                            if events
                                .send(RendererEvent::ReactChromeIntent {
                                    json,
                                    dialog_focus_ticket: None,
                                })
                                .is_err()
                            {
                                eprintln!("hydra-dashboard Windows IPC receiver closed");
                            }
                        }
                    })
                    .with_on_page_load_handler(move |event, url| {
                        if matches!(event, wry::PageLoadEvent::Finished)
                            && trusted_document(&url, &page_url)
                        {
                            if let Some(proxy) = view_proxy.as_ref() {
                                let _ = proxy.send_event(UserEvent::ReactChromePageLoaded { url });
                            }
                        }
                    })
                    .with_bounds(rect(0.0, 0.0, 1.0, 1.0))
                    .build_as_child(window.as_ref())
                    .map_err(|error| format!("create WebView2 surface: {error}"))
            };
        let host = Rc::new(Self {
            sidebar: make_view(&mut context, sidebar, true)?,
            topbar: make_view(&mut context, topbar, true)?,
            overlay: make_view(&mut context, overlay, false)?,
            _context: context,
            window,
            width: Cell::new(chrome.width_logical_px),
            top_height: chrome.top_height_logical_px,
            overlay_visible: Cell::new(false),
            overlay_focus_pending: Cell::new(false),
            sidebar_applied: SurfaceCache::new(true),
            topbar_applied: SurfaceCache::new(true),
            overlay_applied: SurfaceCache::new(false),
            overlay_requested_bounds: Cell::new(None),
        });
        host.resize()?;
        Ok(host)
    }

    pub(crate) fn resize(&self) -> Result<(), String> {
        let size = self.window.inner_size();
        self.resize_to((size.width, size.height), self.width.get())
    }

    /// Use the WGPU allocation accepted by the owner, not a second GetClientRect
    /// observation that can advance while a buffered WM_SIZE is being handled.
    pub(crate) fn resize_to(&self, size: (u32, u32), requested_width: u32) -> Result<(), String> {
        self.width.set(requested_width);
        if size.0 == 0 || size.1 == 0 {
            return Ok(());
        }
        let scale = self.window.scale_factor();
        let width = size.0 as f64 / scale;
        let height = size.1 as f64 / scale;
        let sidebar = f64::from(crate::windows_chrome_geometry::sidebar_width_logical(
            requested_width,
            size.0,
            scale,
        ));
        // Keep the accepted allocation even while the overlay is hidden. Showing
        // it must not sample a newer HWND extent or expose its initial 1px bounds.
        self.overlay_requested_bounds
            .set(Some(physical_rect(0.0, 0.0, width, height, scale)));
        self.sidebar_applied
            .set_bounds(
                &self.sidebar,
                physical_rect(0.0, 0.0, sidebar, height, scale),
            )
            .and_then(|_| {
                self.sidebar_applied
                    .set_visible(&self.sidebar, sidebar > 0.0)
            })
            .and_then(|_| {
                self.topbar_applied.set_bounds(
                    &self.topbar,
                    physical_rect(sidebar, 0.0, width - sidebar, self.top_height as f64, scale),
                )
            })
            .and_then(|_| self.apply_overlay_visibility())
            .map_err(|error| format!("resize WebView2 chrome: {error}"))
    }

    fn apply_overlay_visibility(&self) -> Result<(), wry::Error> {
        let visible = self.overlay_visible.get();
        if visible {
            let Some(bounds) = self.overlay_requested_bounds.get() else {
                // Mounting a minimized/zero-size owner has no accepted allocation
                // yet. Its next nonzero resize will apply this pending request.
                return Ok(());
            };
            self.overlay_applied.set_bounds(&self.overlay, bounds)?;
        }
        self.overlay_applied.set_visible(&self.overlay, visible)?;
        if self.overlay_focus_pending.get() {
            if visible {
                self.overlay.focus()?;
            } else {
                self.sidebar.focus_parent()?;
            }
            self.overlay_focus_pending.set(false);
        }
        Ok(())
    }

    fn report(result: Result<(), wry::Error>) {
        if let Err(error) = result {
            eprintln!("hydra-dashboard Windows surface operation failed: {error}");
        }
    }

    pub(crate) fn native_pointer_pressed(&self) {
        // Clicking the parent HWND does not take keyboard focus back from a WebView2
        // child automatically. Native terminal input must follow the clicked surface.
        // A visible modal keeps ownership even if a parent event was already queued.
        if !self.overlay_visible.get() && self.overlay_applied.visible.get() == Some(false) {
            self.focus_terminal();
        }
    }
}

impl ChromeHostServices for WindowsChromeHost {
    fn evaluate_dashboard_script(&self, script: &str, kind: ReactChromeScriptKind) {
        if kind.targets_persistent_chrome() {
            Self::report(self.sidebar.evaluate_script(script));
            Self::report(self.topbar.evaluate_script(script));
        }
        Self::report(self.overlay.evaluate_script(script));
    }

    fn set_sidebar_width(&self, width_logical_px: u32) {
        self.width.set(width_logical_px);
        if let Err(error) = self.resize() {
            eprintln!("hydra-dashboard Windows sidebar resize failed: {error}");
        }
    }

    fn focus_terminal(&self) {
        Self::report(self.sidebar.focus_parent());
    }

    fn set_overlay_visible(&self, visible: bool) {
        self.overlay_visible.set(visible);
        // A minimized mount or failed bounds/visibility operation can defer the
        // transition. Transfer focus once after success, not on each resize.
        self.overlay_focus_pending.set(true);
        Self::report(self.apply_overlay_visibility());
    }

    fn pick_folder(&self, request_id: &str) {
        let path = rfd::FileDialog::new()
            .set_parent(self.window.as_ref())
            .set_title("Choose project directory")
            .pick_folder()
            .map(|path| path.to_string_lossy().into_owned());
        let request_json = serde_json::to_string(request_id).expect("request id serializes");
        let path_json = serde_json::to_string(&path).expect("folder path serializes");
        self.evaluate_dashboard_script(
            &format!(
                "window.__HYDRA_DASHBOARD_RESOLVE_FOLDER_PICK__?.({request_json}, {path_json});"
            ),
            ReactChromeScriptKind::Transient,
        );
    }
}

fn rect(x: f64, y: f64, width: f64, height: f64) -> wry::Rect {
    wry::Rect {
        position: wry::dpi::LogicalPosition::new(x, y).into(),
        size: wry::dpi::LogicalSize::new(width.max(1.0), height.max(1.0)).into(),
    }
}

fn physical_rect(x: f64, y: f64, width: f64, height: f64, scale: f64) -> PhysicalBounds {
    // Match WRY's logical-to-physical conversion, including its original 1-logical-
    // pixel clamp. Cache physical coordinates so DPI changes cannot be skipped.
    let bounds = rect(x, y, width, height);
    let position = bounds.position.to_physical::<i32>(scale);
    let size = bounds.size.to_physical::<u32>(scale);
    (position.x, position.y, size.width, size.height)
}
