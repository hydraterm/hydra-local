//! Tao/GTK implementation of [`ChromeHostServices`](crate::host_services::ChromeHostServices) (Linux path).
//!
//! On macOS `App` owns the dashboard child WebView directly and drives it in-process (its `react_webview`
//! path, byte-identical). On Linux the WebView is owned by the Tao/GTK
//! [`LinuxDashboardHost`](super::window_host::LinuxDashboardHost) because wry's WebKitGTK backend needs a GTK
//! hierarchy, so `App` cannot touch it directly. This adapter is the neutral seam: `App` calls the
//! [`ChromeHostServices`] trait and this type forwards each call to the host-owned WebViews + GTK sidebar:
//!
//! * `evaluate_dashboard_script` → `wry::WebView::evaluate_script` on the persistent sidebar and topbar
//!   WebViews (model refresh, bridge injection, folder-picker result relay). Same JS bridge calls the macOS
//!   path issues.
//! * `set_sidebar_width`         → update the noninteractive GTK sidebar allocator; GTK's relayout
//!   fires the terminal-slot `size_allocate` (the geometry authority), which grows/shrinks the WGPU child +
//!   PTY into the freed/consumed space. This is what makes collapse/expand physically free/consume space.
//! * `pick_folder`               → open a native GTK `FileChooserNative` folder dialog asynchronously on the
//!   owner GLib context, then relay the chosen path (or cancel) back into the WebView via the SAME
//!   `__HYDRA_DASHBOARD_RESOLVE_FOLDER_PICK__` bridge call the macOS `rfd` path uses.
//!
//! GTK/wry handles are reference-counted and `!Send`; `App` runs on the GTK main thread, so they never cross a
//! thread. No `gtk`/`wry` type leaks past this module — `App` consumes only the neutral trait.

#![cfg(target_os = "linux")]

use std::cell::RefCell;
use std::rc::Rc;

use gtk::prelude::*;

use crate::host_services::ChromeHostServices;
use crate::linux_host::overlay::LinuxOverlayHost;
use crate::linux_host::sidebar_layout::SidebarLayout;
use crate::ReactChromeScriptKind;

/// GTK/wry-backed [`ChromeHostServices`]. Holds the host-owned dashboard WebViews (shared with the
/// [`LinuxDashboardHost`](super::window_host::LinuxDashboardHost) that keeps it alive + wires recovery), the
/// GTK allocator whose physical child rectangles drive collapse/expand, and the top-level window used as the
/// transient parent for the native folder dialog.
pub struct LinuxChromeServices {
    /// The dashboard WebView (wry). Shared `Rc` with the host: the host owns lifetime + recovery signals, this
    /// adapter drives script evaluation + folder-pick relay.
    webview: Rc<wry::WebView>,
    /// Related topbar realm. Model/bridge scripts are delivered here exactly once when mounted.
    topbar: Option<Rc<wry::WebView>>,
    /// The noninteractive GTK allocator between sidebar and terminal column. It retains React's desired width
    /// while its exact child allocation drives collapse/expand; terminal `size_allocate` remains authoritative.
    sidebar_layout: SidebarLayout,
    /// Native terminal focus target. Kept in this cross-surface adapter so dashboard pointer
    /// actions can return focus without exposing GTK types to renderer/app code.
    terminal_slot: gtk::DrawingArea,
    /// The top-level GTK window — the transient parent for the modal folder dialog so it centers over the app.
    top_level: gtk::ApplicationWindow,
    /// Lazily-created full-window overlay. It receives the same model/one-shot scripts as the sidebar,
    /// but owns its own readiness cache so first-open and WebKit recovery cannot lose a modal command.
    overlay: Option<Rc<LinuxOverlayHost>>,
    /// Async native pickers are single-flight. The gate prevents multiple modal portal dialogs and guarantees
    /// every duplicate request receives a terminal `null` result instead of leaving its JS Promise unresolved.
    folder_picker: Rc<RefCell<FolderPickerState>>,
}

#[derive(Default)]
struct FolderPickerState {
    dialog: Option<gtk::FileChooserNative>,
    /// Own the deferred finalizer exactly like the Linux host owns its flush wake: Tao's
    /// `run_return` leaves the process-global GLib context alive after the GUI loop exits, so an
    /// unowned source could otherwise retain the dialog/WebViews and fire after host teardown.
    finalize_source: Option<glib::SourceId>,
    lifecycle: FolderPickerLifecycle,
}

#[derive(Default)]
struct FolderPickerLifecycle {
    active: bool,
    /// A native response was received and its modal teardown is waiting for the next GLib idle
    /// turn. Keep the picker single-flight until destroy, WebKit resolution and focus restoration
    /// all complete.
    completing: bool,
    shutting_down: bool,
}

fn begin_folder_picker_response(state: &mut FolderPickerState) -> bool {
    // The resource check also rejects a stale/reentrant response emitted while destroy runs after
    // the host-owned dialog reference has already been taken.
    if state.dialog.is_none() {
        return false;
    }
    state.lifecycle.begin_response()
}

impl FolderPickerLifecycle {
    fn opened(&mut self) {
        self.active = true;
        self.completing = false;
    }

    fn begin_response(&mut self) -> bool {
        if !self.active || self.shutting_down || self.completing {
            return false;
        }
        self.completing = true;
        true
    }

    /// Finish only after native destroy, Promise resolution and focus restoration. The return
    /// value says whether WebView work is still permitted.
    fn finish_response(&mut self) -> bool {
        self.active = false;
        self.completing = false;
        !self.shutting_down
    }

    fn shut_down(&mut self) {
        self.shutting_down = true;
        self.active = false;
        self.completing = false;
    }
}

impl LinuxChromeServices {
    pub fn new(
        webview: Rc<wry::WebView>,
        topbar: Option<Rc<wry::WebView>>,
        sidebar_layout: SidebarLayout,
        terminal_slot: gtk::DrawingArea,
        top_level: gtk::ApplicationWindow,
        overlay: Option<Rc<LinuxOverlayHost>>,
    ) -> Self {
        Self {
            webview,
            topbar,
            sidebar_layout,
            terminal_slot,
            top_level,
            overlay,
            folder_picker: Rc::new(RefCell::new(FolderPickerState::default())),
        }
    }
}

impl Drop for LinuxChromeServices {
    fn drop(&mut self) {
        let (finalize_source, dialog) = {
            let mut picker = self.folder_picker.borrow_mut();
            picker.lifecycle.shut_down();
            (picker.finalize_source.take(), picker.dialog.take())
        };
        // Cancel before native destruction: removing the source drops its strong captures, and
        // the response callback sees shutting_down if destroy emits a final response.
        if let Some(source) = finalize_source {
            source.remove();
        }
        if let Some(dialog) = dialog {
            // The response callback observes `shutting_down` and deliberately performs no WebView work.
            dialog.destroy();
        }
    }
}

fn for_each_persistent_target<T>(
    sidebar: &T,
    topbar: Option<&T>,
    kind: ReactChromeScriptKind,
    mut visit: impl FnMut(&T, &'static str),
) {
    if !kind.targets_persistent_chrome() {
        return;
    }
    visit(sidebar, "sidebar");
    if let Some(topbar) = topbar {
        visit(topbar, "topbar");
    }
}

fn evaluate_script_on_chrome_targets(
    webview: &wry::WebView,
    topbar: Option<&Rc<wry::WebView>>,
    overlay: Option<&Rc<LinuxOverlayHost>>,
    script: &str,
    kind: ReactChromeScriptKind,
) {
    for_each_persistent_target(
        webview,
        topbar.map(Rc::as_ref),
        kind,
        |target, label| match target.evaluate_script(script) {
            Ok(()) => eprintln!(
                "linux-host dashboard {label} script evaluated bytes={}",
                script.len()
            ),
            Err(err) => eprintln!("linux-host dashboard {label} script eval failed: {err}"),
        },
    );
    // The overlay is a separate JS realm. This includes folder-picker resolution: its Promise
    // lives in the overlay page, so resolving only the sidebar would leave New Project suspended.
    if let Some(overlay) = overlay {
        overlay.evaluate_or_remember(script, kind);
    }
}

fn resolve_folder_picker_on_chrome_targets(
    webview: &wry::WebView,
    topbar: Option<&Rc<wry::WebView>>,
    overlay: Option<&Rc<LinuxOverlayHost>>,
    request_id: &str,
    path: Option<&str>,
) {
    let script = folder_picker_resolution_script(request_id, path);
    evaluate_script_on_chrome_targets(
        webview,
        topbar,
        overlay,
        &script,
        ReactChromeScriptKind::Transient,
    );
}

fn folder_picker_resolution_script(request_id: &str, path: Option<&str>) -> String {
    let request_json = serde_json::to_string(request_id).expect("request id serializes");
    let path_json = serde_json::to_string(&path).expect("folder path serializes");
    format!(
        "if (window.__HYDRA_DASHBOARD_RESOLVE_FOLDER_PICK__) {{ window.__HYDRA_DASHBOARD_RESOLVE_FOLDER_PICK__({request_json}, {path_json}); }}"
    )
}

impl ChromeHostServices for LinuxChromeServices {
    fn evaluate_dashboard_script(&self, script: &str, kind: ReactChromeScriptKind) {
        // wry's `WebView::evaluate_script` is the same cross-platform entry the macOS path uses; on Linux it
        // runs through the WebKitGTK backend. Log bytes so the delegation is provable in the host log.
        evaluate_script_on_chrome_targets(
            &self.webview,
            self.topbar.as_ref(),
            self.overlay.as_ref(),
            script,
            kind,
        );
    }

    fn set_sidebar_width(&self, width_logical_px: u32) {
        // A realized WebKit child may retain an old natural requisition. SidebarLayout deliberately ignores
        // child requisitions and allocates the two clipped bands from this retained React width. If the window
        // is temporarily too narrow, only the visible width is clamped; widening restores this desired value.
        self.sidebar_layout
            .set_desired_sidebar_width(width_logical_px);
        eprintln!("linux-host dashboard sidebar width set width_logical_px={width_logical_px}");
    }

    fn focus_terminal(&self) {
        self.terminal_slot.grab_focus();
        eprintln!("linux-host dashboard returned focus to terminal");
    }

    fn set_overlay_visible(&self, visible: bool) {
        if let Some(overlay) = self.overlay.as_ref() {
            overlay.set_visible(visible);
        } else if visible {
            eprintln!("linux-host dashboard overlay unavailable; terminal remains active");
        }
    }

    fn pick_folder(&self, request_id: &str) {
        let picker_busy = {
            let picker = self.folder_picker.borrow();
            picker.dialog.is_some()
                || picker.finalize_source.is_some()
                || picker.lifecycle.completing
        };
        if picker_busy {
            eprintln!(
                "linux-host dashboard folder picker declined request={request_id:?} reason=already-active"
            );
            resolve_folder_picker_on_chrome_targets(
                &self.webview,
                self.topbar.as_ref(),
                self.overlay.as_ref(),
                request_id,
                None,
            );
            return;
        }

        // Never call `FileChooserNative::run()` here: this method is invoked while the Tao/GTK owner loop is
        // delivering a renderer event. Its recursive GLib loop handles GTK/GDK I/O but suspends Tao's outer Rust
        // loop, starving renderer/terminal UserEvents until the picker returns. The signal-driven `show()` below
        // returns immediately to that owner loop so terminal, WebKit, and compositor traffic remain live.
        let dialog = gtk::FileChooserNative::new(
            Some("Choose project directory"),
            Some(&self.top_level),
            gtk::FileChooserAction::SelectFolder,
            Some("_Select"),
            Some("_Cancel"),
        );
        // `show()` does not impose modal behavior itself, so the single native chooser sets it explicitly.
        dialog.set_modal(true);
        let request_id = request_id.to_owned();
        let webview = self.webview.clone();
        let topbar = self.topbar.clone();
        let overlay = self.overlay.clone();
        let picker = Rc::downgrade(&self.folder_picker);
        let opened_at = std::time::Instant::now();
        let response_request_id = request_id.clone();
        eprintln!("linux-host dashboard folder picker opened request={request_id:?}");
        dialog.connect_response(move |dialog, response| {
            let Some(picker) = picker.upgrade() else {
                return;
            };
            let should_complete = {
                let mut picker = picker.borrow_mut();
                begin_folder_picker_response(&mut picker)
            };
            // Drop/teardown owns destruction and must not evaluate JavaScript against dying WebViews.
            if !should_complete {
                return;
            }

            let path = if response == gtk::ResponseType::Accept {
                dialog
                    .filename()
                    .map(|p| p.to_string_lossy().trim_end_matches('/').to_string())
            } else {
                None
            };
            eprintln!(
                "linux-host dashboard folder picker response request={response_request_id:?} selected={} elapsed_ms={}",
                path.is_some(),
                opened_at.elapsed().as_millis(),
            );

            // Return from GtkNativeDialog::response immediately after hiding it. Destroying the
            // transient, evaluating scripts in two WebKit realms and grabbing focus from inside
            // the response signal races GTK/GDK's Wayland modal teardown; on GNOME that produced
            // a short, self-recovering "Maestro App is not responding" prompt on Cancel. An idle
            // turn lets GTK finish the native-dialog response and compositor bookkeeping first.
            // The state deliberately remains single-flight until this callback finishes.
            dialog.hide();
            let dialog = dialog.clone();
            let finalize_webview = webview.clone();
            let finalize_topbar = topbar.clone();
            let finalize_overlay = overlay.clone();
            let finalize_request_id = response_request_id.clone();
            let finalize_picker = picker.clone();
            let source = glib::idle_add_local_once(move || {
                let owned_dialog = {
                    let mut picker = finalize_picker.borrow_mut();
                    // The source is firing now; GLib removes `_once` automatically. Clear only
                    // our bookkeeping—never call SourceId::remove from its own callback.
                    picker.finalize_source.take();
                    picker.dialog.take()
                };
                // Drop may already have taken and destroyed the host-owned reference. Only the
                // normal completion path owns native-dialog destruction here.
                if owned_dialog.is_some() {
                    dialog.destroy();
                }
                if finalize_picker.borrow().lifecycle.shutting_down {
                    finalize_picker
                        .borrow_mut()
                        .lifecycle
                        .finish_response();
                    return;
                }

                resolve_folder_picker_on_chrome_targets(
                    &finalize_webview,
                    finalize_topbar.as_ref(),
                    finalize_overlay.as_ref(),
                    &finalize_request_id,
                    path.as_deref(),
                );
                if let Some(overlay) = finalize_overlay.as_ref() {
                    overlay.refocus_if_visible();
                }
                // Keep completing=true through every potentially reentrant GTK/WebKit operation
                // above. Only now may a subsequent folder request become active.
                finalize_picker
                    .borrow_mut()
                    .lifecycle
                    .finish_response();
                eprintln!(
                    "linux-host dashboard folder picker finalized request={finalize_request_id:?} selected={} elapsed_ms={}",
                    path.is_some(),
                    opened_at.elapsed().as_millis(),
                );
            });
            picker.borrow_mut().finalize_source = Some(source);
        });
        {
            let mut picker = self.folder_picker.borrow_mut();
            picker.dialog = Some(dialog.clone());
            picker.lifecycle.opened();
        }
        let show_started = std::time::Instant::now();
        dialog.show();
        eprintln!(
            "linux-host dashboard folder picker show returned request={request_id:?} elapsed_ms={}",
            show_started.elapsed().as_millis(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{
        begin_folder_picker_response, folder_picker_resolution_script, for_each_persistent_target,
        FolderPickerLifecycle, FolderPickerState,
    };
    use crate::ReactChromeScriptKind;

    #[test]
    fn persistent_script_targets_include_mounted_topbar_once_and_in_order() {
        let sidebar = "sidebar";
        let topbar = "topbar";
        let mut visited = Vec::new();
        for kind in [
            ReactChromeScriptKind::Model,
            ReactChromeScriptKind::Transient,
        ] {
            visited.clear();
            for_each_persistent_target(&sidebar, Some(&topbar), kind, |target, label| {
                visited.push((label, *target));
            });
            assert_eq!(
                visited,
                vec![("sidebar", "sidebar"), ("topbar", "topbar")],
                "persistent routing changed for {kind:?}"
            );
        }
    }

    #[test]
    fn missing_topbar_does_not_block_sidebar_script_delivery() {
        let mut visited = Vec::new();
        for_each_persistent_target(
            &"sidebar",
            None,
            ReactChromeScriptKind::Model,
            |target, label| {
                visited.push((label, *target));
            },
        );
        assert_eq!(visited, vec![("sidebar", "sidebar")]);
    }

    #[test]
    fn modal_scripts_never_reach_persistent_dashboard_realms() {
        let mut visited = Vec::new();
        for_each_persistent_target(
            &"sidebar",
            Some(&"topbar"),
            ReactChromeScriptKind::Modal,
            |target, label| visited.push((label, *target)),
        );
        assert!(visited.is_empty());
    }

    #[test]
    fn folder_picker_cancel_resolves_with_null() {
        let script = folder_picker_resolution_script("folder-1", None);
        assert!(script.contains("(\"folder-1\", null)"));
    }

    #[test]
    fn folder_picker_result_is_json_escaped() {
        let script = folder_picker_resolution_script("folder-\"2", Some("/tmp/quo\"te"));
        assert!(script.contains(r#""folder-\"2""#));
        assert!(script.contains(r#""/tmp/quo\"te""#));
    }

    #[test]
    fn folder_picker_response_is_single_flight_until_idle_finalize() {
        let mut lifecycle = FolderPickerLifecycle::default();
        lifecycle.opened();
        assert!(lifecycle.begin_response());
        assert!(lifecycle.completing);
        assert!(!lifecycle.begin_response());
        assert!(lifecycle.finish_response());
        assert!(!lifecycle.active);
        assert!(!lifecycle.completing);
    }

    #[test]
    fn folder_picker_response_rejects_missing_dialog_resource() {
        let mut state = FolderPickerState::default();
        state.lifecycle.opened();
        assert!(!begin_folder_picker_response(&mut state));
        assert!(!state.lifecycle.completing);
    }

    #[test]
    fn folder_picker_response_is_suppressed_during_teardown() {
        let mut lifecycle = FolderPickerLifecycle::default();
        lifecycle.opened();
        lifecycle.shut_down();
        assert!(!lifecycle.begin_response());
        assert!(!lifecycle.completing);
    }

    #[test]
    fn folder_picker_idle_finalize_drops_result_if_teardown_started_after_response() {
        let mut lifecycle = FolderPickerLifecycle::default();
        lifecycle.opened();
        assert!(lifecycle.begin_response());
        lifecycle.shutting_down = true;
        assert!(!lifecycle.finish_response());
        assert!(!lifecycle.completing);
    }
}
