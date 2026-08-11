//! Shared host for always-mounted Linux dashboard WebViews (sidebar and topbar).
//!
//! Both surfaces use the same private `hydra://localhost` asset origin, exact-document
//! navigation/IPC policy, typed renderer-event bridge, and generation-bound recovery. The sidebar
//! is the primary view that registers the custom protocol; the topbar is a related view in the
//! same [`wry::WebContext`] and therefore reuses that one protocol/process pool.

#![cfg(target_os = "linux")]

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use gtk::prelude::*;
use tao::event_loop::EventLoopProxy;
use webkit2gtk::WebViewExt as _;
use wry::{NewWindowResponse, WebViewBuilder, WebViewBuilderExtUnix, WebViewExtUnix};

use super::recovery::{
    parse_webkit_document_generation, webkit_recovery_url, RecoveryController, RecoveryDecision,
    RecoverySignalTracker, WebKitFailureReason, WebKitRecoveryEvent, WebKitSurface,
    MAX_WEBKIT_RECOVERY_ATTEMPTS,
};
use super::wake::{webkit_recovery_sender, LinuxLoopEvent};
pub(super) use crate::dashboard_protocol::DashboardAssetServing as ChromeServing;
use crate::dashboard_protocol::DASHBOARD_PROTOCOL_SCHEME;
use crate::{RendererEvent, UserEvent};

/// Installed at document-start, before the bundled dashboard runs. WebKit accessibility can retain
/// a remote action for a DOM control after its native GTK WebView becomes insensitive. While the
/// native overlay owns the modal, this capture listener prevents such stale actions from reaching
/// React (and therefore from mutating presentation-local state). It remains installed for the
/// lifetime of one document so it always precedes application listeners; modal presentation only
/// toggles the small `active` flag.
const PERSISTENT_MODAL_FIREWALL_PRELOAD: &str = r#"
(function () {
  "use strict";
  if (window.__HYDRA_NATIVE_MODAL_UNDERLAY_FIREWALL__) return;
  var blockedEvents = [
    "auxclick", "beforeinput", "blur", "change", "click", "compositionend",
    "compositionstart", "compositionupdate", "contextmenu", "copy", "cut", "dblclick",
    "drag", "dragend", "dragenter", "dragleave", "dragover", "dragstart", "drop",
    "focus", "focusin", "focusout", "input", "keydown", "keypress", "keyup",
    "mousedown", "mouseenter", "mouseleave", "mousemove", "mouseout", "mouseover",
    "mouseup", "paste", "pointercancel", "pointerdown", "pointerenter", "pointerleave",
    "pointermove", "pointerout", "pointerover", "pointerup", "reset", "select",
    "selectstart", "submit", "touchcancel", "touchend", "touchmove", "touchstart", "wheel"
  ];
  // Fail closed until the owner loop accepts this exact document's PageFinished event. A recovery
  // document can otherwise expose fresh controls to a retained AT-SPI proxy while a modal is up.
  var firewall = { active: true };
  var blocker = function (event) {
    if (!firewall.active) return;
    if (event && event.cancelable) event.preventDefault();
    if (event && typeof event.stopImmediatePropagation === "function") {
      event.stopImmediatePropagation();
    }
  };
  blockedEvents.forEach(function (type) {
    window.addEventListener(type, blocker, { capture: true, passive: false });
  });
  Object.defineProperty(window, "__HYDRA_NATIVE_MODAL_UNDERLAY_FIREWALL__", {
    value: firewall,
    configurable: false,
    enumerable: false,
    writable: false
  });
})();
"#;

const RELEASE_PERSISTENT_MODAL_FIREWALL_SCRIPT: &str = r#"
(function () {
  "use strict";
  var firewall = window.__HYDRA_NATIVE_MODAL_UNDERLAY_FIREWALL__;
  if (!firewall) return;
  firewall.active = false;
})();
"#;

fn persistent_initialization_script(base: &str) -> String {
    let mut script =
        String::with_capacity(PERSISTENT_MODAL_FIREWALL_PRELOAD.len() + base.len() + 1);
    script.push_str(PERSISTENT_MODAL_FIREWALL_PRELOAD);
    script.push('\n');
    script.push_str(base);
    script
}

fn persistent_firewall_release_allowed(
    exact_page_finished: bool,
    input_gate: &PersistentInputGate,
) -> bool {
    exact_page_finished && input_gate.accepts_intents()
}

/// Authoritative owner-loop gate for the always-mounted sidebar/topbar while the lazy overlay owns
/// the application modal. GTK sensitivity blocks ordinary pointer/key delivery, but WebKit's
/// out-of-process accessibility actions can bypass that widget flag and still emit IPC. Every
/// persistent surface therefore checks this shared gate at the trusted IPC boundary as well.
#[derive(Default)]
pub(super) struct PersistentInputGate {
    modal_active: Cell<bool>,
}

impl PersistentInputGate {
    pub(super) fn suppress(&self) {
        self.modal_active.set(true);
    }

    pub(super) fn restore(&self) {
        self.modal_active.set(false);
    }

    fn accepts_intents(&self) -> bool {
        !self.modal_active.get()
    }
}

/// How an always-mounted surface joins the shared WebKit context.
pub(super) enum PersistentMount<'a> {
    /// Register the one private asset protocol on the shared context (the sidebar).
    Primary,
    /// Reuse the primary view's context/protocol/process pool (the topbar).
    Related(&'a Rc<wry::WebView>),
}

/// One independently recoverable, always-mounted dashboard presentation surface.
pub(super) struct PersistentChromeSurface {
    surface: WebKitSurface,
    canonical_url: String,
    webview: Option<Rc<wry::WebView>>,
    recovery: RefCell<RecoveryController>,
    tracker: Rc<RefCell<RecoverySignalTracker>>,
    input_gate: Rc<PersistentInputGate>,
}

impl PersistentChromeSurface {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn mount(
        parent: &gtk::Box,
        surface: WebKitSurface,
        serving: &ChromeServing,
        initialization_script: String,
        web_context: &Rc<RefCell<wry::WebContext>>,
        mount: PersistentMount<'_>,
        events: Option<std::sync::mpsc::Sender<RendererEvent>>,
        wake_proxy: EventLoopProxy<LinuxLoopEvent>,
        input_gate: Rc<PersistentInputGate>,
    ) -> Self {
        debug_assert!(matches!(
            surface,
            WebKitSurface::Sidebar | WebKitSurface::Topbar
        ));
        let tracker = Rc::new(RefCell::new(RecoverySignalTracker::default()));
        let webview = mount_webview(
            parent,
            surface,
            serving,
            initialization_script,
            web_context,
            mount,
            events,
            wake_proxy,
            tracker.clone(),
            input_gate.clone(),
        );
        Self {
            surface,
            canonical_url: serving.url.clone(),
            webview,
            recovery: RefCell::new(RecoveryController::default()),
            tracker,
            input_gate,
        }
    }

    pub(super) fn webview(&self) -> Option<Rc<wry::WebView>> {
        self.webview.clone()
    }

    pub(super) fn failure_is_current(&self, generation: Option<u64>) -> bool {
        self.recovery.borrow().failure_is_current(generation)
    }

    /// Owner-loop recovery. WebKit callbacks only classify and enqueue; this is the sole path that
    /// may reload or hide an always-mounted surface.
    pub(super) fn handle_recovery_event(&self, event: WebKitRecoveryEvent) -> Option<UserEvent> {
        if event.surface() != self.surface {
            return None;
        }
        match event {
            WebKitRecoveryEvent::Failure {
                generation, reason, ..
            } => {
                match self.recovery.borrow_mut().on_failure(generation) {
                    RecoveryDecision::Dispatch {
                        attempt,
                        generation,
                    } => {
                        let Some(recovery_url) =
                            webkit_recovery_url(&self.canonical_url, generation)
                        else {
                            eprintln!(
                                "linux-host {} recovery phase=invalid-canonical-url bundled=false bytes={} attempt={attempt} generation={generation}",
                                surface_name(self.surface),
                                self.canonical_url.len()
                            );
                            return None;
                        };
                        self.tracker.borrow_mut().prepare_load(generation);
                        eprintln!(
                            "linux-host {} recovery phase=dispatch bundled=true bytes={} reason={reason:?} attempt={attempt} generation={generation}",
                            surface_name(self.surface),
                            self.canonical_url.len()
                        );
                        if let Some(webview) = self.webview.as_ref() {
                            webview.webview().load_uri(&recovery_url);
                        }
                    }
                    RecoveryDecision::Coalesced => eprintln!(
                        "linux-host {} recovery phase=coalesced bundled=true bytes={} reason={reason:?}",
                        surface_name(self.surface),
                        self.canonical_url.len()
                    ),
                    RecoveryDecision::Exhausted => {
                        // Keep the GTK allocation stable: only this WebView capability retires.
                        self.tracker.borrow_mut().shut_down();
                        if let Some(webview) = self.webview.as_ref() {
                            let _ = webview.set_visible(false);
                        }
                        eprintln!(
                            "linux-host {} recovery phase=exhausted bundled=true bytes={} reason={reason:?} attempts={MAX_WEBKIT_RECOVERY_ATTEMPTS}",
                            surface_name(self.surface),
                            self.canonical_url.len()
                        );
                    }
                    RecoveryDecision::Inactive => {}
                }
                None
            }
            WebKitRecoveryEvent::PageFinished {
                generation,
                bundled,
                ..
            } => {
                let mut accepted = bundled
                    && self
                        .recovery
                        .borrow_mut()
                        .on_exact_page_finished(generation);
                // The document-start firewall is deliberately fail-closed. Only the owner loop may
                // release an exact accepted document, and never while the shared native modal gate
                // is active. During modal recovery, the existing persistent-suppression callback
                // will instead keep the firewall active and add inert/aria-hidden before the
                // overlay is presented again.
                if persistent_firewall_release_allowed(accepted, &self.input_gate) {
                    accepted = self.webview.as_ref().is_some_and(|webview| {
                        match webview.evaluate_script(RELEASE_PERSISTENT_MODAL_FIREWALL_SCRIPT) {
                            Ok(()) => true,
                            Err(error) => {
                                eprintln!(
                                    "linux-host {} modal firewall release failed: {error}",
                                    surface_name(self.surface)
                                );
                                false
                            }
                        }
                    });
                }
                if accepted {
                    eprintln!(
                        "linux-host {} recovery phase=ready bundled=true bytes={} generation={}",
                        surface_name(self.surface),
                        self.canonical_url.len(),
                        generation.unwrap_or_default()
                    );
                }
                persistent_replay_event(accepted, &self.canonical_url)
            }
            WebKitRecoveryEvent::PageStarted { .. } => None,
            WebKitRecoveryEvent::OverlayReady { .. } => None,
        }
    }

    pub(super) fn shut_down_recovery(&self) {
        self.recovery.borrow_mut().shut_down();
        self.tracker.borrow_mut().shut_down();
    }
}

#[allow(clippy::too_many_arguments)]
fn mount_webview(
    parent: &gtk::Box,
    surface: WebKitSurface,
    serving: &ChromeServing,
    initialization_script: String,
    web_context: &Rc<RefCell<wry::WebContext>>,
    mount: PersistentMount<'_>,
    events: Option<std::sync::mpsc::Sender<RendererEvent>>,
    wake_proxy: EventLoopProxy<LinuxLoopEvent>,
    tracker: Rc<RefCell<RecoverySignalTracker>>,
    input_gate: Rc<PersistentInputGate>,
) -> Option<Rc<wry::WebView>> {
    let initialization_script = persistent_initialization_script(&initialization_script);
    let serve_url = serving.url.clone();
    let ipc_events = events.clone();
    let page_recovery_sender = webkit_recovery_sender(wake_proxy.clone());
    let navigation_recovery_sender = webkit_recovery_sender(wake_proxy.clone());
    let bundled_url = serve_url.clone();
    let page_load_tracker = tracker.clone();
    let navigation_tracker = tracker.clone();
    let trusted_ipc_url = serve_url.clone();
    let trusted_ipc_tracker = tracker.clone();
    let trusted_navigation_url = serve_url.clone();
    let trusted_input_gate = input_gate;

    let result = {
        let mut context = web_context.borrow_mut();
        let mut builder = WebViewBuilder::new_with_web_context(&mut context);
        builder = match mount {
            PersistentMount::Primary => {
                let asset_serving = serving.clone();
                builder.with_custom_protocol(
                    DASHBOARD_PROTOCOL_SCHEME.into(),
                    move |_webview_id, request| asset_serving.serve(request),
                )
            }
            PersistentMount::Related(primary) => builder.with_related_view(primary.webview()),
        };
        builder
            .with_url(serve_url.clone())
            .with_background_color((7, 8, 11, 255))
            .with_devtools(cfg!(debug_assertions))
            .with_initialization_script(initialization_script)
            .with_navigation_handler(move |candidate| {
                let generation =
                    parse_webkit_document_generation(&candidate, &trusted_navigation_url)
                        .map(|document| document.value());
                let (allowed, unpermitted_current) =
                    generation.map_or((false, None), |generation| {
                        let mut tracker = navigation_tracker.borrow_mut();
                        if tracker.claim_navigation(generation) {
                            (true, None)
                        } else {
                            (
                                false,
                                tracker.unpermitted_current_navigation(generation),
                            )
                        }
                    });
                if !allowed {
                    eprintln!(
                        "linux-host {} navigation blocked bundled=false bytes={}",
                        surface_name(surface),
                        candidate.len()
                    );
                    if let Some(generation) = unpermitted_current {
                        navigation_recovery_sender.send(WebKitRecoveryEvent::Failure {
                            surface,
                            generation: Some(generation),
                            reason: WebKitFailureReason::EngineReloadRequested,
                        });
                    }
                }
                allowed
            })
            .with_new_window_req_handler(move |url, _| {
                eprintln!(
                    "linux-host {} popup blocked bytes={}",
                    surface_name(surface),
                    url.len()
                );
                NewWindowResponse::Deny
            })
            .with_download_started_handler(move |url, _| {
                eprintln!(
                    "linux-host {} download blocked bytes={}",
                    surface_name(surface),
                    url.len()
                );
                false
            })
            .with_ipc_handler(move |request| {
                let request_uri = request.uri().to_string();
                let owned_generation =
                    parse_webkit_document_generation(&request_uri, &trusted_ipc_url)
                        .map(|document| document.value())
                        .filter(|generation| {
                            trusted_ipc_tracker.borrow().owns_generation(*generation)
                        });
                if !persistent_ipc_is_trusted(
                    &request_uri,
                    &trusted_ipc_url,
                    owned_generation,
                ) {
                    eprintln!(
                        "linux-host {} ipc intent rejected: untrusted_page uri_bytes={} payload_bytes={}",
                        surface_name(surface),
                        request_uri.len(),
                        request.body().len()
                    );
                    return;
                }
                if !trusted_input_gate.accepts_intents() {
                    eprintln!(
                        "linux-host {} ipc intent rejected: modal_underlay payload_bytes={}",
                        surface_name(surface),
                        request.body().len()
                    );
                    return;
                }
                let Some(json) = crate::bounded_react_chrome_ipc_body(request.body()) else {
                    eprintln!(
                        "linux-host {} ipc intent rejected: payload too large bytes={}",
                        surface_name(surface),
                        request.body().len()
                    );
                    return;
                };
                eprintln!(
                    "linux-host {} ipc intent bytes={}",
                    surface_name(surface),
                    json.len()
                );
                if let Some(events) = ipc_events.as_ref() {
                    if events
                        .send(RendererEvent::ReactChromeIntent { json })
                        .is_err()
                    {
                        eprintln!(
                            "linux-host {} ipc intent dropped: receiver closed",
                            surface_name(surface)
                        );
                    }
                } else {
                    eprintln!(
                        "linux-host {} ipc intent dropped: no event channel",
                        surface_name(surface)
                    );
                }
            })
            .with_on_page_load_handler(move |event, url| {
                let phase = match &event {
                    wry::PageLoadEvent::Started => "started",
                    wry::PageLoadEvent::Finished => "finished",
                };
                let document_generation =
                    parse_webkit_document_generation(&url, &bundled_url)
                        .map(|document| document.value());
                let generation = match &event {
                    wry::PageLoadEvent::Started => page_load_tracker
                        .borrow_mut()
                        .page_started(document_generation),
                    wry::PageLoadEvent::Finished => page_load_tracker
                        .borrow_mut()
                        .page_finished(document_generation),
                };
                let bundled = generation.is_some();
                eprintln!(
                    "linux-host {} page load phase={phase} bundled={bundled} bytes={}",
                    surface_name(surface),
                    url.len()
                );
                page_recovery_sender.send(match event {
                    wry::PageLoadEvent::Started => WebKitRecoveryEvent::PageStarted {
                        surface,
                        generation,
                        bundled,
                    },
                    wry::PageLoadEvent::Finished => WebKitRecoveryEvent::PageFinished {
                        surface,
                        generation,
                        bundled,
                    },
                });
            })
            .build_gtk(parent)
    };

    match result {
        Ok(webview) => {
            eprintln!(
                "linux-host {} WebView mounted (persistent, presentation-only)",
                surface_name(surface)
            );
            let inner = webview.webview();
            let crash_sender = webkit_recovery_sender(wake_proxy.clone());
            let crash_tracker = tracker.clone();
            let canonical_bytes = serving.url.len();
            inner.connect_web_process_terminated(move |_, reason| {
                let generation = crash_tracker.borrow_mut().failed_current_process();
                eprintln!(
                    "linux-host {} recovery signal phase=terminated bundled=true bytes={canonical_bytes} reason={reason:?}",
                    surface_name(surface)
                );
                let Some(generation) = generation else {
                    eprintln!(
                        "linux-host {} recovery signal ignored phase=terminated reason=unattributed",
                        surface_name(surface)
                    );
                    return;
                };
                crash_sender.send(WebKitRecoveryEvent::Failure {
                    surface,
                    generation: Some(generation),
                    reason: WebKitFailureReason::ProcessTerminated,
                });
            });

            let fail_sender = webkit_recovery_sender(wake_proxy);
            let fail_tracker = tracker;
            let canonical_fail_url = serving.url.clone();
            inner.connect_load_failed(move |_, _event, failing_uri, _error| {
                let document_generation =
                    parse_webkit_document_generation(failing_uri, &canonical_fail_url)
                        .map(|document| document.value());
                let generation = document_generation.and_then(|generation| {
                    fail_tracker.borrow_mut().failed_generation(generation)
                });
                let Some(generation) = generation else {
                    eprintln!(
                        "linux-host {} recovery signal ignored phase=load-failed bundled=false bytes={} reason=load-failed",
                        surface_name(surface),
                        failing_uri.len()
                    );
                    return true;
                };
                eprintln!(
                    "linux-host {} recovery signal phase=load-failed bundled=true bytes={} reason=load-failed",
                    surface_name(surface),
                    failing_uri.len()
                );
                fail_sender.send(WebKitRecoveryEvent::Failure {
                    surface,
                    generation: Some(generation),
                    reason: WebKitFailureReason::LoadFailed,
                });
                true
            });
            let redraw = inner;
            parent.connect_size_allocate(move |_, _| redraw.queue_draw());
            Some(Rc::new(webview))
        }
        Err(error) => {
            eprintln!(
                "linux-host {} WebView mount failed: {error}; terminal remains available",
                surface_name(surface)
            );
            None
        }
    }
}

fn surface_name(surface: WebKitSurface) -> &'static str {
    match surface {
        WebKitSurface::Sidebar => "dashboard sidebar",
        WebKitSurface::Topbar => "dashboard topbar",
        WebKitSurface::Overlay => "dashboard overlay",
    }
}

fn persistent_replay_event(accepted: bool, canonical_url: &str) -> Option<UserEvent> {
    accepted.then(|| UserEvent::ReactChromePageLoaded {
        url: canonical_url.to_string(),
    })
}

fn navigation_is_bundled_persistent(candidate: &str, canonical_url: &str) -> bool {
    parse_webkit_document_generation(candidate, canonical_url).is_some()
}

fn persistent_ipc_is_trusted(
    request_uri: &str,
    canonical_url: &str,
    owned_generation: Option<u64>,
) -> bool {
    owned_generation.is_some_and(|owned_generation| {
        parse_webkit_document_generation(request_uri, canonical_url)
            .is_some_and(|document| document.value() == owned_generation)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIDEBAR: &str = "hydra://localhost/index.html?chrome=sidebar";
    const TOPBAR: &str = "hydra://localhost/index.html?chrome=topbar";

    #[test]
    fn accepted_persistent_load_emits_replay_for_its_exact_surface_url() {
        assert!(matches!(
            persistent_replay_event(true, TOPBAR),
            Some(UserEvent::ReactChromePageLoaded { url }) if url == TOPBAR
        ));
        assert!(persistent_replay_event(false, TOPBAR).is_none());
    }

    #[test]
    fn persistent_navigation_is_exact_and_cross_surface_is_rejected() {
        assert!(navigation_is_bundled_persistent(TOPBAR, TOPBAR));
        for candidate in [
            SIDEBAR,
            "hydra://localhost/index.html?chrome=topbar#intent",
            "https://example.invalid/",
            "file:///tmp/index.html?chrome=topbar",
        ] {
            assert!(!navigation_is_bundled_persistent(candidate, TOPBAR));
        }
    }

    #[test]
    fn persistent_ipc_requires_exact_url_and_owned_generation() {
        assert!(persistent_ipc_is_trusted(TOPBAR, TOPBAR, Some(0)));
        assert!(!persistent_ipc_is_trusted(TOPBAR, TOPBAR, Some(1)));
        let recovery = "hydra://localhost/index.html?chrome=topbar&__hydra_recovery_generation=1";
        assert!(persistent_ipc_is_trusted(recovery, TOPBAR, Some(1)));
        assert!(!persistent_ipc_is_trusted(recovery, TOPBAR, Some(2)));
        assert!(!persistent_ipc_is_trusted(SIDEBAR, TOPBAR, Some(0)));
    }

    #[test]
    fn active_modal_gate_blocks_and_then_restores_persistent_intents() {
        let gate = PersistentInputGate::default();
        assert!(gate.accepts_intents());
        gate.suppress();
        assert!(!gate.accepts_intents());
        // Reassertion during modal delivery/recovery must remain idempotently closed.
        gate.suppress();
        assert!(!gate.accepts_intents());
        gate.restore();
        assert!(gate.accepts_intents());
    }

    #[test]
    fn persistent_modal_firewall_precedes_every_dashboard_initialization_script() {
        let base = "window.__HYDRA_BASE_PRELOAD_RAN__ = true;";
        let combined = persistent_initialization_script(base);
        let firewall = combined
            .find("__HYDRA_NATIVE_MODAL_UNDERLAY_FIREWALL__")
            .unwrap();
        let dashboard = combined.find(base).unwrap();
        assert!(firewall < dashboard);
        assert!(PERSISTENT_MODAL_FIREWALL_PRELOAD.contains("var firewall = { active: true }"));
        assert!(PERSISTENT_MODAL_FIREWALL_PRELOAD.contains("if (!firewall.active) return"));
        assert!(PERSISTENT_MODAL_FIREWALL_PRELOAD
            .contains("window.addEventListener(type, blocker, { capture: true, passive: false })"));
        assert!(RELEASE_PERSISTENT_MODAL_FIREWALL_SCRIPT.contains("firewall.active = false"));
        for event in [
            "blur",
            "click",
            "dragover",
            "focusout",
            "pointercancel",
            "pointermove",
        ] {
            assert!(PERSISTENT_MODAL_FIREWALL_PRELOAD.contains(&format!("\"{event}\"")));
        }
    }

    #[test]
    fn persistent_modal_firewall_releases_only_for_an_exact_unmodal_document() {
        let gate = PersistentInputGate::default();
        assert!(!persistent_firewall_release_allowed(false, &gate));
        assert!(persistent_firewall_release_allowed(true, &gate));
        gate.suppress();
        assert!(!persistent_firewall_release_allowed(true, &gate));
        gate.restore();
        assert!(persistent_firewall_release_allowed(true, &gate));
    }

    #[test]
    fn topbar_and_sidebar_recovery_budgets_are_independent() {
        let mut sidebar = RecoveryController::default();
        let mut topbar = RecoveryController::default();
        assert!(matches!(
            topbar.on_failure(Some(0)),
            RecoveryDecision::Dispatch {
                attempt: 1,
                generation: 1
            }
        ));
        assert_eq!(sidebar.generation(), 0);
        assert!(matches!(
            sidebar.on_failure(Some(0)),
            RecoveryDecision::Dispatch {
                attempt: 1,
                generation: 1
            }
        ));
        assert_eq!(topbar.generation(), 1);
    }
}
