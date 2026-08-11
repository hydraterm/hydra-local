//! Lazy full-window React overlay for the Linux GTK/WRY dashboard host.
//!
//! The sidebar is created with the window. The overlay WebView is created only on the first
//! `SetReactChromeOverlayVisible(true)` request, shares the sidebar's WRY context/process pool,
//! and remains presentation-only: it owns no terminal, PTY, daemon, protocol, or session state.

#![cfg(target_os = "linux")]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use gtk::prelude::*;
use serde::Deserialize;
use webkit2gtk::WebViewExt as _;
use wry::{NewWindowResponse, WebViewBuilder, WebViewBuilderExtUnix, WebViewExtUnix};

use super::persistent_surface::PersistentInputGate;
use super::present_target::TerminalPresentTarget;
use super::recovery::{
    RecoveryController, RecoveryDecision, RecoveryReadyDecision, RecoverySignalTracker,
    WebKitFailureReason, WebKitRecoveryEvent, WebKitSurface, MAX_WEBKIT_RECOVERY_ATTEMPTS,
};
use super::wake::{webkit_recovery_sender, LinuxLoopEvent};
use crate::{ReactChromeScriptKind, RendererEvent};

fn overlay_event_mask() -> gtk::gdk::EventMask {
    gtk::gdk::EventMask::BUTTON_PRESS_MASK
        | gtk::gdk::EventMask::KEY_PRESS_MASK
        | gtk::gdk::EventMask::KEY_RELEASE_MASK
        | gtk::gdk::EventMask::FOCUS_CHANGE_MASK
        // The lazy WebKit overlay is embedded below this windowed EventBox. GTK only selects
        // wheel/touchpad events for child GDK windows when the owning hierarchy requests both
        // discrete and smooth scrolling, so omitting these masks made transcript previews
        // unscrollable on Linux even though the same DOM/CSS worked in WKWebView on macOS.
        | gtk::gdk::EventMask::SCROLL_MASK
        | gtk::gdk::EventMask::SMOOTH_SCROLL_MASK
}

const MAX_PENDING_SCRIPTS: usize = 32;
const MAX_PENDING_SCRIPT_BYTES: usize = 512 * 1024;
const MAX_OVERLAY_IPC_BYTES: usize = 64 * 1024;
const MAX_OVERLAY_INPUT_TRACE_BYTES: usize = 1024;
const MAX_PENDING_PRODUCT_INTENTS: usize = 8;
const MAX_PENDING_PRODUCT_INTENT_BYTES: usize = 128 * 1024;
const OVERLAY_INPUT_TRACE_TYPE: &str = "__hydraLinuxOverlayInputTrace";
const OVERLAY_VIEWPORT_READY_TYPE: &str = "__hydraLinuxOverlayViewportReady";
const DELIVERY_SUCCESS_SENTINEL: &str = "__HYDRA_OVERLAY_DELIVERY_OK__";
const PERSISTENT_SUPPRESSION_SUCCESS_SENTINEL: &str = "__HYDRA_PERSISTENT_SUPPRESSION_OK__";
const CANCEL_OVERLAY_VIEWPORT_OBSERVER_SCRIPT: &str = r#"
(function () {
  "use strict";
  var active = window.__HYDRA_LINUX_OVERLAY_VIEWPORT_BARRIER__;
  if (active && typeof active.cancel === "function") active.cancel();
  delete window.__HYDRA_LINUX_OVERLAY_VIEWPORT_BARRIER__;
})();
"#;
// Lazy WebKit creation/load is allowed a wider bounded window because it does not own or suppress
// native input. Expiry retires the product request so a late ready marker can only warm the parked
// document; the short presentation deadline below starts only after that exact marker.
const OVERLAY_COLD_LOAD_TIMEOUT: Duration = Duration::from_secs(10);
const MODAL_PRESENTATION_TIMEOUT: Duration = Duration::from_secs(3);
const OVERLAY_RECOVERY_GENERATION_PARAM: &str = "__hydra_recovery_generation";
const CANONICAL_OVERLAY_READY_JSON: &str = r#"{"type":"dashboardOverlayReady"}"#;
const SUPPRESS_PERSISTENT_DOCUMENTS_SCRIPT: &str = r#"
(function () {
  "use strict";
  var root = document.documentElement;
  var firewall = window.__HYDRA_NATIVE_MODAL_UNDERLAY_FIREWALL__;
  if (!root || !("inert" in root) || !firewall) return;
  var active = document.activeElement;
  if (!window.__HYDRA_NATIVE_MODAL_UNDERLAY_STATE__) {
    window.__HYDRA_NATIVE_MODAL_UNDERLAY_STATE__ = {
      inert: Boolean(root.inert),
      ariaHidden: root.getAttribute("aria-hidden"),
      activeElement: active && active !== document.body ? active : null
    };
  }
  firewall.active = true;
  if (active && typeof active.blur === "function") active.blur();
  root.inert = true;
  root.setAttribute("aria-hidden", "true");
  if (!firewall.active || root.inert !== true || root.getAttribute("aria-hidden") !== "true") return;
  return "__HYDRA_PERSISTENT_SUPPRESSION_OK__";
})();
"#;
const RESTORE_PERSISTENT_DOCUMENTS_SCRIPT: &str = r#"
(function (restoreFocus) {
  "use strict";
  var root = document.documentElement;
  var saved = window.__HYDRA_NATIVE_MODAL_UNDERLAY_STATE__;
  var firewall = window.__HYDRA_NATIVE_MODAL_UNDERLAY_FIREWALL__;
  if (!root || !saved || !firewall) return;
  var prior = saved.activeElement;
  try {
    root.inert = Boolean(saved.inert);
    if (saved.ariaHidden === null) root.removeAttribute("aria-hidden");
    else root.setAttribute("aria-hidden", saved.ariaHidden);
  } finally {
    firewall.active = false;
    delete window.__HYDRA_NATIVE_MODAL_UNDERLAY_STATE__;
  }
  if (restoreFocus && !root.inert && prior && prior.isConnected && typeof prior.focus === "function") {
    try {
      prior.focus({ preventScroll: true });
    } catch (_) {
      try { prior.focus(); } catch (_) {}
    }
  }
})(__HYDRA_RESTORE_DOM_FOCUS__);
"#;
const OVERLAY_RECOVERY_GENERATION_PRELOAD: &str = r#"
(function () {
  "use strict";
  if (window.__HYDRA_OVERLAY_RECOVERY_GENERATION_BRIDGE__) return;
  var dashboard = window.hydraDashboard;
  if (!dashboard || typeof dashboard.postIntent !== "function") return;
  var originalPostIntent = dashboard.postIntent;
  dashboard.postIntent = function (intent) {
    if (intent && intent.type === "dashboardOverlayReady") {
      try {
        var raw = new URLSearchParams(window.location.search).get("__hydra_recovery_generation");
        if (raw !== null && /^[1-9][0-9]*$/.test(raw)) {
          var generation = Number(raw);
          if (Number.isSafeInteger(generation)) {
            intent = Object.assign({}, intent, { recovery_generation: generation });
          }
        }
      } catch (_) {}
    }
    return originalPostIntent.call(this, intent);
  };
  window.__HYDRA_OVERLAY_RECOVERY_GENERATION_BRIDGE__ = true;
})();
"#;
const OVERLAY_INPUT_TRACE_PRELOAD: &str = r#"
(function () {
  "use strict";
  if (window.__HYDRA_LINUX_OVERLAY_INPUT_TRACE_INSTALLED__) return;
  var dashboard = window.hydraDashboard;
  if (!dashboard || typeof dashboard.postIntent !== "function") return;

  function boundedToken(value, maxLength) {
    return String(value || "").replace(/[^A-Za-z0-9_-]/g, "").slice(0, maxLength);
  }
  function boundedInteger(value, minimum, maximum) {
    if (typeof value !== "number" || !Number.isFinite(value)) return null;
    return Math.max(minimum, Math.min(maximum, Math.round(value)));
  }
  function viewportDimension(value) {
    var bounded = boundedInteger(value, 0, 100000);
    return bounded === null ? 0 : bounded;
  }
  function emit(event) {
    try {
      var target = event.target && event.target.nodeType === 1 ? event.target : null;
      var rect = target && typeof target.getBoundingClientRect === "function"
        ? target.getBoundingClientRect()
        : null;
      var visual = window.visualViewport;
      var root = document.documentElement;
      var targetValue = target && typeof target.value === "string" ? target.value : "";
      var now = window.performance && typeof window.performance.now === "function"
        ? window.performance.now()
        : 0;
      dashboard.postIntent({
        type: "__hydraLinuxOverlayInputTrace",
        event_kind: String(event.type || ""),
        printable: event.type === "keydown" && typeof event.key === "string" && event.key.length === 1,
        value_len: Math.min(1000000, targetValue.length),
        target_tag: boundedToken(target && target.tagName, 16),
        target_type: boundedToken(target && target.type, 24),
        target_name: boundedToken(target && target.name, 48),
        client_x: boundedInteger(event.clientX, -1000000, 1000000),
        client_y: boundedInteger(event.clientY, -1000000, 1000000),
        rect_x: boundedInteger(rect && rect.x, -1000000, 1000000),
        rect_y: boundedInteger(rect && rect.y, -1000000, 1000000),
        rect_width: viewportDimension(rect && rect.width),
        rect_height: viewportDimension(rect && rect.height),
        visual_width: viewportDimension(visual && visual.width),
        visual_height: viewportDimension(visual && visual.height),
        document_width: viewportDimension(root && root.clientWidth),
        document_height: viewportDimension(root && root.clientHeight),
        monotonic_ms: Math.min(1000000000000, Math.max(0, Math.round(now)))
      });
    } catch (_) {}
  }

  ["pointerdown", "pointerup", "click", "focusin", "focusout", "keydown", "input"]
    .forEach(function (kind) { document.addEventListener(kind, emit, true); });
  window.__HYDRA_LINUX_OVERLAY_INPUT_TRACE_INSTALLED__ = true;
})();
"#;

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OverlayHostIntent {
    #[serde(rename = "type")]
    kind: OverlayHostIntentKind,
    #[serde(default)]
    recovery_generation: Option<u64>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
enum OverlayHostIntentKind {
    #[serde(rename = "dashboardOverlayReady")]
    Ready,
}

fn dashboard_overlay_ready_generation(json: &str) -> Option<Option<u64>> {
    let intent = serde_json::from_str::<OverlayHostIntent>(json).ok()?;
    match intent.kind {
        OverlayHostIntentKind::Ready => Some(intent.recovery_generation),
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OverlayViewportReadyIntent {
    #[serde(rename = "type")]
    kind: OverlayViewportReadyIntentKind,
    presentation_token: u64,
    width: i32,
    height: i32,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
enum OverlayViewportReadyIntentKind {
    #[serde(rename = "__hydraLinuxOverlayViewportReady")]
    Ready,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OverlayViewportReady {
    token: u64,
    width: i32,
    height: i32,
}

fn overlay_viewport_ready(json: &str) -> Option<OverlayViewportReady> {
    let intent = serde_json::from_str::<OverlayViewportReadyIntent>(json).ok()?;
    if intent.width <= 1 || intent.height <= 1 {
        return None;
    }
    Some(OverlayViewportReady {
        token: intent.presentation_token,
        width: intent.width,
        height: intent.height,
    })
}

fn is_overlay_viewport_ready_payload(json: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(json)
        .ok()
        .and_then(|value| {
            value
                .get("type")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .as_deref()
        == Some(OVERLAY_VIEWPORT_READY_TYPE)
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
enum OverlayInputTraceEvent {
    #[serde(rename = "pointerdown")]
    PointerDown,
    #[serde(rename = "pointerup")]
    PointerUp,
    #[serde(rename = "click")]
    Click,
    #[serde(rename = "focusin")]
    FocusIn,
    #[serde(rename = "focusout")]
    FocusOut,
    #[serde(rename = "keydown")]
    KeyDown,
    #[serde(rename = "input")]
    Input,
}

impl OverlayInputTraceEvent {
    fn as_str(self) -> &'static str {
        match self {
            Self::PointerDown => "pointerdown",
            Self::PointerUp => "pointerup",
            Self::Click => "click",
            Self::FocusIn => "focusin",
            Self::FocusOut => "focusout",
            Self::KeyDown => "keydown",
            Self::Input => "input",
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OverlayInputTrace {
    #[serde(rename = "type")]
    kind: OverlayInputTraceKind,
    event_kind: OverlayInputTraceEvent,
    printable: bool,
    value_len: u32,
    target_tag: String,
    target_type: String,
    target_name: String,
    client_x: Option<i32>,
    client_y: Option<i32>,
    rect_x: Option<i32>,
    rect_y: Option<i32>,
    rect_width: u32,
    rect_height: u32,
    visual_width: u32,
    visual_height: u32,
    document_width: u32,
    document_height: u32,
    monotonic_ms: u64,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
enum OverlayInputTraceKind {
    #[serde(rename = "__hydraLinuxOverlayInputTrace")]
    Trace,
}

#[derive(Debug, Deserialize)]
struct OverlayInputTraceDiscriminant {
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Debug, PartialEq, Eq)]
enum OverlayInputTraceRoute {
    NotTrace,
    Disabled,
    Rejected,
    Accepted(OverlayInputTrace),
}

fn overlay_trace_token_is_bounded(value: &str, max_len: usize) -> bool {
    value.len() <= max_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn overlay_trace_coordinate_is_bounded(value: Option<i32>) -> bool {
    value.is_none_or(|value| (-1_000_000..=1_000_000).contains(&value))
}

fn overlay_input_trace_is_bounded(trace: &OverlayInputTrace) -> bool {
    trace.value_len <= 1_000_000
        && overlay_trace_token_is_bounded(&trace.target_tag, 16)
        && overlay_trace_token_is_bounded(&trace.target_type, 24)
        && overlay_trace_token_is_bounded(&trace.target_name, 48)
        && overlay_trace_coordinate_is_bounded(trace.client_x)
        && overlay_trace_coordinate_is_bounded(trace.client_y)
        && overlay_trace_coordinate_is_bounded(trace.rect_x)
        && overlay_trace_coordinate_is_bounded(trace.rect_y)
        && trace.rect_width <= 100_000
        && trace.rect_height <= 100_000
        && trace.visual_width <= 100_000
        && trace.visual_height <= 100_000
        && trace.document_width <= 100_000
        && trace.document_height <= 100_000
        && trace.monotonic_ms <= 1_000_000_000_000
}

fn route_overlay_input_trace(json: &str, enabled: bool) -> OverlayInputTraceRoute {
    let is_trace = serde_json::from_str::<OverlayInputTraceDiscriminant>(json)
        .is_ok_and(|intent| intent.kind == OVERLAY_INPUT_TRACE_TYPE);
    if !is_trace {
        return OverlayInputTraceRoute::NotTrace;
    }
    if !enabled {
        return OverlayInputTraceRoute::Disabled;
    }
    if json.len() > MAX_OVERLAY_INPUT_TRACE_BYTES {
        return OverlayInputTraceRoute::Rejected;
    }
    match serde_json::from_str::<OverlayInputTrace>(json) {
        Ok(trace) if overlay_input_trace_is_bounded(&trace) => {
            OverlayInputTraceRoute::Accepted(trace)
        }
        Ok(_) | Err(_) => OverlayInputTraceRoute::Rejected,
    }
}

fn log_overlay_input_trace(trace: &OverlayInputTrace) {
    eprintln!(
        "linux-host overlay input host_monotonic_us={} event={} printable={} value_len={} target_tag={:?} target_type={:?} target_name={:?} client_x={:?} client_y={:?} rect_x={:?} rect_y={:?} rect_width={} rect_height={} visual_width={} visual_height={} document_width={} document_height={} document_monotonic_ms={}",
        overlay_trace_monotonic_us(),
        trace.event_kind.as_str(),
        trace.printable,
        trace.value_len,
        trace.target_tag,
        trace.target_type,
        trace.target_name,
        trace.client_x,
        trace.client_y,
        trace.rect_x,
        trace.rect_y,
        trace.rect_width,
        trace.rect_height,
        trace.visual_width,
        trace.visual_height,
        trace.document_width,
        trace.document_height,
        trace.monotonic_ms,
    );
}

fn overlay_trace_monotonic_us() -> u128 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_micros()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OverlayDocumentGeneration {
    Initial,
    Recovery(u64),
}

impl OverlayDocumentGeneration {
    fn value(self) -> u64 {
        match self {
            Self::Initial => 0,
            Self::Recovery(generation) => generation,
        }
    }
}

/// Parse only the canonical initial overlay URL or the host-owned recovery form. This intentionally
/// does not normalize URLs: fragments, reordered/extra query parameters, alternate encodings, and
/// lookalike origins are rejected rather than treated as equivalent trusted documents.
fn parse_overlay_document_generation(
    candidate: &str,
    bundled_url: &str,
) -> Option<OverlayDocumentGeneration> {
    if bundled_url.contains('#') || bundled_url.contains(OVERLAY_RECOVERY_GENERATION_PARAM) {
        return None;
    }
    if candidate == bundled_url {
        return Some(OverlayDocumentGeneration::Initial);
    }

    let separator = if bundled_url.contains('?') { '&' } else { '?' };
    let prefix = format!("{bundled_url}{separator}{OVERLAY_RECOVERY_GENERATION_PARAM}=");
    let raw_generation = candidate.strip_prefix(&prefix)?;
    if raw_generation.is_empty()
        || !raw_generation.bytes().all(|byte| byte.is_ascii_digit())
        || raw_generation.starts_with('0')
    {
        return None;
    }
    let generation = raw_generation.parse::<u64>().ok()?;
    Some(OverlayDocumentGeneration::Recovery(generation))
}

fn overlay_recovery_url(bundled_url: &str, generation: u64) -> Option<String> {
    if generation == 0
        || bundled_url.contains('#')
        || bundled_url.contains(OVERLAY_RECOVERY_GENERATION_PARAM)
    {
        return None;
    }
    let separator = if bundled_url.contains('?') { '&' } else { '?' };
    Some(format!(
        "{bundled_url}{separator}{OVERLAY_RECOVERY_GENERATION_PARAM}={generation}"
    ))
}

fn overlay_document_is_current(
    document: OverlayDocumentGeneration,
    current_generation: u64,
) -> bool {
    match document {
        OverlayDocumentGeneration::Initial => current_generation == 0,
        OverlayDocumentGeneration::Recovery(generation) => {
            generation == current_generation && generation > 0
        }
    }
}

fn navigation_is_bundled_overlay(
    candidate: &str,
    bundled_url: &str,
    current_generation: u64,
) -> bool {
    parse_overlay_document_generation(candidate, bundled_url)
        .is_some_and(|document| overlay_document_is_current(document, current_generation))
}

fn overlay_ipc_is_trusted(
    request_uri: &str,
    bundled_url: &str,
    current_generation: u64,
    owned_generation: Option<u64>,
) -> bool {
    owned_generation.is_some_and(|owned_generation| {
        parse_overlay_document_generation(request_uri, bundled_url).is_some_and(|document| {
            document.value() == owned_generation
                && overlay_document_is_current(document, current_generation)
        })
    })
}

fn accepted_overlay_ready_generation(
    document: OverlayDocumentGeneration,
    claimed_generation: Option<u64>,
) -> Option<u64> {
    match (document, claimed_generation) {
        (OverlayDocumentGeneration::Initial, None) => Some(0),
        (OverlayDocumentGeneration::Recovery(document_generation), Some(claimed_generation))
            if document_generation == claimed_generation && claimed_generation > 0 =>
        {
            Some(claimed_generation)
        }
        _ => None,
    }
}

fn authenticated_overlay_ready(
    document: OverlayDocumentGeneration,
    claimed_generation: Option<u64>,
) -> Option<(u64, &'static str)> {
    accepted_overlay_ready_generation(document, claimed_generation)
        .map(|generation| (generation, CANONICAL_OVERLAY_READY_JSON))
}

fn overlay_initialization_script(base: &str, input_trace_enabled: bool) -> String {
    if input_trace_enabled {
        format!("{base}\n{OVERLAY_RECOVERY_GENERATION_PRELOAD}\n{OVERLAY_INPUT_TRACE_PRELOAD}")
    } else {
        format!("{base}\n{OVERLAY_RECOVERY_GENERATION_PRELOAD}")
    }
}

#[derive(Default)]
struct OverlayScripts {
    latest_model: Option<String>,
    active_modal: Option<String>,
    pending: VecDeque<String>,
    pending_bytes: usize,
}

#[derive(Debug, Eq, PartialEq)]
enum ScriptAcceptance {
    /// Rejected without changing any cached script or modal-delivery state.
    Rejected,
    /// Accepted into the recovery cache/queue, but the document cannot evaluate it yet.
    Retained,
    /// Accepted and ready for immediate evaluation in the current document.
    Evaluate(String),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum ModalDelivery {
    #[default]
    Absent,
    AwaitingReady,
    Evaluating(u64),
    Delivered,
}

#[derive(Debug, Eq, PartialEq)]
struct OverlayEvaluation {
    scripts: Vec<String>,
    modal_attempt: Option<u64>,
}

impl OverlayEvaluation {
    fn single(script: String, modal_attempt: Option<u64>) -> Self {
        Self {
            scripts: vec![script],
            modal_attempt,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OverlayEvaluationResult {
    attempt: u64,
    succeeded: bool,
}

/// Content-blind completion of one persistent-document `inert` task. The WebKit callback never
/// changes GTK state; it sends this identity back to the owner loop, which rejects stale epochs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PersistentSuppressionResult {
    epoch: u64,
    index: usize,
    succeeded: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModalEvaluationDecision {
    Delivered,
    Failed,
    Stale,
}

impl OverlayScripts {
    fn remember(
        &mut self,
        script: &str,
        kind: ReactChromeScriptKind,
        can_evaluate_now: bool,
        accept_transient: bool,
    ) -> ScriptAcceptance {
        if script.len() > MAX_PENDING_SCRIPT_BYTES {
            eprintln!(
                "linux-host overlay script dropped: bytes={} exceeds cap={MAX_PENDING_SCRIPT_BYTES}",
                script.len()
            );
            return ScriptAcceptance::Rejected;
        }

        match kind {
            ReactChromeScriptKind::Model => {
                self.latest_model = Some(script.to_owned());
            }
            ReactChromeScriptKind::Modal => {
                // Keep only the newest modal command. Timers/retries are deliberately forbidden:
                // React sends an exact ready marker after installing the handler, so the original
                // typed script executes once.
                self.active_modal = Some(script.to_owned());
            }
            ReactChromeScriptKind::Transient if !accept_transient => {
                return ScriptAcceptance::Rejected;
            }
            ReactChromeScriptKind::Transient => {
                if !can_evaluate_now {
                    self.push_bounded(script.to_owned());
                    return ScriptAcceptance::Retained;
                }
            }
        }

        if can_evaluate_now {
            ScriptAcceptance::Evaluate(script.to_owned())
        } else {
            ScriptAcceptance::Retained
        }
    }

    fn push_bounded(&mut self, script: String) {
        while self.pending.len() >= MAX_PENDING_SCRIPTS
            || self.pending_bytes.saturating_add(script.len()) > MAX_PENDING_SCRIPT_BYTES
        {
            let Some(oldest) = self.pending.pop_front() else {
                break;
            };
            self.pending_bytes = self.pending_bytes.saturating_sub(oldest.len());
        }
        self.pending_bytes = self.pending_bytes.saturating_add(script.len());
        self.pending.push_back(script);
    }

    fn take_ready_replay(&mut self) -> Vec<String> {
        let mut scripts = Vec::with_capacity(2 + self.pending.len());
        if let Some(model) = self.latest_model.clone() {
            scripts.push(model);
        }
        if let Some(modal) = self.active_modal.clone() {
            scripts.push(modal);
        }
        scripts.extend(self.pending.drain(..));
        self.pending_bytes = 0;
        scripts
    }

    fn hide(&mut self) {
        self.active_modal = None;
        self.pending.clear();
        self.pending_bytes = 0;
    }
}

/// Pure delivery state. A document load and React readiness are different phases: only the exact
/// React marker may release cached scripts. `replayed_for_load` makes duplicate markers idempotent.
#[derive(Default)]
struct OverlayDelivery {
    webview_attached: bool,
    react_ready: bool,
    replayed_for_load: bool,
    scripts: OverlayScripts,
    modal_delivery: ModalDelivery,
    next_modal_attempt: u64,
}

impl OverlayDelivery {
    fn page_started(&mut self) {
        self.react_ready = false;
        self.replayed_for_load = false;
        self.modal_delivery = if self.scripts.active_modal.is_some() {
            ModalDelivery::AwaitingReady
        } else {
            ModalDelivery::Absent
        };
    }

    fn page_finished(&mut self) -> Vec<String> {
        // Diagnostic only. React's OverlayChrome effect may not have installed its modal handler yet.
        Vec::new()
    }

    fn attach_webview(&mut self) -> Option<OverlayEvaluation> {
        self.webview_attached = true;
        self.take_replay_if_ready()
    }

    fn react_ready(&mut self) -> Option<OverlayEvaluation> {
        if self.react_ready {
            return None;
        }
        self.react_ready = true;
        self.take_replay_if_ready()
    }

    fn remember(
        &mut self,
        script: &str,
        kind: ReactChromeScriptKind,
        accept_transient: bool,
    ) -> Option<OverlayEvaluation> {
        let acceptance = self.scripts.remember(
            script,
            kind,
            self.webview_attached && self.react_ready,
            accept_transient,
        );
        match acceptance {
            ScriptAcceptance::Rejected => None,
            ScriptAcceptance::Retained => {
                if kind == ReactChromeScriptKind::Modal {
                    self.modal_delivery = ModalDelivery::AwaitingReady;
                }
                None
            }
            ScriptAcceptance::Evaluate(script) => {
                let modal_attempt = if kind == ReactChromeScriptKind::Modal {
                    self.modal_delivery = ModalDelivery::AwaitingReady;
                    Some(self.begin_modal_evaluation())
                } else {
                    None
                };
                Some(OverlayEvaluation::single(script, modal_attempt))
            }
        }
    }

    fn hide(&mut self) {
        self.scripts.hide();
        self.modal_delivery = ModalDelivery::Absent;
    }

    fn has_active_modal(&self) -> bool {
        self.scripts.active_modal.is_some()
    }

    fn can_present(&self) -> bool {
        self.webview_attached
            && self.react_ready
            && self.has_active_modal()
            && self.modal_delivery == ModalDelivery::Delivered
    }

    fn finish_modal_evaluation(
        &mut self,
        result: OverlayEvaluationResult,
    ) -> ModalEvaluationDecision {
        if self.modal_delivery != ModalDelivery::Evaluating(result.attempt) {
            return ModalEvaluationDecision::Stale;
        }
        if result.succeeded && self.has_active_modal() {
            self.modal_delivery = ModalDelivery::Delivered;
            ModalEvaluationDecision::Delivered
        } else {
            self.scripts.hide();
            self.modal_delivery = ModalDelivery::Absent;
            ModalEvaluationDecision::Failed
        }
    }

    fn begin_modal_evaluation(&mut self) -> u64 {
        self.next_modal_attempt = self.next_modal_attempt.wrapping_add(1);
        if self.next_modal_attempt == 0 {
            self.next_modal_attempt = 1;
        }
        self.modal_delivery = ModalDelivery::Evaluating(self.next_modal_attempt);
        self.next_modal_attempt
    }

    fn take_replay_if_ready(&mut self) -> Option<OverlayEvaluation> {
        if !self.webview_attached || !self.react_ready || self.replayed_for_load {
            return None;
        }
        self.replayed_for_load = true;
        let modal_attempt = self
            .has_active_modal()
            .then(|| self.begin_modal_evaluation());
        Some(OverlayEvaluation {
            scripts: self.scripts.take_ready_replay(),
            modal_attempt,
        })
    }
}

/// The overlay document belongs in the application accessibility/input tree only while its
/// corresponding product surface is both requested and ready. `GtkStackAccessible` reports only
/// the selected child, so the document can stay permanently parented (and keep one WebKit backing
/// store) while an inert page removes its embedding socket from the exposed tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OverlayPage {
    Parking,
    Document,
}

fn overlay_page(visible: bool, delivery: &OverlayDelivery) -> OverlayPage {
    if visible && delivery.can_present() {
        OverlayPage::Document
    } else {
        OverlayPage::Parking
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WidgetInteractivity {
    sensitive: bool,
    can_focus: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UnderlayInteractivitySnapshot {
    containers: Vec<WidgetInteractivity>,
    webviews: Vec<WidgetInteractivity>,
    terminal: WidgetInteractivity,
    restore_focus_webview: Option<usize>,
}

/// Snapshot the WebView-owned flags exactly once for one active modal lifetime. Repeated show and
/// recovery transitions may reassert suppression, but must never replace the values hide/failure
/// will restore.
#[derive(Default)]
struct UnderlayInteractivityState {
    saved: Option<UnderlayInteractivitySnapshot>,
}

impl UnderlayInteractivityState {
    fn capture_once(&mut self, current: UnderlayInteractivitySnapshot) {
        if self.saved.is_none() {
            self.saved = Some(current);
        }
    }

    fn take_for_restore(&mut self) -> Option<UnderlayInteractivitySnapshot> {
        self.saved.take()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PersistentSuppressionDecision {
    Pending,
    Ready,
    Failed,
    Stale,
}

#[derive(Debug)]
struct PersistentSuppressionAttempt {
    epoch: u64,
    completed: Vec<bool>,
}

#[derive(Default, Debug)]
struct PersistentSuppressionState {
    next_epoch: u64,
    active: Option<PersistentSuppressionAttempt>,
    ready: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PersistentDocumentReadiness {
    generation: Option<u64>,
    finished: bool,
}

fn persistent_document_index(surface: WebKitSurface, target_count: usize) -> Option<usize> {
    match surface {
        WebKitSurface::Sidebar if target_count >= 1 => Some(0),
        WebKitSurface::Topbar if target_count >= 2 => Some(1),
        _ => None,
    }
}

impl PersistentSuppressionState {
    fn begin(&mut self, target_count: usize) -> u64 {
        self.next_epoch = self.next_epoch.wrapping_add(1);
        if self.next_epoch == 0 {
            self.next_epoch = 1;
        }
        let epoch = self.next_epoch;
        self.ready = target_count == 0;
        self.active = (target_count > 0).then(|| PersistentSuppressionAttempt {
            epoch,
            completed: vec![false; target_count],
        });
        epoch
    }

    fn finish(&mut self, result: PersistentSuppressionResult) -> PersistentSuppressionDecision {
        let Some(active) = self.active.as_mut() else {
            return PersistentSuppressionDecision::Stale;
        };
        if active.epoch != result.epoch
            || result.index >= active.completed.len()
            || active.completed[result.index]
        {
            return PersistentSuppressionDecision::Stale;
        }
        if !result.succeeded {
            self.active = None;
            self.ready = false;
            return PersistentSuppressionDecision::Failed;
        }
        active.completed[result.index] = true;
        if active.completed.iter().all(|completed| *completed) {
            self.active = None;
            self.ready = true;
            PersistentSuppressionDecision::Ready
        } else {
            PersistentSuppressionDecision::Pending
        }
    }

    fn is_ready(&self) -> bool {
        self.ready
    }

    fn is_pending_or_ready(&self) -> bool {
        self.ready || self.active.is_some()
    }

    fn clear(&mut self) {
        self.active = None;
        self.ready = false;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FallbackAccessibility {
    Inactive,
    Loading,
    Recovering,
}

fn fallback_accessible_copy(state: FallbackAccessibility) -> (&'static str, &'static str) {
    match state {
        FallbackAccessibility::Inactive => ("", ""),
        FallbackAccessibility::Loading => (
            "Hydra dialog loading",
            "The Hydra dialog is loading. Keyboard focus remains in the dialog.",
        ),
        FallbackAccessibility::Recovering => (
            "Hydra dialog recovering",
            "The Hydra dialog is recovering. Keyboard focus remains in the dialog.",
        ),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ProductIntentRoute {
    Forward(String),
    Queued,
    RejectedNotPresented,
    RejectedCapacity,
}

#[derive(Debug, Deserialize)]
struct ProductIntentDiscriminant {
    #[serde(rename = "type")]
    kind: String,
}

fn is_deferable_product_intent(json: &str) -> bool {
    serde_json::from_str::<ProductIntentDiscriminant>(json)
        .is_ok_and(|intent| intent.kind == "listFolderSessions")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingProductIntentScope {
    presentation_token: u64,
    recovery_generation: u64,
}

#[derive(Default)]
struct PendingProductIntents {
    intents: VecDeque<String>,
    bytes: usize,
    scope: Option<PendingProductIntentScope>,
}

impl PendingProductIntents {
    fn push(&mut self, scope: PendingProductIntentScope, json: String) -> Result<(), ()> {
        let next_bytes = self.bytes.saturating_add(json.len());
        if self.intents.len() >= MAX_PENDING_PRODUCT_INTENTS
            || next_bytes > MAX_PENDING_PRODUCT_INTENT_BYTES
            || self.scope.is_some_and(|current| current != scope)
        {
            return Err(());
        }
        self.scope = Some(scope);
        self.bytes = next_bytes;
        self.intents.push_back(json);
        Ok(())
    }

    fn take_all(&mut self, scope: PendingProductIntentScope) -> Vec<String> {
        if self.scope != Some(scope) {
            self.clear();
            return Vec::new();
        }
        self.bytes = 0;
        self.scope = None;
        self.intents.drain(..).collect()
    }

    fn clear(&mut self) {
        self.bytes = 0;
        self.scope = None;
        self.intents.clear();
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum OverlayDeadlinePhase {
    #[default]
    Idle,
    ColdLoad,
    Presentation,
}

struct OverlayRuntime {
    webview: Option<Rc<wry::WebView>>,
    delivery: OverlayDelivery,
    visible: bool,
    recovery: RecoveryController,
    persistent_suppression: PersistentSuppressionState,
    persistent_documents: Vec<PersistentDocumentReadiness>,
    presentation_token: u64,
    deadline_phase: OverlayDeadlinePhase,
    presentation_complete: bool,
    pending_product_intents: PendingProductIntents,
}

impl OverlayRuntime {
    fn new(persistent_target_count: usize) -> Self {
        Self {
            webview: None,
            delivery: OverlayDelivery::default(),
            visible: false,
            recovery: RecoveryController::default(),
            persistent_suppression: PersistentSuppressionState::default(),
            persistent_documents: vec![
                PersistentDocumentReadiness::default();
                persistent_target_count
            ],
            presentation_token: 0,
            deadline_phase: OverlayDeadlinePhase::Idle,
            presentation_complete: false,
            pending_product_intents: PendingProductIntents::default(),
        }
    }

    fn all_persistent_documents_finished(&self) -> bool {
        !self.persistent_documents.is_empty()
            && self
                .persistent_documents
                .iter()
                .all(|document| document.finished)
    }

    fn begin_deadline(&mut self, phase: OverlayDeadlinePhase) -> u64 {
        self.presentation_token = self.presentation_token.wrapping_add(1);
        if self.presentation_token == 0 {
            self.presentation_token = 1;
        }
        self.deadline_phase = phase;
        self.presentation_complete = false;
        self.presentation_token
    }

    fn ensure_cold_load_deadline(&mut self) -> Option<u64> {
        if self.deadline_phase == OverlayDeadlinePhase::Idle {
            Some(self.begin_deadline(OverlayDeadlinePhase::ColdLoad))
        } else {
            None
        }
    }

    fn begin_presentation_deadline(&mut self) -> u64 {
        self.begin_deadline(OverlayDeadlinePhase::Presentation)
    }

    fn end_deadline(&mut self) {
        self.deadline_phase = OverlayDeadlinePhase::Idle;
        self.presentation_token = self.presentation_token.wrapping_add(1);
        if self.presentation_token == 0 {
            self.presentation_token = 1;
        }
    }

    fn ensure_presentation_deadline(&mut self) -> Option<u64> {
        if self.deadline_phase == OverlayDeadlinePhase::Presentation {
            None
        } else {
            Some(self.begin_presentation_deadline())
        }
    }

    fn deadline_phase_for_token(&self, token: u64) -> Option<OverlayDeadlinePhase> {
        (self.presentation_token == token && self.deadline_phase != OverlayDeadlinePhase::Idle)
            .then_some(self.deadline_phase)
    }

    fn cold_load_pending(&self) -> bool {
        self.deadline_phase == OverlayDeadlinePhase::ColdLoad
    }

    fn presentation_pending(&self) -> bool {
        self.deadline_phase == OverlayDeadlinePhase::Presentation
    }

    fn promote_cold_load_to_presentation(&mut self) -> Option<u64> {
        if !self.cold_load_pending()
            || !self.delivery.webview_attached
            || !self.delivery.react_ready
            || !self.delivery.has_active_modal()
        {
            return None;
        }
        self.visible = true;
        Some(self.begin_presentation_deadline())
    }

    fn accepts_product_intents(&self) -> bool {
        self.visible
            && self.presentation_complete
            && self.delivery.can_present()
            && self.persistent_suppression.is_ready()
    }

    fn mark_presented(&mut self, token: u64) -> bool {
        if self.presentation_token != token
            || self.deadline_phase != OverlayDeadlinePhase::Presentation
            || !self.visible
            || !self.delivery.can_present()
            || !self.persistent_suppression.is_ready()
        {
            return false;
        }
        self.presentation_complete = true;
        true
    }

    fn route_product_intent(&mut self, json: String) -> ProductIntentRoute {
        if self.accepts_product_intents() {
            return ProductIntentRoute::Forward(json);
        }
        // React renders the cached modal before the GTK owner can complete its independent
        // persistent-document suppression barrier. Read requests triggered by that render (most
        // notably `listFolderSessions`) must not be lost, but a parked/stale document must retain no
        // product authority. Queue only while the current authenticated document has an active modal
        // and is waiting for that final presentation join; the caller has already authenticated the
        // exact document generation.
        let awaiting_current_presentation = is_deferable_product_intent(&json)
            && self.visible
            && self.delivery.webview_attached
            && self.delivery.react_ready
            && self.delivery.has_active_modal()
            && matches!(
                self.delivery.modal_delivery,
                ModalDelivery::Evaluating(_) | ModalDelivery::Delivered
            )
            && self.presentation_pending()
            && !self.recovery.is_exhausted();
        if !awaiting_current_presentation {
            return ProductIntentRoute::RejectedNotPresented;
        }
        let scope = PendingProductIntentScope {
            presentation_token: self.presentation_token,
            recovery_generation: self.recovery.generation(),
        };
        if self.pending_product_intents.push(scope, json).is_err() {
            ProductIntentRoute::RejectedCapacity
        } else {
            ProductIntentRoute::Queued
        }
    }

    fn take_presented_product_intents(&mut self) -> Vec<String> {
        if self.accepts_product_intents() {
            let scope = PendingProductIntentScope {
                presentation_token: self.presentation_token,
                recovery_generation: self.recovery.generation(),
            };
            self.pending_product_intents.take_all(scope)
        } else {
            Vec::new()
        }
    }

    fn clear_pending_product_intents(&mut self) {
        self.pending_product_intents.clear();
    }

    fn can_begin_persistent_suppression(&self, force: bool) -> bool {
        self.visible
            && self.all_persistent_documents_finished()
            && (force || !self.persistent_suppression.is_pending_or_ready())
    }

    fn mark_persistent_document_started(
        &mut self,
        surface: WebKitSurface,
        generation: u64,
    ) -> bool {
        let Some(index) = persistent_document_index(surface, self.persistent_documents.len())
        else {
            return false;
        };
        self.persistent_documents[index] = PersistentDocumentReadiness {
            generation: Some(generation),
            finished: false,
        };
        // Every result from the outgoing document is now stale, even if its callback was already
        // queued on the owner-loop proxy.
        self.persistent_suppression.clear();
        true
    }

    fn mark_persistent_document_finished(
        &mut self,
        surface: WebKitSurface,
        generation: u64,
    ) -> Option<bool> {
        let index = persistent_document_index(surface, self.persistent_documents.len())?;
        let document = &mut self.persistent_documents[index];
        if document.generation != Some(generation) {
            return None;
        }
        document.finished = true;
        Some(self.all_persistent_documents_finished())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct OverlayGeometry {
    x: i32,
    y: i32,
    width: i32,
    height: i32,
    scale: i32,
}

impl OverlayGeometry {
    fn target(widget: &gtk::Widget) -> Option<Self> {
        let allocation = widget.allocation();
        Self::new(
            0,
            0,
            allocation.width(),
            allocation.height(),
            widget.scale_factor(),
        )
    }

    fn relative_to(widget: &gtk::Widget, coordinate_space: &gtk::Widget) -> Option<Self> {
        if !widget.is_visible() || !widget.is_mapped() {
            return None;
        }
        let allocation = widget.allocation();
        let (x, y) = widget.translate_coordinates(coordinate_space, 0, 0)?;
        Self::new(
            x,
            y,
            allocation.width(),
            allocation.height(),
            widget.scale_factor(),
        )
    }

    fn new(x: i32, y: i32, width: i32, height: i32, scale: i32) -> Option<Self> {
        (width > 1 && height > 1 && scale > 0).then_some(Self {
            x,
            y,
            width,
            height,
            scale,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OverlayAllocationSurface {
    Layer,
    PageStack,
    Content,
    WebView,
}

impl OverlayAllocationSurface {
    const COUNT: usize = 4;

    fn index(self) -> usize {
        match self {
            Self::Layer => 0,
            Self::PageStack => 1,
            Self::Content => 2,
            Self::WebView => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OverlayPresentationBarrierPhase {
    Containers,
    WebView,
    WebViewport,
}

#[derive(Debug)]
struct OverlayPresentationAttempt {
    token: u64,
    target: Option<OverlayGeometry>,
    observed: [Option<OverlayGeometry>; OverlayAllocationSurface::COUNT],
    phase: OverlayPresentationBarrierPhase,
    native_event_queued: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OverlayNativeAllocationReady {
    token: u64,
    target: OverlayGeometry,
    phase: OverlayNativeAllocationPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OverlayNativeAllocationPhase {
    Containers,
    WebView,
}

#[derive(Default, Debug)]
struct OverlayPresentationBarrier {
    active: Option<OverlayPresentationAttempt>,
}

impl OverlayPresentationBarrier {
    /// Start one generation-bound presentation join. Re-entering with the same token is
    /// idempotent; a newer token replaces every observation from the superseded attempt.
    fn begin(&mut self, token: u64, target: Option<OverlayGeometry>) -> bool {
        if let Some(active) = self.active.as_mut().filter(|active| active.token == token) {
            Self::update_target(active, target);
            return false;
        }
        self.active = Some(OverlayPresentationAttempt {
            token,
            target,
            observed: [None; OverlayAllocationSurface::COUNT],
            phase: OverlayPresentationBarrierPhase::Containers,
            native_event_queued: false,
        });
        true
    }

    fn cancel(&mut self) -> Option<OverlayPresentationBarrierPhase> {
        self.active.take().map(|active| active.phase)
    }

    fn observe_target(
        &mut self,
        target: Option<OverlayGeometry>,
    ) -> Option<OverlayNativeAllocationReady> {
        let active = self.active.as_mut()?;
        Self::update_target(active, target);
        Self::native_ready(active)
    }

    fn observe_surface(
        &mut self,
        surface: OverlayAllocationSurface,
        geometry: Option<OverlayGeometry>,
    ) -> Option<OverlayNativeAllocationReady> {
        let active = self.active.as_mut()?;
        active.observed[surface.index()] = geometry;
        let containers_still_match = active.target.is_some_and(|target| {
            Self::native_geometry_matches_phase(
                OverlayNativeAllocationPhase::Containers,
                target,
                &active.observed,
            )
        });
        let webview_still_matches = active.target.is_some_and(|target| {
            active.observed[OverlayAllocationSurface::WebView.index()] == Some(target)
        });
        match active.phase {
            OverlayPresentationBarrierPhase::Containers => {
                if !containers_still_match {
                    active.native_event_queued = false;
                }
            }
            OverlayPresentationBarrierPhase::WebView => {
                if !containers_still_match {
                    active.phase = OverlayPresentationBarrierPhase::Containers;
                    active.native_event_queued = false;
                } else if !webview_still_matches {
                    active.native_event_queued = false;
                }
            }
            OverlayPresentationBarrierPhase::WebViewport => {
                if !containers_still_match {
                    active.phase = OverlayPresentationBarrierPhase::Containers;
                    active.native_event_queued = false;
                } else if !webview_still_matches {
                    active.phase = OverlayPresentationBarrierPhase::WebView;
                    active.native_event_queued = false;
                }
            }
        }
        Self::native_ready(active)
    }

    fn accept_native_ready(
        &mut self,
        event: OverlayNativeAllocationReady,
        live_target: Option<OverlayGeometry>,
        live_observed: [Option<OverlayGeometry>; OverlayAllocationSurface::COUNT],
    ) -> bool {
        let Some(active) = self.active.as_mut() else {
            return false;
        };
        let expected_phase = match event.phase {
            OverlayNativeAllocationPhase::Containers => OverlayPresentationBarrierPhase::Containers,
            OverlayNativeAllocationPhase::WebView => OverlayPresentationBarrierPhase::WebView,
        };
        if active.token != event.token
            || active.target != Some(event.target)
            || active.phase != expected_phase
            || !active.native_event_queued
        {
            // A stale generation or phase must never consume the current attempt's wake.
            return false;
        }

        // This exact same-token/same-phase wake has now been consumed. Clear it even if live GTK
        // geometry has changed since it was queued so the final settling allocation may enqueue a
        // fresh wake instead of waiting for the presentation timeout.
        active.native_event_queued = false;
        if live_target != Some(event.target)
            || !Self::native_geometry_matches_phase(event.phase, event.target, &live_observed)
        {
            return false;
        }
        active.target = live_target;
        active.observed = live_observed;
        active.phase = match event.phase {
            OverlayNativeAllocationPhase::Containers => {
                active.observed[OverlayAllocationSurface::WebView.index()] = None;
                OverlayPresentationBarrierPhase::WebView
            }
            OverlayNativeAllocationPhase::WebView => OverlayPresentationBarrierPhase::WebViewport,
        };
        true
    }

    fn accept_viewport_ready(
        &mut self,
        event: OverlayViewportReady,
        live_target: Option<OverlayGeometry>,
        live_observed: [Option<OverlayGeometry>; OverlayAllocationSurface::COUNT],
    ) -> Option<OverlayGeometry> {
        let active = self.active.as_ref()?;
        let target = active.target?;
        if active.token != event.token
            || active.phase != OverlayPresentationBarrierPhase::WebViewport
            || event.width != target.width
            || event.height != target.height
            || live_target != Some(target)
            || live_observed
                .iter()
                .any(|geometry| *geometry != Some(target))
        {
            return None;
        }
        self.active = None;
        Some(target)
    }

    fn update_target(active: &mut OverlayPresentationAttempt, target: Option<OverlayGeometry>) {
        if active.target == target {
            return;
        }
        active.target = target;
        active.phase = OverlayPresentationBarrierPhase::Containers;
        active.native_event_queued = false;
    }

    fn native_geometry_matches_phase(
        phase: OverlayNativeAllocationPhase,
        target: OverlayGeometry,
        observed: &[Option<OverlayGeometry>; OverlayAllocationSurface::COUNT],
    ) -> bool {
        let required = match phase {
            OverlayNativeAllocationPhase::Containers => {
                &observed[..OverlayAllocationSurface::WebView.index()]
            }
            OverlayNativeAllocationPhase::WebView => &observed[..],
        };
        required.iter().all(|geometry| *geometry == Some(target))
    }

    fn native_ready(
        active: &mut OverlayPresentationAttempt,
    ) -> Option<OverlayNativeAllocationReady> {
        if active.native_event_queued {
            return None;
        }
        let target = active.target?;
        let phase = match active.phase {
            OverlayPresentationBarrierPhase::Containers => OverlayNativeAllocationPhase::Containers,
            OverlayPresentationBarrierPhase::WebView => OverlayNativeAllocationPhase::WebView,
            OverlayPresentationBarrierPhase::WebViewport => return None,
        };
        if !Self::native_geometry_matches_phase(phase, target, &active.observed) {
            return None;
        }
        active.native_event_queued = true;
        Some(OverlayNativeAllocationReady {
            token: active.token,
            target,
            phase,
        })
    }
}

#[derive(Default)]
struct OverlayPresentationTimeout {
    armed: Option<(u64, glib::SourceId)>,
}

impl OverlayPresentationTimeout {
    fn cancel(&mut self) {
        if let Some((_, source)) = self.armed.take() {
            source.remove();
        }
    }
}

/// GTK may route Tab from a focused EventBox through the top-level focus chain. While the native
/// loading/recovery fallback owns the modal, every key must stop there; once the authenticated
/// WebKit document is ready, its own React dialog receives keys normally.
fn native_fallback_consumes_keys(visible: bool, can_present: bool) -> bool {
    visible && !can_present
}

fn fallback_key_propagation(state: &std::rc::Weak<RefCell<OverlayRuntime>>) -> glib::Propagation {
    let consume = state
        .upgrade()
        .is_none_or(|state| match state.try_borrow() {
            Ok(state) => native_fallback_consumes_keys(
                state.visible,
                state.presentation_complete
                    && state.delivery.can_present()
                    && state.persistent_suppression.is_ready(),
            ),
            Err(_) => true,
        });
    if consume {
        glib::Propagation::Stop
    } else {
        glib::Propagation::Proceed
    }
}

fn linux_overlay_input_trace_enabled() -> bool {
    std::env::var("HYDRA_LINUX_OVERLAY_INPUT_TRACE").as_deref() == Ok("1")
}

fn linux_geometry_trace_enabled() -> bool {
    std::env::var("HYDRA_LINUX_GEOMETRY_TRACE").as_deref() == Ok("1")
}

fn log_overlay_widget_geometry(
    widget_name: &'static str,
    event: &'static str,
    widget: &gtk::Widget,
) {
    let allocation = widget.allocation();
    eprintln!(
        "linux-host overlay geometry host_monotonic_us={} widget={widget_name} event={event} x={} y={} width={} height={} scale={} mapped={} visible={} child_visible={} sensitive={}",
        overlay_trace_monotonic_us(),
        allocation.x(),
        allocation.y(),
        allocation.width(),
        allocation.height(),
        widget.scale_factor(),
        widget.is_mapped(),
        widget.is_visible(),
        widget.is_child_visible(),
        widget.is_sensitive(),
    );
}

fn log_overlay_presentation_step(token: u64, step: &'static str, started: Instant) {
    if linux_geometry_trace_enabled() {
        eprintln!(
            "linux-host overlay presentation host_monotonic_us={} token={token} step={step} elapsed_us={}",
            overlay_trace_monotonic_us(),
            started.elapsed().as_micros(),
        );
    }
}

fn install_overlay_widget_geometry_trace(widget_name: &'static str, widget: &gtk::Widget) {
    if !linux_geometry_trace_enabled() {
        return;
    }
    log_overlay_widget_geometry(widget_name, "installed", widget);
    widget.connect_size_allocate(move |widget, _| {
        log_overlay_widget_geometry(widget_name, "allocation", widget);
    });
    widget.connect_map(move |widget| {
        log_overlay_widget_geometry(widget_name, "map", widget);
    });
    widget.connect_unmap(move |widget| {
        log_overlay_widget_geometry(widget_name, "unmap", widget);
    });
    widget.connect_visible_notify(move |widget| {
        log_overlay_widget_geometry(widget_name, "visible", widget);
    });
    widget.connect_sensitive_notify(move |widget| {
        log_overlay_widget_geometry(widget_name, "sensitive", widget);
    });
}

fn send_overlay_native_ready(
    barrier: &Rc<RefCell<OverlayPresentationBarrier>>,
    proxy: &tao::event_loop::EventLoopProxy<LinuxLoopEvent>,
    event: Option<OverlayNativeAllocationReady>,
) {
    if let Some(event) = event {
        if proxy
            .send_event(LinuxLoopEvent::OverlayNativeAllocationReady(event))
            .is_err()
        {
            // The owner loop has closed. No later GTK callback can produce a meaningful
            // presentation, so retire the attempt instead of retaining a permanently queued bit.
            barrier.borrow_mut().cancel();
        }
    }
}

fn observe_overlay_surface_geometry(
    surface: OverlayAllocationSurface,
    widget: &gtk::Widget,
    coordinate_space: &gtk::Widget,
    barrier: &Rc<RefCell<OverlayPresentationBarrier>>,
    proxy: &tao::event_loop::EventLoopProxy<LinuxLoopEvent>,
) {
    let event = barrier.borrow_mut().observe_surface(
        surface,
        OverlayGeometry::relative_to(widget, coordinate_space),
    );
    send_overlay_native_ready(barrier, proxy, event);
}

fn install_overlay_target_allocation_barrier(
    widget: &gtk::Widget,
    barrier: &Rc<RefCell<OverlayPresentationBarrier>>,
    proxy: &tao::event_loop::EventLoopProxy<LinuxLoopEvent>,
) {
    {
        let barrier = barrier.clone();
        let proxy = proxy.clone();
        widget.connect_size_allocate(move |widget, _| {
            let event = barrier
                .borrow_mut()
                .observe_target(OverlayGeometry::target(widget));
            send_overlay_native_ready(&barrier, &proxy, event);
        });
    }
    {
        let barrier = barrier.clone();
        let proxy = proxy.clone();
        widget.connect_map(move |widget| {
            let event = barrier
                .borrow_mut()
                .observe_target(OverlayGeometry::target(widget));
            send_overlay_native_ready(&barrier, &proxy, event);
        });
    }
    {
        let barrier = barrier.clone();
        let proxy = proxy.clone();
        widget.connect_scale_factor_notify(move |widget| {
            let event = barrier
                .borrow_mut()
                .observe_target(OverlayGeometry::target(widget));
            send_overlay_native_ready(&barrier, &proxy, event);
        });
    }
}

fn install_overlay_surface_allocation_barrier(
    surface: OverlayAllocationSurface,
    widget: &gtk::Widget,
    coordinate_space: &gtk::Widget,
    barrier: &Rc<RefCell<OverlayPresentationBarrier>>,
    proxy: &tao::event_loop::EventLoopProxy<LinuxLoopEvent>,
) {
    {
        let barrier = barrier.clone();
        let proxy = proxy.clone();
        let coordinate_space = coordinate_space.clone();
        widget.connect_size_allocate(move |widget, _| {
            observe_overlay_surface_geometry(surface, widget, &coordinate_space, &barrier, &proxy);
        });
    }
    {
        let barrier = barrier.clone();
        let proxy = proxy.clone();
        let coordinate_space = coordinate_space.clone();
        widget.connect_map(move |widget| {
            observe_overlay_surface_geometry(surface, widget, &coordinate_space, &barrier, &proxy);
        });
    }
    {
        let barrier = barrier.clone();
        let proxy = proxy.clone();
        let coordinate_space = coordinate_space.clone();
        widget.connect_scale_factor_notify(move |widget| {
            observe_overlay_surface_geometry(surface, widget, &coordinate_space, &barrier, &proxy);
        });
    }
    {
        let barrier = barrier.clone();
        let proxy = proxy.clone();
        widget.connect_unmap(move |_| {
            let event = barrier.borrow_mut().observe_surface(surface, None);
            send_overlay_native_ready(&barrier, &proxy, event);
        });
    }
}

/// GTK/WRY owner for the lazily-created overlay WebView. Every method runs on the GTK owner thread.
pub struct LinuxOverlayHost {
    composition: gtk::Widget,
    layer: gtk::EventBox,
    page_stack: gtk::Stack,
    parking_page: gtk::Box,
    content: gtk::Box,
    terminal_slot: gtk::DrawingArea,
    top_level: gtk::ApplicationWindow,
    present_target: Rc<TerminalPresentTarget>,
    web_context: Rc<RefCell<wry::WebContext>>,
    related_webview: Rc<wry::WebView>,
    underlay_containers: Vec<gtk::Widget>,
    underlay_webviews: Vec<Rc<wry::WebView>>,
    underlay_interactivity: RefCell<UnderlayInteractivityState>,
    persistent_input_gate: Rc<PersistentInputGate>,
    presentation_barrier: Rc<RefCell<OverlayPresentationBarrier>>,
    presentation_timeout: Rc<RefCell<OverlayPresentationTimeout>>,
    overlay_url: String,
    initialization_script: String,
    input_trace_enabled: bool,
    events: Option<std::sync::mpsc::Sender<RendererEvent>>,
    wake_proxy: tao::event_loop::EventLoopProxy<LinuxLoopEvent>,
    state: Rc<RefCell<OverlayRuntime>>,
    recovery_tracker: Rc<RefCell<RecoverySignalTracker>>,
    previous_focus: Rc<RefCell<Option<gtk::Widget>>>,
}

impl LinuxOverlayHost {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        layer: gtk::EventBox,
        content: gtk::Box,
        terminal_slot: gtk::DrawingArea,
        top_level: gtk::ApplicationWindow,
        present_target: Rc<TerminalPresentTarget>,
        web_context: Rc<RefCell<wry::WebContext>>,
        related_webview: Rc<wry::WebView>,
        topbar_webview: Option<Rc<wry::WebView>>,
        underlay_containers: Vec<gtk::Widget>,
        overlay_url: String,
        initialization_script: String,
        events: Option<std::sync::mpsc::Sender<RendererEvent>>,
        wake_proxy: tao::event_loop::EventLoopProxy<LinuxLoopEvent>,
        persistent_input_gate: Rc<PersistentInputGate>,
    ) -> Result<Self, String> {
        // `window_host` owns this one-time hierarchy substitution. Refuse an unexpected parent
        // before mutating either widget: blindly asking `layer` to remove a child owned elsewhere
        // would leave a half-built overlay and GTK warnings while the terminal is occluded.
        let expected_parent: gtk::Widget = layer.clone().upcast();
        match content.parent() {
            Some(parent) if parent == expected_parent => {}
            Some(parent) => {
                return Err(format!(
                    "overlay content has unexpected GTK parent type={}",
                    parent.type_().name()
                ));
            }
            None => return Err("overlay content has no GTK parent".to_owned()),
        }
        let composition = layer
            .parent()
            .ok_or_else(|| "overlay layer has no GTK composition parent".to_owned())?;
        if !composition.is::<gtk::Overlay>() {
            return Err(format!(
                "overlay layer has unexpected GTK parent type={}",
                composition.type_().name()
            ));
        }

        let underlay_webviews: Vec<_> = std::iter::once(related_webview.clone())
            .chain(topbar_webview)
            .collect();
        if underlay_containers.len() != underlay_webviews.len() {
            return Err(format!(
                "overlay underlay container mismatch containers={} webviews={}",
                underlay_containers.len(),
                underlay_webviews.len()
            ));
        }

        // Start fully inert. The EventBox itself is the keyboard fallback while an active overlay
        // document loads, but a hidden overlay is not a product control and must not remain in the
        // GTK focus/accessibility path.
        layer.set_can_focus(false);
        layer.set_sensitive(false);
        layer.set_visible_window(true);
        layer.set_above_child(false);
        layer.add_events(overlay_event_mask());
        let persistent_target_count = underlay_webviews.len();
        let state = Rc::new(RefCell::new(OverlayRuntime::new(persistent_target_count)));
        {
            let key_state = Rc::downgrade(&state);
            layer.connect_key_press_event(move |_, _| fallback_key_propagation(&key_state));
        }
        {
            let key_state = Rc::downgrade(&state);
            layer.connect_key_release_event(move |_, _| fallback_key_propagation(&key_state));
        }
        layer.set_widget_name("hydra-dashboard-overlay-fallback");
        if let Some(accessible) = layer.accessible() {
            let (name, description) = fallback_accessible_copy(FallbackAccessibility::Inactive);
            accessible.set_role(gtk::atk::Role::Panel);
            accessible.set_name(name);
            accessible.set_description(description);
        }
        let css = gtk::CssProvider::new();
        if css
            .load_from_data(b"#hydra-dashboard-overlay-fallback { background-color: #07080b; }")
            .is_ok()
        {
            layer
                .style_context()
                .add_provider(&css, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);
        }

        // `window_host` constructs the ordinary GTK hierarchy before this owner exists. Replace its
        // direct content child once, before WebKit is created, with a non-animating stack. The
        // content then keeps the same GTK parent for its entire lifetime. Reparenting a realized
        // WebKitWebView makes WebKitGTK allocate new DMA-BUF backing stores on every modal cycle;
        // selecting the inert stack page provides the same AT-SPI isolation without that churn.
        content.set_sensitive(false);
        content.hide();
        layer.remove(&content);

        let page_stack = gtk::Stack::new();
        page_stack.set_halign(gtk::Align::Fill);
        page_stack.set_valign(gtk::Align::Fill);
        page_stack.set_hexpand(true);
        page_stack.set_vexpand(true);
        page_stack.set_hhomogeneous(true);
        page_stack.set_vhomogeneous(true);
        page_stack.set_interpolate_size(false);
        page_stack.set_transition_duration(0);
        page_stack.set_transition_type(gtk::StackTransitionType::None);
        page_stack.set_can_focus(false);
        page_stack.set_sensitive(false);

        let parking_page = gtk::Box::new(gtk::Orientation::Vertical, 0);
        parking_page.set_hexpand(true);
        parking_page.set_vexpand(true);
        parking_page.set_can_focus(false);
        parking_page.set_sensitive(false);
        page_stack.add_named(&parking_page, "parking");
        page_stack.add_named(&content, "document");
        parking_page.show();
        page_stack.set_visible_child(&parking_page);
        page_stack.show();
        layer.add(&page_stack);

        let top_level_widget: gtk::Widget = top_level.clone().upcast();
        let layer_widget: gtk::Widget = layer.clone().upcast();
        let page_stack_widget: gtk::Widget = page_stack.clone().upcast();
        let content_widget: gtk::Widget = content.clone().upcast();
        install_overlay_widget_geometry_trace("top-level", &top_level_widget);
        install_overlay_widget_geometry_trace("composition", &composition);
        install_overlay_widget_geometry_trace("layer", &layer_widget);
        install_overlay_widget_geometry_trace("page-stack", &page_stack_widget);
        install_overlay_widget_geometry_trace("content", &content_widget);
        let presentation_barrier = Rc::new(RefCell::new(OverlayPresentationBarrier::default()));
        install_overlay_target_allocation_barrier(&composition, &presentation_barrier, &wake_proxy);
        install_overlay_surface_allocation_barrier(
            OverlayAllocationSurface::Layer,
            &layer_widget,
            &composition,
            &presentation_barrier,
            &wake_proxy,
        );
        install_overlay_surface_allocation_barrier(
            OverlayAllocationSurface::PageStack,
            &page_stack_widget,
            &composition,
            &presentation_barrier,
            &wake_proxy,
        );
        install_overlay_surface_allocation_barrier(
            OverlayAllocationSurface::Content,
            &content_widget,
            &composition,
            &presentation_barrier,
            &wake_proxy,
        );
        let input_trace_enabled = linux_overlay_input_trace_enabled();

        Ok(Self {
            composition,
            layer,
            page_stack,
            parking_page,
            content,
            terminal_slot,
            top_level,
            present_target,
            web_context,
            related_webview,
            underlay_containers,
            underlay_webviews,
            underlay_interactivity: RefCell::new(UnderlayInteractivityState::default()),
            persistent_input_gate,
            presentation_barrier,
            presentation_timeout: Rc::new(RefCell::new(OverlayPresentationTimeout::default())),
            overlay_url,
            initialization_script: overlay_initialization_script(
                &initialization_script,
                input_trace_enabled,
            ),
            input_trace_enabled,
            events,
            wake_proxy,
            state,
            recovery_tracker: Rc::new(RefCell::new(RecoverySignalTracker::default())),
            previous_focus: Rc::new(RefCell::new(None)),
        })
    }

    /// Evaluate a dashboard script in the overlay when ready, or remember the minimum state required
    /// for its lazy first load/recovery. Model and modal scripts are superseding; transient replies are
    /// accepted only while the overlay is active.
    pub fn evaluate_or_remember(&self, script: &str, kind: ReactChromeScriptKind) {
        let evaluate = {
            let mut state = self.state.borrow_mut();
            // A new modal supersedes every request emitted by the previous modal render. The new
            // document/effect will issue fresh requests under its own request ids.
            if kind == ReactChromeScriptKind::Modal {
                state.clear_pending_product_intents();
            }
            // A cold request still owns its bounded script cache even though native input remains
            // active and the overlay is not yet product-visible.
            let accept_transient = state.visible || state.cold_load_pending();
            let evaluation = state.delivery.remember(script, kind, accept_transient);
            evaluation.zip(state.webview.clone())
        };
        if let Some((evaluation, webview)) = evaluate {
            // Replacing a visible modal is also atomic: park the old document until the new modal
            // task has completed, rather than presenting stale controls under a new native cache.
            if evaluation.modal_attempt.is_some() && self.state.borrow().visible {
                self.arm_presentation_timeout();
                self.set_fallback_accessibility(FallbackAccessibility::Loading);
                self.suppress_underlay_inputs();
                let suppression_ready = self.state.borrow().persistent_suppression.is_ready();
                self.park_webview(Some(&webview), suppression_ready);
            }
            self.submit_evaluation(&webview, evaluation);
        }
    }

    fn set_fallback_accessibility(&self, state: FallbackAccessibility) {
        if let Some(accessible) = self.layer.accessible() {
            let (name, description) = fallback_accessible_copy(state);
            accessible.set_role(match state {
                FallbackAccessibility::Inactive => gtk::atk::Role::Panel,
                FallbackAccessibility::Loading | FallbackAccessibility::Recovering => {
                    gtk::atk::Role::Dialog
                }
            });
            accessible.set_name(name);
            accessible.set_description(description);
        }
    }

    /// One full-window modal spans three independent WebKit documents and a native terminal target
    /// on Linux. Native GTK focus therefore has to suppress the terminal and persistent
    /// sidebar/topbar in addition to React's in-document Tab trap. Capture every widget's own flags
    /// only on the first active transition, then reassert suppression across overlay recovery
    /// without overwriting the values restored on exit.
    fn suppress_native_underlay_inputs(&self) {
        let containers = self
            .underlay_containers
            .iter()
            .map(|widget| WidgetInteractivity {
                sensitive: widget.property::<bool>("sensitive"),
                can_focus: widget.can_focus(),
            })
            .collect();
        let webviews = self
            .underlay_webviews
            .iter()
            .map(|webview| {
                let widget = webview.webview();
                WidgetInteractivity {
                    sensitive: widget.property::<bool>("sensitive"),
                    can_focus: widget.can_focus(),
                }
            })
            .collect();
        let terminal = WidgetInteractivity {
            sensitive: self.terminal_slot.property::<bool>("sensitive"),
            can_focus: self.terminal_slot.can_focus(),
        };
        let restore_focus_webview = self.previous_focus.borrow().as_ref().and_then(|focused| {
            self.underlay_webviews.iter().position(|webview| {
                let widget: gtk::Widget = webview.webview().clone().upcast();
                focused == &widget || focused.is_ancestor(&widget)
            })
        });
        self.underlay_interactivity
            .borrow_mut()
            .capture_once(UnderlayInteractivitySnapshot {
                containers,
                webviews,
                terminal,
                restore_focus_webview,
            });

        // Parent bands close native GTK hit-testing first. Keep both WebViews mapped so opening a
        // dialog never reallocates their DMA-BUF backing stores.
        for container in &self.underlay_containers {
            container.set_can_focus(false);
            container.set_sensitive(false);
        }
        for webview in &self.underlay_webviews {
            let widget = webview.webview();
            widget.set_can_focus(false);
            widget.set_sensitive(false);
        }
        self.terminal_slot.set_can_focus(false);
        self.terminal_slot.set_sensitive(false);
        // WebKit accessibility actions are remote and can bypass GTK sensitivity. `inert` removes
        // persistent controls from WebKit's focus/action tree. The shared Rust gate is the
        // authoritative final check before any persistent IPC can reach App.
        self.persistent_input_gate.suppress();
    }

    fn suppress_underlay_inputs(&self) {
        self.suppress_native_underlay_inputs();
        // The script is idempotent and also covers a persistent-page recovery during an active
        // modal. Its exact callback is a presentation barrier, not merely diagnostic logging.
        self.begin_persistent_document_suppression(false);
    }

    fn restore_underlay_inputs(&self) {
        // Cold-load requests deliberately have no native interactivity snapshot. Retire their
        // deadline before the early return as well as the presentation deadline used after
        // suppression begins.
        self.cancel_presentation_timeout();
        let Some(saved) = self.underlay_interactivity.borrow_mut().take_for_restore() else {
            return;
        };
        debug_assert_eq!(saved.containers.len(), self.underlay_containers.len());
        debug_assert_eq!(saved.webviews.len(), self.underlay_webviews.len());
        for (webview, interactivity) in self.underlay_webviews.iter().zip(&saved.webviews) {
            let widget = webview.webview();
            widget.set_sensitive(interactivity.sensitive);
            widget.set_can_focus(interactivity.can_focus);
        }
        self.terminal_slot.set_sensitive(saved.terminal.sensitive);
        self.terminal_slot.set_can_focus(saved.terminal.can_focus);
        // Restore children while their parent bands are still closed, then reopen the bands in one
        // owner-loop turn. The JS restore is exact: pre-existing root inert/aria-hidden values were
        // snapshotted once by the suppression script and are never guessed.
        self.restore_persistent_documents(saved.restore_focus_webview);
        self.persistent_input_gate.restore();
        self.state.borrow_mut().persistent_suppression.clear();
        for (container, interactivity) in self.underlay_containers.iter().zip(&saved.containers) {
            container.set_sensitive(interactivity.sensitive);
            container.set_can_focus(interactivity.can_focus);
        }
    }

    fn restore_persistent_documents(&self, restore_focus_webview: Option<usize>) {
        for (index, webview) in self.underlay_webviews.iter().enumerate() {
            let script = persistent_restore_script(restore_focus_webview == Some(index));
            if let Err(error) = webview.evaluate_script(&script) {
                eprintln!("linux-host persistent modal accessibility restore failed: {error}");
            }
        }
    }

    /// Start one epoch of persistent-document suppression and require an exact callback from every
    /// mounted realm. The overlay document stays parked behind the labeled native fallback until
    /// both this epoch and modal delivery are ready. A dispatch/JavaScript failure fails closed to
    /// the terminal; a late callback from a replaced epoch is ignored.
    fn begin_persistent_document_suppression(&self, force: bool) {
        let epoch = {
            let mut state = self.state.borrow_mut();
            if !state.can_begin_persistent_suppression(force) {
                return;
            }
            state
                .persistent_suppression
                .begin(self.underlay_webviews.len())
        };

        for (index, webview) in self.underlay_webviews.iter().enumerate() {
            let proxy = self.wake_proxy.clone();
            let callback = move |result: String| {
                let succeeded = persistent_suppression_succeeded(&result);
                let _ = proxy.send_event(LinuxLoopEvent::PersistentSuppression(
                    PersistentSuppressionResult {
                        epoch,
                        index,
                        succeeded,
                    },
                ));
            };
            if let Err(error) = webview
                .evaluate_script_with_callback(SUPPRESS_PERSISTENT_DOCUMENTS_SCRIPT, callback)
            {
                eprintln!(
                    "linux-host persistent modal suppression dispatch failed epoch={epoch} index={index}: {error}"
                );
                let _ = self
                    .wake_proxy
                    .send_event(LinuxLoopEvent::PersistentSuppression(
                        PersistentSuppressionResult {
                            epoch,
                            index,
                            succeeded: false,
                        },
                    ));
            }
        }
        eprintln!(
            "linux-host persistent modal suppression dispatched epoch={epoch} targets={}",
            self.underlay_webviews.len()
        );
        if self.underlay_webviews.is_empty() {
            self.try_present_ready_webview();
        }
    }

    /// Begin one bounded lazy-load request without changing native focus or input ownership.
    /// Duplicate visibility requests do not extend the bound.
    fn arm_cold_load_timeout(&self) {
        let Some(token) = self.state.borrow_mut().ensure_cold_load_deadline() else {
            return;
        };
        self.arm_overlay_timeout_source(token, OVERLAY_COLD_LOAD_TIMEOUT);
    }

    /// One short bounded deadline spans only the modal presentation join: persistent document
    /// readiness, persistent suppression callbacks, and overlay modal delivery. A hung WebKit
    /// process therefore degrades back to the retained terminal instead of trapping all input.
    fn arm_presentation_timeout(&self) {
        let token = self.state.borrow_mut().begin_presentation_deadline();
        self.arm_overlay_timeout_source(token, MODAL_PRESENTATION_TIMEOUT);
    }

    fn arm_overlay_timeout_source(&self, token: u64, duration: Duration) {
        self.presentation_timeout.borrow_mut().cancel();
        let timeout_state = Rc::downgrade(&self.presentation_timeout);
        let proxy = self.wake_proxy.clone();
        let source = glib::timeout_add_local_once(duration, move || {
            let should_send = timeout_state.upgrade().is_some_and(|state| {
                let mut state = state.borrow_mut();
                if state.armed.as_ref().map(|(armed_token, _)| *armed_token) == Some(token) {
                    // The GLib one-shot is already firing; take ownership without removing it.
                    state.armed.take();
                    true
                } else {
                    false
                }
            });
            if should_send {
                let _ = proxy.send_event(LinuxLoopEvent::OverlayPresentationTimeout { token });
            }
        });
        self.presentation_timeout.borrow_mut().armed = Some((token, source));
    }

    fn ensure_presentation_timeout(&self) {
        let Some(token) = self.state.borrow_mut().ensure_presentation_deadline() else {
            return;
        };
        self.arm_overlay_timeout_source(token, MODAL_PRESENTATION_TIMEOUT);
    }

    fn cancel_presentation_timeout(&self) {
        self.state.borrow_mut().end_deadline();
        self.presentation_timeout.borrow_mut().cancel();
    }

    pub fn set_visible(&self, visible: bool) {
        if !visible {
            self.hide_and_restore_focus();
            return;
        }
        if self.state.borrow().recovery.is_exhausted() {
            eprintln!(
                "linux-host overlay recovery phase=exhausted bundled=true bytes={} reason=visibility-request attempts={MAX_WEBKIT_RECOVERY_ATTEMPTS}",
                self.overlay_url.len()
            );
            self.fail_closed_to_terminal();
            return;
        }

        if !self.state.borrow().delivery.has_active_modal() {
            eprintln!("linux-host dashboard overlay visibility refused reason=no-cached-modal");
            self.fail_closed_to_terminal();
            return;
        }

        let (already_visible, ready) = {
            let state = self.state.borrow();
            (
                state.visible,
                state.delivery.webview_attached && state.delivery.react_ready,
            )
        };
        if !already_visible && !ready {
            // Lazy WebKit load is request state, not modal presentation state. Keep every native
            // surface interactive until the authenticated document emits its exact ready marker.
            self.arm_cold_load_timeout();
            if let Err(err) = self.ensure_created() {
                eprintln!("linux-host dashboard overlay creation failed: {err}");
                self.fail_closed_to_terminal();
                return;
            }
            let (ready, pending) = {
                let state = self.state.borrow();
                (state.delivery.react_ready, state.cold_load_pending())
            };
            eprintln!(
                "linux-host dashboard overlay cold load requested visible=false ready={ready} pending={pending}"
            );
            return;
        }

        let first_transition = {
            let mut state = self.state.borrow_mut();
            let first = !state.visible;
            state.visible = true;
            first
        };
        if first_transition {
            *self.previous_focus.borrow_mut() = self.top_level.focused_widget();
            self.arm_presentation_timeout();
        }

        self.set_fallback_accessibility(FallbackAccessibility::Loading);
        self.suppress_underlay_inputs();
        // Do not expose a native ATK dialog while the persistent WebKit documents are still visible
        // to remote accessibility. The overlay/fallback is presented only after both documents
        // acknowledge `inert`; the IPC/native gates already prevent input during this short join.
        if first_transition {
            self.park_webview(self.state.borrow().webview.as_deref(), false);
            self.present_target.set_overlay_occluded(false);
            self.top_level.queue_draw();
        }

        if let Err(err) = self.ensure_created() {
            eprintln!("linux-host dashboard overlay creation failed: {err}");
            self.fail_closed_to_terminal();
            return;
        }

        let (ready, actual_visible) = {
            let state = self.state.borrow();
            (state.delivery.react_ready, state.visible)
        };
        self.try_present_ready_webview();
        eprintln!("linux-host dashboard overlay requested visible={actual_visible} ready={ready}");
    }

    /// Return focus to the overlay after a native picker closes, but only if the modal is still active.
    pub fn refocus_if_visible(&self) {
        let (visible, can_present, webview) = {
            let state = self.state.borrow();
            (
                state.visible,
                state.presentation_complete
                    && state.delivery.can_present()
                    && state.persistent_suppression.is_ready(),
                state.webview.clone(),
            )
        };
        if !visible {
            return;
        }
        self.suppress_underlay_inputs();
        if can_present {
            if let Some(webview) = webview {
                webview.webview().grab_focus();
                return;
            }
        }
        if self.state.borrow().persistent_suppression.is_ready() {
            self.show_native_fallback();
        }
    }

    /// A persistent sidebar/topbar document may reload while the modal is active. Its new DOM did
    /// not observe the earlier `inert` script, so reassert the complete native + WebKit + IPC gate
    /// after every persistent recovery event. Hidden overlays deliberately do nothing.
    pub(crate) fn persistent_document_finished(&self, surface: WebKitSurface, generation: u64) {
        let (visible, all_finished, webview) = {
            let mut state = self.state.borrow_mut();
            let Some(all_finished) = state.mark_persistent_document_finished(surface, generation)
            else {
                return;
            };
            (state.visible, all_finished, state.webview.clone())
        };
        if !visible || !all_finished {
            return;
        }
        self.set_fallback_accessibility(FallbackAccessibility::Recovering);
        self.suppress_native_underlay_inputs();
        self.park_webview(webview.as_deref(), false);
        self.present_target.set_overlay_occluded(false);
        self.begin_persistent_document_suppression(true);
    }

    /// A current persistent document has begun navigating. Any callback from its outgoing DOM is
    /// no longer proof about the replacement DOM, so invalidate the epoch immediately and park the
    /// overlay until the accepted PageFinished path starts a fresh callback-gated suppression.
    pub(crate) fn persistent_document_started(&self, surface: WebKitSurface, generation: u64) {
        let (visible, webview) = {
            let mut state = self.state.borrow_mut();
            if !state.mark_persistent_document_started(surface, generation) {
                return;
            }
            if !state.visible {
                return;
            }
            (state.visible, state.webview.clone())
        };
        self.ensure_presentation_timeout();
        debug_assert!(visible);
        self.set_fallback_accessibility(FallbackAccessibility::Recovering);
        self.suppress_native_underlay_inputs();
        self.park_webview(webview.as_deref(), false);
        self.present_target.set_overlay_occluded(false);
    }

    fn hide_and_restore_focus(&self) {
        let (was_visible, webview) = {
            let mut state = self.state.borrow_mut();
            let was_visible = state.visible;
            state.visible = false;
            state.delivery.hide();
            state.clear_pending_product_intents();
            (was_visible, state.webview.clone())
        };
        self.park_webview(webview.as_deref(), false);
        self.present_target.set_overlay_occluded(false);
        self.restore_underlay_inputs();
        self.top_level.queue_draw();
        if was_visible {
            restore_focus(&self.previous_focus, &self.terminal_slot);
            eprintln!("linux-host dashboard overlay hidden");
        }
    }

    fn fail_closed_to_terminal(&self) {
        let (was_visible, webview) = {
            let mut state = self.state.borrow_mut();
            let was_visible = state.visible;
            state.visible = false;
            state.delivery.hide();
            state.clear_pending_product_intents();
            (was_visible, state.webview.clone())
        };
        self.park_webview(webview.as_deref(), false);
        self.present_target.set_overlay_occluded(false);
        self.restore_underlay_inputs();
        self.top_level.queue_draw();
        if was_visible {
            restore_focus(&self.previous_focus, &self.terminal_slot);
        }
    }

    fn current_presentation_geometry(
        &self,
        webview: &wry::WebView,
    ) -> (
        Option<OverlayGeometry>,
        [Option<OverlayGeometry>; OverlayAllocationSurface::COUNT],
    ) {
        let coordinate_space = &self.composition;
        let layer: gtk::Widget = self.layer.clone().upcast();
        let page_stack: gtk::Widget = self.page_stack.clone().upcast();
        let content: gtk::Widget = self.content.clone().upcast();
        let webview_widget: gtk::Widget = webview.webview().clone().upcast();
        (
            OverlayGeometry::target(coordinate_space),
            [
                OverlayGeometry::relative_to(&layer, coordinate_space),
                OverlayGeometry::relative_to(&page_stack, coordinate_space),
                OverlayGeometry::relative_to(&content, coordinate_space),
                OverlayGeometry::relative_to(&webview_widget, coordinate_space),
            ],
        )
    }

    fn observe_current_presentation_geometry(&self, webview: &wry::WebView) {
        let (target, observed) = self.current_presentation_geometry(webview);
        let target_event = self
            .presentation_barrier
            .borrow_mut()
            .observe_target(target);
        send_overlay_native_ready(&self.presentation_barrier, &self.wake_proxy, target_event);
        for (surface, geometry) in [
            OverlayAllocationSurface::Layer,
            OverlayAllocationSurface::PageStack,
            OverlayAllocationSurface::Content,
            OverlayAllocationSurface::WebView,
        ]
        .into_iter()
        .zip(observed)
        {
            let event = self
                .presentation_barrier
                .borrow_mut()
                .observe_surface(surface, geometry);
            send_overlay_native_ready(&self.presentation_barrier, &self.wake_proxy, event);
        }
    }

    fn cancel_viewport_observer(&self, webview: Option<&wry::WebView>) {
        let prior_phase = self.presentation_barrier.borrow_mut().cancel();
        if prior_phase == Some(OverlayPresentationBarrierPhase::WebViewport) {
            let Some(webview) = webview else {
                return;
            };
            // Fire-and-forget teardown is bounded and nonblocking. A callback already queued by
            // the old document remains harmless because its presentation token is rejected.
            let _ = webview.evaluate_script(CANCEL_OVERLAY_VIEWPORT_OBSERVER_SCRIPT);
        }
    }

    /// Map the transparent/inert GTK container hierarchy first. Only after its exact client
    /// allocation returns through the owner loop may the retained WebView map; its own allocation
    /// and a later DOM viewport acknowledgement are separate generation-bound phases.
    fn stage_ready_webview(&self, token: u64, webview: &wry::WebView) -> Result<(), String> {
        let started = Instant::now();
        log_overlay_presentation_step(token, "stage-begin", started);
        self.suppress_underlay_inputs();
        self.present_target.set_overlay_occluded(false);
        let target = OverlayGeometry::target(&self.composition);
        let began = self.presentation_barrier.borrow_mut().begin(token, target);
        if !began {
            self.observe_current_presentation_geometry(webview);
            return Ok(());
        }

        // Opacity does not remove a GTK widget from allocation/mapping. This lets WebKit update its
        // backing store and input region while the terminal remains visually on top. Native input
        // was already suppressed by the modal gate, and every staged widget stays insensitive.
        self.layer.set_opacity(0.0);
        self.layer.set_sensitive(false);
        self.layer.set_can_focus(false);
        self.content.set_sensitive(false);
        self.content.show();

        let widget = webview.webview();
        widget.set_sensitive(false);
        widget.set_can_focus(false);
        if widget.is_visible() {
            webview.set_visible(false).map_err(|err| err.to_string())?;
        }
        self.page_stack.set_sensitive(false);
        self.page_stack.set_visible_child(&self.content);
        // Configure the entire descendant hierarchy while its windowed ancestor is hidden, request
        // layout, and map the transparent layer last. The first native owner-loop event therefore
        // certifies the three GTK containers before WebKit itself is allowed to map.
        self.layer.queue_resize();
        self.layer.queue_draw();
        self.layer.show();
        log_overlay_presentation_step(token, "containers-mapped-inert", started);
        self.observe_current_presentation_geometry(webview);
        log_overlay_presentation_step(token, "native-observation-seeded", started);
        Ok(())
    }

    /// Expose a staged document only after the generation-bound native allocation event and exact
    /// DOM viewport acknowledgement have both been revalidated on later owner-loop turns.
    fn activate_ready_webview(
        &self,
        token: u64,
        target: OverlayGeometry,
        webview: &wry::WebView,
    ) -> Result<(), String> {
        let started = Instant::now();
        let (live_target, live_observed) = self.current_presentation_geometry(webview);
        if live_target != Some(target)
            || live_observed
                .iter()
                .any(|geometry| *geometry != Some(target))
        {
            return Err("overlay geometry changed before activation".to_owned());
        }
        self.present_target.set_overlay_occluded(true);
        self.set_fallback_accessibility(FallbackAccessibility::Inactive);
        self.layer.set_opacity(1.0);
        self.layer.set_sensitive(true);
        self.layer.set_can_focus(false);
        self.content.set_sensitive(true);
        let widget = webview.webview();
        widget.set_sensitive(true);
        widget.set_can_focus(true);
        self.page_stack.set_sensitive(true);
        // Product IPC remains rejected until every native flag is in its final state. Only then
        // publish completion, focus WebKit, and flush queued read-only intents.
        if !self.state.borrow_mut().mark_presented(token) {
            return Err("stale overlay presentation token".to_owned());
        }
        widget.grab_focus();
        self.layer.queue_draw();
        log_overlay_presentation_step(token, "activated-and-focused", started);
        Ok(())
    }

    /// Present only after all independently asynchronous barriers have completed: exact modal
    /// delivery, persistent-document suppression, native GTK/WebKit allocation, and the WebKit
    /// document's matching CSS viewport. No nested GTK drain or polling is used.
    fn try_present_ready_webview(&self) {
        let (can_present, presentation_complete, token, webview) = {
            let state = self.state.borrow();
            if !state.visible || !state.persistent_suppression.is_ready() {
                return;
            }
            (
                state.delivery.can_present(),
                state.presentation_complete,
                state
                    .presentation_pending()
                    .then_some(state.presentation_token),
                state.webview.clone(),
            )
        };
        if !can_present {
            self.show_native_fallback();
            return;
        }
        if presentation_complete {
            return;
        }
        let Some(token) = token else {
            self.fail_closed_to_terminal();
            return;
        };
        let Some(webview) = webview else {
            self.fail_closed_to_terminal();
            return;
        };
        if let Err(error) = self.stage_ready_webview(token, &webview) {
            eprintln!("linux-host overlay gated stage failed: {error}");
            self.fail_closed_to_terminal();
        }
    }

    pub(crate) fn handle_native_allocation_ready(&self, event: OverlayNativeAllocationReady) {
        let webview = {
            let state = self.state.borrow();
            if !state.visible
                || !state.delivery.can_present()
                || !state.persistent_suppression.is_ready()
                || state.deadline_phase_for_token(event.token)
                    != Some(OverlayDeadlinePhase::Presentation)
            {
                return;
            }
            state.webview.clone()
        };
        let Some(webview) = webview else {
            return;
        };
        let (target, observed) = self.current_presentation_geometry(&webview);
        if !self
            .presentation_barrier
            .borrow_mut()
            .accept_native_ready(event, target, observed)
        {
            return;
        }
        match event.phase {
            OverlayNativeAllocationPhase::Containers => {
                let started = Instant::now();
                let widget = webview.webview();
                widget.set_sensitive(false);
                widget.set_can_focus(false);
                if let Err(error) = webview.set_visible(true) {
                    eprintln!(
                        "linux-host overlay inert WebView map failed token={} error={error}",
                        event.token
                    );
                    self.fail_closed_to_terminal();
                    return;
                }
                log_overlay_presentation_step(event.token, "webview-mapped-inert", started);
                widget.queue_resize();
                widget.queue_draw();
                self.observe_current_presentation_geometry(&webview);
            }
            OverlayNativeAllocationPhase::WebView => {
                let script = overlay_viewport_barrier_script(event.token, event.target);
                if let Err(error) = webview.evaluate_script(&script) {
                    eprintln!(
                        "linux-host overlay viewport barrier dispatch failed token={} error={error}",
                        event.token
                    );
                    self.fail_closed_to_terminal();
                }
            }
        }
    }

    pub(crate) fn handle_viewport_ready(&self, event: OverlayViewportReady) {
        let webview = {
            let state = self.state.borrow();
            if !state.visible
                || !state.delivery.can_present()
                || !state.persistent_suppression.is_ready()
                || state.deadline_phase_for_token(event.token)
                    != Some(OverlayDeadlinePhase::Presentation)
            {
                return;
            }
            state.webview.clone()
        };
        let Some(webview) = webview else {
            return;
        };
        let (target, observed) = self.current_presentation_geometry(&webview);
        let Some(target) = self
            .presentation_barrier
            .borrow_mut()
            .accept_viewport_ready(event, target, observed)
        else {
            return;
        };
        if let Err(error) = self.activate_ready_webview(event.token, target, &webview) {
            eprintln!("linux-host overlay gated activation failed: {error}");
            self.fail_closed_to_terminal();
            return;
        }
        self.flush_presented_product_intents();
        self.cancel_presentation_timeout();
    }

    fn flush_presented_product_intents(&self) {
        let intents = self.state.borrow_mut().take_presented_product_intents();
        if intents.is_empty() {
            return;
        }
        let count = intents.len();
        let Some(events) = self.events.as_ref() else {
            eprintln!(
                "linux-host overlay queued ipc intents dropped: no event channel count={count}"
            );
            return;
        };
        for json in intents {
            if events
                .send(RendererEvent::ReactChromeIntent { json })
                .is_err()
            {
                eprintln!(
                    "linux-host overlay queued ipc intents dropped: receiver closed count={count}"
                );
                return;
            }
        }
        eprintln!("linux-host overlay queued ipc intents delivered count={count}");
    }

    fn show_native_fallback(&self) {
        let webview = self.state.borrow().webview.clone();
        self.cancel_viewport_observer(webview.as_deref());
        self.present_target.set_overlay_occluded(true);
        self.layer.set_opacity(1.0);
        self.layer.set_sensitive(true);
        self.layer.set_can_focus(true);
        self.layer.show();
        self.layer.grab_focus();
        self.top_level.queue_draw();
    }

    /// Select the inert page before hiding WebKit, disconnecting its embedding socket from the
    /// GtkStackAccessible tree without unparenting or unrealizing the retained WebView. Its
    /// document, WebContext, backing store, script cache, and recovery generation stay intact.
    /// `keep_fallback_visible` is used while an active modal is loading/recovering so keys cannot
    /// leak to the terminal below it.
    fn park_webview(&self, webview: Option<&wry::WebView>, keep_fallback_visible: bool) {
        let started = Instant::now();
        let token = self.state.borrow().presentation_token;
        log_overlay_presentation_step(token, "park-begin", started);
        self.cancel_viewport_observer(webview);
        self.parking_page.show();
        self.page_stack.set_visible_child(&self.parking_page);
        self.page_stack.set_sensitive(false);
        log_overlay_presentation_step(token, "park-page-switched", started);

        if let Some(webview) = webview {
            let widget = webview.webview();
            widget.set_can_focus(false);
            widget.set_sensitive(false);
            if widget.is_visible() {
                if let Err(err) = webview.set_visible(false) {
                    eprintln!("linux-host overlay hide failed: {err}");
                }
            }
        }
        log_overlay_presentation_step(token, "park-webview-hidden", started);

        self.content.set_sensitive(false);
        self.content.hide();

        self.layer.set_sensitive(keep_fallback_visible);
        self.layer.set_can_focus(keep_fallback_visible);
        self.layer.set_opacity(1.0);
        if keep_fallback_visible {
            self.layer.show();
            self.layer.grab_focus();
        } else {
            // A visible product modal may deliberately keep this native fallback hidden until the
            // persistent documents confirm `inert`. Preserve its Loading/Recovering semantics for
            // the later gated show; only a genuinely hidden modal retires the fallback role.
            if !self.state.borrow().visible {
                self.set_fallback_accessibility(FallbackAccessibility::Inactive);
            }
            self.layer.hide();
        }
        log_overlay_presentation_step(token, "park-layer-updated", started);
        self.layer.queue_resize();
        self.layer.queue_draw();
    }

    fn mark_overlay_react_ready(&self) {
        let (webview, evaluation, visible, duplicate, presentation_token) = {
            let mut state = self.state.borrow_mut();
            let was_ready = state.delivery.react_ready;
            let evaluation = state.delivery.react_ready();
            let presentation_token = if !was_ready
                && evaluation
                    .as_ref()
                    .is_some_and(|evaluation| evaluation.modal_attempt.is_some())
            {
                state.promote_cold_load_to_presentation()
            } else {
                None
            };
            (
                state.webview.clone(),
                evaluation,
                state.visible,
                was_ready,
                presentation_token,
            )
        };
        let Some(webview) = webview else {
            eprintln!("linux-host overlay React ready arrived before WebView attachment");
            return;
        };
        let Some(evaluation) = evaluation else {
            eprintln!(
                "linux-host dashboard overlay React ready visible={visible} duplicate={duplicate}"
            );
            return;
        };
        if evaluation.modal_attempt.is_none() && visible {
            eprintln!("linux-host overlay ready refused reason=no-cached-modal");
            self.fail_closed_to_terminal();
            return;
        }
        if let Some(token) = presentation_token {
            // The exact ready marker is the ownership boundary. Only now capture focus, start the
            // short presentation join, and suppress the native terminal/sidebar/topbar.
            *self.previous_focus.borrow_mut() = self.top_level.focused_widget();
            self.arm_overlay_timeout_source(token, MODAL_PRESENTATION_TIMEOUT);
            self.set_fallback_accessibility(FallbackAccessibility::Loading);
            self.suppress_underlay_inputs();
            self.park_webview(Some(&webview), false);
            self.present_target.set_overlay_occluded(false);
            self.top_level.queue_draw();
        }
        // Submit the current model and modal in one JavaScript task. Visibility remains parked
        // until the exact modal-bearing task reports completion back through the owner-loop FIFO.
        self.submit_evaluation(&webview, evaluation);
        eprintln!(
            "linux-host dashboard overlay React ready visible={visible} duplicate={duplicate}"
        );
    }

    pub(crate) fn handle_evaluation_result(&self, result: OverlayEvaluationResult) {
        let decision = {
            let mut state = self.state.borrow_mut();
            state.delivery.finish_modal_evaluation(result)
        };
        match decision {
            ModalEvaluationDecision::Delivered => self.try_present_ready_webview(),
            ModalEvaluationDecision::Failed => {
                eprintln!(
                    "linux-host overlay modal delivery failed attempt={} reason=javascript-evaluation",
                    result.attempt
                );
                self.fail_closed_to_terminal();
            }
            ModalEvaluationDecision::Stale => eprintln!(
                "linux-host overlay modal delivery ignored attempt={} reason=stale",
                result.attempt
            ),
        }
    }

    pub(crate) fn handle_persistent_suppression_result(&self, result: PersistentSuppressionResult) {
        let decision = self
            .state
            .borrow_mut()
            .persistent_suppression
            .finish(result);
        match decision {
            PersistentSuppressionDecision::Ready => {
                eprintln!(
                    "linux-host persistent modal suppression ready epoch={}",
                    result.epoch
                );
                self.try_present_ready_webview();
            }
            PersistentSuppressionDecision::Failed => {
                eprintln!(
                    "linux-host persistent modal suppression failed epoch={} index={}",
                    result.epoch, result.index
                );
                self.fail_closed_to_terminal();
            }
            PersistentSuppressionDecision::Stale => eprintln!(
                "linux-host persistent modal suppression ignored epoch={} index={} reason=stale",
                result.epoch, result.index
            ),
            PersistentSuppressionDecision::Pending => {}
        }
    }

    pub(crate) fn handle_presentation_timeout(&self, token: u64) {
        let phase = self.state.borrow().deadline_phase_for_token(token);
        match phase {
            Some(OverlayDeadlinePhase::ColdLoad) => {
                eprintln!("linux-host overlay cold load timed out token={token}");
                self.fail_closed_to_terminal();
            }
            Some(OverlayDeadlinePhase::Presentation) => {
                eprintln!("linux-host modal presentation timed out token={token}");
                self.fail_closed_to_terminal();
            }
            Some(OverlayDeadlinePhase::Idle) | None => {}
        }
    }

    /// Advance overlay recovery on the Tao owner loop. WebKit callbacks only enqueue this event;
    /// every reload/visibility/focus operation below is therefore ordered with host teardown.
    pub(crate) fn handle_recovery_event(&self, event: WebKitRecoveryEvent) {
        match event {
            WebKitRecoveryEvent::Failure {
                surface: WebKitSurface::Overlay,
                generation,
                reason,
            } => {
                let (decision, was_visible, webview) = {
                    let mut state = self.state.borrow_mut();
                    let was_visible = state.visible;
                    let decision = state.recovery.on_failure(generation);
                    if matches!(
                        decision,
                        RecoveryDecision::Dispatch { .. } | RecoveryDecision::Exhausted
                    ) {
                        state.delivery.page_started();
                        state.clear_pending_product_intents();
                    }
                    if decision == RecoveryDecision::Exhausted {
                        state.visible = false;
                        state.delivery.hide();
                    }
                    (decision, was_visible, state.webview.clone())
                };

                match decision {
                    RecoveryDecision::Dispatch {
                        attempt,
                        generation,
                    } => {
                        if let Some(webview) = webview {
                            let Some(recovery_url) =
                                overlay_recovery_url(&self.overlay_url, generation)
                            else {
                                eprintln!(
                                    "linux-host overlay recovery phase=invalid-canonical-url bundled=false bytes={} attempt={attempt} generation={generation}",
                                    self.overlay_url.len()
                                );
                                self.fail_closed_to_terminal();
                                return;
                            };
                            // Keep keyboard focus inside the labeled native fallback while a visible
                            // modal recovers. The stale document remains permanently parented behind
                            // the inert GtkStack page.
                            if was_visible {
                                self.ensure_presentation_timeout();
                                self.set_fallback_accessibility(
                                    FallbackAccessibility::Recovering,
                                );
                                self.suppress_underlay_inputs();
                            }
                            let suppression_ready = self
                                .state
                                .borrow()
                                .persistent_suppression
                                .is_ready();
                            self.park_webview(
                                Some(&webview),
                                was_visible && suppression_ready,
                            );
                            self.recovery_tracker
                                .borrow_mut()
                                .prepare_load(generation);
                            eprintln!(
                                "linux-host overlay recovery phase=dispatch bundled=true bytes={} reason={reason:?} attempt={attempt} generation={generation}",
                                self.overlay_url.len()
                            );
                            // Host-generated private URL only; never use WebKit's failing URI.
                            webview.webview().load_uri(&recovery_url);
                        }
                    }
                    RecoveryDecision::Coalesced => eprintln!(
                        "linux-host overlay recovery phase=coalesced bundled=true bytes={} reason={reason:?}",
                        self.overlay_url.len()
                    ),
                    RecoveryDecision::Exhausted => {
                        // The hidden final document must lose IPC/navigation authority before any
                        // later WebKit callback can run. Recovery exhaustion is permanent for this
                        // lazily-created WebView instance.
                        self.recovery_tracker.borrow_mut().shut_down();
                        self.park_webview(webview.as_deref(), false);
                        self.restore_underlay_inputs();
                        if was_visible {
                            self.present_target.set_overlay_occluded(false);
                            self.top_level.queue_draw();
                            restore_focus(&self.previous_focus, &self.terminal_slot);
                        }
                        eprintln!(
                            "linux-host overlay recovery phase=exhausted bundled=true bytes={} reason={reason:?} attempts={MAX_WEBKIT_RECOVERY_ATTEMPTS} visible={was_visible}",
                            self.overlay_url.len()
                        );
                    }
                    RecoveryDecision::Inactive => {}
                }
            }
            WebKitRecoveryEvent::PageStarted {
                surface: WebKitSurface::Overlay,
                generation,
                bundled,
            } => {
                let is_current =
                    bundled && generation == Some(self.state.borrow().recovery.generation());
                if is_current {
                    let webview = {
                        let mut state = self.state.borrow_mut();
                        state.delivery.page_started();
                        state.clear_pending_product_intents();
                        state.webview.clone()
                    };
                    let visible = self.state.borrow().visible;
                    if visible {
                        self.ensure_presentation_timeout();
                        let fallback = if generation.unwrap_or_default() == 0 {
                            FallbackAccessibility::Loading
                        } else {
                            FallbackAccessibility::Recovering
                        };
                        self.set_fallback_accessibility(fallback);
                        self.suppress_underlay_inputs();
                    }
                    let suppression_ready = self.state.borrow().persistent_suppression.is_ready();
                    self.park_webview(webview.as_deref(), visible && suppression_ready);
                }
            }
            WebKitRecoveryEvent::PageFinished {
                surface: WebKitSurface::Overlay,
                generation,
                bundled,
            } => {
                let is_current =
                    bundled && generation == Some(self.state.borrow().recovery.generation());
                if is_current {
                    let scripts = self.state.borrow_mut().delivery.page_finished();
                    debug_assert!(scripts.is_empty());
                }
            }
            WebKitRecoveryEvent::OverlayReady { generation } => {
                let accepted = self
                    .state
                    .borrow_mut()
                    .recovery
                    .on_exact_page_finished(generation);
                if accepted {
                    self.mark_overlay_react_ready();
                } else {
                    eprintln!(
                        "linux-host overlay recovery phase=stale-ready bundled=true bytes={} generation={generation:?}",
                        self.overlay_url.len()
                    );
                }
            }
            _ => {}
        }
    }

    /// Idempotently close both owner and signal-side recovery state before WebKit objects drop.
    pub(crate) fn shut_down_recovery(&self) {
        self.state.borrow_mut().recovery.shut_down();
        self.recovery_tracker.borrow_mut().shut_down();
    }

    fn submit_evaluation(&self, webview: &wry::WebView, evaluation: OverlayEvaluation) {
        let Some(attempt) = evaluation.modal_attempt else {
            evaluate_overlay_script_batch(webview, &evaluation.scripts);
            return;
        };

        let script = modal_delivery_script(&evaluation.scripts);
        let proxy = self.wake_proxy.clone();
        let callback = move |result: String| {
            let succeeded = overlay_delivery_succeeded(&result);
            let _ = proxy.send_event(LinuxLoopEvent::OverlayEvaluation(OverlayEvaluationResult {
                attempt,
                succeeded,
            }));
        };
        if let Err(err) = webview.evaluate_script_with_callback(&script, callback) {
            eprintln!(
                "linux-host overlay modal delivery dispatch failed attempt={attempt} bytes={} error={err}",
                script.len()
            );
            self.handle_evaluation_result(OverlayEvaluationResult {
                attempt,
                succeeded: false,
            });
        } else {
            eprintln!(
                "linux-host overlay modal delivery dispatched attempt={attempt} count={} bytes={}",
                evaluation.scripts.len(),
                script.len()
            );
        }
    }

    fn ensure_created(&self) -> Result<(), String> {
        if self.state.borrow().webview.is_some() {
            return Ok(());
        }
        let creation_started = std::time::Instant::now();

        let ready_tracker = Rc::downgrade(&self.recovery_tracker);
        let ready_sender = webkit_recovery_sender(self.wake_proxy.clone());
        let ipc_events = self.events.clone();
        let viewport_proxy = self.wake_proxy.clone();
        let expected_navigation = self.overlay_url.clone();
        let expected_ipc = self.overlay_url.clone();
        let expected_page_load = self.overlay_url.clone();
        let navigation_state = Rc::downgrade(&self.state);
        let navigation_tracker = Rc::downgrade(&self.recovery_tracker);
        let navigation_recovery_sender = webkit_recovery_sender(self.wake_proxy.clone());
        let ipc_state = Rc::downgrade(&self.state);
        let page_state = Rc::downgrade(&self.state);
        let overlay_url = self.overlay_url.clone();
        let input_trace_enabled = self.input_trace_enabled;
        let build_result = {
            let mut context = self.web_context.borrow_mut();
            WebViewBuilder::new_with_web_context(&mut context)
                .with_related_view(self.related_webview.webview())
                .with_url(overlay_url)
                .with_visible(false)
                .with_focused(false)
                .with_transparent(true)
                .with_background_color((0, 0, 0, 0))
                .with_devtools(cfg!(debug_assertions))
                .with_clipboard(true)
                .with_initialization_script(self.initialization_script.clone())
                .with_navigation_handler(move |candidate| {
                    let current_generation = navigation_state
                        .upgrade()
                        .map(|state| state.borrow().recovery.generation());
                    let document_generation =
                        parse_overlay_document_generation(&candidate, &expected_navigation);
                    let (allowed, unpermitted_current) = current_generation
                        .zip(document_generation)
                        .map_or((false, None), |(current_generation, document)| {
                            if !overlay_document_is_current(document, current_generation) {
                                return (false, None);
                            }
                            let Some(tracker) = navigation_tracker.upgrade() else {
                                return (false, None);
                            };
                            let mut tracker = tracker.borrow_mut();
                            if tracker.claim_navigation(document.value()) {
                                (true, None)
                            } else {
                                (
                                    false,
                                    tracker.unpermitted_current_navigation(document.value()),
                                )
                            }
                        });
                    if !allowed {
                        eprintln!(
                            "linux-host overlay navigation blocked bytes={}",
                            candidate.len()
                        );
                        if let Some(generation) = unpermitted_current {
                            navigation_recovery_sender.send(WebKitRecoveryEvent::Failure {
                                surface: WebKitSurface::Overlay,
                                generation: Some(generation),
                                reason: WebKitFailureReason::EngineReloadRequested,
                            });
                        }
                    }
                    allowed
                })
                .with_new_window_req_handler(|url, _| {
                    eprintln!("linux-host overlay popup blocked bytes={}", url.len());
                    NewWindowResponse::Deny
                })
                .with_download_started_handler(|url, _| {
                    eprintln!("linux-host overlay download blocked bytes={}", url.len());
                    false
                })
                .with_ipc_handler(move |request| {
                    let request_uri = request.uri().to_string();
                    let current_generation = ipc_state
                        .upgrade()
                        .map(|state| state.borrow().recovery.generation());
                    let document_generation =
                        parse_overlay_document_generation(&request_uri, &expected_ipc)
                            .map(OverlayDocumentGeneration::value);
                    let owned_generation = document_generation.filter(|generation| {
                        ready_tracker.upgrade().is_some_and(|tracker| {
                            tracker.borrow().owns_generation(*generation)
                        })
                    });
                    let trusted = current_generation.is_some_and(|current_generation| {
                        overlay_ipc_is_trusted(
                            &request_uri,
                            &expected_ipc,
                            current_generation,
                            owned_generation,
                        )
                    });
                    if !trusted {
                        eprintln!(
                            "linux-host overlay ipc rejected: untrusted_page uri_bytes={} payload_bytes={}",
                            request_uri.len(),
                            request.body().len()
                        );
                        return;
                    }
                    if request.body().len() > MAX_OVERLAY_IPC_BYTES {
                        eprintln!(
                            "linux-host overlay ipc dropped bytes={} cap={MAX_OVERLAY_IPC_BYTES}",
                            request.body().len()
                        );
                        return;
                    }
                    let json = request.body().to_string();
                    match route_overlay_input_trace(&json, input_trace_enabled) {
                        OverlayInputTraceRoute::NotTrace => {}
                        OverlayInputTraceRoute::Disabled => return,
                        OverlayInputTraceRoute::Rejected => {
                            eprintln!("linux-host overlay input trace rejected");
                            return;
                        }
                        OverlayInputTraceRoute::Accepted(trace) => {
                            log_overlay_input_trace(&trace);
                            return;
                        }
                    }
                    if is_overlay_viewport_ready_payload(&json) {
                        let Some(ready) = overlay_viewport_ready(&json) else {
                            eprintln!("linux-host overlay viewport acknowledgement rejected");
                            return;
                        };
                        let _ =
                            viewport_proxy.send_event(LinuxLoopEvent::OverlayViewportReady(ready));
                        return;
                    }
                    let ready_generation = dashboard_overlay_ready_generation(&json);
                    let ready = ready_generation.is_some();
                    eprintln!(
                        "linux-host overlay ipc intent bytes={} ready={ready}",
                        json.len()
                    );
                    let forwarded_json = if let Some(claimed_generation) = ready_generation {
                        let Some(document) =
                            parse_overlay_document_generation(&request_uri, &expected_ipc)
                        else {
                            eprintln!(
                                "linux-host overlay ipc ready rejected: invalid_document uri_bytes={} payload_bytes={}",
                                request_uri.len(),
                                json.len()
                            );
                            return;
                        };
                        let Some((generation, forwarded_json)) =
                            authenticated_overlay_ready(document, claimed_generation)
                        else {
                            eprintln!(
                                "linux-host overlay ipc ready rejected: generation_mismatch uri_bytes={} payload_bytes={}",
                                request_uri.len(),
                                json.len()
                            );
                            return;
                        };
                        let ready_decision = ready_tracker.upgrade().map_or(
                            RecoveryReadyDecision::Rejected,
                            |tracker| tracker.borrow_mut().record_typed_ready(generation),
                        );
                        match ready_decision {
                            RecoveryReadyDecision::Deliver => {
                                ready_sender.send(WebKitRecoveryEvent::OverlayReady {
                                    generation: Some(generation),
                                });
                            }
                            RecoveryReadyDecision::PendingFinish => eprintln!(
                                "linux-host overlay ipc ready pending exact finish generation={generation}"
                            ),
                            RecoveryReadyDecision::Rejected => {
                                eprintln!(
                                    "linux-host overlay ipc ready rejected: stale_or_duplicate uri_bytes={} payload_bytes={}",
                                    request_uri.len(),
                                    json.len()
                                );
                                return;
                            }
                        }
                        // The generation is a Linux host/recovery concern. Keep the shared typed app
                        // schema byte-for-byte unchanged after host-side authentication.
                        Some(forwarded_json.to_owned())
                    } else {
                        let route = ipc_state.upgrade().map_or(
                            ProductIntentRoute::RejectedNotPresented,
                            |state| state.borrow_mut().route_product_intent(json),
                        );
                        match route {
                            ProductIntentRoute::Forward(json) => Some(json),
                            ProductIntentRoute::Queued => {
                                eprintln!(
                                    "linux-host overlay ipc intent queued: awaiting_presentation"
                                );
                                None
                            }
                            ProductIntentRoute::RejectedNotPresented => {
                                eprintln!(
                                    "linux-host overlay ipc intent rejected: not_presented"
                                );
                                return;
                            }
                            ProductIntentRoute::RejectedCapacity => {
                                eprintln!(
                                    "linux-host overlay ipc intent rejected: pending_capacity"
                                );
                                return;
                            }
                        }
                    };
                    let Some(forwarded_json) = forwarded_json else {
                        return;
                    };
                    if let Some(events) = ipc_events.as_ref() {
                        if events
                            .send(RendererEvent::ReactChromeIntent {
                                json: forwarded_json,
                            })
                            .is_err()
                        {
                            eprintln!("linux-host overlay ipc intent dropped: receiver closed");
                        }
                    } else {
                        eprintln!("linux-host overlay ipc intent dropped: no event channel");
                    }
                })
                .with_on_page_load_handler({
                    let page_tracker = Rc::downgrade(&self.recovery_tracker);
                    let page_sender = webkit_recovery_sender(self.wake_proxy.clone());
                    move |event, url| {
                        let current_generation = page_state
                            .upgrade()
                            .map(|state| state.borrow().recovery.generation());
                        let document_generation =
                            parse_overlay_document_generation(&url, &expected_page_load);
                        let document_generation = current_generation
                            .zip(document_generation)
                            .filter(|(current, document)| {
                                overlay_document_is_current(*document, *current)
                            })
                            .map(|(_, document)| document.value());
                        let (phase, generation, recovery_event, ready_after_finish) = match event {
                            wry::PageLoadEvent::Started => {
                                let generation = page_tracker
                                    .upgrade()
                                    .and_then(|tracker| {
                                        tracker.borrow_mut().page_started(document_generation)
                                    });
                                let bundled = generation.is_some();
                                (
                                    "started",
                                    generation,
                                    WebKitRecoveryEvent::PageStarted {
                                        surface: WebKitSurface::Overlay,
                                        generation,
                                        bundled,
                                    },
                                    None,
                                )
                            }
                            wry::PageLoadEvent::Finished => {
                                let (generation, ready_after_finish) = page_tracker
                                    .upgrade()
                                    .map(|tracker| {
                                        let mut tracker = tracker.borrow_mut();
                                        let generation = tracker.page_finished(document_generation);
                                        let ready_after_finish = generation.filter(|generation| {
                                            tracker.take_pending_ready_after_finish(*generation)
                                        });
                                        (generation, ready_after_finish)
                                    })
                                    .unwrap_or((None, None));
                                let bundled = generation.is_some();
                                (
                                    "finished",
                                    generation,
                                    WebKitRecoveryEvent::PageFinished {
                                        surface: WebKitSurface::Overlay,
                                        generation,
                                        bundled,
                                    },
                                    ready_after_finish,
                                )
                            }
                        };
                        let bundled = generation.is_some();
                        eprintln!(
                            "linux-host overlay page load phase={phase} bundled={bundled} bytes={} generation={:?}",
                            url.len(), generation
                        );
                        page_sender.send(recovery_event);
                        if let Some(generation) = ready_after_finish {
                            // Preserve callback FIFO: the owner observes exact Finished before the
                            // early React marker is released for recovery completion/replay.
                            page_sender.send(WebKitRecoveryEvent::OverlayReady {
                                generation: Some(generation),
                            });
                        }
                    }
                })
                .build_gtk(&self.content)
        };

        let webview = Rc::new(build_result.map_err(|err| err.to_string())?);
        let inner = webview.webview();
        inner.set_can_focus(false);
        inner.set_sensitive(false);
        if inner.is_visible() {
            if let Err(err) = webview.set_visible(false) {
                eprintln!("linux-host overlay initial hide failed: {err}");
            }
        }
        let webview_widget: gtk::Widget = inner.clone().upcast();
        install_overlay_widget_geometry_trace("webview", &webview_widget);
        install_overlay_surface_allocation_barrier(
            OverlayAllocationSurface::WebView,
            &webview_widget,
            &self.composition,
            &self.presentation_barrier,
            &self.wake_proxy,
        );

        let crash_tracker = Rc::downgrade(&self.recovery_tracker);
        let crash_sender = webkit_recovery_sender(self.wake_proxy.clone());
        let canonical_bytes = self.overlay_url.len();
        inner.connect_web_process_terminated(move |_, reason| {
            let generation = crash_tracker
                .upgrade()
                .and_then(|tracker| tracker.borrow_mut().failed_current_process());
            eprintln!(
                "linux-host overlay recovery signal phase=terminated bundled=true bytes={canonical_bytes} reason={reason:?}"
            );
            let Some(generation) = generation else {
                eprintln!(
                    "linux-host overlay recovery signal ignored phase=terminated reason=unattributed"
                );
                return;
            };
            crash_sender.send(WebKitRecoveryEvent::Failure {
                surface: WebKitSurface::Overlay,
                generation: Some(generation),
                reason: WebKitFailureReason::ProcessTerminated,
            });
        });

        let fail_tracker = Rc::downgrade(&self.recovery_tracker);
        let fail_sender = webkit_recovery_sender(self.wake_proxy.clone());
        let canonical_fail_url = self.overlay_url.clone();
        inner.connect_load_failed(move |_, _event, failing_uri, _error| {
            let generation = parse_overlay_document_generation(
                failing_uri,
                &canonical_fail_url,
            )
            .map(OverlayDocumentGeneration::value)
            .and_then(|generation| {
                fail_tracker
                    .upgrade()
                    .and_then(|tracker| tracker.borrow_mut().failed_generation(generation))
            });
            let Some(generation) = generation else {
                eprintln!(
                    "linux-host overlay recovery signal ignored phase=load-failed bundled=false bytes={} reason=load-failed",
                    failing_uri.len()
                );
                // Suppress WebKit's error page, but never let a foreign/stale failure consume a
                // canonical generation marker or spend the bounded retry budget.
                return true;
            };
            eprintln!(
                "linux-host overlay recovery signal phase=load-failed bundled=true bytes={} reason=load-failed",
                failing_uri.len()
            );
            fail_sender.send(WebKitRecoveryEvent::Failure {
                surface: WebKitSurface::Overlay,
                generation: Some(generation),
                reason: WebKitFailureReason::LoadFailed,
            });
            true
        });

        let redraw_view = inner.downgrade();
        self.content.connect_size_allocate(move |_, _| {
            if let Some(view) = redraw_view.upgrade() {
                view.queue_draw();
            }
        });

        let evaluation = {
            let mut state = self.state.borrow_mut();
            state.webview = Some(webview.clone());
            state.delivery.attach_webview()
        };
        if let Some(evaluation) = evaluation {
            self.submit_evaluation(&webview, evaluation);
        }
        let ready = {
            let state = self.state.borrow();
            state.delivery.react_ready
        };
        self.park_webview(Some(&webview), false);
        self.try_present_ready_webview();
        eprintln!(
            "linux-host dashboard overlay WebView mounted lazily ready={ready} elapsed_ms={}",
            creation_started.elapsed().as_millis()
        );
        Ok(())
    }
}

impl Drop for LinuxOverlayHost {
    fn drop(&mut self) {
        // Belt-and-braces for construction failures or callers which never enter `run`.
        self.state.borrow_mut().recovery.shut_down();
        self.recovery_tracker.borrow_mut().shut_down();
        self.presentation_barrier.borrow_mut().cancel();
        self.presentation_timeout.borrow_mut().cancel();
        self.restore_underlay_inputs();
    }
}

fn restore_focus(
    previous_focus: &Rc<RefCell<Option<gtk::Widget>>>,
    terminal_slot: &gtk::DrawingArea,
) {
    if let Some(widget) = previous_focus.borrow_mut().take() {
        if widget.is_visible() && widget.is_sensitive() {
            widget.grab_focus();
            return;
        }
    }
    terminal_slot.grab_focus();
}

fn evaluate_overlay_script(webview: &wry::WebView, script: &str) {
    match webview.evaluate_script(script) {
        Ok(()) => eprintln!("linux-host overlay script evaluated bytes={}", script.len()),
        Err(err) => eprintln!("linux-host overlay script eval failed: {err}"),
    }
}

fn evaluate_overlay_script_batch(webview: &wry::WebView, scripts: &[String]) {
    if scripts.is_empty() {
        return;
    }
    let batch = scripts.join("\n");
    match webview.evaluate_script(&batch) {
        Ok(()) => eprintln!(
            "linux-host overlay script batch evaluated count={} bytes={}",
            scripts.len(),
            batch.len()
        ),
        Err(err) => eprintln!(
            "linux-host overlay script batch eval failed count={} bytes={} error={err}",
            scripts.len(),
            batch.len()
        ),
    }
}

fn modal_delivery_script(scripts: &[String]) -> String {
    let body = scripts.join("\n");
    let success = serde_json::to_string(DELIVERY_SUCCESS_SENTINEL)
        .expect("overlay delivery sentinel serializes");
    format!(
        "(function () {{ \"use strict\"; try {{\n{body}\nreturn {success};\n}} catch (_) {{ return null; }} }})()"
    )
}

fn overlay_delivery_succeeded(result_json: &str) -> bool {
    serde_json::from_str::<String>(result_json)
        .is_ok_and(|value| value == DELIVERY_SUCCESS_SENTINEL)
}

fn persistent_suppression_succeeded(result_json: &str) -> bool {
    serde_json::from_str::<String>(result_json)
        .is_ok_and(|value| value == PERSISTENT_SUPPRESSION_SUCCESS_SENTINEL)
}

fn overlay_viewport_barrier_script(token: u64, target: OverlayGeometry) -> String {
    let kind = serde_json::to_string(OVERLAY_VIEWPORT_READY_TYPE)
        .expect("overlay viewport acknowledgement type serializes");
    format!(
        r#"
(function () {{
  "use strict";
  var previous = window.__HYDRA_LINUX_OVERLAY_VIEWPORT_BARRIER__;
  if (previous && typeof previous.cancel === "function") previous.cancel();
  var done = false;
  var observer = null;
  var firstFrame = 0;
  var secondFrame = 0;
  function exactSize() {{
    return Math.round(window.innerWidth) === {width}
      && Math.round(window.innerHeight) === {height};
  }}
  function cancelFrames() {{
    if (firstFrame) window.cancelAnimationFrame(firstFrame);
    if (secondFrame) window.cancelAnimationFrame(secondFrame);
    firstFrame = 0;
    secondFrame = 0;
  }}
  function cancel() {{
    if (done) return;
    done = true;
    cancelFrames();
    if (observer) observer.disconnect();
    window.removeEventListener("resize", schedule);
  }}
  function acknowledge() {{
    if (done) return;
    var width = Math.round(window.innerWidth);
    var height = Math.round(window.innerHeight);
    if (width !== {width} || height !== {height}) return;
    cancel();
    delete window.__HYDRA_LINUX_OVERLAY_VIEWPORT_BARRIER__;
    window.ipc.postMessage(JSON.stringify({{
      type: {kind},
      presentation_token: {token},
      width: width,
      height: height
    }}));
  }}
  function schedule() {{
    if (done) return;
    cancelFrames();
    firstFrame = window.requestAnimationFrame(function () {{
      firstFrame = 0;
      if (!exactSize()) return;
      secondFrame = window.requestAnimationFrame(function () {{
        secondFrame = 0;
        if (exactSize()) acknowledge();
      }});
    }});
  }}
  if (typeof ResizeObserver === "function") {{
    observer = new ResizeObserver(schedule);
    observer.observe(document.documentElement);
  }}
  window.addEventListener("resize", schedule);
  window.__HYDRA_LINUX_OVERLAY_VIEWPORT_BARRIER__ = {{ cancel: cancel }};
  schedule();
}})();
"#,
        width = target.width,
        height = target.height,
    )
}

fn persistent_restore_script(restore_focus: bool) -> String {
    RESTORE_PERSISTENT_DOCUMENTS_SCRIPT.replace(
        "__HYDRA_RESTORE_DOM_FOCUS__",
        if restore_focus { "true" } else { "false" },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODEL_V1: &str = "window.__HYDRA_DASHBOARD_SET_MODEL__({\"v\":1});";
    const MODEL_V2: &str = "window.__HYDRA_DASHBOARD_SET_MODEL__({\"v\":2});";
    const MODAL_ONE: &str = "window.__HYDRA_SHOW_OVERLAY_MODAL__({kind:'newProject',version:1});";
    const MODAL_TWO: &str = "window.__HYDRA_SHOW_OVERLAY_MODAL__({kind:'newProject',version:2});";

    #[test]
    fn overlay_event_mask_selects_discrete_and_smooth_scroll() {
        let mask = overlay_event_mask();
        assert!(mask.contains(gtk::gdk::EventMask::SCROLL_MASK));
        assert!(mask.contains(gtk::gdk::EventMask::SMOOTH_SCROLL_MASK));
        assert!(mask.contains(gtk::gdk::EventMask::BUTTON_PRESS_MASK));
        assert!(mask.contains(gtk::gdk::EventMask::KEY_PRESS_MASK));
    }

    #[test]
    fn document_page_requires_visibility_readiness_and_delivered_cached_modal() {
        let mut delivery = OverlayDelivery::default();
        assert_eq!(overlay_page(true, &delivery), OverlayPage::Parking);

        delivery.attach_webview();
        assert!(delivery
            .remember(MODAL_ONE, ReactChromeScriptKind::Modal, true)
            .is_none());
        let evaluation = delivery.react_ready().expect("ready releases modal");
        let attempt = evaluation.modal_attempt.expect("modal attempt");
        assert!(delivery.has_active_modal());
        assert_eq!(overlay_page(true, &delivery), OverlayPage::Parking);

        assert_eq!(
            delivery.finish_modal_evaluation(OverlayEvaluationResult {
                attempt,
                succeeded: true,
            }),
            ModalEvaluationDecision::Delivered
        );
        assert_eq!(overlay_page(false, &delivery), OverlayPage::Parking);
        assert_eq!(overlay_page(true, &delivery), OverlayPage::Document);
    }

    #[test]
    fn underlay_interactivity_is_captured_once_and_restored_exactly() {
        let original = UnderlayInteractivitySnapshot {
            containers: vec![WidgetInteractivity {
                sensitive: true,
                can_focus: false,
            }],
            webviews: vec![
                WidgetInteractivity {
                    sensitive: true,
                    can_focus: true,
                },
                WidgetInteractivity {
                    sensitive: false,
                    can_focus: true,
                },
            ],
            terminal: WidgetInteractivity {
                sensitive: true,
                can_focus: true,
            },
            restore_focus_webview: Some(1),
        };
        let mut state = UnderlayInteractivityState::default();
        state.capture_once(original.clone());
        state.capture_once(UnderlayInteractivitySnapshot {
            containers: vec![WidgetInteractivity {
                sensitive: false,
                can_focus: false,
            }],
            webviews: vec![
                WidgetInteractivity {
                    sensitive: false,
                    can_focus: false,
                },
                WidgetInteractivity {
                    sensitive: false,
                    can_focus: false,
                },
            ],
            terminal: WidgetInteractivity {
                sensitive: false,
                can_focus: false,
            },
            restore_focus_webview: None,
        });

        assert_eq!(state.take_for_restore(), Some(original));
        assert_eq!(state.take_for_restore(), None);
    }

    #[test]
    fn persistent_document_scripts_preserve_prior_root_accessibility_state() {
        assert!(SUPPRESS_PERSISTENT_DOCUMENTS_SCRIPT.contains("\"inert\" in root"));
        assert!(SUPPRESS_PERSISTENT_DOCUMENTS_SCRIPT.contains("root.inert = true"));
        assert!(SUPPRESS_PERSISTENT_DOCUMENTS_SCRIPT.contains("root.inert !== true"));
        assert!(SUPPRESS_PERSISTENT_DOCUMENTS_SCRIPT.contains("aria-hidden"));
        assert!(SUPPRESS_PERSISTENT_DOCUMENTS_SCRIPT.contains("active.blur"));
        assert!(SUPPRESS_PERSISTENT_DOCUMENTS_SCRIPT.contains("activeElement: active"));
        let activate = SUPPRESS_PERSISTENT_DOCUMENTS_SCRIPT
            .find("firewall.active = true")
            .unwrap();
        let blur = SUPPRESS_PERSISTENT_DOCUMENTS_SCRIPT
            .find("active.blur")
            .unwrap();
        assert!(activate < blur);
        assert!(
            SUPPRESS_PERSISTENT_DOCUMENTS_SCRIPT.contains(PERSISTENT_SUPPRESSION_SUCCESS_SENTINEL)
        );
        assert!(RESTORE_PERSISTENT_DOCUMENTS_SCRIPT.contains("saved.inert"));
        assert!(RESTORE_PERSISTENT_DOCUMENTS_SCRIPT.contains("saved.ariaHidden"));
        assert!(RESTORE_PERSISTENT_DOCUMENTS_SCRIPT.contains("removeAttribute"));
        assert!(RESTORE_PERSISTENT_DOCUMENTS_SCRIPT.contains("prior.isConnected"));
        assert!(RESTORE_PERSISTENT_DOCUMENTS_SCRIPT.contains("preventScroll"));
        assert!(RESTORE_PERSISTENT_DOCUMENTS_SCRIPT.contains("finally"));
        assert!(RESTORE_PERSISTENT_DOCUMENTS_SCRIPT.contains("firewall.active = false"));
        assert!(RESTORE_PERSISTENT_DOCUMENTS_SCRIPT.contains("restoreFocus &&"));
        assert!(RESTORE_PERSISTENT_DOCUMENTS_SCRIPT.contains("__HYDRA_RESTORE_DOM_FOCUS__"));
        let clear = RESTORE_PERSISTENT_DOCUMENTS_SCRIPT
            .find("delete window.__HYDRA_NATIVE_MODAL_UNDERLAY_STATE__")
            .unwrap();
        let focus = RESTORE_PERSISTENT_DOCUMENTS_SCRIPT
            .find("prior.focus({ preventScroll: true })")
            .unwrap();
        assert!(clear < focus);
        let focused_restore = persistent_restore_script(true);
        let passive_restore = persistent_restore_script(false);
        assert!(focused_restore.contains("})(true);"));
        assert!(passive_restore.contains("})(false);"));
        assert!(!focused_restore.contains("__HYDRA_RESTORE_DOM_FOCUS__"));
    }

    #[test]
    fn persistent_suppression_joins_every_target_and_rejects_stale_epochs() {
        let mut state = PersistentSuppressionState::default();
        let first = state.begin(2);
        assert!(!state.is_ready());
        assert_eq!(
            state.finish(PersistentSuppressionResult {
                epoch: first,
                index: 1,
                succeeded: true,
            }),
            PersistentSuppressionDecision::Pending
        );
        assert_eq!(
            state.finish(PersistentSuppressionResult {
                epoch: first,
                index: 1,
                succeeded: true,
            }),
            PersistentSuppressionDecision::Stale
        );
        let second = state.begin(2);
        assert_ne!(first, second);
        assert_eq!(
            state.finish(PersistentSuppressionResult {
                epoch: first,
                index: 0,
                succeeded: true,
            }),
            PersistentSuppressionDecision::Stale
        );
        assert_eq!(
            state.finish(PersistentSuppressionResult {
                epoch: second,
                index: 0,
                succeeded: true,
            }),
            PersistentSuppressionDecision::Pending
        );
        assert_eq!(
            state.finish(PersistentSuppressionResult {
                epoch: second,
                index: 1,
                succeeded: true,
            }),
            PersistentSuppressionDecision::Ready
        );
        assert!(state.is_ready());
    }

    #[test]
    fn persistent_suppression_failure_and_clear_fail_closed() {
        let mut state = PersistentSuppressionState::default();
        let epoch = state.begin(2);
        assert_eq!(
            state.finish(PersistentSuppressionResult {
                epoch,
                index: 0,
                succeeded: false,
            }),
            PersistentSuppressionDecision::Failed
        );
        assert!(!state.is_ready());
        assert_eq!(
            state.finish(PersistentSuppressionResult {
                epoch,
                index: 1,
                succeeded: true,
            }),
            PersistentSuppressionDecision::Stale
        );
        let next = state.begin(1);
        state.clear();
        assert_eq!(
            state.finish(PersistentSuppressionResult {
                epoch: next,
                index: 0,
                succeeded: true,
            }),
            PersistentSuppressionDecision::Stale
        );
        assert!(!state.is_ready());
    }

    #[test]
    fn persistent_suppression_callback_accepts_only_exact_success_sentinel() {
        let exact = serde_json::to_string(PERSISTENT_SUPPRESSION_SUCCESS_SENTINEL).unwrap();
        assert!(persistent_suppression_succeeded(&exact));
        for rejected in [
            "null",
            "true",
            r#""__HYDRA_PERSISTENT_SUPPRESSION_OK__suffix""#,
            PERSISTENT_SUPPRESSION_SUCCESS_SENTINEL,
        ] {
            assert!(!persistent_suppression_succeeded(rejected));
        }
    }

    #[test]
    fn persistent_document_join_waits_for_both_surfaces_and_rejects_stale_finish() {
        let mut runtime = OverlayRuntime::new(2);
        runtime.visible = true;
        assert!(runtime.mark_persistent_document_started(WebKitSurface::Sidebar, 0));
        assert!(runtime.mark_persistent_document_started(WebKitSurface::Topbar, 0));
        assert_eq!(
            runtime.mark_persistent_document_finished(WebKitSurface::Sidebar, 0),
            Some(false)
        );
        assert!(!runtime.can_begin_persistent_suppression(false));
        assert_eq!(
            runtime.mark_persistent_document_finished(WebKitSurface::Topbar, 0),
            Some(true)
        );
        assert!(runtime.can_begin_persistent_suppression(false));

        let outgoing_epoch = runtime.persistent_suppression.begin(2);
        assert!(runtime.mark_persistent_document_started(WebKitSurface::Topbar, 1));
        assert!(!runtime.can_begin_persistent_suppression(false));
        assert_eq!(
            runtime
                .persistent_suppression
                .finish(PersistentSuppressionResult {
                    epoch: outgoing_epoch,
                    index: 1,
                    succeeded: true,
                }),
            PersistentSuppressionDecision::Stale
        );
        assert_eq!(
            runtime.mark_persistent_document_finished(WebKitSurface::Topbar, 0),
            None
        );
        assert!(!runtime.can_begin_persistent_suppression(true));
        assert_eq!(
            runtime.mark_persistent_document_finished(WebKitSurface::Topbar, 1),
            Some(true)
        );
        assert!(runtime.can_begin_persistent_suppression(true));
    }

    #[test]
    fn parked_overlay_rejects_product_intents_until_all_presentation_barriers_are_ready() {
        let mut runtime = OverlayRuntime::new(1);
        runtime.visible = true;
        let token = runtime.begin_presentation_deadline();
        runtime.mark_persistent_document_started(WebKitSurface::Sidebar, 0);
        runtime.mark_persistent_document_finished(WebKitSurface::Sidebar, 0);
        runtime.delivery.attach_webview();
        runtime
            .delivery
            .remember(MODAL_ONE, ReactChromeScriptKind::Modal, true);
        let evaluation = runtime.delivery.react_ready().unwrap();
        let attempt = evaluation.modal_attempt.unwrap();
        runtime
            .delivery
            .finish_modal_evaluation(OverlayEvaluationResult {
                attempt,
                succeeded: true,
            });
        assert!(!runtime.accepts_product_intents());

        runtime.persistent_suppression.begin(0);
        assert!(!runtime.accepts_product_intents());
        assert!(runtime.mark_presented(token));
        assert!(runtime.accepts_product_intents());
        runtime.visible = false;
        assert!(!runtime.accepts_product_intents());
    }

    fn runtime_awaiting_presentation() -> OverlayRuntime {
        let mut runtime = OverlayRuntime::new(1);
        runtime.visible = true;
        runtime.begin_presentation_deadline();
        runtime.mark_persistent_document_started(WebKitSurface::Sidebar, 0);
        runtime.mark_persistent_document_finished(WebKitSurface::Sidebar, 0);
        runtime.delivery.attach_webview();
        runtime
            .delivery
            .remember(MODAL_ONE, ReactChromeScriptKind::Modal, true);
        let evaluation = runtime.delivery.react_ready().unwrap();
        let attempt = evaluation.modal_attempt.unwrap();
        runtime
            .delivery
            .finish_modal_evaluation(OverlayEvaluationResult {
                attempt,
                succeeded: true,
            });
        assert!(!runtime.accepts_product_intents());
        runtime
    }

    #[test]
    fn active_modal_queues_product_intent_until_presentation_then_delivers_once() {
        let mut runtime = runtime_awaiting_presentation();
        let intent = r#"{"type":"listFolderSessions","request_id":"sessions-page-1"}"#;
        assert_eq!(
            runtime.route_product_intent(intent.to_owned()),
            ProductIntentRoute::Queued
        );
        assert!(runtime.take_presented_product_intents().is_empty());

        runtime.persistent_suppression.begin(0);
        let token = runtime.presentation_token;
        assert!(!runtime.accepts_product_intents());
        assert!(runtime.mark_presented(token));
        assert!(runtime.accepts_product_intents());
        assert_eq!(
            runtime.take_presented_product_intents(),
            vec![intent.to_owned()]
        );
        assert!(runtime.take_presented_product_intents().is_empty());
        assert_eq!(
            runtime.route_product_intent("presented".to_owned()),
            ProductIntentRoute::Forward("presented".to_owned())
        );
    }

    #[test]
    fn queued_product_intent_also_waits_when_suppression_finishes_before_modal_evaluation() {
        let mut runtime = OverlayRuntime::new(1);
        runtime.visible = true;
        runtime.begin_presentation_deadline();
        runtime.mark_persistent_document_started(WebKitSurface::Sidebar, 0);
        runtime.mark_persistent_document_finished(WebKitSurface::Sidebar, 0);
        runtime.delivery.attach_webview();
        runtime
            .delivery
            .remember(MODAL_ONE, ReactChromeScriptKind::Modal, true);
        let evaluation = runtime.delivery.react_ready().unwrap();
        let attempt = evaluation.modal_attempt.unwrap();
        runtime.persistent_suppression.begin(0);
        assert!(!runtime.accepts_product_intents());

        let intent = r#"{"type":"listFolderSessions","request_id":"sessions-page-2"}"#;
        assert_eq!(
            runtime.route_product_intent(intent.to_owned()),
            ProductIntentRoute::Queued
        );
        runtime
            .delivery
            .finish_modal_evaluation(OverlayEvaluationResult {
                attempt,
                succeeded: true,
            });
        assert!(!runtime.accepts_product_intents());
        let token = runtime.presentation_token;
        assert!(runtime.mark_presented(token));
        assert!(runtime.accepts_product_intents());
        assert_eq!(
            runtime.take_presented_product_intents(),
            vec![intent.to_owned()]
        );
    }

    #[test]
    fn parked_or_modal_free_document_cannot_queue_product_intents() {
        let mut runtime = OverlayRuntime::new(1);
        runtime.delivery.attach_webview();
        let _ = runtime.delivery.react_ready();
        assert_eq!(
            runtime.route_product_intent("parked".to_owned()),
            ProductIntentRoute::RejectedNotPresented
        );

        runtime.visible = true;
        assert_eq!(
            runtime.route_product_intent("modal-free".to_owned()),
            ProductIntentRoute::RejectedNotPresented
        );
    }

    #[test]
    fn active_unpresented_modal_rejects_mutating_or_unknown_product_intents() {
        let mut runtime = runtime_awaiting_presentation();
        for intent in [
            r#"{"type":"pickProjectFolder","request_id":"folder-page-1"}"#,
            r#"{"type":"createProject","project_id":"p-1"}"#,
            r#"{"type":"unknown"}"#,
            "not-json",
        ] {
            assert_eq!(
                runtime.route_product_intent(intent.to_owned()),
                ProductIntentRoute::RejectedNotPresented
            );
        }
        assert!(runtime.pending_product_intents.intents.is_empty());
    }

    #[test]
    fn pending_product_intents_are_bounded_and_clear_with_modal_lifecycle() {
        let mut runtime = runtime_awaiting_presentation();
        for index in 0..MAX_PENDING_PRODUCT_INTENTS {
            assert_eq!(
                runtime.route_product_intent(format!(
                    r#"{{"type":"listFolderSessions","request_id":"sessions-{index}"}}"#
                )),
                ProductIntentRoute::Queued
            );
        }
        assert_eq!(
            runtime.route_product_intent(
                r#"{"type":"listFolderSessions","request_id":"sessions-overflow"}"#.to_owned(),
            ),
            ProductIntentRoute::RejectedCapacity
        );

        runtime.clear_pending_product_intents();
        runtime.persistent_suppression.begin(0);
        assert!(runtime.take_presented_product_intents().is_empty());
    }

    #[test]
    fn stale_presentation_token_or_page_reload_cannot_release_queued_intent() {
        let mut runtime = runtime_awaiting_presentation();
        let intent = r#"{"type":"listFolderSessions","request_id":"sessions-old"}"#;
        assert_eq!(
            runtime.route_product_intent(intent.to_owned()),
            ProductIntentRoute::Queued
        );
        runtime.end_deadline();
        runtime.begin_presentation_deadline();
        runtime.persistent_suppression.begin(0);
        assert!(runtime.take_presented_product_intents().is_empty());

        let mut runtime = runtime_awaiting_presentation();
        assert_eq!(
            runtime.route_product_intent(intent.to_owned()),
            ProductIntentRoute::Queued
        );
        runtime.delivery.page_started();
        runtime.clear_pending_product_intents();
        assert!(runtime.pending_product_intents.intents.is_empty());
    }

    #[test]
    fn presentation_tokens_make_queued_timeouts_stale_after_success() {
        let mut runtime = OverlayRuntime::new(1);
        let armed = runtime.ensure_presentation_deadline().unwrap();
        // Failure + PageStarted signals for the same logical recovery cannot extend the deadline,
        // including after its GLib source has fired but before the owner handles the queued event.
        assert_eq!(runtime.ensure_presentation_deadline(), None);
        assert_eq!(runtime.presentation_token, armed);
        runtime.end_deadline();
        let completed = runtime.presentation_token;
        assert_ne!(armed, completed);
        assert_ne!(runtime.presentation_token, armed);
        assert!(!runtime.presentation_pending());
        assert_ne!(runtime.ensure_presentation_deadline(), Some(armed));
    }

    fn overlay_geometry(width: i32, height: i32) -> OverlayGeometry {
        OverlayGeometry::new(0, 0, width, height, 1).unwrap()
    }

    fn observe_overlay_containers(
        barrier: &mut OverlayPresentationBarrier,
        geometry: OverlayGeometry,
    ) -> OverlayNativeAllocationReady {
        let mut ready = None;
        for surface in [
            OverlayAllocationSurface::Layer,
            OverlayAllocationSurface::PageStack,
            OverlayAllocationSurface::Content,
        ] {
            if let Some(event) = barrier.observe_surface(surface, Some(geometry)) {
                ready = Some(event);
            }
        }
        ready.expect("last exact native observation releases one owner-loop event")
    }

    fn advance_native_barrier_to_viewport(
        barrier: &mut OverlayPresentationBarrier,
        target: OverlayGeometry,
    ) -> OverlayNativeAllocationReady {
        let containers = observe_overlay_containers(barrier, target);
        assert_eq!(containers.phase, OverlayNativeAllocationPhase::Containers);
        assert!(barrier.accept_native_ready(
            containers,
            Some(target),
            [Some(target), Some(target), Some(target), None,],
        ));
        let webview = barrier
            .observe_surface(OverlayAllocationSurface::WebView, Some(target))
            .expect("exact WebView observation releases its owner-loop event");
        assert_eq!(webview.phase, OverlayNativeAllocationPhase::WebView);
        webview
    }

    #[test]
    fn presentation_barrier_requires_exact_native_geometry_then_exact_viewport() {
        let target = overlay_geometry(1854, 1001);
        let mut barrier = OverlayPresentationBarrier::default();
        assert!(barrier.begin(7, Some(target)));
        let native = advance_native_barrier_to_viewport(&mut barrier, target);
        let live = [Some(target); OverlayAllocationSurface::COUNT];
        assert!(barrier.accept_native_ready(native, Some(target), live));
        assert_eq!(
            barrier.accept_viewport_ready(
                OverlayViewportReady {
                    token: 7,
                    width: 1280,
                    height: 753,
                },
                Some(target),
                live,
            ),
            None
        );
        assert_eq!(
            barrier.accept_viewport_ready(
                OverlayViewportReady {
                    token: 7,
                    width: 1854,
                    height: 1001,
                },
                Some(target),
                live,
            ),
            Some(target)
        );
        assert!(barrier.active.is_none());
    }

    #[test]
    fn repeated_stage_for_the_same_generation_is_idempotent() {
        let target = overlay_geometry(1854, 1001);
        let mut barrier = OverlayPresentationBarrier::default();
        assert!(barrier.begin(8, Some(target)));
        assert_eq!(
            barrier.observe_surface(OverlayAllocationSurface::Layer, Some(target)),
            None
        );
        assert!(!barrier.begin(8, Some(target)));
        let active = barrier.active.as_ref().expect("attempt remains active");
        assert_eq!(active.token, 8);
        assert_eq!(active.phase, OverlayPresentationBarrierPhase::Containers);
        assert_eq!(
            active.observed[OverlayAllocationSurface::Layer.index()],
            Some(target)
        );
    }

    #[test]
    fn presentation_barrier_rejects_superseded_hidden_and_bootstrap_events() {
        let old = overlay_geometry(1280, 753);
        let current = overlay_geometry(1854, 1001);
        let mut barrier = OverlayPresentationBarrier::default();
        assert!(barrier.begin(10, Some(old)));
        let stale = observe_overlay_containers(&mut barrier, old);

        assert!(barrier.begin(11, Some(current)));
        assert!(!barrier.accept_native_ready(
            stale,
            Some(old),
            [Some(old); OverlayAllocationSurface::COUNT],
        ));
        assert_eq!(OverlayGeometry::new(0, 0, 1, 1001, 1), None);
        assert_eq!(OverlayGeometry::new(0, 0, 1854, 0, 1), None);

        let current_event = observe_overlay_containers(&mut barrier, current);
        assert_eq!(
            barrier.cancel(),
            Some(OverlayPresentationBarrierPhase::Containers)
        );
        assert!(!barrier.accept_native_ready(
            current_event,
            Some(current),
            [Some(current); OverlayAllocationSurface::COUNT],
        ));
        assert_eq!(barrier.cancel(), None);
    }

    #[test]
    fn native_barrier_needs_all_containers_in_common_coordinates_without_duplicate_wakes() {
        let target = overlay_geometry(1280, 753);
        let wrong_origin = OverlayGeometry::new(1, 0, 1280, 753, 1).unwrap();
        let wrong_scale = OverlayGeometry::new(0, 0, 1280, 753, 2).unwrap();
        let mut barrier = OverlayPresentationBarrier::default();
        barrier.begin(15, Some(target));
        assert_eq!(
            barrier.observe_surface(OverlayAllocationSurface::Layer, Some(target)),
            None
        );
        assert_eq!(
            barrier.observe_surface(OverlayAllocationSurface::PageStack, Some(target)),
            None
        );
        assert_eq!(
            barrier.observe_surface(OverlayAllocationSurface::Content, Some(wrong_origin)),
            None
        );
        assert_eq!(
            barrier.observe_surface(OverlayAllocationSurface::Content, Some(wrong_scale)),
            None
        );
        let containers = barrier
            .observe_surface(OverlayAllocationSurface::Content, Some(target))
            .expect("third exact container wakes once");
        assert_eq!(
            barrier.observe_surface(OverlayAllocationSurface::Content, Some(target)),
            None
        );
        assert!(barrier.accept_native_ready(
            containers,
            Some(target),
            [Some(target), Some(target), Some(target), None,],
        ));
        let webview = barrier
            .observe_surface(OverlayAllocationSurface::WebView, Some(target))
            .expect("WebView has an independent wake");
        assert_eq!(
            barrier.observe_surface(OverlayAllocationSurface::WebView, Some(target)),
            None
        );
        assert!(barrier.accept_native_ready(
            webview,
            Some(target),
            [Some(target); OverlayAllocationSurface::COUNT],
        ));
    }

    #[test]
    fn queued_container_wake_is_replaced_after_geometry_mismatch_settles() {
        let target = overlay_geometry(1854, 1001);
        let mismatch = OverlayGeometry::new(0, 0, 1853, 1001, 1).unwrap();
        let mut barrier = OverlayPresentationBarrier::default();
        barrier.begin(16, Some(target));
        let stale = observe_overlay_containers(&mut barrier, target);

        assert_eq!(
            barrier.observe_surface(OverlayAllocationSurface::Content, Some(mismatch)),
            None
        );
        let fresh = barrier
            .observe_surface(OverlayAllocationSurface::Content, Some(target))
            .expect("settled containers must enqueue a fresh owner-loop wake");
        assert_eq!(fresh, stale);
        assert!(barrier.accept_native_ready(
            fresh,
            Some(target),
            [Some(target), Some(target), Some(target), None],
        ));
    }

    #[test]
    fn queued_webview_wake_is_replaced_after_geometry_mismatch_settles() {
        let target = overlay_geometry(1854, 1001);
        let mismatch = OverlayGeometry::new(0, 0, 1854, 1000, 1).unwrap();
        let mut barrier = OverlayPresentationBarrier::default();
        barrier.begin(17, Some(target));
        let stale = advance_native_barrier_to_viewport(&mut barrier, target);

        assert_eq!(
            barrier.observe_surface(OverlayAllocationSurface::WebView, Some(mismatch)),
            None
        );
        let fresh = barrier
            .observe_surface(OverlayAllocationSurface::WebView, Some(target))
            .expect("settled WebView must enqueue a fresh owner-loop wake");
        assert_eq!(fresh, stale);
        assert!(barrier.accept_native_ready(
            fresh,
            Some(target),
            [Some(target); OverlayAllocationSurface::COUNT],
        ));
    }

    #[test]
    fn consumed_native_wake_can_retry_after_live_revalidation_rejects_it() {
        let target = overlay_geometry(1854, 1001);
        let mismatch = OverlayGeometry::new(0, 0, 1853, 1001, 1).unwrap();
        let mut barrier = OverlayPresentationBarrier::default();
        barrier.begin(18, Some(target));
        let stale = observe_overlay_containers(&mut barrier, target);

        assert!(!barrier.accept_native_ready(
            stale,
            Some(target),
            [Some(target), Some(target), Some(mismatch), None],
        ));
        let fresh = barrier
            .observe_surface(OverlayAllocationSurface::Content, Some(target))
            .expect("consuming a rejected current wake must permit a fresh wake");
        assert!(barrier.accept_native_ready(
            fresh,
            Some(target),
            [Some(target), Some(target), Some(target), None],
        ));
    }

    #[test]
    fn scale_only_transition_invalidates_the_old_native_wake() {
        let scale_one = overlay_geometry(1280, 753);
        let scale_two = OverlayGeometry::new(0, 0, 1280, 753, 2).unwrap();
        let mut barrier = OverlayPresentationBarrier::default();
        barrier.begin(19, Some(scale_one));
        let stale = observe_overlay_containers(&mut barrier, scale_one);

        assert_eq!(barrier.observe_target(Some(scale_two)), None);
        assert!(!barrier.accept_native_ready(
            stale,
            Some(scale_one),
            [Some(scale_one), Some(scale_one), Some(scale_one), None],
        ));
        let fresh = observe_overlay_containers(&mut barrier, scale_two);
        assert_eq!(fresh.target, scale_two);
        assert!(barrier.accept_native_ready(
            fresh,
            Some(scale_two),
            [Some(scale_two), Some(scale_two), Some(scale_two), None],
        ));
    }

    #[test]
    fn resize_while_waiting_invalidates_old_viewport_without_extending_token() {
        let initial = overlay_geometry(1280, 753);
        let resized = overlay_geometry(1854, 1001);
        let mut barrier = OverlayPresentationBarrier::default();
        barrier.begin(21, Some(initial));
        let initial_event = advance_native_barrier_to_viewport(&mut barrier, initial);
        assert!(barrier.accept_native_ready(
            initial_event,
            Some(initial),
            [Some(initial); OverlayAllocationSurface::COUNT],
        ));

        assert_eq!(barrier.observe_target(Some(resized)), None);
        assert_eq!(
            barrier.accept_viewport_ready(
                OverlayViewportReady {
                    token: 21,
                    width: initial.width,
                    height: initial.height,
                },
                Some(resized),
                [Some(initial); OverlayAllocationSurface::COUNT],
            ),
            None
        );
        let resized_event = advance_native_barrier_to_viewport(&mut barrier, resized);
        assert_eq!(resized_event.token, 21);
        assert!(barrier.accept_native_ready(
            resized_event,
            Some(resized),
            [Some(resized); OverlayAllocationSurface::COUNT],
        ));
        assert_eq!(
            barrier.accept_viewport_ready(
                OverlayViewportReady {
                    token: 21,
                    width: resized.width,
                    height: resized.height,
                },
                Some(resized),
                [Some(resized); OverlayAllocationSurface::COUNT],
            ),
            Some(resized)
        );
    }

    #[test]
    fn viewport_acknowledgement_is_private_strict_and_content_blind() {
        let exact = format!(
            r#"{{"type":"{OVERLAY_VIEWPORT_READY_TYPE}","presentation_token":9,"width":1854,"height":1001}}"#
        );
        assert_eq!(
            overlay_viewport_ready(&exact),
            Some(OverlayViewportReady {
                token: 9,
                width: 1854,
                height: 1001,
            })
        );
        assert!(is_overlay_viewport_ready_payload(&exact));
        for rejected in [
            format!(
                r#"{{"type":"{OVERLAY_VIEWPORT_READY_TYPE}","presentation_token":9,"width":1,"height":1001}}"#
            ),
            format!(
                r#"{{"type":"{OVERLAY_VIEWPORT_READY_TYPE}","presentation_token":9,"width":1854,"height":1001,"text":"secret"}}"#
            ),
        ] {
            assert!(is_overlay_viewport_ready_payload(&rejected));
            assert_eq!(overlay_viewport_ready(&rejected), None);
        }
        let script = overlay_viewport_barrier_script(9, overlay_geometry(1854, 1001));
        assert!(script.contains("ResizeObserver"));
        assert!(script.contains("requestAnimationFrame"));
        assert!(script.contains(OVERLAY_VIEWPORT_READY_TYPE));
        assert!(!script.contains("setInterval"));
        assert!(!script.contains("setTimeout"));
        assert!(!script.contains("textContent"));
        assert!(!script.contains("target.value"));
    }

    #[test]
    fn cold_load_request_stays_hidden_and_duplicate_requests_do_not_extend_it() {
        let mut runtime = OverlayRuntime::new(1);
        runtime
            .delivery
            .remember(MODAL_ONE, ReactChromeScriptKind::Modal, true);

        let cold_token = runtime.ensure_cold_load_deadline().unwrap();
        assert!(OVERLAY_COLD_LOAD_TIMEOUT > MODAL_PRESENTATION_TIMEOUT);
        assert!(runtime.cold_load_pending());
        assert!(!runtime.visible);
        assert!(!runtime.accepts_product_intents());
        assert_eq!(runtime.ensure_cold_load_deadline(), None);
        assert_eq!(runtime.presentation_token, cold_token);
        assert_eq!(
            runtime.deadline_phase_for_token(cold_token),
            Some(OverlayDeadlinePhase::ColdLoad)
        );
    }

    #[test]
    fn exact_ready_promotes_cold_request_with_a_fresh_presentation_token() {
        let mut runtime = OverlayRuntime::new(1);
        runtime.delivery.attach_webview();
        runtime
            .delivery
            .remember(MODAL_ONE, ReactChromeScriptKind::Modal, true);
        let cold_token = runtime.ensure_cold_load_deadline().unwrap();

        let evaluation = runtime.delivery.react_ready().unwrap();
        let attempt = evaluation.modal_attempt.unwrap();
        let presentation_token = runtime.promote_cold_load_to_presentation().unwrap();

        assert!(runtime.visible);
        assert!(runtime.presentation_pending());
        assert_ne!(cold_token, presentation_token);
        assert_eq!(runtime.deadline_phase_for_token(cold_token), None);
        assert_eq!(
            runtime.deadline_phase_for_token(presentation_token),
            Some(OverlayDeadlinePhase::Presentation)
        );
        assert_eq!(
            overlay_page(runtime.visible, &runtime.delivery),
            OverlayPage::Parking
        );

        assert_eq!(
            runtime
                .delivery
                .finish_modal_evaluation(OverlayEvaluationResult {
                    attempt,
                    succeeded: true,
                }),
            ModalEvaluationDecision::Delivered
        );
        assert_eq!(
            overlay_page(runtime.visible, &runtime.delivery),
            OverlayPage::Document
        );
    }

    #[test]
    fn expired_cold_request_cannot_be_resurrected_by_late_ready() {
        let mut runtime = OverlayRuntime::new(1);
        runtime.delivery.attach_webview();
        runtime
            .delivery
            .remember(MODEL_V1, ReactChromeScriptKind::Model, true);
        runtime
            .delivery
            .remember(MODAL_ONE, ReactChromeScriptKind::Modal, true);
        let expired_token = runtime.ensure_cold_load_deadline().unwrap();

        // This is the state mutation performed by the cold-timeout fail-closed path.
        runtime.delivery.hide();
        runtime.clear_pending_product_intents();
        runtime.end_deadline();

        let late_replay = runtime.delivery.react_ready().unwrap();
        assert_eq!(late_replay.scripts, vec![MODEL_V1.to_owned()]);
        assert_eq!(late_replay.modal_attempt, None);
        assert!(!runtime.visible);
        assert!(!runtime.delivery.has_active_modal());
        assert_eq!(runtime.deadline_phase_for_token(expired_token), None);
        assert_eq!(runtime.promote_cold_load_to_presentation(), None);
        assert_eq!(
            overlay_page(runtime.visible, &runtime.delivery),
            OverlayPage::Parking
        );

        // The late document is warm but hidden. Only a new modal plus a new visibility lifecycle
        // can present it, and both receive fresh attempt/deadline identities.
        let fresh = runtime
            .delivery
            .remember(MODAL_TWO, ReactChromeScriptKind::Modal, false)
            .unwrap();
        let fresh_attempt = fresh.modal_attempt.unwrap();
        assert!(!runtime.visible);
        assert_eq!(
            runtime
                .delivery
                .finish_modal_evaluation(OverlayEvaluationResult {
                    attempt: fresh_attempt,
                    succeeded: true,
                }),
            ModalEvaluationDecision::Delivered
        );
        assert_eq!(
            overlay_page(runtime.visible, &runtime.delivery),
            OverlayPage::Parking
        );
        let fresh_token = runtime.begin_presentation_deadline();
        runtime.visible = true;
        assert_ne!(fresh_token, expired_token);
        assert_eq!(
            overlay_page(runtime.visible, &runtime.delivery),
            OverlayPage::Document
        );
    }

    #[test]
    fn native_fallback_alone_consumes_keys() {
        assert!(!native_fallback_consumes_keys(false, false));
        assert!(!native_fallback_consumes_keys(false, true));
        assert!(native_fallback_consumes_keys(true, false));
        assert!(!native_fallback_consumes_keys(true, true));
    }

    #[test]
    fn fallback_announcements_distinguish_loading_from_recovery() {
        let inactive = fallback_accessible_copy(FallbackAccessibility::Inactive);
        let loading = fallback_accessible_copy(FallbackAccessibility::Loading);
        let recovering = fallback_accessible_copy(FallbackAccessibility::Recovering);

        assert_eq!(inactive, ("", ""));
        assert_eq!(loading.0, "Hydra dialog loading");
        assert_eq!(recovering.0, "Hydra dialog recovering");
        assert_ne!(loading, recovering);
        assert!(loading.1.contains("Keyboard focus remains"));
        assert!(recovering.1.contains("Keyboard focus remains"));
    }

    #[test]
    fn load_and_hide_transitions_park_document_until_the_next_ready_marker() {
        let mut delivery = OverlayDelivery::default();
        delivery.attach_webview();
        delivery.remember(MODAL_ONE, ReactChromeScriptKind::Modal, true);
        let initial = delivery.react_ready().unwrap();
        let initial_attempt = initial.modal_attempt.unwrap();
        delivery.finish_modal_evaluation(OverlayEvaluationResult {
            attempt: initial_attempt,
            succeeded: true,
        });
        assert_eq!(overlay_page(true, &delivery), OverlayPage::Document);

        delivery.page_started();
        assert_eq!(overlay_page(true, &delivery), OverlayPage::Parking);

        let recovery = delivery.react_ready().unwrap();
        assert_ne!(recovery.modal_attempt, Some(initial_attempt));
        assert_eq!(overlay_page(true, &delivery), OverlayPage::Parking);
        delivery.finish_modal_evaluation(OverlayEvaluationResult {
            attempt: recovery.modal_attempt.unwrap(),
            succeeded: true,
        });
        assert_eq!(overlay_page(true, &delivery), OverlayPage::Document);
        assert_eq!(overlay_page(false, &delivery), OverlayPage::Parking);
    }

    #[test]
    fn document_finished_alone_never_releases_a_modal() {
        let mut delivery = OverlayDelivery::default();
        delivery.attach_webview();
        delivery.remember(MODAL_ONE, ReactChromeScriptKind::Modal, true);
        assert!(delivery.page_finished().is_empty());
        assert!(!delivery.react_ready);
        assert!(!delivery.can_present());
    }

    #[test]
    fn ready_replays_latest_model_before_latest_modal_exactly_once() {
        let mut delivery = OverlayDelivery::default();
        delivery.attach_webview();
        delivery.remember(MODEL_V1, ReactChromeScriptKind::Model, true);
        delivery.remember(MODEL_V2, ReactChromeScriptKind::Model, true);
        delivery.remember(MODAL_ONE, ReactChromeScriptKind::Modal, true);
        delivery.remember(MODAL_TWO, ReactChromeScriptKind::Modal, true);

        let replay = delivery.react_ready().unwrap();
        assert_eq!(
            replay.scripts,
            vec![MODEL_V2.to_string(), MODAL_TWO.to_string()]
        );
        assert!(replay.modal_attempt.is_some());
        assert!(delivery.react_ready().is_none());
    }

    #[test]
    fn reload_replays_current_model_and_modal_after_new_ready_marker() {
        let mut delivery = OverlayDelivery::default();
        delivery.attach_webview();
        delivery.remember(MODEL_V1, ReactChromeScriptKind::Model, true);
        delivery.remember(MODAL_ONE, ReactChromeScriptKind::Modal, true);
        let first = delivery.react_ready().unwrap();
        assert_eq!(first.scripts.len(), 2);
        assert!(first.modal_attempt.is_some());

        delivery.page_started();
        assert!(delivery.page_finished().is_empty());
        let replay = delivery.react_ready().unwrap();
        assert_eq!(
            replay.scripts,
            vec![MODEL_V1.to_string(), MODAL_ONE.to_string()]
        );
        assert!(replay.modal_attempt.is_some());
    }

    #[test]
    fn hiding_before_ready_prevents_a_stale_modal() {
        let mut delivery = OverlayDelivery::default();
        delivery.attach_webview();
        delivery.remember(MODEL_V1, ReactChromeScriptKind::Model, true);
        delivery.remember(MODAL_ONE, ReactChromeScriptKind::Modal, true);
        delivery.remember(
            "window.transient();",
            ReactChromeScriptKind::Transient,
            true,
        );
        delivery.hide();
        let replay = delivery.react_ready().unwrap();
        assert_eq!(replay.scripts, vec![MODEL_V1.to_string()]);
        assert_eq!(replay.modal_attempt, None);
        assert!(!delivery.has_active_modal());
        assert!(!delivery.can_present());
    }

    #[test]
    fn ready_before_webview_attachment_drains_only_after_attach() {
        let mut delivery = OverlayDelivery::default();
        delivery.remember(MODEL_V1, ReactChromeScriptKind::Model, true);
        delivery.remember(MODAL_ONE, ReactChromeScriptKind::Modal, true);
        assert!(delivery.react_ready().is_none());
        let replay = delivery.attach_webview().unwrap();
        assert_eq!(
            replay.scripts,
            vec![MODEL_V1.to_string(), MODAL_ONE.to_string()]
        );
        assert!(replay.modal_attempt.is_some());
    }

    #[test]
    fn loading_overlay_queues_transient_scripts_in_fifo_order() {
        let mut delivery = OverlayDelivery::default();
        delivery.attach_webview();
        delivery.remember("window.first();", ReactChromeScriptKind::Transient, true);
        delivery.remember("window.second();", ReactChromeScriptKind::Transient, true);
        assert_eq!(
            delivery.react_ready().unwrap().scripts,
            vec![
                "window.first();".to_string(),
                "window.second();".to_string()
            ]
        );
    }

    #[test]
    fn transient_scripts_are_not_retained_while_overlay_is_inactive() {
        let mut delivery = OverlayDelivery::default();
        delivery.attach_webview();
        assert!(delivery
            .remember(
                "window.unrelated();",
                ReactChromeScriptKind::Transient,
                false,
            )
            .is_none());
        assert!(delivery.react_ready().unwrap().scripts.is_empty());
    }

    #[test]
    fn pending_script_queue_is_strictly_bounded() {
        let mut delivery = OverlayDelivery::default();
        delivery.attach_webview();
        for index in 0..(MAX_PENDING_SCRIPTS + 4) {
            delivery.remember(
                &format!("window.pending({index});"),
                ReactChromeScriptKind::Transient,
                true,
            );
        }
        let replay = delivery.react_ready().unwrap();
        assert_eq!(replay.scripts.len(), MAX_PENDING_SCRIPTS);
        assert!(replay.scripts.first().unwrap().contains("pending(4)"));
    }

    #[test]
    fn explicit_script_kind_ignores_adversarial_tokens_in_payload_text() {
        let mut delivery = OverlayDelivery::default();
        delivery.attach_webview();
        delivery.react_ready();

        let model_with_modal_token =
            r#"window.__HYDRA_DASHBOARD_SET_MODEL__({"name":"__HYDRA_SHOW_OVERLAY_MODAL__"});"#;
        let model = delivery
            .remember(model_with_modal_token, ReactChromeScriptKind::Model, false)
            .expect("ready model evaluates immediately");
        assert_eq!(model.modal_attempt, None);
        assert_eq!(delivery.modal_delivery, ModalDelivery::Absent);
        assert!(!delivery.has_active_modal());

        let modal_without_magic_token = "window.hostOwnedModalDispatch();";
        let modal = delivery
            .remember(
                modal_without_magic_token,
                ReactChromeScriptKind::Modal,
                false,
            )
            .expect("explicit modal evaluates immediately");
        let attempt = modal.modal_attempt.expect("modal attempt");
        assert_eq!(
            delivery.scripts.active_modal.as_deref(),
            Some(modal_without_magic_token)
        );
        assert_eq!(
            delivery.finish_modal_evaluation(OverlayEvaluationResult {
                attempt,
                succeeded: true,
            }),
            ModalEvaluationDecision::Delivered
        );

        let resolver_with_reserved_tokens = "window.resolve(\
            '__HYDRA_DASHBOARD_SET_MODEL__ and __HYDRA_SHOW_OVERLAY_MODAL__ from a project path'\
        );";
        let resolver = delivery
            .remember(
                resolver_with_reserved_tokens,
                ReactChromeScriptKind::Transient,
                true,
            )
            .expect("active transient evaluates immediately");
        assert_eq!(resolver.modal_attempt, None);
        assert_eq!(delivery.modal_delivery, ModalDelivery::Delivered);
        assert_eq!(
            delivery.scripts.active_modal.as_deref(),
            Some(modal_without_magic_token)
        );
        assert_eq!(
            delivery.scripts.latest_model.as_deref(),
            Some(model_with_modal_token)
        );
    }

    #[test]
    fn rejected_oversize_modal_never_changes_cached_or_delivery_state() {
        let mut delivery = OverlayDelivery::default();
        delivery.attach_webview();
        delivery.react_ready();
        let accepted = delivery
            .remember(MODAL_ONE, ReactChromeScriptKind::Modal, false)
            .unwrap();
        let attempt = accepted.modal_attempt.unwrap();
        delivery.finish_modal_evaluation(OverlayEvaluationResult {
            attempt,
            succeeded: true,
        });
        assert_eq!(delivery.modal_delivery, ModalDelivery::Delivered);

        let oversized = "x".repeat(MAX_PENDING_SCRIPT_BYTES + 1);
        assert!(delivery
            .remember(&oversized, ReactChromeScriptKind::Modal, false)
            .is_none());
        assert_eq!(delivery.modal_delivery, ModalDelivery::Delivered);
        assert_eq!(delivery.scripts.active_modal.as_deref(), Some(MODAL_ONE));
        assert!(delivery.can_present());
    }

    #[test]
    fn modal_evaluation_failure_clears_cache_and_refuses_future_presentation() {
        let mut delivery = OverlayDelivery::default();
        delivery.attach_webview();
        delivery.react_ready();
        let evaluation = delivery
            .remember(MODAL_ONE, ReactChromeScriptKind::Modal, false)
            .unwrap();
        let attempt = evaluation.modal_attempt.unwrap();
        assert!(delivery.has_active_modal());
        assert!(!delivery.can_present());

        assert_eq!(
            delivery.finish_modal_evaluation(OverlayEvaluationResult {
                attempt,
                succeeded: false,
            }),
            ModalEvaluationDecision::Failed
        );
        assert!(!delivery.has_active_modal());
        assert!(!delivery.can_present());
        assert_eq!(overlay_page(true, &delivery), OverlayPage::Parking);
    }

    #[test]
    fn stale_modal_completion_cannot_expose_a_replaced_or_hidden_modal() {
        let mut delivery = OverlayDelivery::default();
        delivery.attach_webview();
        delivery.react_ready();
        let first = delivery
            .remember(MODAL_ONE, ReactChromeScriptKind::Modal, false)
            .unwrap()
            .modal_attempt
            .unwrap();
        let second = delivery
            .remember(MODAL_TWO, ReactChromeScriptKind::Modal, false)
            .unwrap()
            .modal_attempt
            .unwrap();
        assert_ne!(first, second);
        assert_eq!(
            delivery.finish_modal_evaluation(OverlayEvaluationResult {
                attempt: first,
                succeeded: true,
            }),
            ModalEvaluationDecision::Stale
        );
        assert!(!delivery.can_present());

        delivery.hide();
        assert_eq!(
            delivery.finish_modal_evaluation(OverlayEvaluationResult {
                attempt: second,
                succeeded: true,
            }),
            ModalEvaluationDecision::Stale
        );
        assert!(!delivery.has_active_modal());
    }

    #[test]
    fn modal_delivery_callback_accepts_only_exact_success_sentinel() {
        let wrapped = modal_delivery_script(&[MODEL_V1.to_owned(), MODAL_ONE.to_owned()]);
        assert!(wrapped.find(MODEL_V1).unwrap() < wrapped.find(MODAL_ONE).unwrap());
        assert!(wrapped.contains("try"));
        assert!(wrapped.contains("catch"));
        assert!(overlay_delivery_succeeded(
            &serde_json::to_string(DELIVERY_SUCCESS_SENTINEL).unwrap()
        ));
        for result in ["", "null", "true", r#"\"wrong\""#, "not-json"] {
            assert!(!overlay_delivery_succeeded(result), "accepted {result:?}");
        }
    }

    #[test]
    fn ready_marker_is_strictly_typed() {
        assert_eq!(
            dashboard_overlay_ready_generation(r#"{"type":"dashboardOverlayReady"}"#),
            Some(None)
        );
        assert_eq!(
            dashboard_overlay_ready_generation(
                r#"{"type":"dashboardOverlayReady","recovery_generation":7}"#
            ),
            Some(Some(7))
        );
        assert_eq!(
            dashboard_overlay_ready_generation(r#"{"type":"dashboardOverlayReady","extra":true}"#),
            None
        );
        assert_eq!(
            dashboard_overlay_ready_generation(r#"{"type":"other"}"#),
            None
        );
        assert_eq!(dashboard_overlay_ready_generation("not-json"), None);
    }

    fn valid_overlay_input_trace_json() -> String {
        serde_json::json!({
            "type": OVERLAY_INPUT_TRACE_TYPE,
            "event_kind": "input",
            "printable": false,
            "value_len": 12,
            "target_tag": "INPUT",
            "target_type": "text",
            "target_name": "project_name",
            "client_x": null,
            "client_y": null,
            "rect_x": 620,
            "rect_y": 120,
            "rect_width": 320,
            "rect_height": 34,
            "visual_width": 1920,
            "visual_height": 1080,
            "document_width": 1920,
            "document_height": 1080,
            "monotonic_ms": 4281,
        })
        .to_string()
    }

    #[test]
    fn overlay_input_trace_is_host_only_opt_in_and_strictly_bounded() {
        let json = valid_overlay_input_trace_json();
        assert_eq!(
            route_overlay_input_trace(&json, false),
            OverlayInputTraceRoute::Disabled
        );
        let OverlayInputTraceRoute::Accepted(trace) = route_overlay_input_trace(&json, true) else {
            panic!("valid trace was not accepted");
        };
        assert_eq!(trace.event_kind, OverlayInputTraceEvent::Input);
        assert_eq!(trace.value_len, 12);
        assert_eq!(trace.target_name, "project_name");

        assert_eq!(
            route_overlay_input_trace(r#"{"type":"createProject"}"#, true),
            OverlayInputTraceRoute::NotTrace
        );

        let mut out_of_bounds: serde_json::Value = serde_json::from_str(&json).unwrap();
        out_of_bounds["client_x"] = serde_json::json!(1_000_001);
        assert_eq!(
            route_overlay_input_trace(&out_of_bounds.to_string(), true),
            OverlayInputTraceRoute::Rejected
        );
        out_of_bounds["client_x"] = serde_json::Value::Null;
        out_of_bounds["value_len"] = serde_json::json!(1_000_001);
        assert_eq!(
            route_overlay_input_trace(&out_of_bounds.to_string(), true),
            OverlayInputTraceRoute::Rejected
        );
        out_of_bounds["value_len"] = serde_json::json!(12);
        out_of_bounds["target_name"] = serde_json::json!("x".repeat(49));
        assert_eq!(
            route_overlay_input_trace(&out_of_bounds.to_string(), true),
            OverlayInputTraceRoute::Rejected
        );

        let oversized = serde_json::json!({
            "type": OVERLAY_INPUT_TRACE_TYPE,
            "padding": "x".repeat(MAX_OVERLAY_INPUT_TRACE_BYTES),
        })
        .to_string();
        assert!(oversized.len() > MAX_OVERLAY_INPUT_TRACE_BYTES);
        assert_eq!(
            route_overlay_input_trace(&oversized, true),
            OverlayInputTraceRoute::Rejected
        );
    }

    #[test]
    fn overlay_input_trace_rejects_text_key_path_and_unknown_event_fields() {
        let base: serde_json::Value =
            serde_json::from_str(&valid_overlay_input_trace_json()).unwrap();
        for forbidden in ["value", "key", "path", "text"] {
            let mut candidate = base.clone();
            candidate[forbidden] = serde_json::json!("secret-must-not-be-accepted");
            assert_eq!(
                route_overlay_input_trace(&candidate.to_string(), true),
                OverlayInputTraceRoute::Rejected,
                "accepted forbidden field {forbidden}"
            );
        }

        let mut invalid_event = base.clone();
        invalid_event["event_kind"] = serde_json::json!("compositionupdate");
        assert_eq!(
            route_overlay_input_trace(&invalid_event.to_string(), true),
            OverlayInputTraceRoute::Rejected
        );

        let mut invalid_token = base;
        invalid_token["target_name"] = serde_json::json!("/home/private/project");
        assert_eq!(
            route_overlay_input_trace(&invalid_token.to_string(), true),
            OverlayInputTraceRoute::Rejected
        );
    }

    #[test]
    fn overlay_document_parser_accepts_only_canonical_initial_and_recovery_urls() {
        let bundled = "hydra://localhost/index.html?chrome=overlay";
        assert_eq!(
            parse_overlay_document_generation(bundled, bundled),
            Some(OverlayDocumentGeneration::Initial)
        );
        assert_eq!(
            parse_overlay_document_generation(
                "hydra://localhost/index.html?chrome=overlay&__hydra_recovery_generation=7",
                bundled,
            ),
            Some(OverlayDocumentGeneration::Recovery(7))
        );

        for candidate in [
            "hydra://localhost/index.html?chrome=overlay#section",
            "hydra://localhost/index.html?chrome=overlay&__hydra_recovery_generation=7#section",
            "hydra://localhost/index.html?chrome=overlay&__hydra_recovery_generation=0",
            "hydra://localhost/index.html?chrome=overlay&__hydra_recovery_generation=07",
            "hydra://localhost/index.html?chrome=overlay&__hydra_recovery_generation=7&extra=1",
            "hydra://localhost/index.html?__hydra_recovery_generation=7&chrome=overlay",
            "hydra://localhost/index.html?chrome=sidebar",
            "https://example.com/",
        ] {
            assert_eq!(
                parse_overlay_document_generation(candidate, bundled),
                None,
                "unexpected trusted candidate: {candidate}"
            );
        }
    }

    #[test]
    fn recovery_url_is_host_generated_and_round_trips_through_the_exact_parser() {
        let bundled = "hydra://localhost/index.html?chrome=overlay";
        let recovery = overlay_recovery_url(bundled, 42).expect("valid canonical URL");
        assert_eq!(
            recovery,
            "hydra://localhost/index.html?chrome=overlay&__hydra_recovery_generation=42"
        );
        assert_eq!(
            parse_overlay_document_generation(&recovery, bundled),
            Some(OverlayDocumentGeneration::Recovery(42))
        );
        assert_eq!(overlay_recovery_url(bundled, 0), None);
        assert_eq!(
            overlay_recovery_url("hydra://localhost/index.html?chrome=overlay#fragment", 1),
            None
        );
    }

    #[test]
    fn navigation_and_ipc_require_the_active_exact_document_generation() {
        let bundled = "hydra://localhost/index.html?chrome=overlay";
        let generation_one = overlay_recovery_url(bundled, 1).unwrap();

        assert!(navigation_is_bundled_overlay(bundled, bundled, 0));
        assert!(overlay_ipc_is_trusted(bundled, bundled, 0, Some(0)));
        assert!(!overlay_ipc_is_trusted(bundled, bundled, 0, Some(1)));
        assert!(!navigation_is_bundled_overlay(bundled, bundled, 1));
        assert!(!overlay_ipc_is_trusted(bundled, bundled, 1, Some(0)));
        assert!(navigation_is_bundled_overlay(&generation_one, bundled, 1));
        assert!(overlay_ipc_is_trusted(&generation_one, bundled, 1, Some(1)));
        assert!(!overlay_ipc_is_trusted(
            &generation_one,
            bundled,
            2,
            Some(1)
        ));
        assert!(!overlay_ipc_is_trusted(
            "hydra://localhost/index.html?chrome=overlay#intent",
            bundled,
            0,
            Some(0),
        ));
    }

    #[test]
    fn ready_authentication_binds_document_body_and_finished_generation() {
        assert_eq!(
            authenticated_overlay_ready(OverlayDocumentGeneration::Initial, None),
            Some((0, CANONICAL_OVERLAY_READY_JSON))
        );
        assert_eq!(
            authenticated_overlay_ready(OverlayDocumentGeneration::Recovery(3), Some(3)),
            Some((3, CANONICAL_OVERLAY_READY_JSON))
        );

        // A missing token is accepted only for the initial generation. Old/mismatched documents
        // and bodies can never identify a newer recovery. Signal-side active/Finished ordering is
        // independently enforced by RecoverySignalTracker.
        for result in [
            authenticated_overlay_ready(OverlayDocumentGeneration::Recovery(1), None),
            authenticated_overlay_ready(OverlayDocumentGeneration::Recovery(1), Some(0)),
            authenticated_overlay_ready(OverlayDocumentGeneration::Initial, Some(1)),
        ] {
            assert_eq!(result, None);
        }
    }

    #[test]
    fn recovery_preload_adds_only_the_private_ready_generation_field() {
        let script = overlay_initialization_script("window.basePreload = true;", false);
        assert!(script.starts_with("window.basePreload = true;"));
        assert!(script.contains(OVERLAY_RECOVERY_GENERATION_PARAM));
        assert!(script.contains("intent.type === \"dashboardOverlayReady\""));
        assert!(script.contains("recovery_generation: generation"));
        assert!(script.contains("Number.isSafeInteger(generation)"));
        assert!(!script.contains(OVERLAY_INPUT_TRACE_TYPE));
    }

    #[test]
    fn input_trace_preload_records_only_bounded_non_text_metadata() {
        let script = overlay_initialization_script("window.basePreload = true;", true);
        assert!(script.contains(OVERLAY_INPUT_TRACE_TYPE));
        for event in [
            "pointerdown",
            "pointerup",
            "click",
            "focusin",
            "focusout",
            "keydown",
            "input",
        ] {
            assert!(script.contains(event), "missing event {event}");
        }
        for field in [
            "printable",
            "value_len",
            "target_tag",
            "target_type",
            "target_name",
            "client_x",
            "client_y",
            "rect_width",
            "rect_height",
            "visual_width",
            "visual_height",
            "document_width",
            "document_height",
            "monotonic_ms",
        ] {
            assert!(script.contains(field), "missing field {field}");
        }
        assert!(script.contains("performance.now"));
        assert!(!script.contains("textContent"));
        assert!(!script.contains("innerText"));
        assert!(!script.contains("outerHTML"));
        assert!(!script.contains("event.data"));
        assert!(!script.contains("key: event.key"));
    }
}
