//! Bounded, generation-aware WebKit recovery policy for the Linux dashboard surfaces.
//!
//! WebKit signal callbacks never reload a page directly. They classify the signal, attach the
//! document generation observed by [`RecoverySignalTracker`], and send a typed
//! [`WebKitRecoveryEvent`] through the Tao owner loop. The owner loop alone advances
//! [`RecoveryController`] and dispatches a canonical bundled reload. This keeps recovery ordered
//! with teardown, avoids process-global GLib idle sources, and coalesces duplicate crash/load-fail
//! signals without polling.

#![cfg(target_os = "linux")]

/// Maximum canonical reloads allowed for one failed document chain.
pub const MAX_WEBKIT_RECOVERY_ATTEMPTS: u8 = 3;

/// Reserved query parameter minted only by the native host for replacement documents.
pub const WEBKIT_RECOVERY_GENERATION_PARAM: &str = "__hydra_recovery_generation";

/// Exact identity encoded in one trusted dashboard document URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebKitDocumentGeneration {
    /// The builder-owned canonical URL, accepted exactly once as generation zero.
    Initial,
    /// An owner-minted replacement URL. Zero is deliberately never encoded in this form.
    Recovery(u64),
}

impl WebKitDocumentGeneration {
    pub fn value(self) -> u64 {
        match self {
            Self::Initial => 0,
            Self::Recovery(generation) => generation,
        }
    }
}

/// Parse only the canonical initial URL or the host-minted recovery form. No URL normalization is
/// performed: fragments, reordered/extra parameters, alternate encodings, and lookalike origins
/// fail closed.
pub fn parse_webkit_document_generation(
    candidate: &str,
    canonical_url: &str,
) -> Option<WebKitDocumentGeneration> {
    if canonical_url.contains('#') || canonical_url.contains(WEBKIT_RECOVERY_GENERATION_PARAM) {
        return None;
    }
    if candidate == canonical_url {
        return Some(WebKitDocumentGeneration::Initial);
    }

    let separator = if canonical_url.contains('?') {
        '&'
    } else {
        '?'
    };
    let prefix = format!("{canonical_url}{separator}{WEBKIT_RECOVERY_GENERATION_PARAM}=");
    let raw = candidate.strip_prefix(&prefix)?;
    if raw.is_empty() || raw.starts_with('0') || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(WebKitDocumentGeneration::Recovery(raw.parse().ok()?))
}

/// Mint the sole trusted URL for one replacement generation.
pub fn webkit_recovery_url(canonical_url: &str, generation: u64) -> Option<String> {
    if generation == 0
        || canonical_url.contains('#')
        || canonical_url.contains(WEBKIT_RECOVERY_GENERATION_PARAM)
    {
        return None;
    }
    let separator = if canonical_url.contains('?') {
        '&'
    } else {
        '?'
    };
    Some(format!(
        "{canonical_url}{separator}{WEBKIT_RECOVERY_GENERATION_PARAM}={generation}"
    ))
}

pub fn webkit_document_is_current(
    document: WebKitDocumentGeneration,
    current_generation: u64,
) -> bool {
    match document {
        WebKitDocumentGeneration::Initial => current_generation == 0,
        WebKitDocumentGeneration::Recovery(generation) => {
            generation > 0 && generation == current_generation
        }
    }
}

/// The independently budgeted dashboard presentation surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebKitSurface {
    Sidebar,
    Topbar,
    Overlay,
}

/// Sanitized failure classification. It deliberately carries no URL or WebKit error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebKitFailureReason {
    ProcessTerminated,
    LoadFailed,
    /// WebKit requested a same-document reload without an owner permit (including its own
    /// fallback for termination reasons the GLib API does not surface). The navigation is denied;
    /// the owner decides whether to mint the next bounded generation.
    EngineReloadRequested,
}

/// Typed signal delivered to the Tao owner loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebKitRecoveryEvent {
    Failure {
        surface: WebKitSurface,
        generation: Option<u64>,
        reason: WebKitFailureReason,
    },
    PageStarted {
        surface: WebKitSurface,
        generation: Option<u64>,
        bundled: bool,
    },
    PageFinished {
        surface: WebKitSurface,
        generation: Option<u64>,
        bundled: bool,
    },
    /// The overlay's strictly typed React-ready marker. Persistent-surface recovery completes at
    /// the exact bundled document finish; overlay delivery additionally waits for this marker
    /// before replay.
    OverlayReady { generation: Option<u64> },
}

impl WebKitRecoveryEvent {
    pub fn surface(self) -> WebKitSurface {
        match self {
            Self::Failure { surface, .. }
            | Self::PageStarted { surface, .. }
            | Self::PageFinished { surface, .. } => surface,
            Self::OverlayReady { .. } => WebKitSurface::Overlay,
        }
    }
}

/// Owner-loop action produced by one failure signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryDecision {
    /// Dispatch exactly one canonical reload for this attempt.
    Dispatch { attempt: u8, generation: u64 },
    /// Duplicate, unattributed, or stale failure; an existing attempt already covers it.
    Coalesced,
    /// The third reload failed. Hide/degrade the WebView while preserving its GTK allocation and
    /// the native terminal/PTY.
    Exhausted,
    /// The host is shutting down; late signals are harmless.
    Inactive,
}

/// Signal-side result for the overlay's typed React-ready marker. WebKit does not guarantee that
/// the JavaScript task posting this marker runs after its main-document `LoadEvent::Finished`, so
/// both orders are authenticated without treating an active-but-unfinished document as healthy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryReadyDecision {
    /// The exact active document posted ready first; hold it until exact Finished arrives.
    PendingFinish,
    /// Exact Finished was already observed, so the owner may complete this generation now.
    Deliver,
    /// Stale, duplicate, not-yet-started, or retired document.
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryPhase {
    Idle,
    Reloading,
    Exhausted,
    ShutDown,
}

/// Pure owner-loop recovery state. A controller is created separately for sidebar, topbar, and
/// overlay.
#[derive(Debug)]
pub struct RecoveryController {
    generation: u64,
    attempts: u8,
    phase: RecoveryPhase,
    completed_generation: Option<u64>,
}

impl Default for RecoveryController {
    fn default() -> Self {
        Self {
            generation: 0,
            attempts: 0,
            phase: RecoveryPhase::Idle,
            completed_generation: None,
        }
    }
}

impl RecoveryController {
    /// Register a failure for the document generation named by the signal callback.
    ///
    /// Duplicate crash + load-failed signals retain the failed generation after the first event
    /// has already dispatched the next generation, so they coalesce. A failure for the current
    /// replacement generation advances to the next bounded attempt.
    pub fn on_failure(&mut self, failed_generation: Option<u64>) -> RecoveryDecision {
        match self.phase {
            RecoveryPhase::ShutDown => return RecoveryDecision::Inactive,
            RecoveryPhase::Exhausted => return RecoveryDecision::Coalesced,
            RecoveryPhase::Idle | RecoveryPhase::Reloading => {}
        }

        match failed_generation {
            Some(generation) if generation != self.generation => {
                return RecoveryDecision::Coalesced;
            }
            // Every legitimate signal is attributed by an owner-minted document URL or by the
            // synchronous current-process termination callback. Ambiguous signals never spend a
            // retry budget.
            None => return RecoveryDecision::Coalesced,
            Some(_) => {}
        }

        if self.attempts >= MAX_WEBKIT_RECOVERY_ATTEMPTS {
            self.phase = RecoveryPhase::Exhausted;
            return RecoveryDecision::Exhausted;
        }

        self.attempts += 1;
        self.generation = self.generation.wrapping_add(1);
        self.phase = RecoveryPhase::Reloading;
        self.completed_generation = None;
        RecoveryDecision::Dispatch {
            attempt: self.attempts,
            generation: self.generation,
        }
    }

    /// Complete the current recovery chain only for the exact canonical document generation.
    /// Returns true once for an accepted marker; stale/foreign markers do nothing.
    pub fn on_exact_page_finished(&mut self, generation: Option<u64>) -> bool {
        if self.phase == RecoveryPhase::ShutDown || self.phase == RecoveryPhase::Exhausted {
            return false;
        }
        if generation != Some(self.generation) || self.completed_generation == Some(self.generation)
        {
            return false;
        }
        self.attempts = 0;
        self.phase = RecoveryPhase::Idle;
        self.completed_generation = Some(self.generation);
        true
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn is_exhausted(&self) -> bool {
        self.phase == RecoveryPhase::Exhausted
    }

    /// Read-only owner-loop preflight used to close modal presentation before a current persistent
    /// surface dispatches its replacement load. The immediately following `on_failure` call remains
    /// the sole state transition and retry-budget owner.
    pub fn failure_is_current(&self, failed_generation: Option<u64>) -> bool {
        matches!(self.phase, RecoveryPhase::Idle | RecoveryPhase::Reloading)
            && failed_generation == Some(self.generation)
    }

    /// Make all late signal events inert before GTK/WebKit objects are dropped.
    pub fn shut_down(&mut self) {
        self.phase = RecoveryPhase::ShutDown;
    }
}

/// Signal-side generation markers. This small state is shared only on the GTK owner thread.
///
/// `prepare_load` runs immediately before the owner calls `load_uri`. The navigation handler must
/// claim that exact generation once; only then may Started move it to active. Exact
/// Finished/failure signals carry the URL generation back to the controller. Unsolicited reloads
/// and stale documents therefore cannot steal or relabel the current generation.
#[derive(Debug)]
pub struct RecoverySignalTracker {
    navigation_permit: Option<u64>,
    claimed_navigation: Option<u64>,
    active: Option<u64>,
    exact_finished: Option<u64>,
    pending_ready: Option<u64>,
    delivered_ready: Option<u64>,
    shut_down: bool,
}

impl Default for RecoverySignalTracker {
    fn default() -> Self {
        Self {
            // The builder's initial canonical URL is generation zero.
            navigation_permit: Some(0),
            claimed_navigation: None,
            active: None,
            exact_finished: None,
            pending_ready: None,
            delivered_ready: None,
            shut_down: false,
        }
    }
}

impl RecoverySignalTracker {
    pub fn prepare_load(&mut self, generation: u64) {
        if self.shut_down {
            return;
        }
        self.navigation_permit = Some(generation);
        self.claimed_navigation = None;
        self.active = None;
        self.exact_finished = None;
        self.pending_ready = None;
        self.delivered_ready = None;
    }

    /// Claim the one owner-issued navigation permit. A wrong token or an unsolicited reload does
    /// not mutate the permit and is rejected by the navigation handler.
    pub fn claim_navigation(&mut self, generation: u64) -> bool {
        if self.shut_down || self.navigation_permit != Some(generation) {
            return false;
        }
        self.navigation_permit = None;
        self.claimed_navigation = Some(generation);
        true
    }

    /// Identify an unpermitted reload of the active/finished current document without mutating
    /// any marker. The navigation handler denies it and reports this identity to the owner loop,
    /// which alone may advance recovery and mint a new permit.
    pub fn unpermitted_current_navigation(&self, generation: u64) -> Option<u64> {
        if self.shut_down {
            return None;
        }
        (self.active == Some(generation) || self.exact_finished == Some(generation))
            .then_some(generation)
    }

    /// Whether this generation is the one document currently permitted, loading, or finished.
    /// IPC gates use this to reject delayed messages from an already-retired recovery document.
    pub fn owns_generation(&self, generation: u64) -> bool {
        !self.shut_down
            && [
                self.navigation_permit,
                self.claimed_navigation,
                self.active,
                self.exact_finished,
            ]
            .contains(&Some(generation))
    }

    pub fn page_started(&mut self, generation: Option<u64>) -> Option<u64> {
        if self.shut_down {
            return None;
        }
        let generation = generation?;
        if self.claimed_navigation != Some(generation) {
            return None;
        }
        self.claimed_navigation = None;
        self.active = Some(generation);
        self.exact_finished = None;
        Some(generation)
    }

    pub fn page_finished(&mut self, generation: Option<u64>) -> Option<u64> {
        if self.shut_down {
            return None;
        }
        let generation = generation?;
        if self.active != Some(generation) {
            return None;
        }
        self.active = None;
        // A duplicate Finished signal must not erase the accepted document marker while React's
        // typed ready message is still in flight. Only a real active generation can replace it.
        self.exact_finished = Some(generation);
        Some(generation)
    }

    /// Authenticate one typed React-ready marker against the exact active/finished document.
    /// The marker is one-shot per generation. If JavaScript posts it before WebKit Finished, retain
    /// only its generation and let `take_pending_ready_after_finish` release it later.
    pub fn record_typed_ready(&mut self, generation: u64) -> RecoveryReadyDecision {
        if self.shut_down
            || self.pending_ready == Some(generation)
            || self.delivered_ready == Some(generation)
        {
            return RecoveryReadyDecision::Rejected;
        }
        if self.active == Some(generation) {
            self.pending_ready = Some(generation);
            return RecoveryReadyDecision::PendingFinish;
        }
        if self.exact_finished == Some(generation) {
            self.delivered_ready = Some(generation);
            return RecoveryReadyDecision::Deliver;
        }
        RecoveryReadyDecision::Rejected
    }

    /// Release an early ready marker only after Finished identifies the same exact generation.
    pub fn take_pending_ready_after_finish(&mut self, generation: u64) -> bool {
        if self.shut_down
            || self.exact_finished != Some(generation)
            || self.pending_ready != Some(generation)
            || self.delivered_ready == Some(generation)
        {
            return false;
        }
        self.pending_ready = None;
        self.delivered_ready = Some(generation);
        true
    }

    /// Attribute `load-failed` using its immutable failing URI token. Stale generations cannot
    /// consume the current document marker or the next navigation permit.
    pub fn failed_generation(&mut self, generation: u64) -> Option<u64> {
        if self.shut_down
            || ![
                self.navigation_permit,
                self.claimed_navigation,
                self.active,
                self.exact_finished,
            ]
            .contains(&Some(generation))
        {
            return None;
        }
        if self.navigation_permit == Some(generation) {
            self.navigation_permit = None;
        }
        if self.claimed_navigation == Some(generation) {
            self.claimed_navigation = None;
        }
        if self.active == Some(generation) {
            self.active = None;
        }
        if self.exact_finished == Some(generation) {
            self.exact_finished = None;
        }
        if self.pending_ready == Some(generation) {
            self.pending_ready = None;
        }
        if self.delivered_ready == Some(generation) {
            self.delivered_ready = None;
        }
        Some(generation)
    }

    /// Attribute the synchronous WebKit `web-process-terminated` signal to the one current
    /// WebView process/document. In WebKit's UI-process source,
    /// `WebProcessProxy::processDidTerminateOrFailedToLaunch` first shuts down/nulls the old
    /// connection, then synchronously calls `WebPageProxy::dispatchProcessDidTerminate`; the GLib
    /// navigation client directly reaches `g_signal_emit`. Hydra's callback only enqueues a Tao
    /// event, so the owner cannot dispatch the replacement load until that stack has returned.
    /// `load-failed` companions are independently identified by their tokenized failing URI;
    /// WebKit fallback reloads for non-emitted termination reasons hit the denied-navigation path.
    /// This contract requires the signal handler to remain enqueue-only: it must never call
    /// `load_uri`, pump/re-enter GLib, or add a second deprecated crash handler. The bundled
    /// dashboard also has no subframes; if remote frames/site isolation are introduced, process
    /// attribution must be revisited because the public GLib signal carries no process identity.
    pub fn failed_current_process(&mut self) -> Option<u64> {
        if self.shut_down {
            return None;
        }
        let generation = self
            .active
            .or(self.claimed_navigation)
            .or(self.exact_finished)
            .or(self.navigation_permit)?;
        self.failed_generation(generation)
    }

    /// Generation of the exact bundled document which most recently finished. Clearing this on
    /// failure prevents a queued ready marker from the failed page from completing a new retry.
    pub fn ready_marker(&self) -> Option<u64> {
        (!self.shut_down).then_some(self.exact_finished).flatten()
    }

    pub fn shut_down(&mut self) {
        self.shut_down = true;
        self.navigation_permit = None;
        self.claimed_navigation = None;
        self.active = None;
        self.exact_finished = None;
        self.pending_ready = None;
        self.delivered_ready = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_surface_events_preserve_distinct_recovery_identity() {
        for surface in [WebKitSurface::Sidebar, WebKitSurface::Topbar] {
            assert_eq!(
                WebKitRecoveryEvent::Failure {
                    surface,
                    generation: Some(0),
                    reason: WebKitFailureReason::ProcessTerminated,
                }
                .surface(),
                surface
            );
            assert_eq!(
                WebKitRecoveryEvent::PageStarted {
                    surface,
                    generation: Some(0),
                    bundled: true,
                }
                .surface(),
                surface
            );
            assert_eq!(
                WebKitRecoveryEvent::PageFinished {
                    surface,
                    generation: Some(0),
                    bundled: true,
                }
                .surface(),
                surface
            );
        }
        assert_eq!(
            WebKitRecoveryEvent::OverlayReady {
                generation: Some(0)
            }
            .surface(),
            WebKitSurface::Overlay
        );
    }

    #[test]
    fn crash_and_load_failure_burst_dispatches_once() {
        let mut controller = RecoveryController::default();
        assert!(controller.failure_is_current(Some(0)));
        assert!(!controller.failure_is_current(None));
        assert_eq!(
            controller.on_failure(Some(0)),
            RecoveryDecision::Dispatch {
                attempt: 1,
                generation: 1
            }
        );
        assert!(controller.failure_is_current(Some(1)));
        assert!(!controller.failure_is_current(Some(0)));
        assert_eq!(controller.on_failure(Some(0)), RecoveryDecision::Coalesced);
        assert_eq!(controller.on_failure(None), RecoveryDecision::Coalesced);
    }

    #[test]
    fn retries_are_bounded_and_exhaust_after_three_dispatches() {
        let mut controller = RecoveryController::default();
        for (failed, attempt, next) in [(0, 1, 1), (1, 2, 2), (2, 3, 3)] {
            assert_eq!(
                controller.on_failure(Some(failed)),
                RecoveryDecision::Dispatch {
                    attempt,
                    generation: next
                }
            );
        }
        assert_eq!(controller.on_failure(Some(3)), RecoveryDecision::Exhausted);
        assert!(controller.is_exhausted());
        assert_eq!(controller.on_failure(Some(3)), RecoveryDecision::Coalesced);
    }

    #[test]
    fn exhausted_surface_can_retire_every_document_capability() {
        let mut controller = RecoveryController::default();
        let mut tracker = RecoverySignalTracker::default();
        assert!(tracker.claim_navigation(0));
        assert_eq!(tracker.page_started(Some(0)), Some(0));
        assert_eq!(tracker.page_finished(Some(0)), Some(0));

        for generation in 0..3 {
            let RecoveryDecision::Dispatch {
                generation: next, ..
            } = controller.on_failure(Some(generation))
            else {
                panic!("expected retry dispatch");
            };
            tracker.prepare_load(next);
            assert!(tracker.claim_navigation(next));
            assert_eq!(tracker.page_started(Some(next)), Some(next));
            assert_eq!(tracker.page_finished(Some(next)), Some(next));
        }
        assert_eq!(controller.on_failure(Some(3)), RecoveryDecision::Exhausted);

        // Exhaustion is terminal for this WebView. Hiding it is insufficient: retire every
        // generation marker so its last live document cannot retain typed-IPC authority.
        tracker.shut_down();
        for generation in 0..=3 {
            assert!(!tracker.owns_generation(generation));
        }
        assert_eq!(tracker.ready_marker(), None);
        assert_eq!(tracker.unpermitted_current_navigation(3), None);
    }

    #[test]
    fn exact_current_page_finish_resets_retry_budget() {
        let mut controller = RecoveryController::default();
        assert!(matches!(
            controller.on_failure(Some(0)),
            RecoveryDecision::Dispatch { generation: 1, .. }
        ));
        assert!(controller.on_exact_page_finished(Some(1)));
        assert_eq!(
            controller.on_failure(Some(1)),
            RecoveryDecision::Dispatch {
                attempt: 1,
                generation: 2
            }
        );
    }

    #[test]
    fn duplicate_finish_or_ready_marker_is_accepted_once_per_generation() {
        let mut controller = RecoveryController::default();
        assert!(controller.on_exact_page_finished(Some(0)));
        assert!(!controller.on_exact_page_finished(Some(0)));

        assert!(matches!(
            controller.on_failure(Some(0)),
            RecoveryDecision::Dispatch { generation: 1, .. }
        ));
        assert!(controller.on_exact_page_finished(Some(1)));
        assert!(!controller.on_exact_page_finished(Some(1)));
    }

    #[test]
    fn foreign_and_stale_page_markers_cannot_reset_recovery() {
        let mut controller = RecoveryController::default();
        assert!(matches!(
            controller.on_failure(Some(0)),
            RecoveryDecision::Dispatch { generation: 1, .. }
        ));
        assert!(!controller.on_exact_page_finished(None));
        assert!(!controller.on_exact_page_finished(Some(0)));
        assert_eq!(
            controller.on_failure(Some(1)),
            RecoveryDecision::Dispatch {
                attempt: 2,
                generation: 2
            }
        );
    }

    #[test]
    fn navigation_permit_is_single_use() {
        let mut tracker = RecoverySignalTracker::default();
        assert!(tracker.claim_navigation(0));
        assert!(!tracker.claim_navigation(0));
        assert_eq!(tracker.page_started(Some(0)), Some(0));
        assert_eq!(tracker.page_finished(Some(0)), Some(0));
    }

    #[test]
    fn wrong_token_does_not_consume_pending_permit() {
        let mut tracker = RecoverySignalTracker::default();
        assert!(!tracker.claim_navigation(1));
        assert!(tracker.claim_navigation(0));
    }

    #[test]
    fn owner_external_same_url_reload_is_rejected_without_mutation() {
        let mut tracker = RecoverySignalTracker::default();
        assert!(tracker.claim_navigation(0));
        assert_eq!(tracker.page_started(Some(0)), Some(0));
        assert_eq!(tracker.page_finished(Some(0)), Some(0));
        assert!(tracker.owns_generation(0));
        assert!(!tracker.claim_navigation(0));
        assert_eq!(tracker.unpermitted_current_navigation(0), Some(0));
        assert_eq!(tracker.page_started(Some(0)), None);
        assert_eq!(tracker.ready_marker(), Some(0));
    }

    #[test]
    fn duplicate_finish_preserves_ready_generation_until_typed_ready_arrives() {
        let mut tracker = RecoverySignalTracker::default();
        assert!(tracker.claim_navigation(0));
        assert_eq!(tracker.page_started(Some(0)), Some(0));
        assert_eq!(tracker.page_finished(Some(0)), Some(0));
        assert_eq!(tracker.page_finished(Some(0)), None);
        assert_eq!(tracker.ready_marker(), Some(0));
    }

    #[test]
    fn started_then_ready_then_finished_delivers_exactly_once() {
        let mut tracker = RecoverySignalTracker::default();
        assert!(tracker.claim_navigation(0));
        assert_eq!(tracker.page_started(Some(0)), Some(0));
        assert_eq!(
            tracker.record_typed_ready(0),
            RecoveryReadyDecision::PendingFinish
        );
        assert_eq!(
            tracker.record_typed_ready(0),
            RecoveryReadyDecision::Rejected
        );
        assert_eq!(tracker.page_finished(Some(0)), Some(0));
        assert!(tracker.take_pending_ready_after_finish(0));
        assert!(!tracker.take_pending_ready_after_finish(0));
        assert_eq!(
            tracker.record_typed_ready(0),
            RecoveryReadyDecision::Rejected
        );
    }

    #[test]
    fn started_then_finished_then_ready_delivers_exactly_once() {
        let mut tracker = RecoverySignalTracker::default();
        assert!(tracker.claim_navigation(0));
        assert_eq!(tracker.page_started(Some(0)), Some(0));
        assert_eq!(tracker.page_finished(Some(0)), Some(0));
        assert_eq!(
            tracker.record_typed_ready(0),
            RecoveryReadyDecision::Deliver
        );
        assert_eq!(
            tracker.record_typed_ready(0),
            RecoveryReadyDecision::Rejected
        );
        assert!(!tracker.take_pending_ready_after_finish(0));
    }

    #[test]
    fn late_load_failure_old_token_after_new_ready_is_stale() {
        let mut tracker = RecoverySignalTracker::default();
        assert!(tracker.claim_navigation(0));
        assert_eq!(tracker.page_started(Some(0)), Some(0));
        assert_eq!(tracker.failed_generation(0), Some(0));

        tracker.prepare_load(1);
        assert!(!tracker.owns_generation(0));
        assert!(tracker.owns_generation(1));
        assert!(tracker.claim_navigation(1));
        assert_eq!(tracker.page_started(Some(1)), Some(1));
        assert_eq!(tracker.page_finished(Some(1)), Some(1));
        assert_eq!(tracker.ready_marker(), Some(1));

        assert_eq!(tracker.failed_generation(0), None);
        assert_eq!(tracker.ready_marker(), Some(1));
        assert_eq!(tracker.failed_generation(1), Some(1));
    }

    #[test]
    fn process_termination_attributes_the_current_document_once() {
        let mut tracker = RecoverySignalTracker::default();
        assert!(tracker.claim_navigation(0));
        assert_eq!(tracker.page_started(Some(0)), Some(0));
        assert_eq!(tracker.page_finished(Some(0)), Some(0));
        assert_eq!(tracker.failed_current_process(), Some(0));
        assert_eq!(tracker.failed_current_process(), None);
    }

    #[test]
    fn exact_document_url_policy_rejects_fragments_extra_fields_and_overflow() {
        let canonical = "hydra://localhost/index.html?chrome=sidebar";
        assert_eq!(
            parse_webkit_document_generation(canonical, canonical),
            Some(WebKitDocumentGeneration::Initial)
        );
        let recovery = webkit_recovery_url(canonical, 7).unwrap();
        assert_eq!(
            parse_webkit_document_generation(&recovery, canonical),
            Some(WebKitDocumentGeneration::Recovery(7))
        );
        for candidate in [
            "hydra://localhost/index.html?chrome=sidebar#fragment",
            "hydra://localhost/index.html?chrome=sidebar&__hydra_recovery_generation=0",
            "hydra://localhost/index.html?chrome=sidebar&__hydra_recovery_generation=07",
            "hydra://localhost/index.html?chrome=sidebar&__hydra_recovery_generation=7&extra=1",
            "hydra://localhost/index.html?chrome=sidebar&__hydra_recovery_generation=18446744073709551616",
            "https://example.invalid/index.html?chrome=sidebar",
        ] {
            assert_eq!(parse_webkit_document_generation(candidate, canonical), None);
        }
    }

    #[test]
    fn teardown_makes_late_events_safe_and_inert() {
        let mut controller = RecoveryController::default();
        let mut tracker = RecoverySignalTracker::default();
        controller.shut_down();
        tracker.shut_down();

        assert_eq!(controller.on_failure(Some(0)), RecoveryDecision::Inactive);
        assert!(!controller.on_exact_page_finished(Some(0)));
        tracker.prepare_load(1);
        assert!(!tracker.claim_navigation(1));
        assert_eq!(tracker.page_started(Some(1)), None);
        assert_eq!(tracker.page_finished(Some(1)), None);
        assert_eq!(tracker.failed_generation(1), None);
        assert_eq!(tracker.failed_current_process(), None);
        assert_eq!(tracker.ready_marker(), None);
    }

    #[test]
    fn each_failed_generation_dispatches_exactly_one_attempt() {
        let mut controller = RecoveryController::default();
        let mut dispatches = Vec::new();
        for generation in [Some(0), Some(0), None, Some(1), Some(1), Some(2)] {
            if let RecoveryDecision::Dispatch {
                attempt,
                generation,
            } = controller.on_failure(generation)
            {
                dispatches.push((attempt, generation));
            }
        }
        assert_eq!(dispatches, vec![(1, 1), (2, 2), (3, 3)]);
    }
}
