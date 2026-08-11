//! Owner-loop wake plumbing for the Linux Tao/GTK host: the loop's typed event, the
//! [`UserEventSender`] implementation, and the direct GTK-signal HostEvent delivery.
//!
//! On Linux the Tao/GTK loop in [`super::window_host`] OWNS the window, so every wake must reach
//! *that* loop — not a secondary winit loop that only gets pumped when GTK happens to be busy.
//! Tao's `EventLoopProxy::send_event` enqueues on the loop's FIFO channel and then wakes the GLib
//! `MainContext` directly (`MainContext::wakeup`), so a send unblocks an otherwise completely
//! idle `gtk::main_iteration_do(true)` — no keyboard, mouse, focus, resize, or GTK activity
//! required.
//!
//! Both wake sources share that one proxy channel, distinguished by [`LinuxLoopEvent`]:
//!
//! * [`LinuxLoopEvent::Renderer`] — a renderer [`UserEvent`] from the client reader thread or the
//!   command bridge, delivered by the loop straight into `App::handle_user_event`.
//! * [`LinuxLoopEvent::Host`] — a GTK-signal [`HostEvent`], sent DIRECTLY through the proxy by
//!   [`HostEventSender`] and delivered by the loop into `App::handle_host_event`. There is no
//!   intermediate queue that could go stale: the send itself is the wake. This matters because a
//!   GTK handler that returns `Propagation::Stop` (an IME-consumed keystroke whose commit/preedit
//!   arrives via the IM context) produces NO top-level Tao window event — direct delivery makes
//!   each HostEvent reach the loop on its own, with no dependence on top-level propagation.
//! * [`LinuxLoopEvent::WebKitRecovery`] — a sanitized lifecycle signal. The loop advances the
//!   bounded generation-aware controller and is the only code allowed to reload a dashboard page.
//! * [`LinuxLoopEvent::OverlayEvaluation`] / [`LinuxLoopEvent::PersistentSuppression`] —
//!   content-blind JavaScript completions. The owner loop rejects stale attempt/epoch ids and is
//!   the only code allowed to expose the overlay after modal delivery AND underlay suppression.
//! * [`LinuxLoopEvent::OverlayNativeAllocationReady`] /
//!   [`LinuxLoopEvent::OverlayViewportReady`] — generation-bound native and DOM geometry
//!   acknowledgements. The owner loop revalidates both before enabling or focusing the overlay.
//! * [`LinuxLoopEvent::TerminalRevealReady`] — a generation-bound GTK frame-clock acknowledgement
//!   delivered after the parent paint that publishes a Wayland terminal-subsurface reveal.
//!
//! Ordering and coalescing: typed Host/WebKit/overlay events and non-redraw renderer events stay
//! one-for-one FIFO. Renderer [`UserEvent::Redraw`] is deliberately level-triggered: terminal
//! state was already committed to the shared paint cache, so at most one redraw wake needs to be
//! queued while the owner is behind. The owner clears that gate immediately before handling the
//! delivered redraw, which bounds sustained Grid/Damage traffic without losing an update. A send
//! after the loop has shut down returns the event back (`EventLoopClosed`), which is nonfatal
//! everywhere here — the UI no longer exists to consume the wake.

#![cfg(target_os = "linux")]

use super::event_bridge::HostEvent;
use super::overlay::{
    OverlayEvaluationResult, OverlayNativeAllocationReady, OverlayViewportReady,
    PersistentSuppressionResult,
};
use super::recovery::WebKitRecoveryEvent;
use crate::{UserEvent, UserEventSender};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

/// The Linux owner loop's typed Tao event: a renderer user event (client/bridge wake) or a
/// GTK-signal host event (input/geometry/IME). See the module docs.
pub enum LinuxLoopEvent {
    /// A [`UserEvent`] for `App::handle_user_event`.
    Renderer(UserEvent),
    /// A GTK-signal [`HostEvent`] for `App::handle_host_event`.
    Host(HostEvent),
    /// A WebKit signal classified for bounded recovery on this same owner loop.
    WebKitRecovery(WebKitRecoveryEvent),
    /// Completion of one modal-bearing overlay JavaScript task. The WebKit callback carries only
    /// an opaque attempt id and success bit; the owner loop decides whether it is still current.
    OverlayEvaluation(OverlayEvaluationResult),
    /// Completion of one persistent sidebar/topbar `inert` task. The owner loop joins all targets
    /// with modal delivery before exposing the overlay document.
    PersistentSuppression(PersistentSuppressionResult),
    /// Exact native GTK/WebKit geometry was observed for one presentation token. The owner loop
    /// revalidates it before requesting the content-blind DOM viewport acknowledgement.
    OverlayNativeAllocationReady(OverlayNativeAllocationReady),
    /// A current trusted overlay document acknowledged the expected CSS viewport.
    OverlayViewportReady(OverlayViewportReady),
    /// Bounded owner-loop failure when the complete modal-presentation join never finishes.
    OverlayPresentationTimeout { token: u64 },
    /// The GTK parent completed an after-paint phase for the current Wayland terminal reveal.
    /// WGPU remains gated until the owner loop accepts this exact generation.
    TerminalRevealReady { generation: u64 },
}

/// Level-triggered ownership for renderer redraw wakes.
///
/// Terminal Grid/Damage state is committed to the shared paint cache before the client reader
/// asks the owner loop to redraw. A redraw wake therefore carries no payload of its own: while one
/// redraw is already queued, later redraw sends are redundant because that queued draw observes
/// the newest cache state. Keeping at most one queued redraw prevents sustained terminal output
/// from growing the Tao/GLib FIFO until GTK input and compositor work are starved.
///
/// The owner clears `pending` immediately before handling the delivered redraw. That ordering is
/// important: a producer update racing with the current delivery either happened while the wake
/// was pending (and is covered by the current draw) or happens after the clear (and queues the next
/// draw). No update can be stranded without a wake.
#[derive(Default)]
pub struct RendererRedrawWake {
    pending: AtomicBool,
}

impl RendererRedrawWake {
    fn claim(&self) -> bool {
        if self.pending.load(Ordering::Acquire) {
            return false;
        }
        self.pending
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// A queued renderer event reached the owner loop. Only redraws participate in the gate;
    /// every other renderer event remains one-for-one FIFO.
    pub fn acknowledge(&self, event: &UserEvent) {
        if matches!(event, UserEvent::Redraw) {
            self.pending.store(false, Ordering::Release);
        }
    }

    fn send_failed(&self) {
        self.pending.store(false, Ordering::Release);
    }

    #[cfg(test)]
    fn is_pending(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }
}

/// Submit one renderer event through an injected owner-loop transport. This is the exact
/// production state machine factored from the Tao proxy so redraw burst, failure and race
/// semantics are testable without a display.
// The shared sender contract returns the original owned event when the loop is closed. Preserving
// that contract is more important than boxing an exceptional teardown-only value.
#[allow(clippy::result_large_err)]
fn submit_renderer_event<F>(
    redraw_wake: &RendererRedrawWake,
    event: UserEvent,
    send: F,
) -> Result<(), UserEvent>
where
    F: FnOnce(LinuxLoopEvent) -> Result<(), LinuxLoopEvent>,
{
    let is_redraw = matches!(event, UserEvent::Redraw);
    if is_redraw && !redraw_wake.claim() {
        return Ok(());
    }

    send(LinuxLoopEvent::Renderer(event)).map_err(|returned| match returned {
        LinuxLoopEvent::Renderer(event) => {
            if is_redraw {
                redraw_wake.send_failed();
            }
            event
        }
        // A closed-loop error returns exactly the value that was sent, and this function only
        // ever submits `Renderer`.
        LinuxLoopEvent::Host(_) => {
            unreachable!("renderer event transport only submits LinuxLoopEvent::Renderer")
        }
        LinuxLoopEvent::WebKitRecovery(_) => {
            unreachable!("renderer event transport only submits LinuxLoopEvent::Renderer")
        }
        LinuxLoopEvent::OverlayEvaluation(_) => {
            unreachable!("renderer event transport only submits LinuxLoopEvent::Renderer")
        }
        LinuxLoopEvent::PersistentSuppression(_) => {
            unreachable!("renderer event transport only submits LinuxLoopEvent::Renderer")
        }
        LinuxLoopEvent::OverlayNativeAllocationReady(_) => {
            unreachable!("renderer event transport only submits LinuxLoopEvent::Renderer")
        }
        LinuxLoopEvent::OverlayViewportReady(_) => {
            unreachable!("renderer event transport only submits LinuxLoopEvent::Renderer")
        }
        LinuxLoopEvent::OverlayPresentationTimeout { .. } => {
            unreachable!("renderer event transport only submits LinuxLoopEvent::Renderer")
        }
        LinuxLoopEvent::TerminalRevealReady { .. } => {
            unreachable!("renderer event transport only submits LinuxLoopEvent::Renderer")
        }
    })
}

/// The owner-loop sender held by the client reader thread and command bridge. Non-redraw
/// [`UserEvent`]s remain exact FIFO messages. Redraws are level-triggered through the shared
/// [`RendererRedrawWake`], bounding the Tao queue at one pending renderer redraw.
#[derive(Clone)]
pub struct LinuxUserEventSender {
    proxy: tao::event_loop::EventLoopProxy<LinuxLoopEvent>,
    redraw_wake: Arc<RendererRedrawWake>,
}

impl LinuxUserEventSender {
    pub fn new(
        proxy: tao::event_loop::EventLoopProxy<LinuxLoopEvent>,
        redraw_wake: Arc<RendererRedrawWake>,
    ) -> Self {
        Self { proxy, redraw_wake }
    }
}

impl UserEventSender for LinuxUserEventSender {
    // `UserEventSender` fixes the returned error to the unboxed event so a closed loop can hand
    // ownership back to its caller. Boxing here would change that shared transport contract.
    #[allow(clippy::result_large_err)]
    fn send(&self, event: UserEvent) -> Result<(), UserEvent> {
        submit_renderer_event(self.redraw_wake.as_ref(), event, |message| {
            self.proxy
                .send_event(message)
                .map_err(|tao::event_loop::EventLoopClosed(returned)| returned)
        })
    }

    fn clone_sender(&self) -> Box<dyn UserEventSender> {
        Box::new(self.clone())
    }
}

/// Direct GTK-signal → owner-loop HostEvent delivery: each `send` submits ONE
/// [`LinuxLoopEvent::Host`] through the loop transport, which is itself the wake. GTK callbacks
/// hold this instead of any queue or `App` access; the loop is the single `&mut App` owner.
///
/// Generic over the transport (`Fn(LinuxLoopEvent) -> Result<(), LinuxLoopEvent>`): production
/// injects the Tao proxy send; tests inject a recorder, so the delivery contract — immediate,
/// per-event, FIFO, closed-loop-tolerant — is provable without a display.
pub struct HostEventSender<F: Fn(LinuxLoopEvent) -> Result<(), LinuxLoopEvent>> {
    send: F,
}

/// WebKit signal → owner-loop delivery. Like [`HostEventSender`], this has no passive queue or
/// timer: the typed Tao proxy send is the wake, and a closed loop simply returns the event.
pub struct WebKitRecoveryEventSender<F: Fn(LinuxLoopEvent) -> Result<(), LinuxLoopEvent>> {
    send: F,
}

impl<F: Fn(LinuxLoopEvent) -> Result<(), LinuxLoopEvent>> WebKitRecoveryEventSender<F> {
    pub fn new(send: F) -> Self {
        Self { send }
    }

    pub fn send(&self, event: WebKitRecoveryEvent) {
        let _ = (self.send)(LinuxLoopEvent::WebKitRecovery(event));
    }
}

/// Production adapter over the Tao proxy. Keeping the closed-loop mapping here makes the exact
/// transport exercised by the injected sender tests the one every WebKit callback uses.
// Tao's closed-loop result owns the submitted event. Keep it exact so production and injected
// transports have the same semantics instead of boxing only this adapter's error path.
#[allow(clippy::result_large_err)]
pub fn webkit_recovery_sender(
    proxy: tao::event_loop::EventLoopProxy<LinuxLoopEvent>,
) -> WebKitRecoveryEventSender<impl Fn(LinuxLoopEvent) -> Result<(), LinuxLoopEvent>> {
    WebKitRecoveryEventSender::new(move |message| {
        proxy
            .send_event(message)
            .map_err(|tao::event_loop::EventLoopClosed(returned)| returned)
    })
}

impl<F: Fn(LinuxLoopEvent) -> Result<(), LinuxLoopEvent>> HostEventSender<F> {
    pub fn new(send: F) -> Self {
        Self { send }
    }

    /// Deliver one HostEvent to the owner loop. A closed loop (teardown) is nonfatal: the event
    /// dies with the window.
    pub fn send(&self, event: HostEvent) {
        let _ = (self.send)(LinuxLoopEvent::Host(event));
    }
}

/// Ownership of the one-shot GLib flush-deadline wake the owner loop arms for a pending trailing
/// resize/refit flush (tao's `WaitUntil` arms no GLib timer of its own — see `window_host::run`).
///
/// Invariants:
/// * At most ONE live source at a time; fully idle means NO source (no heartbeat, no polling).
/// * A live source is CANCELLED the moment it is superseded (deadline moved earlier), the moment
///   pending work clears, and at teardown (CloseRequested/LoopDestroyed/before `run` returns) —
///   with `run_return` the process outlives the loop, so an orphaned source would otherwise
///   survive host teardown and fire against the process-global GLib context.
/// * A FIRED source clears its own bookkeeping via [`on_fired`](Self::on_fired) WITHOUT a cancel:
///   GLib auto-removes a `_once` source, so removing its id again would be invalid. Only the live
///   source can ever fire — superseded sources are cancelled before replacement.
///
/// Generic over the source handle `H` (`glib::SourceId` in production, a token in tests) so the
/// arm/keep/replace/fire/clear/teardown state machine is provable without a GLib context.
pub struct FlushWake<H> {
    /// The live one-shot source and the deadline it was armed for. `None` = no timer outstanding.
    armed: Option<(std::time::Instant, H)>,
}

impl<H> FlushWake<H> {
    pub fn new() -> Self {
        Self { armed: None }
    }

    /// Whether a one-shot source is currently live.
    pub fn is_armed(&self) -> bool {
        self.armed.is_some()
    }

    /// Reconcile the live source with the flush deadline the App just reported. `None` (fully
    /// idle) cancels any live source. A live source armed at or before the deadline is KEPT (an
    /// early wake simply reconciles again — no arm/cancel churn during a resize burst). A
    /// deadline earlier than the live source cancels and re-arms. `arm` receives the duration
    /// until the deadline (+1ms: GLib timeouts have millisecond granularity; rounding down could
    /// wake a hair early and force a second source for the same flush).
    pub fn reconcile(
        &mut self,
        now: std::time::Instant,
        deadline: Option<std::time::Instant>,
        arm: impl FnOnce(std::time::Duration) -> H,
        cancel: impl FnOnce(H),
    ) {
        let Some(deadline) = deadline else {
            // Fully idle: no timer may remain (the no-heartbeat invariant).
            self.cancel_armed(cancel);
            return;
        };
        if let Some((armed_at, _)) = &self.armed {
            if *armed_at <= deadline {
                return;
            }
            // The deadline moved EARLIER: the live source is superseded — cancel it (it must
            // never fire against a replaced schedule) before arming the new one.
            self.cancel_armed(cancel);
        }
        // Guard: never arm a source whose deadline is not in the future. The flush that just ran
        // consumed all due work, so this only triggers on a stale deadline — and arming a
        // zero-length source there would risk a wake busy-loop.
        if deadline <= now {
            return;
        }
        let source = arm(deadline - now + std::time::Duration::from_millis(1));
        self.armed = Some((deadline, source));
    }

    /// The live source FIRED (GLib already removed the `_once` source): clear the bookkeeping
    /// WITHOUT cancelling. Safe unconditionally — superseded sources were cancelled before
    /// replacement, so a firing callback always belongs to the currently-armed source.
    pub fn on_fired(&mut self) {
        self.armed = None;
    }

    /// Cancel the live source if any — pending work cleared, CloseRequested/LoopDestroyed, or
    /// final teardown before `run` returns. Idempotent.
    pub fn cancel_armed(&mut self, cancel: impl FnOnce(H)) {
        if let Some((_, source)) = self.armed.take() {
            cancel(source);
        }
    }
}

// ============================================================================
// Direct-delivery contract tests. These run on the Linux CI/container path
// (the module is cfg(linux)); they need no Tao event loop or display — the
// transport is injected, exactly as `wire_events` injects the real proxy send.
// ============================================================================
#[cfg(test)]
mod tests {
    // The injected transports deliberately retain Tao's exact owned-event error shape. The test
    // helpers should exercise that production contract instead of boxing a test-only substitute.
    #![allow(clippy::result_large_err, clippy::type_complexity)]
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use super::super::event_bridge::{ime_commit_event, ime_preedit_event};
    use super::*;
    use crate::host_event::{HostIme, HostKey, HostKeyEvent, HostKeyLocation};

    /// A recording transport standing in for the Tao proxy: every accepted message is one
    /// owner-loop wake (tao pairs the channel push with `MainContext::wakeup`).
    fn recording_sender() -> (
        Rc<RefCell<Vec<LinuxLoopEvent>>>,
        HostEventSender<impl Fn(LinuxLoopEvent) -> Result<(), LinuxLoopEvent>>,
    ) {
        let log: Rc<RefCell<Vec<LinuxLoopEvent>>> = Rc::new(RefCell::new(Vec::new()));
        let sink = log.clone();
        let sender = HostEventSender::new(move |message| {
            sink.borrow_mut().push(message);
            Ok(())
        });
        (log, sender)
    }

    fn host_events(log: &Rc<RefCell<Vec<LinuxLoopEvent>>>) -> Vec<HostEvent> {
        log.borrow()
            .iter()
            .map(|m| match m {
                LinuxLoopEvent::Host(ev) => ev.clone(),
                LinuxLoopEvent::Renderer(_) => panic!("GTK delivery must never submit Renderer"),
                LinuxLoopEvent::WebKitRecovery(_) => {
                    panic!("GTK delivery must never submit WebKitRecovery")
                }
                LinuxLoopEvent::OverlayEvaluation(_) => {
                    panic!("GTK delivery must never submit OverlayEvaluation")
                }
                LinuxLoopEvent::PersistentSuppression(_) => {
                    panic!("GTK delivery must never submit PersistentSuppression")
                }
                LinuxLoopEvent::OverlayNativeAllocationReady(_) => {
                    panic!("GTK delivery must never submit OverlayNativeAllocationReady")
                }
                LinuxLoopEvent::OverlayViewportReady(_) => {
                    panic!("GTK delivery must never submit OverlayViewportReady")
                }
                LinuxLoopEvent::OverlayPresentationTimeout { .. } => {
                    panic!("GTK delivery must never submit OverlayPresentationTimeout")
                }
                LinuxLoopEvent::TerminalRevealReady { .. } => {
                    panic!("GTK delivery must never submit TerminalRevealReady")
                }
            })
            .collect()
    }

    #[test]
    fn ime_commit_and_preedit_each_wake_the_owner_loop() {
        // The regression this design exists for: IM commit/preedit must generate their own
        // owner-loop wakes. Each send below is one proxy message == one MainContext wake; there
        // is no queue that could hold the event awaiting unrelated activity.
        let (log, sender) = recording_sender();
        sender.send(ime_preedit_event("あ"));
        sender.send(ime_commit_event("あ"));
        let delivered = host_events(&log);
        assert_eq!(delivered.len(), 2, "one owner-loop message per IME event");
        assert!(matches!(delivered[0], HostEvent::Ime(HostIme::Preedit(_))));
        assert!(matches!(delivered[1], HostEvent::Ime(HostIme::Commit(_))));
    }

    #[test]
    fn im_consumed_keypress_delivery_needs_no_top_level_propagation() {
        // An IME-consumed keypress returns `Propagation::Stop`, so GTK never propagates it to the
        // top level and Tao translates NOTHING for it. The commit the IM context emits instead
        // must reach the loop purely through this sender — modeled here as the ONLY call made,
        // with no other activity of any kind.
        let (log, sender) = recording_sender();
        sender.send(ime_commit_event("é"));
        let delivered = host_events(&log);
        assert_eq!(
            delivered.len(),
            1,
            "the IM commit is delivered by its own send, not by later propagation"
        );
        assert!(matches!(
            delivered[0],
            HostEvent::Ime(HostIme::Commit(ref text)) if text == "é"
        ));
    }

    #[test]
    fn multiple_host_events_remain_ordered() {
        // The proxy channel is one FIFO: emit order == delivery order, including a keyboard
        // event between IME traffic and focus changes.
        let (log, sender) = recording_sender();
        sender.send(HostEvent::Focused(true));
        sender.send(ime_preedit_event("a"));
        sender.send(HostEvent::Keyboard(HostKeyEvent {
            key: HostKey::Character("x".to_string()),
            text: Some("x".to_string()),
            base_text: Some("x".to_string()),
            location: HostKeyLocation::Standard,
            pressed: true,
            repeat: false,
        }));
        sender.send(ime_commit_event("a"));
        sender.send(HostEvent::CursorLeft);

        let delivered = host_events(&log);
        assert_eq!(delivered.len(), 5);
        assert!(matches!(delivered[0], HostEvent::Focused(true)));
        assert!(matches!(delivered[1], HostEvent::Ime(HostIme::Preedit(_))));
        assert!(matches!(delivered[2], HostEvent::Keyboard(_)));
        assert!(matches!(delivered[3], HostEvent::Ime(HostIme::Commit(_))));
        assert!(matches!(delivered[4], HostEvent::CursorLeft));
    }

    #[test]
    fn closed_owner_loop_is_harmless() {
        // Teardown: the transport refuses every message (the Tao loop is gone). Sends must be
        // silent no-ops — no panic, no retry — matching the `let _ =` production policy.
        let sender = HostEventSender::new(Err);
        sender.send(ime_commit_event("x"));
        sender.send(HostEvent::Focused(false));
        sender.send(HostEvent::CursorLeft);
    }

    #[test]
    fn renderer_redraw_burst_queues_exactly_one_wake_until_delivery() {
        let wake = RendererRedrawWake::default();
        let sent = AtomicUsize::new(0);
        for _ in 0..10_000 {
            submit_renderer_event(&wake, UserEvent::Redraw, |message| {
                assert!(matches!(
                    message,
                    LinuxLoopEvent::Renderer(UserEvent::Redraw)
                ));
                sent.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
            .expect("open owner loop");
        }

        assert_eq!(sent.load(Ordering::Relaxed), 1);
        assert!(wake.is_pending());

        wake.acknowledge(&UserEvent::Redraw);
        submit_renderer_event(&wake, UserEvent::Redraw, |message| {
            assert!(matches!(
                message,
                LinuxLoopEvent::Renderer(UserEvent::Redraw)
            ));
            sent.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .expect("next redraw after delivery");
        assert_eq!(sent.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn renderer_redraw_gate_is_shared_across_concurrent_producers() {
        let wake = Arc::new(RendererRedrawWake::default());
        let sent = Arc::new(AtomicUsize::new(0));
        let mut producers = Vec::new();
        for _ in 0..8 {
            let wake = wake.clone();
            let sent = sent.clone();
            producers.push(std::thread::spawn(move || {
                for _ in 0..1_000 {
                    submit_renderer_event(&wake, UserEvent::Redraw, |message| {
                        assert!(matches!(
                            message,
                            LinuxLoopEvent::Renderer(UserEvent::Redraw)
                        ));
                        sent.fetch_add(1, Ordering::Relaxed);
                        Ok(())
                    })
                    .expect("open owner loop");
                }
            }));
        }
        for producer in producers {
            producer.join().expect("producer thread");
        }

        assert_eq!(sent.load(Ordering::Relaxed), 1);
        assert!(wake.is_pending());
    }

    #[test]
    fn redraw_acknowledge_before_handle_covers_old_state_and_wakes_new_state() {
        // Model the real ordering: the reader commits shared paint state BEFORE asking for a
        // redraw, while the owner clears the gate immediately BEFORE drawing that shared state.
        let wake = RendererRedrawWake::default();
        let paint_revision = AtomicUsize::new(1);
        let sent = AtomicUsize::new(0);

        let queue_redraw = || {
            submit_renderer_event(&wake, UserEvent::Redraw, |_message| {
                sent.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
            .expect("open owner loop");
        };

        queue_redraw();
        paint_revision.store(2, Ordering::Release);
        queue_redraw();
        assert_eq!(sent.load(Ordering::Relaxed), 1);

        // Delivery acknowledges first. The current draw then observes revision 2, including the
        // update whose redundant wake was coalesced while revision 1's wake was pending.
        wake.acknowledge(&UserEvent::Redraw);
        assert_eq!(paint_revision.load(Ordering::Acquire), 2);

        // An update racing after that clear cannot be stranded behind the current draw: it claims
        // a fresh pending marker and queues the next owner-loop wake.
        paint_revision.store(3, Ordering::Release);
        queue_redraw();
        assert_eq!(sent.load(Ordering::Relaxed), 2);
        assert!(wake.is_pending());
    }

    #[test]
    fn renderer_non_redraw_events_remain_exact_fifo_during_a_redraw_burst() {
        let wake = RendererRedrawWake::default();
        let delivered = RefCell::new(Vec::new());
        let record = |event, label| {
            submit_renderer_event(&wake, event, |message| {
                assert!(matches!(message, LinuxLoopEvent::Renderer(_)));
                delivered.borrow_mut().push(label);
                Ok(())
            })
            .expect("open owner loop");
        };

        record(UserEvent::Redraw, "redraw");
        record(UserEvent::Redraw, "coalesced-redraw");
        record(UserEvent::TerminalBell, "bell");
        record(
            UserEvent::TerminalTitle {
                title: Some("title".to_string()),
            },
            "title",
        );
        record(UserEvent::Redraw, "coalesced-redraw-2");

        assert_eq!(&*delivered.borrow(), &["redraw", "bell", "title"]);
    }

    #[test]
    fn acknowledging_a_non_redraw_event_does_not_release_the_redraw_gate() {
        let wake = RendererRedrawWake::default();
        let sent = AtomicUsize::new(0);
        let queue_redraw = || {
            submit_renderer_event(&wake, UserEvent::Redraw, |_message| {
                sent.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
            .expect("open owner loop");
        };

        queue_redraw();
        wake.acknowledge(&UserEvent::TerminalBell);
        queue_redraw();

        assert_eq!(sent.load(Ordering::Relaxed), 1);
        assert!(wake.is_pending());
    }

    #[test]
    fn failed_redraw_send_releases_gate_for_a_later_attempt() {
        let wake = RendererRedrawWake::default();
        let failed = submit_renderer_event(&wake, UserEvent::Redraw, Err)
            .expect_err("closed owner loop returns redraw");
        assert!(matches!(failed, UserEvent::Redraw));
        assert!(!wake.is_pending());

        let sent = AtomicUsize::new(0);
        submit_renderer_event(&wake, UserEvent::Redraw, |_message| {
            sent.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .expect("a later open-loop send is not suppressed");
        assert_eq!(sent.load(Ordering::Relaxed), 1);
        assert!(wake.is_pending());
    }

    #[test]
    fn closed_owner_loop_drops_recovery_event_without_retry_or_panic() {
        use super::super::recovery::{WebKitFailureReason, WebKitRecoveryEvent, WebKitSurface};

        let sender = WebKitRecoveryEventSender::new(Err);
        for surface in [WebKitSurface::Sidebar, WebKitSurface::Topbar] {
            sender.send(WebKitRecoveryEvent::Failure {
                surface,
                generation: Some(0),
                reason: WebKitFailureReason::ProcessTerminated,
            });
        }
    }

    #[test]
    fn sidebar_and_topbar_recovery_signals_preserve_fifo_and_identity() {
        use super::super::recovery::{WebKitFailureReason, WebKitRecoveryEvent, WebKitSurface};

        let log = Rc::new(RefCell::new(Vec::new()));
        let sink = log.clone();
        let sender = WebKitRecoveryEventSender::new(move |message| {
            sink.borrow_mut().push(message);
            Ok(())
        });
        for surface in [WebKitSurface::Sidebar, WebKitSurface::Topbar] {
            sender.send(WebKitRecoveryEvent::Failure {
                surface,
                generation: Some(0),
                reason: WebKitFailureReason::ProcessTerminated,
            });
        }
        let surfaces: Vec<_> = log
            .borrow()
            .iter()
            .map(|message| match message {
                LinuxLoopEvent::WebKitRecovery(event) => event.surface(),
                _ => panic!("recovery sender submitted a non-recovery event"),
            })
            .collect();
        assert_eq!(surfaces, [WebKitSurface::Sidebar, WebKitSurface::Topbar]);
    }
}

// ============================================================================
// FlushWake state-machine tests: arm, keep, replace, fire, clear, teardown.
// The source handle is a plain token and the arm/cancel effects are recorded,
// so the exact GLib source ownership discipline is provable without a display.
// ============================================================================
#[cfg(test)]
mod flush_wake_tests {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    use super::FlushWake;

    /// Recorded arm/cancel effects; each armed source gets a fresh token id.
    struct Effects {
        log: Rc<RefCell<Vec<String>>>,
        next_id: Rc<RefCell<u32>>,
    }

    impl Effects {
        fn new() -> Self {
            Self {
                log: Rc::new(RefCell::new(Vec::new())),
                next_id: Rc::new(RefCell::new(1)),
            }
        }
        fn arm(&self) -> impl FnOnce(Duration) -> u32 + '_ {
            move |_duration| {
                let id = *self.next_id.borrow();
                *self.next_id.borrow_mut() += 1;
                self.log.borrow_mut().push(format!("arm:{id}"));
                id
            }
        }
        fn cancel(&self) -> impl FnOnce(u32) + '_ {
            move |id| self.log.borrow_mut().push(format!("cancel:{id}"))
        }
        fn log(&self) -> Vec<String> {
            self.log.borrow().clone()
        }
    }

    #[test]
    fn idle_arms_nothing_and_pending_arms_exactly_one() {
        let fx = Effects::new();
        let mut wake = FlushWake::new();
        let now = Instant::now();

        // Fully idle: nothing armed, nothing cancelled — the no-heartbeat invariant.
        wake.reconcile(now, None, fx.arm(), fx.cancel());
        assert!(!wake.is_armed());
        assert!(fx.log().is_empty());

        // A pending flush arms exactly one source for its deadline.
        wake.reconcile(
            now,
            Some(now + Duration::from_millis(33)),
            fx.arm(),
            fx.cancel(),
        );
        assert!(wake.is_armed());
        assert_eq!(fx.log(), vec!["arm:1"]);
    }

    #[test]
    fn live_source_covering_the_deadline_is_kept() {
        let fx = Effects::new();
        let mut wake = FlushWake::new();
        let now = Instant::now();
        wake.reconcile(
            now,
            Some(now + Duration::from_millis(33)),
            fx.arm(),
            fx.cancel(),
        );

        // Same deadline and a LATER deadline are both already covered: no churn.
        wake.reconcile(
            now,
            Some(now + Duration::from_millis(33)),
            fx.arm(),
            fx.cancel(),
        );
        wake.reconcile(
            now,
            Some(now + Duration::from_millis(90)),
            fx.arm(),
            fx.cancel(),
        );
        assert_eq!(
            fx.log(),
            vec!["arm:1"],
            "a covering source is never re-armed"
        );
    }

    #[test]
    fn earlier_deadline_cancels_then_replaces_the_live_source() {
        let fx = Effects::new();
        let mut wake = FlushWake::new();
        let now = Instant::now();
        wake.reconcile(
            now,
            Some(now + Duration::from_millis(90)),
            fx.arm(),
            fx.cancel(),
        );
        wake.reconcile(
            now,
            Some(now + Duration::from_millis(33)),
            fx.arm(),
            fx.cancel(),
        );
        assert_eq!(
            fx.log(),
            vec!["arm:1", "cancel:1", "arm:2"],
            "the superseded source is cancelled before its replacement is armed"
        );
        assert!(wake.is_armed());
    }

    #[test]
    fn cleared_work_cancels_the_live_source() {
        let fx = Effects::new();
        let mut wake = FlushWake::new();
        let now = Instant::now();
        wake.reconcile(
            now,
            Some(now + Duration::from_millis(33)),
            fx.arm(),
            fx.cancel(),
        );
        wake.reconcile(now, None, fx.arm(), fx.cancel());
        assert_eq!(fx.log(), vec!["arm:1", "cancel:1"]);
        assert!(!wake.is_armed(), "idle again: no timer outstanding");
    }

    #[test]
    fn fired_source_clears_bookkeeping_without_cancel_and_rearms_cleanly() {
        let fx = Effects::new();
        let mut wake = FlushWake::new();
        let now = Instant::now();
        wake.reconcile(
            now,
            Some(now + Duration::from_millis(33)),
            fx.arm(),
            fx.cancel(),
        );

        // The one-shot fired: GLib already removed it, so bookkeeping clears with NO cancel.
        wake.on_fired();
        assert!(!wake.is_armed());

        // The next pending deadline arms a fresh source — no cancel of the dead id.
        wake.reconcile(
            now,
            Some(now + Duration::from_millis(33)),
            fx.arm(),
            fx.cancel(),
        );
        assert_eq!(fx.log(), vec!["arm:1", "arm:2"]);
    }

    #[test]
    fn teardown_cancels_the_live_source_and_is_idempotent() {
        let fx = Effects::new();
        let mut wake = FlushWake::new();
        let now = Instant::now();
        wake.reconcile(
            now,
            Some(now + Duration::from_millis(33)),
            fx.arm(),
            fx.cancel(),
        );

        // CloseRequested/LoopDestroyed/before-return: the live source must not survive.
        wake.cancel_armed(fx.cancel());
        wake.cancel_armed(fx.cancel());
        assert_eq!(
            fx.log(),
            vec!["arm:1", "cancel:1"],
            "second cancel is a no-op"
        );
        assert!(!wake.is_armed());
    }

    #[test]
    fn stale_past_deadline_never_arms() {
        // Anti-busy-loop guard: a deadline not in the future arms nothing (the flush that just
        // ran consumed all due work; the next real event reconciles again).
        let fx = Effects::new();
        let mut wake = FlushWake::new();
        let now = Instant::now();
        wake.reconcile(
            now,
            Some(now - Duration::from_millis(1)),
            fx.arm(),
            fx.cancel(),
        );
        assert!(!wake.is_armed());
        assert!(fx.log().is_empty());
    }
}
