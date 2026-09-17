//! Window-domain tab selection / switching / strip projection / close + closed-tab session
//! lifecycle for `maestro-app`.
//!
//! This module holds the PURE, unit-testable window/tab surface. It contains the
//! tab-selection resolver ([`select_window_tab_session`]) and its DTO/error ([`TabSelection`],
//! [`TabSelectionError`]); the renderer command-sink seam ([`RendererCommandSink`]); the app-owned
//! tab-switch controller/runtime ([`TabSwitchController`], [`RendererTabRuntime`], [`ActiveTab`]) and
//! their typed error ([`TabSwitchError`]); the pure tab activation / close / next-active / only-tab
//! transition cores ([`apply_tab_activation`], [`apply_inactive_tab_close`], [`apply_active_tab_close`],
//! [`apply_only_tab_close`], [`plan_next_active_tab`], [`is_active_tab_close`],
//! [`selection_from_strip_tabs`]) and their outcomes; the legacy projection-only closed-tab lifecycle
//! classifier/executor ([`plan_closed_tab_session_lifecycle`],
//! [`execute_closed_tab_session_lifecycle`]); the
//! [`WindowRecordParams`] launch-record DTO; the tab-strip DTOs/projections ([`AttentionJson`],
//! [`WindowTabJson`], [`WindowViewTabJson`], [`TabStripItem`], [`TabStripModel`], [`TabStripModelError`],
//! [`build_tab_strip_model`], [`build_tab_strip_model_from_window_view`], [`tab_strip_model_changed`],
//! [`renderer_tab_strip`], [`tab_record_json`]); and the live-strip/durable-record new-tab snapshot
//! helpers ([`new_tab_snapshot_from_strip_tabs`], [`new_tab_snapshot_from_tab_records`]).
//!
//! These items perform no process IO of their own. The argument PARSER (`window ...`), the window
//! success/failure JSON envelopes (`WindowLayoutSuccess`/`WindowViewSuccess`/`WindowFailure`), the
//! `NewTab*` planning/runtime/recovery surface, and the live event-loop runners deliberately remain in
//! `lib.rs`; the crate root re-exports this module's public items for `maestro_app::<Item>` callers.
//! This module REFERENCES the `NewTabSnapshot` type and the
//! attention/indicator helpers via `use crate::{...}`; it does not own them.

// Settlement variants retain the exact pending viewport authority required for retry/neutralize.
#![allow(clippy::large_enum_variant)]

use serde::Serialize;

use crate::{
    attention_needs_attention, attention_source_wire_str, attention_wire_str,
    renderer_attention_indicator, tab_attention_indicator, AttentionJson, LaunchArgs,
    NewTabSnapshot, TabAttentionIndicator,
};

/// The resolved parameters for recording a launched session into a window layout. Built by
/// [`resolve_window_record`] from the launch flags + session id (pure); consumed by the process-IO
/// recording helper in `main.rs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowRecordParams {
    pub window_id: String,
    pub tab_id: String,
    pub tab_title: String,
    pub tab_pinned: bool,
}

/// The default window id used by `launch --record-window` when `--window-id` is omitted.
pub const DEFAULT_WINDOW_ID: &str = "main";

/// Resolve the effective window-record parameters from the parsed launch flags and the launch
/// `session_id`, applying the documented defaults. Pure so the defaulting is unit-testable without
/// any store IO. Returns `None` when `--record-window` was not given.
pub fn resolve_window_record(args: &LaunchArgs, session_id: &str) -> Option<WindowRecordParams> {
    if !args.record_window {
        return None;
    }
    let window_id = args
        .record_window_id
        .clone()
        .unwrap_or_else(|| DEFAULT_WINDOW_ID.to_string());
    let tab_id = args
        .record_tab_id
        .clone()
        .unwrap_or_else(|| session_id.to_string());
    let tab_title = args
        .record_tab_title
        .clone()
        .or_else(|| args.title.clone())
        .unwrap_or_else(|| session_id.to_string());
    let tab_pinned = args.record_tab_pinned.unwrap_or(false);
    Some(WindowRecordParams {
        window_id,
        tab_id,
        tab_title,
        tab_pinned,
    })
}

/// A single tab in an ordered window layout, reduced to the fields the future tab
/// shell needs to decide which session a selected tab points at. This is a PURE DTO:
/// `maestro-app/src/lib.rs` deliberately does NOT depend on `maestro-shell`, so the
/// caller in `main.rs` projects a loaded `WindowLayout`'s `TabRecord`s into these
/// before calling [`select_window_tab_session`]. Keeping the decision pure here makes
/// it deterministic and unit-testable with no daemon/store/renderer dependency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TabSelection {
    /// The tab's stable identity (durable across reorder/rename).
    pub tab_id: String,
    /// The daemon session this tab's viewport should attach to.
    pub session_id: String,
}

/// Why resolving a tab selection failed. Typed so the caller reacts without parsing
/// strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TabSelectionError {
    /// No tab in the layout has the requested `tab_id`.
    TabNotFound { tab_id: String },
    /// Two or more tabs share the requested `tab_id` — an ambiguous layout the caller
    /// must not silently resolve to the first match.
    AmbiguousTab { tab_id: String, count: usize },
}

impl std::fmt::Display for TabSelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TabSelectionError::TabNotFound { tab_id } => {
                write!(f, "no tab with id {tab_id:?} in the window layout")
            }
            TabSelectionError::AmbiguousTab { tab_id, count } => {
                write!(f, "tab id {tab_id:?} appears {count} times in the layout")
            }
        }
    }
}

impl std::error::Error for TabSelectionError {}

/// Resolve which daemon session the future tab shell should attach the single renderer
/// to when the tab `tab_id` is selected from an ordered `layout`.
///
/// This is the PURE app-side half of the renderer rebind primitive: given the durable
/// layout (projected into [`TabSelection`]s) and a selected tab id, return that tab's
/// `session_id`. The caller then posts `UserEvent::AttachSession { session_id }` to the
/// renderer. This helper never connects to the daemon, mutates records, spawns
/// anything, or touches the renderer — it only does the lookup.
///
/// Errors are typed: a missing tab is [`TabSelectionError::TabNotFound`]; a layout with
/// the same `tab_id` twice is [`TabSelectionError::AmbiguousTab`] (we refuse to pick
/// the first rather than silently attach the wrong session).
pub fn select_window_tab_session(
    layout: &[TabSelection],
    tab_id: &str,
) -> Result<String, TabSelectionError> {
    let mut matches = layout.iter().filter(|t| t.tab_id == tab_id);
    let Some(first) = matches.next() else {
        return Err(TabSelectionError::TabNotFound {
            tab_id: tab_id.to_string(),
        });
    };
    let extra = matches.count();
    if extra > 0 {
        return Err(TabSelectionError::AmbiguousTab {
            tab_id: tab_id.to_string(),
            count: extra + 1,
        });
    }
    Ok(first.session_id.clone())
}

/// A sink that delivers a [`maestro_renderer::RendererCommand`] to an already-running
/// in-process renderer's command channel. Abstracted so [`TabSwitchController`] stays
/// GUI-free and unit-testable: production code injects an `mpsc::Sender<RendererCommand>`
/// (which has a blanket impl below), tests inject a closure or a recording fake.
///
/// `send` returns `Err(())` when the channel is closed (the renderer event loop is gone),
/// mirroring the `Result<(), ()>` shape the renderer's own `bridge_commands` sink uses.
pub trait RendererCommandSink {
    // `Result<(), ()>` deliberately mirrors `maestro_renderer::bridge_commands`' sink
    // contract: the only failure mode is "channel closed", carrying no payload. A richer
    // error type here would have to be discarded at that boundary, so we keep the unit
    // error and let `TabSwitchController` translate it into the typed `TabSwitchError`.
    #[allow(clippy::result_unit_err)]
    fn send(&self, command: maestro_renderer::RendererCommand) -> Result<(), ()>;
}

impl RendererCommandSink for std::sync::mpsc::Sender<maestro_renderer::RendererCommand> {
    fn send(&self, command: maestro_renderer::RendererCommand) -> Result<(), ()> {
        std::sync::mpsc::Sender::send(self, command).map_err(|_| ())
    }
}

impl<F> RendererCommandSink for F
where
    F: Fn(maestro_renderer::RendererCommand) -> Result<(), ()>,
{
    fn send(&self, command: maestro_renderer::RendererCommand) -> Result<(), ()> {
        self(command)
    }
}

/// Why switching the renderer to a persisted tab failed. Typed so future GUI code reacts
/// without parsing strings. Window-scoped: a missing or duplicate tab carries the
/// `window_id` it was looked up under, unlike the bare [`TabSelectionError`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TabSwitchError {
    /// No tab with `tab_id` exists in the given window's layout.
    TabNotFound { window_id: String, tab_id: String },
    /// The window's layout has `tab_id` more than once; refuse to guess which session.
    AmbiguousTab { window_id: String, tab_id: String },
    /// The renderer command channel is closed (event loop gone); the switch was not
    /// delivered and the active tab is left unchanged.
    RendererControlClosed,
    /// Ordinary exact viewport requests need the same renderer lifecycle sender that the owner
    /// passed to `run_renderer_with_commands_and_events`. Without it the App could enqueue an
    /// Attach whose terminal publication proof has no route back to the listener.
    RendererEventChannelUnavailable,
    /// One exact lifetime handoff is still awaiting a correlated renderer disposition. No later
    /// switch may overtake it or replace its rollback coordinate.
    HandoffPending,
    /// A textual window/tab/session selection carries no PTY lifetime authority. The caller must
    /// load one coherent Shell viewport snapshot and use the exact viewport request seam.
    ViewportAuthorityRequired,
    /// The one-snapshot viewport could not be projected into a coherent renderer cohort.
    ViewportProjection(RendererViewportProjectionError),
}

impl std::fmt::Display for TabSwitchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TabSwitchError::TabNotFound { window_id, tab_id } => {
                write!(f, "no tab {tab_id:?} in window {window_id:?}")
            }
            TabSwitchError::AmbiguousTab { window_id, tab_id } => {
                write!(
                    f,
                    "tab {tab_id:?} appears more than once in window {window_id:?}"
                )
            }
            TabSwitchError::RendererControlClosed => {
                write!(f, "renderer control channel is closed")
            }
            TabSwitchError::RendererEventChannelUnavailable => {
                write!(f, "renderer lifecycle event channel is unavailable")
            }
            TabSwitchError::HandoffPending => {
                write!(f, "renderer exact viewport transition is still pending")
            }
            TabSwitchError::ViewportAuthorityRequired => {
                write!(f, "renderer switch requires an exact viewport authority")
            }
            TabSwitchError::ViewportProjection(error) => {
                write!(f, "renderer viewport projection failed: {error}")
            }
        }
    }
}

impl std::error::Error for TabSwitchError {}

/// App-owned bridge between a persisted window layout and the renderer's public control
/// channel. Selecting a tab resolves its `session_id` via the existing pure
/// [`select_window_tab_session`] lookup and pushes a
/// `maestro_renderer::RendererCommand::AttachSession` into the injected
/// [`RendererCommandSink`].
///
/// This is NOT a GUI tab strip. It parses no CLI args, spawns/connects no daemon, launches
/// no renderer, and mutates no persisted layout — it only decides what to send and tracks
/// the active tab. Active-tab state advances ONLY after a successful send, so a closed
/// channel or a lookup error leaves the controller unchanged.
pub struct TabSwitchController<S> {
    // Crate-internal so the in-crate test module in `lib.rs` can inspect a recording sink after a
    // switch (it was module-private when the controller lived in `lib.rs`). NOT public API.
    pub(crate) sender: S,
    active_viewport: Option<ActiveRendererViewport>,
    pending_viewport: Option<PendingRendererViewport>,
    /// Clear keeps the correlated facts drainable but irrevocably closes their adoption path.
    /// A queued Published/Claimed disposition after the Clear FIFO admission is therefore consumed
    /// only as a neutral terminal observation.
    pending_viewport_adoption_allowed: bool,
}

/// The full binding of the renderer's currently attached tab. Window-scoped because a bare
/// `tab_id` is NOT unique across windows, and session-scoped because a second local writer may
/// retarget the same durable `(window_id, tab_id)` row to a replacement session. The no-op check
/// must compare all three fields; otherwise an idle projection can paint the replacement row while
/// the native viewport keeps consuming the old PTY.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveTab {
    pub window_id: String,
    pub tab_id: String,
    pub session_id: String,
}

/// One coherent App projection derived exclusively from Shell's all-or-none viewport snapshot.
/// Presentation remains generation-free; `exact_viewport` is the separate immutable Attach
/// authority for exactly the same visible tab/session cohort and primary role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RendererViewportProjection {
    target: ActiveTab,
    strip_tabs: Vec<WindowTabJson>,
    selection: Vec<TabSelection>,
    strip_model: TabStripModel,
    tab_strip: maestro_renderer::RendererTabStrip,
    exact_viewport: maestro_renderer::RendererExactViewport,
}

impl RendererViewportProjection {
    pub fn target(&self) -> &ActiveTab {
        &self.target
    }

    pub fn selection(&self) -> &[TabSelection] {
        &self.selection
    }

    pub fn strip_tabs(&self) -> &[WindowTabJson] {
        &self.strip_tabs
    }

    pub fn strip_model(&self) -> &TabStripModel {
        &self.strip_model
    }

    pub fn tab_strip(&self) -> &maestro_renderer::RendererTabStrip {
        &self.tab_strip
    }

    pub fn exact_viewport(&self) -> &maestro_renderer::RendererExactViewport {
        &self.exact_viewport
    }

    pub fn generation(&self) -> &str {
        self.exact_viewport.primary().generation()
    }
}

/// Typed failure from the single Shell-snapshot → renderer cohort projection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RendererViewportProjectionError {
    Strip(TabStripModelError),
    Exact(maestro_renderer::RendererExactViewportError),
}

impl std::fmt::Display for RendererViewportProjectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Strip(error) => error.fmt(formatter),
            Self::Exact(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for RendererViewportProjectionError {}

/// Build the sole production renderer projection from one coherent Shell snapshot. Stashed tabs
/// stay durable but absent from the visible cohort; the same primary tab drives the selection,
/// generation-free strip and immutable exact viewport.
pub fn renderer_viewport_projection_from_snapshot(
    snapshot: &maestro_shell::WindowViewportSnapshot,
    primary_tab_id: &str,
) -> Result<RendererViewportProjection, RendererViewportProjectionError> {
    let layout = &snapshot.window().layout;
    let visible_tabs = live_tab_records_json(&layout.tabs);
    let selection = selection_from_strip_tabs(&visible_tabs);
    let strip_model = build_tab_strip_model(&layout.window_id, &visible_tabs, Some(primary_tab_id))
        .map_err(RendererViewportProjectionError::Strip)?;
    let tab_strip = renderer_tab_strip(&strip_model);
    let exact_viewport =
        maestro_renderer::RendererExactViewport::from_window_snapshot(snapshot, primary_tab_id)
            .map_err(RendererViewportProjectionError::Exact)?;
    let session_id = select_window_tab_session(&selection, primary_tab_id).map_err(|_| {
        RendererViewportProjectionError::Exact(
            maestro_renderer::RendererExactViewportError::PrimaryMissing,
        )
    })?;
    if exact_viewport.window_id() != layout.window_id
        || exact_viewport.primary_tab_id() != primary_tab_id
        || exact_viewport.primary().session_id() != session_id
    {
        return Err(RendererViewportProjectionError::Exact(
            maestro_renderer::RendererExactViewportError::CohortMismatch,
        ));
    }
    Ok(RendererViewportProjection {
        target: ActiveTab {
            window_id: layout.window_id.clone(),
            tab_id: primary_tab_id.to_string(),
            session_id,
        },
        strip_tabs: visible_tabs,
        selection,
        strip_model,
        tab_strip,
        exact_viewport,
    })
}

/// The App's adopted renderer viewport. Textual coordinates are accompanied by the exact daemon
/// instance, PTY generation and immutable all-pane cohort proven by the renderer disposition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveRendererViewport {
    projection: RendererViewportProjection,
    daemon_instance_id: maestro_shell::DaemonInstanceId,
}

impl ActiveRendererViewport {
    pub fn target(&self) -> &ActiveTab {
        self.projection.target()
    }

    pub fn projection(&self) -> &RendererViewportProjection {
        &self.projection
    }

    pub fn daemon_instance_id(&self) -> &maestro_shell::DaemonInstanceId {
        &self.daemon_instance_id
    }

    pub fn generation(&self) -> &str {
        self.projection.generation()
    }
}

/// App-side correlation for the sole renderer transition in flight. Neither variant advances the
/// active viewport on command send; only its matching proof disposition can consume and adopt it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingRendererViewport {
    Ordinary {
        request_id: maestro_renderer::RendererExactViewportRequestId,
        target: RendererViewportProjection,
        previous_active: Option<ActiveRendererViewport>,
    },
    Handoff {
        request_id: maestro_renderer::RendererAttachmentHandoffRequestId,
        target: RendererViewportProjection,
        previous_active: Option<ActiveRendererViewport>,
        expected_daemon_instance: maestro_shell::DaemonInstanceId,
        expected_generation: String,
    },
}

impl PendingRendererViewport {
    pub fn target(&self) -> &RendererViewportProjection {
        match self {
            Self::Ordinary { target, .. } | Self::Handoff { target, .. } => target,
        }
    }

    pub fn previous_active(&self) -> Option<&ActiveRendererViewport> {
        match self {
            Self::Ordinary {
                previous_active, ..
            }
            | Self::Handoff {
                previous_active, ..
            } => previous_active.as_ref(),
        }
    }

    pub fn handoff_request_id(
        &self,
    ) -> Option<maestro_renderer::RendererAttachmentHandoffRequestId> {
        match self {
            Self::Handoff { request_id, .. } => Some(*request_id),
            Self::Ordinary { .. } => None,
        }
    }

    pub fn ordinary_request_id(&self) -> Option<maestro_renderer::RendererExactViewportRequestId> {
        match self {
            Self::Ordinary { request_id, .. } => Some(*request_id),
            Self::Handoff { .. } => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RendererViewportSettlement {
    Stale,
    Adopted(ActiveRendererViewport),
    Neutralized(PendingRendererViewport),
}

impl<S: RendererCommandSink> TabSwitchController<S> {
    /// Build a controller with no active tab yet.
    pub fn new(sender: S) -> Self {
        Self {
            sender,
            active_viewport: None,
            pending_viewport: None,
            pending_viewport_adoption_allowed: false,
        }
    }

    /// Record `(window_id, tab_id, session_id)` as the active binding WITHOUT sending any
    /// `RendererCommand`. This is for the known initial renderer launch, where the renderer is
    /// started already attached to the selected tab's session (so a `switch_to` would only
    /// enqueue a duplicate attach). It does not touch the sender, so the receiver need not be
    /// alive. It does not weaken `switch_to`: a later switch to the SAME complete binding is the
    /// usual no-op, while a replacement session for the same row sends normally.
    pub fn seed_active_tab(&mut self, window_id: &str, tab_id: &str, session_id: &str) {
        let _ = (window_id, tab_id, session_id);
        // Textual startup facts cannot prove a PTY lifetime. Kept temporarily as a source-compatible
        // fail-closed seam while production call sites migrate to `install_initial_handoff`.
        self.active_viewport = None;
    }

    /// The full active coordinate (`window_id` + `tab_id`), if any tab has been switched to.
    pub fn active_tab_key(&self) -> Option<&ActiveTab> {
        self.active_viewport
            .as_ref()
            .map(ActiveRendererViewport::target)
    }

    pub fn active_viewport(&self) -> Option<&ActiveRendererViewport> {
        self.active_viewport.as_ref()
    }

    /// Unit-test-only setup for display/chrome helpers that are unrelated to Attach admission.
    /// Tests must supply a real coherent projection and a validated daemon instance; textual
    /// coordinates alone never become active, even in this seam.
    #[cfg(test)]
    fn seed_exact_active_for_test(
        &mut self,
        projection: RendererViewportProjection,
        daemon_instance_id: maestro_shell::DaemonInstanceId,
    ) {
        self.pending_viewport = None;
        self.pending_viewport_adoption_allowed = false;
        self.active_viewport = Some(ActiveRendererViewport {
            projection,
            daemon_instance_id,
        });
    }

    /// The currently attached tab id, if any tab has been successfully switched to.
    pub fn active_tab_id(&self) -> Option<&str> {
        self.active_tab_key().map(|active| active.tab_id.as_str())
    }

    /// The currently attached window id, if any tab has been successfully switched to.
    pub fn active_window_id(&self) -> Option<&str> {
        self.active_tab_key()
            .map(|active| active.window_id.as_str())
    }

    /// The daemon session currently bound to the renderer viewport.
    pub fn active_session_id(&self) -> Option<&str> {
        self.active_tab_key()
            .map(|active| active.session_id.as_str())
    }

    pub fn pending_viewport(&self) -> Option<&PendingRendererViewport> {
        self.pending_viewport.as_ref()
    }

    pub fn pending_handoff(&self) -> Option<&PendingRendererViewport> {
        self.pending_viewport
            .as_ref()
            .filter(|pending| matches!(pending, PendingRendererViewport::Handoff { .. }))
    }

    pub fn handoff_is_pending(&self) -> bool {
        self.pending_viewport.is_some()
    }

    /// Install launch-time correlation before the renderer/event listener starts. This sends no
    /// command and exposes no active projection; only a later exact Claimed disposition may adopt
    /// the target.
    pub fn install_initial_handoff(
        &mut self,
        projection: RendererViewportProjection,
        handoff: &maestro_renderer::RendererAttachmentHandoff,
    ) -> Result<(), TabSwitchError> {
        if self.pending_viewport.is_some() {
            return Err(TabSwitchError::HandoffPending);
        }
        if handoff.authority().session_id().0 != projection.target.session_id
            || handoff.authority().expected_generation() != projection.generation()
        {
            return Err(TabSwitchError::ViewportAuthorityRequired);
        }
        self.pending_viewport = Some(PendingRendererViewport::Handoff {
            request_id: handoff.request_id(),
            target: projection,
            previous_active: self.active_viewport.take(),
            expected_daemon_instance: handoff.authority().expected_daemon_instance().clone(),
            expected_generation: handoff.authority().expected_generation().to_string(),
        });
        self.pending_viewport_adoption_allowed = true;
        Ok(())
    }

    /// Switch the renderer to `tab_id` within `window_id`, given that window's layout
    /// already projected into [`TabSelection`]s (the caller scopes the projection to the
    /// window, exactly as `attach-tab`/`main.rs` already do).
    ///
    /// Returns `Ok(true)` if a command was sent, `Ok(false)` if the SAME complete
    /// `(window_id, tab_id, session_id)` binding was already active (no-op, nothing sent). Selecting
    /// the same `tab_id` in a different window or after a durable session retarget is NOT a no-op.
    /// Errors are typed and never advance the active binding.
    pub fn switch_to(
        &mut self,
        window_id: &str,
        layout: &[TabSelection],
        tab_id: &str,
    ) -> Result<bool, TabSwitchError> {
        if self.pending_viewport.is_some() {
            return Err(TabSwitchError::HandoffPending);
        }
        let session_id = select_window_tab_session(layout, tab_id).map_err(|e| match e {
            TabSelectionError::TabNotFound { tab_id } => TabSwitchError::TabNotFound {
                window_id: window_id.to_string(),
                tab_id,
            },
            TabSelectionError::AmbiguousTab { tab_id, .. } => TabSwitchError::AmbiguousTab {
                window_id: window_id.to_string(),
                tab_id,
            },
        })?;

        let already_active = self.active_tab_key().is_some_and(|a| {
            a.window_id == window_id && a.tab_id == tab_id && a.session_id == session_id
        });
        if already_active {
            return Ok(false);
        }
        Err(TabSwitchError::ViewportAuthorityRequired)
    }

    /// Deliver the first renderer bind for a freshly started lifetime together with its opaque
    /// daemon-side attachment handoff. Unlike an ordinary switch this is never collapsed as a
    /// same-binding no-op: the Claim itself must reach the renderer connection so the starter's
    /// pending ownership token is consumed atomically with the new active guard.
    /// Begin an owned runtime handoff. This records only pending correlation facts; active state is
    /// adopted exclusively through [`Self::adopt_claimed_handoff_disposition`].
    pub fn switch_to_with_handoff(
        &mut self,
        projection: RendererViewportProjection,
        handoff: maestro_renderer::RendererAttachmentHandoff,
    ) -> Result<bool, TabSwitchError> {
        if self.pending_viewport.is_some() {
            return Err(TabSwitchError::HandoffPending);
        }
        let session_id = projection.target.session_id.clone();
        if handoff.authority().session_id().0 != session_id
            || handoff.authority().expected_generation() != projection.generation()
        {
            return Err(TabSwitchError::ViewportAuthorityRequired);
        }

        let request_id = handoff.request_id();
        let expected_daemon_instance = handoff.authority().expected_daemon_instance().clone();
        let expected_generation = handoff.authority().expected_generation().to_string();
        self.sender
            .send(
                maestro_renderer::RendererCommand::AttachSessionWithHandoff {
                    session_id: session_id.clone(),
                    handoff,
                    tab_strip: projection.tab_strip.clone(),
                    exact_viewport: projection.exact_viewport.clone(),
                },
            )
            .map_err(|()| TabSwitchError::RendererControlClosed)?;

        self.pending_viewport = Some(PendingRendererViewport::Handoff {
            request_id,
            target: projection,
            previous_active: self.active_viewport.take(),
            expected_daemon_instance,
            expected_generation,
        });
        self.pending_viewport_adoption_allowed = true;
        Ok(true)
    }

    /// Begin an ordinary exact rebind. Command delivery installs pending correlation only; active
    /// state remains neutral until the renderer emits the matching all-baseline `Published` proof.
    pub fn switch_to_exact(
        &mut self,
        projection: RendererViewportProjection,
        events: std::sync::mpsc::Sender<maestro_renderer::RendererEvent>,
    ) -> Result<Option<maestro_renderer::RendererExactViewportRequestId>, TabSwitchError> {
        self.switch_to_exact_with_dialog_focus(projection, events, None)
    }

    fn switch_to_exact_with_dialog_focus(
        &mut self,
        projection: RendererViewportProjection,
        events: std::sync::mpsc::Sender<maestro_renderer::RendererEvent>,
        dialog_focus_ticket: Option<u64>,
    ) -> Result<Option<maestro_renderer::RendererExactViewportRequestId>, TabSwitchError> {
        if self.pending_viewport.is_some() {
            return Err(TabSwitchError::HandoffPending);
        }
        if dialog_focus_ticket.is_none()
            && self.active_viewport.as_ref().is_some_and(|active| {
                active.projection.exact_viewport == projection.exact_viewport
                    && active.projection.target == projection.target
            })
        {
            let strip_changed = self
                .active_viewport
                .as_ref()
                .is_some_and(|active| active.projection.tab_strip != projection.tab_strip);
            if strip_changed {
                self.sender
                    .send(maestro_renderer::RendererCommand::SetTabStrip {
                        tab_strip: Some(projection.tab_strip.clone()),
                    })
                    .map_err(|()| TabSwitchError::RendererControlClosed)?;
            }
            // A coherent durable refresh can change App-only selection/row projections even when
            // the renderer-facing strip bytes are identical. Once the exact lifetime/cohort and
            // primary target match, retain the whole fresh projection rather than leaving those
            // App caches pinned to pre-Claim bytes.
            if let Some(active) = self.active_viewport.as_mut() {
                active.projection = projection;
            }
            return Ok(None);
        }
        // An explicit revival with native focus ownership also re-proves an already displayed
        // target. Focus is granted at exact publication, never merely from this App-side cache.
        let request = maestro_renderer::RendererExactViewportRequest::new_with_dialog_focus(
            projection.target.session_id.clone(),
            projection.exact_viewport.clone(),
            projection.tab_strip.clone(),
            events,
            dialog_focus_ticket,
        )
        .map_err(|error| {
            TabSwitchError::ViewportProjection(RendererViewportProjectionError::Exact(error))
        })?;
        let request_id = request.request_id();
        self.sender
            .send(maestro_renderer::RendererCommand::AttachExactViewport { request })
            .map_err(|()| TabSwitchError::RendererControlClosed)?;
        self.pending_viewport = Some(PendingRendererViewport::Ordinary {
            request_id,
            target: projection,
            previous_active: self.active_viewport.take(),
        });
        self.pending_viewport_adoption_allowed = true;
        Ok(Some(request_id))
    }

    /// Validate and adopt one exact renderer disposition. Request/session/instance/generation must
    /// all match the installed pending facts; stale or contradictory events are inert.
    pub fn adopt_claimed_handoff_disposition(
        &mut self,
        disposition: &maestro_renderer::RendererAttachmentHandoffDisposition,
    ) -> bool {
        matches!(
            self.settle_handoff_disposition(disposition),
            RendererViewportSettlement::Adopted(_)
        )
    }

    pub fn settle_handoff_disposition(
        &mut self,
        disposition: &maestro_renderer::RendererAttachmentHandoffDisposition,
    ) -> RendererViewportSettlement {
        let Some(PendingRendererViewport::Handoff {
            request_id,
            target,
            expected_daemon_instance,
            expected_generation,
            ..
        }) = self.pending_viewport.as_ref()
        else {
            return RendererViewportSettlement::Stale;
        };
        if disposition.request_id() != *request_id
            || disposition.session_id() != target.target.session_id
        {
            return RendererViewportSettlement::Stale;
        }
        let exact_proof = matches!(
            disposition.outcome(),
            maestro_renderer::RendererAttachmentHandoffOutcome::Claimed
                | maestro_renderer::RendererAttachmentHandoffOutcome::ClaimedViewportUnavailable
        );
        if exact_proof
            && (disposition.daemon_instance_id() != Some(expected_daemon_instance)
                || disposition.generation() != Some(expected_generation.as_str()))
        {
            return RendererViewportSettlement::Stale;
        }
        if disposition
            .daemon_instance_id()
            .is_some_and(|instance| instance != expected_daemon_instance)
            || disposition
                .generation()
                .is_some_and(|generation| generation != expected_generation)
        {
            return RendererViewportSettlement::Stale;
        }
        let expected_daemon_instance = expected_daemon_instance.clone();
        let pending = self
            .pending_viewport
            .take()
            .expect("matched pending handoff");
        let adoption_allowed =
            std::mem::replace(&mut self.pending_viewport_adoption_allowed, false);
        if adoption_allowed
            && disposition.outcome() == maestro_renderer::RendererAttachmentHandoffOutcome::Claimed
        {
            let active = ActiveRendererViewport {
                projection: pending.target().clone(),
                daemon_instance_id: expected_daemon_instance,
            };
            self.active_viewport = Some(active.clone());
            RendererViewportSettlement::Adopted(active)
        } else {
            self.active_viewport = None;
            RendererViewportSettlement::Neutralized(pending)
        }
    }

    pub fn settle_exact_viewport_disposition(
        &mut self,
        disposition: &maestro_renderer::RendererExactViewportDisposition,
    ) -> RendererViewportSettlement {
        self.settle_exact_viewport_facts(
            disposition.request_id(),
            disposition.session_id(),
            disposition.generation(),
            disposition.daemon_instance_id(),
            disposition.outcome(),
        )
    }

    /// Keep disposition matching as one testable App-owned transition. The public seam above is
    /// the only production caller; unit tests exercise these already-decoded facts without adding
    /// a forgeable renderer-proof constructor to the cross-crate API.
    fn settle_exact_viewport_facts(
        &mut self,
        disposition_request_id: maestro_renderer::RendererExactViewportRequestId,
        disposition_session_id: &str,
        disposition_generation: &str,
        disposition_daemon_instance_id: Option<&maestro_shell::DaemonInstanceId>,
        disposition_outcome: maestro_renderer::RendererExactViewportOutcome,
    ) -> RendererViewportSettlement {
        let Some(PendingRendererViewport::Ordinary {
            request_id, target, ..
        }) = self.pending_viewport.as_ref()
        else {
            return RendererViewportSettlement::Stale;
        };
        if disposition_request_id != *request_id
            || disposition_session_id != target.target.session_id
            || disposition_generation != target.generation()
        {
            return RendererViewportSettlement::Stale;
        }
        let pending = self
            .pending_viewport
            .take()
            .expect("matched pending viewport");
        let adoption_allowed =
            std::mem::replace(&mut self.pending_viewport_adoption_allowed, false);
        if adoption_allowed
            && disposition_outcome == maestro_renderer::RendererExactViewportOutcome::Published
        {
            let Some(daemon_instance_id) = disposition_daemon_instance_id.cloned() else {
                self.active_viewport = None;
                return RendererViewportSettlement::Neutralized(pending);
            };
            let active = ActiveRendererViewport {
                projection: pending.target().clone(),
                daemon_instance_id,
            };
            self.active_viewport = Some(active.clone());
            RendererViewportSettlement::Adopted(active)
        } else {
            self.active_viewport = None;
            RendererViewportSettlement::Neutralized(pending)
        }
    }

    /// Consume one exact non-Claimed pending coordinate after the renderer has already established
    /// neutrality. The caller decides whether its durable operation is rollbackable.
    pub fn take_nonclaimed_handoff(
        &mut self,
        request_id: maestro_renderer::RendererAttachmentHandoffRequestId,
        session_id: &str,
    ) -> Option<PendingRendererViewport> {
        let matches = self.pending_viewport.as_ref().is_some_and(|pending| {
            pending.handoff_request_id() == Some(request_id)
                && pending.target().target.session_id == session_id
        });
        matches.then(|| {
            self.active_viewport = None;
            self.pending_viewport_adoption_allowed = false;
            self.pending_viewport
                .take()
                .expect("matched pending handoff")
        })
    }

    pub fn take_pending_viewport(&mut self) -> Option<PendingRendererViewport> {
        self.active_viewport = None;
        self.pending_viewport_adoption_allowed = false;
        self.pending_viewport.take()
    }

    /// Restore the prior active renderer only by forcing an Attach followed by the complete strip
    /// projection in FIFO order. Active state remains neutral unless both sends succeed.
    pub fn restore_previous_active_after_handoff(
        &mut self,
        previous_active: Option<ActiveTab>,
        tab_strip: Option<maestro_renderer::RendererTabStrip>,
    ) -> Result<bool, TabSwitchError> {
        let _ = (previous_active, tab_strip);
        self.pending_viewport = None;
        self.pending_viewport_adoption_allowed = false;
        self.active_viewport = None;
        Err(TabSwitchError::ViewportAuthorityRequired)
    }

    /// Replace (`Some`) or clear (`None`) the renderer's read-only tab-strip overlay by sending
    /// a [`maestro_renderer::RendererCommand::SetTabStrip`]. Converts a [`TabStripModel`] via
    /// [`renderer_tab_strip`] so the renderer type carries no app dependency.
    ///
    /// This updates ONLY the displayed strip; it deliberately does NOT touch active-tab state.
    /// Updating the visible strip and switching the attached session are separate operations:
    /// the strip is read-only display chrome, while a switch rebinds the single viewport. A
    /// closed receiver maps to [`TabSwitchError::RendererControlClosed`], the same error
    /// `switch_to` surfaces, without altering the active tab.
    pub fn set_tab_strip(&mut self, model: Option<&TabStripModel>) -> Result<(), TabSwitchError> {
        if self.pending_viewport.is_some() {
            return Err(TabSwitchError::HandoffPending);
        }
        let Some(model) = model else {
            return Err(TabSwitchError::ViewportAuthorityRequired);
        };
        let tab_strip = renderer_tab_strip(model);
        let Some(active) = self.active_viewport.as_mut() else {
            return Err(TabSwitchError::ViewportAuthorityRequired);
        };
        if !display_strip_matches_exact_cohort(&active.projection.tab_strip, &tab_strip) {
            return Err(TabSwitchError::ViewportAuthorityRequired);
        }
        self.sender
            .send(maestro_renderer::RendererCommand::SetTabStrip {
                tab_strip: Some(tab_strip.clone()),
            })
            .map_err(|()| TabSwitchError::RendererControlClosed)?;
        active.projection.strip_model = model.clone();
        active.projection.tab_strip = tab_strip;
        Ok(())
    }

    /// Neutralize the renderer viewport and, only after that single command is delivered, drop the
    /// app's active window/tab/session binding. `ClearViewport` owns both terminal and strip
    /// cleanup in the renderer, so callers must not pair this with `SetTabStrip(None)`: doing so
    /// would introduce a partial-delivery state and could schedule strip-driven resize work after
    /// the viewport became neutral.
    pub fn clear_viewport(&mut self) -> Result<(), TabSwitchError> {
        // Revoke adoption before the Clear can race a previously queued terminal disposition. Keep
        // the pending record itself until that disposition (or shutdown drain) consumes it, so the
        // listener retains its exact recovery correlation while active getters stay neutral.
        self.pending_viewport_adoption_allowed = false;
        self.active_viewport = None;
        self.sender
            .send(maestro_renderer::RendererCommand::ClearViewport)
            .map_err(|()| TabSwitchError::RendererControlClosed)?;
        Ok(())
    }

    /// Update the renderer's read-only picker overlay through the same command channel:
    /// `Some(model)` shows/replaces the overlay, `None` dismisses it. Like `set_tab_strip` this
    /// touches ONLY display chrome — it never switches the attached session or mutates any record.
    /// A closed receiver maps to [`TabSwitchError::RendererControlClosed`].
    pub fn set_picker_overlay(
        &mut self,
        picker: Option<maestro_renderer::RendererPickerModel>,
    ) -> Result<(), TabSwitchError> {
        self.sender
            .send(maestro_renderer::RendererCommand::SetPickerOverlay { picker })
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    /// Replace (`Some`) or clear (`None`) the renderer's app-owned status label through the same
    /// command channel by sending a [`maestro_renderer::RendererCommand::SetStatusLabel`]. Like
    /// `set_tab_strip` this touches ONLY display chrome — it never switches the attached session or
    /// mutates any record. A closed receiver maps to [`TabSwitchError::RendererControlClosed`].
    pub fn set_status_label(&mut self, status_label: Option<String>) -> Result<(), TabSwitchError> {
        self.sender
            .send(maestro_renderer::RendererCommand::SetStatusLabel { status_label })
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    /// Swap the renderer's live color `theme` through the same command channel by sending a
    /// [`maestro_renderer::RendererCommand::SetTheme`]. Color-only — like `set_tab_strip` it touches
    /// ONLY display chrome: it never switches the attached session, resizes, or mutates any record. A
    /// closed receiver maps to [`TabSwitchError::RendererControlClosed`].
    pub fn set_theme(
        &mut self,
        theme: maestro_renderer::RendererTheme,
    ) -> Result<(), TabSwitchError> {
        self.sender
            .send(maestro_renderer::RendererCommand::SetTheme { theme })
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    /// Replace (`Some`) or clear (`None`) the renderer's display-only command-palette execution result
    /// through the same command channel by sending a
    /// [`maestro_renderer::RendererCommand::SetCommandPaletteResult`]. Display-only — like `set_tab_strip`
    /// it touches ONLY overlay chrome: it executes nothing, switches no session, contacts no daemon, and
    /// mutates no record. A closed receiver maps to [`TabSwitchError::RendererControlClosed`].
    pub fn set_command_palette_result(
        &mut self,
        result: Option<maestro_renderer::RendererCommandPaletteResult>,
    ) -> Result<(), TabSwitchError> {
        self.sender
            .send(maestro_renderer::RendererCommand::SetCommandPaletteResult { result })
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    /// Dismiss/clear the renderer's command-palette overlay through the same command channel by sending a
    /// [`maestro_renderer::RendererCommand::DismissCommandPalette`]. Display-only — like `set_tab_strip`
    /// it touches ONLY overlay chrome: it clears the overlay (lines, model, query, and any held result,
    /// matching Escape cleanup), executes nothing, switches no session, contacts no daemon, and mutates
    /// no record. A closed receiver maps to [`TabSwitchError::RendererControlClosed`].
    pub fn dismiss_command_palette(&mut self) -> Result<(), TabSwitchError> {
        self.sender
            .send(maestro_renderer::RendererCommand::DismissCommandPalette)
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    /// Show (`Some`) or clear (`None`) the renderer's command-palette overlay model through the same
    /// command channel by sending a [`maestro_renderer::RendererCommand::SetCommandPaletteOverlay`].
    /// Display-only — like `set_tab_strip` it touches ONLY overlay chrome: `Some(model)` seeds/shows the
    /// overlay (full catalog, deterministic selection, empty query, no result) exactly like launch-time
    /// seeding; `None` clears it. It executes nothing, switches no session, contacts no daemon, and
    /// mutates no record. A closed receiver maps to [`TabSwitchError::RendererControlClosed`].
    pub fn set_command_palette_overlay(
        &mut self,
        command_palette: Option<maestro_renderer::RendererCommandPaletteModel>,
    ) -> Result<(), TabSwitchError> {
        self.sender
            .send(maestro_renderer::RendererCommand::SetCommandPaletteOverlay { command_palette })
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    /// Replace (`Some`) or clear (`None`) the renderer's read-only top dashboard/settings panel through
    /// the same command channel by sending a
    /// [`maestro_renderer::RendererCommand::SetDashboardPanel`]. Display-only — like `set_tab_strip` it
    /// touches ONLY top chrome: `Some(panel)` replaces the displayed panel and recomputes the grid-origin
    /// offset; `None` clears it. It executes nothing, switches no session, contacts no daemon, and mutates
    /// no record. A closed receiver maps to [`TabSwitchError::RendererControlClosed`].
    pub fn set_dashboard_panel(
        &mut self,
        dashboard_panel: Option<maestro_renderer::RendererDashboardPanel>,
    ) -> Result<(), TabSwitchError> {
        self.sender
            .send(maestro_renderer::RendererCommand::SetDashboardPanel { dashboard_panel })
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    /// Push the remote-access toggle UI state (tab-bar button label + status dot) to the renderer via a
    /// [`maestro_renderer::RendererCommand::SetRemoteOpen`]. Display-only.
    pub fn set_remote_open(&mut self, open: bool) -> Result<(), TabSwitchError> {
        self.sender
            .send(maestro_renderer::RendererCommand::SetRemoteOpen { open })
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    /// Push the winsize-owner toggle UI state to the renderer via a
    /// [`maestro_renderer::RendererCommand::SetWinsizeOwner`]. Display-only.
    pub fn set_winsize_owner(&mut self, remote: bool) -> Result<(), TabSwitchError> {
        self.sender
            .send(maestro_renderer::RendererCommand::SetWinsizeOwner { remote })
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    /// Atomically project one negotiated optional-extension snapshot into renderer display and
    /// viewport ownership. This is presentation only; extension authority remains out of process.
    pub fn set_remote_extension_state(
        &mut self,
        available: bool,
        open: bool,
        remote_winsize: bool,
        remote_owned_sessions: Vec<String>,
    ) -> Result<(), TabSwitchError> {
        self.sender
            .send(maestro_renderer::RendererCommand::SetRemoteExtensionState {
                available,
                open,
                remote_winsize,
                remote_owned_sessions,
            })
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    /// Replace (`Some`) or clear (`None`) the renderer's left-dock column through the same command
    /// channel by sending a [`maestro_renderer::RendererCommand::SetDock`]. `Some(dock)` insets the grid
    /// right by the dock width (recomputing the PTY column count); `None` clears it. It switches no
    /// session, contacts no daemon, and mutates no record. A closed receiver maps to
    /// [`TabSwitchError::RendererControlClosed`].
    pub fn set_dock(
        &mut self,
        dock: Option<maestro_renderer::RendererDockModel>,
    ) -> Result<(), TabSwitchError> {
        self.sender
            .send(maestro_renderer::RendererCommand::SetDock { dock })
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    /// Replace (`Some`) or clear (`None`) the renderer's read-only file-preview band through the same
    /// command channel by sending a [`maestro_renderer::RendererCommand::SetFilePreview`]. Display-only —
    /// like `set_tab_strip` it touches ONLY the preview band: `Some(preview)` paints the bounded file the
    /// app already read; `None` clears it. It opens no file, reads nothing, switches no session, contacts
    /// no daemon, and mutates no record. A closed receiver maps to [`TabSwitchError::RendererControlClosed`].
    pub fn set_file_preview(
        &mut self,
        file_preview: Option<maestro_renderer::RendererFilePreview>,
    ) -> Result<(), TabSwitchError> {
        self.sender
            .send(maestro_renderer::RendererCommand::SetFilePreview { file_preview })
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    /// Push a fresh dashboard model into the embedded React chrome. Display-only: it changes no active
    /// terminal session, record, or PTY geometry. A closed receiver maps to
    /// [`TabSwitchError::RendererControlClosed`].
    pub fn set_react_chrome_model(&mut self, model_json: String) -> Result<(), TabSwitchError> {
        eprintln!(
            "hydra-dashboard command send SetReactChromeModel bytes={}",
            model_json.len()
        );
        self.sender
            .send(maestro_renderer::RendererCommand::SetReactChromeModel { model_json })
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    /// Evaluate a small host-owned callback script in the embedded React chrome. Display-only:
    /// changes no terminal session, record, daemon state, or PTY geometry.
    pub fn evaluate_react_chrome_script(&mut self, script: String) -> Result<(), TabSwitchError> {
        eprintln!(
            "hydra-dashboard command send EvaluateReactChromeScript bytes={}",
            script.len()
        );
        self.sender
            .send(
                maestro_renderer::RendererCommand::EvaluateReactChromeScript {
                    script,
                    kind: maestro_renderer::ReactChromeScriptKind::Transient,
                },
            )
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    pub fn set_react_chrome_overlay_visible(
        &mut self,
        visible: bool,
    ) -> Result<(), TabSwitchError> {
        eprintln!("hydra-dashboard command send SetReactChromeOverlayVisible visible={visible}");
        self.sender
            .send(maestro_renderer::RendererCommand::SetReactChromeOverlayVisible { visible })
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    /// Queue one host-owned modal command before queueing overlay visibility on the same FIFO.
    /// If the modal command cannot be accepted, visibility is never sent; a native host therefore
    /// cannot expose a ready overlay realm without first caching the corresponding modal.
    pub fn show_react_chrome_overlay_modal(
        &mut self,
        script: String,
    ) -> Result<(), TabSwitchError> {
        eprintln!(
            "hydra-dashboard command send EvaluateReactChromeScript kind=modal bytes={}",
            script.len()
        );
        self.sender
            .send(
                maestro_renderer::RendererCommand::EvaluateReactChromeScript {
                    script,
                    kind: maestro_renderer::ReactChromeScriptKind::Modal,
                },
            )
            .map_err(|()| TabSwitchError::RendererControlClosed)?;
        self.set_react_chrome_overlay_visible(true)
    }

    /// Ask the renderer/UI side to open a native folder picker for the embedded React chrome.
    pub fn pick_react_chrome_folder(&mut self, request_id: String) -> Result<(), TabSwitchError> {
        eprintln!("hydra-dashboard command send PickReactChromeFolder request={request_id:?}");
        self.sender
            .send(maestro_renderer::RendererCommand::PickReactChromeFolder { request_id })
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    /// Resize the embedded React sidebar through the renderer command channel. The renderer keeps
    /// WebView bounds and terminal grid inset in lockstep.
    pub fn set_react_chrome_width(&mut self, width_logical_px: u32) -> Result<(), TabSwitchError> {
        eprintln!("hydra-dashboard command send SetReactChromeWidth width={width_logical_px}");
        self.sender
            .send(maestro_renderer::RendererCommand::SetReactChromeWidth { width_logical_px })
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    /// Return focus from host-owned dashboard chrome to the native terminal surface.
    pub fn focus_terminal(&mut self) -> Result<(), TabSwitchError> {
        self.sender
            .send(maestro_renderer::RendererCommand::FocusTerminal)
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    /// Set or clear a stashed-pane drag that started in React chrome. The renderer owns only the
    /// hover/drop geometry over the native terminal; app-side event handling owns the actual revive.
    pub fn set_stashed_pane_drag(
        &mut self,
        drag: Option<maestro_renderer::RendererStashedPaneDrag>,
    ) -> Result<(), TabSwitchError> {
        self.sender
            .send(maestro_renderer::RendererCommand::SetStashedPaneDrag { drag })
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    pub fn complete_stashed_pane_drop_at(&mut self, x: i32, y: i32) -> Result<(), TabSwitchError> {
        self.sender
            .send(maestro_renderer::RendererCommand::CompleteStashedPaneDropAt { x, y })
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    pub fn move_stashed_pane_drag_to(&mut self, x: i32, y: i32) -> Result<(), TabSwitchError> {
        self.sender
            .send(maestro_renderer::RendererCommand::MoveStashedPaneDragTo { x, y })
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    /// Set (`Some`) or clear (`None`) the renderer's renderer-local file-path-input prompt through the
    /// same command channel by sending a [`maestro_renderer::RendererCommand::SetFilePathInput`].
    /// Display-only — it touches ONLY the prompt band: the app sends `None` to clear the prompt after it
    /// has read a submitted path. It opens no file, switches no session, contacts no daemon, and mutates
    /// no record. A closed receiver maps to [`TabSwitchError::RendererControlClosed`].
    pub fn set_file_path_input(
        &mut self,
        file_path_input: Option<maestro_renderer::RendererFilePathInput>,
    ) -> Result<(), TabSwitchError> {
        self.sender
            .send(maestro_renderer::RendererCommand::SetFilePathInput { file_path_input })
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    /// Set (`Some`) or clear (`None`) the renderer's display-only settings edit-draft marker through the
    /// same command channel by sending a
    /// [`maestro_renderer::RendererCommand::SetSettingsPanelEditDraft`]. Display-only — like
    /// `set_tab_strip` it touches ONLY top chrome: it shows one bounded "pending / not saved" line for an
    /// editable settings row and collects no input, parses no value, writes no setting, switches no
    /// session, contacts no daemon, and mutates no record. A closed receiver maps to
    /// [`TabSwitchError::RendererControlClosed`].
    pub fn set_settings_edit_draft(
        &mut self,
        draft: Option<maestro_renderer::RendererSettingsPanelEditDraft>,
    ) -> Result<(), TabSwitchError> {
        self.sender
            .send(maestro_renderer::RendererCommand::SetSettingsPanelEditDraft { draft })
            .map_err(|()| TabSwitchError::RendererControlClosed)
    }

    /// Drop the app's active window/tab/session binding: after this there is no controller-owned tab
    /// coordinate, so later close/activation classification no longer treats the previously-active
    /// tab as active. This does not detach or clear the renderer's prior viewport/session/grid/input.
    ///
    /// It sends NO `RendererCommand` — clearing the displayed strip (`set_tab_strip(None)`) and
    /// clearing app active-tab ownership are deliberately separate operations. The only-tab close path
    /// sends the strip clear first and only calls this after that command is delivered, so a closed
    /// receiver never leaves the controller with a cleared active tab but an un-cleared strip.
    pub fn clear_active_tab(&mut self) {
        self.active_viewport = None;
    }
}

/// App-owned runtime holder that owns the `Sender` half of the renderer control channel.
///
/// [`new`](RendererTabRuntime::new) creates exactly one `mpsc` channel, keeps the sender
/// inside a [`TabSwitchController`], and hands back the matching receiver. The receiver is
/// the one the caller passes to `maestro_renderer::run_renderer_with_commands(launch,
/// receiver)` so that [`switch_to`](RendererTabRuntime::switch_to) drives the live renderer.
///
/// This is the runtime ownership seam, NOT a GUI tab strip: it parses no CLI, spawns/connects
/// no daemon, launches no renderer, mutates no persisted layout, and draws no UI. It only owns
/// the sender and delegates every switch (and all active-state/error semantics) to the
/// already-reviewed [`TabSwitchController`].
pub struct RendererTabRuntime {
    controller: TabSwitchController<std::sync::mpsc::Sender<maestro_renderer::RendererCommand>>,
    renderer_events: Option<std::sync::mpsc::Sender<maestro_renderer::RendererEvent>>,
    window_order_warning: Option<String>,
}

impl RendererTabRuntime {
    /// Create the one command channel, returning the runtime (owning the sender) and the
    /// receiver intended for `maestro_renderer::run_renderer_with_commands`.
    pub fn new() -> (
        Self,
        std::sync::mpsc::Receiver<maestro_renderer::RendererCommand>,
    ) {
        let (tx, rx) = std::sync::mpsc::channel();
        (
            Self {
                controller: TabSwitchController::new(tx),
                renderer_events: None,
                window_order_warning: None,
            },
            rx,
        )
    }

    /// Bind the renderer's lifecycle event sender before handing this runtime to the listener.
    /// Ordinary exact viewport requests clone this same route into their request-owned settlement
    /// sink, so command delivery can never leave App pending without a terminal disposition.
    pub fn bind_renderer_events(
        &mut self,
        events: std::sync::mpsc::Sender<maestro_renderer::RendererEvent>,
    ) {
        self.renderer_events = Some(events);
    }

    /// Seed the initial active `(window_id, tab_id, session_id)` WITHOUT sending a command, delegated to
    /// the controller. Use this once, right before passing the receiver to
    /// `run_renderer_with_commands`, when the renderer is launched already attached to that
    /// tab's session — so the active coordinate matches reality without enqueueing a duplicate
    /// attach. Needs no live receiver and does not weaken `switch_to`.
    pub fn seed_active_tab(&mut self, window_id: &str, tab_id: &str, session_id: &str) {
        self.controller
            .seed_active_tab(window_id, tab_id, session_id);
    }

    /// The full active coordinate (`window_id` + `tab_id`), delegated to the controller.
    pub fn active_tab_key(&self) -> Option<&ActiveTab> {
        self.controller.active_tab_key()
    }

    pub fn active_viewport(&self) -> Option<&ActiveRendererViewport> {
        self.controller.active_viewport()
    }

    #[cfg(test)]
    fn seed_exact_active_for_test(
        &mut self,
        projection: RendererViewportProjection,
        daemon_instance_id: maestro_shell::DaemonInstanceId,
    ) {
        self.controller
            .seed_exact_active_for_test(projection, daemon_instance_id);
    }

    /// The currently attached window id, delegated to the controller.
    pub fn active_window_id(&self) -> Option<&str> {
        self.controller.active_window_id()
    }

    /// The currently attached tab id, delegated to the controller.
    pub fn active_tab_id(&self) -> Option<&str> {
        self.controller.active_tab_id()
    }

    /// The daemon session currently bound to the renderer viewport, delegated to the controller.
    pub fn active_session_id(&self) -> Option<&str> {
        self.controller.active_session_id()
    }

    pub fn pending_viewport(&self) -> Option<&PendingRendererViewport> {
        self.controller.pending_viewport()
    }

    pub fn pending_handoff(&self) -> Option<&PendingRendererViewport> {
        self.controller.pending_handoff()
    }

    pub fn handoff_is_pending(&self) -> bool {
        self.controller.handoff_is_pending()
    }

    pub fn install_initial_handoff(
        &mut self,
        projection: RendererViewportProjection,
        handoff: &maestro_renderer::RendererAttachmentHandoff,
    ) -> Result<(), TabSwitchError> {
        self.controller.install_initial_handoff(projection, handoff)
    }

    /// Switch the renderer to `tab_id` within `window_id`, delegating to the controller. All
    /// send/no-op/error semantics are exactly the controller's — including
    /// [`TabSwitchError::RendererControlClosed`] once the receiver is dropped.
    pub fn switch_to(
        &mut self,
        window_id: &str,
        layout: &[TabSelection],
        tab_id: &str,
    ) -> Result<bool, TabSwitchError> {
        self.controller.switch_to(window_id, layout, tab_id)
    }

    pub fn switch_to_with_handoff(
        &mut self,
        projection: RendererViewportProjection,
        handoff: maestro_renderer::RendererAttachmentHandoff,
    ) -> Result<bool, TabSwitchError> {
        self.controller.switch_to_with_handoff(projection, handoff)
    }

    pub fn switch_to_exact(
        &mut self,
        projection: RendererViewportProjection,
    ) -> Result<Option<maestro_renderer::RendererExactViewportRequestId>, TabSwitchError> {
        self.switch_to_exact_with_dialog_focus(projection, None)
    }

    pub fn switch_to_exact_with_dialog_focus(
        &mut self,
        projection: RendererViewportProjection,
        dialog_focus_ticket: Option<u64>,
    ) -> Result<Option<maestro_renderer::RendererExactViewportRequestId>, TabSwitchError> {
        let events = self
            .renderer_events
            .as_ref()
            .cloned()
            .ok_or(TabSwitchError::RendererEventChannelUnavailable)?;
        self.controller
            .switch_to_exact_with_dialog_focus(projection, events, dialog_focus_ticket)
    }

    pub fn adopt_claimed_handoff_disposition(
        &mut self,
        disposition: &maestro_renderer::RendererAttachmentHandoffDisposition,
    ) -> bool {
        self.controller
            .adopt_claimed_handoff_disposition(disposition)
    }

    pub fn settle_handoff_disposition(
        &mut self,
        disposition: &maestro_renderer::RendererAttachmentHandoffDisposition,
    ) -> RendererViewportSettlement {
        self.controller.settle_handoff_disposition(disposition)
    }

    pub fn settle_exact_viewport_disposition(
        &mut self,
        disposition: &maestro_renderer::RendererExactViewportDisposition,
    ) -> RendererViewportSettlement {
        self.controller
            .settle_exact_viewport_disposition(disposition)
    }

    pub fn take_nonclaimed_handoff(
        &mut self,
        request_id: maestro_renderer::RendererAttachmentHandoffRequestId,
        session_id: &str,
    ) -> Option<PendingRendererViewport> {
        self.controller
            .take_nonclaimed_handoff(request_id, session_id)
    }

    pub fn take_pending_viewport(&mut self) -> Option<PendingRendererViewport> {
        self.controller.take_pending_viewport()
    }

    pub fn restore_previous_active_after_handoff(
        &mut self,
        previous_active: Option<ActiveTab>,
        tab_strip: Option<maestro_renderer::RendererTabStrip>,
    ) -> Result<bool, TabSwitchError> {
        self.controller
            .restore_previous_active_after_handoff(previous_active, tab_strip)
    }

    /// Update the renderer's read-only tab-strip overlay through the same command channel,
    /// delegating to the controller. `Some(&model)` replaces the displayed strip (converted via
    /// [`renderer_tab_strip`]); `None` clears it. Does NOT alter active-tab state — updating the
    /// displayed strip and switching the attached session remain separate operations. A closed
    /// receiver surfaces [`TabSwitchError::RendererControlClosed`], exactly like `switch_to`.
    pub fn set_tab_strip(&mut self, model: Option<&TabStripModel>) -> Result<(), TabSwitchError> {
        self.controller.set_tab_strip(model)
    }

    /// Deliver one renderer-local viewport neutralization and adopt cleared controller ownership
    /// only after delivery succeeds.
    pub fn clear_viewport(&mut self) -> Result<(), TabSwitchError> {
        self.controller.clear_viewport()
    }

    /// Update the renderer's read-only picker overlay through the same command channel, delegating
    /// to the controller. `Some(model)` shows/replaces it; `None` dismisses it. Display-chrome only:
    /// it never switches the attached session or mutates any record. A closed receiver surfaces
    /// [`TabSwitchError::RendererControlClosed`], exactly like `set_tab_strip`.
    pub fn set_picker_overlay(
        &mut self,
        picker: Option<maestro_renderer::RendererPickerModel>,
    ) -> Result<(), TabSwitchError> {
        self.controller.set_picker_overlay(picker)
    }

    /// Update the renderer's app-owned status label through the same command channel, delegating to
    /// the controller. `Some(label)` replaces the displayed label; `None` clears it (restoring the
    /// bare overlay). Display-chrome only: it never switches the attached session or mutates any
    /// record. A closed receiver surfaces [`TabSwitchError::RendererControlClosed`], exactly like
    /// `set_tab_strip`.
    pub fn set_status_label(&mut self, status_label: Option<String>) -> Result<(), TabSwitchError> {
        self.controller.set_status_label(status_label)
    }

    /// Swap the renderer's live color `theme` through the same command channel, delegating to the
    /// controller. Color-only display chrome — it never switches the attached session, resizes, or
    /// mutates any record. A closed receiver surfaces [`TabSwitchError::RendererControlClosed`],
    /// exactly like `set_tab_strip`.
    pub fn set_theme(
        &mut self,
        theme: maestro_renderer::RendererTheme,
    ) -> Result<(), TabSwitchError> {
        self.controller.set_theme(theme)
    }

    /// Replace (`Some`) or clear (`None`) the renderer's display-only command-palette execution result
    /// through the same command channel, delegating to the controller. Display-only overlay chrome — it
    /// executes nothing, switches no session, contacts no daemon, and mutates no record. A closed receiver
    /// surfaces [`TabSwitchError::RendererControlClosed`], exactly like `set_tab_strip`.
    pub fn set_command_palette_result(
        &mut self,
        result: Option<maestro_renderer::RendererCommandPaletteResult>,
    ) -> Result<(), TabSwitchError> {
        self.controller.set_command_palette_result(result)
    }

    /// Dismiss/clear the renderer's command-palette overlay through the same command channel, delegating
    /// to the controller. Display-only overlay chrome — it clears the overlay (matching Escape cleanup),
    /// executes nothing, switches no session, contacts no daemon, and mutates no record. A closed receiver
    /// surfaces [`TabSwitchError::RendererControlClosed`], exactly like `set_tab_strip`.
    pub fn dismiss_command_palette(&mut self) -> Result<(), TabSwitchError> {
        self.controller.dismiss_command_palette()
    }

    /// Show/reset the renderer's command-palette overlay with a full model through the same command
    /// channel, delegating to the controller. `Some(model)` seeds/shows the overlay (empty query, no
    /// result line, deterministic initial selection); `None` is equivalent to the dismiss/clear path.
    /// Display-only overlay chrome — it executes nothing, switches no session, contacts no daemon, and
    /// mutates no record. A closed receiver surfaces [`TabSwitchError::RendererControlClosed`], exactly
    /// like `set_tab_strip`.
    pub fn set_command_palette_overlay(
        &mut self,
        command_palette: Option<maestro_renderer::RendererCommandPaletteModel>,
    ) -> Result<(), TabSwitchError> {
        self.controller.set_command_palette_overlay(command_palette)
    }

    /// Replace (`Some`) or clear (`None`) the renderer's read-only top dashboard/settings panel through
    /// the same command channel, delegating to the controller. `Some(panel)` replaces the displayed panel
    /// (recomputing the grid-origin offset); `None` clears it. Display-chrome only — it executes nothing,
    /// switches no session, contacts no daemon, and mutates no record. A closed receiver surfaces
    /// [`TabSwitchError::RendererControlClosed`], exactly like `set_tab_strip`.
    pub fn set_dashboard_panel(
        &mut self,
        dashboard_panel: Option<maestro_renderer::RendererDashboardPanel>,
    ) -> Result<(), TabSwitchError> {
        self.controller.set_dashboard_panel(dashboard_panel)
    }

    /// Push the remote-access toggle UI state (tab-bar button label + status dot) to the renderer.
    pub fn set_remote_open(&mut self, open: bool) -> Result<(), TabSwitchError> {
        self.controller.set_remote_open(open)
    }

    /// Push the winsize-owner toggle UI state to the renderer.
    pub fn set_winsize_owner(&mut self, remote: bool) -> Result<(), TabSwitchError> {
        self.controller.set_winsize_owner(remote)
    }

    /// Atomically project one negotiated optional-extension snapshot into renderer display and
    /// viewport ownership, delegating to the controller.
    pub fn set_remote_extension_state(
        &mut self,
        available: bool,
        open: bool,
        remote_winsize: bool,
        remote_owned_sessions: Vec<String>,
    ) -> Result<(), TabSwitchError> {
        self.controller.set_remote_extension_state(
            available,
            open,
            remote_winsize,
            remote_owned_sessions,
        )
    }

    /// Replace (`Some`) or clear (`None`) the renderer's left-dock column through the same command
    /// channel, delegating to the controller. `Some(dock)` insets the grid right by the dock width;
    /// `None` clears it. Switches no session, contacts no daemon, mutates no record. A closed receiver
    /// surfaces [`TabSwitchError::RendererControlClosed`].
    pub fn set_dock(
        &mut self,
        dock: Option<maestro_renderer::RendererDockModel>,
    ) -> Result<(), TabSwitchError> {
        self.controller.set_dock(dock)
    }

    /// Replace (`Some`) or clear (`None`) the renderer's read-only file-preview band through the same
    /// command channel, delegating to the controller. `Some(preview)` paints the bounded file the app
    /// already read; `None` clears it. Display-chrome only — it opens/reads no file, switches no session,
    /// contacts no daemon, and mutates no record. A closed receiver surfaces
    /// [`TabSwitchError::RendererControlClosed`], exactly like `set_tab_strip`.
    pub fn set_file_preview(
        &mut self,
        file_preview: Option<maestro_renderer::RendererFilePreview>,
    ) -> Result<(), TabSwitchError> {
        self.controller.set_file_preview(file_preview)
    }

    /// Push a fresh dashboard model into the embedded React chrome, delegated to the controller.
    /// Display-chrome only — it does not switch sessions, contact the daemon, or mutate records.
    pub fn set_react_chrome_model(
        &mut self,
        model: &serde_json::Value,
    ) -> Result<(), TabSwitchError> {
        let model_json = if let Some(warning) = &self.window_order_warning {
            let mut model = model.clone();
            model["window_order_warning"] = serde_json::json!(warning);
            serde_json::to_string(&model)
        } else {
            serde_json::to_string(model)
        }
        .expect("dashboard model serializes");
        self.controller.set_react_chrome_model(model_json)
    }

    /// Local presentation status only; preserve it across every ordinary dashboard refresh.
    pub fn set_window_order_warning(&mut self, warning: Option<String>) -> bool {
        let changed = self.window_order_warning != warning;
        self.window_order_warning = warning;
        changed
    }

    /// Evaluate a host-owned callback script in the embedded React chrome, delegated to the
    /// controller. Display-chrome only — used for request/response UI callbacks such as folder picks.
    pub fn evaluate_react_chrome_script(&mut self, script: String) -> Result<(), TabSwitchError> {
        self.controller.evaluate_react_chrome_script(script)
    }

    pub fn set_react_chrome_overlay_visible(
        &mut self,
        visible: bool,
    ) -> Result<(), TabSwitchError> {
        self.controller.set_react_chrome_overlay_visible(visible)
    }

    /// Deliver a modal script and only then request overlay visibility, preserving FIFO ordering.
    pub fn show_react_chrome_overlay_modal(
        &mut self,
        script: String,
    ) -> Result<(), TabSwitchError> {
        self.controller.show_react_chrome_overlay_modal(script)
    }

    /// Ask the renderer/UI side to open a native folder picker for the embedded React chrome.
    pub fn pick_react_chrome_folder(&mut self, request_id: String) -> Result<(), TabSwitchError> {
        self.controller.pick_react_chrome_folder(request_id)
    }

    /// Resize the embedded React sidebar, delegated to the controller. This is runtime chrome
    /// geometry: it changes PTY columns via the renderer's resize path, but mutates no records.
    pub fn set_react_chrome_width(&mut self, width_logical_px: u32) -> Result<(), TabSwitchError> {
        self.controller.set_react_chrome_width(width_logical_px)
    }

    /// Return focus from dashboard chrome to the terminal without changing session state.
    pub fn focus_terminal(&mut self) -> Result<(), TabSwitchError> {
        self.controller.focus_terminal()
    }

    /// Set or clear a stashed-pane drag that started in React chrome, delegated to the controller.
    /// The renderer uses this only for native hover/drop geometry; app event handling owns revive.
    pub fn set_stashed_pane_drag(
        &mut self,
        drag: Option<maestro_renderer::RendererStashedPaneDrag>,
    ) -> Result<(), TabSwitchError> {
        self.controller.set_stashed_pane_drag(drag)
    }

    pub fn complete_stashed_pane_drop_at(&mut self, x: i32, y: i32) -> Result<(), TabSwitchError> {
        self.controller.complete_stashed_pane_drop_at(x, y)
    }

    pub fn move_stashed_pane_drag_to(&mut self, x: i32, y: i32) -> Result<(), TabSwitchError> {
        self.controller.move_stashed_pane_drag_to(x, y)
    }

    /// Set (`Some`) or clear (`None`) the renderer's renderer-local file-path-input prompt through the
    /// same command channel, delegating to the controller. The app sends `None` to clear the prompt
    /// after it has read a submitted path. It opens/reads no file, switches no session, contacts no
    /// daemon, and mutates no record. A closed receiver surfaces
    /// [`TabSwitchError::RendererControlClosed`], exactly like `set_file_preview`.
    pub fn set_file_path_input(
        &mut self,
        file_path_input: Option<maestro_renderer::RendererFilePathInput>,
    ) -> Result<(), TabSwitchError> {
        self.controller.set_file_path_input(file_path_input)
    }

    /// Set (`Some`) or clear (`None`) the renderer's display-only settings edit-draft marker through the
    /// same command channel, delegating to the controller. `Some(draft)` shows one bounded
    /// "pending / not saved" line for an editable settings row; `None` clears it. Display-chrome only —
    /// it collects no input, parses no value, writes no setting, switches no session, contacts no daemon,
    /// and mutates no record. A closed receiver surfaces [`TabSwitchError::RendererControlClosed`],
    /// exactly like `set_tab_strip`.
    pub fn set_settings_edit_draft(
        &mut self,
        draft: Option<maestro_renderer::RendererSettingsPanelEditDraft>,
    ) -> Result<(), TabSwitchError> {
        self.controller.set_settings_edit_draft(draft)
    }

    /// Apply the opt-in clipboard setting without changing terminal or viewport ownership.
    pub fn set_copy_on_select(&self, enabled: bool) -> Result<(), TabSwitchError> {
        self.controller
            .sender
            .send(maestro_renderer::RendererCommand::SetCopyOnSelect { enabled })
            .map_err(|_| TabSwitchError::RendererControlClosed)
    }

    /// Apply the user's program-copy preference without changing terminal ownership.
    pub fn set_program_clipboard(&self, enabled: bool) -> Result<(), TabSwitchError> {
        self.controller
            .sender
            .send(maestro_renderer::RendererCommand::SetProgramClipboard { enabled })
            .map_err(|_| TabSwitchError::RendererControlClosed)
    }

    /// Hand out a narrow, theme-only command handle that owns a CLONE of this runtime's renderer
    /// command sender. A background settings watcher can keep this and drive live theme swaps
    /// WITHOUT owning (or borrowing) the whole [`RendererTabRuntime`], which the foreground listener
    /// thread takes by value. Because `mpsc::Sender` is `Clone`, both the original runtime and every
    /// `RendererThemeRuntime` push onto the SAME channel the renderer drains; cloning the sender does
    /// not consume or mutate the original runtime, tab state, or any record.
    pub fn theme_runtime(&self) -> RendererThemeRuntime {
        RendererThemeRuntime {
            sender: self.controller.sender.clone(),
        }
    }

    /// Hand out a narrow, font-size-only command handle that owns a CLONE of this runtime's renderer
    /// command sender — the mirror of [`theme_runtime`](Self::theme_runtime) for live
    /// `appearance.font_size_px` re-apply. Both the original runtime and every `RendererFontSizeRuntime`
    /// push onto the SAME channel the renderer drains; cloning the sender does not consume or mutate the
    /// original runtime, tab state, or any record.
    pub fn font_size_runtime(&self) -> RendererFontSizeRuntime {
        RendererFontSizeRuntime {
            sender: self.controller.sender.clone(),
        }
    }

    /// Handle one renderer overlay tab activation: switch the viewport to `tab_id` and, on a real
    /// switch, refresh the read-only strip so its active marker follows. Delegates to the pure
    /// [`apply_tab_activation`] so the foreground listener and unit tests share one code path.
    pub fn on_tab_activated(
        &mut self,
        window_id: &str,
        selection: &[TabSelection],
        strip_tabs: &[WindowTabJson],
        tab_id: &str,
    ) -> Result<TabActivation, TabSwitchError> {
        apply_tab_activation(
            &mut self.controller,
            window_id,
            selection,
            strip_tabs,
            tab_id,
        )
    }

    /// Handle one renderer overlay close click for an inactive tab: refresh the read-only
    /// strip from the already-mutated post-close projection `new_strip_tabs`, keeping `active_tab_id`
    /// active; an active close is deferred (nothing sent). Delegates to the pure
    /// [`apply_inactive_tab_close`] so the foreground listener and unit tests share one code path.
    /// The caller performs the `WindowLayoutService::close_tab` record mutation before calling this.
    pub fn on_tab_close_requested(
        &mut self,
        window_id: &str,
        new_strip_tabs: &[WindowTabJson],
        active_tab_id: &str,
        closed_tab_id: &str,
    ) -> Result<TabCloseOutcome, TabSwitchError> {
        apply_inactive_tab_close(
            &mut self.controller,
            window_id,
            new_strip_tabs,
            active_tab_id,
            closed_tab_id,
        )
    }

    /// Handle one renderer overlay close click on the ACTIVE tab when another tab remains: switch the
    /// viewport to the planned next tab (resolving its session through the POST-close `new_selection`)
    /// and refresh the read-only strip with that tab active. An only-tab plan defers (nothing sent).
    /// Delegates to the pure [`apply_active_tab_close`] so the foreground listener and unit tests share
    /// one code path. The caller computes `plan` from the PRE-close tabs via [`plan_next_active_tab`]
    /// and performs the `WindowLayoutService::close_tab` record mutation before calling this.
    pub fn on_active_tab_close(
        &mut self,
        window_id: &str,
        plan: &NextActivePlan,
        new_selection: &[TabSelection],
        new_strip_tabs: &[WindowTabJson],
    ) -> Result<ActiveTabCloseOutcome, TabSwitchError> {
        apply_active_tab_close(
            &mut self.controller,
            window_id,
            plan,
            new_selection,
            new_strip_tabs,
        )
    }

    /// Drop the app's active-tab ownership, delegating to the controller. Sends no command. Used by
    /// the only-tab close path AFTER the strip-clear command is delivered.
    pub fn clear_active_tab(&mut self) {
        self.controller.clear_active_tab();
    }

    /// Handle one renderer overlay close click on the ACTIVE tab when it is the ONLY LIVE tab:
    /// neutralize the complete viewport with one `ClearViewport` and, only after that command is
    /// delivered, drop the app's active window/tab/session ownership. Sends no `AttachSession` or
    /// `SetTabStrip`. Delegates to the pure [`apply_only_tab_close`] so the foreground listener
    /// and unit tests share one code path. The caller computes the plan via [`plan_next_active_tab`]
    /// and performs the `WindowLayoutService::close_tab` record mutation (zero LIVE tabs; durable
    /// parked rows may remain) before calling this.
    pub fn on_only_tab_close(
        &mut self,
        plan: &NextActivePlan,
    ) -> Result<OnlyTabCloseOutcome, TabSwitchError> {
        apply_only_tab_close(&mut self.controller, plan)
    }
}

/// A narrow, theme-only handle onto the renderer command channel, owning a CLONE of the
/// [`RendererTabRuntime`]'s `mpsc::Sender<RendererCommand>` (see
/// [`RendererTabRuntime::theme_runtime`]). It exists so a background settings watcher can drive live
/// theme swaps without owning the whole tab runtime (which the foreground listener thread takes by
/// value). It can ONLY send `SetTheme`: no active-tab/session/layout/record state, no other command.
pub struct RendererThemeRuntime {
    sender: std::sync::mpsc::Sender<maestro_renderer::RendererCommand>,
}

impl RendererThemeRuntime {
    /// Swap the renderer's live color `theme` by sending exactly one
    /// [`maestro_renderer::RendererCommand::SetTheme`] onto the shared command channel. Color-only:
    /// it never switches the attached session, resizes, or mutates any record. A closed receiver
    /// (the renderer's event loop is gone) maps to [`TabSwitchError::RendererControlClosed`], the
    /// signal a watcher uses to stop.
    pub fn set_theme(&self, theme: maestro_renderer::RendererTheme) -> Result<(), TabSwitchError> {
        self.sender
            .send(maestro_renderer::RendererCommand::SetTheme { theme })
            .map_err(|_| TabSwitchError::RendererControlClosed)
    }
}

/// Single-tick decision helper for the foreground `attach-tab` settings theme watcher: given the
/// last-applied theme id and the latest effective theme id, send a live `SetTheme` IFF the id
/// changed AND parses as a [`maestro_renderer::RendererTheme`], updating `last_theme_id` on a real
/// send. Returns:
/// - `Ok(true)` — the id changed, parsed, and exactly one `SetTheme` was sent (`last_theme_id`
///   advanced to `next_theme_id`);
/// - `Ok(false)` — nothing was sent: either the id is unchanged, or it changed but does not parse as
///   a renderer theme (defensive: settings validation should already reject impossible ids, so this
///   path keeps `last_theme_id` UNCHANGED and never panics, leaving the next valid change free to
///   apply);
/// - `Err(RendererControlClosed)` — the renderer command channel is closed; the watcher loop should
///   stop. `last_theme_id` is left unchanged so no spurious "applied" state is recorded.
///
/// Pure and GUI-free: the only side effect is at most one `set_theme` send through the injected
/// [`RendererThemeRuntime`], so change/no-change/unparsable/closed behavior is unit-testable without
/// a window or a real 500ms sleep.
pub fn maybe_send_theme_update(
    runtime: &RendererThemeRuntime,
    last_theme_id: &mut String,
    next_theme_id: &str,
) -> Result<bool, TabSwitchError> {
    if last_theme_id == next_theme_id {
        return Ok(false);
    }
    let Some(theme) = maestro_renderer::RendererTheme::parse(next_theme_id) else {
        // Changed but unparsable: do not advance `last_theme_id`, do not send. Settings validation
        // should prevent this; we tolerate it defensively rather than panic.
        return Ok(false);
    };
    runtime.set_theme(theme)?;
    *last_theme_id = next_theme_id.to_string();
    Ok(true)
}

/// A narrow, font-size-only handle onto the renderer command channel, owning a CLONE of the
/// [`RendererTabRuntime`]'s `mpsc::Sender<RendererCommand>` (see
/// [`RendererTabRuntime::font_size_runtime`]). The mirror of [`RendererThemeRuntime`] for the
/// `appearance.font_size_px` setting: a background settings watcher drives live font-size re-apply
/// without owning the whole tab runtime. It can ONLY send `SetFontSize`: no active-tab/session/layout/
/// record state, no other command.
pub struct RendererFontSizeRuntime {
    sender: std::sync::mpsc::Sender<maestro_renderer::RendererCommand>,
}

impl RendererFontSizeRuntime {
    /// Re-apply the renderer's live font size by sending exactly one
    /// [`maestro_renderer::RendererCommand::SetFontSize`] onto the shared command channel. Unlike
    /// `set_theme` the renderer DOES reflow the grid for a font-size change (it re-measures the cell
    /// and the renderer's own resize path sizes the PTY), but this handle still never switches the
    /// attached session or mutates any record. A closed receiver maps to
    /// [`TabSwitchError::RendererControlClosed`], the signal a watcher uses to stop.
    pub fn set_font_size(&self, px: u32) -> Result<(), TabSwitchError> {
        self.sender
            .send(maestro_renderer::RendererCommand::SetFontSize { px })
            .map_err(|_| TabSwitchError::RendererControlClosed)
    }
}

/// Single-tick decision helper for the foreground `attach-tab` settings font-size watcher: given the
/// last-applied font size and the latest effective font size, send a live `SetFontSize` IFF the size
/// changed, updating `last_font_size_px` on a real send. Returns:
/// - `Ok(true)` — the size changed and exactly one `SetFontSize` was sent (`last_font_size_px`
///   advanced to `next_font_size_px`);
/// - `Ok(false)` — nothing was sent because the size is unchanged;
/// - `Err(RendererControlClosed)` — the renderer command channel is closed; the watcher loop should
///   stop. `last_font_size_px` is left unchanged so no spurious "applied" state is recorded.
///
/// Unlike the theme helper there is no parse step: settings already resolve `appearance.font_size_px`
/// to an in-range `u32` (see [`renderer_font_size_px`](crate::renderer_font_size_px)). Pure and
/// GUI-free: the only side effect is at most one `set_font_size` send through the injected
/// [`RendererFontSizeRuntime`], so change/no-change/closed behavior is unit-testable without a window
/// or a real 500ms sleep.
pub fn maybe_send_font_size_update(
    runtime: &RendererFontSizeRuntime,
    last_font_size_px: &mut u32,
    next_font_size_px: u32,
) -> Result<bool, TabSwitchError> {
    if *last_font_size_px == next_font_size_px {
        return Ok(false);
    }
    runtime.set_font_size(next_font_size_px)?;
    *last_font_size_px = next_font_size_px;
    Ok(true)
}

/// The outcome of [`apply_tab_activation`] for one renderer tab click.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TabActivation {
    /// A real switch happened: an `AttachSession` was sent and the strip was refreshed with the
    /// clicked tab marked active.
    Switched,
    /// The clicked tab was already active; nothing was sent (no attach, no strip refresh).
    AlreadyActive,
}

/// Pure core of the foreground click-to-switch listener: resolve `tab_id` through the app-owned
/// `selection` (never inside the renderer), switch the viewport, and — only on a real switch —
/// rebuild the [`TabStripModel`] from the SAME loaded `strip_tabs` with the clicked tab active and
/// push it so the read-only strip's active marker follows the switched session.
///
/// Behavior:
/// - non-active valid tab: sends exactly one `AttachSession`, then one `SetTabStrip(Some(..))` with
///   the clicked tab active -> [`TabActivation::Switched`];
/// - already-active tab: `switch_to` is a no-op (`Ok(false)`), so NOTHING is sent — no attach and no
///   strip refresh (the marker already matches) -> [`TabActivation::AlreadyActive`];
/// - missing / ambiguous `tab_id`: `switch_to` errors before sending anything; the error is returned
///   and no `SetTabStrip` is attempted;
/// - closed renderer command channel: surfaces [`TabSwitchError::RendererControlClosed`] without
///   advancing active state.
///
/// `strip_tabs` is the persisted projection for the SAME window; `build_tab_strip_model` cannot fail
/// here because `switch_to` already proved the tab exists, but any model error is mapped to
/// [`TabSwitchError::TabNotFound`] for honesty rather than silently dropping the active mark. PURE:
/// no daemon, filesystem, or renderer launch — it only decides what to send through the injected
/// sink.
pub fn apply_tab_activation<S: RendererCommandSink>(
    controller: &mut TabSwitchController<S>,
    window_id: &str,
    selection: &[TabSelection],
    strip_tabs: &[WindowTabJson],
    tab_id: &str,
) -> Result<TabActivation, TabSwitchError> {
    if !controller.switch_to(window_id, selection, tab_id)? {
        return Ok(TabActivation::AlreadyActive);
    }
    let model = build_tab_strip_model(window_id, strip_tabs, Some(tab_id)).map_err(|e| {
        let TabStripModelError::ActiveTabNotFound { tab_id } = e;
        TabSwitchError::TabNotFound {
            window_id: window_id.to_string(),
            tab_id,
        }
    })?;
    controller.set_tab_strip(Some(&model))?;
    Ok(TabActivation::Switched)
}

/// The outcome of [`apply_inactive_tab_close`] for one renderer close click.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TabCloseOutcome {
    /// The closed tab was NOT the active tab: the strip was refreshed without it, keeping the
    /// previous active tab marked active. No session switch happened.
    ClosedInactive,
    /// The closed tab WAS the active tab: this helper does not mutate records or send any command.
    /// The caller logs the deferral and leaves everything running.
    ActiveCloseDeferred,
}

/// Whether closing `closed_tab_id` targets the currently active tab. Pure predicate the foreground
/// listener consults BEFORE mutating any record, so an active close is detected and deferred without
/// ever touching the persisted layout. With no active tab known, a close is treated as inactive.
pub fn is_active_tab_close(active_tab_id: Option<&str>, closed_tab_id: &str) -> bool {
    active_tab_id == Some(closed_tab_id)
}

/// Pure core of the foreground close-click listener for the INACTIVE-close path: given the
/// already-mutated post-close projection `new_strip_tabs` (the returned layout's tabs), the still
/// active `active_tab_id`, and the `closed_tab_id`, refresh the read-only strip without the closed
/// tab while keeping the previous active tab active.
///
/// Behavior:
/// - active close (`closed_tab_id == active_tab_id`): returns [`TabCloseOutcome::ActiveCloseDeferred`]
///   and sends NOTHING — the caller handles active-tab close, next-active selection, and only-tab
///   clearing separately;
/// - inactive close: rebuilds the [`TabStripModel`] from `new_strip_tabs` with `active_tab_id` still
///   active and sends exactly one `SetTabStrip(Some(..))` -> [`TabCloseOutcome::ClosedInactive`];
/// - the previous active tab is unexpectedly absent from `new_strip_tabs` (impossible for a correct
///   inactive close, since only the closed tab is removed): maps `ActiveTabNotFound` to
///   [`TabSwitchError::TabNotFound`] and sends NOTHING rather than pushing a strip with no active mark;
/// - closed renderer command channel: surfaces [`TabSwitchError::RendererControlClosed`].
///
/// PURE: no daemon, filesystem, or renderer launch — it only decides what to send through the injected
/// sink. The caller is responsible for having already performed the `WindowLayoutService::close_tab`
/// record mutation for the inactive case before calling this.
pub fn apply_inactive_tab_close<S: RendererCommandSink>(
    controller: &mut TabSwitchController<S>,
    window_id: &str,
    new_strip_tabs: &[WindowTabJson],
    active_tab_id: &str,
    closed_tab_id: &str,
) -> Result<TabCloseOutcome, TabSwitchError> {
    if is_active_tab_close(Some(active_tab_id), closed_tab_id) {
        return Ok(TabCloseOutcome::ActiveCloseDeferred);
    }
    let model =
        build_tab_strip_model(window_id, new_strip_tabs, Some(active_tab_id)).map_err(|e| {
            let TabStripModelError::ActiveTabNotFound { tab_id } = e;
            TabSwitchError::TabNotFound {
                window_id: window_id.to_string(),
                tab_id,
            }
        })?;
    controller.set_tab_strip(Some(&model))?;
    Ok(TabCloseOutcome::ClosedInactive)
}

/// The plan for which tab becomes active when the CURRENT active tab is closed and at least one
/// tab might remain. Produced by [`plan_next_active_tab`] from the PRE-close ordered tabs so the
/// foreground listener knows its target before mutating the record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NextActivePlan {
    /// Another tab remains: switch the renderer to this `tab_id` after the close.
    SelectNext { tab_id: String },
    /// The closed tab was the ONLY tab in the supplied LIVE projection: this plan defers only-tab close —
    /// the caller must not mutate records, clear the strip, or send any command.
    OnlyTabDeferred,
}

/// Pure selection policy for an ACTIVE-tab close: given the PRE-close ordered `pre_close_tabs` and the
/// closed active `closed_tab_id`, decide which remaining tab becomes active. The order used is the
/// persisted `index` order (NOT input order), matching how the strip is displayed.
///
/// Selection policy:
/// 1. prefer the right neighbor — the tab that occupies the closed tab's old index after compaction,
///    i.e. the tab immediately AFTER the closed one in index order;
/// 2. if the closed tab was last, choose the new last tab (the left neighbor);
/// 3. if the closed tab was the only LIVE projected tab, return [`NextActivePlan::OnlyTabDeferred`].
///
/// A `closed_tab_id` absent from `pre_close_tabs` is a typed, non-destructive
/// [`TabSwitchError::TabNotFound`] — the caller must not mutate anything. PURE: no record, daemon, or
/// renderer work; it only reads the slice and decides a target.
pub fn plan_next_active_tab(
    window_id: &str,
    pre_close_tabs: &[WindowTabJson],
    closed_tab_id: &str,
) -> Result<NextActivePlan, TabSwitchError> {
    let mut ordered: Vec<&WindowTabJson> = pre_close_tabs.iter().collect();
    ordered.sort_by_key(|t| t.index);
    let pos = ordered
        .iter()
        .position(|t| t.tab_id == closed_tab_id)
        .ok_or_else(|| TabSwitchError::TabNotFound {
            window_id: window_id.to_string(),
            tab_id: closed_tab_id.to_string(),
        })?;
    if ordered.len() == 1 {
        return Ok(NextActivePlan::OnlyTabDeferred);
    }
    // Right neighbor occupies the closed index after compaction; if the closed tab was last, fall
    // back to the new last tab (the left neighbor).
    let next = if pos + 1 < ordered.len() {
        &ordered[pos + 1]
    } else {
        &ordered[pos - 1]
    };
    Ok(NextActivePlan::SelectNext {
        tab_id: next.tab_id.clone(),
    })
}

/// The outcome of [`apply_active_tab_close`] for one renderer close click on the ACTIVE tab.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActiveTabCloseOutcome {
    /// Another tab remained: the renderer was switched to `next_tab_id` (one `AttachSession`) and the
    /// strip was refreshed with it active. The record was already mutated by the caller.
    SwitchedTo { next_tab_id: String },
    /// The closed tab was the ONLY LIVE projected tab: only-tab close is deferred. NOTHING was sent
    /// and the caller must NOT have mutated the record.
    OnlyTabDeferred,
}

/// Pure core of the foreground listener's ACTIVE-tab close (with remaining tabs). The caller computes
/// the next active tab from the PRE-close tabs via [`plan_next_active_tab`], performs the
/// `WindowLayoutService::close_tab` record mutation, then calls this with the POST-close projection
/// (`new_strip_tabs`) and matching `new_selection` to switch the renderer to the chosen tab.
///
/// Behavior:
/// - only-tab plan ([`NextActivePlan::OnlyTabDeferred`]): returns [`ActiveTabCloseOutcome::OnlyTabDeferred`]
///   and sends NOTHING — the caller must not have mutated the record in this case;
/// - remaining-tab plan: switch the viewport to the chosen `next_tab_id` via `switch_to`
///   (resolving its session through the POST-close `new_selection`), then rebuild the strip from
///   `new_strip_tabs` with that tab active and push it — exactly one `AttachSession` and one
///   `SetTabStrip(Some(..))`;
/// - the chosen next tab is unexpectedly absent from the post-close `new_selection`/`new_strip_tabs`
///   (record/plan drift): `switch_to` or the strip rebuild surfaces a typed
///   [`TabSwitchError::TabNotFound`] and sends no misleading command — the caller does NOT roll back
///   the already-mutated record;
/// - closed renderer command channel: surfaces [`TabSwitchError::RendererControlClosed`].
///
/// PURE: no record, daemon, or renderer launch — it only decides what to send through the injected
/// sink. The caller owns the record mutation and projection adoption.
pub fn apply_active_tab_close<S: RendererCommandSink>(
    controller: &mut TabSwitchController<S>,
    window_id: &str,
    plan: &NextActivePlan,
    new_selection: &[TabSelection],
    new_strip_tabs: &[WindowTabJson],
) -> Result<ActiveTabCloseOutcome, TabSwitchError> {
    let next_tab_id = match plan {
        NextActivePlan::OnlyTabDeferred => return Ok(ActiveTabCloseOutcome::OnlyTabDeferred),
        NextActivePlan::SelectNext { tab_id } => tab_id.clone(),
    };
    // The closed tab WAS active, so the chosen tab is necessarily a different tab: `switch_to`
    // sends an `AttachSession` (never a no-op here). A drift where the chosen tab is missing from
    // the post-close selection surfaces a typed error and sends nothing further.
    controller.switch_to(window_id, new_selection, &next_tab_id)?;
    let model =
        build_tab_strip_model(window_id, new_strip_tabs, Some(&next_tab_id)).map_err(|e| {
            let TabStripModelError::ActiveTabNotFound { tab_id } = e;
            TabSwitchError::TabNotFound {
                window_id: window_id.to_string(),
                tab_id,
            }
        })?;
    controller.set_tab_strip(Some(&model))?;
    Ok(ActiveTabCloseOutcome::SwitchedTo { next_tab_id })
}

/// The outcome of [`apply_only_tab_close`] for one renderer close click on the ACTIVE tab that is the
/// ONLY tab in the window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OnlyTabCloseOutcome {
    /// The only tab was closed: the renderer accepted one `ClearViewport` and the app's active
    /// window/tab/session ownership was dropped. No `AttachSession` or `SetTabStrip` was sent. The
    /// record was already mutated by the caller to zero LIVE tabs; durable parked rows may remain.
    ClearedEmptyWindow,
}

/// Pure core of the foreground listener's ONLY-LIVE-tab close. The caller computes the plan via
/// [`plan_next_active_tab`] (which returns [`NextActivePlan::OnlyTabDeferred`] for a one-live-tab
/// projection), performs the `WindowLayoutService::close_tab` record mutation (zero LIVE tabs;
/// durable parked rows may remain), then calls this to atomically deliver renderer neutralization
/// before clearing controller ownership. `ClearViewport` is renderer-local and never performs a
/// synchronous daemon detach.
///
/// Behavior:
/// - only-tab plan ([`NextActivePlan::OnlyTabDeferred`]): send exactly one `ClearViewport`, then —
///   ONLY after that command is delivered — drop active-tab ownership and return
///   [`OnlyTabCloseOutcome::ClearedEmptyWindow`]. No `SetTabStrip` or `AttachSession` is sent;
/// - closed renderer command channel: the `ClearViewport` send surfaces
///   [`TabSwitchError::RendererControlClosed`] and active-tab state is left UNCHANGED (not cleared),
///   so the caller does not falsely drop strip/controller ownership for an undelivered clear;
/// - a non-only-tab plan ([`NextActivePlan::SelectNext`]) is a caller bug — this path is only for the
///   only-tab case — and is rejected as a typed [`TabSwitchError::TabNotFound`] without sending
///   anything, so a misrouted remaining-tabs close can never silently clear the window.
///
/// PURE: no record, daemon, or renderer launch — it only decides what to send through the injected
/// sink and mutates the controller's in-memory active state. The caller owns the record mutation and
/// projection adoption.
pub fn apply_only_tab_close<S: RendererCommandSink>(
    controller: &mut TabSwitchController<S>,
    plan: &NextActivePlan,
) -> Result<OnlyTabCloseOutcome, TabSwitchError> {
    match plan {
        NextActivePlan::OnlyTabDeferred => {}
        NextActivePlan::SelectNext { tab_id } => {
            return Err(TabSwitchError::TabNotFound {
                window_id: controller
                    .active_window_id()
                    .map(str::to_owned)
                    .unwrap_or_default(),
                tab_id: tab_id.clone(),
            });
        }
    }
    // One local renderer transition owns both terminal and strip neutralization. Only if it is
    // delivered do we drop controller ownership, so there is no two-command partial-send matrix.
    controller.clear_viewport()?;
    Ok(OnlyTabCloseOutcome::ClearedEmptyWindow)
}

/// Project a post-close strip (`new_strip_tabs`, the returned layout's tabs) into the app-owned
/// `tab_id -> session_id` [`TabSelection`] mapping. Pure: the foreground listener calls this after a
/// successful inactive close so its live `selection` matches the mutated record (the closed tab is
/// gone), keeping future `TabStripActivated` resolution authoritative instead of resolving through a
/// stale pre-close projection. Order is preserved from `new_strip_tabs`.
pub fn selection_from_strip_tabs(new_strip_tabs: &[WindowTabJson]) -> Vec<TabSelection> {
    new_strip_tabs
        .iter()
        .map(|t| TabSelection {
            tab_id: t.tab_id.clone(),
            session_id: t.session_id.clone(),
        })
        .collect()
}

/// Pick the active tab id to project a strip with AFTER a pane close. Keeps the prior active tab when
/// it SURVIVES the close; otherwise (the active pane was the one closed) re-points to a survivor — the
/// closed pane's re-parented parent if it remains, else the first surviving tab. Returns `None` only
/// when nothing survives (the window emptied). Pure: reads the supplied ids only, mutates nothing.
///
/// Why this exists: passing the deleted active id into the strip rebuild fails with `ActiveTabNotFound`
/// and the strip never reprojects — the "last child can't be closed; it pretends to own everything"
/// symptom. Choosing a survivor here lets the active/last pane close cleanly.
pub fn surviving_active_tab_id(
    prior_active: Option<&str>,
    closing_parent_tab_id: Option<&str>,
    surviving_tab_ids: &[String],
) -> Option<String> {
    let survives = |id: &str| surviving_tab_ids.iter().any(|t| t == id);
    if let Some(a) = prior_active {
        if survives(a) {
            return Some(a.to_owned());
        }
    }
    closing_parent_tab_id
        .filter(|p| survives(p))
        .map(str::to_owned)
        .or_else(|| surviving_tab_ids.first().cloned())
}

/// Project a no-I/O [`NewTabSnapshot`] from the listener's current LIVE strip tabs. PURE: reads only
/// the supplied `tabs` + `active_tab_id`, reads no records, and mutates nothing. Because parked rows
/// are deliberately absent from the renderer projection, production new-tab planning must use
/// [`new_tab_snapshot_from_tab_records`] after loading the full durable target layout so parked
/// identities remain reserved.
pub fn new_tab_snapshot_from_strip_tabs(
    tabs: &[WindowTabJson],
    active_tab_id: Option<&str>,
) -> NewTabSnapshot {
    NewTabSnapshot {
        existing_tab_ids: tabs.iter().map(|t| t.tab_id.clone()).collect(),
        existing_session_ids: tabs.iter().map(|t| t.session_id.clone()).collect(),
        active_tab_id: active_tab_id.map(str::to_owned),
    }
}

/// Project a no-I/O [`NewTabSnapshot`] from ALL durable rows in the target window, including parked
/// (`stashed`) rows. Renderer/listener projections stay live-only, but a parked row still owns its
/// `tab_id` and `session_id`; new-tab planning must not mint either identity again. PURE: reads only
/// the supplied records and active id.
pub fn new_tab_snapshot_from_tab_records(
    tabs: &[maestro_shell::TabRecord],
    active_tab_id: Option<&str>,
) -> NewTabSnapshot {
    NewTabSnapshot {
        existing_tab_ids: tabs.iter().map(|tab| tab.tab_id.clone()).collect(),
        existing_session_ids: tabs.iter().map(|tab| tab.session_id.clone()).collect(),
        active_tab_id: active_tab_id.map(str::to_owned),
    }
}

/// Legacy projection-only classification of a closed tab's daemon session.
///
/// This public shape remains for app/test compatibility, but it is not durable release authority:
/// another process can retarget the tab after the PRE-close projection. Production close paths use
/// maestro-shell's transaction-returned opaque release receipt, committed with the tab mutation,
/// then pass it through the central full-ownership fence and generation-conditional daemon adapter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClosedTabSessionLifecycle {
    /// The closed tab's session is no longer referenced by any remaining tab: kill it.
    Kill { session_id: String },
    /// The closed tab's session is still referenced by at least one remaining post-close tab: keep
    /// it alive. Killing it would tear a session out from under a tab that still displays it.
    KeepShared { session_id: String },
    /// The closed tab id was not present in the PRE-close projection: lifecycle cleanup cannot be
    /// performed honestly for this event. Must be logged and must NOT block the record/UI close.
    MissingClosedTab { tab_id: String },
}

/// Classification of a focused tab for the close-focused-pane shortcut, decided PURELY from the
/// current strip tabs. Only a split CHILD LEAF may be closed by the shortcut: the root pane and any
/// non-leaf split pane are refused (no record mutation; the caller surfaces one bounded status).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FocusedPaneCloseClass {
    /// The focused tab is a split child (`split_from` set) AND no other tab splits from it. It is a
    /// closable leaf; the caller runs the close-tab lifecycle for `tab_id`.
    Leaf { tab_id: String },
    /// The focused tab is the root of a split workspace (or a plain top-level tab): `split_from` is
    /// `None`. Refused by this classifier.
    Root { tab_id: String },
    /// The focused tab is a split child that still has its OWN children (another tab splits from it),
    /// so it is not a leaf. Refused by this classifier.
    NonLeaf { tab_id: String },
    /// The focused `tab_id` names no tab in the current strip (stale focus / empty strip). Refused;
    /// nothing to close.
    Missing { tab_id: String },
}

/// Classify the focused tab for the close-focused-pane shortcut from the current strip tabs. PURE: no
/// daemon, record, or renderer work — the caller decides what to do with the classification.
///
/// A tab is a closable LEAF iff it carries `split_from` (it is a split child) AND no other tab in the
/// strip carries `split_from.tab_id == tab_id` (nothing was split off it). A tab with `split_from ==
/// None` is the `Root` (a plain top-level tab or a split-workspace root). A split child that still
/// has descendants is `NonLeaf`. A `tab_id` absent from `strip` is `Missing`.
pub fn classify_focused_pane_close(strip: &[WindowTabJson], tab_id: &str) -> FocusedPaneCloseClass {
    let Some(focused) = strip.iter().find(|t| t.tab_id == tab_id) else {
        return FocusedPaneCloseClass::Missing {
            tab_id: tab_id.to_string(),
        };
    };
    if focused.split_from.is_none() {
        return FocusedPaneCloseClass::Root {
            tab_id: tab_id.to_string(),
        };
    }
    let has_child = strip
        .iter()
        .any(|t| t.split_from.as_ref().is_some_and(|s| s.tab_id == tab_id));
    if has_child {
        FocusedPaneCloseClass::NonLeaf {
            tab_id: tab_id.to_string(),
        }
    } else {
        FocusedPaneCloseClass::Leaf {
            tab_id: tab_id.to_string(),
        }
    }
}

/// The split-subtree rooted at `tab_id`, returned in safe CLOSE ORDER: deepest descendants first,
/// `tab_id` itself last. A tab's children are every strip tab whose `split_from.tab_id == tab_id`;
/// the walk recurses so a `A -> B -> C` chain closing at `A` yields `[C, B, A]`. Closing in this
/// order guarantees no surviving tab ever points its `split_from` at an already-removed parent — the
/// orphaning that breaks the live strip projection (the closed root left dangling split-children
/// behind, after which every refresh failed with "active tab id is not in the tab list").
///
/// Returns an empty vec when `tab_id` is absent from `strip`. Pure + GUI-free so the cascade order is
/// unit-tested without a window. Robust against a malformed cycle: each tab is emitted at most once.
pub fn split_subtree_close_order(strip: &[WindowTabJson], tab_id: &str) -> Vec<String> {
    fn visit(strip: &[WindowTabJson], tab_id: &str, out: &mut Vec<String>) {
        if out.iter().any(|t| t == tab_id) {
            return;
        }
        for child in strip
            .iter()
            .filter(|t| t.split_from.as_ref().is_some_and(|s| s.tab_id == tab_id))
        {
            visit(strip, &child.tab_id, out);
        }
        out.push(tab_id.to_string());
    }
    if !strip.iter().any(|t| t.tab_id == tab_id) {
        return Vec::new();
    }
    let mut out = Vec::new();
    visit(strip, tab_id, &mut out);
    out
}

/// Classify a legacy projection-only closed-tab lifecycle, WITHOUT killing anything.
///
/// PURE: it reads the PRE-close `tab_id -> session_id` projection (`pre_close_selection`) to resolve
/// the closed tab's session, and the POST-close tabs (`post_close_tabs`) to detect a session still
/// shared by a remaining tab. It performs no daemon, record, or renderer work. Because either
/// projection can be stale, production code must never treat the returned plan as destructive
/// Session authority; see [`ClosedTabSessionLifecycle`] for the transaction-fenced replacement.
///
/// Behavior:
/// - closed tab found and NO remaining post-close tab references its `session_id` ->
///   [`ClosedTabSessionLifecycle::Kill`];
/// - closed tab found and at least one remaining post-close tab references the same `session_id` ->
///   [`ClosedTabSessionLifecycle::KeepShared`] (the shared-session guard);
/// - closed tab id absent from `pre_close_selection` ->
///   [`ClosedTabSessionLifecycle::MissingClosedTab`].
///
/// The listener passes ALL remaining durable rows as `post_close_tabs`, not its live-only renderer
/// strip. Therefore an only-live-tab close maps to `Kill` only when no durable row references the
/// session; a parked row sharing that session maps to `KeepShared`.
pub fn plan_closed_tab_session_lifecycle(
    pre_close_selection: &[TabSelection],
    post_close_tabs: &[WindowTabJson],
    closed_tab_id: &str,
) -> ClosedTabSessionLifecycle {
    let Some(closed) = pre_close_selection
        .iter()
        .find(|t| t.tab_id == closed_tab_id)
    else {
        return ClosedTabSessionLifecycle::MissingClosedTab {
            tab_id: closed_tab_id.to_string(),
        };
    };
    let still_shared = post_close_tabs
        .iter()
        .any(|t| t.session_id == closed.session_id);
    if still_shared {
        ClosedTabSessionLifecycle::KeepShared {
            session_id: closed.session_id.clone(),
        }
    } else {
        ClosedTabSessionLifecycle::Kill {
            session_id: closed.session_id.clone(),
        }
    }
}

/// The outcome of executing a [`ClosedTabSessionLifecycle`] plan against an injected kill function.
/// Returned so the foreground listener (and tests) can assert the exact branch taken and the
/// best-effort failure policy without owning a real daemon connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClosedTabKillOutcome {
    /// The plan was `Kill` and the injected kill function succeeded.
    Killed { session_id: String },
    /// The plan was `Kill` but the injected kill function returned an error. The error text is
    /// carried for logging. This is NON-FATAL: the caller must not roll back the record or undo any
    /// renderer/projection state.
    KillFailed { session_id: String, error: String },
    /// The plan was `KeepShared`: no kill was attempted (shared-session guard).
    KeptShared { session_id: String },
    /// The plan was `MissingClosedTab`: no kill was attempted; lifecycle cleanup was skipped.
    SkippedMissingTab { tab_id: String },
}

/// Execute a legacy [`ClosedTabSessionLifecycle`] plan using an injected function, applying the
/// best-effort failure policy. The ONLY side effect is invoking `kill`, and only for `Kill`.
/// Production must not connect this compatibility helper to a destructive daemon request: the plan
/// carries no transaction-local tab proof or global current-reference fence. Tests may pass a
/// recording fake; current production close paths use the maestro-shell service seam documented on
/// [`ClosedTabSessionLifecycle`].
///
/// A `Kill` whose `kill` errors yields [`ClosedTabKillOutcome::KillFailed`] (logged by the caller,
/// never fatal). `KeepShared` and `MissingClosedTab` never call `kill`.
pub fn execute_closed_tab_session_lifecycle<F>(
    plan: ClosedTabSessionLifecycle,
    kill: F,
) -> ClosedTabKillOutcome
where
    F: FnOnce(&str) -> Result<(), String>,
{
    match plan {
        ClosedTabSessionLifecycle::Kill { session_id } => match kill(&session_id) {
            Ok(()) => ClosedTabKillOutcome::Killed { session_id },
            Err(error) => ClosedTabKillOutcome::KillFailed { session_id, error },
        },
        ClosedTabSessionLifecycle::KeepShared { session_id } => {
            ClosedTabKillOutcome::KeptShared { session_id }
        }
        ClosedTabSessionLifecycle::MissingClosedTab { tab_id } => {
            ClosedTabKillOutcome::SkippedMissingTab { tab_id }
        }
    }
}

/// One persisted tab in a `window create`/`show`/`open-tab`/`split-tab` success: the ordered layout
/// fields plus the attention object and optional split provenance. Pure serde DTO; `main` fills it
/// from `maestro-shell`'s `TabRecord`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct WindowTabJson {
    pub tab_id: String,
    pub session_id: String,
    pub index: u32,
    pub title: String,
    pub pinned: bool,
    pub attention: AttentionJson,
    /// Set only when this tab was created by splitting an existing tab. Serializes as JSON `null`
    /// (and round-trips to `None`) for ordinary tabs, so existing consumers are unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split_from: Option<SplitFromJson>,
    /// The AUTHORITATIVE pane geometry copied verbatim from the shell's [`maestro_shell::PaneRect`]:
    /// an exact per-mille tiling rect `{x,y,w,h}` (each `0..=1000`). When present the renderer paints
    /// from it directly; absent (`null`) for older records, falling back to the `split_from` chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pane_rect: Option<PaneRectJson>,
}

/// The per-mille pane geometry rect `{x,y,w,h}` (each `0..=1000`, so `{0,0,500,1000}` is the left
/// half), copied verbatim from the shell's [`maestro_shell::PaneRect`]. Stored as integers so the DTO
/// keeps its `Eq` derive and serializes deterministically. This is the exact tiling description the
/// renderer scales by the grid and paints directly; see `PaneRect`'s doc for why it supersedes the
/// lossy `split_from` chain. Mirrors [`SplitFromJson`]'s derive set (Serialize-only).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PaneRectJson {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

/// Split provenance for a tab created by `window split-tab`: the source tab id and the axis the new
/// pane sits along (`right`|`down`). Pure serde DTO; `main` fills it from `maestro-shell`'s
/// `SplitFrom`/`SplitAxis`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SplitFromJson {
    pub tab_id: String,
    pub axis: String,
    /// Persisted divider position: the first/parent side's PER-MILLE share of the split axis
    /// (`0..=1000`), copied verbatim from the shell's [`maestro_shell::SplitFrom::ratio_per_mille`].
    /// `None` (an even split) for older records and freshly-created splits. Integer so the DTO keeps
    /// its `Eq` derive; serializes as JSON `null` absent, so existing consumers are unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ratio_per_mille: Option<u16>,
}

/// One tab as a future Rust-native tab strip will render it: the persisted layout/attention fields
/// plus the strip-only derived flags `active` and `needs_attention`. Pure, renderer-independent
/// serde DTO produced by [`build_tab_strip_model`]; it does no daemon/renderer/filesystem work.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TabStripItem {
    pub window_id: String,
    pub tab_id: String,
    pub session_id: String,
    pub title: String,
    pub index: u32,
    pub pinned: bool,
    pub active: bool,
    pub attention: AttentionJson,
    pub needs_attention: bool,
    /// State-aware indicator, with the joined live waiting-task override described below.
    /// `None` when the tab shows no marker (seen, `none`, or unknown state). Additive to
    /// `needs_attention`, which keeps its original boolean meaning. Serializes as JSON `null` absent.
    pub attention_indicator: Option<TabAttentionIndicator>,
    /// Split provenance copied verbatim from the persisted [`WindowTabJson::split_from`]: the source
    /// tab id and the axis (`right`|`down`) whose marker the strip draws. `None` for an ordinary tab.
    /// Serializes as JSON `null` when absent, so existing consumers are unaffected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub split_from: Option<SplitFromJson>,
    /// The authoritative per-mille pane rect copied verbatim from [`WindowTabJson::pane_rect`]. Carried
    /// through so the renderer projection ([`renderer_tab_strip`]) can hand the exact tiling to the
    /// draw path. `None` for older records; serializes as JSON `null` when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pane_rect: Option<PaneRectJson>,
}

/// The presentation model a Rust-native tab strip renders for one window: the `window_id`, the
/// resolved `active_tab_id` (the tab actually marked `active`, or `None`), and the persisted-index
/// ordered `tabs`. Pure serde DTO; built by [`build_tab_strip_model`] from existing window/tab JSON.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TabStripModel {
    pub window_id: String,
    pub active_tab_id: Option<String>,
    pub tabs: Vec<TabStripItem>,
}

/// Why [`build_tab_strip_model`] could not build a model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TabStripModelError {
    /// A selected active `tab_id` was supplied but no tab in the list has it. We refuse to silently
    /// produce a strip with no active tab when the caller explicitly asked for one.
    ActiveTabNotFound { tab_id: String },
}

impl std::fmt::Display for TabStripModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TabStripModelError::ActiveTabNotFound { tab_id } => {
                write!(f, "active tab id {tab_id:?} is not in the tab list")
            }
        }
    }
}

impl std::error::Error for TabStripModelError {}

/// Project existing persisted window/tab JSON ([`WindowTabJson`]) into the pure [`TabStripModel`] a
/// future Rust-native tab strip renders. PURE and deterministic: no daemon, renderer, filesystem, or
/// environment access; it only sorts, marks active, and derives `needs_attention`.
///
/// - `tabs` are ordered by persisted `index` (stable for equal indices), matching
///   `WindowLayoutSuccess`/window-command ordering.
/// - `active` is true only for the tab whose `tab_id == active_tab_id`; `active_tab_id` in the model
///   is `Some` only when that tab was actually found.
/// - When `active_tab_id` is `None` (or `tabs` is empty), the model has no active tab.
/// - When a non-`None` `active_tab_id` is NOT present in `tabs`, this returns
///   [`TabStripModelError::ActiveTabNotFound`] rather than silently dropping the active mark.
/// - `needs_attention` per tab is [`attention_needs_attention`] (persisted `unseen` + non-`none`),
///   preserving the nested attention object verbatim.
pub fn build_tab_strip_model(
    window_id: &str,
    tabs: &[WindowTabJson],
    active_tab_id: Option<&str>,
) -> Result<TabStripModel, TabStripModelError> {
    if let Some(wanted) = active_tab_id {
        if !tabs.iter().any(|t| t.tab_id == wanted) {
            return Err(TabStripModelError::ActiveTabNotFound {
                tab_id: wanted.to_string(),
            });
        }
    }

    let mut ordered: Vec<&WindowTabJson> = tabs.iter().collect();
    ordered.sort_by_key(|t| t.index);

    let mut resolved_active: Option<String> = None;
    let items = ordered
        .into_iter()
        .map(|t| {
            let active = active_tab_id == Some(t.tab_id.as_str());
            if active {
                resolved_active = Some(t.tab_id.clone());
            }
            TabStripItem {
                window_id: window_id.to_string(),
                tab_id: t.tab_id.clone(),
                session_id: t.session_id.clone(),
                title: t.title.clone(),
                index: t.index,
                pinned: t.pinned,
                active,
                attention: t.attention.clone(),
                needs_attention: attention_needs_attention(&t.attention),
                attention_indicator: tab_attention_indicator(&t.attention),
                split_from: t.split_from.clone(),
                pane_rect: t.pane_rect.clone(),
            }
        })
        .collect();

    Ok(TabStripModel {
        window_id: window_id.to_string(),
        active_tab_id: resolved_active,
        tabs: items,
    })
}

/// Project the joined `window view` rows ([`WindowViewTabJson`]) into the pure [`TabStripModel`],
/// folding task/session-derived attention into the visible strip. Same ordering and active-tab error
/// semantics as [`build_tab_strip_model`]; the only difference is the attention source:
///
/// - the persisted nested `attention` object is copied verbatim;
/// - a linked, present, live `WaitingOnUser` task with derived attention replaces an unseen
///   persisted `done`/`activity` marker with `needs_input`; all other persisted markers keep priority;
/// - `needs_attention` is `attention_needs_attention(&view.attention) || view.needs_attention`, so a
///   task/session-derived signal lights the legacy `!` fallback (renderer draws `!` when
///   `needs_attention == true` and `attention_indicator == None`) without changing the persisted path.
///
/// Split provenance (`split_from`) is copied verbatim from the view row, so the joined strip draws the
/// same `>`/`v` split markers as the persisted-layout path.
///
/// PURE and deterministic: no daemon, renderer, filesystem, or environment access. The task-derived
/// `view.needs_attention` is taken as already-reconciled input; this helper does not infer task state.
pub fn build_tab_strip_model_from_window_view(
    window_id: &str,
    tabs: &[WindowViewTabJson],
    active_tab_id: Option<&str>,
) -> Result<TabStripModel, TabStripModelError> {
    if let Some(wanted) = active_tab_id {
        if !tabs.iter().any(|t| t.tab_id == wanted && !t.stashed) {
            return Err(TabStripModelError::ActiveTabNotFound {
                tab_id: wanted.to_string(),
            });
        }
    }

    // Stashed tabs are parked on the dashboard, not drawn in the live window strip, so they are
    // excluded here. Their sessions stay alive in the daemon; the dashboard surfaces them as revive
    // candidates via the separate `project_stashed_tabs` path.
    let mut ordered: Vec<&WindowViewTabJson> = tabs.iter().filter(|t| !t.stashed).collect();
    ordered.sort_by_key(|t| t.index);

    let mut resolved_active: Option<String> = None;
    let items = ordered
        .into_iter()
        .map(|t| {
            let active = active_tab_id == Some(t.tab_id.as_str());
            if active {
                resolved_active = Some(t.tab_id.clone());
            }
            TabStripItem {
                window_id: window_id.to_string(),
                tab_id: t.tab_id.clone(),
                session_id: t.session_id.clone(),
                title: t.title.clone(),
                index: t.index,
                pinned: t.pinned,
                active,
                attention: t.attention.clone(),
                needs_attention: attention_needs_attention(&t.attention) || t.needs_attention,
                attention_indicator: joined_tab_attention_indicator(t),
                split_from: t.split_from.clone(),
                pane_rect: t.pane_rect.clone(),
            }
        })
        .collect();

    Ok(TabStripModel {
        window_id: window_id.to_string(),
        active_tab_id: resolved_active,
        tabs: items,
    })
}

// Display-only precedence for an explicitly declared wait, never provider-output detection.
fn joined_tab_attention_indicator(tab: &WindowViewTabJson) -> Option<TabAttentionIndicator> {
    let persisted = tab_attention_indicator(&tab.attention);
    if tab.needs_attention
        && tab.agent_task_id.is_some()
        && tab.agent_task_state.as_deref() == Some("waiting_on_user")
        && tab.session_status.as_deref() == Some("live")
        && !tab.session_record_missing
        && matches!(
            persisted.as_ref().map(|indicator| indicator.kind.as_str()),
            Some("done" | "activity")
        )
    {
        return Some(TabAttentionIndicator {
            kind: "needs_input".into(),
            marker: "?".into(),
        });
    }
    persisted
}

/// Pure change detection for the live tab-strip refresh: returns `true` when `next` differs from the
/// last strip the renderer was sent (`previous`), so the listener sends a fresh `SetTabStrip` ONLY on a
/// real change. A `None` `previous` (no strip sent yet) always counts as changed. Relies on
/// [`TabStripModel`]'s structural `PartialEq`, so any field a tab renders from — title, order, active,
/// pinned, persisted attention, or derived `needs_attention`/indicator — triggers a refresh, while an
/// identical rebuild is suppressed.
pub fn tab_strip_model_changed(previous: Option<&TabStripModel>, next: &TabStripModel) -> bool {
    previous != Some(next)
}

/// Project the pure app-side [`TabStripModel`] into the renderer-side read-only
/// [`maestro_renderer::RendererTabStrip`] the foreground renderer overlay consumes. PURE: it only
/// copies fields in model order (`window_id`, then each tab's `tab_id`, `session_id`, `title`, `active`,
/// `pinned`, `needs_attention`, the state-aware `attention_indicator`, and the `split_from` axis, each
/// mapped into the renderer's own type). The renderer type carries no app dependency, so this one-way
/// conversion is the single seam between the app's persisted model and the renderer's display strip.
pub fn renderer_tab_strip(model: &TabStripModel) -> maestro_renderer::RendererTabStrip {
    maestro_renderer::RendererTabStrip {
        window_id: model.window_id.clone(),
        tabs: model
            .tabs
            .iter()
            .map(|t| maestro_renderer::RendererTab {
                tab_id: t.tab_id.clone(),
                session_id: t.session_id.clone(),
                title: t.title.clone(),
                active: t.active,
                pinned: t.pinned,
                needs_attention: t.needs_attention,
                attention: t
                    .attention_indicator
                    .as_ref()
                    .and_then(renderer_attention_indicator),
                split: t.split_from.as_ref().and_then(renderer_split_axis),
                split_from_tab_id: t.split_from.as_ref().map(|s| s.tab_id.clone()),
                split_ratio_per_mille: t.split_from.as_ref().and_then(|s| s.ratio_per_mille),
                pane_rect: t.pane_rect.as_ref().map(renderer_pane_rect),
            })
            .collect(),
    }
}

/// A display-only strip refresh may change labels, attention and geometry, but never its exact
/// membership or primary role. Duplicate aliases of one session must keep one coherent geometry;
/// otherwise a single PTY could be painted/resized through contradictory pane coordinates.
fn display_strip_matches_exact_cohort(
    current: &maestro_renderer::RendererTabStrip,
    next: &maestro_renderer::RendererTabStrip,
) -> bool {
    if current.window_id != next.window_id || current.tabs.len() != next.tabs.len() {
        return false;
    }
    let cohort = |strip: &maestro_renderer::RendererTabStrip| {
        let mut tabs = std::collections::BTreeMap::new();
        let mut primary = None;
        let mut geometry_by_session = std::collections::BTreeMap::new();
        for tab in &strip.tabs {
            if tabs
                .insert(tab.tab_id.clone(), tab.session_id.clone())
                .is_some()
            {
                return None;
            }
            let geometry = tab.pane_rect.map(|rect| (rect.x, rect.y, rect.w, rect.h));
            if geometry_by_session
                .insert(tab.session_id.clone(), geometry)
                .is_some_and(|existing| existing != geometry)
            {
                return None;
            }
            if tab.active && primary.replace(tab.tab_id.clone()).is_some() {
                return None;
            }
        }
        Some((tabs, primary))
    };
    match (cohort(current), cohort(next)) {
        (Some(current), Some(next)) => current == next && current.1.is_some(),
        _ => false,
    }
}

/// Map a persisted [`PaneRectJson`] into the renderer's own [`maestro_renderer::RendererPaneRect`]
/// for the rect-driven paint path. A trivial field copy — the renderer owns its rect type so it
/// carries no app dependency, mirroring [`renderer_split_axis`].
fn renderer_pane_rect(rect: &PaneRectJson) -> maestro_renderer::RendererPaneRect {
    maestro_renderer::RendererPaneRect {
        x: rect.x,
        y: rect.y,
        w: rect.w,
        h: rect.h,
    }
}

/// Map a persisted [`SplitFromJson`] into the renderer's own [`maestro_renderer::RendererTabSplitAxis`]
/// for the drawn split marker. Returns `None` for an unrecognized axis string so an unknown future
/// axis silently draws no marker rather than guessing a glyph. The renderer owns the marker character;
/// this only resolves the axis variant.
fn renderer_split_axis(split: &SplitFromJson) -> Option<maestro_renderer::RendererTabSplitAxis> {
    match split.axis.as_str() {
        "right" => Some(maestro_renderer::RendererTabSplitAxis::Right),
        "down" => Some(maestro_renderer::RendererTabSplitAxis::Down),
        _ => None,
    }
}

/// One projected tab in a `window view` success: the persisted layout/attention fields plus the
/// joined agent-task/session reconcile fields. Pure serde DTO; `main` fills it from
/// `maestro-shell`'s `WindowTabView`. Optional joins serialize as JSON `null` when absent.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct WindowViewTabJson {
    pub tab_id: String,
    pub session_id: String,
    pub index: u32,
    pub title: String,
    pub pinned: bool,
    pub attention: AttentionJson,
    /// `live`/`exited`/`unknown`, or null when no session record was found.
    pub session_status: Option<String>,
    pub agent_task_id: Option<String>,
    /// The agent task state (`draft`/`running`/…), or null when the tab has no joined task.
    pub agent_task_state: Option<String>,
    pub needs_attention: bool,
    pub session_record_missing: bool,
    /// Split provenance copied verbatim from the persisted [`WindowTabView::split_from`]: the source
    /// tab id and the axis (`right`|`down`) whose marker the strip draws. `None` for an ordinary tab.
    /// Serializes as JSON `null` when absent, so existing consumers are unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split_from: Option<SplitFromJson>,
    /// The authoritative per-mille pane rect copied verbatim from the persisted
    /// [`WindowTabView::pane_rect`]. When present the renderer paints from it directly; `None` for
    /// older records. Serializes as JSON `null` when absent, so existing consumers are unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pane_rect: Option<PaneRectJson>,
    /// True when the tab is STASHED (session kept alive, hidden from the live pane layout, surfaced on
    /// the dashboard as a revive candidate). Defaults to `false` so existing JSON without the field
    /// deserializes as a normal visible tab.
    #[serde(default)]
    pub stashed: bool,
}

/// Project one persisted [`maestro_shell::TabRecord`] into the pure [`WindowTabJson`] DTO, preserving
/// `tab_id`/`session_id`/`index`/`title`/`pinned` verbatim and shaping `attention` into the same
/// wire-stable snake_case strings (`unseen`/`since_ms` preserved) that the `window` subcommands in
/// `maestro-app/src/main.rs` already emit. PURE: no daemon, renderer, filesystem, or environment.
pub fn tab_record_json(tab: &maestro_shell::TabRecord) -> WindowTabJson {
    WindowTabJson {
        tab_id: tab.tab_id.clone(),
        session_id: tab.session_id.clone(),
        index: tab.index,
        title: tab.title.clone(),
        pinned: tab.pinned,
        attention: AttentionJson {
            attention: attention_wire_str(tab.attention.attention).to_string(),
            unseen: tab.attention.unseen,
            since_ms: tab.attention.since_ms,
            source: attention_source_wire_str(tab.attention.source).to_string(),
        },
        split_from: split_from_json(tab.split_from.as_ref()),
        pane_rect: pane_rect_json(tab.pane_rect.as_ref()),
    }
}

/// Central live renderer/listener projection for persisted tab rows. Durable/CLI/dashboard callers
/// continue to inspect every row; only a native viewport projection uses this helper, which excludes
/// `stashed` panes before their identity can enter [`RendererTabRuntime`], activation, close, split,
/// rename, reseed, or recovery state.
pub fn live_tab_records_json(tabs: &[maestro_shell::TabRecord]) -> Vec<WindowTabJson> {
    tabs.iter()
        .filter(|tab| !tab.stashed)
        .map(tab_record_json)
        .collect()
}

/// Shape an optional persisted shell [`maestro_shell::PaneRect`] into the wire DTO [`PaneRectJson`] by
/// a field-by-field copy. The single projection used by every window/tab JSON path so they cannot
/// drift, mirroring [`split_from_json`].
pub(crate) fn pane_rect_json(rect: Option<&maestro_shell::PaneRect>) -> Option<PaneRectJson> {
    rect.map(|r| PaneRectJson {
        x: r.x,
        y: r.y,
        w: r.w,
        h: r.h,
    })
}

/// Shape an optional persisted [`maestro_shell::SplitFrom`] into the wire DTO [`SplitFromJson`],
/// mapping the axis enum to its wire-stable `right`/`down` string. The single projection used by every
/// window/tab JSON path (`tab_record_json` and the joined `window view` rows), so they cannot drift.
pub(crate) fn split_from_json(split: Option<&maestro_shell::SplitFrom>) -> Option<SplitFromJson> {
    split.map(|s| SplitFromJson {
        tab_id: s.tab_id.clone(),
        axis: match s.axis {
            maestro_shell::SplitAxis::Right => "right".to_string(),
            maestro_shell::SplitAxis::Down => "down".to_string(),
        },
        ratio_per_mille: s.ratio_per_mille,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    // The localized window runtime and tab-close tests exercise cross-module helpers and errors that
    // live in `attention.rs` / `new_tab.rs` and are re-exported at the crate root; `use super::*;`
    // only reaches `window.rs` items, so import them explicitly here.
    use crate::{
        clear_tab_attention_and_refresh_strip, new_tab_decline_status_label,
        rebuild_live_tab_strip_model, LiveTabStripRefreshError, TabAttentionClearRefreshError,
        NEW_TAB_DECLINE_HINT,
    };

    // Pure resolver tests for `resolve_window_record` (launch). These construct `LaunchArgs`
    // directly rather than going through the `launch` argument parser; the parser-error tests for
    // the same flags stay in `lib.rs`.

    #[test]
    fn resolve_window_record_defaults_window_tab_title_and_pinned() {
        // --record-window with no explicit ids/title/pinned: window "main", tab id = session id,
        // title = session id (no --tab-title/--title), pinned false.
        let a = LaunchArgs {
            record_window: true,
            session_id: Some("sess-9".to_string()),
            ..Default::default()
        };
        let p = resolve_window_record(&a, "sess-9").expect("record params");
        assert_eq!(p.window_id, "main");
        assert_eq!(p.tab_id, "sess-9");
        assert_eq!(p.tab_title, "sess-9");
        assert!(!p.tab_pinned);
    }

    #[test]
    fn resolve_window_record_tab_title_falls_back_to_window_title() {
        // With an explicit --title but no --tab-title, the recorded tab title falls back to --title.
        let a = LaunchArgs {
            record_window: true,
            title: Some("My Window".to_string()),
            session_id: Some("s1".to_string()),
            ..Default::default()
        };
        let p = resolve_window_record(&a, "s1").expect("record params");
        assert_eq!(p.tab_title, "My Window");
    }

    #[test]
    fn resolve_window_record_uses_explicit_ids_title_and_pinned() {
        let a = LaunchArgs {
            record_window: true,
            record_window_id: Some("w-2".to_string()),
            record_tab_id: Some("t-2".to_string()),
            record_tab_title: Some("Build".to_string()),
            record_tab_pinned: Some(true),
            session_id: Some("s2".to_string()),
            ..Default::default()
        };
        let p = resolve_window_record(&a, "s2").expect("record params");
        assert_eq!(p.window_id, "w-2");
        assert_eq!(p.tab_id, "t-2");
        assert_eq!(p.tab_title, "Build");
        assert!(p.tab_pinned);
    }

    #[test]
    fn resolve_window_record_tab_pinned_false_resolves_unpinned() {
        let a = LaunchArgs {
            record_window: true,
            record_tab_pinned: Some(false),
            ..Default::default()
        };
        assert_eq!(a.record_tab_pinned, Some(false));
        let p = resolve_window_record(&a, "s").expect("record params");
        assert!(!p.tab_pinned);
    }

    #[test]
    fn resolve_window_record_is_none_without_flag() {
        let a = LaunchArgs {
            session_id: Some("s".to_string()),
            ..Default::default()
        };
        assert!(resolve_window_record(&a, "s").is_none());
    }

    // ---- tab strip presentation model -------------------------------------------------------

    fn s(v: &str) -> String {
        v.to_string()
    }

    // The store intentionally caches SQLite connections. A fresh database path per test therefore
    // exhausts file descriptors late in the full App suite. Use one process-local database behind
    // a lease held for every fixture that keeps reading it. The lease serializes default-parallel
    // test workers, while unique durable ids (or explicit fixed-window retirement) prevent residue
    // from becoming authority for the next fixture.
    static EXACT_FIXTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static EXACT_FIXTURE_BASE: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();

    struct ExactFixtureLease {
        _guard: std::sync::MutexGuard<'static, ()>,
        cwd: tempfile::TempDir,
    }

    fn exact_fixture_lease() -> (ExactFixtureLease, maestro_shell::AppPaths) {
        let guard = EXACT_FIXTURE_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let base = EXACT_FIXTURE_BASE.get_or_init(|| {
            tempfile::Builder::new()
                .prefix("maestro-app-window-exact-")
                .tempdir()
                .expect("create process-local exact fixture base")
        });
        let cwd = tempfile::tempdir().expect("exact fixture cwd");
        let paths = maestro_shell::AppPaths::with_base(base.path());
        (ExactFixtureLease { _guard: guard, cwd }, paths)
    }

    fn next_exact_fixture_id(prefix: &str) -> String {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        format!(
            "{prefix}-{}",
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }

    /// Build two primary-role projections from one real Shell viewport snapshot. The fixture goes
    /// through SQLite and `WindowLayoutService::load_viewport_snapshot`, so App tests cannot forge
    /// a display strip independently from the exact generation cohort they exercise.
    fn exact_viewport_fixture() -> (
        ExactFixtureLease,
        maestro_shell::AppPaths,
        RendererViewportProjection,
        RendererViewportProjection,
    ) {
        let (lease, paths) = exact_fixture_lease();
        let suffix = next_exact_fixture_id("viewport");
        let project_id = format!("viewport-project-{suffix}");
        let workspace_id = format!("viewport-workspace-{suffix}");
        let window_id = format!("viewport-window-{suffix}");
        let session_a = format!("viewport-session-a-{suffix}");
        let session_b = format!("viewport-session-b-{suffix}");
        let tab_a = format!("viewport-tab-a-{suffix}");
        let tab_b = format!("viewport-tab-b-{suffix}");
        maestro_shell::ProjectService::new(&paths)
            .create(
                &project_id,
                "Viewport",
                lease.cwd.path().to_string_lossy(),
                maestro_shell::NewProject::default(),
                1,
            )
            .expect("create viewport project");
        maestro_shell::store::write_record(
            &paths,
            maestro_shell::RecordKind::Workspace,
            &workspace_id,
            1,
            &maestro_shell::Workspace {
                workspace_id: workspace_id.clone(),
                project_id: project_id.clone(),
                root: lease.cwd.path().to_string_lossy().into_owned(),
                policy: maestro_shell::WorkspacePolicy::ScratchCwd,
                consent: maestro_shell::WorkspaceConsent::default(),
            },
        )
        .expect("write viewport workspace");
        for (session_id, generation) in [(&session_a, "generation-a"), (&session_b, "generation-b")]
        {
            maestro_shell::store::write_record(
                &paths,
                maestro_shell::RecordKind::Session,
                session_id,
                1,
                &maestro_shell::SessionRecord {
                    session_id: session_id.clone(),
                    workspace_id: workspace_id.clone(),
                    kind: maestro_shell::SessionKind::Shell,
                    launch: maestro_shell::LaunchSpec::OptOut,
                    cwd_resolved: lease.cwd.path().to_string_lossy().into_owned(),
                    agent_task_id: None,
                    created_at_ms: 1,
                    last_attached_at_ms: 1,
                    last_known_generation: Some(generation.into()),
                    status: maestro_shell::SessionStatus::Live,
                },
            )
            .expect("write exact viewport Session");
        }
        let service = maestro_shell::WindowLayoutService::new(&paths);
        service
            .create_empty(&window_id, 1)
            .expect("create viewport window");
        service
            .open_tab(
                &window_id,
                &tab_a,
                &session_a,
                "A",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .expect("open viewport primary");
        service
            .split_tab(
                &window_id,
                &tab_a,
                &tab_b,
                &session_b,
                "B",
                maestro_shell::SplitAxis::Right,
                3,
            )
            .expect("split viewport sibling");
        let snapshot = service
            .load_viewport_snapshot(&window_id)
            .expect("load coherent viewport snapshot");
        let primary_a = renderer_viewport_projection_from_snapshot(&snapshot, &tab_a)
            .expect("project primary A");
        let primary_b = renderer_viewport_projection_from_snapshot(&snapshot, &tab_b)
            .expect("project primary B");
        (lease, paths, primary_a, primary_b)
    }

    fn test_daemon_instance() -> maestro_shell::DaemonInstanceId {
        "00000000000040008000000000000001"
            .parse()
            .expect("valid test daemon instance")
    }

    /// Give an otherwise display-only unit test a proven one-pane lifetime using the same
    /// SQLite→Shell snapshot→App projection path as production. This replaces the retired textual
    /// `seed_active_tab` fixture without reopening any raw Attach behavior.
    fn seed_exact_active_tab(
        runtime: &mut RendererTabRuntime,
        window_id: &str,
        tab_id: &str,
        session_id: &str,
    ) {
        let (lease, paths) = exact_fixture_lease();
        let suffix = next_exact_fixture_id("exact-active");
        let project_id = format!("exact-active-project-{suffix}");
        let workspace_id = format!("exact-active-workspace-{suffix}");
        maestro_shell::ProjectService::new(&paths)
            .create(
                &project_id,
                "Exact Active",
                lease.cwd.path().to_string_lossy(),
                maestro_shell::NewProject::default(),
                1,
            )
            .expect("create exact active project");
        maestro_shell::store::write_record(
            &paths,
            maestro_shell::RecordKind::Workspace,
            &workspace_id,
            1,
            &maestro_shell::Workspace {
                workspace_id: workspace_id.clone(),
                project_id: project_id.clone(),
                root: lease.cwd.path().to_string_lossy().into_owned(),
                policy: maestro_shell::WorkspacePolicy::ScratchCwd,
                consent: maestro_shell::WorkspaceConsent::default(),
            },
        )
        .expect("write exact active workspace");
        maestro_shell::store::write_record(
            &paths,
            maestro_shell::RecordKind::Session,
            session_id,
            1,
            &maestro_shell::SessionRecord {
                session_id: session_id.into(),
                workspace_id,
                kind: maestro_shell::SessionKind::Shell,
                launch: maestro_shell::LaunchSpec::OptOut,
                cwd_resolved: lease.cwd.path().to_string_lossy().into_owned(),
                agent_task_id: None,
                created_at_ms: 1,
                last_attached_at_ms: 1,
                last_known_generation: Some("exact-active-generation".into()),
                status: maestro_shell::SessionStatus::Live,
            },
        )
        .expect("write exact active Session");
        let service = maestro_shell::WindowLayoutService::new(&paths);
        let _ = service.delete(window_id);
        service
            .create_empty(window_id, 1)
            .expect("create exact active window");
        service
            .open_tab(
                window_id,
                tab_id,
                session_id,
                tab_id,
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .expect("open exact active tab");
        let snapshot = service
            .load_viewport_snapshot(window_id)
            .expect("load exact active snapshot");
        let projection = renderer_viewport_projection_from_snapshot(&snapshot, tab_id)
            .expect("project exact active viewport");
        runtime.seed_exact_active_for_test(projection, test_daemon_instance());
    }

    #[test]
    fn sidebar_revival_focus_reproves_cached_target_and_keeps_refresh_focusless() {
        let (_tmp, _paths, projection, _) = exact_viewport_fixture();
        let (mut runtime, commands) = RendererTabRuntime::new();
        let (events, _received) = std::sync::mpsc::channel();
        runtime.bind_renderer_events(events);
        runtime.seed_exact_active_for_test(projection.clone(), test_daemon_instance());
        assert!(runtime
            .switch_to_exact(projection.clone())
            .unwrap()
            .is_none());
        assert!(
            commands.try_recv().is_err(),
            "background refresh does not focus/rebind"
        );
        let id = runtime
            .switch_to_exact_with_dialog_focus(projection.clone(), Some(7))
            .unwrap()
            .unwrap();
        let maestro_renderer::RendererCommand::AttachExactViewport { request } =
            commands.try_recv().unwrap()
        else {
            panic!("explicit revival needs exact publication");
        };
        assert_eq!(request.request_id(), id);
        assert_eq!(request.dialog_focus_ticket(), Some(7));
        assert!(runtime.active_viewport().is_none());
        assert!(matches!(
            runtime.switch_to_exact_with_dialog_focus(projection, Some(8)),
            Err(TabSwitchError::HandoffPending)
        ));
        assert!(
            commands.try_recv().is_err(),
            "newer request cannot replace a pending exact bind"
        );
    }

    #[test]
    fn exact_viewport_send_is_neutral_until_matching_published_and_stale_terminal_is_inert() {
        let (_tmp, _paths, projection, _) = exact_viewport_fixture();
        let (mut runtime, commands) = RendererTabRuntime::new();
        let (events_tx, events_rx) = std::sync::mpsc::channel();
        runtime.bind_renderer_events(events_tx);

        let request_id = runtime
            .switch_to_exact(projection.clone())
            .expect("queue exact viewport")
            .expect("a new exact request is pending");
        assert!(runtime.active_viewport().is_none(), "send is not adoption");
        assert_eq!(
            runtime
                .pending_viewport()
                .and_then(PendingRendererViewport::ordinary_request_id),
            Some(request_id)
        );
        let request = match commands.recv().expect("one exact command") {
            maestro_renderer::RendererCommand::AttachExactViewport { request } => request,
            other => panic!("expected AttachExactViewport, got {other:?}"),
        };
        assert_eq!(request.request_id(), request_id);
        assert!(commands.try_recv().is_err());

        let instance = test_daemon_instance();
        let settlement = runtime.controller.settle_exact_viewport_facts(
            request_id,
            projection.target().session_id.as_str(),
            projection.generation(),
            Some(&instance),
            maestro_renderer::RendererExactViewportOutcome::Published,
        );
        assert!(matches!(
            settlement,
            RendererViewportSettlement::Adopted(ref active)
                if active.projection() == &projection
                    && active.daemon_instance_id() == &instance
        ));
        assert_eq!(
            runtime.active_viewport().map(|active| active.projection()),
            Some(&projection)
        );
        assert!(runtime.pending_viewport().is_none());

        // The unit test cannot mint a renderer proof, so dropping its request-owned sink emits the
        // conservative terminal. Once the matching Published facts were consumed, that later event
        // is stale and must not revoke the adopted viewport.
        drop(request);
        let stale = match events_rx.recv().expect("request drop terminal") {
            maestro_renderer::RendererEvent::ExactViewportDisposition(disposition) => disposition,
            other => panic!("expected exact viewport terminal, got {other:?}"),
        };
        assert_eq!(
            runtime.settle_exact_viewport_disposition(&stale),
            RendererViewportSettlement::Stale
        );
        assert_eq!(
            runtime.active_viewport().map(|active| active.projection()),
            Some(&projection)
        );
    }

    #[test]
    fn exact_viewport_unavailable_and_clear_after_send_both_remain_neutral() {
        let (_tmp, _paths, projection_a, projection_b) = exact_viewport_fixture();
        let (mut runtime, commands) = RendererTabRuntime::new();
        let (events_tx, events_rx) = std::sync::mpsc::channel();
        runtime.bind_renderer_events(events_tx);

        let request_a = runtime
            .switch_to_exact(projection_a.clone())
            .expect("queue A")
            .expect("A request");
        let request = match commands.recv().expect("A command") {
            maestro_renderer::RendererCommand::AttachExactViewport { request } => request,
            other => panic!("expected exact A, got {other:?}"),
        };
        drop(request);
        let unavailable = match events_rx.recv().expect("A unavailable") {
            maestro_renderer::RendererEvent::ExactViewportDisposition(disposition) => disposition,
            other => panic!("expected exact terminal, got {other:?}"),
        };
        assert_eq!(unavailable.request_id(), request_a);
        assert!(matches!(
            runtime.settle_exact_viewport_disposition(&unavailable),
            RendererViewportSettlement::Neutralized(_)
        ));
        assert!(runtime.active_viewport().is_none());
        assert!(runtime.pending_viewport().is_none());

        let request_b = runtime
            .switch_to_exact(projection_b.clone())
            .expect("queue B")
            .expect("B request");
        let request = match commands.recv().expect("B command") {
            maestro_renderer::RendererCommand::AttachExactViewport { request } => request,
            other => panic!("expected exact B, got {other:?}"),
        };
        runtime.clear_viewport().expect("queue neutralizing Clear");
        assert!(matches!(
            commands.recv().expect("Clear follows exact B"),
            maestro_renderer::RendererCommand::ClearViewport
        ));
        let instance = test_daemon_instance();
        assert!(matches!(
            runtime.controller.settle_exact_viewport_facts(
                request_b,
                projection_b.target().session_id.as_str(),
                projection_b.generation(),
                Some(&instance),
                maestro_renderer::RendererExactViewportOutcome::Published,
            ),
            RendererViewportSettlement::Neutralized(_)
        ));
        assert!(runtime.active_viewport().is_none());
        assert!(runtime.pending_viewport().is_none());
        drop(request);
    }

    #[test]
    fn exact_primary_replacement_sends_one_request_and_stays_pending_until_published() {
        let (_tmp, _paths, projection_a, projection_b) = exact_viewport_fixture();
        let (mut runtime, commands) = RendererTabRuntime::new();
        let (events_tx, events_rx) = std::sync::mpsc::channel();
        runtime.bind_renderer_events(events_tx);
        let instance = test_daemon_instance();

        let request_a = runtime
            .switch_to_exact(projection_a.clone())
            .expect("queue A")
            .expect("A request");
        let delivered_a = match commands.recv().expect("A command") {
            maestro_renderer::RendererCommand::AttachExactViewport { request } => request,
            other => panic!("expected exact A, got {other:?}"),
        };
        assert!(matches!(
            runtime.controller.settle_exact_viewport_facts(
                request_a,
                projection_a.target().session_id.as_str(),
                projection_a.generation(),
                Some(&instance),
                maestro_renderer::RendererExactViewportOutcome::Published,
            ),
            RendererViewportSettlement::Adopted(_)
        ));
        drop(delivered_a);
        let stale = match events_rx.recv().expect("stale A terminal") {
            maestro_renderer::RendererEvent::ExactViewportDisposition(disposition) => disposition,
            other => panic!("expected exact terminal, got {other:?}"),
        };
        assert_eq!(
            runtime.settle_exact_viewport_disposition(&stale),
            RendererViewportSettlement::Stale
        );

        let request_b = runtime
            .switch_to_exact(projection_b.clone())
            .expect("queue replacement B")
            .expect("primary replacement needs a new exact request");
        assert!(runtime.active_viewport().is_none());
        assert_eq!(
            runtime
                .pending_viewport()
                .and_then(PendingRendererViewport::ordinary_request_id),
            Some(request_b)
        );
        let delivered_b = match commands.recv().expect("one replacement command") {
            maestro_renderer::RendererCommand::AttachExactViewport { request } => request,
            other => panic!("expected replacement AttachExactViewport, got {other:?}"),
        };
        assert_eq!(delivered_b.request_id(), request_b);
        assert!(commands.try_recv().is_err());
        assert!(events_rx.try_recv().is_err(), "send alone emits no proof");
        drop(delivered_b);
    }

    #[test]
    fn same_exact_primary_cosmetic_refresh_sends_only_compatible_strip_without_request() {
        let (_tmp, paths, projection, projection_b) = exact_viewport_fixture();
        let (mut runtime, commands) = RendererTabRuntime::new();
        let (events_tx, events_rx) = std::sync::mpsc::channel();
        runtime.bind_renderer_events(events_tx);
        let instance = test_daemon_instance();

        let request_id = runtime
            .switch_to_exact(projection.clone())
            .expect("queue initial projection")
            .expect("initial exact request");
        let delivered = match commands.recv().expect("initial exact command") {
            maestro_renderer::RendererCommand::AttachExactViewport { request } => request,
            other => panic!("expected initial exact request, got {other:?}"),
        };
        assert!(matches!(
            runtime.controller.settle_exact_viewport_facts(
                request_id,
                projection.target().session_id.as_str(),
                projection.generation(),
                Some(&instance),
                maestro_renderer::RendererExactViewportOutcome::Published,
            ),
            RendererViewportSettlement::Adopted(_)
        ));
        drop(delivered);
        let stale = match events_rx.recv().expect("stale initial terminal") {
            maestro_renderer::RendererEvent::ExactViewportDisposition(disposition) => disposition,
            other => panic!("expected exact terminal, got {other:?}"),
        };
        assert_eq!(
            runtime.settle_exact_viewport_disposition(&stale),
            RendererViewportSettlement::Stale
        );

        maestro_shell::WindowLayoutService::new(&paths)
            .update_attention(
                projection.target().window_id.as_str(),
                projection_b.target().tab_id.as_str(),
                maestro_shell::AttentionState {
                    attention: maestro_shell::Attention::Activity,
                    unseen: true,
                    since_ms: 8,
                    source: maestro_shell::AttentionSource::Process,
                },
                8,
            )
            .expect("update inactive presentation");
        let snapshot = maestro_shell::WindowLayoutService::new(&paths)
            .load_viewport_snapshot(projection.target().window_id.as_str())
            .expect("reload coherent viewport");
        let refreshed = renderer_viewport_projection_from_snapshot(
            &snapshot,
            projection.target().tab_id.as_str(),
        )
        .expect("refresh same exact primary");
        assert_eq!(refreshed.exact_viewport(), projection.exact_viewport());
        assert_ne!(refreshed.tab_strip(), projection.tab_strip());

        assert_eq!(
            runtime
                .switch_to_exact(refreshed.clone())
                .expect("compatible display refresh"),
            None,
            "same exact cohort does not create a lifecycle request"
        );
        assert!(matches!(
            commands.recv().expect("one display refresh"),
            maestro_renderer::RendererCommand::SetTabStrip { tab_strip: Some(_) }
        ));
        assert!(commands.try_recv().is_err());
        assert!(events_rx.try_recv().is_err());
        assert!(runtime.pending_viewport().is_none());
        assert_eq!(
            runtime
                .active_viewport()
                .map(ActiveRendererViewport::projection),
            Some(&refreshed)
        );
    }

    /// A `TabRecord` with the given attention roll-up, for the pure `tab_record_json` conversion
    /// tests (no daemon/layout needed).
    fn tab_record_with_attention(
        tab_id: &str,
        attention: maestro_shell::AttentionState,
    ) -> maestro_shell::TabRecord {
        maestro_shell::TabRecord {
            tab_id: s(tab_id),
            session_id: format!("{tab_id}-sess"),
            index: 0,
            title: format!("Title {tab_id}"),
            pinned: false,
            attention,
            split_from: None,
            pane_rect: None,
            stashed_from: None,
            stashed: false,
        }
    }

    #[test]
    fn tab_record_json_maps_every_attention_variant_to_snake_case() {
        let cases = [
            (maestro_shell::Attention::None, "none"),
            (maestro_shell::Attention::Activity, "activity"),
            (maestro_shell::Attention::NeedsInput, "needs_input"),
            (maestro_shell::Attention::Error, "error"),
            (maestro_shell::Attention::Done, "done"),
        ];
        for (variant, expected) in cases {
            let state = maestro_shell::AttentionState {
                attention: variant,
                ..maestro_shell::AttentionState::default()
            };
            let json = tab_record_json(&tab_record_with_attention("t", state));
            assert_eq!(json.attention.attention, expected);
        }
    }

    #[test]
    fn tab_record_json_maps_every_source_and_preserves_unseen_and_since_ms() {
        let cases = [
            (maestro_shell::AttentionSource::Process, "process"),
            (maestro_shell::AttentionSource::Agent, "agent"),
            (maestro_shell::AttentionSource::User, "user"),
        ];
        for (variant, expected) in cases {
            let state = maestro_shell::AttentionState {
                attention: maestro_shell::Attention::Activity,
                unseen: true,
                since_ms: 1_700_000_123,
                source: variant,
            };
            let json = tab_record_json(&tab_record_with_attention("t", state));
            assert_eq!(json.attention.source, expected);
            assert!(json.attention.unseen, "unseen must be preserved");
            assert_eq!(json.attention.since_ms, 1_700_000_123);
        }
    }

    #[test]
    fn tab_record_json_preserves_identity_index_title_pinned() {
        let mut tab = tab_record_with_attention("tab-7", maestro_shell::AttentionState::default());
        tab.session_id = s("sess-7");
        tab.index = 7;
        tab.title = s("My Tab");
        tab.pinned = true;
        let json = tab_record_json(&tab);
        assert_eq!(json.tab_id, "tab-7");
        assert_eq!(json.session_id, "sess-7");
        assert_eq!(json.index, 7);
        assert_eq!(json.title, "My Tab");
        assert!(json.pinned);
    }

    #[test]
    fn durable_new_tab_snapshot_reserves_stashed_identities() {
        let live = tab_record_with_attention("live-tab", maestro_shell::AttentionState::default());
        let mut stashed =
            tab_record_with_attention("parked-tab", maestro_shell::AttentionState::default());
        stashed.session_id = s("parked-session");
        stashed.stashed = true;

        let snapshot = new_tab_snapshot_from_tab_records(&[live, stashed], Some("live-tab"));

        assert_eq!(
            snapshot.existing_tab_ids,
            vec![s("live-tab"), s("parked-tab")],
            "parked durable rows still reserve their tab ids"
        );
        assert_eq!(
            snapshot.existing_session_ids,
            vec![s("live-tab-sess"), s("parked-session")],
            "parked durable rows still reserve their session ids"
        );
        assert_eq!(snapshot.active_tab_id, Some(s("live-tab")));
    }

    fn attention(state: &str, unseen: bool) -> AttentionJson {
        AttentionJson {
            attention: s(state),
            unseen,
            since_ms: 0,
            source: s("process"),
        }
    }

    fn strip_tab(tab_id: &str, index: u32, attention: AttentionJson) -> WindowTabJson {
        WindowTabJson {
            tab_id: s(tab_id),
            session_id: format!("sess-{tab_id}"),
            index,
            title: format!("Title {tab_id}"),
            pinned: false,
            attention,
            split_from: None,
            pane_rect: None,
        }
    }

    #[test]
    fn tab_strip_empty_list_is_stable_empty_model() {
        let model = build_tab_strip_model("w1", &[], None).unwrap();
        assert_eq!(model.window_id, "w1");
        assert_eq!(model.active_tab_id, None);
        assert!(model.tabs.is_empty());
    }

    #[test]
    fn tab_strip_sorts_by_persisted_index() {
        let tabs = vec![
            strip_tab("t2", 2, attention("none", false)),
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", false)),
        ];
        let model = build_tab_strip_model("w1", &tabs, None).unwrap();
        let ids: Vec<&str> = model.tabs.iter().map(|t| t.tab_id.as_str()).collect();
        assert_eq!(ids, ["t0", "t1", "t2"]);
        let idx: Vec<u32> = model.tabs.iter().map(|t| t.index).collect();
        assert_eq!(idx, [0, 1, 2]);
    }

    #[test]
    fn tab_strip_marks_active_exactly_once() {
        let tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", false)),
            strip_tab("t2", 2, attention("none", false)),
        ];
        let model = build_tab_strip_model("w1", &tabs, Some("t1")).unwrap();
        assert_eq!(model.active_tab_id.as_deref(), Some("t1"));
        let active: Vec<&str> = model
            .tabs
            .iter()
            .filter(|t| t.active)
            .map(|t| t.tab_id.as_str())
            .collect();
        assert_eq!(active, ["t1"]);
    }

    #[test]
    fn tab_strip_no_active_when_none_supplied() {
        let tabs = vec![strip_tab("t0", 0, attention("none", false))];
        let model = build_tab_strip_model("w1", &tabs, None).unwrap();
        assert_eq!(model.active_tab_id, None);
        assert!(model.tabs.iter().all(|t| !t.active));
    }

    #[test]
    fn tab_strip_selected_missing_tab_is_typed_error() {
        let tabs = vec![strip_tab("t0", 0, attention("none", false))];
        let err = build_tab_strip_model("w1", &tabs, Some("ghost")).unwrap_err();
        assert_eq!(
            err,
            TabStripModelError::ActiveTabNotFound { tab_id: s("ghost") }
        );
    }

    #[test]
    fn tab_strip_preserves_pinned_flag() {
        let mut pinned = strip_tab("t0", 0, attention("none", false));
        pinned.pinned = true;
        let plain = strip_tab("t1", 1, attention("none", false));
        let model = build_tab_strip_model("w1", &[pinned, plain], None).unwrap();
        assert!(model.tabs[0].pinned);
        assert!(!model.tabs[1].pinned);
    }

    #[test]
    fn tab_strip_attention_none_never_needs_attention() {
        // `none` does not need attention even when marked unseen.
        let tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", true)),
        ];
        let model = build_tab_strip_model("w1", &tabs, None).unwrap();
        assert!(!model.tabs[0].needs_attention);
        assert!(!model.tabs[1].needs_attention);
    }

    #[test]
    fn tab_strip_non_none_needs_attention_only_when_unseen() {
        for state in ["activity", "needs_input", "error", "done"] {
            let unseen = strip_tab("t0", 0, attention(state, true));
            let seen = strip_tab("t1", 1, attention(state, false));
            let model = build_tab_strip_model("w1", &[unseen, seen], None).unwrap();
            assert!(
                model.tabs[0].needs_attention,
                "{state} unseen should need attention"
            );
            assert!(
                !model.tabs[1].needs_attention,
                "{state} seen should not need attention"
            );
        }
    }

    #[test]
    fn attention_indicator_marker_per_kind() {
        for (state, marker) in [
            ("activity", "~"),
            ("needs_input", "?"),
            ("error", "!"),
            ("done", "="),
        ] {
            let ind = super::tab_attention_indicator(&attention(state, true))
                .unwrap_or_else(|| panic!("{state} unseen should have an indicator"));
            assert_eq!(ind.kind, state);
            assert_eq!(ind.marker, marker);
        }
    }

    #[test]
    fn attention_indicator_none_for_seen_none_or_unknown() {
        // Seen attention: no indicator even for a real kind.
        assert!(super::tab_attention_indicator(&attention("error", false)).is_none());
        // `none` never produces an indicator even when unseen.
        assert!(super::tab_attention_indicator(&attention("none", true)).is_none());
        // Unknown state string: defensive None, never a marker.
        assert!(super::tab_attention_indicator(&attention("mystery", true)).is_none());
    }

    #[test]
    fn tab_strip_carries_indicator_alongside_needs_attention() {
        let tabs = vec![
            strip_tab("t0", 0, attention("needs_input", true)),
            strip_tab("t1", 1, attention("error", false)),
            strip_tab("t2", 2, attention("none", true)),
        ];
        let model = build_tab_strip_model("w1", &tabs, None).unwrap();
        // Unseen needs_input -> both the boolean and the state-aware indicator.
        assert!(model.tabs[0].needs_attention);
        let ind = model.tabs[0].attention_indicator.as_ref().unwrap();
        assert_eq!(ind.kind, "needs_input");
        assert_eq!(ind.marker, "?");
        // Seen error -> neither.
        assert!(!model.tabs[1].needs_attention);
        assert!(model.tabs[1].attention_indicator.is_none());
        // Unseen none -> neither.
        assert!(!model.tabs[2].needs_attention);
        assert!(model.tabs[2].attention_indicator.is_none());
    }

    #[test]
    fn renderer_tab_strip_maps_state_aware_indicator() {
        use maestro_renderer::RendererTabAttentionKind;
        let cases = [
            ("activity", RendererTabAttentionKind::Activity, '~'),
            ("needs_input", RendererTabAttentionKind::NeedsInput, '?'),
            ("error", RendererTabAttentionKind::Error, '!'),
            ("done", RendererTabAttentionKind::Done, '='),
        ];
        for (state, kind, marker) in cases {
            let tabs = vec![strip_tab("t0", 0, attention(state, true))];
            let model = build_tab_strip_model("w1", &tabs, None).unwrap();
            let strip = super::renderer_tab_strip(&model);
            let att = strip.tabs[0]
                .attention
                .expect("indicator must carry through");
            assert_eq!(att.kind, kind);
            assert_eq!(att.marker, marker);
        }
        // Seen attention carries no renderer indicator.
        let seen = vec![strip_tab("t0", 0, attention("error", false))];
        let model = build_tab_strip_model("w1", &seen, None).unwrap();
        assert!(super::renderer_tab_strip(&model).tabs[0]
            .attention
            .is_none());
    }

    fn split_strip_tab(tab_id: &str, index: u32, from_tab_id: &str, axis: &str) -> WindowTabJson {
        let mut tab = strip_tab(tab_id, index, attention("none", false));
        tab.split_from = Some(SplitFromJson {
            tab_id: s(from_tab_id),
            axis: s(axis),
            ratio_per_mille: None,
        });
        tab
    }

    #[test]
    fn tab_strip_model_preserves_split_from() {
        let tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            split_strip_tab("t1", 1, "t0", "right"),
            split_strip_tab("t2", 2, "t0", "down"),
        ];
        let model = build_tab_strip_model("w1", &tabs, None).unwrap();
        // Ordinary tab carries no split provenance.
        assert!(model.tabs[0].split_from.is_none());
        // Split tabs carry the source tab id and axis verbatim.
        assert_eq!(
            model.tabs[1].split_from,
            Some(SplitFromJson {
                tab_id: s("t0"),
                axis: s("right"),
                ratio_per_mille: None,
            })
        );
        assert_eq!(
            model.tabs[2].split_from,
            Some(SplitFromJson {
                tab_id: s("t0"),
                axis: s("down"),
                ratio_per_mille: None,
            })
        );
    }

    #[test]
    fn split_subtree_close_order_is_empty_for_absent_tab() {
        let tabs = vec![strip_tab("t0", 0, attention("none", false))];
        assert!(super::split_subtree_close_order(&tabs, "ghost").is_empty());
    }

    #[test]
    fn split_subtree_close_order_singleton_for_childless_tab() {
        let tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            split_strip_tab("t1", 1, "t0", "down"),
        ];
        // t1 is a leaf: closing it touches only itself.
        assert_eq!(super::split_subtree_close_order(&tabs, "t1"), vec![s("t1")]);
    }

    #[test]
    fn split_subtree_close_order_returns_descendants_before_parent() {
        // root t0 -> t1 (right) -> t2 (down); plus a second child t3 split off t0.
        let tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            split_strip_tab("t1", 1, "t0", "right"),
            split_strip_tab("t2", 2, "t1", "down"),
            split_strip_tab("t3", 3, "t0", "down"),
        ];
        let order = super::split_subtree_close_order(&tabs, "t0");
        // Every descendant precedes its parent, and t0 is last.
        let pos = |id: &str| order.iter().position(|t| t == id).unwrap();
        assert!(pos("t2") < pos("t1"));
        assert!(pos("t1") < pos("t0"));
        assert!(pos("t3") < pos("t0"));
        assert_eq!(order.last().map(String::as_str), Some("t0"));
        // No tab is emitted twice.
        let mut sorted = order.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), order.len());
    }

    #[test]
    fn renderer_tab_strip_maps_split_axis() {
        use maestro_renderer::RendererTabSplitAxis;
        let tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            split_strip_tab("t1", 1, "t0", "right"),
            split_strip_tab("t2", 2, "t0", "down"),
        ];
        let model = build_tab_strip_model("w1", &tabs, None).unwrap();
        let strip = super::renderer_tab_strip(&model);
        assert_eq!(strip.tabs[0].split, None);
        assert_eq!(strip.tabs[1].split, Some(RendererTabSplitAxis::Right));
        assert_eq!(strip.tabs[2].split, Some(RendererTabSplitAxis::Down));
        // The renderer owns the drawn glyph.
        assert_eq!(strip.tabs[1].split.unwrap().marker(), '>');
        assert_eq!(strip.tabs[2].split.unwrap().marker(), 'v');
    }

    #[test]
    fn split_from_and_renderer_strip_carry_the_persisted_ratio() {
        // A split child whose record holds a per-mille ratio carries it verbatim through both the
        // tab-strip model's `split_from` DTO and the renderer projection's `split_ratio_per_mille`.
        let mut t1 = split_strip_tab("t1", 1, "t0", "right");
        t1.split_from.as_mut().unwrap().ratio_per_mille = Some(640);
        let tabs = vec![strip_tab("t0", 0, attention("none", false)), t1];
        let model = build_tab_strip_model("w1", &tabs, None).unwrap();
        // The DTO preserves the integer ratio on the split provenance.
        assert_eq!(
            model.tabs[1]
                .split_from
                .as_ref()
                .and_then(|s| s.ratio_per_mille),
            Some(640)
        );
        // The renderer projection surfaces it on the dedicated field for hydration.
        let strip = super::renderer_tab_strip(&model);
        assert_eq!(strip.tabs[1].split_ratio_per_mille, Some(640));
        // A non-split tab and a split tab without a recorded ratio both project `None` (even split).
        assert_eq!(strip.tabs[0].split_ratio_per_mille, None);
    }

    #[test]
    fn renderer_tab_strip_preserves_session_ids() {
        let tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", false)),
        ];
        let model = build_tab_strip_model("w1", &tabs, None).unwrap();
        let strip = super::renderer_tab_strip(&model);
        // The renderer tab carries the same session id the app projected (sess-<tab_id>), so the split
        // model can name the exact sibling session per pane.
        assert_eq!(strip.tabs[0].session_id, "sess-t0");
        assert_eq!(strip.tabs[1].session_id, "sess-t1");
    }

    #[test]
    fn renderer_tab_strip_unknown_split_axis_draws_nothing() {
        let tabs = vec![split_strip_tab("t0", 0, "src", "diagonal")];
        let model = build_tab_strip_model("w1", &tabs, None).unwrap();
        // The model preserves the raw string, but an unrecognized axis projects to no marker.
        assert!(model.tabs[0].split_from.is_some());
        assert_eq!(super::renderer_tab_strip(&model).tabs[0].split, None);
    }

    fn view_tab(
        tab_id: &str,
        index: u32,
        attention: AttentionJson,
        needs_attention: bool,
    ) -> WindowViewTabJson {
        WindowViewTabJson {
            tab_id: s(tab_id),
            session_id: format!("sess-{tab_id}"),
            index,
            title: format!("Title {tab_id}"),
            pinned: false,
            attention,
            session_status: None,
            agent_task_id: None,
            agent_task_state: None,
            needs_attention,
            session_record_missing: false,
            split_from: None,
            pane_rect: None,
            stashed: false,
        }
    }

    #[test]
    fn task_attention_only_sets_boolean_without_indicator() {
        // Persisted `none`, but the join reports task/session-derived attention: the legacy boolean
        // lights (renderer draws `!`) while no state-aware indicator is invented.
        let tabs = vec![view_tab("t0", 0, attention("none", true), true)];
        let model = build_tab_strip_model_from_window_view("w1", &tabs, None).unwrap();
        assert!(model.tabs[0].needs_attention);
        assert!(model.tabs[0].attention_indicator.is_none());
    }

    #[test]
    fn persisted_indicator_wins_over_task_attention() {
        // Both persisted unseen attention AND task-derived attention: the persisted state-aware
        // indicator is preserved (priority), and the boolean is true.
        let tabs = vec![view_tab("t0", 0, attention("needs_input", true), true)];
        let model = build_tab_strip_model_from_window_view("w1", &tabs, None).unwrap();
        assert!(model.tabs[0].needs_attention);
        let ind = model.tabs[0].attention_indicator.as_ref().unwrap();
        assert_eq!(ind.kind, "needs_input");
        assert_eq!(ind.marker, "?");
    }

    #[test]
    fn seen_persisted_plus_task_attention_is_boolean_only() {
        // Seen persisted attention contributes no indicator; task-derived attention still lights the
        // boolean -> legacy `!` fallback with no state-aware marker.
        let tabs = vec![view_tab("t0", 0, attention("error", false), true)];
        let model = build_tab_strip_model_from_window_view("w1", &tabs, None).unwrap();
        assert!(model.tabs[0].needs_attention);
        assert!(model.tabs[0].attention_indicator.is_none());
    }

    #[test]
    fn tab_strip_from_window_view_no_task_attention_matches_persisted() {
        // With task-derived attention false, the result must equal the persisted-only path exactly.
        let view = vec![
            view_tab("t1", 1, attention("activity", true), false),
            view_tab("t0", 0, attention("none", false), false),
        ];
        let from_view = build_tab_strip_model_from_window_view("w1", &view, Some("t0")).unwrap();
        let persisted = vec![
            strip_tab("t1", 1, attention("activity", true)),
            strip_tab("t0", 0, attention("none", false)),
        ];
        let from_persisted = build_tab_strip_model("w1", &persisted, Some("t0")).unwrap();
        assert_eq!(from_view, from_persisted);
    }

    #[test]
    fn tab_strip_from_window_view_order_and_active_error_parity() {
        // Ordering by persisted index matches `build_tab_strip_model`.
        let tabs = vec![
            view_tab("t2", 2, attention("none", false), false),
            view_tab("t0", 0, attention("none", false), false),
            view_tab("t1", 1, attention("none", false), false),
        ];
        let model = build_tab_strip_model_from_window_view("w1", &tabs, Some("t1")).unwrap();
        let ids: Vec<&str> = model.tabs.iter().map(|t| t.tab_id.as_str()).collect();
        assert_eq!(ids, ["t0", "t1", "t2"]);
        assert_eq!(model.active_tab_id.as_deref(), Some("t1"));
        // A missing active tab is the same typed error as the persisted path.
        let err = build_tab_strip_model_from_window_view("w1", &tabs, Some("ghost")).unwrap_err();
        assert_eq!(
            err,
            TabStripModelError::ActiveTabNotFound { tab_id: s("ghost") }
        );
    }

    fn split_view_tab(
        tab_id: &str,
        index: u32,
        from_tab_id: &str,
        axis: &str,
    ) -> WindowViewTabJson {
        let mut tab = view_tab(tab_id, index, attention("none", false), false);
        tab.split_from = Some(SplitFromJson {
            tab_id: s(from_tab_id),
            axis: s(axis),
            ratio_per_mille: None,
        });
        tab
    }

    #[test]
    fn tab_strip_from_window_view_hides_stashed_tabs() {
        // A stashed tab is parked on the dashboard, so the live window strip must omit it entirely
        // while the live siblings keep their relative order.
        let mut stashed = view_tab("t1", 1, attention("none", false), false);
        stashed.stashed = true;
        let view = vec![
            view_tab("t0", 0, attention("none", false), false),
            stashed,
            view_tab("t2", 2, attention("none", false), false),
        ];
        let model = build_tab_strip_model_from_window_view("w1", &view, Some("t0")).unwrap();
        let ids: Vec<&str> = model.tabs.iter().map(|t| t.tab_id.as_str()).collect();
        assert_eq!(
            ids,
            ["t0", "t2"],
            "stashed t1 is hidden from the live strip"
        );
    }

    #[test]
    fn tab_strip_from_window_view_rejects_stashed_tab_as_active() {
        // Passing a stashed tab id as the active tab is the same typed error as an unknown tab: the
        // strip never makes a hidden pane the active/focused one.
        let mut stashed = view_tab("t1", 1, attention("none", false), false);
        stashed.stashed = true;
        let view = vec![view_tab("t0", 0, attention("none", false), false), stashed];
        let err = build_tab_strip_model_from_window_view("w1", &view, Some("t1")).unwrap_err();
        assert_eq!(
            err,
            TabStripModelError::ActiveTabNotFound { tab_id: s("t1") }
        );
    }

    #[test]
    fn tab_strip_from_window_view_preserves_split_from_and_renders_markers() {
        use maestro_renderer::RendererTabSplitAxis;
        let view = vec![
            view_tab("t0", 0, attention("none", false), false),
            split_view_tab("t1", 1, "t0", "right"),
            split_view_tab("t2", 2, "t0", "down"),
        ];
        let model = build_tab_strip_model_from_window_view("w1", &view, None).unwrap();
        // The joined-view builder copies split provenance verbatim into the strip item.
        assert!(model.tabs[0].split_from.is_none());
        assert_eq!(
            model.tabs[1].split_from,
            Some(SplitFromJson {
                tab_id: s("t0"),
                axis: s("right"),
                ratio_per_mille: None,
            })
        );
        assert_eq!(
            model.tabs[2].split_from,
            Some(SplitFromJson {
                tab_id: s("t0"),
                axis: s("down"),
                ratio_per_mille: None,
            })
        );
        // And the renderer projection draws the `>` / `v` markers.
        let strip = super::renderer_tab_strip(&model);
        assert_eq!(strip.tabs[0].split, None);
        assert_eq!(strip.tabs[1].split, Some(RendererTabSplitAxis::Right));
        assert_eq!(strip.tabs[2].split, Some(RendererTabSplitAxis::Down));
        assert_eq!(strip.tabs[1].split.unwrap().marker(), '>');
        assert_eq!(strip.tabs[2].split.unwrap().marker(), 'v');
    }

    #[test]
    fn renderer_tab_strip_renders_task_derived_legacy_fallback() {
        // Task-derived-only attention -> renderer payload with `needs_attention: true` and no
        // state-aware indicator, which the renderer draws as the legacy `!` fallback.
        let tabs = vec![view_tab("t0", 0, attention("none", true), true)];
        let model = build_tab_strip_model_from_window_view("w1", &tabs, None).unwrap();
        let strip = super::renderer_tab_strip(&model);
        assert!(strip.tabs[0].needs_attention);
        assert!(strip.tabs[0].attention.is_none());
    }

    #[test]
    fn tab_strip_json_shape_is_stable() {
        let tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("error", true)),
        ];
        let model = build_tab_strip_model("w1", &tabs, Some("t1")).unwrap();
        let v: serde_json::Value = serde_json::to_value(&model).unwrap();
        assert_eq!(v["window_id"], serde_json::json!("w1"));
        assert_eq!(v["active_tab_id"], serde_json::json!("t1"));
        // Ordered tabs, each with the strip-derived flags.
        assert_eq!(v["tabs"][0]["tab_id"], serde_json::json!("t0"));
        assert_eq!(v["tabs"][0]["index"], serde_json::json!(0));
        assert_eq!(v["tabs"][0]["active"], serde_json::json!(false));
        assert_eq!(v["tabs"][0]["pinned"], serde_json::json!(false));
        assert_eq!(v["tabs"][0]["needs_attention"], serde_json::json!(false));
        assert_eq!(v["tabs"][1]["tab_id"], serde_json::json!("t1"));
        assert_eq!(v["tabs"][1]["session_id"], serde_json::json!("sess-t1"));
        assert_eq!(v["tabs"][1]["active"], serde_json::json!(true));
        assert_eq!(v["tabs"][1]["needs_attention"], serde_json::json!(true));
        // Attention reuses the same nested object shape as window layout JSON.
        assert_eq!(
            v["tabs"][1]["attention"]["attention"],
            serde_json::json!("error")
        );
        assert_eq!(v["tabs"][1]["attention"]["unseen"], serde_json::json!(true));
        assert_eq!(
            v["tabs"][1]["attention"]["source"],
            serde_json::json!("process")
        );
        assert_eq!(v["tabs"][1]["attention"]["since_ms"], serde_json::json!(0));
        // State-aware indicator: null for `none`, the kind+marker object for unseen `error`.
        assert_eq!(v["tabs"][0]["attention_indicator"], serde_json::Value::Null);
        assert_eq!(
            v["tabs"][1]["attention_indicator"]["kind"],
            serde_json::json!("error")
        );
        assert_eq!(
            v["tabs"][1]["attention_indicator"]["marker"],
            serde_json::json!("!")
        );
    }

    #[test]
    fn renderer_tab_strip_preserves_order_and_flags() {
        let mut pinned = strip_tab("t0", 0, attention("error", true));
        pinned.pinned = true;
        let tabs = vec![pinned, strip_tab("t1", 1, attention("none", false))];
        // Active = t0, which is also pinned + needs_attention.
        let model = build_tab_strip_model("w1", &tabs, Some("t0")).unwrap();
        let strip = super::renderer_tab_strip(&model);

        assert_eq!(strip.window_id, "w1");
        assert_eq!(strip.tabs.len(), 2);

        assert_eq!(strip.tabs[0].tab_id, "t0");
        assert_eq!(strip.tabs[0].title, model.tabs[0].title);
        assert!(strip.tabs[0].active);
        assert!(strip.tabs[0].pinned);
        assert!(strip.tabs[0].needs_attention);

        assert_eq!(strip.tabs[1].tab_id, "t1");
        assert!(!strip.tabs[1].active);
        assert!(!strip.tabs[1].pinned);
        assert!(!strip.tabs[1].needs_attention);
    }

    #[test]
    fn tab_strip_active_tab_id_none_when_no_tabs() {
        let model = build_tab_strip_model("w1", &[], Some("t0"));
        assert_eq!(
            model.unwrap_err(),
            TabStripModelError::ActiveTabNotFound { tab_id: s("t0") }
        );
    }

    fn tab(tab_id: &str, session_id: &str) -> TabSelection {
        TabSelection {
            tab_id: tab_id.to_string(),
            session_id: session_id.to_string(),
        }
    }

    /// A recording sink that captures every command it receives and can be flipped to a
    /// "closed channel" so tests exercise the renderer-control-closed path without a real
    /// renderer event loop.
    #[derive(Default)]
    struct RecordingSink {
        sent: std::cell::RefCell<Vec<maestro_renderer::RendererCommand>>,
        closed: bool,
    }

    impl RendererCommandSink for RecordingSink {
        fn send(&self, command: maestro_renderer::RendererCommand) -> Result<(), ()> {
            if self.closed {
                return Err(());
            }
            self.sent.borrow_mut().push(command);
            Ok(())
        }
    }

    fn attach_ids(sink: &RecordingSink) -> Vec<String> {
        sink.sent
            .borrow()
            .iter()
            .map(|c| match c {
                maestro_renderer::RendererCommand::AttachSession { session_id } => {
                    session_id.clone()
                }
                other => panic!("expected only AttachSession commands, got {other:?}"),
            })
            .collect()
    }

    #[test]
    fn overlay_modal_command_precedes_visibility_on_the_same_fifo() {
        let mut controller = TabSwitchController::new(RecordingSink::default());
        assert_eq!(
            controller.show_react_chrome_overlay_modal("window.modal();".to_owned()),
            Ok(())
        );
        let sent = controller.sender.sent.borrow();
        assert_eq!(sent.len(), 2);
        assert!(matches!(
            &sent[0],
            maestro_renderer::RendererCommand::EvaluateReactChromeScript { script, kind }
                if script == "window.modal();"
                    && *kind == maestro_renderer::ReactChromeScriptKind::Modal
        ));
        assert!(matches!(
            sent[1],
            maestro_renderer::RendererCommand::SetReactChromeOverlayVisible { visible: true }
        ));
    }

    #[test]
    fn failed_modal_send_never_queues_overlay_visibility() {
        let sink = RecordingSink {
            closed: true,
            ..Default::default()
        };
        let mut controller = TabSwitchController::new(sink);
        assert_eq!(
            controller.show_react_chrome_overlay_modal("window.modal();".to_owned()),
            Err(TabSwitchError::RendererControlClosed)
        );
        assert!(controller.sender.sent.borrow().is_empty());
    }

    fn recv_set_tab_strip(
        rx: &std::sync::mpsc::Receiver<maestro_renderer::RendererCommand>,
    ) -> Option<maestro_renderer::RendererTabStrip> {
        match rx.try_recv() {
            Ok(maestro_renderer::RendererCommand::SetTabStrip { tab_strip }) => tab_strip,
            other => panic!("expected one SetTabStrip, got {other:?}"),
        }
    }

    fn one_strip_model() -> TabStripModel {
        let mut tab = strip_tab("t0", 0, attention("none", false));
        tab.session_id = "sess-0".to_string();
        let tabs = vec![tab];
        build_tab_strip_model("w1", &tabs, Some("t0")).unwrap()
    }

    #[test]
    fn renderer_tab_runtime_set_tab_strip_some_sends_command_and_preserves_active_tab() {
        let (mut rt, rx) = RendererTabRuntime::new();
        // Establish an active tab so we can prove set_tab_strip leaves it untouched.
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-0");

        let model = one_strip_model();
        assert_eq!(rt.set_tab_strip(Some(&model)), Ok(()));
        let sent = recv_set_tab_strip(&rx).expect("a strip must be sent");
        assert_eq!(sent, renderer_tab_strip(&model));
        assert!(rx.try_recv().is_err(), "exactly one command is sent");

        // Active tab is unchanged: updating the strip is not a switch.
        assert_eq!(
            rt.active_tab_key(),
            Some(&ActiveTab {
                window_id: "w1".to_string(),
                tab_id: "t0".to_string(),
                session_id: "sess-0".to_string(),
            })
        );
    }

    #[test]
    fn renderer_tab_runtime_set_tab_strip_none_cannot_clear_an_exact_active_cohort() {
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-0");

        assert_eq!(
            rt.set_tab_strip(None),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(rx.try_recv().is_err(), "no display-only clear is emitted");
        assert_eq!(rt.active_tab_id(), Some("t0"));
    }

    #[test]
    fn renderer_tab_runtime_set_tab_strip_dropped_receiver_is_control_closed() {
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-0");
        drop(rx);
        let model = one_strip_model();
        assert_eq!(
            rt.set_tab_strip(Some(&model)),
            Err(TabSwitchError::RendererControlClosed)
        );
        assert_eq!(
            rt.set_tab_strip(None),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        // Neither failure invents a replacement lifetime.
        assert_eq!(rt.active_tab_id(), Some("t0"));
    }

    fn recv_set_dashboard_panel(
        rx: &std::sync::mpsc::Receiver<maestro_renderer::RendererCommand>,
    ) -> Option<maestro_renderer::RendererDashboardPanel> {
        match rx.try_recv() {
            Ok(maestro_renderer::RendererCommand::SetDashboardPanel { dashboard_panel }) => {
                dashboard_panel
            }
            other => panic!("expected one SetDashboardPanel, got {other:?}"),
        }
    }

    /// `set_dashboard_panel(Some(..))` sends exactly one display-only `SetDashboardPanel` carrying
    /// the panel lines, and mutates no active-tab/record state (it is not a switch).
    #[test]
    fn renderer_tab_runtime_set_dashboard_panel_some_sends_one_command() {
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-0");

        let panel = maestro_renderer::RendererDashboardPanel::settings(vec![
            "Settings".to_string(),
            "font-size: 14".to_string(),
        ]);
        assert_eq!(rt.set_dashboard_panel(Some(panel.clone())), Ok(()));
        assert_eq!(recv_set_dashboard_panel(&rx), Some(panel));
        assert!(rx.try_recv().is_err(), "exactly one command is sent");

        // Showing a panel is not a switch: the active tab is untouched.
        assert_eq!(rt.active_tab_id(), Some("t0"));
    }

    /// `set_dashboard_panel(None)` sends exactly one clear command and leaves active-tab state intact.
    #[test]
    fn renderer_tab_runtime_set_dashboard_panel_none_sends_one_clear() {
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-0");

        assert_eq!(rt.set_dashboard_panel(None), Ok(()));
        assert_eq!(recv_set_dashboard_panel(&rx), None, "None clears the panel");
        assert!(rx.try_recv().is_err());
        assert_eq!(rt.active_tab_id(), Some("t0"));
    }

    /// A dropped receiver surfaces [`TabSwitchError::RendererControlClosed`] for both arms, exactly
    /// like the tab-strip path.
    #[test]
    fn renderer_tab_runtime_set_dashboard_panel_dropped_receiver_is_control_closed() {
        let (mut rt, rx) = RendererTabRuntime::new();
        drop(rx);
        let panel =
            maestro_renderer::RendererDashboardPanel::settings(vec!["Settings".to_string()]);
        assert_eq!(
            rt.set_dashboard_panel(Some(panel)),
            Err(TabSwitchError::RendererControlClosed)
        );
        assert_eq!(
            rt.set_dashboard_panel(None),
            Err(TabSwitchError::RendererControlClosed)
        );
        assert_eq!(rt.active_tab_key(), None);
    }

    fn one_file_preview() -> maestro_renderer::RendererFilePreview {
        maestro_renderer::RendererFilePreview {
            path: "/tmp/notes.txt".to_string(),
            lines: vec!["alpha".to_string(), "beta".to_string()],
            truncated_bytes: false,
            truncated_lines: false,
            truncated_line_width: false,
        }
    }

    /// `set_file_preview(Some(..))` sends exactly one display-only `SetFilePreview` carrying the
    /// bounded body, and mutates no active-tab/record state (it is not a switch).
    #[test]
    fn renderer_tab_runtime_set_file_preview_some_sends_one_command() {
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-0");

        let preview = one_file_preview();
        assert_eq!(rt.set_file_preview(Some(preview.clone())), Ok(()));
        match rx.try_recv() {
            Ok(maestro_renderer::RendererCommand::SetFilePreview { file_preview }) => {
                assert_eq!(file_preview, Some(preview));
            }
            other => panic!("expected one SetFilePreview(Some(..)), got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "exactly one command is sent");
        // Painting a preview is not a switch: the active tab is untouched.
        assert_eq!(rt.active_tab_id(), Some("t0"));
    }

    /// `set_file_preview(None)` sends exactly one clear command and leaves active-tab state intact.
    #[test]
    fn renderer_tab_runtime_set_file_preview_none_sends_one_clear() {
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-0");

        assert_eq!(rt.set_file_preview(None), Ok(()));
        match rx.try_recv() {
            Ok(maestro_renderer::RendererCommand::SetFilePreview { file_preview }) => {
                assert!(file_preview.is_none(), "None clears the preview");
            }
            other => panic!("expected one SetFilePreview(None), got {other:?}"),
        }
        assert!(rx.try_recv().is_err());
        assert_eq!(rt.active_tab_id(), Some("t0"));
    }

    /// A dropped receiver surfaces [`TabSwitchError::RendererControlClosed`] for both arms, exactly
    /// like the dashboard-panel path.
    #[test]
    fn renderer_tab_runtime_set_file_preview_dropped_receiver_is_control_closed() {
        let (mut rt, rx) = RendererTabRuntime::new();
        drop(rx);
        assert_eq!(
            rt.set_file_preview(Some(one_file_preview())),
            Err(TabSwitchError::RendererControlClosed)
        );
        assert_eq!(
            rt.set_file_preview(None),
            Err(TabSwitchError::RendererControlClosed)
        );
        assert_eq!(rt.active_tab_key(), None);
    }

    /// `set_file_path_input(Some(..))` sends exactly one `SetFilePathInput` carrying the prompt and
    /// `set_file_path_input(None)` sends one clear; neither is a switch, so the active tab is untouched.
    #[test]
    fn renderer_tab_runtime_set_file_path_input_some_then_none_sends_two_commands() {
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-0");

        let input = maestro_renderer::RendererFilePathInput {
            path: "/tmp/x".to_string(),
        };
        assert_eq!(rt.set_file_path_input(Some(input.clone())), Ok(()));
        match rx.try_recv() {
            Ok(maestro_renderer::RendererCommand::SetFilePathInput { file_path_input }) => {
                assert_eq!(file_path_input, Some(input));
            }
            other => panic!("expected one SetFilePathInput(Some(..)), got {other:?}"),
        }
        assert_eq!(rt.set_file_path_input(None), Ok(()));
        match rx.try_recv() {
            Ok(maestro_renderer::RendererCommand::SetFilePathInput { file_path_input }) => {
                assert!(file_path_input.is_none(), "None clears the prompt");
            }
            other => panic!("expected one SetFilePathInput(None), got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "exactly two commands were sent");
        assert_eq!(rt.active_tab_id(), Some("t0"));
    }

    /// A dropped receiver surfaces [`TabSwitchError::RendererControlClosed`] for the file-path-input
    /// command, exactly like the file-preview path.
    #[test]
    fn renderer_tab_runtime_set_file_path_input_dropped_receiver_is_control_closed() {
        let (mut rt, rx) = RendererTabRuntime::new();
        drop(rx);
        assert_eq!(
            rt.set_file_path_input(Some(maestro_renderer::RendererFilePathInput::default())),
            Err(TabSwitchError::RendererControlClosed)
        );
        assert_eq!(
            rt.set_file_path_input(None),
            Err(TabSwitchError::RendererControlClosed)
        );
    }

    /// The picker dismiss listener must send exactly one `SetPickerOverlay { picker: None }` and
    /// must not mutate runtime/record state (browse-only overlay). Mirrors the tab-strip clear path.
    #[test]
    fn renderer_tab_runtime_set_picker_overlay_none_sends_one_clear_and_mutates_nothing() {
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-0");

        assert_eq!(rt.set_picker_overlay(None), Ok(()));
        match rx.try_recv() {
            Ok(maestro_renderer::RendererCommand::SetPickerOverlay { picker }) => {
                assert!(picker.is_none(), "dismiss clears the overlay");
            }
            other => panic!("expected one SetPickerOverlay(None), got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "exactly one command is sent");
        // Active tab is unchanged: dismissing the overlay is not a switch.
        assert_eq!(rt.active_tab_id(), Some("t0"));
    }

    #[test]
    fn renderer_tab_runtime_set_picker_overlay_dropped_receiver_is_control_closed() {
        let (mut rt, rx) = RendererTabRuntime::new();
        drop(rx);
        assert_eq!(
            rt.set_picker_overlay(None),
            Err(TabSwitchError::RendererControlClosed)
        );
        assert_eq!(rt.active_tab_key(), None);
    }

    /// The no-policy `+` decline path sends exactly one `SetStatusLabel { Some(..) }` carrying the
    /// composed decline label and must not mutate runtime/record state (display-only).
    #[test]
    fn renderer_tab_runtime_set_status_label_some_sends_one_command_and_mutates_nothing() {
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-0");

        let label = new_tab_decline_status_label("Maestro \u{b7} w1/t1");
        assert_eq!(rt.set_status_label(Some(label.clone())), Ok(()));
        match rx.try_recv() {
            Ok(maestro_renderer::RendererCommand::SetStatusLabel { status_label }) => {
                assert_eq!(status_label.as_deref(), Some(label.as_str()));
            }
            other => panic!("expected one SetStatusLabel(Some), got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "exactly one command is sent");
        // Updating the status label is display-only: it is not a switch.
        assert_eq!(rt.active_tab_id(), Some("t0"));
    }

    #[test]
    fn renderer_tab_runtime_set_status_label_dropped_receiver_is_control_closed() {
        let (mut rt, rx) = RendererTabRuntime::new();
        drop(rx);
        assert_eq!(
            rt.set_status_label(Some("hint".to_string())),
            Err(TabSwitchError::RendererControlClosed)
        );
        assert_eq!(rt.active_tab_key(), None);
    }

    /// A live theme swap sends exactly one `SetTheme { theme }` carrying the requested theme and must
    /// not mutate runtime/record state (color-only display chrome, not a switch).
    #[test]
    fn renderer_tab_runtime_set_theme_some_sends_one_command_and_mutates_nothing() {
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-0");

        assert_eq!(
            rt.set_theme(maestro_renderer::RendererTheme::HighContrastDark),
            Ok(())
        );
        match rx.try_recv() {
            Ok(maestro_renderer::RendererCommand::SetTheme { theme }) => {
                assert_eq!(theme, maestro_renderer::RendererTheme::HighContrastDark);
            }
            other => panic!("expected one SetTheme, got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "exactly one command is sent");
        // Swapping the theme is display-only: it is not a switch.
        assert_eq!(rt.active_tab_id(), Some("t0"));
    }

    #[test]
    fn renderer_tab_runtime_set_theme_dropped_receiver_is_control_closed() {
        let (mut rt, rx) = RendererTabRuntime::new();
        drop(rx);
        assert_eq!(
            rt.set_theme(maestro_renderer::RendererTheme::BuiltInDark),
            Err(TabSwitchError::RendererControlClosed)
        );
        assert_eq!(rt.active_tab_key(), None);
    }

    /// `theme_runtime()` hands out a narrow handle that owns a CLONE of the renderer command sender:
    /// it can drive a live `SetTheme` and does NOT consume or mutate the original `RendererTabRuntime`
    /// (the foreground listener thread still owns it by value), and both push onto the SAME channel.
    #[test]
    fn theme_runtime_set_theme_sends_one_command_without_consuming_runtime() {
        let layout = vec![tab("t0", "sess-0")];
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-0");

        let theme_runtime = rt.theme_runtime();
        assert_eq!(
            theme_runtime.set_theme(maestro_renderer::RendererTheme::HighContrastDark),
            Ok(())
        );
        match rx.try_recv() {
            Ok(maestro_renderer::RendererCommand::SetTheme { theme }) => {
                assert_eq!(theme, maestro_renderer::RendererTheme::HighContrastDark);
            }
            other => panic!("expected one SetTheme, got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "exactly one command is sent");
        // The original runtime is untouched and still usable.
        assert_eq!(rt.active_tab_id(), Some("t0"));
        assert_eq!(rt.switch_to("w1", &layout, "t0"), Ok(false));
    }

    #[test]
    fn theme_runtime_set_theme_dropped_receiver_is_control_closed() {
        let (rt, rx) = RendererTabRuntime::new();
        let theme_runtime = rt.theme_runtime();
        drop(rx);
        drop(rt);
        assert_eq!(
            theme_runtime.set_theme(maestro_renderer::RendererTheme::BuiltInDark),
            Err(TabSwitchError::RendererControlClosed)
        );
    }

    /// The single-tick decision helper sends exactly one live `SetTheme` and advances the last-applied
    /// id when the effective theme id changes to a parseable theme.
    #[test]
    fn maybe_send_theme_update_sends_one_command_on_change_and_advances_last() {
        let (rt, rx) = RendererTabRuntime::new();
        let theme_runtime = rt.theme_runtime();
        let mut last = "built_in_dark".to_string();

        assert_eq!(
            maybe_send_theme_update(&theme_runtime, &mut last, "high_contrast_dark"),
            Ok(true)
        );
        match rx.try_recv() {
            Ok(maestro_renderer::RendererCommand::SetTheme { theme }) => {
                assert_eq!(theme, maestro_renderer::RendererTheme::HighContrastDark);
            }
            other => panic!("expected one SetTheme, got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "exactly one command is sent");
        assert_eq!(last, "high_contrast_dark");
    }

    #[test]
    fn maybe_send_theme_update_no_change_sends_nothing() {
        let (rt, rx) = RendererTabRuntime::new();
        let theme_runtime = rt.theme_runtime();
        let mut last = "high_contrast_dark".to_string();

        assert_eq!(
            maybe_send_theme_update(&theme_runtime, &mut last, "high_contrast_dark"),
            Ok(false)
        );
        assert!(
            rx.try_recv().is_err(),
            "no command on an unchanged theme id"
        );
        assert_eq!(last, "high_contrast_dark");
    }

    /// A changed-but-unparseable id is tolerated defensively: no send, no panic, and `last` is left
    /// UNCHANGED so the next valid change is still free to apply.
    #[test]
    fn maybe_send_theme_update_unparseable_id_is_noop() {
        let (rt, rx) = RendererTabRuntime::new();
        let theme_runtime = rt.theme_runtime();
        let mut last = "built_in_dark".to_string();

        assert_eq!(
            maybe_send_theme_update(&theme_runtime, &mut last, "not_a_real_theme_id"),
            Ok(false)
        );
        assert!(
            rx.try_recv().is_err(),
            "no command on an unparseable theme id"
        );
        assert_eq!(last, "built_in_dark", "last-applied id is unchanged");

        // A subsequent valid change still applies.
        assert_eq!(
            maybe_send_theme_update(&theme_runtime, &mut last, "high_contrast_dark"),
            Ok(true)
        );
        assert!(matches!(
            rx.try_recv(),
            Ok(maestro_renderer::RendererCommand::SetTheme {
                theme: maestro_renderer::RendererTheme::HighContrastDark
            })
        ));
        assert_eq!(last, "high_contrast_dark");
    }

    #[test]
    fn maybe_send_theme_update_closed_channel_is_control_closed_and_keeps_last() {
        let (rt, rx) = RendererTabRuntime::new();
        let theme_runtime = rt.theme_runtime();
        drop(rx);
        drop(rt);
        let mut last = "built_in_dark".to_string();

        assert_eq!(
            maybe_send_theme_update(&theme_runtime, &mut last, "high_contrast_dark"),
            Err(TabSwitchError::RendererControlClosed)
        );
        assert_eq!(
            last, "built_in_dark",
            "a closed channel records no spurious applied state"
        );
    }

    /// `font_size_runtime()` hands out a narrow handle owning a CLONE of the renderer command sender;
    /// it drives a live `SetFontSize` without consuming or mutating the original `RendererTabRuntime`.
    #[test]
    fn font_size_runtime_set_font_size_sends_one_command_without_consuming_runtime() {
        let layout = vec![tab("t0", "sess-0")];
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-0");

        let font_size_runtime = rt.font_size_runtime();
        assert_eq!(font_size_runtime.set_font_size(22), Ok(()));
        match rx.try_recv() {
            Ok(maestro_renderer::RendererCommand::SetFontSize { px }) => assert_eq!(px, 22),
            other => panic!("expected one SetFontSize, got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "exactly one command is sent");
        assert_eq!(rt.active_tab_id(), Some("t0"));
        assert_eq!(rt.switch_to("w1", &layout, "t0"), Ok(false));
    }

    #[test]
    fn font_size_runtime_set_font_size_dropped_receiver_is_control_closed() {
        let (rt, rx) = RendererTabRuntime::new();
        let font_size_runtime = rt.font_size_runtime();
        drop(rx);
        drop(rt);
        assert_eq!(
            font_size_runtime.set_font_size(18),
            Err(TabSwitchError::RendererControlClosed)
        );
    }

    #[test]
    fn maybe_send_font_size_update_sends_one_command_on_change_and_advances_last() {
        let (rt, rx) = RendererTabRuntime::new();
        let font_size_runtime = rt.font_size_runtime();
        let mut last = 16u32;

        assert_eq!(
            maybe_send_font_size_update(&font_size_runtime, &mut last, 22),
            Ok(true)
        );
        match rx.try_recv() {
            Ok(maestro_renderer::RendererCommand::SetFontSize { px }) => assert_eq!(px, 22),
            other => panic!("expected one SetFontSize, got {other:?}"),
        }
        assert!(rx.try_recv().is_err(), "exactly one command is sent");
        assert_eq!(last, 22);
    }

    #[test]
    fn maybe_send_font_size_update_no_change_sends_nothing() {
        let (rt, rx) = RendererTabRuntime::new();
        let font_size_runtime = rt.font_size_runtime();
        let mut last = 22u32;

        assert_eq!(
            maybe_send_font_size_update(&font_size_runtime, &mut last, 22),
            Ok(false)
        );
        assert!(
            rx.try_recv().is_err(),
            "no command on an unchanged font size"
        );
        assert_eq!(last, 22);
    }

    #[test]
    fn maybe_send_font_size_update_closed_channel_is_control_closed_and_keeps_last() {
        let (rt, rx) = RendererTabRuntime::new();
        let font_size_runtime = rt.font_size_runtime();
        drop(rx);
        drop(rt);
        let mut last = 16u32;

        assert_eq!(
            maybe_send_font_size_update(&font_size_runtime, &mut last, 22),
            Err(TabSwitchError::RendererControlClosed)
        );
        assert_eq!(
            last, 16,
            "a closed channel records no spurious applied state"
        );
    }

    /// The pure decline-label composer appends the ASCII hint after a ` \u{b7} ` separator and is
    /// message-stable so the renderer-side decline signal stays deterministic.
    #[test]
    fn new_tab_decline_status_label_appends_hint_after_separator() {
        let composed = new_tab_decline_status_label("Maestro \u{b7} w1/t1 \u{b7} s-live");
        assert_eq!(
            composed,
            format!("Maestro \u{b7} w1/t1 \u{b7} s-live \u{b7} {NEW_TAB_DECLINE_HINT}")
        );
        assert!(composed.is_ascii() || composed.contains('\u{b7}'));
    }

    // --- clear_tab_attention_and_refresh_strip: app-side click-to-clear runtime seam ---

    /// Seed an on-disk window `w1` with two tabs through the real `WindowLayoutService`, then stamp
    /// tab `t-clear` with an unseen `activity` attention so a clear is observable. Returns the temp
    /// dir (kept alive by the caller) and its `AppPaths`.
    fn seed_window_for_clear(
        unseen_attention: maestro_shell::Attention,
    ) -> (ExactFixtureLease, maestro_shell::AppPaths) {
        let (lease, paths) = exact_fixture_lease();
        let suffix = next_exact_fixture_id("clear");
        let project_id = format!("clear-project-{suffix}");
        let workspace_id = format!("clear-workspace-{suffix}");
        maestro_shell::ProjectService::new(&paths)
            .create(
                &project_id,
                "Clear",
                lease.cwd.path().to_string_lossy(),
                maestro_shell::NewProject::default(),
                1,
            )
            .expect("create clear project");
        maestro_shell::store::write_record(
            &paths,
            maestro_shell::RecordKind::Workspace,
            &workspace_id,
            1,
            &maestro_shell::Workspace {
                workspace_id: workspace_id.clone(),
                project_id,
                root: lease.cwd.path().to_string_lossy().into_owned(),
                policy: maestro_shell::WorkspacePolicy::ScratchCwd,
                consent: maestro_shell::WorkspaceConsent::default(),
            },
        )
        .expect("write clear workspace");
        for (session_id, generation) in [
            ("sess-clear", "clear-generation"),
            ("sess-other", "other-generation"),
        ] {
            maestro_shell::store::write_record(
                &paths,
                maestro_shell::RecordKind::Session,
                session_id,
                1,
                &maestro_shell::SessionRecord {
                    session_id: session_id.into(),
                    workspace_id: workspace_id.clone(),
                    kind: maestro_shell::SessionKind::Shell,
                    launch: maestro_shell::LaunchSpec::OptOut,
                    cwd_resolved: lease.cwd.path().to_string_lossy().into_owned(),
                    agent_task_id: None,
                    created_at_ms: 1,
                    last_attached_at_ms: 1,
                    last_known_generation: Some(generation.into()),
                    status: maestro_shell::SessionStatus::Live,
                },
            )
            .expect("write clear Session");
        }
        let service = maestro_shell::WindowLayoutService::new(&paths);
        let _ = service.delete("w1");
        service.create_empty("w1", 0).expect("create window");
        let default_attention = maestro_shell::AttentionState::default();
        service
            .open_tab(
                "w1",
                "t-clear",
                "sess-clear",
                "Clear Me",
                false,
                default_attention,
                0,
            )
            .expect("open t-clear");
        service
            .open_tab(
                "w1",
                "t-other",
                "sess-other",
                "Other",
                false,
                default_attention,
                0,
            )
            .expect("open t-other");
        service
            .update_attention(
                "w1",
                "t-clear",
                maestro_shell::AttentionState {
                    attention: unseen_attention,
                    unseen: true,
                    since_ms: 5,
                    source: maestro_shell::AttentionSource::Process,
                },
                10,
            )
            .expect("seed unseen attention");
        (lease, paths)
    }

    fn seed_exact_active_from_window(
        paths: &maestro_shell::AppPaths,
        runtime: &mut RendererTabRuntime,
        active_tab_id: &str,
    ) {
        let snapshot = maestro_shell::WindowLayoutService::new(paths)
            .load_viewport_snapshot("w1")
            .expect("load exact clear viewport");
        let projection = renderer_viewport_projection_from_snapshot(&snapshot, active_tab_id)
            .expect("project exact clear viewport");
        runtime.seed_exact_active_for_test(projection, test_daemon_instance());
    }

    /// Write a `SessionRecord` + a linked `AgentTask` in the given state pointing at `session_id`, so
    /// the local reconcile join produces a task-derived `needs_attention` for the tab on that session.
    fn write_task_for_session(
        paths: &maestro_shell::AppPaths,
        session_id: &str,
        task_id: &str,
        state: maestro_shell::AgentTaskState,
    ) {
        // Seed the FK parents this record pair references before writing them: the SessionRecord's
        // `workspace_id` (→ workspaces → projects) and the AgentTask's `project_id` (→ projects).
        // Under the SQLite store's `foreign_keys=ON`, these INSERTs fail without the parent rows.
        maestro_shell::project::ProjectService::new(paths)
            .create(
                "p1",
                "p1",
                "/r",
                maestro_shell::project::NewProject::default(),
                1,
            )
            .ok();
        let workspace = maestro_shell::records::Workspace {
            workspace_id: "ws-1".into(),
            project_id: "p1".into(),
            root: "/tmp".into(),
            policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            consent: Default::default(),
        };
        maestro_shell::store::write_record(
            paths,
            maestro_shell::RecordKind::Workspace,
            "ws-1",
            1,
            &workspace,
        )
        .expect("write workspace parent");
        // The SessionRecord's `agent_task_id` is itself an FK to `agent_tasks`, so the task must be
        // persisted BEFORE the session that references it. The AgentTask's `current_session_id` is
        // not an FK, so this ordering is safe.
        let task = maestro_shell::AgentTask {
            agent_task_id: task_id.into(),
            project_id: "p1".into(),
            goal: "goal".into(),
            state,
            current_session_id: Some(session_id.into()),
            session_history: vec![],
            created_at_ms: 1,
            updated_at_ms: 1,
            result_summary: None,
        };
        maestro_shell::store::write_record(
            paths,
            maestro_shell::RecordKind::AgentTask,
            task_id,
            1,
            &task,
        )
        .expect("write task");
        let session = maestro_shell::SessionRecord {
            session_id: session_id.into(),
            workspace_id: "ws-1".into(),
            kind: maestro_shell::SessionKind::Agent,
            launch: maestro_shell::LaunchSpec::KnownSafe {
                launch_spec_id: "ls-1".into(),
                params: vec![],
            },
            cwd_resolved: "/tmp".into(),
            agent_task_id: Some(task_id.into()),
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status: maestro_shell::SessionStatus::Unknown,
        };
        maestro_shell::store::write_record(
            paths,
            maestro_shell::RecordKind::Session,
            session_id,
            1,
            &session,
        )
        .expect("write session");
    }

    fn refreshed_tab<'a>(model: &'a TabStripModel, tab_id: &str) -> &'a TabStripItem {
        model
            .tabs
            .iter()
            .find(|t| t.tab_id == tab_id)
            .unwrap_or_else(|| panic!("tab {tab_id} present in refreshed model"))
    }

    #[test]
    fn clear_and_refresh_clears_persisted_attention_and_sends_one_set_tab_strip() {
        let (_tmp, paths) = seed_window_for_clear(maestro_shell::Attention::Activity);
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_from_window(&paths, &mut rt, "t-clear");

        let out = clear_tab_attention_and_refresh_strip(
            &paths,
            &mut rt,
            "w1",
            "t-clear",
            Some("t-clear"),
            99,
        )
        .expect("clear + refresh must succeed");
        assert_eq!(out.window_id, "w1");
        assert_eq!(out.tab_id, "t-clear");

        // Exactly one SetTabStrip(Some(..)) carrying the refreshed model.
        let sent = recv_set_tab_strip(&rx).expect("a strip must be sent");
        assert_eq!(sent, renderer_tab_strip(&out.model));
        assert!(rx.try_recv().is_err(), "exactly one command is sent");

        // The cleared tab now has no persisted indicator and no attention signal.
        let cleared = refreshed_tab(&out.model, "t-clear");
        assert_eq!(cleared.attention.attention, "none");
        assert!(!cleared.attention.unseen);
        assert_eq!(cleared.attention.source, "user");
        assert!(cleared.attention_indicator.is_none());
        assert!(!cleared.needs_attention);

        // The persisted record on disk reflects the clear.
        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .expect("load")
            .expect("window exists");
        let rec = layout
            .tabs
            .iter()
            .find(|t| t.tab_id == "t-clear")
            .expect("t-clear persisted");
        assert_eq!(rec.attention.attention, maestro_shell::Attention::None);
        assert!(!rec.attention.unseen);
        assert_eq!(rec.attention.source, maestro_shell::AttentionSource::User);
    }

    #[test]
    fn clear_and_refresh_preserves_task_derived_needs_attention() {
        let (_tmp, paths) = seed_window_for_clear(maestro_shell::Attention::Activity);
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_from_window(&paths, &mut rt, "t-clear");
        // A waiting-on-user task on t-clear's session => task-derived needs_attention.
        write_task_for_session(
            &paths,
            "sess-clear",
            "task-wait",
            maestro_shell::AgentTaskState::WaitingOnUser,
        );
        let out = clear_tab_attention_and_refresh_strip(
            &paths,
            &mut rt,
            "w1",
            "t-clear",
            Some("t-clear"),
            99,
        )
        .expect("clear + refresh must succeed");

        let cleared = refreshed_tab(&out.model, "t-clear");
        // Persisted attention is cleared, but the task-derived signal survives as the legacy fallback.
        assert_eq!(cleared.attention.attention, "none");
        assert!(cleared.attention_indicator.is_none());
        assert!(
            cleared.needs_attention,
            "task-derived needs_attention must survive the persisted clear"
        );
        assert!(recv_set_tab_strip(&rx).is_some());
        assert!(rx.try_recv().is_err());
    }

    // --- rebuild_live_tab_strip_model + tab_strip_model_changed: periodic live-refresh seam ---

    #[test]
    fn live_refresh_rebuild_preserves_task_derived_needs_attention() {
        let (_tmp, paths) = seed_window_for_clear(maestro_shell::Attention::Activity);
        // A waiting-on-user task on t-clear's session => task-derived needs_attention that a
        // running renderer must learn about on an idle tick, NOT just on an event.
        write_task_for_session(
            &paths,
            "sess-clear",
            "task-wait",
            maestro_shell::AgentTaskState::WaitingOnUser,
        );

        let model = rebuild_live_tab_strip_model(&paths, "w1", Some("t-clear"))
            .expect("live rebuild must succeed");

        let row = refreshed_tab(&model, "t-clear");
        // Persisted activity attention is still present AND the task-derived signal is folded in,
        // exactly like the clear path's join — the rebuild reads live records only.
        assert!(
            row.needs_attention,
            "task-derived needs_attention must appear in the live rebuild"
        );
        assert_eq!(model.active_tab_id.as_deref(), Some("t-clear"));
    }

    #[test]
    fn live_refresh_rebuild_does_not_mutate_records() {
        let (_tmp, paths) = seed_window_for_clear(maestro_shell::Attention::Activity);

        // Rebuild several times; the persisted attention on t-clear must be untouched (no write).
        for _ in 0..3 {
            let _ = rebuild_live_tab_strip_model(&paths, "w1", Some("t-clear"))
                .expect("live rebuild must succeed");
        }

        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .expect("load")
            .expect("window exists");
        let rec = layout
            .tabs
            .iter()
            .find(|t| t.tab_id == "t-clear")
            .expect("t-clear persisted");
        // Still the seeded unseen activity from Process — a refresh is read-only.
        assert_eq!(rec.attention.attention, maestro_shell::Attention::Activity);
        assert!(rec.attention.unseen);
        assert_eq!(
            rec.attention.source,
            maestro_shell::AttentionSource::Process
        );
    }

    #[test]
    fn live_refresh_change_detection_suppresses_identical_rebuild() {
        let (_tmp, paths) = seed_window_for_clear(maestro_shell::Attention::Activity);

        let first =
            rebuild_live_tab_strip_model(&paths, "w1", Some("t-clear")).expect("first rebuild");
        let second =
            rebuild_live_tab_strip_model(&paths, "w1", Some("t-clear")).expect("second rebuild");

        // No external change between rebuilds => the listener must NOT send a no-op SetTabStrip.
        assert!(
            !tab_strip_model_changed(Some(&first), &second),
            "an identical rebuild must be suppressed"
        );
        // No prior strip ever counts as changed (initial send).
        assert!(tab_strip_model_changed(None, &second));
    }

    #[test]
    fn live_refresh_change_detection_notices_persisted_attention_change() {
        let (_tmp, paths) = seed_window_for_clear(maestro_shell::Attention::Activity);
        let baseline =
            rebuild_live_tab_strip_model(&paths, "w1", Some("t-clear")).expect("baseline rebuild");

        // Simulate ANOTHER process writing a different persisted attention on t-other.
        maestro_shell::WindowLayoutService::new(&paths)
            .update_attention(
                "w1",
                "t-other",
                maestro_shell::AttentionState {
                    attention: maestro_shell::Attention::Error,
                    unseen: true,
                    since_ms: 7,
                    source: maestro_shell::AttentionSource::Process,
                },
                20,
            )
            .expect("external attention write");

        let after = rebuild_live_tab_strip_model(&paths, "w1", Some("t-clear"))
            .expect("rebuild after external change");
        assert!(
            tab_strip_model_changed(Some(&baseline), &after),
            "an external persisted-attention change must be detected"
        );
    }

    #[test]
    fn live_refresh_rebuild_active_tab_not_found_is_error_and_caller_sends_nothing() {
        let (_tmp, paths) = seed_window_for_clear(maestro_shell::Attention::Activity);

        // A bogus active tab id surfaces a typed error; the listener treats this as non-fatal and
        // (per the main.rs timeout arm) sends no renderer command and keeps the last good strip.
        let err = rebuild_live_tab_strip_model(&paths, "w1", Some("does-not-exist"))
            .expect_err("missing active tab must error");
        assert!(matches!(
            err,
            LiveTabStripRefreshError::TabStripModel(TabStripModelError::ActiveTabNotFound { .. })
        ));
    }

    #[test]
    fn clear_and_refresh_keeps_supplied_active_tab() {
        let (_tmp, paths) = seed_window_for_clear(maestro_shell::Attention::Activity);
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_from_window(&paths, &mut rt, "t-other");

        // Clear t-clear but keep t-other active.
        let out = clear_tab_attention_and_refresh_strip(
            &paths,
            &mut rt,
            "w1",
            "t-clear",
            Some("t-other"),
            99,
        )
        .expect("clear + refresh must succeed");
        assert_eq!(out.model.active_tab_id.as_deref(), Some("t-other"));
        assert!(refreshed_tab(&out.model, "t-other").active);
        assert!(!refreshed_tab(&out.model, "t-clear").active);
        assert!(recv_set_tab_strip(&rx).is_some());
    }

    #[test]
    fn clear_and_refresh_update_failure_sends_no_command() {
        // No window on disk: update_attention fails before any reconcile/projection/renderer send.
        let (_lease, paths) = exact_fixture_lease();
        let _ = maestro_shell::WindowLayoutService::new(&paths).delete("ghost-w");
        let (mut rt, rx) = RendererTabRuntime::new();

        let err =
            clear_tab_attention_and_refresh_strip(&paths, &mut rt, "ghost-w", "ghost-t", None, 99)
                .expect_err("a missing window must fail the clear");
        assert!(matches!(
            err,
            TabAttentionClearRefreshError::WindowLayout(_)
        ));
        assert!(
            rx.try_recv().is_err(),
            "no renderer command on update failure"
        );
    }

    #[test]
    fn clear_and_refresh_model_failure_surfaces_typed_error_and_sends_no_command() {
        let (_tmp, paths) = seed_window_for_clear(maestro_shell::Attention::Activity);
        let (mut rt, rx) = RendererTabRuntime::new();

        // The clear succeeds, but the supplied active tab id is not in the window: model build fails.
        let err = clear_tab_attention_and_refresh_strip(
            &paths,
            &mut rt,
            "w1",
            "t-clear",
            Some("not-a-real-tab"),
            99,
        )
        .expect_err("an unknown active tab id must fail the strip projection");
        assert!(matches!(
            err,
            TabAttentionClearRefreshError::TabStripModel(
                TabStripModelError::ActiveTabNotFound { .. }
            )
        ));
        assert!(
            rx.try_recv().is_err(),
            "no renderer command on model failure"
        );

        // The clear still landed on disk (it happens before the failing projection).
        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .expect("load")
            .expect("window exists");
        let rec = layout
            .tabs
            .iter()
            .find(|t| t.tab_id == "t-clear")
            .expect("t-clear persisted");
        assert_eq!(rec.attention.attention, maestro_shell::Attention::None);
    }

    #[test]
    fn clear_and_refresh_closed_channel_surfaces_renderer_control_closed() {
        let (_tmp, paths) = seed_window_for_clear(maestro_shell::Attention::Activity);
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_from_window(&paths, &mut rt, "t-clear");
        drop(rx);

        let err = clear_tab_attention_and_refresh_strip(
            &paths,
            &mut rt,
            "w1",
            "t-clear",
            Some("t-clear"),
            99,
        )
        .expect_err("a closed renderer channel must surface a typed error");
        assert!(matches!(
            err,
            TabAttentionClearRefreshError::RendererControlClosed
        ));

        // Even though the refresh was not delivered, the record clear already landed.
        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .expect("load")
            .expect("window exists");
        let rec = layout
            .tabs
            .iter()
            .find(|t| t.tab_id == "t-clear")
            .expect("t-clear persisted");
        assert_eq!(rec.attention.attention, maestro_shell::Attention::None);
        assert!(!rec.attention.unseen);
    }

    // --- apply_tab_activation: the pure core of the foreground click-to-switch listener ---

    /// Two tabs (`t0`, `t1`) whose `strip_tabs` session ids (`sess-t0`/`sess-t1`, from `strip_tab`)
    /// match the `selection` projection, so resolving a click yields a consistent session id.
    fn activation_layout() -> (Vec<TabSelection>, Vec<WindowTabJson>) {
        let strip_tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", false)),
        ];
        let selection = strip_tabs
            .iter()
            .map(|t| TabSelection {
                tab_id: t.tab_id.clone(),
                session_id: t.session_id.clone(),
            })
            .collect();
        (selection, strip_tabs)
    }

    #[test]
    fn activation_non_active_tab_requires_fresh_exact_viewport_authority() {
        let (selection, strip_tabs) = activation_layout();
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");

        // Click the non-active tab t1.
        assert_eq!(
            rt.on_tab_activated("w1", &selection, &strip_tabs, "t1"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(
            rx.try_recv().is_err(),
            "no raw Attach or strip update is sent"
        );
        assert_eq!(rt.active_tab_id(), Some("t0"));
    }

    #[test]
    fn activation_already_active_tab_is_noop_no_attach_no_strip() {
        let (selection, strip_tabs) = activation_layout();
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");

        // Click the already-active tab t0: documented no-op — nothing is sent (no attach, no
        // strip refresh, since the active marker already matches).
        assert_eq!(
            rt.on_tab_activated("w1", &selection, &strip_tabs, "t0"),
            Ok(TabActivation::AlreadyActive)
        );
        assert!(
            rx.try_recv().is_err(),
            "an already-active click sends nothing"
        );
        assert_eq!(rt.active_tab_id(), Some("t0"));
    }

    #[test]
    fn activation_missing_tab_is_non_fatal_and_sends_nothing() {
        let (selection, strip_tabs) = activation_layout();
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");

        assert_eq!(
            rt.on_tab_activated("w1", &selection, &strip_tabs, "t-missing"),
            Err(TabSwitchError::TabNotFound {
                window_id: "w1".to_string(),
                tab_id: "t-missing".to_string(),
            })
        );
        assert!(rx.try_recv().is_err(), "a missing tab sends no commands");
        assert_eq!(rt.active_tab_id(), Some("t0"));
    }

    #[test]
    fn activation_ambiguous_tab_is_non_fatal_and_sends_nothing() {
        // Two tabs share id `dup` -> ambiguous; refuse to guess a session.
        let strip_tabs = vec![
            strip_tab("dup", 0, attention("none", false)),
            strip_tab("dup", 1, attention("none", false)),
        ];
        let selection: Vec<TabSelection> = strip_tabs
            .iter()
            .map(|t| TabSelection {
                tab_id: t.tab_id.clone(),
                session_id: t.session_id.clone(),
            })
            .collect();
        let (mut rt, rx) = RendererTabRuntime::new();

        assert_eq!(
            rt.on_tab_activated("w1", &selection, &strip_tabs, "dup"),
            Err(TabSwitchError::AmbiguousTab {
                window_id: "w1".to_string(),
                tab_id: "dup".to_string(),
            })
        );
        assert!(rx.try_recv().is_err(), "an ambiguous tab sends no commands");
        assert_eq!(rt.active_tab_id(), None);
    }

    #[test]
    fn activation_without_authority_fails_before_observing_closed_channel() {
        let (selection, strip_tabs) = activation_layout();
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");
        drop(rx); // the renderer event loop is gone

        assert_eq!(
            rt.on_tab_activated("w1", &selection, &strip_tabs, "t1"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        // Active state never advanced to t1 because the attach was not delivered.
        assert_eq!(rt.active_tab_id(), Some("t0"));
    }

    // --- apply_inactive_tab_close: the pure core of the foreground close-click listener ---

    #[test]
    fn close_is_active_predicate_detects_active_and_inactive() {
        assert!(is_active_tab_close(Some("t0"), "t0"));
        assert!(!is_active_tab_close(Some("t0"), "t1"));
        // With no known active tab, a close is treated as inactive.
        assert!(!is_active_tab_close(None, "t0"));
    }

    #[test]
    fn close_inactive_tab_refreshes_strip_keeping_previous_active() {
        // Active tab is t0; close the inactive t1. The post-close projection drops t1.
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");
        let new_strip_tabs = vec![strip_tab("t0", 0, attention("none", false))];

        assert_eq!(
            rt.on_tab_close_requested("w1", &new_strip_tabs, "t0", "t1"),
            Ok(TabCloseOutcome::ClosedInactive)
        );

        // Exactly one SetTabStrip without the closed tab and with t0 still active. No AttachSession.
        let model = build_tab_strip_model("w1", &new_strip_tabs, Some("t0")).unwrap();
        assert_eq!(
            recv_set_tab_strip(&rx),
            Some(renderer_tab_strip(&model)),
            "the refreshed strip keeps the previous active tab and drops the closed one"
        );
        assert!(rx.try_recv().is_err(), "exactly one command is sent");
        assert_eq!(rt.active_tab_id(), Some("t0"), "active tab is unchanged");
    }

    #[test]
    fn close_active_tab_is_deferred_and_sends_nothing() {
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");
        // A projection is irrelevant for the active path; pass the pre-close tabs.
        let strip_tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", false)),
        ];

        assert_eq!(
            rt.on_tab_close_requested("w1", &strip_tabs, "t0", "t0"),
            Ok(TabCloseOutcome::ActiveCloseDeferred)
        );
        assert!(
            rx.try_recv().is_err(),
            "an active close sends no renderer command"
        );
        assert_eq!(rt.active_tab_id(), Some("t0"));
    }

    #[test]
    fn close_inactive_structural_change_requires_fresh_exact_projection() {
        // A display-only strip cannot authorize the post-close two-pane membership.
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t1", "sess-t1");
        let new_strip_tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", false)),
        ];

        assert_eq!(
            rt.on_tab_close_requested("w1", &new_strip_tabs, "t1", "t2"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(rt.active_tab_id(), Some("t1"));
    }

    #[test]
    fn close_inactive_with_missing_active_in_projection_is_typed_and_sends_nothing() {
        // Impossible for a correct inactive close, but if the returned projection somehow lacks the
        // previous active tab, surface a typed TabNotFound and send NOTHING (no misleading strip).
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");
        // Projection is missing the active tab t0 entirely.
        let new_strip_tabs = vec![strip_tab("t9", 0, attention("none", false))];

        assert_eq!(
            rt.on_tab_close_requested("w1", &new_strip_tabs, "t0", "t1"),
            Err(TabSwitchError::TabNotFound {
                window_id: "w1".to_string(),
                tab_id: "t0".to_string(),
            })
        );
        assert!(
            rx.try_recv().is_err(),
            "a missing active tab in the projection sends no command"
        );
    }

    #[test]
    fn close_inactive_with_closed_command_channel_is_control_closed_after_mutation() {
        // The record mutation happened in the caller; here the renderer command channel is gone, so
        // the strip refresh surfaces RendererControlClosed without panicking.
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");
        drop(rx); // the renderer event loop is gone
        let new_strip_tabs = vec![strip_tab("t0", 0, attention("none", false))];

        assert_eq!(
            rt.on_tab_close_requested("w1", &new_strip_tabs, "t0", "t1"),
            Err(TabSwitchError::RendererControlClosed)
        );
        assert_eq!(rt.active_tab_id(), Some("t0"));
    }

    #[test]
    fn close_projection_update_drops_closed_tab_and_keeps_remaining_selections() {
        // The post-close strip (t0, t2) projects to the remaining tab_id -> session_id selections,
        // with the closed t1 gone and the others preserved in order.
        let new_strip_tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t2", 1, attention("none", false)),
        ];
        let selection = selection_from_strip_tabs(&new_strip_tabs);
        assert_eq!(
            selection,
            vec![
                TabSelection {
                    tab_id: s("t0"),
                    session_id: s("sess-t0"),
                },
                TabSelection {
                    tab_id: s("t2"),
                    session_id: s("sess-t2"),
                },
            ],
            "the updated selection mirrors the post-close strip exactly (t1 removed)"
        );
        assert!(
            !selection.iter().any(|s| s.tab_id == "t1"),
            "the closed tab is absent from the updated selection"
        );
    }

    #[test]
    fn raw_close_then_activation_cannot_bypass_exact_projection_authority() {
        // Window has t0 (active), t1, t2. Close inactive t1, then activate t2. The hardened listener
        // resolves t2 through the UPDATED selection, so AttachSession carries t2's real session.
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");

        // Post-close strip after removing t1.
        let new_strip_tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t2", 1, attention("none", false)),
        ];
        assert_eq!(
            rt.on_tab_close_requested("w1", &new_strip_tabs, "t0", "t1"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(rx.try_recv().is_err());

        // The listener adopts the updated projections (this is what main.rs does on ClosedInactive).
        let updated_selection = selection_from_strip_tabs(&new_strip_tabs);

        // Activate t2 THROUGH the updated selection: a real switch sends AttachSession for sess-t2.
        assert_eq!(
            rt.on_tab_activated("w1", &updated_selection, &new_strip_tabs, "t2"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(rt.active_tab_id(), Some("t0"));
    }

    #[test]
    fn activation_of_just_closed_tab_after_update_is_missing_and_sends_nothing() {
        // After closing t1 and adopting the updated projections, an activation for the GONE t1
        // resolves against the updated selection, is missing, and sends no command.
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");
        let new_strip_tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t2", 1, attention("none", false)),
        ];
        let updated_selection = selection_from_strip_tabs(&new_strip_tabs);

        let err = rt
            .on_tab_activated("w1", &updated_selection, &new_strip_tabs, "t1")
            .expect_err("the closed tab is no longer selectable");
        assert!(
            matches!(err, TabSwitchError::TabNotFound { ref tab_id, .. } if tab_id == "t1"),
            "activation for the closed tab is a typed TabNotFound: {err:?}"
        );
        assert!(
            rx.try_recv().is_err(),
            "a missing tab activation sends no renderer command"
        );
    }

    #[test]
    fn active_close_deferred_keeps_exact_active_until_authorized_replacement() {
        // Models the main.rs listener decision: only the ClosedInactive arm adopts new projections.
        // For an active close the outcome is ActiveCloseDeferred, so the listener keeps its existing
        // selection and strip_tabs untouched (no recompute from any post-close layout).
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");

        let strip_tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", false)),
        ];
        let selection = selection_from_strip_tabs(&strip_tabs);

        // The active close defers and sends nothing.
        assert_eq!(
            rt.on_tab_close_requested("w1", &strip_tabs, "t0", "t0"),
            Ok(TabCloseOutcome::ActiveCloseDeferred)
        );
        assert!(rx.try_recv().is_err(), "active close sends no command");

        // The listener does NOT adopt new projections on the deferred arm; the existing ones stand.
        // A subsequent activation of t1 still resolves through the unchanged selection.
        assert_eq!(
            rt.on_tab_activated("w1", &selection, &strip_tabs, "t1"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(rt.active_tab_id(), Some("t0"));
    }

    // The listener's close classification now reads the CURRENT active tab from the runtime
    // (`active_tab_id()`), not a fixed launch tab. These model that decision flow end-to-end through
    // `RendererTabRuntime`: each `on_tab_activated` advances the runtime's active tab, and a close is
    // classified against `rt.active_tab_id()` exactly as `maestro-app/src/main.rs` does.
    #[test]
    fn refused_raw_activation_keeps_close_classification_on_exact_active() {
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");
        let strip_tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", false)),
            strip_tab("t2", 2, attention("none", false)),
        ];
        let selection = selection_from_strip_tabs(&strip_tabs);

        // Activate t2: the runtime advances its active tab.
        assert_eq!(
            rt.on_tab_activated("w1", &selection, &strip_tabs, "t2"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(rt.active_tab_id(), Some("t0"));

        assert!(is_active_tab_close(rt.active_tab_id(), "t0"));
        assert!(!is_active_tab_close(rt.active_tab_id(), "t2"));
    }

    #[test]
    fn failed_activation_leaves_active_state_and_close_classification_on_previous_tab() {
        // Launch on t0; a FAILED activation (missing tab) must not advance the active tab. A later
        // close of t0 is then still classified as active against the unchanged runtime state.
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");
        let strip_tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", false)),
        ];
        let selection = selection_from_strip_tabs(&strip_tabs);

        // Activate a tab that is not in the selection -> typed error, no command, no active advance.
        let err = rt
            .on_tab_activated("w1", &selection, &strip_tabs, "t9")
            .expect_err("a missing tab cannot be activated");
        assert!(matches!(err, TabSwitchError::TabNotFound { ref tab_id, .. } if tab_id == "t9"));
        assert!(rx.try_recv().is_err(), "a failed activation sends nothing");
        assert_eq!(
            rt.active_tab_id(),
            Some("t0"),
            "a failed activation leaves the active tab unchanged"
        );

        // Close classification still uses the previous (unchanged) active tab t0.
        assert!(
            is_active_tab_close(rt.active_tab_id(), "t0"),
            "after a failed activation, closing t0 is still an active close"
        );
        assert!(
            !is_active_tab_close(rt.active_tab_id(), "t1"),
            "closing t1 is inactive against the unchanged active tab"
        );
    }

    #[test]
    fn already_active_activation_does_not_disturb_runtime_active_state() {
        // Re-activating the already-active tab is a no-op and leaves the active tab in place, so close
        // classification is unaffected.
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");
        let strip_tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", false)),
        ];
        let selection = selection_from_strip_tabs(&strip_tabs);

        assert_eq!(
            rt.on_tab_activated("w1", &selection, &strip_tabs, "t0"),
            Ok(TabActivation::AlreadyActive)
        );
        assert!(
            rx.try_recv().is_err(),
            "already-active activation sends nothing"
        );
        assert_eq!(rt.active_tab_id(), Some("t0"), "active tab is unchanged");
        assert!(is_active_tab_close(rt.active_tab_id(), "t0"));
    }

    #[test]
    fn inactive_close_after_refused_activation_keeps_original_exact_active() {
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");
        let strip_tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", false)),
            strip_tab("t2", 2, attention("none", false)),
        ];
        let selection = selection_from_strip_tabs(&strip_tabs);

        assert_eq!(
            rt.on_tab_activated("w1", &selection, &strip_tabs, "t2"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(rx.try_recv().is_err());

        // The refused switch leaves t0 as the exact active lifetime.
        let current_active = rt.active_tab_id().map(str::to_owned).unwrap();
        assert_eq!(current_active, "t0");
        assert!(!is_active_tab_close(rt.active_tab_id(), "t1"));
        // Post-close strip (t0, t2) keeps t2 active.
        let new_strip_tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t2", 1, attention("none", false)),
        ];
        assert_eq!(
            rt.on_tab_close_requested("w1", &new_strip_tabs, &current_active, "t1"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(
            rt.active_tab_id(),
            Some("t0"),
            "the proven active lifetime stays active"
        );
    }

    // --- Active-tab close (with remaining tabs) — pure next-active planner ---

    #[test]
    fn close_active_first_tab_plans_right_neighbor() {
        // [t0(active), t1, t2] closing t0 -> right neighbor t1.
        let tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", false)),
            strip_tab("t2", 2, attention("none", false)),
        ];
        assert_eq!(
            plan_next_active_tab("w1", &tabs, "t0"),
            Ok(NextActivePlan::SelectNext { tab_id: s("t1") })
        );
    }

    #[test]
    fn close_active_middle_tab_plans_right_neighbor() {
        // [t0, t1(active), t2] closing t1 -> right neighbor t2.
        let tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", false)),
            strip_tab("t2", 2, attention("none", false)),
        ];
        assert_eq!(
            plan_next_active_tab("w1", &tabs, "t1"),
            Ok(NextActivePlan::SelectNext { tab_id: s("t2") })
        );
    }

    #[test]
    fn close_active_last_tab_plans_left_neighbor() {
        // [t0, t1(active)] closing t1 (the last) -> new last / left neighbor t0.
        let tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", false)),
        ];
        assert_eq!(
            plan_next_active_tab("w1", &tabs, "t1"),
            Ok(NextActivePlan::SelectNext { tab_id: s("t0") })
        );
    }

    #[test]
    fn close_active_planner_uses_persisted_index_order_not_input_order() {
        // Same tabs supplied out of index order: the planner sorts by `index`, so closing t1 still
        // picks the right neighbor t2 by index, not whatever follows in the input vec.
        let tabs = vec![
            strip_tab("t2", 2, attention("none", false)),
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", false)),
        ];
        assert_eq!(
            plan_next_active_tab("w1", &tabs, "t1"),
            Ok(NextActivePlan::SelectNext { tab_id: s("t2") })
        );
    }

    #[test]
    fn close_only_active_tab_plans_deferred() {
        // [t0(active)] closing t0 -> only-tab: deferred, no selection.
        let tabs = vec![strip_tab("t0", 0, attention("none", false))];
        assert_eq!(
            plan_next_active_tab("w1", &tabs, "t0"),
            Ok(NextActivePlan::OnlyTabDeferred)
        );
    }

    #[test]
    fn close_active_planner_missing_target_is_typed_error() {
        // A close target absent from the pre-close tabs is a typed, non-destructive error.
        let tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", false)),
        ];
        let err = plan_next_active_tab("w1", &tabs, "t9").expect_err("missing target");
        assert!(matches!(err, TabSwitchError::TabNotFound { ref tab_id, .. } if tab_id == "t9"));
    }

    // --- Active-tab close (with remaining tabs) — runtime/app behavior through RendererTabRuntime ---

    #[test]
    fn active_first_tab_close_requires_exact_replacement_authority() {
        // Active t0 in [t0,t1,t2]: plan right neighbor t1, then the runtime switches (AttachSession
        // sess-t1) and refreshes the strip with t1 active.
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");
        let pre_close = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", false)),
            strip_tab("t2", 2, attention("none", false)),
        ];
        let plan = plan_next_active_tab("w1", &pre_close, "t0").unwrap();
        assert_eq!(plan, NextActivePlan::SelectNext { tab_id: s("t1") });

        // Post-close projection (t0 gone, reindexed): selection + strip the listener would rebuild.
        let new_strip_tabs = vec![
            strip_tab("t1", 0, attention("none", false)),
            strip_tab("t2", 1, attention("none", false)),
        ];
        let new_selection = selection_from_strip_tabs(&new_strip_tabs);

        assert_eq!(
            rt.on_active_tab_close("w1", &plan, &new_selection, &new_strip_tabs),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(rt.active_tab_id(), Some("t0"));
    }

    #[test]
    fn active_middle_tab_close_requires_exact_replacement_authority() {
        // Active t1 in [t0,t1,t2]: plan right neighbor t2; runtime attaches sess-t2.
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t1", "sess-t1");
        let pre_close = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", false)),
            strip_tab("t2", 2, attention("none", false)),
        ];
        let plan = plan_next_active_tab("w1", &pre_close, "t1").unwrap();
        let new_strip_tabs = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t2", 1, attention("none", false)),
        ];
        let new_selection = selection_from_strip_tabs(&new_strip_tabs);
        assert_eq!(
            rt.on_active_tab_close("w1", &plan, &new_selection, &new_strip_tabs),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(rt.active_tab_id(), Some("t1"));
    }

    #[test]
    fn active_last_tab_close_requires_exact_replacement_authority() {
        // Active t1 in [t0,t1] (last): plan left neighbor t0; runtime attaches sess-t0.
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t1", "sess-t1");
        let pre_close = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", false)),
        ];
        let plan = plan_next_active_tab("w1", &pre_close, "t1").unwrap();
        let new_strip_tabs = vec![strip_tab("t0", 0, attention("none", false))];
        let new_selection = selection_from_strip_tabs(&new_strip_tabs);
        assert_eq!(
            rt.on_active_tab_close("w1", &plan, &new_selection, &new_strip_tabs),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(rt.active_tab_id(), Some("t1"));
    }

    #[test]
    fn only_active_tab_close_sends_nothing_and_leaves_active_state() {
        // Only-tab plan: the runtime sends nothing and leaves the active tab in place. The caller
        // must not have mutated the record in this case (verified at the listener layer).
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");
        let pre_close = vec![strip_tab("t0", 0, attention("none", false))];
        let plan = plan_next_active_tab("w1", &pre_close, "t0").unwrap();
        assert_eq!(plan, NextActivePlan::OnlyTabDeferred);
        // The post-close projection is irrelevant here (no mutation happens); pass the unchanged tabs.
        assert_eq!(
            rt.on_active_tab_close("w1", &plan, &[], &[]),
            Ok(ActiveTabCloseOutcome::OnlyTabDeferred)
        );
        assert!(rx.try_recv().is_err(), "only-tab close sends nothing");
        assert_eq!(
            rt.active_tab_id(),
            Some("t0"),
            "active state is left in place"
        );
    }

    // --- Only-live-tab active close — strip/controller ownership through RendererTabRuntime ---

    #[test]
    fn only_tab_close_sends_one_clear_viewport_then_drops_active_state() {
        // [t0(active)] closing t0 (only tab): one ClearViewport owns terminal+strip neutralization;
        // no SetTabStrip/AttachSession is sent before controller ownership is dropped.
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");
        let pre_close = vec![strip_tab("t0", 0, attention("none", false))];
        let plan = plan_next_active_tab("w1", &pre_close, "t0").unwrap();
        assert_eq!(plan, NextActivePlan::OnlyTabDeferred);

        assert_eq!(
            rt.on_only_tab_close(&plan),
            Ok(OnlyTabCloseOutcome::ClearedEmptyWindow)
        );
        assert!(matches!(
            rx.try_recv(),
            Ok(maestro_renderer::RendererCommand::ClearViewport)
        ));
        assert!(
            rx.try_recv().is_err(),
            "exactly one ClearViewport and no SetTabStrip/AttachSession"
        );
        assert_eq!(
            rt.active_tab_id(),
            None,
            "app active-tab ownership is dropped"
        );
    }

    #[test]
    fn only_tab_close_subsequent_classification_does_not_treat_closed_tab_as_active() {
        // After only-tab close success, the runtime no longer reports the closed tab as active, so a
        // later close/activation classification cannot misclassify the orphaned tab.
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");
        let pre_close = vec![strip_tab("t0", 0, attention("none", false))];
        let plan = plan_next_active_tab("w1", &pre_close, "t0").unwrap();
        assert_eq!(
            rt.on_only_tab_close(&plan),
            Ok(OnlyTabCloseOutcome::ClearedEmptyWindow)
        );
        assert!(matches!(
            rx.try_recv(),
            Ok(maestro_renderer::RendererCommand::ClearViewport)
        ));
        assert_eq!(rt.active_tab_id(), None);
        assert!(
            !is_active_tab_close(rt.active_tab_id(), "t0"),
            "the closed tab is no longer the active tab"
        );
    }

    #[test]
    fn only_tab_close_with_closed_channel_is_typed_and_stays_neutral() {
        // The record is (notionally) already mutated when the renderer command channel is gone: the
        // strip-clear surfaces RendererControlClosed and the runtime does NOT drop active-tab
        // ownership (the clear was never delivered), so the caller will not falsely drop its
        // strip/controller ownership.
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");
        drop(rx); // renderer event loop gone -> sends fail.
        let pre_close = vec![strip_tab("t0", 0, attention("none", false))];
        let plan = plan_next_active_tab("w1", &pre_close, "t0").unwrap();
        let err = rt
            .on_only_tab_close(&plan)
            .expect_err("a closed channel surfaces a typed error");
        assert!(matches!(err, TabSwitchError::RendererControlClosed));
        assert_eq!(
            rt.active_tab_id(),
            None,
            "neutral-first Clear revokes App adoption before observing delivery failure"
        );
    }

    #[test]
    fn only_tab_close_rejects_a_select_next_plan_without_sending_a_command() {
        // Defensive: a remaining-tabs plan must never be routed through the only-tab path. It is a
        // typed TabNotFound (caller bug) and sends nothing, so a misrouted close cannot clear a
        // window that still has tabs.
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");
        let plan = NextActivePlan::SelectNext { tab_id: s("t1") };
        let err = rt
            .on_only_tab_close(&plan)
            .expect_err("a SelectNext plan is rejected by the only-tab path");
        assert!(matches!(err, TabSwitchError::TabNotFound { ref tab_id, .. } if tab_id == "t1"));
        assert!(
            rx.try_recv().is_err(),
            "no command is sent for a misrouted plan"
        );
        assert_eq!(
            rt.active_tab_id(),
            Some("t0"),
            "active state is untouched on a rejected plan"
        );
    }

    #[test]
    fn raw_active_close_requires_exact_authority_before_observing_closed_channel() {
        // The record is (notionally) already mutated when the renderer command channel is gone: the
        // switch surfaces RendererControlClosed without panicking. The caller does not roll back.
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");
        drop(rx); // renderer event loop gone -> sends fail.
        let pre_close = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", false)),
        ];
        let plan = plan_next_active_tab("w1", &pre_close, "t0").unwrap();
        let new_strip_tabs = vec![strip_tab("t1", 0, attention("none", false))];
        let new_selection = selection_from_strip_tabs(&new_strip_tabs);
        let err = rt
            .on_active_tab_close("w1", &plan, &new_selection, &new_strip_tabs)
            .expect_err("a closed channel surfaces a typed error");
        assert!(matches!(err, TabSwitchError::ViewportAuthorityRequired));
    }

    #[test]
    fn active_tab_close_with_chosen_tab_missing_in_projection_is_typed_no_misleading_command() {
        // Plan/record drift: the chosen next tab is absent from the post-close selection (e.g. the
        // record changed underneath). The switch surfaces a typed TabNotFound and sends no
        // AttachSession for a tab that is not there.
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t0", "sess-t0");
        let pre_close = vec![
            strip_tab("t0", 0, attention("none", false)),
            strip_tab("t1", 1, attention("none", false)),
        ];
        let plan = plan_next_active_tab("w1", &pre_close, "t0").unwrap();
        assert_eq!(plan, NextActivePlan::SelectNext { tab_id: s("t1") });
        // Post-close projection unexpectedly lacks t1 (drift): only t2 remains.
        let new_strip_tabs = vec![strip_tab("t2", 0, attention("none", false))];
        let new_selection = selection_from_strip_tabs(&new_strip_tabs);
        let err = rt
            .on_active_tab_close("w1", &plan, &new_selection, &new_strip_tabs)
            .expect_err("chosen tab missing from projection is typed");
        assert!(matches!(err, TabSwitchError::TabNotFound { ref tab_id, .. } if tab_id == "t1"));
        assert!(
            rx.try_recv().is_err(),
            "no misleading AttachSession is sent for the missing tab"
        );
    }
    #[test]
    fn select_window_tab_session_resolves_valid_tab() {
        let layout = vec![tab("t-a", "sess-a"), tab("t-b", "sess-b")];
        assert_eq!(
            select_window_tab_session(&layout, "t-b").unwrap(),
            "sess-b".to_string()
        );
    }

    #[test]
    fn select_window_tab_session_missing_tab_is_typed_error() {
        let layout = vec![tab("t-a", "sess-a")];
        assert_eq!(
            select_window_tab_session(&layout, "t-x"),
            Err(TabSelectionError::TabNotFound {
                tab_id: "t-x".to_string()
            })
        );
    }

    #[test]
    fn select_window_tab_session_empty_layout_is_not_found() {
        let layout: Vec<TabSelection> = Vec::new();
        assert_eq!(
            select_window_tab_session(&layout, "t-a"),
            Err(TabSelectionError::TabNotFound {
                tab_id: "t-a".to_string()
            })
        );
    }

    #[test]
    fn select_window_tab_session_duplicate_tab_is_ambiguous() {
        let layout = vec![tab("t-a", "sess-a1"), tab("t-a", "sess-a2")];
        assert_eq!(
            select_window_tab_session(&layout, "t-a"),
            Err(TabSelectionError::AmbiguousTab {
                tab_id: "t-a".to_string(),
                count: 2,
            })
        );
    }

    #[test]
    fn select_window_tab_session_is_deterministic() {
        let layout = vec![tab("t-a", "sess-a"), tab("t-b", "sess-b")];
        let first = select_window_tab_session(&layout, "t-a");
        let second = select_window_tab_session(&layout, "t-a");
        assert_eq!(first, second);
        assert_eq!(first.unwrap(), "sess-a".to_string());
    }

    #[test]
    fn switch_to_valid_tab_requires_exact_viewport_authority_and_sends_nothing() {
        let layout = vec![tab("t-a", "sess-a"), tab("t-b", "sess-b")];
        let mut ctrl = TabSwitchController::new(RecordingSink::default());
        assert_eq!(
            ctrl.switch_to("w1", &layout, "t-b"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(attach_ids(&ctrl.sender).is_empty());
        assert_eq!(ctrl.active_tab_id(), None);
    }

    #[test]
    fn repeated_textual_switch_never_invents_an_active_lifetime() {
        let layout = vec![tab("t-a", "sess-a"), tab("t-b", "sess-b")];
        let mut ctrl = TabSwitchController::new(RecordingSink::default());
        assert_eq!(
            ctrl.switch_to("w1", &layout, "t-a"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert_eq!(
            ctrl.switch_to("w1", &layout, "t-a"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(attach_ids(&ctrl.sender).is_empty());
        assert_eq!(ctrl.active_tab_key(), None);
    }

    #[test]
    fn textual_retarget_requires_exact_viewport_authority_for_both_lifetimes() {
        let original = vec![tab("t-a", "sess-old")];
        let retargeted = vec![tab("t-a", "sess-new")];
        let mut ctrl = TabSwitchController::new(RecordingSink::default());

        assert_eq!(
            ctrl.switch_to("w1", &original, "t-a"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert_eq!(
            ctrl.switch_to("w1", &retargeted, "t-a"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(attach_ids(&ctrl.sender).is_empty());
    }

    #[test]
    fn textual_switch_a_then_b_sends_nothing_and_stays_neutral() {
        let layout = vec![tab("t-a", "sess-a"), tab("t-b", "sess-b")];
        let mut ctrl = TabSwitchController::new(RecordingSink::default());
        assert_eq!(
            ctrl.switch_to("w1", &layout, "t-a"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert_eq!(
            ctrl.switch_to("w1", &layout, "t-b"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(attach_ids(&ctrl.sender).is_empty());
        assert_eq!(ctrl.active_tab_id(), None);
    }

    #[test]
    fn switch_to_missing_tab_is_window_scoped_not_found_and_sends_nothing() {
        let layout = vec![tab("t-a", "sess-a")];
        let mut ctrl = TabSwitchController::new(RecordingSink::default());
        assert_eq!(
            ctrl.switch_to("w1", &layout, "t-x"),
            Err(TabSwitchError::TabNotFound {
                window_id: "w1".to_string(),
                tab_id: "t-x".to_string(),
            })
        );
        assert!(attach_ids(&ctrl.sender).is_empty());
        assert_eq!(ctrl.active_tab_id(), None);
    }

    #[test]
    fn switch_to_duplicate_tab_is_window_scoped_ambiguous_and_sends_nothing() {
        let layout = vec![tab("t-a", "sess-a1"), tab("t-a", "sess-a2")];
        let mut ctrl = TabSwitchController::new(RecordingSink::default());
        assert_eq!(
            ctrl.switch_to("w1", &layout, "t-a"),
            Err(TabSwitchError::AmbiguousTab {
                window_id: "w1".to_string(),
                tab_id: "t-a".to_string(),
            })
        );
        assert!(attach_ids(&ctrl.sender).is_empty());
        assert_eq!(ctrl.active_tab_id(), None);
    }

    #[test]
    fn switch_to_without_authority_fails_before_observing_a_closed_channel() {
        let layout = vec![tab("t-a", "sess-a")];
        let sink = RecordingSink {
            closed: true,
            ..Default::default()
        };
        let mut ctrl = TabSwitchController::new(sink);
        assert_eq!(
            ctrl.switch_to("w1", &layout, "t-a"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(attach_ids(&ctrl.sender).is_empty());
        assert_eq!(ctrl.active_tab_id(), None);
    }

    #[test]
    fn textual_window_scoped_layouts_cannot_authorize_any_attach() {
        // Window scoping is the caller's responsibility: each window's projection is
        // independent. The same tab title `t-1` lives in both windows but maps to that
        // window's own session, so resolution follows the layout passed in, never a
        // global table.
        let w1 = vec![tab("t-1", "sess-w1-1"), tab("t-2", "sess-w1-2")];
        let w2 = vec![tab("t-1", "sess-w2-1")];
        let mut ctrl = TabSwitchController::new(RecordingSink::default());
        for (window_id, layout, tab_id) in
            [("w1", &w1, "t-1"), ("w1", &w1, "t-2"), ("w2", &w2, "t-1")]
        {
            assert_eq!(
                ctrl.switch_to(window_id, layout, tab_id),
                Err(TabSwitchError::ViewportAuthorityRequired)
            );
        }
        assert!(attach_ids(&ctrl.sender).is_empty());
        assert_eq!(ctrl.active_tab_id(), None);
    }

    #[test]
    fn mpsc_sender_receives_no_raw_attach_without_exact_authority() {
        let layout = vec![tab("t-a", "sess-a")];
        let (tx, rx) = std::sync::mpsc::channel();
        let mut ctrl = TabSwitchController::new(tx);
        assert_eq!(
            ctrl.switch_to("w1", &layout, "t-a"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn same_textual_tab_id_in_different_windows_is_not_lifetime_authority() {
        let w1 = vec![tab("t1", "sess-w1")];
        let w2 = vec![tab("t1", "sess-w2")];
        let mut ctrl = TabSwitchController::new(RecordingSink::default());
        assert_eq!(
            ctrl.switch_to("w1", &w1, "t1"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert_eq!(
            ctrl.switch_to("w2", &w2, "t1"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(attach_ids(&ctrl.sender).is_empty());
        assert_eq!(ctrl.active_tab_key(), None);
    }

    #[test]
    fn renderer_tab_runtime_raw_switch_requires_exact_authority() {
        let layout = vec![tab("t-a", "sess-a")];
        let (mut rt, rx) = RendererTabRuntime::new();
        assert_eq!(
            rt.switch_to("w1", &layout, "t-a"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(rt.active_tab_key(), None);
    }

    #[test]
    fn renderer_tab_runtime_repeated_raw_switch_remains_neutral() {
        let layout = vec![tab("t-a", "sess-a")];
        let (mut rt, rx) = RendererTabRuntime::new();
        assert_eq!(
            rt.switch_to("w1", &layout, "t-a"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert_eq!(
            rt.switch_to("w1", &layout, "t-a"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn renderer_tab_runtime_rejects_raw_window_scoped_switches() {
        let w1 = vec![tab("t1", "sess-w1")];
        let w2 = vec![tab("t1", "sess-w2")];
        let (mut rt, rx) = RendererTabRuntime::new();
        assert_eq!(
            rt.switch_to("w1", &w1, "t1"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert_eq!(
            rt.switch_to("w2", &w2, "t1"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(rt.active_tab_key(), None);
    }

    #[test]
    fn renderer_tab_runtime_raw_switch_fails_before_observing_dropped_receiver() {
        let layout = vec![tab("t-a", "sess-a")];
        let (mut rt, rx) = RendererTabRuntime::new();
        drop(rx);
        assert_eq!(
            rt.switch_to("w1", &layout, "t-a"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert_eq!(rt.active_tab_id(), None);
        assert_eq!(rt.active_tab_key(), None);
    }

    #[test]
    fn renderer_tab_runtime_noop_survives_dropped_receiver() {
        let layout = vec![tab("t-a", "sess-a")];
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t-a", "sess-a");
        drop(rx);
        assert_eq!(rt.switch_to("w1", &layout, "t-a"), Ok(false));
        assert_eq!(rt.active_tab_id(), Some("t-a"));
    }

    #[test]
    fn seed_active_tab_sets_active_coordinate_without_sending() {
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t1", "sess-t1");
        assert_eq!(rt.active_window_id(), Some("w1"));
        assert_eq!(rt.active_tab_id(), Some("t1"));
        assert_eq!(
            rt.active_tab_key(),
            Some(&ActiveTab {
                window_id: "w1".to_string(),
                tab_id: "t1".to_string(),
                session_id: "sess-t1".to_string(),
            })
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn seeded_same_tab_is_noop_even_with_dropped_receiver() {
        let layout = vec![tab("t1", "sess-1")];
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t1", "sess-1");
        drop(rx);
        assert_eq!(rt.switch_to("w1", &layout, "t1"), Ok(false));
        assert_eq!(rt.active_tab_id(), Some("t1"));
    }

    #[test]
    fn seeded_then_different_textual_tab_requires_new_exact_authority() {
        let layout = vec![tab("t1", "sess-1"), tab("t2", "sess-2")];
        let (mut rt, rx) = RendererTabRuntime::new();
        seed_exact_active_tab(&mut rt, "w1", "t1", "sess-1");
        assert_eq!(
            rt.switch_to("w1", &layout, "t2"),
            Err(TabSwitchError::ViewportAuthorityRequired)
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(rt.active_tab_id(), Some("t1"));
    }

    // ---- close-to-kill session lifecycle ----------------------------------------------------

    fn lifecycle_sel(tab_id: &str, session_id: &str) -> TabSelection {
        TabSelection {
            tab_id: s(tab_id),
            session_id: s(session_id),
        }
    }

    fn lifecycle_tab(tab_id: &str, session_id: &str, index: u32) -> WindowTabJson {
        WindowTabJson {
            tab_id: s(tab_id),
            session_id: s(session_id),
            index,
            title: format!("Title {tab_id}"),
            pinned: false,
            attention: attention("none", false),
            split_from: None,
            pane_rect: None,
        }
    }

    fn split_child_tab(
        tab_id: &str,
        session_id: &str,
        index: u32,
        source_tab_id: &str,
    ) -> WindowTabJson {
        WindowTabJson {
            split_from: Some(SplitFromJson {
                tab_id: s(source_tab_id),
                axis: s("right"),
                ratio_per_mille: None,
            }),
            ..lifecycle_tab(tab_id, session_id, index)
        }
    }

    #[test]
    fn classify_focused_pane_close_recognizes_a_split_child_leaf() {
        // Root + one split child off it. The child has no descendants -> Leaf.
        let strip = vec![
            lifecycle_tab("t-root", "sess-root", 0),
            split_child_tab("t-child", "sess-child", 1, "t-root"),
        ];
        assert_eq!(
            classify_focused_pane_close(&strip, "t-child"),
            FocusedPaneCloseClass::Leaf {
                tab_id: s("t-child")
            }
        );
    }

    #[test]
    fn classify_focused_pane_close_refuses_the_root_pane() {
        let strip = vec![
            lifecycle_tab("t-root", "sess-root", 0),
            split_child_tab("t-child", "sess-child", 1, "t-root"),
        ];
        // The root carries no `split_from` -> Root (refused by the classifier).
        assert_eq!(
            classify_focused_pane_close(&strip, "t-root"),
            FocusedPaneCloseClass::Root {
                tab_id: s("t-root")
            }
        );
    }

    #[test]
    fn classify_focused_pane_close_refuses_a_non_leaf_split_pane() {
        // root -> mid -> leaf: `t-mid` is a split child that ALSO has a child -> NonLeaf.
        let strip = vec![
            lifecycle_tab("t-root", "sess-root", 0),
            split_child_tab("t-mid", "sess-mid", 1, "t-root"),
            split_child_tab("t-leaf", "sess-leaf", 2, "t-mid"),
        ];
        assert_eq!(
            classify_focused_pane_close(&strip, "t-mid"),
            FocusedPaneCloseClass::NonLeaf { tab_id: s("t-mid") }
        );
        // ...while the deepest pane is still a closable leaf.
        assert_eq!(
            classify_focused_pane_close(&strip, "t-leaf"),
            FocusedPaneCloseClass::Leaf {
                tab_id: s("t-leaf")
            }
        );
    }

    #[test]
    fn classify_focused_pane_close_reports_missing_for_unknown_tab() {
        let strip = vec![lifecycle_tab("t-root", "sess-root", 0)];
        assert_eq!(
            classify_focused_pane_close(&strip, "t-ghost"),
            FocusedPaneCloseClass::Missing {
                tab_id: s("t-ghost")
            }
        );
        // An empty strip is also Missing for any id.
        assert_eq!(
            classify_focused_pane_close(&[], "t-root"),
            FocusedPaneCloseClass::Missing {
                tab_id: s("t-root")
            }
        );
    }

    #[test]
    fn close_lifecycle_plans_kill_when_no_remaining_tab_shares_session() {
        let pre = vec![lifecycle_sel("t0", "sess-0"), lifecycle_sel("t1", "sess-1")];
        // t0 closed; the remaining tab t1 points at a DIFFERENT session.
        let post = vec![lifecycle_tab("t1", "sess-1", 0)];
        assert_eq!(
            plan_closed_tab_session_lifecycle(&pre, &post, "t0"),
            ClosedTabSessionLifecycle::Kill {
                session_id: s("sess-0")
            }
        );
    }

    #[test]
    fn close_lifecycle_keeps_shared_when_remaining_tab_has_same_session() {
        let pre = vec![
            lifecycle_sel("t0", "sess-shared"),
            lifecycle_sel("t1", "sess-shared"),
        ];
        // t0 closed but t1 still references the SAME session: must not kill.
        let post = vec![lifecycle_tab("t1", "sess-shared", 0)];
        assert_eq!(
            plan_closed_tab_session_lifecycle(&pre, &post, "t0"),
            ClosedTabSessionLifecycle::KeepShared {
                session_id: s("sess-shared")
            }
        );
    }

    #[test]
    fn only_live_close_keeps_session_referenced_by_a_stashed_durable_row() {
        let pre = vec![lifecycle_sel("live", "sess-shared")];
        let mut parked =
            tab_record_with_attention("parked", maestro_shell::AttentionState::default());
        parked.session_id = s("sess-shared");
        parked.stashed = true;

        assert!(
            live_tab_records_json(std::slice::from_ref(&parked)).is_empty(),
            "the renderer strip is empty after closing the only live row"
        );
        let durable_post = vec![tab_record_json(&parked)];
        assert_eq!(
            plan_closed_tab_session_lifecycle(&pre, &durable_post, "live"),
            ClosedTabSessionLifecycle::KeepShared {
                session_id: s("sess-shared")
            },
            "session ownership is guarded by all durable rows, including parked ones"
        );
    }

    #[test]
    fn close_lifecycle_reports_missing_tab_when_absent_from_pre_close() {
        let pre = vec![lifecycle_sel("t1", "sess-1")];
        let post = vec![lifecycle_tab("t1", "sess-1", 0)];
        assert_eq!(
            plan_closed_tab_session_lifecycle(&pre, &post, "t0"),
            ClosedTabSessionLifecycle::MissingClosedTab { tab_id: s("t0") }
        );
    }

    #[test]
    fn close_lifecycle_only_tab_empty_projection_plans_kill() {
        let pre = vec![lifecycle_sel("t0", "sess-0")];
        // This only-live-tab close has no remaining durable rows.
        let post: Vec<WindowTabJson> = Vec::new();
        assert_eq!(
            plan_closed_tab_session_lifecycle(&pre, &post, "t0"),
            ClosedTabSessionLifecycle::Kill {
                session_id: s("sess-0")
            }
        );
    }

    #[test]
    fn execute_lifecycle_kill_invokes_kill_with_resolved_session() {
        let killed = std::cell::RefCell::new(Vec::<String>::new());
        let outcome = execute_closed_tab_session_lifecycle(
            ClosedTabSessionLifecycle::Kill {
                session_id: s("sess-0"),
            },
            |id| {
                killed.borrow_mut().push(id.to_string());
                Ok(())
            },
        );
        assert_eq!(
            outcome,
            ClosedTabKillOutcome::Killed {
                session_id: s("sess-0")
            }
        );
        assert_eq!(killed.into_inner(), vec![s("sess-0")]);
    }

    #[test]
    fn execute_lifecycle_kill_failure_is_non_fatal_and_carries_error() {
        let outcome = execute_closed_tab_session_lifecycle(
            ClosedTabSessionLifecycle::Kill {
                session_id: s("sess-0"),
            },
            |_| Err(s("daemon down")),
        );
        assert_eq!(
            outcome,
            ClosedTabKillOutcome::KillFailed {
                session_id: s("sess-0"),
                error: s("daemon down"),
            }
        );
    }

    #[test]
    fn execute_lifecycle_keep_shared_never_calls_kill() {
        let mut called = false;
        let outcome = execute_closed_tab_session_lifecycle(
            ClosedTabSessionLifecycle::KeepShared {
                session_id: s("sess-shared"),
            },
            |_| {
                called = true;
                Ok(())
            },
        );
        assert_eq!(
            outcome,
            ClosedTabKillOutcome::KeptShared {
                session_id: s("sess-shared")
            }
        );
        assert!(!called, "shared session must not be killed");
    }

    #[test]
    fn execute_lifecycle_missing_tab_never_calls_kill() {
        let mut called = false;
        let outcome = execute_closed_tab_session_lifecycle(
            ClosedTabSessionLifecycle::MissingClosedTab { tab_id: s("t0") },
            |_| {
                called = true;
                Ok(())
            },
        );
        assert_eq!(
            outcome,
            ClosedTabKillOutcome::SkippedMissingTab { tab_id: s("t0") }
        );
        assert!(!called, "missing-tab skip must not call kill");
    }

    #[test]
    fn active_close_kills_closed_session_not_the_next_active_one() {
        // t0 (active) closed with t1 remaining; t1 is the next active tab. The plan computed from
        // the PRE-close selection and the POST-close (t1-only) tabs must target the CLOSED session.
        let pre = vec![lifecycle_sel("t0", "sess-0"), lifecycle_sel("t1", "sess-1")];
        let post = vec![lifecycle_tab("t1", "sess-1", 0)];
        let plan = plan_closed_tab_session_lifecycle(&pre, &post, "t0");
        // The next-active session (sess-1) must NOT be the kill target.
        match plan {
            ClosedTabSessionLifecycle::Kill { session_id } => {
                assert_eq!(session_id, "sess-0");
                assert_ne!(session_id, "sess-1");
            }
            other => panic!("expected Kill of the closed session, got {other:?}"),
        }
    }

    #[test]
    fn surviving_active_tab_id_keeps_the_prior_active_when_it_survives() {
        // Closing an INACTIVE pane: the active tab is untouched, so the projection keeps it.
        let survivors = vec!["a".to_string(), "c".to_string()];
        assert_eq!(
            surviving_active_tab_id(Some("a"), Some("a"), &survivors),
            Some("a".to_string()),
            "a still survives, so it stays active"
        );
    }

    #[test]
    fn surviving_active_tab_id_repoints_to_the_reparented_parent_when_active_is_closed() {
        // The active pane (b) was the one closed. close_pane re-parents b's child c onto b's parent a;
        // both a and c survive. The active slot moves to the reparented parent a, NOT a
        // crash from passing the deleted b.
        let survivors = vec!["a".to_string(), "c".to_string()];
        assert_eq!(
            surviving_active_tab_id(Some("b"), Some("a"), &survivors),
            Some("a".to_string()),
            "closing the active pane hands the active slot to its surviving parent"
        );
    }

    #[test]
    fn surviving_active_tab_id_falls_back_to_first_survivor_when_parent_is_gone() {
        // Active pane closed and its parent did not survive (e.g. closing a root whose children
        // detached to roots). Fall back to the first remaining tab so the strip can still reproject.
        let survivors = vec!["c".to_string(), "d".to_string()];
        assert_eq!(
            surviving_active_tab_id(Some("a"), Some("gone"), &survivors),
            Some("c".to_string())
        );
        // No parent recorded at all (closed a root): same first-survivor fallback.
        assert_eq!(
            surviving_active_tab_id(Some("a"), None, &survivors),
            Some("c".to_string())
        );
    }

    #[test]
    fn surviving_active_tab_id_is_none_only_when_nothing_survives() {
        // The window emptied: there is no tab to make active.
        assert_eq!(surviving_active_tab_id(Some("a"), Some("a"), &[]), None);
        assert_eq!(surviving_active_tab_id(None, None, &[]), None);
    }
}
