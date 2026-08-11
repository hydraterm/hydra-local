//! The extracted attention projection / wire-string / clear-refresh / live-refresh cluster.

use serde::Serialize;

use crate::{
    agent_task_state_wire_str, build_tab_strip_model_from_window_view, RendererTabRuntime,
    TabStripModel, TabStripModelError, TabSwitchError, WindowViewTabJson,
};

/// The wire-stable snake_case string for a [`maestro_shell::Attention`], matching the strings
/// `maestro-app/src/main.rs` already emits (`none`/`activity`/`needs_input`/`error`/`done`). Pure.
pub(crate) fn attention_wire_str(attention: maestro_shell::Attention) -> &'static str {
    match attention {
        maestro_shell::Attention::None => "none",
        maestro_shell::Attention::Activity => "activity",
        maestro_shell::Attention::NeedsInput => "needs_input",
        maestro_shell::Attention::Error => "error",
        maestro_shell::Attention::Done => "done",
    }
}

/// The wire-stable snake_case string for a [`maestro_shell::AttentionSource`], matching the strings
/// `maestro-app/src/main.rs` already emits (`process`/`agent`/`user`). Pure.
pub(crate) fn attention_source_wire_str(source: maestro_shell::AttentionSource) -> &'static str {
    match source {
        maestro_shell::AttentionSource::Process => "process",
        maestro_shell::AttentionSource::Agent => "agent",
        maestro_shell::AttentionSource::User => "user",
    }
}

/// The wire-stable snake_case string for a [`maestro_shell::SessionStatus`], matching its serde
/// repr and the `live`/`exited`/`unknown` strings `maestro-app/src/main.rs` already emits. Pure.
pub(crate) fn session_status_wire_str(status: maestro_shell::SessionStatus) -> &'static str {
    match status {
        maestro_shell::SessionStatus::Live => "live",
        maestro_shell::SessionStatus::Exited => "exited",
        maestro_shell::SessionStatus::Unknown => "unknown",
    }
}

/// A tab's persisted attention state, as a pure serde DTO. Mirrors `maestro-shell`'s
/// `AttentionState` field shape (`attention`/`unseen`/`since_ms`/`source`) but lives here so
/// `lib.rs` keeps no `maestro-shell` dependency. `attention` and `source` are the snake_case
/// strings (`none`/`activity`/… and `process`/`agent`/`user`).
#[derive(Clone, Debug, serde::Serialize, PartialEq, Eq)]
pub struct AttentionJson {
    pub attention: String,
    pub unseen: bool,
    pub since_ms: u64,
    pub source: String,
}

/// Whether a persisted [`AttentionJson`] should surface in a tab strip. Mirrors the persisted-only
/// half of `maestro-shell`'s `tab_needs_attention`: a tab needs attention when it has UNSEEN
/// attention whose state is not `none`. The renderer/GUI later ORs in any task-derived signal; this
/// pure helper only knows the persisted object, so `none` never needs attention regardless of the
/// other fields.
pub fn attention_needs_attention(attention: &AttentionJson) -> bool {
    attention.unseen && attention.attention != "none"
}

/// A tab's state-aware attention indicator: the persisted attention `kind` plus the single
/// deterministic ASCII `marker` a tab strip draws for it. Pure serde DTO derived ONLY from
/// [`AttentionJson`] by [`tab_attention_indicator`]; it carries no daemon/renderer/task signal and is
/// the app-side projection mirrored by the renderer's own indicator type. `kind` is the persisted
/// attention string (`activity`/`needs_input`/`error`/`done`); `marker` is its fixed glyph.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TabAttentionIndicator {
    pub kind: String,
    pub marker: String,
}

/// Map a persisted [`AttentionJson`] to its state-aware [`TabAttentionIndicator`], or `None` when the
/// tab should show no marker. PURE and persisted-only: an indicator appears only for an UNSEEN
/// attention whose state is one of the known non-`none` kinds. `none` (or any seen attention, or any
/// unknown state string) yields `None`, never a marker. The marker mapping is the single app-side
/// source of truth: `activity`->`~`, `needs_input`->`?`, `error`->`!`, `done`->`=`.
pub fn tab_attention_indicator(attention: &AttentionJson) -> Option<TabAttentionIndicator> {
    if !attention.unseen {
        return None;
    }
    let marker = match attention.attention.as_str() {
        "activity" => '~',
        "needs_input" => '?',
        "error" => '!',
        "done" => '=',
        _ => return None,
    };
    Some(TabAttentionIndicator {
        kind: attention.attention.clone(),
        marker: marker.to_string(),
    })
}

/// Map an app-side [`TabAttentionIndicator`] to the renderer's own attention indicator type. PURE:
/// the one seam translating the persisted `kind` string into the renderer's typed kind enum and
/// carrying the same ASCII marker, so the two crates agree on the drawn glyph without sharing a type.
/// Returns `None` for an unknown `kind` string (defensive; `tab_attention_indicator` only ever
/// produces known kinds).
pub(crate) fn renderer_attention_indicator(
    indicator: &TabAttentionIndicator,
) -> Option<maestro_renderer::RendererTabAttention> {
    let kind = match indicator.kind.as_str() {
        "activity" => maestro_renderer::RendererTabAttentionKind::Activity,
        "needs_input" => maestro_renderer::RendererTabAttentionKind::NeedsInput,
        "error" => maestro_renderer::RendererTabAttentionKind::Error,
        "done" => maestro_renderer::RendererTabAttentionKind::Done,
        _ => return None,
    };
    Some(maestro_renderer::RendererTabAttention {
        kind,
        marker: kind.marker(),
    })
}

/// Shape a persisted [`maestro_shell::AttentionState`] into its pure [`AttentionJson`] DTO with the
/// wire-stable snake_case strings, mirroring `main`'s private `attention_json` so the runtime helper
/// can build [`WindowViewTabJson`] rows without depending on `main`.
fn attention_state_to_json(attention: &maestro_shell::AttentionState) -> AttentionJson {
    AttentionJson {
        attention: attention_wire_str(attention.attention).to_string(),
        unseen: attention.unseen,
        since_ms: attention.since_ms,
        source: attention_source_wire_str(attention.source).to_string(),
    }
}

/// Project one joined [`maestro_shell::WindowTabView`] into the pure [`WindowViewTabJson`] DTO,
/// mirroring `main`'s private `view_tab_json` so the runtime helper can rebuild the strip from the
/// same joined-view shape that `window view` returns.
fn window_tab_view_to_json(view: &maestro_shell::WindowTabView) -> WindowViewTabJson {
    WindowViewTabJson {
        tab_id: view.tab_id.clone(),
        session_id: view.session_id.clone(),
        index: view.index,
        title: view.title.clone(),
        pinned: view.pinned,
        attention: attention_state_to_json(&view.attention),
        session_status: view
            .session_status
            .map(|s| session_status_wire_str(s).to_string()),
        agent_task_id: view.agent_task_id.clone(),
        agent_task_state: view
            .agent_task_state
            .map(|s| agent_task_state_wire_str(s).to_string()),
        needs_attention: view.needs_attention,
        session_record_missing: view.session_record_missing,
        split_from: crate::window::split_from_json(view.split_from.as_ref()),
        // Carry the AUTHORITATIVE pane rect through the join so the periodic live refresh keeps painting
        // from rects (dropping it here made the layout snap to a split_from-derived shape ~750ms later).
        pane_rect: crate::window::pane_rect_json(view.pane_rect.as_ref()),
        stashed: view.stashed,
    }
}

/// The successful outcome of [`clear_tab_attention_and_refresh_strip`]: the cleared tab's coordinate
/// plus the refreshed [`TabStripModel`] that was pushed to the renderer. The model is the same one
/// sent as `SetTabStrip(Some(..))`, so callers can log or assert what the renderer now shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TabAttentionClearRefresh {
    pub window_id: String,
    pub tab_id: String,
    pub model: TabStripModel,
}

/// Why [`clear_tab_attention_and_refresh_strip`] failed. Typed so future GUI click handling reacts
/// without parsing strings, and so the caller can tell a record-write failure (nothing sent, nothing
/// changed downstream) from a post-clear projection failure (record already cleared) from a closed
/// renderer channel (record cleared and strip rebuilt, but the refresh was not delivered).
#[derive(Debug)]
pub enum TabAttentionClearRefreshError {
    /// The persisted `update_attention` clear write failed; no reconcile, projection, or renderer
    /// command was attempted. The on-disk attention is unchanged.
    WindowLayout(maestro_shell::window_layout::WindowLayoutError),
    /// The local agent-task reconcile (run AFTER a successful clear) failed; no renderer command was
    /// sent. The attention clear is already persisted.
    TaskReconcile(maestro_shell::store::StoreError),
    /// Building the joined `tab_view` for the strip failed AFTER a successful clear; no renderer
    /// command was sent. The attention clear is already persisted.
    TabView(maestro_shell::window_layout::WindowLayoutError),
    /// The supplied active tab id was not present in the refreshed tab list; no renderer command was
    /// sent. The attention clear is already persisted.
    TabStripModel(TabStripModelError),
    /// The record was cleared and the strip rebuilt, but the renderer command channel is closed
    /// (event loop gone); the `SetTabStrip` refresh was not delivered.
    RendererControlClosed,
}

impl std::fmt::Display for TabAttentionClearRefreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TabAttentionClearRefreshError::WindowLayout(e) => {
                write!(f, "clearing persisted tab attention failed: {e}")
            }
            TabAttentionClearRefreshError::TaskReconcile(e) => {
                write!(
                    f,
                    "reconciling agent tasks for the strip refresh failed: {e}"
                )
            }
            TabAttentionClearRefreshError::TabView(e) => {
                write!(
                    f,
                    "building the joined tab view for the strip refresh failed: {e}"
                )
            }
            TabAttentionClearRefreshError::TabStripModel(e) => {
                write!(f, "projecting the refreshed tab strip failed: {e}")
            }
            TabAttentionClearRefreshError::RendererControlClosed => {
                write!(f, "renderer control channel is closed")
            }
        }
    }
}

impl std::error::Error for TabAttentionClearRefreshError {}

/// Clear one tab's persisted attention and refresh the live renderer's read-only tab strip — the
/// app-side runtime seam a future GUI click-to-clear event calls. This does NOT wire any renderer
/// click/input event, open a window, connect a daemon, watch anything, or clear task-derived
/// attention; it only performs the record write + strip rebuild + one renderer refresh.
///
/// Sequence (each step's failure stops the rest and is surfaced typed):
/// 1. [`WindowLayoutService::update_attention`] writes the fixed cleared state
///    (`Attention::None`, `unseen:false`, `source:User`, `since_ms:now_ms`). A failure here means
///    NOTHING downstream ran — no renderer command is sent ([`TabAttentionClearRefreshError::WindowLayout`]).
/// 2. the existing local records-only [`maestro_shell::agent_task_reconcile::AgentTaskReconciler`]
///    reconciles (no second daemon connect), then [`WindowLayoutService::tab_view`] joins it — so
///    task/session-derived `needs_attention` SURVIVES the persisted-attention clear.
/// 3. [`build_tab_strip_model_from_window_view`] projects the joined rows, keeping `active_tab_id`
///    active.
/// 4. [`RendererTabRuntime::set_tab_strip`]`(Some(&model))` sends EXACTLY ONE `SetTabStrip` refresh.
///    A closed receiver surfaces [`TabAttentionClearRefreshError::RendererControlClosed`] AFTER the
///    record was already cleared and the strip rebuilt.
///
/// Failures are surfaced, never hidden or retried. The `window attention-clear` CLI command keeps
/// its own direct runner path and is unaffected.
pub fn clear_tab_attention_and_refresh_strip(
    paths: &maestro_shell::AppPaths,
    runtime: &mut RendererTabRuntime,
    window_id: &str,
    tab_id: &str,
    active_tab_id: Option<&str>,
    now_ms: u64,
) -> Result<TabAttentionClearRefresh, TabAttentionClearRefreshError> {
    let cleared = maestro_shell::AttentionState {
        attention: maestro_shell::Attention::None,
        unseen: false,
        since_ms: now_ms,
        source: maestro_shell::AttentionSource::User,
    };
    maestro_shell::WindowLayoutService::new(paths)
        .update_attention(window_id, tab_id, cleared, now_ms)
        .map_err(TabAttentionClearRefreshError::WindowLayout)?;

    let report = maestro_shell::agent_task_reconcile::AgentTaskReconciler::new(paths)
        .reconcile()
        .map_err(TabAttentionClearRefreshError::TaskReconcile)?;
    let views = maestro_shell::WindowLayoutService::new(paths)
        .tab_view(window_id, &report)
        .map_err(TabAttentionClearRefreshError::TabView)?;
    let view_tabs: Vec<WindowViewTabJson> = views.iter().map(window_tab_view_to_json).collect();

    let model = build_tab_strip_model_from_window_view(window_id, &view_tabs, active_tab_id)
        .map_err(TabAttentionClearRefreshError::TabStripModel)?;

    runtime.set_tab_strip(Some(&model)).map_err(|e| match e {
        TabSwitchError::RendererControlClosed => {
            TabAttentionClearRefreshError::RendererControlClosed
        }
        // set_tab_strip only ever reports a closed channel; tab-lookup variants are unreachable here.
        other => unreachable!("set_tab_strip returned an unexpected error: {other:?}"),
    })?;

    Ok(TabAttentionClearRefresh {
        window_id: window_id.to_string(),
        tab_id: tab_id.to_string(),
        model,
    })
}

/// Why [`rebuild_live_tab_strip_model`] could not rebuild the live strip. Each variant maps to the
/// local step that failed; the foreground listener logs it non-fatally and keeps the last good visible
/// strip (a transient read failure must never blank or tear down a running renderer).
#[derive(Debug)]
pub enum LiveTabStripRefreshError {
    /// The local records-only agent-task reconcile failed; nothing was projected.
    TaskReconcile(maestro_shell::store::StoreError),
    /// Joining the window/tab view against the reconcile report failed; nothing was projected.
    TabView(maestro_shell::window_layout::WindowLayoutError),
    /// The supplied active tab id was not present in the rebuilt tab list.
    TabStripModel(TabStripModelError),
}

impl std::fmt::Display for LiveTabStripRefreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LiveTabStripRefreshError::TaskReconcile(e) => {
                write!(
                    f,
                    "reconciling agent tasks for the live strip refresh failed: {e}"
                )
            }
            LiveTabStripRefreshError::TabView(e) => {
                write!(
                    f,
                    "building the joined tab view for the live strip refresh failed: {e}"
                )
            }
            LiveTabStripRefreshError::TabStripModel(e) => {
                write!(f, "projecting the live tab strip failed: {e}")
            }
        }
    }
}

impl std::error::Error for LiveTabStripRefreshError {}

/// Rebuild the live read-only [`TabStripModel`] from LOCAL RECORDS ONLY — the periodic-refresh
/// counterpart to [`clear_tab_attention_and_refresh_strip`], minus the record write and minus the
/// renderer command. The foreground `attach-tab` listener calls this on an idle `recv_timeout` tick so
/// external changes (another process writing persisted attention, tab metadata edits, and recomputed
/// task/session-derived `needs_attention`) become visible in a running renderer without a reattach.
///
/// It is intentionally NON-MUTATING and self-contained:
/// - it runs the existing local records-only
///   [`maestro_shell::agent_task_reconcile::AgentTaskReconciler`] reconcile (NO daemon/session
///   connect) and [`WindowLayoutService::tab_view`] join, so task/session-derived attention is folded
///   in exactly like the clear path;
/// - it projects through [`build_tab_strip_model_from_window_view`], keeping `active_tab_id` active;
/// - it does NOT write any record, does NOT send any renderer command, and does NOT touch the daemon.
///
/// The caller owns change detection ([`tab_strip_model_changed`]) and the single `SetTabStrip` send, so
/// a steady state with no external change costs one local rebuild and ZERO renderer commands.
pub fn rebuild_live_tab_strip_model(
    paths: &maestro_shell::AppPaths,
    window_id: &str,
    active_tab_id: Option<&str>,
) -> Result<TabStripModel, LiveTabStripRefreshError> {
    let report = maestro_shell::agent_task_reconcile::AgentTaskReconciler::new(paths)
        .reconcile()
        .map_err(LiveTabStripRefreshError::TaskReconcile)?;
    let views = maestro_shell::WindowLayoutService::new(paths)
        .tab_view(window_id, &report)
        .map_err(LiveTabStripRefreshError::TabView)?;
    let view_tabs: Vec<WindowViewTabJson> = views.iter().map(window_tab_view_to_json).collect();

    build_tab_strip_model_from_window_view(window_id, &view_tabs, active_tab_id)
        .map_err(LiveTabStripRefreshError::TabStripModel)
}
