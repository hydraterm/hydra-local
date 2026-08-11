//! Durable window/tab layout service.
//!
//! [`WindowLayoutService`] is a thin, store-backed manager over the existing
//! [`WindowLayout`]/[`TabRecord`] records: it creates/loads a window's ordered tab list and
//! applies the small set of layout mutations the app shell needs (open/close/rename/pin/
//! reorder/swap a tab, update a tab's persisted attention roll-up). Every mutation loads the
//! current layout, edits it, RENORMALIZES tab indices to a contiguous `0..n` run, and writes
//! it back through the store's atomic [`write_record`](crate::store::write_record).
//!
//! It also offers a READ-ONLY [`WindowLayoutService::tab_view`] projection that joins the
//! persisted tabs with an [`AgentTaskReconcileReport`], so the UI can show task state /
//! attention alongside each tab without this layer ever talking to the daemon.
//!
//! Hard boundaries (matching the rest of the shell's records layer):
//!
//! - NO daemon/socket/PTY/git/renderer/UI shell. Records in, records out, under an injected
//!   [`AppPaths`].
//! - This layer NEVER creates sessions or tasks and NEVER validates that a tab's `session_id`
//!   names a live (or even existing) session: a layout may legitimately reference a recovered
//!   or future session, and reconciliation — not layout — owns that linkage.
//! - Future-version and corrupt layout records are surfaced as typed errors
//!   ([`WindowLayoutError::FutureVersion`] / [`WindowLayoutError::Corrupt`]); the store leaves a
//!   future record byte-identical in place and quarantines a corrupt one. A mutation never
//!   "repairs" such a record by overwriting it.

use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use crate::agent_task_reconcile::AgentTaskReconcileReport;
#[cfg(test)]
use crate::pane_layout::SlotId;
use crate::pane_layout::{
    slot_rects, CanonicalLayout, EdgeDir, PaneLayoutModel, SwallowDir, UnitRect,
};
use crate::paths::{AppPaths, RecordKind};
use crate::records::{
    AgentTaskState, Attention, AttentionState, PaneRect, SessionStatus, SplitAxis, SplitFrom,
    TabRecord, WindowLayout,
};
use crate::store::{self, LoadOutcome, StoreError};

/// Errors from the window-layout service.
#[derive(Debug)]
pub enum WindowLayoutError {
    /// A mutation/projection targeted a window that has no current-version layout record.
    WindowLayoutNotFound { window_id: String },
    /// `create_empty` was asked to create a layout for a window that already has one. The
    /// existing record is left untouched.
    WindowLayoutAlreadyExists { window_id: String },
    /// A tab operation named a `tab_id` not present in the window's layout.
    TabNotFound { window_id: String, tab_id: String },
    /// `open_tab` was given a `tab_id` already present in the layout. Nothing is rewritten.
    TabAlreadyExists { window_id: String, tab_id: String },
    /// `reorder_tabs` was given an order that is not an exact permutation of the existing tab
    /// ids (missing id, unknown id, or a duplicate). The layout is left untouched.
    InvalidTabOrder { reason: String },
    /// `stash_pane` was asked to stash the window's only remaining live (non-stashed) pane. Stashing
    /// it would leave the window with an empty live layout, so the request is refused and the layout
    /// is left untouched.
    CannotStashLastPane { window_id: String, tab_id: String },
    /// The on-disk layout was written by a newer schema version than this build understands. It
    /// is left byte-identical in place; surfaced so the caller can tell the user.
    FutureVersion { path: PathBuf, ours: u32, got: u32 },
    /// The on-disk layout failed validation and was quarantined by the store (bytes preserved
    /// at `moved_to`).
    Corrupt {
        original: PathBuf,
        moved_to: PathBuf,
        reason: String,
    },
    /// Underlying store IO / id-validation error (an unsafe `window_id`/`tab_id` is refused here
    /// before any path is built).
    Store(StoreError),
}

impl fmt::Display for WindowLayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WindowLayoutError::WindowLayoutNotFound { window_id } => {
                write!(f, "no window layout for window_id {window_id:?}")
            }
            WindowLayoutError::WindowLayoutAlreadyExists { window_id } => {
                write!(
                    f,
                    "window layout already exists for window_id {window_id:?}"
                )
            }
            WindowLayoutError::TabNotFound { window_id, tab_id } => {
                write!(f, "no tab {tab_id:?} in window {window_id:?}")
            }
            WindowLayoutError::TabAlreadyExists { window_id, tab_id } => {
                write!(f, "tab {tab_id:?} already exists in window {window_id:?}")
            }
            WindowLayoutError::InvalidTabOrder { reason } => {
                write!(f, "invalid tab order: {reason}")
            }
            WindowLayoutError::CannotStashLastPane { window_id, tab_id } => {
                write!(
                    f,
                    "cannot stash the only live pane {tab_id:?} of window {window_id:?}"
                )
            }
            WindowLayoutError::FutureVersion { path, ours, got } => write!(
                f,
                "window layout at {} was written by a newer schema (ours {ours}, got {got})",
                path.display()
            ),
            WindowLayoutError::Corrupt {
                original,
                moved_to,
                reason,
            } => write!(
                f,
                "window layout at {} is corrupt ({reason}); quarantined to {}",
                original.display(),
                moved_to.display()
            ),
            WindowLayoutError::Store(e) => write!(f, "window layout store error: {e}"),
        }
    }
}

impl Error for WindowLayoutError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            WindowLayoutError::Store(e) => Some(e),
            _ => None,
        }
    }
}

impl From<StoreError> for WindowLayoutError {
    fn from(e: StoreError) -> Self {
        WindowLayoutError::Store(e)
    }
}

/// One projected tab row: the persisted [`TabRecord`] fields joined with whatever the
/// [`AgentTaskReconcileReport`] knows about the task whose `current_session_id` is this tab's
/// `session_id`. Purely derived; producing it mutates nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowTabView {
    pub tab_id: String,
    pub session_id: String,
    pub index: u32,
    pub title: String,
    pub pinned: bool,
    /// The tab's persisted attention roll-up (survives restarts).
    pub attention: AttentionState,
    /// Recorded status of the joined task's current session, if a task currently points at this
    /// tab's session. `None` when no reconciled task links here (the common plain-tab case).
    pub session_status: Option<SessionStatus>,
    /// The joined task's id, if any.
    pub agent_task_id: Option<String>,
    /// The joined task's state, if any.
    pub agent_task_state: Option<AgentTaskState>,
    /// True if the persisted tab attention is unseen-and-non-`None`, OR the joined task report
    /// says the task needs attention. See [`tab_needs_attention`].
    pub needs_attention: bool,
    /// True when a task links here but its current session record is missing on disk.
    pub session_record_missing: bool,
    /// Split provenance copied verbatim from the persisted [`TabRecord::split_from`] (`None` for an
    /// ordinary tab). Carried so the joined window-view strip keeps the same split markers the
    /// persisted-layout strip shows.
    pub split_from: Option<SplitFrom>,
    /// The AUTHORITATIVE live geometry, copied verbatim from [`TabRecord::pane_rect`]. Carried through the
    /// joined window-view strip so the periodic live refresh keeps painting from rects (NOT the legacy
    /// split_from chain) — dropping it here made the layout "snap to another shape" ~750ms after an op.
    pub pane_rect: Option<PaneRect>,
    /// True when the tab is STASHED: its session is kept alive but the renderer hides it from the live
    /// pane layout and the dashboard surfaces it as a revive candidate. Copied verbatim from
    /// [`TabRecord::stashed`] so the joined window-view strip can exclude stashed panes.
    pub stashed: bool,
}

/// Resolve the tab a dock should attach to so the new pane appends at the END of a split chain.
///
/// Starting from `target`, follow the chain of tabs whose `split_from.tab_id` points at the current
/// tab (the next descendant) until a tab with no further child is reached — that tail is the parent
/// the docked source should split from, letting the canonical engine grow the layout one pane wider.
/// `exclude` (the source being docked) is skipped when choosing the next descendant so a tab never
/// docks onto itself. Bounded by the tab count to defend against a corrupt cyclic chain.
fn resolve_chain_tail(layout: &WindowLayout, target: &str, exclude: &str) -> String {
    let mut tail = target.to_string();
    for _ in 0..=layout.tabs.len() {
        let next_child = layout.tabs.iter().find(|t| {
            t.tab_id != exclude && t.split_from.as_ref().is_some_and(|s| s.tab_id == tail)
        });
        match next_child {
            Some(child) => tail = child.tab_id.clone(),
            None => break,
        }
    }
    tail
}

fn live_tab_ids_for_revive(layout: &WindowLayout, reviving_tab_id: &str) -> Vec<String> {
    let mut live: Vec<&TabRecord> = layout
        .tabs
        .iter()
        .filter(|t| !t.stashed && t.tab_id != reviving_tab_id)
        .collect();
    live.sort_by_key(|t| t.index);
    live.into_iter().map(|t| t.tab_id.clone()).collect()
}

fn split_from_parent(parent_id: &str, axis: SplitAxis) -> Option<SplitFrom> {
    Some(SplitFrom {
        tab_id: parent_id.to_string(),
        axis,
        ratio_per_mille: None,
    })
}

fn edge_from_split_axis(axis: SplitAxis) -> EdgeDir {
    match axis {
        SplitAxis::Right => EdgeDir::Right,
        SplitAxis::Down => EdgeDir::Bottom,
    }
}

fn live_tabs_sorted(layout: &WindowLayout) -> Vec<&TabRecord> {
    let mut live: Vec<&TabRecord> = layout.tabs.iter().filter(|t| !t.stashed).collect();
    live.sort_by_key(|t| t.index);
    live
}

/// Every canonical layout, for matching a rect set against each layout's `slot_rects`.
const ALL_CANONICAL_LAYOUTS: [CanonicalLayout; 18] = [
    CanonicalLayout::OneFull,
    CanonicalLayout::TwoColumns,
    CanonicalLayout::TwoRows,
    CanonicalLayout::ThreeColumns,
    CanonicalLayout::ThreeRows,
    CanonicalLayout::ThreeLeftMain,
    CanonicalLayout::ThreeRightMain,
    CanonicalLayout::ThreeTopMain,
    CanonicalLayout::ThreeBottomMain,
    CanonicalLayout::FourGrid,
    CanonicalLayout::FourColumns,
    CanonicalLayout::FourRows,
    CanonicalLayout::FourLeftSplit,
    CanonicalLayout::FourTopSplit,
    CanonicalLayout::FourLeftMain,
    CanonicalLayout::FourRightMain,
    CanonicalLayout::FourTopMain,
    CanonicalLayout::FourBottomMain,
];

/// Classify the live panes' AUTHORITATIVE rects into a canonical [`PaneLayoutModel`]. This reads the
/// real geometry (pane_rect), so it stays correct even after a stash/drag-drop where the legacy
/// split_from chain diverges from what's painted — the cause of swallow silently failing ("no legal
/// swallow") after such an op. Matches a rect set to the canonical layout whose `slot_rects` it equals
/// (within rounding), binding panes in reading order. `None` when no rect, or the shape isn't one of the
/// canonical layouts.
fn canonical_model_from_rects(live: &[&TabRecord]) -> Option<PaneLayoutModel> {
    let n = live.len();
    if !(1..=4).contains(&n) || live.iter().any(|t| t.pane_rect.is_none()) {
        return None;
    }
    // (id, rect) in reading order (y then x).
    let mut panes: Vec<(&str, UnitRect)> = live
        .iter()
        .map(|t| (t.tab_id.as_str(), t.pane_rect.unwrap().to_unit()))
        .collect();
    panes.sort_by(|a, b| {
        a.1[1]
            .partial_cmp(&b.1[1])
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                a.1[0]
                    .partial_cmp(&b.1[0])
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });
    let agents_ro: Vec<String> = panes.iter().map(|(id, _)| id.to_string()).collect();
    let r = |i: usize| panes[i].1;

    // Match the canonical layout whose `slot_rects` have the SAME TOPOLOGY as these rects, ignoring exact
    // proportions (a local split makes unequal panes that still read as e.g. left-main). Two rects share a
    // topology when each canonical slot rect and the corresponding pane rect agree on which edges are
    // flush to 0/1 (full-height / full-width / which corner) — i.e. the sign pattern matches.
    let sig = |rect: UnitRect| -> (bool, bool, bool, bool) {
        (
            nearly_eq(rect[0], 0.0),           // touches left
            nearly_eq(rect[1], 0.0),           // touches top
            nearly_eq(rect_right(rect), 1.0),  // touches right
            nearly_eq(rect_bottom(rect), 1.0), // touches bottom
        )
    };
    for layout in ALL_CANONICAL_LAYOUTS {
        if layout.pane_count() != n {
            continue;
        }
        let slots = slot_rects(layout, &std::collections::BTreeMap::new());
        if slots.len() != n {
            continue;
        }
        // slot_rects come in reading order, as do `panes`. Compare edge-flush signatures slot-by-slot.
        let same_topology = (0..n).all(|i| sig(slots[i]) == sig(r(i)));
        if same_topology {
            return PaneLayoutModel::from_agents(&agents_ro, Some(layout)).ok();
        }
    }
    None
}

fn canonical_model_from_live_tabs(live: &[&TabRecord]) -> Option<PaneLayoutModel> {
    if live.is_empty() || live.len() > 4 {
        return None;
    }
    // PREFER the authoritative rect geometry — it stays correct when the split_from chain diverges.
    if let Some(model) = canonical_model_from_rects(live) {
        return Some(model);
    }
    if live.len() == 4 {
        let ids: Vec<String> = live.iter().map(|tab| tab.tab_id.clone()).collect();
        let [a, b, c, d] = ids.as_slice() else {
            return None;
        };
        let layout = if split_axis_between_records(live, b, a) == Some(SplitAxis::Right)
            && split_axis_between_records(live, c, b) == Some(SplitAxis::Right)
            && split_axis_between_records(live, d, a) == Some(SplitAxis::Down)
        {
            Some(CanonicalLayout::FourBottomMain)
        } else if split_axis_between_records(live, b, a) == Some(SplitAxis::Down)
            && split_axis_between_records(live, c, b) == Some(SplitAxis::Right)
            && split_axis_between_records(live, d, c) == Some(SplitAxis::Right)
        {
            Some(CanonicalLayout::FourTopMain)
        } else if split_axis_between_records(live, b, a) == Some(SplitAxis::Right)
            && split_axis_between_records(live, c, b) == Some(SplitAxis::Down)
            && split_axis_between_records(live, d, c) == Some(SplitAxis::Down)
        {
            Some(CanonicalLayout::FourLeftMain)
        } else if split_axis_between_records(live, b, a) == Some(SplitAxis::Right)
            && split_axis_between_records(live, c, a) == Some(SplitAxis::Down)
            && split_axis_between_records(live, d, c) == Some(SplitAxis::Down)
        {
            Some(CanonicalLayout::FourRightMain)
        } else {
            None
        };
        if let Some(layout) = layout {
            return PaneLayoutModel::from_agents(&ids, Some(layout)).ok();
        }
    }
    let root = live.iter().find(|t| t.split_from.is_none())?;
    if live.iter().filter(|t| t.split_from.is_none()).count() != 1 {
        return None;
    }

    let mut model = PaneLayoutModel::from_agents(std::slice::from_ref(&root.tab_id), None).ok()?;
    for tab in live.iter().filter(|t| t.tab_id != root.tab_id) {
        let split = tab.split_from.as_ref()?;
        let parent_slot = model.slot_of(&split.tab_id)?;
        model = model
            .split_ordered_from_slot(parent_slot, edge_from_split_axis(split.axis), &tab.tab_id)
            .ok()??;
    }
    Some(model)
}

#[derive(Clone, Debug)]
struct AgentRect {
    agent: String,
    rect: UnitRect,
}

const RECT_EPS: f32 = 0.001;

fn rect_right(rect: UnitRect) -> f32 {
    rect[0] + rect[2]
}

/// GLOBAL TILING INVARIANT. The live panes' rects must perfectly TILE the unit square: every rect lies
/// inside [0,1]², no two overlap (more than epsilon), and their areas sum to 1 (no gap, no pane hidden
/// behind another). This is the single guard every geometry write goes through — so NO operation, even
/// an unexplored 4-pane layout, can ever leave panes overlapping or overflowing. Returns `true` when the
/// set is a valid tiling.
fn rects_tile_unit_square(panes: &[AgentRect]) -> bool {
    if panes.is_empty() {
        return false;
    }
    // In-bounds.
    for p in panes {
        let [x, y, w, h] = p.rect;
        if w <= RECT_EPS || h <= RECT_EPS {
            return false;
        }
        if x < -RECT_EPS
            || y < -RECT_EPS
            || rect_right(p.rect) > 1.0 + RECT_EPS
            || rect_bottom(p.rect) > 1.0 + RECT_EPS
        {
            return false;
        }
    }
    // Pairwise non-overlap (positive-area intersection is a violation).
    for (i, p) in panes.iter().enumerate() {
        for q in &panes[i + 1..] {
            let ox =
                p.rect[0].max(q.rect[0]) + RECT_EPS < rect_right(p.rect).min(rect_right(q.rect));
            let oy =
                p.rect[1].max(q.rect[1]) + RECT_EPS < rect_bottom(p.rect).min(rect_bottom(q.rect));
            if ox && oy {
                return false;
            }
        }
    }
    // Areas sum to the whole square (no gap). Combined with non-overlap + in-bounds this proves a tiling.
    let area: f32 = panes.iter().map(|p| p.rect[2] * p.rect[3]).sum();
    (area - 1.0).abs() <= 1e-3
}

fn rect_bottom(rect: UnitRect) -> f32 {
    rect[1] + rect[3]
}

fn nearly_eq(a: f32, b: f32) -> bool {
    (a - b).abs() <= RECT_EPS
}

fn same_height(a: UnitRect, b: UnitRect) -> bool {
    nearly_eq(a[1], b[1]) && nearly_eq(a[3], b[3])
}

/// LOCAL edge-absorb SWALLOW (rect-only). The focused pane `focus` EXTENDS across its `dir` edge,
/// absorbing only the overlapping slice of whatever sits directly across that edge; every neighbor keeps
/// the part that does NOT overlap the focused pane's perpendicular span. Pure geometry, no canonical
/// reshape — so e.g. A/(B│C│D) with B swallowing UP makes B span both rows on the left while A keeps the
/// portion over C and D.
///
/// Mechanics for an Up swallow (others are the four rotations): let `seam = focus.top`. Among the OTHER
/// panes, those whose bottom edge is the seam AND whose x-span overlaps the focus x-span are "across the
/// edge". The focus top moves up to the highest such neighbor's top (the band it can cleanly reclaim
/// without leaving a hole — here a single full row above, so up to 0). Each across neighbor is clipped to
/// the part OUTSIDE the focus x-span; a neighbor fully inside the focus span is wholly absorbed (returned
/// as `None` → caller stashes it). Non-across panes are untouched.
///
/// Returns the new rects (every pane kept alive — focus grown, the across neighbor clipped). Returns
/// `None` when no pane lies across the edge (nothing to swallow), when the absorb would ELIMINATE a
/// neighbor (that is a close, not a resize), or when it would split a neighbor in two.
fn swallow_rect_local(panes: &[AgentRect], focus: &str, dir: SwallowDir) -> Option<Vec<AgentRect>> {
    let f = panes.iter().find(|p| p.agent == focus)?.rect;
    let horizontal = matches!(dir, SwallowDir::Left | SwallowDir::Right);

    // Overlap of two 1-D intervals (strictly, with epsilon tolerance).
    let overlaps =
        |a0: f32, a1: f32, b0: f32, b1: f32| a0.min(a1) < b1 - RECT_EPS && b0 < a1 - RECT_EPS;

    // Identify the panes directly across the swallow edge whose PERPENDICULAR span overlaps the focus.
    let across: Vec<usize> = panes
        .iter()
        .enumerate()
        .filter(|(_, p)| p.agent != focus)
        .filter(|(_, p)| {
            let r = p.rect;
            match dir {
                // neighbor's bottom == focus.top, x-spans overlap.
                SwallowDir::Up => {
                    nearly_eq(rect_bottom(r), f[1])
                        && overlaps(r[0], rect_right(r), f[0], rect_right(f))
                }
                SwallowDir::Down => {
                    nearly_eq(r[1], rect_bottom(f))
                        && overlaps(r[0], rect_right(r), f[0], rect_right(f))
                }
                SwallowDir::Left => {
                    nearly_eq(rect_right(r), f[0])
                        && overlaps(r[1], rect_bottom(r), f[1], rect_bottom(f))
                }
                SwallowDir::Right => {
                    nearly_eq(r[0], rect_right(f))
                        && overlaps(r[1], rect_bottom(r), f[1], rect_bottom(f))
                }
            }
        })
        .map(|(i, _)| i)
        .collect();
    if across.is_empty() {
        return None;
    }

    // How far the focus extends: to the far edge of the across panes (e.g. up to their topmost top).
    let new_f = {
        let mut r = f;
        match dir {
            SwallowDir::Up => {
                let top = across
                    .iter()
                    .map(|&i| panes[i].rect[1])
                    .fold(f[1], f32::min);
                r[3] = rect_bottom(f) - top;
                r[1] = top;
            }
            SwallowDir::Down => {
                let bot = across
                    .iter()
                    .map(|&i| rect_bottom(panes[i].rect))
                    .fold(rect_bottom(f), f32::max);
                r[3] = bot - f[1];
            }
            SwallowDir::Left => {
                let left = across
                    .iter()
                    .map(|&i| panes[i].rect[0])
                    .fold(f[0], f32::min);
                r[2] = rect_right(f) - left;
                r[0] = left;
            }
            SwallowDir::Right => {
                let right = across
                    .iter()
                    .map(|&i| rect_right(panes[i].rect))
                    .fold(rect_right(f), f32::max);
                r[2] = right - f[0];
            }
        }
        r
    };

    let mut out: Vec<AgentRect> = Vec::new();
    for (i, p) in panes.iter().enumerate() {
        if p.agent == focus {
            out.push(AgentRect {
                agent: focus.to_string(),
                rect: new_f,
            });
            continue;
        }
        if !across.contains(&i) {
            out.push(p.clone());
            continue;
        }
        // Clip this across-pane to the part OUTSIDE the focus's perpendicular span.
        let r = p.rect;
        let clipped: Vec<UnitRect> = if horizontal {
            // focus grows L/R: keep the parts of `r` above/below the focus y-span.
            let mut parts = Vec::new();
            if r[1] < f[1] - RECT_EPS {
                parts.push([r[0], r[1], r[2], f[1] - r[1]]);
            }
            if rect_bottom(r) > rect_bottom(f) + RECT_EPS {
                parts.push([r[0], rect_bottom(f), r[2], rect_bottom(r) - rect_bottom(f)]);
            }
            parts
        } else {
            // focus grows U/D: keep the parts of `r` left/right of the focus x-span.
            let mut parts = Vec::new();
            if r[0] < f[0] - RECT_EPS {
                parts.push([r[0], r[1], f[0] - r[0], r[3]]);
            }
            if rect_right(r) > rect_right(f) + RECT_EPS {
                parts.push([rect_right(f), r[1], rect_right(r) - rect_right(f), r[3]]);
            }
            parts
        };
        match clipped.len() {
            // Wholly inside the focus span → the neighbor would be ELIMINATED. Swallow is a resize that
            // keeps every pane alive, so this is NOT a clean swallow: bail and leave the layout unchanged.
            // (Eliminating a pane is "close", a different action.)
            0 => return None,
            1 => out.push(AgentRect {
                agent: p.agent.clone(),
                rect: clipped[0],
            }),
            // A neighbor straddling BOTH sides would split into two — not representable as one pane; treat
            // as not-clean and bail so the caller leaves the layout unchanged.
            _ => return None,
        }
    }
    Some(out)
}

/// Split `rect` in half along `edge` for a local INSERT (drag/drop). Returns `(kept, inserted)` where
/// `inserted` is the half on the dropped edge (taken by the dragged pane) and `kept` is the other half
/// (retained by the target pane). L/R split the width; Top/Bottom split the height. Only this one rect
/// changes — the confirmed drag/drop rule: a drop subdivides the target locally, nothing else moves.
fn split_rect_local(rect: UnitRect, edge: EdgeDir) -> (UnitRect, UnitRect) {
    let [x, y, w, h] = rect;
    match edge {
        EdgeDir::Left => ([x + w / 2.0, y, w / 2.0, h], [x, y, w / 2.0, h]),
        EdgeDir::Right => ([x, y, w / 2.0, h], [x + w / 2.0, y, w / 2.0, h]),
        EdgeDir::Top => ([x, y + h / 2.0, w, h / 2.0], [x, y, w, h / 2.0]),
        EdgeDir::Bottom => ([x, y, w, h / 2.0], [x, y + h / 2.0, w, h / 2.0]),
    }
}

fn split_axis_between_records(
    tabs: &[&TabRecord],
    child_id: &str,
    parent_id: &str,
) -> Option<SplitAxis> {
    tabs.iter()
        .find(|tab| tab.tab_id == child_id)
        .and_then(|tab| tab.split_from.as_ref())
        .filter(|split| split.tab_id == parent_id)
        .map(|split| split.axis)
}

/// The confirmed stash rule, applied to rects. Removing `removed`, the freed cell is reclaimed by:
///   1. a SAME-HEIGHT, column-adjacent neighbor (extends horizontally; row heights untouched), else
///   2. a SAME-COLUMN, row-adjacent neighbor (extends vertically), else
///   3. RE-PACK: the removed pane was a full-span edge band whose neighbors are column/row groups of
///      differing internal structure — the surviving column-GROUPS (or row-groups) re-pack into a fresh
///      equal-width (or equal-height) track one unit smaller, each group keeping its internal split.
///
/// Returns the survivor rects tiling the unit square.
/// (75 cases verified to tile with no gap/overlap).
/// The user's general STASH-FILL rule. The freed `removed` rect is reclaimed by the neighbours on ONE
/// of its four sides whose edges EXACTLY TILE that side — they extend into the gap. It can be one OR
/// several neighbours (e.g. a stacked B/C pair both extending left to fill A's column). Try the WIDTH
/// sides first (left, then right — extend horizontally), then the HEIGHT sides (top, then bottom). A side
/// "fits" when the neighbours across that edge together span the freed rect's full perpendicular extent
/// with no gap/overlap (their edge lengths sum to it and they tile it). Returns the updated rects, or
/// `None` if no single side cleanly fits (caller falls back to re-pack).
fn fill_freed_by_neighbors(panes: &[AgentRect], removed: UnitRect) -> Option<Vec<AgentRect>> {
    // Across each side: the neighbours whose touching edge lies on that side AND whose perpendicular span
    // overlaps the freed rect. `extend` rewrites a matching pane to grow into the gap.
    // side = (selector of touching panes, does this set tile the freed perpendicular extent?, extend fn)
    let touches = |p: &AgentRect, side: usize| -> bool {
        let r = p.rect;
        match side {
            0 => nearly_eq(rect_right(r), removed[0]), // left side: pane's right == freed left
            1 => nearly_eq(r[0], rect_right(removed)), // right side
            2 => nearly_eq(rect_bottom(r), removed[1]), // top side
            _ => nearly_eq(r[1], rect_bottom(removed)), // bottom side
        }
    };
    // Try sides in order: left, right (width), top, bottom (height).
    for side in [0usize, 1, 2, 3] {
        let horizontal = side < 2; // left/right grow horizontally; the matching panes share the freed HEIGHT.
        let group: Vec<usize> = panes
            .iter()
            .enumerate()
            .filter(|(_, p)| touches(p, side))
            .filter(|(_, p)| {
                // perpendicular overlap with the freed rect.
                if horizontal {
                    p.rect[1].max(removed[1])
                        < rect_bottom(p.rect).min(rect_bottom(removed)) - RECT_EPS
                } else {
                    p.rect[0].max(removed[0])
                        < rect_right(p.rect).min(rect_right(removed)) - RECT_EPS
                }
            })
            .map(|(i, _)| i)
            .collect();
        if group.is_empty() {
            continue;
        }
        // Do the group's perpendicular spans EXACTLY tile the freed rect's perpendicular extent (cover it
        // fully, no overlap)? If so, each grows across the freed rect.
        let (lo, hi) = if horizontal {
            (removed[1], rect_bottom(removed))
        } else {
            (removed[0], rect_right(removed))
        };
        let mut spans: Vec<(f32, f32)> = group
            .iter()
            .map(|&i| {
                if horizontal {
                    (panes[i].rect[1], rect_bottom(panes[i].rect))
                } else {
                    (panes[i].rect[0], rect_right(panes[i].rect))
                }
            })
            .collect();
        spans.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        // Contiguous coverage of [lo, hi] with no gaps and matching endpoints.
        let mut covered = true;
        if !nearly_eq(spans[0].0, lo) || !nearly_eq(spans[spans.len() - 1].1, hi) {
            covered = false;
        }
        for w in spans.windows(2) {
            if !nearly_eq(w[0].1, w[1].0) {
                covered = false;
            }
        }
        if !covered {
            continue;
        }
        // Fits. Extend each group pane across the freed rect along the grow axis.
        let mut out = panes.to_vec();
        for &i in &group {
            let mut r = out[i].rect;
            if horizontal {
                // extend in x to cover the freed rect's x-extent (merge edge → other side of freed).
                let new_left = r[0].min(removed[0]);
                let new_right = rect_right(r).max(rect_right(removed));
                r[0] = new_left;
                r[2] = new_right - new_left;
            } else {
                let new_top = r[1].min(removed[1]);
                let new_bottom = rect_bottom(r).max(rect_bottom(removed));
                r[1] = new_top;
                r[3] = new_bottom - new_top;
            }
            out[i].rect = r;
        }
        return Some(out);
    }
    None
}

fn reduce_rects_by_spec(mut panes: Vec<AgentRect>, removed: UnitRect) -> Vec<AgentRect> {
    if panes.len() <= 1 {
        // Last survivor (or none): it fills the whole screen.
        for p in &mut panes {
            p.rect = [0.0, 0.0, 1.0, 1.0];
        }
        return panes;
    }

    // PRIMARY: the general edge-fitting fill (one or more neighbours on a side that exactly tiles it).
    if let Some(filled) = fill_freed_by_neighbors(&panes, removed) {
        return filled;
    }

    // 3. Re-pack. Decide whether a full-height column or a full-width row was freed by comparing the
    // removed band against the survivors' bounding span.
    let surv_left = panes
        .iter()
        .map(|p| p.rect[0])
        .fold(f32::INFINITY, f32::min);
    let surv_right = panes
        .iter()
        .map(|p| rect_right(p.rect))
        .fold(f32::NEG_INFINITY, f32::max);
    let freed_column =
        removed[0] < surv_left - RECT_EPS || rect_right(removed) > surv_right + RECT_EPS;

    if freed_column {
        // Distinct surviving column groups, left→right; assign each an equal-width slot of a smaller track.
        let mut spans: Vec<(f32, f32)> = Vec::new();
        for p in &panes {
            let key = (p.rect[0], rect_right(p.rect));
            if !spans
                .iter()
                .any(|s| nearly_eq(s.0, key.0) && nearly_eq(s.1, key.1))
            {
                spans.push(key);
            }
        }
        spans.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        let w = 1.0 / spans.len() as f32;
        for p in &mut panes {
            let i = spans
                .iter()
                .position(|s| nearly_eq(s.0, p.rect[0]) && nearly_eq(s.1, rect_right(p.rect)))
                .unwrap_or(0);
            p.rect = [i as f32 * w, p.rect[1], w, p.rect[3]]; // y kept (heights free)
        }
    } else {
        // Full-width row freed: surviving row groups re-pack into equal-height bands; columns kept.
        let mut spans: Vec<(f32, f32)> = Vec::new();
        for p in &panes {
            let key = (p.rect[1], rect_bottom(p.rect));
            if !spans
                .iter()
                .any(|s| nearly_eq(s.0, key.0) && nearly_eq(s.1, key.1))
            {
                spans.push(key);
            }
        }
        spans.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        let h = 1.0 / spans.len() as f32;
        for p in &mut panes {
            let i = spans
                .iter()
                .position(|s| nearly_eq(s.0, p.rect[1]) && nearly_eq(s.1, rect_bottom(p.rect)))
                .unwrap_or(0);
            p.rect = [p.rect[0], i as f32 * h, p.rect[2], h];
        }
    }
    panes
}

/// General guillotine recovery: turn a set of rects that tile the unit square into `split_from`
/// topology. Recursively finds a full-span vertical (or horizontal) cut separating the panes into two
/// non-empty groups, emits the right/bottom group as split from the left/top group's first pane, and
/// recurses. Handles any pane count and any of the spec's output shapes — replacing the old per-count
/// match arms. Returns survivors in topology order (root first, `None` split_from).
fn topology_from_rects(panes: &[AgentRect]) -> Vec<(String, Option<SplitFrom>)> {
    fn collect(
        panes: &[AgentRect],
        bounds: UnitRect,
        parent: Option<(&str, SplitAxis)>,
        out: &mut Vec<(String, Option<SplitFrom>)>,
    ) {
        if panes.is_empty() {
            return;
        }
        if panes.len() == 1 {
            let split = parent.and_then(|(pid, axis)| split_from_parent(pid, axis));
            out.push((panes[0].agent.clone(), split));
            return;
        }
        // Try a full-span vertical cut: an x where every pane is entirely left or entirely right of it.
        if let Some((left, right, _cut)) = guillotine(panes, bounds, true) {
            collect(&left, bounds, parent, out);
            // root of the left group is the parent for the right group, split Right.
            let left_root = left_root_agent(&left, bounds, true);
            collect(&right, bounds, Some((&left_root, SplitAxis::Right)), out);
            return;
        }
        // Else a full-span horizontal cut.
        if let Some((top, bottom, _cut)) = guillotine(panes, bounds, false) {
            collect(&top, bounds, parent, out);
            let top_root = left_root_agent(&top, bounds, false);
            collect(&bottom, bounds, Some((&top_root, SplitAxis::Down)), out);
            return;
        }
        // No clean guillotine cut (shouldn't happen for spec-tiled rects): fall back to flat order.
        for (i, p) in panes.iter().enumerate() {
            let split = if i == 0 {
                parent.and_then(|(pid, axis)| split_from_parent(pid, axis))
            } else {
                split_from_parent(&panes[0].agent, SplitAxis::Right)
            };
            out.push((p.agent.clone(), split));
        }
    }

    // Split `panes` at the first full-span cut along the chosen axis (vertical=true → x-cut).
    fn guillotine(
        panes: &[AgentRect],
        _bounds: UnitRect,
        vertical: bool,
    ) -> Option<(Vec<AgentRect>, Vec<AgentRect>, f32)> {
        // candidate cut positions = the trailing edge of each pane along the axis.
        let mut cuts: Vec<f32> = panes
            .iter()
            .map(|p| {
                if vertical {
                    rect_right(p.rect)
                } else {
                    rect_bottom(p.rect)
                }
            })
            .collect();
        cuts.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        for cut in cuts {
            let near_max = panes
                .iter()
                .map(|p| {
                    if vertical {
                        rect_right(p.rect)
                    } else {
                        rect_bottom(p.rect)
                    }
                })
                .fold(f32::NEG_INFINITY, f32::max);
            if nearly_eq(cut, near_max) {
                continue; // the outer edge is not an interior cut
            }
            let mut before = Vec::new();
            let mut after = Vec::new();
            let mut clean = true;
            for p in panes {
                let lo = if vertical { p.rect[0] } else { p.rect[1] };
                let hi = if vertical {
                    rect_right(p.rect)
                } else {
                    rect_bottom(p.rect)
                };
                if hi <= cut + RECT_EPS {
                    before.push(p.clone());
                } else if lo >= cut - RECT_EPS {
                    after.push(p.clone());
                } else {
                    clean = false; // a pane straddles this cut → not full-span here
                    break;
                }
            }
            if clean && !before.is_empty() && !after.is_empty() {
                return Some((before, after, cut));
            }
        }
        None
    }

    // The reading-order root agent of a group (top-left-most pane).
    fn left_root_agent(group: &[AgentRect], _bounds: UnitRect, _vertical: bool) -> String {
        group
            .iter()
            .min_by(|a, b| {
                a.rect[1]
                    .partial_cmp(&b.rect[1])
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| {
                        a.rect[0]
                            .partial_cmp(&b.rect[0])
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
            })
            .map(|p| p.agent.clone())
            .unwrap_or_default()
    }

    let mut out = Vec::new();
    collect(panes, [0.0, 0.0, 1.0, 1.0], None, &mut out);
    out
}

/// Survivor geometry after removing one pane (stash/close), as a RECT set per the confirmed stash rule.
/// `Some(rects)` on success; `None` when the live layout can't be reconstructed (corrupt records) so the
/// caller falls back to a flat survivor chain.
fn reduce_pane_rects(layout: &WindowLayout, removing_tab_id: &str) -> Option<Vec<AgentRect>> {
    let mut panes = live_pane_rects(layout)?;
    let removed_pos = panes.iter().position(|p| p.agent == removing_tab_id)?;
    let removed = panes.remove(removed_pos).rect;
    Some(reduce_rects_by_spec(panes, removed))
}

/// The live panes' AUTHORITATIVE rects, read from each pane's persisted `pane_rect`. Falls back to
/// reconstructing from the legacy `split_from` chain (via the canonical model) for OLD records that
/// predate `pane_rect`. `None` when neither is available (no live panes / unreconstructable).
fn live_pane_rects(layout: &WindowLayout) -> Option<Vec<AgentRect>> {
    let live = live_tabs_sorted(layout);
    if live.is_empty() {
        return None;
    }
    // Preferred: every live pane has a persisted rect — use it verbatim (exact, unambiguous).
    if live.iter().all(|t| t.pane_rect.is_some()) {
        return Some(
            live.iter()
                .map(|t| AgentRect {
                    agent: t.tab_id.clone(),
                    rect: t.pane_rect.unwrap().to_unit(),
                })
                .collect(),
        );
    }
    // Legacy fallback: reconstruct from the split_from chain via the canonical model.
    let model = canonical_model_from_live_tabs(&live)?;
    let rects = slot_rects(model.layout, &model.ratios);
    Some(
        model
            .layout
            .slots()
            .iter()
            .zip(rects)
            .filter_map(|(slot, rect)| {
                model.agent_at(*slot).map(|agent| AgentRect {
                    agent: agent.clone(),
                    rect,
                })
            })
            .collect(),
    )
}

/// Apply a pane-remove (stash/close) to `layout`: write the survivor RECT geometry from
/// [`reduce_pane_rects`], or fall back to a flat survivor chain when geometry can't be reconstructed.
fn apply_reduce(layout: &mut WindowLayout, removing_tab_id: &str) {
    match reduce_pane_rects(layout, removing_tab_id) {
        Some(rects) => apply_pane_geometry(layout, &rects),
        None => {
            // Fallback: flat survivor list (each its own root). Clears rects so the renderer falls back.
            let survivors: Vec<(String, Option<SplitFrom>)> = live_tabs_sorted(layout)
                .iter()
                .filter(|t| t.tab_id != removing_tab_id)
                .map(|t| (t.tab_id.clone(), None))
                .collect();
            for (id, _) in &survivors {
                if let Some(tab) = layout.tabs.iter_mut().find(|t| &t.tab_id == id) {
                    tab.pane_rect = None;
                }
            }
            apply_revive_topology(layout, survivors);
        }
    }
}

/// Click-revive placement, applied to rects. Given the EXISTING live panes' rects (the survivors) and a
/// reviving id, produce the new rect set per the confirmed click-revive rule:
///   1:        A            -> A│X                 (new equal-width column on the right)
///   2 cols:   A│B          -> (A/X)│B             (left column splits; X below A)
///   2 rows:   A/B          -> (A│X)/B             (top row splits; X right of A)
///   3 cols:   A│B│C        -> (A/X)│B│C
///   3 rows:   A/B/C        -> (A│X)/B/C
///   left-main A│(B/C)      -> (A│B)/(X│C)         2×2 grid, X bottom-left
///   right-main (A/C)│B     -> (A│B)/(C│X)         2×2 grid, X bottom-right
///   top-main  A/(B│C)      -> (A│X)/(B│C)         2×2 grid, X top-right
///   bottom-main (A│B)/C    -> (A│B)/(C│X)         2×2 grid, X bottom-right
/// The existing panes keep their relative pairing; only the revived pane is new. Returns the survivor +
/// revived rects (tiling the unit square) for `topology_from_rects` to turn into `split_from`.
fn revive_rects_by_spec(existing: &[AgentRect], reviving: &str) -> Vec<AgentRect> {
    let n = existing.len();
    let r = |agent: &str, rect: UnitRect| AgentRect {
        agent: agent.to_string(),
        rect,
    };
    // Reading order (y then x) of the survivors gives A,B,C positions.
    let mut ro: Vec<&AgentRect> = existing.iter().collect();
    ro.sort_by(|a, b| {
        a.rect[1]
            .partial_cmp(&b.rect[1])
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                a.rect[0]
                    .partial_cmp(&b.rect[0])
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });
    let id = |i: usize| ro[i].agent.as_str();

    match n {
        0 => vec![r(reviving, [0.0, 0.0, 1.0, 1.0])],
        1 => vec![
            // A│X
            r(id(0), [0.0, 0.0, 0.5, 1.0]),
            r(reviving, [0.5, 0.0, 0.5, 1.0]),
        ],
        2 => {
            // same row (two columns) vs stacked (two rows)
            let same_row = same_height(ro[0].rect, ro[1].rect);
            if same_row {
                // A│B -> (A/X)│B
                vec![
                    r(id(0), [0.0, 0.0, 0.5, 0.5]),
                    r(reviving, [0.0, 0.5, 0.5, 0.5]),
                    r(id(1), [0.5, 0.0, 0.5, 1.0]),
                ]
            } else {
                // A/B -> (A│X)/B
                vec![
                    r(id(0), [0.0, 0.0, 0.5, 0.5]),
                    r(reviving, [0.5, 0.0, 0.5, 0.5]),
                    r(id(1), [0.0, 0.5, 1.0, 0.5]),
                ]
            }
        }
        3 => {
            let full_h =
                |p: &AgentRect| nearly_eq(p.rect[1], 0.0) && nearly_eq(rect_bottom(p.rect), 1.0);
            let full_w =
                |p: &AgentRect| nearly_eq(p.rect[0], 0.0) && nearly_eq(rect_right(p.rect), 1.0);
            let all_cols = existing.iter().all(full_h);
            let all_rows = existing.iter().all(full_w);
            if all_cols {
                // A│B│C -> (A/X)│B│C  (third = 3 equal columns, left one split)
                let t = 1.0 / 3.0;
                vec![
                    r(id(0), [0.0, 0.0, t, 0.5]),
                    r(reviving, [0.0, 0.5, t, 0.5]),
                    r(id(1), [t, 0.0, t, 1.0]),
                    r(id(2), [2.0 * t, 0.0, t, 1.0]),
                ]
            } else if all_rows {
                // A/B/C -> (A│X)/B/C
                let t = 1.0 / 3.0;
                vec![
                    r(id(0), [0.0, 0.0, 0.5, t]),
                    r(reviving, [0.5, 0.0, 0.5, t]),
                    r(id(1), [0.0, t, 1.0, t]),
                    r(id(2), [0.0, 2.0 * t, 1.0, t]),
                ]
            } else if let Some(main) = existing.iter().find(|p| full_h(p)) {
                // left-main (main on left) or right-main (main on right) -> 2×2 grid.
                let a = main.agent.as_str();
                let mut pair: Vec<&AgentRect> = existing.iter().filter(|p| p.agent != a).collect();
                pair.sort_by(|x, y| {
                    x.rect[1]
                        .partial_cmp(&y.rect[1])
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                let (p, q) = (pair[0].agent.as_str(), pair[1].agent.as_str());
                if main.rect[0] < 0.5 {
                    // left-main A│(B/C) -> (A│B)/(X│C): A tl, B tr, X bl, C br
                    vec![
                        r(a, [0.0, 0.0, 0.5, 0.5]),
                        r(p, [0.5, 0.0, 0.5, 0.5]),
                        r(reviving, [0.0, 0.5, 0.5, 0.5]),
                        r(q, [0.5, 0.5, 0.5, 0.5]),
                    ]
                } else {
                    // right-main (A/C)│B -> (A│B)/(C│X): A tl, B tr, C bl, X br
                    vec![
                        r(p, [0.0, 0.0, 0.5, 0.5]),
                        r(a, [0.5, 0.0, 0.5, 0.5]),
                        r(q, [0.0, 0.5, 0.5, 0.5]),
                        r(reviving, [0.5, 0.5, 0.5, 0.5]),
                    ]
                }
            } else {
                // full-width main -> top-main or bottom-main -> 2×2 grid.
                let main = existing.iter().find(|p| full_w(p)).unwrap();
                let a = main.agent.as_str();
                let mut pair: Vec<&AgentRect> = existing.iter().filter(|p| p.agent != a).collect();
                pair.sort_by(|x, y| {
                    x.rect[0]
                        .partial_cmp(&y.rect[0])
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                let (p, q) = (pair[0].agent.as_str(), pair[1].agent.as_str());
                if main.rect[1] < 0.5 {
                    // top-main A/(B│C) -> (A│X)/(B│C): A tl, X tr, B bl, C br
                    vec![
                        r(a, [0.0, 0.0, 0.5, 0.5]),
                        r(reviving, [0.5, 0.0, 0.5, 0.5]),
                        r(p, [0.0, 0.5, 0.5, 0.5]),
                        r(q, [0.5, 0.5, 0.5, 0.5]),
                    ]
                } else {
                    // bottom-main (A│B)/C -> (A│B)/(C│X): A tl, B tr, C bl, X br
                    vec![
                        r(p, [0.0, 0.0, 0.5, 0.5]),
                        r(q, [0.5, 0.0, 0.5, 0.5]),
                        r(a, [0.0, 0.5, 0.5, 0.5]),
                        r(reviving, [0.5, 0.5, 0.5, 0.5]),
                    ]
                }
            }
        }
        _ => existing
            .iter()
            .cloned()
            .chain(std::iter::once(r(reviving, [0.0, 0.0, 0.0, 0.0])))
            .collect(),
    }
}

/// Click-revive geometry: the existing live panes plus the revived pane, as a RECT set per the confirmed
/// click-revive spec. `Some(rects)` on success; `None` when the existing layout can't be reconstructed
/// (corrupt records) so the caller falls back to a flat chain.
fn revive_pane_rects(
    layout: &WindowLayout,
    existing_live_ids: &[String],
    reviving_tab_id: &str,
) -> Option<Vec<AgentRect>> {
    let existing_set: std::collections::HashSet<&str> =
        existing_live_ids.iter().map(|s| s.as_str()).collect();
    // The existing live panes' authoritative rects (excluding the pane being revived).
    let existing: Vec<AgentRect> = live_pane_rects(layout)?
        .into_iter()
        .filter(|p| existing_set.contains(p.agent.as_str()))
        .collect();
    if existing.len() != existing_live_ids.len() {
        return None;
    }
    Some(revive_rects_by_spec(&existing, reviving_tab_id))
}

/// Apply a revive (or repair) to `layout`: write the rect geometry from [`revive_pane_rects`], or fall
/// back to a flat chain (revived appended right of the first existing pane) when geometry can't be built.
fn apply_revive(layout: &mut WindowLayout, existing_live_ids: &[String], reviving_tab_id: &str) {
    match revive_pane_rects(layout, existing_live_ids, reviving_tab_id) {
        Some(rects) => apply_pane_geometry(layout, &rects),
        None => {
            let mut out = Vec::with_capacity(existing_live_ids.len() + 1);
            for (i, id) in existing_live_ids.iter().enumerate() {
                let split = if i == 0 {
                    None
                } else {
                    split_from_parent(&existing_live_ids[0], SplitAxis::Right)
                };
                out.push((id.clone(), split));
            }
            let parent = existing_live_ids.first().cloned();
            out.push((
                reviving_tab_id.to_string(),
                parent.and_then(|p| split_from_parent(&p, SplitAxis::Right)),
            ));
            for (id, _) in &out {
                if let Some(tab) = layout.tabs.iter_mut().find(|t| &t.tab_id == id) {
                    tab.pane_rect = None;
                }
            }
            apply_revive_topology(layout, out);
        }
    }
}

fn apply_revive_topology(layout: &mut WindowLayout, order: Vec<(String, Option<SplitFrom>)>) {
    for (tab_id, split_from) in &order {
        if let Some(tab) = layout.tabs.iter_mut().find(|t| t.tab_id == *tab_id) {
            tab.split_from = split_from.clone();
        }
    }

    let mut ordered = Vec::with_capacity(layout.tabs.len());
    for (tab_id, _) in &order {
        if let Some(pos) = layout.tabs.iter().position(|t| t.tab_id == *tab_id) {
            ordered.push(layout.tabs.remove(pos));
        }
    }
    let mut rest = std::mem::take(&mut layout.tabs);
    rest.sort_by_key(|t| t.index);
    ordered.extend(rest);
    layout.tabs = ordered;
}

/// Write the AUTHORITATIVE pane geometry from a rect set: set each live pane's `pane_rect` from its
/// `AgentRect`, and ALSO refresh the legacy `split_from` topology (so focus-chain navigation and old
/// readers keep working during the transition). Stashed panes are left with `pane_rect = None`. This is
/// the single funnel every rect-producing op (stash/revive/insert/split/close) routes through, so the
/// persisted rect always matches the computed geometry — the renderer paints it directly, no guessing.
fn apply_pane_geometry(layout: &mut WindowLayout, panes: &[AgentRect]) {
    for p in panes {
        if let Some(tab) = layout.tabs.iter_mut().find(|t| t.tab_id == p.agent) {
            tab.pane_rect = Some(PaneRect::from_unit(p.rect));
        }
    }
    // Keep split_from in sync from the same rects (legacy/focus path).
    let order = topology_from_rects(panes);
    apply_revive_topology(layout, order);
}

/// Like [`apply_pane_geometry`] but GUARDED by the [`rects_tile_unit_square`] invariant: if the proposed
/// rects do not perfectly tile (overlap, gap, or out of bounds), it makes NO change and returns an error
/// so the caller leaves the prior valid layout intact. Every interactive geometry op should write
/// through this so a buggy/unexplored case can never paint overlapping panes.
fn apply_pane_geometry_checked(
    layout: &mut WindowLayout,
    panes: &[AgentRect],
) -> Result<(), WindowLayoutError> {
    if !rects_tile_unit_square(panes) {
        return Err(WindowLayoutError::InvalidTabOrder {
            reason: "proposed pane geometry does not tile the window (overlap/gap)".into(),
        });
    }
    apply_pane_geometry(layout, panes);
    Ok(())
}

fn live_topology_needs_repair(layout: &WindowLayout) -> bool {
    let live_ids: Vec<&str> = layout
        .tabs
        .iter()
        .filter(|tab| !tab.stashed)
        .map(|tab| tab.tab_id.as_str())
        .collect();
    if live_ids.len() <= 1 {
        return false;
    }

    let live_set: std::collections::HashSet<&str> = live_ids.iter().copied().collect();
    let root_count = layout
        .tabs
        .iter()
        .filter(|tab| !tab.stashed && tab.split_from.is_none())
        .count();
    if root_count != 1 {
        return true;
    }

    for tab in layout.tabs.iter().filter(|tab| !tab.stashed) {
        let mut seen = std::collections::HashSet::new();
        let mut current = tab;
        while let Some(split) = current.split_from.as_ref() {
            if split.tab_id == current.tab_id || !seen.insert(current.tab_id.as_str()) {
                return true;
            }
            if !live_set.contains(split.tab_id.as_str()) {
                return true;
            }
            let Some(parent) = layout
                .tabs
                .iter()
                .find(|candidate| candidate.tab_id == split.tab_id && !candidate.stashed)
            else {
                return true;
            };
            current = parent;
        }
    }

    false
}

/// Whether pane-op debug tracing (`PANE-DBG …` on stderr) is enabled. OFF by default because the
/// pane-operation regression suite covers the normal path and per-op output is log noise. Opt back
/// in for debugging with `HYDRA_PANE_DEBUG=1`. Checked once and cached.
pub fn pane_debug_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("HYDRA_PANE_DEBUG")
            .map(|v| !v.is_empty() && v != "0")
            .unwrap_or(false)
    })
}

/// Emit a `PANE-DBG …` stderr line, but ONLY when `HYDRA_PANE_DEBUG` is set (see `pane_debug_enabled`).
/// Keeps the tracing available for debugging without spamming the log in normal use.
macro_rules! pane_dbg {
    ($($arg:tt)*) => {
        if $crate::window_layout::pane_debug_enabled() {
            eprintln!($($arg)*);
        }
    };
}

/// Compact one-line dump of a window's live panes for debugging pane-op bugs. Each pane shows its state
/// (`S`=stashed, `L`=live+rect, `G`=GHOST: live but no rect), its rect, and its split_from parent/axis.
/// Goes to stderr (the Hydra log). Prefixed `PANE-DBG` for easy grepping. No-op unless `HYDRA_PANE_DEBUG`.
fn dbg_panes(op: &str, layout: &WindowLayout) {
    if !pane_debug_enabled() {
        return;
    }
    let parts: Vec<String> = layout
        .tabs
        .iter()
        .map(|t| {
            let state = if t.stashed {
                "S"
            } else if t.pane_rect.is_some() {
                "L"
            } else {
                "G"
            };
            let r = t
                .pane_rect
                .map(|r| format!("{},{},{},{}", r.x, r.y, r.w, r.h))
                .unwrap_or_else(|| "-".into());
            let sf = t
                .split_from
                .as_ref()
                .map(|s| {
                    format!(
                        "{}{}",
                        &s.tab_id,
                        match s.axis {
                            SplitAxis::Right => "→",
                            SplitAxis::Down => "↓",
                        }
                    )
                })
                .unwrap_or_else(|| "root".into());
            format!("{}:{}[{r}]<{sf}", t.tab_id, state)
        })
        .collect();
    eprintln!("PANE-DBG {op}: {}", parts.join("  ")); // already gated by the early return above
}

/// Store-backed manager for one app's window layouts, over an injected [`AppPaths`].
pub struct WindowLayoutService<'a> {
    paths: &'a AppPaths,
}

impl<'a> WindowLayoutService<'a> {
    pub fn new(paths: &'a AppPaths) -> Self {
        WindowLayoutService { paths }
    }

    /// Load the current-version layout for `window_id`.
    ///
    /// - `Ok(None)` — no record on disk yet.
    /// - `Ok(Some(layout))` — a valid current-version layout.
    /// - `Err(FutureVersion/Corrupt)` — surfaced typed; the store left a future record in place
    ///   and quarantined a corrupt one.
    /// - `Err(Store(Id(_)))` — `window_id` is unsafe for a path (refused before any IO).
    pub fn load(&self, window_id: &str) -> Result<Option<WindowLayout>, WindowLayoutError> {
        match store::load_one::<WindowLayout>(self.paths, RecordKind::WindowLayout, window_id)? {
            None => Ok(None),
            Some(LoadOutcome::Loaded(layout)) => Ok(Some(layout)),
            Some(LoadOutcome::FutureVersion { path, ours, got }) => {
                Err(WindowLayoutError::FutureVersion { path, ours, got })
            }
            Some(LoadOutcome::Quarantined {
                original,
                moved_to,
                reason,
            }) => Err(WindowLayoutError::Corrupt {
                original,
                moved_to,
                reason,
            }),
        }
    }

    /// Create and persist an empty layout (`tabs: []`) for `window_id`.
    ///
    /// Refuses to overwrite an existing CURRENT-version layout
    /// ([`WindowLayoutError::WindowLayoutAlreadyExists`]). A future-version or corrupt record is
    /// surfaced as its own typed error rather than silently clobbered.
    pub fn create_empty(
        &self,
        window_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        // Probe first so we never overwrite an existing/newer/corrupt record. `load` maps a
        // future/corrupt record to a typed error, which we propagate.
        if self.load(window_id)?.is_some() {
            return Err(WindowLayoutError::WindowLayoutAlreadyExists {
                window_id: window_id.to_string(),
            });
        }
        let layout = WindowLayout {
            window_id: window_id.to_string(),
            name: None,
            tabs: Vec::new(),
        };
        self.write(&layout, now_ms)?;
        Ok(layout)
    }

    /// Load the layout for `window_id`, creating an empty one if none exists. A future-version or
    /// corrupt record is surfaced (not replaced).
    pub fn load_or_create(
        &self,
        window_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        match self.load(window_id)? {
            Some(layout) => Ok(layout),
            None => self.create_empty(window_id, now_ms),
        }
    }

    /// Replace the current-version layout for `window_id` with an empty window layout.
    ///
    /// This is intentionally narrower than a general delete: it preserves the window record identity and
    /// refuses future-version/corrupt records exactly like [`load`], so a clean-window launch cannot
    /// silently clobber data this build cannot safely understand.
    pub fn replace_empty(
        &self,
        window_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        let _ = self.load(window_id)?;
        let layout = WindowLayout {
            window_id: window_id.to_string(),
            name: None,
            tabs: Vec::new(),
        };
        self.write(&layout, now_ms)?;
        Ok(layout)
    }

    /// Permanently remove a window-layout record. Returns `Ok(true)` when a record was removed and
    /// `Ok(false)` when it was already absent. This is the durable backing for "Remove from shelf":
    /// it removes only the layout/shelf record and does not kill daemon sessions.
    pub fn delete(&self, window_id: &str) -> Result<bool, WindowLayoutError> {
        // FK ON DELETE CASCADE removes this window's tabs. Idempotent (missing id → Ok(false)).
        crate::store::delete_record(self.paths, RecordKind::WindowLayout, window_id)
            .map_err(WindowLayoutError::Store)
    }

    /// Rename the window itself. This is intentionally separate from [`rename_tab`]: window chrome
    /// and pane labels are different product concepts.
    pub fn rename_window(
        &self,
        window_id: &str,
        name: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        let mut layout = self.require(window_id)?;
        layout.name = Some(name.trim().to_string());
        self.normalize_and_write(layout, now_ms)
    }

    /// Open a new tab at the END of the window (its pre-normalization index is `max + 1`), then
    /// renormalize. Fails with [`WindowLayoutError::TabAlreadyExists`] (no rewrite) on a
    /// duplicate `tab_id`, and [`WindowLayoutError::WindowLayoutNotFound`] if the window has no
    /// layout. Does NOT verify `session_id` exists.
    #[allow(clippy::too_many_arguments)]
    pub fn open_tab(
        &self,
        window_id: &str,
        tab_id: &str,
        session_id: &str,
        title: &str,
        pinned: bool,
        attention: AttentionState,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.open_tab_with_stash_state(
            window_id, tab_id, session_id, title, pinned, attention, false, now_ms,
        )
    }

    /// Open a new tab that starts stashed. This is for remote/browser existence records: the pane
    /// belongs under the window in the sidebar, but it must not mutate the local desktop split geometry.
    #[allow(clippy::too_many_arguments)]
    pub fn open_stashed_tab(
        &self,
        window_id: &str,
        tab_id: &str,
        session_id: &str,
        title: &str,
        pinned: bool,
        attention: AttentionState,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.open_tab_with_stash_state(
            window_id, tab_id, session_id, title, pinned, attention, true, now_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn open_tab_with_stash_state(
        &self,
        window_id: &str,
        tab_id: &str,
        session_id: &str,
        title: &str,
        pinned: bool,
        attention: AttentionState,
        stashed: bool,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        let mut layout = self.require(window_id)?;
        if layout.tabs.iter().any(|t| t.tab_id == tab_id) {
            return Err(WindowLayoutError::TabAlreadyExists {
                window_id: window_id.to_string(),
                tab_id: tab_id.to_string(),
            });
        }
        let next_index = layout
            .tabs
            .iter()
            .map(|t| t.index)
            .max()
            .map_or(0, |m| m + 1);
        // Keep pane titles unique within the window (auto-number collisions). The new tab isn't in `tabs` yet, so all
        // current tabs are siblings.
        let sibling_titles: Vec<String> = layout.tabs.iter().map(|t| t.title.clone()).collect();
        let title = crate::unique_name(title, &sibling_titles);
        layout.tabs.push(TabRecord {
            tab_id: tab_id.to_string(),
            session_id: session_id.to_string(),
            index: next_index,
            title,
            pinned,
            attention,
            split_from: None,
            pane_rect: None,
            stashed_from: None,
            stashed,
        });
        self.normalize_and_write(layout, now_ms)
    }

    /// Split an existing tab: add a NEW tab at the end of the window that records it was split
    /// from `from_tab_id` along `axis`. The source tab must exist; the new `tab_id` must not
    /// already exist. Preserves tab order (the new tab lands last, like `open_tab`) and renormalizes
    /// indices. Storage/headless only — no pane geometry, no session spawning, no `session_id`
    /// existence check. Returns the updated layout.
    #[allow(clippy::too_many_arguments)]
    pub fn split_tab(
        &self,
        window_id: &str,
        from_tab_id: &str,
        tab_id: &str,
        session_id: &str,
        title: &str,
        axis: SplitAxis,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        let mut layout = self.require(window_id)?;
        if !layout.tabs.iter().any(|t| t.tab_id == from_tab_id) {
            return Err(WindowLayoutError::TabNotFound {
                window_id: window_id.to_string(),
                tab_id: from_tab_id.to_string(),
            });
        }
        if layout.tabs.iter().any(|t| t.tab_id == tab_id) {
            return Err(WindowLayoutError::TabAlreadyExists {
                window_id: window_id.to_string(),
                tab_id: tab_id.to_string(),
            });
        }
        let next_index = layout
            .tabs
            .iter()
            .map(|t| t.index)
            .max()
            .map_or(0, |m| m + 1);
        // Unique pane title within the window (auto-number collisions). The new tab isn't in `tabs` yet.
        let sibling_titles: Vec<String> = layout.tabs.iter().map(|t| t.title.clone()).collect();
        let title = crate::unique_name(title, &sibling_titles);
        layout.tabs.push(TabRecord {
            tab_id: tab_id.to_string(),
            session_id: session_id.to_string(),
            index: next_index,
            title,
            pinned: false,
            attention: AttentionState::default(),
            split_from: Some(SplitFrom {
                tab_id: from_tab_id.to_string(),
                axis,
                ratio_per_mille: None,
            }),
            pane_rect: None,
            stashed_from: None,
            stashed: false,
        });
        // Persist the AUTHORITATIVE geometry: a split is a LOCAL split of the source pane's rect — the
        // source keeps half, the new pane takes the other half along `axis`. Every other live pane is
        // untouched. Build the live rect set (each pane's existing pane_rect, or the source's full screen
        // on the first split) and write it. This makes split == the same local-split rule as drag/drop.
        let edge = match axis {
            SplitAxis::Right => EdgeDir::Right,
            SplitAxis::Down => EdgeDir::Bottom,
        };
        let mut panes: Vec<AgentRect> = layout
            .tabs
            .iter()
            .filter(|t| !t.stashed && t.tab_id != tab_id)
            .map(|t| AgentRect {
                agent: t.tab_id.clone(),
                rect: t.pane_rect.map_or([0.0, 0.0, 1.0, 1.0], PaneRect::to_unit),
            })
            .collect();
        // Pick the pane to split FROM. Normally it's `from_tab_id`. But a split must operate on a real
        // LIVE pane — if the requested source isn't live (stashed/stale), splitting it would leave the
        // new pane with no rect (an invisible "live" pane). In that case fall back to the largest live
        // pane so the new pane always lands somewhere visible. (If there are NO live panes, the new pane
        // takes the full screen.)
        let src = panes
            .iter()
            .position(|p| p.agent == from_tab_id)
            .or_else(|| {
                // largest-area live pane as the anchor
                panes
                    .iter()
                    .enumerate()
                    .max_by(|(_, a), (_, b)| {
                        (a.rect[2] * a.rect[3])
                            .partial_cmp(&(b.rect[2] * b.rect[3]))
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .map(|(i, _)| i)
            });
        match src {
            Some(src) => {
                let (kept, inserted) = split_rect_local(panes[src].rect, edge);
                panes[src].rect = kept;
                panes.push(AgentRect {
                    agent: tab_id.to_string(),
                    rect: inserted,
                });
            }
            None => {
                // No live panes at all — the new pane is the whole screen.
                panes.push(AgentRect {
                    agent: tab_id.to_string(),
                    rect: [0.0, 0.0, 1.0, 1.0],
                });
            }
        }
        // Write ONLY the rects — keep the direct split_from set at construction (the new pane splits
        // from `from_tab_id` along `axis`). This preserves the canonical split chain that swallow and
        // other split_from readers rely on, while the renderer paints from the authoritative rects.
        for p in &panes {
            if let Some(tab) = layout.tabs.iter_mut().find(|t| t.tab_id == p.agent) {
                tab.pane_rect = Some(PaneRect::from_unit(p.rect));
            }
        }
        self.normalize_and_write(layout, now_ms)
    }

    /// Remove a tab and compact the remaining indices.
    pub fn close_tab(
        &self,
        window_id: &str,
        tab_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        let mut layout = self.require(window_id)?;
        let before = layout.tabs.len();
        layout.tabs.retain(|t| t.tab_id != tab_id);
        if layout.tabs.len() == before {
            return Err(WindowLayoutError::TabNotFound {
                window_id: window_id.to_string(),
                tab_id: tab_id.to_string(),
            });
        }
        self.normalize_and_write(layout, now_ms)
    }

    /// Rename a single tab, preserving order.
    pub fn rename_tab(
        &self,
        window_id: &str,
        tab_id: &str,
        title: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        // Load the layout so we can keep the title unique within the window. Siblings EXCLUDE the tab being renamed, so
        // renaming a pane to its OWN current title is a no-op (no collision → returned verbatim).
        let mut layout = self.require(window_id)?;
        let sibling_titles: Vec<String> = layout
            .tabs
            .iter()
            .filter(|t| t.tab_id != tab_id)
            .map(|t| t.title.clone())
            .collect();
        let unique = crate::unique_name(title, &sibling_titles);
        let tab = layout
            .tabs
            .iter_mut()
            .find(|t| t.tab_id == tab_id)
            .ok_or_else(|| WindowLayoutError::TabNotFound {
                window_id: window_id.to_string(),
                tab_id: tab_id.to_string(),
            })?;
        tab.title = unique;
        self.normalize_and_write(layout, now_ms)
    }

    /// Set a single tab's pinned flag, preserving order.
    pub fn set_pinned(
        &self,
        window_id: &str,
        tab_id: &str,
        pinned: bool,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.mutate_tab(window_id, tab_id, now_ms, |tab| tab.pinned = pinned)
    }

    /// Mark a tab STASHED or revive it, preserving order, index, session, and every other field.
    /// Stashing is the soft alternative to [`close_tab`]: the record is kept (so its session can be
    /// relaunched and its place in the layout remembered) but the renderer hides it from the live
    /// pane layout and the dashboard surfaces it as a dim revive candidate. Reviving (`stashed =
    /// false`) simply clears the flag. An unknown window/tab is a typed error; the layout is
    /// otherwise untouched.
    pub fn set_tab_stashed(
        &self,
        window_id: &str,
        tab_id: &str,
        stashed: bool,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.mutate_tab(window_id, tab_id, now_ms, |tab| tab.stashed = stashed)
    }

    /// Close a single PANE, removing its tab record while keeping the split chain valid. This is the
    /// record edit behind a per-pane close `x`. Unlike [`close_tab`] (a blind `retain`), it first
    /// RE-PARENTS any children of the closed pane onto the closed pane's own parent — or detaches them
    /// to roots (`split_from = None`) when the closed pane was itself a root — so no surviving tab is
    /// left pointing at a vanished parent (the dangling-`split_from` orphan/scramble class). The
    /// canonical renderer replay then re-snaps the survivors into the right smaller layout. An unknown
    /// window/tab is a typed error; the layout is otherwise untouched.
    pub fn close_pane(
        &self,
        window_id: &str,
        tab_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        let mut layout = self.require(window_id)?;
        pane_dbg!("PANE-DBG CLOSE-ENTER tab={tab_id}");
        dbg_panes("CLOSE-BEFORE", &layout);
        let Some(_closing) = layout.tabs.iter().find(|t| t.tab_id == tab_id) else {
            return Err(WindowLayoutError::TabNotFound {
                window_id: window_id.to_string(),
                tab_id: tab_id.to_string(),
            });
        };
        apply_reduce(&mut layout, tab_id);
        layout.tabs.retain(|t| t.tab_id != tab_id);
        self.normalize_and_write(layout, now_ms)
    }

    /// STASH a single pane instead of closing it: the soft close behind a per-pane `x`. The record is
    /// KEPT (its `session_id` is preserved so the live daemon session keeps running and can be
    /// relaunched from the dashboard) but `stashed` is set so the joined window-view strip hides it
    /// from the live layout while the dashboard surfaces it as a revive candidate. Like
    /// [`close_pane`], it RE-PARENTS the stashed pane's children onto the stashed pane's own parent
    /// (or detaches them to roots when the stashed pane was a root) so no survivor dangles at a hidden
    /// parent, and the canonical replay re-snaps survivors into the smaller layout. Refuses to stash
    /// the window's only NON-stashed pane (`CannotStashLastPane`) so a window is never left with an
    /// empty live layout. An unknown window/tab is a typed error.
    pub fn stash_pane(
        &self,
        window_id: &str,
        tab_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        let mut layout = self.require(window_id)?;
        pane_dbg!("PANE-DBG STASH-ENTER tab={tab_id}");
        dbg_panes("STASH-BEFORE", &layout);
        let Some(closing) = layout.tabs.iter().find(|t| t.tab_id == tab_id) else {
            return Err(WindowLayoutError::TabNotFound {
                window_id: window_id.to_string(),
                tab_id: tab_id.to_string(),
            });
        };
        // Guard the last live pane: if this is the only pane not already stashed, stashing it would
        // leave the window with nothing to draw. The caller (or dashboard) handles closing the empty
        // window itself; here we refuse rather than create an empty live layout.
        let live_count = layout.tabs.iter().filter(|t| !t.stashed).count();
        if live_count <= 1 && !closing.stashed {
            return Err(WindowLayoutError::CannotStashLastPane {
                window_id: window_id.to_string(),
                tab_id: tab_id.to_string(),
            });
        }
        let inherited_parent = closing.split_from.clone();
        apply_reduce(&mut layout, tab_id);
        if let Some(tab) = layout.tabs.iter_mut().find(|t| t.tab_id == tab_id) {
            tab.stashed = true;
            tab.stashed_from = inherited_parent.clone();
            // A stashed pane is no longer part of the live split chain; drop its own provenance and live
            // geometry so live rendering never points through a hidden pane. The original provenance is
            // preserved in `stashed_from` for `revive_pane`.
            tab.split_from = None;
            tab.pane_rect = None;
        }
        self.normalize_and_write(layout, now_ms)
    }

    /// REVIVE a stashed pane into the live layout while preserving its session identity.
    ///
    /// This is the layout-aware counterpart to [`set_tab_stashed(false)`]. It first restores the
    /// pane's saved `stashed_from` parent when that parent is still live. If the old parent was closed
    /// or is itself stashed, it falls back to a deterministic four-pane growth rule: the second pane
    /// docks right of the sole survivor, the third docks below the first survivor, and the fourth
    /// docks below a stable right-side/second survivor when available. The transition never revives
    /// beyond four active panes.
    pub fn revive_pane(
        &self,
        window_id: &str,
        tab_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        let mut layout = self.require(window_id)?;
        pane_dbg!("PANE-DBG REVIVE-ENTER tab={tab_id}");
        dbg_panes("REVIVE-BEFORE", &layout);
        let revive_pos = layout
            .tabs
            .iter()
            .position(|t| t.tab_id == tab_id)
            .ok_or_else(|| WindowLayoutError::TabNotFound {
                window_id: window_id.to_string(),
                tab_id: tab_id.to_string(),
            })?;
        if !layout.tabs[revive_pos].stashed {
            return self.normalize_and_write(layout, now_ms);
        }

        let live_tabs: Vec<&TabRecord> = layout
            .tabs
            .iter()
            .filter(|t| !t.stashed && t.tab_id != tab_id)
            .collect();
        if live_tabs.len() >= 4 {
            return Err(WindowLayoutError::InvalidTabOrder {
                reason: format!(
                    "cannot revive pane {tab_id:?}; four live panes are already active"
                ),
            });
        }

        let existing_live_ids = live_tab_ids_for_revive(&layout, tab_id);

        // Compute the revive geometry while the pane is STILL stashed (so live_pane_rects sees only the
        // existing live panes), then unstash and write. apply_revive sets pane_rect for the revived pane.
        // NOTE: apply_revive REORDERS layout.tabs, so the earlier `revive_pos` index is now stale — find
        // the pane by id to unstash it. (This index-staleness left the revived pane stashed → invisible.)
        apply_revive(&mut layout, &existing_live_ids, tab_id);
        if let Some(tab) = layout.tabs.iter_mut().find(|t| t.tab_id == tab_id) {
            tab.stashed = false;
            tab.stashed_from = None;
        }
        self.normalize_and_write(layout, now_ms)
    }

    /// Repair a visible multi-pane window whose live tabs no longer form one connected split tree.
    ///
    /// Older/dev builds could leave several live panes as independent roots (`split_from: null` for
    /// every tab). The dashboard still shows those panes as green/live, but the renderer can only
    /// compose a split frame from one root plus child provenance. This repair preserves tab/session
    /// identities and rewrites only live `split_from` topology into the canonical growth order:
    /// 1 pane = root, 2 = right, 3 = below first column, 4 = filled grid.
    pub fn repair_live_topology(
        &self,
        window_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        let mut layout = self.require(window_id)?;
        if !live_topology_needs_repair(&layout) {
            return Ok(layout);
        }

        let live_ids: Vec<String> = layout
            .tabs
            .iter()
            .filter(|tab| !tab.stashed)
            .map(|tab| tab.tab_id.clone())
            .collect();
        if live_ids.len() > 4 {
            return Err(WindowLayoutError::InvalidTabOrder {
                reason: format!(
                    "cannot repair window {window_id:?}; {} live panes exceeds the 4-pane limit",
                    live_ids.len()
                ),
            });
        }
        let Some((reviving, existing)) = live_ids.split_last() else {
            return Ok(layout);
        };
        apply_revive(&mut layout, existing, reviving);
        self.normalize_and_write(layout, now_ms)
    }

    /// Update a single tab's persisted attention roll-up, preserving order.
    pub fn update_attention(
        &self,
        window_id: &str,
        tab_id: &str,
        attention: AttentionState,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.mutate_tab(window_id, tab_id, now_ms, |tab| tab.attention = attention)
    }

    /// Persist the divider position for a split-child tab as the first/parent side's PER-MILLE share
    /// (`ratio_per_mille`, clamped to `0..=1000`), preserving order. A no-op on a tab that is not a
    /// split child (`split_from` is `None`): there is no divider to persist, so the record is left
    /// unchanged rather than inventing split provenance. An unknown tab id is `TabNotFound`.
    pub fn set_split_ratio(
        &self,
        window_id: &str,
        tab_id: &str,
        ratio_per_mille: u16,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        let clamped = ratio_per_mille.min(1000);
        self.mutate_tab(window_id, tab_id, now_ms, |tab| {
            if let Some(split) = tab.split_from.as_mut() {
                split.ratio_per_mille = Some(clamped);
            }
        })
    }

    /// Write `pane_rect` VERBATIM for each `(tab_id, PaneRect)` in `rects`, then renormalize+write.
    /// This is the persist target for a settled rect-based divider drag: the renderer hands back the
    /// final rects of every pane whose geometry moved, and we store them as-is (no topology recompute —
    /// a divider drag only resizes existing panes, it doesn't change the split tree). Only LIVE
    /// (non-stashed) tabs that are present in the layout are written; unknown ids are ignored so a
    /// stale drag payload can't error or resurrect a closed pane. A missing window is a typed error.
    pub fn set_pane_rects(
        &self,
        window_id: &str,
        rects: &[(String, PaneRect)],
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        let mut layout = self.require(window_id)?;
        for (tab_id, rect) in rects {
            if let Some(tab) = layout
                .tabs
                .iter_mut()
                .find(|t| &t.tab_id == tab_id && !t.stashed)
            {
                tab.pane_rect = Some(*rect);
            }
        }
        // GUARD the resize: the new live geometry MUST still tile. A divider drag that would push a pane
        // over its neighbor (overlap) or leave a gap is refused — panes are separate objects and must
        // never overlap/overflow. The prior valid layout is kept.
        if let Some(live) = live_pane_rects(&layout) {
            if !rects_tile_unit_square(&live) {
                return Err(WindowLayoutError::InvalidTabOrder {
                    reason: "resize would make panes overlap or leave a gap".into(),
                });
            }
        }
        self.normalize_and_write(layout, now_ms)
    }

    /// Point an existing tab at a different `session_id`, preserving every other field (title,
    /// pinned, attention, order, index). Used when a task is resumed: the durable task tab must
    /// follow the task to its newest live session. A missing window/tab is a typed error and the
    /// layout is left unchanged.
    pub fn retarget_tab_session(
        &self,
        window_id: &str,
        tab_id: &str,
        session_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.mutate_tab(window_id, tab_id, now_ms, |tab| {
            tab.session_id = session_id.to_string()
        })
    }

    /// Reorder the window's tabs to match `ordered_tab_ids`, which MUST be an exact permutation
    /// of the current tab ids (every id once, no unknowns, no duplicates). On any violation the
    /// layout is left untouched and [`WindowLayoutError::InvalidTabOrder`] is returned. Indices
    /// are renormalized to the new order.
    pub fn reorder_tabs(
        &self,
        window_id: &str,
        ordered_tab_ids: &[String],
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        let mut layout = self.require(window_id)?;

        if ordered_tab_ids.len() != layout.tabs.len() {
            return Err(WindowLayoutError::InvalidTabOrder {
                reason: format!(
                    "expected {} tab ids, got {}",
                    layout.tabs.len(),
                    ordered_tab_ids.len()
                ),
            });
        }
        // Exact-set check: the requested order must be a permutation of the existing ids. We
        // verify "no duplicates in the request" and "every requested id exists"; with equal
        // lengths those two together imply every existing id appears exactly once.
        let mut seen = std::collections::HashSet::with_capacity(ordered_tab_ids.len());
        for id in ordered_tab_ids {
            if !seen.insert(id.as_str()) {
                return Err(WindowLayoutError::InvalidTabOrder {
                    reason: format!("duplicate tab id {id:?} in requested order"),
                });
            }
            if !layout.tabs.iter().any(|t| &t.tab_id == id) {
                return Err(WindowLayoutError::InvalidTabOrder {
                    reason: format!("unknown tab id {id:?} in requested order"),
                });
            }
        }

        layout.tabs.sort_by_key(|t| {
            ordered_tab_ids
                .iter()
                .position(|id| id == &t.tab_id)
                .expect("every existing id is present in the validated order")
        });
        self.normalize_and_write(layout, now_ms)
    }

    /// Swap the POSITIONS of two existing tabs, leaving every other tab in place. Only the slot
    /// each tab occupies changes; `session_id`, `split_from`, `title`, `pinned`, and `attention`
    /// travel with their tab, so a swap moves layout position without disturbing the running
    /// session, its provenance, or its label. Indices are renormalized to the new order. Both tab
    /// ids must exist and differ; a missing id is [`WindowLayoutError::TabNotFound`] and swapping a
    /// tab with itself is [`WindowLayoutError::InvalidTabOrder`]. On any violation the layout is
    /// left untouched.
    pub fn swap_tab_positions(
        &self,
        window_id: &str,
        tab_id_a: &str,
        tab_id_b: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        let mut layout = self.require(window_id)?;
        if tab_id_a == tab_id_b {
            return Err(WindowLayoutError::InvalidTabOrder {
                reason: format!("cannot swap tab {tab_id_a:?} with itself"),
            });
        }
        let pos_a = layout
            .tabs
            .iter()
            .position(|t| t.tab_id == tab_id_a)
            .ok_or_else(|| WindowLayoutError::TabNotFound {
                window_id: window_id.to_string(),
                tab_id: tab_id_a.to_string(),
            })?;
        let pos_b = layout
            .tabs
            .iter()
            .position(|t| t.tab_id == tab_id_b)
            .ok_or_else(|| WindowLayoutError::TabNotFound {
                window_id: window_id.to_string(),
                tab_id: tab_id_b.to_string(),
            })?;
        layout.tabs.swap(pos_a, pos_b);
        self.normalize_and_write(layout, now_ms)
    }

    /// Swap the two panes' OCCUPANTS — which running session sits in each pane — while leaving the split
    /// TOPOLOGY (every tab's `split_from` provenance, `tab_id`, and `index`) completely fixed. This is the
    /// live-model equivalent of the canonical engine's `PaneLayoutModel::swap_agents`, which swaps slot
    /// ASSIGNMENTS within a fixed slot tree rather than rewiring the tree. The pane regions stay exactly
    /// where they are; only the `session_id`, `title`, `pinned`, and `attention` payloads trade places, so
    /// the two terminals visibly swap positions.
    ///
    /// Why occupant-swap and not provenance-rewrite: the renderer derives N-pane geometry by walking the
    /// `split_from` chain to the root. Rewiring provenance for an arbitrary pair (especially a non-adjacent
    /// ancestor/descendant pair in a 4-pane tree) can orphan an intermediate pane from the root chain,
    /// dropping it from the window. Swapping occupants over a fixed topology is correct for EVERY pair
    /// (disjoint, parent/child, ancestor/descendant) and can never drop a pane, because the chain is
    /// untouched. Unlike [`swap_tab_positions`] (a Vec reorder that is a visual no-op when geometry derives
    /// from provenance), this moves the visible occupant, so the swap is always observable.
    ///
    /// Rejections (layout untouched): a missing id is [`WindowLayoutError::TabNotFound`]; swapping a tab
    /// with itself is [`WindowLayoutError::InvalidTabOrder`].
    pub fn swap_tab_panes(
        &self,
        window_id: &str,
        tab_id_a: &str,
        tab_id_b: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        let mut layout = self.require(window_id)?;
        if tab_id_a == tab_id_b {
            return Err(WindowLayoutError::InvalidTabOrder {
                reason: format!("cannot swap pane {tab_id_a:?} with itself"),
            });
        }
        let pos_a = layout
            .tabs
            .iter()
            .position(|t| t.tab_id == tab_id_a)
            .ok_or_else(|| WindowLayoutError::TabNotFound {
                window_id: window_id.to_string(),
                tab_id: tab_id_a.to_string(),
            })?;
        let pos_b = layout
            .tabs
            .iter()
            .position(|t| t.tab_id == tab_id_b)
            .ok_or_else(|| WindowLayoutError::TabNotFound {
                window_id: window_id.to_string(),
                tab_id: tab_id_b.to_string(),
            })?;
        // Exchange only the OCCUPANT payload between the two panes; `tab_id`, `index`, `split_from`,
        // `stashed`, and `stashed_from` stay put so the split topology is byte-stable. The session,
        // its label, pin, and attention roll-up travel to the other pane's fixed slot.
        let (lo, hi) = if pos_a < pos_b {
            (pos_a, pos_b)
        } else {
            (pos_b, pos_a)
        };
        let (left, right) = layout.tabs.split_at_mut(hi);
        let a = &mut left[lo];
        let b = &mut right[0];
        std::mem::swap(&mut a.session_id, &mut b.session_id);
        std::mem::swap(&mut a.title, &mut b.title);
        std::mem::swap(&mut a.pinned, &mut b.pinned);
        std::mem::swap(&mut a.attention, &mut b.attention);

        self.normalize_and_write(layout, now_ms)
    }

    /// Swallow the split that `tab_id` belongs to WITHOUT killing any pane's session. Two-pane
    /// splits keep the historical behavior: the divider dissolves and both sessions become ordinary
    /// tabs. Three-pane live layouts use the canonical swallow table:
    /// the selected pane re-snaps into the same-pane-count target shape where it becomes the full
    /// row/column main. Sessions, labels, pins, and attention stay attached to their tabs; only
    /// split topology/order changes. Four-pane swallow remains unsupported until the UI exposes an
    /// explicit legal direction.
    ///
    /// `tab_id` must exist ([`WindowLayoutError::TabNotFound`]) and must participate in a split as
    /// either a split child or the parent of one; a tab that is in no split is
    /// [`WindowLayoutError::InvalidTabOrder`] (nothing to swallow). On any violation the layout is
    /// left untouched.
    pub fn swallow_split(
        &self,
        window_id: &str,
        tab_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.swallow_split_with_direction(window_id, tab_id, None, now_ms)
    }

    /// Directional variant of [`swallow_split`], used by the per-pane swallow arrows. Three-pane
    /// layouts apply exactly `direction` and reject illegal direction/slot combinations. Two-pane
    /// splits still dissolve because the historical two-pane action has no directional table.
    pub fn swallow_split_direction(
        &self,
        window_id: &str,
        tab_id: &str,
        direction: SwallowDir,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.swallow_split_with_direction(window_id, tab_id, Some(direction), now_ms)
    }

    fn swallow_split_with_direction(
        &self,
        window_id: &str,
        tab_id: &str,
        direction: Option<SwallowDir>,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        let mut layout = self.require(window_id)?;
        pane_dbg!("PANE-DBG SWALLOW-ENTER tab={tab_id} dir={direction:?}");
        dbg_panes("SWALLOW-BEFORE", &layout);
        if !layout.tabs.iter().any(|t| t.tab_id == tab_id) {
            return Err(WindowLayoutError::TabNotFound {
                window_id: window_id.to_string(),
                tab_id: tab_id.to_string(),
            });
        }

        // Log the canonical model the swallow will read (this is what decides legal directions).
        {
            let live = live_tabs_sorted(&layout);
            match canonical_model_from_live_tabs(&live) {
                Some(m) => pane_dbg!("PANE-DBG SWALLOW-MODEL {:?}", m.layout),
                None => pane_dbg!("PANE-DBG SWALLOW-MODEL none (cannot classify!)"),
            }
        }

        let live = live_tabs_sorted(&layout);
        if live.iter().any(|t| t.tab_id == tab_id) && (live.len() == 3 || live.len() == 4) {
            // LOCAL edge-absorb swallow: the focused pane extends across its edge and eats only the
            // overlapping slice of its neighbor; neighbors keep the rest. Pure rect op — no canonical
            // reshape, so the result is exactly the user's "B grows up, A keeps the part over C and D"
            // model. The arrows pass a direction; a directionless call tries each edge and takes the first
            // clean absorb (stable order: Up, Down, Left, Right).
            let Some(panes) = live_pane_rects(&layout) else {
                return Err(WindowLayoutError::InvalidTabOrder {
                    reason: "live pane geometry unavailable for swallow".into(),
                });
            };
            let all = [
                SwallowDir::Up,
                SwallowDir::Down,
                SwallowDir::Left,
                SwallowDir::Right,
            ];
            let candidates: Vec<SwallowDir> = match direction {
                Some(d) => vec![d],
                None => all.to_vec(),
            };
            let Some((dir, new_rects)) = candidates
                .iter()
                .find_map(|&d| swallow_rect_local(&panes, tab_id, d).map(|r| (d, r)))
            else {
                eprintln!(
                    "PANE-DBG SWALLOW-REJECT tab={tab_id} dir={direction:?} no clean edge-absorb"
                );
                return Err(WindowLayoutError::InvalidTabOrder {
                    reason: format!("tab {tab_id:?} has no legal swallow {direction:?}"),
                });
            };
            pane_dbg!("PANE-DBG SWALLOW-OK tab={tab_id} dir={dir:?}");
            // GUARD: never write geometry that doesn't tile (no overlap/gap/overflow).
            apply_pane_geometry_checked(&mut layout, &new_rects)?;
            return self.normalize_and_write(layout, now_ms);
        }

        // The split child to dissolve: either `tab_id` itself (it is the child) or the child whose
        // `split_from.tab_id` points at `tab_id` (it is the parent). A tab can be the parent of at
        // most one split child in this 2-pane model, so the first match is the frame partner.
        let child_pos = layout.tabs.iter().position(|t| {
            t.tab_id == tab_id && t.split_from.is_some()
                || t.split_from.as_ref().is_some_and(|s| s.tab_id == tab_id)
        });
        let Some(child_pos) = child_pos else {
            return Err(WindowLayoutError::InvalidTabOrder {
                reason: format!("tab {tab_id:?} is not part of a split; nothing to swallow"),
            });
        };
        // 2-pane dissolve: remove the divider (drop the child's split_from). The two panes become
        // independent full-window tabs, so give each the full-screen rect (the rect path then sees a
        // single-member split per tab and correctly draws no divider).
        layout.tabs[child_pos].split_from = None;
        let full = PaneRect {
            x: 0,
            y: 0,
            w: 1000,
            h: 1000,
        };
        for tab in layout.tabs.iter_mut().filter(|t| !t.stashed) {
            tab.pane_rect = Some(full);
        }
        self.normalize_and_write(layout, now_ms)
    }

    /// Dock `source_tab_id` beside `target_tab_id`: re-point the source tab so it becomes the split
    /// child of the target on `axis`, WITHOUT creating or killing any session. This is the record edit
    /// behind an edge drag/drop — the source pane lifts out of wherever it was and re-binds beside the
    /// target. Every field (`session_id`, `title`, `pinned`, `attention`) travels with the source tab;
    /// only its `split_from` provenance changes. The divider ratio resets (`ratio_per_mille: None` =
    /// even) because the split relationship is new. Indices are renormalized.
    ///
    /// When `target_tab_id` already hosts a split child, the dock does NOT reject: it RETARGETS onto
    /// the tail of the target's split chain (the deepest descendant on the `split_from` path) so the
    /// new pane appends as the next canonical growth step (`TwoColumns -> ThreeColumns`, etc.) rather
    /// than forming a forbidden second child of the same parent. This is what lets edge drag/drop grow
    /// a layout past two panes — the canonical engine in `pane_layout.rs` derives the geometry from the
    /// chain, so appending at the tail grows the canonical layout deterministically.
    ///
    /// Rejections (layout left untouched), matching the "never guess an ambiguous drop" rule:
    /// - either tab id missing -> [`WindowLayoutError::TabNotFound`];
    /// - source == target -> [`WindowLayoutError::InvalidTabOrder`] (a pane cannot dock beside itself);
    /// - docking onto a tab inside the source's OWN split subtree would form a cycle
    ///   -> [`WindowLayoutError::InvalidTabOrder`].
    pub fn dock_tab_beside(
        &self,
        window_id: &str,
        source_tab_id: &str,
        target_tab_id: &str,
        axis: SplitAxis,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        let mut layout = self.require(window_id)?;
        if source_tab_id == target_tab_id {
            return Err(WindowLayoutError::InvalidTabOrder {
                reason: format!("cannot dock tab {source_tab_id:?} beside itself"),
            });
        }
        if !layout.tabs.iter().any(|t| t.tab_id == source_tab_id) {
            return Err(WindowLayoutError::TabNotFound {
                window_id: window_id.to_string(),
                tab_id: source_tab_id.to_string(),
            });
        }
        if !layout.tabs.iter().any(|t| t.tab_id == target_tab_id) {
            return Err(WindowLayoutError::TabNotFound {
                window_id: window_id.to_string(),
                tab_id: target_tab_id.to_string(),
            });
        }
        // Cycle guard: the source must not dock anywhere inside its own split subtree, or the chain
        // would loop (source -> ... -> source). Walk the target's `split_from` ancestry; if it passes
        // through the source, reject. This also covers the direct source-is-target-parent case.
        {
            let mut cursor = Some(target_tab_id.to_string());
            for _ in 0..=layout.tabs.len() {
                let Some(cur) = cursor else { break };
                if cur == source_tab_id {
                    return Err(WindowLayoutError::InvalidTabOrder {
                        reason: format!(
                            "cannot dock tab {source_tab_id:?} inside its own split subtree \
                             (target {target_tab_id:?})"
                        ),
                    });
                }
                cursor = layout
                    .tabs
                    .iter()
                    .find(|t| t.tab_id == cur)
                    .and_then(|t| t.split_from.as_ref())
                    .map(|s| s.tab_id.clone());
            }
        }
        // The live 2-pane-per-split model allows one child per parent, but the canonical layout engine
        // grows past two panes by APPENDING to the chain tail. So if the requested target already has a
        // split child, retarget the dock onto the deepest descendant on its chain (skipping the source
        // itself if it happens to be in the way) — the new pane then lands as the next canonical growth
        // step instead of an illegal second child of the same parent.
        let dock_parent = resolve_chain_tail(&layout, target_tab_id, source_tab_id);
        let source = layout
            .tabs
            .iter_mut()
            .find(|t| t.tab_id == source_tab_id)
            .expect("source presence checked above");
        source.split_from = Some(SplitFrom {
            tab_id: dock_parent,
            axis,
            ratio_per_mille: None,
        });
        self.normalize_and_write(layout, now_ms)
    }

    /// Dock `source_tab_id` against the exact edge of `target_tab_id` using the canonical pane-layout
    /// engine. Unlike [`dock_tab_beside`], this preserves the user's chosen edge instead of collapsing
    /// left/right into one axis and appending to the chain tail. It is intended for stashed-pane
    /// drag/drop from the dashboard.
    pub fn dock_tab_at_edge(
        &self,
        window_id: &str,
        source_tab_id: &str,
        target_tab_id: &str,
        edge: EdgeDir,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        let mut layout = self.require(window_id)?;
        pane_dbg!("PANE-DBG DOCK-ENTER src={source_tab_id} target={target_tab_id} edge={edge:?}");
        dbg_panes("DOCK-BEFORE", &layout);
        if source_tab_id == target_tab_id {
            return Err(WindowLayoutError::InvalidTabOrder {
                reason: format!("cannot dock tab {source_tab_id:?} beside itself"),
            });
        }
        if !layout.tabs.iter().any(|t| t.tab_id == source_tab_id) {
            return Err(WindowLayoutError::TabNotFound {
                window_id: window_id.to_string(),
                tab_id: source_tab_id.to_string(),
            });
        }
        if !layout.tabs.iter().any(|t| t.tab_id == target_tab_id) {
            return Err(WindowLayoutError::TabNotFound {
                window_id: window_id.to_string(),
                tab_id: target_tab_id.to_string(),
            });
        }

        let source_is_live = layout
            .tabs
            .iter()
            .find(|tab| tab.tab_id == source_tab_id)
            .is_some_and(|tab| !tab.stashed);
        let mut projected = layout.clone();
        if source_is_live {
            apply_reduce(&mut projected, source_tab_id);
        }

        let live: Vec<&TabRecord> = projected
            .tabs
            .iter()
            .filter(|tab| !tab.stashed && tab.tab_id != source_tab_id)
            .collect();
        if live.is_empty() || live.len() >= 4 {
            return Err(WindowLayoutError::InvalidTabOrder {
                reason: format!(
                    "cannot dock tab {source_tab_id:?}: live target set has {} panes",
                    live.len()
                ),
            });
        }

        // INSERT = a LOCAL split of the TARGET pane's own rectangle (confirmed drag/drop spec,
        // described by the public placement rules above). Read the target set's AUTHORITATIVE rects (source already
        // removed by apply_reduce above), split the target rect in half along the dropped edge — source
        // takes the dropped side, target keeps the other. Only the target pane subdivides; every other
        // pane is untouched.
        let mut panes =
            live_pane_rects(&projected).ok_or_else(|| WindowLayoutError::InvalidTabOrder {
                reason: "current live pane geometry is unavailable".into(),
            })?;
        panes.retain(|p| p.agent != source_tab_id);
        let Some(target) = panes.iter().position(|p| p.agent == target_tab_id) else {
            return Err(WindowLayoutError::InvalidTabOrder {
                reason: format!("target tab {target_tab_id:?} is not live"),
            });
        };
        let t = panes[target].rect;
        let (kept, inserted) = split_rect_local(t, edge);
        panes[target].rect = kept;
        panes.push(AgentRect {
            agent: source_tab_id.to_string(),
            rect: inserted,
        });

        if let Some(source) = layout
            .tabs
            .iter_mut()
            .find(|tab| tab.tab_id == source_tab_id)
        {
            source.stashed = false;
            source.stashed_from = None;
        }
        // GUARD: a dock must produce a clean tiling (no overlap/gap).
        apply_pane_geometry_checked(&mut layout, &panes)?;
        self.normalize_and_write(layout, now_ms)
    }

    /// Read-only projection: the window's tabs (sorted by index), each joined with the
    /// task report. A tab is linked to a task when some reconciled task's `current_session_id`
    /// equals the tab's `session_id`; that task contributes `agent_task_id`, `agent_task_state`,
    /// `session_status`, `session_record_missing`, and its `needs_attention`.
    ///
    /// Limitation (documented, intentional): the task report is task-centric, so a tab whose
    /// session is NOT the current session of any task gets no `session_status` here even if a
    /// `SessionRecord` exists on disk. This projection joins only the current task sessions the
    /// existing report provides.
    pub fn tab_view(
        &self,
        window_id: &str,
        task_report: &AgentTaskReconcileReport,
    ) -> Result<Vec<WindowTabView>, WindowLayoutError> {
        let layout = self.require(window_id)?;
        let mut tabs = layout.tabs;
        tabs.sort_by_key(|t| t.index);

        let views = tabs
            .into_iter()
            .map(|tab| {
                let linked = task_report
                    .tasks
                    .iter()
                    .find(|t| t.current_session_id.as_deref() == Some(tab.session_id.as_str()));
                let needs_attention = tab_needs_attention(
                    &tab.attention,
                    linked.map(|t| t.needs_attention).unwrap_or(false),
                );
                WindowTabView {
                    tab_id: tab.tab_id,
                    session_id: tab.session_id,
                    index: tab.index,
                    title: tab.title,
                    pinned: tab.pinned,
                    attention: tab.attention,
                    session_status: linked.and_then(|t| t.current_session_status),
                    agent_task_id: linked.map(|t| t.agent_task_id.clone()),
                    agent_task_state: linked.map(|t| t.state),
                    needs_attention,
                    session_record_missing: linked
                        .map(|t| t.session_record_missing)
                        .unwrap_or(false),
                    split_from: tab.split_from,
                    pane_rect: tab.pane_rect,
                    stashed: tab.stashed,
                }
            })
            .collect();
        Ok(views)
    }

    // --- internals ---

    /// Load the layout or fail with `WindowLayoutNotFound` (future/corrupt propagate as typed).
    fn require(&self, window_id: &str) -> Result<WindowLayout, WindowLayoutError> {
        self.load(window_id)?
            .ok_or_else(|| WindowLayoutError::WindowLayoutNotFound {
                window_id: window_id.to_string(),
            })
    }

    /// Find a tab by id, apply `edit`, then renormalize+write. Order is preserved (only the named
    /// tab is touched); indices are renormalized for consistency even though a field edit cannot
    /// change order.
    fn mutate_tab(
        &self,
        window_id: &str,
        tab_id: &str,
        now_ms: u64,
        edit: impl FnOnce(&mut TabRecord),
    ) -> Result<WindowLayout, WindowLayoutError> {
        let mut layout = self.require(window_id)?;
        let tab = layout
            .tabs
            .iter_mut()
            .find(|t| t.tab_id == tab_id)
            .ok_or_else(|| WindowLayoutError::TabNotFound {
                window_id: window_id.to_string(),
                tab_id: tab_id.to_string(),
            })?;
        edit(tab);
        self.normalize_and_write(layout, now_ms)
    }

    /// Renormalize tab indices to a contiguous `0..n` run in current vec order, then write.
    fn normalize_and_write(
        &self,
        mut layout: WindowLayout,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        for (i, tab) in layout.tabs.iter_mut().enumerate() {
            tab.index = i as u32;
        }
        dbg_panes("WRITE", &layout);
        self.write(&layout, now_ms)?;
        Ok(layout)
    }

    fn write(&self, layout: &WindowLayout, now_ms: u64) -> Result<(), WindowLayoutError> {
        store::write_record(
            self.paths,
            RecordKind::WindowLayout,
            &layout.window_id,
            now_ms,
            layout,
        )?;
        Ok(())
    }
}

/// The projected `needs_attention`: true if the persisted tab attention is a real (non-`None`)
/// unseen signal, OR the joined task report flagged the task. Pure.
fn tab_needs_attention(persisted: &AttentionState, task_needs_attention: bool) -> bool {
    task_needs_attention || (persisted.unseen && persisted.attention != Attention::None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_task_reconcile::ReconciledAgentTask;
    use crate::records::AttentionSource;
    use tempfile::TempDir;

    fn temp_paths() -> (TempDir, AppPaths) {
        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::with_base(tmp.path().join("Maestro"));
        (tmp, paths)
    }

    fn svc(paths: &AppPaths) -> WindowLayoutService<'_> {
        WindowLayoutService::new(paths)
    }

    fn attn(attention: Attention, unseen: bool) -> AttentionState {
        AttentionState {
            attention,
            unseen,
            since_ms: 0,
            source: AttentionSource::Process,
        }
    }

    /// Regression: reviving a stashed pane into a 3-pane layout must leave the revived pane LIVE (not
    /// stashed) AND placed per the click-revive spec. A stale tab index after the geometry reorder used
    /// to leave the revived pane stashed → invisible (it had a rect but never un-stashed).
    #[test]
    fn revive_into_three_pane_layouts_makes_revived_pane_live_and_placed() {
        type Split = (&'static str, &'static str, SplitAxis);
        type ReviveCase = (&'static str, &'static [Split], (u16, u16, u16, u16));
        let cases: &[ReviveCase] = &[
            // (label, splits building the 3-pane layout, expected X rect after revive)
            // A│(B/C) left-main → (A│B)/(X│C): X bottom-LEFT.
            (
                "leftMain",
                &[("a", "b", SplitAxis::Right), ("b", "c", SplitAxis::Down)],
                (0, 500, 500, 500),
            ),
            // A/(B│C) top-main → (A│X)/(B│C): X top-RIGHT.
            (
                "topMain",
                &[("a", "b", SplitAxis::Down), ("b", "c", SplitAxis::Right)],
                (500, 0, 500, 500),
            ),
        ];
        for (label, splits, want_x) in cases {
            let (_tmp, paths) = temp_paths();
            let s = svc(&paths);
            s.create_empty("w1", 1).unwrap();
            s.open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
                .unwrap();
            for (idx, (from, new, axis)) in splits.iter().enumerate() {
                s.split_tab(
                    "w1",
                    from,
                    new,
                    &format!("s{new}"),
                    new,
                    *axis,
                    3 + idx as u64,
                )
                .unwrap();
            }
            s.open_tab("w1", "x", "sx", "X", false, attn(Attention::None, false), 9)
                .unwrap();
            s.set_tab_stashed("w1", "x", true, 10).unwrap();
            let l = s.revive_pane("w1", "x", 11).unwrap();
            let x = l.tabs.iter().find(|t| t.tab_id == "x").unwrap();
            assert!(!x.stashed, "{label}: revived X must be LIVE, not stashed");
            assert_eq!(
                x.pane_rect.map(|r| (r.x, r.y, r.w, r.h)),
                Some(*want_x),
                "{label}: revived X placed per spec"
            );
            let live = l.tabs.iter().filter(|t| !t.stashed).count();
            assert_eq!(live, 4, "{label}: all four panes live after revive");
        }
    }

    fn tab_ids(layout: &WindowLayout) -> Vec<String> {
        layout.tabs.iter().map(|t| t.tab_id.clone()).collect()
    }

    fn indices(layout: &WindowLayout) -> Vec<u32> {
        layout.tabs.iter().map(|t| t.index).collect()
    }

    /// The window's CURRENT stored layout value, loaded through the service. Used by the
    /// "rejects X without rewrite" tests to compare the persisted `WindowLayout` before/after a
    /// refused op — the SQLite-store analog of the old byte-for-byte `fs::read(layout_path(..))`
    /// comparison (records are DB rows now, not JSON files, so we compare the loaded value).
    fn stored(paths: &AppPaths, window_id: &str) -> WindowLayout {
        svc(paths).load(window_id).unwrap().unwrap()
    }

    fn reconciled(
        agent_task_id: &str,
        state: AgentTaskState,
        current_session_id: Option<&str>,
        current_session_status: Option<SessionStatus>,
        session_record_missing: bool,
        needs_attention: bool,
    ) -> ReconciledAgentTask {
        ReconciledAgentTask {
            agent_task_id: agent_task_id.into(),
            state,
            current_session_id: current_session_id.map(str::to_string),
            current_session_status,
            session_record_missing,
            needs_attention,
        }
    }

    #[test]
    fn create_empty_writes_expected_layout() {
        let (_tmp, paths) = temp_paths();
        let layout = svc(&paths).create_empty("w1", 5).unwrap();
        assert_eq!(layout.window_id, "w1");
        assert!(layout.tabs.is_empty());

        // Round-trips from disk.
        let reloaded = svc(&paths).load("w1").unwrap().unwrap();
        assert_eq!(reloaded, layout);
    }

    #[test]
    fn create_refuses_overwrite() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        let err = svc(&paths).create_empty("w1", 2).unwrap_err();
        assert!(matches!(
            err,
            WindowLayoutError::WindowLayoutAlreadyExists { .. }
        ));
    }

    #[test]
    fn load_or_create_creates_then_loads() {
        let (_tmp, paths) = temp_paths();
        let created = svc(&paths).load_or_create("w1", 1).unwrap();
        assert!(created.tabs.is_empty());
        // Second call loads the same one (does not error on already-exists).
        let loaded = svc(&paths).load_or_create("w1", 2).unwrap();
        assert_eq!(loaded, created);
    }

    #[test]
    fn replace_empty_overwrites_current_window_with_no_tabs() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "t1",
                "s1",
                "one",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();

        let replaced = svc(&paths).replace_empty("w1", 3).unwrap();
        assert_eq!(replaced.window_id, "w1");
        assert!(replaced.tabs.is_empty());
        assert_eq!(svc(&paths).load("w1").unwrap().unwrap(), replaced);
    }

    #[test]
    fn unsafe_window_id_is_rejected_before_write() {
        let (_tmp, paths) = temp_paths();
        for bad in ["../escape", "a/b", "..", "/abs", "x y"] {
            let r = svc(&paths).create_empty(bad, 1);
            assert!(
                matches!(r, Err(WindowLayoutError::Store(StoreError::Id(_)))),
                "create_empty({bad:?}) must be refused, got {r:?}"
            );
        }
        // Nothing escaped the base.
        assert!(!_tmp.path().join("escape").exists());
    }

    #[test]
    fn unsafe_tab_id_does_not_corrupt_layout() {
        // A tab_id is stored INSIDE the layout (it is not a path component), so it is not a path
        // escape; but an open with an existing/duplicate guard still applies. This documents that
        // tab ids are free-form and never reach the filesystem.
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        let layout = svc(&paths)
            .open_tab(
                "w1",
                "tab/with/slashes",
                "s1",
                "t",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();
        assert_eq!(tab_ids(&layout), vec!["tab/with/slashes"]);
    }

    #[test]
    fn open_tab_appends_and_normalizes_indices() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "b", "sb", "B", true, attn(Attention::None, false), 3)
            .unwrap();
        let layout = svc(&paths)
            .open_tab("w1", "c", "sc", "C", false, attn(Attention::None, false), 4)
            .unwrap();
        assert_eq!(tab_ids(&layout), vec!["a", "b", "c"]);
        assert_eq!(indices(&layout), vec![0, 1, 2]);
    }

    #[test]
    fn duplicate_tab_open_fails_without_rewrite() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        let before = stored(&paths, "w1");
        let err = svc(&paths)
            .open_tab(
                "w1",
                "a",
                "sa2",
                "A2",
                true,
                attn(Attention::Error, true),
                3,
            )
            .unwrap_err();
        assert!(matches!(err, WindowLayoutError::TabAlreadyExists { .. }));
        // Byte-identical: the failed open rewrote nothing.
        assert_eq!(stored(&paths, "w1"), before);
    }

    #[test]
    fn close_tab_compacts_indices() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        for (id, s) in [("a", "sa"), ("b", "sb"), ("c", "sc")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        let layout = svc(&paths).close_tab("w1", "b", 5).unwrap();
        assert_eq!(tab_ids(&layout), vec!["a", "c"]);
        assert_eq!(indices(&layout), vec![0, 1]);
    }

    #[test]
    fn close_missing_tab_errors_without_rewrite() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        let before = stored(&paths, "w1");
        let err = svc(&paths).close_tab("w1", "nope", 3).unwrap_err();
        assert!(matches!(err, WindowLayoutError::TabNotFound { .. }));
        assert_eq!(stored(&paths, "w1"), before);
    }

    #[test]
    fn rename_pin_attention_update_only_intended_tab_and_preserve_order() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        for (id, s) in [("a", "sa"), ("b", "sb"), ("c", "sc")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        svc(&paths).rename_tab("w1", "b", "Renamed B", 3).unwrap();
        svc(&paths).set_pinned("w1", "b", true, 4).unwrap();
        let layout = svc(&paths)
            .update_attention("w1", "b", attn(Attention::NeedsInput, true), 5)
            .unwrap();

        assert_eq!(tab_ids(&layout), vec!["a", "b", "c"], "order preserved");
        assert_eq!(indices(&layout), vec![0, 1, 2]);
        let a = &layout.tabs[0];
        let b = &layout.tabs[1];
        let c = &layout.tabs[2];
        assert_eq!(b.title, "Renamed B");
        assert!(b.pinned);
        assert_eq!(b.attention.attention, Attention::NeedsInput);
        assert!(b.attention.unseen);
        // Siblings untouched.
        assert_eq!(a.title, "a");
        assert!(!a.pinned);
        assert_eq!(a.attention.attention, Attention::None);
        assert_eq!(c.title, "c");
        assert!(!c.pinned);
    }

    #[test]
    fn close_deletes_the_tab_row_but_stash_keeps_it() {
        // The DB payoff for panes: closing a pane DELETES its tab row (gone for good); stashing KEEPS the row with
        // stashed=1 (revivable). "Closed things gone, stashed things kept."
        let (_tmp, paths) = temp_paths();
        let s = svc(&paths);
        s.create_empty("w1", 1).unwrap();
        for (id, sess) in [("a", "sa"), ("b", "sb"), ("c", "sc")] {
            s.open_tab("w1", id, sess, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        let row_count = |window: &str| -> i64 {
            let arc = crate::db::conn_for(paths.base()).unwrap();
            let conn = arc.lock().unwrap();
            conn.query_row(
                "SELECT COUNT(*) FROM tabs WHERE window_id = ?1",
                [window],
                |r| r.get(0),
            )
            .unwrap()
        };
        let stashed_flag = |tab: &str| -> bool {
            let arc = crate::db::conn_for(paths.base()).unwrap();
            let conn = arc.lock().unwrap();
            conn.query_row("SELECT stashed FROM tabs WHERE tab_id = ?1", [tab], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap()
                != 0
        };
        assert_eq!(row_count("w1"), 3);
        // Stash 'a' → its row survives with stashed=1.
        s.stash_pane("w1", "a", 3).unwrap();
        assert_eq!(row_count("w1"), 3, "stash keeps the row");
        assert!(stashed_flag("a"), "stashed pane row has stashed=1");
        // Close 'b' → its row is deleted.
        s.close_tab("w1", "b", 4).unwrap();
        assert_eq!(row_count("w1"), 2, "close deletes the tab row");
        let after = s.load("w1").unwrap().unwrap();
        assert!(
            after.tabs.iter().all(|t| t.tab_id != "b"),
            "closed pane is gone"
        );
        assert!(
            after.tabs.iter().any(|t| t.tab_id == "a" && t.stashed),
            "stashed pane persists"
        );
    }

    #[test]
    fn set_tab_stashed_marks_and_revives_only_intended_tab_preserving_order() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        for (id, s) in [("a", "sa"), ("b", "sb"), ("c", "sc")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        // Fresh tabs are never stashed.
        let opened = svc(&paths).load("w1").unwrap().unwrap();
        assert!(opened.tabs.iter().all(|t| !t.stashed));

        // Stash "b": flag flips, nothing else moves, sibling tabs stay live.
        let stashed = svc(&paths).set_tab_stashed("w1", "b", true, 3).unwrap();
        assert_eq!(tab_ids(&stashed), vec!["a", "b", "c"], "order preserved");
        assert_eq!(indices(&stashed), vec![0, 1, 2]);
        assert!(stashed.tabs[1].stashed);
        assert!(!stashed.tabs[0].stashed);
        assert!(!stashed.tabs[2].stashed);
        // The session id is preserved so the stashed tab can be relaunched.
        assert_eq!(stashed.tabs[1].session_id, "sb");

        // Revive "b": flag clears.
        let revived = svc(&paths).set_tab_stashed("w1", "b", false, 4).unwrap();
        assert!(!revived.tabs[1].stashed);
        assert_eq!(tab_ids(&revived), vec!["a", "b", "c"]);
    }

    #[test]
    fn set_tab_stashed_missing_tab_errors() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        let err = svc(&paths)
            .set_tab_stashed("w1", "ghost", true, 2)
            .unwrap_err();
        assert!(matches!(err, WindowLayoutError::TabNotFound { .. }));
    }

    #[test]
    fn mutate_missing_tab_errors() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        let err = svc(&paths).rename_tab("w1", "ghost", "x", 2).unwrap_err();
        assert!(matches!(err, WindowLayoutError::TabNotFound { .. }));
    }

    #[test]
    fn retarget_tab_session_changes_only_session_id_and_preserves_everything_else() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        for (id, s) in [("a", "sa"), ("b", "sb"), ("c", "sc")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        // Give "b" a distinctive title/pinned/attention to prove they survive the retarget.
        svc(&paths).rename_tab("w1", "b", "Renamed B", 3).unwrap();
        svc(&paths).set_pinned("w1", "b", true, 4).unwrap();
        svc(&paths)
            .update_attention("w1", "b", attn(Attention::NeedsInput, true), 5)
            .unwrap();

        let layout = svc(&paths)
            .retarget_tab_session("w1", "b", "sb-new", 6)
            .unwrap();

        assert_eq!(tab_ids(&layout), vec!["a", "b", "c"], "order preserved");
        assert_eq!(indices(&layout), vec![0, 1, 2]);
        let b = &layout.tabs[1];
        assert_eq!(b.session_id, "sb-new", "session retargeted");
        // Everything else preserved.
        assert_eq!(b.title, "Renamed B");
        assert!(b.pinned);
        assert_eq!(b.attention.attention, Attention::NeedsInput);
        assert!(b.attention.unseen);
        // Siblings untouched (including their session ids).
        assert_eq!(layout.tabs[0].session_id, "sa");
        assert_eq!(layout.tabs[2].session_id, "sc");
    }

    #[test]
    fn retarget_missing_window_or_tab_errors_typed_without_rewrite() {
        let (_tmp, paths) = temp_paths();
        // Missing window.
        let err = svc(&paths)
            .retarget_tab_session("nope", "a", "s", 1)
            .unwrap_err();
        assert!(matches!(
            err,
            WindowLayoutError::WindowLayoutNotFound { .. }
        ));

        // Missing tab leaves the layout byte-identical.
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        let before = stored(&paths, "w1");
        let err = svc(&paths)
            .retarget_tab_session("w1", "ghost", "s", 3)
            .unwrap_err();
        assert!(matches!(err, WindowLayoutError::TabNotFound { .. }));
        assert_eq!(stored(&paths, "w1"), before);
    }

    #[test]
    fn reorder_exact_set_succeeds_and_normalizes() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        for (id, s) in [("a", "sa"), ("b", "sb"), ("c", "sc")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        let order = vec!["c".to_string(), "a".to_string(), "b".to_string()];
        let layout = svc(&paths).reorder_tabs("w1", &order, 5).unwrap();
        assert_eq!(tab_ids(&layout), vec!["c", "a", "b"]);
        assert_eq!(indices(&layout), vec![0, 1, 2]);
    }

    #[test]
    fn reorder_missing_unknown_or_duplicate_fails_without_rewrite() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        for (id, s) in [("a", "sa"), ("b", "sb"), ("c", "sc")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        let before = stored(&paths, "w1");

        // Wrong length (missing an id).
        let missing = vec!["a".to_string(), "b".to_string()];
        assert!(matches!(
            svc(&paths).reorder_tabs("w1", &missing, 5).unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));
        // Unknown id (same length).
        let unknown = vec!["a".to_string(), "b".to_string(), "z".to_string()];
        assert!(matches!(
            svc(&paths).reorder_tabs("w1", &unknown, 5).unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));
        // Duplicate id (same length).
        let dup = vec!["a".to_string(), "a".to_string(), "b".to_string()];
        assert!(matches!(
            svc(&paths).reorder_tabs("w1", &dup, 5).unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));

        assert_eq!(
            stored(&paths, "w1"),
            before,
            "no failed reorder rewrote the layout"
        );
    }

    #[test]
    fn swap_tab_positions_swaps_slots_and_preserves_identity() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        for (id, s) in [("a", "sa"), ("b", "sb"), ("c", "sc")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        // Give "c" split provenance so we can prove it travels with the tab through a swap.
        svc(&paths)
            .split_tab("w1", "a", "d", "sd", "D", SplitAxis::Right, 2)
            .unwrap();

        let layout = svc(&paths).swap_tab_positions("w1", "a", "c", 5).unwrap();
        // Positions swap; the rest stay put. Indices renormalize to the new vec order.
        assert_eq!(tab_ids(&layout), vec!["c", "b", "a", "d"]);
        assert_eq!(indices(&layout), vec![0, 1, 2, 3]);

        // session_id travels with each tab (a swap moves position, not the running session).
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(by_id("a").session_id, "sa");
        assert_eq!(by_id("c").session_id, "sc");
        // split provenance is untouched by a position swap of unrelated tabs.
        assert!(by_id("d").split_from.is_some());
    }

    #[test]
    fn swap_tab_panes_swaps_occupants_and_leaves_topology_fixed() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        // Build: root "a" with child "b" (a|b). Then a separate root "c" with child "d" (c|d).
        svc(&paths)
            .open_tab("w1", "a", "sa", "a", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "b", SplitAxis::Right, 2)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "c", "sc", "c", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "c", "d", "sd", "d", SplitAxis::Down, 2)
            .unwrap();
        let before = svc(&paths).require("w1").unwrap();

        // Swap occupants of panes b and c. The pane TOPOLOGY (every split_from) must be byte-identical;
        // only the occupant session/title trades between the two fixed slots.
        let layout = svc(&paths).swap_tab_panes("w1", "b", "c", 5).unwrap();
        let from = |l: &WindowLayout, id: &str| {
            l.tabs
                .iter()
                .find(|t| t.tab_id == id)
                .unwrap()
                .split_from
                .clone()
        };
        for id in ["a", "b", "c", "d"] {
            assert_eq!(
                from(&layout, id),
                from(&before, id),
                "topology of {id} must be unchanged by an occupant swap"
            );
        }
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        // The sessions traded slots: pane "b" now hosts c's session and vice versa.
        assert_eq!(by_id("b").session_id, "sc");
        assert_eq!(by_id("c").session_id, "sb");
        // The other two panes are untouched.
        assert_eq!(by_id("a").session_id, "sa");
        assert_eq!(by_id("d").session_id, "sd");
    }

    #[test]
    fn swap_tab_panes_parent_child_swaps_occupants() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        // root "a", child "b" split Right (a is outer/parent, b is inner/child).
        svc(&paths)
            .open_tab("w1", "a", "sa", "a", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "b", SplitAxis::Right, 2)
            .unwrap();
        let before = svc(&paths).require("w1").unwrap();

        let layout = svc(&paths).swap_tab_panes("w1", "a", "b", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        // Topology fixed: "a" stays root, "b" stays its child; only the occupants trade.
        let from = |l: &WindowLayout, id: &str| {
            l.tabs
                .iter()
                .find(|t| t.tab_id == id)
                .unwrap()
                .split_from
                .clone()
        };
        assert_eq!(from(&layout, "a"), from(&before, "a"));
        assert_eq!(from(&layout, "b"), from(&before, "b"));
        assert_eq!(by_id("a").session_id, "sb");
        assert_eq!(by_id("b").session_id, "sa");
    }

    #[test]
    fn swap_tab_panes_is_observable_in_the_three_pane_regression_case() {
        // The exact case the directional arrows hit and `swap_tab_positions` left a no-op:
        // left | (rt / rb). Swapping left <-> rb must MOVE the visible occupant while keeping topology.
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "left",
                "sl",
                "left",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();
        svc(&paths)
            .split_tab("w1", "left", "rt", "srt", "rt", SplitAxis::Right, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "rt", "rb", "srb", "rb", SplitAxis::Down, 2)
            .unwrap();
        let before = svc(&paths).require("w1").unwrap();
        let sess = |l: &WindowLayout, id: &str| {
            l.tabs
                .iter()
                .find(|t| t.tab_id == id)
                .unwrap()
                .session_id
                .clone()
        };
        let layout = svc(&paths).swap_tab_panes("w1", "left", "rb", 5).unwrap();
        // Observable: the two panes' occupants traded (the old position-swap left this byte-identical).
        assert_ne!(
            sess(&before, "left"),
            sess(&layout, "left"),
            "left pane's occupant must change"
        );
        assert_eq!(sess(&layout, "left"), "srb");
        assert_eq!(sess(&layout, "rb"), "sl");
        // Topology untouched.
        let from = |l: &WindowLayout, id: &str| {
            l.tabs
                .iter()
                .find(|t| t.tab_id == id)
                .unwrap()
                .split_from
                .clone()
        };
        for id in ["left", "rt", "rb"] {
            assert_eq!(from(&layout, id), from(&before, id));
        }
    }

    #[test]
    fn canonical_live_replay_matches_ordered_renderer_splits() {
        // Renderer split replay inserts a new pane next to the active source, not at the
        // append/end slot. Shell mutation paths must read records the same way or pane header
        // arrows can swallow/swap the wrong visual slot.
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "c", "sc", "C", SplitAxis::Right, 4)
            .unwrap();

        let layout = svc(&paths).require("w1").unwrap();
        let live = live_tabs_sorted(&layout);
        let model = canonical_model_from_live_tabs(&live).expect("canonical topology");
        assert_eq!(model.layout, CanonicalLayout::ThreeColumns);
        assert_eq!(model.agent_at(SlotId::S0), Some(&"a".to_string()));
        assert_eq!(model.agent_at(SlotId::S1), Some(&"c".to_string()));
        assert_eq!(model.agent_at(SlotId::S2), Some(&"b".to_string()));
    }

    #[test]
    fn repro_four_pane_second_row_swap_keeps_all_panes_in_chain() {
        // 2x2 grid built the way the app does: root tl; tr=split-right(tl); bl=split-down(tl);
        // br=split-down(tr). Chain: tl(root) <- tr(tl,Right), bl(tl,Down), br(tr,Down).
        // Second row = bl, br. Swapping them must keep ALL FOUR reachable from the root.
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "tl",
                "stl",
                "tl",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();
        svc(&paths)
            .split_tab("w1", "tl", "tr", "str", "tr", SplitAxis::Right, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "tl", "bl", "sbl", "bl", SplitAxis::Down, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "tr", "br", "sbr", "br", SplitAxis::Down, 2)
            .unwrap();

        let layout = svc(&paths).swap_tab_panes("w1", "bl", "br", 5).unwrap();
        // Reachability: every tab must walk split_from up to the root "tl".
        let reaches_root = |id: &str| {
            let mut cur = id.to_string();
            for _ in 0..layout.tabs.len() + 1 {
                if cur == "tl" {
                    return true;
                }
                match layout
                    .tabs
                    .iter()
                    .find(|t| t.tab_id == cur)
                    .and_then(|t| t.split_from.as_ref())
                {
                    Some(s) => cur = s.tab_id.clone(),
                    None => return cur == "tl",
                }
            }
            false
        };
        for id in ["tl", "tr", "bl", "br"] {
            assert!(
                reaches_root(id),
                "pane {id} dropped out of the root chain after swap"
            );
        }
    }

    #[test]
    fn repro_four_pane_grandparent_swap_keeps_all_panes_in_chain() {
        // Linear chain (split-right, then split-down on the new pane, etc.):
        // tl(root) <- a(tl,Right) <- b(a,Down) <- c(b,Right). Swap a NON-adjacent ancestor/descendant
        // pair (tl <-> b: tl is b's grandparent via a) and an arbitrary pair (a <-> c).
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "tl",
                "stl",
                "tl",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();
        svc(&paths)
            .split_tab("w1", "tl", "a", "sa", "a", SplitAxis::Right, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "b", SplitAxis::Down, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "c", SplitAxis::Right, 2)
            .unwrap();

        let reaches_root = |layout: &WindowLayout, id: &str| {
            let mut cur = id.to_string();
            for _ in 0..layout.tabs.len() + 1 {
                if cur == "tl" {
                    return true;
                }
                match layout
                    .tabs
                    .iter()
                    .find(|t| t.tab_id == cur)
                    .and_then(|t| t.split_from.as_ref())
                {
                    Some(s) => cur = s.tab_id.clone(),
                    None => return cur == "tl",
                }
            }
            false
        };

        let layout = svc(&paths).swap_tab_panes("w1", "tl", "b", 5).unwrap();
        for id in ["tl", "a", "b", "c"] {
            assert!(
                reaches_root(&layout, id),
                "pane {id} dropped after grandparent swap tl<->b"
            );
        }
    }

    #[test]
    fn swap_tab_panes_rejects_missing_or_self_without_rewrite() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "a", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "b", "sb", "b", false, attn(Attention::None, false), 2)
            .unwrap();
        let before = stored(&paths, "w1");
        match svc(&paths)
            .swap_tab_panes("w1", "a", "ghost", 5)
            .unwrap_err()
        {
            WindowLayoutError::TabNotFound { tab_id, .. } => assert_eq!(tab_id, "ghost"),
            other => panic!("expected TabNotFound, got {other:?}"),
        }
        assert!(matches!(
            svc(&paths).swap_tab_panes("w1", "a", "a", 5).unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));
        assert_eq!(
            stored(&paths, "w1"),
            before,
            "a rejected swap leaves the layout byte-identical"
        );
    }

    #[test]
    fn swap_tab_positions_rejects_missing_or_self_without_rewrite() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        for (id, s) in [("a", "sa"), ("b", "sb")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        let before = stored(&paths, "w1");

        // Unknown tab id -> TabNotFound naming the missing id.
        match svc(&paths)
            .swap_tab_positions("w1", "a", "ghost", 5)
            .unwrap_err()
        {
            WindowLayoutError::TabNotFound { tab_id, .. } => assert_eq!(tab_id, "ghost"),
            other => panic!("expected TabNotFound for the missing target, got {other:?}"),
        }
        // Swapping a tab with itself -> InvalidTabOrder.
        assert!(matches!(
            svc(&paths)
                .swap_tab_positions("w1", "a", "a", 5)
                .unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));

        assert_eq!(
            stored(&paths, "w1"),
            before,
            "no failed swap rewrote the layout"
        );
    }

    #[test]
    fn swallow_split_named_by_child_dissolves_divider_keeping_both_sessions() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // Split "a" -> child "b". The frame is parent "a" + child "b".
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();

        // Swallow naming the CHILD: the child reclaims the full frame; its split binding is gone.
        let layout = svc(&paths).swallow_split("w1", "b", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(by_id("b").split_from, None, "the divider is dissolved");
        // Neither session is killed; both tabs remain with their sessions and labels.
        assert_eq!(tab_ids(&layout), vec!["a", "b"]);
        assert_eq!(by_id("a").session_id, "sa");
        assert_eq!(by_id("b").session_id, "sb");
        assert_eq!(by_id("a").split_from, None);
    }

    #[test]
    fn swallow_split_named_by_parent_dissolves_the_child_binding() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();

        // Swallow naming the PARENT "a": the same frame dissolves (the child "b" loses split_from).
        let layout = svc(&paths).swallow_split("w1", "a", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(by_id("b").split_from, None, "the divider is dissolved");
        assert_eq!(tab_ids(&layout), vec!["a", "b"]);
        assert_eq!(by_id("a").session_id, "sa");
        assert_eq!(by_id("b").session_id, "sb");
    }

    #[test]
    fn swallow_split_three_left_main_bottom_reclaims_full_bottom_band() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // A | B/C: a is the full-height left pane, b/c are stacked on the right.
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 2)
            .unwrap();

        // C (bottom-right) swallow LEFT: absorbs A's slice across C's left edge → C becomes the full-width
        // bottom band, A keeps the top-left, B the top-right = (A│B)/C. All three stay alive.
        let layout = svc(&paths)
            .swallow_split_direction("w1", "c", SwallowDir::Left, 5)
            .unwrap();
        let r = |id: &str| {
            let p = layout
                .tabs
                .iter()
                .find(|t| t.tab_id == id)
                .unwrap()
                .pane_rect
                .unwrap();
            (p.x, p.y, p.w, p.h)
        };
        assert_eq!(layout.tabs.iter().filter(|t| !t.stashed).count(), 3);
        let c = r("c");
        assert_eq!(
            (c.0, c.2),
            (0, 1000),
            "C spans the full width along the bottom"
        );
        let a = r("a");
        assert_eq!((a.0, a.1), (0, 0), "A keeps the top-left");
        assert!(r("b").0 > a.0, "B remains to the right of A on the top row");
    }

    #[test]
    fn swallow_split_direction_rejects_wrong_axis_instead_of_guessing() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 2)
            .unwrap();
        let before = stored(&paths, "w1");

        assert!(matches!(
            svc(&paths)
                .swallow_split_direction("w1", "c", SwallowDir::Down, 5)
                .unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));
        assert_eq!(
            stored(&paths, "w1"),
            before,
            "wrong-axis directional swallow leaves records untouched"
        );

        // C swallow LEFT absorbs A's slice across C's left edge → C becomes the full-width bottom band.
        let layout = svc(&paths)
            .swallow_split_direction("w1", "c", SwallowDir::Left, 6)
            .unwrap();
        let cr = layout
            .tabs
            .iter()
            .find(|t| t.tab_id == "c")
            .unwrap()
            .pane_rect
            .unwrap();
        assert_eq!(
            (cr.x, cr.w),
            (0, 1000),
            "C now spans the full width along the bottom"
        );
        assert_eq!(layout.tabs.iter().filter(|t| !t.stashed).count(), 3);
    }

    #[test]
    fn swallow_split_three_top_main_bottom_left_becomes_left_main() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // A/(B|C): a is full-width top; b/c share the bottom row.
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Down, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Right, 2)
            .unwrap();

        // Swallow UP on B: B becomes the full-height left pane, A/C stack to its right.
        let layout = svc(&paths)
            .swallow_split_direction("w1", "b", SwallowDir::Up, 5)
            .unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(tab_ids(&layout), vec!["b", "a", "c"]);
        assert_eq!(by_id("b").split_from, None);
        assert_eq!(
            by_id("a").split_from,
            split_from_parent("b", SplitAxis::Right)
        );
        assert_eq!(
            by_id("c").split_from,
            split_from_parent("a", SplitAxis::Down)
        );
    }

    #[test]
    fn swallow_split_three_left_main_top_right_becomes_top_main() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // A|(B/C): a is full-height left; b/c stack on the right.
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 2)
            .unwrap();

        // Swallow LEFT on B: B becomes the full-width top pane, A/C share the bottom row.
        let layout = svc(&paths)
            .swallow_split_direction("w1", "b", SwallowDir::Left, 5)
            .unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(tab_ids(&layout), vec!["b", "a", "c"]);
        assert_eq!(by_id("b").split_from, None);
        assert_eq!(
            by_id("a").split_from,
            split_from_parent("b", SplitAxis::Down)
        );
        assert_eq!(
            by_id("c").split_from,
            split_from_parent("a", SplitAxis::Right)
        );
    }

    #[test]
    fn swallow_split_three_bottom_main_top_left_round_trips_to_left_main() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // (A|B)/C: c is full-width bottom, a/b share the top row.
        svc(&paths)
            .split_tab("w1", "a", "c", "sc", "C", SplitAxis::Down, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();

        // Inverse of the anchor case: swallowing A vertically returns to A | B/C.
        let layout = svc(&paths).swallow_split("w1", "a", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(tab_ids(&layout), vec!["a", "b", "c"]);
        assert_eq!(by_id("a").split_from, None);
        assert_eq!(
            by_id("b").split_from,
            split_from_parent("a", SplitAxis::Right)
        );
        assert_eq!(
            by_id("c").split_from,
            split_from_parent("b", SplitAxis::Down)
        );
    }

    #[test]
    fn swallow_split_rejects_illegal_three_pane_main_without_rewrite() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 2)
            .unwrap();
        let before = stored(&paths, "w1");

        assert!(matches!(
            svc(&paths).swallow_split("w1", "a", 5).unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));
        assert_eq!(
            stored(&paths, "w1"),
            before,
            "illegal three-pane swallow leaves records untouched"
        );
    }

    /// Build a window whose live panes hold the canonical `layout`'s slot rects, agents a,b,c,d in slot
    /// order.
    fn build_four_pane(paths: &AppPaths, layout: CanonicalLayout) {
        let s = svc(paths);
        s.create_empty("w1", 1).unwrap();
        for (id, sid, title, t) in [
            ("a", "sa", "A", 2),
            ("b", "sb", "B", 3),
            ("c", "sc", "C", 4),
            ("d", "sd", "D", 5),
        ] {
            s.open_tab("w1", id, sid, title, false, attn(Attention::None, false), t)
                .unwrap();
        }
        let rects = slot_rects(layout, &std::collections::BTreeMap::new());
        let agents: Vec<AgentRect> = ["a", "b", "c", "d"]
            .iter()
            .zip(rects)
            .map(|(id, rect)| AgentRect {
                agent: id.to_string(),
                rect,
            })
            .collect();
        let mut l0 = s.require("w1").unwrap();
        apply_pane_geometry(&mut l0, &agents);
        s.write(&l0, 6).unwrap();
    }

    #[test]
    fn stash_fill_nested_a_filled_by_bc_pair() {
        // (A│(B/C))/D, stash A: A's right side has B+C whose heights tile A's full height → B and C
        // extend LEFT to fill A. Every survivor tiles, no gap.
        let panes = vec![
            AgentRect {
                agent: "b".into(),
                rect: [0.5, 0.0, 0.5, 0.275],
            },
            AgentRect {
                agent: "c".into(),
                rect: [0.5, 0.275, 0.5, 0.275],
            },
            AgentRect {
                agent: "d".into(),
                rect: [0.0, 0.55, 1.0, 0.45],
            },
        ];
        let removed = [0.0, 0.0, 0.5, 0.55]; // A.
        let out = reduce_rects_by_spec(panes, removed);
        let r = |id: &str| out.iter().find(|p| p.agent == id).unwrap().rect;
        // B and C now span the full top-left+right (x from 0), keeping their own heights.
        assert!(
            (r("b")[0] - 0.0).abs() < 1e-3 && (r("b")[2] - 1.0).abs() < 1e-3,
            "B fills width"
        );
        assert!(
            (r("c")[0] - 0.0).abs() < 1e-3 && (r("c")[2] - 1.0).abs() < 1e-3,
            "C fills width"
        );
        assert_eq!(r("d"), [0.0, 0.55, 1.0, 0.45], "D untouched");
        assert!(
            rects_tile_unit_square(&out),
            "survivors tile with no gap/overlap"
        );
    }

    #[test]
    fn tiling_invariant_accepts_valid_and_rejects_overlap_gap_and_overflow() {
        // A clean 2×2 grid tiles.
        let grid = vec![
            AgentRect {
                agent: "a".into(),
                rect: [0.0, 0.0, 0.5, 0.5],
            },
            AgentRect {
                agent: "b".into(),
                rect: [0.5, 0.0, 0.5, 0.5],
            },
            AgentRect {
                agent: "c".into(),
                rect: [0.0, 0.5, 0.5, 0.5],
            },
            AgentRect {
                agent: "d".into(),
                rect: [0.5, 0.5, 0.5, 0.5],
            },
        ];
        assert!(rects_tile_unit_square(&grid));
        // Overlap: B sits over A.
        let overlap = vec![
            AgentRect {
                agent: "a".into(),
                rect: [0.0, 0.0, 0.6, 1.0],
            },
            AgentRect {
                agent: "b".into(),
                rect: [0.4, 0.0, 0.6, 1.0],
            },
        ];
        assert!(
            !rects_tile_unit_square(&overlap),
            "overlap must be rejected"
        );
        // Gap: only covers the left half.
        let gap = vec![AgentRect {
            agent: "a".into(),
            rect: [0.0, 0.0, 0.5, 1.0],
        }];
        assert!(!rects_tile_unit_square(&gap), "gap must be rejected");
        // Overflow: extends past the right edge.
        let overflow = vec![AgentRect {
            agent: "a".into(),
            rect: [0.0, 0.0, 1.4, 1.0],
        }];
        assert!(
            !rects_tile_unit_square(&overflow),
            "overflow must be rejected"
        );
    }

    /// The user's report: in a nested layout a swallow could leave a pane behind/over another. The
    /// edge-absorb refuses the un-tileable case, and even if it didn't the geometry GUARD would. Here
    /// (A│(B/C))/D, D swallow-up cannot cleanly absorb (it would split A) → rejected, layout unchanged.
    #[test]
    fn nested_swallow_that_would_overlap_is_refused() {
        let panes = vec![
            AgentRect {
                agent: "a".into(),
                rect: [0.0, 0.0, 0.5, 0.55],
            },
            AgentRect {
                agent: "b".into(),
                rect: [0.5, 0.0, 0.5, 0.275],
            },
            AgentRect {
                agent: "c".into(),
                rect: [0.5, 0.275, 0.5, 0.275],
            },
            AgentRect {
                agent: "d".into(),
                rect: [0.0, 0.55, 1.0, 0.45],
            },
        ];
        assert!(
            swallow_rect_local(&panes, "d", SwallowDir::Up).is_none(),
            "a swallow that can't cleanly tile must be refused, not painted as overlap"
        );
    }

    /// The user's headline case: A/(B│C│D), B swallows UP → B spans both rows on the left (its own width),
    /// A keeps only the slice over C and D. Local edge-absorb, NOT a canonical reshape.
    #[test]
    fn swallow_up_absorbs_only_the_overlapping_slice_of_the_neighbor() {
        let (_tmp, paths) = temp_paths();
        build_four_pane(&paths, CanonicalLayout::FourTopMain);
        let after = svc(&paths)
            .swallow_split_direction("w1", "b", SwallowDir::Up, 7)
            .unwrap();
        let r = |id: &str| {
            let t = after.tabs.iter().find(|t| t.tab_id == id).unwrap();
            let p = t.pane_rect.unwrap();
            (p.x, p.y, p.w, p.h)
        };
        assert_eq!(
            r("b"),
            (0, 0, 330, 1000),
            "B is full-height on the left at its own width"
        );
        assert_eq!(
            r("a"),
            (330, 0, 670, 550),
            "A keeps only the part over C and D"
        );
        assert_eq!(r("c"), (330, 550, 340, 450), "C untouched");
        assert_eq!(r("d"), (670, 550, 330, 450), "D untouched");
        // No pane was wholly absorbed (all four still live).
        assert_eq!(after.tabs.iter().filter(|t| !t.stashed).count(), 4);
    }

    /// FourBottomMain (A│B│C)/D: A (top-left corner) swallows DOWN → A absorbs only the slice of the
    /// bottom main D directly below it (A's width); D keeps the rest under B and C. A becomes full-height
    /// on the left; B,C,D all stay alive.
    #[test]
    fn swallow_down_four_bottom_main_corner_absorbs_only_its_slice_of_the_main() {
        let (_tmp, paths) = temp_paths();
        build_four_pane(&paths, CanonicalLayout::FourBottomMain);
        let after = svc(&paths)
            .swallow_split_direction("w1", "a", SwallowDir::Down, 8)
            .expect("edge-absorb swallow succeeds");
        let r = |id: &str| {
            let p = after
                .tabs
                .iter()
                .find(|t| t.tab_id == id)
                .unwrap()
                .pane_rect
                .unwrap();
            (p.x, p.y, p.w, p.h)
        };
        assert_eq!(after.tabs.iter().filter(|t| !t.stashed).count(), 4);
        // A full-height left at its own width (≈333); D keeps the part to the right of A.
        let a = r("a");
        assert_eq!(
            (a.0, a.1, a.3),
            (0, 0, 1000),
            "A spans full height on the left"
        );
        let d = r("d");
        assert_eq!(
            d.0, a.2,
            "D now starts where A's column ends (its left slice was absorbed)"
        );
        assert_eq!(d.0 + d.2, 1000, "D still reaches the right edge");
    }

    #[test]
    fn swallow_split_rejects_missing_or_non_split_tab_without_rewrite() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        for (id, s) in [("a", "sa"), ("b", "sb")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        let before = stored(&paths, "w1");

        // Unknown tab id -> TabNotFound.
        match svc(&paths).swallow_split("w1", "ghost", 5).unwrap_err() {
            WindowLayoutError::TabNotFound { tab_id, .. } => assert_eq!(tab_id, "ghost"),
            other => panic!("expected TabNotFound, got {other:?}"),
        }
        // A tab that is in no split -> InvalidTabOrder (nothing to swallow).
        assert!(matches!(
            svc(&paths).swallow_split("w1", "a", 5).unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));

        assert_eq!(
            stored(&paths, "w1"),
            before,
            "no failed swallow rewrote the layout"
        );
    }

    #[test]
    fn dock_tab_beside_repoints_source_split_from_to_target() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        for (id, s) in [("a", "sa"), ("b", "sb")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        // Dock "b" beside "a" on the Right edge -> b becomes a's split child on the vertical axis.
        let layout = svc(&paths)
            .dock_tab_beside("w1", "b", "a", SplitAxis::Right, 5)
            .unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        let split = by_id("b").split_from.expect("b now docked beside a");
        assert_eq!(split.tab_id, "a");
        assert_eq!(split.axis, SplitAxis::Right);
        assert_eq!(by_id("a").split_from, None);
    }

    #[test]
    fn dock_tab_beside_retargets_to_chain_tail_when_target_already_has_a_child() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // a -> child b (a now has a split child).
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();
        // A third standalone pane c to dock onto a's chain.
        svc(&paths)
            .open_tab("w1", "c", "sc", "C", false, attn(Attention::None, false), 2)
            .unwrap();

        // Dock c beside a. a already has child b, so the dock must RETARGET to the chain tail (b),
        // appending c as the next canonical growth step rather than rejecting.
        let layout = svc(&paths)
            .dock_tab_beside("w1", "c", "a", SplitAxis::Right, 5)
            .unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        let c_split = by_id("c").split_from.expect("c is docked");
        assert_eq!(
            c_split.tab_id, "b",
            "c appends to the chain tail (b), not a (which is full)"
        );
        // b's binding to a is untouched; the chain is a -> b -> c.
        assert_eq!(by_id("b").split_from.unwrap().tab_id, "a");
    }

    #[test]
    fn dock_tab_beside_rejects_a_dock_into_the_sources_own_subtree() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // a -> child b: b's parent is a.
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();
        let before = stored(&paths, "w1");

        // Docking a (the parent) onto b (its own child) would loop the chain -> reject, no rewrite.
        assert!(matches!(
            svc(&paths)
                .dock_tab_beside("w1", "a", "b", SplitAxis::Right, 5)
                .unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));
        assert_eq!(
            stored(&paths, "w1"),
            before,
            "a rejected dock left the layout untouched"
        );
    }

    #[test]
    fn dock_tab_beside_rejects_docking_a_tab_beside_itself() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        assert!(matches!(
            svc(&paths)
                .dock_tab_beside("w1", "a", "a", SplitAxis::Right, 5)
                .unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));
    }

    #[test]
    fn dock_tab_at_edge_moves_visible_pane_into_requested_edge_layout() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Right, 4)
            .unwrap();

        // Move A below C: after removing A, B | C is split at C's bottom edge, yielding
        // B full-height left and C/A stacked on the right.
        let layout = svc(&paths)
            .dock_tab_at_edge("w1", "a", "c", EdgeDir::Bottom, 5)
            .unwrap();
        let live = live_tabs_sorted(&layout);
        let model = canonical_model_from_live_tabs(&live).expect("canonical topology");
        assert_eq!(model.layout, CanonicalLayout::ThreeLeftMain);
        assert_eq!(tab_ids(&layout), vec!["b", "c", "a"]);
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(by_id("b").split_from, None);
        assert_eq!(
            by_id("c").split_from,
            split_from_parent("b", SplitAxis::Right)
        );
        assert_eq!(
            by_id("a").split_from,
            split_from_parent("c", SplitAxis::Down)
        );
    }

    #[test]
    fn dock_tab_at_edge_from_four_grid_keeps_three_side_plus_one_main_shape() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "one",
                "s1",
                "One",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();
        svc(&paths)
            .split_tab("w1", "one", "two", "s2", "Two", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "one", "three", "s3", "Three", SplitAxis::Down, 4)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "two", "four", "s4", "Four", SplitAxis::Down, 5)
            .unwrap();

        // 2x2: one|two / three|four. Drag pane THREE onto the RIGHT edge of pane TWO (confirmed
        // local-split INSERT). three is removed (four expands to the full-width bottom row), then two's
        // OWN cell splits in half — two keeps its left, three takes the right. Result geometry:
        // one|two|three over a full-width four. The split tree below is one valid decomposition of that
        // grid; three docks directly off two (the local split), four off one (the absorbed bottom).
        let layout = svc(&paths)
            .dock_tab_at_edge("w1", "three", "two", EdgeDir::Right, 6)
            .unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(by_id("one").split_from, None);
        assert_eq!(
            by_id("two").split_from,
            split_from_parent("one", SplitAxis::Right)
        );
        assert_eq!(
            by_id("three").split_from,
            split_from_parent("two", SplitAxis::Right)
        );
        assert_eq!(
            by_id("four").split_from,
            split_from_parent("one", SplitAxis::Down)
        );
    }

    #[test]
    fn dock_tab_at_edge_from_four_grid_bottom_left_to_top_row_expands_bottom_neighbor() {
        for target in ["one", "two"] {
            let (_tmp, paths) = temp_paths();
            svc(&paths).create_empty("w1", 1).unwrap();
            svc(&paths)
                .open_tab(
                    "w1",
                    "one",
                    "s1",
                    "One",
                    false,
                    attn(Attention::None, false),
                    2,
                )
                .unwrap();
            svc(&paths)
                .split_tab("w1", "one", "two", "s2", "Two", SplitAxis::Right, 3)
                .unwrap();
            svc(&paths)
                .split_tab("w1", "one", "three", "s3", "Three", SplitAxis::Down, 4)
                .unwrap();
            svc(&paths)
                .split_tab("w1", "two", "four", "s4", "Four", SplitAxis::Down, 5)
                .unwrap();

            // Confirmed local-split INSERT: dragging three onto the TOP edge of `target` removes three
            // from its cell (the survivors re-tile), then splits `target`'s OWN cell so three takes the
            // top half. All four panes stay live and the layout stays a valid single-rooted tree.
            let layout = svc(&paths)
                .dock_tab_at_edge("w1", "three", target, EdgeDir::Top, 6)
                .unwrap_or_else(|err| panic!("dock three to {target} top failed: {err}"));
            let live = live_tabs_sorted(&layout);
            assert_eq!(live.len(), 4, "all four panes stay live (target {target})");
            // exactly one root, every non-root splits from another LIVE pane (no orphans).
            let live_ids: std::collections::HashSet<&str> =
                live.iter().map(|t| t.tab_id.as_str()).collect();
            let roots = live.iter().filter(|t| t.split_from.is_none()).count();
            assert_eq!(roots, 1, "exactly one root after dock (target {target})");
            for t in &live {
                if let Some(sf) = &t.split_from {
                    assert!(
                        live_ids.contains(sf.tab_id.as_str()),
                        "pane {} splits from a live pane (target {target})",
                        t.tab_id
                    );
                }
            }
            // three is adjacent to the target it was dropped onto (its parent or the target's parent).
            let three = live.iter().find(|t| t.tab_id == "three").unwrap();
            assert!(
                three
                    .split_from
                    .as_ref()
                    .is_some_and(|sf| sf.tab_id == target)
                    || live.iter().any(|t| {
                        t.tab_id == target
                            && t.split_from.as_ref().is_some_and(|sf| sf.tab_id == "three")
                    }),
                "three docks locally next to {target}"
            );
        }
    }

    #[test]
    fn dock_stashed_tab_at_edge_extends_right_side_stack() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 4)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "d", "sd", "D", false, attn(Attention::None, false), 5)
            .unwrap();
        svc(&paths).set_tab_stashed("w1", "d", true, 6).unwrap();

        let layout = svc(&paths)
            .dock_tab_at_edge("w1", "d", "c", EdgeDir::Bottom, 7)
            .unwrap();
        let live = live_tabs_sorted(&layout);
        let model = canonical_model_from_live_tabs(&live).expect("canonical topology");
        assert_eq!(model.layout, CanonicalLayout::FourLeftMain);
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(
            tab_ids(&layout),
            vec!["a", "b", "c", "d"],
            "drag/drop revive should honor the drop edge and produce A|B/C/D"
        );
        assert_eq!(by_id("a").split_from, None);
        assert_eq!(
            by_id("b").split_from,
            split_from_parent("a", SplitAxis::Right)
        );
        assert_eq!(
            by_id("c").split_from,
            split_from_parent("b", SplitAxis::Down)
        );
        assert_eq!(
            by_id("d").split_from,
            split_from_parent("c", SplitAxis::Down),
            "D must be below C for the requested side-stack drop"
        );
    }

    /// Regression: swallow must keep working after a drag-drop/stash that routes split_from through
    /// topology_from_rects. The split_from chain there can diverge from the painted rects, and swallow
    /// used to classify the layout from the (wrong) chain → "no legal swallow" → it silently stopped
    /// working until the project was reopened. The rect-based classifier reads the authoritative geometry.
    #[test]
    fn swallow_works_after_a_drag_drop_op() {
        let (_tmp, paths) = temp_paths();
        let s = svc(&paths);
        s.create_empty("w1", 1).unwrap();
        s.open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        s.split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        s.open_tab("w1", "c", "sc", "C", false, attn(Attention::None, false), 4)
            .unwrap();
        s.set_tab_stashed("w1", "c", true, 5).unwrap();
        // Drag-drop C below A — produces (A/C)│B; split_from chain reads c-Down-from-a, b-Right-from-a
        // (which the old chain-classifier mistook for ThreeBottomMain).
        s.dock_tab_at_edge("w1", "c", "a", EdgeDir::Bottom, 6)
            .unwrap();

        // The canonical model must come from the RECTS: (A/C)│B is right-main (B is the full-height side).
        let layout = s.require("w1").unwrap();
        let live = live_tabs_sorted(&layout);
        let model = canonical_model_from_live_tabs(&live).expect("model reconstructs from rects");
        assert_eq!(
            model.layout,
            CanonicalLayout::ThreeRightMain,
            "classified from rects, not the divergent split_from chain"
        );
        // And swallow on a side pane must SUCCEED (it had a legal direction all along).
        s.swallow_split("w1", "c", 7)
            .expect("swallow must work after a drag-drop op");
    }

    /// Drag-revive (from the dashboard) must produce the SAME final shape as a normal pane-to-pane drop
    /// for the same gesture: both end with A over the dropped pane on the left, B full-height right.
    /// (The bug: drag-revive used to run click-revive placement first, giving a different shape.)
    #[test]
    fn drag_revive_matches_normal_drop_shape() {
        type IdRect = (String, (u16, u16, u16, u16));
        let drop_result = |stashed_source: bool| -> Vec<IdRect> {
            let (_tmp, paths) = temp_paths();
            let s = svc(&paths);
            s.create_empty("w1", 1).unwrap();
            s.open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
                .unwrap();
            s.split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
                .unwrap();
            // The dropped source pane is "src" — live (normal drop) or stashed (drag-revive).
            if stashed_source {
                s.open_tab(
                    "w1",
                    "src",
                    "ss",
                    "S",
                    false,
                    attn(Attention::None, false),
                    4,
                )
                .unwrap();
                s.set_tab_stashed("w1", "src", true, 5).unwrap();
            } else {
                // a live src: split it off B so a normal drop has something to vacate.
                s.split_tab("w1", "b", "src", "ss", "S", SplitAxis::Down, 4)
                    .unwrap();
            }
            let l = s
                .dock_tab_at_edge("w1", "src", "a", EdgeDir::Bottom, 6)
                .unwrap();
            let mut out: Vec<(String, (u16, u16, u16, u16))> = l
                .tabs
                .iter()
                .filter(|t| !t.stashed)
                .map(|t| {
                    let r = t.pane_rect.unwrap();
                    (t.tab_id.clone(), (r.x, r.y, r.w, r.h))
                })
                .collect();
            out.sort();
            out
        };
        // A and the dropped src share A's column (A top, src bottom); B full-height right — identical
        // in both paths for the panes they share (A, B, src).
        let revive = drop_result(true);
        let pick = |v: &[IdRect], id: &str| v.iter().find(|(i, _)| i == id).map(|(_, r)| *r);
        assert_eq!(pick(&revive, "a"), Some((0, 0, 500, 500)), "A top-left");
        assert_eq!(
            pick(&revive, "src"),
            Some((0, 500, 500, 500)),
            "src below A"
        );
        assert_eq!(
            pick(&revive, "b"),
            Some((500, 0, 500, 1000)),
            "B full-height right"
        );
        // A normal drop of a live pane onto A.bottom yields the same A/src/B placement.
        let normal = drop_result(false);
        assert_eq!(pick(&normal, "a"), pick(&revive, "a"), "A identical");
        assert_eq!(pick(&normal, "src"), pick(&revive, "src"), "src identical");
        assert_eq!(pick(&normal, "b"), pick(&revive, "b"), "B identical");
    }

    /// Drag-revive a stashed pane onto A's BOTTOM edge: the source must land BELOW A (A keeps the top
    /// half). Regression for the inverted drop — A was ending up below the new pane. dock_tab_at_edge is
    /// the ONLY operation (the app no longer calls revive_pane first).
    #[test]
    fn drag_revive_onto_bottom_edge_places_source_below_target() {
        let (_tmp, paths) = temp_paths();
        let s = svc(&paths);
        s.create_empty("w1", 1).unwrap();
        s.open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // A│B so A is a real column; stash X.
        s.split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        s.open_tab("w1", "x", "sx", "X", false, attn(Attention::None, false), 4)
            .unwrap();
        s.set_tab_stashed("w1", "x", true, 5).unwrap();

        // Drop X on A's BOTTOM edge (the single drag-revive operation).
        let layout = s
            .dock_tab_at_edge("w1", "x", "a", EdgeDir::Bottom, 6)
            .unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        let a = by_id("a").pane_rect.unwrap();
        let x = by_id("x").pane_rect.unwrap();
        assert!(!by_id("x").stashed, "X is revived (live)");
        // A and X share A's column; A is the TOP half, X the BOTTOM half.
        assert_eq!(a.x, x.x, "A and X in the same column");
        assert_eq!(a.w, x.w);
        assert!(a.y < x.y, "A stays on TOP, X goes BELOW (not inverted)");
        assert_eq!(a.h + x.h, 1000, "A/X split A's height");
    }

    #[test]
    fn dock_tab_at_edge_from_four_grid_bottom_pane_to_top_row_keeps_four_visible_panes() {
        for (source, target, edge) in [
            ("three", "one", EdgeDir::Left),
            ("three", "one", EdgeDir::Top),
            ("three", "two", EdgeDir::Right),
            ("three", "two", EdgeDir::Top),
            ("four", "one", EdgeDir::Left),
            ("four", "one", EdgeDir::Top),
            ("four", "two", EdgeDir::Right),
            ("four", "two", EdgeDir::Top),
        ] {
            let (_tmp, paths) = temp_paths();
            svc(&paths).create_empty("w1", 1).unwrap();
            svc(&paths)
                .open_tab(
                    "w1",
                    "one",
                    "s1",
                    "One",
                    false,
                    attn(Attention::None, false),
                    2,
                )
                .unwrap();
            svc(&paths)
                .split_tab("w1", "one", "two", "s2", "Two", SplitAxis::Right, 3)
                .unwrap();
            svc(&paths)
                .split_tab("w1", "one", "three", "s3", "Three", SplitAxis::Down, 4)
                .unwrap();
            svc(&paths)
                .split_tab("w1", "two", "four", "s4", "Four", SplitAxis::Down, 5)
                .unwrap();

            // Local-split INSERT must keep ALL FOUR panes live and form a valid single-rooted tree (no
            // orphan, no hidden pane) regardless of which pane/edge is dropped. The exact shape varies by
            // drop; the invariant is "nothing disappears" — the bug this guards against is the dropped
            // pane (or a displaced neighbor) vanishing.
            let layout = svc(&paths)
                .dock_tab_at_edge("w1", source, target, edge, 6)
                .unwrap_or_else(|err| panic!("dock {source} to {target} {edge:?} failed: {err}"));
            let live = live_tabs_sorted(&layout);
            let live_ids: std::collections::HashSet<&str> =
                live.iter().map(|t| t.tab_id.as_str()).collect();
            for id in ["one", "two", "three", "four"] {
                assert!(
                    live_ids.contains(id),
                    "dock {source} to {target} {edge:?} hid pane {id}"
                );
            }
            assert_eq!(
                live.len(),
                4,
                "dock {source} to {target} {edge:?} must keep all panes live"
            );
            let roots = live.iter().filter(|t| t.split_from.is_none()).count();
            assert_eq!(
                roots, 1,
                "dock {source} to {target} {edge:?}: exactly one root"
            );
            for t in &live {
                if let Some(sf) = &t.split_from {
                    assert!(
                        live_ids.contains(sf.tab_id.as_str()),
                        "dock {source} to {target} {edge:?}: {} splits from a live pane",
                        t.tab_id
                    );
                }
            }
        }
    }

    #[test]
    fn close_pane_reparents_children_onto_the_closed_panes_parent() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // Chain a -> b -> c (`A | B/C`). Closing b lets c expand upward into b's right-column space,
        // so the surviving layout is `A | C`.
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 2)
            .unwrap();

        let layout = svc(&paths).close_pane("w1", "b", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(
            tab_ids(&layout),
            vec!["a", "c"],
            "b removed, a and c survive"
        );
        let c_split = by_id("c").split_from.expect("c keeps a split parent");
        assert_eq!(
            c_split.tab_id, "a",
            "c expands into b's column and remains beside a"
        );
        assert_eq!(c_split.axis, SplitAxis::Right);
        assert_eq!(by_id("a").split_from, None);
    }

    #[test]
    fn close_pane_detaches_children_to_roots_when_closing_a_root() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // a is the root; b is its child. Closing the root a must detach b to a root (no parent).
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();

        let layout = svc(&paths).close_pane("w1", "a", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(tab_ids(&layout), vec!["b"], "a removed, b survives");
        assert_eq!(
            by_id("b").split_from,
            None,
            "b detached to a root, not pointing at the vanished a"
        );
    }

    #[test]
    fn close_pane_rejects_unknown_tab_without_rewrite() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        let before = stored(&paths, "w1");
        assert!(matches!(
            svc(&paths).close_pane("w1", "ghost", 5).unwrap_err(),
            WindowLayoutError::TabNotFound { .. }
        ));
        assert_eq!(
            stored(&paths, "w1"),
            before,
            "a rejected close left the layout untouched"
        );
    }

    #[test]
    fn stash_pane_keeps_the_record_flags_it_and_reparents_children() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // Chain a -> b -> c (`A | B/C`). Stashing b must KEEP b (flagged stashed, session preserved)
        // and let c expand upward into b's right-column space.
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 2)
            .unwrap();

        let layout = svc(&paths).stash_pane("w1", "b", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(
            tab_ids(&layout),
            vec!["a", "c", "b"],
            "live panes stay first; b is kept as a stashed revive candidate"
        );
        let b = by_id("b");
        assert!(b.stashed, "b is flagged stashed");
        assert_eq!(b.session_id, "sb", "b's session is preserved for revive");
        assert_eq!(
            b.split_from, None,
            "stashed b is hidden from the live split chain"
        );
        let b_stashed_from = b.stashed_from.expect("b keeps revive provenance");
        assert_eq!(b_stashed_from.tab_id, "a");
        assert_eq!(b_stashed_from.axis, SplitAxis::Right);
        assert!(
            !by_id("a").stashed && !by_id("c").stashed,
            "siblings stay live"
        );
        assert_eq!(
            by_id("c").split_from.expect("c keeps a parent").tab_id,
            "a",
            "c expands into b's column and remains beside a"
        );
        assert_eq!(by_id("c").split_from.unwrap().axis, SplitAxis::Right);
    }

    #[test]
    fn revive_pane_restores_stashed_leaf_to_original_live_parent() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths).stash_pane("w1", "b", 4).unwrap();

        let layout = svc(&paths).revive_pane("w1", "b", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        let b = by_id("b");
        assert!(!b.stashed);
        assert_eq!(
            b.session_id, "sb",
            "revive preserves the running-session identity"
        );
        assert_eq!(b.stashed_from, None, "revive consumes saved provenance");
        let split = b.split_from.expect("b restored beside a");
        assert_eq!(split.tab_id, "a");
        assert_eq!(split.axis, SplitAxis::Right);
    }

    #[test]
    fn revive_pane_of_stashed_middle_appends_to_live_parent_chain_tail() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // a -> b -> c. Stashing b re-parents c onto a, so revive must not create a second direct
        // child of a; it appends b at the current chain tail (c).
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 4)
            .unwrap();
        svc(&paths).stash_pane("w1", "b", 5).unwrap();

        let layout = svc(&paths).revive_pane("w1", "b", 6).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(by_id("c").split_from.unwrap().tab_id, "a");
        let b_split = by_id("b").split_from.expect("b revived into live chain");
        assert_eq!(
            b_split.tab_id, "a",
            "b revives into the current visible 2-column layout by filling below the first column"
        );
        assert_eq!(b_split.axis, SplitAxis::Down);
    }

    #[test]
    fn revive_pane_falls_back_to_deterministic_growth_when_original_parent_is_gone() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths).stash_pane("w1", "b", 4).unwrap();
        svc(&paths).close_pane("w1", "a", 5).unwrap();

        // With no live panes left after closing the old parent, revive becomes a root.
        let layout = svc(&paths).revive_pane("w1", "b", 6).unwrap();
        let b = layout.tabs.iter().find(|t| t.tab_id == "b").unwrap();
        assert!(!b.stashed);
        assert_eq!(b.split_from, None);

        // Add a second stashed pane with a missing parent: it revives to the right of the sole live
        // pane, matching the fixed 1 -> 2 growth rule.
        svc(&paths)
            .open_tab("w1", "c", "sc", "C", false, attn(Attention::None, false), 7)
            .unwrap();
        svc(&paths).stash_pane("w1", "c", 8).unwrap();
        let layout = svc(&paths).revive_pane("w1", "c", 9).unwrap();
        let c_split = layout
            .tabs
            .iter()
            .find(|t| t.tab_id == "c")
            .unwrap()
            .split_from
            .clone()
            .expect("c revived beside b");
        assert_eq!(c_split.tab_id, "b");
        assert_eq!(c_split.axis, SplitAxis::Right);
    }

    #[test]
    fn revive_pane_uses_current_visible_topology_for_third_pane() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Down, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Right, 4)
            .unwrap();
        svc(&paths).stash_pane("w1", "c", 5).unwrap();
        svc(&paths).stash_pane("w1", "b", 6).unwrap();

        let layout = svc(&paths).revive_pane("w1", "b", 7).unwrap();
        let b = layout.tabs.iter().find(|t| t.tab_id == "b").unwrap();
        assert_eq!(
            b.split_from,
            Some(SplitFrom {
                tab_id: "a".into(),
                axis: SplitAxis::Right,
                ratio_per_mille: None,
            }),
            "the second live pane always comes back to the right of the first"
        );

        let layout = svc(&paths).revive_pane("w1", "c", 8).unwrap();
        let c = layout.tabs.iter().find(|t| t.tab_id == "c").unwrap();
        assert_eq!(
            c.split_from,
            Some(SplitFrom {
                tab_id: "a".into(),
                axis: SplitAxis::Down,
                ratio_per_mille: None,
            }),
            "with two live columns, the third pane fills below the first column"
        );
    }

    #[test]
    fn repair_live_topology_connects_multiple_live_roots() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "b", "sb", "B", false, attn(Attention::None, false), 3)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "c", "sc", "C", false, attn(Attention::None, false), 4)
            .unwrap();

        let broken = svc(&paths).load("w1").unwrap().unwrap();
        assert!(
            broken
                .tabs
                .iter()
                .filter(|tab| !tab.stashed)
                .all(|tab| tab.split_from.is_none()),
            "regression setup must match old bad records: three green roots"
        );

        // Repair reconnects three orphaned roots into a valid single-rooted tree. With no surviving
        // split geometry to reconstruct, the reviving rule falls back to a uniform chain off the first
        // root (A│B│C) — any valid single-root tree is acceptable here; the invariant is one root + no
        // orphans, which the assertions below pin down.
        let repaired = svc(&paths).repair_live_topology("w1", 5).unwrap();
        let by_id = |id: &str| repaired.tabs.iter().find(|t| t.tab_id == id).unwrap();
        assert_eq!(by_id("a").split_from, None, "exactly one root after repair");
        assert_eq!(
            by_id("b").split_from,
            Some(SplitFrom {
                tab_id: "a".into(),
                axis: SplitAxis::Right,
                ratio_per_mille: None,
            })
        );
        assert_eq!(
            by_id("c").split_from,
            Some(SplitFrom {
                tab_id: "a".into(),
                axis: SplitAxis::Right,
                ratio_per_mille: None,
            }),
            "C reattaches under the single root (uniform fallback chain)"
        );
        assert!(
            repaired.tabs.iter().all(|tab| !tab.stashed),
            "repair must not stash or kill any live pane"
        );
    }

    #[test]
    fn revive_fourth_pane_restores_bottom_row_after_stash_neighbor_expansion() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "c", "sc", "C", SplitAxis::Down, 4)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "d", "sd", "D", SplitAxis::Down, 5)
            .unwrap();
        svc(&paths).stash_pane("w1", "d", 6).unwrap();

        // After stashing D, the live layout is bottom-main (A│B)/C (C is the full-width bottom row).
        // Per the confirmed click-revive spec, reviving D yields the 2×2 grid (A│B)/(C│X): A tl, B tr,
        // C bl, D br. So D lands in the bottom-right corner (below B in this grid decomposition).
        let layout = svc(&paths).revive_pane("w1", "d", 7).unwrap();
        let d = layout.tabs.iter().find(|t| t.tab_id == "d").unwrap();
        assert_eq!(
            d.split_from,
            Some(SplitFrom {
                tab_id: "b".into(),
                axis: SplitAxis::Down,
                ratio_per_mille: None,
            }),
            "revived D is the bottom-right of the (A│B)/(C│D) grid"
        );
    }

    #[test]
    fn revive_fourth_pane_splits_the_single_full_width_row_to_the_right() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Down, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Right, 4)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "d", "sd", "D", false, attn(Attention::None, false), 5)
            .unwrap();
        svc(&paths).set_tab_stashed("w1", "d", true, 6).unwrap();

        // Source is top-main A/(B│C): A full-width top, B│C bottom row. Per the confirmed click-revive
        // spec, reviving the fourth pane (D) yields the 2×2 grid (A│D)/(B│C): A tl, D tr, B bl, C br.
        let layout = svc(&paths).revive_pane("w1", "d", 7).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        // Verify the GEOMETRY is the (A│D)/(B│C) grid via the resulting split tree (one valid
        // decomposition of that grid): A root; B below A; D right of A; C completes the bottom-right.
        assert_eq!(by_id("a").split_from, None);
        assert_eq!(
            by_id("b").split_from,
            Some(SplitFrom {
                tab_id: "a".into(),
                axis: SplitAxis::Down,
                ratio_per_mille: None,
            }),
            "B is the bottom-left of the grid (below A)"
        );
        assert_eq!(
            by_id("d").split_from,
            Some(SplitFrom {
                tab_id: "a".into(),
                axis: SplitAxis::Right,
                ratio_per_mille: None,
            }),
            "revived D is the top-right of the grid (right of A)"
        );
        assert_eq!(
            by_id("c").split_from,
            Some(SplitFrom {
                tab_id: "d".into(),
                axis: SplitAxis::Down,
                ratio_per_mille: None,
            }),
            "C is the bottom-right of the grid (below D in this decomposition)"
        );
    }

    #[test]
    fn stash_from_four_grid_expands_the_full_edge_neighbor() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "c", "sc", "C", SplitAxis::Down, 4)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "d", "sd", "D", SplitAxis::Down, 5)
            .unwrap();

        let layout = svc(&paths).stash_pane("w1", "b", 6).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert!(by_id("b").stashed);
        assert_eq!(tab_ids(&layout), vec!["a", "c", "d", "b"]);
        assert_eq!(by_id("a").split_from, None);
        assert_eq!(
            by_id("d").split_from,
            Some(SplitFrom {
                tab_id: "c".into(),
                axis: SplitAxis::Right,
                ratio_per_mille: None,
            }),
            "same-height side neighbor a consumes b's top-right space, leaving c|d in the lower row"
        );
        assert_eq!(
            by_id("c").split_from,
            Some(SplitFrom {
                tab_id: "a".into(),
                axis: SplitAxis::Down,
                ratio_per_mille: None,
            }),
            "lower-left neighbor c remains below expanded a"
        );
    }

    #[test]
    fn stash_from_four_grid_bottom_left_expands_bottom_row_neighbor() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "c", "sc", "C", SplitAxis::Down, 4)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "d", "sd", "D", SplitAxis::Down, 5)
            .unwrap();

        let layout = svc(&paths).stash_pane("w1", "c", 6).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        // Reading order (y then x): top row A,B then full-width bottom D; stashed c trails.
        assert_eq!(tab_ids(&layout), vec!["a", "b", "d", "c"]);
        assert!(by_id("c").stashed, "c is flagged stashed for the dashboard");
        assert_eq!(
            by_id("c").split_from,
            None,
            "stashed c must not stay in the live split chain"
        );
        assert!(
            !by_id("a").stashed && !by_id("b").stashed && !by_id("d").stashed,
            "the remaining panes stay live"
        );
        assert_eq!(by_id("a").split_from, None);
        assert_eq!(
            by_id("b").split_from,
            Some(SplitFrom {
                tab_id: "a".into(),
                axis: SplitAxis::Right,
                ratio_per_mille: None,
            }),
            "top row remains A|B"
        );
        assert_eq!(
            by_id("d").split_from,
            Some(SplitFrom {
                tab_id: "a".into(),
                axis: SplitAxis::Down,
                ratio_per_mille: None,
            }),
            "d expands across the bottom row instead of moving into the upper group"
        );
    }

    /// Three columns A│B│C, revive X → (A/X)│B│C — STAYS three columns, the LEFT column splits into
    /// A over X. Does NOT become a 2×2 grid. (This pins the user's fixed rule for the columnar case.)
    #[test]
    fn click_revive_three_columns_splits_left_column_not_grid() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Right, 4)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "x", "sx", "X", false, attn(Attention::None, false), 5)
            .unwrap();
        svc(&paths).set_tab_stashed("w1", "x", true, 6).unwrap();

        let layout = svc(&paths).revive_pane("w1", "x", 7).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        // Sequential right-splits make a LOCAL split each time, so the live layout before revive is
        // A(left half) │ B(quarter) │ C(quarter) — not equal thirds. Click-revive splits the LEFT column
        // (A's column) into A over X; B and C remain FULL-HEIGHT columns (the key: NOT a grid).
        let a = by_id("a").pane_rect.unwrap();
        let x = by_id("x").pane_rect.unwrap();
        let b = by_id("b").pane_rect.unwrap();
        let c = by_id("c").pane_rect.unwrap();
        // A and X share A's column (same x and width), A on top, X below.
        assert_eq!(a.x, x.x);
        assert_eq!(a.w, x.w);
        assert!(a.y < x.y, "A above X in the left column");
        assert_eq!(a.h + x.h, 1000, "A and X split the column height");
        // B and C stay full-height columns — NOT split into a grid.
        assert_eq!(b.y, 0);
        assert_eq!(b.h, 1000, "B is a full-height column");
        assert_eq!(c.y, 0);
        assert_eq!(c.h, 1000, "C is a full-height column — not a grid");
    }

    // ---- click-revive specification coverage ----

    /// Single pane A, revive X → A│X (new equal-width column on the right).
    #[test]
    fn click_revive_one_pane_adds_right_column() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "x", "sx", "X", false, attn(Attention::None, false), 3)
            .unwrap();
        svc(&paths).set_tab_stashed("w1", "x", true, 4).unwrap();

        let layout = svc(&paths).revive_pane("w1", "x", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        // AUTHORITATIVE A│X — equal halves.
        assert_eq!(
            by_id("a").pane_rect,
            Some(PaneRect {
                x: 0,
                y: 0,
                w: 500,
                h: 1000
            })
        );
        assert_eq!(
            by_id("x").pane_rect,
            Some(PaneRect {
                x: 500,
                y: 0,
                w: 500,
                h: 1000
            })
        );
    }

    /// Two columns A│B, revive X → (A/X)│B (the LEFT column splits; X below A).
    #[test]
    fn click_revive_two_columns_splits_left_column() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "x", "sx", "X", false, attn(Attention::None, false), 4)
            .unwrap();
        svc(&paths).set_tab_stashed("w1", "x", true, 5).unwrap();

        let layout = svc(&paths).revive_pane("w1", "x", 6).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        // AUTHORITATIVE (A/X)│B: A top-left, X bottom-left, B full-height right.
        assert_eq!(
            by_id("a").pane_rect,
            Some(PaneRect {
                x: 0,
                y: 0,
                w: 500,
                h: 500
            })
        );
        assert_eq!(
            by_id("x").pane_rect,
            Some(PaneRect {
                x: 0,
                y: 500,
                w: 500,
                h: 500
            })
        );
        assert_eq!(
            by_id("b").pane_rect,
            Some(PaneRect {
                x: 500,
                y: 0,
                w: 500,
                h: 1000
            })
        );
    }

    /// Two rows A/B, revive X → (A│X)/B (the TOP row splits; X right of A).
    #[test]
    fn click_revive_two_rows_splits_top_row() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Down, 3)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "x", "sx", "X", false, attn(Attention::None, false), 4)
            .unwrap();
        svc(&paths).set_tab_stashed("w1", "x", true, 5).unwrap();

        let layout = svc(&paths).revive_pane("w1", "x", 6).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        // AUTHORITATIVE (A│X)/B: A top-left, X top-right, B full-width bottom.
        assert_eq!(
            by_id("a").pane_rect,
            Some(PaneRect {
                x: 0,
                y: 0,
                w: 500,
                h: 500
            })
        );
        assert_eq!(
            by_id("x").pane_rect,
            Some(PaneRect {
                x: 500,
                y: 0,
                w: 500,
                h: 500
            })
        );
        assert_eq!(
            by_id("b").pane_rect,
            Some(PaneRect {
                x: 0,
                y: 500,
                w: 1000,
                h: 500
            })
        );
    }

    // ---- spec-coverage: the cases that diverged before the single-rule rewrite ----

    /// `A│(B/C/D)` (left main + right 3-stack). Stashing the BOTTOM of the right stack (D) leaves the
    /// surviving panes as `A│(B/C)` — A as the left half (root), the B/C stack as the right half, in
    /// reading order A,B,C. Verifies the same-column absorb plus reading-order topology.
    #[test]
    fn stash_bottom_of_right_stack_leaves_left_main_with_pair() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 4)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "d", "sd", "D", SplitAxis::Right, 5)
            .unwrap();

        let layout = svc(&paths).stash_pane("w1", "d", 6).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert!(by_id("d").stashed);
        assert_eq!(
            by_id("d").pane_rect,
            None,
            "stashed pane has no live geometry"
        );
        // AUTHORITATIVE geometry A│(B/C): A left half full-height, B top-right, C bottom-right.
        assert_eq!(
            by_id("a").pane_rect,
            Some(PaneRect {
                x: 0,
                y: 0,
                w: 500,
                h: 1000
            })
        );
        assert_eq!(
            by_id("b").pane_rect,
            Some(PaneRect {
                x: 500,
                y: 0,
                w: 500,
                h: 500
            })
        );
        assert_eq!(
            by_id("c").pane_rect,
            Some(PaneRect {
                x: 500,
                y: 500,
                w: 500,
                h: 500
            })
        );
    }

    /// `A│(B/C/D)` (left main + right column split into a 3-stack). Stashing the full-height main A must
    /// leave the surviving 3-stack as a single full-width column B/C/D — NOT split them into two columns.
    #[test]
    fn stash_full_height_main_leaves_survivor_stack_as_full_width_column() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 4)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "c", "d", "sd", "D", SplitAxis::Down, 5)
            .unwrap();

        let layout = svc(&paths).stash_pane("w1", "a", 6).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        // B/C/D become a single full-width column, each stacked below the previous.
        assert_eq!(by_id("b").split_from, None);
        assert_eq!(
            by_id("c").split_from,
            Some(SplitFrom {
                tab_id: "b".into(),
                axis: SplitAxis::Down,
                ratio_per_mille: None,
            }),
            "C below B in the full-width column"
        );
        assert_eq!(
            by_id("d").split_from,
            Some(SplitFrom {
                tab_id: "c".into(),
                axis: SplitAxis::Down,
                ratio_per_mille: None,
            }),
            "D below C — the 3-stack stays one full-width column, not split into two"
        );
    }

    #[test]
    fn stash_full_height_column_lets_split_neighbor_column_expand() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 4)
            .unwrap();

        let layout = svc(&paths).stash_pane("w1", "a", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert!(by_id("a").stashed);
        assert_eq!(tab_ids(&layout), vec!["b", "c", "a"]);
        assert_eq!(
            by_id("b").split_from,
            None,
            "top-right pane becomes the full-width top row"
        );
        assert_eq!(
            by_id("c").split_from,
            Some(SplitFrom {
                tab_id: "b".into(),
                axis: SplitAxis::Down,
                ratio_per_mille: None,
            }),
            "bottom-right pane keeps its row relationship and expands with b into the old full column"
        );
    }

    #[test]
    fn stash_full_width_row_lets_split_neighbor_row_expand() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Down, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Right, 4)
            .unwrap();

        let layout = svc(&paths).stash_pane("w1", "a", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert!(by_id("a").stashed);
        assert_eq!(tab_ids(&layout), vec!["b", "c", "a"]);
        assert_eq!(
            by_id("b").split_from,
            None,
            "bottom-left pane becomes the full-height left column"
        );
        assert_eq!(
            by_id("c").split_from,
            Some(SplitFrom {
                tab_id: "b".into(),
                axis: SplitAxis::Right,
                ratio_per_mille: None,
            }),
            "bottom-right pane keeps its column relationship and expands with b into the old full row"
        );
    }

    #[test]
    fn revive_pane_refuses_more_than_four_live_panes() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 4)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "c", "d", "sd", "D", SplitAxis::Right, 5)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "e", "se", "E", false, attn(Attention::None, false), 6)
            .unwrap();
        svc(&paths).set_tab_stashed("w1", "e", true, 7).unwrap();
        let before = stored(&paths, "w1");
        assert!(matches!(
            svc(&paths).revive_pane("w1", "e", 8).unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));
        assert_eq!(stored(&paths, "w1"), before);
    }

    #[test]
    fn stash_pane_refuses_the_only_live_pane() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();
        // Stash a -> only b live. Stashing b too would empty the window's live layout -> refused.
        svc(&paths).stash_pane("w1", "a", 5).unwrap();
        let before = stored(&paths, "w1");
        assert!(matches!(
            svc(&paths).stash_pane("w1", "b", 6).unwrap_err(),
            WindowLayoutError::CannotStashLastPane { .. }
        ));
        assert_eq!(
            stored(&paths, "w1"),
            before,
            "a refused last-pane stash left the layout untouched"
        );
    }

    #[test]
    fn stash_pane_rejects_unknown_tab() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        assert!(matches!(
            svc(&paths).stash_pane("w1", "ghost", 5).unwrap_err(),
            WindowLayoutError::TabNotFound { .. }
        ));
    }

    #[test]
    fn mutations_on_missing_window_error() {
        let (_tmp, paths) = temp_paths();
        let err = svc(&paths)
            .open_tab(
                "nope",
                "a",
                "s",
                "A",
                false,
                attn(Attention::None, false),
                1,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            WindowLayoutError::WindowLayoutNotFound { .. }
        ));
    }

    // NOTE: the old per-record `future_version_layout_is_left_byte_identical_and_surfaced` test wrote a raw JSON
    // envelope FILE with a future `schema_version` to assert it was surfaced and left byte-identical. That
    // per-record file mechanism is GONE in the SQLite store: future-version is now a DB-LEVEL guard, tested in
    // store::future_version_db_is_refused_on_open.

    #[test]
    fn old_window_record_without_split_metadata_still_loads() {
        // A tab persisted without split metadata must load back with `split_from` defaulting to None. In the
        // file era this was verified by writing a raw envelope whose tab lacked a `split_from` field (serde
        // `#[serde(default)]`); in the SQLite store `split_from` is a nullable JSON column, so we exercise the
        // same invariant behaviorally: open an ordinary (un-split) tab, reload, and assert its split_from is None.
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w-old", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w-old",
                "t0",
                "s0",
                "Legacy",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();

        let layout = svc(&paths)
            .load("w-old")
            .expect("old record loads")
            .expect("record present");
        assert_eq!(tab_ids(&layout), vec!["t0"]);
        assert_eq!(
            layout.tabs[0].split_from, None,
            "a tab with no split metadata loads with split_from None"
        );
    }

    #[test]
    fn split_tab_appends_new_tab_with_split_metadata() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "t0",
                "s0",
                "Source",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();

        let layout = svc(&paths)
            .split_tab("w1", "t0", "t1", "s1", "Split", SplitAxis::Right, 3)
            .unwrap();

        // The new tab lands LAST, preserving the source order, with contiguous indices.
        assert_eq!(tab_ids(&layout), vec!["t0", "t1"]);
        assert_eq!(indices(&layout), vec![0, 1]);
        let new_tab = layout.tabs.iter().find(|t| t.tab_id == "t1").unwrap();
        assert_eq!(
            new_tab.split_from,
            Some(SplitFrom {
                tab_id: "t0".into(),
                axis: SplitAxis::Right,
                ratio_per_mille: None,
            })
        );
        // The source tab is untouched (no split metadata back-written onto it).
        let src = layout.tabs.iter().find(|t| t.tab_id == "t0").unwrap();
        assert_eq!(src.split_from, None);

        // Persisted: round-trips from disk including the split metadata.
        let reloaded = svc(&paths).load("w1").unwrap().unwrap();
        assert_eq!(reloaded, layout);
    }

    #[test]
    fn split_tab_refuses_missing_source_tab() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        let err = svc(&paths)
            .split_tab("w1", "ghost", "t1", "s1", "Split", SplitAxis::Down, 2)
            .unwrap_err();
        match err {
            WindowLayoutError::TabNotFound { tab_id, .. } => assert_eq!(tab_id, "ghost"),
            other => panic!("expected TabNotFound for the source, got {other:?}"),
        }
        // Nothing was written.
        assert!(svc(&paths).load("w1").unwrap().unwrap().tabs.is_empty());
    }

    #[test]
    fn set_split_ratio_persists_only_the_dragged_child_and_round_trips() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "t0",
                "s0",
                "Source",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();
        svc(&paths)
            .split_tab("w1", "t0", "t1", "s1", "Split", SplitAxis::Right, 3)
            .unwrap();

        let layout = svc(&paths).set_split_ratio("w1", "t1", 333, 4).unwrap();

        // ONLY the dragged child carries the persisted per-mille ratio; the source tab is untouched.
        let child = layout.tabs.iter().find(|t| t.tab_id == "t1").unwrap();
        assert_eq!(
            child.split_from,
            Some(SplitFrom {
                tab_id: "t0".into(),
                axis: SplitAxis::Right,
                ratio_per_mille: Some(333),
            })
        );
        let src = layout.tabs.iter().find(|t| t.tab_id == "t0").unwrap();
        assert_eq!(src.split_from, None);

        // Persisted: the ratio survives a reload from disk.
        let reloaded = svc(&paths).load("w1").unwrap().unwrap();
        assert_eq!(reloaded, layout);
    }

    #[test]
    fn set_split_ratio_clamps_above_one_thousand_and_no_ops_on_a_non_split_tab() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "t0",
                "s0",
                "Plain",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();
        svc(&paths)
            .split_tab("w1", "t0", "t1", "s1", "Split", SplitAxis::Down, 3)
            .unwrap();

        // Over-range input clamps to 1000 on the child.
        let layout = svc(&paths).set_split_ratio("w1", "t1", 5000, 4).unwrap();
        let child = layout.tabs.iter().find(|t| t.tab_id == "t1").unwrap();
        assert_eq!(
            child.split_from.as_ref().unwrap().ratio_per_mille,
            Some(1000)
        );

        // A plain (non-split) tab has no divider to persist: the call succeeds but leaves it `None`.
        let layout = svc(&paths).set_split_ratio("w1", "t0", 600, 5).unwrap();
        let src = layout.tabs.iter().find(|t| t.tab_id == "t0").unwrap();
        assert_eq!(src.split_from, None);

        // An unknown tab id is a typed error.
        let err = svc(&paths)
            .set_split_ratio("w1", "ghost", 500, 6)
            .unwrap_err();
        assert!(matches!(err, WindowLayoutError::TabNotFound { tab_id, .. } if tab_id == "ghost"));
    }

    #[test]
    fn set_pane_rects_writes_verbatim_ignores_unknown_and_round_trips() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "t0",
                "s0",
                "Source",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();
        svc(&paths)
            .split_tab("w1", "t0", "t1", "s1", "Split", SplitAxis::Right, 3)
            .unwrap();

        // Move the shared vertical edge to 40%: left pane 0..400, right pane 400..1000.
        let left = PaneRect {
            x: 0,
            y: 0,
            w: 400,
            h: 1000,
        };
        let right = PaneRect {
            x: 400,
            y: 0,
            w: 600,
            h: 1000,
        };
        let layout = svc(&paths)
            .set_pane_rects(
                "w1",
                &[
                    ("t0".into(), left),
                    ("t1".into(), right),
                    // An unknown id is silently ignored (no error, no resurrection).
                    ("ghost".into(), left),
                ],
                4,
            )
            .unwrap();

        assert_eq!(
            layout
                .tabs
                .iter()
                .find(|t| t.tab_id == "t0")
                .unwrap()
                .pane_rect,
            Some(left)
        );
        assert_eq!(
            layout
                .tabs
                .iter()
                .find(|t| t.tab_id == "t1")
                .unwrap()
                .pane_rect,
            Some(right)
        );
        assert!(!layout.tabs.iter().any(|t| t.tab_id == "ghost"));

        // Persisted: the verbatim rects survive a reload from disk.
        let reloaded = svc(&paths).load("w1").unwrap().unwrap();
        assert_eq!(reloaded, layout);

        // A missing window is a typed error.
        let err = svc(&paths)
            .set_pane_rects("nope", &[("t0".into(), left)], 5)
            .unwrap_err();
        assert!(
            matches!(err, WindowLayoutError::WindowLayoutNotFound { window_id } if window_id == "nope")
        );
    }

    #[test]
    fn old_split_record_without_ratio_field_loads_and_defaults_to_none() {
        // A V-current record JSON whose `split_from` predates the ratio field must still load, with
        // the missing field defaulting to `None` (an even split for the renderer).
        let json = r#"{"tab_id":"t1","session_id":"s1","index":0,"title":"Split","pinned":false,"attention":{"attention":"none","unseen":false,"since_ms":0,"source":"process"},"split_from":{"tab_id":"t0","axis":"right"}}"#;
        let rec: TabRecord = serde_json::from_str(json).unwrap();
        assert_eq!(
            rec.split_from,
            Some(SplitFrom {
                tab_id: "t0".into(),
                axis: SplitAxis::Right,
                ratio_per_mille: None,
            })
        );
    }

    #[test]
    fn split_tab_refuses_duplicate_new_tab_id() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "t0",
                "s0",
                "Source",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();
        let err = svc(&paths)
            .split_tab("w1", "t0", "t0", "s1", "Split", SplitAxis::Right, 3)
            .unwrap_err();
        match err {
            WindowLayoutError::TabAlreadyExists { tab_id, .. } => assert_eq!(tab_id, "t0"),
            other => panic!("expected TabAlreadyExists, got {other:?}"),
        }
        // Layout unchanged: still just the source tab, no split metadata.
        let layout = svc(&paths).load("w1").unwrap().unwrap();
        assert_eq!(tab_ids(&layout), vec!["t0"]);
        assert_eq!(layout.tabs[0].split_from, None);
    }

    // NOTE: the old per-record `corrupt_layout_is_quarantined_and_surfaced` test wrote a malformed raw envelope
    // FILE and asserted the store quarantined it (moved to `corrupt/`). That per-file quarantine mechanism is GONE
    // in the SQLite store; a stored row that won't deserialize into the requested type now surfaces as
    // Quarantined, tested in store::row_that_wont_deserialize_is_quarantined_and_excluded.

    #[test]
    fn tab_view_sorts_by_index_and_joins_task_report() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        // Open in one order...
        for (id, s) in [("a", "sa"), ("b", "sb"), ("c", "sc")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        // ...then reorder so index order differs from insertion order.
        let order = vec!["c".to_string(), "a".to_string(), "b".to_string()];
        svc(&paths).reorder_tabs("w1", &order, 3).unwrap();

        // Task report: a Running task whose current session is tab "a"'s session, exited -> needs
        // attention; nothing for b/c.
        let report = AgentTaskReconcileReport {
            tasks: vec![reconciled(
                "task-a",
                AgentTaskState::Running,
                Some("sa"),
                Some(SessionStatus::Exited),
                false,
                true,
            )],
            ..Default::default()
        };

        let views = svc(&paths).tab_view("w1", &report).unwrap();
        let view_ids: Vec<&str> = views.iter().map(|v| v.tab_id.as_str()).collect();
        assert_eq!(view_ids, vec!["c", "a", "b"], "sorted by index");
        assert_eq!(
            views.iter().map(|v| v.index).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );

        let a = views.iter().find(|v| v.tab_id == "a").unwrap();
        assert_eq!(a.agent_task_id.as_deref(), Some("task-a"));
        assert_eq!(a.agent_task_state, Some(AgentTaskState::Running));
        assert_eq!(a.session_status, Some(SessionStatus::Exited));
        assert!(a.needs_attention, "joined task needs attention");

        let b = views.iter().find(|v| v.tab_id == "b").unwrap();
        assert_eq!(b.agent_task_id, None, "no task links to b");
        assert_eq!(b.agent_task_state, None);
        assert_eq!(b.session_status, None);
        assert!(!b.needs_attention);
    }

    #[test]
    fn tab_view_uses_persisted_attention_when_no_task_links() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        // Persisted unseen Error attention, but NO linking task in the report.
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::Error, true), 2)
            .unwrap();
        // A non-unseen signal must NOT flag attention.
        svc(&paths)
            .open_tab(
                "w1",
                "b",
                "sb",
                "B",
                false,
                attn(Attention::Error, false),
                3,
            )
            .unwrap();
        // unseen but None attention must NOT flag.
        svc(&paths)
            .open_tab("w1", "c", "sc", "C", false, attn(Attention::None, true), 4)
            .unwrap();

        let views = svc(&paths)
            .tab_view("w1", &AgentTaskReconcileReport::default())
            .unwrap();
        let a = views.iter().find(|v| v.tab_id == "a").unwrap();
        let b = views.iter().find(|v| v.tab_id == "b").unwrap();
        let c = views.iter().find(|v| v.tab_id == "c").unwrap();
        assert!(
            a.needs_attention,
            "unseen non-None persisted attention flags"
        );
        assert!(!b.needs_attention, "seen attention does not flag");
        assert!(!c.needs_attention, "unseen None does not flag");
    }

    #[test]
    fn tab_view_carries_split_from_for_split_tabs() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "t0",
                "s0",
                "Source",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();
        svc(&paths)
            .split_tab("w1", "t0", "t1", "s1", "Split", SplitAxis::Down, 3)
            .unwrap();

        let views = svc(&paths)
            .tab_view("w1", &AgentTaskReconcileReport::default())
            .unwrap();
        let src = views.iter().find(|v| v.tab_id == "t0").unwrap();
        let split = views.iter().find(|v| v.tab_id == "t1").unwrap();
        // The ordinary source tab carries no split provenance.
        assert_eq!(src.split_from, None);
        // The split tab's view carries the persisted source id + axis verbatim.
        assert_eq!(
            split.split_from,
            Some(SplitFrom {
                tab_id: "t0".into(),
                axis: SplitAxis::Down,
                ratio_per_mille: None,
            })
        );
        // CRITICAL: tab_view (the path the 750ms periodic strip refresh uses) must carry the
        // AUTHORITATIVE pane_rect — dropping it here made the periodic rebuild repaint from the
        // split_from chain, snapping the layout to another shape ~750ms after every op.
        // split a down -> b: A│B as a row split = A top half, t1 bottom half.
        assert_eq!(
            src.pane_rect,
            Some(PaneRect {
                x: 0,
                y: 0,
                w: 1000,
                h: 500
            })
        );
        assert_eq!(
            split.pane_rect,
            Some(PaneRect {
                x: 0,
                y: 500,
                w: 1000,
                h: 500
            })
        );
    }

    #[test]
    fn tab_view_handles_missing_task_session_linkage_without_error() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // A task whose current_session_id is None (no linkage) and one pointing elsewhere.
        let report = AgentTaskReconcileReport {
            tasks: vec![
                reconciled("t-none", AgentTaskState::Draft, None, None, false, false),
                reconciled(
                    "t-other",
                    AgentTaskState::Running,
                    Some("s-elsewhere"),
                    Some(SessionStatus::Live),
                    false,
                    false,
                ),
            ],
            ..Default::default()
        };
        let views = svc(&paths).tab_view("w1", &report).unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].agent_task_id, None);
        assert!(!views[0].needs_attention);
    }

    #[test]
    fn tab_view_on_missing_window_errors() {
        let (_tmp, paths) = temp_paths();
        let err = svc(&paths)
            .tab_view("nope", &AgentTaskReconcileReport::default())
            .unwrap_err();
        assert!(matches!(
            err,
            WindowLayoutError::WindowLayoutNotFound { .. }
        ));
    }

    /// REGRESSION (user report: "no live pane may be hidden by layout math"). Splitting FROM a pane that
    /// isn't in the live set (e.g. a stashed source) used to push the new tab LIVE but with no rect — an
    /// invisible green pane. The split must always operate from a real live pane (the active one) and
    /// every resulting live pane must have a rect that tiles the screen.
    #[test]
    fn split_from_stashed_source_never_leaves_a_live_pane_without_a_rect() {
        let (_tmp, paths) = temp_paths();
        let s = svc(&paths);
        s.create_empty("w1", 1).unwrap();
        s.open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // A│B, then stash A (stash_pane fills A's space with B, so the live set tiles: B = full screen).
        s.split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        s.stash_pane("w1", "a", 4).unwrap();

        // Split FROM the now-stashed pane "a" (a stale/non-live source). The new pane must still land as a
        // real live pane with a rect — never a hidden, rect-less live tab — and the result must tile.
        let l = s
            .split_tab("w1", "a", "c", "sc", "C", SplitAxis::Down, 5)
            .unwrap();

        // INVARIANT: every live (non-stashed) pane has a rect (nothing hidden).
        let live: Vec<_> = l.tabs.iter().filter(|t| !t.stashed).collect();
        for t in &live {
            assert!(
                t.pane_rect.is_some(),
                "live pane {:?} has no rect — it would be invisible",
                t.tab_id
            );
        }
        // INVARIANT: the live rects perfectly tile the screen (no overlap/gap/overflow).
        let rects: Vec<AgentRect> = live
            .iter()
            .map(|t| AgentRect {
                agent: t.tab_id.clone(),
                rect: t.pane_rect.unwrap().to_unit(),
            })
            .collect();
        assert!(
            rects_tile_unit_square(&rects),
            "live panes must tile the unit square; got {rects:?}"
        );
    }

    /// REGRESSION (user case: "A|B/C|D, drag C to the first row"). In the 2×2 grid (A│B)/(C│D), dragging
    /// the bottom-left pane C up beside A must: land C visibly in the top row, expand D to fill the freed
    /// bottom row, hide nothing, and keep the live rects tiling the window.
    #[test]
    fn drag_c_to_first_row_keeps_all_panes_visible_and_tiling() {
        let (_tmp, paths) = temp_paths();
        let s = svc(&paths);
        s.create_empty("w1", 1).unwrap();
        s.open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // Build (A│B)/(C│D): A/C, then A│B (top), then C│D (bottom).
        s.split_tab("w1", "a", "c", "sc", "C", SplitAxis::Down, 3)
            .unwrap();
        s.split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 4)
            .unwrap();
        s.split_tab("w1", "c", "d", "sd", "D", SplitAxis::Right, 5)
            .unwrap();

        // Sanity: 4 live panes before the drag.
        let pre = s
            .require("w1")
            .unwrap()
            .tabs
            .iter()
            .filter(|t| !t.stashed)
            .count();
        assert_eq!(pre, 4, "precondition: 4 live panes");

        // Drag C up beside A — i.e. dock C onto A's TOP edge. (Source C is live; D should fill C's freed
        // bottom-left space, then C inserts into A's row.)
        let l = s.dock_tab_at_edge("w1", "c", "a", EdgeDir::Top, 6).unwrap();

        let live: Vec<_> = l.tabs.iter().filter(|t| !t.stashed).collect();
        // Nothing hidden: every live pane has a rect.
        for t in &live {
            assert!(
                t.pane_rect.is_some(),
                "live pane {:?} has no rect after the drag — it would be invisible",
                t.tab_id
            );
        }
        // All four still live (C wasn't lost, D wasn't replaced).
        assert_eq!(
            live.len(),
            4,
            "all four panes stay live after dragging C to the first row"
        );
        // Live rects tile the window — no gap/overlap.
        let rects: Vec<AgentRect> = live
            .iter()
            .map(|t| AgentRect {
                agent: t.tab_id.clone(),
                rect: t.pane_rect.unwrap().to_unit(),
            })
            .collect();
        assert!(
            rects_tile_unit_square(&rects),
            "live panes must tile after the drag; got {rects:?}"
        );
    }

    #[test]
    fn open_tab_dedups_title_within_window() {
        let (_tmp, paths) = temp_paths();
        let s = svc(&paths);
        s.create_empty("w1", 1).unwrap();
        s.open_tab(
            "w1",
            "a",
            "sa",
            "shell",
            false,
            attn(Attention::None, false),
            2,
        )
        .unwrap();
        let layout = s
            .open_tab(
                "w1",
                "b",
                "sb",
                "shell",
                false,
                attn(Attention::None, false),
                3,
            )
            .unwrap();
        let titles: Vec<&str> = layout.tabs.iter().map(|t| t.title.as_str()).collect();
        assert_eq!(
            titles,
            vec!["shell", "shell 2"],
            "duplicate pane title auto-numbers"
        );
    }

    #[test]
    fn rename_tab_dedups_against_siblings_but_self_is_noop() {
        let (_tmp, paths) = temp_paths();
        let s = svc(&paths);
        s.create_empty("w1", 1).unwrap();
        s.open_tab(
            "w1",
            "a",
            "sa",
            "Pane 1",
            false,
            attn(Attention::None, false),
            2,
        )
        .unwrap();
        s.open_tab(
            "w1",
            "b",
            "sb",
            "Pane 2",
            false,
            attn(Attention::None, false),
            3,
        )
        .unwrap();
        // rename b to a's title → collides → auto-numbers.
        let layout = s.rename_tab("w1", "b", "Pane 1", 4).unwrap();
        let b = layout.tabs.iter().find(|t| t.tab_id == "b").unwrap();
        assert_eq!(
            b.title, "Pane 2",
            "rename to an existing title bumps the counter"
        );
        // rename a to its OWN current title → no-op (self excluded).
        let layout = s.rename_tab("w1", "a", "Pane 1", 5).unwrap();
        let a = layout.tabs.iter().find(|t| t.tab_id == "a").unwrap();
        assert_eq!(a.title, "Pane 1", "rename-to-self keeps the name");
    }
}
