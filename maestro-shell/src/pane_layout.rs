//! Pure canonical pane-layout engine: the bounded registry of named multi-pane layouts plus the
//! transitions over them (swap, swallow, split-growth, revive). This is a native model with no
//! terminal-multiplexer or React coupling.
//!
//! Built so far: the [`CanonicalLayout`] registry, the [`SlotId`] topology of each layout, the
//! per-layout unit-square geometry [`slot_rects`], ratio normalization [`normalize_ratios`], the
//! [`PaneLayoutModel`] (agent-to-slot assignment) with `from_agents` and the involutive `swap_agents`,
//! the [`PaneLayoutModel::apply_swallow`] transition (re-snap a pane to a full row/column main on a
//! same-pane-count target layout, per the self-inverse [`swallow_target`] table), and the pane-count
//! transitions: [`PaneLayoutModel::split_in_direction`] (+1 new pane at an edge, [`split_growth_target`]),
//! [`PaneLayoutModel::revive`] (+1 stashed pane back, [`revive_target`]), and
//! [`PaneLayoutModel::reduce_removing`] (−1, survivors re-snap to the smaller default). Max 4 active
//! panes is enforced by every grow path returning `None` at the cap. Everything here is pure: no IO, no
//! sessions, no daemon, no pixels. Rects live in the unit square `[0,1] x [0,1]`; the renderer maps them
//! to cells/pixels elsewhere.
//!
//! Invariants the tests pin down: every layout's slot rects TILE the unit square (area sums to 1, no
//! overlap, all in-bounds), slots are returned in READING ORDER (y then x ascending),
//! [`normalize_ratios`] always yields complete, clamped, 2-dp ratios with ordered-cut layouts keeping a
//! monotone gap between adjacent cuts, and swallow is self-inverse across the opposite axis while
//! preserving agents in reading order.

use std::collections::BTreeMap;

/// Minimum gap enforced between adjacent cuts in an ordered-cut layout (columns/rows), so two dividers
/// can never cross or coincide. A fraction of the splittable axis.
pub const MIN_CUT_GAP: f32 = 0.05;

/// Decimal places ratios are rounded to, so persisted/compared ratios are stable and free of float
/// noise.
pub const RATIO_PRECISION: u32 = 2;

/// A named position within a layout. Slots are layout-local and always referred to in reading order
/// (`S0` first). A layout uses a contiguous prefix of these (`one-full` uses only `S0`; a 4-pane layout
/// uses `S0..=S3`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SlotId {
    S0,
    S1,
    S2,
    S3,
}

impl SlotId {
    /// The first `n` slots in reading order. `n` is the layout's pane count (1..=4).
    fn first(n: usize) -> &'static [SlotId] {
        const ALL: [SlotId; 4] = [SlotId::S0, SlotId::S1, SlotId::S2, SlotId::S3];
        &ALL[..n]
    }
}

/// A named split divider within a layout. Each layout names only the cuts it actually has; the ratio
/// map is keyed by these. Values are the position of the cut along its axis as a fraction in `(0,1)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SplitId {
    /// First vertical cut (left|right) in a column layout, or the main|side cut in a `*-columns`.
    Col0,
    /// Second vertical cut (for 3+ column layouts).
    Col1,
    /// Third vertical cut (for 4-column layouts).
    Col2,
    /// First horizontal cut in a row layout.
    Row0,
    /// Second horizontal cut (for 3+ row layouts).
    Row1,
    /// Third horizontal cut (for 4-row layouts).
    Row2,
    /// The big pane's share in a `*-main` mixed layout (main|rest along the main axis).
    Main,
    /// The stacked side's internal divider in a `*-main` mixed layout.
    Side,
}

/// The 14 canonical layouts. Each names a fixed topology (which slots exist and how they tile the unit
/// square given the ratio map). Transitions move between these ids without inventing geometry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CanonicalLayout {
    OneFull,
    TwoColumns,
    TwoRows,
    ThreeColumns,
    ThreeRows,
    ThreeLeftMain,
    ThreeRightMain,
    ThreeTopMain,
    ThreeBottomMain,
    FourGrid,
    FourColumns,
    FourRows,
    FourLeftSplit,
    FourTopSplit,
    FourLeftMain,
    FourRightMain,
    FourTopMain,
    FourBottomMain,
}

/// A rect in the unit square: `[x, y, w, h]`, all in `[0,1]`, `w,h > 0`.
pub type UnitRect = [f32; 4];

/// One split's allowed band and default, used by [`normalize_ratios`].
struct SplitSpec {
    id: SplitId,
    min: f32,
    max: f32,
    default: f32,
}

const fn spec(id: SplitId, min: f32, max: f32, default: f32) -> SplitSpec {
    SplitSpec {
        id,
        min,
        max,
        default,
    }
}

impl CanonicalLayout {
    /// Number of panes (slots) this layout holds: 1..=4.
    pub fn pane_count(self) -> usize {
        match self {
            CanonicalLayout::OneFull => 1,
            CanonicalLayout::TwoColumns | CanonicalLayout::TwoRows => 2,
            CanonicalLayout::ThreeColumns
            | CanonicalLayout::ThreeRows
            | CanonicalLayout::ThreeLeftMain
            | CanonicalLayout::ThreeRightMain
            | CanonicalLayout::ThreeTopMain
            | CanonicalLayout::ThreeBottomMain => 3,
            CanonicalLayout::FourGrid
            | CanonicalLayout::FourColumns
            | CanonicalLayout::FourRows
            | CanonicalLayout::FourLeftSplit
            | CanonicalLayout::FourTopSplit
            | CanonicalLayout::FourLeftMain
            | CanonicalLayout::FourRightMain
            | CanonicalLayout::FourTopMain
            | CanonicalLayout::FourBottomMain => 4,
        }
    }

    /// The layout's slots in reading order (a contiguous prefix of [`SlotId`]).
    pub fn slots(self) -> &'static [SlotId] {
        SlotId::first(self.pane_count())
    }

    /// Whether this layout's cuts are ORDERED along one axis (the `*-columns` / `*-rows` families),
    /// where adjacent cuts must keep a [`MIN_CUT_GAP`] and stay monotonically increasing.
    fn ordered_cuts(self) -> Option<&'static [SplitId]> {
        match self {
            CanonicalLayout::ThreeColumns | CanonicalLayout::ThreeRows => {
                Some(&[SplitId::Col0, SplitId::Col1])
            }
            CanonicalLayout::FourColumns | CanonicalLayout::FourRows => {
                Some(&[SplitId::Col0, SplitId::Col1, SplitId::Col2])
            }
            CanonicalLayout::FourLeftMain
            | CanonicalLayout::FourRightMain
            | CanonicalLayout::FourTopMain
            | CanonicalLayout::FourBottomMain => Some(&[SplitId::Col0, SplitId::Col1]),
            _ => None,
        }
    }

    /// The splits this layout uses, with their allowed bands and defaults. The single source of truth
    /// for both [`normalize_ratios`] and [`slot_rects`] (which reads the normalized values).
    fn split_specs(self) -> Vec<SplitSpec> {
        // For the ordered `*-rows` families the cuts are horizontal but reuse the `Col*` ids with the
        // same bands; geometry decides the axis. This keeps the ordered-cut machinery uniform.
        match self {
            CanonicalLayout::OneFull => vec![],
            CanonicalLayout::TwoColumns | CanonicalLayout::TwoRows => {
                vec![spec(SplitId::Col0, 0.2, 0.8, 0.5)]
            }
            CanonicalLayout::ThreeColumns | CanonicalLayout::ThreeRows => vec![
                spec(SplitId::Col0, 0.15, 0.6, 1.0 / 3.0),
                spec(SplitId::Col1, 0.4, 0.85, 2.0 / 3.0),
            ],
            CanonicalLayout::ThreeLeftMain
            | CanonicalLayout::ThreeRightMain
            | CanonicalLayout::ThreeTopMain
            | CanonicalLayout::ThreeBottomMain => vec![
                spec(SplitId::Main, 0.2, 0.8, 0.6),
                spec(SplitId::Side, 0.2, 0.8, 0.5),
            ],
            CanonicalLayout::FourGrid => vec![
                spec(SplitId::Col0, 0.2, 0.8, 0.5),
                spec(SplitId::Row0, 0.2, 0.8, 0.5),
            ],
            CanonicalLayout::FourColumns | CanonicalLayout::FourRows => vec![
                spec(SplitId::Col0, 0.1, 0.4, 0.25),
                spec(SplitId::Col1, 0.35, 0.65, 0.5),
                spec(SplitId::Col2, 0.6, 0.9, 0.75),
            ],
            CanonicalLayout::FourLeftSplit => vec![
                spec(SplitId::Col0, 0.15, 0.6, 1.0 / 3.0),
                spec(SplitId::Col1, 0.4, 0.85, 2.0 / 3.0),
                spec(SplitId::Row0, 0.2, 0.8, 0.5),
            ],
            CanonicalLayout::FourTopSplit => vec![
                spec(SplitId::Row0, 0.15, 0.6, 1.0 / 3.0),
                spec(SplitId::Row1, 0.4, 0.85, 2.0 / 3.0),
                spec(SplitId::Col0, 0.2, 0.8, 0.5),
            ],
            CanonicalLayout::FourLeftMain
            | CanonicalLayout::FourRightMain
            | CanonicalLayout::FourTopMain
            | CanonicalLayout::FourBottomMain => vec![
                spec(SplitId::Main, 0.2, 0.8, 0.55),
                spec(SplitId::Col0, 0.15, 0.6, 1.0 / 3.0),
                spec(SplitId::Col1, 0.4, 0.85, 2.0 / 3.0),
            ],
        }
    }
}

/// Round a fraction to [`RATIO_PRECISION`] decimal places.
fn round_ratio(v: f32) -> f32 {
    let f = 10f32.powi(RATIO_PRECISION as i32);
    (v * f).round() / f
}

/// Complete, clamp, order, and round the ratio map for `layout`. Missing splits take their default;
/// each is clamped to its band; ordered-cut layouts then have adjacent cuts pushed apart to keep at
/// least [`MIN_CUT_GAP`] monotone increasing (walking back from the right edge if forward clamping
/// crossed a later cut); finally every value is rounded to [`RATIO_PRECISION`]. The result has exactly
/// the splits `layout` uses and nothing else — so [`slot_rects`] can read it without re-deriving.
pub fn normalize_ratios(
    layout: CanonicalLayout,
    partial: &BTreeMap<SplitId, f32>,
) -> BTreeMap<SplitId, f32> {
    let mut out = BTreeMap::new();
    for s in layout.split_specs() {
        let v = partial.get(&s.id).copied().unwrap_or(s.default);
        let clamped = v.clamp(s.min, s.max);
        out.insert(s.id, clamped);
    }

    if let Some(order) = layout.ordered_cuts() {
        // Forward pass: each cut at least MIN_CUT_GAP past its predecessor.
        for w in order.windows(2) {
            let prev = out[&w[0]];
            let cur = out[&w[1]];
            if cur < prev + MIN_CUT_GAP {
                out.insert(w[1], prev + MIN_CUT_GAP);
            }
        }
        // Backward pass: if the forward pass pushed the last cut past 1.0 - gap, walk back so every cut
        // stays in (0,1) with the gap preserved. The rightmost cut is capped below 1.0.
        let n = order.len();
        let mut upper = 1.0 - MIN_CUT_GAP;
        for &id in order.iter().rev().take(n) {
            let cur = out[&id];
            if cur > upper {
                out.insert(id, upper);
            }
            upper = out[&id] - MIN_CUT_GAP;
        }
    }

    for v in out.values_mut() {
        *v = round_ratio(*v);
    }
    out
}

/// The unit-square rects of `layout`'s slots, in reading order, given a ratio map (normalized
/// internally so callers may pass a partial/empty map). Each returned rect pairs with the slot at the
/// same index in [`CanonicalLayout::slots`]. The rects tile the unit square: areas sum to 1, no two
/// overlap, all lie within `[0,1]`.
pub fn slot_rects(layout: CanonicalLayout, ratios: &BTreeMap<SplitId, f32>) -> Vec<UnitRect> {
    let r = normalize_ratios(layout, ratios);
    let g = |id: SplitId| r[&id];
    match layout {
        CanonicalLayout::OneFull => vec![[0.0, 0.0, 1.0, 1.0]],
        CanonicalLayout::TwoColumns => {
            let c = g(SplitId::Col0);
            vec![[0.0, 0.0, c, 1.0], [c, 0.0, 1.0 - c, 1.0]]
        }
        CanonicalLayout::TwoRows => {
            let c = g(SplitId::Col0);
            vec![[0.0, 0.0, 1.0, c], [0.0, c, 1.0, 1.0 - c]]
        }
        CanonicalLayout::ThreeColumns => {
            let a = g(SplitId::Col0);
            let b = g(SplitId::Col1);
            vec![
                [0.0, 0.0, a, 1.0],
                [a, 0.0, b - a, 1.0],
                [b, 0.0, 1.0 - b, 1.0],
            ]
        }
        CanonicalLayout::ThreeRows => {
            let a = g(SplitId::Col0);
            let b = g(SplitId::Col1);
            vec![
                [0.0, 0.0, 1.0, a],
                [0.0, a, 1.0, b - a],
                [0.0, b, 1.0, 1.0 - b],
            ]
        }
        CanonicalLayout::ThreeLeftMain => {
            let m = g(SplitId::Main);
            let s = g(SplitId::Side);
            vec![
                [0.0, 0.0, m, 1.0],
                [m, 0.0, 1.0 - m, s],
                [m, s, 1.0 - m, 1.0 - s],
            ]
        }
        CanonicalLayout::ThreeRightMain => {
            let m = g(SplitId::Main);
            let s = g(SplitId::Side);
            let left = 1.0 - m;
            vec![
                [0.0, 0.0, left, s],
                [left, 0.0, m, 1.0],
                [0.0, s, left, 1.0 - s],
            ]
        }
        CanonicalLayout::ThreeTopMain => {
            let m = g(SplitId::Main);
            let s = g(SplitId::Side);
            vec![
                [0.0, 0.0, 1.0, m],
                [0.0, m, s, 1.0 - m],
                [s, m, 1.0 - s, 1.0 - m],
            ]
        }
        CanonicalLayout::ThreeBottomMain => {
            let m = g(SplitId::Main);
            let s = g(SplitId::Side);
            let top = 1.0 - m;
            vec![
                [0.0, 0.0, s, top],
                [s, 0.0, 1.0 - s, top],
                [0.0, top, 1.0, m],
            ]
        }
        CanonicalLayout::FourGrid => {
            let c = g(SplitId::Col0);
            let r0 = g(SplitId::Row0);
            vec![
                [0.0, 0.0, c, r0],
                [c, 0.0, 1.0 - c, r0],
                [0.0, r0, c, 1.0 - r0],
                [c, r0, 1.0 - c, 1.0 - r0],
            ]
        }
        CanonicalLayout::FourColumns => {
            let a = g(SplitId::Col0);
            let b = g(SplitId::Col1);
            let d = g(SplitId::Col2);
            vec![
                [0.0, 0.0, a, 1.0],
                [a, 0.0, b - a, 1.0],
                [b, 0.0, d - b, 1.0],
                [d, 0.0, 1.0 - d, 1.0],
            ]
        }
        CanonicalLayout::FourRows => {
            let a = g(SplitId::Col0);
            let b = g(SplitId::Col1);
            let d = g(SplitId::Col2);
            vec![
                [0.0, 0.0, 1.0, a],
                [0.0, a, 1.0, b - a],
                [0.0, b, 1.0, d - b],
                [0.0, d, 1.0, 1.0 - d],
            ]
        }
        CanonicalLayout::FourLeftSplit => {
            let c0 = g(SplitId::Col0);
            let c1 = g(SplitId::Col1);
            let row = g(SplitId::Row0);
            vec![
                [0.0, 0.0, c0, row],
                [c0, 0.0, c1 - c0, 1.0],
                [c1, 0.0, 1.0 - c1, 1.0],
                [0.0, row, c0, 1.0 - row],
            ]
        }
        CanonicalLayout::FourTopSplit => {
            let r0 = g(SplitId::Row0);
            let r1 = g(SplitId::Row1);
            let col = g(SplitId::Col0);
            vec![
                [0.0, 0.0, col, r0],
                [col, 0.0, 1.0 - col, r0],
                [0.0, r0, 1.0, r1 - r0],
                [0.0, r1, 1.0, 1.0 - r1],
            ]
        }
        CanonicalLayout::FourLeftMain => {
            let m = g(SplitId::Main);
            let a = g(SplitId::Col0);
            let b = g(SplitId::Col1);
            let side = 1.0 - m;
            vec![
                [0.0, 0.0, m, 1.0],
                [m, 0.0, side, a],
                [m, a, side, b - a],
                [m, b, side, 1.0 - b],
            ]
        }
        CanonicalLayout::FourRightMain => {
            let m = g(SplitId::Main);
            let a = g(SplitId::Col0);
            let b = g(SplitId::Col1);
            let side = 1.0 - m;
            vec![
                [0.0, 0.0, side, a],
                [side, 0.0, m, 1.0],
                [0.0, a, side, b - a],
                [0.0, b, side, 1.0 - b],
            ]
        }
        CanonicalLayout::FourTopMain => {
            let m = g(SplitId::Main);
            let a = g(SplitId::Col0);
            let b = g(SplitId::Col1);
            let side = 1.0 - m;
            vec![
                [0.0, 0.0, 1.0, m],
                [0.0, m, a, side],
                [a, m, b - a, side],
                [b, m, 1.0 - b, side],
            ]
        }
        CanonicalLayout::FourBottomMain => {
            let m = g(SplitId::Main);
            let a = g(SplitId::Col0);
            let b = g(SplitId::Col1);
            let side = 1.0 - m;
            vec![
                [0.0, 0.0, a, side],
                [a, 0.0, b - a, side],
                [b, 0.0, 1.0 - b, side],
                [0.0, side, 1.0, m],
            ]
        }
    }
}

/// An agent (pane occupant) identifier — the stable id of the session/agent shown in a slot. The
/// layout engine treats it opaquely; it only permutes and preserves these strings.
pub type AgentId = String;

/// A complete window layout: which canonical topology is active, which agent occupies each slot, and
/// the (un-normalized) ratio map. Construct via [`PaneLayoutModel::from_agents`] or the transitions;
/// the invariants ([`PaneLayoutModel::is_valid`]) are: exactly the layout's slots are assigned (no
/// holes, no extras) and no agent occupies two slots.
#[derive(Clone, Debug, PartialEq)]
pub struct PaneLayoutModel {
    pub layout: CanonicalLayout,
    pub assignment: BTreeMap<SlotId, AgentId>,
    pub ratios: BTreeMap<SplitId, f32>,
}

/// Why a [`PaneLayoutModel`] operation could not be performed. Pure/value errors — no IO.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PaneLayoutError {
    /// The agent count does not match any canonical layout (must be 1..=4).
    UnsupportedAgentCount { count: usize },
    /// An agent id was empty.
    EmptyAgentId,
    /// Two agents shared the same id (occupancy must be unique).
    DuplicateAgent { agent: AgentId },
    /// An operation named an agent that is not in the model.
    AgentNotFound { agent: AgentId },
}

/// The default canonical layout for `n` panes: the simplest uniform topology (1=full, 2=columns,
/// 3=columns, 4=grid). `None` when `n` is out of the 1..=4 range.
pub fn default_layout_for(n: usize) -> Option<CanonicalLayout> {
    match n {
        1 => Some(CanonicalLayout::OneFull),
        2 => Some(CanonicalLayout::TwoColumns),
        3 => Some(CanonicalLayout::ThreeColumns),
        4 => Some(CanonicalLayout::FourGrid),
        _ => None,
    }
}

impl PaneLayoutModel {
    /// Build a model from agents in READING ORDER, assigning the i-th agent to the i-th slot of
    /// `prefer` (or the [`default_layout_for`] the count if `prefer` is `None` or has the wrong pane
    /// count). Ratios start empty (defaults apply on read). Fails on an unsupported count (not 1..=4),
    /// an empty id, or a duplicate id.
    pub fn from_agents(
        agents: &[AgentId],
        prefer: Option<CanonicalLayout>,
    ) -> Result<Self, PaneLayoutError> {
        let layout = match prefer {
            Some(p) if p.pane_count() == agents.len() => p,
            _ => {
                default_layout_for(agents.len()).ok_or(PaneLayoutError::UnsupportedAgentCount {
                    count: agents.len(),
                })?
            }
        };
        let mut assignment = BTreeMap::new();
        for (slot, agent) in layout.slots().iter().copied().zip(agents.iter()) {
            if agent.is_empty() {
                return Err(PaneLayoutError::EmptyAgentId);
            }
            if assignment.values().any(|a: &AgentId| a == agent) {
                return Err(PaneLayoutError::DuplicateAgent {
                    agent: agent.clone(),
                });
            }
            assignment.insert(slot, agent.clone());
        }
        Ok(Self {
            layout,
            assignment,
            ratios: BTreeMap::new(),
        })
    }

    /// Whether the model satisfies the no-hole / unique-occupancy invariants: exactly the layout's
    /// slots are assigned (one agent each, none missing, none extra) and no agent appears twice.
    pub fn is_valid(&self) -> bool {
        let slots = self.layout.slots();
        if self.assignment.len() != slots.len() {
            return false;
        }
        if !slots.iter().all(|s| self.assignment.contains_key(s)) {
            return false;
        }
        let mut seen = std::collections::BTreeSet::new();
        self.assignment
            .values()
            .all(|a| !a.is_empty() && seen.insert(a.clone()))
    }

    /// The agent currently in `slot`, if assigned.
    pub fn agent_at(&self, slot: SlotId) -> Option<&AgentId> {
        self.assignment.get(&slot)
    }

    /// The slot currently holding `agent`, if any.
    pub fn slot_of(&self, agent: &str) -> Option<SlotId> {
        self.assignment
            .iter()
            .find(|(_, a)| a.as_str() == agent)
            .map(|(s, _)| *s)
    }

    /// Swap two agents' SLOTS, leaving the layout id and ratios untouched (a pure positional
    /// permutation). Both agents must be in the model; swapping an agent with itself is a no-op. The
    /// operation is involutive: applying it twice with the same pair restores the original assignment.
    /// Sessions/labels are preserved — only which slot each agent sits in changes.
    pub fn swap_agents(&self, agent_a: &str, agent_b: &str) -> Result<Self, PaneLayoutError> {
        let slot_a = self
            .slot_of(agent_a)
            .ok_or_else(|| PaneLayoutError::AgentNotFound {
                agent: agent_a.to_string(),
            })?;
        let slot_b = self
            .slot_of(agent_b)
            .ok_or_else(|| PaneLayoutError::AgentNotFound {
                agent: agent_b.to_string(),
            })?;
        let mut next = self.clone();
        if slot_a != slot_b {
            next.assignment.insert(slot_a, agent_b.to_string());
            next.assignment.insert(slot_b, agent_a.to_string());
        }
        Ok(next)
    }

    /// The model's agents in the SOURCE layout's reading order (slot S0, S1, ...). Used when re-snapping
    /// to a different canonical layout of the SAME pane count so spatial reading order is preserved.
    fn agents_in_reading_order(&self) -> Vec<AgentId> {
        self.layout
            .slots()
            .iter()
            .filter_map(|s| self.assignment.get(s).cloned())
            .collect()
    }

    fn main_slot_for_layout(layout: CanonicalLayout) -> Option<SlotId> {
        match layout {
            CanonicalLayout::ThreeLeftMain | CanonicalLayout::ThreeTopMain => Some(SlotId::S0),
            CanonicalLayout::ThreeRightMain => Some(SlotId::S1),
            CanonicalLayout::ThreeBottomMain => Some(SlotId::S2),
            // 4-pane mains: the full-span main is the slot the enlarged pane occupies (verified against
            // slot_rects reading order). LeftMain/TopMain main = S0; RightMain main = S1 (the right
            // full-height column comes 2nd in reading order); BottomMain main = S3 (the full-width row).
            CanonicalLayout::FourLeftMain | CanonicalLayout::FourTopMain => Some(SlotId::S0),
            CanonicalLayout::FourRightMain => Some(SlotId::S1),
            CanonicalLayout::FourBottomMain => Some(SlotId::S3),
            _ => None,
        }
    }

    /// Swallow: the pane in `slot` expands to reclaim a full row/column, re-snapping the whole model to
    /// a different canonical layout of the SAME pane count where that pane becomes the full-span main on
    /// its band. The selected pane is rebound into the target layout's main slot; the remaining agents
    /// keep their relative reading order in the remaining target slots. Ratios reset to the target
    /// layout's defaults (the topology changed). Returns `None` when the `(layout, slot, dir)`
    /// combination has no legal swallow (per [`swallow_target`]) — the caller should treat that as "no
    /// valid target" and leave the model unchanged.
    ///
    /// Self-inverse across the opposite axis: swallowing a pane one way and then the perpendicular way
    /// returns to the original layout (see the table in [`swallow_target`]).
    pub fn apply_swallow(&self, slot: SlotId, dir: SwallowDir) -> Option<Self> {
        let target = swallow_target(self.layout, slot, dir)?;
        debug_assert_eq!(target.pane_count(), self.layout.pane_count());
        let selected = self.assignment.get(&slot)?.clone();
        let main_slot = Self::main_slot_for_layout(target)?;
        let mut next = PaneLayoutModel {
            layout: target,
            assignment: BTreeMap::new(),
            ratios: BTreeMap::new(),
        };
        next.assignment.insert(main_slot, selected.clone());
        let mut survivors = self
            .agents_in_reading_order()
            .into_iter()
            .filter(|agent| agent != &selected);
        for target_slot in target.slots().iter().copied().filter(|s| *s != main_slot) {
            next.assignment.insert(target_slot, survivors.next()?);
        }
        survivors.next().is_none().then_some(next)
    }

    /// Split-growth: drop a NEW agent at the given edge, growing the layout by one pane along that edge.
    /// The new agent lands at the slot the [`split_growth_target`] table designates for that edge (a
    /// fresh column/row at the L/R/T/B boundary), survivors keep their reading order. Returns `None`
    /// when the layout is already at the 4-pane max, when `new_agent` is empty/already present, or when
    /// the `(layout, edge)` pair is ambiguous (e.g. T/B on a column layout — the caller must show a
    /// picker, not guess). Ratios reset to the target layout's defaults.
    pub fn split_in_direction(
        &self,
        edge: EdgeDir,
        new_agent: &str,
    ) -> Result<Option<Self>, PaneLayoutError> {
        if new_agent.is_empty() {
            return Err(PaneLayoutError::EmptyAgentId);
        }
        if self.assignment.values().any(|a| a == new_agent) {
            return Err(PaneLayoutError::DuplicateAgent {
                agent: new_agent.to_string(),
            });
        }
        let Some((target, at_front)) = split_growth_target(self.layout, edge) else {
            return Ok(None);
        };
        debug_assert_eq!(target.pane_count(), self.layout.pane_count() + 1);
        let mut agents = self.agents_in_reading_order();
        // L/T edges prepend the new pane (it becomes the first in reading order); R/B append it.
        if at_front {
            agents.insert(0, new_agent.to_string());
        } else {
            agents.push(new_agent.to_string());
        }
        Ok(Some(PaneLayoutModel::from_agents(&agents, Some(target))?))
    }

    /// Source-pane-aware split-growth: split the pane in `from_slot` toward `edge`, growing the layout
    /// by one pane. Unlike [`split_in_direction`], which docks the new pane at the WINDOW edge, this
    /// splits the SPECIFIC active cell — so `TwoColumns` with the left pane (`S0`) split downward yields
    /// `ThreeRightMain` (left column becomes a stacked pair, right stays full-height), leaving the other
    /// column untouched. The routing lives in [`split_growth_target_from_slot`]; agents re-bind in
    /// reading order (the new agent appended), which lands every survivor and the new pane in the
    /// intended slot for the supported transitions. Returns `None` when the `(layout, from_slot, edge)`
    /// triple is at the 4-pane max or ambiguous; errors on an empty/duplicate `new_agent` or a
    /// `from_slot` not present in this model.
    pub fn split_in_direction_from_slot(
        &self,
        from_slot: SlotId,
        edge: EdgeDir,
        new_agent: &str,
    ) -> Result<Option<Self>, PaneLayoutError> {
        if new_agent.is_empty() {
            return Err(PaneLayoutError::EmptyAgentId);
        }
        if self.assignment.values().any(|a| a == new_agent) {
            return Err(PaneLayoutError::DuplicateAgent {
                agent: new_agent.to_string(),
            });
        }
        if !self.assignment.contains_key(&from_slot) {
            return Err(PaneLayoutError::AgentNotFound {
                agent: format!("{from_slot:?}"),
            });
        }
        let Some(target) = split_growth_target_from_slot(self.layout, from_slot, edge) else {
            return Ok(None);
        };
        debug_assert_eq!(target.pane_count(), self.layout.pane_count() + 1);
        let mut agents = self.agents_in_reading_order();
        if self.layout == CanonicalLayout::TwoRows
            && from_slot == SlotId::S0
            && edge == EdgeDir::Right
        {
            agents.insert(1, new_agent.to_string());
        } else {
            agents.push(new_agent.to_string());
        }
        Ok(Some(PaneLayoutModel::from_agents(&agents, Some(target))?))
    }

    /// Source-pane-aware split-growth with explicit reading-order placement. This mirrors the old
    /// app's `splitPaneInDirection`/`dockAgentRelative` behavior: the selected target cell is split on
    /// the requested edge, and the new agent is inserted before/after that cell rather than appended.
    /// That extra order control is what makes every 2/3-pane drag/drop direction land where the user
    /// dropped it, including mixed `*-main` layouts whose main pane is at the front of reading order.
    pub fn split_ordered_from_slot(
        &self,
        from_slot: SlotId,
        edge: EdgeDir,
        new_agent: &str,
    ) -> Result<Option<Self>, PaneLayoutError> {
        if new_agent.is_empty() {
            return Err(PaneLayoutError::EmptyAgentId);
        }
        if self.assignment.values().any(|a| a == new_agent) {
            return Err(PaneLayoutError::DuplicateAgent {
                agent: new_agent.to_string(),
            });
        }
        let source =
            self.agent_at(from_slot)
                .cloned()
                .ok_or_else(|| PaneLayoutError::AgentNotFound {
                    agent: format!("{from_slot:?}"),
                })?;
        let agents = self.agents_in_reading_order();
        let Some(source_index) = self
            .layout
            .slots()
            .iter()
            .position(|slot| *slot == from_slot)
        else {
            return Err(PaneLayoutError::AgentNotFound {
                agent: format!("{from_slot:?}"),
            });
        };
        let insert_after = edge.is_after();
        let h = edge.is_horizontal();
        let insert_near_source = |target: CanonicalLayout| {
            let mut next = agents.clone();
            let insert_at = source_index + usize::from(insert_after);
            next.insert(insert_at, new_agent.to_string());
            PaneLayoutModel::from_agents(&next, Some(target))
        };
        let pair = || -> [AgentId; 2] {
            if insert_after {
                [source.clone(), new_agent.to_string()]
            } else {
                [new_agent.to_string(), source.clone()]
            }
        };

        use CanonicalLayout as L;
        use SlotId::*;
        let next = match self.layout {
            L::OneFull => insert_near_source(if h { L::TwoColumns } else { L::TwoRows })?,
            L::TwoColumns if h => insert_near_source(L::ThreeColumns)?,
            L::TwoRows if !h => insert_near_source(L::ThreeRows)?,
            L::TwoColumns => {
                let p = pair();
                let other = agents
                    .get(usize::from(source_index == 0))
                    .cloned()
                    .unwrap_or_default();
                let (target, order) = if from_slot == S0 {
                    (L::ThreeRightMain, vec![p[0].clone(), other, p[1].clone()])
                } else {
                    (L::ThreeLeftMain, vec![other, p[0].clone(), p[1].clone()])
                };
                PaneLayoutModel::from_agents(&order, Some(target))?
            }
            L::TwoRows => {
                let p = pair();
                let other = agents
                    .get(usize::from(source_index == 0))
                    .cloned()
                    .unwrap_or_default();
                let (target, order) = if from_slot == S0 {
                    (L::ThreeBottomMain, vec![p[0].clone(), p[1].clone(), other])
                } else {
                    (L::ThreeTopMain, vec![other, p[0].clone(), p[1].clone()])
                };
                PaneLayoutModel::from_agents(&order, Some(target))?
            }
            L::ThreeRightMain if from_slot == S1 && !h => {
                let p = pair();
                PaneLayoutModel::from_agents(
                    &[
                        agents[0].clone(),
                        p[0].clone(),
                        agents[2].clone(),
                        p[1].clone(),
                    ],
                    Some(L::FourGrid),
                )?
            }
            L::ThreeLeftMain if from_slot == S0 && !h => {
                let p = pair();
                PaneLayoutModel::from_agents(
                    &[
                        p[0].clone(),
                        agents[1].clone(),
                        p[1].clone(),
                        agents[2].clone(),
                    ],
                    Some(L::FourGrid),
                )?
            }
            L::ThreeBottomMain if from_slot == S2 && h => {
                let p = pair();
                PaneLayoutModel::from_agents(
                    &[
                        agents[0].clone(),
                        agents[1].clone(),
                        p[0].clone(),
                        p[1].clone(),
                    ],
                    Some(L::FourGrid),
                )?
            }
            L::ThreeBottomMain if from_slot == S2 && !h => {
                let p = pair();
                PaneLayoutModel::from_agents(
                    &[
                        agents[0].clone(),
                        agents[1].clone(),
                        p[0].clone(),
                        p[1].clone(),
                    ],
                    Some(L::FourTopSplit),
                )?
            }
            L::ThreeRightMain if from_slot == S1 && h => {
                let p = pair();
                PaneLayoutModel::from_agents(
                    &[
                        agents[0].clone(),
                        p[0].clone(),
                        p[1].clone(),
                        agents[2].clone(),
                    ],
                    Some(L::FourLeftSplit),
                )?
            }
            L::ThreeTopMain if from_slot == S0 && h => {
                let p = pair();
                PaneLayoutModel::from_agents(
                    &[
                        p[0].clone(),
                        p[1].clone(),
                        agents[1].clone(),
                        agents[2].clone(),
                    ],
                    Some(L::FourGrid),
                )?
            }
            L::ThreeBottomMain if matches!(from_slot, S0 | S1) => {
                insert_near_source(L::FourBottomMain)?
            }
            L::ThreeTopMain if matches!(from_slot, S1 | S2) => insert_near_source(L::FourTopMain)?,
            L::ThreeLeftMain if matches!(from_slot, S1 | S2) => {
                insert_near_source(L::FourLeftMain)?
            }
            L::ThreeRightMain if matches!(from_slot, S0 | S2) => {
                let p = pair();
                let order = if from_slot == S0 {
                    vec![
                        p[0].clone(),
                        agents[1].clone(),
                        p[1].clone(),
                        agents[2].clone(),
                    ]
                } else {
                    vec![
                        agents[0].clone(),
                        agents[1].clone(),
                        p[0].clone(),
                        p[1].clone(),
                    ]
                };
                PaneLayoutModel::from_agents(&order, Some(L::FourRightMain))?
            }
            L::ThreeColumns
            | L::ThreeRows
            | L::ThreeLeftMain
            | L::ThreeRightMain
            | L::ThreeTopMain
            | L::ThreeBottomMain => {
                insert_near_source(if h { L::FourColumns } else { L::FourRows })?
            }
            _ => return Ok(None),
        };
        Ok(Some(next))
    }

    /// Revive: bring a stashed agent back as a +1 pane. The survivors are re-bound nearest their current
    /// slot into the [`revive_target`] layout for the current pane count, and the revived agent fills the
    /// freed slot (last in reading order). Returns `None` when already at the 4-pane max (no room to
    /// revive) or when `revived` is empty/already present is treated as an error. Ratios reset to the
    /// target's defaults.
    pub fn revive(&self, revived: &str) -> Result<Option<Self>, PaneLayoutError> {
        if revived.is_empty() {
            return Err(PaneLayoutError::EmptyAgentId);
        }
        if self.assignment.values().any(|a| a == revived) {
            return Err(PaneLayoutError::DuplicateAgent {
                agent: revived.to_string(),
            });
        }
        let Some(target) = revive_target(self.layout) else {
            return Ok(None);
        };
        debug_assert_eq!(target.pane_count(), self.layout.pane_count() + 1);
        let mut agents = self.agents_in_reading_order();
        agents.push(revived.to_string());
        Ok(Some(PaneLayoutModel::from_agents(&agents, Some(target))?))
    }

    /// Reduce: remove `agent` (it is being stashed/closed) and re-snap the survivors into the default
    /// layout for the new, smaller pane count, binding them nearest their current reading-order position.
    /// Returns `None` when removing would leave zero panes (the caller decides what an empty workspace
    /// means). Errors if `agent` is not in the model. Ratios reset to the target's defaults.
    pub fn reduce_removing(&self, agent: &str) -> Result<Option<Self>, PaneLayoutError> {
        if self.slot_of(agent).is_none() {
            return Err(PaneLayoutError::AgentNotFound {
                agent: agent.to_string(),
            });
        }
        let survivors: Vec<AgentId> = self
            .agents_in_reading_order()
            .into_iter()
            .filter(|a| a != agent)
            .collect();
        if survivors.is_empty() {
            return Ok(None);
        }
        Ok(Some(PaneLayoutModel::from_agents(&survivors, None)?))
    }
}

/// The axis/direction a pane reaches when it swallows: left/right makes it a full-width ROW main;
/// up/down makes it a full-height COLUMN main.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwallowDir {
    Left,
    Right,
    Up,
    Down,
}

impl SwallowDir {
    /// True for the horizontal directions (left/right) — the ones that produce a full-width row main.
    fn is_horizontal(self) -> bool {
        matches!(self, SwallowDir::Left | SwallowDir::Right)
    }
}

/// The canonical layout a swallow produces, or `None` when the `(from, slot, dir)` combination is
/// illegal. Every entry in the static swallow table is self-inverse across the
/// opposite axis. Only the 3-pane layouts have legal swallows; 1/2/4-pane layouts always return `None`.
pub fn swallow_target(
    from: CanonicalLayout,
    slot: SlotId,
    dir: SwallowDir,
) -> Option<CanonicalLayout> {
    use CanonicalLayout as L;
    use SlotId::*;
    let h = dir.is_horizontal();
    match (from, slot) {
        // three-left-main: the two stacked-right panes can swallow horizontally into a row main.
        (L::ThreeLeftMain, S1) if h => Some(L::ThreeTopMain),
        (L::ThreeLeftMain, S2) if h => Some(L::ThreeBottomMain),
        // three-right-main: the two stacked-left panes swallow horizontally into a row main.
        (L::ThreeRightMain, S0) if h => Some(L::ThreeTopMain),
        (L::ThreeRightMain, S2) if h => Some(L::ThreeBottomMain),
        // three-top-main: the two bottom panes swallow vertically into a column main.
        (L::ThreeTopMain, S1) if !h => Some(L::ThreeLeftMain),
        (L::ThreeTopMain, S2) if !h => Some(L::ThreeRightMain),
        // three-bottom-main: the two top panes swallow vertically into a column main.
        (L::ThreeBottomMain, S0) if !h => Some(L::ThreeLeftMain),
        (L::ThreeBottomMain, S1) if !h => Some(L::ThreeRightMain),
        // uniform three-columns: the outer columns swallow vertically into a column main.
        (L::ThreeColumns, S0) if !h => Some(L::ThreeLeftMain),
        (L::ThreeColumns, S2) if !h => Some(L::ThreeRightMain),
        // uniform three-rows: the outer rows swallow horizontally into a row main.
        (L::ThreeRows, S0) if h => Some(L::ThreeTopMain),
        (L::ThreeRows, S2) if h => Some(L::ThreeBottomMain),

        // ── 4-pane swallows (4→4: a focused pane ENLARGES along an axis, every pane stays alive). These
        // are the FIXED cases the user specified, not a derived rule. The two stacked side panes of a
        // *-main grow to fill a full row/column main; both directions along the axis give the same target
        // (self-inverse, like the 3-pane entries).
        //
        // FourLeftmain A│(B/C/D): the right column's top (B) / bottom (D) grow to a full-width row main.
        (L::FourLeftMain, S1) if h => Some(L::FourTopMain),
        (L::FourLeftMain, S3) if h => Some(L::FourBottomMain),
        // FourRightMain (A/B/C)│D: the left column's top (A) / bottom (C) grow to a full-width row main.
        (L::FourRightMain, S0) if h => Some(L::FourTopMain),
        (L::FourRightMain, S2) if h => Some(L::FourBottomMain),
        // FourTopMain A/(B│C│D): the bottom row's left (B) / right (D) grow UP to a full-height col main.
        (L::FourTopMain, S1) if !h => Some(L::FourLeftMain),
        (L::FourTopMain, S3) if !h => Some(L::FourRightMain),
        // FourBottomMain (A│B│C)/D: the top row's left (A) / right (C) grow DOWN to a full-height col main.
        (L::FourBottomMain, S0) if !h => Some(L::FourLeftMain),
        (L::FourBottomMain, S2) if !h => Some(L::FourRightMain),
        _ => None,
    }
}

/// An edge of the active area a new/dropped pane can dock against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeDir {
    Left,
    Right,
    Top,
    Bottom,
}

impl EdgeDir {
    /// True for the left/right edges, which grow a new COLUMN; top/bottom grow a new ROW.
    fn is_horizontal(self) -> bool {
        matches!(self, EdgeDir::Left | EdgeDir::Right)
    }

    /// True when docking at this edge prepends the new pane in reading order (left/top come first).
    fn is_front(self) -> bool {
        matches!(self, EdgeDir::Left | EdgeDir::Top)
    }

    /// True when docking at this edge places the incoming pane after the source pane in reading order.
    fn is_after(self) -> bool {
        matches!(self, EdgeDir::Right | EdgeDir::Bottom)
    }
}

/// The layout produced by SPLIT-GROWTH when a new pane docks at `edge`, plus whether the new pane goes
/// to the FRONT of reading order (left/top) or the back (right/bottom). `None` when the layout is at the
/// 4-pane max or the `(layout, edge)` pair is ambiguous (e.g. top/bottom on a `*-columns` layout — which
/// column would it split?). The caller must surface a picker for ambiguous drops, never guess.
pub fn split_growth_target(
    from: CanonicalLayout,
    edge: EdgeDir,
) -> Option<(CanonicalLayout, bool)> {
    use CanonicalLayout as L;
    let h = edge.is_horizontal();
    let target = match from {
        // one-full grows into a 2-pane layout along whichever axis the edge implies.
        L::OneFull if h => L::TwoColumns,
        L::OneFull => L::TwoRows,
        // uniform column/row families extend by one along their own axis; the perpendicular edge is
        // ambiguous (NULL -> picker).
        L::TwoColumns if h => L::ThreeColumns,
        L::ThreeColumns if h => L::FourColumns,
        L::TwoRows if !h => L::ThreeRows,
        L::ThreeRows if !h => L::FourRows,
        // every mixed *-main and every 4-pane layout is ambiguous or full: NULL.
        _ => return None,
    };
    Some((target, edge.is_front()))
}

/// Source-pane-aware split-growth target: which canonical layout results when the pane in `from_slot`
/// is split toward `edge`. This resolves the ambiguity [`split_growth_target`] punts on — splitting a
/// column layout vertically (or a row layout horizontally) now knows WHICH cell is being split, so it
/// can route to the right mixed `*-main` layout instead of returning `None`.
///
/// Supported transitions (everything else is `None` — at the 4-pane max, or a triple with no canonical
/// home, which the caller treats as a no-op rather than guessing):
/// - `OneFull` + any edge → `TwoColumns` (horizontal edge) / `TwoRows` (vertical edge).
/// - `TwoColumns` + same-axis edge (L/R) → `ThreeColumns`. Perpendicular (T/B): splitting the LEFT
///   pane (`S0`) → `ThreeRightMain` (left becomes the stacked pair, right is the full-height main);
///   splitting the RIGHT pane (`S1`) → `ThreeLeftMain` (left is the full-height main, right is the
///   stacked pair).
/// - `TwoRows` + same-axis edge (T/B) → `ThreeRows`. Perpendicular (L/R): splitting the TOP pane
///   (`S0`) → `ThreeBottomMain` (top becomes the side pair, bottom is the full-width main); splitting
///   the BOTTOM pane (`S1`) → `ThreeTopMain` (top is the full-width main, bottom is the side pair).
///
/// 3→4 routing (all chosen so a plain reading-order rebind — survivors S0..S2 ++ new=S3 — leaves every
/// survivor in roughly its current screen cell and lands the new pane on the split slot's `edge`;
/// verified against [`slot_rects`]):
/// - `ThreeColumns` + same-axis (L/R) → `FourColumns` (appends a 4th column; reading order matches
///   left-to-right). Splitting the LEFT column (`S0`) perpendicular (T/B) → `FourLeftSplit` (left
///   column splits into top `S0` / bottom new `S3`; middle and right columns stay full-height). The
///   middle/right columns (`S1`,`S2`) perpendicular have no canonical home → `None`.
/// - `ThreeRows` + same-axis (T/B) → `FourRows`. Perpendicular splits of a row have no clean canonical
///   4-target whose reading order survives a plain append (`FourTopSplit`'s new slot is the bottom
///   full-width row, not adjacent to the split top row) → `None`.
/// - `ThreeRightMain` + splitting the right MAIN (`S1`) perpendicular (T/B) → `FourGrid` (right column
///   splits top/bottom; the left top/bottom pair already tiles the left, so the result is a clean 2×2,
///   new pane bottom-right). `ThreeBottomMain` + splitting the bottom MAIN (`S2`) same-axis (L/R) →
///   `FourGrid` (bottom row splits left/bottom-right; top pair already tiles the top → 2×2, new pane
///   bottom-right). These two work because the main is LAST in reading order, so the appended new pane
///   (`S3`) lands at the grid's `BR` slot adjacent to it.
/// - `ThreeLeftMain` / `ThreeTopMain` (main is `S0`, FRONT of reading order) and the side-stack splits
///   of any `*-main` produce no representable target that survives a plain reading-order append → `None`
///   (the caller no-ops rather than scrambling panes).
///
/// The `*-main` routings are chosen so the source pane and the new pane occupy the SPLIT band while the
/// untouched pane keeps its full span — verified against [`slot_rects`] reading order.
pub fn split_growth_target_from_slot(
    from: CanonicalLayout,
    from_slot: SlotId,
    edge: EdgeDir,
) -> Option<CanonicalLayout> {
    use CanonicalLayout as L;
    use SlotId::*;
    let h = edge.is_horizontal();
    match (from, from_slot) {
        // one-full: only one pane, splits exactly like the edge-only growth.
        (L::OneFull, S0) => Some(if h { L::TwoColumns } else { L::TwoRows }),
        // two-columns split along its own axis just extends to three columns.
        (L::TwoColumns, _) if h => Some(L::ThreeColumns),
        // two-columns split perpendicular splits the chosen column into a stacked pair.
        (L::TwoColumns, S0) => Some(L::ThreeRightMain),
        (L::TwoColumns, S1) => Some(L::ThreeLeftMain),
        // two-rows split along its own axis extends to three rows.
        (L::TwoRows, _) if !h => Some(L::ThreeRows),
        // two-rows split perpendicular splits the chosen row into a side pair.
        (L::TwoRows, S0) => Some(L::ThreeBottomMain),
        (L::TwoRows, S1) => Some(L::ThreeTopMain),
        // three-columns: same-axis (L/R) appends a 4th column.
        (L::ThreeColumns, _) if h => Some(L::FourColumns),
        // three-columns: splitting the LEFT column vertically nests it into a left top/bottom split,
        // leaving the middle and right columns full-height (FourLeftSplit). Middle/right have no home.
        (L::ThreeColumns, S0) => Some(L::FourLeftSplit),
        // three-rows: same-axis (T/B) appends a 4th row.
        (L::ThreeRows, _) if !h => Some(L::FourRows),
        // three-right-main: splitting the full-height right main vertically yields a clean 2x2 grid;
        // the new pane (appended last) lands bottom-right, adjacent to the split.
        (L::ThreeRightMain, S1) if !h => Some(L::FourGrid),
        // three-bottom-main: splitting the full-width bottom main horizontally yields a clean 2x2 grid;
        // the new pane (appended last) lands bottom-right, adjacent to the split.
        (L::ThreeBottomMain, S2) if h => Some(L::FourGrid),
        // every remaining 3-pane case is ambiguous/unrepresentable, and 4-pane is full: no canonical home.
        _ => None,
    }
}

/// The layout REVIVE snaps to when bringing a stashed pane back as a +1 pane, binding survivors nearest
/// their current slots. `None` when already at the 4-pane max (no room to revive).
pub fn revive_target(from: CanonicalLayout) -> Option<CanonicalLayout> {
    use CanonicalLayout as L;
    match from {
        L::OneFull => Some(L::TwoColumns),
        L::TwoColumns => Some(L::ThreeRightMain),
        L::TwoRows => Some(L::ThreeBottomMain),
        L::ThreeColumns => Some(L::FourLeftSplit),
        L::ThreeRows => Some(L::FourTopSplit),
        L::ThreeLeftMain | L::ThreeRightMain | L::ThreeTopMain | L::ThreeBottomMain => {
            Some(L::FourGrid)
        }
        // already 4 panes: full.
        L::FourGrid | L::FourColumns | L::FourRows | L::FourLeftSplit | L::FourTopSplit => None,
        L::FourLeftMain | L::FourRightMain | L::FourTopMain | L::FourBottomMain => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_LAYOUTS: [CanonicalLayout; 18] = [
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

    const EPS: f32 = 1e-4;

    fn rects(layout: CanonicalLayout) -> Vec<UnitRect> {
        slot_rects(layout, &BTreeMap::new())
    }

    #[test]
    fn every_layout_returns_one_rect_per_slot() {
        for l in ALL_LAYOUTS {
            assert_eq!(
                rects(l).len(),
                l.pane_count(),
                "{l:?} must return one rect per slot"
            );
            assert_eq!(l.slots().len(), l.pane_count());
        }
    }

    #[test]
    fn every_layout_tiles_the_unit_square_with_default_ratios() {
        for l in ALL_LAYOUTS {
            let rs = rects(l);
            // All rects in-bounds with positive extent.
            for [x, y, w, h] in rs.iter().copied() {
                assert!(
                    w > 0.0 && h > 0.0,
                    "{l:?}: degenerate rect {:?}",
                    [x, y, w, h]
                );
                assert!(
                    x >= -EPS && y >= -EPS && x + w <= 1.0 + EPS && y + h <= 1.0 + EPS,
                    "{l:?}: rect out of unit square {:?}",
                    [x, y, w, h]
                );
            }
            // Areas sum to 1.
            let area: f32 = rs.iter().map(|[_, _, w, h]| w * h).sum();
            assert!((area - 1.0).abs() < EPS, "{l:?}: area {area} != 1");
            // No two rects overlap (positive-area intersection).
            for i in 0..rs.len() {
                for j in (i + 1)..rs.len() {
                    let [ax, ay, aw, ah] = rs[i];
                    let [bx, by, bw, bh] = rs[j];
                    let ox = (ax + aw).min(bx + bw) - ax.max(bx);
                    let oy = (ay + ah).min(by + bh) - ay.max(by);
                    assert!(ox <= EPS || oy <= EPS, "{l:?}: slots {i} and {j} overlap");
                }
            }
        }
    }

    #[test]
    fn slots_are_returned_in_reading_order() {
        for l in ALL_LAYOUTS {
            let rs = rects(l);
            for w in rs.windows(2) {
                let [_, py, _, _] = w[0];
                let [px, ..] = w[0];
                let [_, cy, _, _] = w[1];
                let [cx, ..] = w[1];
                let before = cy < py - EPS || ((cy - py).abs() <= EPS && cx < px - EPS);
                assert!(!before, "{l:?}: rects not in reading order: {rs:?}");
            }
        }
    }

    #[test]
    fn normalize_fills_defaults_and_clamps_out_of_band() {
        // Empty map -> all defaults present, nothing extra.
        let n = normalize_ratios(CanonicalLayout::ThreeLeftMain, &BTreeMap::new());
        assert_eq!(n.len(), 2);
        assert_eq!(n[&SplitId::Main], 0.6);
        assert_eq!(n[&SplitId::Side], 0.5);

        // Out-of-band values clamp to the band edges.
        let mut p = BTreeMap::new();
        p.insert(SplitId::Main, 0.99); // above max 0.8
        p.insert(SplitId::Side, 0.01); // below min 0.2
        let n = normalize_ratios(CanonicalLayout::ThreeLeftMain, &p);
        assert_eq!(n[&SplitId::Main], 0.8);
        assert_eq!(n[&SplitId::Side], 0.2);
    }

    #[test]
    fn ordered_cuts_keep_monotone_gap_and_round() {
        // Two cuts that would cross get pushed apart by at least MIN_CUT_GAP.
        let mut p = BTreeMap::new();
        p.insert(SplitId::Col0, 0.6); // clamps to its max 0.6
        p.insert(SplitId::Col1, 0.4); // would sit BEFORE Col0
        let n = normalize_ratios(CanonicalLayout::ThreeColumns, &p);
        let c0 = n[&SplitId::Col0];
        let c1 = n[&SplitId::Col1];
        assert!(
            c1 >= c0 + MIN_CUT_GAP - EPS,
            "cuts must stay {MIN_CUT_GAP} apart: {c0} {c1}"
        );
        assert!(c1 < 1.0, "rightmost cut stays inside the unit square");
        // Rounded to 2 dp.
        assert_eq!(c0, round_ratio(c0));
        assert_eq!(c1, round_ratio(c1));
        // And the resulting 3-column layout still tiles.
        let rs = slot_rects(CanonicalLayout::ThreeColumns, &p);
        let area: f32 = rs.iter().map(|[_, _, w, h]| w * h).sum();
        assert!((area - 1.0).abs() < EPS);
        for [_, _, w, h] in rs {
            assert!(w > 0.0 && h > 0.0);
        }
    }

    #[test]
    fn four_column_cuts_stay_ordered_under_adversarial_input() {
        // All three cuts collapsed to the same value -> normalization spreads them with the gap.
        let mut p = BTreeMap::new();
        p.insert(SplitId::Col0, 0.5);
        p.insert(SplitId::Col1, 0.5);
        p.insert(SplitId::Col2, 0.5);
        let n = normalize_ratios(CanonicalLayout::FourColumns, &p);
        let (a, b, c) = (n[&SplitId::Col0], n[&SplitId::Col1], n[&SplitId::Col2]);
        assert!(b >= a + MIN_CUT_GAP - EPS, "{a} {b}");
        assert!(c >= b + MIN_CUT_GAP - EPS, "{b} {c}");
        assert!(c < 1.0);
        let rs = slot_rects(CanonicalLayout::FourColumns, &p);
        for [_, _, w, h] in rs {
            assert!(w > 0.0 && h > 0.0, "no degenerate column");
        }
    }

    fn ag(ids: &[&str]) -> Vec<AgentId> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn from_agents_picks_default_layout_and_assigns_in_reading_order() {
        for (n, expected) in [
            (1, CanonicalLayout::OneFull),
            (2, CanonicalLayout::TwoColumns),
            (3, CanonicalLayout::ThreeColumns),
            (4, CanonicalLayout::FourGrid),
        ] {
            let agents = ag(&["a", "b", "c", "d"][..n]);
            let m = PaneLayoutModel::from_agents(&agents, None).unwrap();
            assert_eq!(m.layout, expected);
            assert!(m.is_valid());
            // i-th agent lands in the i-th slot.
            for (slot, agent) in m.layout.slots().iter().zip(agents.iter()) {
                assert_eq!(m.agent_at(*slot), Some(agent));
            }
        }
    }

    #[test]
    fn from_agents_honors_a_matching_preferred_layout_else_falls_back() {
        // A preferred layout with the right pane count is used as-is.
        let m = PaneLayoutModel::from_agents(
            &ag(&["a", "b", "c"]),
            Some(CanonicalLayout::ThreeRightMain),
        )
        .unwrap();
        assert_eq!(m.layout, CanonicalLayout::ThreeRightMain);
        // A preferred layout with the WRONG count is ignored in favor of the default.
        let m = PaneLayoutModel::from_agents(&ag(&["a", "b"]), Some(CanonicalLayout::FourGrid))
            .unwrap();
        assert_eq!(m.layout, CanonicalLayout::TwoColumns);
    }

    #[test]
    fn from_agents_rejects_bad_counts_and_duplicates_and_empties() {
        assert_eq!(
            PaneLayoutModel::from_agents(&[], None).unwrap_err(),
            PaneLayoutError::UnsupportedAgentCount { count: 0 }
        );
        assert_eq!(
            PaneLayoutModel::from_agents(&ag(&["a", "b", "c", "d", "e"]), None).unwrap_err(),
            PaneLayoutError::UnsupportedAgentCount { count: 5 }
        );
        assert!(matches!(
            PaneLayoutModel::from_agents(&ag(&["a", "a"]), None).unwrap_err(),
            PaneLayoutError::DuplicateAgent { .. }
        ));
        assert_eq!(
            PaneLayoutModel::from_agents(&ag(&["a", ""]), None).unwrap_err(),
            PaneLayoutError::EmptyAgentId
        );
    }

    #[test]
    fn swap_agents_permutes_slots_is_involutive_and_keeps_layout_and_ratios() {
        let m = PaneLayoutModel::from_agents(&ag(&["a", "b", "c"]), None).unwrap();
        let swapped = m.swap_agents("a", "c").unwrap();
        // a and c traded slots; b stayed.
        assert_eq!(swapped.slot_of("a"), m.slot_of("c"));
        assert_eq!(swapped.slot_of("c"), m.slot_of("a"));
        assert_eq!(swapped.slot_of("b"), m.slot_of("b"));
        // Layout id and ratios untouched; model stays valid.
        assert_eq!(swapped.layout, m.layout);
        assert_eq!(swapped.ratios, m.ratios);
        assert!(swapped.is_valid());
        // Involutive: swapping the same pair again restores the original.
        let restored = swapped.swap_agents("a", "c").unwrap();
        assert_eq!(restored, m);
        // Self-swap is a no-op.
        assert_eq!(m.swap_agents("b", "b").unwrap(), m);
    }

    #[test]
    fn swap_agents_rejects_unknown_agent() {
        let m = PaneLayoutModel::from_agents(&ag(&["a", "b"]), None).unwrap();
        assert!(matches!(
            m.swap_agents("a", "ghost").unwrap_err(),
            PaneLayoutError::AgentNotFound { .. }
        ));
    }

    #[test]
    fn swallow_target_table_matches_the_canonical_spec_entries() {
        use CanonicalLayout as L;
        use SlotId::*;
        use SwallowDir::*;
        // The 12 legal entries (each direction along its axis collapses to the same target).
        let legal: &[(CanonicalLayout, SlotId, SwallowDir, CanonicalLayout)] = &[
            (L::ThreeLeftMain, S1, Left, L::ThreeTopMain),
            (L::ThreeLeftMain, S1, Right, L::ThreeTopMain),
            (L::ThreeLeftMain, S2, Left, L::ThreeBottomMain),
            (L::ThreeRightMain, S0, Right, L::ThreeTopMain),
            (L::ThreeRightMain, S2, Left, L::ThreeBottomMain),
            (L::ThreeTopMain, S1, Up, L::ThreeLeftMain),
            (L::ThreeTopMain, S2, Down, L::ThreeRightMain),
            (L::ThreeBottomMain, S0, Up, L::ThreeLeftMain),
            (L::ThreeBottomMain, S1, Down, L::ThreeRightMain),
            (L::ThreeColumns, S0, Up, L::ThreeLeftMain),
            (L::ThreeColumns, S2, Down, L::ThreeRightMain),
            (L::ThreeRows, S0, Left, L::ThreeTopMain),
            (L::ThreeRows, S2, Right, L::ThreeBottomMain),
            // 4-pane swallows (both directions along the axis → same target, self-inverse).
            (L::FourLeftMain, S1, Left, L::FourTopMain),
            (L::FourLeftMain, S1, Right, L::FourTopMain),
            (L::FourLeftMain, S3, Left, L::FourBottomMain),
            (L::FourLeftMain, S3, Right, L::FourBottomMain),
            (L::FourRightMain, S0, Left, L::FourTopMain),
            (L::FourRightMain, S2, Right, L::FourBottomMain),
            (L::FourTopMain, S1, Up, L::FourLeftMain),
            (L::FourTopMain, S1, Down, L::FourLeftMain),
            (L::FourTopMain, S3, Up, L::FourRightMain),
            (L::FourBottomMain, S0, Up, L::FourLeftMain),
            (L::FourBottomMain, S2, Down, L::FourRightMain),
        ];
        for &(from, slot, dir, want) in legal {
            assert_eq!(
                swallow_target(from, slot, dir),
                Some(want),
                "{from:?} {slot:?} {dir:?} should swallow to {want:?}"
            );
        }
    }

    #[test]
    fn four_pane_swallow_enlarges_the_focused_pane_to_a_full_main_band_and_keeps_all_panes() {
        use CanonicalLayout as L;
        use SlotId::*;
        use SwallowDir::*;
        // (start layout, focused slot, dir, target, expected FULL-SPAN rect of the focused pane).
        let full_left = [0.0, 0.0, 0.55, 1.0]; // FourLeftMain main (m=0.55).
        let full_right = [0.45, 0.0, 0.55, 1.0]; // FourRightMain main.
        let full_top = [0.0, 0.0, 1.0, 0.55]; // FourTopMain main.
        let full_bottom = [0.0, 0.45, 1.0, 0.55]; // FourBottomMain main.
        let cases: &[(
            CanonicalLayout,
            SlotId,
            SwallowDir,
            CanonicalLayout,
            UnitRect,
        )] = &[
            (L::FourBottomMain, S0, Up, L::FourLeftMain, full_left),
            (L::FourBottomMain, S2, Down, L::FourRightMain, full_right),
            (L::FourTopMain, S1, Up, L::FourLeftMain, full_left),
            (L::FourTopMain, S3, Down, L::FourRightMain, full_right),
            (L::FourLeftMain, S1, Left, L::FourTopMain, full_top),
            (L::FourLeftMain, S3, Right, L::FourBottomMain, full_bottom),
            (L::FourRightMain, S0, Left, L::FourTopMain, full_top),
            (L::FourRightMain, S2, Right, L::FourBottomMain, full_bottom),
        ];
        let agents: Vec<AgentId> = ["a", "b", "c", "d"].iter().map(|s| s.to_string()).collect();
        for &(from, slot, dir, want_layout, want_rect) in cases {
            let model = PaneLayoutModel::from_agents(&agents, Some(from)).unwrap();
            let focused = model.assignment.get(&slot).unwrap().clone();
            let next = model
                .apply_swallow(slot, dir)
                .unwrap_or_else(|| panic!("{from:?} {slot:?} {dir:?} must swallow"));
            assert_eq!(next.layout, want_layout, "{from:?} {slot:?} {dir:?}");
            // All four panes survive.
            assert_eq!(next.agents_in_reading_order().len(), 4);
            // The focused pane now occupies the full main band.
            let rects = slot_rects(next.layout, &next.ratios);
            let main_slot = PaneLayoutModel::main_slot_for_layout(next.layout).unwrap();
            let main_idx = next
                .layout
                .slots()
                .iter()
                .position(|s| *s == main_slot)
                .unwrap();
            assert_eq!(
                next.assignment.get(&main_slot).unwrap(),
                &focused,
                "focused pane should hold the main slot after {from:?} {slot:?} {dir:?}"
            );
            for (a, b) in rects[main_idx].iter().zip(want_rect.iter()) {
                assert!(
                    (a - b).abs() < EPS,
                    "{from:?} {slot:?} {dir:?}: main rect {:?} != {want_rect:?}",
                    rects[main_idx]
                );
            }
        }
    }

    #[test]
    fn swallow_target_rejects_wrong_axis_wrong_slot_and_non_three_pane_layouts() {
        use CanonicalLayout as L;
        use SlotId::*;
        use SwallowDir::*;
        // Wrong axis: three-left-main panes only swallow horizontally.
        assert_eq!(swallow_target(L::ThreeLeftMain, S1, Up), None);
        assert_eq!(swallow_target(L::ThreeLeftMain, S2, Down), None);
        // The main slot itself has no swallow.
        assert_eq!(swallow_target(L::ThreeLeftMain, S0, Left), None);
        assert_eq!(swallow_target(L::ThreeTopMain, S0, Up), None);
        // 1/2/4-pane layouts never swallow.
        for layout in [
            L::OneFull,
            L::TwoColumns,
            L::TwoRows,
            L::FourGrid,
            L::FourColumns,
            L::FourRows,
            L::FourLeftSplit,
            L::FourTopSplit,
        ] {
            for slot in [S0, S1, S2, S3] {
                for dir in [Left, Right, Up, Down] {
                    assert_eq!(
                        swallow_target(layout, slot, dir),
                        None,
                        "{layout:?} must not swallow"
                    );
                }
            }
        }
    }

    #[test]
    fn apply_swallow_moves_selected_pane_into_target_main_slot() {
        let m = PaneLayoutModel::from_agents(
            &ag(&["a", "b", "c"]),
            Some(CanonicalLayout::ThreeLeftMain),
        )
        .unwrap();
        // a=S0 (main), b=S1, c=S2 in reading order.
        let swallowed = m.apply_swallow(SlotId::S1, SwallowDir::Left).unwrap();
        assert_eq!(swallowed.layout, CanonicalLayout::ThreeTopMain);
        // The pane whose arrow was clicked becomes the target layout's full-span main.
        assert_eq!(swallowed.agent_at(SlotId::S0), Some(&"b".to_string()));
        // The remaining panes keep their relative reading order.
        assert_eq!(swallowed.agents_in_reading_order(), ag(&["b", "a", "c"]));
        assert!(swallowed.is_valid());
        // Ratios reset to the target's defaults (topology changed).
        let fresh = PaneLayoutModel::from_agents(
            &ag(&["b", "a", "c"]),
            Some(CanonicalLayout::ThreeTopMain),
        )
        .unwrap();
        assert_eq!(swallowed.ratios, fresh.ratios);
    }

    #[test]
    fn apply_swallow_repros_selected_bottom_left_and_top_right_become_main() {
        use CanonicalLayout as L;
        use SlotId::*;
        use SwallowDir::*;

        // A/(B|C), swallow up on B => B/(A|C), not A|(B/C).
        let top_main =
            PaneLayoutModel::from_agents(&ag(&["a", "b", "c"]), Some(L::ThreeTopMain)).unwrap();
        let b_left_main = top_main.apply_swallow(S1, Up).unwrap();
        assert_eq!(b_left_main.layout, L::ThreeLeftMain);
        assert_eq!(b_left_main.agents_in_reading_order(), ag(&["b", "a", "c"]));

        // A|(B/C), swallow left on B => B/(A|C), not A/(B|C).
        let left_main =
            PaneLayoutModel::from_agents(&ag(&["a", "b", "c"]), Some(L::ThreeLeftMain)).unwrap();
        let b_top_main = left_main.apply_swallow(S1, Left).unwrap();
        assert_eq!(b_top_main.layout, L::ThreeTopMain);
        assert_eq!(b_top_main.agents_in_reading_order(), ag(&["b", "a", "c"]));
    }

    #[test]
    fn apply_swallow_is_self_inverse_across_the_opposite_axis() {
        let m = PaneLayoutModel::from_agents(
            &ag(&["a", "b", "c"]),
            Some(CanonicalLayout::ThreeLeftMain),
        )
        .unwrap();
        // Swallow S2 horizontally -> ThreeBottomMain, then swallow S0 vertically back -> ThreeLeftMain.
        let once = m.apply_swallow(SlotId::S2, SwallowDir::Left).unwrap();
        assert_eq!(once.layout, CanonicalLayout::ThreeBottomMain);
        let back = once.apply_swallow(SlotId::S0, SwallowDir::Up).unwrap();
        assert_eq!(back.layout, CanonicalLayout::ThreeLeftMain);
        assert_eq!(back.assignment, m.assignment);
        assert_eq!(back.ratios, m.ratios);
    }

    #[test]
    fn apply_swallow_returns_none_for_illegal_combinations() {
        let m = PaneLayoutModel::from_agents(
            &ag(&["a", "b", "c"]),
            Some(CanonicalLayout::ThreeLeftMain),
        )
        .unwrap();
        // Wrong axis.
        assert!(m.apply_swallow(SlotId::S1, SwallowDir::Up).is_none());
        // Main slot.
        assert!(m.apply_swallow(SlotId::S0, SwallowDir::Left).is_none());
        // 2-pane and 4-pane models never swallow.
        let two = PaneLayoutModel::from_agents(&ag(&["a", "b"]), None).unwrap();
        assert!(two.apply_swallow(SlotId::S0, SwallowDir::Left).is_none());
        let four = PaneLayoutModel::from_agents(&ag(&["a", "b", "c", "d"]), None).unwrap();
        assert!(four.apply_swallow(SlotId::S0, SwallowDir::Left).is_none());
    }

    #[test]
    fn split_growth_target_table_matches_the_canonical_spec() {
        use CanonicalLayout as L;
        use EdgeDir::*;
        // (from, edge) -> (target, new-pane-at-front in reading order)
        let legal: &[(CanonicalLayout, EdgeDir, CanonicalLayout, bool)] = &[
            (L::OneFull, Left, L::TwoColumns, true),
            (L::OneFull, Right, L::TwoColumns, false),
            (L::OneFull, Top, L::TwoRows, true),
            (L::OneFull, Bottom, L::TwoRows, false),
            (L::TwoColumns, Left, L::ThreeColumns, true),
            (L::TwoColumns, Right, L::ThreeColumns, false),
            (L::ThreeColumns, Left, L::FourColumns, true),
            (L::ThreeColumns, Right, L::FourColumns, false),
            (L::TwoRows, Top, L::ThreeRows, true),
            (L::TwoRows, Bottom, L::ThreeRows, false),
            (L::ThreeRows, Top, L::FourRows, true),
            (L::ThreeRows, Bottom, L::FourRows, false),
        ];
        for &(from, edge, want, front) in legal {
            assert_eq!(
                split_growth_target(from, edge),
                Some((want, front)),
                "{from:?} {edge:?}"
            );
        }
    }

    #[test]
    fn split_growth_target_is_none_for_ambiguous_and_full_layouts() {
        use CanonicalLayout as L;
        use EdgeDir::*;
        // Perpendicular edge on a uniform family is ambiguous.
        assert_eq!(split_growth_target(L::TwoColumns, Top), None);
        assert_eq!(split_growth_target(L::TwoColumns, Bottom), None);
        assert_eq!(split_growth_target(L::TwoRows, Left), None);
        assert_eq!(split_growth_target(L::ThreeColumns, Top), None);
        assert_eq!(split_growth_target(L::ThreeRows, Left), None);
        // All mixed 3-mains are ambiguous; all 4-pane layouts are full.
        for from in [
            L::ThreeLeftMain,
            L::ThreeRightMain,
            L::ThreeTopMain,
            L::ThreeBottomMain,
            L::FourGrid,
            L::FourColumns,
            L::FourRows,
            L::FourLeftSplit,
            L::FourTopSplit,
        ] {
            for edge in [Left, Right, Top, Bottom] {
                assert_eq!(split_growth_target(from, edge), None, "{from:?} {edge:?}");
            }
        }
    }

    #[test]
    fn split_in_direction_adds_new_pane_preserving_survivor_order() {
        // Right edge appends; survivors keep order, new pane last.
        let m = PaneLayoutModel::from_agents(&ag(&["a", "b"]), None).unwrap();
        let grown = m.split_in_direction(EdgeDir::Right, "c").unwrap().unwrap();
        assert_eq!(grown.layout, CanonicalLayout::ThreeColumns);
        assert_eq!(grown.agents_in_reading_order(), ag(&["a", "b", "c"]));
        assert!(grown.is_valid());
        // Left edge prepends; new pane first.
        let grown_l = m.split_in_direction(EdgeDir::Left, "c").unwrap().unwrap();
        assert_eq!(grown_l.agents_in_reading_order(), ag(&["c", "a", "b"]));
    }

    #[test]
    fn split_in_direction_returns_none_when_ambiguous_or_full_and_errs_on_bad_agent() {
        let cols = PaneLayoutModel::from_agents(&ag(&["a", "b"]), None).unwrap();
        // Ambiguous edge -> Ok(None), not an error (caller shows a picker).
        assert!(cols
            .split_in_direction(EdgeDir::Top, "c")
            .unwrap()
            .is_none());
        // Full layout -> Ok(None).
        let four = PaneLayoutModel::from_agents(&ag(&["a", "b", "c", "d"]), None).unwrap();
        assert!(four
            .split_in_direction(EdgeDir::Right, "e")
            .unwrap()
            .is_none());
        // Empty / duplicate agent -> error.
        assert_eq!(
            cols.split_in_direction(EdgeDir::Right, "").unwrap_err(),
            PaneLayoutError::EmptyAgentId
        );
        assert!(matches!(
            cols.split_in_direction(EdgeDir::Right, "a").unwrap_err(),
            PaneLayoutError::DuplicateAgent { .. }
        ));
    }

    #[test]
    fn split_growth_target_from_slot_table_matches_the_spec() {
        use CanonicalLayout as L;
        use EdgeDir::*;
        use SlotId::*;
        let cases: &[(L, SlotId, EdgeDir, Option<L>)] = &[
            // one-full grows along the edge's axis.
            (L::OneFull, S0, Right, Some(L::TwoColumns)),
            (L::OneFull, S0, Bottom, Some(L::TwoRows)),
            // two-columns same-axis -> three columns regardless of which column splits.
            (L::TwoColumns, S0, Right, Some(L::ThreeColumns)),
            (L::TwoColumns, S1, Left, Some(L::ThreeColumns)),
            // two-columns perpendicular splits the chosen column into a stacked pair.
            (L::TwoColumns, S0, Bottom, Some(L::ThreeRightMain)),
            (L::TwoColumns, S0, Top, Some(L::ThreeRightMain)),
            (L::TwoColumns, S1, Bottom, Some(L::ThreeLeftMain)),
            (L::TwoColumns, S1, Top, Some(L::ThreeLeftMain)),
            // two-rows same-axis -> three rows.
            (L::TwoRows, S0, Bottom, Some(L::ThreeRows)),
            (L::TwoRows, S1, Top, Some(L::ThreeRows)),
            // two-rows perpendicular splits the chosen row into a side pair.
            (L::TwoRows, S0, Right, Some(L::ThreeBottomMain)),
            (L::TwoRows, S1, Right, Some(L::ThreeTopMain)),
            // three- and four-pane sources have no canonical home yet.
            (L::ThreeColumns, S1, Bottom, None),
            (L::FourGrid, S0, Right, None),
        ];
        for &(from, slot, edge, want) in cases {
            assert_eq!(
                split_growth_target_from_slot(from, slot, edge),
                want,
                "from {from:?} slot {slot:?} edge {edge:?}"
            );
        }
    }

    #[test]
    fn split_growth_target_from_slot_three_to_four_table() {
        use CanonicalLayout as L;
        use EdgeDir::*;
        use SlotId::*;
        // Every 3->4 routing implemented, with the cases that must stay None and why.
        let cases: &[(L, SlotId, EdgeDir, Option<L>)] = &[
            // --- same-axis extension ---
            (L::ThreeColumns, S0, Left, Some(L::FourColumns)),
            (L::ThreeColumns, S0, Right, Some(L::FourColumns)),
            (L::ThreeColumns, S1, Right, Some(L::FourColumns)),
            (L::ThreeColumns, S2, Left, Some(L::FourColumns)),
            (L::ThreeRows, S0, Top, Some(L::FourRows)),
            (L::ThreeRows, S0, Bottom, Some(L::FourRows)),
            (L::ThreeRows, S1, Bottom, Some(L::FourRows)),
            (L::ThreeRows, S2, Top, Some(L::FourRows)),
            // --- side-column of three-columns split perpendicular (left col only) ---
            (L::ThreeColumns, S0, Top, Some(L::FourLeftSplit)),
            (L::ThreeColumns, S0, Bottom, Some(L::FourLeftSplit)),
            // --- *-main: splitting the trailing-in-reading-order main into a clean 2x2 ---
            (L::ThreeRightMain, S1, Top, Some(L::FourGrid)),
            (L::ThreeRightMain, S1, Bottom, Some(L::FourGrid)),
            (L::ThreeBottomMain, S2, Left, Some(L::FourGrid)),
            (L::ThreeBottomMain, S2, Right, Some(L::FourGrid)),
            // --- None: middle/right column of three-columns split perpendicular (no FourRightSplit) ---
            (L::ThreeColumns, S1, Top, None),
            (L::ThreeColumns, S1, Bottom, None),
            (L::ThreeColumns, S2, Top, None),
            (L::ThreeColumns, S2, Bottom, None),
            // --- None: three-rows perpendicular (FourTopSplit's new slot is the bottom row, not the
            //     split top row, so a plain append would scramble) ---
            (L::ThreeRows, S0, Left, None),
            (L::ThreeRows, S0, Right, None),
            (L::ThreeRows, S1, Left, None),
            (L::ThreeRows, S2, Right, None),
            // --- None: three-right-main main split along its own axis, or a side pane ---
            (L::ThreeRightMain, S1, Left, None),
            (L::ThreeRightMain, S0, Bottom, None),
            (L::ThreeRightMain, S2, Right, None),
            // --- None: three-bottom-main main split along its own axis, or a side pane ---
            (L::ThreeBottomMain, S2, Top, None),
            (L::ThreeBottomMain, S0, Right, None),
            (L::ThreeBottomMain, S1, Bottom, None),
            // --- None: three-left-main / three-top-main (main is S0, FRONT of reading order) ---
            (L::ThreeLeftMain, S0, Bottom, None),
            (L::ThreeLeftMain, S1, Left, None),
            (L::ThreeLeftMain, S2, Right, None),
            (L::ThreeTopMain, S0, Right, None),
            (L::ThreeTopMain, S1, Top, None),
            (L::ThreeTopMain, S2, Bottom, None),
        ];
        for &(from, slot, edge, want) in cases {
            assert_eq!(
                split_growth_target_from_slot(from, slot, edge),
                want,
                "from {from:?} slot {slot:?} edge {edge:?}"
            );
        }
    }

    #[test]
    fn split_in_direction_from_slot_three_to_four_keeps_all_agents_and_places_new_pane() {
        use CanonicalLayout as L;

        // Helper: build a 3-pane model in a specific layout, split a slot toward an edge, and assert the
        // result is Ok(Some(target)) with all 4 agents present and the new agent at the expected slot.
        fn check(
            from: CanonicalLayout,
            slot: SlotId,
            edge: EdgeDir,
            want_layout: CanonicalLayout,
            want_new_slot: SlotId,
        ) {
            let m = PaneLayoutModel::from_agents(&ag(&["a", "b", "c"]), Some(from)).unwrap();
            let grown = m
                .split_in_direction_from_slot(slot, edge, "n")
                .expect("no error")
                .expect("a 4-pane target");
            assert_eq!(
                grown.layout, want_layout,
                "{from:?} {slot:?} {edge:?} layout"
            );
            assert!(grown.is_valid(), "{from:?} {slot:?} {edge:?} valid");
            // All three originals plus the new pane are present (none dropped).
            let mut got: Vec<AgentId> = grown.assignment.values().cloned().collect();
            got.sort();
            assert_eq!(
                got,
                ag(&["a", "b", "c", "n"]),
                "{from:?} {slot:?} {edge:?} agents"
            );
            // The new agent landed in the geometrically-expected slot (last in reading order).
            assert_eq!(
                grown.slot_of("n"),
                Some(want_new_slot),
                "{from:?} {slot:?} {edge:?} new-slot"
            );
        }

        // Same-axis extension: new column is rightmost (S3), bottom row is S3.
        check(
            L::ThreeColumns,
            SlotId::S2,
            EdgeDir::Right,
            L::FourColumns,
            SlotId::S3,
        );
        check(
            L::ThreeRows,
            SlotId::S2,
            EdgeDir::Bottom,
            L::FourRows,
            SlotId::S3,
        );
        // Side column of three-columns split down -> left column becomes top/bottom; new is bottom-left S3.
        check(
            L::ThreeColumns,
            SlotId::S0,
            EdgeDir::Bottom,
            L::FourLeftSplit,
            SlotId::S3,
        );
        // *-main side-split case: right main split down -> 2x2 grid; new pane bottom-right (S3).
        check(
            L::ThreeRightMain,
            SlotId::S1,
            EdgeDir::Bottom,
            L::FourGrid,
            SlotId::S3,
        );
        // *-main second supported case: bottom main split right -> 2x2 grid; new pane bottom-right (S3).
        check(
            L::ThreeBottomMain,
            SlotId::S2,
            EdgeDir::Right,
            L::FourGrid,
            SlotId::S3,
        );
    }

    #[test]
    fn split_from_slot_splits_only_the_active_cell() {
        // A | B, split the LEFT pane (a) down -> A/C on the left, B full-height right (three-right-main).
        let m = PaneLayoutModel::from_agents(&ag(&["a", "b"]), None).unwrap();
        let grown = m
            .split_in_direction_from_slot(SlotId::S0, EdgeDir::Bottom, "c")
            .unwrap()
            .unwrap();
        assert_eq!(grown.layout, CanonicalLayout::ThreeRightMain);
        assert_eq!(grown.agents_in_reading_order(), ag(&["a", "b", "c"]));
        assert!(grown.is_valid());
        // three-right-main reading order: S0 top-left, S1 full-height right, S2 bottom-left.
        // So a=top-left, b=right main, c=bottom-left == A/C | B.
        assert_eq!(grown.agent_at(SlotId::S0), Some(&"a".to_string()));
        assert_eq!(grown.agent_at(SlotId::S1), Some(&"b".to_string()));
        assert_eq!(grown.agent_at(SlotId::S2), Some(&"c".to_string()));

        // Split the RIGHT pane (b) down -> A full-height left, B/C on the right (three-left-main).
        let grown_r = m
            .split_in_direction_from_slot(SlotId::S1, EdgeDir::Bottom, "c")
            .unwrap()
            .unwrap();
        assert_eq!(grown_r.layout, CanonicalLayout::ThreeLeftMain);
        // three-left-main: S0 full-height left, S1 top-right, S2 bottom-right.
        assert_eq!(grown_r.agent_at(SlotId::S0), Some(&"a".to_string()));
        assert_eq!(grown_r.agent_at(SlotId::S1), Some(&"b".to_string()));
        assert_eq!(grown_r.agent_at(SlotId::S2), Some(&"c".to_string()));

        // A over B, split the TOP row right -> A/C over B. The new pane must be inserted into the
        // top-row side slot so the old bottom row remains the full-width main.
        let rows =
            PaneLayoutModel::from_agents(&ag(&["a", "b"]), Some(CanonicalLayout::TwoRows)).unwrap();
        let grown_top = rows
            .split_in_direction_from_slot(SlotId::S0, EdgeDir::Right, "c")
            .unwrap()
            .unwrap();
        assert_eq!(grown_top.layout, CanonicalLayout::ThreeBottomMain);
        assert_eq!(grown_top.agents_in_reading_order(), ag(&["a", "c", "b"]));
        assert_eq!(grown_top.agent_at(SlotId::S0), Some(&"a".to_string()));
        assert_eq!(grown_top.agent_at(SlotId::S1), Some(&"c".to_string()));
        assert_eq!(grown_top.agent_at(SlotId::S2), Some(&"b".to_string()));
    }

    #[test]
    fn split_ordered_from_slot_matches_old_app_relative_docking() {
        use CanonicalLayout as L;

        // A | B, move A above B -> B is the remaining one-full model, then B is split upward.
        let m = PaneLayoutModel::from_agents(&ag(&["b"]), Some(L::OneFull)).unwrap();
        let docked = m
            .split_ordered_from_slot(SlotId::S0, EdgeDir::Top, "a")
            .unwrap()
            .unwrap();
        assert_eq!(docked.layout, L::TwoRows);
        assert_eq!(docked.agents_in_reading_order(), ag(&["a", "b"]));

        // A | B | C, move A below C. Remove A, then split C downward:
        // B stays full-height left; C/A stack on the right.
        let remaining =
            PaneLayoutModel::from_agents(&ag(&["b", "c"]), Some(L::TwoColumns)).unwrap();
        let docked = remaining
            .split_ordered_from_slot(SlotId::S1, EdgeDir::Bottom, "a")
            .unwrap()
            .unwrap();
        assert_eq!(docked.layout, L::ThreeLeftMain);
        assert_eq!(docked.agents_in_reading_order(), ag(&["b", "c", "a"]));

        // Three-left-main, split the big left pane downward. This is one of the cases the previous
        // append-only implementation could not express; explicit ordering completes a 2x2 grid.
        let mixed =
            PaneLayoutModel::from_agents(&ag(&["a", "b", "c"]), Some(L::ThreeLeftMain)).unwrap();
        let grid = mixed
            .split_ordered_from_slot(SlotId::S0, EdgeDir::Bottom, "d")
            .unwrap()
            .unwrap();
        assert_eq!(grid.layout, L::FourGrid);
        assert_eq!(grid.agents_in_reading_order(), ag(&["a", "b", "d", "c"]));
    }

    #[test]
    fn split_ordered_from_slot_covers_side_band_four_pane_growth() {
        use CanonicalLayout as L;

        // Top band A|B, bottom C full. Split B to the right -> A|B|N over C, not four columns.
        let bottom_main =
            PaneLayoutModel::from_agents(&ag(&["a", "b", "c"]), Some(L::ThreeBottomMain)).unwrap();
        let grown = bottom_main
            .split_ordered_from_slot(SlotId::S1, EdgeDir::Right, "n")
            .unwrap()
            .unwrap();
        assert_eq!(grown.layout, L::FourBottomMain);
        assert_eq!(grown.agents_in_reading_order(), ag(&["a", "b", "n", "c"]));
        let grown = bottom_main
            .split_ordered_from_slot(SlotId::S0, EdgeDir::Top, "n")
            .unwrap()
            .unwrap();
        assert_eq!(grown.layout, L::FourBottomMain);
        assert_eq!(grown.agents_in_reading_order(), ag(&["n", "a", "b", "c"]));

        // Top A full, bottom B|C. Split B to the left -> A over N|B|C.
        let top_main =
            PaneLayoutModel::from_agents(&ag(&["a", "b", "c"]), Some(L::ThreeTopMain)).unwrap();
        let grown = top_main
            .split_ordered_from_slot(SlotId::S1, EdgeDir::Left, "n")
            .unwrap()
            .unwrap();
        assert_eq!(grown.layout, L::FourTopMain);
        assert_eq!(grown.agents_in_reading_order(), ag(&["a", "n", "b", "c"]));
        let grown = top_main
            .split_ordered_from_slot(SlotId::S2, EdgeDir::Bottom, "n")
            .unwrap()
            .unwrap();
        assert_eq!(grown.layout, L::FourTopMain);
        assert_eq!(grown.agents_in_reading_order(), ag(&["a", "b", "c", "n"]));

        // Left A full, right B/C. Split C downward -> A | B/N/C.
        let left_main =
            PaneLayoutModel::from_agents(&ag(&["a", "b", "c"]), Some(L::ThreeLeftMain)).unwrap();
        let grown = left_main
            .split_ordered_from_slot(SlotId::S2, EdgeDir::Bottom, "n")
            .unwrap()
            .unwrap();
        assert_eq!(grown.layout, L::FourLeftMain);
        assert_eq!(grown.agents_in_reading_order(), ag(&["a", "b", "c", "n"]));
        let grown = left_main
            .split_ordered_from_slot(SlotId::S1, EdgeDir::Right, "n")
            .unwrap()
            .unwrap();
        assert_eq!(grown.layout, L::FourLeftMain);
        assert_eq!(grown.agents_in_reading_order(), ag(&["a", "b", "n", "c"]));

        // Left A/C, right B full. Split A upward -> N/A/C | B.
        let right_main =
            PaneLayoutModel::from_agents(&ag(&["a", "b", "c"]), Some(L::ThreeRightMain)).unwrap();
        let grown = right_main
            .split_ordered_from_slot(SlotId::S0, EdgeDir::Top, "n")
            .unwrap()
            .unwrap();
        assert_eq!(grown.layout, L::FourRightMain);
        assert_eq!(grown.agents_in_reading_order(), ag(&["n", "b", "a", "c"]));
        let grown = right_main
            .split_ordered_from_slot(SlotId::S2, EdgeDir::Left, "n")
            .unwrap()
            .unwrap();
        assert_eq!(grown.layout, L::FourRightMain);
        assert_eq!(grown.agents_in_reading_order(), ag(&["a", "b", "n", "c"]));
    }

    #[test]
    fn split_ordered_from_slot_preserves_mixed_main_when_splitting_the_main_outward() {
        use CanonicalLayout as L;

        // (A | B) / C, split C down -> (A | B) / C / N.
        // The old fallback flattened this into four equal rows, losing the existing A|B top band.
        let bottom_main =
            PaneLayoutModel::from_agents(&ag(&["a", "b", "c"]), Some(L::ThreeBottomMain)).unwrap();
        let grown = bottom_main
            .split_ordered_from_slot(SlotId::S2, EdgeDir::Bottom, "n")
            .unwrap()
            .unwrap();
        assert_eq!(grown.layout, L::FourTopSplit);
        assert_eq!(grown.agents_in_reading_order(), ag(&["a", "b", "c", "n"]));

        // (A / B) | C, split C right -> (A / B) | C | N.
        // The old fallback flattened this into four equal columns, losing the existing A/B side stack.
        let right_main =
            PaneLayoutModel::from_agents(&ag(&["a", "c", "b"]), Some(L::ThreeRightMain)).unwrap();
        let grown = right_main
            .split_ordered_from_slot(SlotId::S1, EdgeDir::Right, "n")
            .unwrap()
            .unwrap();
        assert_eq!(grown.layout, L::FourLeftSplit);
        assert_eq!(grown.agents_in_reading_order(), ag(&["a", "c", "n", "b"]));
    }

    #[test]
    fn split_from_slot_none_and_errors() {
        let m = PaneLayoutModel::from_agents(&ag(&["a", "b"]), None).unwrap();
        // Three-pane source, a slot with no canonical home -> Ok(None), not an error. (The default
        // 3-pane layout is ThreeColumns; splitting the MIDDLE column (S1) perpendicular has no clean
        // 4-target, so it no-ops. Splitting S0 perpendicular IS supported -> FourLeftSplit, tested below.)
        let three = PaneLayoutModel::from_agents(&ag(&["a", "b", "c"]), None).unwrap();
        assert!(three
            .split_in_direction_from_slot(SlotId::S1, EdgeDir::Bottom, "d")
            .unwrap()
            .is_none());
        // Empty / duplicate agent -> error.
        assert_eq!(
            m.split_in_direction_from_slot(SlotId::S0, EdgeDir::Bottom, "")
                .unwrap_err(),
            PaneLayoutError::EmptyAgentId
        );
        assert!(matches!(
            m.split_in_direction_from_slot(SlotId::S0, EdgeDir::Bottom, "a")
                .unwrap_err(),
            PaneLayoutError::DuplicateAgent { .. }
        ));
        // from_slot not present in this 2-pane model -> AgentNotFound.
        assert!(matches!(
            m.split_in_direction_from_slot(SlotId::S2, EdgeDir::Bottom, "c")
                .unwrap_err(),
            PaneLayoutError::AgentNotFound { .. }
        ));
    }

    #[test]
    fn revive_target_table_matches_the_canonical_spec_and_is_none_at_max() {
        use CanonicalLayout as L;
        assert_eq!(revive_target(L::OneFull), Some(L::TwoColumns));
        assert_eq!(revive_target(L::TwoColumns), Some(L::ThreeRightMain));
        assert_eq!(revive_target(L::TwoRows), Some(L::ThreeBottomMain));
        assert_eq!(revive_target(L::ThreeColumns), Some(L::FourLeftSplit));
        assert_eq!(revive_target(L::ThreeRows), Some(L::FourTopSplit));
        for from in [
            L::ThreeLeftMain,
            L::ThreeRightMain,
            L::ThreeTopMain,
            L::ThreeBottomMain,
        ] {
            assert_eq!(revive_target(from), Some(L::FourGrid), "{from:?}");
        }
        for from in [
            L::FourGrid,
            L::FourColumns,
            L::FourRows,
            L::FourLeftSplit,
            L::FourTopSplit,
        ] {
            assert_eq!(revive_target(from), None, "{from:?}");
        }
    }

    #[test]
    fn revive_brings_back_a_pane_with_survivors_preserved_and_none_at_max() {
        let m = PaneLayoutModel::from_agents(&ag(&["a", "b", "c"]), None).unwrap();
        let revived = m.revive("d").unwrap().unwrap();
        assert_eq!(revived.layout, CanonicalLayout::FourLeftSplit);
        assert_eq!(revived.agents_in_reading_order(), ag(&["a", "b", "c", "d"]));
        assert!(revived.is_valid());
        // At max -> Ok(None).
        let four = PaneLayoutModel::from_agents(&ag(&["a", "b", "c", "d"]), None).unwrap();
        assert!(four.revive("e").unwrap().is_none());
        // Duplicate revived agent -> error.
        assert!(matches!(
            m.revive("a").unwrap_err(),
            PaneLayoutError::DuplicateAgent { .. }
        ));
    }

    #[test]
    fn reduce_removing_re_snaps_survivors_to_smaller_default_layout() {
        let m = PaneLayoutModel::from_agents(&ag(&["a", "b", "c"]), None).unwrap();
        // Remove the middle pane; survivors keep reading order in the 2-pane default (two-columns).
        let reduced = m.reduce_removing("b").unwrap().unwrap();
        assert_eq!(reduced.layout, CanonicalLayout::TwoColumns);
        assert_eq!(reduced.agents_in_reading_order(), ag(&["a", "c"]));
        assert!(reduced.is_valid());
        // Removing the last survivor -> Ok(None) (empty workspace is the caller's call).
        let one = PaneLayoutModel::from_agents(&ag(&["a"]), None).unwrap();
        assert!(one.reduce_removing("a").unwrap().is_none());
        // Unknown agent -> error.
        assert!(matches!(
            m.reduce_removing("ghost").unwrap_err(),
            PaneLayoutError::AgentNotFound { .. }
        ));
    }

    #[test]
    fn split_then_reduce_round_trips_the_pane_count() {
        let m = PaneLayoutModel::from_agents(&ag(&["a", "b"]), None).unwrap();
        let grown = m.split_in_direction(EdgeDir::Right, "c").unwrap().unwrap();
        assert_eq!(grown.layout.pane_count(), 3);
        let back = grown.reduce_removing("c").unwrap().unwrap();
        assert_eq!(back.layout.pane_count(), 2);
        assert_eq!(back.agents_in_reading_order(), ag(&["a", "b"]));
    }
}
