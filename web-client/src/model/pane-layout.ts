// Pure browser pane-layout model (roadmap §4 "Window / pane / session layout"). A binary split tree of
// terminal panes — no DOM, no transport, no terminal attach. The renderer/controller will later map each
// leaf pane to one session + the existing single-session renderer; this layer only owns the layout shape.
//
// Concepts mirror the native maestro-shell pane model (split axes, an active pane, a max-active guard) but
// kept as a simple BSP tree the browser can grow into, rather than the full canonical-layout engine.

export type SplitDir = 'horizontal' | 'vertical'

/** A leaf pane: one terminal slot. `sessionId` is null until a session is attached (attach is a later slice). */
export interface PaneLeaf {
  readonly kind: 'leaf'
  readonly id: string
  readonly sessionId: string | null
}

/** An internal split: two children laid out along `dir` with `ratio` of space to the first child. */
export interface PaneSplit {
  readonly kind: 'split'
  readonly id: string
  readonly dir: SplitDir
  /** Fraction (0..1) of the split's space given to `first`; `second` gets the rest. */
  readonly ratio: number
  readonly first: PaneNode
  readonly second: PaneNode
}

export type PaneNode = PaneLeaf | PaneSplit

export interface PaneLayout {
  readonly root: PaneNode
  /** The focused leaf pane id. Always references a leaf that exists in `root`. */
  readonly activePaneId: string
}

/** Browser cap on simultaneously-open panes (mirrors the native max-4-active guard). */
export const MAX_PANES = 4

/** A swallow/move edge (local desktop's ← ↓ ↑ → / ⇤ ⤓ ⤒ ⇥ arrows). */
export type EdgeDir = 'left' | 'right' | 'up' | 'down'

const MIN_RATIO = 0.1
const MAX_RATIO = 0.9
const clampRatio = (r: number): number => Math.min(MAX_RATIO, Math.max(MIN_RATIO, r))

let idSeq = 0
/** Deterministic id source — pass an explicit `mkId` in tests for stable ids. */
function nextId(prefix: string): string {
  idSeq += 1
  return `${prefix}-${idSeq}`
}

// ── construction ────────────────────────────────────────────────────────────

export function singlePane(sessionId: string | null = null, paneId = nextId('pane')): PaneLayout {
  return { root: { kind: 'leaf', id: paneId, sessionId }, activePaneId: paneId }
}

/** One pane spec for {@link layoutFromPanes}: the desktop pane id (used as the leaf id so split/swap/close map back
 * to the desktop pane) and the session it holds. */
export interface PaneSpec {
  readonly paneId: string
  readonly sessionId: string
}

/**
 * Build a canonical BSP grid mirroring a desktop WINDOW's live panes, so the browser workspace shows every pane's
 * live terminal side by side — like the desktop's multi-pane window. The desktop metadata carries the pane SET (in
 * order) but no geometry, so we lay them out in the canonical arrangements the desktop uses:
 *   1 → single · 2 → left|right · 3 → left | (right split top/bottom) · 4 → 2×2 grid.
 * Leaf ids are the desktop pane ids (so downstream split/swap/close reference real desktop panes). `activeSessionId`
 * (if present) is focused; else the first pane. Empty input → a single empty pane.
 */
export function layoutFromPanes(
  panes: readonly PaneSpec[],
  activeSessionId: string | null = null,
  mkId: (prefix: string) => string = nextId,
): PaneLayout {
  const live = panes.slice(0, MAX_PANES)
  if (live.length === 0) return singlePane()
  const leaf = (p: PaneSpec): PaneLeaf => ({ kind: 'leaf', id: p.paneId, sessionId: p.sessionId })
  const vsplit = (first: PaneNode, second: PaneNode): PaneSplit =>
    ({ kind: 'split', id: mkId('split'), dir: 'vertical', ratio: DEFAULT_RATIO, first, second })
  const hsplit = (first: PaneNode, second: PaneNode): PaneSplit =>
    ({ kind: 'split', id: mkId('split'), dir: 'horizontal', ratio: DEFAULT_RATIO, first, second })

  let root: PaneNode
  if (live.length === 1) {
    root = leaf(live[0])
  } else if (live.length === 2) {
    root = vsplit(leaf(live[0]), leaf(live[1]))
  } else if (live.length === 3) {
    // left column | right column split top/bottom
    root = vsplit(leaf(live[0]), hsplit(leaf(live[1]), leaf(live[2])))
  } else {
    // 2×2 grid: (left split top/bottom) | (right split top/bottom)
    root = vsplit(hsplit(leaf(live[0]), leaf(live[2])), hsplit(leaf(live[1]), leaf(live[3])))
  }
  const active = live.find((p) => p.sessionId === activeSessionId) ?? live[0]
  return { root, activePaneId: active.paneId }
}

// ── queries ─────────────────────────────────────────────────────────────────

export function leaves(node: PaneNode): PaneLeaf[] {
  return node.kind === 'leaf' ? [node] : [...leaves(node.first), ...leaves(node.second)]
}

export function paneCount(layout: PaneLayout): number {
  return leaves(layout.root).length
}

export function findLeaf(layout: PaneLayout, paneId: string): PaneLeaf | null {
  return leaves(layout.root).find((l) => l.id === paneId) ?? null
}

export function activeLeaf(layout: PaneLayout): PaneLeaf {
  // activePaneId is an invariant (always a real leaf); fall back to the first leaf defensively.
  return findLeaf(layout, layout.activePaneId) ?? leaves(layout.root)[0]
}

// ── transforms (all return a new layout; inputs are never mutated) ────────────

function mapNode(node: PaneNode, fn: (leaf: PaneLeaf) => PaneNode): PaneNode {
  if (node.kind === 'leaf') return fn(node)
  return { ...node, first: mapNode(node.first, fn), second: mapNode(node.second, fn) }
}

/**
 * Split the active pane into two along `dir`. The active pane keeps its session as the FIRST child; a fresh
 * empty leaf becomes the SECOND child and the new active pane. No-op (returns the same layout) once MAX_PANES
 * is reached.
 */
export function splitActive(
  layout: PaneLayout,
  dir: SplitDir,
  opts: { sessionId?: string | null; mkId?: (prefix: string) => string } = {},
): PaneLayout {
  if (paneCount(layout) >= MAX_PANES) return layout
  const mk = opts.mkId ?? nextId
  const newLeafId = mk('pane')
  const splitId = mk('split')
  const root = mapNode(layout.root, (leaf) => {
    if (leaf.id !== layout.activePaneId) return leaf
    const second: PaneLeaf = { kind: 'leaf', id: newLeafId, sessionId: opts.sessionId ?? null }
    const split: PaneSplit = { kind: 'split', id: splitId, dir, ratio: 0.5, first: leaf, second }
    return split
  })
  return { root, activePaneId: newLeafId }
}

/** Set the divider ratio of a split (by split id), clamped to [MIN, MAX]. No-op for an unknown split id. */
export function setSplitRatio(layout: PaneLayout, splitId: string, ratio: number): PaneLayout {
  let changed = false
  const walk = (node: PaneNode): PaneNode => {
    if (node.kind === 'leaf') return node
    if (node.id === splitId) {
      changed = true
      return { ...node, ratio: clampRatio(ratio), first: walk(node.first), second: walk(node.second) }
    }
    return { ...node, first: walk(node.first), second: walk(node.second) }
  }
  const root = walk(layout.root)
  return changed ? { ...layout, root } : layout
}

/** Default split ratio — an even split. Splitting creates this; rebalance restores it. */
export const DEFAULT_RATIO = 0.5

/**
 * Rebalance: reset EVERY split's ratio back to an even DEFAULT_RATIO (the local desktop's Cmd+K). Pure tree
 * rewrite — the topology, session bindings, and active pane are all unchanged; only drag-skewed ratios snap
 * back. A no-op (returns the same object) when nothing was off-default, so callers can early-return.
 */
export function rebalanceLayout(layout: PaneLayout): PaneLayout {
  let changed = false
  const walk = (node: PaneNode): PaneNode => {
    if (node.kind === 'leaf') return node
    const first = walk(node.first)
    const second = walk(node.second)
    if (node.ratio !== DEFAULT_RATIO) changed = true
    return { ...node, ratio: DEFAULT_RATIO, first, second }
  }
  const root = walk(layout.root)
  return changed ? { ...layout, root } : layout
}

/** Move focus to an existing leaf pane. No-op if `paneId` is not a leaf in the layout. */
export function focusPane(layout: PaneLayout, paneId: string): PaneLayout {
  if (!findLeaf(layout, paneId)) return layout
  return { ...layout, activePaneId: paneId }
}

/**
 * Rename a leaf pane's ID in place (geometry, sessions, and every other leaf untouched). The single-id-space
 * identity upgrade for a BROWSER-minted reserve pane (an optimistic split leaf) once the desktop names the real
 * pane id (split_pane_ok `tab_id` / the naming push): from then on stash/revive/reconcile all key on the desktop
 * id. `activePaneId` follows the rename. No-op when `oldId` is not a leaf or `newId` already exists.
 */
export function renamePaneId(layout: PaneLayout, oldId: string, newId: string): PaneLayout {
  if (oldId === newId) return layout
  if (!findLeaf(layout, oldId) || findLeaf(layout, newId)) return layout
  const root = mapNode(layout.root, (leaf) => (leaf.id === oldId ? { ...leaf, id: newId } : leaf))
  return { root, activePaneId: layout.activePaneId === oldId ? newId : layout.activePaneId }
}

/** Attach (or clear) the session on a specific leaf pane. */
export function setPaneSession(layout: PaneLayout, paneId: string, sessionId: string | null): PaneLayout {
  if (!findLeaf(layout, paneId)) return layout
  const root = mapNode(layout.root, (leaf) => (leaf.id === paneId ? { ...leaf, sessionId } : leaf))
  return { ...layout, root }
}

/**
 * Swap the SESSIONS of two panes — the split geometry (positions/ratios) is unchanged; only which session each
 * pane shows is exchanged. This mirrors the local desktop's swap-pane (and tmux): the layout stays put, the
 * contents trade places. The active pane id is preserved (the user's focus follows the pane slot, not the
 * session). A no-op if either pane id is missing or they are the same pane. Pure.
 */
export function swapPaneSessions(layout: PaneLayout, paneA: string, paneB: string): PaneLayout {
  if (paneA === paneB) return layout
  const a = findLeaf(layout, paneA)
  const b = findLeaf(layout, paneB)
  if (!a || !b) return layout
  const root = mapNode(layout.root, (leaf) => {
    if (leaf.id === paneA) return { ...leaf, sessionId: b.sessionId }
    if (leaf.id === paneB) return { ...leaf, sessionId: a.sessionId }
    return leaf
  })
  return { ...layout, root }
}

/**
 * Rebind a (e.g. restored-from-storage) layout against the sessions that are actually live now: a leaf keeps
 * its sessionId only if that session is still available, else it becomes an empty (null) slot. The SPLIT shape
 * is always preserved. The active pane is kept if it still exists, else the first leaf. Pure.
 */
export function rebindLayoutToSessions(layout: PaneLayout, availableSessionIds: readonly string[]): PaneLayout {
  const available = new Set(availableSessionIds)
  const root = mapNode(layout.root, (leaf) =>
    leaf.sessionId !== null && available.has(leaf.sessionId) ? leaf : { ...leaf, sessionId: null },
  )
  const ids = leaves(root).map((l) => l.id)
  const activePaneId = ids.includes(layout.activePaneId) ? layout.activePaneId : (ids[0] ?? layout.activePaneId)
  return { root, activePaneId }
}

/**
 * Close a pane. Its sibling takes the split's place (the split collapses). Closing the last pane is a no-op
 * (a layout always has ≥1 pane). If the closed pane was active, focus moves to the sibling's first leaf.
 */
export function closePane(layout: PaneLayout, paneId: string): PaneLayout {
  if (layout.root.kind === 'leaf') return layout // last pane — keep at least one

  const collapse = (node: PaneNode): { node: PaneNode; removed: boolean } => {
    if (node.kind === 'leaf') return { node, removed: false }
    // direct child is the target → replace this split with the OTHER child
    if (node.first.kind === 'leaf' && node.first.id === paneId) return { node: node.second, removed: true }
    if (node.second.kind === 'leaf' && node.second.id === paneId) return { node: node.first, removed: true }
    const f = collapse(node.first)
    if (f.removed) return { node: { ...node, first: f.node }, removed: true }
    const s = collapse(node.second)
    if (s.removed) return { node: { ...node, second: s.node }, removed: true }
    return { node, removed: false }
  }

  const { node: root, removed } = collapse(layout.root)
  if (!removed) return layout
  const stillActive = findLeaf({ root, activePaneId: layout.activePaneId }, layout.activePaneId)
  const activePaneId = stillActive ? layout.activePaneId : leaves(root)[0].id
  return { root, activePaneId }
}

// ── geometry: rects, neighbors, swallow ───────────────────────────────────────

/** A pane's rect in the unit square [x, y, w, h] (x/y = top-left, 0..1). */
export interface PaneRect { readonly id: string; readonly x: number; readonly y: number; readonly w: number; readonly h: number }

/** Compute each leaf's rect by walking the split tree (ratios divide the parent's space). Mirrors how the desktop
 * derives pane_rect; used for directional neighbor-finding + swallow (edge-absorb) like the local move/swallow arrows. */
export function paneRects(layout: PaneLayout): PaneRect[] {
  const out: PaneRect[] = []
  const walk = (node: PaneNode, x: number, y: number, w: number, h: number): void => {
    if (node.kind === 'leaf') { out.push({ id: node.id, x, y, w, h }); return }
    const r = clampRatio(node.ratio)
    if (node.dir === 'vertical') { // left | right
      walk(node.first, x, y, w * r, h)
      walk(node.second, x + w * r, y, w * (1 - r), h)
    } else { // top / bottom
      walk(node.first, x, y, w, h * r)
      walk(node.second, x, y + h * r, w, h * (1 - r))
    }
  }
  walk(layout.root, 0, 0, 1, 1)
  return out
}

const EPS = 1e-4
const rectRight = (r: PaneRect) => r.x + r.w
const rectBottom = (r: PaneRect) => r.y + r.h
/** Do the two 1-D ranges overlap (with a small epsilon)? */
const spanOverlap = (a0: number, a1: number, b0: number, b1: number) => Math.min(a1, b1) - Math.max(a0, b0) > EPS

/** The pane immediately across `dir` from `paneId` whose perpendicular span overlaps it (local pane_neighbor_in_direction).
 * Returns the nearest such neighbor's id, or null at the window edge. Used for directional (arrow) swap. */
/**
 * The neighbor pane toward `dir`, resolved EXACTLY like local's pane_neighbor_in_direction
 * (maestro-renderer/src/lib.rs:2756). A candidate qualifies only when it lies on the requested SIDE (its near
 * edge is at/past the source's far edge — a gap is allowed, not just strict adjacency) AND its span overlaps the
 * source on the PERPENDICULAR axis (so a full-height left pane isn't treated as "below" a short right pane).
 * Distance = edge gap along the move axis, TIE-BROKEN by perpendicular CENTER distance, then pane order — so when
 * several neighbors border the same edge (e.g. a tall pane facing two stacked ones) we pick the most-aligned, like
 * local. (The previous version required strict adjacency + only broke ties by gap → wrong pick in those cases.)
 */
export function paneNeighbor(layout: PaneLayout, paneId: string, dir: EdgeDir): string | null {
  const rects = paneRects(layout)
  if (rects.length < 2) return null
  const me = rects.find((r) => r.id === paneId)
  if (!me) return null
  const meCx = me.x + me.w / 2
  const meCy = me.y + me.h / 2
  let best: PaneRect | null = null
  let bestGap = Infinity
  let bestPerp = Infinity
  for (const r of rects) {
    if (r.id === paneId) continue
    // qualifies? (on the requested side + perpendicular overlap). gap = edge distance along the move axis;
    // perp = |perpendicular center distance| (the tie-breaker). tol absorbs the 1-cell divider (EPS + 0.02).
    const tol = EPS + 0.02
    let ok = false
    let gap = Infinity
    let perp = Infinity
    if (dir === 'right') { ok = r.x + tol >= rectRight(me) && spanOverlap(me.y, rectBottom(me), r.y, rectBottom(r)); gap = r.x - rectRight(me); perp = Math.abs((r.y + r.h / 2) - meCy) }
    else if (dir === 'left') { ok = rectRight(r) <= me.x + tol && spanOverlap(me.y, rectBottom(me), r.y, rectBottom(r)); gap = me.x - rectRight(r); perp = Math.abs((r.y + r.h / 2) - meCy) }
    else if (dir === 'down') { ok = r.y + tol >= rectBottom(me) && spanOverlap(me.x, rectRight(me), r.x, rectRight(r)); gap = r.y - rectBottom(me); perp = Math.abs((r.x + r.w / 2) - meCx) }
    else { ok = rectBottom(r) <= me.y + tol && spanOverlap(me.x, rectRight(me), r.x, rectRight(r)); gap = me.y - rectBottom(r); perp = Math.abs((r.x + r.w / 2) - meCx) }
    if (!ok) continue
    const g = Math.abs(gap)
    // min by (gap, perp) — nearest along the axis, then most-aligned perpendicular. (pane order is the input order.)
    if (g < bestGap - EPS || (Math.abs(g - bestGap) <= EPS && perp < bestPerp - EPS)) {
      best = r; bestGap = g; bestPerp = perp
    }
  }
  return best?.id ?? null
}

/**
 * Legal MOVE/swap directions for a pane = the directions that have a neighbor (ports
 * pane_move_directions, maestro-renderer/src/lib.rs:2809): [Left,Down,Up,Right].filter(dir =>
 * pane_neighbor_in_direction(..).is_some()). A move/swap arrow shows toward D iff there IS a neighbor
 * across that edge.
 */
export function paneEdgeDirections(layout: PaneLayout, paneId: string): EdgeDir[] {
  return (['left', 'right', 'up', 'down'] as EdgeDir[]).filter((d) => paneNeighbor(layout, paneId, d) !== null)
}

/** Alias for {@link paneEdgeDirections} — the pane's legal MOVE (swap) arrow directions. */
export const moveDirections = paneEdgeDirections

/**
 * Legal SWALLOW directions for a pane (ports pane_swallow_directions, maestro-renderer/src/lib.rs:2832-2902).
 * A pane P can swallow toward direction D iff, across P's D-edge, there is EXACTLY ONE neighbour whose
 * PERPENDICULAR span on the shared boundary STRICTLY CONTAINS P's — it starts at/before P's start AND ends
 * at/after P's end, extending strictly beyond on ≥1 side (a tolerance absorbs divider rounding so "equal
 * length" reads as equal → NO swallow). If P's edge borders MULTIPLE neighbours, or the single neighbour's
 * edge is equal/shorter, P CANNOT swallow that way. Checked independently for all four directions.
 *
 * The Rust operates on integer cell regions (col/row/cols/rows) with `adj = |a-b|<=1` (1-cell divider) and
 * `tol = 2` cells (divider rounding). The browser's rects are the unit square (x/y/w/h) with exact fractional
 * dividers, so the cell tolerances map to a single float epsilon TOL: adjacency uses TOL and the strict-longer
 * check requires the neighbour to extend beyond P by MORE than TOL on ≥1 side (equal spans → false, matching
 * "equal length → no swallow"). Structure is byte-for-byte the Rust `can(dir)` closure.
 */
export function swallowDirections(layout: PaneLayout, paneId: string): EdgeDir[] {
  const rects = paneRects(layout)
  const pr = rects.find((r) => r.id === paneId)
  if (!pr) return []

  // Span overlap of two intervals (strict), mirroring Rust `overlaps(a0,a1,b0,b1) = a0.max(b0) < a1.min(b1)`.
  const overlaps = (a0: number, a1: number, b0: number, b1: number) => Math.max(a0, b0) < Math.min(a1, b1) - EPS
  // Unit-space stand-in for the Rust cell tolerances (`adj = |a-b|<=1`, `tol = 2`): edges within TOL count as
  // adjacent/coincident; a neighbour must extend beyond P by MORE than TOL to count as strictly longer.
  const TOL = 0.02
  const adj = (a: number, b: number) => Math.abs(a - b) <= TOL

  const can = (dir: EdgeDir): boolean => {
    // Panes across P's `dir` edge whose PERPENDICULAR span overlaps P's (mirrors Rust `across` filter).
    const across = rects.filter((q) => {
      if (q.id === paneId) return false
      switch (dir) {
        case 'up': // neighbour's bottom touches my top, columns overlap
          return adj(rectBottom(q), pr.y) && overlaps(q.x, rectRight(q), pr.x, rectRight(pr))
        case 'down':
          return adj(q.y, rectBottom(pr)) && overlaps(q.x, rectRight(q), pr.x, rectRight(pr))
        case 'left':
          return adj(rectRight(q), pr.x) && overlaps(q.y, rectBottom(q), pr.y, rectBottom(pr))
        case 'right':
          return adj(q.x, rectRight(pr)) && overlaps(q.y, rectBottom(q), pr.y, rectBottom(pr))
      }
    })
    // Exactly one neighbour, whose shared-edge span STRICTLY contains mine (so it's strictly longer).
    if (across.length !== 1) return false
    const n = across[0]
    // The neighbour must start at/before my start AND end at/after my end (within TOL), and extend strictly
    // beyond (> TOL) on ≥1 side. Up/Down compare the horizontal (col) span; Left/Right the vertical (row) span.
    if (dir === 'up' || dir === 'down') {
      return (
        n.x <= pr.x + TOL &&
        rectRight(n) + TOL >= rectRight(pr) &&
        (n.x + TOL < pr.x || rectRight(n) > rectRight(pr) + TOL)
      )
    }
    return (
      n.y <= pr.y + TOL &&
      rectBottom(n) + TOL >= rectBottom(pr) &&
      (n.y + TOL < pr.y || rectBottom(n) > rectBottom(pr) + TOL)
    )
  }

  return (['up', 'down', 'left', 'right'] as EdgeDir[]).filter((d) => can(d))
}

/**
 * SWALLOW (local edge-absorb): the pane grows across `dir`, absorbing its neighbor there — the two collapse into the
 * grown pane's space. In the BSP model this means: find the split whose divider the pane crosses in `dir`, and
 * collapse it so the pane's subtree takes the whole split (the neighbor subtree is removed). Self-inverse-friendly:
 * swallowing merges; a later split re-divides. No-op (returns same layout) when there's no neighbor that way.
 *
 * Faithful to the desktop's "B grows up, eats the overlapping neighbor" model for the common 2- and 3-pane cases.
 * The swallowed neighbor's session(s) detach from the grid (they keep running on the desktop; revive re-adds them).
 */
export function swallowPane(layout: PaneLayout, paneId: string, dir: EdgeDir): PaneLayout {
  if (paneNeighbor(layout, paneId, dir) === null) return layout
  // The pane is `first` when it's on the top/left side of a split, `second` on the bottom/right side.
  // Growing right/down means the pane is the `first` child of a matching-axis split → keep first, drop second.
  // Growing left/up means the pane is the `second` child → keep second, drop first.
  const wantAxis: SplitDir = dir === 'left' || dir === 'right' ? 'vertical' : 'horizontal'
  const paneIsFirst = dir === 'right' || dir === 'down'

  let done = false
  const walk = (node: PaneNode): PaneNode => {
    if (done || node.kind === 'leaf') return node
    // Does THIS split, on the wanted axis, have the pane on the side that grows across the divider?
    if (node.dir === wantAxis) {
      const growSide = paneIsFirst ? node.first : node.second
      const dropSide = paneIsFirst ? node.second : node.first
      if (subtreeContainsActiveEdge(growSide, paneId, wantAxis, paneIsFirst)) {
        done = true
        void dropSide
        return growSide // collapse: the growing subtree takes the whole split
      }
    }
    const first = walk(node.first)
    if (done) return { ...node, first }
    const second = walk(node.second)
    return { ...node, first: node.first === first ? node.first : first, second }
  }
  const root = walk(layout.root)
  if (!done) return layout
  const activePaneId = findLeaf({ root, activePaneId: paneId }, paneId) ? paneId : leaves(root)[0].id
  return { root, activePaneId }
}

/** Is `paneId` the leaf on the divider-facing edge of `subtree`? For a swallow we want the split where the pane
 * directly abuts the divider it's crossing — i.e. the pane is the rightmost/bottommost (first side) or
 * leftmost/topmost (second side) leaf of the growing subtree on the swallow axis. Approximated by rect adjacency
 * on the parent split, which the caller has already matched by axis/side. */
function subtreeContainsActiveEdge(subtree: PaneNode, paneId: string, _axis: SplitDir, _isFirst: boolean): boolean {
  return leaves(subtree).some((l) => l.id === paneId)
}

// ── canonical layout engine (ported from maestro-shell/src/pane_layout.rs) ────
//
// The browser runs its OWN independent canonical layout engine (the "14/24 strategy"): placed panes
// always sit in a canonical arrangement for their count. This ports the pure rules from
// maestro-shell/src/pane_layout.rs — default_layout_for, reduce_removing, apply_swallow + swallow_target,
// revive + revive_target, swap_agents. We represent each canonical layout as the BSP tree that yields the
// same geometry as the Rust `slot_rects` (pane_layout.rs:271), with leaf ids assigned in READING ORDER
// (top→bottom, left→right) so sessions stay bound across a re-snap.

/** The subset of the Rust `CanonicalLayout` enum (pane_layout.rs:77) the browser engine needs: the default
 * for each count plus the swallow/revive target layouts. */
export type CanonicalLayout =
  | 'OneFull'
  | 'TwoColumns'
  | 'TwoRows'
  | 'ThreeColumns'
  | 'ThreeRows'
  | 'ThreeLeftMain'
  | 'ThreeRightMain'
  | 'ThreeTopMain'
  | 'ThreeBottomMain'
  | 'FourGrid'
  | 'FourColumns'
  | 'FourRows'
  | 'FourLeftSplit'
  | 'FourTopSplit'
  | 'FourLeftMain'
  | 'FourRightMain'
  | 'FourTopMain'
  | 'FourBottomMain'

/** Pane count of a canonical layout (mirrors CanonicalLayout::pane_count, pane_layout.rs:120). */
export function canonicalPaneCount(layout: CanonicalLayout): number {
  switch (layout) {
    case 'OneFull':
      return 1
    case 'TwoColumns':
    case 'TwoRows':
      return 2
    case 'ThreeColumns':
    case 'ThreeRows':
    case 'ThreeLeftMain':
    case 'ThreeRightMain':
    case 'ThreeTopMain':
    case 'ThreeBottomMain':
      return 3
    default:
      return 4
  }
}

/**
 * The default canonical layout for `n` panes (ports default_layout_for, pane_layout.rs:475): 1→OneFull,
 * 2→TwoColumns, 3→ThreeColumns, 4→FourGrid. Returns null outside 1..=4.
 */
export function defaultLayoutForCount(n: number): CanonicalLayout | null {
  switch (n) {
    case 1:
      return 'OneFull'
    case 2:
      return 'TwoColumns'
    case 3:
      return 'ThreeColumns'
    case 4:
      return 'FourGrid'
    default:
      return null
  }
}

/** Default divider fractions per canonical layout (from split_specs defaults, pane_layout.rs:167). Only
 * the layouts the browser engine builds are listed. */
const THIRD = 1 / 3

/**
 * Build the BSP tree for a canonical `layout`, filling leaves with `agents` in reading order (agents[i] →
 * the i-th slot = i-th rect in Rust `slot_rects` reading order). Ratios reset to the layout defaults. The
 * geometry each tree yields (via {@link paneRects}) matches slot_rects(layout) exactly. `agents.length`
 * must equal the layout's pane count.
 */
export function buildCanonicalLayout(
  layout: CanonicalLayout,
  agents: readonly (string | null)[],
  mkId: (prefix: string) => string = nextId,
): PaneNode {
  const leaf = (i: number): PaneLeaf => ({ kind: 'leaf', id: mkId('pane'), sessionId: agents[i] ?? null })
  const v = (ratio: number, first: PaneNode, second: PaneNode): PaneSplit => ({ kind: 'split', id: mkId('split'), dir: 'vertical', ratio, first, second })
  const h = (ratio: number, first: PaneNode, second: PaneNode): PaneSplit => ({ kind: 'split', id: mkId('split'), dir: 'horizontal', ratio, first, second })

  switch (layout) {
    case 'OneFull':
      return leaf(0)
    // TwoColumns: [0,0,c,1][c,0,1-c,1] with c=0.5.
    case 'TwoColumns':
      return v(0.5, leaf(0), leaf(1))
    // TwoRows: top/bottom, c=0.5.
    case 'TwoRows':
      return h(0.5, leaf(0), leaf(1))
    // ThreeColumns: cuts a=1/3, b=2/3 → nested vertical splits (thirds), reading L→R.
    case 'ThreeColumns':
      return v(THIRD, leaf(0), v(0.5, leaf(1), leaf(2)))
    // ThreeRows: a=1/3, b=2/3 rows.
    case 'ThreeRows':
      return h(THIRD, leaf(0), h(0.5, leaf(1), leaf(2)))
    // ThreeLeftMain: [0,0,m,1] | (right split top/bottom). m=0.6, s=0.5.
    case 'ThreeLeftMain':
      return v(0.6, leaf(0), h(0.5, leaf(1), leaf(2)))
    // ThreeRightMain: (left split top/bottom) | [left,0,m,1]. left=1-m=0.4. Reading order: S0=top-left,
    // S1=right main, S2=bottom-left. left column outer split is top(S0)/bottom(S2); the WHOLE-left column
    // is `first`, right main `second`.
    case 'ThreeRightMain':
      return v(0.4, h(0.5, leaf(0), leaf(2)), leaf(1))
    // ThreeTopMain: [0,0,1,m] / (bottom split left/right). m=0.6, s=0.5.
    case 'ThreeTopMain':
      return h(0.6, leaf(0), v(0.5, leaf(1), leaf(2)))
    // ThreeBottomMain: (top split left/right) / [0,top,1,m]. top=1-m=0.4. Reading order S0=top-left,
    // S1=top-right, S2=bottom main.
    case 'ThreeBottomMain':
      return h(0.4, v(0.5, leaf(0), leaf(1)), leaf(2))
    // FourGrid: 2×2, c=0.5,row0=0.5. Reading order S0=TL,S1=TR,S2=BL,S3=BR. Left column top(S0)/bottom(S2),
    // right column top(S1)/bottom(S3).
    case 'FourGrid':
      return v(0.5, h(0.5, leaf(0), leaf(2)), h(0.5, leaf(1), leaf(3)))
    // FourColumns: cuts 0.25/0.5/0.75 → nested vertical thirds→quarters. Reading L→R.
    case 'FourColumns':
      return v(0.25, leaf(0), v(THIRD, leaf(1), v(0.5, leaf(2), leaf(3))))
    // FourRows: 0.25/0.5/0.75 rows.
    case 'FourRows':
      return h(0.25, leaf(0), h(THIRD, leaf(1), h(0.5, leaf(2), leaf(3))))
    // FourLeftSplit: c0=1/3,c1=2/3,row=0.5. Rects: S0=[0,0,c0,row] S1=[c0,0,c1-c0,1] S2=[c1,0,1-c1,1]
    // S3=[0,row,c0,1-row]. Left column split top(S0)/bottom(S3); then middle(S1); then right(S2).
    case 'FourLeftSplit':
      return v(THIRD, h(0.5, leaf(0), leaf(3)), v(0.5, leaf(1), leaf(2)))
    // FourTopSplit: r0=1/3,r1=2/3,col=0.5. Rects: S0=[0,0,col,r0] S1=[col,0,1-col,r0] S2=[0,r0,1,r1-r0]
    // S3=[0,r1,1,1-r1]. Top row split left(S0)/right(S1); then middle row(S2); then bottom(S3).
    case 'FourTopSplit':
      return h(THIRD, v(0.5, leaf(0), leaf(1)), h(0.5, leaf(2), leaf(3)))
    // FourLeftMain: [0,0,m,1] | (right column split into 3 rows a=1/3,b=2/3). m=0.55. S0=main,S1/S2/S3 rows.
    case 'FourLeftMain':
      return v(0.55, leaf(0), h(THIRD, leaf(1), h(0.5, leaf(2), leaf(3))))
    // FourRightMain: (left column 3 rows) | main. side=1-m=0.45. Reading order S0=top-left,S1=right main,
    // S2/S3 = left rows below. left column outer split: S0 / (S2 / S3).
    case 'FourRightMain':
      return v(0.45, h(THIRD, leaf(0), h(0.5, leaf(2), leaf(3))), leaf(1))
    // FourTopMain: [0,0,1,m] / (bottom row split into 3 columns). m=0.55. S0=main,S1/S2/S3 columns.
    case 'FourTopMain':
      return h(0.55, leaf(0), v(THIRD, leaf(1), v(0.5, leaf(2), leaf(3))))
    // FourBottomMain: (top row 3 columns) / main. side=1-m=0.45, so the top/bottom split ratio = side = 0.45.
    // Top row is three columns (cuts 1/3,2/3). Reading order S0=top-left,S1=top-mid,S2=top-right,S3=bottom main.
    case 'FourBottomMain':
      return h(0.45, v(THIRD, leaf(0), v(0.5, leaf(1), leaf(2))), leaf(3))
  }
}

/** The full-span "main" slot index for a *-main layout (ports main_slot_for_layout, pane_layout.rs:583).
 * Slots are 0-indexed reading order (S0→0). null if the layout has no main. */
function mainSlotIndex(layout: CanonicalLayout): number | null {
  switch (layout) {
    case 'ThreeLeftMain':
    case 'ThreeTopMain':
      return 0
    case 'ThreeRightMain':
      return 1
    case 'ThreeBottomMain':
      return 2
    case 'FourLeftMain':
    case 'FourTopMain':
      return 0
    case 'FourRightMain':
      return 1
    case 'FourBottomMain':
      return 3
    default:
      return null
  }
}

/** Reading-order leaf ids of a layout (top→bottom, left→right), derived from paneRects. */
export function readingOrderIds(layout: PaneLayout): string[] {
  const rects = paneRects(layout)
  return [...rects]
    .sort((a, b) => (Math.abs(a.y - b.y) > EPS ? a.y - b.y : a.x - b.x))
    .map((r) => r.id)
}

/** Reading-order (paneId, sessionId) pairs of the placed layout. Reading order = top→bottom, left→right. */
export function readingOrderPanes(layout: PaneLayout): { paneId: string; sessionId: string | null }[] {
  const byId = new Map(leaves(layout.root).map((l) => [l.id, l.sessionId]))
  return readingOrderIds(layout).map((id) => ({ paneId: id, sessionId: byId.get(id) ?? null }))
}

/**
 * Re-snap the survivors (in reading order) into a target canonical layout, KEEPING each survivor's paneId +
 * sessionId. `survivors[i]` (reading order) → slot i of `target`. Leaf ids are the survivors' own paneIds
 * (so sessions stay bound); split ids are minted fresh via `mkId`. Ratios are the target's canonical
 * defaults. `activePaneId` is preserved if still present, else the first placed pane. This is the shared
 * core of reduceRemoving / reviveInto / swallowPane.
 */
function snapToCanonical(
  target: CanonicalLayout,
  survivors: readonly { paneId: string; sessionId: string | null }[],
  activePaneId: string,
  mkId: (prefix: string) => string,
): PaneLayout {
  if (canonicalPaneCount(target) !== survivors.length) {
    throw new Error(`snapToCanonical: ${target} needs ${canonicalPaneCount(target)} panes, got ${survivors.length}`)
  }
  // Assign survivor paneIds as the leaf ids by wrapping buildCanonicalLayout: we mint the tree with the
  // survivors' sessionIds, then overwrite the freshly-minted leaf ids with the survivors' real paneIds in
  // reading order (buildCanonicalLayout fills slot i with agents[i], and its rects are in reading order).
  const sessions = survivors.map((s) => s.sessionId)
  const tree = buildCanonicalLayout(target, sessions, mkId)
  const built: PaneLayout = { root: tree, activePaneId }
  const builtOrder = readingOrderIds(built) // reading-order leaf ids of the fresh tree
  const remap = new Map<string, string>()
  builtOrder.forEach((freshId, i) => remap.set(freshId, survivors[i].paneId))
  const root = mapNode(tree, (l) => ({ ...l, id: remap.get(l.id) ?? l.id }))
  const ids = leaves(root).map((l) => l.id)
  const active = ids.includes(activePaneId) ? activePaneId : ids[0]
  return { root, activePaneId: active }
}

/**
 * The STASH super-rule (ports reduce_removing, pane_layout.rs:928): remove `paneId`; survivors re-snap to
 * defaultLayoutForCount(survivors.length) preserving reading order (topmost/leftmost stays first), keeping
 * paneIds + sessions bound. Returns null if removing would leave ZERO panes (caller decides — an empty
 * placed grid is valid). No-op (returns same layout) if `paneId` is not placed.
 */
export function reduceRemoving(
  layout: PaneLayout,
  paneId: string,
  mkId: (prefix: string) => string = nextId,
): PaneLayout | null {
  if (!findLeaf(layout, paneId)) return layout
  const survivors = readingOrderPanes(layout).filter((p) => p.paneId !== paneId)
  if (survivors.length === 0) return null
  const target = defaultLayoutForCount(survivors.length)
  if (!target) return layout
  const nextActive = layout.activePaneId === paneId ? survivors[0].paneId : layout.activePaneId
  return snapToCanonical(target, survivors, nextActive, mkId)
}

/**
 * R10 — the READING-ORDER SLOT the revived pane lands in, per base layout. Ported 1:1 from local's
 * click-revive geometry `revive_rects_by_spec` (maestro-shell/src/window_layout.rs:992-1126): the revived
 * pane X does NOT always land last — its slot in the target layout follows the local table:
 *   OneFull         A        → A│X                  (rs:1014-1018)  X = slot 1 (last)
 *   TwoColumns      A│B      → (A/X)│B              (rs:1023-1028)  X = bottom-left = ThreeRightMain S2 (last)
 *   TwoRows         A/B      → (A│X)/B              (rs:1030-1036)  X = top-right  = ThreeBottomMain S1
 *   ThreeColumns    A│B│C    → (A/X)│B│C            (rs:1046-1053)  X = bottom-left = FourLeftSplit S3 (last)
 *   ThreeRows       A/B/C    → (A│X)/B/C            (rs:1055-1062)  X = top-right  = FourTopSplit S1
 *   ThreeLeftMain   A│(B/C)  → (A│B)/(X│C)  2×2     (rs:1074-1080)  X = bottom-left = FourGrid S2
 *   ThreeRightMain  (A/C)│B  → (A│B)/(C│X)  2×2     (rs:1082-1088)  X = bottom-right = FourGrid S3 (last)
 *   ThreeTopMain    A/(B│C)  → (A│X)/(B│C)  2×2     (rs:1102-1108)  X = top-right  = FourGrid S1
 *   ThreeBottomMain (A│B)/C  → (A│B)/(C│X)  2×2     (rs:1110-1116)  X = bottom-right = FourGrid S3 (last)
 * The survivors keep their relative reading order; only X is inserted at this slot.
 */
export function reviveSlot(from: CanonicalLayout): number {
  switch (from) {
    case 'OneFull':
      return 1
    case 'TwoColumns':
      return 2
    case 'TwoRows':
      return 1
    case 'ThreeColumns':
      return 3
    case 'ThreeRows':
      return 1
    case 'ThreeLeftMain':
      return 2
    case 'ThreeRightMain':
      return 3
    case 'ThreeTopMain':
      return 1
    case 'ThreeBottomMain':
      return 3
    default:
      return 4 // unreachable via reviveTarget (4-pane bases have no revive)
  }
}

/**
 * Revive: add `revivedPaneId` (with `sessionId`) to the placed layout; it goes to the canonical
 * revive-target for the new count, landing at the local table's slot ({@link reviveSlot} — ported from
 * revive_rects_by_spec, window_layout.rs:992-1126; NOT always the last slot). Ratios reset to defaults.
 * Ports revive + revive_target (pane_layout.rs:906/1148). Returns null when already at 4 panes (revive_target
 * is None) or the revived pane is already placed.
 */
export function reviveInto(
  layout: PaneLayout,
  revivedPaneId: string,
  sessionId: string | null,
  mkId: (prefix: string) => string = nextId,
): PaneLayout | null {
  if (findLeaf(layout, revivedPaneId)) return null
  const current = readingOrderPanes(layout)
  // Empty placed grid → the revived pane becomes the sole OneFull pane.
  const from = current.length === 0 ? null : layoutName(layout)
  const target = current.length === 0 ? 'OneFull' : from ? reviveTarget(from) : defaultLayoutForCount(current.length + 1)
  if (!target) return null
  // Insert the revived pane at the ported slot (survivors keep their relative reading order). A
  // non-canonical base (layoutName null → default target) keeps the legacy last-slot fallback, mirroring
  // local's apply_revive fallback chain (window_layout.rs:1151-1177).
  const slot = from ? Math.min(reviveSlot(from), current.length) : current.length
  const survivors = [...current]
  survivors.splice(slot, 0, { paneId: revivedPaneId, sessionId })
  return snapToCanonical(target, survivors, revivedPaneId, mkId)
}

/** revive_target table (ports pane_layout.rs:1148). null when already 4-pane (full). */
export function reviveTarget(from: CanonicalLayout): CanonicalLayout | null {
  switch (from) {
    case 'OneFull':
      return 'TwoColumns'
    case 'TwoColumns':
      return 'ThreeRightMain'
    case 'TwoRows':
      return 'ThreeBottomMain'
    case 'ThreeColumns':
      return 'FourLeftSplit'
    case 'ThreeRows':
      return 'FourTopSplit'
    case 'ThreeLeftMain':
    case 'ThreeRightMain':
    case 'ThreeTopMain':
    case 'ThreeBottomMain':
      return 'FourGrid'
    default:
      return null // already 4 panes
  }
}

/**
 * swallow_target table (ports pane_layout.rs:966). `slotIndex` = 0-based reading-order slot of the selected
 * pane in `from`; `dir` is the swallow direction. Returns the target canonical layout, or null for an
 * illegal (from, slot, dir) combination. Only 3-pane and *-main 4-pane layouts have legal swallows.
 */
export function swallowTarget(from: CanonicalLayout, slotIndex: number, dir: EdgeDir): CanonicalLayout | null {
  const hor = dir === 'left' || dir === 'right'
  const key = `${from}:${slotIndex}:${hor ? 'h' : 'v'}`
  // Each entry is self-inverse across the opposite axis; both directions along the axis give the same target.
  const table: Record<string, CanonicalLayout> = {
    // three-left-main
    'ThreeLeftMain:1:h': 'ThreeTopMain',
    'ThreeLeftMain:2:h': 'ThreeBottomMain',
    // three-right-main
    'ThreeRightMain:0:h': 'ThreeTopMain',
    'ThreeRightMain:2:h': 'ThreeBottomMain',
    // three-top-main
    'ThreeTopMain:1:v': 'ThreeLeftMain',
    'ThreeTopMain:2:v': 'ThreeRightMain',
    // three-bottom-main
    'ThreeBottomMain:0:v': 'ThreeLeftMain',
    'ThreeBottomMain:1:v': 'ThreeRightMain',
    // uniform three-columns
    'ThreeColumns:0:v': 'ThreeLeftMain',
    'ThreeColumns:2:v': 'ThreeRightMain',
    // uniform three-rows
    'ThreeRows:0:h': 'ThreeTopMain',
    'ThreeRows:2:h': 'ThreeBottomMain',
    // 4-pane (4→4, all panes survive)
    'FourLeftMain:1:h': 'FourTopMain',
    'FourLeftMain:3:h': 'FourBottomMain',
    'FourRightMain:0:h': 'FourTopMain',
    'FourRightMain:2:h': 'FourBottomMain',
    'FourTopMain:1:v': 'FourLeftMain',
    'FourTopMain:3:v': 'FourRightMain',
    'FourBottomMain:0:v': 'FourLeftMain',
    'FourBottomMain:2:v': 'FourRightMain',
  }
  return table[key] ?? null
}

/**
 * SWALLOW (ports apply_swallow, pane_layout.rs:608) — the FIX for the pane-losing bug: ALL panes survive.
 * The pane in `paneId` becomes the full-span main of the canonical swallow-target (same pane count); the
 * other panes re-flow into the target's remaining slots in reading order. Ratios reset to defaults. Returns
 * the same layout (no-op) when the (layout, slot, dir) combination has no legal swallow.
 *
 * This REPLACES the old geometric swallowPane (which removed the neighbor, losing a pane). Signature
 * changes to (layout, paneId, dir) using canonical rules.
 */
export function swallowCanonical(
  layout: PaneLayout,
  paneId: string,
  dir: EdgeDir,
  mkId: (prefix: string) => string = nextId,
): PaneLayout {
  const from = layoutName(layout)
  if (!from) return layout
  const order = readingOrderPanes(layout)
  const slotIndex = order.findIndex((p) => p.paneId === paneId)
  if (slotIndex < 0) return layout
  const target = swallowTarget(from, slotIndex, dir)
  if (!target) return layout
  const mainIdx = mainSlotIndex(target)
  if (mainIdx === null) return layout
  const selected = order[slotIndex]
  const survivors = order.filter((_, i) => i !== slotIndex)
  // Place `selected` at the target's main slot; fill the rest with survivors in reading order.
  const arranged: { paneId: string; sessionId: string | null }[] = []
  let s = 0
  for (let i = 0; i < order.length; i++) {
    if (i === mainIdx) arranged.push(selected)
    else arranged.push(survivors[s++])
  }
  return snapToCanonical(target, arranged, paneId, mkId)
}

/**
 * Identify which canonical layout a placed `layout` currently is, by matching its pane rects (in reading
 * order) against every canonical layout's rects at that pane count. Returns null if it matches none (e.g. a
 * non-canonical tree from an ad-hoc splitActive). Used to drive revive/swallow transitions from the current
 * arrangement.
 */
export function layoutName(layout: PaneLayout): CanonicalLayout | null {
  const n = paneCount(layout)
  const mine = [...paneRects(layout)].sort((a, b) => (Math.abs(a.y - b.y) > EPS ? a.y - b.y : a.x - b.x))
  const candidates = ALL_CANONICAL.filter((c) => canonicalPaneCount(c) === n)
  for (const c of candidates) {
    const built: PaneLayout = { root: buildCanonicalLayout(c, new Array(n).fill(null)), activePaneId: '' }
    const theirs = [...paneRects(built)].sort((a, b) => (Math.abs(a.y - b.y) > EPS ? a.y - b.y : a.x - b.x))
    if (theirs.length !== mine.length) continue
    const same = theirs.every((r, i) => {
      const m = mine[i]
      return Math.abs(r.x - m.x) < 0.02 && Math.abs(r.y - m.y) < 0.02 && Math.abs(r.w - m.w) < 0.02 && Math.abs(r.h - m.h) < 0.02
    })
    if (same) return c
  }
  return null
}

const ALL_CANONICAL: CanonicalLayout[] = [
  'OneFull', 'TwoColumns', 'TwoRows', 'ThreeColumns', 'ThreeRows',
  'ThreeLeftMain', 'ThreeRightMain', 'ThreeTopMain', 'ThreeBottomMain',
  'FourGrid', 'FourColumns', 'FourRows', 'FourLeftSplit', 'FourTopSplit',
  'FourLeftMain', 'FourRightMain', 'FourTopMain', 'FourBottomMain',
]

// ── placed / stashed model (WorkspacePanes) ───────────────────────────────────
//
// The browser runs its own layout engine over PLACED panes (in the grid) and tracks STASHED panes: panes
// that EXIST on local (from workspaceMetadata) but the browser hasn't placed yet. See
// pane existence contract. PaneLayout stays focused on placed geometry; this wrapper adds the
// stashed set + the existence-sync reconcile.

/** A pane that exists on local but is not placed in the browser grid. */
export interface StashedPane {
  readonly paneId: string
  readonly sessionId: string | null
  readonly name?: string
  /** A row displaced by a browser-local swap/single-pane switch. It stays green/switchable, unlike an explicit stash. */
  readonly swappedOut?: boolean
}

/** The browser's full pane state: the placed grid (canonical geometry) + the stashed set. A placed count of
 * 0 is valid (empty grid = nothing shown); in that case `layout` is null. */
export interface WorkspacePanes {
  /** The placed grid, or null when nothing is placed (empty grid). */
  readonly layout: PaneLayout | null
  readonly stashed: readonly StashedPane[]
  /** Rule R2: the USER stashed this whole window in the BROWSER (topbar tab × / window menu "Close (stash)").
   * Hides the window's topbar tab until it is reopened (setActiveWindow clears it) or a pane is placed again.
   * Deliberately DISTINCT from R4's landing state (layout:null + stashed rows WITHOUT this flag), which keeps
   * its tab — only an explicit user stash may hide a window. Absent = false. Rides the persisted JSON as-is. */
  readonly windowStashed?: boolean
}

/** An empty workspace: nothing placed, nothing stashed. */
export function emptyWorkspace(): WorkspacePanes {
  return { layout: null, stashed: [] }
}

/** Every pane id known to the workspace (placed + stashed). */
function allPaneIds(state: WorkspacePanes): Set<string> {
  const ids = new Set<string>()
  if (state.layout) for (const l of leaves(state.layout.root)) ids.add(l.id)
  for (const s of state.stashed) ids.add(s.paneId)
  return ids
}

/** Is `paneId` placed in the grid? */
export function isPlaced(state: WorkspacePanes, paneId: string): boolean {
  return state.layout ? findLeaf(state.layout, paneId) !== null : false
}

/** Is `paneId` in the stashed set? */
export function isStashed(state: WorkspacePanes, paneId: string): boolean {
  return state.stashed.some((s) => s.paneId === paneId)
}

/**
 * Move a PLACED pane → stashed. The placed grid REDUCES via the canonical super-rule ({@link reduceRemoving}):
 * survivors re-snap to the default layout for the smaller count. Stashing the last placed pane leaves an
 * empty grid (layout=null). No-op if `paneId` is not placed.
 */
export function stashPane(state: WorkspacePanes, paneId: string, mkId: (prefix: string) => string = nextId): WorkspacePanes {
  if (!state.layout || !findLeaf(state.layout, paneId)) return state
  const leaf = findLeaf(state.layout, paneId)!
  const reduced = reduceRemoving(state.layout, paneId, mkId) // null = grid now empty
  const stashedPane: StashedPane = { paneId, sessionId: leaf.sessionId }
  return { layout: reduced, stashed: [...state.stashed, stashedPane] }
}

/**
 * Move a STASHED pane → placed, inserting it via canonical revive geometry ({@link reviveInto}). The revived
 * pane lands in the last slot (reading order). No-op if the pane is not stashed or the placed grid is already
 * at MAX_PANES.
 */
export function revivePane(state: WorkspacePanes, paneId: string, mkId: (prefix: string) => string = nextId): WorkspacePanes {
  const stashed = state.stashed.find((s) => s.paneId === paneId)
  if (!stashed) return state
  const restStashed = state.stashed.filter((s) => s.paneId !== paneId)
  if (!state.layout) {
    // empty grid → the revived pane becomes the sole OneFull pane.
    const layout: PaneLayout = { root: { kind: 'leaf', id: paneId, sessionId: stashed.sessionId }, activePaneId: paneId }
    return { layout, stashed: restStashed }
  }
  if (paneCount(state.layout) >= MAX_PANES) return state
  const revived = reviveInto(state.layout, paneId, stashed.sessionId, mkId)
  if (!revived) return state
  return { layout: revived, stashed: restStashed }
}

/**
 * R10/R11 — WINDOW revive: revive ALL of a window's stashed panes (≤ MAX_PANES) "sequentially but
 * instantly" — the user-delegated revive decision (memory rules, 2026-07-07): apply local's SINGLE-revive
 * slot table ({@link reviveSlot} / {@link reviveTarget}, ported from window_layout.rs revive_rects_by_spec)
 * REPEATEDLY, one stashed pane at a time in stash order (= the window's pane order). The former separate
 * bulk-shape path is removed — bulk is now DERIVED from the incremental chain. From an empty grid the chain
 * yields: 1 → OneFull · 2 → A│B (TwoColumns) · 3 → (A/C)│B (ThreeRightMain) · 4 → (A/C)│(B/D) (FourGrid,
 * reading-order slots). Panes beyond the first 4 STAY stashed (R11(2) cap). A window that already has a
 * placed grid continues the same chain from its current shape. `windowStashed` is always cleared —
 * reviving a window un-stashes it (R2's inverse). Pure.
 */
export function reviveWindow(state: WorkspacePanes, mkId: (prefix: string) => string = nextId): WorkspacePanes {
  let ws: WorkspacePanes = { layout: state.layout, stashed: state.stashed } // drops windowStashed
  for (const s of [...state.stashed]) {
    // A SESSION-LESS row is not revivable: it is a desktop pane whose session hasn't been named yet (the
    // agent redacts session_id until the session is live) — placing it would show a dead shell AND the
    // mirror's lone-empty-leaf canonicalization would silently drop the row. It stays stashed until the
    // `session-named` identity upgrade binds its session (pane lifecycle contract §0).
    if (!s.sessionId) continue
    if (ws.layout && paneCount(ws.layout) >= MAX_PANES) break
    ws = revivePane(ws, s.paneId, mkId)
  }
  return { layout: ws.layout, stashed: ws.stashed }
}

/**
 * Append a pane to the stashed set (used by existence-sync when local adds a pane). No-op if the pane is
 * already placed or already stashed.
 */
export function addStashed(state: WorkspacePanes, paneId: string, sessionId: string | null, name?: string): WorkspacePanes {
  if (allPaneIds(state).has(paneId)) return state
  return { ...state, stashed: [...state.stashed, { paneId, sessionId, name }] }
}

/**
 * Remove a pane from wherever it is — used when local KILLS a pane. Placed → the grid reduces (survivors
 * re-snap, or the grid empties). Stashed → just dropped. No-op if the pane is unknown.
 */
export function removePaneEverywhere(state: WorkspacePanes, paneId: string, mkId: (prefix: string) => string = nextId): WorkspacePanes {
  if (state.layout && findLeaf(state.layout, paneId)) {
    const reduced = reduceRemoving(state.layout, paneId, mkId)
    return { ...state, layout: reduced }
  }
  if (isStashed(state, paneId)) {
    return { ...state, stashed: state.stashed.filter((s) => s.paneId !== paneId) }
  }
  return state
}

/**
 * Reconcile the browser state against the panes that EXIST on local (from workspaceMetadata). For each
 * existing pane not already placed-or-stashed → {@link addStashed} it; for each placed-or-stashed pane no
 * longer existing → {@link removePaneEverywhere}. On the FIRST reconcile (empty state), ALL existing panes go
 * to stashed (nothing placed) — matching "first connect = all stashed". Pure core for Task #600.
 */
export function reconcileExistence(
  state: WorkspacePanes,
  existing: readonly { paneId: string; sessionId: string | null; name?: string }[],
  mkId: (prefix: string) => string = nextId,
): WorkspacePanes {
  // CRITICAL: match by SESSION, not paneId. The browser's placed/stashed panes use the BROWSER's own pane ids
  // (pane-N), while `existing` comes from local's workspaceMetadata with LOCAL's pane ids — the two id-spaces never
  // match. Keying on paneId made every reconcile REMOVE the just-placed pane (browser id ∉ local ids) and ADD a
  // duplicate stashed copy — which continuously unbound the active pane so the user couldn't type. Sessions are the
  // shared identity across both sides, so reconcile on sessionId.
  const existingSessions = new Set(existing.map((e) => e.sessionId).filter((s): s is string => !!s))
  const placedOrStashedSessions = new Set<string>()
  if (state.layout) for (const l of leaves(state.layout.root)) if (l.sessionId) placedOrStashedSessions.add(l.sessionId)
  for (const s of state.stashed) if (s.sessionId) placedOrStashedSessions.add(s.sessionId)

  let next = state
  // Drop panes whose SESSION no longer exists on local (placed → reduce; stashed → remove). Panes with no session
  // bound (empty placeholder) are left alone — they're the browser's own empty slots, not a killed local pane.
  for (const id of [...allPaneIds(state)]) {
    const sid = sessionIdOf(state, id)
    if (sid && !existingSessions.has(sid)) next = removePaneEverywhere(next, id, mkId)
  }
  // IDENTITY UPGRADE (redacted-pane heal; lifecycle edge `session-named`, pane lifecycle contract): the agent
  // redacts a pane's session_id to "" until its session is live/visible (remote_bridge filter_workspace_metadata),
  // so during a desktop-side create the pane arrives FIRST as {paneId, session:null} and only a LATER push names
  // the real session. A session-less row keyed by that DESKTOP pane id (stash entry from an earlier reconcile, or
  // a placed leaf from a premature revive / persisted layout) IS the same pane — bind the session onto it in
  // place. Without this the add loop below NO-OPs on the duplicate paneId and the session becomes unreachable:
  // grey tree rows forever, revive placing a session-less "Empty pane", refresh restoring the same dead shape.
  for (const e of existing) {
    if (!e.sessionId || placedOrStashedSessions.has(e.sessionId)) continue
    if (next.layout && leaves(next.layout.root).some((l) => l.id === e.paneId && !l.sessionId)) {
      next = { ...next, layout: setPaneSession(next.layout, e.paneId, e.sessionId) }
      placedOrStashedSessions.add(e.sessionId)
      continue
    }
    if (next.stashed.some((s) => s.paneId === e.paneId && !s.sessionId)) {
      next = {
        ...next,
        stashed: next.stashed.map((s) =>
          s.paneId === e.paneId && !s.sessionId
            ? { ...s, sessionId: e.sessionId, ...(e.name !== undefined ? { name: e.name } : {}) }
            : s,
        ),
      }
      placedOrStashedSessions.add(e.sessionId)
    }
  }
  // Add sessions that exist on local but aren't placed/stashed here yet → as STASHED (keyed by the LOCAL pane id).
  for (const e of existing) {
    if (e.sessionId && placedOrStashedSessions.has(e.sessionId)) continue // already have this session somewhere
    next = addStashed(next, e.paneId, e.sessionId, e.name)
  }
  return next
}

/** The session id a pane (placed or stashed) currently holds, or null. */
function sessionIdOf(state: WorkspacePanes, paneId: string): string | null {
  if (state.layout) {
    const leaf = leaves(state.layout.root).find((l) => l.id === paneId)
    if (leaf) return leaf.sessionId
  }
  const s = state.stashed.find((p) => p.paneId === paneId)
  return s ? s.sessionId : null
}

// ── serialize / deserialize ───────────────────────────────────────────────────

/** Round-trippable plain JSON (no functions/ids beyond what's needed to rebuild the tree). */
export function serializeLayout(layout: PaneLayout): string {
  return JSON.stringify(layout)
}

function isNode(v: unknown): v is PaneNode {
  if (!v || typeof v !== 'object') return false
  const n = v as Record<string, unknown>
  if (n.kind === 'leaf') return typeof n.id === 'string' && (n.sessionId === null || typeof n.sessionId === 'string')
  if (n.kind === 'split') {
    return (
      typeof n.id === 'string' &&
      (n.dir === 'horizontal' || n.dir === 'vertical') &&
      typeof n.ratio === 'number' &&
      isNode(n.first) &&
      isNode(n.second)
    )
  }
  return false
}

/** Parse a serialized layout. Returns null on malformed input (caller falls back to a fresh single pane). */
export function deserializeLayout(raw: string): PaneLayout | null {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return null
  }
  if (!parsed || typeof parsed !== 'object') return null
  const p = parsed as Record<string, unknown>
  if (!isNode(p.root) || typeof p.activePaneId !== 'string') return null
  const layout = { root: p.root, activePaneId: p.activePaneId }
  // honor the invariant: activePaneId must be a real leaf, else snap to the first leaf
  if (!findLeaf(layout, layout.activePaneId)) {
    return { root: p.root, activePaneId: leaves(p.root)[0].id }
  }
  return layout
}
