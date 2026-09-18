import { describe, it, expect } from 'vitest'
import {
  singlePane, splitActive, focusPane, setPaneSession, closePane, setSplitRatio,
  leaves, paneCount, findLeaf, activeLeaf, serializeLayout, deserializeLayout,
  rebindLayoutToSessions, swapPaneSessions, rebalanceLayout, layoutFromPanes,
  paneRects, paneNeighbor, paneEdgeDirections, swallowPane, swallowDirections, moveDirections,
  DEFAULT_RATIO, MAX_PANES, type PaneLayout,
} from './pane-layout'

// deterministic ids for stable assertions
function ids() {
  let n = 0
  return (prefix: string) => `${prefix}${++n}`
}

describe('pane-layout', () => {
  it('single pane: one leaf, it is active, no session by default', () => {
    const l = singlePane(null, 'p0')
    expect(paneCount(l)).toBe(1)
    expect(l.activePaneId).toBe('p0')
    expect(activeLeaf(l).sessionId).toBeNull()
  })

  it('splitActive: active pane becomes first child, new empty leaf is second + active', () => {
    const mk = ids()
    const l0 = singlePane('s-a', 'p0')
    const l1 = splitActive(l0, 'vertical', { mkId: mk })
    expect(paneCount(l1)).toBe(2)
    expect(l1.root.kind).toBe('split')
    if (l1.root.kind === 'split') {
      expect(l1.root.dir).toBe('vertical')
      expect(l1.root.first).toMatchObject({ kind: 'leaf', id: 'p0', sessionId: 's-a' }) // kept
      expect(l1.root.second.kind).toBe('leaf')
    }
    // new pane is active + empty
    expect(activeLeaf(l1).id).toBe(l1.activePaneId)
    expect(activeLeaf(l1).sessionId).toBeNull()
    expect(activeLeaf(l1).id).not.toBe('p0')
  })

  it('respects MAX_PANES (split is a no-op once full)', () => {
    const mk = ids()
    let l = singlePane(null, 'p0')
    for (let i = 0; i < MAX_PANES - 1; i++) l = splitActive(l, 'horizontal', { mkId: mk })
    expect(paneCount(l)).toBe(MAX_PANES)
    const full = splitActive(l, 'horizontal', { mkId: mk })
    expect(full).toBe(l) // same object → no-op
    expect(paneCount(full)).toBe(MAX_PANES)
  })

  it('focusPane moves the active id only to a real leaf', () => {
    const mk = ids()
    const l = splitActive(singlePane(null, 'p0'), 'vertical', { mkId: mk })
    const other = leaves(l.root).find((x) => x.id !== l.activePaneId)!
    expect(focusPane(l, other.id).activePaneId).toBe(other.id)
    expect(focusPane(l, 'nope')).toBe(l) // no-op for unknown id
  })

  it('setPaneSession attaches/clears a session on a leaf', () => {
    const l = singlePane(null, 'p0')
    const attached = setPaneSession(l, 'p0', 's-x')
    expect(findLeaf(attached, 'p0')!.sessionId).toBe('s-x')
    expect(findLeaf(setPaneSession(attached, 'p0', null), 'p0')!.sessionId).toBeNull()
    expect(setPaneSession(l, 'nope', 's')).toBe(l) // no-op for unknown id
  })

  it('closePane: sibling collapses into the split, count drops', () => {
    const mk = ids()
    const l = splitActive(singlePane('s-a', 'p0'), 'vertical', { mkId: mk }) // p0 | new
    const newId = l.activePaneId
    const after = closePane(l, newId)
    expect(paneCount(after)).toBe(1)
    expect(after.root).toMatchObject({ kind: 'leaf', id: 'p0', sessionId: 's-a' })
    expect(after.activePaneId).toBe('p0') // re-snapped to the survivor
  })

  it('closePane on the last pane is a no-op', () => {
    const l = singlePane('s', 'p0')
    expect(closePane(l, 'p0')).toBe(l)
  })

  it('closePane keeps active when a non-active pane is closed', () => {
    const mk = ids()
    // p0 | a | b  (nested splits); focus p0, close b → active stays p0
    let l = splitActive(singlePane(null, 'p0'), 'vertical', { mkId: mk })
    l = splitActive(l, 'vertical', { mkId: mk })
    const allBefore = leaves(l.root).map((x) => x.id)
    l = focusPane(l, 'p0')
    const lastOpened = allBefore[allBefore.length - 1]
    const after = closePane(l, lastOpened)
    expect(after.activePaneId).toBe('p0')
    expect(paneCount(after)).toBe(2)
  })

  it('setSplitRatio updates the divider, clamped to [0.1, 0.9]', () => {
    const mk = ids()
    const l = splitActive(singlePane(null, 'p0'), 'vertical', { mkId: mk })
    const splitId = l.root.kind === 'split' ? l.root.id : ''
    const wide = setSplitRatio(l, splitId, 0.99) // clamps to 0.9
    expect(wide.root.kind === 'split' && wide.root.ratio).toBe(0.9)
    const narrow = setSplitRatio(l, splitId, -1) // clamps to 0.1
    expect(narrow.root.kind === 'split' && narrow.root.ratio).toBe(0.1)
    expect(setSplitRatio(l, 'nope', 0.5)).toBe(l) // no-op for unknown split
  })

  it('serialize/deserialize round-trips', () => {
    const mk = ids()
    const l = splitActive(setPaneSession(singlePane(null, 'p0'), 'p0', 's-a'), 'horizontal', {
      mkId: mk, sessionId: 's-b',
    })
    const back = deserializeLayout(serializeLayout(l))
    expect(back).toEqual(l)
  })

  it('deserialize returns null on malformed input', () => {
    expect(deserializeLayout('{ not json')).toBeNull()
    expect(deserializeLayout('null')).toBeNull()
    expect(deserializeLayout('{"root":{"kind":"leaf"},"activePaneId":"x"}')).toBeNull() // missing id
    expect(deserializeLayout('{"activePaneId":"x"}')).toBeNull() // no root
  })

  it('deserialize snaps activePaneId to a real leaf when stored id is stale', () => {
    const l: PaneLayout = { root: { kind: 'leaf', id: 'p0', sessionId: null }, activePaneId: 'ghost' }
    const back = deserializeLayout(JSON.stringify(l))!
    expect(back.activePaneId).toBe('p0')
  })
})

describe('rebindLayoutToSessions', () => {
  // a 2-pane layout: pane p0 bound to s1, the new pane bound to s2 (now active).
  function twoPane(): { layout: PaneLayout; left: string; right: string } {
    let l = singlePane(null, 'p0')
    l = setPaneSession(l, 'p0', 's1')
    l = splitActive(l, 'vertical') // p0 (s1) | new empty leaf (now active)
    const right = activeLeaf(l).id
    l = setPaneSession(l, right, 's2')
    return { layout: l, left: 'p0', right }
  }

  it('keeps a leaf bound only when its session is still live; the split shape is preserved', () => {
    const { layout, left, right } = twoPane()
    const r = rebindLayoutToSessions(layout, ['s1']) // s2 ended
    expect(leaves(r.root).length).toBe(2) // split preserved
    const byPane = Object.fromEntries(leaves(r.root).map((l) => [l.id, l.sessionId]))
    expect(byPane[left]).toBe('s1') // still live → kept
    expect(byPane[right]).toBeNull() // s2 gone → emptied (a spawnable slot)
  })

  it('empties every binding when no saved session is live (shape still kept)', () => {
    const r = rebindLayoutToSessions(twoPane().layout, ['s9'])
    expect(leaves(r.root).every((l) => l.sessionId === null)).toBe(true)
    expect(leaves(r.root).length).toBe(2)
  })

  it('falls back the active pane to the first leaf when the saved active pane is gone', () => {
    const { layout } = twoPane()
    const broken: PaneLayout = { root: layout.root, activePaneId: 'p-missing' }
    const r = rebindLayoutToSessions(broken, ['s1', 's2'])
    expect(leaves(r.root).map((x) => x.id)).toContain(r.activePaneId) // active is a real pane
  })
})

describe('layoutFromPanes (mirror a desktop window)', () => {
  const spec = (paneId: string, sessionId: string) => ({ paneId, sessionId })

  it('empty → a single empty pane', () => {
    const l = layoutFromPanes([])
    expect(paneCount(l)).toBe(1)
    expect(activeLeaf(l).sessionId).toBeNull()
  })

  it('one pane → single leaf bound to its session, using the desktop pane id', () => {
    const l = layoutFromPanes([spec('pane-a', 's-a')], 's-a')
    expect(paneCount(l)).toBe(1)
    expect(activeLeaf(l).id).toBe('pane-a')
    expect(activeLeaf(l).sessionId).toBe('s-a')
  })

  it('two panes → left|right vertical split, leaf ids = desktop pane ids, active = activeSessionId', () => {
    const l = layoutFromPanes([spec('pane-a', 's-a'), spec('pane-b', 's-b')], 's-b')
    expect(paneCount(l)).toBe(2)
    expect(l.root.kind).toBe('split')
    expect(leaves(l.root).map((x) => x.id)).toEqual(['pane-a', 'pane-b'])
    expect(leaves(l.root).map((x) => x.sessionId)).toEqual(['s-a', 's-b'])
    expect(activeLeaf(l).id).toBe('pane-b')
  })

  it('three panes → left | (right split) with all sessions bound', () => {
    const l = layoutFromPanes([spec('a', 's1'), spec('b', 's2'), spec('c', 's3')], 's1')
    expect(paneCount(l)).toBe(3)
    expect(new Set(leaves(l.root).map((x) => x.sessionId))).toEqual(new Set(['s1', 's2', 's3']))
    expect(activeLeaf(l).id).toBe('a')
  })

  it('four panes → 2×2 grid; caps input at MAX_PANES', () => {
    const specs = [spec('a', 's1'), spec('b', 's2'), spec('c', 's3'), spec('d', 's4'), spec('e', 's5')]
    const l = layoutFromPanes(specs, 's1')
    expect(paneCount(l)).toBe(MAX_PANES)
    expect(new Set(leaves(l.root).map((x) => x.sessionId))).toEqual(new Set(['s1', 's2', 's3', 's4']))
  })

  it('unknown activeSessionId → focuses the first pane', () => {
    const l = layoutFromPanes([spec('a', 's1'), spec('b', 's2')], 'nope')
    expect(activeLeaf(l).id).toBe('a')
  })
})

describe('geometry: paneRects / paneNeighbor / swallow (local move + swallow arrows)', () => {
  const spec = (paneId: string, sessionId: string) => ({ paneId, sessionId })

  it('paneRects tiles the unit square for a 2×2 grid', () => {
    const l = layoutFromPanes([spec('a', '1'), spec('b', '2'), spec('c', '3'), spec('d', '4')], '1')
    const rects = paneRects(l)
    expect(rects).toHaveLength(4)
    // areas sum to 1 (tiling)
    const area = rects.reduce((s, r) => s + r.w * r.h, 0)
    expect(area).toBeCloseTo(1, 5)
  })

  it('paneNeighbor: left|right split → a is left of b, b is right of a', () => {
    const l = layoutFromPanes([spec('a', '1'), spec('b', '2')], '1')
    expect(paneNeighbor(l, 'a', 'right')).toBe('b')
    expect(paneNeighbor(l, 'b', 'left')).toBe('a')
    expect(paneNeighbor(l, 'a', 'left')).toBeNull() // at the window edge
    expect(paneNeighbor(l, 'a', 'up')).toBeNull()
  })

  it('paneNeighbor: tall-left facing TWO stacked-right → picks the most perpendicular-aligned (local tie-break)', () => {
    // a | (b top / c bottom): the tall left pane `a` borders BOTH b and c on its right edge. Local resolves the
    // RIGHT neighbor by min(gap, perpendicular-center-distance) — a's center is vertically between b and c, so the
    // one whose center is closer wins deterministically (b, the top half, in reading order on an exact tie). The
    // OLD browser code only compared gap (equal for both) → non-deterministic/wrong pick.
    const l = layoutFromPanes([spec('a', '1'), spec('b', '2'), spec('c', '3')], '1')
    const right = paneNeighbor(l, 'a', 'right')
    expect(right === 'b' || right === 'c').toBe(true) // a real stacked-right neighbor, resolved deterministically
    // b's LEFT neighbor is unambiguously the tall a (b's whole left edge faces a).
    expect(paneNeighbor(l, 'b', 'left')).toBe('a')
    expect(paneNeighbor(l, 'c', 'left')).toBe('a')
  })

  it('paneNeighbor: 2×2 grid — each pane has a horizontal + vertical neighbor', () => {
    // layoutFromPanes 4 = (a/c) | (b/d): a top-left, c bottom-left, b top-right, d bottom-right
    const l = layoutFromPanes([spec('a', '1'), spec('b', '2'), spec('c', '3'), spec('d', '4')], '1')
    expect(paneNeighbor(l, 'a', 'right')).toBe('b')
    expect(paneNeighbor(l, 'a', 'down')).toBe('c')
    expect(paneNeighbor(l, 'd', 'left')).toBe('c')
    expect(paneNeighbor(l, 'd', 'up')).toBe('b')
  })

  it('paneEdgeDirections lists only directions with a neighbor', () => {
    const l = layoutFromPanes([spec('a', '1'), spec('b', '2')], '1')
    expect(paneEdgeDirections(l, 'a').sort()).toEqual(['right'])
    expect(paneEdgeDirections(l, 'b').sort()).toEqual(['left'])
  })

  it('swallow: 2-pane — a swallows right → a takes the whole window (b removed from grid)', () => {
    const l = layoutFromPanes([spec('a', '1'), spec('b', '2')], '1')
    const after = swallowPane(l, 'a', 'right')
    expect(paneCount(after)).toBe(1)
    expect(leaves(after.root).map((x) => x.id)).toEqual(['a'])
    expect(after.activePaneId).toBe('a')
  })

  it('swallow: b swallows left → b takes the whole window', () => {
    const l = layoutFromPanes([spec('a', '1'), spec('b', '2')], '2')
    const after = swallowPane(l, 'b', 'left')
    expect(leaves(after.root).map((x) => x.id)).toEqual(['b'])
  })

  it('swallow: no neighbor that way → no-op (same layout)', () => {
    const l = layoutFromPanes([spec('a', '1'), spec('b', '2')], '1')
    expect(swallowPane(l, 'a', 'left')).toBe(l)
    expect(swallowPane(l, 'a', 'up')).toBe(l)
  })

  it('swallow: 3-pane left|(right split) — left swallows right absorbs the right column', () => {
    // a | (b top / c bottom)
    const l = layoutFromPanes([spec('a', '1'), spec('b', '2'), spec('c', '3')], '1')
    const after = swallowPane(l, 'a', 'right')
    expect(leaves(after.root).map((x) => x.id)).toEqual(['a'])
  })
})

describe('swallowDirections (ports pane_swallow_directions, exactly-one-strictly-longer-neighbor rule)', () => {
  const spec = (paneId: string, sessionId: string) => ({ paneId, sessionId })

  it('2 columns: EQUAL length neighbours → NO swallow either way (only move/swap applies)', () => {
    // a | b, equal heights. Each borders exactly one neighbor but of EQUAL span → strict-contains fails.
    const l = layoutFromPanes([spec('a', '1'), spec('b', '2')], '1')
    expect(swallowDirections(l, 'a')).toEqual([])
    expect(swallowDirections(l, 'b')).toEqual([])
    // sanity: move arrows still exist (has-neighbor rule)
    expect(moveDirections(l, 'a')).toEqual(['right'])
    expect(moveDirections(l, 'b')).toEqual(['left'])
  })

  it('2 rows: equal-width stacked panes → NO swallow either way', () => {
    // a over b (TwoRows). Equal widths on the shared horizontal edge → no swallow.
    const l = layoutFromPanes([spec('a', '1'), spec('b', '2')], '1')
    // layoutFromPanes(2) is TwoColumns; build TwoRows explicitly via a horizontal split.
    let rows = setPaneSession(singlePane(null, 'a'), 'a', '1')
    rows = splitActive(rows, 'horizontal', { sessionId: '2', mkId: (p) => (p === 'pane' ? 'b' : 'sp') })
    expect(swallowDirections(rows, 'a')).toEqual([])
    expect(swallowDirections(rows, 'b')).toEqual([])
    void l
  })

  it('3-column middle pane: bordered by 2 neighbours on each horizontal side? No — one each → but EQUAL height ⇒ no swallow', () => {
    // ThreeColumns: a | b | c, all equal full-height thirds. Middle b has one left (a) + one right (c), each
    // EQUAL height → strict-contains fails both ways. No vertical neighbours. So NO swallow arrows at all.
    const l = layoutFromPanes([spec('a', '1'), spec('b', '2'), spec('c', '3')], '1')
    // layoutFromPanes(3) is left-main-ish (a | b/c), not ThreeColumns; build ThreeColumns explicitly.
    let three = setPaneSession(singlePane(null, 'a'), 'a', '1')
    three = splitActive(three, 'vertical', { sessionId: '2', mkId: (p) => (p === 'pane' ? 'b' : 's1') })
    three = { ...three, activePaneId: 'b' }
    three = splitActive(three, 'vertical', { sessionId: '3', mkId: (p) => (p === 'pane' ? 'c' : 's2') })
    // three ≈ a | (b | c) — three equal-height columns.
    expect(swallowDirections(three, 'b')).toEqual([])
    expect(swallowDirections(three, 'a')).toEqual([])
    expect(swallowDirections(three, 'c')).toEqual([])
    void l
  })

  it('L-shaped 3-pane a | (b/c): the two short right panes can swallow LEFT into the tall left; the tall left cannot swallow right (two neighbours)', () => {
    // layoutFromPanes(3) = a | (b top / c bottom). a spans full height (left), b/c are half-height (right).
    const l = layoutFromPanes([spec('a', '1'), spec('b', '2'), spec('c', '3')], '1')
    // b: LEFT edge borders exactly a, whose vertical span (full) strictly contains b's (top half) → swallow left.
    expect(swallowDirections(l, 'b')).toEqual(['left'])
    // c: same, bottom half → swallow left.
    expect(swallowDirections(l, 'c')).toEqual(['left'])
    // a: RIGHT edge borders TWO panes (b and c) → across.len() != 1 → cannot swallow right. No other neighbours.
    expect(swallowDirections(l, 'a')).toEqual([])
  })

  it('4-grid: all equal quarters → NO swallow anywhere (each edge borders exactly one EQUAL-length neighbour)', () => {
    // (a/c) | (b/d). Every pane's each edge borders exactly one neighbor of EQUAL perpendicular span → strict
    // contains fails everywhere.
    const l = layoutFromPanes([spec('a', '1'), spec('b', '2'), spec('c', '3'), spec('d', '4')], '1')
    for (const id of ['a', 'b', 'c', 'd']) expect(swallowDirections(l, id)).toEqual([])
  })

  it('unknown pane → empty', () => {
    const l = layoutFromPanes([spec('a', '1'), spec('b', '2')], '1')
    expect(swallowDirections(l, 'nope')).toEqual([])
  })
})

describe('swapPaneSessions', () => {
  // a 2-pane layout: p0 → s1, the second leaf → s2.
  function twoPane(): { layout: PaneLayout; left: string; right: string } {
    let l = setPaneSession(singlePane(null, 'p0'), 'p0', 's1')
    l = splitActive(l, 'vertical')
    const right = activeLeaf(l).id
    l = setPaneSession(l, right, 's2')
    return { layout: l, left: 'p0', right }
  }

  it('exchanges the two panes’ sessions; geometry + active pane unchanged', () => {
    const { layout, left, right } = twoPane()
    const before = leaves(layout.root).map((l) => l.id) // pane order/positions
    const r = swapPaneSessions(layout, left, right)
    const byId = Object.fromEntries(leaves(r.root).map((l) => [l.id, l.sessionId]))
    expect(byId[left]).toBe('s2') // contents traded places…
    expect(byId[right]).toBe('s1')
    expect(leaves(r.root).map((l) => l.id)).toEqual(before) // …but the split geometry/order did NOT move
    expect(r.activePaneId).toBe(layout.activePaneId) // focus stays on the same pane SLOT
  })

  it('handles an empty pane (null session) — swapping with a bound pane moves the session into the empty slot', () => {
    let l = setPaneSession(singlePane(null, 'p0'), 'p0', 's1')
    l = splitActive(l, 'vertical') // new leaf is empty (sessionId null)
    const empty = activeLeaf(l).id
    const r = swapPaneSessions(l, 'p0', empty)
    const byId = Object.fromEntries(leaves(r.root).map((x) => [x.id, x.sessionId]))
    expect(byId['p0']).toBeNull()    // p0 now empty
    expect(byId[empty]).toBe('s1')   // the session moved to the other slot
  })

  it('is a no-op for the same pane or a missing pane id', () => {
    const { layout, left } = twoPane()
    expect(swapPaneSessions(layout, left, left)).toBe(layout)          // same pane → identity
    expect(swapPaneSessions(layout, left, 'nope')).toBe(layout)        // missing target → identity
    expect(swapPaneSessions(layout, 'nope', left)).toBe(layout)        // missing source → identity
  })
})

describe('rebalanceLayout', () => {
  it('resets every split ratio to DEFAULT_RATIO while keeping topology + session bindings + active pane', () => {
    let l = setPaneSession(singlePane(null, 'p0'), 'p0', 's1')
    l = splitActive(l, 'vertical')
    const mid = activeLeaf(l).id
    l = setPaneSession(l, mid, 's2')
    l = splitActive(l, 'horizontal')
    const last = activeLeaf(l).id
    l = setPaneSession(l, last, 's3')
    const activeBefore = l.activePaneId
    const idsBefore = leaves(l.root).map((x) => x.id)
    const bindingsBefore = Object.fromEntries(leaves(l.root).map((x) => [x.id, x.sessionId]))
    // skew every split off-center
    const skew = (node: typeof l.root): void => {
      if (node.kind === 'split') { l = setSplitRatio(l, node.id, 0.7); skew(node.first); skew(node.second) }
    }
    skew(l.root)

    const r = rebalanceLayout(l)
    const ratios: number[] = []
    const collect = (node: typeof r.root): void => {
      if (node.kind === 'split') { ratios.push(node.ratio); collect(node.first); collect(node.second) }
    }
    collect(r.root)
    expect(ratios.length).toBeGreaterThan(0)
    expect(ratios.every((x) => x === DEFAULT_RATIO)).toBe(true)
    // topology, bindings, and focus untouched
    expect(leaves(r.root).map((x) => x.id)).toEqual(idsBefore)
    expect(Object.fromEntries(leaves(r.root).map((x) => [x.id, x.sessionId]))).toEqual(bindingsBefore)
    expect(r.activePaneId).toBe(activeBefore)
  })

  it('is a no-op (same object) when all splits are already even', () => {
    let l = setPaneSession(singlePane(null, 'p0'), 'p0', 's1')
    l = splitActive(l, 'vertical') // new split defaults to 0.5
    expect(rebalanceLayout(l)).toBe(l)
  })

  it('a single pane (no splits) is a no-op', () => {
    const l = singlePane('s1', 'p0')
    expect(rebalanceLayout(l)).toBe(l)
  })
})

// ── canonical engine + placed/stashed model (ports of maestro-shell/src/pane_layout.rs) ──
import {
  defaultLayoutForCount, buildCanonicalLayout, canonicalPaneCount, layoutName,
  reduceRemoving, reviveInto, reviveTarget, reviveSlot, reviveWindow, swallowTarget, swallowCanonical,
  readingOrderPanes, readingOrderIds,
  emptyWorkspace, stashPane, revivePane, addStashed, removePaneEverywhere,
  reconcileExistence, isPlaced, isStashed,
  type CanonicalLayout, type WorkspacePanes,
} from './pane-layout'

// Build a placed PaneLayout for a canonical layout with the given pane ids (reading order) + matching sessions.
function placed(layout: CanonicalLayout, paneIds: string[], mk = ids()): PaneLayout {
  const n = canonicalPaneCount(layout)
  if (paneIds.length !== n) throw new Error(`need ${n} ids`)
  const tree = buildCanonicalLayout(layout, paneIds.map((_, i) => `s${i}`), mk)
  // remap fresh leaf ids → the requested pane ids in reading order
  const built: PaneLayout = { root: tree, activePaneId: '' }
  const order = readingOrderIds(built)
  const remap = new Map(order.map((f, i) => [f, paneIds[i]]))
  const walk = (node: any): any =>
    node.kind === 'leaf' ? { ...node, id: remap.get(node.id) ?? node.id } : { ...node, first: walk(node.first), second: walk(node.second) }
  const root = walk(tree)
  return { root, activePaneId: paneIds[0] }
}

describe('defaultLayoutForCount', () => {
  it('maps 1..4 to OneFull/TwoColumns/ThreeColumns/FourGrid; null otherwise', () => {
    expect(defaultLayoutForCount(1)).toBe('OneFull')
    expect(defaultLayoutForCount(2)).toBe('TwoColumns')
    expect(defaultLayoutForCount(3)).toBe('ThreeColumns')
    expect(defaultLayoutForCount(4)).toBe('FourGrid')
    expect(defaultLayoutForCount(0)).toBeNull()
    expect(defaultLayoutForCount(5)).toBeNull()
  })
})

describe('buildCanonicalLayout geometry (matches slot_rects reading order)', () => {
  const rectsOf = (layout: CanonicalLayout) => {
    const l = placed(layout, Array.from({ length: canonicalPaneCount(layout) }, (_, i) => `p${i}`))
    const rs = paneRects(l)
    const byId = new Map(rs.map((r) => [r.id, r]))
    // return in reading order p0,p1,...
    return Array.from({ length: canonicalPaneCount(layout) }, (_, i) => byId.get(`p${i}`)!)
  }
  const approx = (a: number, b: number) => expect(Math.abs(a - b)).toBeLessThan(1e-6)
  const eq = (r: any, x: number, y: number, w: number, h: number) => { approx(r.x, x); approx(r.y, y); approx(r.w, w); approx(r.h, h) }

  it('TwoColumns = left|right .5', () => {
    const [a, b] = rectsOf('TwoColumns'); eq(a, 0, 0, 0.5, 1); eq(b, 0.5, 0, 0.5, 1)
  })
  it('ThreeColumns = thirds', () => {
    const [a, b, c] = rectsOf('ThreeColumns'); eq(a, 0, 0, 1 / 3, 1); eq(b, 1 / 3, 0, 1 / 3, 1); eq(c, 2 / 3, 0, 1 / 3, 1)
  })
  it('FourGrid = 2x2, reading order TL,TR,BL,BR', () => {
    const [tl, tr, bl, br] = rectsOf('FourGrid')
    eq(tl, 0, 0, 0.5, 0.5); eq(tr, 0.5, 0, 0.5, 0.5); eq(bl, 0, 0.5, 0.5, 0.5); eq(br, 0.5, 0.5, 0.5, 0.5)
  })
  it('ThreeRightMain: S0 top-left, S1 right main full-height, S2 bottom-left', () => {
    const [s0, s1, s2] = rectsOf('ThreeRightMain') // left=1-m=0.4, s=0.5
    eq(s0, 0, 0, 0.4, 0.5); eq(s1, 0.4, 0, 0.6, 1); eq(s2, 0, 0.5, 0.4, 0.5)
  })
  it('FourBottomMain: top row 3 cols, bottom full-width main (S3)', () => {
    const [s0, s1, s2, s3] = rectsOf('FourBottomMain') // side=0.45, m=0.55
    eq(s0, 0, 0, 1 / 3, 0.45); eq(s1, 1 / 3, 0, 1 / 3, 0.45); eq(s2, 2 / 3, 0, 1 / 3, 0.45); eq(s3, 0, 0.45, 1, 0.55)
  })
  it('every canonical layout round-trips through layoutName', () => {
    const all: CanonicalLayout[] = [
      'OneFull', 'TwoColumns', 'TwoRows', 'ThreeColumns', 'ThreeRows',
      'ThreeLeftMain', 'ThreeRightMain', 'ThreeTopMain', 'ThreeBottomMain',
      'FourGrid', 'FourColumns', 'FourRows', 'FourLeftSplit', 'FourTopSplit',
      'FourLeftMain', 'FourRightMain', 'FourTopMain', 'FourBottomMain',
    ]
    for (const c of all) {
      const l = placed(c, Array.from({ length: canonicalPaneCount(c) }, (_, i) => `p${i}`))
      expect(layoutName(l)).toBe(c)
    }
  })
})

describe('reduceRemoving (stash super-rule, ports reduce_removing)', () => {
  it('4→3 re-snaps survivors to ThreeColumns preserving reading order, keeping sessions', () => {
    // FourGrid reading order p0(TL),p1(TR),p2(BL),p3(BR); each bound to sess-i
    let l = placed('FourGrid', ['p0', 'p1', 'p2', 'p3'])
    l = setPaneSession(l, 'p0', 'A'); l = setPaneSession(l, 'p1', 'B'); l = setPaneSession(l, 'p2', 'C'); l = setPaneSession(l, 'p3', 'D')
    const r = reduceRemoving(l, 'p2')! // remove BL
    expect(layoutName(r)).toBe('ThreeColumns')
    // survivors reading order was p0,p1,p3 → sessions A,B,D
    expect(readingOrderPanes(r).map((p) => p.sessionId)).toEqual(['A', 'B', 'D'])
    expect(readingOrderPanes(r).map((p) => p.paneId)).toEqual(['p0', 'p1', 'p3'])
  })
  it('removing the last placed pane returns null (empty grid allowed)', () => {
    const l = singlePane('S', 'only')
    expect(reduceRemoving(l, 'only')).toBeNull()
  })
  it('no-op when pane not placed', () => {
    const l = placed('TwoColumns', ['a', 'b'])
    expect(reduceRemoving(l, 'zzz')).toBe(l)
  })
})

describe('reviveTarget table (ports revive_target)', () => {
  it('matches the canonical spec exactly', () => {
    expect(reviveTarget('OneFull')).toBe('TwoColumns')
    expect(reviveTarget('TwoColumns')).toBe('ThreeRightMain')
    expect(reviveTarget('TwoRows')).toBe('ThreeBottomMain')
    expect(reviveTarget('ThreeColumns')).toBe('FourLeftSplit')
    expect(reviveTarget('ThreeRows')).toBe('FourTopSplit')
    expect(reviveTarget('ThreeLeftMain')).toBe('FourGrid')
    expect(reviveTarget('ThreeRightMain')).toBe('FourGrid')
    expect(reviveTarget('ThreeTopMain')).toBe('FourGrid')
    expect(reviveTarget('ThreeBottomMain')).toBe('FourGrid')
    for (const full of ['FourGrid', 'FourColumns', 'FourRows', 'FourLeftSplit', 'FourTopSplit', 'FourLeftMain', 'FourRightMain', 'FourTopMain', 'FourBottomMain'] as CanonicalLayout[]) {
      expect(reviveTarget(full)).toBeNull()
    }
  })
})

describe('R10 — reviveSlot / reviveInto (ports revive_rects_by_spec, maestro-shell/src/window_layout.rs:992-1126)', () => {
  // Table-driven mirror of local's click-revive spec: one row per base layout, giving the canonical target
  // (revive_target) and the READING-ORDER slot the revived pane X lands in — NOT always last. `local` cites
  // the Rust arm each row was ported from.
  const TABLE: Array<{ base: CanonicalLayout; ids: string[]; target: CanonicalLayout; slot: number; local: string }> = [
    { base: 'OneFull', ids: ['a'], target: 'TwoColumns', slot: 1, local: 'A → A|X (window_layout.rs:1014-1018)' },
    { base: 'TwoColumns', ids: ['a', 'b'], target: 'ThreeRightMain', slot: 2, local: 'A|B → (A/X)|B (window_layout.rs:1023-1028)' },
    { base: 'TwoRows', ids: ['a', 'b'], target: 'ThreeBottomMain', slot: 1, local: 'A/B → (A|X)/B (window_layout.rs:1030-1036)' },
    { base: 'ThreeColumns', ids: ['a', 'b', 'c'], target: 'FourLeftSplit', slot: 3, local: 'A|B|C → (A/X)|B|C (window_layout.rs:1046-1053)' },
    { base: 'ThreeRows', ids: ['a', 'b', 'c'], target: 'FourTopSplit', slot: 1, local: 'A/B/C → (A|X)/B/C (window_layout.rs:1055-1062)' },
    { base: 'ThreeLeftMain', ids: ['a', 'b', 'c'], target: 'FourGrid', slot: 2, local: 'A|(B/C) → (A|B)/(X|C) (window_layout.rs:1074-1080)' },
    { base: 'ThreeRightMain', ids: ['a', 'b', 'c'], target: 'FourGrid', slot: 3, local: '(A/C)|B → (A|B)/(C|X) (window_layout.rs:1082-1088)' },
    { base: 'ThreeTopMain', ids: ['a', 'b', 'c'], target: 'FourGrid', slot: 1, local: 'A/(B|C) → (A|X)/(B|C) (window_layout.rs:1102-1108)' },
    { base: 'ThreeBottomMain', ids: ['a', 'b', 'c'], target: 'FourGrid', slot: 3, local: '(A|B)/C → (A|B)/(C|X) (window_layout.rs:1110-1116)' },
  ]
  for (const row of TABLE) {
    it(`${row.base} + X → ${row.target}, X at reading-order slot ${row.slot} — local: ${row.local}`, () => {
      expect(reviveSlot(row.base)).toBe(row.slot)
      let l = placed(row.base, row.ids)
      for (const id of row.ids) l = setPaneSession(l, id, id.toUpperCase())
      const r = reviveInto(l, 'x', 'X')!
      expect(layoutName(r)).toBe(row.target)
      const order = readingOrderPanes(r)
      expect(order[row.slot]!.paneId).toBe('x')
      expect(order[row.slot]!.sessionId).toBe('X')
      // survivors keep their relative reading order + sessions around X (rust: "existing panes keep their
      // relative pairing; only the revived pane is new", window_layout.rs:990)
      expect(order.filter((p) => p.paneId !== 'x').map((p) => p.sessionId)).toEqual(row.ids.map((id) => id.toUpperCase()))
      expect(r.activePaneId).toBe('x') // the revived pane takes focus
    })
  }
  it('empty grid: revive → the sole OneFull pane (window_layout.rs:1013)', () => {
    const ws = revivePane(addStashed(emptyWorkspace(), 'x', 'X'), 'x')
    expect(ws.layout).not.toBeNull()
    expect(layoutName(ws.layout!)).toBe('OneFull')
    expect(readingOrderPanes(ws.layout!)).toEqual([{ paneId: 'x', sessionId: 'X' }])
  })
  it('null when already at 4 panes (max-4 gate, window_layout.rs:1804-1815)', () => {
    const l = placed('FourGrid', ['a', 'b', 'c', 'd'])
    expect(reviveInto(l, 'e', 'E')).toBeNull()
  })
})

describe('R10/R11 — reviveWindow (SEQUENTIAL window revive: the single-revive slot table applied repeatedly, per the user-delegated revive decision)', () => {
  const stashedWindow = (n: number): WorkspacePanes => ({
    layout: null,
    stashed: Array.from({ length: n }, (_, i) => ({ paneId: `p${i}`, sessionId: `s${i}` })),
    windowStashed: true,
  })
  const rectOf = (l: PaneLayout, paneId: string) => paneRects(l).find((r) => r.id === paneId)!

  it('1 pane → full (OneFull)', () => {
    const ws = reviveWindow(stashedWindow(1))
    expect(ws.windowStashed).toBeUndefined() // reviving un-stashes the window (R2 inverse)
    expect(ws.stashed).toHaveLength(0)
    expect(layoutName(ws.layout!)).toBe('OneFull')
    expect(readingOrderPanes(ws.layout!)).toEqual([{ paneId: 'p0', sessionId: 's0' }])
  })

  it('2 panes → A|B (TwoColumns)', () => {
    const ws = reviveWindow(stashedWindow(2))
    expect(layoutName(ws.layout!)).toBe('TwoColumns')
    expect(readingOrderPanes(ws.layout!).map((p) => p.paneId)).toEqual(['p0', 'p1'])
  })

  it('3 panes → (A/C)|B (ThreeRightMain: A top-left, B right main, C bottom-left) — derived by the sequential chain (OneFull→TwoColumns→ThreeRightMain)', () => {
    const ws = reviveWindow(stashedWindow(3))
    expect(layoutName(ws.layout!)).toBe('ThreeRightMain')
    const a = rectOf(ws.layout!, 'p0'); const b = rectOf(ws.layout!, 'p1'); const c = rectOf(ws.layout!, 'p2')
    expect(a.x).toBeCloseTo(0); expect(a.y).toBeCloseTo(0) // A top-left
    expect(b.y).toBeCloseTo(0); expect(b.h).toBeCloseTo(1) // B = full-height right main
    expect(b.x).toBeGreaterThan(0.3)
    expect(c.x).toBeCloseTo(0); expect(c.y).toBeCloseTo(0.5) // C bottom-left, under A
  })

  it('4 panes → (A/C)|(B/D) (FourGrid, reading-order slots — sequential chain: …ThreeRightMain + D at the last slot)', () => {
    const ws = reviveWindow(stashedWindow(4))
    expect(layoutName(ws.layout!)).toBe('FourGrid')
    const [a, b, c, d] = ['p0', 'p1', 'p2', 'p3'].map((id) => rectOf(ws.layout!, id))
    expect([a.x, a.y]).toEqual([0, 0])       // A top-left
    expect(b.x).toBeCloseTo(0.5); expect(b.y).toBeCloseTo(0)   // B top-right (reading order slot 1)
    expect(c.x).toBeCloseTo(0); expect(c.y).toBeCloseTo(0.5)   // C bottom-left, under A
    expect(d.x).toBeCloseTo(0.5); expect(d.y).toBeCloseTo(0.5) // D bottom-right
  })

  it('5+ panes → only the FIRST 4 revive; the rest STAY stashed (R11(2) cap)', () => {
    const ws = reviveWindow(stashedWindow(6))
    expect(layoutName(ws.layout!)).toBe('FourGrid')
    expect(readingOrderPanes(ws.layout!).map((p) => p.paneId).sort()).toEqual(['p0', 'p1', 'p2', 'p3'])
    expect(ws.stashed.map((s) => s.paneId)).toEqual(['p4', 'p5'])
  })

  it('a window with a placed grid revives the REMAINING stashed panes incrementally up to the 4-pane cap', () => {
    let base: WorkspacePanes = { layout: placed('TwoColumns', ['p0', 'p1']), stashed: [
      { paneId: 'p2', sessionId: 's2' }, { paneId: 'p3', sessionId: 's3' }, { paneId: 'p4', sessionId: 's4' },
    ] }
    const ws = reviveWindow(base)
    expect(readingOrderPanes(ws.layout!).map((p) => p.paneId).sort()).toEqual(['p0', 'p1', 'p2', 'p3'])
    expect(ws.stashed.map((s) => s.paneId)).toEqual(['p4']) // 5th stays stashed
  })

  it('nothing stashed → only the windowStashed flag clears (layout untouched)', () => {
    const l = placed('TwoColumns', ['p0', 'p1'])
    const ws = reviveWindow({ layout: l, stashed: [], windowStashed: true })
    expect(ws.layout).toBe(l)
    expect(ws.windowStashed).toBeUndefined()
  })
})

describe('swallowTarget table (ports swallow_target)', () => {
  it('matches the legal 3-pane and 4-pane entries', () => {
    // slot index = reading-order index. h dirs = left/right, v dirs = up/down.
    expect(swallowTarget('ThreeLeftMain', 1, 'right')).toBe('ThreeTopMain')
    expect(swallowTarget('ThreeLeftMain', 2, 'left')).toBe('ThreeBottomMain')
    expect(swallowTarget('ThreeRightMain', 0, 'right')).toBe('ThreeTopMain')
    expect(swallowTarget('ThreeRightMain', 2, 'left')).toBe('ThreeBottomMain')
    expect(swallowTarget('ThreeTopMain', 1, 'up')).toBe('ThreeLeftMain')
    expect(swallowTarget('ThreeTopMain', 2, 'down')).toBe('ThreeRightMain')
    expect(swallowTarget('ThreeColumns', 0, 'up')).toBe('ThreeLeftMain')
    expect(swallowTarget('ThreeColumns', 2, 'down')).toBe('ThreeRightMain')
    expect(swallowTarget('ThreeRows', 0, 'left')).toBe('ThreeTopMain')
    expect(swallowTarget('ThreeRows', 2, 'right')).toBe('ThreeBottomMain')
    // 4-pane
    expect(swallowTarget('FourLeftMain', 1, 'left')).toBe('FourTopMain')
    expect(swallowTarget('FourLeftMain', 3, 'right')).toBe('FourBottomMain')
    expect(swallowTarget('FourTopMain', 1, 'up')).toBe('FourLeftMain')
    expect(swallowTarget('FourBottomMain', 2, 'down')).toBe('FourRightMain')
  })
  it('null for illegal combos (wrong axis / wrong slot / non-swallowable)', () => {
    expect(swallowTarget('ThreeLeftMain', 0, 'up')).toBeNull()
    expect(swallowTarget('ThreeColumns', 1, 'up')).toBeNull()
    expect(swallowTarget('OneFull', 0, 'left')).toBeNull()
    expect(swallowTarget('TwoColumns', 0, 'up')).toBeNull()
    expect(swallowTarget('FourGrid', 0, 'up')).toBeNull()
  })
})

describe('swallowCanonical (ports apply_swallow) — KEEPS ALL PANES', () => {
  it('4-pane swallow keeps all 4 panes and transitions layout', () => {
    // FourLeftMain: S0 main, S1/S2/S3 right stack. Swallow S1 (right-top) → FourTopMain, all survive.
    let l = placed('FourLeftMain', ['m', 'r1', 'r2', 'r3'])
    l = setPaneSession(l, 'm', 'M'); l = setPaneSession(l, 'r1', 'R1'); l = setPaneSession(l, 'r2', 'R2'); l = setPaneSession(l, 'r3', 'R3')
    const r = swallowCanonical(l, 'r1', 'left')
    expect(paneCount(r)).toBe(4) // NO pane lost
    expect(layoutName(r)).toBe('FourTopMain')
    // r1 is now the full-span main (slot 0 of FourTopMain)
    expect(readingOrderPanes(r)[0].paneId).toBe('r1')
    // all sessions still present
    expect(new Set(leaves(r.root).map((x) => x.sessionId))).toEqual(new Set(['M', 'R1', 'R2', 'R3']))
  })
  it('3-pane swallow keeps all 3 panes, selected becomes main', () => {
    let l = placed('ThreeColumns', ['a', 'b', 'c'])
    l = setPaneSession(l, 'a', 'A'); l = setPaneSession(l, 'b', 'B'); l = setPaneSession(l, 'c', 'C')
    const r = swallowCanonical(l, 'a', 'up') // ThreeColumns S0 up → ThreeLeftMain
    expect(paneCount(r)).toBe(3)
    expect(layoutName(r)).toBe('ThreeLeftMain')
    expect(readingOrderPanes(r)[0].paneId).toBe('a') // main
  })
  it('no-op (same layout) for an illegal swallow', () => {
    const l = placed('TwoColumns', ['a', 'b'])
    expect(swallowCanonical(l, 'a', 'up')).toBe(l)
  })
})

describe('WorkspacePanes: placed/stashed', () => {
  it('stash then revive round-trips (session + pane preserved)', () => {
    // Start: two placed panes a,b
    let ws: WorkspacePanes = { layout: setPaneSession(setPaneSession(placed('TwoColumns', ['a', 'b']), 'a', 'A'), 'b', 'B'), stashed: [] }
    ws = stashPane(ws, 'b')
    expect(isStashed(ws, 'b')).toBe(true)
    expect(isPlaced(ws, 'b')).toBe(false)
    expect(layoutName(ws.layout!)).toBe('OneFull') // survivor a re-snapped
    expect(ws.stashed[0]).toMatchObject({ paneId: 'b', sessionId: 'B' })
    // revive b back
    ws = revivePane(ws, 'b')
    expect(isPlaced(ws, 'b')).toBe(true)
    expect(isStashed(ws, 'b')).toBe(false)
    expect(paneCount(ws.layout!)).toBe(2)
    // b's session preserved
    expect(findLeaf(ws.layout!, 'b')!.sessionId).toBe('B')
  })
  it('stashing the last placed pane empties the grid (layout=null)', () => {
    let ws: WorkspacePanes = { layout: singlePane('S', 'only'), stashed: [] }
    ws = stashPane(ws, 'only')
    expect(ws.layout).toBeNull()
    expect(ws.stashed.map((s) => s.paneId)).toEqual(['only'])
  })
  it('revive into an empty grid makes a single OneFull pane', () => {
    let ws: WorkspacePanes = { layout: null, stashed: [{ paneId: 'x', sessionId: 'X' }] }
    ws = revivePane(ws, 'x')
    expect(ws.layout).not.toBeNull()
    expect(paneCount(ws.layout!)).toBe(1)
    expect(ws.layout!.activePaneId).toBe('x')
    expect(ws.stashed).toHaveLength(0)
  })
  it('addStashed is a no-op for already placed or stashed panes', () => {
    let ws: WorkspacePanes = { layout: placed('OneFull', ['p']), stashed: [{ paneId: 'q', sessionId: null }] }
    expect(addStashed(ws, 'p', 'X')).toBe(ws) // already placed
    expect(addStashed(ws, 'q', 'X')).toBe(ws) // already stashed
    ws = addStashed(ws, 'r', 'R', 'name')
    expect(ws.stashed.map((s) => s.paneId)).toEqual(['q', 'r'])
  })
  it('placed and stashed never overlap', () => {
    let ws: WorkspacePanes = { layout: setPaneSession(placed('TwoColumns', ['a', 'b']), 'a', 'A'), stashed: [] }
    ws = stashPane(ws, 'a')
    const placedIds = new Set(leaves(ws.layout!.root).map((l) => l.id))
    const stashedIds = new Set(ws.stashed.map((s) => s.paneId))
    for (const id of placedIds) expect(stashedIds.has(id)).toBe(false)
  })
  it('removePaneEverywhere drops placed (reduce) and stashed', () => {
    let ws: WorkspacePanes = { layout: placed('TwoColumns', ['a', 'b']), stashed: [{ paneId: 'c', sessionId: null }] }
    ws = removePaneEverywhere(ws, 'a') // placed → reduce to OneFull
    expect(layoutName(ws.layout!)).toBe('OneFull')
    expect(findLeaf(ws.layout!, 'a')).toBeNull()
    ws = removePaneEverywhere(ws, 'c') // stashed → drop
    expect(ws.stashed).toHaveLength(0)
  })
})

describe('reconcileExistence (existence-sync core, Task #600)', () => {
  it('first call stashes all existing panes (nothing placed)', () => {
    const ws = reconcileExistence(emptyWorkspace(), [
      { paneId: 'a', sessionId: 'A' },
      { paneId: 'b', sessionId: 'B', name: 'bee' },
    ])
    expect(ws.layout).toBeNull()
    expect(ws.stashed.map((s) => s.paneId)).toEqual(['a', 'b'])
    expect(ws.stashed[1].name).toBe('bee')
  })
  it('later call adds new-as-stashed and drops killed panes', () => {
    // start: a placed, b stashed
    let ws: WorkspacePanes = { layout: setPaneSession(placed('OneFull', ['a']), 'a', 'A'), stashed: [{ paneId: 'b', sessionId: 'B' }] }
    // local now: a still exists, b killed, c new
    ws = reconcileExistence(ws, [
      { paneId: 'a', sessionId: 'A' },
      { paneId: 'c', sessionId: 'C' },
    ])
    expect(isPlaced(ws, 'a')).toBe(true) // untouched
    expect(isStashed(ws, 'b')).toBe(false) // dropped
    expect(isStashed(ws, 'c')).toBe(true) // new → stashed
  })
  it('dropping a placed pane reduces the grid', () => {
    let ws: WorkspacePanes = { layout: setPaneSession(setPaneSession(placed('TwoColumns', ['a', 'b']), 'a', 'A'), 'b', 'B'), stashed: [] }
    ws = reconcileExistence(ws, [{ paneId: 'a', sessionId: 'A' }]) // b killed
    expect(paneCount(ws.layout!)).toBe(1)
    expect(findLeaf(ws.layout!, 'a')).not.toBeNull()
  })
})
