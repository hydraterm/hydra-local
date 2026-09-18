import { describe, it, expect } from 'vitest'
import {
  createPreset, renamePreset, deletePreset, setDefaultPreset, restorePreset,
  serializePresetState, deserializePresetState, type LayoutPresetState,
} from './layout-preset'
import { singlePane, splitActive, leaves, serializeLayout, type PaneLayout } from './pane-layout'

const EMPTY: LayoutPresetState = { presets: [] }

/** A deterministic 2-pane layout: pane p1 → session s-a, split → p2 → session s-b. */
function twoPane(): PaneLayout {
  let n = 0
  const mkId = (prefix: string) => `${prefix}${++n}`
  const a = singlePane('s-a', 'p1')
  return splitActive(a, 'vertical', { sessionId: 's-b', mkId })
}

describe('layout-preset model (§8)', () => {
  it('createPreset stores a named snapshot (name trimmed, blank → "Untitled layout")', () => {
    const s1 = createPreset(EMPTY, { id: 'L1', name: '  Build  ', layout: twoPane(), nowMs: 100 })
    expect(s1.presets).toHaveLength(1)
    expect(s1.presets[0]).toMatchObject({ id: 'L1', name: 'Build', createdAtMs: 100 })
    const s2 = createPreset(s1, { id: 'L2', name: '   ', layout: singlePane('s-a'), nowMs: 200 })
    expect(s2.presets[1].name).toBe('Untitled layout')
  })

  it('rename ignores blanks; delete removes by id', () => {
    const s = createPreset(EMPTY, { id: 'L1', name: 'A', layout: singlePane(null), nowMs: 1 })
    expect(renamePreset(s, 'L1', '   ').presets[0].name).toBe('A') // blank ignored
    expect(renamePreset(s, 'L1', 'Renamed').presets[0].name).toBe('Renamed')
    expect(deletePreset(s, 'L1').presets).toEqual([])
    expect(deletePreset(s, 'nope').presets).toHaveLength(1) // unknown id is a no-op
  })

  it('tracks one default preset and clears it when deleted', () => {
    const s1 = createPreset(EMPTY, { id: 'L1', name: 'A', layout: singlePane(null), nowMs: 1 })
    const s2 = createPreset(s1, { id: 'L2', name: 'B', layout: singlePane(null), nowMs: 2 })
    expect(setDefaultPreset(s2, 'nope')).toBe(s2)
    const withDefault = setDefaultPreset(s2, 'L2')
    expect(withDefault.defaultPresetId).toBe('L2')
    expect(setDefaultPreset(withDefault, null).defaultPresetId).toBeUndefined()
    expect(deletePreset(withDefault, 'L2').defaultPresetId).toBeUndefined()
  })

  it('restore keeps live sessions and frees panes whose session is gone (structure preserved)', () => {
    const layout0 = twoPane()
    // pane ids straight from the built layout (don't hardcode — splitActive names them)
    const paneOfA = leaves(layout0.root).find((l) => l.sessionId === 's-a')!.id
    const paneOfB = leaves(layout0.root).find((l) => l.sessionId === 's-b')!.id
    const preset = createPreset(EMPTY, { id: 'L1', name: 'two', layout: layout0, nowMs: 1 }).presets[0]
    // only s-a is still live; s-b is gone
    const { layout, freshPaneIds } = restorePreset(preset, ['s-a'])
    const byId = Object.fromEntries(leaves(layout.root).map((l) => [l.id, l.sessionId]))
    expect(byId[paneOfA]).toBe('s-a')   // live session kept
    expect(byId[paneOfB]).toBeNull()    // gone session → fresh slot
    expect(freshPaneIds).toEqual([paneOfB])
    expect(leaves(layout.root)).toHaveLength(2) // structure preserved
  })

  it('restore with no live sessions frees every pane', () => {
    const layout0 = twoPane()
    const allPaneIds = leaves(layout0.root).map((l) => l.id).sort()
    const preset = createPreset(EMPTY, { id: 'L1', name: 'two', layout: layout0, nowMs: 1 }).presets[0]
    const { layout, freshPaneIds } = restorePreset(preset, [])
    expect(leaves(layout.root).every((l) => l.sessionId === null)).toBe(true)
    expect([...freshPaneIds].sort()).toEqual(allPaneIds)
  })

  it('restore snaps activePaneId to a real leaf', () => {
    const preset = createPreset(EMPTY, { id: 'L1', name: 'one', layout: singlePane('s-a', 'pX'), nowMs: 1 }).presets[0]
    const { layout } = restorePreset(preset, ['s-a'])
    expect(leaves(layout.root).some((l) => l.id === layout.activePaneId)).toBe(true)
  })

  it('serialize → deserialize round-trips presets; malformed input → empty; broken layout dropped', () => {
    const s = setDefaultPreset(createPreset(EMPTY, { id: 'L1', name: 'two', layout: twoPane(), nowMs: 7 }), 'L1')
    const back = deserializePresetState(serializePresetState(s))
    expect(back.presets).toHaveLength(1)
    expect(back.presets[0]).toMatchObject({ id: 'L1', name: 'two', createdAtMs: 7 })
    expect(leaves(back.presets[0].layout.root)).toHaveLength(2)
    expect(back.defaultPresetId).toBe('L1')

    expect(deserializePresetState('{ not json').presets).toEqual([])
    expect(deserializePresetState(JSON.stringify({ nope: 1 })).presets).toEqual([])
    // a preset whose layout is broken is dropped, not fatal
    const dirty = JSON.stringify({ presets: [{ id: 'x', name: 'n', createdAtMs: 1, layout: { junk: true } }] })
    expect(deserializePresetState(dirty).presets).toEqual([])
    const staleDefault = JSON.stringify({
      presets: [{ id: 'x', name: 'n', createdAtMs: 1, layout: JSON.parse(serializeLayout(singlePane(null))) }],
      defaultPresetId: 'missing',
    })
    expect(deserializePresetState(staleDefault).defaultPresetId).toBeUndefined()
  })
})
