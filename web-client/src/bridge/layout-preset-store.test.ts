import { describe, it, expect, beforeEach } from 'vitest'
import { loadLayoutPresetState, saveLayoutPresetState } from './layout-preset-store'
import { createPreset, setDefaultPreset, type LayoutPresetState } from '../model/layout-preset'
import { singlePane, splitActive } from '../model/pane-layout'

if (typeof (globalThis as any).localStorage === 'undefined') {
  const m = new Map<string, string>()
  ;(globalThis as any).localStorage = {
    get length() { return m.size }, clear: () => m.clear(),
    getItem: (k: string) => (m.has(k) ? m.get(k)! : null), key: (i: number) => Array.from(m.keys())[i] ?? null,
    removeItem: (k: string) => m.delete(k), setItem: (k: string, v: string) => m.set(k, v),
  }
}

beforeEach(() => localStorage.clear())

const EMPTY: LayoutPresetState = { presets: [] }

function sample(): LayoutPresetState {
  const base = singlePane('s-a', 'p-a')
  const layout = splitActive(base, 'vertical')
  return createPreset(EMPTY, { id: 'lp-1', name: 'Two agents', layout, nowMs: 1000 })
}

describe('layout-preset-store', () => {
  it('loads empty state when nothing is stored', () => {
    expect(loadLayoutPresetState('acct_x')).toEqual(EMPTY)
  })

  it('round-trips a layout preset state for an account', () => {
    const s = setDefaultPreset(sample(), 'lp-1')
    saveLayoutPresetState('acct_x', s)
    expect(loadLayoutPresetState('acct_x')).toEqual(s)
  })

  it('returns empty state for malformed or broken stored JSON', () => {
    const k = 'hydra.remote.layoutPresets:acct_x'
    localStorage.setItem(k, '{ not json')
    expect(loadLayoutPresetState('acct_x')).toEqual(EMPTY)
    localStorage.setItem(k, JSON.stringify({ presets: [{ id: 'lp-1', name: 'Broken', createdAtMs: 1, layout: { nope: true } }] }))
    expect(loadLayoutPresetState('acct_x')).toEqual(EMPTY)
  })

  it('is scoped by account and encodes separators in account ids', () => {
    saveLayoutPresetState('a:b', sample())
    saveLayoutPresetState('a', createPreset(EMPTY, { id: 'lp-2', name: 'Other', layout: singlePane(null, 'p'), nowMs: 2 }))
    expect(loadLayoutPresetState('a:b').presets[0].id).toBe('lp-1')
    expect(loadLayoutPresetState('a').presets[0].id).toBe('lp-2')
    expect(localStorage.getItem('hydra.remote.layoutPresets:a%3Ab')).not.toBeNull()
  })

  it('removes the storage item when the preset list becomes empty', () => {
    saveLayoutPresetState('acct_x', sample())
    saveLayoutPresetState('acct_x', EMPTY)
    expect(localStorage.getItem('hydra.remote.layoutPresets:acct_x')).toBeNull()
    expect(loadLayoutPresetState('acct_x')).toEqual(EMPTY)
  })

  it('degrades gracefully when storage throws', () => {
    const orig = globalThis.localStorage
    ;(globalThis as any).localStorage = {
      getItem: () => { throw new Error('blocked') },
      setItem: () => { throw new Error('blocked') },
      removeItem: () => { throw new Error('blocked') },
    }
    expect(() => saveLayoutPresetState('acct_x', sample())).not.toThrow()
    expect(loadLayoutPresetState('acct_x')).toEqual(EMPTY)
    ;(globalThis as any).localStorage = orig
  })
})
