import { describe, it, expect, beforeEach } from 'vitest'
import { loadSessionLabels, saveSessionLabels } from './session-label-store'

// node env has no DOM storage — give the store a tiny in-memory localStorage (same shape the
// remote-client test installs). Each test starts from a clean map.
if (typeof (globalThis as any).localStorage === 'undefined') {
  const m = new Map<string, string>()
  ;(globalThis as any).localStorage = {
    get length() { return m.size }, clear: () => m.clear(),
    getItem: (k: string) => (m.has(k) ? m.get(k)! : null), key: (i: number) => Array.from(m.keys())[i] ?? null,
    removeItem: (k: string) => m.delete(k), setItem: (k: string, v: string) => m.set(k, v),
  }
}

beforeEach(() => localStorage.clear())

describe('session-label-store', () => {
  it('round-trips labels for the same account + desktop', () => {
    saveSessionLabels('acct_x', 'dev_1', { 's-aaa': 'Build', 's-bbb': 'Logs' })
    expect(loadSessionLabels('acct_x', 'dev_1')).toEqual({ 's-aaa': 'Build', 's-bbb': 'Logs' })
  })

  it('empty when nothing stored', () => {
    expect(loadSessionLabels('acct_x', 'dev_1')).toEqual({})
  })

  it('scopes by account AND desktop (no cross-leak)', () => {
    saveSessionLabels('acct_x', 'dev_1', { 's1': 'A' })
    expect(loadSessionLabels('acct_x', 'dev_2')).toEqual({}) // different desktop
    expect(loadSessionLabels('acct_y', 'dev_1')).toEqual({}) // different account
    expect(loadSessionLabels('acct_x', 'dev_1')).toEqual({ 's1': 'A' })
  })

  it('sanitizes on save: trims, drops blank/whitespace + non-string values', () => {
    // a deliberately mixed-type map (a real caller is typed, but storage must be defensive)
    const dirty = { 's1': '  Padded  ', 's2': '   ', 's3': '', 's4': 123 } as unknown as Record<string, string>
    saveSessionLabels('acct_x', 'dev_1', dirty)
    expect(loadSessionLabels('acct_x', 'dev_1')).toEqual({ 's1': 'Padded' })
  })

  it('sanitizes on load: ignores non-object / array / malformed JSON', () => {
    const k = 'hydra.remote.sessionLabels:acct_x:dev_1'
    localStorage.setItem(k, JSON.stringify(['not', 'an', 'object']))
    expect(loadSessionLabels('acct_x', 'dev_1')).toEqual({})
    localStorage.setItem(k, '{ not valid json')
    expect(loadSessionLabels('acct_x', 'dev_1')).toEqual({})
  })

  it('removes the storage item when labels become empty', () => {
    saveSessionLabels('acct_x', 'dev_1', { 's1': 'A' })
    saveSessionLabels('acct_x', 'dev_1', {}) // e.g. after the last rename-to-blank
    const k = 'hydra.remote.sessionLabels:acct_x:dev_1'
    expect(localStorage.getItem(k)).toBeNull()
    expect(loadSessionLabels('acct_x', 'dev_1')).toEqual({})
  })

  it('account/desktop ids with separators are encoded (no key collision)', () => {
    // ids containing ':' must not let one scope read another's value
    saveSessionLabels('a:b', 'd', { 's1': 'X' })
    saveSessionLabels('a', 'b:d', { 's1': 'Y' })
    expect(loadSessionLabels('a:b', 'd')).toEqual({ 's1': 'X' })
    expect(loadSessionLabels('a', 'b:d')).toEqual({ 's1': 'Y' })
  })

  it('degrades gracefully when storage throws (private mode / quota)', () => {
    const orig = globalThis.localStorage
    ;(globalThis as any).localStorage = {
      getItem: () => { throw new Error('blocked') },
      setItem: () => { throw new Error('blocked') },
      removeItem: () => { throw new Error('blocked') },
    }
    // neither should throw; load returns {}
    expect(() => saveSessionLabels('acct_x', 'dev_1', { 's1': 'A' })).not.toThrow()
    expect(loadSessionLabels('acct_x', 'dev_1')).toEqual({})
    ;(globalThis as any).localStorage = orig
  })
})
