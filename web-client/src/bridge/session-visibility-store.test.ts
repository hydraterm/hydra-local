import { describe, it, expect, beforeEach } from 'vitest'
import { loadHiddenSessions, saveHiddenSessions } from './session-visibility-store'

if (typeof (globalThis as any).localStorage === 'undefined') {
  const m = new Map<string, string>()
  ;(globalThis as any).localStorage = {
    get length() { return m.size }, clear: () => m.clear(),
    getItem: (k: string) => (m.has(k) ? m.get(k)! : null), key: (i: number) => Array.from(m.keys())[i] ?? null,
    removeItem: (k: string) => m.delete(k), setItem: (k: string, v: string) => m.set(k, v),
  }
}

beforeEach(() => localStorage.clear())

describe('session-visibility-store', () => {
  it('empty when nothing stored', () => {
    expect(loadHiddenSessions('acct_x', 'dev_1')).toEqual([])
  })

  it('round-trips hidden sessions for the same account + desktop', () => {
    saveHiddenSessions('acct_x', 'dev_1', ['s-a', 's-b'])
    expect(loadHiddenSessions('acct_x', 'dev_1')).toEqual(['s-a', 's-b'])
  })

  it('scopes by account AND desktop', () => {
    saveHiddenSessions('acct_x', 'dev_1', ['s1'])
    expect(loadHiddenSessions('acct_x', 'dev_2')).toEqual([])
    expect(loadHiddenSessions('acct_y', 'dev_1')).toEqual([])
    expect(loadHiddenSessions('acct_x', 'dev_1')).toEqual(['s1'])
  })

  it('sanitizes stored ids', () => {
    saveHiddenSessions('acct_x', 'dev_1', ['  s1  ', '', 's1', 's2'] as unknown as string[])
    expect(loadHiddenSessions('acct_x', 'dev_1')).toEqual(['s1', 's2'])
  })

  it('malformed / non-array stored JSON -> empty', () => {
    const k = 'hydra.remote.hiddenSessions:acct_x:dev_1'
    localStorage.setItem(k, '{ not json')
    expect(loadHiddenSessions('acct_x', 'dev_1')).toEqual([])
    localStorage.setItem(k, JSON.stringify({ not: 'an array' }))
    expect(loadHiddenSessions('acct_x', 'dev_1')).toEqual([])
  })

  it('removes the storage item when hidden sessions become empty', () => {
    saveHiddenSessions('acct_x', 'dev_1', ['s1'])
    saveHiddenSessions('acct_x', 'dev_1', [])
    expect(localStorage.getItem('hydra.remote.hiddenSessions:acct_x:dev_1')).toBeNull()
  })

  it('degrades gracefully when storage throws', () => {
    const orig = globalThis.localStorage
    ;(globalThis as any).localStorage = {
      getItem: () => { throw new Error('blocked') },
      setItem: () => { throw new Error('blocked') },
      removeItem: () => { throw new Error('blocked') },
    }
    expect(() => saveHiddenSessions('acct_x', 'dev_1', ['s1'])).not.toThrow()
    expect(loadHiddenSessions('acct_x', 'dev_1')).toEqual([])
    ;(globalThis as any).localStorage = orig
  })
})
