import { describe, it, expect, beforeEach } from 'vitest'
import { loadFavoriteSessions, saveFavoriteSessions, toggleFavorite } from './session-favorites-store'

// node env has no DOM storage — give the store a tiny in-memory localStorage (same shape the other store
// tests install). Each test starts clean.
if (typeof (globalThis as any).localStorage === 'undefined') {
  const m = new Map<string, string>()
  ;(globalThis as any).localStorage = {
    get length() { return m.size }, clear: () => m.clear(),
    getItem: (k: string) => (m.has(k) ? m.get(k)! : null), key: (i: number) => Array.from(m.keys())[i] ?? null,
    removeItem: (k: string) => m.delete(k), setItem: (k: string, v: string) => m.set(k, v),
  }
}

beforeEach(() => localStorage.clear())

describe('session-favorites-store', () => {
  it('empty when nothing stored', () => {
    expect(loadFavoriteSessions('acct_x', 'dev_1')).toEqual([])
  })

  it('round-trips favorites for the same account + desktop', () => {
    saveFavoriteSessions('acct_x', 'dev_1', ['s-a', 's-b'])
    expect(loadFavoriteSessions('acct_x', 'dev_1')).toEqual(['s-a', 's-b'])
  })

  it('scopes by account AND desktop (no cross-leak)', () => {
    saveFavoriteSessions('acct_x', 'dev_1', ['s1'])
    expect(loadFavoriteSessions('acct_x', 'dev_2')).toEqual([]) // different desktop
    expect(loadFavoriteSessions('acct_y', 'dev_1')).toEqual([]) // different account
    expect(loadFavoriteSessions('acct_x', 'dev_1')).toEqual(['s1'])
  })

  it('sanitizes: trims, drops blanks/non-strings, de-dups', () => {
    saveFavoriteSessions('acct_x', 'dev_1', ['  s1  ', '', 's1', 's2'] as unknown as string[])
    expect(loadFavoriteSessions('acct_x', 'dev_1')).toEqual(['s1', 's2'])
  })

  it('malformed / non-array stored JSON → empty', () => {
    const k = 'hydra.remote.favoriteSessions:acct_x:dev_1'
    localStorage.setItem(k, '{ not json')
    expect(loadFavoriteSessions('acct_x', 'dev_1')).toEqual([])
    localStorage.setItem(k, JSON.stringify({ not: 'an array' }))
    expect(loadFavoriteSessions('acct_x', 'dev_1')).toEqual([])
  })

  it('removes the storage item when favorites become empty', () => {
    saveFavoriteSessions('acct_x', 'dev_1', ['s1'])
    saveFavoriteSessions('acct_x', 'dev_1', [])
    expect(localStorage.getItem('hydra.remote.favoriteSessions:acct_x:dev_1')).toBeNull()
    expect(loadFavoriteSessions('acct_x', 'dev_1')).toEqual([])
  })

  it('toggleFavorite adds when absent, removes when present (pure)', () => {
    expect(toggleFavorite([], 's1')).toEqual(['s1'])
    expect(toggleFavorite(['s1', 's2'], 's1')).toEqual(['s2'])
    expect(toggleFavorite(['s1'], 's2')).toEqual(['s1', 's2'])
    expect(toggleFavorite(['s1'], '  ')).toEqual(['s1']) // blank id → no-op
  })

  it('degrades gracefully when storage throws', () => {
    const orig = globalThis.localStorage
    ;(globalThis as any).localStorage = {
      getItem: () => { throw new Error('blocked') },
      setItem: () => { throw new Error('blocked') },
      removeItem: () => { throw new Error('blocked') },
    }
    expect(() => saveFavoriteSessions('acct_x', 'dev_1', ['s1'])).not.toThrow()
    expect(loadFavoriteSessions('acct_x', 'dev_1')).toEqual([])
    ;(globalThis as any).localStorage = orig
  })
})
