import { describe, it, expect, beforeEach } from 'vitest'
import { loadSessionOrder, saveSessionOrder } from './session-order-store'

// node env has no DOM storage — give the store a tiny in-memory localStorage.
if (typeof (globalThis as any).localStorage === 'undefined') {
  const m = new Map<string, string>()
  ;(globalThis as any).localStorage = {
    get length() { return m.size }, clear: () => m.clear(),
    getItem: (k: string) => (m.has(k) ? m.get(k)! : null), key: (i: number) => Array.from(m.keys())[i] ?? null,
    removeItem: (k: string) => m.delete(k), setItem: (k: string, v: string) => m.set(k, v),
  }
}

beforeEach(() => localStorage.clear())

describe('session-order-store', () => {
  it('empty when nothing stored', () => {
    expect(loadSessionOrder('acct_x', 'dev_1')).toEqual([])
  })

  it('round-trips order for the same account + desktop', () => {
    saveSessionOrder('acct_x', 'dev_1', ['s-b', 's-a'])
    expect(loadSessionOrder('acct_x', 'dev_1')).toEqual(['s-b', 's-a'])
  })

  it('scopes by account AND desktop', () => {
    saveSessionOrder('acct_x', 'dev_1', ['s1'])
    expect(loadSessionOrder('acct_x', 'dev_2')).toEqual([])
    expect(loadSessionOrder('acct_y', 'dev_1')).toEqual([])
    expect(loadSessionOrder('acct_x', 'dev_1')).toEqual(['s1'])
  })

  it('sanitizes: trims, drops blanks/non-strings, de-dups', () => {
    saveSessionOrder('acct_x', 'dev_1', ['  s1  ', '', 's1', 's2'] as unknown as string[])
    expect(loadSessionOrder('acct_x', 'dev_1')).toEqual(['s1', 's2'])
  })

  it('malformed / non-array stored JSON -> empty', () => {
    const k = 'hydra.remote.sessionOrder:acct_x:dev_1'
    localStorage.setItem(k, '{ not json')
    expect(loadSessionOrder('acct_x', 'dev_1')).toEqual([])
    localStorage.setItem(k, JSON.stringify({ not: 'an array' }))
    expect(loadSessionOrder('acct_x', 'dev_1')).toEqual([])
  })

  it('removes the storage item when order becomes empty', () => {
    saveSessionOrder('acct_x', 'dev_1', ['s1'])
    saveSessionOrder('acct_x', 'dev_1', [])
    expect(localStorage.getItem('hydra.remote.sessionOrder:acct_x:dev_1')).toBeNull()
    expect(loadSessionOrder('acct_x', 'dev_1')).toEqual([])
  })

  it('degrades gracefully when storage throws', () => {
    const orig = globalThis.localStorage
    ;(globalThis as any).localStorage = {
      getItem: () => { throw new Error('blocked') },
      setItem: () => { throw new Error('blocked') },
      removeItem: () => { throw new Error('blocked') },
    }
    expect(() => saveSessionOrder('acct_x', 'dev_1', ['s1'])).not.toThrow()
    expect(loadSessionOrder('acct_x', 'dev_1')).toEqual([])
    ;(globalThis as any).localStorage = orig
  })
})
