import { describe, it, expect, beforeEach } from 'vitest'
import { loadKnownSessions, saveKnownSessions } from './session-cache-store'

if (typeof (globalThis as any).localStorage === 'undefined') {
  const m = new Map<string, string>()
  ;(globalThis as any).localStorage = {
    get length() { return m.size }, clear: () => m.clear(),
    getItem: (k: string) => (m.has(k) ? m.get(k)! : null), key: (i: number) => Array.from(m.keys())[i] ?? null,
    removeItem: (k: string) => m.delete(k), setItem: (k: string, v: string) => m.set(k, v),
  }
}

beforeEach(() => localStorage.clear())

describe('session-cache-store', () => {
  it('round-trips known sessions for the same account + desktop', () => {
    saveKnownSessions('acct_x', 'dev_1', ['s-a', 's-b'])
    saveKnownSessions('acct_x', 'dev_2', ['s-other'])
    saveKnownSessions('acct_y', 'dev_1', ['s-y'])

    expect(loadKnownSessions('acct_x', 'dev_1')).toEqual(['s-a', 's-b'])
    expect(loadKnownSessions('acct_x', 'dev_2')).toEqual(['s-other'])
    expect(loadKnownSessions('acct_y', 'dev_1')).toEqual(['s-y'])
  })

  it('dedupes/cleans malformed ids and removes the item when empty', () => {
    saveKnownSessions('acct_x', 'dev_1', ['s-a', '', '  ', 's-a', 's-b'])
    expect(loadKnownSessions('acct_x', 'dev_1')).toEqual(['s-a', 's-b'])

    saveKnownSessions('acct_x', 'dev_1', [])
    expect(loadKnownSessions('acct_x', 'dev_1')).toEqual([])
    expect(localStorage.getItem('hydra.remote.knownSessions:acct_x:dev_1')).toBeNull()
  })

  it('treats invalid stored data as empty', () => {
    localStorage.setItem('hydra.remote.knownSessions:acct_x:dev_1', '{ nope')
    expect(loadKnownSessions('acct_x', 'dev_1')).toEqual([])

    localStorage.setItem('hydra.remote.knownSessions:acct_x:dev_1', JSON.stringify({ not: 'an array' }))
    expect(loadKnownSessions('acct_x', 'dev_1')).toEqual([])
  })
})
