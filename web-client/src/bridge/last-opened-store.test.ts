import { describe, it, expect, beforeEach } from 'vitest'
import { loadLastOpenedSession, saveLastOpenedSession } from './last-opened-store'

if (typeof (globalThis as any).localStorage === 'undefined') {
  const m = new Map<string, string>()
  ;(globalThis as any).localStorage = {
    get length() { return m.size }, clear: () => m.clear(),
    getItem: (k: string) => (m.has(k) ? m.get(k)! : null), key: (i: number) => Array.from(m.keys())[i] ?? null,
    removeItem: (k: string) => m.delete(k), setItem: (k: string, v: string) => m.set(k, v),
  }
}

beforeEach(() => localStorage.clear())

describe('last-opened-store', () => {
  it('round-trips the last opened session for the same account + desktop', () => {
    saveLastOpenedSession('acct_x', 'dev_1', 's-a')
    expect(loadLastOpenedSession('acct_x', 'dev_1')).toBe('s-a')
  })

  it('scopes by account and desktop', () => {
    saveLastOpenedSession('acct_x', 'dev_1', 's-a')
    expect(loadLastOpenedSession('acct_x', 'dev_2')).toBeNull()
    expect(loadLastOpenedSession('acct_y', 'dev_1')).toBeNull()
  })

  it('removes the hint when saved empty/null', () => {
    saveLastOpenedSession('acct_x', 'dev_1', 's-a')
    saveLastOpenedSession('acct_x', 'dev_1', null)
    expect(loadLastOpenedSession('acct_x', 'dev_1')).toBeNull()
  })

  it('encodes account/desktop ids to avoid key collisions', () => {
    saveLastOpenedSession('a:b', 'd', 's-x')
    saveLastOpenedSession('a', 'b:d', 's-y')
    expect(loadLastOpenedSession('a:b', 'd')).toBe('s-x')
    expect(loadLastOpenedSession('a', 'b:d')).toBe('s-y')
  })

  it('degrades gracefully when storage throws', () => {
    const orig = globalThis.localStorage
    ;(globalThis as any).localStorage = {
      getItem: () => { throw new Error('blocked') },
      setItem: () => { throw new Error('blocked') },
      removeItem: () => { throw new Error('blocked') },
    }
    expect(() => saveLastOpenedSession('acct_x', 'dev_1', 's-a')).not.toThrow()
    expect(loadLastOpenedSession('acct_x', 'dev_1')).toBeNull()
    ;(globalThis as any).localStorage = orig
  })
})
