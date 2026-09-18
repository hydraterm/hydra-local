import { describe, it, expect, beforeEach } from 'vitest'
import { loadDeviceLabels, saveDeviceLabels } from './device-label-store'

if (typeof (globalThis as any).localStorage === 'undefined') {
  const m = new Map<string, string>()
  ;(globalThis as any).localStorage = {
    get length() { return m.size }, clear: () => m.clear(),
    getItem: (k: string) => (m.has(k) ? m.get(k)! : null), key: (i: number) => Array.from(m.keys())[i] ?? null,
    removeItem: (k: string) => m.delete(k), setItem: (k: string, v: string) => m.set(k, v),
  }
}

beforeEach(() => localStorage.clear())

describe('device-label-store', () => {
  it('round-trips labels for an account', () => {
    saveDeviceLabels('acct_x', { dev_1: 'Mac mini' })
    expect(loadDeviceLabels('acct_x')).toEqual({ dev_1: 'Mac mini' })
  })

  it('scopes by account', () => {
    saveDeviceLabels('acct_x', { dev_1: 'Mac mini' })
    expect(loadDeviceLabels('acct_y')).toEqual({})
  })

  it('cleans labels and removes empty state', () => {
    saveDeviceLabels('acct_x', { ' dev_1 ': '  Build    Mac  ', dev_2: '   ' })
    expect(loadDeviceLabels('acct_x')).toEqual({ dev_1: 'Build Mac' })
    saveDeviceLabels('acct_x', {})
    expect(loadDeviceLabels('acct_x')).toEqual({})
    expect(localStorage.getItem('hydra.remote.deviceLabels:acct_x')).toBeNull()
  })

  it('returns empty for malformed JSON', () => {
    localStorage.setItem('hydra.remote.deviceLabels:acct_x', '{ nope')
    expect(loadDeviceLabels('acct_x')).toEqual({})
  })

  it('encodes account ids to avoid key collisions', () => {
    saveDeviceLabels('a:b', { dev: 'A' })
    saveDeviceLabels('a', { dev: 'B' })
    expect(loadDeviceLabels('a:b').dev).toBe('A')
    expect(loadDeviceLabels('a').dev).toBe('B')
  })

  it('degrades gracefully when storage throws', () => {
    const orig = globalThis.localStorage
    ;(globalThis as any).localStorage = {
      getItem: () => { throw new Error('blocked') },
      setItem: () => { throw new Error('blocked') },
      removeItem: () => { throw new Error('blocked') },
    }
    expect(() => saveDeviceLabels('acct_x', { dev_1: 'Mac' })).not.toThrow()
    expect(loadDeviceLabels('acct_x')).toEqual({})
    ;(globalThis as any).localStorage = orig
  })
})
