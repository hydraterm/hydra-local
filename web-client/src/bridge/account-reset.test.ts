import { describe, it, expect } from 'vitest'
import { clearAllAccountState } from './account-reset'

/** Minimal in-memory Storage double (localStorage/sessionStorage-shaped). */
function fakeStorage(init: Record<string, string> = {}): Storage {
  const m = new Map<string, string>(Object.entries(init))
  return {
    get length() { return m.size },
    key: (i: number) => Array.from(m.keys())[i] ?? null,
    getItem: (k: string) => (m.has(k) ? m.get(k)! : null),
    setItem: (k: string, v: string) => { m.set(k, v) },
    removeItem: (k: string) => { m.delete(k) },
    clear: () => { m.clear() },
  } as Storage
}

describe('clearAllAccountState', () => {
  it('removes every account-scoped hydra.remote.* key but PRESERVES device preferences', () => {
    const local = fakeStorage({
      // account-scoped — must be wiped
      'hydra.remote.deviceLabels:acctA': '{}',
      'hydra.remote.sessionLabels:acctA:dev1': '{}',
      'hydra.remote.layoutPresets:acctA': '[]',
      'hydra.remote.favoriteSessions:acctA:dev1': '[]',
      'hydra.remote.reconnect': '{}',
      // device preferences — must survive
      'hydra.remote.rendererMode': 'grid',
      'hydra.remote.terminalFontSize': '14',
      // unrelated key — untouched
      'some.other.app': 'keep',
    })
    const session = fakeStorage({
      'hydra.remote.token': 'redeem_xyz', // per-device token — wiped
      'hydra.remote.reconnect': '{}',
    })

    clearAllAccountState([local, session])

    // account-scoped gone
    expect(local.getItem('hydra.remote.deviceLabels:acctA')).toBeNull()
    expect(local.getItem('hydra.remote.sessionLabels:acctA:dev1')).toBeNull()
    expect(local.getItem('hydra.remote.layoutPresets:acctA')).toBeNull()
    expect(local.getItem('hydra.remote.favoriteSessions:acctA:dev1')).toBeNull()
    expect(local.getItem('hydra.remote.reconnect')).toBeNull()
    expect(session.getItem('hydra.remote.token')).toBeNull()
    expect(session.getItem('hydra.remote.reconnect')).toBeNull()
    // preferences preserved
    expect(local.getItem('hydra.remote.rendererMode')).toBe('grid')
    expect(local.getItem('hydra.remote.terminalFontSize')).toBe('14')
    // non-hydra key untouched
    expect(local.getItem('some.other.app')).toBe('keep')
  })

  it('fail-safe: a NEW account-scoped key (not in the preserve list) is wiped automatically', () => {
    const local = fakeStorage({ 'hydra.remote.brandNewFeature:acctA': 'secret-ish' })
    clearAllAccountState([local])
    expect(local.getItem('hydra.remote.brandNewFeature:acctA')).toBeNull()
  })

  it('is a no-op when storage is undefined (SSR / disabled)', () => {
    expect(() => clearAllAccountState([undefined])).not.toThrow()
  })
})
