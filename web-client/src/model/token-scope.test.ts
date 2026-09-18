import { describe, it, expect } from 'vitest'
import { validateTokenScope } from './token-scope'

// build a fake unsigned JWT (header.payload.signature) — only the payload matters to the validator
function jwt(payload: Record<string, unknown>): string {
  const b64url = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  return `${b64url({ alg: 'none' })}.${b64url(payload)}.sig`
}

const NOW = 1_700_000_000_000 // ms

describe('validateTokenScope — client-side defense-in-depth (no signature check)', () => {
  it('OK for a fresh token scoped to the expected desktop', () => {
    const t = jwt({ exp: NOW / 1000 + 300, device_id: 'dev_1' })
    expect(validateTokenScope(t, 'dev_1', NOW)).toEqual({ ok: true })
  })

  it('rejects an ALREADY-EXPIRED token (the short-lived contract)', () => {
    const t = jwt({ exp: NOW / 1000 - 1, device_id: 'dev_1' })
    expect(validateTokenScope(t, 'dev_1', NOW)).toEqual({ ok: false, reason: 'expired' })
  })

  it('rejects a token scoped to a DIFFERENT desktop (device_id / dev / aud)', () => {
    expect(validateTokenScope(jwt({ exp: NOW / 1000 + 300, device_id: 'dev_other' }), 'dev_1', NOW)).toEqual({ ok: false, reason: 'wrong-device' })
    expect(validateTokenScope(jwt({ exp: NOW / 1000 + 300, dev: 'dev_other' }), 'dev_1', NOW)).toEqual({ ok: false, reason: 'wrong-device' })
    expect(validateTokenScope(jwt({ exp: NOW / 1000 + 300, aud: 'dev_other' }), 'dev_1', NOW)).toEqual({ ok: false, reason: 'wrong-device' })
  })

  it('FAILS OPEN for tokens it cannot confidently judge (opaque / non-JWT / no claims)', () => {
    expect(validateTokenScope('opaque-not-a-jwt', 'dev_1', NOW)).toEqual({ ok: true }) // not 3-part
    expect(validateTokenScope(jwt({}), 'dev_1', NOW)).toEqual({ ok: true }) // no exp, no scope
    expect(validateTokenScope(jwt({ exp: NOW / 1000 + 300 }), 'dev_1', NOW)).toEqual({ ok: true }) // fresh, unscoped
    expect(validateTokenScope('a.b.c', 'dev_1', NOW)).toEqual({ ok: true }) // 3 parts but payload not JSON
  })

  it('does not reject a future-but-present exp at exactly now+epsilon, but does at exp<=now', () => {
    expect(validateTokenScope(jwt({ exp: NOW / 1000 + 1 }), 'dev_1', NOW).ok).toBe(true)
    expect(validateTokenScope(jwt({ exp: NOW / 1000 }), 'dev_1', NOW).ok).toBe(false) // exp == now → expired
  })
})
