import { describe, it, expect } from 'vitest'
import { safeMessage } from './safe-message'

describe('safeMessage — content-blind boundary redactor', () => {
  it('redacts named secret fields (token/cookie/secret/key/password/reason/signature)', () => {
    const out = safeMessage('connect failed token=eyJ.abc cookie=hydra_session=z reason=invalid')
    expect(out).not.toContain('eyJ.abc')
    expect(out).not.toContain('hydra_session=z')
    expect(out).toContain('token=[redacted]')
    expect(out).toContain('cookie=[redacted]')
    expect(out).toContain('reason=[redacted]')
  })

  it('redacts Bearer values and PEM blocks', () => {
    expect(safeMessage('auth Bearer abcdef123456')).toContain('Bearer [redacted]')
    expect(safeMessage('key -----BEGIN PRIVATE KEY-----')).toContain('[redacted]')
  })

  it('redacts JWT-ish and oversized opaque tokens', () => {
    const jwt = 'aaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbb'
    expect(safeMessage(`got ${jwt}`)).not.toContain(jwt)
    const big = 'x'.repeat(200)
    expect(safeMessage(`blob ${big}`)).not.toContain(big)
  })

  it('keeps short, safe text intact', () => {
    expect(safeMessage('reconnect failed — tap Reconnect to retry')).toBe('reconnect failed — tap Reconnect to retry')
  })

  it('caps the overall length (no unbounded strings)', () => {
    expect(safeMessage('w '.repeat(300)).length).toBeLessThanOrEqual(180)
  })
})
