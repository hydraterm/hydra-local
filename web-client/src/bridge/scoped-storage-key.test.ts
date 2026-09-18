import { describe, it, expect } from 'vitest'
import { accountScopedKey, scopedKey } from './scoped-storage-key'

describe('scopedKey', () => {
  it('joins prefix + encoded account + encoded desktop with colons', () => {
    expect(scopedKey('hydra.remote.x', 'acct_1', 'dev_1')).toBe('hydra.remote.x:acct_1:dev_1')
  })

  it('encodes separators in ids so scopes cannot collide', () => {
    // "a:b"/"d" and "a"/"b:d" must NOT produce the same key
    expect(scopedKey('p', 'a:b', 'd')).not.toBe(scopedKey('p', 'a', 'b:d'))
    expect(scopedKey('p', 'a:b', 'd')).toBe('p:a%3Ab:d')
  })

  it('is the exact shape P1/P2 stores rely on', () => {
    expect(scopedKey('hydra.remote.sessionLabels', 'acct_x', 'dev_1'))
      .toBe('hydra.remote.sessionLabels:acct_x:dev_1')
    expect(scopedKey('hydra.remote.lastOpenedSession', 'acct_x', 'dev_1'))
      .toBe('hydra.remote.lastOpenedSession:acct_x:dev_1')
  })

  it('builds account-only scoped keys for project/layout stores', () => {
    expect(accountScopedKey('hydra.remote.layoutPresets', 'acct_x'))
      .toBe('hydra.remote.layoutPresets:acct_x')
    expect(accountScopedKey('hydra.remote.layoutPresets', 'a:b'))
      .toBe('hydra.remote.layoutPresets:a%3Ab')
  })
})
