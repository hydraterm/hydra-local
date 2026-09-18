import { describe, it, expect } from 'vitest'
import { cleanHiddenSessions, hideSession, unhideSession, visibleSessions } from './session-visibility'

describe('session-visibility model', () => {
  it('cleanHiddenSessions trims, drops invalid values, and de-dups', () => {
    expect(cleanHiddenSessions([' s-a ', '', 's-a', 3, 's-b'])).toEqual(['s-a', 's-b'])
    expect(cleanHiddenSessions({ nope: true })).toEqual([])
  })

  it('visibleSessions filters hidden ids without changing daemon order', () => {
    expect(visibleSessions(['s-a', 's-b', 's-c'], ['s-b'])).toEqual(['s-a', 's-c'])
  })

  it('hideSession adds a known session id once', () => {
    expect(hideSession(['s-a', 's-b'], [], 's-b')).toEqual(['s-b'])
    expect(hideSession(['s-a', 's-b'], ['s-b'], 's-b')).toEqual(['s-b'])
  })

  it('hideSession ignores blanks and unknown session ids', () => {
    expect(hideSession(['s-a'], ['s-a'], '  ')).toEqual(['s-a'])
    expect(hideSession(['s-a'], ['s-a'], 'ghost')).toEqual(['s-a'])
  })

  it('unhideSession removes a hidden id', () => {
    expect(unhideSession(['s-a', 's-b'], 's-a')).toEqual(['s-b'])
    expect(unhideSession(['s-a'], '  ')).toEqual(['s-a'])
  })
})
