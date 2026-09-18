import { describe, expect, it } from 'vitest'
import { diagnosticQueryFlag } from './diagnostic-flags'

describe('diagnostic query flags', () => {
  it('enables only an exact explicit diagnostic opt-in', () => {
    expect(diagnosticQueryFlag('inspect', '?inspect=1')).toBe(true)
    expect(diagnosticQueryFlag('metrics', '?metrics=1')).toBe(true)
    expect(diagnosticQueryFlag('inspect', '?inspect=0')).toBe(false)
    expect(diagnosticQueryFlag('inspect', '?inspect=true')).toBe(false)
    expect(diagnosticQueryFlag('inspect', '')).toBe(false)
  })
})
