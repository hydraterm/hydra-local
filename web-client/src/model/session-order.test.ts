import { describe, it, expect } from 'vitest'
import { applySessionOrder, moveSession, cleanSessionOrder } from './session-order'

describe('applySessionOrder', () => {
  it('orders sessions by the saved order', () => {
    expect(applySessionOrder(['a', 'b', 'c'], ['c', 'a', 'b'])).toEqual(['c', 'a', 'b'])
  })

  it('drops saved ids that no longer exist', () => {
    expect(applySessionOrder(['a', 'b'], ['gone', 'b', 'a'])).toEqual(['b', 'a'])
  })

  it('appends NEW sessions (not in the saved order) at the end, in daemon order', () => {
    expect(applySessionOrder(['a', 'b', 'c', 'd'], ['c', 'a'])).toEqual(['c', 'a', 'b', 'd'])
  })

  it('empty saved order → daemon order unchanged', () => {
    expect(applySessionOrder(['a', 'b', 'c'], [])).toEqual(['a', 'b', 'c'])
  })

  it('de-dups a repeated id in the saved order', () => {
    expect(applySessionOrder(['a', 'b'], ['a', 'a', 'b'])).toEqual(['a', 'b'])
  })
})

describe('moveSession', () => {
  it('moves a session up and down within the effective order', () => {
    expect(moveSession(['a', 'b', 'c'], [], 'b', -1)).toEqual(['b', 'a', 'c'])
    expect(moveSession(['a', 'b', 'c'], [], 'b', 1)).toEqual(['a', 'c', 'b'])
  })

  it('is a no-op at the edges', () => {
    expect(moveSession(['a', 'b', 'c'], [], 'a', -1)).toEqual(['a', 'b', 'c']) // first up
    expect(moveSession(['a', 'b', 'c'], [], 'c', 1)).toEqual(['a', 'b', 'c'])  // last down
  })

  it('operates on the EFFECTIVE order (respects a prior saved order)', () => {
    // effective order is [c, a, b]; moving a up swaps with c
    expect(moveSession(['a', 'b', 'c'], ['c', 'a', 'b'], 'a', -1)).toEqual(['a', 'c', 'b'])
  })

  it('unknown session id → effective order unchanged', () => {
    expect(moveSession(['a', 'b'], [], 'ghost', 1)).toEqual(['a', 'b'])
  })
})

describe('cleanSessionOrder', () => {
  it('trims, drops blanks/non-strings, de-dups; non-array → []', () => {
    expect(cleanSessionOrder(['  a ', '', 'a', 'b', 5])).toEqual(['a', 'b'])
    expect(cleanSessionOrder('nope')).toEqual([])
    expect(cleanSessionOrder(null)).toEqual([])
  })
})
