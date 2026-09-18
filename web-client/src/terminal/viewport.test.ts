import { describe, it, expect } from 'vitest'
import { availableViewport, gridForViewport, ResizeCoalescer, shouldResize, defaultSessionGrid, DEFAULT_SESSION_GRID, MIN_COLS, MIN_ROWS } from './viewport'

const cell = { cellWidthPx: 9, cellHeightPx: 18 }

describe('gridForViewport — mobile/desktop sizing', () => {
  it('floors to fit the available box', () => {
    expect(gridForViewport(900, 360, cell)).toEqual({ cols: 100, rows: 20 })
    // non-integer fit floors (don't overflow)
    expect(gridForViewport(905, 365, cell)).toEqual({ cols: 100, rows: 20 })
  })
  it('clamps to minimums for a tiny viewport', () => {
    expect(gridForViewport(5, 5, cell)).toEqual({ cols: MIN_COLS, rows: MIN_ROWS })
  })
  it('handles a zero/garbage cell size without dividing by zero', () => {
    const g = gridForViewport(100, 100, { cellWidthPx: 0, cellHeightPx: 0 })
    expect(g.cols).toBeGreaterThanOrEqual(MIN_COLS)
    expect(g.rows).toBeGreaterThanOrEqual(MIN_ROWS)
  })
})

describe('shouldResize — coalescing', () => {
  it('suppresses no-op resizes (mobile keyboard storms)', () => {
    expect(shouldResize(null, { cols: 80, rows: 24 })).toBe(true)
    expect(shouldResize({ cols: 80, rows: 24 }, { cols: 80, rows: 24 })).toBe(false)
    expect(shouldResize({ cols: 80, rows: 24 }, { cols: 80, rows: 25 })).toBe(true)
  })
})

describe('ResizeCoalescer — keyed pane resize coalescing', () => {
  it('suppresses no-op resize storms per key while allowing real changes', () => {
    const c = new ResizeCoalescer()
    expect(c.shouldResize('pane-a', { cols: 80, rows: 24 })).toBe(true)
    expect(c.shouldResize('pane-a', { cols: 80, rows: 24 })).toBe(false)
    expect(c.shouldResize('pane-a', { cols: 100, rows: 24 })).toBe(true)
    expect(c.shouldResize('pane-b', { cols: 80, rows: 24 })).toBe(true)
  })

  it('can clear one key or all keys after pane/session teardown', () => {
    const c = new ResizeCoalescer()
    expect(c.shouldResize('pane-a', { cols: 80, rows: 24 })).toBe(true)
    expect(c.shouldResize('pane-b', { cols: 80, rows: 24 })).toBe(true)
    c.clear('pane-a')
    expect(c.shouldResize('pane-a', { cols: 80, rows: 24 })).toBe(true)
    expect(c.shouldResize('pane-b', { cols: 80, rows: 24 })).toBe(false)
    c.clear()
    expect(c.shouldResize('pane-b', { cols: 80, rows: 24 })).toBe(true)
  })
})

describe('availableViewport — soft keyboard', () => {
  it('prefers visualViewport (excludes the keyboard) when present', () => {
    expect(availableViewport({ innerWidth: 390, innerHeight: 844, visualViewport: { width: 390, height: 500 } }))
      .toEqual({ width: 390, height: 500 })
  })
  it('falls back to inner size when visualViewport is absent', () => {
    expect(availableViewport({ innerWidth: 390, innerHeight: 844, visualViewport: null }))
      .toEqual({ width: 390, height: 844 })
  })
})

describe('defaultSessionGrid — measured-where-possible new-session size', () => {
  const cell = { cellWidthPx: 9, cellHeightPx: 18 }

  it('measures the window when one with real dimensions is available', () => {
    const grid = defaultSessionGrid({ innerWidth: 900, innerHeight: 360, visualViewport: null }, cell)
    expect(grid).toEqual(gridForViewport(900, 360, cell)) // same math as a normal fit
  })

  it('falls back to the conventional 80x24 with no window (tests / SSR)', () => {
    expect(defaultSessionGrid(undefined)).toEqual(DEFAULT_SESSION_GRID)
    expect(DEFAULT_SESSION_GRID).toEqual({ cols: 80, rows: 24 })
  })

  it('falls back to 80x24 for a degenerate (zero-size) window', () => {
    expect(defaultSessionGrid({ innerWidth: 0, innerHeight: 0, visualViewport: null })).toEqual(DEFAULT_SESSION_GRID)
  })
})
