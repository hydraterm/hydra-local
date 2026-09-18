import { describe, it, expect } from 'vitest'
import { highlightSpans } from './search-highlight'
import type { TerminalSearchMatch } from './search'

const m = (row: number, startCol: number, endCol: number): TerminalSearchMatch =>
  ({ row, startCol, endCol, text: 'x' })

const GRID = { rows: 10, cols: 20 }

describe('highlightSpans — paint-ready search highlights', () => {
  it('maps each match to a cell-coordinate span', () => {
    const spans = highlightSpans([m(2, 3, 5), m(4, 0, 2)], null, GRID)
    expect(spans).toEqual([
      { row: 2, startCol: 3, endCol: 5, active: false },
      { row: 4, startCol: 0, endCol: 2, active: false },
    ])
  })

  it('flags exactly the active match', () => {
    const matches = [m(1, 0, 2), m(3, 4, 6)]
    const spans = highlightSpans(matches, matches[1], GRID)
    expect(spans.map((s) => s.active)).toEqual([false, true])
  })

  it('clips spans to the grid and drops off-grid / zero-width matches', () => {
    const spans = highlightSpans(
      [
        m(2, 18, 25), // endCol clipped to cols=20
        m(99, 0, 2),  // row off-grid → dropped
        m(5, 7, 7),   // zero-width → dropped
        m(6, -3, 1),  // startCol clipped to 0
      ],
      null,
      GRID,
    )
    expect(spans).toEqual([
      { row: 2, startCol: 18, endCol: 20, active: false },
      { row: 6, startCol: 0, endCol: 1, active: false },
    ])
  })

  it('no matches → no spans', () => {
    expect(highlightSpans([], null, GRID)).toEqual([])
  })

  it('active match that is off-grid does not crash and flags nothing', () => {
    const spans = highlightSpans([m(0, 0, 2)], m(99, 0, 2), GRID)
    expect(spans).toEqual([{ row: 0, startCol: 0, endCol: 2, active: false }])
  })
})
