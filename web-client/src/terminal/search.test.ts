import { describe, expect, it } from 'vitest'
import { findInGrid, visibleGridLines, TerminalSearch } from './search'
import type { Cell, GridSnapshot } from '../protocol/web-protocol'

function cell(text: string, over: Partial<Cell> = {}): Cell {
  return {
    text,
    fg: { kind: 'named', name: 'foreground' },
    bg: { kind: 'named', name: 'background' },
    bold: false,
    italic: false,
    underline: 'none',
    inverse: false,
    strikeout: false,
    dim: false,
    hidden: false,
    width: 1,
    ...over,
  }
}

function grid(rows: Cell[][]): GridSnapshot {
  return {
    version: 2,
    generation: 'g',
    revision: 1,
    base_revision: 1,
    cols: rows[0]?.length ?? 0,
    rows: rows.length,
    rows_cells: rows,
    cursor_line: 0,
    cursor_col: 0,
    cursor_visible: true,
    cursor_shape: 'block',
    alt_screen: false,
    app_cursor: false,
    bracketed_paste: false,
    focus_reporting: false,
    mouse_report: false,
    mouse_drag: false,
    mouse_motion: false,
    mouse_sgr: false,
  }
}

describe('terminal search model', () => {
  it('extracts visible row text and skips wide-cell spacer cells', () => {
    const g = grid([
      [cell('h'), cell('i'), cell('界', { width: 2 }), cell('', { width: 0 }), cell('!')],
      [cell('o'), cell('k')],
    ])
    expect(visibleGridLines(g)).toEqual(['hi界!', 'ok'])
  })

  it('finds case-insensitive matches with grid row/column coordinates', () => {
    const g = grid([[cell('H'), cell('e'), cell('l'), cell('l'), cell('o')]])
    expect(findInGrid(g, 'ell')).toEqual([{ row: 0, startCol: 1, endCol: 4, text: 'ell' }])
    expect(findInGrid(g, 'HEL')).toEqual([{ row: 0, startCol: 0, endCol: 3, text: 'Hel' }])
  })

  it('supports case-sensitive search', () => {
    const g = grid([[cell('H'), cell('e'), cell('l'), cell('l'), cell('o')]])
    expect(findInGrid(g, 'hel', { caseSensitive: true })).toEqual([])
    expect(findInGrid(g, 'Hel', { caseSensitive: true })).toHaveLength(1)
  })

  it('does not index hidden cell text', () => {
    const g = grid([[cell('t'), cell('o'), cell('k', { hidden: true }), cell('e'), cell('n')]])
    expect(visibleGridLines(g)).toEqual(['to en'])
    expect(findInGrid(g, 'token')).toEqual([])
    expect(findInGrid(g, 'to en')).toEqual([{ row: 0, startCol: 0, endCol: 5, text: 'to en' }])
  })

  it('bounds results with maxMatches', () => {
    const g = grid([
      [cell('a'), cell('a'), cell('a')],
      [cell('a'), cell('a'), cell('a')],
    ])
    expect(findInGrid(g, 'a', { maxMatches: 4 }).map((m) => [m.row, m.startCol])).toEqual([
      [0, 0],
      [0, 1],
      [0, 2],
      [1, 0],
    ])
    expect(findInGrid(g, 'a', { maxMatches: 0 })).toEqual([])
  })

  it('ignores empty and whitespace-only queries', () => {
    const g = grid([[cell('a')]])
    expect(findInGrid(g, '')).toEqual([])
    expect(findInGrid(g, '   ')).toEqual([])
  })
})

/** A single-row grid from a plain string (one cell per char). */
function row(text: string): GridSnapshot {
  return grid([[...text].map((c) => cell(c))])
}

describe('TerminalSearch — navigation over findInGrid', () => {
  it('tracks matches, active index, and a "n/total" status', () => {
    const s = new TerminalSearch()
    s.setGrid(row('ab xx ab yy ab')) // three "ab" matches
    s.setQuery('ab')
    expect(s.matches().length).toBe(3)
    expect(s.status().label).toBe('1/3')
    expect(s.active()?.startCol).toBe(0)
  })

  it('next()/prev() wrap around', () => {
    const s = new TerminalSearch()
    s.setGrid(row('ab ab ab'))
    s.setQuery('ab')
    expect(s.status().active).toBe(1)
    s.next(); expect(s.status().active).toBe(2)
    s.next(); expect(s.status().active).toBe(3)
    s.next(); expect(s.status().active).toBe(1) // wraps to first
    s.prev(); expect(s.status().active).toBe(3) // wraps to last
  })

  it('empty query → empty status; no matches → "No matches"', () => {
    const s = new TerminalSearch()
    s.setGrid(row('hello world'))
    expect(s.status().label).toBe('') // no query yet
    s.setQuery('zzz')
    expect(s.status().label).toBe('No matches')
    expect(s.active()).toBeNull()
    expect(s.next()).toBeNull() // no-op, no throw
  })

  it('changing the query re-runs the search and resets to the first match', () => {
    const s = new TerminalSearch()
    s.setGrid(row('cat hat cat'))
    s.setQuery('cat')
    s.next() // active = 2/2
    expect(s.status().active).toBe(2)
    s.setQuery('hat') // reset
    expect(s.status().label).toBe('1/1')
  })

  it('a fresh grid snapshot re-runs the current query', () => {
    const s = new TerminalSearch()
    s.setQuery('ok')
    s.setGrid(row('ok')) // grid arrives after the query
    expect(s.matches().length).toBe(1)
    s.setGrid(row('no match here'))
    expect(s.status().label).toBe('No matches')
  })

  it('honors case sensitivity from options', () => {
    const sensitive = new TerminalSearch({ caseSensitive: true })
    sensitive.setGrid(row('AB ab'))
    sensitive.setQuery('ab')
    expect(sensitive.matches().length).toBe(1) // only the lowercase one
  })
})
