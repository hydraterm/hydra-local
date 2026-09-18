import { describe, it, expect } from 'vitest'
import {
  caretPointFromPixel,
  cellPointFromPixel,
  isEmptySelection,
  selectionHighlightSpans,
  selectionRangeFromPixels,
  selectionText,
  visibleGridText,
} from './selection'
import type { Cell, GridSnapshot } from '../protocol/web-protocol'

function cell(text: string, over: Partial<Cell> = {}): Cell {
  return {
    text, fg: { kind: 'named', name: 'foreground' }, bg: { kind: 'named', name: 'background' },
    bold: false, italic: false, underline: 'none', inverse: false, strikeout: false, dim: false,
    hidden: false, width: 1, ...over,
  }
}
/** Build a grid from lines of text (rows padded to equal width with spaces). */
function grid(textLines: string[]): GridSnapshot {
  const width = Math.max(0, ...textLines.map((l) => l.length))
  const rows = textLines.map((l) => [...l.padEnd(width)].map((c) => cell(c)))
  return {
    version: 2, generation: 'g', revision: 1, base_revision: 1, cols: width, rows: rows.length,
    rows_cells: rows, cursor_line: 0, cursor_col: 0, cursor_visible: true, cursor_shape: 'block',
    alt_screen: false, app_cursor: false, bracketed_paste: false, focus_reporting: false,
    mouse_report: false, mouse_drag: false, mouse_motion: false, mouse_sgr: false,
  }
}
const pt = (row: number, col: number) => ({ row, col })

function wrappedGrid(textLines: string[], wraps: boolean[]): GridSnapshot {
  return {
    ...grid(textLines),
    row_copy: wraps.map((soft_wrap, index) => ({
      starts_line: index === 0 ? undefined : !wraps[index - 1],
      soft_wrap,
      excluded_columns: [],
    })),
  }
}

describe('selectionText', () => {
  it('extracts a single-row range (end col exclusive)', () => {
    const g = grid(['hello world'])
    expect(selectionText(g, { anchor: pt(0, 0), focus: pt(0, 5) })).toBe('hello')
    expect(selectionText(g, { anchor: pt(0, 6), focus: pt(0, 11) })).toBe('world')
  })

  it('extracts a multi-row range: first row from start, full middles, last row to end', () => {
    const g = grid(['abc', 'def', 'ghi'])
    // from (0,1) to (2,2): "bc" + "def" + "gh"
    expect(selectionText(g, { anchor: pt(0, 1), focus: pt(2, 2) })).toBe('bc\ndef\ngh')
  })

  it('normalizes a backwards selection (focus before anchor)', () => {
    const g = grid(['hello world'])
    expect(selectionText(g, { anchor: pt(0, 11), focus: pt(0, 6) })).toBe('world')
  })

  it('trims trailing padding spaces per line', () => {
    const g = grid(['hi        ', 'there     '])
    expect(selectionText(g, { anchor: pt(0, 0), focus: pt(1, 10) })).toBe('hi\nthere')
  })

  it('empty selection (anchor === focus) → ""', () => {
    const g = grid(['x'])
    expect(selectionText(g, { anchor: pt(0, 0), focus: pt(0, 0) })).toBe('')
    expect(isEmptySelection({ anchor: pt(2, 3), focus: pt(2, 3) })).toBe(true)
  })

  // §7 #3 — verify copy is content-correct for typical LLM/AI session output (multi-line prose, indented
  // code blocks, wrapped padded rows) and never leaks hidden cells / wide-cell spacers.
  describe('LLM session output', () => {
    it('copies a multi-line assistant answer verbatim across rows', () => {
      const g = grid([
        'Here is the plan:',
        '1. read the file',
        '2. run the tests',
      ])
      expect(selectionText(g, { anchor: pt(0, 0), focus: pt(2, 16) }))
        .toBe('Here is the plan:\n1. read the file\n2. run the tests')
    })

    it('preserves leading indentation inside a code block', () => {
      const g = grid([
        'def f():',
        '    return 42', // 4-space indent must survive
      ])
      // select the whole indented line (cols 0..13)
      expect(selectionText(g, { anchor: pt(1, 0), focus: pt(1, 13) })).toBe('    return 42')
      // full two-line block
      expect(selectionText(g, { anchor: pt(0, 0), focus: pt(1, 13) })).toBe('def f():\n    return 42')
    })

    it('does NOT leak hidden cells — they read as spaces (e.g. a password echo masked by the app)', () => {
      // "ok " then 3 hidden cells then " end" → hidden cells must be spaces, never their underlying text
      const row = [
        cell('o'), cell('k'), cell(' '),
        cell('S', { hidden: true }), cell('E', { hidden: true }), cell('C', { hidden: true }),
        cell(' '), cell('e'), cell('n'), cell('d'),
      ]
      const g: GridSnapshot = { ...grid(['..........']), cols: row.length, rows_cells: [row] }
      const copied = selectionText(g, { anchor: pt(0, 0), focus: pt(0, row.length) })
      expect(copied).not.toContain('SEC') // the masked text never leaks
      expect(copied).toBe('ok     end') // "ok" + space + 3 hidden→spaces + space + "end" = 5 internal spaces
    })

    it('handles wide (CJK/emoji) cells: the glyph once, its width:0 spacer skipped', () => {
      // "ab" + a width-2 glyph "世" (occupies cols 2-3) + "cd"
      const row = [
        cell('a'), cell('b'),
        cell('世', { width: 2 }), cell('', { width: 0 }),
        cell('c'), cell('d'),
      ]
      const g: GridSnapshot = { ...grid(['......']), cols: 6, rows_cells: [row] }
      // select across the wide glyph (grid cols 0..6) — glyph appears exactly once
      expect(selectionText(g, { anchor: pt(0, 0), focus: pt(0, 6) })).toBe('ab世cd')
    })

    it('a backwards drag over an indented block still copies it forwards/correctly', () => {
      const g = grid(['  step one', '  step two'])
      // anchor at the END, focus at the START (backwards) → same forward text
      expect(selectionText(g, { anchor: pt(1, 10), focus: pt(0, 0) })).toBe('  step one\n  step two')
    })
  })

  it('clamps out-of-range rows/cols', () => {
    const g = grid(['abc'])
    expect(selectionText(g, { anchor: pt(0, 0), focus: pt(9, 99) })).toBe('abc') // beyond the grid
    expect(selectionText(g, { anchor: pt(5, 0), focus: pt(9, 0) })).toBe('')     // wholly off-grid
  })
})

describe('cell-aligned wrap-aware copy', () => {
  it('joins proven soft wraps, keeping actual hard breaks and legacy full-width rows separate', () => {
    const g = wrappedGrid(['ABCDEFGH', '12345678', 'xyz     ', 'new line'], [true, true, false, false])
    const range = { anchor: pt(0, 0), focus: pt(3, 8) }
    expect(selectionText(g, range)).toBe('ABCDEFGH12345678xyz\nnew line')
    expect(selectionText({ ...g, row_copy: null }, range)).toBe('ABCDEFGH\n12345678\nxyz\nnew line')
    expect(selectionText({ ...g, row_copy: undefined }, range)).toBe('ABCDEFGH\n12345678\nxyz\nnew line')
  })

  it('preserves genuine seam spaces, partial selected spaces and Unicode whitespace', () => {
    const g = wrappedGrid(['ab  ', 'cd  '], [true, false])
    expect(selectionText(g, { anchor: pt(0, 0), focus: pt(0, 4) })).toBe('ab  ')
    expect(selectionText(g, { anchor: pt(0, 0), focus: pt(1, 3) })).toBe('ab  cd ')
    expect(selectionText(g, { anchor: pt(0, 0), focus: pt(1, 4) })).toBe('ab  cd')
    expect(selectionText(grid(['x\u00a0 ']), { anchor: pt(0, 0), focus: pt(0, 3) })).toBe('x\u00a0')
    expect(selectionText(grid(['abc ']), { anchor: pt(0, 2), focus: pt(0, 3) })).toBe('c')
  })

  it('keeps ASCII-blank-only selection a no-op without stripping meaningful whitespace', () => {
    expect(selectionText(grid(['one  two']), { anchor: pt(0, 3), focus: pt(0, 5) })).toBe('')
    expect(selectionText(grid(['        ']), { anchor: pt(0, 0), focus: pt(0, 6) })).toBe('')
    expect(selectionText(grid(['\u00a0 ']), { anchor: pt(0, 0), focus: pt(0, 1) })).toBe('\u00a0')
    expect(selectionText(grid([' ', ' ']), { anchor: pt(0, 0), focus: pt(1, 0) })).toBe('\n')
  })

  it('drops only certified wide-glyph placeholders, never an ordinary space at a wrap', () => {
    const g = wrappedGrid(['ab  ', '....'], [true, false])
    g.rows_cells[1] = [cell('界', { width: 2 }), cell('', { width: 0 }), cell('c'), cell(' ')]
    g.row_copy![0].excluded_columns = [3]
    const range = { anchor: pt(0, 0), focus: pt(1, 4) }
    expect(selectionText(g, range)).toBe('ab 界c')
    g.row_copy![0].excluded_columns = []
    expect(selectionText(g, range)).toBe('ab  界c')
  })

  it('normalizes partial backwards ranges and distinguishes a wrap from an explicit hard end caret', () => {
    const g = wrappedGrid(['abcd', 'efgh'], [true, false])
    expect(selectionText(g, { anchor: pt(1, 2), focus: pt(0, 2) })).toBe('cdef')
    expect(selectionText(g, { anchor: pt(0, 0), focus: pt(0, 4) })).toBe('abcd')
    expect(selectionText(g, { anchor: pt(0, 0), focus: pt(1, 0) })).toBe('abcd')
    expect(selectionText(grid(['abcd', 'efgh']), { anchor: pt(0, 0), focus: pt(1, 0) })).toBe('abcd\n')
    expect(selectionText(g, { anchor: pt(1, 0), focus: pt(1, 2) })).toBe('ef')
  })

  it('uses newline fallback for unknown origin or invalid metadata without excluding real text', () => {
    const g = wrappedGrid(['abcd', 'efgh'], [true, false])
    const range = { anchor: pt(0, 0), focus: pt(1, 4) }
    g.row_copy![1].starts_line = undefined
    expect(selectionText(g, range)).toBe('abcd\nefgh')
    g.row_copy![1].starts_line = false
    g.row_copy![0].excluded_columns = [0] // Not a synthetic blank: metadata is invalid.
    expect(selectionText(g, range)).toBe('abcd\nefgh')
    for (const malformed of [[], [null], { soft_wrap: true }] as unknown[]) {
      expect(selectionText({ ...g, row_copy: malformed as GridSnapshot['row_copy'] }, range)).toBe('abcd\nefgh')
    }
  })

  it('uses terminal columns for partial CJK, emoji and combining-grapheme ranges', () => {
    const g = grid(['........'])
    g.rows_cells = [[cell('界', { width: 2 }), cell('', { width: 0 }), cell('e\u0301'),
      cell('🙂', { width: 2 }), cell('', { width: 0 }), cell('Z'), cell(' '), cell(' ')]]
    expect(selectionText(g, { anchor: pt(0, 2), focus: pt(0, 3) })).toBe('e\u0301')
    expect(selectionText(g, { anchor: pt(0, 3), focus: pt(0, 5) })).toBe('🙂')
    expect(selectionText(g, { anchor: pt(0, 5), focus: pt(0, 6) })).toBe('Z')
    expect(selectionText(g, { anchor: pt(0, 1), focus: pt(0, 2) })).toBe('界') // Selected right half belongs to this glyph.
    expect(selectionText(g, { anchor: pt(0, 4), focus: pt(0, 5) })).toBe('🙂')
    expect(selectionText(g, { anchor: pt(0, 0), focus: pt(0, 2) })).toBe('界')
  })

  it('retains existing hidden-cell masking even across a soft wrap', () => {
    const g = wrappedGrid(['ab  ', 'done'], [true, false])
    g.rows_cells[0][2] = cell('SECRET', { hidden: true })
    expect(selectionText(g, { anchor: pt(0, 0), focus: pt(1, 4) })).toBe('ab  done')
  })

  it('uses the same wrap rules for Copy Screen and keeps hard blank lines inside text', () => {
    const g = wrappedGrid(['abcd', 'ef  ', '', 'next', '', ''], [true, false, false, false, false, false])
    expect(visibleGridText(g)).toBe('abcdef\n\nnext')
    expect(visibleGridText(grid(['x\u00a0', '']))).toBe('x\u00a0')
    expect(visibleGridText(grid([]))).toBe('')
  })
})

describe('selection geometry', () => {
  const geometry = { rows: 3, cols: 5, cellW: 10, cellH: 20 }

  it('maps pixels to the cell under the pointer and clamps outside the grid', () => {
    expect(cellPointFromPixel({ x: 0, y: 0 }, geometry)).toEqual(pt(0, 0))
    expect(cellPointFromPixel({ x: 29, y: 39 }, geometry)).toEqual(pt(1, 2))
    expect(cellPointFromPixel({ x: -50, y: -1 }, geometry)).toEqual(pt(0, 0))
    expect(cellPointFromPixel({ x: 999, y: 999 }, geometry)).toEqual(pt(2, 4))
  })

  it('maps pixels to end-exclusive caret coordinates for text selection', () => {
    expect(caretPointFromPixel({ x: 0, y: 0 }, geometry)).toEqual(pt(0, 0))
    expect(caretPointFromPixel({ x: 30, y: 20 }, geometry)).toEqual(pt(1, 3))
    expect(caretPointFromPixel({ x: 999, y: 999 }, geometry)).toEqual(pt(3, 5))
  })

  it('builds a range from pointer pixels using terminal cell metrics', () => {
    expect(selectionRangeFromPixels({ x: 10, y: 0 }, { x: 40, y: 40 }, geometry)).toEqual({
      anchor: pt(0, 1),
      focus: pt(2, 4),
    })
  })

  it('turns a single-row selection range into a clipped paint span', () => {
    expect(selectionHighlightSpans({ anchor: pt(1, 1), focus: pt(1, 4) }, geometry)).toEqual([
      { row: 1, startCol: 1, endCol: 4, active: true },
    ])
  })

  it('turns a multi-row selection range into first/middle/last paint spans', () => {
    expect(selectionHighlightSpans({ anchor: pt(0, 2), focus: pt(2, 3) }, geometry)).toEqual([
      { row: 0, startCol: 2, endCol: 5, active: true },
      { row: 1, startCol: 0, endCol: 5, active: true },
      { row: 2, startCol: 0, endCol: 3, active: true },
    ])
  })

  it('normalizes backwards ranges and drops empty or off-grid spans', () => {
    expect(selectionHighlightSpans({ anchor: pt(2, 3), focus: pt(0, 2) }, geometry)).toEqual([
      { row: 0, startCol: 2, endCol: 5, active: true },
      { row: 1, startCol: 0, endCol: 5, active: true },
      { row: 2, startCol: 0, endCol: 3, active: true },
    ])
    expect(selectionHighlightSpans({ anchor: pt(1, 2), focus: pt(1, 2) }, geometry)).toEqual([])
    expect(selectionHighlightSpans({ anchor: pt(7, 0), focus: pt(8, 5) }, geometry)).toEqual([])
  })
})
