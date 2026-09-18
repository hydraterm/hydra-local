import { describe, it, expect } from 'vitest'
import { SelectionController } from './selection-controller'
import { visibleGridText } from './selection'
import type { Cell, GridSnapshot } from '../protocol/web-protocol'

function cell(text: string, over: Partial<Cell> = {}): Cell {
  return {
    text, fg: { kind: 'named', name: 'foreground' }, bg: { kind: 'named', name: 'background' },
    bold: false, italic: false, underline: 'none', inverse: false, strikeout: false, dim: false,
    hidden: false, width: 1, ...over,
  }
}
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

// 10px wide, 20px tall cells; "hello world" is 11 cells on one row.
const GEOM = { rows: 1, cols: 11, cellW: 10, cellH: 20 }

function make(): SelectionController {
  const c = new SelectionController()
  c.setGeometry(GEOM)
  return c
}

describe('SelectionController — pointer-drag selection state machine', () => {
  it('begin/drag/end builds a range and yields the selected text', () => {
    const c = make()
    c.begin({ x: 0, y: 0 })       // caret col 0
    c.drag({ x: 50, y: 0 })       // caret col 5
    expect(c.isDragging()).toBe(true)
    expect(c.hasSelection()).toBe(true)
    expect(c.text(grid(['hello world']))).toBe('hello')
    c.end()
    expect(c.isDragging()).toBe(false)
  })

  it('produces paint spans for the live selection', () => {
    const c = make()
    c.begin({ x: 60, y: 0 }) // col 6
    c.drag({ x: 110, y: 0 }) // col 11
    expect(c.spans()).toEqual([{ row: 0, startCol: 6, endCol: 11, active: true }])
  })

  it('the Copy button shows only AFTER the drag ends on a non-empty selection', () => {
    const c = make()
    c.begin({ x: 0, y: 0 })
    c.drag({ x: 50, y: 0 })
    expect(c.shouldShowCopy()).toBe(false) // still dragging
    c.end()
    expect(c.shouldShowCopy()).toBe(true)
    expect(c.copyAnchorPx()).toEqual({ x: 50, y: 20 }) // past the selection end (col 5 → x=50, row 0 → y=20)
  })

  it('an empty selection (no drag) shows nothing and copies nothing', () => {
    const c = make()
    c.begin({ x: 30, y: 0 })
    c.end() // no movement → empty
    expect(c.hasSelection()).toBe(false)
    expect(c.shouldShowCopy()).toBe(false)
    expect(c.spans()).toEqual([])
    expect(c.text(grid(['hello world']))).toBe('')
    expect(c.copyAnchorPx()).toBeNull()
  })

  it('clear() drops the selection', () => {
    const c = make()
    c.begin({ x: 0, y: 0 }); c.drag({ x: 50, y: 0 }); c.end()
    expect(c.hasSelection()).toBe(true)
    c.clear()
    expect(c.hasSelection()).toBe(false)
    expect(c.range()).toBeNull()
  })

  it('drag() is a no-op when not dragging', () => {
    const c = make()
    c.drag({ x: 90, y: 0 }) // no begin → ignored
    expect(c.range()).toBeNull()
  })

  it('visibleGridText copies the visible screen without padded trailing blanks', () => {
    expect(visibleGridText(grid(['alpha', 'beta ', '', '']))).toBe('alpha\nbeta')
  })
})
