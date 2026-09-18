import { describe, expect, it } from 'vitest'
import type { Cell, GridSnapshot } from '../protocol/web-protocol'
import { PaneSelectionBank } from './pane-selection-bank'

function cell(text: string): Cell {
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
  }
}

function grid(textLines: string[]): GridSnapshot {
  const width = Math.max(0, ...textLines.map((l) => l.length))
  const rows = textLines.map((l) => [...l.padEnd(width)].map((c) => cell(c)))
  return {
    version: 2,
    generation: 'g',
    revision: 1,
    base_revision: 1,
    cols: width,
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

const GEOM = { rows: 1, cols: 11, cellW: 10, cellH: 20 }

describe('PaneSelectionBank', () => {
  it('keeps selected text and spans independent per session', () => {
    const bank = new PaneSelectionBank()
    bank.setGeometry('s-a', GEOM)
    bank.setGeometry('s-b', GEOM)
    bank.setGrid('s-a', grid(['hello world']))
    bank.setGrid('s-b', grid(['other text']))

    bank.begin('s-a', { x: 0, y: 0 })
    bank.drag('s-a', { x: 50, y: 0 })
    bank.end('s-a')
    bank.begin('s-b', { x: 60, y: 0 })
    bank.drag('s-b', { x: 100, y: 0 })
    bank.end('s-b')

    expect(bank.text('s-a')).toBe('hello')
    expect(bank.text('s-b')).toBe('text')
    expect(bank.spans('s-a')).toEqual([{ row: 0, startCol: 0, endCol: 5, active: true }])
    expect(bank.spans('s-b')).toEqual([{ row: 0, startCol: 6, endCol: 10, active: true }])
  })

  it('tracks dragging and copy affordance per session', () => {
    const bank = new PaneSelectionBank()
    bank.setGeometry('s-a', GEOM)
    bank.setGrid('s-a', grid(['hello world']))
    bank.begin('s-a', { x: 0, y: 0 })
    bank.drag('s-a', { x: 50, y: 0 })

    expect(bank.isDragging('s-a')).toBe(true)
    expect(bank.shouldShowCopy('s-a')).toBe(false)
    bank.end('s-a')
    expect(bank.isDragging('s-a')).toBe(false)
    expect(bank.shouldShowCopy('s-a')).toBe(true)
    expect(bank.copyAnchorPx('s-a')).toEqual({ x: 50, y: 20 })
  })

  it('updates selected text when a fresh grid arrives without changing the selection range', () => {
    const bank = new PaneSelectionBank()
    bank.setGeometry('s-a', GEOM)
    bank.setGrid('s-a', grid(['hello world']))
    bank.begin('s-a', { x: 0, y: 0 })
    bank.drag('s-a', { x: 5 * 10, y: 0 })
    bank.end('s-a')

    expect(bank.text('s-a')).toBe('hello')
    bank.setGrid('s-a', grid(['HELLO world']))
    expect(bank.text('s-a')).toBe('HELLO')
    expect(bank.spans('s-a')).toEqual([{ row: 0, startCol: 0, endCol: 5, active: true }])
  })

  it('copies all visible text for a session from its latest grid', () => {
    const bank = new PaneSelectionBank()
    bank.setGrid('s-a', grid(['alpha', 'beta ', '', '']))

    expect(bank.visibleText('s-a')).toBe('alpha\nbeta')
    expect(bank.visibleText('missing')).toBe('')
  })

  it('read methods for unknown sessions are passive and empty', () => {
    const bank = new PaneSelectionBank()

    expect(bank.text('missing')).toBe('')
    expect(bank.spans('missing')).toEqual([])
    expect(bank.range('missing')).toBeNull()
    expect(bank.copyAnchorPx('missing')).toBeNull()
    expect(bank.hasSelection('missing')).toBe(false)
    expect(bank.shouldShowCopy('missing')).toBe(false)
    expect(bank.size).toBe(0)
  })

  it('clears individual sessions and all selection state', () => {
    const bank = new PaneSelectionBank()
    bank.setGeometry('s-a', GEOM)
    bank.setGeometry('s-b', GEOM)
    expect(bank.size).toBe(2)
    expect(bank.has('s-a')).toBe(true)

    bank.clear('s-a')
    expect(bank.has('s-a')).toBe(false)
    expect(bank.size).toBe(1)

    bank.clearAll()
    expect(bank.size).toBe(0)
  })
})
