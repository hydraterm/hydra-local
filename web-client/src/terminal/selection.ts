// Pure terminal text-selection model (Terminal Comfort Polish §7 — "floating copy action after selection").
// Given the visible grid + a selection range (anchor → focus in cell coordinates), extract the selected text
// so a floating "Copy" button can write it to the clipboard. DOM-free, transport-free, clipboard-free — it
// only turns a range into a string. The canvas renderer owns drawing the selection; this owns the text.
//
// Extracts by terminal columns, not string offsets: a grapheme can span two cells or many UTF-16 units.
// End column is EXCLUSIVE. Selections can be drawn backwards; the range is normalized first.

import { rowCopyCellsValid, type Cell, type GridSnapshot } from '../protocol/web-protocol.js'
import type { HighlightSpan } from './search-highlight.js'

export interface CellPoint {
  readonly row: number
  readonly col: number
}

export interface SelectionRange {
  readonly anchor: CellPoint
  readonly focus: CellPoint
}

export interface PixelPoint {
  readonly x: number
  readonly y: number
}

export interface SelectionGeometry {
  readonly rows: number
  readonly cols: number
  readonly cellW: number
  readonly cellH: number
}

/** Order two points top-to-bottom, left-to-right (so a backwards drag selects the same text). */
function order(a: CellPoint, b: CellPoint): [CellPoint, CellPoint] {
  if (a.row !== b.row) return a.row < b.row ? [a, b] : [b, a]
  return a.col <= b.col ? [a, b] : [b, a]
}

/** True when the range selects nothing (anchor === focus). */
export function isEmptySelection(range: SelectionRange): boolean {
  return range.anchor.row === range.focus.row && range.anchor.col === range.focus.col
}

function clamp(n: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, n))
}

function positive(n: number): number {
  return Number.isFinite(n) && n > 0 ? n : 1
}

/** Map a pointer pixel to the cell under it, clamped to the visible terminal grid. */
export function cellPointFromPixel(point: PixelPoint, geometry: SelectionGeometry): CellPoint {
  const rows = Math.max(1, geometry.rows)
  const cols = Math.max(1, geometry.cols)
  return {
    row: clamp(Math.floor(point.y / positive(geometry.cellH)), 0, rows - 1),
    col: clamp(Math.floor(point.x / positive(geometry.cellW)), 0, cols - 1),
  }
}

/**
 * Map a pointer pixel to a caret boundary. Columns are clamped to [0, cols] because ranges use an exclusive
 * end column; rows are allowed to land one past the last row so dragging below the canvas selects through the
 * final row after selectionText() clamps to the grid.
 */
export function caretPointFromPixel(point: PixelPoint, geometry: SelectionGeometry): CellPoint {
  const rows = Math.max(1, geometry.rows)
  const cols = Math.max(0, geometry.cols)
  return {
    row: clamp(Math.floor(point.y / positive(geometry.cellH)), 0, rows),
    col: clamp(Math.floor(point.x / positive(geometry.cellW)), 0, cols),
  }
}

/** Build a selection range from pointer pixels using the same end-exclusive caret coordinates as selectionText(). */
export function selectionRangeFromPixels(anchor: PixelPoint, focus: PixelPoint, geometry: SelectionGeometry): SelectionRange {
  return {
    anchor: caretPointFromPixel(anchor, geometry),
    focus: caretPointFromPixel(focus, geometry),
  }
}

/** Convert a selection range into clipped paint spans, one row at a time, for the canvas renderer. */
export function selectionHighlightSpans(range: SelectionRange, grid: { rows: number; cols: number }): HighlightSpan[] {
  if (isEmptySelection(range)) return []
  const rows = Math.max(0, grid.rows)
  const cols = Math.max(0, grid.cols)
  if (rows === 0 || cols === 0) return []

  const [start, end] = order(range.anchor, range.focus)
  if (start.row >= rows || end.row < 0) return []
  const firstRow = clamp(start.row, 0, rows - 1)
  const lastRow = clamp(end.row, 0, rows - 1)
  if (firstRow > lastRow) return []

  const spans: HighlightSpan[] = []
  for (let row = firstRow; row <= lastRow; row++) {
    const startCol = row === start.row ? clamp(start.col, 0, cols) : 0
    const endCol = row === end.row ? clamp(end.col, 0, cols) : cols
    if (endCol > startCol) spans.push({ row, startCol, endCol, active: true })
  }
  return spans
}

/**
 * Extract selected cells with complete graphemes and hidden-cell masking. Only proven soft-wrap boundaries
 * join without a newline; spaces inside those logical lines are preserved. Unknown metadata keeps the
 * legacy visual-row/newline behavior. Only ASCII padding at full right edges is trimmed; explicitly
 * selected spaces before that edge and Unicode whitespace remain intact.
 */
export function selectionText(grid: GridSnapshot, range: SelectionRange): string {
  if (isEmptySelection(range)) return ''
  const rows = grid.rows_cells
  if (rows.length === 0) return ''
  const metadata = rowCopyCellsValid(rows, grid.row_copy) ? grid.row_copy : undefined

  const [start, end] = order(range.anchor, range.focus)
  const firstRow = Math.max(0, start.row)
  const lastRow = Math.min(rows.length - 1, end.row)
  if (firstRow > lastRow) return ''

  const out: string[] = []
  for (let row = firstRow; row <= lastRow; row++) {
    const cells = rows[row]
    const from = row === start.row ? clamp(start.col, 0, cells.length) : 0
    const to = row === end.row ? clamp(end.col, from, cells.length) : cells.length
    const excluded = new Set(metadata?.[row].excluded_columns)
    let text = ''
    // Selecting either half of a wide glyph copies its complete grapheme exactly once.
    const lead = from < to && cells[from]?.width === 0 && cells[from - 1]?.width === 2 ? from - 1 : from
    for (let col = lead; col < to; col++) {
      const cell = cells[col]
      if (cell.width === 0 || excluded.has(col)) continue
      text += copyCellText(cell)
    }
    const softBoundary = metadata?.[row].soft_wrap === true && metadata[row + 1]?.starts_line === false
    const joinsNext = row < lastRow && softBoundary
    out.push(softBoundary || to < cells.length ? text : text.replace(/ +$/, ''))
    if (row < lastRow && !joinsNext) out.push('\n')
  }
  const text = out.join('')
  // Preserve the established blank-only no-op; do not clear the clipboard with padding.
  return /[^ ]/.test(text) ? text : ''
}

function copyCellText(cell: Cell): string {
  return cell.hidden ? ' '.repeat(Math.max(1, cell.width)) : cell.text
}

/** Copy the currently visible terminal grid, trimming padded cells and trailing empty rows. */
export function visibleGridText(grid: GridSnapshot): string {
  return selectionText(grid, {
    anchor: { row: 0, col: 0 },
    focus: { row: grid.rows_cells.length, col: 0 },
  }).replace(/[ \n]+$/, '')
}
