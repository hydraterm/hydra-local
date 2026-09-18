// Pure search-highlight adapter (Terminal Comfort Polish). Turns TerminalSearch results into paint-ready
// highlight spans in CELL coordinates, so the renderer can draw a fillRect per span WITHOUT re-implementing
// search or knowing about TerminalSearch. DOM-free, transport-free.
//
// A span is one match on one row: [startCol, endCol) (end-exclusive, the same convention findInGrid emits).
// `active` flags the currently-focused match so the renderer can paint it in a distinct colour.

import type { TerminalSearchMatch } from './search.js'

export interface HighlightSpan {
  readonly row: number
  readonly startCol: number
  /** Exclusive end column (so width in cells = endCol - startCol). */
  readonly endCol: number
  readonly active: boolean
}

/** Structural equality for paint-ready spans. Callers rebuild these small arrays whenever search/selection state
 * is published, so reference equality would turn an unchanged highlight set into a redundant full-grid paint. */
export function highlightSpansEqual(
  left: readonly HighlightSpan[],
  right: readonly HighlightSpan[],
): boolean {
  if (left.length !== right.length) return false
  for (let i = 0; i < left.length; i++) {
    const a = left[i]!
    const b = right[i]!
    if (
      a.row !== b.row
      || a.startCol !== b.startCol
      || a.endCol !== b.endCol
      || a.active !== b.active
    ) return false
  }
  return true
}

/** True when two matches refer to the same span (row + columns) — used to flag the active one. */
function sameMatch(a: TerminalSearchMatch, b: TerminalSearchMatch): boolean {
  return a.row === b.row && a.startCol === b.startCol && a.endCol === b.endCol
}

/**
 * Build the highlight spans for the current matches, flagging the active one. Spans are clipped to the grid
 * (`rows` × `cols`) and zero-width / off-grid matches are dropped, so the renderer can paint each blindly.
 */
export function highlightSpans(
  matches: readonly TerminalSearchMatch[],
  active: TerminalSearchMatch | null,
  grid: { rows: number; cols: number },
): HighlightSpan[] {
  const spans: HighlightSpan[] = []
  for (const m of matches) {
    if (m.row < 0 || m.row >= grid.rows) continue
    const startCol = Math.max(0, m.startCol)
    const endCol = Math.min(grid.cols, m.endCol)
    if (endCol <= startCol) continue // off-grid or zero-width after clipping
    spans.push({ row: m.row, startCol, endCol, active: active ? sameMatch(m, active) : false })
  }
  return spans
}
