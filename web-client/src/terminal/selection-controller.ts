// Pure pointer-drag selection state machine (Terminal Comfort Polish §7 — floating copy). The canvas renderer
// feeds it begin/drag/end pixel events + the current grid geometry; it owns the live SelectionRange and
// derives everything the UI needs: paint spans, selected text, whether a "Copy" button should show, and where
// to anchor that button. DOM-free, clipboard-free, transport-free — remote-app's wiring stays thin glue.

import type { GridSnapshot } from '../protocol/web-protocol.js'
import {
  isEmptySelection,
  selectionHighlightSpans,
  selectionRangeFromPixels,
  selectionText,
  type PixelPoint,
  type SelectionGeometry,
  type SelectionRange,
} from './selection.js'
import type { HighlightSpan } from './search-highlight.js'

export class SelectionController {
  private anchorPx: PixelPoint | null = null
  private focusPx: PixelPoint | null = null
  private dragging = false
  private geometry: SelectionGeometry = { rows: 0, cols: 0, cellW: 1, cellH: 1 }

  /** Update the cell metrics (call whenever the grid is re-laid-out / a snapshot arrives). */
  setGeometry(geometry: SelectionGeometry): void {
    this.geometry = geometry
  }

  /** Pointer down: start a fresh selection at this pixel. */
  begin(point: PixelPoint): void {
    this.anchorPx = point
    this.focusPx = point
    this.dragging = true
  }

  /** Pointer move while dragging: extend the selection to this pixel. No-op if not dragging. */
  drag(point: PixelPoint): void {
    if (!this.dragging) return
    this.focusPx = point
  }

  /** Pointer up: finish the drag (the range is kept so the Copy button can act on it). */
  end(): void {
    this.dragging = false
  }

  /** Clear the selection entirely (e.g. Escape, or a click that starts elsewhere). */
  clear(): void {
    this.anchorPx = null
    this.focusPx = null
    this.dragging = false
  }

  isDragging(): boolean {
    return this.dragging
  }

  /** The current range in cell coordinates, or null when there is no selection. */
  range(): SelectionRange | null {
    if (!this.anchorPx || !this.focusPx) return null
    return selectionRangeFromPixels(this.anchorPx, this.focusPx, this.geometry)
  }

  /** True when there is a non-empty selection (something is actually highlighted). */
  hasSelection(): boolean {
    const r = this.range()
    return r !== null && !isEmptySelection(r)
  }

  /** Paint spans for the renderer to draw the selection highlight. */
  spans(): HighlightSpan[] {
    const r = this.range()
    if (!r) return []
    return selectionHighlightSpans(r, { rows: this.geometry.rows, cols: this.geometry.cols })
  }

  /** The selected text for the given grid (''. when there is no selection). */
  text(grid: GridSnapshot): string {
    const r = this.range()
    return r ? selectionText(grid, r) : ''
  }

  /** Show the floating Copy button only when a drag has FINISHED on a non-empty selection. */
  shouldShowCopy(): boolean {
    return !this.dragging && this.hasSelection()
  }

  /**
   * Where to anchor the floating Copy button — just past the end of the selection, in pixels. Returns null
   * when nothing is selected.
   */
  copyAnchorPx(): PixelPoint | null {
    const r = this.range()
    if (!r || isEmptySelection(r)) return null
    // bottom-right of the focus cell, ordered so it follows the visual end of the selection
    const end = r.focus.row > r.anchor.row || (r.focus.row === r.anchor.row && r.focus.col >= r.anchor.col)
      ? r.focus
      : r.anchor
    return { x: end.col * this.geometry.cellW, y: (end.row + 1) * this.geometry.cellH }
  }
}
