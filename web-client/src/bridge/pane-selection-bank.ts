import type { GridSnapshot } from '../protocol/web-protocol.js'
import { visibleGridText } from '../terminal/selection.js'
import { SelectionController } from '../terminal/selection-controller.js'
import type { PixelPoint, SelectionGeometry, SelectionRange } from '../terminal/selection.js'
import type { HighlightSpan } from '../terminal/search-highlight.js'

interface PaneSelectionState {
  readonly controller: SelectionController
  grid: GridSnapshot | null
}

/** Per-session terminal selection/copy state for N-up panes. Mirrors PaneSearchBank without DOM/clipboard. */
export class PaneSelectionBank {
  private readonly selections = new Map<string, PaneSelectionState>()

  setGeometry(sessionId: string, geometry: SelectionGeometry): void {
    this.stateFor(sessionId).controller.setGeometry(geometry)
  }

  setGrid(sessionId: string, grid: GridSnapshot): void {
    this.stateFor(sessionId).grid = grid
  }

  begin(sessionId: string, point: PixelPoint): void {
    this.stateFor(sessionId).controller.begin(point)
  }

  drag(sessionId: string, point: PixelPoint): void {
    this.selections.get(sessionId)?.controller.drag(point)
  }

  end(sessionId: string): void {
    this.selections.get(sessionId)?.controller.end()
  }

  clear(sessionId: string): void {
    this.selections.delete(sessionId)
  }

  clearSelection(sessionId: string): void {
    this.selections.get(sessionId)?.controller.clear()
  }

  clearAll(): void {
    this.selections.clear()
  }

  isDragging(sessionId: string): boolean {
    return this.selections.get(sessionId)?.controller.isDragging() ?? false
  }

  range(sessionId: string): SelectionRange | null {
    return this.selections.get(sessionId)?.controller.range() ?? null
  }

  hasSelection(sessionId: string): boolean {
    return this.selections.get(sessionId)?.controller.hasSelection() ?? false
  }

  spans(sessionId: string): readonly HighlightSpan[] {
    return this.selections.get(sessionId)?.controller.spans() ?? []
  }

  text(sessionId: string): string {
    const state = this.selections.get(sessionId)
    return state?.grid ? state.controller.text(state.grid) : ''
  }

  visibleText(sessionId: string): string {
    const state = this.selections.get(sessionId)
    return state?.grid ? visibleGridText(state.grid) : ''
  }

  shouldShowCopy(sessionId: string): boolean {
    const state = this.selections.get(sessionId)
    return !!state?.grid && state.controller.shouldShowCopy() && state.controller.text(state.grid).length > 0
  }

  copyAnchorPx(sessionId: string): PixelPoint | null {
    return this.selections.get(sessionId)?.controller.copyAnchorPx() ?? null
  }

  has(sessionId: string): boolean {
    return this.selections.has(sessionId)
  }

  get size(): number {
    return this.selections.size
  }

  private stateFor(sessionId: string): PaneSelectionState {
    const existing = this.selections.get(sessionId)
    if (existing) return existing
    const created = { controller: new SelectionController(), grid: null }
    this.selections.set(sessionId, created)
    return created
  }
}
