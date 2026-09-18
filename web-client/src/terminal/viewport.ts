// S5 — viewport → terminal grid sizing (mobile + desktop browser). Pure math, independent of the canvas,
// so it's unit-testable and shared between resize handlers. Given the available pixel box and a measured
// cell size, compute cols/rows; clamp to sane bounds; and coalesce rapid changes (the caller debounces).

export interface CellMetrics {
  cellWidthPx: number
  cellHeightPx: number
}

export const MIN_COLS = 2
export const MIN_ROWS = 1
// Realistic ceilings: every daemon Grid/Damage cell is full JSON (~180 B even when blank), so a grid is
// cols×rows×~180 B. A 1000×1000 grid would be ~180 MB per frame — pathological over the relay. A normal
// terminal is ≤ ~250 cols; cap there so frames stay small and typing/scroll stay responsive.
export const MAX_COLS = 250
export const MAX_ROWS = 100

/** Compute the grid that fits `availPx`, given the cell box. Floors (don't overflow the viewport). */
export function gridForViewport(
  availWidthPx: number,
  availHeightPx: number,
  cell: CellMetrics,
): { cols: number; rows: number } {
  const cols = clamp(Math.floor(availWidthPx / Math.max(1, cell.cellWidthPx)), MIN_COLS, MAX_COLS)
  const rows = clamp(Math.floor(availHeightPx / Math.max(1, cell.cellHeightPx)), MIN_ROWS, MAX_ROWS)
  return { cols, rows }
}

function clamp(v: number, lo: number, hi: number): number {
  if (!Number.isFinite(v)) return lo
  return Math.max(lo, Math.min(hi, v))
}

/** True if a resize is worth sending (changed from the last reported size). Prevents no-op resize storms
 * on mobile (the soft keyboard open/close fires many resize events). */
export function shouldResize(
  prev: { cols: number; rows: number } | null,
  next: { cols: number; rows: number },
): boolean {
  return !prev || prev.cols !== next.cols || prev.rows !== next.rows
}

/**
 * Keyed resize coalescer for multi-pane terminals. Each pane/session has its own last reported grid so
 * ResizeObserver storms do not repeatedly send identical sizes, while maximize/restore changes still pass.
 */
export class ResizeCoalescer {
  private readonly sizes = new Map<string, { cols: number; rows: number }>()

  shouldResize(key: string, next: { cols: number; rows: number }): boolean {
    const prev = this.sizes.get(key) ?? null
    if (!shouldResize(prev, next)) return false
    this.sizes.set(key, next)
    return true
  }

  clear(key?: string): void {
    if (typeof key === 'string') this.sizes.delete(key)
    else this.sizes.clear()
  }
}

/** The visible area on mobile when the soft keyboard is up: prefer visualViewport (excludes the keyboard)
 * over innerHeight. Returns {width,height} in CSS px. Falls back gracefully when visualViewport is absent. */
export function availableViewport(win: {
  innerWidth: number
  innerHeight: number
  visualViewport?: { width: number; height: number } | null
}): { width: number; height: number } {
  const vv = win.visualViewport
  if (vv && vv.width > 0 && vv.height > 0) return { width: vv.width, height: vv.height }
  return { width: win.innerWidth, height: win.innerHeight }
}

/** The conventional 80×24 terminal size — used when no real viewport is measurable (tests / SSR). */
export const DEFAULT_SESSION_GRID = { cols: 80, rows: 24 }

/**
 * A sensible initial grid for a NEW session (e.g. opening a session into an empty pane) — measured from the
 * window when one is available, else the conventional 80×24. The next ResizeObserver/resize tick refits it to
 * the actual pane; this just avoids a hardcoded size that's wrong on small/large screens.
 */
export function defaultSessionGrid(
  win?: { innerWidth: number; innerHeight: number; visualViewport?: { width: number; height: number } | null },
  cell: CellMetrics = { cellWidthPx: 9, cellHeightPx: 18 },
): { cols: number; rows: number } {
  if (!win || !(win.innerWidth > 0) || !(win.innerHeight > 0)) return DEFAULT_SESSION_GRID
  const { width, height } = availableViewport(win)
  return gridForViewport(width, height, cell)
}
