// Canvas grid renderer. Paints a GridSnapshot to a 2D canvas with a monospace font: per-cell bg/fg with
// attributes (bold/italic/underline/inverse/dim/strikeout/hidden), wide-cell handling, and the cursor.
//
// We paint the AUTHORITATIVE grid cells only — no VT parsing (the daemon already parsed). One source of
// truth, matching the native renderer's "no second VT parser" rule.

import type { Cell, GridSnapshot } from '../protocol/web-protocol.js'
import { metricsOn, recordPaint } from '../bridge/render-metrics.js'
import { applyDim, cssRgb, resolveColor, THEME } from './theme.js'
import type { HighlightSpan } from './search-highlight.js'

export interface CellMetrics {
  cellW: number
  cellH: number
  baseline: number
  fontPx: number
}

// Resolve a cell's effective (fg, bg) CSS colors, applying inverse + dim. Pure — unit-testable.
export function cellColors(cell: Cell): { fg: string; bg: string } {
  let fg = resolveColor(cell.fg)
  let bg = resolveColor(cell.bg)
  if (cell.inverse) {
    const t = fg
    fg = bg
    bg = t
  }
  if (cell.dim) fg = applyDim(fg)
  if (cell.hidden) fg = bg // hidden text paints as background
  return { fg: cssRgb(fg), bg: cssRgb(bg) }
}

export class GridRenderer {
  private readonly ctx: CanvasRenderingContext2D
  private metrics: CellMetrics
  private readonly fontFamily: string

  constructor(
    private readonly canvas: HTMLCanvasElement,
    fontPx = 15,
    fontFamily = 'ui-monospace, SFMono-Regular, Menlo, "Cascadia Mono", "DejaVu Sans Mono", Consolas, monospace',
  ) {
    const ctx = canvas.getContext('2d')
    if (!ctx) throw new Error('2d canvas context unavailable')
    this.ctx = ctx
    this.fontFamily = fontFamily
    this.applyTextQualityHints()
    this.metrics = this.measure(fontPx)
  }

  getMetrics(): CellMetrics {
    return this.metrics
  }

  /** Identity seam used by mount code to make repeated attachment of the same DOM canvas a true no-op. */
  usesCanvas(canvas: HTMLCanvasElement): boolean {
    return this.canvas === canvas
  }

  setFontPx(fontPx: number): void {
    this.metrics = this.measure(fontPx)
  }

  // Measure the monospace cell box for the given font size.
  private measure(fontPx: number): CellMetrics {
    this.ctx.font = `${fontPx}px ${this.fontFamily}`
    this.applyTextQualityHints()
    const m = this.ctx.measureText('M')
    const cellW = Math.ceil(m.width)
    // ascent/descent are available in modern browsers; fall back to a ratio.
    const ascent = m.actualBoundingBoxAscent || fontPx * 0.8
    const descent = m.actualBoundingBoxDescent || fontPx * 0.2
    const cellH = Math.ceil(ascent + descent + Math.max(2, Math.round(fontPx * 0.18)))
    const baseline = Math.round(ascent + (cellH - ascent - descent) / 2)
    return { cellW, cellH, baseline, fontPx }
  }

  private applyTextQualityHints(): void {
    this.ctx.imageSmoothingEnabled = false
    const ctx = this.ctx as CanvasRenderingContext2D & {
      fontKerning?: CanvasFontKerning
      fontStretch?: string
      fontVariantCaps?: string
      letterSpacing?: string
      textRendering?: string
      wordSpacing?: string
    }
    ctx.fontKerning = 'none'
    ctx.fontStretch = 'normal'
    ctx.fontVariantCaps = 'normal'
    ctx.letterSpacing = '0px'
    ctx.wordSpacing = '0px'
    ctx.textRendering = 'optimizeLegibility'
  }

  // Size the CSS canvas to the grid's logical pixel size and the backing store to that size × devicePixelRatio.
  // Do NOT stretch the grid to fill the tile: browser interpolation makes terminal glyphs visibly blurry. The
  // surrounding shell computes cols/rows from the available viewport, so an exact grid-size canvas should already
  // nearly fill the pane while preserving crisp text.
  private lastBackW = -1
  private lastBackH = -1
  private lastScale = -1
  private lastDpr = 1

  resizeForGrid(cols: number, rows: number, dpr = window.devicePixelRatio || 1): void {
    const { cellW, cellH } = this.metrics
    const gridW = cols * cellW
    const gridH = rows * cellH
    const backW = Math.round(gridW * dpr)
    const backH = Math.round(gridH * dpr)
    const scale = dpr
    this.lastDpr = dpr
    // CRITICAL: resizeForGrid runs on EVERY paint. Writing canvas.width/height (a full reset + relayout) each time
    // churns the layout → the tile's ResizeObserver fires → sendResize → repaint → the canvas "resizes non-stop".
    // Only touch the backing store when it ACTUALLY changed; otherwise just re-apply the transform (cheap, no relayout).
    if (backW !== this.lastBackW || backH !== this.lastBackH) {
      this.canvas.width = backW
      this.canvas.height = backH
      this.canvas.style.width = `${gridW}px`
      this.canvas.style.height = `${gridH}px`
      this.lastBackW = backW
      this.lastBackH = backH
      this.lastScale = -1 // width write cleared the ctx transform → force re-apply below
    }
    if (scale !== this.lastScale) {
      this.ctx.setTransform(scale, 0, 0, scale, 0, 0)
      this.lastScale = scale
    }
  }

  /** The on-screen size of ONE painted cell in CSS pixels under the current contain transform — the value
   * mouse handlers must divide by to map a pointer position to a grid cell. Null before the first
   * resizeForGrid (nothing painted yet, no scale established). */
  screenCellPx(): { cellW: number; cellH: number } | null {
    if (this.lastScale <= 0) return null
    const cssScale = this.lastScale / this.lastDpr
    return { cellW: this.metrics.cellW * cssScale, cellH: this.metrics.cellH * cssScale }
  }

  // Compute the grid (cols, rows) that fit a logical pixel box, for Resize requests.
  gridForPixels(logicalW: number, logicalH: number): { cols: number; rows: number } {
    const { cellW, cellH } = this.metrics
    return {
      cols: Math.max(1, Math.floor(logicalW / cellW)),
      rows: Math.max(1, Math.floor(logicalH / cellH)),
    }
  }

  // Paint an arbitrary block of cell rows (no cursor) — used by both the live grid and the scrollback
  // history view. `cols` is the row width; `viewRows` is how many rows of canvas to clear (so a short
  // history page still clears the full viewport).
  paintRows(rows: ReadonlyArray<ReadonlyArray<Cell>>, cols: number, viewRows: number, highlights: readonly HighlightSpan[] = []): void {
    const t0 = metricsOn() ? performance.now() : 0
    const { cellW, cellH, baseline, fontPx } = this.metrics
    const ctx = this.ctx
    // Clear the FULL backing store (in device px, transform-independent) so any contain-scaling margin outside the
    // grid shows the terminal background — not stale pixels from a previous, differently-sized paint.
    ctx.save()
    ctx.setTransform(1, 0, 0, 1, 0, 0)
    ctx.fillStyle = cssRgb(THEME.background)
    ctx.fillRect(0, 0, this.canvas.width, this.canvas.height)
    ctx.restore()
    ctx.fillStyle = cssRgb(THEME.background)
    ctx.fillRect(0, 0, cols * cellW, viewRows * cellH)

    // Background pass first; highlights are painted after cell backgrounds and before glyphs.
    for (let row = 0; row < rows.length; row++) {
      const cells = rows[row]
      if (!cells) continue
      const y = row * cellH
      for (let col = 0; col < cols; col++) {
        const cell = cells[col]
        if (!cell || cell.width === 0) continue // wide spacer: drawn by its lead
        const w = cell.width === 2 ? 2 : 1
        const x = col * cellW
        const { bg } = cellColors(cell)
        ctx.fillStyle = bg
        ctx.fillRect(x, y, cellW * w, cellH)
      }
    }

    for (const span of highlights) {
      if (span.row < 0 || span.row >= viewRows) continue
      const startCol = Math.max(0, Math.min(cols, span.startCol))
      const endCol = Math.max(startCol, Math.min(cols, span.endCol))
      if (endCol <= startCol) continue
      ctx.fillStyle = span.active ? 'rgba(255, 214, 102, 0.55)' : 'rgba(98, 160, 234, 0.34)'
      ctx.fillRect(startCol * cellW, span.row * cellH, (endCol - startCol) * cellW, cellH)
    }

    for (let row = 0; row < rows.length; row++) {
      const cells = rows[row]
      if (!cells) continue
      const y = row * cellH
      for (let col = 0; col < cols; col++) {
        const cell = cells[col]
        if (!cell || cell.width === 0) continue // wide spacer: drawn by its lead
        const w = cell.width === 2 ? 2 : 1
        const x = col * cellW
        const { fg } = cellColors(cell)
        if (cell.text && cell.text !== ' ' && !cell.hidden) {
          let font = ''
          if (cell.italic) font += 'italic '
          if (cell.bold) font += 'bold '
          font += `${fontPx}px ${this.fontFamily}`
          ctx.font = font
          this.applyTextQualityHints()
          ctx.fillStyle = fg
          ctx.textBaseline = 'alphabetic'
          ctx.fillText(cell.text, x, y + baseline)
        }
        if (cell.underline !== 'none') {
          // Match the local renderer's decoration styles (render.rs decoration_rects): single / double (stacked) /
          // dotted / dashed / curly (dense-dotted stand-in, same as local until a wavy shader exists).
          const uw = cellW * w
          const baseY = Math.round(y + cellH - 2) + 0.5
          const drawSolid = (ly: number) => {
            ctx.strokeStyle = fg
            ctx.lineWidth = 1
            ctx.beginPath()
            ctx.moveTo(x, ly)
            ctx.lineTo(x + uw, ly)
            ctx.stroke()
          }
          const drawSegments = (ly: number, seg: number, gap: number) => {
            ctx.fillStyle = fg
            for (let sx = 0; sx < uw; sx += seg + gap) {
              ctx.fillRect(x + sx, ly - 0.5, Math.min(seg, uw - sx), 1)
            }
          }
          switch (cell.underline) {
            case 'double':
              drawSolid(baseY)
              drawSolid(baseY - 2)
              break
            case 'dotted':
            case 'curly': // curly ≈ dense dots (parity with local's approximation)
              drawSegments(baseY, 1, 1)
              break
            case 'dashed':
              drawSegments(baseY, 4, 2)
              break
            default: // 'single'
              drawSolid(baseY)
          }
        }
        if (cell.strikeout) {
          ctx.strokeStyle = fg
          ctx.lineWidth = 1
          ctx.beginPath()
          const sy = Math.round(y + cellH / 2) + 0.5
          ctx.moveTo(x, sy)
          ctx.lineTo(x + cellW * w, sy)
          ctx.stroke()
        }
      }
    }
    if (t0) recordPaint(performance.now() - t0, rows.length)
  }

  // Paint a full grid snapshot (live view): the visible rows + the cursor.
  paint(grid: GridSnapshot, highlights: readonly HighlightSpan[] = []): void {
    const { cellW, cellH, baseline, fontPx } = this.metrics
    const ctx = this.ctx
    this.paintRows(grid.rows_cells, grid.cols, grid.rows, highlights)

    // cursor (block) — only when visible.
    if (grid.cursor_visible && grid.cursor_line < grid.rows && grid.cursor_col < grid.cols) {
      const cx = grid.cursor_col * cellW
      const cy = grid.cursor_line * cellH
      ctx.fillStyle = cssRgb(THEME.cursor)
      // Parity with local (render.rs): ALL cursor shapes use 0.7 alpha, not just the block.
      ctx.globalAlpha = 0.7
      if (grid.cursor_shape === 'beam') {
        ctx.fillRect(cx, cy, 2, cellH)
        ctx.globalAlpha = 1
      } else if (grid.cursor_shape === 'underline') {
        ctx.fillRect(cx, cy + cellH - 2, cellW, 2)
        ctx.globalAlpha = 1
      } else {
        // block: fill + redraw glyph in inverted color
        ctx.fillRect(cx, cy, cellW, cellH)
        ctx.globalAlpha = 1
        const cell = grid.rows_cells[grid.cursor_line]?.[grid.cursor_col]
        if (cell && cell.text && cell.text !== ' ') {
          ctx.fillStyle = cssRgb(THEME.background)
          ctx.font = `${fontPx}px ${this.fontFamily}`
          this.applyTextQualityHints()
          ctx.fillText(cell.text, cx, cy + baseline)
        }
      }
    }
  }
}
