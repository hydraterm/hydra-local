import { describe, expect, it } from 'vitest'
import { GridRenderer } from './grid-renderer'
import type { Cell, GridSnapshot } from '../protocol/web-protocol'
import type { HighlightSpan } from './search-highlight'

interface FillCall {
  style: string
  x: number
  y: number
  w: number
  h: number
}

class FakeContext {
  font = ''
  fillStyle = ''
  strokeStyle = ''
  lineWidth = 1
  textBaseline = ''
  globalAlpha = 1
  readonly fills: FillCall[] = []
  readonly texts: Array<{ text: string; x: number; y: number }> = []

  measureText() {
    return { width: 9, actualBoundingBoxAscent: 12, actualBoundingBoxDescent: 3 }
  }
  readonly transforms: Array<{ a: number; d: number }> = []
  setTransform(a: number, _b: number, _c: number, d: number) {
    this.transforms.push({ a, d })
  }
  save() {}
  restore() {}
  fillRect(x: number, y: number, w: number, h: number) {
    this.fills.push({ style: String(this.fillStyle), x, y, w, h })
  }
  fillText(text: string, x: number, y: number) {
    this.texts.push({ text, x, y })
  }
  strokes = 0
  beginPath() {}
  moveTo() {}
  lineTo() {}
  stroke() { this.strokes += 1 }
}

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

function grid(text: string): GridSnapshot {
  return {
    version: 2,
    generation: 'g',
    revision: 1,
    base_revision: 0,
    cols: text.length,
    rows: 1,
    rows_cells: [Array.from(text).map(cell)],
    cursor_line: 0,
    cursor_col: 0,
    cursor_visible: false,
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

function renderer() {
  const ctx = new FakeContext()
  const canvas = {
    width: 0,
    height: 0,
    clientWidth: 0,
    clientHeight: 0,
    style: {},
    getContext: () => ctx,
  } as unknown as HTMLCanvasElement
  return { ctx, renderer: new GridRenderer(canvas) }
}

describe('GridRenderer search highlights', () => {
  it('sizes the canvas to exact grid CSS pixels with a DPR backing store', () => {
    const { ctx, renderer: r } = renderer()
    const canvas = (r as unknown as { canvas: HTMLCanvasElement }).canvas

    r.resizeForGrid(10, 2, 2)

    expect(canvas.width).toBe(180)
    expect(canvas.height).toBe(72)
    expect(canvas.style.width).toBe('90px')
    expect(canvas.style.height).toBe('36px')
    expect(ctx.transforms.at(-1)).toEqual({ a: 2, d: 2 })
  })

  it('paints search highlight spans at cell coordinates before glyphs', () => {
    const { ctx, renderer: r } = renderer()
    const spans: HighlightSpan[] = [
      { row: 0, startCol: 1, endCol: 3, active: false },
      { row: 0, startCol: 3, endCol: 4, active: true },
    ]

    r.paint(grid('test'), spans)

    const highlightFills = ctx.fills.filter((f) => f.style.startsWith('rgba('))
    expect(highlightFills).toEqual([
      { style: 'rgba(98, 160, 234, 0.34)', x: 9, y: 0, w: 18, h: 18 },
      { style: 'rgba(255, 214, 102, 0.55)', x: 27, y: 0, w: 9, h: 18 },
    ])
    expect(ctx.texts.map((t) => t.text)).toEqual(['t', 'e', 's', 't'])
    const firstTextIndex = ctx.fills.length
    expect(firstTextIndex).toBeGreaterThan(0)
  })

  it('renders distinct underline styles (single/double solid strokes; dotted/dashed/curly as fill segments)', () => {
    const styles = ['single', 'double', 'dotted', 'dashed', 'curly'] as const
    const results = styles.map((style) => {
      const { ctx, renderer: r } = renderer()
      const g = grid('x')
      g.rows_cells[0][0] = { ...g.rows_cells[0][0], underline: style }
      r.paint(g, [])
      // underline segment fills are 1px tall (h===1); cell-bg fills are full cellH tall — count only the segments.
      const segFills = ctx.fills.filter((f) => f.h === 1).length
      return { style, strokes: ctx.strokes, segFills }
    })
    const by = (s: string) => results.find((r) => r.style === s)!
    // single = one solid stroke, no segment fills
    expect(by('single').strokes).toBe(1)
    expect(by('single').segFills).toBe(0)
    // double = two stacked solid strokes
    expect(by('double').strokes).toBe(2)
    // dotted/dashed/curly = segment fills, no strokes
    expect(by('dotted').strokes).toBe(0)
    expect(by('dotted').segFills).toBeGreaterThan(1)
    expect(by('dashed').strokes).toBe(0)
    expect(by('dashed').segFills).toBeGreaterThan(0)
    expect(by('curly').segFills).toBeGreaterThan(1) // curly ≈ dense dots (local parity)
  })

  it('clips bad highlight spans defensively in the renderer', () => {
    const { ctx, renderer: r } = renderer()
    r.paint(grid('abc'), [
      { row: 0, startCol: -2, endCol: 2, active: false },
      { row: 9, startCol: 0, endCol: 2, active: true },
      { row: 0, startCol: 2, endCol: 2, active: true },
    ])

    expect(ctx.fills.filter((f) => f.style.startsWith('rgba('))).toEqual([
      { style: 'rgba(98, 160, 234, 0.34)', x: 0, y: 0, w: 18, h: 18 },
    ])
  })
})
