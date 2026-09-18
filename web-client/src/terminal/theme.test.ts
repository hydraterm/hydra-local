// Theme + cell-color tests (pure parts of the renderer; canvas painting is manual-smoke).

import { describe, expect, it } from 'vitest'
import { cssRgb, resolveColor } from './theme'
import { cellColors } from './grid-renderer'
import type { Cell } from '../protocol/web-protocol'

function cell(over: Partial<Cell>): Cell {
  return {
    text: 'x',
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
    ...over,
  }
}

describe('resolveColor (built-in dark palette, in lockstep with theme.rs)', () => {
  it('named ANSI colors', () => {
    expect(cssRgb(resolveColor({ kind: 'named', name: 'red' }))).toBe('rgb(205,0,0)')
    expect(cssRgb(resolveColor({ kind: 'named', name: 'bright_green' }))).toBe('rgb(0,255,0)')
    expect(cssRgb(resolveColor({ kind: 'named', name: 'foreground' }))).toBe('rgb(208,208,208)')
    expect(cssRgb(resolveColor({ kind: 'named', name: 'background' }))).toBe('rgb(5,6,7)')
  })

  it('indexed cube + grayscale', () => {
    // index 16 = cube (0,0,0) = rgb(0,0,0)
    expect(cssRgb(resolveColor({ kind: 'indexed', index: 16 }))).toBe('rgb(0,0,0)')
    // index 196 = cube (5,0,0) = rgb(255,0,0)
    expect(cssRgb(resolveColor({ kind: 'indexed', index: 196 }))).toBe('rgb(255,0,0)')
    // index 232 = grayscale level 8
    expect(cssRgb(resolveColor({ kind: 'indexed', index: 232 }))).toBe('rgb(8,8,8)')
    // index 0..15 follow ANSI
    expect(cssRgb(resolveColor({ kind: 'indexed', index: 1 }))).toBe('rgb(205,0,0)')
  })

  it('rgb passes through', () => {
    expect(cssRgb(resolveColor({ kind: 'rgb', r: 10, g: 20, b: 30 }))).toBe('rgb(10,20,30)')
  })
})

describe('cellColors (inverse / dim / hidden)', () => {
  it('plain cell uses fg/bg', () => {
    const { fg, bg } = cellColors(cell({}))
    expect(fg).toBe('rgb(208,208,208)')
    expect(bg).toBe('rgb(5,6,7)')
  })

  it('inverse swaps fg/bg', () => {
    const { fg, bg } = cellColors(cell({ inverse: true }))
    expect(fg).toBe('rgb(5,6,7)')
    expect(bg).toBe('rgb(208,208,208)')
  })

  it('dim scales the foreground to 60%', () => {
    const { fg } = cellColors(cell({ dim: true }))
    // 208 * 0.6 = 124.8 -> trunc 124
    expect(fg).toBe('rgb(124,124,124)')
  })

  it('hidden paints text in the background color', () => {
    const { fg, bg } = cellColors(cell({ hidden: true }))
    expect(fg).toBe(bg)
  })
})
