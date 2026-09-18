// Color resolution — TS port of maestro-renderer/src/theme.rs (BuiltInDark palette).
// Resolves a wire `Color` (named / indexed / rgb) to a CSS rgb string. Keep palette in lockstep.

import type { Color, NamedColor } from '../protocol/web-protocol.js'

type Rgb = [number, number, number]

const FOREGROUND: Rgb = [0xd0, 0xd0, 0xd0]
const BACKGROUND: Rgb = [0x05, 0x06, 0x07]
const CURSOR: Rgb = [0xd0, 0xd0, 0xd0]

// 16 ANSI colors (built-in dark), indices 0..15.
const ANSI: Rgb[] = [
  [0x00, 0x00, 0x00], // black
  [0xcd, 0x00, 0x00], // red
  [0x00, 0xcd, 0x00], // green
  [0xcd, 0xcd, 0x00], // yellow
  [0x00, 0x00, 0xee], // blue
  [0xcd, 0x00, 0xcd], // magenta
  [0x00, 0xcd, 0xcd], // cyan
  [0xe5, 0xe5, 0xe5], // white
  [0x7f, 0x7f, 0x7f], // bright black
  [0xff, 0x00, 0x00], // bright red
  [0x00, 0xff, 0x00], // bright green
  [0xff, 0xff, 0x00], // bright yellow
  [0x5c, 0x5c, 0xff], // bright blue
  [0xff, 0x00, 0xff], // bright magenta
  [0x00, 0xff, 0xff], // bright cyan
  [0xff, 0xff, 0xff], // bright white
]

function dim(c: Rgb): Rgb {
  return [Math.trunc(c[0] * 0.6), Math.trunc(c[1] * 0.6), Math.trunc(c[2] * 0.6)]
}

function named(n: NamedColor): Rgb {
  switch (n) {
    case 'black': return ANSI[0]
    case 'red': return ANSI[1]
    case 'green': return ANSI[2]
    case 'yellow': return ANSI[3]
    case 'blue': return ANSI[4]
    case 'magenta': return ANSI[5]
    case 'cyan': return ANSI[6]
    case 'white': return ANSI[7]
    case 'bright_black': return ANSI[8]
    case 'bright_red': return ANSI[9]
    case 'bright_green': return ANSI[10]
    case 'bright_yellow': return ANSI[11]
    case 'bright_blue': return ANSI[12]
    case 'bright_magenta': return ANSI[13]
    case 'bright_cyan': return ANSI[14]
    case 'bright_white': return ANSI[15]
    case 'foreground': return FOREGROUND
    case 'background': return BACKGROUND
    case 'cursor': return CURSOR
    case 'dim_black': return dim(ANSI[0])
    case 'dim_red': return dim(ANSI[1])
    case 'dim_green': return dim(ANSI[2])
    case 'dim_yellow': return dim(ANSI[3])
    case 'dim_blue': return dim(ANSI[4])
    case 'dim_magenta': return dim(ANSI[5])
    case 'dim_cyan': return dim(ANSI[6])
    case 'dim_white': return dim(ANSI[7])
    case 'bright_foreground': return [0xff, 0xff, 0xff]
    case 'dim_foreground': return dim(FOREGROUND)
  }
}

// xterm 256-color: 0..16 ANSI, 16..232 the 6x6x6 cube, 232..256 grayscale ramp.
function indexed(i: number): Rgb {
  if (i < 16) return ANSI[i]
  if (i < 232) {
    const n = i - 16
    const r = Math.trunc(n / 36)
    const g = Math.trunc((n % 36) / 6)
    const b = n % 6
    const chan = (v: number): number => (v === 0 ? 0 : v * 40 + 55)
    return [chan(r), chan(g), chan(b)]
  }
  const level = 8 + (i - 232) * 10
  return [level, level, level]
}

export function resolveColor(c: Color): Rgb {
  if (c.kind === 'named') return named(c.name)
  if (c.kind === 'indexed') return indexed(c.index)
  return [c.r, c.g, c.b]
}

export function applyDim(c: Rgb): Rgb {
  return dim(c)
}

export function cssRgb(c: Rgb): string {
  return `rgb(${c[0]},${c[1]},${c[2]})`
}

export const THEME = {
  foreground: FOREGROUND,
  background: BACKGROUND,
  cursor: CURSOR,
}
