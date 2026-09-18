// Terminal sync tests — ported from maestro-renderer/src/sync.rs tests. Keep in lockstep.

import { describe, expect, it } from 'vitest'
import { SyncState, SUPPORTED_VERSION } from './terminal-sync'
import type { Cell, CursorState, DamageFrame, DamageOp, GridSnapshot, ModeState } from '../protocol/web-protocol'
import { DAMAGE_SCHEMA, rowCopyValid, rowCopyCellsValid } from '../protocol/web-protocol'

const SESSION = 'sess-1'

function cell(width: number, text: string): Cell {
  return {
    text,
    fg: { kind: 'named', name: 'foreground' },
    bg: { kind: 'named', name: 'foreground' },
    bold: false,
    italic: false,
    underline: 'none',
    inverse: false,
    strikeout: false,
    dim: false,
    hidden: false,
    width,
  }
}
const blank = (): Cell => cell(1, ' ')
const plainRow = (cols: number): Cell[] => Array.from({ length: cols }, () => cell(1, ' '))

function snap(gen: string, rev: number, rowsCells: Cell[][]): GridSnapshot {
  const rows = rowsCells.length
  const cols = rowsCells[0]?.length ?? 0
  return {
    version: SUPPORTED_VERSION,
    generation: gen,
    revision: rev,
    base_revision: rev,
    cols,
    rows,
    rows_cells: rowsCells,
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

const cursor = (): CursorState => ({ line: 0, col: 0, visible: true, shape: 'block' })
const modes = (): ModeState => ({
  alt_screen: false,
  app_cursor: false,
  bracketed_paste: false,
  focus_reporting: false,
  mouse_report: false,
  mouse_drag: false,
  mouse_motion: false,
  mouse_sgr: false,
})
function dmg(gen: string, base: number, rev: number, cols: number, rows: number, ops: DamageOp[]): DamageFrame {
  return {
    schema: DAMAGE_SCHEMA,
    id: SESSION,
    generation: gen,
    base_revision: base,
    revision: rev,
    cols,
    rows,
    cursor: cursor(),
    modes: modes(),
    ops,
  }
}
const rowsText = (g: GridSnapshot): string[] => g.rows_cells.map((r) => r.map((c) => c.text).join(''))

describe('grid baseline & rejection', () => {
  it('validates runtime row-copy JSON without throwing or changing a held baseline', () => {
    const row = { starts_line: null, soft_wrap: false, excluded_columns: [] }
    const invalid = [0, false, {}, 'x', [null], [1], [false], [{ ...row, soft_wrap: 1 }],
      ...[null, 0, {}, 'x', [NaN], [-1], [3], [1.5], [1, 1], [2, 1]].map(excluded_columns => [{ ...row, excluded_columns }]),
      [{ ...row, starts_line: 1 }]]
    for (const row_copy of invalid) {
      expect(rowCopyValid(row_copy, 3, 1)).toBe(false)
      expect(rowCopyCellsValid([plainRow(3)], row_copy)).toBe(false)
      const s = new SyncState(SESSION)
      const held = snap('gen-a', 10, [plainRow(3)])
      expect(s.onGrid(SESSION, held)).toHaveProperty('ok')
      const saved = structuredClone(held)
      const frame = { ...dmg('gen-a', 10, 11, 3, 1, []), row_copy } as DamageFrame
      expect(s.onDamage(SESSION, frame, held).kind).not.toBe('applied')
      expect(held).toEqual(saved)
      expect(s.onGrid(SESSION, { ...held, row_copy } as GridSnapshot)).toHaveProperty('err')
    }
    for (const row_copy of [undefined, null, [row], [{ ...row, starts_line: undefined }]]) {
      expect(rowCopyCellsValid([plainRow(3)], row_copy)).toBe(true)
    }
    expect(rowCopyValid([{ ...row, soft_wrap: true }, { ...row, starts_line: true }], 3, 2)).toBe(false)
    expect(rowCopyValid([{ ...row, excluded_columns: [65536] }], 100000, 1)).toBe(false)
  })

  it('replaces metadata atomically and clears it on an older peer frame', () => {
    const s = new SyncState(SESSION)
    const held = snap('gen-a', 10, [plainRow(3)])
    s.onGrid(SESSION, held)
    const frame = { ...dmg('gen-a', 10, 11, 3, 1, []), row_copy: [{ soft_wrap: true, excluded_columns: [2] }] }
    const applied = s.onDamage(SESSION, frame, held)
    expect(applied.kind).toBe('applied')
    if (applied.kind !== 'applied') throw new Error('metadata-only frame rejected')
    expect(applied.grid.row_copy).toEqual(frame.row_copy)
    frame.row_copy[0].excluded_columns.push(0)
    expect(applied.grid.row_copy?.[0].excluded_columns).toEqual([2])
    const next = s.onDamage(SESSION, dmg('gen-a', 11, 12, 3, 1, []), applied.grid)
    if (next.kind !== 'applied') throw new Error('old peer frame rejected')
    expect(next.grid.row_copy).toBeUndefined()
  })

  it('moves to synchronized on first valid grid', () => {
    const s = new SyncState(SESSION)
    expect(s.getPhase()).toBe('awaiting_baseline')
    const r = s.onGrid(SESSION, snap('gen-a', 5, [plainRow(3), plainRow(3)]))
    expect(r).toEqual({ ok: { repaint: true, request_snapshot: false } })
    expect(s.getPhase()).toBe('synchronized')
    expect(s.accepted()).toEqual({ gen: 'gen-a', rev: 5 })
  })

  it('rejects unsupported version (incl. V1) before reading modes', () => {
    const s = new SyncState(SESSION)
    const g = snap('gen-a', 1, [plainRow(2)])
    g.version = 1
    expect(s.onGrid(SESSION, g)).toEqual({ err: { kind: 'unsupported_version', got: 1 } })
    expect(s.accepted()).toBeNull()
  })

  it('rejects wrong session', () => {
    const s = new SyncState(SESSION)
    expect(s.onGrid('other', snap('gen-a', 1, [plainRow(2)]))).toEqual({ err: { kind: 'wrong_session' } })
  })

  it('rejects a stale revision in the same generation', () => {
    const s = new SyncState(SESSION)
    s.onGrid(SESSION, snap('gen-a', 10, [plainRow(2)]))
    expect(s.onGrid(SESSION, snap('gen-a', 9, [plainRow(2)]))).toEqual({
      err: { kind: 'stale_revision', got: 9, have: 10 },
    })
    expect(s.onGrid(SESSION, snap('gen-a', 11, [plainRow(2)]))).toEqual({ ok: { repaint: true, request_snapshot: false } })
  })

  it('ignores a duplicate revision without repaint', () => {
    const s = new SyncState(SESSION)
    s.onGrid(SESSION, snap('gen-a', 10, [plainRow(2)]))
    expect(s.onGrid(SESSION, snap('gen-a', 10, [plainRow(2)]))).toEqual({ ok: { repaint: false, request_snapshot: false } })
  })

  it('adopts a new generation and retires the old one', () => {
    const s = new SyncState(SESSION)
    s.onGrid(SESSION, snap('gen-a', 100, [plainRow(2)]))
    expect(s.onGrid(SESSION, snap('gen-b', 1, [plainRow(2)]))).toEqual({ ok: { repaint: true, request_snapshot: false } })
    expect(s.accepted()).toEqual({ gen: 'gen-b', rev: 1 })
    // a delayed frame from the retired gen-a must not replace gen-b
    expect(s.onGrid(SESSION, snap('gen-a', 9999, [plainRow(2)]))).toEqual({ err: { kind: 'retired_generation' } })
    expect(s.accepted()).toEqual({ gen: 'gen-b', rev: 1 })
  })

  it('rejects zero/ragged dimensions and bad wide layout', () => {
    const errKind = (g: GridSnapshot): string => {
      const r = new SyncState(SESSION).onGrid(SESSION, g)
      return 'err' in r ? r.err.kind : 'OK'
    }
    expect(errKind(snap('g', 1, []))).toBe('invalid_dimensions')
    expect(errKind(snap('g', 1, [plainRow(3), plainRow(2)]))).toBe('invalid_dimensions')
    // lead without spacer
    expect(errKind(snap('g', 1, [[cell(2, '界'), cell(1, 'x')]]))).toBe('invalid_wide_layout')
    // bare spacer
    expect(errKind(snap('g', 1, [[cell(0, ''), cell(1, 'x')]]))).toBe('invalid_wide_layout')
    // a valid wide pair is accepted
    expect(new SyncState(SESSION).onGrid(SESSION, snap('g', 1, [[cell(2, '界'), cell(0, ''), cell(1, 'x')]]))).toEqual({
      ok: { repaint: true, request_snapshot: false },
    })
  })
})

describe('resync & exit', () => {
  it('awaits a grid after resync without extra action', () => {
    const s = new SyncState(SESSION)
    s.onGrid(SESSION, snap('gen-a', 10, [plainRow(2)]))
    expect(s.onResyncRequired(SESSION)).toEqual({ ok: true })
    expect(s.getPhase()).toBe('awaiting_resync')
    expect(s.onGrid(SESSION, snap('gen-a', 30, [plainRow(2)]))).toEqual({ ok: { repaint: true, request_snapshot: false } })
    expect(s.getPhase()).toBe('synchronized')
  })

  it('stops accepting grids after exit', () => {
    const s = new SyncState(SESSION)
    s.onGrid(SESSION, snap('gen-a', 10, [plainRow(2)]))
    expect(s.onSessionExited(SESSION)).toEqual({ ok: true })
    expect(s.getPhase()).toBe('exited')
    expect(s.onGrid(SESSION, snap('gen-a', 11, [plainRow(2)]))).toEqual({ err: { kind: 'session_ended' } })
  })
})

describe('damage application', () => {
  function baseline(s: SyncState, gen: string, rev: number): GridSnapshot {
    const g = snap(gen, rev, [plainRow(3), plainRow(3)])
    s.onGrid(SESSION, g)
    return g
  }

  it('applies a RowSpan onto a scratch and advances revision', () => {
    const s = new SyncState(SESSION)
    const held = baseline(s, 'gen-a', 10)
    const frame = dmg('gen-a', 10, 11, 3, 2, [{ op: 'row_span', row: 0, start: 1, cells: [cell(1, 'a'), cell(1, 'b')] }])
    const out = s.onDamage(SESSION, frame, held)
    expect(out.kind).toBe('applied')
    if (out.kind === 'applied') {
      expect(rowsText(out.grid)).toEqual([' ab', '   '])
      expect(out.grid.revision).toBe(11)
      expect(out.grid.base_revision).toBe(10)
    }
    // held grid is untouched
    expect(rowsText(held)).toEqual(['   ', '   '])
    expect(s.accepted()).toEqual({ gen: 'gen-a', rev: 11 })
  })

  it('clear_all blanks every cell', () => {
    const s = new SyncState(SESSION)
    const g = snap('gen-a', 10, [
      [cell(1, 'x'), cell(1, 'y'), cell(1, 'z')],
      [cell(1, '1'), cell(1, '2'), cell(1, '3')],
    ])
    s.onGrid(SESSION, g)
    const out = s.onDamage(SESSION, dmg('gen-a', 10, 11, 3, 2, [{ op: 'clear_all', cell: blank() }]), g)
    expect(out.kind).toBe('applied')
    if (out.kind === 'applied') expect(rowsText(out.grid)).toEqual(['   ', '   '])
  })

  it('resyncs on an invalid frame, leaving the baseline', () => {
    const s = new SyncState(SESSION)
    const held = baseline(s, 'gen-a', 10)
    const frame = dmg('gen-a', 10, 11, 3, 2, [{ op: 'row_span', row: 0, start: 0, cells: [cell(1, 'a')] }])
    frame.schema = 99
    expect(s.onDamage(SESSION, frame, held).kind).toBe('resync')
    expect(s.accepted()).toEqual({ gen: 'gen-a', rev: 10 })
  })

  it('resyncs on a revision gap', () => {
    const s = new SyncState(SESSION)
    const held = baseline(s, 'gen-a', 10)
    const out = s.onDamage(SESSION, dmg('gen-a', 12, 13, 3, 2, []), held)
    expect(out.kind).toBe('resync')
    expect(s.accepted()).toEqual({ gen: 'gen-a', rev: 10 })
  })

  it('ignores a duplicate/stale frame', () => {
    const s = new SyncState(SESSION)
    const held = baseline(s, 'gen-a', 10)
    expect(s.onDamage(SESSION, dmg('gen-a', 9, 10, 3, 2, []), held).kind).toBe('ignore')
    expect(s.onDamage(SESSION, dmg('gen-a', 8, 9, 3, 2, []), held).kind).toBe('ignore')
    expect(s.accepted()).toEqual({ gen: 'gen-a', rev: 10 })
  })

  it('empty-ops frame advances cursor/modes', () => {
    const s = new SyncState(SESSION)
    const held = baseline(s, 'gen-a', 10)
    const frame = dmg('gen-a', 10, 11, 3, 2, [])
    frame.cursor = { line: 1, col: 2, visible: false, shape: 'beam' }
    frame.modes = {
      alt_screen: true,
      app_cursor: true,
      bracketed_paste: true,
      focus_reporting: true,
      mouse_report: true,
      mouse_drag: true,
      mouse_motion: true,
      mouse_sgr: true,
    }
    const out = s.onDamage(SESSION, frame, held)
    expect(out.kind).toBe('applied')
    if (out.kind === 'applied') {
      expect(rowsText(out.grid)).toEqual(rowsText(held))
      expect(out.grid.cursor_col).toBe(2)
      expect(out.grid.cursor_shape).toBe('beam')
      expect(out.grid.app_cursor).toBe(true)
      expect(out.grid.mouse_sgr).toBe(true)
    }
  })

  it('scroll_up shifts the region', () => {
    const s = new SyncState(SESSION)
    // 3 rows: A / B / C → scroll up 1 in [0,3) → B / C / (B?C left, repainted by following RowSpan)
    const g = snap('gen-a', 10, [
      [cell(1, 'A'), cell(1, 'A')],
      [cell(1, 'B'), cell(1, 'B')],
      [cell(1, 'C'), cell(1, 'C')],
    ])
    s.onGrid(SESSION, g)
    const out = s.onDamage(SESSION, dmg('gen-a', 10, 11, 2, 3, [{ op: 'scroll_up', top: 0, bottom_exclusive: 3, lines: 1 }]), g)
    expect(out.kind).toBe('applied')
    if (out.kind === 'applied') {
      expect(rowsText(out.grid)[0]).toBe('BB')
      expect(rowsText(out.grid)[1]).toBe('CC')
    }
  })
})
