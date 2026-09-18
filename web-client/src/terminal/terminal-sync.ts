// Terminal sync state machine — TS port of maestro-renderer/src/sync.rs.
//
// The web client trusts the daemon's grid, but a malformed, stale, cross-generation, or wrong-session
// snapshot must never reach the paint path. This is the single gate every daemon event passes through,
// bound to one expected session id. Four explicit phases (AwaitingBaseline / Synchronized /
// AwaitingResync / Exited) and the same rejection rules as the Rust renderer.
//
// Keep in lockstep with sync.rs. The decode/validation of frames lives in protocol/web-protocol.ts
// (mirror of wire.rs); this file is the STATE MACHINE on top of those types.

import type { Cell, DamageFrame, DamageOp, GridSnapshot } from '../protocol/web-protocol.js'
import { cloneRowCopy, rowCopyCellsValid, validateDamage } from '../protocol/web-protocol.js'

export const SUPPORTED_VERSION = 2
const MAX_DIMENSION = 2000

export type SyncPhase = 'awaiting_baseline' | 'synchronized' | 'awaiting_resync' | 'exited'

// Why a grid was rejected (mirror of Rust `Reject`, the subset the web client acts on).
export type Reject =
  | { kind: 'wrong_session' }
  | { kind: 'unsupported_version'; got: number }
  | { kind: 'invalid_dimensions'; reason: string }
  | { kind: 'invalid_wide_layout'; row: number; col: number }
  | { kind: 'retired_generation' }
  | { kind: 'stale_revision'; got: number; have: number }
  | { kind: 'session_ended' }

// Outcome of accepting a Grid: paint it, and/or (rarely) re-request a snapshot. With the structured-only
// client (want_raw_output:false) request_snapshot is effectively never set, but we mirror the shape.
export interface GridOutcome {
  repaint: boolean
  request_snapshot: boolean
}

// Outcome of a damage frame.
export type DamageOutcome =
  | { kind: 'applied'; grid: GridSnapshot } // commit this grid, repaint once
  | { kind: 'ignore' } // duplicate/stale — do nothing
  | { kind: 'resync'; reason: string } // drop to resync; held grid untouched

export class SyncState {
  private phase: SyncPhase = 'awaiting_baseline'
  private curGen: string | null = null
  private curRev = 0
  private readonly retired = new Set<string>()

  constructor(private readonly sessionId: string) {}

  getPhase(): SyncPhase {
    return this.phase
  }
  accepted(): { gen: string; rev: number } | null {
    return this.curGen === null ? null : { gen: this.curGen, rev: this.curRev }
  }

  // Validate + apply a Grid. On success the state advances and the caller paints; on rejection the
  // state is unchanged and the held grid keeps painting.
  onGrid(id: string, snap: GridSnapshot): { ok: GridOutcome } | { err: Reject } {
    if (id !== this.sessionId) return { err: { kind: 'wrong_session' } }
    if (this.phase === 'exited') return { err: { kind: 'session_ended' } }
    if (snap.version !== SUPPORTED_VERSION) return { err: { kind: 'unsupported_version', got: snap.version } }
    const dim = validateDimensions(snap)
    if (dim) return { err: dim }
    const wide = validateWideLayout(snap)
    if (wide) return { err: { kind: 'invalid_wide_layout', row: wide.row, col: wide.col } }
    if (!rowCopyCellsValid(snap.rows_cells, snap.row_copy)) {
      return { err: { kind: 'invalid_dimensions', reason: 'invalid row copy metadata' } }
    }

    const gen = snap.generation
    const rev = snap.revision

    if (this.retired.has(gen)) return { err: { kind: 'retired_generation' } }

    if (this.curGen !== null && this.curGen === gen) {
      if (rev < this.curRev) return { err: { kind: 'stale_revision', got: rev, have: this.curRev } }
      if (rev === this.curRev) {
        // benign duplicate of the current baseline
        return { ok: { repaint: false, request_snapshot: false } }
      }
    } else if (this.curGen !== null) {
      // a DIFFERENT, non-retired generation: the daemon rebuilt the grid (respawn). retire the old one.
      this.retired.add(this.curGen)
    }

    this.curGen = gen
    this.curRev = rev
    this.phase = 'synchronized'
    return { ok: { repaint: true, request_snapshot: false } }
  }

  // Validate + apply a damage frame against the held grid (never mutates `held`).
  onDamage(id: string, frame: DamageFrame, held: GridSnapshot): DamageOutcome {
    if (id !== this.sessionId) return { kind: 'ignore' }
    if (this.phase === 'exited') return { kind: 'resync', reason: 'session ended' }
    if (this.retired.has(frame.generation)) return { kind: 'ignore' }

    const invalid = validateDamage(frame)
    if (invalid) return { kind: 'resync', reason: `damage invalid: ${invalid}` }

    if (this.curGen === null) return { kind: 'resync', reason: 'no baseline grid held' }
    if (frame.generation !== this.curGen) return { kind: 'resync', reason: 'generation mismatch' }

    // duplicate/stale
    if (frame.revision <= this.curRev) return { kind: 'ignore' }
    // continuity gap
    if (frame.base_revision !== this.curRev) {
      return { kind: 'resync', reason: `revision gap base=${frame.base_revision} have=${this.curRev}` }
    }
    // damage never resizes
    if (frame.cols !== held.cols || frame.rows !== held.rows) {
      return { kind: 'resync', reason: 'frame geometry disagrees with held grid' }
    }

    // SCRATCH-FIRST: apply onto a deep clone; the held grid is untouched on any failure.
    const scratch = cloneGrid(held)
    const applyErr = applyOps(scratch, frame.ops)
    if (applyErr) return { kind: 'resync', reason: applyErr }

    // carry absolute post-frame cursor/modes/revision
    scratch.revision = frame.revision
    // Absent metadata clears the previous vector; it cannot describe new cells.
    scratch.row_copy = cloneRowCopy(frame.row_copy)
    scratch.base_revision = frame.base_revision
    scratch.cursor_line = frame.cursor.line
    scratch.cursor_col = frame.cursor.col
    scratch.cursor_visible = frame.cursor.visible
    scratch.cursor_shape = frame.cursor.shape
    scratch.alt_screen = frame.modes.alt_screen
    scratch.app_cursor = frame.modes.app_cursor
    scratch.bracketed_paste = frame.modes.bracketed_paste
    scratch.focus_reporting = frame.modes.focus_reporting
    scratch.mouse_report = frame.modes.mouse_report
    scratch.mouse_drag = frame.modes.mouse_drag
    scratch.mouse_motion = frame.modes.mouse_motion
    scratch.mouse_sgr = frame.modes.mouse_sgr

    const postWide = validateWideLayout(scratch)
    if (postWide) return { kind: 'resync', reason: `post-apply wide layout invalid r${postWide.row}c${postWide.col}` }
    if (!rowCopyCellsValid(scratch.rows_cells, scratch.row_copy)) return { kind: 'resync', reason: 'invalid row copy metadata' }

    this.curRev = frame.revision
    this.phase = 'synchronized'
    return { kind: 'applied', grid: scratch }
  }

  // The daemon signalled a lag; it guarantees a fresh Grid follows. We just await it.
  onResyncRequired(id: string): { ok: true } | { err: Reject } {
    if (id !== this.sessionId) return { err: { kind: 'wrong_session' } }
    if (this.phase === 'exited') return { err: { kind: 'session_ended' } }
    this.phase = 'awaiting_resync'
    return { ok: true }
  }

  onSessionExited(id: string): { ok: true } | { err: Reject } {
    if (id !== this.sessionId) return { err: { kind: 'wrong_session' } }
    this.phase = 'exited'
    return { ok: true }
  }
}

// ---- pure helpers (mirror of sync.rs free functions) ------------------------------------------------

function validateDimensions(snap: GridSnapshot): Reject | null {
  if (snap.cols === 0 || snap.rows === 0) return { kind: 'invalid_dimensions', reason: 'zero cols or rows' }
  if (snap.cols > MAX_DIMENSION || snap.rows > MAX_DIMENSION) {
    return { kind: 'invalid_dimensions', reason: 'cols or rows exceed maximum' }
  }
  if (snap.rows_cells.length !== snap.rows) return { kind: 'invalid_dimensions', reason: 'rows_cells length != rows' }
  for (const r of snap.rows_cells) {
    if (r.length !== snap.cols) return { kind: 'invalid_dimensions', reason: "a row's cell count != cols" }
  }
  return null
}

// width-2 lead must be followed by a width-0 spacer (not in last col); a width-0 spacer must be preceded
// by a width-2 lead. Any other width is a normal cell.
function validateWideLayout(snap: GridSnapshot): { row: number; col: number } | null {
  for (let rowIdx = 0; rowIdx < snap.rows_cells.length; rowIdx++) {
    const row = snap.rows_cells[rowIdx]
    let col = 0
    while (col < row.length) {
      const w = row[col].width
      if (w === 2) {
        const spacer = row[col + 1]
        if (!spacer || spacer.width !== 0) return { row: rowIdx, col }
        col += 2
      } else if (w === 0) {
        return { row: rowIdx, col }
      } else {
        col += 1
      }
    }
  }
  return null
}

function applyOps(grid: GridSnapshot, ops: DamageOp[]): string | null {
  for (const op of ops) {
    if (op.op === 'clear_all') {
      for (const row of grid.rows_cells) {
        for (let i = 0; i < row.length; i++) row[i] = cloneCell(op.cell)
      }
    } else if (op.op === 'row_span') {
      const dstRow = grid.rows_cells[op.row]
      if (!dstRow) return 'RowSpan row past held grid'
      const end = op.start + op.cells.length
      if (end > dstRow.length) return 'RowSpan span past held row width'
      for (let i = 0; i < op.cells.length; i++) dstRow[op.start + i] = cloneCell(op.cells[i])
    } else {
      // scroll_up / scroll_down
      const up = op.op === 'scroll_up'
      const err = applyScroll(grid.rows_cells, op.top, op.bottom_exclusive, op.lines, up)
      if (err) return err
    }
  }
  return null
}

// Mirror of daemon/renderer apply_scroll: forward copy for up, reverse for down; re-validate region.
function applyScroll(rows: Cell[][], top: number, bottomExclusive: number, lines: number, up: boolean): string | null {
  if (!(top < bottomExclusive && bottomExclusive <= rows.length && lines > 0) || lines > bottomExclusive - top) {
    return 'scroll region out of bounds'
  }
  if (up) {
    for (let i = top; i < bottomExclusive - lines; i++) rows[i] = rows[i + lines].map(cloneCell)
  } else {
    for (let i = bottomExclusive - 1; i >= top + lines; i--) rows[i] = rows[i - lines].map(cloneCell)
  }
  return null
}

function cloneCell(c: Cell): Cell {
  return { ...c }
}
function cloneGrid(g: GridSnapshot): GridSnapshot {
  return { ...g, rows_cells: g.rows_cells.map((row) => row.map(cloneCell)), row_copy: cloneRowCopy(g.row_copy) }
}
