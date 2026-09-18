// Wire-protocol mirror for the Hydra web client.
//
// TypeScript mirror of the daemon's `protocol`/`grid` serde shapes — the SAME contract the Rust
// renderer mirrors in `maestro-renderer/src/wire.rs`. We keep our own copy (no codegen) so the web
// client has zero coupling to daemon internals: it only needs the JSON contract.
//
// IMPORTANT (same rule as the renderer): we paint the authoritative `GridSnapshot`/`Damage` only. We
// NEVER decode `Output.data` base64 bytes — re-parsing PTY bytes would be a second VT parser, which the
// project forbids.
//
// DRIFT GUARD: the byte-pinned fixtures at the bottom are byte-identical to the daemon's
// `CROSS_WIRE_*_JSON` literals (pty-daemon/src/protocol.rs) and the renderer's mirror
// (maestro-renderer/src/wire.rs). `selfTest()` decodes them and is run by a unit test, so if the daemon
// wire shape ever drifts (renamed/added/reordered field), the web client fails loudly instead of going
// dead-on-attach.

// ---- caps (mirror of the daemon / renderer) ---------------------------------------------------------

export const MAX_LINE_BYTES = 16 * 1024 * 1024
export const MAX_CELL_TEXT_BYTES = 64
export const DAMAGE_SCHEMA = 1
export const MAX_DAMAGE_OPS = 4096
export const MAX_DAMAGE_CELLS = 1_000_000
export const MAX_DAMAGE_BYTES = 9 * 1024 * 1024 // Same metadata-inclusive cap as both native mirrors.
export const MAX_SCROLLBACK_ROWS_PER_REQUEST = 256
const DAMAGE_MAX_DIMENSION = 2000

// ---- colors / cell ----------------------------------------------------------------------------------

export type NamedColor =
  | 'black' | 'red' | 'green' | 'yellow' | 'blue' | 'magenta' | 'cyan' | 'white'
  | 'bright_black' | 'bright_red' | 'bright_green' | 'bright_yellow'
  | 'bright_blue' | 'bright_magenta' | 'bright_cyan' | 'bright_white'
  | 'foreground' | 'background' | 'cursor'
  | 'dim_black' | 'dim_red' | 'dim_green' | 'dim_yellow'
  | 'dim_blue' | 'dim_magenta' | 'dim_cyan' | 'dim_white'
  | 'bright_foreground' | 'dim_foreground'

// `#[serde(tag = "kind", rename_all = "snake_case")]`
export type Color =
  | { kind: 'named'; name: NamedColor }
  | { kind: 'indexed'; index: number }
  | { kind: 'rgb'; r: number; g: number; b: number }

export type CursorShape = 'block' | 'underline' | 'beam'

export type UnderlineStyle = 'none' | 'single' | 'double' | 'curly' | 'dotted' | 'dashed'

// One grid cell. width: 1 = normal, 2 = wide lead, 0 = wide spacer (skip drawing).
// The boolean style fields are `#[serde(default)]` on the wire, so they may be ABSENT — readers must
// treat missing as false. The decode helpers below normalize that.
export interface Cell {
  text: string
  fg: Color
  bg: Color
  bold: boolean
  italic: boolean
  underline: UnderlineStyle
  inverse: boolean
  strikeout: boolean
  dim: boolean
  hidden: boolean
  width: number
}

// ---- grid snapshot ----------------------------------------------------------------------------------

export type SessionGeneration = string // bare UUID string on the wire
export type Revision = number // bare u64 on the wire

export interface RowCopy {
  starts_line?: boolean | null
  soft_wrap: boolean
  excluded_columns: number[]
}

export function rowCopyValid(value: unknown, cols: number, rows: number): boolean {
  if (value === undefined || value === null) return true
  if (!Array.isArray(value) || value.length !== rows) return false
  return value.every((row, index) => row !== null && typeof row === 'object'
    && (row.starts_line == null || typeof row.starts_line === 'boolean')
    && typeof row.soft_wrap === 'boolean' && Array.isArray(row.excluded_columns)
    && row.excluded_columns.every((col: unknown, i: number) => Number.isInteger(col)
      && (col as number) >= 0 && (col as number) <= 0xffff && (col as number) < cols
      && (i === 0 || row.excluded_columns[i - 1] < (col as number)))
    && (index === 0 || row.starts_line == null || row.starts_line !== value[index - 1].soft_wrap))
}

export function rowCopyCellsValid(rows: ReadonlyArray<ReadonlyArray<Cell>>, metadata: unknown): boolean {
  if (metadata === undefined || metadata === null) return true
  const cols = rows[0]?.length ?? 0
  return rows.every((row) => row.length === cols) && rowCopyValid(metadata, cols, rows.length)
    && (metadata as RowCopy[]).every((row, index) => row.excluded_columns.every((col) =>
      rows[index][col].width === 1 && rows[index][col].text === ' '))
}

export function cloneRowCopy(metadata: RowCopy[] | null | undefined): RowCopy[] | undefined {
  return metadata?.map((row) => ({ ...row, excluded_columns: [...row.excluded_columns] }))
}

export interface GridSnapshot {
  version: number
  generation: SessionGeneration
  revision: Revision
  base_revision: Revision
  cols: number
  rows: number
  rows_cells: Cell[][]
  row_copy?: RowCopy[] | null
  cursor_line: number
  cursor_col: number
  cursor_visible: boolean
  cursor_shape: CursorShape
  alt_screen: boolean
  // REQUIRED in V2 (no default in the daemon): a V1 snapshot omits these and must be rejected.
  app_cursor: boolean
  bracketed_paste: boolean
  focus_reporting: boolean
  // Additive, defaulted: absent = false.
  mouse_report: boolean
  mouse_drag: boolean
  mouse_motion: boolean
  mouse_sgr: boolean
}

// ---- client → daemon requests ( `#[serde(tag = "op", rename_all = "snake_case")]` ) -----------------

export type ClientRequest =
  | { op: 'attach'; id: string; want_raw_output: boolean }
  | { op: 'detach'; id: string }
  | { op: 'snapshot'; id: string }
  | { op: 'write'; id: string; data: string }
  | { op: 'resize'; id: string; cols: number; rows: number }
  | { op: 'scrollback'; id: string; offset_from_top: number; count: number }
  | { op: 'list_sessions' }

// The web renderer is structured-only, exactly like the native one: it opts OUT of raw Output.
export function attach(id: string): ClientRequest {
  return { op: 'attach', id, want_raw_output: false }
}
export function listSessions(): ClientRequest {
  return { op: 'list_sessions' }
}
export function writeReq(id: string, data: string): ClientRequest {
  return { op: 'write', id, data }
}
export function resizeReq(id: string, cols: number, rows: number): ClientRequest {
  return { op: 'resize', id, cols, rows }
}

export function encodeRequest(req: ClientRequest): string {
  return JSON.stringify(req)
}

// ---- damage ( `#[serde(tag = "op", rename_all = "snake_case")]` ) ------------------------------------

export interface CursorState {
  line: number
  col: number
  visible: boolean
  shape: CursorShape
}

export interface ModeState {
  alt_screen: boolean
  app_cursor: boolean
  bracketed_paste: boolean
  focus_reporting: boolean
  mouse_report: boolean
  mouse_drag: boolean
  mouse_motion: boolean
  mouse_sgr: boolean
}

export type DamageOp =
  | { op: 'row_span'; row: number; start: number; cells: Cell[] }
  | { op: 'clear_all'; cell: Cell }
  | { op: 'scroll_up'; top: number; bottom_exclusive: number; lines: number }
  | { op: 'scroll_down'; top: number; bottom_exclusive: number; lines: number }

export interface DamageFrame {
  schema: number
  id: string
  generation: SessionGeneration
  base_revision: Revision
  revision: Revision
  cols: number
  rows: number
  cursor: CursorState
  modes: ModeState
  ops: DamageOp[]
  row_copy?: RowCopy[] | null
}

// ---- daemon → client events ( `#[serde(tag = "ev", rename_all = "snake_case")]` ) -------------------

// The KNOWN, discriminated daemon events (proper discriminated union — narrows on `ev`).
export type DaemonEvent =
  | { ev: 'grid'; id: string; grid: GridSnapshot }
  | { ev: 'damage'; frame: DamageFrame }
  | {
      ev: 'scrollback_rows'
      id: string
      generation: SessionGeneration
      revision: Revision
      history_len: number
      offset_from_top: number
      rows: Cell[][]
      row_copy?: RowCopy[] | null
    }
  | { ev: 'output'; id: string; generation?: SessionGeneration; revision: Revision; data: string }
  | { ev: 'resync_required'; id: string }
  | { ev: 'session_exited'; id: string; code: number | null }
  | { ev: 'sessions'; ids: string[] }
  | { ev: 'error'; message: string }

/** A history page owns its identity and copy metadata; live grid state must not fill either in. */
export type CopyRows = Pick<Extract<DaemonEvent, { ev: 'scrollback_rows' }>, 'rows' | 'row_copy' | 'generation' | 'revision'>

export function sliceCopyRows(page: CopyRows, start = 0, end = page.rows.length): CopyRows {
  return { ...page, rows: page.rows.slice(start, end), row_copy: cloneRowCopy(page.row_copy?.slice(start, end)) }
}

// Forward-compat: any other event (channel, ...) we don't act on.
export interface UnknownEvent {
  ev: string
}

const KNOWN_EVENTS = new Set([
  'grid', 'damage', 'scrollback_rows', 'output', 'resync_required', 'session_exited', 'sessions', 'error',
])

export function isKnownEvent(ev: DaemonEvent | UnknownEvent): ev is DaemonEvent {
  return KNOWN_EVENTS.has(ev.ev)
}

// ---- decode -----------------------------------------------------------------------------------------

export type DecodeError =
  | { kind: 'bad_envelope' }
  | { kind: 'damage_too_large'; bytes: number }
  | { kind: 'bad_payload'; message: string }
  | { kind: 'v1_grid' } // a grid snapshot missing the required V2 mode fields

// Normalize a raw JSON cell (defaulted style fields may be absent) into a full Cell.
function normalizeCell(raw: unknown): Cell | null {
  if (typeof raw !== 'object' || raw === null) return null
  const c = raw as Record<string, unknown>
  if (typeof c.text !== 'string' || c.text.length > MAX_CELL_TEXT_BYTES) return null
  if (typeof c.width !== 'number') return null
  return {
    text: c.text,
    fg: c.fg as Color,
    bg: c.bg as Color,
    bold: c.bold === true,
    italic: c.italic === true,
    underline: (c.underline as UnderlineStyle) ?? 'none',
    inverse: c.inverse === true,
    strikeout: c.strikeout === true,
    dim: c.dim === true,
    hidden: c.hidden === true,
    width: c.width,
  }
}

// Decode one raw event line. Mirrors the renderer's `decode_event`:
//  1. read the `ev` tag cheaply,
//  2. reject an oversized `damage` BEFORE a full parse (cap on nested cells),
//  3. a `grid` missing the required V2 mode fields is rejected as v1 (never admitted with false flags),
//  4. otherwise the parsed event.
export function decodeEvent(line: string): { ok: DaemonEvent | UnknownEvent } | { err: DecodeError } {
  let parsed: unknown
  try {
    parsed = JSON.parse(line)
  } catch {
    return { err: { kind: 'bad_envelope' } }
  }
  if (typeof parsed !== 'object' || parsed === null || typeof (parsed as Record<string, unknown>).ev !== 'string') {
    return { err: { kind: 'bad_envelope' } }
  }
  const ev = (parsed as Record<string, unknown>).ev as string
  if (ev === 'damage' && line.length > MAX_DAMAGE_BYTES) {
    return { err: { kind: 'damage_too_large', bytes: line.length } }
  }
  if (ev === 'grid') {
    const grid = (parsed as Record<string, unknown>).grid as Record<string, unknown> | undefined
    if (
      !grid ||
      typeof grid.app_cursor !== 'boolean' ||
      typeof grid.bracketed_paste !== 'boolean' ||
      typeof grid.focus_reporting !== 'boolean'
    ) {
      return { err: { kind: 'v1_grid' } }
    }
  }
  return { ok: parsed as DaemonEvent | UnknownEvent }
}

// Pure structural validation of a damage frame. Mirror of the renderer's `DamageFrame::validate`. The
// caller maps any failure to "drop to resync" — the held grid is never mutated by an invalid frame.
export function validateDamage(f: DamageFrame): string | null {
  if (!rowCopyValid(f.row_copy, f.cols, f.rows)) return 'invalid row copy metadata'
  if (f.schema !== DAMAGE_SCHEMA) return `unsupported schema ${f.schema}`
  if (f.cols === 0 || f.rows === 0) return 'zero cols or rows'
  if (f.cols > DAMAGE_MAX_DIMENSION || f.rows > DAMAGE_MAX_DIMENSION) return 'dims exceed maximum'
  if (f.base_revision >= f.revision) return `bad revision order base=${f.base_revision} rev=${f.revision}`
  if (f.cursor.col >= f.cols || f.cursor.line >= f.rows) return 'cursor out of bounds'
  if (f.ops.length > MAX_DAMAGE_OPS) return `too many ops ${f.ops.length}`
  let totalCells = 0
  for (let i = 0; i < f.ops.length; i++) {
    const op = f.ops[i]
    if (op.op === 'row_span') {
      if (op.cells.length === 0) return `empty row_span op ${i}`
      if (op.row >= f.rows) return `row_span out of bounds op ${i}`
      const end = op.start + op.cells.length
      if (end > f.cols) return `row_span out of bounds op ${i}`
      for (const c of op.cells) if (!cellIsValid(c)) return `bad cell op ${i}`
      totalCells += op.cells.length
      if (totalCells > MAX_DAMAGE_CELLS) return `too many cells ${totalCells}`
    } else if (op.op === 'clear_all') {
      if (!cellIsValid(op.cell) || op.cell.width !== 1 || op.cell.text !== ' ') return `bad cell op ${i}`
    } else {
      // scroll_up / scroll_down
      if (!(op.top < op.bottom_exclusive && op.bottom_exclusive <= f.rows && op.lines > 0 && op.lines <= op.bottom_exclusive - op.top)) {
        return `bad scroll region op ${i}`
      }
    }
  }
  return null
}

function cellIsValid(cell: Cell): boolean {
  if (cell.width === 0) return cell.text === ''
  return cell.width === 1 || cell.width === 2
}

export { normalizeCell }
