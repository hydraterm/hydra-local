// Drift guard for the TS wire mirror.
//
// The three CROSS_WIRE_*_JSON literals below are BYTE-IDENTICAL to the daemon's
// `CROSS_WIRE_*_JSON` (pty-daemon/src/protocol.rs) and the renderer's mirror
// (maestro-renderer/src/wire.rs). The daemon's own tests prove it emits exactly these bytes; these
// tests prove the web client decodes them. If the daemon wire shape drifts (renamed/added/reordered
// field), these decode assertions fail loudly — the web client can't go silently dead-on-attach.
//
// Keep all three literals in lockstep with the Rust copies.

import { describe, expect, it } from 'vitest'
import {
  decodeEvent,
  validateDamage,
  type DaemonEvent,
  type DamageFrame,
  type GridSnapshot,
} from './web-protocol'

const CROSS_WIRE_GRID_JSON =
  '{"ev":"grid","id":"s1","grid":{"version":2,"generation":"11111111-1111-1111-1111-111111111111","revision":5,"base_revision":4,"cols":3,"rows":1,"rows_cells":[[{"text":"界","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":2},{"text":"","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":0},{"text":"x","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":1}]],"cursor_line":0,"cursor_col":2,"cursor_visible":true,"cursor_shape":"beam","alt_screen":true,"app_cursor":true,"bracketed_paste":true,"focus_reporting":true,"mouse_report":true,"mouse_drag":true,"mouse_motion":true,"mouse_sgr":true}}'

const CROSS_WIRE_DAMAGE_JSON =
  '{"ev":"damage","frame":{"schema":1,"id":"s1","generation":"11111111-1111-1111-1111-111111111111","base_revision":4,"revision":5,"cols":10,"rows":4,"cursor":{"line":1,"col":2,"visible":true,"shape":"block"},"modes":{"alt_screen":false,"app_cursor":true,"bracketed_paste":false,"focus_reporting":true,"mouse_report":false,"mouse_drag":false,"mouse_motion":false,"mouse_sgr":false},"ops":[{"op":"row_span","row":1,"start":2,"cells":[{"text":"a","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":1}]},{"op":"clear_all","cell":{"text":" ","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":1}}]}}'

const CROSS_WIRE_SCROLLBACK_JSON =
  '{"ev":"scrollback_rows","id":"s1","generation":"11111111-1111-1111-1111-111111111111","revision":7,"history_len":5000,"offset_from_top":3,"rows":[[{"text":"a","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":1}]]}'

describe('cross-wire decode (drift guard vs daemon bytes)', () => {
  it('decodes the canonical Grid and every field survives', () => {
    const r = decodeEvent(CROSS_WIRE_GRID_JSON)
    expect('ok' in r).toBe(true)
    const ev = (r as { ok: DaemonEvent }).ok
    expect(ev.ev).toBe('grid')
    const g = (ev as { ev: 'grid'; grid: GridSnapshot }).grid
    expect(g.version).toBe(2)
    expect(g.generation).toBe('11111111-1111-1111-1111-111111111111')
    expect(g.revision).toBe(5)
    expect(g.base_revision).toBe(4)
    expect(g.cols).toBe(3)
    expect(g.rows).toBe(1)
    expect(g.rows_cells).toHaveLength(1)
    expect(g.rows_cells[0]).toHaveLength(3)
    // wide pair: width-2 lead then width-0 spacer
    expect(g.rows_cells[0][0].width).toBe(2)
    expect(g.rows_cells[0][1].width).toBe(0)
    expect(g.cursor_col).toBe(2)
    expect(g.cursor_shape).toBe('beam')
    // all mode + mouse flags true on the wire — a dropped/renamed field would not be true here
    expect(g.alt_screen).toBe(true)
    expect(g.app_cursor).toBe(true)
    expect(g.bracketed_paste).toBe(true)
    expect(g.focus_reporting).toBe(true)
    expect(g.mouse_report).toBe(true)
    expect(g.mouse_drag).toBe(true)
    expect(g.mouse_motion).toBe(true)
    expect(g.mouse_sgr).toBe(true)
  })

  it('decodes the canonical Damage and it validates', () => {
    const r = decodeEvent(CROSS_WIRE_DAMAGE_JSON)
    expect('ok' in r).toBe(true)
    const ev = (r as { ok: DaemonEvent }).ok
    expect(ev.ev).toBe('damage')
    const f = (ev as { ev: 'damage'; frame: DamageFrame }).frame
    expect(f.schema).toBe(1)
    expect(f.id).toBe('s1')
    expect(f.base_revision).toBe(4)
    expect(f.revision).toBe(5)
    expect(f.cols).toBe(10)
    expect(f.rows).toBe(4)
    expect(f.cursor.line).toBe(1)
    expect(f.cursor.col).toBe(2)
    expect(f.modes.app_cursor).toBe(true)
    expect(f.modes.focus_reporting).toBe(true)
    expect(f.ops).toHaveLength(2)
    expect(validateDamage(f)).toBeNull()
  })

  it('decodes the canonical ScrollbackRows', () => {
    const r = decodeEvent(CROSS_WIRE_SCROLLBACK_JSON)
    expect('ok' in r).toBe(true)
    const ev = (r as { ok: DaemonEvent }).ok
    expect(ev.ev).toBe('scrollback_rows')
    const sb = ev as Extract<DaemonEvent, { ev: 'scrollback_rows' }>
    expect(sb.id).toBe('s1')
    expect(sb.revision).toBe(7)
    expect(sb.history_len).toBe(5000)
    expect(sb.offset_from_top).toBe(3)
    expect(sb.rows).toHaveLength(1)
    expect(sb.rows[0]).toHaveLength(1)
    expect(sb.rows[0][0].text).toBe('a')
  })
})

describe('v1 grid rejection (security: no false mode flags)', () => {
  it('rejects a grid missing the required V2 mode fields', () => {
    // canonical grid with the three V2 mode fields stripped — a V1-shaped snapshot
    const v1 = CROSS_WIRE_GRID_JSON.replace('"app_cursor":true,"bracketed_paste":true,"focus_reporting":true,', '')
    expect(v1).not.toBe(CROSS_WIRE_GRID_JSON)
    const r = decodeEvent(v1)
    expect('err' in r).toBe(true)
    expect((r as { err: { kind: string } }).err.kind).toBe('v1_grid')
  })
})

describe('framing guards', () => {
  it('reports a bad envelope', () => {
    expect((decodeEvent('not json') as { err: { kind: string } }).err.kind).toBe('bad_envelope')
    expect((decodeEvent('{"foo":1}') as { err: { kind: string } }).err.kind).toBe('bad_envelope')
  })

  it('validateDamage rejects a bad schema / backwards revision', () => {
    const base = (decodeEvent(CROSS_WIRE_DAMAGE_JSON) as { ok: DaemonEvent }).ok as {
      ev: 'damage'
      frame: DamageFrame
    }
    expect(validateDamage({ ...base.frame, schema: 99 })).toContain('unsupported schema')
    expect(validateDamage({ ...base.frame, base_revision: 9, revision: 5 })).toContain('bad revision order')
  })
})
