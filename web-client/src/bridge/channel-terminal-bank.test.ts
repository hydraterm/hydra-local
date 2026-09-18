import { describe, it, expect } from 'vitest'
import { ChannelTerminalBank, type TerminalPaneRenderer } from './channel-terminal-bank'
import type { Cell, DamageFrame, GridSnapshot } from '../protocol/web-protocol'

function cell(text = ' '): Cell {
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

function grid(sessionId: string, text: string, revision = 1): GridSnapshot {
  return {
    version: 2,
    generation: `gen-${sessionId}`,
    revision,
    base_revision: Math.max(0, revision - 1),
    cols: 1,
    rows: 1,
    rows_cells: [[cell(text)]],
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

function damage(sessionId: string, text: string, base = 1, revision = 2): DamageFrame {
  return {
    schema: 1,
    id: sessionId,
    generation: `gen-${sessionId}`,
    base_revision: base,
    revision,
    cols: 1,
    rows: 1,
    cursor: { line: 0, col: 0, visible: true, shape: 'block' },
    modes: {
      alt_screen: false,
      app_cursor: false,
      bracketed_paste: false,
      focus_reporting: false,
      mouse_report: false,
      mouse_drag: false,
      mouse_motion: false,
      mouse_sgr: false,
    },
    ops: [{ op: 'row_span', row: 0, start: 0, cells: [cell(text)] }],
  }
}

function line(sessionId: string, event: unknown) {
  return { channel: sessionId === 's-a' ? 1 : 2, sessionId, line: JSON.stringify(event) }
}

class FakeRenderer implements TerminalPaneRenderer {
  paints: string[] = []
  sizes: [number, number][] = []
  highlightCounts: number[] = [] // spans passed to each paint
  grids: GridSnapshot[] = [] // full snapshots passed to each paint (for scrollback assertions)
  resizeForGrid(cols: number, rows: number): void {
    this.sizes.push([cols, rows])
  }
  paint(g: GridSnapshot, highlights: readonly { row: number }[] = []): void {
    this.paints.push(g.rows_cells[0]?.[0]?.text ?? '')
    this.highlightCounts.push(highlights.length)
    this.grids.push(g)
  }
}

describe('ChannelTerminalBank', () => {
  it('retains history metadata with its own revision and dimensions, rejects corruption, and clears absence', () => {
    const bank = new ChannelTerminalBank()
    const renderer = new FakeRenderer()
    bank.bindSession('s-a', renderer)
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'L', 40) }))
    bank.scrollBy('s-a', 2)
    const row_copy = [{ starts_line: null, soft_wrap: true, excluded_columns: [1] },
      { starts_line: false, soft_wrap: false, excluded_columns: [] }]
    const reply = { ev: 'scrollback_rows', id: 's-a', generation: 'gen-s-a', revision: 7,
      history_len: 20, offset_from_top: 2, rows: [[cell('h'), cell()], [cell('i'), cell()]], row_copy }
    bank.handle(line('s-a', reply))
    expect(renderer.grids.at(-1)).toMatchObject({ cols: 2, rows: 1, revision: 7, row_copy: [row_copy[0]] })
    bank.scrollBy('s-a', -1)
    expect(renderer.grids.at(-1)).toMatchObject({ revision: 7, row_copy: [row_copy[1]] })
    const count = renderer.grids.length
    bank.handle(line('s-a', { ...reply, row_copy: [null] }))
    expect(renderer.grids.length).toBe(count)
    bank.handle(line('s-a', { ...reply, row_copy: undefined }))
    expect(renderer.grids.at(-1)?.row_copy).toBeUndefined()
  })

  it('keeps the ordinary disabled-metrics path free of clock/timing work', () => {
    let clockCalls = 0
    const bank = new ChannelTerminalBank(() => {
      clockCalls++
      return 1
    })
    bank.bindSession('s-a', new FakeRenderer())
    expect(bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'A') }))).toMatchObject({
      kind: 'painted',
    })
    expect(clockCalls).toBe(0)
  })

  it('routes grids to each session renderer independently', () => {
    const bank = new ChannelTerminalBank()
    const a = new FakeRenderer()
    const b = new FakeRenderer()
    bank.bindSession('s-a', a)
    bank.bindSession('s-b', b)

    expect(bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'A') }))).toEqual({ kind: 'painted', sessionId: 's-a' })
    expect(bank.handle(line('s-b', { ev: 'grid', id: 's-b', grid: grid('s-b', 'B') }))).toEqual({ kind: 'painted', sessionId: 's-b' })

    expect(a.paints).toEqual(['A'])
    expect(b.paints).toEqual(['B'])
    expect(a.sizes).toEqual([[1, 1]])
    expect(b.sizes).toEqual([[1, 1]])
  })

  it('damage for one session does not touch the other renderer state', () => {
    const bank = new ChannelTerminalBank()
    const a = new FakeRenderer()
    const b = new FakeRenderer()
    bank.bindSession('s-a', a)
    bank.bindSession('s-b', b)
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'A') }))
    bank.handle(line('s-b', { ev: 'grid', id: 's-b', grid: grid('s-b', 'B') }))

    expect(bank.handle(line('s-a', { ev: 'damage', frame: damage('s-a', 'Z') }))).toEqual({ kind: 'painted', sessionId: 's-a' })

    expect(a.paints).toEqual(['A', 'Z'])
    expect(b.paints).toEqual(['B'])
  })

  it('wrong-session events are ignored by that pane sync state', () => {
    const bank = new ChannelTerminalBank()
    const a = new FakeRenderer()
    bank.bindSession('s-a', a)

    expect(bank.handle(line('s-a', { ev: 'grid', id: 's-b', grid: grid('s-b', 'B') }))).toEqual({
      kind: 'ignored',
      sessionId: 's-a',
      reason: 'wrong_session',
    })
    expect(a.paints).toEqual([])
  })

  it('rejects a cross-session scrollback reply before it mutates or paints the bound pane', () => {
    const bank = new ChannelTerminalBank()
    const a = new FakeRenderer()
    bank.bindSession('s-a', a)
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'A') }))
    bank.scrollBy('s-a', 2)

    expect(bank.handle(line('s-a', {
      ev: 'scrollback_rows',
      id: 's-b',
      generation: 'gen-s-a',
      revision: 2,
      history_len: 10,
      offset_from_top: 2,
      rows: [[cell('B')]],
    }))).toEqual({ kind: 'ignored', sessionId: 's-a', reason: 'wrong_session' })
    expect(a.paints).toEqual(['A'])
  })

  it('damage before a baseline requests resync for only that session', () => {
    const bank = new ChannelTerminalBank()
    bank.bindSession('s-a', new FakeRenderer())
    bank.bindSession('s-b', new FakeRenderer())

    expect(bank.handle(line('s-a', { ev: 'damage', frame: damage('s-a', 'x') }))).toEqual({
      kind: 'resync',
      sessionId: 's-a',
      reason: 'damage before grid',
    })
    expect(bank.hasSession('s-b')).toBe(true)
  })

  it('late renderer attachment repaints the held grid', () => {
    const bank = new ChannelTerminalBank()
    bank.bindSession('s-a')
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'A') }))

    const renderer = new FakeRenderer()
    bank.attachRenderer('s-a', renderer)
    expect(renderer.paints).toEqual(['A'])
  })

  it('unbind removes a session and future lines for it are ignored', () => {
    const bank = new ChannelTerminalBank()
    const renderer = new FakeRenderer()
    bank.bindSession('s-a', renderer)
    expect(bank.sessionCount).toBe(1)
    bank.unbindSession('s-a')
    expect(bank.sessionCount).toBe(0)

    expect(bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'A') }))).toEqual({
      kind: 'ignored',
      sessionId: 's-a',
      reason: 'unbound session',
    })
    expect(renderer.paints).toEqual([])
  })

  it('session_exited marks only that session result as exited', () => {
    const bank = new ChannelTerminalBank()
    bank.bindSession('s-a', new FakeRenderer())
    bank.bindSession('s-b', new FakeRenderer())

    expect(bank.handle(line('s-a', { ev: 'session_exited', id: 's-a', code: 0 }))).toEqual({
      kind: 'exited',
      sessionId: 's-a',
    })
    expect(bank.hasSession('s-b')).toBe(true)
  })
})

describe('ChannelTerminalBank — grid observer (pane-local search feed)', () => {
  it('notifies the observer with each session\'s painted grid (grid + damage), keyed by session', () => {
    const bank = new ChannelTerminalBank()
    const seen: [string, string][] = [] // [sessionId, first cell text] for a content-blind assert
    bank.setGridObserver((sid, g) => seen.push([sid, g.rows_cells[0]?.[0]?.text ?? '']))
    bank.bindSession('s-a')
    bank.bindSession('s-b')

    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'A') }))
    bank.handle(line('s-b', { ev: 'grid', id: 's-b', grid: grid('s-b', 'B') }))
    bank.handle(line('s-a', { ev: 'damage', id: 's-a', frame: damage('s-a', 'X') }))

    expect(seen).toEqual([['s-a', 'A'], ['s-b', 'B'], ['s-a', 'X']])
  })

  it('does NOT notify on ignored/duplicate frames', () => {
    const bank = new ChannelTerminalBank()
    let calls = 0
    bank.setGridObserver(() => { calls++ })
    bank.bindSession('s-a')
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'A') }))        // painted → 1
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'A') }))        // duplicate → no
    bank.handle(line('s-unbound', { ev: 'grid', id: 's-unbound', grid: grid('s-unbound', 'Z') })) // ignored → no
    expect(calls).toBe(1)
  })

  it('unsubscribes when set to null', () => {
    const bank = new ChannelTerminalBank()
    let calls = 0
    bank.setGridObserver(() => { calls++ })
    bank.bindSession('s-a')
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'A') }))
    bank.setGridObserver(null)
    bank.handle(line('s-a', { ev: 'damage', id: 's-a', frame: damage('s-a', 'Y') }))
    expect(calls).toBe(1) // only the pre-unsubscribe paint
  })
})

describe('ChannelTerminalBank — pane search highlights', () => {
  it('setSearchHighlights repaints the held grid with the spans (drawn under glyphs)', () => {
    const bank = new ChannelTerminalBank()
    const r = new FakeRenderer()
    bank.bindSession('s-a', r)
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'A') })) // initial paint, 0 highlights
    bank.setSearchHighlights('s-a', [{ row: 0, startCol: 0, endCol: 1, active: true }])
    expect(r.highlightCounts).toEqual([0, 1]) // repainted once more, now with 1 span
    // a fresh grid keeps the standing highlights
    bank.handle(line('s-a', { ev: 'damage', id: 's-a', frame: damage('s-a', 'B') }))
    expect(r.highlightCounts.at(-1)).toBe(1)
  })

  it('setSearchHighlights is a no-op for an unbound session', () => {
    const bank = new ChannelTerminalBank()
    expect(() => bank.setSearchHighlights('ghost', [{ row: 0, startCol: 0, endCol: 1, active: true }])).not.toThrow()
  })

  it('paints Grid/Damage once across production-style highlight re-entry and keeps user updates immediate', () => {
    const bank = new ChannelTerminalBank()
    const renderer = new FakeRenderer()
    bank.bindSession('s-a', renderer)
    // Mirrors the live chain: holdGrid -> grid observer -> fresh-but-equal highlight publication.
    bank.setGridObserver(() => bank.setSearchHighlights('s-a', []))

    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'A') }))
    bank.handle(line('s-a', { ev: 'damage', frame: damage('s-a', 'B') }))
    expect(renderer.paints).toEqual(['A', 'B'])

    const selected = [{ row: 0, startCol: 0, endCol: 1, active: true }] as const
    bank.setSearchHighlights('s-a', selected)
    expect(renderer.paints).toEqual(['A', 'B', 'B'])
    expect(renderer.highlightCounts).toEqual([0, 0, 1])
    bank.setSearchHighlights('s-a', [{ ...selected[0] }])
    expect(renderer.paints).toEqual(['A', 'B', 'B']) // structurally identical is a no-op

    bank.attachRenderer('s-a', renderer)
    bank.bindSession('s-a', null)
    expect(renderer.paints).toEqual(['A', 'B', 'B']) // same renderer / absent replacement is idempotent
    const replacement = new FakeRenderer()
    bank.attachRenderer('s-a', replacement)
    expect(replacement.paints).toEqual(['B'])
    expect(replacement.highlightCounts).toEqual([1])
  })

  it('paints a scrollback_rows page (history) to the pane renderer, cursor hidden', () => {
    const bank = new ChannelTerminalBank()
    const r = new FakeRenderer()
    bank.bindSession('s-a', r)
    // live grid first so the pane has a held width to derive cols from.
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'L') }))
    expect(r.paints).toEqual(['L'])
    // the user must be SCROLLED UP (viewOffset>0) for a history reply to apply (local-parity is-scrolled guard).
    bank.scrollBy('s-a', 3)

    // a scrollback reply (matching the held grid's generation) → paints history rows to THIS pane's renderer.
    const historyRows = [[cell('H')]]
    const res = bank.handle(line('s-a', {
      ev: 'scrollback_rows',
      id: 's-a',
      generation: 'gen-s-a',
      revision: 5,
      history_len: 42,
      offset_from_top: 3,
      rows: historyRows,
    }))
    expect(res).toEqual({ kind: 'painted', sessionId: 's-a' })
    expect(r.paints).toEqual(['L', 'H']) // history row painted
    const painted = r.grids.at(-1)!
    expect(painted.rows_cells).toEqual(historyRows)
    expect(painted.cursor_visible).toBe(false) // view-only page: no cursor over history
    expect(painted.rows).toBe(1)
    expect(painted.cols).toBe(1) // derived from the held live grid
  })

  it('scrollback_rows at offset 0 repaints the held live grid (jump to live)', () => {
    const bank = new ChannelTerminalBank()
    const r = new FakeRenderer()
    bank.bindSession('s-a', r)
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'L') }))
    r.paints.length = 0
    r.grids.length = 0
    const res = bank.handle(line('s-a', {
      ev: 'scrollback_rows',
      id: 's-a',
      generation: 'gen-s-a',
      revision: 6,
      history_len: 42,
      offset_from_top: 0,
      rows: [],
    }))
    expect(res).toEqual({ kind: 'painted', sessionId: 's-a' })
    expect(r.paints).toEqual(['L']) // held live grid repainted, not the empty history page
    expect(r.grids.at(-1)!.cursor_visible).toBe(true)
  })

  it('scrollback_rows for one session does not paint another session renderer', () => {
    const bank = new ChannelTerminalBank()
    const a = new FakeRenderer()
    const b = new FakeRenderer()
    bank.bindSession('s-a', a)
    bank.bindSession('s-b', b)
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'A') }))
    bank.handle(line('s-b', { ev: 'grid', id: 's-b', grid: grid('s-b', 'B') }))
    bank.scrollBy('s-a', 2) // s-a scrolled up so its history reply applies (is-scrolled guard)
    a.paints.length = 0
    b.paints.length = 0
    bank.handle(line('s-a', {
      ev: 'scrollback_rows', id: 's-a', generation: 'gen-s-a', revision: 5,
      history_len: 10, offset_from_top: 2, rows: [[cell('H')]],
    }))
    expect(a.paints).toEqual(['H'])
    expect(b.paints).toEqual([]) // s-b untouched
  })

  it('paneModes reflects the last live grid modes, or null before any paint', () => {
    const bank = new ChannelTerminalBank()
    bank.bindSession('s-a')
    expect(bank.paneModes('s-a')).toBeNull() // no grid yet
    const g = grid('s-a', 'A')
    g.app_cursor = true
    g.bracketed_paste = true
    g.focus_reporting = false
    g.mouse_report = true
    g.mouse_sgr = true
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: g }))
    expect(bank.paneModes('s-a')).toEqual({
      app_cursor: true, bracketed_paste: true, focus_reporting: false,
      mouse_report: true, mouse_drag: false, mouse_motion: false, mouse_sgr: true,
    })
    expect(bank.paneModes('ghost')).toBeNull()
  })

  it('gridBounds returns the last painted grid size, or null before any paint', () => {
    const bank = new ChannelTerminalBank()
    bank.bindSession('s-a')
    expect(bank.gridBounds('s-a')).toBeNull()
    const g = grid('s-a', 'A')
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: g }))
    expect(bank.gridBounds('s-a')).toEqual({ rows: g.rows, cols: g.cols })
    expect(bank.gridBounds('ghost')).toBeNull()
  })
})

describe('ChannelTerminalBank — per-pane scroll (scrollBy / jumpToLive / viewOffsetFor)', () => {
  it('replays pinned history once on a new renderer after live Damage invalidates the offset cache', () => {
    const bank = new ChannelTerminalBank()
    const first = new FakeRenderer()
    bank.bindSession('s-a', first)
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'L') }))
    bank.scrollBy('s-a', 1)
    bank.handle(line('s-a', {
      ev: 'scrollback_rows', id: 's-a', generation: 'gen-s-a', revision: 1,
      history_len: 4, offset_from_top: 1, rows: [[cell('H')]],
    }))
    expect(first.paints).toEqual(['L', 'H'])

    bank.handle(line('s-a', { ev: 'damage', frame: damage('s-a', 'N') }))
    expect(bank.viewOffsetFor('s-a')).toBe(1)
    expect(first.paints).toEqual(['L', 'H']) // live stays underneath the pinned history viewport

    bank.attachRenderer('s-a', first)
    bank.bindSession('s-a', null)
    expect(first.paints).toEqual(['L', 'H'])
    const replacement = new FakeRenderer()
    bank.attachRenderer('s-a', replacement)
    expect(replacement.paints).toEqual(['H'])
    expect(replacement.grids[0]?.cursor_visible).toBe(false)
  })

  it('does not let a re-entrant highlight refresh paint a same-generation live Grid over history', () => {
    const bank = new ChannelTerminalBank()
    const r = new FakeRenderer()
    bank.bindSession('s-a', r)
    // Mirrors the production callback chain:
    // holdGrid -> gridObserver -> search refresh -> setSearchHighlights.
    bank.setGridObserver(() => bank.setSearchHighlights('s-a', []))
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'L') }))
    bank.scrollBy('s-a', 1)
    bank.handle(line('s-a', {
      ev: 'scrollback_rows', id: 's-a', generation: 'gen-s-a', revision: 1,
      history_len: 4, offset_from_top: 1, rows: [[cell('H')]],
    }))
    expect(r.paints.at(-1)).toBe('H')
    r.paints.length = 0

    const result = bank.handle(line('s-a', {
      ev: 'grid', id: 's-a', grid: grid('s-a', 'N', 2),
    }))

    expect(result).toEqual({ kind: 'ignored', sessionId: 's-a', reason: 'held-while-scrolled' })
    expect(bank.viewOffsetFor('s-a')).toBe(1)
    expect(r.paints).toEqual([])
  })

  it('does not let a re-entrant highlight refresh paint live Damage over history', () => {
    const bank = new ChannelTerminalBank()
    const r = new FakeRenderer()
    bank.bindSession('s-a', r)
    bank.setGridObserver(() => bank.setSearchHighlights('s-a', []))
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'L') }))
    bank.scrollBy('s-a', 1)
    bank.handle(line('s-a', {
      ev: 'scrollback_rows', id: 's-a', generation: 'gen-s-a', revision: 1,
      history_len: 4, offset_from_top: 1, rows: [[cell('H')]],
    }))
    expect(r.paints.at(-1)).toBe('H')
    r.paints.length = 0

    const result = bank.handle(line('s-a', { ev: 'damage', frame: damage('s-a', 'N') }))

    expect(result).toEqual({ kind: 'ignored', sessionId: 's-a', reason: 'held-while-scrolled' })
    expect(bank.viewOffsetFor('s-a')).toBe(1)
    expect(r.paints).toEqual([])
  })

  it('caches a live-view warm reply so the first upward scroll paints without a request', () => {
    const bank = new ChannelTerminalBank()
    const r = new FakeRenderer()
    const replies: Array<[string, number, boolean]> = []
    bank.setScrollbackReplyObserver((sessionId, offset, accepted) => replies.push([sessionId, offset, accepted]))
    bank.bindSession('s-a', r)
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'L') }))
    bank.handle(line('s-a', {
      ev: 'scrollback_rows', id: 's-a', generation: 'gen-s-a', revision: 5,
      history_len: 4, offset_from_top: 4,
      rows: [[cell('4')], [cell('3')], [cell('2')], [cell('1')]],
    }))
    r.paints.length = 0

    expect(bank.scrollBy('s-a', 1)).toBeNull() // null = served locally; caller sends no wire request
    expect(bank.viewOffsetFor('s-a')).toBe(1)
    expect(r.paints).toEqual(['1'])
    expect(replies).toEqual([['s-a', 4, true]])
  })

  it('does not treat a partial cached slice as a complete viewport', () => {
    const bank = new ChannelTerminalBank()
    const r = new FakeRenderer()
    bank.bindSession('s-a', r)
    const live = grid('s-a', 'L')
    live.cols = 2
    live.rows = 3
    live.rows_cells = [
      [cell('L'), cell('1')],
      [cell('L'), cell('2')],
      [cell('L'), cell('3')],
    ]
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: live }))
    bank.handle(line('s-a', {
      ev: 'scrollback_rows', id: 's-a', generation: 'gen-s-a', revision: 5,
      history_len: 4, offset_from_top: 4,
      rows: [[cell('4')], [cell('3')], [cell('2')], [cell('1')]],
    }))
    r.grids.length = 0
    r.sizes.length = 0

    expect(bank.scrollBy('s-a', 1)).toBe(1)
    expect(bank.scrollbackRequestOffset('s-a')).toBe(1)
    expect(r.grids).toEqual([])
    expect(r.sizes).toEqual([])
  })

  it('does not enter history when the viewport exceeds one protocol page', () => {
    const bank = new ChannelTerminalBank()
    const r = new FakeRenderer()
    bank.bindSession('s-a', r)
    const tall = grid('s-a', 'A')
    tall.rows = 257
    tall.rows_cells = Array.from({ length: 257 }, () => [cell('A')])
    bank.handle({ channel: 1, sessionId: 's-a', line: JSON.stringify({ ev: 'grid', id: 's-a', grid: tall }) })

    expect(bank.scrollBy('s-a', 20)).toBeNull()
    expect(bank.viewOffsetFor('s-a')).toBe(0)
  })

  it('returns to the live Grid when a resize makes an already-scrolled viewport exceed one page', () => {
    const bank = new ChannelTerminalBank()
    const r = new FakeRenderer()
    bank.bindSession('s-a', r)
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'L') }))
    expect(bank.scrollBy('s-a', 1)).toBe(1)
    expect(bank.viewOffsetFor('s-a')).toBe(1)

    const tall = grid('s-a', 'N', 2)
    tall.rows = 257
    tall.rows_cells = Array.from({ length: 257 }, () => [cell('N')])
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: tall }))

    expect(bank.viewOffsetFor('s-a')).toBe(0)
    expect(bank.scrollbackRequestOffset('s-a')).toBeNull()
    expect(r.paints.at(-1)).toBe('N')
  })

  it('retains the live warm page across ordinary damage so first upward scroll stays local', () => {
    const bank = new ChannelTerminalBank()
    const r = new FakeRenderer()
    bank.bindSession('s-a', r)
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'L') }))
    bank.handle(line('s-a', {
      ev: 'scrollback_rows', id: 's-a', generation: 'gen-s-a', revision: 5,
      history_len: 4, offset_from_top: 4,
      rows: [[cell('4')], [cell('3')], [cell('2')], [cell('1')]],
    }))

    bank.handle(line('s-a', { ev: 'damage', frame: damage('s-a', 'N') }))
    r.paints.length = 0
    expect(bank.scrollBy('s-a', 1)).toBeNull()
    expect(r.paints).toEqual(['1'])
  })

  it('scrollBy advances the pane viewOffset UP into history and returns the offset to request', () => {
    const bank = new ChannelTerminalBank()
    bank.bindSession('s-a', new FakeRenderer())
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'L') }))
    expect(bank.viewOffsetFor('s-a')).toBe(0)
    // wheel up (positive delta = UP into history). historyLen unknown (0) → first request may fire.
    expect(bank.scrollBy('s-a', 5)).toBe(5)
    expect(bank.viewOffsetFor('s-a')).toBe(5)
    expect(bank.scrollBy('s-a', 3)).toBe(8) // accumulates
    expect(bank.viewOffsetFor('s-a')).toBe(8)
  })

  it('keeps the latest desired offset when an older in-flight reply arrives', () => {
    const bank = new ChannelTerminalBank()
    const r = new FakeRenderer()
    bank.bindSession('s-a', r)
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'L') }))
    expect(bank.scrollBy('s-a', 3)).toBe(3)
    expect(bank.scrollBy('s-a', 2)).toBe(5)
    r.paints.length = 0

    const result = bank.handle(line('s-a', {
      ev: 'scrollback_rows', id: 's-a', generation: 'gen-s-a', revision: 5,
      history_len: 100, offset_from_top: 3, rows: [[cell('3')]],
    }))

    expect(result).toEqual({ kind: 'ignored', sessionId: 's-a', reason: 'scrollback cache fill' })
    expect(bank.viewOffsetFor('s-a')).toBe(5)
    expect(bank.scrollbackRequestOffset('s-a')).toBe(5)
    expect(r.paints).toEqual([])
  })

  it('scrollBy clamps to historyLen once the pane learns it from a reply', () => {
    const bank = new ChannelTerminalBank()
    bank.bindSession('s-a', new FakeRenderer())
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'L') }))
    bank.scrollBy('s-a', 4) // user scrolls up first (real flow) so the reply applies
    // a scrollback reply teaches historyLen=10 and echoes viewOffset=4
    bank.handle(line('s-a', {
      ev: 'scrollback_rows', id: 's-a', generation: 'gen-s-a', revision: 5,
      history_len: 10, offset_from_top: 4, rows: [[cell('H')]],
    }))
    expect(bank.viewOffsetFor('s-a')).toBe(4)
    // scrolling up by 100 clamps at historyLen (10), not 104
    expect(bank.scrollBy('s-a', 100)).toBe(10)
    expect(bank.viewOffsetFor('s-a')).toBe(10)
  })

  it('scrollBy returns null on a no-op (offset unchanged) and for an unbound session', () => {
    const bank = new ChannelTerminalBank()
    bank.bindSession('s-a', new FakeRenderer())
    // already at live (0); scrolling DOWN (negative) clamps at 0 → no change → null
    expect(bank.scrollBy('s-a', -3)).toBeNull()
    expect(bank.viewOffsetFor('s-a')).toBe(0)
    // unbound session
    expect(bank.scrollBy('ghost', 5)).toBeNull()
  })

  it('scrollBy back down to 0 returns 0 (jump-to-live signal), not null', () => {
    const bank = new ChannelTerminalBank()
    bank.bindSession('s-a', new FakeRenderer())
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'L') }))
    bank.scrollBy('s-a', 4) // scroll up first so the reply applies
    bank.handle(line('s-a', {
      ev: 'scrollback_rows', id: 's-a', generation: 'gen-s-a', revision: 5,
      history_len: 10, offset_from_top: 4, rows: [[cell('H')]],
    }))
    expect(bank.scrollBy('s-a', -4)).toBe(0) // back to live
    expect(bank.viewOffsetFor('s-a')).toBe(0)
  })

  it('jumpToLive repaints the held live grid and resets the offset', () => {
    const bank = new ChannelTerminalBank()
    const r = new FakeRenderer()
    bank.bindSession('s-a', r)
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'L') })) // held = live grid 'L'
    // scroll up + paint a history page
    bank.scrollBy('s-a', 3)
    bank.handle(line('s-a', {
      ev: 'scrollback_rows', id: 's-a', generation: 'gen-s-a', revision: 5,
      history_len: 10, offset_from_top: 3, rows: [[cell('H')]],
    }))
    expect(bank.viewOffsetFor('s-a')).toBe(3)
    r.paints.length = 0
    bank.jumpToLive('s-a')
    expect(bank.viewOffsetFor('s-a')).toBe(0)
    expect(r.paints).toEqual(['L']) // repainted the held live grid
  })

  it('two panes scroll INDEPENDENTLY — scrolling A does not move B', () => {
    const bank = new ChannelTerminalBank()
    bank.bindSession('s-a', new FakeRenderer())
    bank.bindSession('s-b', new FakeRenderer())
    bank.handle(line('s-a', { ev: 'grid', id: 's-a', grid: grid('s-a', 'A') }))
    bank.handle(line('s-b', { ev: 'grid', id: 's-b', grid: grid('s-b', 'B') }))
    bank.scrollBy('s-a', 7)
    expect(bank.viewOffsetFor('s-a')).toBe(7)
    expect(bank.viewOffsetFor('s-b')).toBe(0) // B untouched
    bank.scrollBy('s-b', 2)
    expect(bank.viewOffsetFor('s-a')).toBe(7) // A untouched by B's scroll
    expect(bank.viewOffsetFor('s-b')).toBe(2)
  })
})
