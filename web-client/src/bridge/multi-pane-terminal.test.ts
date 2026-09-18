import { afterEach, describe, it, expect } from 'vitest'
import { MultiPaneTerminalSession } from './multi-pane-terminal'
import type { TerminalPaneRenderer } from './channel-terminal-bank'
import { FrameKind, type TerminalFrame } from '../protocol/terminal-frame'
import type { Cell, DamageFrame, GridSnapshot } from '../protocol/web-protocol'
import {
  disableRenderMetrics,
  enableRenderMetrics,
  renderMetricsSnapshot,
  type TransportMetricEntry,
} from './render-metrics'

function cell(text = ' '): Cell {
  return {
    text, fg: { kind: 'named', name: 'foreground' }, bg: { kind: 'named', name: 'background' },
    bold: false, italic: false, underline: 'none', inverse: false, strikeout: false, dim: false,
    hidden: false, width: 1,
  }
}
function grid(sessionId: string, text: string, revision = 1): GridSnapshot {
  return {
    version: 2, generation: `gen-${sessionId}`, revision, base_revision: Math.max(0, revision - 1),
    cols: 1, rows: 1, rows_cells: [[cell(text)]], cursor_line: 0, cursor_col: 0, cursor_visible: true,
    cursor_shape: 'block', alt_screen: false, app_cursor: false, bracketed_paste: false,
    focus_reporting: false, mouse_report: false, mouse_drag: false, mouse_motion: false, mouse_sgr: false,
  }
}
function damage(sessionId: string, text: string, base = 1, revision = 2): DamageFrame {
  return {
    schema: 1, id: sessionId, generation: `gen-${sessionId}`, base_revision: base, revision, cols: 1, rows: 1,
    cursor: { line: 0, col: 0, visible: true, shape: 'block' },
    modes: { alt_screen: false, app_cursor: false, bracketed_paste: false, focus_reporting: false,
      mouse_report: false, mouse_drag: false, mouse_motion: false, mouse_sgr: false },
    ops: [{ op: 'row_span', row: 0, start: 0, cells: [cell(text)] }],
  }
}
/** a real inbound binary frame carrying one daemon JSON line for a channel */
function frame(channel: number, event: unknown): TerminalFrame {
  return { kind: FrameKind.TerminalOutput, channel, payload: new TextEncoder().encode(JSON.stringify(event)) }
}

function chunkFrame(channel: number, bytes: Uint8Array, isLast: boolean): TerminalFrame {
  const payload = new Uint8Array(bytes.length + 1)
  payload[0] = isLast ? 1 : 0
  payload.set(bytes, 1)
  return { kind: FrameKind.TerminalOutputChunk, channel, payload }
}

class FakeRenderer implements TerminalPaneRenderer {
  paints: string[] = []
  resizeForGrid(): void {}
  paint(g: GridSnapshot): void { this.paints.push(g.rows_cells[0][0].text) }
}

describe('MultiPaneTerminalSession', () => {
  afterEach(() => disableRenderMetrics())

  it('routes each channel\'s frames to ONLY that session\'s renderer (N-up isolation)', () => {
    const s = new MultiPaneTerminalSession()
    const a = new FakeRenderer()
    const b = new FakeRenderer()
    s.attachPane(1, 's-a', a)
    s.attachPane(2, 's-b', b)
    expect(s.paneCount).toBe(2)

    expect(s.onFrame(frame(1, { ev: 'grid', id: 's-a', grid: grid('s-a', 'A') }))).toEqual({ kind: 'painted', sessionId: 's-a' })
    expect(s.onFrame(frame(2, { ev: 'grid', id: 's-b', grid: grid('s-b', 'B') }))).toEqual({ kind: 'painted', sessionId: 's-b' })
    // A's frame painted A only; B's painted B only
    expect(a.paints).toEqual(['A'])
    expect(b.paints).toEqual(['B'])

    // damage on channel 1 touches A, never B
    expect(s.onFrame(frame(1, { ev: 'damage', frame: damage('s-a', 'Z') }))).toEqual({ kind: 'painted', sessionId: 's-a' })
    expect(a.paints).toEqual(['A', 'Z'])
    expect(b.paints).toEqual(['B'])
  })

  it('a frame on an unbound channel routes nowhere', () => {
    const s = new MultiPaneTerminalSession()
    s.attachPane(1, 's-a', new FakeRenderer())
    expect(s.onFrame(frame(9, { ev: 'grid', id: 's-a', grid: grid('s-a', 'X') }))).toBeNull()
  })

  it('treats an exact pane re-attachment as a no-op without dropping an in-flight chunk', () => {
    const s = new MultiPaneTerminalSession()
    const renderer = new FakeRenderer()
    s.attachPane(1, 's-a', renderer)
    const bytes = new TextEncoder().encode(JSON.stringify({
      ev: 'grid', id: 's-a', grid: grid('s-a', 'A'),
    }))
    const split = Math.floor(bytes.length / 2)
    expect(s.onFrame(chunkFrame(1, bytes.subarray(0, split), false))).toBeNull()

    s.attachPane(1, 's-a', renderer)
    expect(renderer.paints).toEqual([])
    expect(s.onFrame(chunkFrame(1, bytes.subarray(split), true))).toEqual({
      kind: 'painted', sessionId: 's-a',
    })
    expect(renderer.paints).toEqual(['A'])
  })

  it('counts the real chunked multi-pane path once and excludes invalid, unbound, and retired traffic', () => {
    let now = 100
    const s = new MultiPaneTerminalSession(() => now)
    const privateSession = 'session-do-not-capture'
    s.attachPane(7, privateSession, new FakeRenderer())
    s.setActiveSessionProvider(() => privateSession)
    enableRenderMetrics(now)

    const secretCell = 'TERMINAL-CONTENT-MUST-NOT-ENTER-METRICS'
    const bytes = new TextEncoder().encode(JSON.stringify({
      ev: 'grid', id: privateSession, grid: grid(privateSession, secretCell),
    }))
    const split = Math.floor(bytes.length / 2)
    expect(s.onFrame(chunkFrame(7, bytes.subarray(0, split), false))).toBeNull()
    now = 125
    expect(s.onFrame(chunkFrame(7, bytes.subarray(split), true))).toMatchObject({ kind: 'painted' })

    // Bound but malformed, valid JSON for the wrong session, an unbound channel, and a frame after detach are all
    // rejected before metrics. This models late callbacks from a retired transport/channel.
    s.onFrame({ kind: FrameKind.TerminalOutput, channel: 7, payload: new TextEncoder().encode('{bad') })
    s.onFrame(frame(7, { ev: 'grid', id: 'wrong-session', grid: grid('wrong-session', 'wrong') }))
    s.onFrame(frame(99, { ev: 'grid', id: privateSession, grid: grid(privateSession, 'unbound') }))
    s.detachPane(7)
    s.onFrame(frame(7, { ev: 'grid', id: privateSession, grid: grid(privateSession, 'retired') }))

    const snapshot = renderMetricsSnapshot(now) as {
      frames: number
      rawWireBytesTotal: number
      chunksTotal: number
      ev: Record<string, number>
      transport: TransportMetricEntry[]
    }
    expect(snapshot.frames).toBe(1)
    expect(snapshot.ev).toEqual({ grid: 1 })
    expect(snapshot.chunksTotal).toBe(2)
    expect(snapshot.rawWireBytesTotal).toBe((8 + 1 + split) + (8 + 1 + bytes.length - split))
    expect(snapshot.transport).toHaveLength(1)
    expect(snapshot.transport[0]).toMatchObject({
      kind: 'terminal_event',
      pane: 'pane-1',
      eventType: 'grid',
      logicalBytes: bytes.length,
      chunkCount: 2,
      transferMs: 25,
      active: true,
      firstGrid: true,
    })
    expect(snapshot.transport[0]).not.toHaveProperty('channel')
    const serialized = JSON.stringify(snapshot)
    expect(serialized).not.toContain(secretCell)
    expect(serialized).not.toContain(privateSession)
    expect(serialized).not.toContain('wrong-session')
  })

  it('detachPane stops routing that channel + drops its terminal state', () => {
    const s = new MultiPaneTerminalSession()
    const a = new FakeRenderer()
    s.attachPane(1, 's-a', a)
    s.detachPane(1)
    expect(s.paneCount).toBe(0)
    expect(s.sessionForChannel(1)).toBeNull()
    expect(s.onFrame(frame(1, { ev: 'grid', id: 's-a', grid: grid('s-a', 'X') }))).toBeNull()
    expect(a.paints).toEqual([])
  })

  it('setRenderer replays the held grid for a late-mounting pane canvas', () => {
    const s = new MultiPaneTerminalSession()
    s.attachPane(1, 's-a', null) // bound but no renderer yet
    s.onFrame(frame(1, { ev: 'grid', id: 's-a', grid: grid('s-a', 'H') })) // held
    const a = new FakeRenderer()
    s.setRenderer('s-a', a) // canvas mounts → bank replays the held grid
    expect(a.paints).toEqual(['H'])
  })

  it('reports a valid duplicate Grid as materialized after channel release/rebind without repainting it', () => {
    const s = new MultiPaneTerminalSession()
    const a = new FakeRenderer()
    const materialized: string[] = []
    s.setMaterializationObserver((sessionId) => materialized.push(sessionId))
    s.attachPane(1, 's-a', a)
    const sameGrid = { ev: 'grid', id: 's-a', grid: grid('s-a', 'A') }

    expect(s.onFrame(frame(1, sameGrid))).toEqual({ kind: 'painted', sessionId: 's-a' })
    s.releaseChannel(1)
    s.attachPane(2, 's-a') // channel-only rebind keeps the already-painted renderer untouched
    expect(a.paints).toEqual(['A'])

    expect(s.onFrame(frame(2, sameGrid))).toEqual({
      kind: 'ignored',
      sessionId: 's-a',
      reason: 'duplicate grid',
    })
    expect(a.paints).toEqual(['A']) // duplicate proves materialization but needs no second paint
    expect(materialized).toEqual(['s-a', 's-a'])
  })

  it('feeds each pane grid into independent pane-local search state', () => {
    const s = new MultiPaneTerminalSession()
    s.attachPane(1, 's-a', new FakeRenderer())
    s.attachPane(2, 's-b', new FakeRenderer())

    s.setSearchQuery('s-a', 'A')
    s.setSearchQuery('s-b', 'B')
    s.onFrame(frame(1, { ev: 'grid', id: 's-a', grid: grid('s-a', 'A') }))
    s.onFrame(frame(2, { ev: 'grid', id: 's-b', grid: grid('s-b', 'B') }))

    expect(s.searchStatus('s-a')).toMatchObject({ query: 'A', count: 1, label: '1/1' })
    expect(s.searchStatus('s-b')).toMatchObject({ query: 'B', count: 1, label: '1/1' })

    s.onFrame(frame(1, { ev: 'damage', frame: damage('s-a', 'B') }))
    expect(s.searchStatus('s-a')).toMatchObject({ query: 'A', count: 0, label: 'No matches' })
    expect(s.searchStatus('s-b')).toMatchObject({ query: 'B', count: 1, label: '1/1' })
  })

  it('exposes pane-local search navigation and clears search state on detach', () => {
    const s = new MultiPaneTerminalSession()
    s.attachPane(1, 's-a', new FakeRenderer())
    s.setSearchQuery('s-a', 'A')
    s.onFrame(frame(1, { ev: 'grid', id: 's-a', grid: grid('s-a', 'A A') }))

    expect(s.searchStatus('s-a')).toMatchObject({ count: 2, active: 1 })
    expect(s.nextSearchMatch('s-a')?.text).toBe('A')
    expect(s.searchStatus('s-a').active).toBe(2)
    expect(s.prevSearchMatch('s-a')?.text).toBe('A')
    expect(s.searchMatches('s-a')).toHaveLength(2)
    expect(s.activeSearchMatch('s-a')?.text).toBe('A')

    s.detachPane(1)
    expect(s.searchStatus('s-a')).toMatchObject({ query: '', count: 0, label: '' })
    expect(s.searchMatches('s-a')).toEqual([])
    expect(s.activeSearchMatch('s-a')).toBeNull()
  })

  it('feeds pane grids into independent pane-local selection/copy state', () => {
    const selectionGrid = (id: string, text: string): GridSnapshot => ({
      ...grid(id, text), cols: text.length, rows_cells: [Array.from(text, (char) => cell(char))],
    })
    const s = new MultiPaneTerminalSession()
    s.attachPane(1, 's-a', new FakeRenderer())
    s.attachPane(2, 's-b', new FakeRenderer())
    s.setSelectionGeometry('s-a', { rows: 1, cols: 5, cellW: 10, cellH: 20 })
    s.setSelectionGeometry('s-b', { rows: 1, cols: 4, cellW: 10, cellH: 20 })
    s.onFrame(frame(1, { ev: 'grid', id: 's-a', grid: selectionGrid('s-a', 'hello') }))
    s.onFrame(frame(2, { ev: 'grid', id: 's-b', grid: selectionGrid('s-b', 'zzzz') }))

    s.beginSelection('s-a', { x: 0, y: 0 })
    s.dragSelection('s-a', { x: 50, y: 0 })
    s.endSelection('s-a')
    s.beginSelection('s-b', { x: 10, y: 0 })
    s.dragSelection('s-b', { x: 30, y: 0 })
    s.endSelection('s-b')

    expect(s.selectedText('s-a')).toBe('hello')
    expect(s.selectedText('s-b')).toBe('zz')
    expect(s.selectionSpans('s-a')).toEqual([{ row: 0, startCol: 0, endCol: 5, active: true }])
    expect(s.selectionSpans('s-b')).toEqual([{ row: 0, startCol: 1, endCol: 3, active: true }])
    expect(s.shouldShowSelectionCopy('s-a')).toBe(true)
    expect(s.selectionCopyAnchorPx('s-a')).toEqual({ x: 50, y: 20 })

    const update = damage('s-a', 'HELLO')
    update.cols = 5
    update.ops = [{ op: 'row_span', row: 0, start: 0, cells: Array.from('HELLO', (char) => cell(char)) }]
    s.onFrame(frame(1, { ev: 'damage', frame: update }))
    expect(s.selectedText('s-a')).toBe('HELLO')
    expect(s.selectedText('s-b')).toBe('zz')
  })

  it('clears pane-local selection state on detach', () => {
    const s = new MultiPaneTerminalSession()
    s.attachPane(1, 's-a', new FakeRenderer())
    s.setSelectionGeometry('s-a', { rows: 1, cols: 5, cellW: 10, cellH: 20 })
    s.onFrame(frame(1, { ev: 'grid', id: 's-a', grid: grid('s-a', 'hello') }))
    s.beginSelection('s-a', { x: 0, y: 0 })
    s.dragSelection('s-a', { x: 50, y: 0 })
    s.endSelection('s-a')
    expect(s.selectedText('s-a')).toBe('hello')

    s.detachPane(1)
    expect(s.selectedText('s-a')).toBe('')
    expect(s.selectionSpans('s-a')).toEqual([])
    expect(s.selectionRange('s-a')).toBeNull()
    expect(s.shouldShowSelectionCopy('s-a')).toBe(false)
    expect(s.selectionCopyAnchorPx('s-a')).toBeNull()
  })
})
