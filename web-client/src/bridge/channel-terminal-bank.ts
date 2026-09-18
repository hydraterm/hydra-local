// Per-session terminal state bank for N-up pane rendering (roadmap §4). ChannelRouter demuxes a terminal
// frame into {channel, sessionId, line}; this layer owns the per-session SyncState + renderer and applies the
// daemon line to the right session. It is transport-free and keeps the ordinary single-session path intact.

import {
  decodeEvent,
  rowCopyCellsValid,
  sliceCopyRows,
  type CopyRows,
  isKnownEvent,
  MAX_SCROLLBACK_ROWS_PER_REQUEST,
  type DaemonEvent,
  type GridSnapshot,
} from '../protocol/web-protocol.js'
import { SyncState } from '../terminal/terminal-sync.js'
import type { RoutedLine } from './channel-router.js'
import { highlightSpansEqual, type HighlightSpan } from '../terminal/search-highlight.js'
import type { TermModes } from '../terminal/input-encoder.js'
import { metricsOn } from './render-metrics.js'

export interface TerminalPaneRenderer {
  resizeForGrid(cols: number, rows: number): void
  /** Paint the grid; `highlights` are optional search-highlight spans drawn under the glyphs. */
  paint(grid: GridSnapshot, highlights?: readonly HighlightSpan[]): void
  /** Optional: the on-screen CSS-px size of one painted cell under the renderer's current transform (see
   * GridRenderer.screenCellPx). Mouse px→cell mapping uses this; null/absent = caller falls back. */
  screenCellPx?(): { cellW: number; cellH: number } | null
  /** Optional DOM identity seam used by the browser mount layer to avoid wrapping one canvas repeatedly. */
  usesCanvas?(canvas: HTMLCanvasElement): boolean
}

export type TerminalBankResult =
  | { kind: 'painted'; sessionId: string }
  | { kind: 'ignored'; sessionId: string; reason: string }
  | { kind: 'resync'; sessionId: string; reason: string }
  | { kind: 'exited'; sessionId: string }

export interface TerminalBankMeasurement {
  readonly eventType: string
  readonly parseMs: number
  readonly applyMs: number
  readonly paintMs: number
  readonly materialized: boolean
}

export interface MeasuredTerminalBankResult {
  readonly result: TerminalBankResult
  /** Null means the line/event was unbound, malformed, stale, cross-session, or otherwise rejected. */
  readonly measurement: TerminalBankMeasurement | null
}

interface AppliedEvent {
  readonly result: TerminalBankResult
  readonly accepted: boolean
  readonly materialized: boolean
}

function defaultNow(): number {
  return typeof performance !== 'undefined' ? performance.now() : Date.now()
}

interface PaneTerminalState {
  readonly sessionId: string
  readonly sync: SyncState
  renderer: TerminalPaneRenderer | null
  held: GridSnapshot | null
  /** Pane-local search-highlight spans drawn on every paint of this session (default: none). */
  highlights: readonly HighlightSpan[]
  // ---- scrollback view state (per pane; mirrors RemoteSession's single-channel scroll state) ----
  // viewOffset 0 = live (follow bottom); >0 = that many rows scrolled UP into history. historyLen is the
  // total history the daemon last reported (0 until the first scrollback_rows reply).
  viewOffset: number
  historyLen: number
  /** True once a scrollback_rows reply has told us the real historyLen (distinguishes "no history" from "not learned
   * yet" — like local's Option<u32>). Guards the no-history scroll oscillation. */
  historyKnown: boolean
  /** One bounded first-history page, populated by the active-pane warm or a visible request. This is enough to
   * make the first upward scroll instant without introducing a second general-purpose history cache. */
  historyPage: CopyRows & {
    offset: number
  } | null
  /** Exact history snapshot currently visible. It is deliberately separate from historyPage: live output while
   * scrolled invalidates offset-addressed cache data but must leave the pinned viewport replayable on a new canvas. */
  displayedHistory: {
    grid: GridSnapshot
    highlights: readonly HighlightSpan[]
  } | null
}

export class ChannelTerminalBank {
  private states = new Map<string, PaneTerminalState>()
  /** Optional observer notified with each session's latest painted grid (for pane-local search, etc.).
   * Default: none — the bank behaves exactly as before. */
  private gridObserver: ((sessionId: string, grid: GridSnapshot) => void) | null = null
  private gridObserverNotificationDepth = 0
  /** A fully decoded, known Grid reached this session's SyncState successfully. Unlike gridObserver, this also
   * fires for an already-applied duplicate: the retained pane is already materialized even though no repaint is
   * needed. It never fires for damage, scrollback, malformed/unknown events, or a wrong session. */
  private gridMaterializationObserver: ((sessionId: string) => void) | null = null
  private scrollbackReplyObserver: ((sessionId: string, offset: number, accepted: boolean) => void) | null = null
  private capturePaintTiming = false
  private capturedPaintMs = 0

  constructor(private readonly now: () => number = defaultNow) {}

  /** Subscribe to per-session grid updates. Called whenever a session's held grid changes (grid/damage paint).
   * Pass null to unsubscribe. Does NOT replay the current held grids. */
  setGridObserver(observer: ((sessionId: string, grid: GridSnapshot) => void) | null): void {
    this.gridObserver = observer
  }

  setGridMaterializationObserver(observer: ((sessionId: string) => void) | null): void {
    this.gridMaterializationObserver = observer
  }

  setScrollbackReplyObserver(
    observer: ((sessionId: string, offset: number, accepted: boolean) => void) | null,
  ): void {
    this.scrollbackReplyObserver = observer
  }

  /** Record + announce the latest grid for a session (single place so the observer can't be missed). */
  private holdGrid(state: PaneTerminalState, grid: GridSnapshot): void {
    state.held = grid
    this.gridObserverNotificationDepth++
    try {
      this.gridObserver?.(state.sessionId, grid)
    } finally {
      this.gridObserverNotificationDepth--
    }
  }

  bindSession(sessionId: string, renderer: TerminalPaneRenderer | null = null): void {
    const existing = this.states.get(sessionId)
    if (existing) {
      if (renderer === null || renderer === existing.renderer) return
      existing.renderer = renderer
      this.replayRetainedView(existing)
      return
    }
    this.states.set(sessionId, {
      sessionId,
      sync: new SyncState(sessionId),
      renderer,
      held: null,
      highlights: [],
      viewOffset: 0,
      historyLen: 0,
      historyKnown: false,
      historyPage: null,
      displayedHistory: null,
    })
  }

  unbindSession(sessionId: string): void {
    this.states.delete(sessionId)
  }

  /** Set a session's pane-local search highlights and repaint its held grid (no-op if the session is unbound). */
  setSearchHighlights(sessionId: string, highlights: readonly HighlightSpan[]): void {
    const state = this.states.get(sessionId)
    if (!state) return
    if (highlightSpansEqual(state.highlights, highlights)) return
    state.highlights = highlights
    // holdGrid notifies search/selection observers synchronously. Fold their publication into the outer frame
    // paint; otherwise live frames paint twice and scrolled panes can flash live content over retained history.
    // Calls from user interaction happen outside that notification and repaint the current view immediately.
    if (this.gridObserverNotificationDepth > 0) return
    if (state.viewOffset === 0) {
      this.paintLive(state)
    } else if (state.displayedHistory) {
      state.displayedHistory = { grid: state.displayedHistory.grid, highlights }
      if (state.renderer) this.paint(state.renderer, state.displayedHistory.grid, highlights)
    }
  }

  rendererUsesCanvas(sessionId: string, canvas: HTMLCanvasElement): boolean {
    return this.states.get(sessionId)?.renderer?.usesCanvas?.(canvas) ?? false
  }

  /** The bounds of a session's last painted grid, or null if it hasn't painted yet (for highlight sizing). */
  gridBounds(sessionId: string): { rows: number; cols: number } | null {
    const held = this.states.get(sessionId)?.held
    return held ? { rows: held.rows, cols: held.cols } : null
  }

  /** The on-screen CSS-px cell size of a session's renderer (null if unbound / renderer can't report it). */
  screenCellPx(sessionId: string): { cellW: number; cellH: number } | null {
    return this.states.get(sessionId)?.renderer?.screenCellPx?.() ?? null
  }

  /** The input-affecting terminal modes of a session's last live grid, or null before it paints. Used to encode
   * keys/paste for the ACTIVE pane (app_cursor arrows, bracketed paste) — the per-pane analogue of the single
   * session's held modes, since in multi-pane the live grid lives here, not on the RemoteSession. */
  paneModes(sessionId: string): TermModes | null {
    const held = this.states.get(sessionId)?.held
    if (!held) return null
    return {
      app_cursor: held.app_cursor,
      bracketed_paste: held.bracketed_paste,
      focus_reporting: held.focus_reporting,
      // mouse modes so a wheel over a mouse-tracking app (Claude/vim) can be encoded as an SGR mouse report.
      mouse_report: held.mouse_report,
      mouse_drag: held.mouse_drag,
      mouse_motion: held.mouse_motion,
      mouse_sgr: held.mouse_sgr,
    }
  }

  /** Is this pane's live grid on the ALTERNATE screen (a full-screen app like Claude Code / vim)? Such panes have NO
   * daemon scrollback — scrolling must be sent to the APP as input, not a scrollback query. Null-safe: false if unbound
   * or nothing painted yet. */
  isAltScreen(sessionId: string): boolean {
    return this.states.get(sessionId)?.held?.alt_screen ?? false
  }

  attachRenderer(sessionId: string, renderer: TerminalPaneRenderer): void {
    this.bindSession(sessionId, renderer)
  }

  /** A pane's current scroll view offset (0 = live). 0 for an unbound session. */
  viewOffsetFor(sessionId: string): number {
    return this.states.get(sessionId)?.viewOffset ?? 0
  }

  /** Latest pane-local history target that still needs a daemon page. A reply for an older target may fill the
   * bounded cache without painting; the controller calls this after that reply to send only the newest target. */
  scrollbackRequestOffset(sessionId: string): number | null {
    const state = this.states.get(sessionId)
    if (!state || state.viewOffset <= 0) return null
    return this.cachedRowsForOffset(state, state.viewOffset) ? null : state.viewOffset
  }

  /**
   * Advance a pane's scroll view by `deltaRows` (positive = UP into history, negative = DOWN toward live),
   * using the SAME clamping as RemoteSession.scrollByRows. Returns the offset the caller should request from
   * the daemon (0 = jump-to-live), or null when the offset doesn't change (no-op — nothing to request).
   *
   * This drives multi-pane scroll from the pane's OWN per-pane state (viewOffset/historyLen learned from that
   * pane's scrollback_rows replies), so two panes scroll independently and the request offset always tracks the
   * pane the wheel is over. The optimistic set here is reconciled by the reply (which trusts offset_from_top).
   */
  scrollBy(sessionId: string, deltaRows: number): number | null {
    const state = this.states.get(sessionId)
    if (!state?.held) return null
    if ((state.held?.rows ?? 0) > MAX_SCROLLBACK_ROWS_PER_REQUEST) return null
    // If a reply has DEFINITIVELY told us this pane has NO history (historyKnown && historyLen===0), refuse to scroll
    // up — otherwise scrollBy sets viewOffset UP, the reply resets it to 0 ("no history"), scrollBy sets it up again…
    // = the "two forces fighting, waves up-and-down" oscillation. Down-to-live still works. (A pane with no scrollback
    // is a full-screen app / fresh session; scrolling there is a no-op, like local.)
    if (state.historyKnown && state.historyLen === 0 && deltaRows > 0) return null
    // historyLen 0 + not-yet-known: allow the FIRST scroll up so one request can fire to learn the real length.
    const maxOffset = state.historyLen > 0 ? state.historyLen : state.viewOffset + Math.max(1, deltaRows)
    const next = Math.max(0, Math.min(maxOffset, state.viewOffset + deltaRows))
    if (next === state.viewOffset) return null
    state.viewOffset = next
    const cached = this.cachedRowsForOffset(state, next)
    if (cached) {
      this.paintHistoryRows(state, cached)
      return null
    }
    return next
  }

  /** Return a pane to the live (bottom) view: repaint its held live grid and reset the offset. No-op if unbound
   * or it hasn't painted a live grid yet. */
  jumpToLive(sessionId: string): void {
    const state = this.states.get(sessionId)
    if (!state) return
    state.viewOffset = 0
    this.paintLive(state)
  }

  /** Retire history state at a channel-rebind boundary without repainting the old surface. The new channel's
   * authoritative Grid will be the next paint, so replaying the old held grid here only adds flicker/duplicate work. */
  resetScrollbackForReattach(sessionId: string): void {
    const state = this.states.get(sessionId)
    if (!state) return
    state.viewOffset = 0
    state.historyLen = 0
    state.historyKnown = false
    state.historyPage = null
    state.displayedHistory = null
  }

  hasSession(sessionId: string): boolean {
    return this.states.has(sessionId)
  }

  get sessionCount(): number {
    return this.states.size
  }

  handle(line: RoutedLine): TerminalBankResult {
    return this.handleMeasured(line).result
  }

  /** Apply one complete line and return content-blind timings only when the event passes validation/sync gates. */
  handleMeasured(line: RoutedLine): MeasuredTerminalBankResult {
    const state = this.states.get(line.sessionId)
    if (!state) {
      return {
        result: { kind: 'ignored', sessionId: line.sessionId, reason: 'unbound session' },
        measurement: null,
      }
    }

    const collect = metricsOn() && line.transport !== undefined
    const parseStart = collect ? this.now() : 0
    const decoded = decodeEvent(line.line)
    const parseMs = collect ? Math.max(0, this.now() - parseStart) : 0
    if ('err' in decoded) {
      return {
        result: { kind: 'ignored', sessionId: line.sessionId, reason: `decode:${decoded.err.kind}` },
        measurement: null,
      }
    }
    if (!isKnownEvent(decoded.ok)) {
      return {
        result: { kind: 'ignored', sessionId: line.sessionId, reason: 'unknown event' },
        measurement: null,
      }
    }

    this.capturePaintTiming = collect
    this.capturedPaintMs = 0
    const applyStart = collect ? this.now() : 0
    let applied: AppliedEvent
    try {
      applied = this.applyEvent(state, line, decoded.ok)
    } finally {
      this.capturePaintTiming = false
    }
    const applyAndPaintMs = collect ? Math.max(0, this.now() - applyStart) : 0
    if (!collect || !applied.accepted) return { result: applied.result, measurement: null }
    return {
      result: applied.result,
      measurement: {
        eventType: decoded.ok.ev,
        parseMs,
        applyMs: Math.max(0, applyAndPaintMs - this.capturedPaintMs),
        paintMs: this.capturedPaintMs,
        materialized: applied.materialized,
      },
    }
  }

  private applyEvent(state: PaneTerminalState, line: RoutedLine, ev: DaemonEvent): AppliedEvent {
    switch (ev.ev) {
      case 'grid': {
        const r = state.sync.onGrid(ev.id, ev.grid)
        if ('err' in r) {
          return {
            result: { kind: 'ignored', sessionId: line.sessionId, reason: r.err.kind },
            accepted: false,
            materialized: false,
          }
        }
        if (!r.ok.repaint) {
          this.gridMaterializationObserver?.(state.sessionId)
          return {
            result: { kind: 'ignored', sessionId: line.sessionId, reason: 'duplicate grid' },
            accepted: true,
            materialized: true,
          }
        }
        state.historyPage = null
        if (ev.grid.rows > MAX_SCROLLBACK_ROWS_PER_REQUEST) {
          // The wire protocol can return at most 256 rows. If a resize makes the viewport taller while the user
          // is in history, preserving viewOffset would hold this new live Grid forever and then walk sequential
          // partial pages that can never fill the viewport. Oversized viewports always follow live.
          state.viewOffset = 0
          state.historyLen = 0
          state.historyKnown = false
        }
        this.holdGrid(state, ev.grid)
        this.gridMaterializationObserver?.(state.sessionId)
        // SCROLLED UP (viewOffset>0): keep the held grid current but DON'T repaint — else live output (Claude's
        // spinner/ticks) would yank the view back to the bottom every frame, so the user can never stay in history.
        if (state.viewOffset > 0) {
          return {
            result: { kind: 'ignored', sessionId: line.sessionId, reason: 'held-while-scrolled' },
            accepted: true,
            materialized: true,
          }
        }
        this.paintLive(state)
        return { result: { kind: 'painted', sessionId: line.sessionId }, accepted: true, materialized: true }
      }
      case 'damage': {
        if (!state.held) {
          return {
            result: { kind: 'resync', sessionId: line.sessionId, reason: 'damage before grid' },
            accepted: false,
            materialized: false,
          }
        }
        const out = state.sync.onDamage(ev.frame.id, ev.frame, state.held)
        if (out.kind === 'ignore') {
          return {
            result: { kind: 'ignored', sessionId: line.sessionId, reason: 'damage ignored' },
            accepted: false,
            materialized: false,
          }
        }
        if (out.kind === 'resync') {
          return {
            result: { kind: 'resync', sessionId: line.sessionId, reason: out.reason },
            accepted: false,
            materialized: false,
          }
        }
        // Match the single-session path: ordinary cursor/output damage while following live must not discard the
        // just-warmed first history page. Its offsets remain useful for the first upward scroll. Once the user is
        // already scrolled, however, live output can shift the historical window underneath that view, so discard
        // it. A generation change is also a hard invalidation even at live.
        if (
          state.viewOffset > 0
          || (state.historyPage !== null && state.historyPage.generation !== out.grid.generation)
        ) {
          state.historyPage = null
        }
        this.holdGrid(state, out.grid)
        if (state.viewOffset > 0) {
          return {
            result: { kind: 'ignored', sessionId: line.sessionId, reason: 'held-while-scrolled' },
            accepted: true,
            materialized: false,
          }
        }
        this.paintLive(state)
        return { result: { kind: 'painted', sessionId: line.sessionId }, accepted: true, materialized: false }
      }
      case 'scrollback_rows': {
        // A reply to a Scrollback request for THIS pane's channel. Ported from the LOCAL Hydra renderer's handler
        // (maestro-renderer/src/client.rs ~440) — the browser was MISSING these three guards, which is why scroll
        // never stuck while local's did (same daemon, same protocol):
        // 1. GENERATION check: ignore a reply whose generation != the live grid's. Claude constantly emits output, so
        //    the grid generation advances; a stale reply for an old generation must be dropped, not painted.
        // 2. is-scrolled guard: only apply the historical view if the user is STILL scrolled up (viewOffset>0). A late
        //    reply must not yank a user who already returned to live back into history.
        // 3. history_len==0 → snap to live (no history to show).
        if (ev.id !== state.sessionId) {
          return {
            result: { kind: 'ignored', sessionId: line.sessionId, reason: 'wrong_session' },
            accepted: false,
            materialized: false,
          }
        }
        if (!state.held || ev.generation !== state.held.generation) {
          this.scrollbackReplyObserver?.(state.sessionId, ev.offset_from_top, false)
          return {
            result: { kind: 'ignored', sessionId: line.sessionId, reason: 'scrollback stale generation' },
            accepted: false,
            materialized: false,
          }
        }
        if (!rowCopyCellsValid(ev.rows, ev.row_copy)) {
          this.scrollbackReplyObserver?.(state.sessionId, ev.offset_from_top, false)
          return { result: { kind: 'ignored', sessionId: line.sessionId, reason: 'invalid row copy metadata' }, accepted: false, materialized: false }
        }
        state.historyLen = ev.history_len
        state.historyKnown = true // we now know the real length → the scrollBy no-history guard can trust historyLen===0
        if (ev.history_len === 0) {
          state.historyPage = null
          state.viewOffset = 0
          this.paintLive(state)
          this.scrollbackReplyObserver?.(state.sessionId, ev.offset_from_top, true)
          return { result: { kind: 'painted', sessionId: line.sessionId }, accepted: true, materialized: false }
        }
        state.historyPage = {
          ...sliceCopyRows(ev),
          offset: ev.offset_from_top,
        }
        if (state.viewOffset <= 0) {
          // user returned to live before this reply landed → repaint live, don't re-enter history.
          this.paintLive(state)
          this.scrollbackReplyObserver?.(state.sessionId, ev.offset_from_top, true)
          return { result: { kind: 'painted', sessionId: line.sessionId }, accepted: true, materialized: false }
        }
        // Clamp the CURRENT desired viewport, not the reply's older requested viewport. Trackpad bursts update
        // viewOffset while one request is in flight; a late reply may populate the cache but must never yank the
        // terminal back to its stale offset.
        state.viewOffset = Math.max(0, Math.min(ev.history_len, state.viewOffset))
        if (state.viewOffset === 0) {
          this.paintLive(state)
          this.scrollbackReplyObserver?.(state.sessionId, ev.offset_from_top, true)
          return { result: { kind: 'painted', sessionId: line.sessionId }, accepted: true, materialized: false }
        }
        const visibleRows = this.cachedRowsForOffset(state, state.viewOffset)
        if (!state.renderer) {
          if (visibleRows) this.paintHistoryRows(state, visibleRows)
          this.scrollbackReplyObserver?.(state.sessionId, ev.offset_from_top, true)
          return {
            result: { kind: 'ignored', sessionId: line.sessionId, reason: 'no renderer' },
            accepted: true,
            materialized: false,
          }
        }
        if (!visibleRows) {
          this.scrollbackReplyObserver?.(state.sessionId, ev.offset_from_top, true)
          return {
            result: { kind: 'ignored', sessionId: line.sessionId, reason: 'scrollback cache fill' },
            accepted: true,
            materialized: false,
          }
        }
        // Build a view-only GridSnapshot from the rows matching the latest viewport, never the stale request.
        this.paintHistoryRows(state, visibleRows)
        this.scrollbackReplyObserver?.(state.sessionId, ev.offset_from_top, true)
        return { result: { kind: 'painted', sessionId: line.sessionId }, accepted: true, materialized: false }
      }
      case 'resync_required': {
        const r = state.sync.onResyncRequired(ev.id)
        if ('err' in r) {
          return {
            result: { kind: 'ignored', sessionId: line.sessionId, reason: r.err.kind },
            accepted: false,
            materialized: false,
          }
        }
        state.historyPage = null
        return {
          result: { kind: 'resync', sessionId: line.sessionId, reason: 'daemon requested resync' },
          accepted: true,
          materialized: false,
        }
      }
      case 'session_exited': {
        const r = state.sync.onSessionExited(ev.id)
        if ('err' in r) {
          return {
            result: { kind: 'ignored', sessionId: line.sessionId, reason: r.err.kind },
            accepted: false,
            materialized: false,
          }
        }
        return { result: { kind: 'exited', sessionId: line.sessionId }, accepted: true, materialized: false }
      }
      case 'output': {
        const accepted = ev.id === state.sessionId
        return {
          result: {
            kind: 'ignored',
            sessionId: line.sessionId,
            reason: accepted ? ev.ev : 'wrong_session',
          },
          accepted,
          materialized: false,
        }
      }
      case 'sessions':
      case 'error':
        return {
          result: { kind: 'ignored', sessionId: line.sessionId, reason: ev.ev },
          accepted: true,
          materialized: false,
        }
    }
  }

  private cachedRowsForOffset(
    state: PaneTerminalState,
    offset: number,
  ): CopyRows | null {
    const page = state.historyPage
    if (!page || offset <= 0 || offset > page.offset) return null
    const start = page.offset - offset
    if (start < 0 || start >= page.rows.length) return null
    const visibleRows = Math.max(1, state.held?.rows ?? page.rows.length)
    const rows = page.rows.slice(start, start + visibleRows)
    return rows.length === visibleRows ? sliceCopyRows(page, start, start + visibleRows) : null
  }

  private replayRetainedView(state: PaneTerminalState): void {
    if (!state.renderer || !state.held) return
    if (state.viewOffset === 0) {
      this.paintLive(state)
      return
    }
    if (state.displayedHistory) {
      this.paint(state.renderer, state.displayedHistory.grid, state.displayedHistory.highlights)
      return
    }
    const cached = this.cachedRowsForOffset(state, state.viewOffset)
    if (cached) {
      this.paintHistoryRows(state, cached)
    }
  }

  private paintLive(state: PaneTerminalState): void {
    if (state.viewOffset !== 0 || !state.held) return
    state.displayedHistory = null
    if (state.renderer) this.paint(state.renderer, state.held, state.highlights)
  }

  private paintHistoryRows(
    state: PaneTerminalState,
    page: CopyRows,
  ): void {
    const { rows, generation, revision, row_copy } = sliceCopyRows(page)
    const cols = rows[0]?.length ?? 0
    const historyGrid: GridSnapshot = {
      ...(state.held ?? EMPTY_GRID_TEMPLATE),
      generation,
      revision,
      base_revision: revision,
      cols,
      rows: rows.length,
      rows_cells: rows.map((row) => [...row]),
      row_copy,
      cursor_line: 0,
      cursor_col: 0,
      cursor_visible: false,
    }
    state.displayedHistory = { grid: historyGrid, highlights: state.highlights }
    if (state.renderer) this.paint(state.renderer, historyGrid, state.highlights)
  }

  private paint(
    renderer: TerminalPaneRenderer,
    grid: GridSnapshot,
    highlights: readonly HighlightSpan[] = [],
  ): void {
    const startedAt = this.capturePaintTiming ? this.now() : 0
    renderer.resizeForGrid(grid.cols, grid.rows)
    renderer.paint(grid, highlights)
    if (this.capturePaintTiming) this.capturedPaintMs += Math.max(0, this.now() - startedAt)
  }
}

// Fallback base for a history GridSnapshot when a pane somehow receives scrollback_rows before its first live
// grid (no `held`). Mode flags are all inert; the scrollback_rows case overrides cols/rows/rows_cells/cursor.
const EMPTY_GRID_TEMPLATE: GridSnapshot = {
  version: 2,
  generation: '',
  revision: 0,
  base_revision: 0,
  cols: 0,
  rows: 0,
  rows_cells: [],
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
