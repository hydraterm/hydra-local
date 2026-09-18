// Multi-pane terminal bridge (roadmap §4). Ties the two pure halves of the N-up foundation together:
//   ChannelRouter   — demuxes inbound binary frames by channel → a session-tagged RoutedLine
//   ChannelTerminalBank — fans each RoutedLine to that session's own SyncState + renderer
// so ?panes=1 can drive MANY live terminals from one transport. Pure + transport-free: a thin layer the live
// attach path calls (attachPane on attach, onFrame for each inbound binary frame, detachPane on close). The
// default single-channel RemoteSession path is untouched.

import { ChannelRouter } from './channel-router.js'
import { ChannelTerminalBank, type TerminalBankResult, type TerminalPaneRenderer } from './channel-terminal-bank.js'
import { PaneSelectionBank } from './pane-selection-bank.js'
import { PaneSearchBank } from './pane-search-bank.js'
import type { TerminalFrame } from '../protocol/terminal-frame.js'
import type { TerminalSearchMatch, TerminalSearchStatus } from '../terminal/search.js'
import type { TermModes } from '../terminal/input-encoder.js'
import type { HighlightSpan } from '../terminal/search-highlight.js'
import type { PixelPoint, SelectionGeometry, SelectionRange } from '../terminal/selection.js'
import type { GridSnapshot } from '../protocol/web-protocol.js'
import { recordMultiPaneTerminalEvent } from './render-metrics.js'

function defaultNow(): number {
  return typeof performance !== 'undefined' ? performance.now() : Date.now()
}

export class MultiPaneTerminalSession {
  private router: ChannelRouter
  private bank: ChannelTerminalBank
  private paneSearch = new PaneSearchBank()
  private paneSelection = new PaneSelectionBank()

  // Fired (content-blind: session id only) whenever a session paints fresh output. The controller uses this to
  // mark unread activity on non-focused panes. Never carries the grid/payload.
  private activityObserver: ((sessionId: string) => void) | null = null
  private gridObserver: ((sessionId: string, grid: GridSnapshot) => void) | null = null
  private activeSessionProvider: (() => string | null) | null = null

  constructor(private readonly now: () => number = defaultNow) {
    this.router = new ChannelRouter(undefined, undefined, now)
    this.bank = new ChannelTerminalBank(now)
    this.bank.setGridObserver((sessionId, grid) => {
      this.paneSearch.setGrid(sessionId, grid)
      this.paneSelection.setGrid(sessionId, grid)
      this.gridObserver?.(sessionId, grid)
      this.activityObserver?.(sessionId)
    })
  }

  /** Subscribe to per-session activity (a paint occurred). The callback gets ONLY the session id. */
  setActivityObserver(observer: ((sessionId: string) => void) | null): void {
    this.activityObserver = observer
  }

  setGridObserver(observer: ((sessionId: string, grid: GridSnapshot) => void) | null): void {
    this.gridObserver = observer
  }

  /** Content-blind active/background classification sampled when a complete validated event is applied. */
  setActiveSessionProvider(provider: (() => string | null) | null): void {
    this.activeSessionProvider = provider
  }

  /** A valid Grid reached a pane's sync state, including an already-held duplicate that needs no repaint. */
  setMaterializationObserver(observer: ((sessionId: string) => void) | null): void {
    this.bank.setGridMaterializationObserver(observer)
  }

  setScrollbackReplyObserver(
    observer: ((sessionId: string, offset: number, accepted: boolean) => void) | null,
  ): void {
    this.bank.setScrollbackReplyObserver(observer)
  }

  /** Accepted, bounded chunk progress for an already-bound pane. Carries no terminal content. */
  setProgressObserver(observer: ((sessionId: string) => void) | null): void {
    this.router.setProgressObserver(observer)
  }

  /** Bind a pane: channel ↔ session, plus the session's renderer. Called when a pane attaches a session. */
  attachPane(channel: number, sessionId: string, renderer: TerminalPaneRenderer | null = null): void {
    // DOM reconciliation may offer the same mounted pane repeatedly. Preserve any partial inbound frame when the
    // route is already exact; a real channel/session rebind still clears the retired route's bounded chunks.
    if (this.router.sessionForChannel(channel) !== sessionId) this.router.bind(channel, sessionId)
    this.bank.bindSession(sessionId, renderer)
  }

  /** Attach (or replace) a renderer for an already-bound session — e.g. the pane's canvas mounts after attach. */
  setRenderer(sessionId: string, renderer: TerminalPaneRenderer): void {
    this.bank.attachRenderer(sessionId, renderer)
  }

  rendererUsesCanvas(sessionId: string, canvas: HTMLCanvasElement): boolean {
    return this.bank.rendererUsesCanvas(sessionId, canvas)
  }

  /** Release ONLY a channel's routing (a wire re-attach is in flight) while KEEPING the session's bank
   * state — renderer, held grid, scroll/search/selection. Used by the automatic re-attach recovery: the
   * fresh attach_ok re-binds the session to its NEW channel without repainting the already-visible surface;
   * only a genuinely new renderer replays retained live/history. */
  releaseChannel(channel: number): void {
    this.router.unbind(channel)
  }

  /** Detach a pane by channel: stop routing it and drop its terminal state. No-op for an unknown channel. */
  detachPane(channel: number): void {
    const sessionId = this.router.sessionForChannel(channel)
    this.router.unbind(channel)
    if (sessionId) {
      this.bank.unbindSession(sessionId)
      this.paneSearch.clear(sessionId)
      this.paneSelection.clear(sessionId)
    }
  }

  /**
   * Feed one inbound binary terminal frame. Routes it to its channel's session and paints that session's
   * renderer. Returns the bank result, or null when the frame isn't for one of our panes / is still
   * accumulating chunks / is agent-bound input.
   */
  onFrame(frame: TerminalFrame): TerminalBankResult | null {
    const routed = this.router.routeFrame(frame)
    if (!routed) return null
    const handled = this.bank.handleMeasured(routed)
    if (handled.measurement && routed.transport) {
      recordMultiPaneTerminalEvent({
        sessionId: routed.sessionId,
        eventType: handled.measurement.eventType,
        rawWireBytes: routed.transport.rawWireBytes,
        logicalBytes: routed.transport.logicalBytes,
        encodedBytes: routed.transport.encodedBytes,
        decodedBytes: routed.transport.decodedBytes,
        chunkCount: routed.transport.chunkCount,
        compressed: routed.transport.compressed,
        transferMs: routed.transport.transferMs,
        reassembleMs: routed.transport.reassembleMs,
        parseMs: handled.measurement.parseMs,
        applyMs: handled.measurement.applyMs,
        paintMs: handled.measurement.paintMs,
        active: this.activeSessionProvider?.() === routed.sessionId,
        materialized: handled.measurement.materialized,
      }, this.now())
    }
    return handled.result
  }

  get paneCount(): number {
    return this.router.channelCount
  }

  hasSession(sessionId: string): boolean {
    return this.bank.hasSession(sessionId)
  }

  sessionForChannel(channel: number): string | null {
    return this.router.sessionForChannel(channel)
  }

  setSearchQuery(sessionId: string, query: string): void {
    this.paneSearch.setQuery(sessionId, query)
  }

  /** Push pane-local search highlights to a session's renderer (drawn under glyphs; repaints the held grid). */
  setSearchHighlights(sessionId: string, highlights: readonly HighlightSpan[]): void {
    this.bank.setSearchHighlights(sessionId, highlights)
  }

  /** The bounds of a session's last painted grid, or null if it hasn't painted yet. */
  gridBounds(sessionId: string): { rows: number; cols: number } | null {
    return this.bank.gridBounds(sessionId)
  }

  /** The on-screen CSS-px cell size of a session's pane renderer (for mouse px→cell mapping). */
  screenCellPx(sessionId: string): { cellW: number; cellH: number } | null {
    return this.bank.screenCellPx(sessionId)
  }

  /** A pane's current scroll view offset (0 = live). */
  viewOffsetFor(sessionId: string): number {
    return this.bank.viewOffsetFor(sessionId)
  }

  /** Latest history offset that is not covered by the pane's bounded cache. */
  scrollbackRequestOffset(sessionId: string): number | null {
    return this.bank.scrollbackRequestOffset(sessionId)
  }

  /** Advance a pane's scroll view by `deltaRows` (positive = UP into history) using the pane's OWN state.
   * Returns the offset to request (0 = jump-to-live), or null on a no-op. See ChannelTerminalBank.scrollBy. */
  scrollBy(sessionId: string, deltaRows: number): number | null {
    return this.bank.scrollBy(sessionId, deltaRows)
  }

  /** Return a pane to live: repaint its held grid + reset its offset. */
  jumpToLive(sessionId: string): void {
    this.bank.jumpToLive(sessionId)
  }

  resetScrollbackForReattach(sessionId: string): void {
    this.bank.resetScrollbackForReattach(sessionId)
  }

  /** The input-affecting terminal modes (app_cursor / bracketed_paste / focus_reporting) of a pane's live grid,
   * or null before it paints. Lets the controller encode keys/paste for the ACTIVE pane with ITS real modes. */
  paneModes(sessionId: string): TermModes | null {
    return this.bank.paneModes(sessionId)
  }

  /** Alt-screen (full-screen app like Claude) → scroll is app input, not scrollback. */
  isAltScreen(sessionId: string): boolean {
    return this.bank.isAltScreen(sessionId)
  }

  searchMatches(sessionId: string): readonly TerminalSearchMatch[] {
    return this.paneSearch.matches(sessionId)
  }

  activeSearchMatch(sessionId: string): TerminalSearchMatch | null {
    return this.paneSearch.active(sessionId)
  }

  nextSearchMatch(sessionId: string): TerminalSearchMatch | null {
    return this.paneSearch.next(sessionId)
  }

  prevSearchMatch(sessionId: string): TerminalSearchMatch | null {
    return this.paneSearch.prev(sessionId)
  }

  searchStatus(sessionId: string): TerminalSearchStatus {
    return this.paneSearch.status(sessionId)
  }

  setSelectionGeometry(sessionId: string, geometry: SelectionGeometry): void {
    this.paneSelection.setGeometry(sessionId, geometry)
  }

  beginSelection(sessionId: string, point: PixelPoint): void {
    this.paneSelection.begin(sessionId, point)
  }

  dragSelection(sessionId: string, point: PixelPoint): void {
    this.paneSelection.drag(sessionId, point)
  }

  endSelection(sessionId: string): void {
    this.paneSelection.end(sessionId)
  }

  clearSelection(sessionId: string): void {
    this.paneSelection.clearSelection(sessionId)
  }

  selectionRange(sessionId: string): SelectionRange | null {
    return this.paneSelection.range(sessionId)
  }

  selectionSpans(sessionId: string): readonly HighlightSpan[] {
    return this.paneSelection.spans(sessionId)
  }

  selectedText(sessionId: string): string {
    return this.paneSelection.text(sessionId)
  }

  visibleText(sessionId: string): string {
    return this.paneSelection.visibleText(sessionId)
  }

  shouldShowSelectionCopy(sessionId: string): boolean {
    return this.paneSelection.shouldShowCopy(sessionId)
  }

  selectionCopyAnchorPx(sessionId: string): PixelPoint | null {
    return this.paneSelection.copyAnchorPx(sessionId)
  }
}
