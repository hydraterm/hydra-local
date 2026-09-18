// S5 — RemoteSession: drives the S3b auth handshake + S4 terminal flow over a RemoteTransport, reusing
// the existing terminal core (SyncState/GridRenderer/input-encoder). This is the client mirror of the
// agent's control+bridge: present a token (auth), then session_list / attach / input / resize / detach,
// rendering the daemon Grid/Damage frames carried by terminal_output.
//
// "Connected ≠ authorized": no terminal action is sent before auth_ok. Terminal bytes ride ONLY the
// transport (DTLS) — never the cloud. No terminal data is ever logged.

import { connTrace, currentTraceId } from './conn-trace.js'
import { diagnosticQueryFlag } from './diagnostic-flags.js'
import { publishDbWrites, setDbWriteFetcher } from './inspector-hooks.js'
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
import {
  decodeFrame,
  encodeInputFrames,
  FrameKind,
  MAX_INPUT_PAYLOAD,
  TERMINAL_GZIP_JSON_V1,
} from '../protocol/terminal-frame.js'
import type { TerminalFrame } from '../protocol/terminal-frame.js'
import { BoundedChunkReassembler } from './bounded-chunk-reassembler.js'
import { GridRenderer } from '../terminal/grid-renderer.js'
import { highlightSpansEqual, type HighlightSpan } from '../terminal/search-highlight.js'
import {
  encodeKey,
  encodePasteChunks,
  type KeyEvent,
  type TermModes,
} from '../terminal/input-encoder.js'
import { SyncState } from '../terminal/terminal-sync.js'
import type { BoundAuthorization, ControlState, RemoteTransport } from './remote-transport.js'
import {
  buildCloseWindow,
  buildCreateSession,
  buildFocusWindow,
  buildListAgentSessions,
  buildListDirectories,
  buildManageAgentSession,
  buildNewPane,
  buildNewWindow,
  buildPreviewAgentSession,
  buildProjectCreate,
  buildProjectDelete,
  buildProjectUpdate,
  buildRevivePane,
  buildRename,
  buildRemovePane,
  buildSplitPane,
  buildStartPaneSession,
  buildStashPane,
  parseAgentSessionPreviewReply,
  parseAgentSessionManageReply,
  parseAgentSessionsReply,
  parseCloseWindowReply,
  parseCreateSessionReply,
  parseDesktopAccessStatus,
  parseDirectoriesReply,
  parseFocusWindowReply,
  parseNewWindowReply,
  parseProjectEditReply,
  parseRenameReply,
  parseRevivePaneReply,
  parseRemovePaneReply,
  parseSplitPaneReply,
  parseStartPaneSessionReply,
  parseStashPaneReply,
  type AgentSessionPreviewReply,
  type AgentSessionManageReply,
  type AgentSessionsResultMsg,
  type AgentSessionsErrorMsg,
  type CreateSessionOptions,
  type DesktopAccessStatusMsg,
  type DirectoriesErrorMsg,
  type DirectoriesResultMsg,
  type NewPaneOptions,
  type NewWindowOptions,
  type ProjectCreateOptions,
  type ProjectEditOptions,
  type RemoteAgentKind,
  type RevivePaneOptions,
  type SplitPaneDir,
  type SplitPaneOptions,
  type StartPaneSessionOptions,
} from '../protocol/control-messages.js'
import { recordEvent, recordFrame } from './render-metrics.js'
import { OrderedTerminalCodecDecoder, terminalGzipDecoderAvailable } from './terminal-codec-decoder.js'
import type { RemoteWorkspaceMetadata } from './remote-client.js'
import { isRunnableAgentKind } from '../model/agent-provider-core.js'
import { parseBoundedControlJson } from '../protocol/bounded-control-json.js'

export const PROTOCOL_VERSION = 1
const VIEWED_RESIZE_CAPABILITY = 'viewed_resize_v1'
export const CREATION_REQUEST_REPLAY_CAPABILITY = 'creation_request_replay_v1'
export const DESKTOP_ACCESS_STATUS_CAPABILITY = 'desktop_access_status_v1'
export const AUTHORIZATION_REFRESH_CAPABILITY = 'authorization_refresh_v1'
export const AUTHORIZATION_REFRESH_LEAD_MS = 2 * 60_000
export const AUTHORIZATION_REFRESH_JITTER_MS = 15_000
export const AUTHORIZATION_REFRESH_REQUEST_TIMEOUT_MS = 8_000
/** Above the agent's 10 s native DataChannel bufferedAmount stall bound. Control priority cannot bypass bytes
 * already accepted by SCTP, so a healthy auth_refresh_ok may legitimately need that drain window. */
export const AUTHORIZATION_REFRESH_ACK_TIMEOUT_MS = 15_000
export const AUTHORIZATION_REFRESH_EXPIRY_GUARD_MS = 5_000
export const AUTHORIZATION_REFRESH_RETRY_DELAYS_MS = [1_000, 3_000, 7_000] as const
/** One exact-frame retry lands before the controller's 12 s mutation watchdog. A capable agent replays the
 * cached typed result without executing the desktop mutation twice. */
export const CREATION_DELIVERY_RETRY_MS = 4_000
const CREATION_REPLAY_RETIRE_MS = 120_000
type CreationRequestType =
  | 'create_session'
  | 'split_pane'
  | 'new_pane'
  | 'revive_pane'
  | 'start_pane_session'
  | 'new_window'
  | 'project_create'
type PendingCreationReplay = {
  readonly type: CreationRequestType
  readonly frame: string
  retryTimer: ReturnType<typeof setTimeout> | null
  retireTimer: ReturnType<typeof setTimeout> | null
}
function isCreationRequestType(value: unknown): value is CreationRequestType {
  return value === 'create_session'
    || value === 'split_pane'
    || value === 'new_pane'
    || value === 'revive_pane'
    || value === 'start_pane_session'
    || value === 'new_window'
    || value === 'project_create'
}
const MAX_HELLO_CAPABILITIES = 16
const MAX_HELLO_CAPABILITY_BYTES = 64
const AGENT_BUILD_GIT = /^[0-9a-f]{7,40}$/u
const MAX_PENDING_ATTACHES = 32
const PENDING_ATTACH_TTL_MS = 15_000
/** A scrollback page may progress in chunks, but an owner that never receives a complete reply must reconnect
 * rather than remain permanently pending or admit an overlapping retry. This is deliberately later than the
 * controller's 30 s initial-history warm cap: optional sibling hydration must be released first, while a truly
 * lost reply still gets a terminal fail/reconnect bound. */
export const SCROLLBACK_RESPONSE_TIMEOUT_MS = 45_000

/** Accept only the agent's bounded lowercase Git identity. Free-form build stamps, dirty markers, URLs, and other
 * text stay out of the browser view/QA strip. */
export function parseAgentBuildGit(value: unknown): string | null {
  return typeof value === 'string' && AGENT_BUILD_GIT.test(value) ? value : null
}

type ScrollbackRequestTrace = {
  sessionId: string
  sentAt: number
  count: number
  prefetch: boolean
}

type IncomingLineTrace = {
  bytes: number
  chunks: number
  transferMs: number
  reassembleMs: number
}

type PendingChunkTrace = {
  firstAt: number
  chunks: number
  bytes: number
}

export type ScrollbackPerfEntry = {
  ts: number
  session: string
  offset: number
  count: number
  rows: number
  historyLen: number
  bytes: number
  chunks: number
  transferMs: number
  reassembleMs: number
  parseMs: number
  cachePaintMs: number
  totalMs: number
  prefetch: boolean
}

const SCROLLBACK_PERF_MAX = 80
const scrollbackPerf: ScrollbackPerfEntry[] = []

function perfNow(): number {
  return typeof performance !== 'undefined' ? performance.now() : Date.now()
}

function pushScrollbackPerf(entry: ScrollbackPerfEntry): void {
  scrollbackPerf.push(entry)
  if (scrollbackPerf.length > SCROLLBACK_PERF_MAX) scrollbackPerf.shift()
}

if (typeof globalThis !== 'undefined' && diagnosticQueryFlag('metrics')) {
  ;(globalThis as unknown as {
    __HYDRA_SCROLL_DEBUG__?: () => ScrollbackPerfEntry[]
    __HYDRA_SCROLL_DEBUG_SUMMARY__?: () => {
      count: number
      avgTotalMs: number
      maxTotalMs: number
      avgTransferMs: number
      maxTransferMs: number
      avgChunks: number
      maxChunks: number
      avgBytes: number
      maxBytes: number
    }
  }).__HYDRA_SCROLL_DEBUG__ = () => [...scrollbackPerf]
  ;(globalThis as unknown as {
    __HYDRA_SCROLL_DEBUG_SUMMARY__?: () => {
      count: number
      avgTotalMs: number
      maxTotalMs: number
      avgTransferMs: number
      maxTransferMs: number
      avgChunks: number
      maxChunks: number
      avgBytes: number
      maxBytes: number
    }
  }).__HYDRA_SCROLL_DEBUG_SUMMARY__ = () => {
    const entries = scrollbackPerf
    const count = entries.length
    const avg = (pick: (e: ScrollbackPerfEntry) => number): number =>
      count ? entries.reduce((n, e) => n + pick(e), 0) / count : 0
    const max = (pick: (e: ScrollbackPerfEntry) => number): number =>
      count ? Math.max(...entries.map(pick)) : 0
    return {
      count,
      avgTotalMs: avg((e) => e.totalMs),
      maxTotalMs: max((e) => e.totalMs),
      avgTransferMs: avg((e) => e.transferMs),
      maxTransferMs: max((e) => e.transferMs),
      avgChunks: avg((e) => e.chunks),
      maxChunks: max((e) => e.chunks),
      avgBytes: avg((e) => e.bytes),
      maxBytes: max((e) => e.bytes),
    }
  }
}

export interface RemoteSessionCallbacks {
  onState?: (state: ControlState) => void
  /** Authenticated, bounded agent Git label for QA cohort visibility. Null means legacy/invalid/omitted. */
  onAgentBuild?: (git: string | null) => void
  /** Negotiated, authenticated desktop filesystem-access readiness. */
  onDesktopAccessStatus?: (status: DesktopAccessStatusMsg) => void
  onSessions?: (
    sessions: string[],
    metadata?: RemoteSessionMetadata[],
    workspaceMetadata?: RemoteWorkspaceMetadata | null,
  ) => void
  /** UNSOLICITED live-sync push: the desktop's workspace changed while attached. Same workspaceMetadata shape/
   * semantics as onSessions (null = omitted). `epoch` is echoed back in the ack. Fires WITHOUT a page refresh. */
  onWorkspaceUpdate?: (
    epoch: number,
    workspaceMetadata: RemoteWorkspaceMetadata | null,
    /** The live session ids the push carried (self-sufficient push); null = an older agent omitted them. */
    sessions?: string[] | null,
  ) => void
  /** Pre-commit ownership gate for attach_ok. Called before RemoteSession replaces its active channel/sync/grid.
   * Returning false drains the newly-proven agent attach while preserving the current terminal state. */
  shouldAcceptAttach?: (sessionId: string, channel: number, requestId: string) => boolean
  onAttached?: (sessionId: string, channel: number) => void
  onError?: (
    code: string,
    message: string,
    correlation?: { requestId?: string; sessionId?: string },
  ) => void
  /** The agent's EFFECTIVE winsize owner (after applying serving>0 + the 10s grace). The browser reflects it into
   * view.winsizeOwner so the toggle shows the truth (e.g. reverts to 'local' when the connection drops past grace). */
  onWinsizeOwnerChanged?: (owner: 'local' | 'remote') => void
  /** Reply to a `create_session` (Slice E): on success the new session id, else a typed error code +
   * short message. The caller (controller) attaches the id on success or surfaces the error. */
  onSessionCreated?: (sessionId: string, label: string | undefined, requestId: string) => void
  onSessionCreateError?: (code: string, message: string, requestId: string) => void
  onAgentSessions?: (result: AgentSessionsResultMsg) => void
  onAgentSessionsError?: (error: AgentSessionsErrorMsg) => void
  onDirectoriesResult?: (result: DirectoriesResultMsg) => void
  onDirectoriesError?: (error: DirectoriesErrorMsg) => void
  onAgentSessionPreview?: (result: AgentSessionPreviewReply) => void
  onAgentSessionManaged?: (result: AgentSessionManageReply) => void
  onSplitPaneOk?: (sessionId: string, tabId: string, requestId: string) => void
  onSplitPaneError?: (code: string, message: string, requestId: string) => void
  onRevivePaneOk?: (sessionId: string, requestId: string) => void
  onRevivePaneError?: (code: string, message: string, requestId: string) => void
  onStartPaneSessionOk?: (sessionId: string, requestId: string) => void
  onStartPaneSessionError?: (code: string, message: string, requestId: string) => void
  onStashPaneOk?: (requestId: string) => void
  onStashPaneError?: (code: string, message: string, requestId: string) => void
  onRemovePaneOk?: (requestId: string) => void
  onRemovePaneError?: (code: string, message: string, requestId: string) => void
  onRenameOk?: (requestId: string) => void
  onRenameError?: (code: string, message: string, requestId: string) => void
  onFocusWindowOk?: (requestId: string) => void
  onFocusWindowError?: (code: string, message: string, requestId: string) => void
  onCloseWindowOk?: (requestId: string) => void
  onCloseWindowError?: (code: string, message: string, requestId: string) => void
  onNewWindowOk?: (windowId: string, sessionId: string, requestId: string) => void
  onNewWindowError?: (code: string, message: string, requestId: string) => void
  /** `sessionId` = the seeded pane's session on a project CREATE (auto-attach target); undefined on update. */
  onProjectEditOk?: (projectId: string, sessionId: string | undefined, requestId: string) => void
  onProjectEditError?: (code: string, message: string, requestId: string) => void
  /** Scroll view state, for the "jump to live" affordance. atLive=true → following live output. */
  onScrollView?: (view: { atLive: boolean; offset: number; historyLen: number }) => void
  /** Current live structured grid, for browser-local UI affordances such as search. Never logged/stored. */
  onGridSnapshot?: (grid: GridSnapshot) => void
  /** RAW renderer mode (xterm.js): raw PTY bytes from the daemon's `Output` events. Set ⇒ the session
   * routes `output` here and does NOT drive the structured grid renderer. */
  onRawOutput?: (bytes: Uint8Array) => void
  /** Optional structured-frame consumer for the gated multi-pane path. Return true to consume the frame
   * before RemoteSession's single-channel renderer sees it. Default path leaves this unset. */
  onTerminalFrame?: (frame: TerminalFrame) => boolean
  /** A validated, bounded output chunk arrived on the current attached channel. Content-blind; the controller
   * uses it only to re-arm the attach inactivity watchdog while a large initial Grid is transferring. */
  onTerminalProgress?: (sessionId: string) => void
  /** Content-blind scrollback lifecycle signals. The controller uses them only to keep low-priority pane
   * hydration from competing with foreground history traffic. */
  onScrollbackRequest?: (
    sessionId: string,
    offset: number,
    count: number,
    sessionTraceOwned: boolean,
  ) => void
  onScrollbackReply?: (sessionId: string, offset: number, accepted: boolean) => void
  /** The single-session renderer could not apply an incremental frame because it lacks a baseline grid.
   * The controller can recover by forcing a fresh attach, which makes the daemon stream a full grid. */
  onBaselineRequired?: (sessionId: string, reason: string) => void
  /** Content-blind remote-sync debug reply from the agent. */
  onDebugSyncSnapshot?: (requestId: string, agent: unknown) => void
}

export interface RemoteSessionMetadata {
  readonly id: string
  readonly cwd?: string
}

export class RemoteSession {
  private authenticated = false
  /** Fail closed for mixed-version peers. A legacy agent treats an omitted `Resize.viewed` as true, so the browser
   * may send background (`viewed:false`) resizes only after the current transport's agent Hello advertises the exact
   * additive capability. Foreground resizes remain compatible with every agent version. */
  private supportsViewedResize = false
  /** Selected only when both peers advertised the exact additive capability. It permits ONE byte-identical
   * delivery retry for a creation request; it never retries against a legacy agent. */
  private supportsCreationReplay = false
  private supportsDesktopAccessStatus = false
  private supportsAuthorizationRefresh = false
  /** What this concrete browser transport actually proposed. Agent advertisement alone is never selection. */
  private offeredTerminalGzip = false
  private supportsTerminalGzip = false
  private transportConnected = false
  private authorization: BoundAuthorization | null = null
  private pendingAuthorization: BoundAuthorization | null = null
  private authorizationRefreshTimer: ReturnType<typeof setTimeout> | null = null
  private authorizationRefreshAckTimer: ReturnType<typeof setTimeout> | null = null
  private authorizationRefreshAbort: AbortController | null = null
  private authorizationRefreshGeneration = 0
  private authorizationRefreshFailures = 0
  private pendingCreationReplays = new Map<string, PendingCreationReplay>()
  /** The session ids from the most recent session_list_result — reused to parse an unsolicited workspace_update push
   * (which carries workspace_metadata but not the session list). */
  private lastKnownSessions: string[] = []
  private attachedChannel: number | null = null
  private attachedSessionId: string | null = null
  /** Proven session↔channel bindings for this transport lifetime. This lets explicit detach retire buffered state
   * even when the detached pane is not currently focused; focus changes alone never retire a binding. */
  private attachedChannels = new Map<string, number>()
  private channelEncodings = new Map<number, string>()
  private viewedChannelEpoch = 0
  private pendingAttachEncodings = new Map<string, { sessionId: string; encoding: string | null; deadline: number }>()
  private pendingAttachTimer: ReturnType<typeof setTimeout> | null = null
  private codecDecoder: OrderedTerminalCodecDecoder
  private sync: SyncState | null = null
  private held: GridSnapshot | null = null
  private renderer: GridRenderer | null = null
  private searchHighlights: readonly HighlightSpan[] = []
  /** Synchronous onGridSnapshot subscribers recompute search/selection spans. Their publication belongs to the
   * accepted Grid/Damage paint already in progress and must not recursively paint the same grid first. */
  private gridSnapshotNotificationDepth = 0
  // Multi-pane input encoding: in the N-up path the live grid (and thus app_cursor/bracketed_paste modes) lives
  // in the per-pane bank, not on `held`. The controller wires this to report the ACTIVE pane's modes so keys/
  // paste encode correctly (arrow keys in app-cursor apps, bracketed paste). Null ⇒ fall back to `held` (the
  // ordinary single-session path is unchanged).
  private activePaneModes: (() => TermModes | null) | null = null

  // ---- scrollback view state (client-side, daemon Scrollback protocol) ----
  // viewOffset 0 = live (follow bottom). >0 = that many rows scrolled UP into history. While scrolled up,
  // live grid/damage updates `held` but do NOT repaint the viewport (no yank-to-bottom). historyLen is the
  // total history the daemon reports; gridRows is the visible height (for paging).
  private viewOffset = 0
  private historyLen = 0
  private gridRows = 24
  private gridCols = 80
  private pendingScrollback = false // a visible Scrollback request is in flight; wheel spam updates viewOffset only.
  private pendingScrollbackOffset: number | null = null
  private pendingScrollbackPrefetch = new Set<number>()
  private scrollbackPrefetchTimer: ReturnType<typeof setTimeout> | null = null
  private scrollbackResponseTimer: ReturnType<typeof setTimeout> | null = null
  private scrollbackRequests = new Map<number, ScrollbackRequestTrace>()
  private incomingChunkTrace = new Map<number, PendingChunkTrace>()
  private dbwSeq = 0 // db_write_trace request counter (?inspect=1 debug fetches)
  private syncDebugSeq = 0 // debug_sync_snapshot request counter
  // Cache of fetched history pages (offset_from_top → painted rows) so re-scrolling over the same region
  // is instant instead of a relay round-trip. Bounded + cleared when history shifts (live output grows).
  private sbCache = new Map<number, CopyRows>()
  /** The history rows currently visible on the canvas. Unlike the fetch cache, this survives live output while
   * scrolled so a terminal-chrome relayout can replay the pinned viewport onto a genuinely new canvas. */
  private displayedHistory: CopyRows & {
    cols: number
    viewRows: number
    highlights: readonly HighlightSpan[]
  } | null = null
  private static readonly SB_CACHE_MAX = 64
  private static readonly SB_PREFETCH_PAGES = 4
  /**
   * Bound one decoded scrollback response by cell volume as well as by the daemon's 256-row protocol cap.
   * A wide terminal previously requested 256 verbose Cell rows (about 6-7 MiB in the reproduced 250-column
   * relay case). Four such replies can fill the agent's deliberate 32 MiB daemon-output safety queue before
   * WebRTC drains one. This budget keeps the existing multi-screen cache on ordinary terminals while shrinking
   * wide pages; it never returns fewer rows than the visible viewport unless the protocol's row cap itself does.
   */
  private static readonly SB_TARGET_CELLS = 8_192

  constructor(
    private readonly transport: RemoteTransport,
    private readonly token: string,
    private readonly deviceId: string,
    private readonly cbs: RemoteSessionCallbacks = {},
    /** Correlation id for the connection trace — sent in the auth message so the agent tags its structured events
     * with the SAME id (one grep spans browser+agent). Optional; empty means uncorrelated (still traced). */
    private readonly traceId: string = '',
    /** Monotonic attach-ownership clock; injectable only so timeout/retirement invariants are deterministic. */
    private readonly pendingAttachNow: () => number = perfNow,
    /** Wall clock for authorization expiry/catch-up; injectable so suspend/wake boundaries are deterministic. */
    private readonly authorizationNow: () => number = () => Date.now(),
  ) {
    this.codecDecoder = new OrderedTerminalCodecDecoder({
      isSelected: (channel) => this.channelEncodings.get(channel) === TERMINAL_GZIP_JSON_V1,
      isBound: (channel) => [...this.attachedChannels.values()].includes(channel),
      onFrame: (frame) => this.onDecodedBinaryFrame(frame),
      onProgress: (channel) => {
        const sessionId = this.sessionForAttachedChannel(channel)
        if (sessionId) this.cbs.onTerminalProgress?.(sessionId)
      },
      onFatal: () => {
        // A codec failure means this owner can no longer prove an ordered terminal baseline. Closing the current
        // transport enters the controller's existing fresh-session reconnect path; never continue after a gap.
        this.transport.fail()
      },
    })
    connTrace.resetWireSeq() // new connection → wire ordering starts at #1 for both directions
    transport.onState((s) => this.onState(s))
    transport.onText((t) => this.onText(t))
    transport.onBinary((b) => this.onBinary(b))
    // Inspector seam (?inspect=1): the newest session is the one the "DB writes" fetch rides.
    setDbWriteFetcher((count) => this.dbWriteTrace(count))
  }

  // ---- lifecycle ----

  private onState(state: ControlState): void {
    this.cbs.onState?.(state)
    if (state === 'connected') {
      // Capabilities belong to one concrete transport lifetime. A reconnect must prove them again; otherwise a
      // delayed message from a retired channel could make an older replacement peer look capable.
      this.transportConnected = true
      this.supportsViewedResize = false
      this.supportsCreationReplay = false
      this.supportsDesktopAccessStatus = false
      this.supportsAuthorizationRefresh = false
      this.cancelAuthorizationRefresh()
      this.authorization = this.transport.currentAuthorization?.() ?? null
      this.offeredTerminalGzip = terminalGzipDecoderAvailable()
      this.supportsTerminalGzip = false
      this.channelEncodings.clear()
      this.pendingAttachEncodings.clear()
      this.cancelPendingAttachTimer()
      this.codecDecoder.clearAll()
      // DataChannel open → S3b handshake. hello then auth (connected ≠ authorized).
      this.send({
        type: 'hello',
        protocol_version: PROTOCOL_VERSION,
        device_id: this.deviceId,
        role: 'client',
        capabilities: [
          CREATION_REQUEST_REPLAY_CAPABILITY,
          DESKTOP_ACCESS_STATUS_CAPABILITY,
          AUTHORIZATION_REFRESH_CAPABILITY,
          ...(this.offeredTerminalGzip ? [TERMINAL_GZIP_JSON_V1] : []),
        ],
      })
      // Present the token bound to the CURRENT signaling session. The transport mints a fresh token per
      // signaling session (direct, then relay), so its `currentToken()` names the session the agent is
      // answering; the agent fail-closed-requires token.signal_session_id to match. When the transport mints
      // per-session, we present ONLY that token — never the unbound constructor token (no downgrade): a null
      // here means minting failed, so we send an empty token and let the agent refuse. The constructor token
      // is used solely by legacy/fake transports that don't implement currentToken (tests).
      const token = this.transport.currentToken ? (this.transport.currentToken() ?? '') : this.token
      // trace_id (optional) lets the agent correlate its structured events with the browser's for this connection.
      this.send({ type: 'auth', token, trace_id: this.traceId })
    }
    if (
      state === 'revoked' ||
      state === 'closed' ||
      state === 'authorization_required' ||
      state === 'auth_refused' ||
      state === 'offline' ||
      state === 'error'
    ) {
      this.transportConnected = false
      this.supportsViewedResize = false
      this.supportsCreationReplay = false
      this.supportsDesktopAccessStatus = false
      this.supportsAuthorizationRefresh = false
      this.offeredTerminalGzip = false
      this.supportsTerminalGzip = false
      this.authenticated = false
      this.cancelAuthorizationRefresh()
      this.authorization = null
      this.clearCreationReplayTimers()
      // SECURITY: drop the attach so no further input/paste can be sent on a revoked/closed channel.
      this.chunks.clearAll()
      this.codecDecoder.clearAll()
      this.incomingChunkTrace.clear()
      this.attachedChannels.clear()
      this.channelEncodings.clear()
      this.pendingAttachEncodings.clear()
      this.cancelPendingAttachTimer()
      this.attachedChannel = null
      this.attachedSessionId = null
      this.resetScrollbackState()
    }
  }

  private onText(json: string): void {
    const parsed = parseBoundedControlJson(json)
    if ('err' in parsed) {
      // A malformed or over-budget agent frame is a transport-integrity failure, not a message to keep retrying.
      // Retire the peer so repeated frames cannot consume browser parse/walk work or mutate partial UI state.
      this.transport.fail()
      return
    }
    const msg = parsed.ok
    const type = msg.type
    // WIRE TRACE (inbound ← agent). Content-blind (counts only). Before dispatch so EVERY inbound message is recorded,
    // even if a handler early-returns or the type is unknown.
    connTrace.wire(this.traceId, 'in', String(type ?? 'unknown'), wireDetail(msg))
    // Connected is not authenticated. Until the agent has accepted this transport's token, only the protocol
    // greeting and the two initial-auth outcomes may affect browser state. In particular, never surface cached or
    // injected session metadata, transcript previews, workspace pushes, debug replies, or correlated errors from a
    // DataChannel that has not crossed the auth boundary.
    if (!this.authenticated && type !== 'hello' && type !== 'auth_ok' && type !== 'auth_refused') return
    switch (type) {
      case 'hello':
        // Only a current, structurally valid agent Hello can enable an additive behavior. In particular, never
        // infer capabilities from auth_ok, unknown messages, near-match strings, or a callback after transport
        // retirement. Old agents omit `capabilities`, which intentionally leaves the safer legacy mode selected.
        if (!this.transportConnected) return
        {
          const capabilities = boundedCapabilities(msg.capabilities)
          const validHello = msg.protocol_version === PROTOCOL_VERSION && msg.role === 'agent' && capabilities !== null
          this.supportsViewedResize = validHello && capabilities.includes(VIEWED_RESIZE_CAPABILITY)
          const supportsCreationReplay =
            validHello && capabilities.includes(CREATION_REQUEST_REPLAY_CAPABILITY)
          if (this.supportsCreationReplay && !supportsCreationReplay) this.clearCreationReplayTimers()
          this.supportsCreationReplay = supportsCreationReplay
          this.supportsDesktopAccessStatus =
            validHello && capabilities.includes(DESKTOP_ACCESS_STATUS_CAPABILITY)
          this.supportsAuthorizationRefresh =
            validHello && capabilities.includes(AUTHORIZATION_REFRESH_CAPABILITY)
          this.supportsTerminalGzip =
            this.offeredTerminalGzip && validHello && capabilities.includes(TERMINAL_GZIP_JSON_V1)
          if (this.authenticated) this.scheduleAuthorizationRefresh()
        }
        return
      case 'auth_ok':
        if (!this.transportConnected) return
        // AuthOk is the initial lifecycle transition only. A duplicate frame must not re-emit authenticated and
        // trigger session_list/winsize/attach/history hydration in the controller.
        if (this.authenticated) return
        this.authenticated = true
        this.cbs.onAgentBuild?.(parseAgentBuildGit(msg.agent_build_git))
        this.cbs.onState?.('authenticated')
        this.scheduleAuthorizationRefresh()
        return
      case 'auth_refresh_ok':
        if (!this.transportConnected || !this.authenticated || !this.pendingAuthorization) return
        if (!Number.isSafeInteger(msg.expires_at_ms) ||
            Number(msg.expires_at_ms) !== this.pendingAuthorization.expiresAtMs ||
            this.pendingAuthorization.deadlineMs <= this.authorizationNow()) {
          this.failAuthorizationRefresh()
          return
        }
        if (this.authorizationRefreshAckTimer) clearTimeout(this.authorizationRefreshAckTimer)
        this.authorizationRefreshAckTimer = null
        this.authorization = this.pendingAuthorization
        this.pendingAuthorization = null
        this.authorizationRefreshFailures = 0
        this.scheduleAuthorizationRefresh()
        return
      case 'auth_refresh_refused':
        if (!this.transportConnected || !this.authenticated) return
        this.failAuthorizationRefresh()
        return
      case 'auth_refused':
        if (!this.transportConnected) return
        this.authenticated = false
        this.cbs.onState?.(String(msg.reason) === 'revoked' ? 'revoked' : 'auth_refused')
        return
      case 'desktop_access_status': {
        if (!this.transportConnected || !this.authenticated || !this.supportsDesktopAccessStatus) return
        const status = parseDesktopAccessStatus(msg)
        if (status) this.cbs.onDesktopAccessStatus?.(status)
        return
      }
      case 'session_list_result':
        {
          const sessions = parseSessionIds(msg.sessions)
          this.lastKnownSessions = sessions // reused to parse an unsolicited workspace_update push
          this.cbs.onSessions?.(
            sessions,
            parseSessionMetadata(msg.session_metadata),
            parseWorkspaceMetadata(msg.workspace_metadata, sessions),
          )
        }
        return
      case 'workspace_update':
        {
          // Unsolicited live-sync push. It now carries the SAME triple as session_list_result — sessions +
          // metadata — so the pushed state is SELF-SUFFICIENT: refresh lastKnownSessions FIRST (pane liveness
          // parses against it; a desktop-created pane must arrive live/clickable, not as a dead placeholder).
          // `sessions` absent = an older agent build → keep the previous list (old behavior, degraded).
          const epoch = Number(msg.epoch)
          const pushedSessions = Array.isArray(msg.sessions) ? parseSessionIds(msg.sessions) : null
          if (pushedSessions) this.lastKnownSessions = pushedSessions
          const workspaceMetadata = parseWorkspaceMetadata(msg.workspace_metadata, this.lastKnownSessions)
          this.cbs.onWorkspaceUpdate?.(epoch, workspaceMetadata, pushedSessions)
          // Slice 4: ack RECEIPT unconditionally — even when the epoch guard in remote-client drops the apply as a
          // duplicate (e.g. the agent re-pushed because our previous ack was lost). Acking only applied epochs would
          // make a lost ACK re-push forever; acking receipt makes both loss cases converge. Content-blind (epoch only).
          if (Number.isFinite(epoch)) {
            this.send({ type: 'workspace_update_ack', epoch })
          }
        }
        return
      case 'db_write_trace_result':
        // Debug ledger rows for ?inspect=1 — already content-blind at the source; hand to the panel.
        publishDbWrites(Array.isArray(msg.entries) ? (msg.entries as Record<string, unknown>[]) : [])
        return
      case 'debug_sync_snapshot_result':
        this.cbs.onDebugSyncSnapshot?.(String(msg.request_id ?? ''), msg.agent)
        return
      case 'attach_ok':
        {
          if (!this.authenticated) return // queued proof from a retired transport cannot recreate a binding
          const channel = Number(msg.channel)
          const sessionId = String(msg.session_id)
          const requestId = String(msg.request_id ?? '')
          const requested = this.pendingAttachEncodings.get(requestId)
          this.pendingAttachEncodings.delete(requestId)
          this.armPendingAttachTimer()
          const confirmedEncoding = msg.terminal_encoding
          let selectedEncoding: string | null = null
          if (confirmedEncoding !== undefined) {
            if (
              confirmedEncoding !== TERMINAL_GZIP_JSON_V1 ||
              !this.supportsTerminalGzip ||
              requested?.sessionId !== sessionId ||
              requested.encoding !== TERMINAL_GZIP_JSON_V1
            ) {
              this.transport.fail()
              return
            }
            selectedEncoding = TERMINAL_GZIP_JSON_V1
          }
          if (this.cbs.shouldAcceptAttach?.(sessionId, channel, requestId) === false) {
            // attach_ok is the first proof that the strict agent owns this session for us. Drain exactly once
            // without mutating the currently-active channel, sync state, held grid, or scrollback cache.
            this.send({ type: 'detach', session_id: sessionId })
            return
          }
          // A newly-proven channel starts a fresh stream. Do not clear the previously active channel here: in the
          // multi-pane path it may still own a large, partially reassembled frame while focus changes.
          this.chunks.clear(channel)
          this.codecDecoder.clear(channel)
          this.incomingChunkTrace.delete(channel)
          for (const [boundSessionId, boundChannel] of this.attachedChannels) {
            if (boundSessionId !== sessionId && boundChannel === channel) this.attachedChannels.delete(boundSessionId)
          }
          this.attachedChannels.set(sessionId, channel)
          if (selectedEncoding) this.channelEncodings.set(channel, selectedEncoding)
          else this.channelEncodings.delete(channel)
          this.attachedChannel = channel
          this.attachedSessionId = sessionId
        }
        this.sync = new SyncState(this.attachedSessionId)
        this.held = null
        const viewedEpoch = this.viewedChannelEpoch
        this.cbs.onAttached?.(this.attachedSessionId, this.attachedChannel)
        // Standalone/single-pane consumers view the newly attached channel. A multi-pane callback explicitly
        // signals its actual viewed channel (or null) before returning; never let attach arrival order overwrite it.
        if (this.viewedChannelEpoch === viewedEpoch) this.setViewedChannel(this.attachedChannel)
        return
      case 'error':
        {
          const requestId = typeof msg.request_id === 'string' ? msg.request_id : undefined
          const sessionId = typeof msg.session_id === 'string' ? msg.session_id : undefined
          const correlation = requestId !== undefined || sessionId !== undefined
            ? { requestId, sessionId }
            : undefined
          if (requestId !== undefined) {
            this.pendingAttachEncodings.delete(requestId)
            this.armPendingAttachTimer()
          }
          const code = String(msg.code)
          this.cbs.onError?.(code, String(msg.message), correlation)
          // The agent refuses an over-budget input frame rather than partially forwarding that frame. Continuing
          // on the same terminal stream after such a gap would make a paste look successful when it was not. Retire
          // the owner so the controller reconnects explicitly; no payload is logged or replayed automatically.
          if (code === 'input_rate_limited') this.transport.fail()
        }
        return
      case 'winsize_owner_changed':
        this.cbs.onWinsizeOwnerChanged?.(msg.owner === 'remote' ? 'remote' : 'local')
        return
      default: {
        const agentSessions = parseAgentSessionsReply(msg)
        if (agentSessions?.type === 'agent_sessions_result') {
          this.cbs.onAgentSessions?.(agentSessions)
          return
        }
        if (agentSessions?.type === 'agent_sessions_error') {
          this.cbs.onAgentSessionsError?.(agentSessions)
          return
        }
        const directories = parseDirectoriesReply(msg)
        if (directories?.type === 'directories_result') {
          this.cbs.onDirectoriesResult?.(directories)
          return
        }
        if (directories?.type === 'directories_error') {
          this.cbs.onDirectoriesError?.(directories)
          return
        }
        const preview = parseAgentSessionPreviewReply(msg)
        if (preview) {
          this.cbs.onAgentSessionPreview?.(preview)
          return
        }
        const managed = parseAgentSessionManageReply(msg)
        if (managed) {
          this.cbs.onAgentSessionManaged?.(managed)
          return
        }
        // Slice E: create_session replies (session_created / session_create_error). The E1 parser validates
        // shape + coerces unknown error codes; non-matching messages return null and are ignored below.
        const reply = parseCreateSessionReply(msg)
        if (reply) this.completeCreationDelivery(reply.request_id, ['create_session'])
        if (reply?.type === 'session_created') this.cbs.onSessionCreated?.(reply.session_id, reply.label, reply.request_id)
        else if (reply?.type === 'session_create_error') this.cbs.onSessionCreateError?.(reply.code, reply.message, reply.request_id)
        const splitReply = parseSplitPaneReply(msg)
        if (splitReply) this.completeCreationDelivery(splitReply.request_id, ['split_pane', 'new_pane'])
        if (splitReply?.type === 'split_pane_ok') this.cbs.onSplitPaneOk?.(splitReply.session_id, splitReply.tab_id, splitReply.request_id)
        else if (splitReply?.type === 'split_pane_error') this.cbs.onSplitPaneError?.(splitReply.code, splitReply.message, splitReply.request_id)
        const reviveReply = parseRevivePaneReply(msg)
        if (reviveReply) this.completeCreationDelivery(reviveReply.request_id, ['revive_pane'])
        if (reviveReply?.type === 'revive_pane_ok') this.cbs.onRevivePaneOk?.(reviveReply.session_id, reviveReply.request_id)
        else if (reviveReply?.type === 'revive_pane_error') this.cbs.onRevivePaneError?.(reviveReply.code, reviveReply.message, reviveReply.request_id)
        const startPaneReply = parseStartPaneSessionReply(msg)
        if (startPaneReply) this.completeCreationDelivery(startPaneReply.request_id, ['start_pane_session'])
        if (startPaneReply?.type === 'start_pane_session_ok') this.cbs.onStartPaneSessionOk?.(startPaneReply.session_id, startPaneReply.request_id)
        else if (startPaneReply?.type === 'start_pane_session_error') this.cbs.onStartPaneSessionError?.(startPaneReply.code, startPaneReply.message, startPaneReply.request_id)
        const stashReply = parseStashPaneReply(msg)
        if (stashReply?.type === 'stash_pane_ok') this.cbs.onStashPaneOk?.(stashReply.request_id)
        else if (stashReply?.type === 'stash_pane_error') this.cbs.onStashPaneError?.(stashReply.code, stashReply.message, stashReply.request_id)
        const removeReply = parseRemovePaneReply(msg)
        if (removeReply?.type === 'remove_pane_ok') this.cbs.onRemovePaneOk?.(removeReply.request_id)
        else if (removeReply?.type === 'remove_pane_error') this.cbs.onRemovePaneError?.(removeReply.code, removeReply.message, removeReply.request_id)
        const renameReply = parseRenameReply(msg)
        if (renameReply?.type === 'rename_ok') this.cbs.onRenameOk?.(renameReply.request_id)
        else if (renameReply?.type === 'rename_error') this.cbs.onRenameError?.(renameReply.code, renameReply.message, renameReply.request_id)
        const focusWindowReply = parseFocusWindowReply(msg)
        if (focusWindowReply?.type === 'focus_window_ok') this.cbs.onFocusWindowOk?.(focusWindowReply.request_id)
        else if (focusWindowReply?.type === 'focus_window_error') this.cbs.onFocusWindowError?.(focusWindowReply.code, focusWindowReply.message, focusWindowReply.request_id)
        const closeWindowReply = parseCloseWindowReply(msg)
        if (closeWindowReply?.type === 'close_window_ok') this.cbs.onCloseWindowOk?.(closeWindowReply.request_id)
        else if (closeWindowReply?.type === 'close_window_error') this.cbs.onCloseWindowError?.(closeWindowReply.code, closeWindowReply.message, closeWindowReply.request_id)
        const newWindowReply = parseNewWindowReply(msg)
        if (newWindowReply) this.completeCreationDelivery(newWindowReply.request_id, ['new_window'])
        if (newWindowReply?.type === 'new_window_ok') this.cbs.onNewWindowOk?.(newWindowReply.window_id, newWindowReply.session_id, newWindowReply.request_id)
        else if (newWindowReply?.type === 'new_window_error') this.cbs.onNewWindowError?.(newWindowReply.code, newWindowReply.message, newWindowReply.request_id)
        const projectReply = parseProjectEditReply(msg)
        if (projectReply) this.completeCreationDelivery(projectReply.request_id, ['project_create'])
        if (projectReply?.type === 'project_edit_ok') this.cbs.onProjectEditOk?.(projectReply.project_id, projectReply.session_id, projectReply.request_id)
        else if (projectReply?.type === 'project_edit_error') this.cbs.onProjectEditError?.(projectReply.code, projectReply.message, projectReply.request_id)
        return // ignore anything else (hello/pong/etc.)
      }
    }
  }

  // Protocol-bounded reassembly for chunked terminal_output (large Grid frames are split by the agent).
  private chunks = new BoundedChunkReassembler()

  // Inbound binary terminal_output: decode the frame, reassemble chunks, then the daemon line → render.
  private onBinary(bytes: Uint8Array): void {
    // A queued DataChannel callback can run after closed/revoked/offline. Reject it before the optional multi-pane
    // consumer so retired router bindings can never append, paint, or report progress.
    if (!this.authenticated) return
    const res = decodeFrame(bytes)
    if ('err' in res) {
      this.transport.fail()
      return
    }
    this.codecDecoder.push(res.ok)
  }

  private onDecodedBinaryFrame(frame: TerminalFrame): void {
    const decodeStart = perfNow()
    if (this.cbs.onTerminalFrame?.(frame)) return
    // Before attach_ok, after detach, and for a retired channel, output is not ours and must neither allocate
    // reassembly memory nor extend an attach watchdog.
    if (this.attachedChannel === null || this.attachedSessionId === null || frame.channel !== this.attachedChannel) return

    let line: string
    let lineTrace: IncomingLineTrace
    if (frame.kind === FrameKind.TerminalOutputChunk) {
      const receivedAt = perfNow()
      const assembled = this.chunks.push(frame.channel, frame.payload)
      if (assembled.kind === 'dropped') {
        this.incomingChunkTrace.delete(frame.channel)
        return
      }
      if (assembled.chunkBytes > 0) this.cbs.onTerminalProgress?.(this.attachedSessionId)
      const prior = this.incomingChunkTrace.get(frame.channel)
      const nextTrace: PendingChunkTrace = prior
        ? { firstAt: prior.firstAt, chunks: prior.chunks + 1, bytes: assembled.totalBytes }
        : { firstAt: receivedAt, chunks: 1, bytes: assembled.totalBytes }
      this.incomingChunkTrace.set(frame.channel, nextTrace)
      if (assembled.kind === 'partial') return
      this.incomingChunkTrace.delete(frame.channel)
      const reassembleStart = perfNow()
      line = new TextDecoder().decode(assembled.bytes)
      lineTrace = {
        bytes: nextTrace.bytes,
        chunks: nextTrace.chunks,
        transferMs: receivedAt - nextTrace.firstAt,
        reassembleMs: perfNow() - reassembleStart,
      }
    } else if (frame.kind === FrameKind.TerminalOutput) {
      const textStart = perfNow()
      line = frame.decodedText ?? new TextDecoder().decode(frame.payload)
      lineTrace = {
        bytes: frame.transport?.decodedBytes ?? frame.payload.length,
        chunks: frame.transport?.chunkCount ?? 1,
        transferMs: frame.transport?.transferMs ?? 0,
        reassembleMs: (frame.transport?.codecQueueMs ?? 0) +
          (frame.transport?.codecMs ?? 0) + (perfNow() - textStart),
      }
    } else {
      return // TerminalInput is agent-bound; ignore here
    }

    recordFrame(line.length)
    this.onDaemonLine(line, lineTrace, perfNow() - decodeStart)
  }

  // ---- terminal core (reused from the existing client) ----

  attachRenderer(canvas: HTMLCanvasElement): void {
    if (this.renderer?.usesCanvas(canvas)) return
    this.renderer = new GridRenderer(canvas)
    if (!this.held) return

    // The app deliberately replaces the scalar canvas when terminal chrome changes (for example, when a sidebar
    // drag ends). Rebinding a renderer must not rely on a later daemon frame: the just-settled PTY size may be a
    // no-op, in which case the daemon correctly emits no replacement Grid and the fresh canvas would otherwise
    // remain black until another resize/output event. Repaint the already-validated snapshot immediately. While
    // viewing history, replay the retained visible page instead of jumping to live. That retained page survives
    // live output invalidating the offset cache, because the old canvas intentionally stayed pinned too.
    if (this.viewOffset === 0) {
      this.paintHeldLive()
      return
    }
    if (this.displayedHistory) {
      this.renderer.resizeForGrid(this.displayedHistory.cols, this.displayedHistory.viewRows)
      this.renderer.paintRows(
        this.displayedHistory.rows,
        this.displayedHistory.cols,
        this.displayedHistory.viewRows,
        this.displayedHistory.highlights,
      )
      return
    }
    const cached = this.cachedRowsForOffset(this.viewOffset)
    if (cached) {
      this.renderer.resizeForGrid(this.gridCols, this.gridRows)
      this.paintScrollbackRows(cached)
    }
  }

  /** The on-screen CSS-px cell size of the single-session renderer's current paint (null before it paints).
   * Mouse px→cell mapping must use this, not a hardcoded cell constant — the grid is contain-scaled. */
  screenCellPx(): { cellW: number; cellH: number } | null {
    return this.renderer?.screenCellPx() ?? null
  }

  liveModes(): TermModes | null {
    return this.held ? this.modes() : null
  }

  isAltScreen(): boolean {
    return this.held?.alt_screen ?? false
  }

  setSearchHighlights(spans: readonly HighlightSpan[]): void {
    if (highlightSpansEqual(this.searchHighlights, spans)) return
    this.searchHighlights = spans
    // A Grid/Damage observer publication is folded into the outer immediate paint. User-driven search/selection
    // updates occur outside that notification and repaint the currently visible live/history view immediately.
    if (this.gridSnapshotNotificationDepth > 0) return
    if (this.viewOffset === 0) {
      this.paintHeldLive()
      return
    }
    if (this.displayedHistory) {
      this.displayedHistory = { ...this.displayedHistory, highlights: spans }
      this.renderer?.paintRows(
        this.displayedHistory.rows,
        this.displayedHistory.cols,
        this.displayedHistory.viewRows,
        spans,
      )
    }
  }

  // Measurement showed paint is cheap (~6 ms) and infrequent, so accepted live frames paint IMMEDIATELY.
  // requestAnimationFrame deferral made sparse typing echo lag; observer re-entry is suppressed above instead.
  private paintHeldLive(): void {
    if (this.viewOffset !== 0 || !this.held) return
    this.displayedHistory = null
    this.renderer?.resizeForGrid(this.held.cols, this.held.rows)
    this.renderer?.paint(this.held, this.searchHighlights)
  }

  private notifyGridSnapshot(grid: GridSnapshot): void {
    this.gridSnapshotNotificationDepth++
    try {
      this.cbs.onGridSnapshot?.(grid)
    } finally {
      this.gridSnapshotNotificationDepth--
    }
  }

  private onDaemonLine(line: string, lineTrace?: IncomingLineTrace, frameDecodeMs = 0): void {
    const parseStart = perfNow()
    const dec = decodeEvent(line)
    if ('err' in dec) return
    const parseMs = perfNow() - parseStart + frameDecodeMs
    if (isKnownEvent(dec.ok)) this.handle(dec.ok, lineTrace, parseMs)
  }

  private handle(ev: DaemonEvent, lineTrace?: IncomingLineTrace, parseMs = 0): void {
    if (!this.sync) return
    recordEvent(ev.ev)
    switch (ev.ev) {
      case 'grid': {
        const r = this.sync.onGrid(ev.id, ev.grid)
        if ('ok' in r && r.ok.repaint) {
          this.held = ev.grid
          this.gridRows = ev.grid.rows
          this.gridCols = ev.grid.cols
          this.notifyGridSnapshot(ev.grid)
          if (ev.grid.rows > MAX_SCROLLBACK_ROWS_PER_REQUEST) {
            this.viewOffset = 0
            this.invalidateScrollCache()
          }
          // Follow live only when at the bottom; while scrolled up keep the history view in place. The
          // scroll cache only matters while scrolled up — skip the bookkeeping on the live (typing) path.
          if (this.viewOffset === 0) {
            this.paintHeldLive()
          } else {
            this.invalidateScrollCache() // history shifted under the new grid
            this.notifyScrollView()
          }
        }
        break
      }
      case 'damage': {
        if (!this.held) {
          this.cbs.onBaselineRequired?.(ev.frame.id, 'damage before grid')
          this.requestSnapshot()
          break
        }
        const out = this.sync.onDamage(ev.frame.id, ev.frame, this.held)
        if (out.kind === 'applied') {
          this.held = out.grid
          this.notifyGridSnapshot(out.grid)
          if (this.viewOffset === 0) {
            this.paintHeldLive()
          } else {
            this.invalidateScrollCache() // new live output → history offsets shift
            this.notifyScrollView() // live moved underneath; "jump to live" stays available
          }
        } else if (out.kind === 'resync') {
          this.cbs.onBaselineRequired?.(ev.frame.id, out.reason)
          this.requestSnapshot()
        }
        break
      }
      case 'scrollback_rows': {
        // Scrollback replies carry no request id, so the currently attached session is the first ownership
        // boundary. A late reply from a previously viewed channel must not consume the new pane's same-offset
        // trace, paint its rows, or settle the controller's timeout.
        if (!this.attachedSessionId || ev.id !== this.attachedSessionId) break
        // a reply to our Scrollback request — paint the historical page (view-only, cursor hidden).
        // The daemon is allowed to clamp an over-deep requested offset to history_len. Correlate that echoed
        // offset with the sole in-flight request instead of leaving the requested key pending forever.
        let requestOffset = ev.offset_from_top
        let trace = this.scrollbackRequests.get(requestOffset)
        if (trace?.sessionId !== ev.id) trace = undefined
        if (!trace && this.scrollbackRequests.size === 1) {
          const only = this.scrollbackRequests.entries().next().value as [number, ScrollbackRequestTrace] | undefined
          if (only?.[1].sessionId === ev.id) [requestOffset, trace] = only
        }
        if (!rowCopyCellsValid(ev.rows, ev.row_copy)) {
          if (trace) {
            this.scrollbackRequests.delete(requestOffset)
            this.pendingScrollbackPrefetch.delete(requestOffset)
            if (!trace.prefetch && requestOffset === this.pendingScrollbackOffset) {
              this.pendingScrollback = false
              this.pendingScrollbackOffset = null
            }
            this.clearScrollbackResponseTimerIfIdle()
          }
          this.cbs.onScrollbackReply?.(ev.id, requestOffset, false)
          break
        }
        const accepted = this.held !== null && ev.generation === this.held.generation
        if (!trace) {
          // A bank-owned request can cross a multi→single route transition without a RemoteSession-local trace.
          // Settle only the controller owner for this same session; the scalar cache/view must remain untouched.
          this.cbs.onScrollbackReply?.(ev.id, ev.offset_from_top, accepted)
          break
        }
        this.scrollbackRequests.delete(requestOffset)
        this.cbs.onScrollbackReply?.(ev.id, requestOffset, accepted)
        if (!accepted) {
          this.pendingScrollbackPrefetch.delete(requestOffset)
          if (!trace.prefetch && requestOffset === this.pendingScrollbackOffset) {
            this.pendingScrollback = false
            this.pendingScrollbackOffset = null
          }
          this.clearScrollbackResponseTimerIfIdle()
          this.viewOffset = 0
          this.invalidateScrollCache()
          this.paintHeldLive()
          this.notifyScrollView()
          break
        }
        this.historyLen = ev.history_len
        const isVisibleReply = trace
          ? !trace.prefetch && requestOffset === this.pendingScrollbackOffset
          : requestOffset === this.pendingScrollbackOffset
        if (isVisibleReply) {
          this.pendingScrollback = false
          this.pendingScrollbackOffset = null
        }
        this.pendingScrollbackPrefetch.delete(requestOffset)
        this.clearScrollbackResponseTimerIfIdle()
        // A first-history-page warm deliberately lands while the user is still at live. Cache it so the first
        // upward scroll is instant, but never repaint/yank the viewport away from live.
        if (this.viewOffset === 0) {
          if (trace?.prefetch) this.cacheScrollbackRows(ev.offset_from_top, ev)
          break
        }
        // clamp if we over-scrolled past the real history top.
        if (this.viewOffset > ev.history_len) this.viewOffset = ev.history_len
        if (this.viewOffset === 0) {
          this.jumpToLive()
          break
        }
        // Cache this fetched window (bounded). We request more than one visible page, but paint only the page that
        // matches the current viewOffset. If the user scrolled again while this request was in flight, keep the rows
        // for later but don't yank the visible terminal back to the older offset.
        const cachePaintStart = perfNow()
        this.cacheScrollbackRows(ev.offset_from_top, ev)
        const page = this.cachedRowsForOffset(this.viewOffset)
        if (page) this.paintScrollbackRows(page)
        const cachePaintMs = perfNow() - cachePaintStart
        if (trace) {
          const line = lineTrace ?? { bytes: 0, chunks: 0, transferMs: 0, reassembleMs: 0 }
          const entry: ScrollbackPerfEntry = {
            ts: Date.now(),
            session: ev.id,
            offset: ev.offset_from_top,
            count: trace.count,
            rows: ev.rows.length,
            historyLen: ev.history_len,
            bytes: line.bytes,
            chunks: line.chunks,
            transferMs: line.transferMs,
            reassembleMs: line.reassembleMs,
            parseMs,
            cachePaintMs,
            totalMs: perfNow() - trace.sentAt,
            prefetch: trace.prefetch,
          }
          pushScrollbackPerf(entry)
          connTrace.log(
            this.traceId,
            'scrollback',
            'reply',
            'ok',
            `offset=${entry.offset} rows=${entry.rows} bytes=${entry.bytes} chunks=${entry.chunks} transferMs=${entry.transferMs.toFixed(1)} parseMs=${entry.parseMs.toFixed(1)} paintMs=${entry.cachePaintMs.toFixed(1)} totalMs=${entry.totalMs.toFixed(1)} ${entry.prefetch ? 'prefetch' : 'visible'}`,
          )
        }
        // Wheel/trackpad bursts can move the desired viewport while an older Scrollback request is still in
        // flight. Treat that stale reply as cache-fill, then request only the latest desired offset instead of
        // walking through every intermediate scroll position.
        const needsLatestVisiblePage = this.viewOffset > 0 && !page && !this.hasScrollbackInFlight()
        // One visible response may schedule one adjacent look-ahead page. A prefetch response never recursively
        // schedules another: the previous behavior walked the entire history every 80 ms while the user was idle.
        if (!needsLatestVisiblePage && trace && !trace.prefetch) {
          this.scheduleScrollbackPrefetch(ev.offset_from_top, ev.history_len)
        }
        this.notifyScrollView()
        if (needsLatestVisiblePage) this.requestScrollback()
        break
      }
      case 'output': {
        // RAW renderer mode: the daemon sends base64 PTY bytes; hand them to the xterm.js sink.
        if (this.cbs.onRawOutput) {
          const bin = atob(ev.data)
          const bytes = new Uint8Array(bin.length)
          for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
          this.cbs.onRawOutput(bytes)
        }
        break
      }
      case 'resync_required': {
        this.sync.onResyncRequired(ev.id)
        break
      }
      default:
        break
    }
  }

  // ---- outbound (post-auth only) ----

  listSessions(requestId = 'list'): void {
    if (!this.authenticated) return
    this.send({ type: 'session_list', request_id: requestId })
  }

  /** Debug surface (?inspect=1): fetch the tail of the desktop's db-write.jsonl — the two-writer DB
   * mutation ledger (content-blind rows). The reply is published via inspector-hooks. Auth-gated. */
  dbWriteTrace(count = 200): void {
    if (!this.authenticated) return
    this.dbwSeq += 1
    this.send({ type: 'db_write_trace', request_id: `dbw-${this.dbwSeq}`, count })
  }

  /** Content-blind one-shot debugger: ask the agent what workspace payload it would currently push/reply with. */
  debugSyncSnapshot(requestId?: string): string | null {
    if (!this.authenticated) return null
    this.syncDebugSeq += 1
    const id = requestId ?? `sync-debug-${this.syncDebugSeq}`
    this.send({ type: 'debug_sync_snapshot', request_id: id })
    return id
  }

  /** Tell the agent whether THIS browser should own the shared PTY winsize (the "Sized: Remote" toggle). The agent
   * computes the effective owner (serving>0 && selected) and replies winsize_owner_changed. Auth-gated. */
  setWinsizeOwner(selected: boolean): void {
    if (!this.authenticated) return
    this.send({ type: 'set_winsize_owner', selected })
  }

  /** Ask the agent to create a new local terminal session on demand. Auth-gated: pre-auth is a NO-OP.
   * The second arg accepts the old label string or richer desktop launch context. */
  createSession(requestId = 'create', labelOrOptions?: string | CreateSessionOptions): void {
    if (!this.authenticated) return
    this.sendCreation(buildCreateSession(requestId, labelOrOptions) as unknown as Record<string, unknown>)
  }

  listAgentSessions(requestId: string, agent: RemoteAgentKind, cwd?: string, includeHidden = false): void {
    if (!this.authenticated) return
    this.send(buildListAgentSessions(requestId, agent, cwd, includeHidden) as unknown as Record<string, unknown>)
  }

  /** Returns false if not authenticated OR the send was dropped (channel not open) — so the folder browser can
   * fail fast with an honest error instead of spinning until the 8s timeout. */
  listDirectories(requestId: string, path?: string): boolean {
    if (!this.authenticated) return false
    return this.send(buildListDirectories(requestId, path) as unknown as Record<string, unknown>)
  }

  previewAgentSession(requestId: string, agent: RemoteAgentKind, sessionId: string, cwd?: string, maxLines?: number): void {
    if (!this.authenticated) return
    this.send(buildPreviewAgentSession(requestId, agent, sessionId, cwd, maxLines) as unknown as Record<string, unknown>)
  }

  manageAgentSession(
    requestId: string,
    action: 'rename' | 'hide' | 'unhide' | 'delete',
    agent: RemoteAgentKind,
    sessionId: string,
    opts: { cwd?: string; name?: string } = {},
  ): void {
    if (!this.authenticated) return
    this.send(buildManageAgentSession(requestId, action, agent, sessionId, opts) as unknown as Record<string, unknown>)
  }

  splitPane(
    requestId: string,
    windowId: string,
    fromPaneId: string,
    dir: SplitPaneDir,
    opts: SplitPaneOptions = {},
  ): void {
    if (!this.authenticated) return
    this.sendCreation(buildSplitPane(requestId, windowId, fromPaneId, dir, opts) as unknown as Record<string, unknown>)
  }

  newPane(
    requestId: string,
    windowId: string,
    fromPaneId: string,
    opts: NewPaneOptions = {},
  ): void {
    if (!this.authenticated) return
    this.sendCreation(buildNewPane(requestId, windowId, fromPaneId, opts) as unknown as Record<string, unknown>)
  }

  revivePane(requestId: string, windowId: string, paneId: string, opts: RevivePaneOptions = {}): void {
    if (!this.authenticated) return
    this.sendCreation(buildRevivePane(requestId, windowId, paneId, opts) as unknown as Record<string, unknown>)
  }

  startPaneSession(requestId: string, windowId: string, paneId: string, opts: StartPaneSessionOptions = {}): void {
    if (!this.authenticated) return
    this.sendCreation(buildStartPaneSession(requestId, windowId, paneId, opts) as unknown as Record<string, unknown>)
  }

  stashPane(requestId: string, windowId: string, paneId: string): void {
    if (!this.authenticated) return
    this.send(buildStashPane(requestId, windowId, paneId) as unknown as Record<string, unknown>)
  }

  removePane(requestId: string, windowId: string, paneId: string): void {
    if (!this.authenticated) return
    this.send(buildRemovePane(requestId, windowId, paneId) as unknown as Record<string, unknown>)
  }

  rename(requestId: string, windowId: string, name: string, paneId?: string): void {
    if (!this.authenticated) return
    this.send(buildRename(requestId, windowId, name, paneId) as unknown as Record<string, unknown>)
  }

  closeWindow(requestId: string, windowId: string): void {
    if (!this.authenticated) return
    this.send(buildCloseWindow(requestId, windowId) as unknown as Record<string, unknown>)
  }

  focusWindow(requestId: string, windowId: string): void {
    if (!this.authenticated) return
    this.send(buildFocusWindow(requestId, windowId) as unknown as Record<string, unknown>)
  }

  newWindow(requestId: string, projectId: string, name: string, opts: NewWindowOptions = {}): void {
    if (!this.authenticated) return
    this.sendCreation(buildNewWindow(requestId, projectId, name, opts) as unknown as Record<string, unknown>)
  }

  createProject(requestId: string, opts: ProjectCreateOptions): void {
    if (!this.authenticated) return
    this.sendCreation(buildProjectCreate(requestId, opts) as unknown as Record<string, unknown>)
  }

  updateProject(requestId: string, projectId: string, opts: ProjectEditOptions): void {
    if (!this.authenticated) return
    this.send(buildProjectUpdate(requestId, projectId, opts) as unknown as Record<string, unknown>)
  }

  deleteProject(requestId: string, projectId: string): void {
    if (!this.authenticated) return
    this.send(buildProjectDelete(requestId, projectId) as unknown as Record<string, unknown>)
  }

  attach(sessionId: string, cols: number, rows: number, raw = false, requestId = 'attach', viewed = false): void {
    if (!this.authenticated) return
    // A background attach must not erase the active pane's warm/history state. Foreground attaches retain the
    // legacy reset semantics; the per-pane bank owns background terminal state independently.
    if (viewed || this.attachedSessionId === null) {
      this.gridCols = cols
      this.gridRows = rows
      this.resetScrollbackState()
    }
    const terminalEncoding = this.supportsTerminalGzip ? TERMINAL_GZIP_JSON_V1 : null
    if (!this.pendingAttachEncodings.has(requestId) && this.pendingAttachEncodings.size >= MAX_PENDING_ATTACHES) {
      this.transport.fail()
      return
    }
    this.pendingAttachEncodings.set(requestId, {
      sessionId,
      encoding: terminalEncoding,
      deadline: this.pendingAttachNow() + PENDING_ATTACH_TTL_MS,
    })
    this.armPendingAttachTimer()
    const sent = this.send({
      type: 'attach_session',
      request_id: requestId,
      session_id: sessionId,
      cols,
      rows,
      raw,
      viewed,
      ...(terminalEncoding ? { terminal_encoding: terminalEncoding } : {}),
    })
    if (!sent) {
      this.pendingAttachEncodings.delete(requestId)
      this.armPendingAttachTimer()
    }
  }

  detach(): void {
    if (this.attachedSessionId) this.send({ type: 'detach', session_id: this.attachedSessionId })
    this.chunks.clearAll()
    this.codecDecoder.clearAll()
    this.incomingChunkTrace.clear()
    this.attachedChannels.clear()
    this.channelEncodings.clear()
    this.pendingAttachEncodings.clear()
    this.cancelPendingAttachTimer()
    this.attachedChannel = null
    this.attachedSessionId = null
    this.sync = null
    this.held = null
    this.resetScrollbackState()
  }

  /** Detach a specific session channel in the gated multi-pane path. */
  detachSession(sessionId: string): void {
    if (!this.authenticated) return
    this.send({ type: 'detach', session_id: sessionId })
    for (const [requestId, pending] of this.pendingAttachEncodings) {
      if (pending.sessionId === sessionId) this.pendingAttachEncodings.delete(requestId)
    }
    this.armPendingAttachTimer()
    const channel = this.attachedChannels.get(sessionId)
    if (channel !== undefined) {
      this.chunks.clear(channel)
      this.codecDecoder.clear(channel)
      this.incomingChunkTrace.delete(channel)
      this.attachedChannels.delete(sessionId)
      this.channelEncodings.delete(channel)
    }
    if (this.attachedSessionId === sessionId) {
      this.attachedChannel = null
      this.attachedSessionId = null
      this.resetScrollbackState()
    }
  }

  /** Roadmap §4 gated multi-pane path: switch which attached channel receives input/resize. */
  setActiveAttach(sessionId: string, channel: number): void {
    // Focus is not channel retirement. Preserve any bounded, per-channel partial frame so a quick switch away and
    // back cannot discard its prefix. Transport close/revoke and explicit detach still clear retired state.
    if (this.attachedSessionId !== null && this.attachedSessionId !== sessionId) {
      // Scroll/cache/timer state belongs to the formerly active single-session surface. Channel reassembly remains
      // per-channel and is deliberately preserved, but a reply for the old surface must not poison the new one.
      this.resetScrollbackState()
    }
    this.attachedChannels.set(sessionId, channel)
    this.attachedSessionId = sessionId
    this.attachedChannel = channel
    this.setViewedChannel(channel)
  }

  /** Content-blind decoder priority signal. Null reserves the foreground lane for a viewed attach still in flight. */
  setViewedChannel(channel: number | null): void {
    this.viewedChannelEpoch++
    this.codecDecoder.setActiveChannel(channel)
  }

  resize(cols: number, rows: number, viewed = true): void {
    if (!this.attachedSessionId) return
    this.resizeSession(this.attachedSessionId, cols, rows, viewed)
  }

  /** Resize a specific attached-or-in-flight session without changing the active input channel. DataChannel
   * ordering makes this safe immediately after attach_session: the agent processes attach before resize. */
  resizeSession(sessionId: string, cols: number, rows: number, viewed = true): void {
    if (!this.authenticated) return
    // Mixed-version safety: legacy agents default a missing Resize.viewed to true, so a background resize could
    // steal winsize ownership. Suppress it until this exact transport advertises the additive semantic. Active
    // viewed resizes remain wire-compatible and are always sent.
    if (!viewed && !this.supportsViewedResize) return
    // resize returns to live (history reflow on resize is out of scope; the daemon pins the live grid).
    if (this.attachedSessionId === sessionId) {
      if (this.gridCols !== cols || this.gridRows !== rows) this.resetScrollbackState()
      this.gridCols = cols
      this.gridRows = rows
    }
    this.send({ type: 'resize', session_id: sessionId, cols, rows, viewed })
    if (this.attachedSessionId === sessionId) {
      this.paintHeldLive()
      this.notifyScrollView()
    }
  }

  // ---- scrollback (client-side view over the daemon's Scrollback protocol) ----

  /** Scroll the view by `deltaRows` (positive = UP into history, negative = DOWN toward live). */
  scrollByRows(deltaRows: number): void {
    if (!this.authenticated || this.attachedChannel === null) return
    // The protocol returns at most one 256-row page. A taller viewport cannot be painted completely without a
    // multi-page assembly contract, so keep following live instead of entering an impossible request loop.
    if (this.gridRows > MAX_SCROLLBACK_ROWS_PER_REQUEST) return
    // historyLen starts at 0 and is learned from the first scrollback_rows reply; until then, allow
    // scrolling up so the first request can fire (the daemon clamps offset; we clamp on the reply).
    const maxOffset = this.historyLen > 0 ? this.historyLen : this.viewOffset + Math.max(1, deltaRows)
    const next = Math.max(0, Math.min(maxOffset, this.viewOffset + deltaRows))
    if (next === 0) {
      if (this.viewOffset !== 0) this.jumpToLive()
      return
    }
    if (next === this.viewOffset) return
    this.viewOffset = next
    // A real gesture supersedes optional look-ahead. Cancel a not-yet-sent prefetch; an already-sent page remains
    // the sole in-flight request and its reply becomes cache-fill before the newest visible offset is requested.
    if (this.scrollbackPrefetchTimer) clearTimeout(this.scrollbackPrefetchTimer)
    this.scrollbackPrefetchTimer = null
    this.requestScrollback()
  }

  /**
   * Multi-pane scroll: send a Scrollback request for a SPECIFIC pane session + offset, WITHOUT touching this
   * single-session RemoteSession's own viewOffset/held/cache. The daemon replies on that session's channel; in
   * the N-up path the reply is routed to the ChannelTerminalBank (which owns that pane's view state + paint).
   *
   * The request frame is keyed by session_id (same shape as requestScrollback), so no channel arg is needed —
   * the pane's channel is used only for demuxing the reply, which the bank handles. offset must be > 0 (offset 0
   * = jump-to-live, painted client-side by the bank; nothing to fetch).
   */
  requestScrollbackOn(sessionId: string, offset: number, count: number): boolean {
    if (!this.authenticated || offset <= 0) return false
    const sent = this.send({ type: 'scrollback', session_id: sessionId, offset_from_top: offset, count })
    if (!sent) {
      this.transport.fail()
      return false
    }
    this.cbs.onScrollbackRequest?.(sessionId, offset, count, false)
    return sent
  }

  /** Reuse the existing bounded scrollback page shape to warm exactly one first-history page after the active
   * pane's first Grid. Background panes never call this. Returns the requested offset for timeout correlation. */
  requestInitialScrollbackWarm(
    sessionId: string,
    rows: number,
    cols = this.gridCols,
  ): number | null {
    if (
      !this.authenticated
      || rows > MAX_SCROLLBACK_ROWS_PER_REQUEST
      || this.hasScrollbackInFlight()
    ) return null
    const count = this.scrollbackRequestCount(rows, cols)
    // A page beginning at -offset and containing `count` rows covers the immediate scroll range only when it also
    // includes the visible rows below history. The old offset=count page ended at -1, so a one-row upward scroll
    // could reuse only one cached row. This overlap makes the first upward gesture genuinely cache-hot.
    const offset = Math.max(1, count - Math.min(count, Math.max(1, Math.floor(rows))) + 1)
    this.scrollbackRequests.set(offset, { sessionId, sentAt: perfNow(), count, prefetch: true })
    this.pendingScrollbackPrefetch.add(offset)
    connTrace.log(this.traceId, 'scrollback', 'request', 'pending', `offset=${offset} count=${count} warm`)
    if (!this.send({ type: 'scrollback', session_id: sessionId, offset_from_top: offset, count })) {
      this.scrollbackRequests.delete(offset)
      this.pendingScrollbackPrefetch.delete(offset)
      this.transport.fail()
      return null
    }
    this.cbs.onScrollbackRequest?.(sessionId, offset, count, true)
    this.armScrollbackResponseTimer()
    return offset
  }

  /** A ChannelTerminalBank-owned reply bypasses this class's decoder. Settle the stable request owner explicitly
   * so a single→multi pane mount transition cannot strand the warm trace or its timeout. */
  settleExternallyRoutedScrollback(sessionId: string, requestedOffset: number): void {
    const trace = this.scrollbackRequests.get(requestedOffset)
    if (!trace || trace.sessionId !== sessionId) return
    this.scrollbackRequests.delete(requestedOffset)
    this.pendingScrollbackPrefetch.delete(requestedOffset)
    if (!trace.prefetch && this.pendingScrollbackOffset === requestedOffset) {
      this.pendingScrollback = false
      this.pendingScrollbackOffset = null
    }
    this.clearScrollbackResponseTimerIfIdle()
  }

  /** Return to the live (bottom) view and repaint the current grid. */
  jumpToLive(): void {
    this.viewOffset = 0
    if (this.scrollbackPrefetchTimer) clearTimeout(this.scrollbackPrefetchTimer)
    this.scrollbackPrefetchTimer = null
    this.paintHeldLive()
    this.notifyScrollView()
  }

  get atLive(): boolean {
    return this.viewOffset === 0
  }

  // Show `viewOffset` rows of history. If that page is already cached, paint it INSTANTLY (no relay
  // round-trip — this is what makes re-scrolling smooth); otherwise request it (coalesced, one in flight).
  private requestScrollback(): void {
    if (!this.attachedSessionId || this.viewOffset <= 0) return
    const cached = this.cachedRowsForOffset(this.viewOffset)
    if (cached) {
      this.paintScrollbackRows(cached)
      this.notifyScrollView()
      return
    }
    if (this.hasScrollbackInFlight()) return
    const count = this.scrollbackFetchCount()
    this.pendingScrollback = true
    this.pendingScrollbackOffset = this.viewOffset
    this.scrollbackRequests.set(this.viewOffset, {
      sessionId: this.attachedSessionId,
      sentAt: perfNow(),
      count,
      prefetch: false,
    })
    connTrace.log(
      this.traceId,
      'scrollback',
      'request',
      'pending',
      `offset=${this.viewOffset} count=${count} visible`,
    )
    if (!this.send({
      type: 'scrollback',
      session_id: this.attachedSessionId,
      offset_from_top: this.viewOffset,
      count,
    })) {
      this.transport.fail()
      return
    }
    this.cbs.onScrollbackRequest?.(this.attachedSessionId, this.viewOffset, count, true)
    this.armScrollbackResponseTimer()
    this.notifyScrollView()
  }

  private scrollbackFetchCount(): number {
    return this.scrollbackRequestCount(this.gridRows, this.gridCols)
  }

  /** Protocol-compatible page sizing shared by the single- and multi-pane request paths. */
  scrollbackRequestCount(rows: number, cols: number): number {
    const visibleRows = Math.max(1, Math.floor(rows))
    const visibleCols = Math.max(1, Math.floor(cols))
    const desiredRows = visibleRows * RemoteSession.SB_PREFETCH_PAGES
    const cellBudgetRows = Math.max(
      Math.min(MAX_SCROLLBACK_ROWS_PER_REQUEST, visibleRows),
      Math.floor(RemoteSession.SB_TARGET_CELLS / visibleCols),
    )
    return Math.max(1, Math.min(MAX_SCROLLBACK_ROWS_PER_REQUEST, desiredRows, cellBudgetRows))
  }

  private hasScrollbackInFlight(): boolean {
    return this.pendingScrollback || this.pendingScrollbackPrefetch.size > 0 || this.scrollbackRequests.size > 0
  }

  private resetScrollbackState(): void {
    this.viewOffset = 0
    this.historyLen = 0
    this.displayedHistory = null
    this.pendingScrollback = false
    this.pendingScrollbackOffset = null
    this.pendingScrollbackPrefetch.clear()
    this.scrollbackRequests.clear()
    if (this.scrollbackPrefetchTimer) clearTimeout(this.scrollbackPrefetchTimer)
    this.scrollbackPrefetchTimer = null
    if (this.scrollbackResponseTimer) clearTimeout(this.scrollbackResponseTimer)
    this.scrollbackResponseTimer = null
    this.sbCache.clear()
  }

  private armScrollbackResponseTimer(): void {
    if (this.scrollbackResponseTimer) clearTimeout(this.scrollbackResponseTimer)
    this.scrollbackResponseTimer = setTimeout(() => {
      this.scrollbackResponseTimer = null
      if (this.hasScrollbackInFlight()) this.transport.fail()
    }, SCROLLBACK_RESPONSE_TIMEOUT_MS)
    this.scrollbackResponseTimer.unref?.()
  }

  private clearScrollbackResponseTimerIfIdle(): void {
    if (this.hasScrollbackInFlight() || !this.scrollbackResponseTimer) return
    clearTimeout(this.scrollbackResponseTimer)
    this.scrollbackResponseTimer = null
  }

  private scheduleScrollbackPrefetch(servedOffset: number, historyLen: number): void {
    if (!this.attachedSessionId || historyLen <= 0 || this.hasScrollbackInFlight()) return
    const count = this.scrollbackFetchCount()
    // Adjacent cached windows overlap by one viewport. Advancing by the entire response count left a viewport-sized
    // hole between pages and encouraged another network request as soon as the user crossed that gap.
    const pageStep = Math.max(1, count - Math.min(count, Math.max(1, this.gridRows)))
    const nextOffset = Math.min(historyLen, servedOffset + pageStep)
    if (nextOffset <= servedOffset) return
    if (this.sbCache.has(nextOffset) || this.pendingScrollbackPrefetch.has(nextOffset)) return
    if (this.scrollbackPrefetchTimer) clearTimeout(this.scrollbackPrefetchTimer)
    this.scrollbackPrefetchTimer = setTimeout(() => {
      this.scrollbackPrefetchTimer = null
      if (!this.attachedSessionId || this.viewOffset === 0 || this.hasScrollbackInFlight()) return
      if (this.sbCache.has(nextOffset)) return
      this.pendingScrollbackPrefetch.add(nextOffset)
      this.scrollbackRequests.set(nextOffset, {
        sessionId: this.attachedSessionId,
        sentAt: perfNow(),
        count,
        prefetch: true,
      })
      connTrace.log(
        this.traceId,
        'scrollback',
        'request',
        'pending',
        `offset=${nextOffset} count=${count} prefetch`,
      )
      if (!this.send({
        type: 'scrollback',
        session_id: this.attachedSessionId,
        offset_from_top: nextOffset,
        count,
      })) {
        this.transport.fail()
        return
      }
      this.cbs.onScrollbackRequest?.(this.attachedSessionId, nextOffset, count, true)
      this.armScrollbackResponseTimer()
    }, 80)
  }

  private cacheScrollbackRows(offset: number, page: CopyRows): void {
    if (page.rows.length === 0) return
    if (this.sbCache.size >= RemoteSession.SB_CACHE_MAX) this.sbCache.clear()
    this.sbCache.set(offset, sliceCopyRows(page))
  }

  private cachedRowsForOffset(offset: number): CopyRows | null {
    if (offset <= 0) return null
    const visibleRows = Math.max(1, this.gridRows)
    for (const [startOffset, cached] of this.sbCache) {
      const { rows } = cached
      if (offset > startOffset) continue
      const start = startOffset - offset
      if (start < 0 || start >= rows.length) continue
      const page = rows.slice(start, start + visibleRows)
      if (page.length === visibleRows) return sliceCopyRows(cached, start, start + visibleRows)
    }
    return null
  }

  private paintScrollbackRows(page: CopyRows): void {
    const cols = page.rows[0]?.length ?? 0
    const viewRows = page.rows.length
    this.displayedHistory = {
      ...sliceCopyRows(page),
      cols,
      viewRows,
      highlights: this.searchHighlights,
    }
    this.renderer?.paintRows(page.rows, cols, viewRows, this.searchHighlights)
  }

  // History grew (new live output while scrolled up) → offsets shift, so cached pages are stale. Clear.
  private invalidateScrollCache(): void {
    if (this.sbCache.size) this.sbCache.clear()
  }

  private notifyScrollView(): void {
    this.cbs.onScrollView?.({
      atLive: this.viewOffset === 0,
      offset: this.viewOffset,
      historyLen: this.historyLen,
    })
  }

  sendKey(ev: KeyEvent): void {
    const data = encodeKey(ev, this.modes())
    if (data) this.sendInputBytes(data)
  }
  /** Literal interactive text from a browser IME. This is typing, not paste, so no bracketed-paste framing. */
  sendText(text: string): void {
    if (text) this.sendInputBytes(text)
  }
  sendPaste(text: string): void {
    const chunks = encodePasteChunks(text, this.modes().bracketed_paste, MAX_INPUT_PAYLOAD)
    if (chunks.length === 0) return
    if (!this.authenticated) { connTrace.log(currentTraceId(), 'input', 'drop', 'error', 'not authenticated'); return }
    if (this.attachedChannel === null) { connTrace.log(currentTraceId(), 'input', 'drop', 'error', 'no attachedChannel'); return }
    const encoder = new TextEncoder()
    this.sendInputPayloadBatch(this.attachedChannel, chunks.map((chunk) => encoder.encode(chunk)), true)
  }

  private sendInputBytes(data: string): void {
    // DIAGNOSTIC (input path): trace WHY a keystroke is/ isn't sent so "can't type" is decidable from the copied log.
    // Content-blind: logs only the DROP REASON + byte count, never the key/bytes themselves.
    if (!this.authenticated) { connTrace.log(currentTraceId(), 'input', 'drop', 'error', 'not authenticated'); return }
    if (this.attachedChannel === null) { connTrace.log(currentTraceId(), 'input', 'drop', 'error', 'no attachedChannel'); return }
    const bytes = new TextEncoder().encode(data)
    this.sendInputBatch(this.attachedChannel, bytes)
  }

  /** RAW renderer mode: send xterm.js's already-encoded input bytes straight to the PTY. */
  sendRawInput(bytes: Uint8Array): void {
    if (!this.authenticated || this.attachedChannel === null) return
    this.sendInputBatch(this.attachedChannel, bytes)
  }

  /** Send raw bytes (e.g. an SGR mouse-wheel report) to a SPECIFIC pane's channel, WITHOUT changing the active-input
   * target — mirrors requestScrollbackOn's per-pane routing. Used for wheel-over-a-pane in a full-screen app. */
  sendRawInputOn(_sessionId: string, channel: number, seq: string): void {
    if (!this.authenticated) return
    const bytes = new TextEncoder().encode(seq)
    this.sendInputBatch(channel, bytes)
  }

  private authorizationJitter(token: string, maxMs: number): number {
    let hash = 0
    for (let i = 0; i < token.length; i++) hash = (Math.imul(hash, 33) + token.charCodeAt(i)) >>> 0
    return maxMs > 0 ? hash % (maxMs + 1) : 0
  }

  private cancelAuthorizationRefresh(): void {
    this.authorizationRefreshGeneration++
    if (this.authorizationRefreshTimer) clearTimeout(this.authorizationRefreshTimer)
    if (this.authorizationRefreshAckTimer) clearTimeout(this.authorizationRefreshAckTimer)
    this.authorizationRefreshTimer = null
    this.authorizationRefreshAckTimer = null
    this.authorizationRefreshAbort?.abort()
    this.authorizationRefreshAbort = null
    this.pendingAuthorization = null
    this.authorizationRefreshFailures = 0
  }

  private scheduleAuthorizationRefresh(): void {
    this.cancelAuthorizationRefresh()
    const authorization = this.authorization
    if (!this.transportConnected || !this.authenticated || !this.supportsAuthorizationRefresh ||
        !authorization || !this.transport.refreshAuthorization) return
    const generation = this.authorizationRefreshGeneration
    const refreshAt = authorization.deadlineMs - AUTHORIZATION_REFRESH_LEAD_MS -
      this.authorizationJitter(authorization.token, AUTHORIZATION_REFRESH_JITTER_MS)
    const delay = Math.max(0, refreshAt - this.authorizationNow())
    this.authorizationRefreshTimer = setTimeout(() => {
      this.authorizationRefreshTimer = null
      this.beginAuthorizationRefresh(generation, authorization)
    }, delay)
  }

  private beginAuthorizationRefresh(generation: number, predecessor: BoundAuthorization): void {
    if (generation !== this.authorizationRefreshGeneration || !this.transportConnected || !this.authenticated ||
        this.authorization?.token !== predecessor.token || !this.transport.refreshAuthorization) return
    if (this.authorizationNow() >= predecessor.deadlineMs - AUTHORIZATION_REFRESH_EXPIRY_GUARD_MS) {
      this.failAuthorizationRefresh()
      return
    }
    const abort = new AbortController()
    this.authorizationRefreshAbort = abort
    let finished = false
    const timeout = setTimeout(() => {
      if (finished) return
      finished = true
      abort.abort()
      if (generation === this.authorizationRefreshGeneration && this.authorization?.token === predecessor.token) {
        this.authorizationRefreshAbort = null
        this.retryAuthorizationRefresh(generation, predecessor)
      }
    }, AUTHORIZATION_REFRESH_REQUEST_TIMEOUT_MS)
    void this.transport.refreshAuthorization(predecessor, abort.signal).then((successor) => {
      if (finished) return
      finished = true
      clearTimeout(timeout)
      if (generation !== this.authorizationRefreshGeneration || abort.signal.aborted ||
          !this.transportConnected || !this.authenticated || this.authorization?.token !== predecessor.token) return
      this.authorizationRefreshAbort = null
      if (!successor || successor.token === predecessor.token || successor.deadlineMs <= predecessor.deadlineMs ||
          successor.deadlineMs <= this.authorizationNow()) {
        this.retryAuthorizationRefresh(generation, predecessor)
        return
      }
      this.pendingAuthorization = successor
      if (!this.send({ type: 'auth_refresh', token: successor.token })) {
        this.failAuthorizationRefresh()
        return
      }
      this.authorizationRefreshAckTimer = setTimeout(() => {
        this.authorizationRefreshAckTimer = null
        if (generation === this.authorizationRefreshGeneration && this.pendingAuthorization === successor) {
          this.failAuthorizationRefresh()
        }
      }, AUTHORIZATION_REFRESH_ACK_TIMEOUT_MS)
    }).catch(() => {
      if (finished) return
      finished = true
      clearTimeout(timeout)
      if (generation !== this.authorizationRefreshGeneration || !this.transportConnected || !this.authenticated ||
          this.authorization?.token !== predecessor.token) return
      this.authorizationRefreshAbort = null
      this.retryAuthorizationRefresh(generation, predecessor)
    })
  }

  private retryAuthorizationRefresh(generation: number, predecessor: BoundAuthorization): void {
    if (generation !== this.authorizationRefreshGeneration) return
    const index = this.authorizationRefreshFailures++
    const baseDelay = AUTHORIZATION_REFRESH_RETRY_DELAYS_MS[index]
    if (baseDelay === undefined) {
      this.failAuthorizationRefresh()
      return
    }
    const delay = baseDelay + this.authorizationJitter(`${predecessor.token}:${index}`, 250)
    if (this.authorizationNow() + delay >= predecessor.deadlineMs - AUTHORIZATION_REFRESH_EXPIRY_GUARD_MS) {
      this.failAuthorizationRefresh()
      return
    }
    this.authorizationRefreshTimer = setTimeout(() => {
      this.authorizationRefreshTimer = null
      this.beginAuthorizationRefresh(generation, predecessor)
    }, delay)
  }

  private failAuthorizationRefresh(): void {
    this.cancelAuthorizationRefresh()
    this.transport.fail()
  }

  private sendInputBatch(channel: number, bytes: Uint8Array): boolean {
    return this.sendInputPayloadBatch(channel, [bytes])
  }

  private sendInputPayloadBatch(
    channel: number,
    payloads: readonly Uint8Array[],
    bulkPaste = false,
  ): boolean {
    const frames = payloads.flatMap((payload) => encodeInputFrames(channel, payload))
    const bytes = payloads.reduce((total, payload) => total + payload.byteLength, 0)
    const admitted = bulkPaste
      ? this.transport.sendBulkBinaryBatch(frames)
      : this.transport.sendBinaryBatch(frames)
    if (!admitted) {
      connTrace.log(currentTraceId(), 'input', 'drop', 'error', `outbound unavailable ch=${channel} n=${bytes}`)
      // The transport either already retired itself (overflow/native send failure) or lost ownership before
      // admission. Closing is idempotent and gives the controller one honest reconnect boundary; never retry an
      // input batch because the sender cannot prove whether native SCTP accepted a prefix.
      this.transport.fail()
      return false
    }
    connTrace.log(currentTraceId(), 'input', 'sent', 'ok', `ch=${channel} n=${bytes}`)
    return true
  }

  close(): void {
    // Do not depend on the transport delivering a final `closed` callback: controller ownership intentionally
    // suppresses callbacks from superseded generations. Retire every local timer/buffer synchronously so an
    // intentional leave or replacement connection cannot retain this session until a 15/45 s deadline.
    this.transportConnected = false
    this.authenticated = false
    this.cancelAuthorizationRefresh()
    this.authorization = null
    this.supportsViewedResize = false
    this.supportsCreationReplay = false
    this.offeredTerminalGzip = false
    this.supportsTerminalGzip = false
    this.clearCreationReplayTimers()
    this.chunks.clearAll()
    this.codecDecoder.clearAll()
    this.incomingChunkTrace.clear()
    this.attachedChannels.clear()
    this.channelEncodings.clear()
    this.pendingAttachEncodings.clear()
    this.cancelPendingAttachTimer()
    this.attachedChannel = null
    this.attachedSessionId = null
    this.sync = null
    this.held = null
    this.resetScrollbackState()
    this.transport.close()
  }

  /** Fail the current transport so the controller mints a fresh signaling/token/peer owner. */
  failConnection(): void {
    this.transport.fail()
  }

  // ---- helpers ----

  /** Wire a provider for the ACTIVE pane's input modes (multi-pane N-up path). When set and it returns modes,
   * key/paste encoding uses them instead of the single-session `held` (which never updates for pane channels). */
  setActivePaneModesProvider(provider: (() => TermModes | null) | null): void {
    this.activePaneModes = provider
  }

  private modes(): TermModes {
    // Prefer the active pane's modes in the multi-pane path (held is null for pane channels); fall back to the
    // single-session held grid, then to safe defaults.
    const pane = this.activePaneModes?.()
    if (pane) return pane
    return {
      app_cursor: this.held?.app_cursor ?? false,
      bracketed_paste: this.held?.bracketed_paste ?? false,
      focus_reporting: this.held?.focus_reporting ?? false,
      mouse_report: this.held?.mouse_report ?? false,
      mouse_drag: this.held?.mouse_drag ?? false,
      mouse_motion: this.held?.mouse_motion ?? false,
      mouse_sgr: this.held?.mouse_sgr ?? false,
    }
  }

  // Resync recovery WITHOUT adding an S4 message: the daemon already drives resync server-side — it emits
  // `resync_required` then a GUARANTEED fresh Grid, which the agent streams through. So the client just
  // awaits the next Grid via SyncState; there is no client-originated `snapshot` in S4 (the WSS path sends
  // one only as an optimization). See docs/architecture/terminal.md. No-op by design.
  private requestSnapshot(): void {
    // intentionally nothing — await the daemon's guaranteed post-resync Grid.
  }

  private send(msg: Record<string, unknown>): boolean {
    // WIRE TRACE (outbound → agent). Content-blind: type + a few metadata counts, never the payload/token.
    connTrace.wire(this.traceId, 'out', String(msg.type ?? 'unknown'), wireDetail(msg))
    return this.transport.sendText(JSON.stringify(msg))
  }

  /** Send one of the seven allocating creation mutations. A capable agent keeps a bounded result cache keyed by
   * request id + exact frame, so retrying these exact bytes recovers a lost reply without allocating a second
   * session/pane/window/project. Mixed-version peers stay single-send. */
  private sendCreation(msg: Record<string, unknown>): boolean {
    if (!this.supportsCreationReplay) return this.send(msg)
    const requestId = typeof msg.request_id === 'string' ? msg.request_id : ''
    const type = msg.type
    if (
      !requestId
      || !isCreationRequestType(type)
      || this.pendingCreationReplays.has(requestId)
    ) return false
    const frame = JSON.stringify(msg)
    connTrace.wire(this.traceId, 'out', type, wireDetail(msg))
    if (!this.transport.sendText(frame)) return false
    const pending: PendingCreationReplay = { type, frame, retryTimer: null, retireTimer: null }
    pending.retryTimer = setTimeout(() => {
      if (this.pendingCreationReplays.get(requestId) !== pending) return
      pending.retryTimer = null
      if (!this.transportConnected || !this.authenticated || !this.supportsCreationReplay) return
      connTrace.wire(this.traceId, 'out', type, 'replay=1')
      this.transport.sendText(frame)
    }, CREATION_DELIVERY_RETRY_MS)
    pending.retireTimer = setTimeout(() => {
      if (this.pendingCreationReplays.get(requestId) === pending) {
        if (pending.retryTimer !== null) clearTimeout(pending.retryTimer)
        this.pendingCreationReplays.delete(requestId)
      }
    }, CREATION_REPLAY_RETIRE_MS)
    this.pendingCreationReplays.set(requestId, pending)
    return true
  }

  private completeCreationDelivery(
    requestId: string,
    expectedTypes: readonly CreationRequestType[],
  ): void {
    const pending = this.pendingCreationReplays.get(requestId)
    if (!pending || !expectedTypes.includes(pending.type)) return
    if (pending.retryTimer !== null) clearTimeout(pending.retryTimer)
    if (pending.retireTimer !== null) clearTimeout(pending.retireTimer)
    this.pendingCreationReplays.delete(requestId)
  }

  private clearCreationReplayTimers(): void {
    for (const pending of this.pendingCreationReplays.values()) {
      if (pending.retryTimer !== null) clearTimeout(pending.retryTimer)
      if (pending.retireTimer !== null) clearTimeout(pending.retireTimer)
    }
    this.pendingCreationReplays.clear()
  }

  get isAuthenticated(): boolean {
    return this.authenticated
  }
  get channel(): number | null {
    return this.attachedChannel
  }

  private sessionForAttachedChannel(channel: number): string | null {
    for (const [sessionId, boundChannel] of this.attachedChannels) {
      if (boundChannel === channel) return sessionId
    }
    return null
  }

  private armPendingAttachTimer(): void {
    this.cancelPendingAttachTimer()
    if (this.pendingAttachEncodings.size === 0) return
    const earliest = Math.min(...[...this.pendingAttachEncodings.values()].map((pending) => pending.deadline))
    this.pendingAttachTimer = setTimeout(() => {
      this.pendingAttachTimer = null
      const now = this.pendingAttachNow()
      for (const [requestId, pending] of this.pendingAttachEncodings) {
        if (pending.deadline <= now) this.pendingAttachEncodings.delete(requestId)
      }
      this.armPendingAttachTimer()
    }, Math.max(0, earliest - this.pendingAttachNow()))
  }

  private cancelPendingAttachTimer(): void {
    if (this.pendingAttachTimer !== null) clearTimeout(this.pendingAttachTimer)
    this.pendingAttachTimer = null
  }
}

function boundedCapabilities(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length > MAX_HELLO_CAPABILITIES) return null
  if (value.some((entry) => typeof entry !== 'string' || new TextEncoder().encode(entry).byteLength > MAX_HELLO_CAPABILITY_BYTES)) {
    return null
  }
  return value as string[]
}

/** A CONTENT-BLIND one-line detail for the wire trace: counts/sizes/ids only, NEVER payload/token/cookie/bytes.
 * Recognizes the high-value message types; unknown types get just their key count. Used for both directions. */
function wireDetail(msg: Record<string, unknown>): string {
  const type = String(msg.type ?? '')
  const num = (v: unknown): number => (Array.isArray(v) ? v.length : 0)
  const wm = msg.workspace_metadata as { projects?: unknown[] } | undefined
  const projects = Array.isArray(wm?.projects) ? wm!.projects!.length : 0
  switch (type) {
    case 'session_list':
    case 'session_list_result':
      return `sessions=${num(msg.sessions)} projects=${projects}`
    case 'workspace_update':
      return `epoch=${msg.epoch ?? '-'} sessions=${num(msg.sessions)} projects=${projects}`
    case 'workspace_update_ack':
      return `epoch=${msg.epoch ?? '-'}`
    case 'db_write_trace':
      return `count=${msg.count ?? '-'}`
    case 'db_write_trace_result':
      return `entries=${num(msg.entries)}`
    case 'debug_sync_snapshot':
    case 'debug_sync_snapshot_result':
      return `rid=${msg.request_id ?? '-'}`
    case 'auth':
      return 'token=<redacted>' // NEVER log the token itself
    case 'attach_session':
    case 'attach_ok':
      return `channel=${msg.channel ?? '-'}`
    case 'resize':
      return `cols=${msg.cols ?? '-'} rows=${msg.rows ?? '-'}`
    default: {
      // Unknown/other: key count only, no values (content-blind by default). Request ids are deliberately not
      // copied: some product operations use cwd/session-bearing ids internally, so even a scrubbed diagnostics
      // ring must reveal only that correlation exists, never the identifier itself.
      const keys = Object.keys(msg).filter((k) => k !== 'type').length
      const rid = typeof msg.request_id === 'string' ? ' rid=<opaque>' : ''
      return keys ? `fields=${keys}${rid}` : ''
    }
  }
}

function parseSessionIds(raw: unknown): string[] {
  if (!Array.isArray(raw)) return []
  return raw.filter((id): id is string =>
    typeof id === 'string' && id.trim().length > 0 && id !== PRODUCT_RECOVERY_SESSION_ID)
}

function parseSessionMetadata(raw: unknown): RemoteSessionMetadata[] {
  if (!Array.isArray(raw)) return []
  return raw.flatMap((item) => {
    if (typeof item !== 'object' || item === null) return []
    const m = item as Record<string, unknown>
    if (typeof m.id !== 'string' || m.id === PRODUCT_RECOVERY_SESSION_ID) return []
    const cwd = typeof m.cwd === 'string' && m.cwd.trim() ? m.cwd : undefined
    return [{ id: m.id, ...(cwd ? { cwd } : {}) }]
  })
}

function stringProp(item: Record<string, unknown>, key: string): string | undefined {
  const value = item[key]
  return typeof value === 'string' && value.trim().length > 0 ? value : undefined
}

function boolProp(item: Record<string, unknown>, key: string): boolean | undefined {
  const value = item[key]
  return typeof value === 'boolean' ? value : undefined
}

function rawProp(item: Record<string, unknown>, ...keys: string[]): unknown {
  for (const key of keys) {
    if (item[key] !== undefined) return item[key]
  }
  return undefined
}

function parseProjectLaunchDefaults(raw: unknown): RemoteWorkspaceMetadata['projects'][number]['launchDefaults'] | undefined {
  if (typeof raw !== 'object' || raw === null) return undefined
  const data = raw as Record<string, unknown>
  const agent = stringProp(data, 'agent')
  const resumeMode = stringProp(data, 'resumeMode') ?? stringProp(data, 'resume_mode')
  const model = stringProp(data, 'model')
  const dangerous = boolProp(data, 'dangerouslySkipPermissions') ?? boolProp(data, 'dangerous')
  const customCommand = stringProp(data, 'customCommand') ?? stringProp(data, 'custom_command')
  const parsed: NonNullable<RemoteWorkspaceMetadata['projects'][number]['launchDefaults']> = {}
  if (isRunnableAgentKind(agent)) parsed.agent = agent
  if (resumeMode === 'new' || resumeMode === 'resume' || resumeMode === 'continue') parsed.resumeMode = resumeMode
  if (model) parsed.model = model
  if (dangerous !== undefined) parsed.dangerouslySkipPermissions = dangerous
  if (customCommand !== undefined) parsed.customCommand = customCommand
  return Object.keys(parsed).length > 0 ? parsed : undefined
}

function parseProjectDirectories(raw: unknown): Array<{ name?: string; path: string }> | undefined {
  if (!Array.isArray(raw)) return undefined
  return raw.flatMap((entry) => {
    if (typeof entry !== 'object' || entry === null) return []
    const dir = entry as Record<string, unknown>
    const path = stringProp(dir, 'path')
    if (!path) return []
    const name = stringProp(dir, 'name')
    return [{ ...(name ? { name } : {}), path }]
  })
}

// Internal desktop startup fallback. Current agents remove it before serialization; keep this exact-ID
// defense so an older installed agent cannot expose a hidden, non-deletable recovery project in the browser.
const PRODUCT_RECOVERY_PROJECT_ID = 'system-product-recovery'
const PRODUCT_RECOVERY_SESSION_ID = 'system-product-recovery-session'

function parseWorkspaceMetadata(raw: unknown, liveSessions: readonly string[]): RemoteWorkspaceMetadata | null {
  if (typeof raw !== 'object' || raw === null) return null
  const root = raw as Record<string, unknown>
  const projectsRaw = root.projects
  if (!Array.isArray(projectsRaw)) return null

  const live = new Set(liveSessions)
  const projects = projectsRaw.flatMap((projectRaw) => {
    if (typeof projectRaw !== 'object' || projectRaw === null) return []
    const project = projectRaw as Record<string, unknown>
    const id = stringProp(project, 'id')
    const name = stringProp(project, 'name')
    const projectRoot = stringProp(project, 'root')
    const windowsRaw = project.windows
    if (!id || !name || !projectRoot || !Array.isArray(windowsRaw)) return []
    if (id === PRODUCT_RECOVERY_PROJECT_ID) return []

    const windows = windowsRaw.flatMap((windowRaw) => {
      if (typeof windowRaw !== 'object' || windowRaw === null) return []
      const windowNode = windowRaw as Record<string, unknown>
      const windowId = stringProp(windowNode, 'id')
      const panesRaw = windowNode.panes
      if (!windowId || !Array.isArray(panesRaw)) return []

      const panes = panesRaw.flatMap((paneRaw) => {
        if (typeof paneRaw !== 'object' || paneRaw === null) return []
        const pane = paneRaw as Record<string, unknown>
        const paneId = stringProp(pane, 'id')
        // KEEP a pane even when its session_id is empty. The agent deliberately redacts hidden/idle sessions to an
        // empty session_id but KEEPS the pane as a placeholder (remote_bridge filter), so an idle project (e.g. the
        // built-in Terminal, or one whose pane isn't a live session) still surfaces its window/pane. Dropping empty-
        // session panes cascaded to drop the window → the project → the whole project vanished. Only drop a pane with
        // no id (genuinely malformed). An empty-session pane is non-live + stashed (not attachable, but visible).
        if (!paneId) return []
        const sessionId = stringProp(pane, 'sessionId') ?? stringProp(pane, 'session_id') ?? ''
        const isLive = sessionId !== '' && live.has(sessionId)
        const explicitStashed = boolProp(pane, 'stashed')
        const cwd = stringProp(pane, 'cwd')
        return [{
          id: paneId,
          sessionId,
          live: isLive,
          ...(stringProp(pane, 'name') ? { name: stringProp(pane, 'name') } : {}),
          stashed: explicitStashed ?? !isLive,
          ...(cwd ? { cwd } : {}),
        }]
      })

      // Do NOT drop a window with no live panes — an idle window (its pane redacted/non-live) must still appear so
      // the project stays visible. Only a genuinely empty window (no pane rows at all) collapses to nothing.
      if (panes.length === 0 && panesRaw.length === 0) return []
      return [{
        id: windowId,
        ...(stringProp(windowNode, 'name') ? { name: stringProp(windowNode, 'name') } : {}),
        ...(boolProp(windowNode, 'focused') !== undefined ? { focused: boolProp(windowNode, 'focused') } : {}),
        ...(boolProp(windowNode, 'stashed') !== undefined ? { stashed: boolProp(windowNode, 'stashed') } : {}),
        panes,
      }]
    })

    // Do NOT drop a project just because it currently has no live windows — an idle/empty project (e.g. the
    // built-in Terminal, or a freshly-created one whose window isn't live yet) must still appear in the browser
    // so the user can see it and open a window. The agent surfaces all projects (commit 1e670fc1a); the browser
    // must not re-filter them out. (Previously `if (windows.length === 0) return []` hid every window-less
    // project → only the last window-bearing project survived.)
    const accentColor = stringProp(project, 'accentColor') ?? stringProp(project, 'accent_color')
    const launchDefaults = parseProjectLaunchDefaults(rawProp(project, 'launchDefaults', 'launch_defaults'))
    const directories = parseProjectDirectories(rawProp(project, 'directories'))
    return [{
      id,
      name,
      root: projectRoot,
      ...(stringProp(project, 'icon') ? { icon: stringProp(project, 'icon') } : {}),
      ...(accentColor ? { accentColor } : {}),
      ...(boolProp(project, 'selected') !== undefined ? { selected: boolProp(project, 'selected') } : {}),
      ...(launchDefaults ? { launchDefaults } : {}),
      ...(directories !== undefined ? { directories } : {}),
      // The built-in "Terminal" system project + user-hidden flag (agent sends snake_case) — the browser uses these to
      // simplify its dialogs (Terminal: name-only) + refuse delete + honor hide.
      ...(boolProp(project, 'system') ? { system: true } : {}),
      ...(boolProp(project, 'hidden') ? { hidden: true } : {}),
      windows,
    }]
  })

  return projects.length > 0 ? { projects } : null
}
