// S5 — the remote-control transport seam. The terminal core (SyncState/GridRenderer/input-encoder) is
// transport-agnostic; this interface lets it ride EITHER the existing WebSocket path OR the new WebRTC
// DataChannel (webrtc-bridge.ts), and lets tests drive it with a fake. It carries S3b control + S4
// terminal messages; terminal bytes travel ONLY here (peer↔agent over DTLS), never to the cloud.
//
// Two message planes over one DataChannel:
//   - TEXT  (JSON): S3b control (hello/auth/auth_ok/…) + S4 terminal metadata (session_list/attach/
//     resize/detach/error). Delivered as strings.
//   - BINARY (terminal-frame.ts): S4 terminal_input (out) / terminal_output (in). Delivered as Uint8Array.

export type ControlState =
  | 'connecting' // signaling + ICE
  | 'connected' // DataChannel open, not yet authenticated
  | 'authenticated' // auth_ok received
  | 'authorization_required' // a registered passkey could not authorize this browser; requires explicit user action
  | 'access_required' // an adapter explicitly refused setup; requires user action, not a network retry
  | 'entitlement_required' // paid remote access is unavailable; stable until explicit user action
  | 'auth_refused'
  | 'revoked'
  | 'offline' // desktop unreachable — even relay failed (S3c)
  | 'error'
  | 'closed'

/** Fixed, content-blind milestones for the opt-in cold-connect timing ring. These names are the complete
 * telemetry vocabulary: transports may report only these phases, and the collector retains only their first
 * monotonic observation relative to one controller-owned connection attempt. */
export const CONNECTION_ATTEMPT_PHASES = [
  'preparation_ready',
  'identity_ready',
  'relay_fetch_start',
  'relay_fetch_ready',
  'peer_created',
  'offer_created',
  'local_description_set',
  'first_local_ice',
  'passkey_certificate_resolved',
  'signaling_created',
  'bound_authority_ready',
  'signaling_polling_started',
  'first_remote_ice',
  'remote_description_set',
  'data_channel_open',
  'control_auth_ok',
] as const

export type ConnectionAttemptPhase = typeof CONNECTION_ATTEMPT_PHASES[number]

/** S3c — which path carried the connection (for the UI badge). 'failed' = neither direct nor relay worked. */
export type ConnectionMode = 'unknown' | 'direct' | 'relay' | 'failed'

/** Maximum server-advertised token lifetime accepted by the browser. Current tokens are exactly ten minutes;
 * the small rollout ceiling fails closed on malformed timestamps without coupling parsing to one exact TTL. */
export const MAX_BOUND_AUTHORIZATION_TTL_MS = 15 * 60_000

/** Short-lived cloud authority presented inside one authenticated DataChannel. The token is never persisted or
 * logged. `expiresAtMs` remains in the server clock domain solely for exact agent-ack comparison; every browser
 * schedule/guard uses `deadlineMs`, derived from the server TTL at local receipt so wall-clock skew is irrelevant. */
export interface BoundAuthorization {
  token: string
  expiresAtMs: number
  deadlineMs: number
}

/** Parse one cloud mint response without comparing server timestamps to the browser wall clock. Date.now is used
 * as a duration-bearing local deadline clock because it continues advancing across browser/device sleep. */
export function parseBoundAuthorization(
  value: unknown,
  receivedAtMs: number = Date.now(),
): BoundAuthorization | null {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      !Number.isSafeInteger(receivedAtMs)) return null
  const raw = value as Record<string, unknown>
  if (typeof raw.token !== 'string' || raw.token.length === 0 || raw.token.length > 16 * 1024 ||
      !Number.isSafeInteger(raw.issuedAtMs) || !Number.isSafeInteger(raw.expiresAtMs)) return null
  if (Number(raw.issuedAtMs) < 0 || Number(raw.expiresAtMs) < 0) return null
  const ttlMs = Number(raw.expiresAtMs) - Number(raw.issuedAtMs)
  const deadlineMs = receivedAtMs + ttlMs
  if (ttlMs <= 0 || ttlMs > MAX_BOUND_AUTHORIZATION_TTL_MS ||
      !Number.isSafeInteger(deadlineMs)) return null
  return { token: raw.token, expiresAtMs: Number(raw.expiresAtMs), deadlineMs }
}

export type IceRoute = 'direct' | 'relay' | 'unknown'
export type IceRelayLeg = 'none' | 'local' | 'remote' | 'both' | 'unknown'
export type IcePairProtocol = 'udp' | 'tcp' | 'unknown'
export type LocalTurnProtocol = 'udp' | 'tcp' | 'tls' | 'unknown' | 'not_applicable'

/** S3c-browser-smoke — observable connection diagnostics for the dev panel. NEVER carries the token,
 * SDP/ICE bodies, or terminal bytes — only enum-ish states + a bounded error string. */
export interface Diagnostics {
  /** signaling phase: idle → creating → awaiting-answer → answered; 'dead' = session expired/gone (409/404). */
  signaling: 'idle' | 'creating' | 'awaiting_answer' | 'answered' | 'dead'
  /** raw RTCPeerConnection.iceConnectionState (new/checking/connected/completed/failed/disconnected/closed). */
  ice: string
  /** selected ICE pair classification: relay if either leg is relay; otherwise host/srflx/prflx/unknown. */
  candidateType: 'host' | 'srflx' | 'prflx' | 'relay' | 'unknown'
  /** Legacy compatibility field. For a browser-local relay this may be its TURN transport; otherwise it is the
   * selected pair's UDP/TCP protocol. Use the exact fields below for new diagnostics. */
  candidateProtocol: 'udp' | 'tcp' | 'tls' | 'unknown'
  /** Sanitized selected-pair route. Relay means at least one leg is a relay; direct requires two known non-relay
   * candidates. */
  route: IceRoute
  /** Which selected-pair leg is relayed. `unknown` is retained until both candidate records are authoritative. */
  relayLeg: IceRelayLeg
  /** The selected ICE pair transport. TURN-over-TLS is not a pair protocol; it is reported only below when the
   * browser-local candidate exposes it. */
  pairProtocol: IcePairProtocol
  /** TURN transport for the browser-local relay candidate only. Browser stats cannot prove the remote leg's TURN
   * transport, so a remote-only relay remains `not_applicable` here. */
  localTurnProtocol: LocalTurnProtocol
  /** whether the client was asked to force relay (so the UI can flag a non-relay selection as wrong). */
  forcedRelay: boolean
  /** ICE candidate-gathering timing (ms from the attempt start), for reliability diagnosis. No content. */
  timing: {
    /** ms to the FIRST relay (TURN) candidate gathered — high → slow TURN allocation. */
    toFirstRelayMs: number | null
    /** ms to the connection opening (DataChannel open). */
    toConnectedMs: number | null
    /** ms until browser stats exposed a complete selected pair. This is collected after DataChannel open. */
    toSelectedPairMs?: number | null
  }
}

/** A fresh, idle Diagnostics value (all call sites use this so new fields can't be forgotten). */
export function defaultDiagnostics(): Diagnostics {
  return {
    signaling: 'idle',
    ice: 'new',
    candidateType: 'unknown',
    candidateProtocol: 'unknown',
    route: 'unknown',
    relayLeg: 'unknown',
    pairProtocol: 'unknown',
    localTurnProtocol: 'unknown',
    forcedRelay: false,
    timing: { toFirstRelayMs: null, toConnectedMs: null, toSelectedPairMs: null },
  }
}

export interface RemoteTransport {
  /** Send a JSON control/terminal-metadata message (TEXT). Returns false if the channel was NOT open (message
   * dropped) so callers can surface an honest error instead of waiting on a reply that will never come. */
  sendText(json: string): boolean
  /** Send a binary terminal frame (terminal_input). Returns false when this connection cannot accept it. */
  sendBinary(bytes: Uint8Array): boolean
  /** Atomically admit every frame from one foreground terminal-input operation, or none of them. */
  sendBinaryBatch(frames: readonly Uint8Array[]): boolean
  /**
   * Atomically admit a complete structured paste as bulk input.
   *
   * Each supplied frame is an independently safe paste boundary. Foreground control/input may overtake only unsent
   * frames after admission; frame order within this operation is preserved.
   */
  sendBulkBinaryBatch(frames: readonly Uint8Array[]): boolean
  /** Inbound TEXT messages (JSON control/metadata). */
  onText(handler: (json: string) => void): void
  /** Inbound BINARY messages (terminal_output frames). */
  onBinary(handler: (bytes: Uint8Array) => void): void
  /** Transport/connection state changes. */
  onState(handler: (state: ControlState) => void): void
  /** S3c-browser-smoke — observable diagnostics updates (optional; the WebRTC bridge emits them). */
  onDiagnostics?(handler: (d: Diagnostics) => void): void
  /** Opt-in metrics seam. The transport exposes fixed milestones only—never identifiers, URLs, status values,
   * description/candidate bodies, credentials, or terminal content. Absent when phase timing is unavailable. */
  onConnectionPhase?(handler: (phase: ConnectionAttemptPhase) => void): void
  /** RELEASE-BLOCKER FIX: the cloud token minted for the CURRENT signaling session (bound to its id), or null
   * if the transport doesn't mint per-session (legacy/fake). RemoteSession reads this at auth time so the
   * token it presents names the session the channel actually runs over (including every fresh reconnect). */
  currentToken?(): string | null
  /** Structured form for continuity-capable transports. Legacy transports intentionally omit it. */
  currentAuthorization?(): BoundAuthorization | null
  /** Mint, but do not commit, one exact successor. RemoteSession commits only after auth_refresh_ok. */
  refreshAuthorization?(
    current: BoundAuthorization,
    signal?: AbortSignal,
  ): Promise<BoundAuthorization | null>
  /** Retire a broken owner and emit one terminal `closed` state before teardown so the controller reconnects. */
  fail(): void
  /** Close the channel + peer. */
  close(): void
}

/** An in-memory fake transport for tests: scripts inbound messages, captures outbound. No WebRTC. */
export class FakeTransport implements RemoteTransport {
  readonly sentText: string[] = []
  readonly sentBinary: Uint8Array[] = []
  binaryBatchCalls = 0
  /** Tests: number of upcoming sendText calls to DROP (return false, record nothing) — simulates a DataChannel that
   * isn't open yet (WebRTC flap). Decrements per dropped call. */
  dropTextCount = 0
  private textHandler: (json: string) => void = () => {}
  private binaryHandler: (bytes: Uint8Array) => void = () => {}
  private stateHandler: (state: ControlState) => void = () => {}
  private diagHandler: (d: Diagnostics) => void = () => {}
  private connectionPhaseHandler: (phase: ConnectionAttemptPhase) => void = () => {}
  closed = false
  private failedStateEmitted = false
  authorization: BoundAuthorization | null = null
  refreshAuthorizationHandler: ((
    current: BoundAuthorization,
    signal?: AbortSignal,
  ) => Promise<BoundAuthorization | null>) | null = null

  sendText(json: string): boolean {
    if (this.dropTextCount > 0) { this.dropTextCount -= 1; return false } // channel not open → dropped
    this.sentText.push(json)
    return true
  }
  /** Tests: reject the next complete binary batch without recording any prefix. */
  dropBinaryBatchCount = 0
  sendBinary(bytes: Uint8Array): boolean {
    return this.sendBinaryBatch([bytes])
  }
  sendBinaryBatch(frames: readonly Uint8Array[]): boolean {
    return this.recordBinaryBatch(frames)
  }
  bulkBinaryBatchCalls = 0
  sendBulkBinaryBatch(frames: readonly Uint8Array[]): boolean {
    this.bulkBinaryBatchCalls += 1
    return this.recordBinaryBatch(frames)
  }
  private recordBinaryBatch(frames: readonly Uint8Array[]): boolean {
    this.binaryBatchCalls += 1
    if (this.dropBinaryBatchCount > 0) {
      this.dropBinaryBatchCount -= 1
      return false
    }
    for (const bytes of frames) this.sentBinary.push(bytes.slice())
    return true
  }
  onText(handler: (json: string) => void): void {
    this.textHandler = handler
  }
  onBinary(handler: (bytes: Uint8Array) => void): void {
    this.binaryHandler = handler
  }
  onState(handler: (state: ControlState) => void): void {
    this.stateHandler = handler
  }
  onDiagnostics(handler: (d: Diagnostics) => void): void {
    this.diagHandler = handler
  }
  onConnectionPhase(handler: (phase: ConnectionAttemptPhase) => void): void {
    this.connectionPhaseHandler = handler
  }
  currentAuthorization(): BoundAuthorization | null {
    return this.authorization ? { ...this.authorization } : null
  }
  refreshAuthorization(current: BoundAuthorization, signal?: AbortSignal): Promise<BoundAuthorization | null> {
    return this.refreshAuthorizationHandler?.({ ...current }, signal) ?? Promise.resolve(null)
  }
  close(): void {
    this.closed = true
  }
  fail(): void {
    this.closed = true
    if (this.failedStateEmitted) return
    this.failedStateEmitted = true
    this.stateHandler('closed')
  }

  // --- test drivers ---
  /** Simulate an inbound TEXT message from the agent. */
  emitText(json: string): void {
    this.textHandler(json)
  }
  /** Simulate an inbound BINARY frame from the agent. */
  emitBinary(bytes: Uint8Array): void {
    this.binaryHandler(bytes)
  }
  /** Simulate a transport state change. */
  emitState(state: ControlState): void {
    this.stateHandler(state)
  }
  /** Simulate a diagnostics update. */
  emitDiagnostics(d: Diagnostics): void {
    this.diagHandler(d)
  }
  /** Simulate one fixed connection milestone. */
  emitConnectionPhase(phase: ConnectionAttemptPhase): void {
    this.connectionPhaseHandler(phase)
  }
}
