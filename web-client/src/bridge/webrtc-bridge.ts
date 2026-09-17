// S5/S3c — the WebRTC RemoteTransport (browser side). Builds an RTCPeerConnection, drives the S3a
// signaling exchange (offer → poll answer → trickle ICE, with backoff), opens the control DataChannel,
// and exposes the RemoteTransport surface. S3c: one ICE attempt receives both direct and TURN candidates;
// ICE prefers the best direct path and uses relay only when required. `?relay=1` remains an explicit
// relay-only qualification mode. Terminal data rides the DTLS DataChannel, never the cloud; the relay
// forwards ciphertext only.

import {
  DEFAULT_BACKOFF,
  SignalProgressUnsupported,
  SignalSessionDead,
  type PollBackoff,
  type SignalingPort,
} from './signaling-contract.js'
import type {
  ConnectionAttemptPhase,
  ConnectionMode,
  ControlState,
  Diagnostics,
  RemoteTransport,
  BoundAuthorization,
} from './remote-transport.js'
import { defaultDiagnostics } from './remote-transport.js'
import {
  IcePathPolicy,
  iceServersFromRelay,
  stunServersFromRelay,
  type RelayCredentials,
} from './relay-fallback.js'
import { verifyAndParseRemoteDescription, extractSha256Fingerprint } from './sdp-security.js'
import { safeParseRemoteCandidate } from './ice-candidate-security.js'
import { classifySelectedIcePair, type SelectedIcePath } from './ice-path-classifier.js'
import { DataChannelSendQueue } from './datachannel-send-queue.js'
import {
  ProgressDeadline,
  REMOTE_CONNECT_ABSOLUTE_MS,
  type ConnectDeadlineScope,
} from './connect-deadline.js'
import { isStableSetupRefusal, type SetupRefusalState } from './setup-refusal-contract.js'
import { controlJsonTextFitsByteLimit } from '../protocol/bounded-control-json.js'

// NO public third-party STUN. We never hand a client's IP to Google (or any outside party) during ICE.
// The default attempt uses host/mDNS candidates plus STUN/TURN URLs on OUR OWN relay host. Cross-NAT
// falls back to our TURN relay inside the SAME ICE negotiation. If relay credentials cannot be fetched,
// the attempt safely degrades to host candidates (and our STUN URLs when available). Default is empty:
// host candidates only, zero external IP disclosure.
export const PROTOTYPE_ICE_SERVERS: RTCIceServer[] = []

/** A transient ICE disconnect is common while a device roams between networks. Give the current established
 * attempt a short recovery window, but never leave a dead terminal looking connected indefinitely. */
export const WEBRTC_DISCONNECTED_GRACE_MS = 10_000
/** Trickle ICE can temporarily report `failed` after exhausting the candidates already received while a later
 * TURN candidate is still crossing signaling. Keep the exact pre-open attempt alive for one fixed, non-extending
 * window so that late candidate can resume checks. Established transports retain the immediate-failure contract. */
export const WEBRTC_PREOPEN_ICE_FAILED_GRACE_MS = 5_000
/** Browser stats can lag DataChannel open. Poll briefly after open, but never delay the connected callback or
 * leave an unbounded diagnostics task behind. */
export const WEBRTC_SELECTED_PAIR_POLL_INTERVAL_MS = 100
export const WEBRTC_SELECTED_PAIR_POLL_DEADLINE_MS = 2_000
export const WEBRTC_SELECTED_PAIR_POLL_MAX_ATTEMPTS =
  Math.ceil(WEBRTC_SELECTED_PAIR_POLL_DEADLINE_MS / WEBRTC_SELECTED_PAIR_POLL_INTERVAL_MS) + 1
const WEBRTC_STATS_CALL_TIMEOUT_MS = 250
/** The cloud accepts 128 ICE blobs total for both peers and caps each opaque blob at 2 KiB. Keep the browser's
 * attempt-owned half bounded so early gathering cannot grow without limit or crowd the desktop out. */
export const WEBRTC_LOCAL_ICE_MAX_CANDIDATES = 64
export const WEBRTC_LOCAL_ICE_MAX_CANDIDATE_BYTES = 2 * 1024
export const WEBRTC_LOCAL_ICE_MAX_QUEUE_BYTES =
  WEBRTC_LOCAL_ICE_MAX_CANDIDATES * WEBRTC_LOCAL_ICE_MAX_CANDIDATE_BYTES
export const WEBRTC_LOCAL_ICE_POST_TIMEOUT_MS = 5_000
export const WEBRTC_LOCAL_ICE_RETRY_DELAYS_MS = [100, 250, 500] as const
/** The desktop reserves the other half of the cloud's 128-candidate session quota. Apply the same hard bounds to
 * candidates fetched from it so a content-blind signaling response cannot create an unbounded browser queue. */
export const WEBRTC_REMOTE_ICE_MAX_CANDIDATES = 64
export const WEBRTC_REMOTE_ICE_MAX_CANDIDATE_BYTES = 2 * 1024
export const WEBRTC_REMOTE_ICE_MAX_QUEUE_BYTES =
  WEBRTC_REMOTE_ICE_MAX_CANDIDATES * WEBRTC_REMOTE_ICE_MAX_CANDIDATE_BYTES
const WEBRTC_SIGNAL_ICE_MAX_SEQUENCE = WEBRTC_LOCAL_ICE_MAX_CANDIDATES + WEBRTC_REMOTE_ICE_MAX_CANDIDATES
const WEBRTC_SIGNAL_ANSWER_MAX_BYTES = 16 * 1024

export interface WebrtcBridgeOptions {
  signaling: SignalingPort
  targetDeviceId: string
  targetDevicePublicKeyB64?: string | null
  /** Dev/legacy escape: allow connecting to a desktop WITHOUT verifying its answer proof (no pinned key).
   * Default false → production fails closed and requires the desktop's public key. */
  allowUnverifiedDesktop?: boolean
  iceServers?: RTCIceServer[]
  backoff?: PollBackoff
  /** S3c: fetch short-lived relay (TURN) creds from the cloud. Omit → direct-only. */
  fetchRelayCreds?: (signal?: AbortSignal) => Promise<RelayCredentials | null>
  /** @deprecated Production single-attempt ICE ignores this. It only times the explicit `iceServers` dev seam. */
  directTimeoutMs?: number
  /** S3c: constrain the one attempt to relay candidates (for the forced-relay smoke). */
  forceRelay?: boolean
  /** Report the connection mode for the UI badge. */
  onMode?: (mode: ConnectionMode) => void
  /** Injectable for tests; defaults to the global RTCPeerConnection. */
  peerFactory?: (config: RTCConfiguration) => RTCPeerConnection
  /** PROOF OF POSSESSION: sign the offer challenge with the browser's device key. The bridge stays
   * decoupled from device-identity — it just calls this to produce `{ pop, alg }` bound to the signaling
   * session + this offer's DTLS fingerprint. Omit → no offer proof attached (dev / legacy). */
  signOffer?: (challenge: string, signal?: AbortSignal) => Promise<{ pop: string; alg: 'ed25519' | 'p256' }>
  /** This browser's device id, embedded in the signed offer-proof challenge (binds the proof to us). */
  browserDeviceId?: string
  /** RELEASE-BLOCKER FIX: mint the cloud token AFTER the signaling session exists, bound to its id. The
   * agent fail-closed-requires token.signal_session_id == the session it's answering; since the relay
   * reconnect opens a DISTINCT session, so the token must be minted PER signaling session. Called with the live
   * `sessionId` right after createSession resolves; the result is presented as the auth token for that
   * attempt's DataChannel. Omit → no token minting here (legacy/dev; auth uses whatever RemoteSession has). */
  mintToken?: (
    signalSessionId: string,
    signal?: AbortSignal,
  ) => Promise<string | BoundAuthorization | null>
  /** Content-blind same-channel successor mint. The callback must validate the still-live predecessor in cloud;
   * this transport additionally suppresses any completion after its peer owner is retired. */
  refreshAuthorization?: (
    current: BoundAuthorization,
    signal?: AbortSignal,
  ) => Promise<BoundAuthorization | null>
  /** Production-only contract: the bridge must mint and expose a fresh signaling-session-bound token before it can
   * await the answer or open terminal authentication. A missing callback, refusal, or empty result fails setup
   * closed. Omit only for explicit legacy/dev transports whose RemoteSession receives a constructor token. */
  requireSessionBoundToken?: boolean
  /** ACCESS PASSKEY (#11): produce the WebAuthn-passkey-signed browser certificate to embed in the offer, or
   * null only when no account passkey is registered. A declined/failed ceremony throws and fails the connection
   * closed. The bridge owns one immutable result across its attempts; callers may additionally cache successful
   * certificates across transports. The desktop verifies it against the account passkey it pinned at enrollment. */
  browserCert?: (context?: BrowserCertificateRequestContext) => Promise<Record<string, unknown> | null>
  /** Optional non-interactive warm-up for browserCert. It may fetch only the account passkey descriptor and must
   * share that exact result with browserCert; it must never invoke WebAuthn or otherwise prompt the user. */
  browserCertPreflight?: (signal?: AbortSignal) => Promise<void>
  /** Production passes the controller-owned scope so preflight, relay/signaling, ICE, passkey, and auth share one
   * lifetime. Standalone bridges omit it and receive an equivalent internal scope. */
  connectDeadline?: ConnectDeadlineScope
}

export interface BrowserCertificateRequestContext {
  signal: AbortSignal
  onUserInteractionStart: () => void
  onUserInteractionEnd: () => void
}

type BrowserCertificateResolution =
  | { readonly ok: true; readonly certificate: Record<string, unknown> | null }
  | { readonly ok: false }

interface OwnedBrowserCertificateTask {
  readonly abort: AbortController
  readonly result: Promise<BrowserCertificateResolution>
}

interface OwnedBrowserCertificatePreflight {
  readonly abort: AbortController
  readonly settled: Promise<void>
}

type AttemptKind = 'all' | 'relay'

interface PendingLocalIce {
  readonly payload: string
  readonly bytes: number
  failures: number
}

interface PendingRemoteIce {
  readonly init: RTCIceCandidateInit
  readonly bytes: number
}

interface StagedRemoteIceBatch {
  readonly candidates: PendingRemoteIce[]
  readonly bytes: number
  readonly nextSince: number
}

interface StagedSignalProgress {
  readonly answer?: string
  readonly ice: StagedRemoteIceBatch
}

/**
 * Everything that can outlive a connection attempt is owned by this object. Promise continuations and browser
 * callbacks capture the owner instead of consulting mutable bridge fields, then prove it is still current before
 * changing shared state. Closing a peer cannot cancel already-running fetch/getStats/WebRTC promises, so this
 * ownership check is the cancellation boundary.
 */
interface AttemptOwner {
  readonly epoch: number
  readonly kind: AttemptKind
  readonly pc: RTCPeerConnection
  readonly dc: RTCDataChannel
  outbound: DataChannelSendQueue | null
  sessionId: string | null
  iceSince: number
  answerSeen: boolean
  progressPollTimer: ReturnType<typeof setTimeout> | null
  answerPollTimer: ReturnType<typeof setTimeout> | null
  icePollTimer: ReturnType<typeof setTimeout> | null
  signalingPollAbort: AbortController
  signalingAbortListener: (() => void) | null
  signalingRetired: boolean
  progressFallbackUsed: boolean
  preopenIceFailedGraceTimer: ReturnType<typeof setTimeout> | null
  disconnectGraceTimer: ReturnType<typeof setTimeout> | null
  candidatePollTimer: ReturnType<typeof setTimeout> | null
  candidatePollAttempts: number
  localIceQueue: PendingLocalIce[]
  localIceQueueBytes: number
  localIceAcceptedCandidates: number
  localIceSending: boolean
  localIceRetryTimer: ReturnType<typeof setTimeout> | null
  localIceAbort: AbortController | null
  localIceRetired: boolean
  remoteIceQueue: PendingRemoteIce[]
  remoteIceQueueBytes: number
  remoteIceAcceptedCandidates: number
  remoteIceApplying: boolean
  remoteIceReady: boolean
  remoteIceRetired: boolean
  localIcePhaseEmitted: boolean
  remoteIcePhaseEmitted: boolean
  /** A source that reported `disconnected` stays outstanding through its intermediate recovery states. The other
   * source being healthy must not cancel this attempt's bounded grace. */
  peerDisconnected: boolean
  iceDisconnected: boolean
  startedAt: number
  firstRelayAt: number
  established: boolean
  closedEmitted: boolean
  /** Compatibility path only: callers that inject an explicit direct-only ICE config may still request a
   * second forced-relay attempt. The production path never sets this flag. */
  fallbackEligible: boolean
}

export class WebrtcBridge implements RemoteTransport {
  // Peer creation is lazy because relay credentials are asynchronous. That lets the normal path create exactly
  // ONE native RTCPeerConnection with host/STUN/TURN candidates instead of constructing a throwaway direct peer.
  private pc: RTCPeerConnection | null = null
  private attemptEpoch = 0
  private activeAttempt: AttemptOwner | null = null
  // The cloud token minted for the CURRENT signaling session (bound to sessionId). Refreshed per attempt
  // (including every reconnect) so token.signal_session_id always matches the session actually in use. Null until
  // the first mint, or on the explicit legacy path where no mintToken callback is provided.
  private mintedAuthorization: BoundAuthorization | null = null
  private mintedToken: string | null = null

  private textHandler: (json: string) => void = () => {}
  private binaryHandler: (bytes: Uint8Array) => void = () => {}
  private stateHandler: (state: ControlState) => void = () => {}
  private diagHandler: (d: Diagnostics) => void = () => {}
  private connectionPhaseHandler: (phase: ConnectionAttemptPhase) => void = () => {}

  private readonly backoff: PollBackoff
  private readonly policy = new IcePathPolicy()
  private connectDeadline: ConnectDeadlineScope | null = null
  private ownedConnectDeadline: ProgressDeadline | null = null
  private connectAbortListener: (() => void) | null = null
  private compatibilityFallbackTimer: ReturnType<typeof setTimeout> | null = null
  /** One explicit connect owns one authorization result once its offer reaches the interactive authorization gate.
   * A legacy compatibility fallback consumes the same immutable outcome instead of opening another prompt. */
  private browserCertificateTask: OwnedBrowserCertificateTask | null = null
  /** Descriptor-only preparation may overlap relay discovery because it cannot open native WebAuthn UI. */
  private browserCertificatePreflight: OwnedBrowserCertificatePreflight | null = null
  private closed = false
  /** A registered account passkey could not authorize this browser. This is a user-action gate, not a network
   * outage: automatic transport retries must not reopen the WebAuthn prompt. */
  private authorizationBlocked = false
  /** An explicit stable adapter refusal (including hosted entitlement), not an ICE/network outage eligible for retry. */
  private setupRefusalBlocked = false

  // observable diagnostics (S3c-browser-smoke) — no secrets, no bodies.
  private diag: Diagnostics = defaultDiagnostics()

  constructor(private readonly opts: WebrtcBridgeOptions) {
    this.backoff = opts.backoff ?? DEFAULT_BACKOFF
    this.diag.forcedRelay = !!opts.forceRelay
  }

  /** Merge a diagnostics patch + notify (a fresh object so subscribers see a change). */
  private emitDiag(patch: Partial<Diagnostics>): void {
    this.diag = { ...this.diag, ...patch }
    this.diagHandler({ ...this.diag })
  }

  /** Publish only a fixed, content-blind milestone. Metrics observers must never be able to disrupt setup. */
  private emitConnectionPhase(phase: ConnectionAttemptPhase, owner?: AttemptOwner): void {
    if (this.closed || this.connectDeadline?.signal.aborted || (owner && !this.isCurrentAttempt(owner))) return
    try {
      this.connectionPhaseHandler(phase)
    } catch {
      // A diagnostic observer has no transport authority.
    }
  }

  private newPeer(iceServers: RTCIceServer[], policy?: RTCIceTransportPolicy): RTCPeerConnection {
    const config: RTCConfiguration = { iceServers, ...(policy ? { iceTransportPolicy: policy } : {}) }
    return (this.opts.peerFactory ?? ((c) => new RTCPeerConnection(c)))(config)
  }

  /** One stats read with its own short timeout. Browsers normally resolve getStats immediately, but a broken
   * implementation must not turn a bounded post-open poll into a page-lifetime promise. */
  private async selectedCandidate(peer: RTCPeerConnection): Promise<SelectedIcePath | null> {
    let timeout: ReturnType<typeof setTimeout> | null = null
    try {
      const stats = await Promise.race<RTCStatsReport | null>([
        peer.getStats(),
        new Promise<null>((resolve) => {
          timeout = setTimeout(() => resolve(null), WEBRTC_STATS_CALL_TIMEOUT_MS)
        }),
      ])
      return stats ? classifySelectedIcePair(stats) : null
    } catch {
      return null
    } finally {
      if (timeout) clearTimeout(timeout)
    }
  }

  private applySelectedCandidate(owner: AttemptOwner, path: SelectedIcePath, selectedAt: number): void {
    if (!this.isCurrentAttempt(owner)) return
    this.policy.onConnected(owner.kind === 'relay', path.candidateType)
    this.opts.onMode?.(this.policy.connectionMode)
    this.emitAttemptDiag(owner, {
      candidateType: path.candidateType,
      candidateProtocol: path.candidateProtocol,
      route: path.route,
      relayLeg: path.relayLeg,
      pairProtocol: path.pairProtocol,
      localTurnProtocol: path.localTurnProtocol,
      timing: { ...this.diag.timing, toSelectedPairMs: Math.max(0, selectedAt - owner.startedAt) },
    })
  }

  /** Browser selected-pair stats often materialize shortly after DataChannel open. Retry only while this owner is
   * current and only until the fixed post-open deadline. The connection callback has already fired before this
   * method is queued. */
  private pollSelectedCandidate(owner: AttemptOwner, deadlineAt: number): void {
    if (!this.isCurrentAttempt(owner) || !owner.established) return
    if (owner.candidatePollAttempts >= WEBRTC_SELECTED_PAIR_POLL_MAX_ATTEMPTS) {
      this.policy.onConnected(owner.kind === 'relay', null)
      this.opts.onMode?.(this.policy.connectionMode)
      return
    }
    owner.candidatePollAttempts++
    void this.selectedCandidate(owner.pc).then((path) => {
      if (!this.isCurrentAttempt(owner) || !owner.established) return
      if (path) {
        this.applySelectedCandidate(owner, path, nowMs())
        return
      }
      const remaining = deadlineAt - nowMs()
      if (remaining <= 0 || owner.candidatePollAttempts >= WEBRTC_SELECTED_PAIR_POLL_MAX_ATTEMPTS) {
        // Forced-relay qualification still knows its configured route even when a browser withholds stats. Normal
        // attempts remain honestly unknown.
        this.policy.onConnected(owner.kind === 'relay', null)
        this.opts.onMode?.(this.policy.connectionMode)
        return
      }
      const timer = setTimeout(() => {
        if (owner.candidatePollTimer === timer) owner.candidatePollTimer = null
        this.pollSelectedCandidate(owner, deadlineAt)
      }, Math.min(WEBRTC_SELECTED_PAIR_POLL_INTERVAL_MS, remaining))
      owner.candidatePollTimer = timer
    })
  }

  onText(h: (json: string) => void): void {
    this.textHandler = h
  }
  onBinary(h: (bytes: Uint8Array) => void): void {
    this.binaryHandler = h
  }
  onState(h: (state: ControlState) => void): void {
    this.stateHandler = h
  }
  onDiagnostics(h: (d: Diagnostics) => void): void {
    this.diagHandler = h
    h({ ...this.diag })
  }
  onConnectionPhase(h: (phase: ConnectionAttemptPhase) => void): void {
    this.connectionPhaseHandler = h
  }

  sendText(json: string): boolean {
    const owner = this.activeAttempt
    if (owner && this.isCurrentAttempt(owner) && owner.dc.readyState === 'open' && owner.outbound) {
      return owner.outbound.enqueueText(json)
    }
    return false // channel not open (connecting/closing/closed) → dropped; caller surfaces the failure
  }
  /** The cloud token minted for the CURRENT signaling session (bound to its id). RemoteSession reads this at
   * auth-send time so the token it presents matches the session the DataChannel runs over. Null when no
   * mintToken callback was provided (legacy: auth falls back to the session's constructor token). */
  currentToken(): string | null {
    return this.mintedToken
  }
  currentAuthorization(): BoundAuthorization | null {
    return this.opts.refreshAuthorization && this.mintedAuthorization ? { ...this.mintedAuthorization } : null
  }
  async refreshAuthorization(
    current: BoundAuthorization,
    signal?: AbortSignal,
  ): Promise<BoundAuthorization | null> {
    const owner = this.activeAttempt
    if (!owner || !this.isCurrentAttempt(owner) || !owner.established || !this.opts.refreshAuthorization || signal?.aborted) {
      return null
    }
    const refreshed = await this.opts.refreshAuthorization({ ...current }, signal)
    if (!this.isCurrentAttempt(owner) || !owner.established || signal?.aborted) return null
    if (!refreshed || typeof refreshed.token !== 'string' || refreshed.token.length === 0 ||
        !Number.isSafeInteger(refreshed.expiresAtMs) || !Number.isSafeInteger(refreshed.deadlineMs) ||
        refreshed.deadlineMs <= Date.now()) return null
    return { ...refreshed }
  }
  sendBinary(bytes: Uint8Array): boolean {
    return this.sendBinaryBatch([bytes])
  }
  sendBinaryBatch(frames: readonly Uint8Array[]): boolean {
    const owner = this.activeAttempt
    if (owner && this.isCurrentAttempt(owner) && owner.dc.readyState === 'open' && owner.outbound) {
      return owner.outbound.enqueueBinaryBatch(frames)
    }
    return false
  }
  sendBulkBinaryBatch(frames: readonly Uint8Array[]): boolean {
    const owner = this.activeAttempt
    if (owner && this.isCurrentAttempt(owner) && owner.dc.readyState === 'open' && owner.outbound) {
      return owner.outbound.enqueueBulkBinaryBatch(frames)
    }
    return false
  }

  private static readonly COMPATIBILITY_DIRECT_TIMEOUT_MS = 8_000

  private ownsAttempt(owner: AttemptOwner, sessionId?: string): boolean {
    return this.activeAttempt === owner && owner.epoch === this.attemptEpoch &&
      (sessionId === undefined || owner.sessionId === sessionId)
  }

  private isCurrentAttempt(owner: AttemptOwner, sessionId?: string): boolean {
    return !this.closed && this.ownsAttempt(owner, sessionId)
  }

  private emitAttemptDiag(owner: AttemptOwner, patch: Partial<Diagnostics>): void {
    if (this.isCurrentAttempt(owner)) this.emitDiag(patch)
  }

  private attemptConnected(owner: AttemptOwner): boolean {
    return this.policy.isConnected || owner.dc.readyState === 'open'
  }

  private clearDisconnectGrace(owner: AttemptOwner): void {
    if (owner.disconnectGraceTimer) clearTimeout(owner.disconnectGraceTimer)
    owner.disconnectGraceTimer = null
  }

  private clearPreopenIceFailedGrace(owner: AttemptOwner): void {
    if (owner.preopenIceFailedGraceTimer) clearTimeout(owner.preopenIceFailedGraceTimer)
    owner.preopenIceFailedGraceTimer = null
  }

  /** A native `failed` verdict is not final while trickle signaling can still deliver a candidate. The first
   * failure owns one absolute grace window; intermediate `checking` states do not move it. This prevents a noisy
   * peer from extending setup forever while still allowing a late TURN candidate to reach Connected/Open. */
  private armPreopenIceFailedGrace(owner: AttemptOwner): void {
    if (
      !this.isCurrentAttempt(owner) || owner.established || owner.fallbackEligible ||
      owner.preopenIceFailedGraceTimer
    ) return
    const timer = setTimeout(() => {
      if (owner.preopenIceFailedGraceTimer !== timer) return
      owner.preopenIceFailedGraceTimer = null
      if (!this.isCurrentAttempt(owner) || this.attemptConnected(owner)) return
      const state = owner.pc.iceConnectionState
      if (state === 'connected' || state === 'completed') return
      this.failAttempt(owner)
    }, WEBRTC_PREOPEN_ICE_FAILED_GRACE_MS)
    owner.preopenIceFailedGraceTimer = timer
  }

  /** Notify the controller at most once for an attempt. A native DataChannel close and a peer-state failure can
   * race, and both browser callbacks can already be queued when teardown starts. */
  private emitAttemptClosed(owner: AttemptOwner): void {
    if (!this.isCurrentAttempt(owner) || owner.closedEmitted) return
    owner.closedEmitted = true
    this.clearDisconnectGrace(owner)
    // Detach first so the controller can abort its shared scope from inside this callback without re-entering the
    // bridge. A standalone bridge aborts its internally owned scope here.
    this.finishConnectDeadline(true)
    this.stateHandler('closed')
  }

  /** A post-connect peer failure is terminal for this transport instance. The controller's existing `closed`
   * path owns reconnect and will mint a fresh signaling session/token; this bridge only retires the dead peer. */
  private failEstablishedAttempt(owner: AttemptOwner): void {
    if (!this.isCurrentAttempt(owner) || !owner.established) return
    this.emitAttemptClosed(owner)
    // `closed` may already have been emitted by a racing DataChannel callback. Resource retirement is a
    // separate invariant: the current peer/signaling owner must still be torn down exactly once.
    this.close()
  }

  /** A DataChannel close is terminal even if the browser never follows it with peer/ICE state callbacks. Emit the
   * controller signal once, then always retire the current peer and signaling session. */
  private closeCurrentAttempt(owner: AttemptOwner): void {
    if (!this.isCurrentAttempt(owner)) return
    this.emitAttemptClosed(owner)
    this.close()
  }

  fail(): void {
    if (this.closed) return
    const owner = this.activeAttempt
    if (owner && this.isCurrentAttempt(owner)) {
      this.closeCurrentAttempt(owner)
      return
    }
    this.finishConnectDeadline(true)
    this.stateHandler('closed')
    this.close()
  }

  private armDisconnectGrace(owner: AttemptOwner): void {
    if (!this.isCurrentAttempt(owner) || !owner.established || owner.closedEmitted || owner.disconnectGraceTimer) return
    const timer = setTimeout(() => {
      if (owner.disconnectGraceTimer !== timer) return
      owner.disconnectGraceTimer = null
      this.failEstablishedAttempt(owner)
    }, WEBRTC_DISCONNECTED_GRACE_MS)
    owner.disconnectGraceTimer = timer
  }

  /** Reconcile both peer-state APIs because browsers do not all surface a silent network loss through the same
   * callback. Track each source independently: once it reports `disconnected`, Connecting/Checking is only a
   * recovery attempt, not proof of recovery. Only that same source reaching Connected/Completed clears its flag.
   * State is recorded before DataChannel open too, so a pre-open disconnect cannot disappear merely by advancing
   * to an intermediate state before `onopen`. All actions remain tied to the captured attempt owner. */
  private handlePeerState(owner: AttemptOwner): void {
    if (!this.isCurrentAttempt(owner) || owner.closedEmitted) return
    const connectionState = owner.pc.connectionState
    const iceState = owner.pc.iceConnectionState

    if (connectionState === 'disconnected') owner.peerDisconnected = true
    else if (connectionState === 'connected') owner.peerDisconnected = false

    if (iceState === 'disconnected') owner.iceDisconnected = true
    else if (iceState === 'connected' || iceState === 'completed') owner.iceDisconnected = false

    // Setup records these flags before establishment. `dc.onopen` calls this method again and reconciles them.
    if (!owner.established) return
    if (
      connectionState === 'failed' || connectionState === 'closed' ||
      iceState === 'failed' || iceState === 'closed'
    ) {
      this.failEstablishedAttempt(owner)
      return
    }
    if (owner.peerDisconnected || owner.iceDisconnected) {
      this.armDisconnectGrace(owner)
      return
    }
    this.clearDisconnectGrace(owner)
  }

  /** Stop setup-only local ICE work without touching the live peer. Async completions remain harmless because every
   * continuation proves attempt ownership again before changing queue or connection state. */
  private retireLocalIce(owner: AttemptOwner): void {
    owner.localIceRetired = true
    if (owner.localIceRetryTimer) clearTimeout(owner.localIceRetryTimer)
    owner.localIceRetryTimer = null
    owner.localIceAbort?.abort()
    owner.localIceAbort = null
    owner.localIceSending = false
    owner.localIceQueue = []
    owner.localIceQueueBytes = 0
  }

  /** A malformed/overflowing/exhausted candidate queue cannot silently continue a pre-open attempt with an
   * incomplete candidate set. Once the DataChannel is open, signaling is already obsolete and only its queue is
   * retired. */
  private failLocalIce(owner: AttemptOwner): void {
    if (!this.isCurrentAttempt(owner)) return
    const connected = this.attemptConnected(owner)
    this.retireLocalIce(owner)
    if (!connected) this.failAttempt(owner)
  }

  /** Remote candidates are setup-only state. `addIceCandidate` is not abortable, so retirement clears all queued
   * work and makes the in-flight promise's owner checks inert instead of letting it affect an established or
   * replacement transport. */
  private retireRemoteIce(owner: AttemptOwner): void {
    owner.remoteIceRetired = true
    owner.remoteIceQueue = []
    owner.remoteIceQueueBytes = 0
    owner.remoteIceApplying = false
  }

  /** If one fetched candidate cannot be validated, admitted, or applied, this pre-open attempt no longer has a
   * provably complete peer candidate set. Fail honestly so the controller reconnects with a fresh signaling
   * session. Once the DataChannel is open, signaling is obsolete and late setup work is only retired. */
  private failRemoteIce(owner: AttemptOwner): void {
    if (!this.isCurrentAttempt(owner)) return
    const connected = this.attemptConnected(owner)
    this.retireRemoteIce(owner)
    if (!connected) this.failAttempt(owner)
  }

  /** Treat each cloud ICE response as one untrusted transaction. Validate its outer shape, cursor, sequence,
   * candidate payloads, and aggregate bounds without mutating owner state. That prevents a malformed suffix from
   * advancing the cursor or applying a valid prefix before the attempt fails closed. Gaps are valid because the
   * opposite peer's records share a session sequence; duplicates, reordering, and regressions are not. */
  private stageRemoteIceBatch(owner: AttemptOwner, response: unknown): StagedRemoteIceBatch | null {
    if (!response || typeof response !== 'object' || Array.isArray(response)) return null
    const record = response as Record<string, unknown>
    const candidates = record.candidates
    const nextSince = record.nextSince
    const priorSince = owner.iceSince
    if (
      !Array.isArray(candidates) ||
      !Number.isSafeInteger(nextSince) ||
      (nextSince as number) < 0 ||
      (nextSince as number) > WEBRTC_SIGNAL_ICE_MAX_SEQUENCE ||
      (nextSince as number) < priorSince ||
      candidates.length > WEBRTC_REMOTE_ICE_MAX_CANDIDATES - owner.remoteIceAcceptedCandidates
    ) return null

    const staged: PendingRemoteIce[] = []
    let stagedBytes = 0
    let previousSeq = priorSince
    for (const candidate of candidates) {
      if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return null
      const entry = candidate as Record<string, unknown>
      if (
        typeof entry.candidate !== 'string' ||
        entry.candidate.length === 0 ||
        entry.candidate.length > WEBRTC_REMOTE_ICE_MAX_CANDIDATE_BYTES ||
        !Number.isSafeInteger(entry.seq) ||
        (entry.seq as number) <= 0 ||
        (entry.seq as number) > WEBRTC_SIGNAL_ICE_MAX_SEQUENCE ||
        (entry.seq as number) <= previousSeq
      ) return null

      const bytes = utf8ByteLength(entry.candidate)
      const init = bytes > 0 && bytes <= WEBRTC_REMOTE_ICE_MAX_CANDIDATE_BYTES
        ? safeParseRemoteCandidate(entry.candidate)
        : null
      if (!init) return null
      stagedBytes += bytes
      if (owner.remoteIceQueueBytes + stagedBytes > WEBRTC_REMOTE_ICE_MAX_QUEUE_BYTES) return null
      staged.push({ init, bytes })
      previousSeq = entry.seq as number
    }
    if ((nextSince as number) < previousSeq) return null
    return { candidates: staged, bytes: stagedBytes, nextSince: nextSince as number }
  }

  /** Validate the complete combined cloud response before verifying/installing an answer or admitting any ICE.
   * This new boundary is deliberately exact: unlike the legacy ICE shape, unknown outer/candidate fields do not
   * survive a rolling protocol mismatch. */
  private stageSignalProgress(owner: AttemptOwner, response: unknown): StagedSignalProgress | null {
    if (!response || typeof response !== 'object' || Array.isArray(response)) return null
    const record = response as Record<string, unknown>
    const keys = Object.keys(record).sort()
    const expected = record.answer === undefined
      ? ['candidates', 'expiresAtMs', 'nextSince', 'status']
      : ['answer', 'candidates', 'expiresAtMs', 'nextSince', 'status']
    if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) return null
    if (record.status !== 'pending' && record.status !== 'answered') return null
    if (owner.answerSeen && record.status !== 'answered') return null
    if (!Number.isSafeInteger(record.expiresAtMs) || (record.expiresAtMs as number) < 0) return null
    if (!Array.isArray(record.candidates)) return null
    for (const candidate of record.candidates) {
      if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) return null
      const candidateKeys = Object.keys(candidate as Record<string, unknown>).sort()
      if (
        candidateKeys.length !== 2 || candidateKeys[0] !== 'candidate' || candidateKeys[1] !== 'seq'
      ) return null
    }
    const answer = record.answer
    if (answer !== undefined) {
      if (
        owner.answerSeen || record.status !== 'answered' || typeof answer !== 'string' || answer.length === 0 ||
        utf8ByteLength(answer) > WEBRTC_SIGNAL_ANSWER_MAX_BYTES
      ) return null
    } else if (!owner.answerSeen && record.status === 'answered') {
      // A one-snapshot server cannot report answered without returning the answer to a caller that has not seen it.
      return null
    }
    const ice = this.stageRemoteIceBatch(owner, {
      candidates: record.candidates,
      nextSince: record.nextSince,
    })
    return ice ? { ...(answer !== undefined ? { answer } : {}), ice } : null
  }

  private admitRemoteIceBatch(
    owner: AttemptOwner,
    sessionId: string,
    batch: StagedRemoteIceBatch,
  ): boolean {
    if (!this.isCurrentAttempt(owner, sessionId) || owner.remoteIceRetired) return false
    owner.remoteIceAcceptedCandidates += batch.candidates.length
    owner.remoteIceQueue.push(...batch.candidates)
    owner.remoteIceQueueBytes += batch.bytes
    // Cursor advancement is the commit point and deliberately follows admission of the complete validated batch.
    owner.iceSince = batch.nextSince
    if (batch.candidates.length > 0 && !owner.remoteIcePhaseEmitted) {
      owner.remoteIcePhaseEmitted = true
      this.emitConnectionPhase('first_remote_ice', owner)
    }
    this.flushRemoteIce(owner, sessionId)
    return true
  }

  /** Apply one candidate at a time, in cloud sequence order, and only after this exact owner successfully installed
   * its remote description. A later poll may append while one application is pending, but it cannot overtake it. */
  private flushRemoteIce(owner: AttemptOwner, sessionId: string): void {
    if (
      !this.isCurrentAttempt(owner, sessionId) || owner.remoteIceRetired || !owner.remoteIceReady ||
      owner.remoteIceApplying || owner.remoteIceQueue.length === 0
    ) return
    const pending = owner.remoteIceQueue[0]!
    owner.remoteIceApplying = true
    void Promise.resolve().then(() => {
      if (!this.isCurrentAttempt(owner, sessionId) || owner.remoteIceRetired) return
      return owner.pc.addIceCandidate(pending.init)
    }).then(() => {
      if (!this.isCurrentAttempt(owner, sessionId) || owner.remoteIceRetired) return
      owner.remoteIceApplying = false
      if (owner.remoteIceQueue[0] !== pending) {
        this.failRemoteIce(owner)
        return
      }
      owner.remoteIceQueue.shift()
      owner.remoteIceQueueBytes = Math.max(0, owner.remoteIceQueueBytes - pending.bytes)
      this.flushRemoteIce(owner, sessionId)
    }).catch(() => {
      if (!this.isCurrentAttempt(owner, sessionId) || owner.remoteIceRetired) return
      owner.remoteIceApplying = false
      this.failRemoteIce(owner)
    })
  }

  private enqueueLocalIce(owner: AttemptOwner, payload: string): void {
    if (!this.isCurrentAttempt(owner) || owner.localIceRetired) return
    const bytes = utf8ByteLength(payload)
    if (
      bytes === 0 || bytes > WEBRTC_LOCAL_ICE_MAX_CANDIDATE_BYTES ||
      owner.localIceAcceptedCandidates >= WEBRTC_LOCAL_ICE_MAX_CANDIDATES ||
      owner.localIceQueueBytes + bytes > WEBRTC_LOCAL_ICE_MAX_QUEUE_BYTES
    ) {
      this.failLocalIce(owner)
      return
    }
    owner.localIceAcceptedCandidates++
    owner.localIceQueue.push({ payload, bytes, failures: 0 })
    owner.localIceQueueBytes += bytes
    const sessionId = owner.sessionId
    if (sessionId) this.flushLocalIce(owner, sessionId)
  }

  /** Post exactly one candidate at a time. This preserves native gathering order, applies bounded retry to a
   * transient cloud/network refusal, and aborts an in-flight fetch when this owner retires. A retry can duplicate an
   * opaque ICE candidate if the response was lost after commit; WebRTC candidate application is idempotent and the
   * retry/count bounds keep that ambiguity finite. */
  private flushLocalIce(owner: AttemptOwner, sessionId: string): void {
    if (
      !this.isCurrentAttempt(owner, sessionId) || owner.localIceRetired || owner.localIceSending ||
      owner.localIceRetryTimer || owner.localIceQueue.length === 0
    ) return
    const pending = owner.localIceQueue[0]!
    const abort = new AbortController()
    const attemptSignal = this.connectDeadline?.signal
    const abortForAttempt = (): void => abort.abort()
    attemptSignal?.addEventListener('abort', abortForAttempt, { once: true })
    if (attemptSignal?.aborted) abort.abort()
    owner.localIceAbort = abort
    owner.localIceSending = true
    const timeout = setTimeout(() => abort.abort(), WEBRTC_LOCAL_ICE_POST_TIMEOUT_MS)

    void this.opts.signaling.postIce(sessionId, pending.payload, abort.signal).then(() => {
      clearTimeout(timeout)
      attemptSignal?.removeEventListener('abort', abortForAttempt)
      if (owner.localIceAbort === abort) owner.localIceAbort = null
      if (!this.isCurrentAttempt(owner, sessionId) || owner.localIceRetired) return
      owner.localIceSending = false
      if (owner.localIceQueue[0] !== pending) {
        this.failLocalIce(owner)
        return
      }
      owner.localIceQueue.shift()
      owner.localIceQueueBytes = Math.max(0, owner.localIceQueueBytes - pending.bytes)
      this.progress('bridge:first-local-ice-posted')
      this.flushLocalIce(owner, sessionId)
    }).catch((error: unknown) => {
      clearTimeout(timeout)
      attemptSignal?.removeEventListener('abort', abortForAttempt)
      if (owner.localIceAbort === abort) owner.localIceAbort = null
      if (!this.isCurrentAttempt(owner, sessionId) || owner.localIceRetired) return
      owner.localIceSending = false
      if (error instanceof SignalSessionDead) {
        this.failLocalIce(owner)
        return
      }
      const delay = WEBRTC_LOCAL_ICE_RETRY_DELAYS_MS[pending.failures]
      if (delay === undefined) {
        this.failLocalIce(owner)
        return
      }
      pending.failures++
      const timer = setTimeout(() => {
        if (owner.localIceRetryTimer !== timer) return
        owner.localIceRetryTimer = null
        this.flushLocalIce(owner, sessionId)
      }, delay)
      owner.localIceRetryTimer = timer
    })
  }

  /** Fail setup only while the owner that observed the failure is still authoritative. `owner=null` covers
   * credential/peer construction failures before an attempt exists. */
  private failAttempt(owner: AttemptOwner | null): void {
    if (this.closed) return
    if (owner) {
      if (!this.isCurrentAttempt(owner) || this.attemptConnected(owner)) return
    } else if (this.activeAttempt) {
      return
    }
    this.policy.onFailed()
    this.opts.onMode?.('failed')
    // See emitAttemptClosed: terminal setup state is reported only after the bridge is no longer listening to the
    // shared abort signal. The controller's terminal-state handler can then abort in-flight cloud work exactly once.
    this.finishConnectDeadline(true)
    this.stateHandler('offline')
    this.close()
  }

  private blockForSetupRefusal(owner: AttemptOwner | null, state: SetupRefusalState): void {
    if (this.closed) return
    if (owner && (!this.isCurrentAttempt(owner) || this.attemptConnected(owner))) return
    if (!owner && this.activeAttempt) return
    this.setupRefusalBlocked = true
    this.opts.onMode?.('failed')
    this.finishConnectDeadline(true)
    this.stateHandler(state)
    if (owner) this.teardownAttempt(owner)
  }

  private cancelSignalingSession(sessionId: string): void {
    void this.opts.signaling.cancel(sessionId).catch(() => {
      // Session cancellation is best-effort cleanup. Attempt ownership has already been revoked locally.
    })
  }

  private beginConnectDeadline(): void {
    if (this.connectDeadline) return
    if (this.opts.connectDeadline) {
      this.connectDeadline = this.opts.connectDeadline
    } else {
      const inactivityMs = this.backoff.staleTimeoutMs
      this.ownedConnectDeadline = new ProgressDeadline({
        inactivityMs,
        absoluteMs: Math.max(REMOTE_CONNECT_ABSOLUTE_MS, inactivityMs),
        onExpire: () => {
          // ProgressDeadline aborts first. The abort listener below owns the fail/close transition, keeping expiry
          // and explicit supersession on exactly the same owner-gated teardown path.
        },
      })
      this.connectDeadline = this.ownedConnectDeadline
    }
    const deadline = this.connectDeadline
    const onAbort = (): void => {
      if (this.closed || this.authorizationBlocked || this.setupRefusalBlocked || this.connectDeadline !== deadline) return
      const owner = this.activeAttempt
      if (owner && this.isCurrentAttempt(owner)) {
        if (this.attemptConnected(owner)) this.closeCurrentAttempt(owner)
        else this.failAttempt(owner)
      } else {
        this.failAttempt(null)
      }
    }
    this.connectAbortListener = onAbort
    deadline.signal.addEventListener('abort', onAbort, { once: true })
    if (deadline.signal.aborted) onAbort()
  }

  private progress(stage: string): void {
    this.connectDeadline?.progress(stage)
  }

  private finishConnectDeadline(abortOwned: boolean): void {
    const deadline = this.connectDeadline
    const listener = this.connectAbortListener
    this.connectDeadline = null
    this.connectAbortListener = null
    if (deadline && listener) deadline.signal.removeEventListener('abort', listener)
    if (this.ownedConnectDeadline) {
      if (abortOwned) this.ownedConnectDeadline.abort()
      else this.ownedConnectDeadline.complete()
      this.ownedConnectDeadline = null
    }
  }

  private clearCompatibilityFallbackTimer(): void {
    if (this.compatibilityFallbackTimer) clearTimeout(this.compatibilityFallbackTimer)
    this.compatibilityFallbackTimer = null
  }

  /** Start only the non-interactive descriptor read beside relay discovery. Its callback owns the descriptor value
   * and shares it with browserCert; this wrapper owns cancellation/settlement without learning trust material. */
  private beginBrowserCertificatePreflight(): Promise<void> | null {
    if (!this.opts.browserCertPreflight || !this.opts.browserCert) return null
    if (this.browserCertificatePreflight) return this.browserCertificatePreflight.settled
    const deadline = this.connectDeadline
    if (!deadline) return null

    const abort = new AbortController()
    const onDeadlineAbort = (): void => abort.abort()
    deadline.signal.addEventListener('abort', onDeadlineAbort, { once: true })
    if (deadline.signal.aborted) abort.abort()
    const request = Promise.resolve().then(() => this.opts.browserCertPreflight!(abort.signal))
    const settled = waitForAttempt(request, abort.signal).then(
      () => {},
      () => {},
    ).finally(() => deadline.signal.removeEventListener('abort', onDeadlineAbort))
    this.browserCertificatePreflight = { abort, settled }
    return settled
  }

  /** Full authorization remains at the existing post-offer gate. A derived abort controller is necessary when the
   * controller supplied the parent deadline: bridge-local failure must still dismiss native WebAuthn without waiting
   * for the controller's state callback. The normalized result is consumed immediately at that gate. */
  private beginBrowserCertificateResolution(): Promise<BrowserCertificateResolution> | null {
    if (!this.opts.browserCert) return null
    if (this.browserCertificateTask) return this.browserCertificateTask.result
    const deadline = this.connectDeadline
    if (!deadline) return null

    const abort = new AbortController()
    const onDeadlineAbort = (): void => abort.abort()
    deadline.signal.addEventListener('abort', onDeadlineAbort, { once: true })
    if (deadline.signal.aborted) abort.abort()

    // Defer the callback by one microtask so the owned task is published before user code can resolve or throw.
    const request = Promise.resolve().then(() => this.opts.browserCert!({
      signal: abort.signal,
      onUserInteractionStart: () => deadline.pauseInactivity('passkey'),
      onUserInteractionEnd: () => deadline.resumeInactivity('passkey'),
    }))
    const result: Promise<BrowserCertificateResolution> = waitForAttempt(request, abort.signal).then(
      (certificate): BrowserCertificateResolution => ({ ok: true, certificate }),
      (): BrowserCertificateResolution => ({ ok: false }),
    ).finally(() => deadline.signal.removeEventListener('abort', onDeadlineAbort))
    this.browserCertificateTask = { abort, result }
    return result
  }

  private abortBrowserCertificateResolution(): void {
    this.browserCertificateTask?.abort.abort()
  }

  private abortBrowserCertificatePreflight(): void {
    this.browserCertificatePreflight?.abort.abort()
  }

  private async settleBrowserCertificatePreflight(): Promise<void> {
    const preflight = this.browserCertificatePreflight
    if (preflight) await preflight.settled
  }

  /** Begin one ICE attempt. Normal mode gives the peer host + STUN + TURN candidates together, so ICE can
   * select direct without an 8-second gate and relay without tearing down/re-signaling. */
  async connect(): Promise<void> {
    if (this.closed) return
    this.beginConnectDeadline()
    if (this.closed || this.connectDeadline?.signal.aborted) return
    this.progress('bridge:connect')
    this.stateHandler('connecting')
    if (this.opts.requireSessionBoundToken && !this.opts.mintToken) {
      // Production must never silently downgrade to RemoteSession's constructor-token compatibility seam.
      this.failAttempt(null)
      return
    }
    // connect() is the explicit user intent boundary. Only the non-interactive descriptor GET overlaps relay
    // discovery; native WebAuthn remains behind a viable peer and completed offer.
    this.beginBrowserCertificatePreflight()
    if (this.opts.forceRelay) {
      // S3c forced-relay: one relay-only peer, used only for explicit qualification.
      let creds: RelayCredentials | null = null
      this.emitConnectionPhase('relay_fetch_start')
      try {
        const signal = this.connectDeadline?.signal
        creds = this.opts.fetchRelayCreds
          ? await waitForAttempt(this.opts.fetchRelayCreds(signal), signal)
          : null
        this.progress('bridge:relay-credentials')
      } catch (error) {
        if (isStableSetupRefusal(error)) {
          this.blockForSetupRefusal(null, error.state)
          await this.settleBrowserCertificatePreflight()
          return
        }
        // handled by the fail-closed branch below
      }
      if (this.closed) {
        await this.settleBrowserCertificatePreflight()
        return
      }
      if (!creds || creds.urls.length === 0) {
        this.failAttempt(null)
        await this.settleBrowserCertificatePreflight()
        return
      }
      this.emitConnectionPhase('relay_fetch_ready')
      try {
        this.pc = this.newPeer(iceServersFromRelay(creds), 'relay')
        this.emitConnectionPhase('peer_created')
        this.progress('bridge:peer-created')
        const relay = await this.startAttempt('relay')
        if (!relay || !this.isCurrentAttempt(relay) || this.authorizationBlocked || this.setupRefusalBlocked) return
      } catch (error) {
        if (isStableSetupRefusal(error)) {
          this.blockForSetupRefusal(this.activeAttempt, error.state)
          await this.settleBrowserCertificatePreflight()
          return
        }
        this.failAttempt(this.activeAttempt)
        await this.settleBrowserCertificatePreflight()
      }
      return
    }

    // Fetch once BEFORE creating the peer. The same short-lived credential supplies our STUN and TURN URLs;
    // default `iceTransportPolicy: all` lets ICE race them and prefer the best path. A failed credentials request
    // is not an authorization bypass or a reason to block host-direct connectivity: proceed in degraded mode.
    let iceServers = this.opts.iceServers ?? PROTOTYPE_ICE_SERVERS
    if (this.opts.iceServers === undefined && this.opts.fetchRelayCreds) {
      this.emitConnectionPhase('relay_fetch_start')
      try {
        const signal = this.connectDeadline?.signal
        const creds = await waitForAttempt(this.opts.fetchRelayCreds(signal), signal)
        if (this.closed) {
          await this.settleBrowserCertificatePreflight()
          return
        }
        this.progress('bridge:relay-credentials')
        if (creds && creds.urls.length > 0) {
          iceServers = iceServersFromRelay(creds)
          this.emitConnectionPhase('relay_fetch_ready')
        } else {
          iceServers = creds ? stunServersFromRelay(creds) : PROTOTYPE_ICE_SERVERS
        }
      } catch (error) {
        if (this.closed) {
          await this.settleBrowserCertificatePreflight()
          return
        }
        if (isStableSetupRefusal(error)) {
          this.blockForSetupRefusal(null, error.state)
          await this.settleBrowserCertificatePreflight()
          return
        }
        iceServers = PROTOTYPE_ICE_SERVERS
      }
    }
    if (this.closed) {
      await this.settleBrowserCertificatePreflight()
      return
    }
    try {
      this.pc = this.newPeer(iceServers)
      this.emitConnectionPhase('peer_created')
      this.progress('bridge:peer-created')
      // Explicit caller-supplied ICE lists are a legacy/dev seam. Preserve their requested direct→relay retry,
      // while the production path above (no explicit list) remains one peer / one session.
      const fallbackEligible = this.opts.iceServers !== undefined && !!this.opts.fetchRelayCreds
      const owner = await this.startAttempt('all', fallbackEligible)
      if (!owner || !this.isCurrentAttempt(owner) || this.authorizationBlocked || this.setupRefusalBlocked) return
      if (fallbackEligible) {
        const timer = setTimeout(() => {
          if (this.compatibilityFallbackTimer === timer) this.compatibilityFallbackTimer = null
          void this.onCompatibilityDirectTimeout(owner)
        }, this.opts.directTimeoutMs ?? WebrtcBridge.COMPATIBILITY_DIRECT_TIMEOUT_MS)
        this.compatibilityFallbackTimer = timer
      }
    } catch {
      this.failAttempt(this.activeAttempt)
      await this.settleBrowserCertificatePreflight()
    }
  }

  private async startAttempt(
    kind: AttemptKind,
    fallbackEligible = false,
  ): Promise<AttemptOwner | null> {
    if (this.closed) return null
    if (this.activeAttempt) this.teardownAttempt(this.activeAttempt)

    const peer = this.pc
    if (!peer) return null
    const dc = peer.createDataChannel('hydra-control')
    const owner: AttemptOwner = {
      epoch: ++this.attemptEpoch,
      kind,
      pc: peer,
      dc,
      outbound: null,
      sessionId: null,
      iceSince: 0,
      answerSeen: false,
      progressPollTimer: null,
      answerPollTimer: null,
      icePollTimer: null,
      signalingPollAbort: new AbortController(),
      signalingAbortListener: null,
      signalingRetired: false,
      progressFallbackUsed: false,
      preopenIceFailedGraceTimer: null,
      disconnectGraceTimer: null,
      candidatePollTimer: null,
      candidatePollAttempts: 0,
      localIceQueue: [],
      localIceQueueBytes: 0,
      localIceAcceptedCandidates: 0,
      localIceSending: false,
      localIceRetryTimer: null,
      localIceAbort: null,
      localIceRetired: false,
      remoteIceQueue: [],
      remoteIceQueueBytes: 0,
      remoteIceAcceptedCandidates: 0,
      remoteIceApplying: false,
      remoteIceReady: false,
      remoteIceRetired: false,
      localIcePhaseEmitted: false,
      remoteIcePhaseEmitted: false,
      peerDisconnected: false,
      iceDisconnected: false,
      startedAt: nowMs(),
      firstRelayAt: 0,
      established: false,
      closedEmitted: false,
      fallbackEligible,
    }
    this.activeAttempt = owner
    owner.outbound = new DataChannelSendQueue(dc, () => this.closeCurrentAttempt(owner))
    // A token is useful only for the signaling session owned by this attempt. Never expose a previous
    // connection's token while a fresh attempt is in flight.
    this.mintedToken = null
    this.mintedAuthorization = null

    dc.binaryType = 'arraybuffer'
    dc.onopen = () => {
      if (!this.isCurrentAttempt(owner)) return
      owner.established = true
      this.clearPreopenIceFailedGrace(owner)
      this.progress('bridge:data-channel-open')
      this.retireSignalingPolls(owner)
      // A standalone bridge's setup lifetime ends at DataChannel open. In production the controller owns the
      // shared scope and keeps it live through RemoteSession authentication.
      if (this.ownedConnectDeadline) this.finishConnectDeadline(false)
      // Signaling candidates are no longer needed once the authenticated DataChannel is open. Cancel a late POST
      // rather than allowing setup-only work to outlive the transport it helped establish.
      this.retireLocalIce(owner)
      this.retireRemoteIce(owner)
      // A state callback can run immediately before `open` while this attempt is still classified as setup. Read
      // the authoritative current states now so that a pre-open failure/disconnect cannot be lost forever.
      this.handlePeerState(owner)
      if (!this.isCurrentAttempt(owner)) return
      const openedAt = nowMs()
      const toConnectedMs = openedAt - owner.startedAt
      this.emitAttemptDiag(owner, {
        timing: { ...this.diag.timing, toConnectedMs },
      })
      // Opening the DataChannel is the product-critical event. Publish it before even invoking getStats; selected
      // pair diagnostics are a bounded, post-open observer and can never delay auth or terminal hydration.
      this.emitConnectionPhase('data_channel_open', owner)
      this.stateHandler('connected')
      queueMicrotask(() => {
        if (!this.isCurrentAttempt(owner)) return
        this.pollSelectedCandidate(owner, openedAt + WEBRTC_SELECTED_PAIR_POLL_DEADLINE_MS)
      })
    }
    dc.onclose = () => this.closeCurrentAttempt(owner)
    dc.onbufferedamountlow = () => {
      if (this.isCurrentAttempt(owner)) owner.outbound?.onBufferedAmountLow()
    }
    dc.onmessage = (e: MessageEvent) => {
      if (!this.isCurrentAttempt(owner)) return
      if (typeof e.data === 'string') {
        // Bound text before it reaches a parser or product callback. An over-budget authenticated peer is retired:
        // dropping one frame and keeping the owner alive would let it repeat the allocation/validation pressure.
        if (!controlJsonTextFitsByteLimit(e.data)) {
          this.closeCurrentAttempt(owner)
          return
        }
        this.textHandler(e.data)
      } else this.binaryHandler(new Uint8Array(e.data as ArrayBuffer))
    }

    peer.oniceconnectionstatechange = () => {
      if (!this.isCurrentAttempt(owner)) return
      const s = owner.pc.iceConnectionState
      this.progress(`bridge:ice:${s}`)
      this.emitAttemptDiag(owner, { ice: s })
      this.handlePeerState(owner)
      if (owner.established) {
        return
      }
      if (s === 'connected' || s === 'completed') this.clearPreopenIceFailedGrace(owner)
      else if (s === 'failed' && !this.attemptConnected(owner)) this.armPreopenIceFailedGrace(owner)
    }

    peer.onconnectionstatechange = () => {
      if (!this.isCurrentAttempt(owner)) return
      this.progress(`bridge:peer:${owner.pc.connectionState}`)
      this.handlePeerState(owner)
    }

    peer.onicecandidate = (e: RTCPeerConnectionIceEvent) => {
      if (!this.isCurrentAttempt(owner)) return
      if (e.candidate) {
        // candidate-timing: stamp the FIRST relay candidate (TURN allocation latency = reliability signal).
        if (owner.firstRelayAt === 0 && e.candidate.type === 'relay') {
          owner.firstRelayAt = nowMs()
          this.emitAttemptDiag(owner, {
            timing: { ...this.diag.timing, toFirstRelayMs: owner.firstRelayAt - owner.startedAt },
          })
        }
        let payload: string | undefined
        try {
          payload = JSON.stringify(e.candidate)
        } catch {
          this.failLocalIce(owner)
          return
        }
        if (!payload) {
          this.failLocalIce(owner)
          return
        }
        if (!owner.localIcePhaseEmitted) {
          owner.localIcePhaseEmitted = true
          this.emitConnectionPhase('first_local_ice', owner)
        }
        this.enqueueLocalIce(owner, payload)
      }
    }
    const offer = await owner.pc.createOffer()
    if (!this.isCurrentAttempt(owner)) return owner
    this.progress('bridge:offer-created')
    this.emitConnectionPhase('offer_created', owner)
    await owner.pc.setLocalDescription(offer)
    if (!this.isCurrentAttempt(owner)) return owner
    this.progress('bridge:local-description')
    this.emitConnectionPhase('local_description_set', owner)
    this.emitAttemptDiag(owner, { signaling: 'creating' })
    // PROOF OF POSSESSION: sign a challenge bound to THIS offer's DTLS fingerprint + our device id, and
    // embed it in the offer JSON. The desktop verifies it against our enrolled public key (from the token),
    // so a token alone — without our private key — can't produce a valid connecting offer. Binding to the
    // fingerprint stops replaying the proof onto a different DTLS session.
    let offerPayload: Record<string, unknown> = { ...(offer as unknown as Record<string, unknown>) }
    if (this.opts.signOffer && this.opts.browserDeviceId) {
      const fp = extractSha256Fingerprint((offer.sdp as string) ?? '')
      if (fp) {
        const challenge = `hydra-webrtc-offer-v1:${this.opts.browserDeviceId}:${fp}`
        try {
          const signal = this.connectDeadline?.signal
          const { pop, alg } = await waitForAttempt(this.opts.signOffer(challenge, signal), signal)
          if (!this.isCurrentAttempt(owner)) return owner
          this.progress('bridge:offer-proof')
          offerPayload = { ...offerPayload, hydra_offer_proof: { device_id: this.opts.browserDeviceId, alg, sig: pop } }
        } catch {
          if (!this.isCurrentAttempt(owner)) return owner
          // signing failed → proceed without the proof (dev/legacy); the agent fails closed once tokens
          // carry browser_pubkey, so a missing proof will simply be refused there.
        }
      }
    }
    // ACCESS PASSKEY (#11): embed the WebAuthn-passkey-signed browser certificate so the desktop can trust
    // this browser INDEPENDENTLY of the cloud. Null is allowed only when the account has no passkey. A thrown
    // error means a registered passkey could not authorize this browser, so stop before signaling.
    if (this.opts.browserCert) {
      // The preflight wrapper must be settled before invoking the interactive half. Production's callback consumes
      // the same raw descriptor promise, while this await guarantees no separate warm-up task can outlive the gate.
      await this.settleBrowserCertificatePreflight()
      if (!this.isCurrentAttempt(owner)) return owner
      const resolution = this.beginBrowserCertificateResolution()
      if (!resolution) return owner
      const resolved = await resolution
      if (!this.isCurrentAttempt(owner)) return owner
      if (resolved.ok) {
        this.emitConnectionPhase('passkey_certificate_resolved', owner)
        this.progress('bridge:browser-certificate')
        if (resolved.certificate) {
          offerPayload = { ...offerPayload, hydra_browser_cert: resolved.certificate }
        }
      } else {
        if (this.connectDeadline?.signal.aborted) return owner
        this.authorizationBlocked = true
        this.opts.onMode?.('failed')
        this.finishConnectDeadline(true)
        this.stateHandler('authorization_required')
        this.teardownAttempt(owner)
        return owner
      }
    }
    if (!this.isCurrentAttempt(owner)) return owner
    try {
      const signal = this.connectDeadline?.signal
      // Bound even an injected/legacy fetch that ignores AbortSignal, while retaining its eventual session id for
      // cleanup if the server committed just as cancellation won. The claimed flag prevents the late observer and
      // the normal continuation from cancelling the same signaling session twice.
      const createRequest = this.opts.signaling.createSession(
        this.opts.targetDeviceId,
        JSON.stringify(offerPayload),
        signal,
      )
      let cancellationClaimed = false
      void createRequest.then((lateSessionId) => {
        if ((signal?.aborted || !this.isCurrentAttempt(owner)) && !cancellationClaimed) {
          cancellationClaimed = true
          this.cancelSignalingSession(lateSessionId)
        }
      }, () => {})
      const sessionId = await waitForAttempt(createRequest, signal)
      if (!this.isCurrentAttempt(owner)) {
        if (!cancellationClaimed) {
          cancellationClaimed = true
          this.cancelSignalingSession(sessionId)
        }
        return owner
      }
      this.progress('bridge:signaling-session')
      owner.sessionId = sessionId
      this.emitConnectionPhase('signaling_created', owner)
      this.flushLocalIce(owner, sessionId)
    } catch (e) {
      if (!this.isCurrentAttempt(owner)) return owner
      if (isStableSetupRefusal(e)) {
        this.blockForSetupRefusal(owner, e.state)
        return owner
      }
      this.failAttempt(owner)
      return owner
    }
    // RELEASE-BLOCKER FIX: now that the signaling session EXISTS and has an id, mint the cloud token bound
    // to it. The agent fail-closed-requires token.signal_session_id == this session; every reconnect opens a
    // distinct session, so we mint here for EACH attempt and never reuse an earlier session's token. A mint
    // failure fails this attempt closed rather than presenting a stale/mismatched token.
    if (this.opts.mintToken) {
      const sessionId = owner.sessionId
      if (!sessionId) return owner
      let mintedToken: string | BoundAuthorization | null = null
      try {
        const signal = this.connectDeadline?.signal
        mintedToken = await waitForAttempt(this.opts.mintToken(sessionId, signal), signal)
      } catch (error) {
        if (isStableSetupRefusal(error)) {
          this.blockForSetupRefusal(owner, error.state)
          return owner
        }
        // handled as a failed mint below
      }
      // Do not let an in-flight mint repopulate authorization state after close() or attempt replacement.
      if (!this.isCurrentAttempt(owner, sessionId)) return owner
      this.mintedAuthorization = typeof mintedToken === 'string' ? null : mintedToken
      this.mintedToken = typeof mintedToken === 'string' ? mintedToken : mintedToken?.token ?? null
      if (!this.mintedToken) {
        this.failAttempt(owner)
        return owner
      }
      this.emitConnectionPhase('bound_authority_ready', owner)
      this.progress('bridge:bound-token')
    } else if (this.opts.requireSessionBoundToken) {
      // Kept as a local invariant even though connect() rejects this configuration before peer creation.
      this.failAttempt(owner)
      return owner
    }
    const sessionId = owner.sessionId
    if (!sessionId || !this.isCurrentAttempt(owner, sessionId)) return owner
    this.emitAttemptDiag(owner, { signaling: 'awaiting_answer' })
    this.activateSignalingPolls(owner)
    return owner
  }

  /** Compatibility for explicit/test ICE configurations only. Production gets TURN credentials before its first
   * peer and never enters this path. Keep ownership checks because async credential fetch can finish after the
   * direct peer opens or is retired. */
  private async onCompatibilityDirectTimeout(direct: AttemptOwner): Promise<void> {
    if (
      !this.isCurrentAttempt(direct) || !direct.fallbackEligible ||
      direct.kind !== 'all' || this.authorizationBlocked || this.setupRefusalBlocked || this.attemptConnected(direct)
    ) return
    let creds: RelayCredentials | null = null
    this.emitConnectionPhase('relay_fetch_start', direct)
    try {
      const signal = this.connectDeadline?.signal
      creds = this.opts.fetchRelayCreds
        ? await waitForAttempt(this.opts.fetchRelayCreds(signal), signal)
        : null
      this.progress('bridge:compatibility-relay-credentials')
    } catch (error) {
      if (isStableSetupRefusal(error)) {
        this.blockForSetupRefusal(direct, error.state)
        return
      }
      this.failAttempt(direct)
      return
    }
    if (!this.isCurrentAttempt(direct) || this.attemptConnected(direct)) return
    if (!creds || creds.urls.length === 0) {
      this.failAttempt(direct)
      return
    }
    this.emitConnectionPhase('relay_fetch_ready', direct)
    this.teardownAttempt(direct)
    try {
      this.pc = this.newPeer(iceServersFromRelay(creds), 'relay')
      this.progress('bridge:compatibility-relay-peer')
      const relay = await this.startAttempt('relay')
      if (!relay || !this.isCurrentAttempt(relay) || this.authorizationBlocked || this.setupRefusalBlocked) return
    } catch (error) {
      if (isStableSetupRefusal(error)) {
        this.blockForSetupRefusal(this.activeAttempt, error.state)
        return
      }
      this.failAttempt(this.activeAttempt)
    }
  }

  /** All answer/ICE/progress reads for one owner share this one abort scope. Opening the native channel or retiring
   * the owner aborts the in-flight fetch and clears every timer without aborting the controller's wider auth scope. */
  private activateSignalingPolls(owner: AttemptOwner): void {
    if (!this.isCurrentAttempt(owner) || owner.signalingRetired) return
    const attemptSignal = this.connectDeadline?.signal
    if (attemptSignal) {
      const onAbort = (): void => owner.signalingPollAbort.abort()
      owner.signalingAbortListener = onAbort
      attemptSignal.addEventListener('abort', onAbort, { once: true })
      if (attemptSignal.aborted) owner.signalingPollAbort.abort()
    }
    if (owner.signalingPollAbort.signal.aborted) return
    // Ports without combined progress retain the separate readers. A present implementation may switch this
    // owner to those readers only through the explicit unsupported-capability error, never an arbitrary failure.
    this.emitConnectionPhase('signaling_polling_started', owner)
    if (typeof this.opts.signaling.fetchProgress === 'function') this.pollProgress(owner, owner.sessionId!)
    else this.startLegacySignalPolls(owner, owner.sessionId!)
  }

  private retireSignalingPolls(owner: AttemptOwner): void {
    if (owner.signalingRetired) return
    owner.signalingRetired = true
    if (owner.progressPollTimer) clearTimeout(owner.progressPollTimer)
    if (owner.answerPollTimer) clearTimeout(owner.answerPollTimer)
    if (owner.icePollTimer) clearTimeout(owner.icePollTimer)
    owner.progressPollTimer = null
    owner.answerPollTimer = null
    owner.icePollTimer = null
    owner.signalingPollAbort.abort()
    const attemptSignal = this.connectDeadline?.signal
    if (attemptSignal && owner.signalingAbortListener) {
      attemptSignal.removeEventListener('abort', owner.signalingAbortListener)
    }
    owner.signalingAbortListener = null
  }

  private startLegacySignalPolls(owner: AttemptOwner, sessionId: string): void {
    if (!this.isCurrentAttempt(owner, sessionId) || owner.signalingRetired) return
    this.pollAnswer(owner, sessionId)
    this.pollIce(owner, sessionId)
  }

  private teardownAttempt(owner: AttemptOwner | null = this.activeAttempt): void {
    if (!owner || !this.ownsAttempt(owner)) return
    this.activeAttempt = null
    this.attemptEpoch++
    this.clearCompatibilityFallbackTimer()
    this.retireSignalingPolls(owner)
    if (owner.candidatePollTimer) clearTimeout(owner.candidatePollTimer)
    this.retireLocalIce(owner)
    this.retireRemoteIce(owner)
    this.clearPreopenIceFailedGrace(owner)
    this.clearDisconnectGrace(owner)
    owner.candidatePollTimer = null
    const sessionId = owner.sessionId
    owner.sessionId = null
    this.mintedToken = null
    this.mintedAuthorization = null
    try {
      // Teardown owns user-visible state. Suppress the native close callback before closing so a queued browser
      // event cannot publish a duplicate disconnect after the controller already received the terminal state.
      owner.dc.onopen = null
      owner.dc.onmessage = null
      owner.dc.onclose = null
      owner.dc.onbufferedamountlow = null
      owner.outbound?.close()
      owner.outbound = null
      owner.dc.close()
    } catch {
      // ignore
    }
    try {
      owner.pc.onicecandidate = null
      owner.pc.oniceconnectionstatechange = null
      owner.pc.onconnectionstatechange = null
      owner.pc.close()
    } catch {
      // ignore
    }
    if (this.pc === owner.pc) this.pc = null
    if (sessionId) this.cancelSignalingSession(sessionId)
  }

  private pollProgress(owner: AttemptOwner, sessionId: string): void {
    if (!this.isCurrentAttempt(owner, sessionId) || owner.signalingRetired) return
    const fetchProgress = this.opts.signaling.fetchProgress
    if (typeof fetchProgress !== 'function') {
      this.startLegacySignalPolls(owner, sessionId)
      return
    }
    const signal = owner.signalingPollAbort.signal
    void waitForAttempt(
      fetchProgress.call(this.opts.signaling, sessionId, owner.iceSince, owner.answerSeen, signal),
      signal,
    ).then(async (response: unknown) => {
      if (!this.isCurrentAttempt(owner, sessionId) || owner.signalingRetired) return
      const staged = this.stageSignalProgress(owner, response)
      if (!staged) {
        this.failRemoteIce(owner)
        return
      }

      // Verification and installation must succeed for this exact owner before any ICE from the same snapshot is
      // admitted. Candidate application remains gated by remoteIceReady, preserving answer-before-ICE ordering.
      if (staged.answer !== undefined) {
        try {
          const description = await verifyAndParseRemoteDescription(staged.answer, {
            deviceId: this.opts.targetDeviceId,
            publicKeyB64: this.opts.targetDevicePublicKeyB64 ?? null,
            signalSessionId: sessionId,
            allowUnverifiedDesktop: this.opts.allowUnverifiedDesktop ?? false,
          })
          if (!this.isCurrentAttempt(owner, sessionId) || owner.signalingRetired) return
          await owner.pc.setRemoteDescription(description)
          if (!this.isCurrentAttempt(owner, sessionId) || owner.signalingRetired) return
          owner.answerSeen = true
          owner.remoteIceReady = true
          this.emitConnectionPhase('remote_description_set', owner)
          this.progress('bridge:remote-description')
          this.emitAttemptDiag(owner, { signaling: 'answered' })
        } catch {
          if (!this.isCurrentAttempt(owner, sessionId) || owner.signalingRetired) return
          this.failAttempt(owner)
          return
        }
      }

      if (!this.admitRemoteIceBatch(owner, sessionId, staged.ice)) return
      if (staged.ice.candidates.length > 0) this.progress('bridge:first-remote-ice')
      this.scheduleProgress(owner, sessionId)
    }).catch((e: unknown) => {
      if (!this.isCurrentAttempt(owner, sessionId) || owner.signalingRetired) return
      if (e instanceof SignalProgressUnsupported) {
        if (owner.progressFallbackUsed) {
          this.failAttempt(owner)
          return
        }
        owner.progressFallbackUsed = true
        this.startLegacySignalPolls(owner, sessionId)
        return
      }
      this.onPollError(owner, sessionId, 'progress', e, () => this.scheduleProgress(owner, sessionId))
    })
  }

  private scheduleProgress(owner: AttemptOwner, sessionId: string): void {
    if (!this.isCurrentAttempt(owner, sessionId) || owner.signalingRetired) return
    if (owner.dc.readyState === 'open') return
    const timer = setTimeout(() => {
      if (owner.progressPollTimer === timer) owner.progressPollTimer = null
      this.pollProgress(owner, sessionId)
    }, this.backoff.fastMs)
    owner.progressPollTimer = timer
  }

  private pollAnswer(owner: AttemptOwner, sessionId: string): void {
    if (!this.isCurrentAttempt(owner, sessionId) || owner.signalingRetired) return
    const signal = owner.signalingPollAbort.signal
    void waitForAttempt(this.opts.signaling.fetchAnswer(sessionId, signal), signal).then(async (answer) => {
      if (!this.isCurrentAttempt(owner, sessionId) || owner.signalingRetired) return
      if (answer && !owner.pc.currentRemoteDescription) {
        try {
          const description = await verifyAndParseRemoteDescription(answer, {
            deviceId: this.opts.targetDeviceId,
            publicKeyB64: this.opts.targetDevicePublicKeyB64 ?? null,
            signalSessionId: sessionId,
            allowUnverifiedDesktop: this.opts.allowUnverifiedDesktop ?? false,
          })
          if (!this.isCurrentAttempt(owner, sessionId) || owner.signalingRetired) return
          await owner.pc.setRemoteDescription(description)
          if (!this.isCurrentAttempt(owner, sessionId) || owner.signalingRetired) return
          this.emitConnectionPhase('remote_description_set', owner)
          this.progress('bridge:remote-description')
          owner.answerSeen = true
          owner.remoteIceReady = true
          this.flushRemoteIce(owner, sessionId)
        } catch {
          if (!this.isCurrentAttempt(owner, sessionId) || owner.signalingRetired) return
          this.failAttempt(owner)
          return
        }
        this.emitAttemptDiag(owner, { signaling: 'answered' })
        return // answer set; ICE polling carries the rest
      }
      this.scheduleAnswer(owner, sessionId)
    }).catch((e) => this.onPollError(owner, sessionId, 'answer', e, () => this.scheduleAnswer(owner, sessionId)))
  }

  /** A poll failed. If the SESSION is dead (409/404), stop polling and go offline so the reconnect starts a FRESH
   * signaling session (otherwise we'd 409 forever). Once this exact owner already has an OPEN DataChannel,
   * signaling has finished its job: a late response from an in-flight answer/ICE request cannot invalidate the
   * authenticated DTLS transport. Any other (transient) error → keep polling via `retry`. */
  private onPollError(
    owner: AttemptOwner,
    sessionId: string,
    _operation: 'answer' | 'ice' | 'progress',
    e: unknown,
    retry: () => void,
  ): void {
    if (!this.isCurrentAttempt(owner, sessionId) || owner.signalingRetired) return
    if (e instanceof SignalSessionDead) {
      if (owner.established || owner.dc.readyState === 'open') {
        // Expected race when cleanup/cancellation overtakes an already-issued poll after the peer opened.
        this.emitAttemptDiag(owner, { signaling: 'answered' })
        return
      }
      this.emitAttemptDiag(owner, { signaling: 'dead' })
      this.failAttempt(owner)
      return
    }
    retry()
  }

  private scheduleAnswer(owner: AttemptOwner, sessionId: string): void {
    if (!this.isCurrentAttempt(owner, sessionId) || owner.signalingRetired) return
    const delay = owner.pc.currentRemoteDescription ? this.backoff.idleMs : this.backoff.fastMs
    const timer = setTimeout(() => {
      if (owner.answerPollTimer === timer) owner.answerPollTimer = null
      this.pollAnswer(owner, sessionId)
    }, delay)
    owner.answerPollTimer = timer
  }

  private pollIce(owner: AttemptOwner, sessionId: string): void {
    if (!this.isCurrentAttempt(owner, sessionId) || owner.signalingRetired) return
    const signal = owner.signalingPollAbort.signal
    void waitForAttempt(this.opts.signaling.fetchIce(sessionId, owner.iceSince, signal), signal).then((response: unknown) => {
      if (!this.isCurrentAttempt(owner, sessionId) || owner.signalingRetired) return
      if (owner.remoteIceRetired) return
      const batch = this.stageRemoteIceBatch(owner, response)
      if (!batch) {
        // This is a protocol-integrity failure, not a transient fetch failure. Do not retry from a cursor derived
        // from an untrusted response. Established peers remain live; pre-open owners restart with fresh signaling.
        this.failRemoteIce(owner)
        return
      }
      if (!this.admitRemoteIceBatch(owner, sessionId, batch)) return
      if (batch.candidates.length > 0) this.progress('bridge:first-remote-ice')
      this.scheduleIce(owner, sessionId)
    }).catch((e) => this.onPollError(owner, sessionId, 'ice', e, () => this.scheduleIce(owner, sessionId)))
  }

  private scheduleIce(owner: AttemptOwner, sessionId: string): void {
    if (!this.isCurrentAttempt(owner, sessionId) || owner.signalingRetired) return
    // Once the DataChannel is OPEN we have the candidates we need — stop polling (the cloud also refuses
    // ICE fetch on a no-longer-pending session with 409). Keeps the console + network quiet post-connect.
    if (owner.dc.readyState === 'open') return
    const timer = setTimeout(() => {
      if (owner.icePollTimer === timer) owner.icePollTimer = null
      this.pollIce(owner, sessionId)
    }, this.backoff.fastMs)
    owner.icePollTimer = timer
  }

  close(): void {
    if (this.closed) return
    this.closed = true
    this.abortBrowserCertificatePreflight()
    this.abortBrowserCertificateResolution()
    this.finishConnectDeadline(true)
    this.clearCompatibilityFallbackTimer()
    const owner = this.activeAttempt
    if (owner) this.teardownAttempt(owner)
    else {
      this.mintedToken = null
      this.mintedAuthorization = null
      this.attemptEpoch++
      const peer = this.pc
      this.pc = null
      if (peer) {
        try {
          peer.close()
        } catch {
          // ignore
        }
      }
    }
  }
}

function nowMs(): number {
  // This is also the scheduling/deadline clock exercised by existing fake-timer tests. Keep Date.now semantics;
  // the opt-in connection accumulator independently converts observations to monotonic relative durations.
  return Date.now()
}

/** Abort the await even when an injected/legacy callback ignores AbortSignal. Its eventual continuation is still
 * consumed here and every caller re-checks attempt ownership before mutating state. */
function waitForAttempt<T>(promise: Promise<T>, signal?: AbortSignal): Promise<T> {
  if (!signal) return promise
  if (signal.aborted) return Promise.reject(new DOMException('Connection attempt was cancelled.', 'AbortError'))
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => reject(new DOMException('Connection attempt was cancelled.', 'AbortError'))
    signal.addEventListener('abort', onAbort, { once: true })
    promise.then(
      (value) => {
        signal.removeEventListener('abort', onAbort)
        resolve(value)
      },
      (error) => {
        signal.removeEventListener('abort', onAbort)
        reject(error)
      },
    )
  })
}

function utf8ByteLength(value: string): number {
  return new TextEncoder().encode(value).byteLength
}
