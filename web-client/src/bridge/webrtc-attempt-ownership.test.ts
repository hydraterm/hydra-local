import { afterEach, describe, expect, it, vi } from 'vitest'
import { SignalProgressUnsupported, SignalSessionDead, type SignalingPort } from './signaling-contract'
import type { ConnectionAttemptPhase, ControlState, Diagnostics } from './remote-transport'
import {
  WEBRTC_DISCONNECTED_GRACE_MS,
  WEBRTC_LOCAL_ICE_MAX_CANDIDATES,
  WEBRTC_LOCAL_ICE_POST_TIMEOUT_MS,
  WEBRTC_LOCAL_ICE_RETRY_DELAYS_MS,
  WEBRTC_PREOPEN_ICE_FAILED_GRACE_MS,
  WEBRTC_REMOTE_ICE_MAX_CANDIDATE_BYTES,
  WEBRTC_REMOTE_ICE_MAX_CANDIDATES,
  WebrtcBridge,
} from './webrtc-bridge'
import { MAX_BROWSER_CONTROL_JSON_BYTES } from '../protocol/bounded-control-json'
import {
  WEBRTC_OUTBOUND_BUFFER_HIGH_BYTES,
  WEBRTC_OUTBOUND_QUEUE_MAX_BYTES,
} from './datachannel-send-queue'
import type { ConnectDeadlineScope } from './connect-deadline'

interface Deferred<T> {
  promise: Promise<T>
  resolve: (value: T) => void
  reject: (reason: unknown) => void
}

function deferred<T>(): Deferred<T> {
  let resolve: (value: T) => void = () => {}
  let reject: (reason: unknown) => void = () => {}
  const promise = new Promise<T>((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

const VALID_ANSWER = JSON.stringify({
  type: 'answer',
  sdp: [
    'v=0',
    'a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
    '',
  ].join('\r\n'),
})

const VALID_CANDIDATE = JSON.stringify({
  candidate: 'candidate:1 1 udp 1 192.0.2.1 5000 typ host',
  sdpMid: '0',
  sdpMLineIndex: 0,
})

function selectedStats(
  candidateType: 'host' | 'relay',
  protocol = 'udp',
  remoteCandidateType: 'host' | 'relay' = 'host',
  remoteProtocol = protocol,
): RTCStatsReport {
  const pairProtocol = protocol === 'tls' ? 'tcp' : protocol
  return new Map<string, any>([
    ['transport', { id: 'transport', type: 'transport', selectedCandidatePairId: 'pair' }],
    ['pair', {
      id: 'pair', type: 'candidate-pair', selected: true,
      localCandidateId: 'local', remoteCandidateId: 'remote',
    }],
    ['local', {
      id: 'local', type: 'local-candidate', candidateType, protocol: pairProtocol,
      ...(candidateType === 'relay' ? { relayProtocol: protocol } : {}),
    }],
    ['remote', {
      id: 'remote', type: 'remote-candidate', candidateType: remoteCandidateType, protocol: pairProtocol,
      ...(remoteCandidateType === 'relay' ? { relayProtocol: remoteProtocol } : {}),
    }],
  ]) as unknown as RTCStatsReport
}

class ControlledChannel {
  binaryType: BinaryType = 'arraybuffer'
  readyState: RTCDataChannelState = 'connecting'
  bufferedAmount = 0
  bufferedAmountLowThreshold = 0
  onopen: ((this: RTCDataChannel, ev: Event) => any) | null = null
  onclose: ((this: RTCDataChannel, ev: Event) => any) | null = null
  onmessage: ((this: RTCDataChannel, ev: MessageEvent) => any) | null = null
  onbufferedamountlow: ((this: RTCDataChannel, ev: Event) => any) | null = null
  closed = false
  sent: unknown[] = []

  send(value: unknown): void {
    this.sent.push(value)
    this.bufferedAmount += typeof value === 'string'
      ? new TextEncoder().encode(value).byteLength
      : value instanceof ArrayBuffer ? value.byteLength : 0
  }
  close(): void {
    this.closed = true
    this.readyState = 'closed'
    this.onclose?.call(this as unknown as RTCDataChannel, new Event('close'))
  }
  triggerOpen(): void {
    this.readyState = 'open'
    this.onopen?.call(this as unknown as RTCDataChannel, new Event('open'))
  }
  triggerBufferedAmountLow(amount = this.bufferedAmountLowThreshold): void {
    this.bufferedAmount = amount
    this.onbufferedamountlow?.call(this as unknown as RTCDataChannel, new Event('bufferedamountlow'))
  }
}

interface PeerGates {
  offer?: Deferred<RTCSessionDescriptionInit>
  remote?: Deferred<void>
  ice?: Deferred<void>
  stats?: Deferred<RTCStatsReport>
  statsValue?: RTCStatsReport
  offerError?: Error
  localDescriptionError?: Error
}

class ControlledPeer {
  readonly channel = new ControlledChannel()
  onicecandidate: ((this: RTCPeerConnection, ev: RTCPeerConnectionIceEvent) => any) | null = null
  oniceconnectionstatechange: ((this: RTCPeerConnection, ev: Event) => any) | null = null
  onconnectionstatechange: ((this: RTCPeerConnection, ev: Event) => any) | null = null
  iceConnectionState: RTCIceConnectionState = 'new'
  connectionState: RTCPeerConnectionState = 'new'
  currentRemoteDescription: RTCSessionDescription | null = null
  closed = false
  remoteCalls = 0
  iceCalls = 0
  addedIce: RTCIceCandidateInit[] = []
  statsCalls = 0

  constructor(readonly gates: PeerGates = {}) {}

  createDataChannel(): RTCDataChannel {
    return this.channel as unknown as RTCDataChannel
  }
  async createOffer(): Promise<RTCSessionDescriptionInit> {
    if (this.gates.offerError) throw this.gates.offerError
    if (this.gates.offer) return this.gates.offer.promise
    return { type: 'offer', sdp: 'v=0\r\n' }
  }
  async setLocalDescription(): Promise<void> {
    if (this.gates.localDescriptionError) throw this.gates.localDescriptionError
  }
  async setRemoteDescription(description: RTCSessionDescriptionInit): Promise<void> {
    this.remoteCalls++
    if (this.gates.remote) await this.gates.remote.promise
    this.currentRemoteDescription = description as RTCSessionDescription
  }
  async addIceCandidate(init?: RTCIceCandidateInit | null): Promise<void> {
    this.iceCalls++
    if (init) this.addedIce.push(init)
    if (this.gates.ice) await this.gates.ice.promise
  }
  async getStats(): Promise<RTCStatsReport> {
    this.statsCalls++
    if (this.gates.stats) return this.gates.stats.promise
    return this.gates.statsValue ?? selectedStats('relay')
  }
  close(): void {
    this.closed = true
    this.iceConnectionState = 'closed'
    this.connectionState = 'closed'
  }
}

async function flushUntil(predicate: () => boolean, label: string): Promise<void> {
  for (let i = 0; i < 80; i++) {
    if (predicate()) return
    await Promise.resolve()
  }
  throw new Error(`timed out waiting for ${label}`)
}

function directLivenessHarness(peer = new ControlledPeer({ statsValue: selectedStats('host') })) {
  const states: ControlState[] = []
  const cancelled: string[] = []
  const signaling = {
    createSession: async () => 'sig-direct',
    fetchAnswer: async () => new Promise<string | null>(() => {}),
    fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
    postIce: async () => {},
    cancel: async (sessionId: string) => { cancelled.push(sessionId) },
  } as unknown as SignalingPort
  const bridge = new WebrtcBridge({
    signaling,
    targetDeviceId: 'desktop',
    iceServers: [],
    peerFactory: () => peer as unknown as RTCPeerConnection,
  })
  bridge.onState((state) => states.push(state))
  return { bridge, peer, states, cancelled }
}

function localCandidateEvent(label: string): RTCPeerConnectionIceEvent {
  return {
    candidate: {
      type: 'host',
      toJSON: () => ({ candidate: `candidate:${label}` }),
    },
  } as unknown as RTCPeerConnectionIceEvent
}

function remoteCandidate(label: string, type: 'host' | 'relay' = 'host'): string {
  return JSON.stringify({
    candidate: `candidate:${label} 1 udp 1 192.0.2.1 5000 typ ${type}`,
    sdpMid: '0',
    sdpMLineIndex: 0,
  })
}

describe('WebrtcBridge attempt ownership', () => {
  afterEach(() => vi.useRealTimers())

  it('buffers early local ICE and flushes it in order after this attempt receives its session id', async () => {
    const created = deferred<string>()
    const peer = new ControlledPeer()
    const posts: { sessionId: string; candidate: string }[] = []
    const signaling = {
      createSession: () => created.promise,
      fetchAnswer: async () => new Promise<string | null>(() => {}),
      fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async (sessionId: string, candidate: string) => { posts.push({ sessionId, candidate }) },
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      iceServers: [],
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })

    const connecting = bridge.connect()
    await flushUntil(() => peer.onicecandidate !== null, 'local ICE handler')
    peer.onicecandidate?.call(peer as unknown as RTCPeerConnection, localCandidateEvent('first'))
    peer.onicecandidate?.call(peer as unknown as RTCPeerConnection, localCandidateEvent('second'))
    expect(posts).toEqual([])

    created.resolve('sig-early')
    await connecting
    await flushUntil(() => posts.length === 2, 'ordered early ICE flush')

    expect(posts.map((post) => post.sessionId)).toEqual(['sig-early', 'sig-early'])
    expect(posts.map((post) => JSON.parse(post.candidate).candidate)).toEqual([
      'candidate:first',
      'candidate:second',
    ])
    bridge.close()
  })

  it('drops a phase callback captured from a retired peer while the current peer records its own phase', async () => {
    vi.useFakeTimers()
    const peers: ControlledPeer[] = []
    let creates = 0
    const signaling = {
      createSession: async () => `sig-${++creates}`,
      fetchAnswer: async () => new Promise<string | null>(() => {}),
      fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const phases: ConnectionAttemptPhase[] = []
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      iceServers: [],
      directTimeoutMs: 10,
      fetchRelayCreds: async () => ({
        urls: ['turn:relay.example:3478'], username: 'u', credential: 'p', expiresAtMs: Date.now() + 60_000,
      }),
      peerFactory: () => {
        const peer = new ControlledPeer()
        peers.push(peer)
        return peer as unknown as RTCPeerConnection
      },
    })
    bridge.onConnectionPhase((phase) => phases.push(phase))

    await bridge.connect()
    const retiredIceCallback = peers[0]!.onicecandidate!
    await vi.advanceTimersByTimeAsync(10)
    await flushUntil(() => peers.length === 2 && peers[1]!.onicecandidate !== null, 'relay fallback owner')

    const before = phases.filter((phase) => phase === 'first_local_ice').length
    retiredIceCallback.call(peers[0] as unknown as RTCPeerConnection, localCandidateEvent('retired'))
    expect(phases.filter((phase) => phase === 'first_local_ice')).toHaveLength(before)

    peers[1]!.onicecandidate?.call(peers[1] as unknown as RTCPeerConnection, localCandidateEvent('current'))
    expect(phases.filter((phase) => phase === 'first_local_ice')).toHaveLength(before + 1)
    bridge.close()
  })

  it('retries transient local ICE failures in order before advancing the candidate queue', async () => {
    vi.useFakeTimers()
    const peer = new ControlledPeer()
    const calls: string[] = []
    let firstFailures = 0
    const signaling = {
      createSession: async () => 'sig-retry',
      fetchAnswer: async () => new Promise<string | null>(() => {}),
      fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async (_sessionId: string, candidate: string) => {
        const label = JSON.parse(candidate).candidate as string
        calls.push(label)
        if (label === 'candidate:first' && firstFailures++ < 2) throw new Error('transient')
      },
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      iceServers: [],
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })

    await bridge.connect()
    peer.onicecandidate?.call(peer as unknown as RTCPeerConnection, localCandidateEvent('first'))
    peer.onicecandidate?.call(peer as unknown as RTCPeerConnection, localCandidateEvent('second'))
    await flushUntil(() => calls.length === 1, 'first ICE post')
    await vi.advanceTimersByTimeAsync(WEBRTC_LOCAL_ICE_RETRY_DELAYS_MS[0])
    await flushUntil(() => calls.length === 2, 'first ICE retry')
    await vi.advanceTimersByTimeAsync(WEBRTC_LOCAL_ICE_RETRY_DELAYS_MS[1])
    await flushUntil(() => calls.length === 4, 'retry success and next ICE post')

    expect(calls).toEqual([
      'candidate:first',
      'candidate:first',
      'candidate:first',
      'candidate:second',
    ])
    expect(peer.closed).toBe(false)
    bridge.close()
  })

  it('buffers fetched remote ICE until its answer is installed, then applies it serially in FIFO order', async () => {
    const remoteGate = deferred<void>()
    const iceGate = deferred<void>()
    const peer = new ControlledPeer({ remote: remoteGate, ice: iceGate })
    const phases: ConnectionAttemptPhase[] = []
    let icePolls = 0
    const signaling = {
      createSession: async () => 'sig-remote-early',
      fetchAnswer: async () => VALID_ANSWER,
      fetchIce: async () => ++icePolls === 1
        ? {
            candidates: [
              { candidate: remoteCandidate('first'), seq: 1 },
              { candidate: remoteCandidate('second'), seq: 2 },
            ],
            nextSince: 2,
          }
        : new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      allowUnverifiedDesktop: true,
      iceServers: [],
      backoff: { fastMs: 100_000, idleMs: 100_000, staleTimeoutMs: 1_000_000 },
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })
    bridge.onConnectionPhase((phase) => phases.push(phase))

    await bridge.connect()
    await flushUntil(() => peer.remoteCalls === 1 && icePolls === 1, 'concurrent answer and ICE fetch')
    expect(peer.iceCalls).toBe(0)
    // The legacy readers are independent: a validated ICE batch may be admitted while setRemoteDescription is
    // still pending. The metrics contract therefore records each first hit independently, not by enum ordinal.
    expect(phases).toContain('first_remote_ice')
    expect(phases).not.toContain('remote_description_set')

    remoteGate.resolve(undefined)
    await flushUntil(() => peer.iceCalls === 1, 'first remote ICE application')
    expect(phases).toContain('remote_description_set')
    expect(peer.addedIce.map((candidate) => candidate.candidate)).toEqual([
      'candidate:first 1 udp 1 192.0.2.1 5000 typ host',
    ])
    await Promise.resolve()
    expect(peer.iceCalls).toBe(1)

    iceGate.resolve(undefined)
    await flushUntil(() => peer.iceCalls === 2, 'second remote ICE application')
    expect(peer.addedIce.map((candidate) => candidate.candidate)).toEqual([
      'candidate:first 1 udp 1 192.0.2.1 5000 typ host',
      'candidate:second 1 udp 1 192.0.2.1 5000 typ host',
    ])
    bridge.close()
  })

  it.each([
    ['null response', null],
    ['array response', []],
    ['missing fields', {}],
    ['non-array candidates', { candidates: {}, nextSince: 0 }],
  ])('fails a pre-open attempt on malformed remote ICE outer shape: %s', async (_label, response) => {
    const peer = new ControlledPeer()
    const states: ControlState[] = []
    const fetchSince: number[] = []
    const signaling = {
      createSession: async () => 'sig-malformed-outer',
      fetchAnswer: async () => VALID_ANSWER,
      fetchIce: async (_sessionId: string, since: number) => {
        fetchSince.push(since)
        return response as never
      },
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      allowUnverifiedDesktop: true,
      iceServers: [],
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    await flushUntil(() => states.includes('offline'), 'malformed outer response failure')

    expect(fetchSince).toEqual([0])
    expect(peer.iceCalls).toBe(0)
    expect(peer.closed).toBe(true)
  })

  it.each([
    ['null entry', null],
    ['array entry', []],
    ['non-string candidate', { candidate: 7, seq: 2 }],
    ['missing sequence', { candidate: remoteCandidate('missing-seq') }],
  ])('stages the whole remote ICE batch before admitting a valid prefix: %s', async (_label, malformedEntry) => {
    const peer = new ControlledPeer()
    const states: ControlState[] = []
    const signaling = {
      createSession: async () => 'sig-malformed-entry',
      fetchAnswer: async () => VALID_ANSWER,
      fetchIce: async () => ({
        candidates: [
          { candidate: remoteCandidate('valid-prefix'), seq: 1 },
          malformedEntry,
        ],
        nextSince: 2,
      }),
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      allowUnverifiedDesktop: true,
      iceServers: [],
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    await flushUntil(() => states.includes('offline'), 'malformed entry failure')

    expect(peer.iceCalls).toBe(0)
    expect(peer.addedIce).toEqual([])
    expect(peer.closed).toBe(true)
  })

  it.each([
    ['duplicate', [1, 1]],
    ['reordered', [2, 1]],
    ['unsafe', [1, Number.MAX_SAFE_INTEGER + 1]],
    ['beyond the cloud session quota', [1, 129]],
  ])('rejects %s remote ICE sequences without applying their valid prefix', async (_label, sequences) => {
    const peer = new ControlledPeer()
    const states: ControlState[] = []
    const signaling = {
      createSession: async () => 'sig-bad-sequence',
      fetchAnswer: async () => VALID_ANSWER,
      fetchIce: async () => ({
        candidates: sequences.map((seq, index) => ({ candidate: remoteCandidate(String(index)), seq })),
        nextSince: 2,
      }),
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      allowUnverifiedDesktop: true,
      iceServers: [],
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    await flushUntil(() => states.includes('offline'), 'invalid sequence failure')

    expect(peer.iceCalls).toBe(0)
    expect(peer.closed).toBe(true)
  })

  it.each([
    ['negative', { candidates: [], nextSince: -1 }],
    ['unsafe', { candidates: [], nextSince: Number.MAX_SAFE_INTEGER + 1 }],
    ['beyond the cloud session quota', { candidates: [], nextSince: 129 }],
    ['behind the last sequence', {
      candidates: [{ candidate: remoteCandidate('cursor-behind'), seq: 2 }],
      nextSince: 1,
    }],
  ])('rejects a %s remote ICE cursor', async (_label, response) => {
    const peer = new ControlledPeer()
    const states: ControlState[] = []
    const signaling = {
      createSession: async () => 'sig-bad-cursor',
      fetchAnswer: async () => VALID_ANSWER,
      fetchIce: async () => response,
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      allowUnverifiedDesktop: true,
      iceServers: [],
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    await flushUntil(() => states.includes('offline'), 'invalid cursor failure')

    expect(peer.iceCalls).toBe(0)
    expect(peer.closed).toBe(true)
  })

  it('rejects a regressive cursor relative to the last committed empty-batch advance', async () => {
    vi.useFakeTimers()
    const peer = new ControlledPeer()
    const states: ControlState[] = []
    const fetchSince: number[] = []
    const signaling = {
      createSession: async () => 'sig-regressive-cursor',
      fetchAnswer: async () => VALID_ANSWER,
      fetchIce: async (_sessionId: string, since: number) => {
        fetchSince.push(since)
        return fetchSince.length === 1
          ? { candidates: [], nextSince: 5 }
          : { candidates: [], nextSince: 4 }
      },
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      allowUnverifiedDesktop: true,
      iceServers: [],
      backoff: { fastMs: 10, idleMs: 100_000, staleTimeoutMs: 1_000_000 },
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    await flushUntil(() => fetchSince.length === 1, 'initial cursor advance')
    await vi.advanceTimersByTimeAsync(10)
    await flushUntil(() => states.includes('offline'), 'regressive cursor failure')

    expect(fetchSince).toEqual([0, 5])
    expect(peer.iceCalls).toBe(0)
    expect(peer.closed).toBe(true)
  })

  it('accepts candidate sequence gaps and an empty batch that advances the cursor', async () => {
    vi.useFakeTimers()
    const peer = new ControlledPeer()
    const fetchSince: number[] = []
    const signaling = {
      createSession: async () => 'sig-valid-gaps',
      fetchAnswer: async () => VALID_ANSWER,
      fetchIce: async (_sessionId: string, since: number) => {
        fetchSince.push(since)
        if (fetchSince.length === 1) {
          return {
            candidates: [
              { candidate: remoteCandidate('gap-two'), seq: 2 },
              { candidate: remoteCandidate('gap-four'), seq: 4 },
            ],
            nextSince: 5,
          }
        }
        if (fetchSince.length === 2) return { candidates: [], nextSince: 9 }
        return new Promise<{ candidates: []; nextSince: number }>(() => {})
      },
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      allowUnverifiedDesktop: true,
      iceServers: [],
      backoff: { fastMs: 10, idleMs: 100_000, staleTimeoutMs: 1_000_000 },
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })

    await bridge.connect()
    await flushUntil(() => peer.iceCalls === 2, 'gapped candidates')
    expect(peer.addedIce.map((candidate) => candidate.candidate)).toEqual([
      'candidate:gap-two 1 udp 1 192.0.2.1 5000 typ host',
      'candidate:gap-four 1 udp 1 192.0.2.1 5000 typ host',
    ])

    await vi.advanceTimersByTimeAsync(10)
    await flushUntil(() => fetchSince.length === 2, 'empty cursor advance')
    await vi.advanceTimersByTimeAsync(10)
    await flushUntil(() => fetchSince.length === 3, 'poll after empty cursor advance')
    expect(fetchSince).toEqual([0, 5, 9])
    bridge.close()
  })

  it('retires a malformed late ICE response without closing an established owner', async () => {
    const response = deferred<never>()
    const peer = new ControlledPeer({ statsValue: selectedStats('host') })
    const states: ControlState[] = []
    const signaling = {
      createSession: async () => 'sig-malformed-after-open',
      fetchAnswer: async () => VALID_ANSWER,
      fetchIce: () => response.promise,
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      allowUnverifiedDesktop: true,
      iceServers: [],
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    peer.channel.triggerOpen()
    response.resolve(null as never)
    await Promise.resolve()
    await Promise.resolve()

    expect(states.at(-1)).toBe('connected')
    expect(states).not.toContain('offline')
    expect(peer.closed).toBe(false)
    expect(bridge.sendText('{}')).toBe(true)
    bridge.close()
  })

  it('retires queued remote ICE when a replacement attempt takes ownership', async () => {
    vi.useFakeTimers()
    const oldRemoteGate = deferred<void>()
    const peers: ControlledPeer[] = []
    let creates = 0
    let oldIceFetched = false
    const signaling = {
      createSession: async () => `sig-${++creates}`,
      fetchAnswer: async (sessionId: string) => sessionId === 'sig-1'
        ? VALID_ANSWER
        : new Promise<string | null>(() => {}),
      fetchIce: async (sessionId: string) => {
        if (sessionId === 'sig-1') {
          oldIceFetched = true
          return { candidates: [{ candidate: remoteCandidate('retired'), seq: 1 }], nextSince: 1 }
        }
        return new Promise<{ candidates: []; nextSince: number }>(() => {})
      },
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      allowUnverifiedDesktop: true,
      iceServers: [],
      directTimeoutMs: 10,
      backoff: { fastMs: 100_000, idleMs: 100_000, staleTimeoutMs: 1_000_000 },
      fetchRelayCreds: async () => ({
        urls: ['turn:relay.example:3478'], username: 'u', credential: 'p', expiresAtMs: Date.now() + 60_000,
      }),
      peerFactory: () => {
        const peer = peers.length === 0
          ? new ControlledPeer({ remote: oldRemoteGate })
          : new ControlledPeer()
        peers.push(peer)
        return peer as unknown as RTCPeerConnection
      },
    })

    await bridge.connect()
    await flushUntil(() => peers[0]!.remoteCalls === 1 && oldIceFetched, 'queued direct candidate')
    expect(peers[0]!.iceCalls).toBe(0)
    await vi.advanceTimersByTimeAsync(10)
    await flushUntil(() => peers.length === 2, 'replacement relay owner')

    oldRemoteGate.resolve(undefined)
    await Promise.resolve()
    await Promise.resolve()
    expect(peers[0]!.iceCalls).toBe(0)
    expect(peers[0]!.closed).toBe(true)
    expect(peers[1]!.closed).toBe(false)
    bridge.close()
  })

  it('fails a pre-open attempt when remote ICE exceeds its reserved candidate quota', async () => {
    const remoteGate = deferred<void>()
    const peer = new ControlledPeer({ remote: remoteGate })
    const states: ControlState[] = []
    const cancelled: string[] = []
    const signaling = {
      createSession: async () => 'sig-remote-overflow',
      fetchAnswer: async () => VALID_ANSWER,
      fetchIce: async () => ({
        candidates: Array.from({ length: WEBRTC_REMOTE_ICE_MAX_CANDIDATES + 1 }, (_, index) => ({
          candidate: remoteCandidate(String(index)),
          seq: index + 1,
        })),
        nextSince: WEBRTC_REMOTE_ICE_MAX_CANDIDATES + 1,
      }),
      postIce: async () => {},
      cancel: async (sessionId: string) => { cancelled.push(sessionId) },
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      allowUnverifiedDesktop: true,
      iceServers: [],
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    await flushUntil(() => states.includes('offline'), 'remote ICE quota failure')

    expect(peer.iceCalls).toBe(0)
    expect(peer.closed).toBe(true)
    expect(cancelled).toEqual(['sig-remote-overflow'])
  })

  it('fails a pre-open attempt when one remote ICE blob exceeds the cloud-compatible byte bound', async () => {
    const peer = new ControlledPeer()
    const states: ControlState[] = []
    const oversized = JSON.stringify({ candidate: 'x'.repeat(WEBRTC_REMOTE_ICE_MAX_CANDIDATE_BYTES) })
    const signaling = {
      createSession: async () => 'sig-remote-bytes',
      fetchAnswer: async () => VALID_ANSWER,
      fetchIce: async () => ({ candidates: [{ candidate: oversized, seq: 1 }], nextSince: 1 }),
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      allowUnverifiedDesktop: true,
      iceServers: [],
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    await flushUntil(() => states.includes('offline'), 'remote ICE byte-bound failure')

    expect(peer.iceCalls).toBe(0)
    expect(peer.closed).toBe(true)
  })

  it('fails a pre-open attempt when the browser rejects an admitted remote ICE candidate', async () => {
    const iceGate = deferred<void>()
    const peer = new ControlledPeer({ ice: iceGate })
    const states: ControlState[] = []
    let iceFetched = false
    const signaling = {
      createSession: async () => 'sig-remote-rejected',
      fetchAnswer: async () => VALID_ANSWER,
      fetchIce: async () => {
        if (iceFetched) return new Promise<{ candidates: []; nextSince: number }>(() => {})
        iceFetched = true
        return { candidates: [{ candidate: remoteCandidate('rejected'), seq: 1 }], nextSince: 1 }
      },
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      allowUnverifiedDesktop: true,
      iceServers: [],
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    await flushUntil(() => peer.iceCalls === 1, 'pre-open remote ICE application')
    iceGate.reject(new Error('browser rejected candidate'))
    await flushUntil(() => states.includes('offline'), 'pre-open remote ICE rejection')

    expect(peer.closed).toBe(true)
    expect(peer.channel.closed).toBe(true)
  })

  it('does not let a queued remote ICE rejection close an established DataChannel', async () => {
    const iceGate = deferred<void>()
    const peer = new ControlledPeer({ ice: iceGate, statsValue: selectedStats('host') })
    const states: ControlState[] = []
    let iceFetched = false
    const signaling = {
      createSession: async () => 'sig-open-race',
      fetchAnswer: async () => VALID_ANSWER,
      fetchIce: async () => {
        if (iceFetched) return new Promise<{ candidates: []; nextSince: number }>(() => {})
        iceFetched = true
        return { candidates: [{ candidate: remoteCandidate('pending-open'), seq: 1 }], nextSince: 1 }
      },
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      allowUnverifiedDesktop: true,
      iceServers: [],
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    await flushUntil(() => peer.iceCalls === 1, 'pending remote ICE application')
    peer.channel.triggerOpen()
    iceGate.reject(new Error('late browser ICE rejection'))
    await Promise.resolve()
    await Promise.resolve()

    expect(states.at(-1)).toBe('connected')
    expect(states).not.toContain('offline')
    expect(peer.closed).toBe(false)
    expect(peer.channel.closed).toBe(false)
    expect(bridge.sendText('{}')).toBe(true)
    bridge.close()
  })

  it('turns a hung local ICE POST into a bounded owner-scoped retry', async () => {
    vi.useFakeTimers()
    const peer = new ControlledPeer()
    const signals: AbortSignal[] = []
    let calls = 0
    const signaling = {
      createSession: async () => 'sig-timeout',
      fetchAnswer: async () => new Promise<string | null>(() => {}),
      fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async (_sessionId: string, _candidate: string, signal?: AbortSignal) => {
        calls++
        if (signal) signals.push(signal)
        await new Promise<void>((_resolve, reject) => {
          signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true })
        })
      },
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      iceServers: [],
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })

    await bridge.connect()
    peer.onicecandidate?.call(peer as unknown as RTCPeerConnection, localCandidateEvent('hung'))
    await flushUntil(() => calls === 1, 'hung local ICE post')
    await vi.advanceTimersByTimeAsync(WEBRTC_LOCAL_ICE_POST_TIMEOUT_MS)
    await flushUntil(() => signals[0]?.aborted === true, 'local ICE post abort')
    await vi.advanceTimersByTimeAsync(WEBRTC_LOCAL_ICE_RETRY_DELAYS_MS[0])
    await flushUntil(() => calls === 2, 'local ICE timeout retry')

    expect(signals).toHaveLength(2)
    expect(signals[0]!.aborted).toBe(true)
    expect(peer.closed).toBe(false)
    bridge.close()
  })

  it('aborts an in-flight local ICE post and leaves no retry after attempt retirement', async () => {
    vi.useFakeTimers()
    const peer = new ControlledPeer()
    const signals: AbortSignal[] = []
    let calls = 0
    const signaling = {
      createSession: async () => 'sig-retired',
      fetchAnswer: async () => new Promise<string | null>(() => {}),
      fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async (_sessionId: string, _candidate: string, signal?: AbortSignal) => {
        calls++
        if (signal) signals.push(signal)
        await new Promise<void>((_resolve, reject) => {
          signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true })
        })
      },
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      iceServers: [],
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })

    await bridge.connect()
    peer.onicecandidate?.call(peer as unknown as RTCPeerConnection, localCandidateEvent('pending'))
    await flushUntil(() => calls === 1, 'in-flight local ICE post')
    bridge.close()
    await Promise.resolve()
    await vi.advanceTimersByTimeAsync(
      WEBRTC_LOCAL_ICE_POST_TIMEOUT_MS
      + WEBRTC_LOCAL_ICE_RETRY_DELAYS_MS.reduce((sum, delay) => sum + delay, 0),
    )

    expect(signals).toHaveLength(1)
    expect(signals[0]!.aborted).toBe(true)
    expect(calls).toBe(1)
  })

  it('retires pending local ICE when the DataChannel opens without harming the live channel', async () => {
    vi.useFakeTimers()
    const peer = new ControlledPeer()
    const signals: AbortSignal[] = []
    let calls = 0
    const signaling = {
      createSession: async () => 'sig-open',
      fetchAnswer: async () => new Promise<string | null>(() => {}),
      fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async (_sessionId: string, _candidate: string, signal?: AbortSignal) => {
        calls++
        if (signal) signals.push(signal)
        await new Promise<void>((_resolve, reject) => {
          signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')), { once: true })
        })
      },
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      iceServers: [],
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })

    await bridge.connect()
    peer.onicecandidate?.call(peer as unknown as RTCPeerConnection, localCandidateEvent('pending-open'))
    await flushUntil(() => calls === 1, 'pending ICE before DataChannel open')
    peer.channel.triggerOpen()
    await Promise.resolve()

    expect(signals[0]!.aborted).toBe(true)
    expect(bridge.sendText('still-live')).toBe(true)
    expect(peer.channel.sent).toEqual(['still-live'])
    await vi.advanceTimersByTimeAsync(
      WEBRTC_LOCAL_ICE_POST_TIMEOUT_MS
      + WEBRTC_LOCAL_ICE_RETRY_DELAYS_MS.reduce((sum, delay) => sum + delay, 0),
    )
    expect(calls).toBe(1)
    expect(peer.closed).toBe(false)
    bridge.close()
  })

  it('drains bridge sends only from the current owner low-water callback', async () => {
    const { bridge, peer } = directLivenessHarness()
    await bridge.connect()
    peer.channel.triggerOpen()
    peer.channel.bufferedAmount = WEBRTC_OUTBOUND_BUFFER_HIGH_BYTES

    expect(bridge.sendText('queued-control')).toBe(true)
    expect(bridge.sendBinary(new Uint8Array([1, 2, 3]))).toBe(true)
    expect(peer.channel.sent).toEqual([])

    const retiredLow = peer.channel.onbufferedamountlow!
    peer.channel.triggerBufferedAmountLow()
    expect(peer.channel.sent).toEqual(['queued-control', new Uint8Array([1, 2, 3]).buffer])

    bridge.close()
    retiredLow.call(peer.channel as unknown as RTCDataChannel, new Event('bufferedamountlow'))
    expect(peer.channel.sent).toHaveLength(2)
  })

  it('routes an atomically admitted bulk paste behind newly arrived foreground at a native low-water wake', async () => {
    const { bridge, peer } = directLivenessHarness()
    await bridge.connect()
    peer.channel.triggerOpen()
    peer.channel.bufferedAmount = WEBRTC_OUTBOUND_BUFFER_HIGH_BYTES

    expect(bridge.sendBulkBinaryBatch([
      new Uint8Array([1]),
      new Uint8Array([2]),
    ])).toBe(true)
    expect(bridge.sendText('foreground-control')).toBe(true)
    expect(peer.channel.sent).toEqual([])

    peer.channel.triggerBufferedAmountLow()
    expect(peer.channel.sent).toEqual([
      'foreground-control',
      new Uint8Array([1]).buffer,
    ])
    bridge.close() // invalidates the scheduled second bulk quantum
  })

  it('retires an established owner on bounded outbound overflow', async () => {
    const { bridge, peer, states } = directLivenessHarness()
    await bridge.connect()
    peer.channel.triggerOpen()
    peer.channel.bufferedAmount = WEBRTC_OUTBOUND_BUFFER_HIGH_BYTES

    expect(bridge.sendText('x'.repeat(WEBRTC_OUTBOUND_QUEUE_MAX_BYTES + 1))).toBe(false)
    expect(states.filter((state) => state === 'closed')).toHaveLength(1)
    expect(peer.closed).toBe(true)
    expect(peer.channel.closed).toBe(true)
    expect(bridge.sendText('late')).toBe(false)
    // RemoteSession observes the false admission and invokes fail() too; reentrancy must not duplicate state.
    bridge.fail()
    expect(states.filter((state) => state === 'closed')).toHaveLength(1)
  })

  it('admits the exact inbound JSON byte ceiling and retires one byte over before the product callback', async () => {
    const { bridge, peer, states } = directLivenessHarness()
    const delivered: number[] = []
    bridge.onText((text) => delivered.push(text.length))
    await bridge.connect()
    peer.channel.triggerOpen()

    const prefix = '{"type":"unknown","padding":"'
    const suffix = '"}'
    const exact = `${prefix}${'x'.repeat(MAX_BROWSER_CONTROL_JSON_BYTES - prefix.length - suffix.length)}${suffix}`
    const queuedMessage = peer.channel.onmessage!
    queuedMessage.call(
      peer.channel as unknown as RTCDataChannel,
      new MessageEvent('message', { data: exact }),
    )
    expect(delivered).toEqual([MAX_BROWSER_CONTROL_JSON_BYTES])
    expect(peer.closed).toBe(false)

    queuedMessage.call(
      peer.channel as unknown as RTCDataChannel,
      new MessageEvent('message', { data: `${exact} ` }),
    )
    expect(delivered).toEqual([MAX_BROWSER_CONTROL_JSON_BYTES])
    expect(states.filter((state) => state === 'closed')).toHaveLength(1)
    expect(peer.closed).toBe(true)
    expect(peer.channel.closed).toBe(true)

    // A browser callback queued before teardown is now a retired-owner callback. Repeated excess cannot publish
    // another close or reach the product handler.
    queuedMessage.call(
      peer.channel as unknown as RTCDataChannel,
      new MessageEvent('message', { data: `${exact} ` }),
    )
    expect(delivered).toEqual([MAX_BROWSER_CONTROL_JSON_BYTES])
    expect(states.filter((state) => state === 'closed')).toHaveLength(1)
  })

  it('fails a pre-open attempt instead of silently dropping an overflowing local ICE backlog', async () => {
    const created = deferred<string>()
    const peer = new ControlledPeer()
    const states: ControlState[] = []
    const cancelled: string[] = []
    let createStarted = false
    const signaling = {
      createSession: () => {
        createStarted = true
        return created.promise
      },
      fetchAnswer: async () => new Promise<string | null>(() => {}),
      fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async () => {},
      cancel: async (sessionId: string) => { cancelled.push(sessionId) },
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      iceServers: [],
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })
    bridge.onState((state) => states.push(state))

    const connecting = bridge.connect()
    await flushUntil(() => createStarted, 'pending signaling session creation')
    for (let i = 0; i <= WEBRTC_LOCAL_ICE_MAX_CANDIDATES; i++) {
      peer.onicecandidate?.call(peer as unknown as RTCPeerConnection, localCandidateEvent(String(i)))
    }
    expect(states.at(-1)).toBe('offline')
    expect(peer.closed).toBe(true)

    created.resolve('sig-after-overflow')
    await connecting
    await flushUntil(() => cancelled.length === 1, 'late signaling session cancellation')
    expect(cancelled).toEqual(['sig-after-overflow'])
  })

  it('reserves the desktop half of the cloud ICE quota even when browser posts drain immediately', async () => {
    const peer = new ControlledPeer()
    const states: ControlState[] = []
    let posts = 0
    const signaling = {
      createSession: async () => 'sig-total-cap',
      fetchAnswer: async () => new Promise<string | null>(() => {}),
      fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async () => { posts++ },
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      iceServers: [],
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    for (let i = 0; i < WEBRTC_LOCAL_ICE_MAX_CANDIDATES; i++) {
      peer.onicecandidate?.call(peer as unknown as RTCPeerConnection, localCandidateEvent(String(i)))
      await flushUntil(() => posts === i + 1, `ICE post ${i + 1}`)
    }
    expect(peer.closed).toBe(false)

    peer.onicecandidate?.call(peer as unknown as RTCPeerConnection, localCandidateEvent('over-total-cap'))
    expect(states.at(-1)).toBe('offline')
    expect(peer.closed).toBe(true)
    expect(posts).toBe(WEBRTC_LOCAL_ICE_MAX_CANDIDATES)
  })

  it('creates exactly one forced-relay peer (no unused constructor peer)', async () => {
    const peers: ControlledPeer[] = []
    const signaling = {
      createSession: async () => 'sig-relay',
      fetchAnswer: async () => new Promise<string | null>(() => {}),
      fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      forceRelay: true,
      fetchRelayCreds: async () => ({
        urls: ['turn:relay.example:3478'], username: 'u', credential: 'p', expiresAtMs: Date.now() + 60_000,
      }),
      peerFactory: () => {
        const peer = new ControlledPeer()
        peers.push(peer)
        return peer as unknown as RTCPeerConnection
      },
    })

    await bridge.connect()
    expect(peers).toHaveLength(1)
    expect(peers[0]!.closed).toBe(false)
    bridge.close()
    expect(peers[0]!.closed).toBe(true)
  })

  it('retires every direct continuation before relay and cancels the old signaling session once', async () => {
    vi.useFakeTimers()
    const remoteGate = deferred<void>()
    const iceGate = deferred<void>()
    const statsGate = deferred<RTCStatsReport>()
    const relayMint = deferred<string | null>()
    const peers: ControlledPeer[] = []
    const cancelled: string[] = []
    const postedIce: string[] = []
    let creates = 0
    let answerCalls = 0
    let iceCalls = 0
    const signaling = {
      createSession: async () => `sig-${++creates}`,
      fetchAnswer: async (sessionId: string) => {
        answerCalls++
        return sessionId === 'sig-1' ? VALID_ANSWER : new Promise<string | null>(() => {})
      },
      fetchIce: async (sessionId: string) => {
        iceCalls++
        return sessionId === 'sig-1'
          ? { candidates: [{ candidate: VALID_CANDIDATE, seq: 1 }], nextSince: 1 }
          : new Promise<{ candidates: []; nextSince: number }>(() => {})
      },
      postIce: async (sessionId: string) => { postedIce.push(sessionId) },
      cancel: async (sessionId: string) => {
        cancelled.push(sessionId)
        throw new Error('cleanup failure must not block fallback')
      },
    } as unknown as SignalingPort
    const states: ControlState[] = []
    const modes: string[] = []
    const diagnostics: Diagnostics[] = []
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      allowUnverifiedDesktop: true,
      iceServers: [], // keep relay credentials exclusively for the timeout path
      directTimeoutMs: 10,
      backoff: { fastMs: 100_000, idleMs: 100_000, staleTimeoutMs: 1_000_000 },
      fetchRelayCreds: async () => ({
        urls: ['turn:relay.example:3478'], username: 'u', credential: 'p', expiresAtMs: Date.now() + 60_000,
      }),
      mintToken: async (sessionId) => sessionId === 'sig-1' ? 'token-direct' : relayMint.promise,
      peerFactory: () => {
        const peer = peers.length === 0
          ? new ControlledPeer({ remote: remoteGate, ice: iceGate, stats: statsGate })
          : new ControlledPeer({ statsValue: selectedStats('relay', 'tls') })
        peers.push(peer)
        return peer as unknown as RTCPeerConnection
      },
      onMode: (mode) => modes.push(mode),
    })
    bridge.onState((state) => states.push(state))
    bridge.onDiagnostics((diag) => diagnostics.push(diag))

    await bridge.connect()
    await flushUntil(() => peers[0]!.remoteCalls === 1 && iceCalls === 1, 'direct answer and ICE fetch')
    expect(peers[0]!.iceCalls).toBe(0)
    expect(bridge.currentToken()).toBe('token-direct')

    // Queue/capture callbacks exactly as the browser can do before close() detaches the JS properties.
    const staleIceState = peers[0]!.oniceconnectionstatechange!
    const staleIceCandidate = peers[0]!.onicecandidate!
    const staleMessage = peers[0]!.channel.onmessage!
    const staleClose = peers[0]!.channel.onclose!
    peers[0]!.channel.triggerOpen() // starts an asynchronous selected-candidate getStats continuation
    await flushUntil(() => peers[0]!.statsCalls === 1, 'direct selected-candidate stats')
    // Model a connection that dropped again before the fallback deadline while getStats was still queued.
    peers[0]!.channel.readyState = 'connecting'

    await vi.advanceTimersByTimeAsync(10)
    await flushUntil(() => peers.length === 2 && creates === 2, 'relay attempt')
    expect(peers[0]!.closed).toBe(true)
    expect(cancelled.filter((id) => id === 'sig-1')).toHaveLength(1)
    expect(bridge.currentToken()).toBeNull() // the direct token was retired before relay mint completed

    const stateCount = states.length
    const modeCount = modes.length
    const diagCount = diagnostics.length
    peers[0]!.iceConnectionState = 'failed'
    staleIceState.call(peers[0] as unknown as RTCPeerConnection, new Event('iceconnectionstatechange'))
    staleIceCandidate.call(peers[0] as unknown as RTCPeerConnection, {
      candidate: { type: 'relay', toJSON: () => ({ candidate: VALID_CANDIDATE }) },
    } as unknown as RTCPeerConnectionIceEvent)
    staleMessage.call(peers[0]!.channel as unknown as RTCDataChannel, new MessageEvent('message', { data: 'stale' }))
    staleClose.call(peers[0]!.channel as unknown as RTCDataChannel, new Event('close'))
    remoteGate.resolve(undefined)
    iceGate.resolve(undefined)
    statsGate.resolve(selectedStats('host'))
    await Promise.resolve()
    await Promise.resolve()

    expect(states).toHaveLength(stateCount)
    expect(modes).toHaveLength(modeCount)
    expect(diagnostics).toHaveLength(diagCount)
    expect(postedIce).toEqual([])
    expect(peers[1]!.closed).toBe(false)

    relayMint.resolve('token-relay')
    await flushUntil(() => bridge.currentToken() === 'token-relay' && answerCalls >= 2 && iceCalls >= 2, 'relay signaling')
    peers[1]!.channel.triggerOpen()
    await flushUntil(() => modes.at(-1) === 'relay', 'relay connected mode')

    expect(states.at(-1)).toBe('connected')
    expect(modes.at(-1)).toBe('relay')
    expect(diagnostics.at(-1)).toMatchObject({ candidateType: 'relay', candidateProtocol: 'tls' })
    expect(peers[1]!.closed).toBe(false)
    bridge.close()
  })

  it('ignores a stale direct signaling-session error after relay owns the bridge', async () => {
    vi.useFakeTimers()
    const oldAnswer = deferred<string | null>()
    const oldIce = deferred<{ candidates: { candidate: string; seq: number }[]; nextSince: number }>()
    const peers: ControlledPeer[] = []
    let creates = 0
    const signaling = {
      createSession: async () => `sig-${++creates}`,
      fetchAnswer: (sessionId: string) => sessionId === 'sig-1' ? oldAnswer.promise : new Promise<string | null>(() => {}),
      fetchIce: (sessionId: string) => sessionId === 'sig-1'
        ? oldIce.promise
        : new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const states: ControlState[] = []
    const modes: string[] = []
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      iceServers: [],
      directTimeoutMs: 10,
      fetchRelayCreds: async () => ({
        urls: ['turn:relay.example:3478'], username: 'u', credential: 'p', expiresAtMs: Date.now() + 60_000,
      }),
      peerFactory: () => {
        const peer = new ControlledPeer({ statsValue: selectedStats(peers.length === 0 ? 'host' : 'relay') })
        peers.push(peer)
        return peer as unknown as RTCPeerConnection
      },
      onMode: (mode) => modes.push(mode),
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    await vi.advanceTimersByTimeAsync(10)
    await flushUntil(() => peers.length === 2 && creates === 2, 'relay attempt')
    const stateCount = states.length
    oldAnswer.reject(new SignalSessionDead('sig-1', 409))
    oldIce.reject(new SignalSessionDead('sig-1', 409))
    await Promise.resolve()
    await Promise.resolve()

    expect(states).toHaveLength(stateCount)
    expect(states).not.toContain('offline')
    expect(modes).not.toContain('failed')
    expect(peers[0]!.iceCalls).toBe(0)
    expect(peers[1]!.closed).toBe(false)
    peers[1]!.channel.triggerOpen()
    await flushUntil(() => modes.at(-1) === 'relay', 'relay connected mode')
    expect(states.at(-1)).toBe('connected')
    bridge.close()
  })

  it.each(['answer', 'ice'] as const)(
    'keeps an already-open current DataChannel when an in-flight %s poll reports a dead signaling session',
    async (operation) => {
      const lateAnswer = deferred<string | null>()
      const lateIce = deferred<{ candidates: { candidate: string; seq: number }[]; nextSince: number }>()
      const peer = new ControlledPeer({ statsValue: selectedStats('host') })
      const states: ControlState[] = []
      const cancelled: string[] = []
      let pollSignal: AbortSignal | undefined
      const signaling = {
        createSession: async () => 'sig-direct',
        fetchAnswer: (_sessionId: string, signal?: AbortSignal) => {
          if (operation === 'answer') pollSignal = signal
          return operation === 'answer' ? lateAnswer.promise : Promise.resolve(VALID_ANSWER)
        },
        fetchIce: (_sessionId: string, _since: number, signal?: AbortSignal) => {
          if (operation === 'ice') pollSignal = signal
          return operation === 'ice'
            ? lateIce.promise
            : new Promise<{ candidates: []; nextSince: number }>(() => {})
        },
        postIce: async () => {},
        cancel: async (sessionId: string) => { cancelled.push(sessionId) },
      } as unknown as SignalingPort
      const bridge = new WebrtcBridge({
        signaling,
        targetDeviceId: 'desktop',
        allowUnverifiedDesktop: true,
        iceServers: [],
        peerFactory: () => peer as unknown as RTCPeerConnection,
      })
      bridge.onState((state) => states.push(state))

      await bridge.connect()
      if (operation === 'ice') {
        await flushUntil(() => peer.currentRemoteDescription !== null, 'answer application before DataChannel open')
      }
      peer.channel.triggerOpen()
      expect(states.at(-1)).toBe('connected')
      expect(pollSignal?.aborted).toBe(true)

      if (operation === 'answer') lateAnswer.reject(new SignalSessionDead('sig-direct', 409))
      else lateIce.reject(new SignalSessionDead('sig-direct', 409))
      await Promise.resolve()
      await Promise.resolve()

      expect(states).not.toContain('offline')
      expect(states).not.toContain('closed')
      expect(peer.closed).toBe(false)
      expect(peer.channel.closed).toBe(false)
      expect(bridge.sendText('{}')).toBe(true)
      expect(cancelled).toEqual([])
      bridge.close()
    },
  )

  it.each(['answer', 'ice'] as const)(
    'retires a current pre-open attempt when its %s poll reports a dead signaling session',
    async (operation) => {
      const deadAnswer = deferred<string | null>()
      const deadIce = deferred<{ candidates: { candidate: string; seq: number }[]; nextSince: number }>()
      const peer = new ControlledPeer()
      const states: ControlState[] = []
      const cancelled: string[] = []
      const signaling = {
        createSession: async () => 'sig-direct',
        fetchAnswer: () => operation === 'answer'
          ? deadAnswer.promise
          : new Promise<string | null>(() => {}),
        fetchIce: () => operation === 'ice'
          ? deadIce.promise
          : new Promise<{ candidates: []; nextSince: number }>(() => {}),
        postIce: async () => {},
        cancel: async (sessionId: string) => { cancelled.push(sessionId) },
      } as unknown as SignalingPort
      const bridge = new WebrtcBridge({
        signaling,
        targetDeviceId: 'desktop',
        iceServers: [],
        peerFactory: () => peer as unknown as RTCPeerConnection,
      })
      bridge.onState((state) => states.push(state))

      await bridge.connect()
      if (operation === 'answer') deadAnswer.reject(new SignalSessionDead('sig-direct', 409))
      else deadIce.reject(new SignalSessionDead('sig-direct', 409))
      await flushUntil(() => states.includes('offline'), `pre-open ${operation} signaling failure`)

      expect(states.at(-1)).toBe('offline')
      expect(peer.closed).toBe(true)
      expect(peer.channel.closed).toBe(true)
      expect(cancelled).toEqual(['sig-direct'])
      expect(bridge.sendText('{}')).toBe(false)
    },
  )

  it('fails closed without an unhandled rejection when relay credential fetch rejects', async () => {
    vi.useFakeTimers()
    const peer = new ControlledPeer()
    const states: ControlState[] = []
    const modes: string[] = []
    const signaling = {
      createSession: async () => 'sig-direct',
      fetchAnswer: async () => new Promise<string | null>(() => {}),
      fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      iceServers: [],
      directTimeoutMs: 10,
      fetchRelayCreds: async () => { throw new Error('relay unavailable') },
      peerFactory: () => peer as unknown as RTCPeerConnection,
      onMode: (mode) => modes.push(mode),
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    await vi.advanceTimersByTimeAsync(10)
    await flushUntil(() => states.includes('offline'), 'credential rejection failure state')

    expect(modes.at(-1)).toBe('failed')
    expect(peer.closed).toBe(true)
  })

  it.each(['offer', 'local-description'] as const)(
    'fails closed without an unhandled rejection when relay %s setup rejects',
    async (failurePoint) => {
      vi.useFakeTimers()
      const peers: ControlledPeer[] = []
      const states: ControlState[] = []
      const modes: string[] = []
      const signaling = {
        createSession: async () => 'sig-direct',
        fetchAnswer: async () => new Promise<string | null>(() => {}),
        fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
        postIce: async () => {},
        cancel: async () => {},
      } as unknown as SignalingPort
      const bridge = new WebrtcBridge({
        signaling,
        targetDeviceId: 'desktop',
        iceServers: [],
        directTimeoutMs: 10,
        fetchRelayCreds: async () => ({
          urls: ['turn:relay.example:3478'], username: 'u', credential: 'p', expiresAtMs: Date.now() + 60_000,
        }),
        peerFactory: () => {
          const peer = peers.length === 0
            ? new ControlledPeer()
            : new ControlledPeer(failurePoint === 'offer'
              ? { offerError: new Error('offer rejected') }
              : { localDescriptionError: new Error('local description rejected') })
          peers.push(peer)
          return peer as unknown as RTCPeerConnection
        },
        onMode: (mode) => modes.push(mode),
      })
      bridge.onState((state) => states.push(state))

      await bridge.connect()
      await vi.advanceTimersByTimeAsync(10)
      await flushUntil(() => states.includes('offline'), `${failurePoint} rejection failure state`)

      expect(peers).toHaveLength(2)
      expect(peers[0]!.closed).toBe(true)
      expect(peers[1]!.closed).toBe(true)
      expect(modes.at(-1)).toBe('failed')
    },
  )

  it('keeps a direct connection that opens while relay credentials are still in flight', async () => {
    vi.useFakeTimers()
    const relayCreds = deferred<{ urls: string[]; username: string; credential: string; expiresAtMs: number } | null>()
    const peers: ControlledPeer[] = []
    const cancelled: string[] = []
    const signaling = {
      createSession: async () => 'sig-direct',
      fetchAnswer: async () => new Promise<string | null>(() => {}),
      fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async () => {},
      cancel: async (sessionId: string) => { cancelled.push(sessionId) },
    } as unknown as SignalingPort
    const modes: string[] = []
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      iceServers: [],
      directTimeoutMs: 10,
      fetchRelayCreds: () => relayCreds.promise,
      peerFactory: () => {
        const peer = new ControlledPeer({ statsValue: selectedStats('host') })
        peers.push(peer)
        return peer as unknown as RTCPeerConnection
      },
      onMode: (mode) => modes.push(mode),
    })

    await bridge.connect()
    await vi.advanceTimersByTimeAsync(10) // timeout is now waiting on TURN credentials
    peers[0]!.channel.triggerOpen()
    await flushUntil(() => modes.at(-1) === 'direct', 'late direct connection')
    relayCreds.resolve({
      urls: ['turn:relay.example:3478'], username: 'u', credential: 'p', expiresAtMs: Date.now() + 60_000,
    })
    await Promise.resolve()
    await Promise.resolve()

    expect(peers).toHaveLength(1)
    expect(peers[0]!.closed).toBe(false)
    expect(cancelled).toEqual([])
    expect(modes.at(-1)).toBe('direct')
    bridge.close()
  })

  it('does not start relay fallback when the direct channel is already open at the deadline', async () => {
    vi.useFakeTimers()
    const peers: ControlledPeer[] = []
    const stats = deferred<RTCStatsReport>()
    let relayCredCalls = 0
    const signaling = {
      createSession: async () => 'sig-direct',
      fetchAnswer: async () => new Promise<string | null>(() => {}),
      fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const modes: string[] = []
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      iceServers: [],
      directTimeoutMs: 10,
      fetchRelayCreds: async () => {
        relayCredCalls++
        return { urls: ['turn:relay.example:3478'], username: 'u', credential: 'p', expiresAtMs: Date.now() + 60_000 }
      },
      peerFactory: () => {
        const peer = new ControlledPeer({ stats })
        peers.push(peer)
        return peer as unknown as RTCPeerConnection
      },
      onMode: (mode) => modes.push(mode),
    })

    await bridge.connect()
    peers[0]!.channel.triggerOpen()
    // The state callback is synchronous; deliberately leave getStats/policy settlement to a later microtask.
    await vi.advanceTimersByTimeAsync(10)

    expect(relayCredCalls).toBe(0)
    expect(peers).toHaveLength(1)
    expect(peers[0]!.closed).toBe(false)
    stats.resolve(selectedStats('host'))
    await flushUntil(() => modes.at(-1) === 'direct', 'direct mode after selected-candidate stats')
    expect(modes.at(-1)).toBe('direct')
    bridge.close()
  })

  it('does not close an open relay while selected-candidate stats are pending at its deadline', async () => {
    vi.useFakeTimers()
    const stats = deferred<RTCStatsReport>()
    const peers: ControlledPeer[] = []
    const states: ControlState[] = []
    const modes: string[] = []
    const signaling = {
      createSession: async () => 'sig-relay',
      fetchAnswer: async () => new Promise<string | null>(() => {}),
      fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      forceRelay: true,
      fetchRelayCreds: async () => ({
        urls: ['turn:relay.example:3478'], username: 'u', credential: 'p', expiresAtMs: Date.now() + 60_000,
      }),
      peerFactory: () => {
        const peer = new ControlledPeer({ stats })
        peers.push(peer)
        return peer as unknown as RTCPeerConnection
      },
      onMode: (mode) => modes.push(mode),
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    const relay = peers[0]!
    relay.channel.triggerOpen()
    expect(states.at(-1)).toBe('connected')
    relay.iceConnectionState = 'connected'
    relay.oniceconnectionstatechange?.call(
      relay as unknown as RTCPeerConnection,
      new Event('iceconnectionstatechange'),
    )
    await vi.advanceTimersByTimeAsync(45_000)

    expect(relay.closed).toBe(false)
    expect(states).not.toContain('offline')
    expect(modes).not.toContain('failed')
    stats.resolve(selectedStats('relay'))
    await flushUntil(() => modes.at(-1) === 'relay', 'relay mode after selected-candidate stats')
    bridge.close()
  })

  it('keeps a pre-open failed attempt alive for a late trickled relay candidate', async () => {
    vi.useFakeTimers()
    const lateIce = deferred<{
      candidates: { candidate: string; seq: number }[]
      nextSince: number
    }>()
    const peer = new ControlledPeer({ statsValue: selectedStats('relay') })
    const states: ControlState[] = []
    const signaling = {
      createSession: async () => 'sig-late-relay',
      fetchAnswer: async () => VALID_ANSWER,
      fetchIce: async () => lateIce.promise,
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      allowUnverifiedDesktop: true,
      iceServers: [],
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    await flushUntil(() => peer.remoteCalls === 1, 'remote answer')
    peer.iceConnectionState = 'failed'
    peer.oniceconnectionstatechange?.call(
      peer as unknown as RTCPeerConnection,
      new Event('iceconnectionstatechange'),
    )

    expect(states).not.toContain('offline')
    expect(peer.closed).toBe(false)
    await vi.advanceTimersByTimeAsync(1_000)
    lateIce.resolve({
      candidates: [{ candidate: remoteCandidate('late-relay', 'relay'), seq: 1 }],
      nextSince: 1,
    })
    await flushUntil(() => peer.iceCalls === 1, 'late relay candidate')
    peer.iceConnectionState = 'checking'
    peer.oniceconnectionstatechange?.call(
      peer as unknown as RTCPeerConnection,
      new Event('iceconnectionstatechange'),
    )
    peer.iceConnectionState = 'connected'
    peer.connectionState = 'connected'
    peer.oniceconnectionstatechange?.call(
      peer as unknown as RTCPeerConnection,
      new Event('iceconnectionstatechange'),
    )
    peer.channel.triggerOpen()
    await vi.advanceTimersByTimeAsync(WEBRTC_PREOPEN_ICE_FAILED_GRACE_MS)

    expect(states.at(-1)).toBe('connected')
    expect(states).not.toContain('offline')
    expect(peer.closed).toBe(false)
    bridge.close()
  })

  it('does not extend the first pre-open failed deadline when ICE returns only to checking', async () => {
    vi.useFakeTimers()
    const peer = new ControlledPeer()
    const states: ControlState[] = []
    const signaling = {
      createSession: async () => 'sig-still-failed',
      fetchAnswer: async () => new Promise<string | null>(() => {}),
      fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      iceServers: [],
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    peer.iceConnectionState = 'failed'
    peer.oniceconnectionstatechange?.call(
      peer as unknown as RTCPeerConnection,
      new Event('iceconnectionstatechange'),
    )
    await vi.advanceTimersByTimeAsync(WEBRTC_PREOPEN_ICE_FAILED_GRACE_MS - 1)
    peer.iceConnectionState = 'checking'
    peer.oniceconnectionstatechange?.call(
      peer as unknown as RTCPeerConnection,
      new Event('iceconnectionstatechange'),
    )
    expect(states).not.toContain('offline')
    await vi.advanceTimersByTimeAsync(1)

    expect(states.filter((state) => state === 'offline')).toHaveLength(1)
    expect(peer.closed).toBe(true)
  })

  it('cancels a retired attempt pre-open failure timer without affecting its replacement', async () => {
    vi.useFakeTimers()
    const peers: ControlledPeer[] = []
    const states: ControlState[] = []
    let sessions = 0
    const signaling = {
      createSession: async () => `sig-replacement-${++sessions}`,
      fetchAnswer: async () => new Promise<string | null>(() => {}),
      fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      iceServers: [],
      peerFactory: () => {
        const peer = new ControlledPeer()
        peers.push(peer)
        return peer as unknown as RTCPeerConnection
      },
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    peers[0]!.iceConnectionState = 'failed'
    peers[0]!.oniceconnectionstatechange?.call(
      peers[0] as unknown as RTCPeerConnection,
      new Event('iceconnectionstatechange'),
    )
    await bridge.connect()
    expect(peers).toHaveLength(2)
    await vi.advanceTimersByTimeAsync(WEBRTC_PREOPEN_ICE_FAILED_GRACE_MS)

    expect(peers[0]!.closed).toBe(true)
    expect(peers[1]!.closed).toBe(false)
    expect(states).not.toContain('offline')
    bridge.close()
  })

  it('closes an established current attempt when ICE fails without a DataChannel close event', async () => {
    vi.useFakeTimers()
    const peer = new ControlledPeer({ statsValue: selectedStats('host') })
    const states: ControlState[] = []
    const signaling = {
      createSession: async () => 'sig-direct',
      fetchAnswer: async () => new Promise<string | null>(() => {}),
      fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      iceServers: [],
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    peer.channel.triggerOpen()
    expect(states.at(-1)).toBe('connected')
    expect(peer.channel.readyState).toBe('open')

    // Model the silent-drop class: ICE fails, but the browser never dispatches dc.onclose.
    peer.iceConnectionState = 'failed'
    peer.oniceconnectionstatechange?.call(
      peer as unknown as RTCPeerConnection,
      new Event('iceconnectionstatechange'),
    )

    expect(states.filter((state) => state === 'closed')).toHaveLength(1)
    expect(states.at(-1)).toBe('closed')
    expect(peer.closed).toBe(true)
  })

  it('cancels the bounded disconnect grace when the established attempt recovers', async () => {
    vi.useFakeTimers()
    const peer = new ControlledPeer({ statsValue: selectedStats('host') })
    const states: ControlState[] = []
    const signaling = {
      createSession: async () => 'sig-direct',
      fetchAnswer: async () => new Promise<string | null>(() => {}),
      fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      iceServers: [],
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    peer.channel.triggerOpen()
    peer.iceConnectionState = 'disconnected'
    peer.connectionState = 'disconnected'
    peer.oniceconnectionstatechange?.call(
      peer as unknown as RTCPeerConnection,
      new Event('iceconnectionstatechange'),
    )
    await vi.advanceTimersByTimeAsync(WEBRTC_DISCONNECTED_GRACE_MS - 1)
    expect(states).not.toContain('closed')

    peer.iceConnectionState = 'completed'
    peer.connectionState = 'connected'
    peer.onconnectionstatechange?.call(
      peer as unknown as RTCPeerConnection,
      new Event('connectionstatechange'),
    )
    await vi.advanceTimersByTimeAsync(WEBRTC_DISCONNECTED_GRACE_MS)

    expect(states).not.toContain('closed')
    expect(peer.closed).toBe(false)
    bridge.close()
  })

  it('keeps the grace armed when PC advances from disconnected only to connecting while ICE stays healthy', async () => {
    vi.useFakeTimers()
    const { bridge, peer, states } = directLivenessHarness()
    peer.connectionState = 'connected'
    peer.iceConnectionState = 'connected'
    await bridge.connect()
    peer.channel.triggerOpen()

    peer.connectionState = 'disconnected'
    peer.onconnectionstatechange?.call(
      peer as unknown as RTCPeerConnection,
      new Event('connectionstatechange'),
    )
    await vi.advanceTimersByTimeAsync(WEBRTC_DISCONNECTED_GRACE_MS - 1)
    expect(states).not.toContain('closed')

    // `connecting` means recovery is being attempted. The still-healthy ICE source must not clear the PC source's
    // outstanding disconnect or move its original deadline.
    peer.connectionState = 'connecting'
    peer.onconnectionstatechange?.call(
      peer as unknown as RTCPeerConnection,
      new Event('connectionstatechange'),
    )
    await vi.advanceTimersByTimeAsync(1)

    expect(states.filter((state) => state === 'closed')).toHaveLength(1)
    expect(peer.closed).toBe(true)
  })

  it('keeps the grace armed when ICE advances from disconnected only to checking while PC stays healthy', async () => {
    vi.useFakeTimers()
    const { bridge, peer, states } = directLivenessHarness()
    peer.connectionState = 'connected'
    peer.iceConnectionState = 'connected'
    await bridge.connect()
    peer.channel.triggerOpen()

    peer.iceConnectionState = 'disconnected'
    peer.oniceconnectionstatechange?.call(
      peer as unknown as RTCPeerConnection,
      new Event('iceconnectionstatechange'),
    )
    await vi.advanceTimersByTimeAsync(WEBRTC_DISCONNECTED_GRACE_MS - 1)
    expect(states).not.toContain('closed')

    // `checking` is not a successful ICE recovery. A connected PC snapshot cannot forgive this source.
    peer.iceConnectionState = 'checking'
    peer.oniceconnectionstatechange?.call(
      peer as unknown as RTCPeerConnection,
      new Event('iceconnectionstatechange'),
    )
    await vi.advanceTimersByTimeAsync(1)

    expect(states.filter((state) => state === 'closed')).toHaveLength(1)
    expect(peer.closed).toBe(true)
  })

  it.each(['connection', 'ice'] as const)(
    'cancels only the %s source disconnect after that source genuinely recovers',
    async (source) => {
      vi.useFakeTimers()
      const { bridge, peer, states } = directLivenessHarness()
      peer.connectionState = 'connected'
      peer.iceConnectionState = 'connected'
      await bridge.connect()
      peer.channel.triggerOpen()

      if (source === 'connection') {
        peer.connectionState = 'disconnected'
        peer.onconnectionstatechange?.call(
          peer as unknown as RTCPeerConnection,
          new Event('connectionstatechange'),
        )
      } else {
        peer.iceConnectionState = 'disconnected'
        peer.oniceconnectionstatechange?.call(
          peer as unknown as RTCPeerConnection,
          new Event('iceconnectionstatechange'),
        )
      }
      await vi.advanceTimersByTimeAsync(WEBRTC_DISCONNECTED_GRACE_MS - 1)
      expect(states).not.toContain('closed')

      if (source === 'connection') {
        peer.connectionState = 'connected'
        peer.onconnectionstatechange?.call(
          peer as unknown as RTCPeerConnection,
          new Event('connectionstatechange'),
        )
      } else {
        peer.iceConnectionState = 'completed'
        peer.oniceconnectionstatechange?.call(
          peer as unknown as RTCPeerConnection,
          new Event('iceconnectionstatechange'),
        )
      }
      await vi.advanceTimersByTimeAsync(WEBRTC_DISCONNECTED_GRACE_MS)

      expect(states).not.toContain('closed')
      expect(peer.closed).toBe(false)
      bridge.close()
    },
  )

  it('closes an established attempt once when disconnection outlives its grace', async () => {
    vi.useFakeTimers()
    const peer = new ControlledPeer({ statsValue: selectedStats('host') })
    const states: ControlState[] = []
    const signaling = {
      createSession: async () => 'sig-direct',
      fetchAnswer: async () => new Promise<string | null>(() => {}),
      fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      iceServers: [],
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    peer.channel.triggerOpen()
    const queuedConnectionState = peer.onconnectionstatechange!
    peer.connectionState = 'disconnected'
    queuedConnectionState.call(peer as unknown as RTCPeerConnection, new Event('connectionstatechange'))
    // A duplicate callback must share the existing timer, not enqueue another close.
    queuedConnectionState.call(peer as unknown as RTCPeerConnection, new Event('connectionstatechange'))
    await vi.advanceTimersByTimeAsync(WEBRTC_DISCONNECTED_GRACE_MS)

    expect(states.filter((state) => state === 'closed')).toHaveLength(1)
    expect(peer.closed).toBe(true)
    // A callback that was queued before teardown is stale and cannot emit a second close.
    queuedConnectionState.call(peer as unknown as RTCPeerConnection, new Event('connectionstatechange'))
    expect(states.filter((state) => state === 'closed')).toHaveLength(1)
  })

  it('makes a retired attempt liveness callback and grace timer inert', async () => {
    vi.useFakeTimers()
    const directStats = deferred<RTCStatsReport>()
    const peers: ControlledPeer[] = []
    let creates = 0
    const signaling = {
      createSession: async () => `sig-${++creates}`,
      fetchAnswer: async () => new Promise<string | null>(() => {}),
      fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
    const states: ControlState[] = []
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'desktop',
      iceServers: [],
      directTimeoutMs: 10,
      fetchRelayCreds: async () => ({
        urls: ['turn:relay.example:3478'], username: 'u', credential: 'p', expiresAtMs: Date.now() + 60_000,
      }),
      peerFactory: () => {
        const peer = peers.length === 0
          ? new ControlledPeer({ stats: directStats })
          : new ControlledPeer({ statsValue: selectedStats('relay') })
        peers.push(peer)
        return peer as unknown as RTCPeerConnection
      },
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    const direct = peers[0]!
    direct.channel.triggerOpen()
    const staleConnectionState = direct.onconnectionstatechange!
    direct.connectionState = 'disconnected'
    staleConnectionState.call(direct as unknown as RTCPeerConnection, new Event('connectionstatechange'))
    // Make the attempt eligible for the already-armed direct fallback while its liveness timer remains armed.
    direct.channel.readyState = 'connecting'
    await vi.advanceTimersByTimeAsync(10)
    await flushUntil(() => peers.length === 2, 'relay attempt')
    const relay = peers[1]!
    relay.channel.triggerOpen()
    const closedBeforeStaleCallbacks = states.filter((state) => state === 'closed').length

    direct.connectionState = 'failed'
    staleConnectionState.call(direct as unknown as RTCPeerConnection, new Event('connectionstatechange'))
    directStats.resolve(selectedStats('host'))
    await vi.advanceTimersByTimeAsync(WEBRTC_DISCONNECTED_GRACE_MS)

    expect(states.filter((state) => state === 'closed')).toHaveLength(closedBeforeStaleCallbacks)
    expect(relay.closed).toBe(false)
    bridge.close()
  })

  it('retires a pre-open failed attempt without ever publishing connected', async () => {
    vi.useFakeTimers()
    const { bridge, peer, states, cancelled } = directLivenessHarness()
    await bridge.connect()

    peer.connectionState = 'failed'
    peer.onconnectionstatechange?.call(
      peer as unknown as RTCPeerConnection,
      new Event('connectionstatechange'),
    )
    expect(states).not.toContain('closed') // setup failure is reconciled authoritatively at DataChannel open

    peer.channel.triggerOpen()

    expect(states).not.toContain('connected')
    expect(states.filter((state) => state === 'closed')).toHaveLength(1)
    expect(peer.closed).toBe(true)
    expect(peer.channel.closed).toBe(true)
    expect(cancelled).toEqual(['sig-direct'])
  })

  it('arms the bounded grace when a pre-open disconnect is still present at DataChannel open', async () => {
    vi.useFakeTimers()
    const { bridge, peer, states } = directLivenessHarness()
    await bridge.connect()

    peer.connectionState = 'disconnected'
    peer.onconnectionstatechange?.call(
      peer as unknown as RTCPeerConnection,
      new Event('connectionstatechange'),
    )
    peer.channel.triggerOpen()
    expect(states.at(-1)).toBe('connected')

    await vi.advanceTimersByTimeAsync(WEBRTC_DISCONNECTED_GRACE_MS - 1)
    expect(states).not.toContain('closed')
    expect(peer.closed).toBe(false)
    await vi.advanceTimersByTimeAsync(1)

    expect(states.filter((state) => state === 'closed')).toHaveLength(1)
    expect(peer.closed).toBe(true)
  })

  it.each(['connection', 'ice'] as const)(
    'retires an established attempt when the %s state closes without dc.onclose',
    async (source) => {
      vi.useFakeTimers()
      const { bridge, peer, states } = directLivenessHarness()
      await bridge.connect()
      peer.channel.triggerOpen()

      if (source === 'connection') {
        peer.connectionState = 'closed'
        peer.onconnectionstatechange?.call(
          peer as unknown as RTCPeerConnection,
          new Event('connectionstatechange'),
        )
      } else {
        peer.iceConnectionState = 'closed'
        peer.oniceconnectionstatechange?.call(
          peer as unknown as RTCPeerConnection,
          new Event('iceconnectionstatechange'),
        )
      }

      expect(states.filter((state) => state === 'closed')).toHaveLength(1)
      expect(peer.closed).toBe(true)
      expect(peer.channel.closed).toBe(true)
    },
  )

  it.each(['data-channel-first', 'peer-failed-first'] as const)(
    'emits one close and fully retires when dc.onclose races a queued peer failure (%s)',
    async (order) => {
      vi.useFakeTimers()
      const { bridge, peer, states, cancelled } = directLivenessHarness()
      await bridge.connect()
      peer.channel.triggerOpen()
      const queuedDataChannelClose = peer.channel.onclose!
      const queuedPeerFailure = peer.onconnectionstatechange!
      peer.connectionState = 'failed'

      if (order === 'data-channel-first') {
        queuedDataChannelClose.call(peer.channel as unknown as RTCDataChannel, new Event('close'))
        queuedPeerFailure.call(peer as unknown as RTCPeerConnection, new Event('connectionstatechange'))
      } else {
        queuedPeerFailure.call(peer as unknown as RTCPeerConnection, new Event('connectionstatechange'))
        queuedDataChannelClose.call(peer.channel as unknown as RTCDataChannel, new Event('close'))
      }

      expect(states.filter((state) => state === 'closed')).toHaveLength(1)
      expect(peer.closed).toBe(true)
      expect(peer.channel.closed).toBe(true)
      expect(bridge.sendText('{}')).toBe(false)
      expect(cancelled).toEqual(['sig-direct'])
    },
  )
})

describe('WebrtcBridge cold dependency overlap', () => {
  afterEach(() => vi.useRealTimers())

  function inertSignaling(createSession: (offer: string) => Promise<string> | string): SignalingPort {
    return {
      createSession: async (_target: string, offer: string) => createSession(offer),
      fetchAnswer: async () => new Promise<string | null>(() => {}),
      fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort
  }

  it('starts descriptor-only preflight beside relay discovery and defers authorization until a peer is viable', async () => {
    const relay = deferred<{ urls: string[]; username: string; credential: string; expiresAtMs: number } | null>()
    const descriptor = deferred<void>()
    const peers: ControlledPeer[] = []
    const offers: string[] = []
    let relayCalls = 0
    let preflightCalls = 0
    let certificateCalls = 0
    const bridge = new WebrtcBridge({
      signaling: inertSignaling((offer) => { offers.push(offer); return 'sig-overlap' }),
      targetDeviceId: 'desktop',
      fetchRelayCreds: () => { relayCalls++; return relay.promise },
      browserCertPreflight: async () => { preflightCalls++; await descriptor.promise },
      browserCert: async () => {
        certificateCalls++
        await descriptor.promise
        return { proof: 'certificate' }
      },
      peerFactory: () => {
        const peer = new ControlledPeer()
        peers.push(peer)
        return peer as unknown as RTCPeerConnection
      },
    })

    expect(preflightCalls).toBe(0)
    expect(certificateCalls).toBe(0) // construction/background preparation never starts a native prompt
    const connecting = bridge.connect()
    await flushUntil(() => relayCalls === 1 && preflightCalls === 1, 'parallel cold dependencies')
    expect(peers).toHaveLength(0)
    expect(offers).toHaveLength(0)
    expect(certificateCalls).toBe(0)

    descriptor.resolve()
    await Promise.resolve()
    expect(peers).toHaveLength(0)
    expect(certificateCalls).toBe(0)
    relay.resolve({
      urls: ['turn:relay.example:3478'], username: 'u', credential: 'p', expiresAtMs: Date.now() + 60_000,
    })
    await connecting

    expect(peers).toHaveLength(1)
    expect(certificateCalls).toBe(1)
    expect(offers).toHaveLength(1)
    expect(JSON.parse(offers[0]!).hydra_browser_cert).toEqual({ proof: 'certificate' })
    bridge.close()
  })

  it('keeps WebAuthn and signaling behind the offer, then gates signaling on the certificate', async () => {
    const offer = deferred<RTCSessionDescriptionInit>()
    const certificate = deferred<Record<string, unknown> | null>()
    const peer = new ControlledPeer({ offer })
    let sessions = 0
    let certificateCalls = 0
    const bridge = new WebrtcBridge({
      signaling: inertSignaling(() => { sessions++; return 'sig-gated' }),
      targetDeviceId: 'desktop',
      fetchRelayCreds: async () => ({
        urls: ['turn:relay.example:3478'], username: 'u', credential: 'p', expiresAtMs: Date.now() + 60_000,
      }),
      browserCertPreflight: async () => {},
      browserCert: () => { certificateCalls++; return certificate.promise },
      peerFactory: () => peer as unknown as RTCPeerConnection,
    })

    const connecting = bridge.connect()
    await flushUntil(() => peer.onicecandidate !== null, 'offer setup')
    expect(certificateCalls).toBe(0)
    expect(sessions).toBe(0)

    offer.resolve({ type: 'offer', sdp: 'v=0\r\n' })
    await flushUntil(() => certificateCalls === 1, 'offer-gated certificate request')
    expect(sessions).toBe(0)
    certificate.resolve({ proof: 'certificate' })
    await connecting
    expect(sessions).toBe(1)
    bridge.close()
  })

  it('aborts and settles descriptor preflight without opening WebAuthn when forced relay cannot proceed', async () => {
    const relay = deferred<null>()
    const externalAbort = new AbortController()
    let preflightSignal: AbortSignal | undefined
    let preflightCalls = 0
    let preflightSettles = 0
    let certificateCalls = 0
    let pauses = 0
    let resumes = 0
    let peerCreates = 0
    let sessions = 0
    const states: ControlState[] = []
    const deadline: ConnectDeadlineScope = {
      signal: externalAbort.signal,
      progress: () => true,
      pauseInactivity: () => { pauses++ },
      resumeInactivity: () => { resumes++ },
    }
    const bridge = new WebrtcBridge({
      signaling: inertSignaling(() => { sessions++; return 'must-not-open' }),
      targetDeviceId: 'desktop',
      forceRelay: true,
      connectDeadline: deadline,
      fetchRelayCreds: () => relay.promise,
      browserCertPreflight: async (signal) => {
        preflightCalls++
        preflightSignal = signal
        return new Promise((_resolve, reject) => {
          signal?.addEventListener('abort', () => {
            preflightSettles++
            reject(new DOMException('cancelled', 'AbortError'))
          }, { once: true })
        })
      },
      browserCert: async (context) => {
        certificateCalls++
        context?.onUserInteractionStart()
        context?.onUserInteractionEnd()
        return { proof: 'must-not-authorize' }
      },
      peerFactory: () => { peerCreates++; return new ControlledPeer() as unknown as RTCPeerConnection },
    })
    bridge.onState((state) => states.push(state))

    const connecting = bridge.connect()
    await flushUntil(() => preflightCalls === 1 && preflightSignal !== undefined, 'owned descriptor preflight')
    relay.resolve(null)
    await connecting

    expect(preflightSignal?.aborted).toBe(true)
    expect(externalAbort.signal.aborted).toBe(false)
    expect(preflightSettles).toBe(1)
    expect(certificateCalls).toBe(0)
    expect(pauses).toBe(0)
    expect(resumes).toBe(0)
    expect(peerCreates).toBe(0)
    expect(sessions).toBe(0)
    expect(states).toEqual(['connecting', 'offline'])
  })

  it('reuses one certificate result across the explicit compatibility fallback', async () => {
    vi.useFakeTimers()
    const peers: ControlledPeer[] = []
    const offers: Record<string, unknown>[] = []
    let preflightCalls = 0
    let certificateCalls = 0
    const bridge = new WebrtcBridge({
      signaling: inertSignaling((offer) => {
        offers.push(JSON.parse(offer))
        return `sig-${offers.length}`
      }),
      targetDeviceId: 'desktop',
      iceServers: [],
      directTimeoutMs: 10,
      fetchRelayCreds: async () => ({
        urls: ['turn:relay.example:3478'], username: 'u', credential: 'p', expiresAtMs: Date.now() + 60_000,
      }),
      browserCertPreflight: async () => { preflightCalls++ },
      browserCert: async () => {
        certificateCalls++
        return { proof: 'one-owned-result' }
      },
      peerFactory: () => {
        const peer = new ControlledPeer()
        peers.push(peer)
        return peer as unknown as RTCPeerConnection
      },
    })

    await bridge.connect()
    expect(preflightCalls).toBe(1)
    expect(certificateCalls).toBe(1)
    expect(offers).toHaveLength(1)
    await vi.advanceTimersByTimeAsync(10)
    await flushUntil(() => offers.length === 2, 'compatibility relay signaling')

    expect(peers).toHaveLength(2)
    expect(preflightCalls).toBe(1)
    expect(certificateCalls).toBe(1)
    expect(offers.map((offer) => offer.hydra_browser_cert)).toEqual([
      { proof: 'one-owned-result' },
      { proof: 'one-owned-result' },
    ])
    bridge.close()
  })

  it('keeps an early descriptor-preflight refusal fail-closed at the existing authorization gate', async () => {
    const relay = deferred<{ urls: string[]; username: string; credential: string; expiresAtMs: number } | null>()
    const descriptor = deferred<void>()
    let preflightCalls = 0
    let certificateCalls = 0
    let sessions = 0
    const states: ControlState[] = []
    const bridge = new WebrtcBridge({
      signaling: inertSignaling(() => { sessions++; return 'must-not-open' }),
      targetDeviceId: 'desktop',
      fetchRelayCreds: () => relay.promise,
      browserCertPreflight: async () => { preflightCalls++; await descriptor.promise },
      browserCert: async () => { certificateCalls++; await descriptor.promise; return null },
      peerFactory: () => new ControlledPeer() as unknown as RTCPeerConnection,
    })
    bridge.onState((state) => states.push(state))

    const connecting = bridge.connect()
    await flushUntil(() => preflightCalls === 1, 'descriptor preflight')
    descriptor.reject(new Error('descriptor unavailable'))
    await Promise.resolve()
    expect(certificateCalls).toBe(0)
    expect(sessions).toBe(0)
    relay.resolve({
      urls: ['turn:relay.example:3478'], username: 'u', credential: 'p', expiresAtMs: Date.now() + 60_000,
    })
    await connecting

    expect(preflightCalls).toBe(1)
    expect(certificateCalls).toBe(1)
    expect(sessions).toBe(0)
    expect(states).toEqual(['connecting', 'authorization_required'])
  })
})

describe('WebrtcBridge combined signaling progress', () => {
  afterEach(() => vi.useRealTimers())

  function pendingProgress(nextSince = 0) {
    return { status: 'pending', expiresAtMs: 9_999_999_999_999, candidates: [], nextSince }
  }

  function combinedBridge(
    peer: ControlledPeer,
    signaling: Record<string, unknown>,
    states: ControlState[] = [],
    connectDeadline?: ConnectDeadlineScope,
  ): WebrtcBridge {
    const bridge = new WebrtcBridge({
      signaling: {
        createSession: async () => 'sig-combined',
        fetchAnswer: async () => new Promise<string | null>(() => {}),
        fetchIce: async () => new Promise<{ candidates: []; nextSince: number }>(() => {}),
        postIce: async () => {},
        cancel: async () => {},
        ...signaling,
      } as unknown as SignalingPort,
      targetDeviceId: 'desktop',
      allowUnverifiedDesktop: true,
      iceServers: [],
      backoff: { fastMs: 1, idleMs: 50, staleTimeoutMs: 1_000 },
      peerFactory: () => peer as unknown as RTCPeerConnection,
      ...(connectDeadline ? { connectDeadline } : {}),
    })
    bridge.onState((state) => states.push(state))
    return bridge
  }

  it('installs a combined answer before applying its ICE and uses one fast pre-open poll loop', async () => {
    vi.useFakeTimers()
    const peer = new ControlledPeer()
    const progressCalls: Array<{ since: number; answerSeen: boolean; signal?: AbortSignal }> = []
    let answerReads = 0
    let iceReads = 0
    const bridge = combinedBridge(peer, {
      fetchAnswer: async () => { answerReads++; return null },
      fetchIce: async () => { iceReads++; return { candidates: [], nextSince: 0 } },
      fetchProgress: async (_sessionId: string, since: number, answerSeen: boolean, signal?: AbortSignal) => {
        progressCalls.push({ since, answerSeen, signal })
        if (progressCalls.length === 1) {
          return {
            status: 'answered',
            expiresAtMs: 9_999_999_999_999,
            answer: VALID_ANSWER,
            candidates: [{ candidate: VALID_CANDIDATE, seq: 1 }],
            nextSince: 1,
          }
        }
        return { status: 'answered', expiresAtMs: 9_999_999_999_999, candidates: [], nextSince: 1 }
      },
    })

    await bridge.connect()
    await flushUntil(() => peer.remoteCalls === 1 && peer.iceCalls === 1, 'combined answer and ICE')
    expect(progressCalls[0]).toMatchObject({ since: 0, answerSeen: false })
    expect(answerReads).toBe(0)
    expect(iceReads).toBe(0)
    expect(peer.currentRemoteDescription).not.toBeNull()
    expect(peer.addedIce).toHaveLength(1)

    await vi.advanceTimersByTimeAsync(1)
    await flushUntil(() => progressCalls.length === 2, 'second combined progress tick')
    expect(progressCalls[1]).toMatchObject({ since: 1, answerSeen: true })
    expect(progressCalls[1]!.signal).toBe(progressCalls[0]!.signal)
    expect(answerReads).toBe(0)
    expect(iceReads).toBe(0)
    bridge.close()
  })

  it('keeps answer absent and does not mutate description/cursor state on an empty pending tick', async () => {
    const peer = new ControlledPeer()
    const next = deferred<unknown>()
    const calls: Array<{ since: number; answerSeen: boolean }> = []
    const bridge = combinedBridge(peer, {
      fetchProgress: (_sessionId: string, since: number, answerSeen: boolean) => {
        calls.push({ since, answerSeen })
        return calls.length === 1 ? Promise.resolve(pendingProgress()) : next.promise
      },
    })

    await bridge.connect()
    await flushUntil(() => calls.length === 1, 'initial empty progress')
    expect(calls[0]).toEqual({ since: 0, answerSeen: false })
    expect(peer.remoteCalls).toBe(0)
    expect(peer.iceCalls).toBe(0)
    bridge.close()
  })

  it('reports only verified answer and first-ICE stages; empty progress ticks add no deadline progress', async () => {
    vi.useFakeTimers()
    const peer = new ControlledPeer()
    const stages: string[] = []
    const abort = new AbortController()
    const deadline: ConnectDeadlineScope = {
      signal: abort.signal,
      progress: (stage) => { stages.push(stage); return true },
      pauseInactivity: () => {},
      resumeInactivity: () => {},
    }
    let calls = 0
    const bridge = combinedBridge(peer, {
      fetchProgress: async () => {
        calls++
        if (calls === 1) return pendingProgress()
        if (calls === 2) {
          return {
            status: 'answered', expiresAtMs: 9_999_999_999_999, answer: VALID_ANSWER,
            candidates: [{ candidate: VALID_CANDIDATE, seq: 1 }], nextSince: 1,
          }
        }
        return { status: 'answered', expiresAtMs: 9_999_999_999_999, candidates: [], nextSince: 1 }
      },
    }, [], deadline)
    await bridge.connect()
    await flushUntil(() => calls === 1, 'empty deadline progress tick')
    expect(stages.filter((stage) =>
      stage === 'bridge:remote-description' || stage === 'bridge:first-remote-ice')).toEqual([])

    await vi.advanceTimersByTimeAsync(1)
    await flushUntil(() => peer.remoteCalls === 1 && peer.iceCalls === 1, 'meaningful deadline progress')
    expect(stages.filter((stage) =>
      stage === 'bridge:remote-description' || stage === 'bridge:first-remote-ice')).toEqual([
      'bridge:remote-description',
      'bridge:first-remote-ice',
    ])

    await vi.advanceTimersByTimeAsync(1)
    await flushUntil(() => calls === 3, 'post-answer empty progress tick')
    expect(stages.filter((stage) =>
      stage === 'bridge:remote-description' || stage === 'bridge:first-remote-ice')).toHaveLength(2)
    bridge.close()
  })

  it('fails a malformed combined body atomically before answer or candidate admission', async () => {
    const peer = new ControlledPeer()
    const states: ControlState[] = []
    const bridge = combinedBridge(peer, {
      fetchProgress: async () => ({
        status: 'answered',
        expiresAtMs: 9_999_999_999_999,
        answer: VALID_ANSWER,
        candidates: [
          { candidate: VALID_CANDIDATE, seq: 1 },
          { candidate: VALID_CANDIDATE, seq: 2, unknown: true },
        ],
        nextSince: 2,
      }),
    }, states)

    await bridge.connect()
    await flushUntil(() => states.includes('offline'), 'malformed progress failure')
    expect(peer.remoteCalls).toBe(0)
    expect(peer.iceCalls).toBe(0)
    expect(peer.closed).toBe(true)
  })

  it('makes a retired progress completion inert and aborts its one shared poll signal', async () => {
    const peer = new ControlledPeer()
    const response = deferred<unknown>()
    let pollSignal: AbortSignal | undefined
    const bridge = combinedBridge(peer, {
      fetchProgress: (_sessionId: string, _since: number, _answerSeen: boolean, signal?: AbortSignal) => {
        pollSignal = signal
        return response.promise
      },
    })

    await bridge.connect()
    await flushUntil(() => pollSignal !== undefined, 'owned progress request')
    bridge.close()
    expect(pollSignal?.aborted).toBe(true)
    response.resolve({
      status: 'answered', expiresAtMs: 9_999_999_999_999, answer: VALID_ANSWER,
      candidates: [{ candidate: VALID_CANDIDATE, seq: 1 }], nextSince: 1,
    })
    await Promise.resolve()
    await Promise.resolve()
    expect(peer.remoteCalls).toBe(0)
    expect(peer.iceCalls).toBe(0)
  })

  it('native DataChannel open aborts an in-flight progress read and no second loop is scheduled', async () => {
    vi.useFakeTimers()
    const peer = new ControlledPeer({ statsValue: selectedStats('host') })
    const pending = deferred<unknown>()
    let calls = 0
    let pollSignal: AbortSignal | undefined
    const bridge = combinedBridge(peer, {
      fetchProgress: (_sessionId: string, _since: number, _answerSeen: boolean, signal?: AbortSignal) => {
        calls++
        pollSignal = signal
        return pending.promise
      },
    })

    await bridge.connect()
    await flushUntil(() => calls === 1, 'one in-flight progress request')
    await vi.advanceTimersByTimeAsync(100)
    expect(calls).toBe(1)
    peer.channel.triggerOpen()
    expect(pollSignal?.aborted).toBe(true)
    await vi.advanceTimersByTimeAsync(100)
    expect(calls).toBe(1)
    bridge.close()
  })

  it('retries transient progress failure but exact unsupported falls back once to legacy readers', async () => {
    vi.useFakeTimers()
    const transientPeer = new ControlledPeer()
    let transientCalls = 0
    const transient = combinedBridge(transientPeer, {
      fetchProgress: async () => {
        transientCalls++
        if (transientCalls === 1) throw new Error('temporary')
        return pendingProgress()
      },
    })
    await transient.connect()
    await Promise.resolve()
    await Promise.resolve()
    await vi.advanceTimersByTimeAsync(1)
    await flushUntil(() => transientCalls === 2, 'transient combined retry')
    expect(transientPeer.closed).toBe(false)
    transient.close()

    const fallbackPeer = new ControlledPeer()
    let progressReads = 0
    let answerReads = 0
    let iceReads = 0
    let progressSignal: AbortSignal | undefined
    let answerSignal: AbortSignal | undefined
    let iceSignal: AbortSignal | undefined
    const fallback = combinedBridge(fallbackPeer, {
      fetchProgress: async (
        _sessionId: string,
        _since: number,
        _answerSeen: boolean,
        signal?: AbortSignal,
      ) => { progressReads++; progressSignal = signal; throw new SignalProgressUnsupported() },
      fetchAnswer: async (_sessionId: string, signal?: AbortSignal) => {
        answerReads++; answerSignal = signal; return VALID_ANSWER
      },
      fetchIce: async (_sessionId: string, _since: number, signal?: AbortSignal) => {
        iceReads++; iceSignal = signal; return { candidates: [], nextSince: 0 }
      },
    })
    await fallback.connect()
    await flushUntil(() => fallbackPeer.remoteCalls === 1 && iceReads === 1, 'legacy compatibility fallback')
    expect(progressReads).toBe(1)
    expect(answerReads).toBe(1)
    expect(iceReads).toBe(1)
    expect(answerSignal).toBe(progressSignal)
    expect(iceSignal).toBe(progressSignal)
    expect(progressSignal?.aborted).toBe(false)
    await vi.advanceTimersByTimeAsync(1)
    expect(progressReads).toBe(1)
    fallback.close()
  })

  it('never turns typed dead or answer-status regression into legacy fallback', async () => {
    const deadPeer = new ControlledPeer()
    const deadStates: ControlState[] = []
    let deadLegacyReads = 0
    const dead = combinedBridge(deadPeer, {
      fetchProgress: async () => { throw new SignalSessionDead('sig-combined', 404) },
      fetchAnswer: async () => { deadLegacyReads++; return null },
      fetchIce: async () => { deadLegacyReads++; return { candidates: [], nextSince: 0 } },
    }, deadStates)
    await dead.connect()
    await flushUntil(() => deadStates.includes('offline'), 'typed dead progress')
    expect(deadLegacyReads).toBe(0)

    vi.useFakeTimers()
    const regressionPeer = new ControlledPeer()
    const regressionStates: ControlState[] = []
    let calls = 0
    let regressionLegacyReads = 0
    const regression = combinedBridge(regressionPeer, {
      fetchProgress: async () => {
        calls++
        return calls === 1
          ? {
              status: 'answered', expiresAtMs: 9_999_999_999_999, answer: VALID_ANSWER,
              candidates: [], nextSince: 0,
            }
          : {
              status: 'pending', expiresAtMs: 9_999_999_999_999,
              candidates: [{ candidate: VALID_CANDIDATE, seq: 1 }], nextSince: 1,
            }
      },
      fetchAnswer: async () => { regressionLegacyReads++; return null },
      fetchIce: async () => { regressionLegacyReads++; return { candidates: [], nextSince: 0 } },
    }, regressionStates)
    await regression.connect()
    await flushUntil(() => regressionPeer.remoteCalls === 1, 'first verified combined answer')
    await vi.advanceTimersByTimeAsync(1)
    await flushUntil(() => regressionStates.includes('offline'), 'answer status regression failure')
    expect(regressionPeer.iceCalls).toBe(0)
    expect(regressionLegacyReads).toBe(0)
  })
})
