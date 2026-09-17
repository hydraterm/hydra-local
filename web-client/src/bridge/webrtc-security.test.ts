import { describe, expect, it, vi } from 'vitest'
import { generateKeyPairSync, sign } from 'node:crypto'
import { WebrtcBridge } from './webrtc-bridge'
import type { SignalingPort } from './signaling-contract'
import type { ConnectionAttemptPhase, ControlState } from './remote-transport'

function signalingWithAnswer(answer: string): SignalingPort {
  return {
    createSession: async () => 'sig_1',
    fetchAnswer: async () => answer,
    fetchIce: async (_sessionId: string, since: number) => ({ candidates: [], nextSince: since }),
    postIce: async () => {},
    cancel: async () => {},
  } as unknown as SignalingPort
}

function peerWithRemoteRecorder(record: { setRemoteCalls: number; closed: boolean }): RTCPeerConnection {
  let remoteDescription: RTCSessionDescriptionInit | null = null
  const pc: any = {
    createDataChannel: () => ({ binaryType: '', send: () => {}, close: () => {}, readyState: 'connecting' }),
    createOffer: async () => ({ type: 'offer', sdp: 'v=0\r\n' }),
    setLocalDescription: async () => {},
    setRemoteDescription: async (description: RTCSessionDescriptionInit) => {
      remoteDescription = description
      record.setRemoteCalls++
    },
    addIceCandidate: async () => {},
    getStats: async () => new Map(),
    close: () => { record.closed = true },
    get currentRemoteDescription() {
      return remoteDescription
    },
  }
  return pc as RTCPeerConnection
}

describe('WebrtcBridge SDP signaling hardening', () => {
  it('fails closed when the signaling answer omits a modern SHA-256 DTLS fingerprint', async () => {
    const record = { setRemoteCalls: 0, closed: false }
    const states: ControlState[] = []
    const modes: string[] = []
    const bridge = new WebrtcBridge({
      signaling: signalingWithAnswer(JSON.stringify({ type: 'answer', sdp: 'v=0\r\n' })),
      targetDeviceId: 'dev_desk',
      directTimeoutMs: 100,
      backoff: { fastMs: 1, idleMs: 1, staleTimeoutMs: 1000 },
      peerFactory: () => peerWithRemoteRecorder(record),
      onMode: (mode) => modes.push(mode),
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    await Promise.resolve()
    await Promise.resolve()

    expect(record.setRemoteCalls).toBe(0)
    expect(record.closed).toBe(true)
    expect(states).toContain('offline')
    expect(modes).toContain('failed')
  })

  it('fails closed when signaling returns an offer-shaped answer payload', async () => {
    const record = { setRemoteCalls: 0, closed: false }
    const states: ControlState[] = []
    const validSdp = [
      'v=0',
      'a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99',
      '',
    ].join('\r\n')
    const bridge = new WebrtcBridge({
      signaling: signalingWithAnswer(JSON.stringify({ type: 'offer', sdp: validSdp })),
      targetDeviceId: 'dev_desk',
      directTimeoutMs: 100,
      backoff: { fastMs: 1, idleMs: 1, staleTimeoutMs: 1000 },
      peerFactory: () => peerWithRemoteRecorder(record),
    })
    bridge.onState((state) => states.push(state))

    await bridge.connect()
    await Promise.resolve()
    await Promise.resolve()

    expect(record.setRemoteCalls).toBe(0)
    expect(record.closed).toBe(true)
    expect(states).toContain('offline')
  })

  it('fails a pre-open attempt rather than continuing with an incomplete malformed ICE set', async () => {
    const added: unknown[] = []
    const states: ControlState[] = []
    const phases: ConnectionAttemptPhase[] = []
    const record = { setRemoteCalls: 0, closed: false }
    const pc = peerWithRemoteRecorder(record) as any
    pc.addIceCandidate = async (init: unknown) => { added.push(init) }
    const sessionId = 'synthetic-ice-session'
    const deviceId = 'synthetic-ice-desktop'
    const fingerprint = Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, '0')).join(':')
    // Fresh in-memory fixture key: use the real answer verifier without a policy escape.
    const pair = generateKeyPairSync('ed25519')
    const jwk = pair.publicKey.export({ format: 'jwk' })
    const publicKeyB64 = Buffer.from(jwk.x!, 'base64url').toString('base64')
    const signature = sign(null, Buffer.from(
      `hydra-webrtc-answer-v1:${sessionId}:${deviceId}:${fingerprint}`,
    ), pair.privateKey).toString('base64')
    const validAnswer = JSON.stringify({
      type: 'answer',
      sdp: `v=0\r\na=fingerprint:sha-256 ${fingerprint}\r\n`,
      hydra_answer_proof: {
        version: 1, device_id: deviceId, signal_session_id: sessionId, fingerprint, signature,
      },
    })
    let releaseIce!: (response: unknown) => void
    const iceResponse = new Promise<unknown>((resolve) => { releaseIce = resolve })
    let iceReads = 0
    const signaling = {
      createSession: async () => sessionId,
      fetchAnswer: async () => validAnswer,
      // Answer and ICE polls start concurrently; hold ICE until authenticated installation is proved.
      fetchIce: async (_s: string, since: number) => {
        iceReads++
        return iceReads === 1 ? iceResponse : { candidates: [], nextSince: since }
      },
      postIce: async () => {},
      cancel: async () => {},
    } as unknown as SignalingPort

    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: deviceId,
      targetDevicePublicKeyB64: publicKeyB64,
      directTimeoutMs: 100,
      backoff: { fastMs: 1, idleMs: 1, staleTimeoutMs: 1000 },
      peerFactory: () => pc as RTCPeerConnection,
    })
    bridge.onState((state) => states.push(state))
    bridge.onConnectionPhase((phase) => phases.push(phase))
    try {
      await bridge.connect()
      await vi.waitFor(() => expect(phases).toContain('remote_description_set'))
      expect(record.setRemoteCalls).toBe(1)
      expect(pc.currentRemoteDescription?.type).toBe('answer')
      expect(iceReads).toBe(1)
      expect(record.closed).toBe(false)
      expect(states).not.toContain('offline')
      expect(added).toEqual([])

      releaseIce({
        candidates: [
          { candidate: 'not-json-at-all', seq: 1 },
          { candidate: JSON.stringify({ sdpMid: '0' }), seq: 2 }, // missing the candidate field
          { candidate: JSON.stringify({ candidate: 'candidate:1 1 udp 1 192.0.2.1 5 typ host', sdpMid: '0', sdpMLineIndex: 0 }), seq: 3 },
        ],
        nextSince: 3,
      })
      // Wait for processing, then distinguish rejection from accidentally admitting any candidate.
      await vi.waitFor(() => expect(record.closed || added.length > 0).toBe(true))
      expect.soft(added).toEqual([])
      expect.soft(phases).not.toContain('first_remote_ice')
      expect.soft(record.closed).toBe(true)
      expect.soft(states).toContain('offline')
    } finally {
      bridge.close()
    }
  })
})
