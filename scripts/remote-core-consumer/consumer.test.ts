import { afterEach, expect, it, vi } from 'vitest'
import { generateKeyPairSync, sign } from 'node:crypto'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import postcss from 'postcss'
import { WebrtcBridge } from '@hydraterm/remote-browser-core'
import { SignalSessionDead, type SignalingPort } from '@hydraterm/remote-browser-core/signaling'
import { StableSetupRefusal } from '@hydraterm/remote-browser-core/refusal'
import type { ControlState } from '@hydraterm/remote-browser-core/transport'
import { SESSION_TTL_MS } from '@hydraterm/signaling-broker-core'
import { fixture } from './broker-fixture.js'
import { createTransport, currentAuthority } from './browser-consumer.js'
import { createEngine, createHttpAdapters, encodePaste, AGENT_PROVIDERS } from './browser-consumer.js'
import { StubDeviceIdentity } from '@hydraterm/remote-browser-core/identity'
import type { AuthProvider } from '@hydraterm/remote-browser-core/auth'

const bridges: WebrtcBridge[] = []
afterEach(() => {
  for (const bridge of bridges.splice(0)) bridge.close()
  vi.restoreAllMocks()
})
const accountId = 'synthetic-account'
const fingerprint = Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, '0')).join(':')

it.each(['absolute', 'relative'] as const)('does not disclose an external source map through %s CSS paths', async kind => {
  const root = mkdtempSync(join(tmpdir(), 'hydra-postcss-regression-'))
  try {
    const input = join(root, 'input')
    mkdirSync(input)
    const map = join(root, 'outside.map')
    const marker = 'HYDRA_SYNTHETIC_SOURCE_MAP_CONTENT'
    writeFileSync(map, JSON.stringify({ version: 3, sources: ['outside.ts'], sourcesContent: [marker], names: [], mappings: 'AAAA' }))
    const annotation = kind === 'absolute' ? map : '../outside.map'
    const result = await postcss().process(`a{color:red}\n/*# sourceMappingURL=${annotation} */`, {
      from: kind === 'absolute' ? undefined : join(input, 'input.css'),
      map: { inline: false, annotation: false },
    })
    expect(result.css).toContain('color:red')
    expect(result.map?.toString() ?? '').not.toContain(marker)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})

function consumer() {
  const { broker, advance } = fixture()
  const desktop = generateKeyPairSync('ed25519')
  const browser = generateKeyPairSync('ed25519')
  const publicKey = Buffer.from(desktop.publicKey.export({ format: 'jwk' }).x!, 'base64url').toString('base64')
  const channel = {
    binaryType: 'arraybuffer', readyState: 'connecting', bufferedAmount: 0, bufferedAmountLowThreshold: 0,
    onopen: null as (() => void) | null,
    onmessage: null as ((event: MessageEvent) => void) | null,
    onclose: null as (() => void) | null,
    send: vi.fn(), close: vi.fn(() => { channel.readyState = 'closed' }),
  }
  const peer = {
    connectionState: 'new', iceConnectionState: 'new', currentRemoteDescription: null as RTCSessionDescriptionInit | null,
    createDataChannel: () => channel,
    createOffer: async () => ({ type: 'offer', sdp: `v=0\r\na=fingerprint:sha-256 ${fingerprint}\r\n` }),
    setLocalDescription: async () => {},
    setRemoteDescription: vi.fn(async (description: RTCSessionDescriptionInit) => { peer.currentRemoteDescription = description }),
    addIceCandidate: vi.fn(async () => {}), getStats: async () => new Map(),
    close: vi.fn(() => { peer.connectionState = 'closed' }),
  }
  let currentSession = ''
  const fetchAnswer = vi.fn(async (sessionId: string) => (await broker.getSession(accountId, 'browser', sessionId)).answer ?? null)
  const cancel = vi.fn(async (sessionId: string) => { await broker.cancel(accountId, 'browser', sessionId) })
  const port: SignalingPort = {
    createSession: async (targetDeviceId, offer) => {
      const row = await broker.createSession({ accountId, sourceDeviceId: 'browser', targetDeviceId, offer })
      currentSession = row.sessionId
      const signature = sign(null, Buffer.from(`hydra-webrtc-answer-v1:${row.sessionId}:desktop:${fingerprint}`), desktop.privateKey).toString('base64')
      await broker.answer({ accountId, deviceId: 'desktop', sessionId: row.sessionId, answer: JSON.stringify({
        type: 'answer', sdp: `v=0\r\na=fingerprint:sha-256 ${fingerprint}\r\n`,
        hydra_answer_proof: { version: 1, device_id: 'desktop', signal_session_id: row.sessionId, fingerprint, signature },
      }) })
      return row.sessionId
    },
    fetchAnswer,
    postIce: async (sessionId, candidate) => { await broker.addIce({ accountId, deviceId: 'browser', sessionId, candidate }) },
    fetchIce: async (sessionId, since) => broker.iceSince({ accountId, deviceId: 'browser', sessionId, since }),
    fetchProgress: async (sessionId, since, answerSeen) => broker.progress({ accountId, deviceId: 'browser', sessionId, since, answerSeen }),
    cancel,
  }
  const mintToken = vi.fn(async (sessionId: string) => {
    expect(sessionId).toBe(currentSession)
    return { token: 'synthetic-session-bound-authority', expiresAtMs: Date.now() + 60_000, deadlineMs: Date.now() + 60_000 }
  })
  const signOffer = vi.fn(async (challenge: string) => ({
    pop: sign(null, Buffer.from(challenge), browser.privateKey).toString('base64'), alg: 'ed25519' as const,
  }))
  // Synthetic peer only: this record is NOT an enrolled-agent certificate. Actual self-host composition
  // must provide valid enrolled passkey proof and authenticated bound authority; no agent is tested here.
  const browserCert = vi.fn(async () => ({ synthetic_fixture_only: true }))
  const bridge = createTransport(port, {
    targetDeviceId: 'desktop', targetDevicePublicKeyB64: publicKey, browserDeviceId: 'browser',
    peerFactory: () => peer as unknown as RTCPeerConnection,
    signOffer, browserCert, mintToken, requireSessionBoundToken: true,
  })
  bridges.push(bridge)
  const states: ControlState[] = []
  bridge.onState(state => states.push(state))
  return { broker, port, bridge, states, peer, channel, cancel, fetchAnswer, mintToken, signOffer, browserCert, advance, session: () => currentSession }
}

it('uses installed browser and broker packages together with real pinned answer proof and retained owner cleanup', async () => {
  const http = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('No HTTP allowed in synthetic consumer'))
  const c = consumer()
  await c.bridge.connect()
  await vi.waitFor(() => expect(c.peer.setRemoteDescription).toHaveBeenCalledOnce())
  expect(c.signOffer).toHaveBeenCalledOnce()
  expect(c.browserCert).toHaveBeenCalledOnce()
  expect(c.mintToken).toHaveBeenCalledOnce()
  // Refreshable authorization is deliberately absent without a refresh adapter; initial auth uses currentToken.
  expect(currentAuthority(c.bridge)).toBeNull()
  expect(c.bridge.currentToken()).toBe('synthetic-session-bound-authority')
  c.channel.readyState = 'open'
  c.peer.connectionState = 'connected'
  c.channel.onopen!()
  expect(c.states.at(-1)).toBe('connected')
  expect(c.bridge.sendText('synthetic-peer-only-control')).toBe(true)
  expect(c.channel.send).toHaveBeenCalledWith('synthetic-peer-only-control')
  const staleOpen = c.channel.onopen!
  c.bridge.close()
  const retired = [...c.states]
  staleOpen()
  expect(c.states).toEqual(retired)
  expect(c.cancel).toHaveBeenCalledExactlyOnceWith(c.session())
  await expect(c.broker.getSession(accountId, 'browser', c.session())).rejects.toMatchObject({ refusal: 'cancelled' })
  expect(c.bridge.currentToken()).toBeNull()
  expect(http).not.toHaveBeenCalled()
})

it('shares the packaged dead-session constructor across export entries without legacy fallback', async () => {
  const c = consumer()
  c.port.fetchProgress = async () => { throw new SignalSessionDead(c.session(), 409) }
  await c.bridge.connect()
  await vi.waitFor(() => expect(c.states).toContain('offline'))
  expect(c.fetchAnswer).not.toHaveBeenCalled()
  expect(c.peer.setRemoteDescription).not.toHaveBeenCalled()
  expect(c.cancel).toHaveBeenCalledExactlyOnceWith(c.session())
})

it('shares the explicit refusal constructor across entries; no implicit paywall or retry is added', async () => {
  const c = consumer()
  c.port.createSession = async () => { throw new StableSetupRefusal() }
  await c.bridge.connect()
  await vi.waitFor(() => expect(c.states).toContain('access_required'))
  expect(c.states).not.toContain('entitlement_required')
  expect(c.peer.setRemoteDescription).not.toHaveBeenCalled()
})

it('keeps broker account and expiry refusals in the installed artifact', async () => {
  const c = consumer()
  await expect(c.broker.createSession({ accountId: 'other-synthetic-account', sourceDeviceId: 'browser', targetDeviceId: 'desktop', offer: 'opaque' }))
    .rejects.toMatchObject({ refusal: 'cross_account' })
  const row = await c.broker.createSession({ accountId, sourceDeviceId: 'browser', targetDeviceId: 'desktop', offer: 'opaque' })
  c.advance(SESSION_TTL_MS)
  await expect(c.broker.getSession(accountId, 'browser', row.sessionId)).rejects.toMatchObject({ refusal: 'expired' })
})

it('runs the installed controller with injected auth without hosted SDKs or enrollment fallback', async () => {
  const absent = vi.fn(async () => null)
  const auth: AuthProvider = { signIn: absent, signUp: absent, restore: absent, resumeIdentitySession: absent,
    current: () => null, signOut: async () => {} }
  const prepareConnection = vi.fn(async () => { throw new Error('No enrollment in consumer') })
  const makeTransport = vi.fn((): never => { throw new Error('No connection in consumer') })
  const engine = createEngine({ auth, identity: new StubDeviceIdentity('synthetic-consumer'),
    listDesktops: async () => [], issueLinkCode: async () => null, revokeDevice: async () => false,
    prepareConnection, makeTransport, reconnectLifecycle: null })
  try {
    await engine.restoreSession()
    expect(engine.snapshot().phase).toBe('signed_out')
    expect(prepareConnection).not.toHaveBeenCalled()
    expect(makeTransport).not.toHaveBeenCalled()
  } finally { engine.dispose() }
})

it('uses the installed explicit HTTP adapters with injected fetch, without making network requests', async () => {
  const fetchImpl = vi.fn<typeof fetch>()
    .mockResolvedValueOnce(new Response(JSON.stringify({ sessionId: 'synthetic-session' }), { status: 201 }))
    .mockResolvedValueOnce(new Response(JSON.stringify({ layout: null }), { status: 200 }))
  const adapters = createHttpAdapters({ baseUrl: 'https://signal.invalid', authToken: 'synthetic-test-authority', deviceId: 'browser' },
    { baseUrl: 'https://layout.invalid', authToken: 'cookie' }, fetchImpl)
  try {
    expect(await adapters.signaling.createSession('desktop', 'opaque-offer')).toBe('synthetic-session')
    expect(fetchImpl.mock.calls[0][0]).toBe('https://signal.invalid/v1/signal/sessions')
    expect(fetchImpl.mock.calls[0][1]?.headers).toMatchObject({ authorization: 'Bearer synthetic-test-authority' })
    expect(await adapters.layout.fetchLayout('desktop')).toBeNull()
    expect(fetchImpl.mock.calls[1][1]?.credentials).toBe('include')
    expect(fetchImpl.mock.calls[1][1]?.headers).toBeUndefined()
  } finally { adapters.layout.dispose() }
})

it('keeps terminal paste encoding and icon-free provider metadata in the installed engine', () => {
  expect(encodePaste('synthetic', true)).toBe('\u001b[200~synthetic\u001b[201~')
  expect(Object.values(AGENT_PROVIDERS).every(provider => !provider.icon)).toBe(true)
})
