import { afterEach, describe, expect, it, vi } from 'vitest'
import { StableSetupRefusal, isStableSetupRefusal, type SetupRefusalState } from './setup-refusal-contract'
import type { SignalingPort } from './signaling-contract'
import type { AuthProvider } from './auth-contract'
import type { ControlState } from './remote-transport'
import { WebrtcBridge } from './webrtc-bridge'
import { RemoteClientController } from './remote-client'
import { StubDeviceIdentity } from './device-identity'

vi.mock('./remote-entitlement', () => { throw new Error('hosted policy entered neutral refusal consumer') })
vi.mock('./auth-provider', () => { throw new Error('hosted identity entered neutral refusal consumer') })

const bridges: WebrtcBridge[] = []
const controllers: RemoteClientController[] = []
afterEach(() => {
  for (const controller of controllers.splice(0)) controller.dispose()
  for (const bridge of bridges.splice(0)) bridge.close()
  vi.restoreAllMocks()
})

function portFixture() {
  const createSession = vi.fn(async () => 'synthetic-signal')
  const fetchAnswer = vi.fn(async (): Promise<string | null> => null)
  const fetchIce = vi.fn(async () => ({ candidates: [], nextSince: 0 }))
  const postIce = vi.fn(async () => {})
  const cancel = vi.fn(async () => {})
  const port: SignalingPort = { createSession, fetchAnswer, fetchIce, postIce, cancel }
  return { port, createSession, fetchAnswer, fetchIce, cancel }
}

function peerFixture() {
  const channel = { readyState: 'connecting', close: vi.fn(), send: vi.fn() }
  const peer = {
    connectionState: 'new', iceConnectionState: 'new', currentRemoteDescription: null,
    createDataChannel: () => channel,
    createOffer: async () => ({ type: 'offer', sdp: 'v=0\r\n' }),
    setLocalDescription: async () => {},
    close: vi.fn(),
  }
  const factory = vi.fn(() => peer as unknown as RTCPeerConnection)
  return { channel, peer, factory }
}

function observe(bridge: WebrtcBridge): ControlState[] {
  bridges.push(bridge)
  const states: ControlState[] = []
  bridge.onState((state) => states.push(state))
  return states
}

describe('provider-neutral stable setup refusal', () => {
  it('recognizes only nominal refusals carrying a closed local state', () => {
    const neutral = new StableSetupRefusal()
    expect(neutral.state).toBe('access_required')
    expect(neutral.message).toBe('remote_access_required')
    expect(isStableSetupRefusal(neutral)).toBe(true)
    expect(isStableSetupRefusal(new StableSetupRefusal('entitlement_required'))).toBe(true)
    expect(isStableSetupRefusal({ name: 'StableSetupRefusal', state: 'access_required' })).toBe(false)
    expect(isStableSetupRefusal(new Error('remote_access_required'))).toBe(false)
    expect(isStableSetupRefusal(new StableSetupRefusal('connected' as SetupRefusalState))).toBe(false)
  })

  it.each([false, true])('explicit relay refusal has no peer or fallback (forceRelay=%s)', async (forceRelay) => {
    const http = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('unexpected HTTP'))
    const adapter = portFixture()
    const fixture = peerFixture()
    const bridge = new WebrtcBridge({
      signaling: adapter.port, targetDeviceId: 'synthetic-desktop', forceRelay,
      fetchRelayCreds: async () => { throw new StableSetupRefusal() }, peerFactory: fixture.factory,
    })
    const states = observe(bridge)
    await bridge.connect()
    expect(states).toEqual(['connecting', 'access_required'])
    expect(fixture.factory).not.toHaveBeenCalled()
    expect(adapter.createSession).not.toHaveBeenCalled()
    expect(http).not.toHaveBeenCalled()
  })

  it.each(['signaling', 'mint'] as const)('alternate port %s refusal retires exact setup without a token', async (stage) => {
    const http = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('unexpected HTTP'))
    const adapter = portFixture()
    if (stage === 'signaling') adapter.createSession.mockRejectedValue(new StableSetupRefusal())
    const fixture = peerFixture()
    const mint = vi.fn(async () => { throw new StableSetupRefusal() })
    const bridge = new WebrtcBridge({
      signaling: adapter.port, targetDeviceId: 'synthetic-desktop', peerFactory: fixture.factory,
      requireSessionBoundToken: true, mintToken: mint,
    })
    const states = observe(bridge)
    await bridge.connect()
    expect(states).toEqual(['connecting', 'access_required'])
    expect(fixture.factory).toHaveBeenCalledOnce()
    expect(fixture.channel.close).toHaveBeenCalledOnce()
    expect(fixture.peer.close).toHaveBeenCalledOnce()
    expect(bridge.currentToken()).toBeNull()
    expect(adapter.fetchAnswer).not.toHaveBeenCalled()
    expect(adapter.fetchIce).not.toHaveBeenCalled()
    if (stage === 'signaling') {
      expect(mint).not.toHaveBeenCalled()
      expect(adapter.cancel).not.toHaveBeenCalled()
    } else {
      expect(mint).toHaveBeenCalledWith('synthetic-signal', expect.any(AbortSignal))
      expect(adapter.cancel).toHaveBeenCalledExactlyOnceWith('synthetic-signal')
    }
    expect(http).not.toHaveBeenCalled()
  })

  it('a closed setup ignores a late neutral refusal from its owned signaling port', async () => {
    let reject!: (error: Error) => void
    const adapter = portFixture()
    adapter.createSession.mockImplementation(() => new Promise((_resolve, decline) => { reject = decline }))
    const fixture = peerFixture()
    const bridge = new WebrtcBridge({
      signaling: adapter.port, targetDeviceId: 'synthetic-desktop', peerFactory: fixture.factory,
    })
    const states = observe(bridge)
    const pending = bridge.connect()
    await vi.waitFor(() => expect(adapter.createSession).toHaveBeenCalledOnce())
    bridge.close()
    const retired = [...states]
    reject(new StableSetupRefusal())
    await pending
    expect(states).toEqual(retired)
    expect(states).not.toContain('access_required')
    expect(fixture.channel.close).toHaveBeenCalledOnce()
    expect(fixture.peer.close).toHaveBeenCalledOnce()
  })

  it('passes a real alternate-port refusal through the controller without hosted policy or HTTP', async () => {
    const http = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('unexpected HTTP'))
    const session = { accountId: 'synthetic-principal', credential: 'synthetic-session-marker' }
    const auth: AuthProvider = {
      signIn: async () => session, signUp: async () => null, restore: async () => null,
      resumeIdentitySession: async () => null, current: () => session, signOut: async () => {},
    }
    const adapter = portFixture()
    adapter.createSession.mockRejectedValue(new StableSetupRefusal())
    const fixture = peerFixture()
    const controller = new RemoteClientController({
      auth, identity: new StubDeviceIdentity('synthetic-browser'),
      listDesktops: async () => [{ deviceId: 'synthetic-desktop', label: 'Synthetic', revoked: false }],
      issueLinkCode: async () => { throw new Error('unexpected enrollment') }, revokeDevice: async () => false,
      legacyMintToken: async () => 'synthetic-authority-marker', reconnectLifecycle: null,
      makeTransport: (targetDeviceId, onMode) => {
        const bridge = new WebrtcBridge({ signaling: adapter.port, targetDeviceId, onMode, peerFactory: fixture.factory })
        bridges.push(bridge)
        return { transport: bridge, connect: () => bridge.connect() }
      },
    })
    controllers.push(controller)
    await controller.signIn()
    await controller.connectTo('synthetic-desktop')
    expect(adapter.createSession).toHaveBeenCalledOnce()
    expect(controller.snapshot()).toMatchObject({
      phase: 'offline', selectedDevice: 'synthetic-desktop', nextRetryAtMs: undefined,
      error: 'Remote access was declined. Check access with your service, then tap Reconnect to try again.',
    })
    await controller.reconnect()
    expect(adapter.createSession).toHaveBeenCalledTimes(2)
    expect(controller.snapshot().phase).toBe('offline') // the explicit retry does not bypass the adapter's refusal
    expect(http).not.toHaveBeenCalled()
  })
})
