import { afterEach, describe, expect, it, vi } from 'vitest'
import { generateKeyPairSync, sign } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'vite'
import ts from 'typescript'
import { SignalSessionDead, type SignalingPort } from './signaling-contract'
import { WebrtcBridge } from './webrtc-bridge'
import type { ControlState } from './remote-transport'

const bridges: WebrtcBridge[] = []
afterEach(() => {
  for (const bridge of bridges.splice(0)) bridge.close()
  vi.restoreAllMocks()
})

const SESSION_ID = 'synthetic-signal-session'
const DEVICE_ID = 'synthetic-desktop'
const FINGERPRINT = Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, '0')).join(':')

function signedAnswer() {
  // Fresh in-memory fixture key; no static private key, account credential or external signing service.
  const pair = generateKeyPairSync('ed25519')
  const jwk = pair.publicKey.export({ format: 'jwk' })
  const publicKeyB64 = Buffer.from(jwk.x!, 'base64url').toString('base64')
  const signature = sign(null, Buffer.from(
    `hydra-webrtc-answer-v1:${SESSION_ID}:${DEVICE_ID}:${FINGERPRINT}`,
  ), pair.privateKey).toString('base64')
  return {
    publicKeyB64,
    answer: JSON.stringify({
      type: 'answer',
      sdp: `v=0\r\na=fingerprint:sha-256 ${FINGERPRINT}\r\n`,
      hydra_answer_proof: {
        version: 1, device_id: DEVICE_ID, signal_session_id: SESSION_ID,
        fingerprint: FINGERPRINT, signature,
      },
    }),
  }
}

function peerFixture() {
  const channel = {
    binaryType: 'arraybuffer', readyState: 'connecting', bufferedAmount: 0, bufferedAmountLowThreshold: 0,
    onopen: null as (() => void) | null,
    onmessage: null as ((event: MessageEvent) => void) | null,
    onclose: null as (() => void) | null,
    send: vi.fn(),
    close: vi.fn(() => { channel.readyState = 'closed' }),
  }
  const peer = {
    connectionState: 'new', iceConnectionState: 'new',
    currentRemoteDescription: null as RTCSessionDescriptionInit | null,
    createDataChannel: () => channel,
    createOffer: async () => ({ type: 'offer', sdp: `v=0\r\na=fingerprint:sha-256 ${FINGERPRINT}\r\n` }),
    setLocalDescription: async () => {},
    setRemoteDescription: vi.fn(async (description: RTCSessionDescriptionInit) => {
      peer.currentRemoteDescription = description
    }),
    addIceCandidate: vi.fn(async () => {}),
    getStats: async () => new Map(),
    close: vi.fn(() => { peer.connectionState = 'closed' }),
  }
  return { channel, peer, peerFactory: () => peer as unknown as RTCPeerConnection }
}

function memoryPort(answer: string) {
  const createSession = vi.fn(async (_target: string, _offer: string, _signal?: AbortSignal) => SESSION_ID)
  const fetchAnswer = vi.fn(async (_session: string, _signal?: AbortSignal) => answer)
  const fetchIce = vi.fn(async (_session: string, since: number, _signal?: AbortSignal) => ({ candidates: [], nextSince: since }))
  const postIce = vi.fn(async (_session: string, _candidate: string, _signal?: AbortSignal) => {})
  const cancel = vi.fn(async (_session: string, _signal?: AbortSignal) => {})
  const port: SignalingPort = { createSession, fetchAnswer, fetchIce, postIce, cancel }
  return { port, createSession, fetchAnswer, fetchIce, postIce, cancel }
}

describe('provider-neutral signaling port', () => {
  it('emits the complete browser declaration closure for strict NodeNext consumers', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hydra-core-declarations-'))
    try {
      await writeFile(join(root, 'package.json'), '{"type":"module"}\n')
      const options: ts.CompilerOptions = {
        target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext,
        moduleResolution: ts.ModuleResolutionKind.Bundler, strict: true,
        skipLibCheck: false, types: [],
        lib: ['lib.es2022.d.ts', 'lib.dom.d.ts', 'lib.dom.iterable.d.ts'],
        rootDir: fileURLToPath(new URL('../', import.meta.url)), outDir: join(root, 'types'),
        declaration: true, emitDeclarationOnly: true, noEmitOnError: true,
      }
      const host = ts.createCompilerHost(options)
      const emitted: string[] = []
      const write = host.writeFile.bind(host)
      host.writeFile = (name, ...args) => { emitted.push(name); write(name, ...args) }
      const program = ts.createProgram([fileURLToPath(new URL('./webrtc-bridge.ts', import.meta.url))], options, host)
      const describeDiagnostics = (checked: ts.Program) => ts.getPreEmitDiagnostics(checked)
        .map((diagnostic) => ({ code: diagnostic.code, message: ts.flattenDiagnosticMessageText(diagnostic.messageText, '\n') }))
      expect(describeDiagnostics(program)).toEqual([])
      expect(program.emit().emitSkipped).toBe(false)
      expect(emitted).toHaveLength(11)
      expect(emitted.every((name) => name.endsWith('.d.ts'))).toBe(true)
      const consumer = ts.createProgram(emitted, {
        target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.NodeNext,
        moduleResolution: ts.ModuleResolutionKind.NodeNext, strict: true,
        noEmit: true, skipLibCheck: false, types: [], lib: options.lib,
      })
      expect(describeDiagnostics(consumer)).toEqual([])
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })

  it('bundles the actual bridge without the hosted signaling or identity adapters', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hydra-signaling-port-'))
    try {
      const result = await build({
        configFile: false, root, envDir: root, publicDir: false,
        cacheDir: join(root, 'cache'), logLevel: 'silent',
        plugins: [{
          name: 'reject-hosted-signaling-imports',
          resolveId(id) {
            if (/(?:^|\/)(?:signaling-client|auth-provider|remote-entitlement|clerk-[^/]*)(?:\.|$)|^@clerk\//.test(id)) {
              throw new Error('hosted adapter entered neutral signaling consumer')
            }
          },
        }],
        build: {
          write: false, minify: false,
          lib: { entry: fileURLToPath(new URL('./webrtc-bridge.ts', import.meta.url)), formats: ['es'] },
        },
      })
      const modules = (Array.isArray(result) ? result : [result]).flatMap((bundle) => {
        if (!('output' in bundle)) throw new Error('unexpected watch build')
        return bundle.output.flatMap((chunk) => chunk.type === 'chunk' ? Object.keys(chunk.modules) : [])
      })
      expect(modules.some((id) => id.endsWith('/webrtc-bridge.ts'))).toBe(true)
      expect(modules.some((id) => id.endsWith('/signaling-contract.ts'))).toBe(true)
      expect(modules.some((id) => id.endsWith('/setup-refusal-contract.ts'))).toBe(true)
      expect(modules.some((id) => /signaling-client|auth-provider|remote-entitlement|clerk/i.test(id))).toBe(false)
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })

  it.each(['separate', 'combined'] as const)('uses a non-HTTP %s port with pinned proof and owned retirement', async (mode) => {
    const http = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('unexpected HTTP request'))
    const { answer, publicKeyB64 } = signedAnswer()
    const fixture = peerFixture()
    const adapter = memoryPort(answer)
    const fetchProgress = vi.fn(async (_session: string, _since: number, _seen: boolean, _signal?: AbortSignal) => ({
      status: 'answered', expiresAtMs: Date.now() + 60_000, answer, candidates: [], nextSince: 0,
    }))
    if (mode === 'combined') adapter.port.fetchProgress = fetchProgress
    const mintToken = vi.fn(async (_session: string) => 'synthetic-bound-authority')
    const states: ControlState[] = []
    const messages: string[] = []
    const bridge = new WebrtcBridge({
      signaling: adapter.port, targetDeviceId: DEVICE_ID, targetDevicePublicKeyB64: publicKeyB64,
      peerFactory: fixture.peerFactory, requireSessionBoundToken: true, mintToken,
    })
    bridges.push(bridge)
    bridge.onState((state) => states.push(state))
    bridge.onText((message) => messages.push(message))
    await bridge.connect()
    await vi.waitFor(() => expect(fixture.peer.setRemoteDescription).toHaveBeenCalledOnce())
    expect(adapter.createSession).toHaveBeenCalledOnce()
    expect(adapter.createSession.mock.calls[0]![0]).toBe(DEVICE_ID)
    expect(JSON.parse(adapter.createSession.mock.calls[0]![1]).type).toBe('offer')
    expect(mintToken).toHaveBeenCalledWith(SESSION_ID, expect.any(AbortSignal))
    expect(bridge.currentToken()).toBe('synthetic-bound-authority')
    const pollSignal = mode === 'combined'
      ? fetchProgress.mock.calls[0]![3]
      : adapter.fetchAnswer.mock.calls[0]![1]
    expect(pollSignal?.aborted).toBe(false)
    if (mode === 'combined') {
      expect(adapter.fetchAnswer).not.toHaveBeenCalled()
      expect(adapter.fetchIce).not.toHaveBeenCalled()
    } else {
      expect(fetchProgress).not.toHaveBeenCalled()
      expect(adapter.fetchIce).toHaveBeenCalledWith(SESSION_ID, 0, pollSignal)
    }

    fixture.channel.readyState = 'open'
    fixture.peer.connectionState = 'connected'
    fixture.channel.onopen!()
    expect(states.at(-1)).toBe('connected')
    expect(pollSignal?.aborted).toBe(true)
    expect(bridge.sendText('synthetic-terminal-control')).toBe(true)
    expect(fixture.channel.send).toHaveBeenCalledWith('synthetic-terminal-control')
    fixture.channel.onmessage!(new MessageEvent('message', { data: 'synthetic-terminal-response' }))
    expect(messages).toEqual(['synthetic-terminal-response'])
    expect(JSON.stringify(adapter.createSession.mock.calls)).not.toContain('synthetic-terminal-control')
    expect(adapter.postIce).not.toHaveBeenCalled()
    expect(http).not.toHaveBeenCalled()

    const staleOpen = fixture.channel.onopen!
    const staleMessage = fixture.channel.onmessage!
    bridge.close()
    const retiredStates = [...states]
    bridge.close()
    staleOpen()
    staleMessage(new MessageEvent('message', { data: 'stale-owner-response' }))
    expect(states).toEqual(retiredStates)
    expect(messages).toEqual(['synthetic-terminal-response'])
    expect(adapter.cancel).toHaveBeenCalledExactlyOnceWith(SESSION_ID)
    expect(fixture.peer.close).toHaveBeenCalledOnce()
    expect(bridge.currentToken()).toBeNull()
  })

  it('does not treat a neutral dead-session error as a progress capability miss', async () => {
    const fixture = peerFixture()
    const adapter = memoryPort('unused')
    adapter.port.fetchProgress = async () => { throw new SignalSessionDead(SESSION_ID, 409) }
    const states: ControlState[] = []
    const bridge = new WebrtcBridge({
      signaling: adapter.port, targetDeviceId: DEVICE_ID, peerFactory: fixture.peerFactory,
    })
    bridges.push(bridge)
    bridge.onState((state) => states.push(state))
    await bridge.connect()
    await vi.waitFor(() => expect(states).toContain('offline'))
    expect(adapter.fetchAnswer).not.toHaveBeenCalled()
    expect(adapter.fetchIce).not.toHaveBeenCalled()
    expect(fixture.peer.setRemoteDescription).not.toHaveBeenCalled()
    expect(adapter.cancel).toHaveBeenCalledExactlyOnceWith(SESSION_ID)
  })
})
