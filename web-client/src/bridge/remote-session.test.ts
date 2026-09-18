import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import {
  CREATION_DELIVERY_RETRY_MS,
  CREATION_REQUEST_REPLAY_CAPABILITY,
  DESKTOP_ACCESS_STATUS_CAPABILITY,
  AUTHORIZATION_REFRESH_CAPABILITY,
  AUTHORIZATION_REFRESH_LEAD_MS,
  AUTHORIZATION_REFRESH_ACK_TIMEOUT_MS,
  AUTHORIZATION_REFRESH_REQUEST_TIMEOUT_MS,
  parseAgentBuildGit,
  RemoteSession,
  SCROLLBACK_RESPONSE_TIMEOUT_MS,
} from './remote-session'
import { OrderedTerminalCodecDecoder } from './terminal-codec-decoder'
import {
  FakeTransport,
  MAX_BOUND_AUTHORIZATION_TTL_MS,
  parseBoundAuthorization,
  type ControlState,
} from './remote-transport'
import {
  decodeFrame,
  encodeFrame,
  encodeTerminalGzipChunkPayload,
  FrameKind,
  MAX_INPUT_PAYLOAD,
  TERMINAL_CODEC_CHUNK_BYTES,
  TERMINAL_GZIP_JSON_V1,
} from '../protocol/terminal-frame'
import { MAX_PASTE_BYTES } from '../terminal/input-encoder'
import { MAX_BROWSER_CONTROL_JSON_BYTES } from '../protocol/bounded-control-json'

function lastText(t: FakeTransport): Record<string, unknown> {
  return JSON.parse(t.sentText[t.sentText.length - 1]!)
}
function textsOfType(t: FakeTransport, type: string): Record<string, unknown>[] {
  return t.sentText.map((s) => JSON.parse(s)).filter((m) => m.type === type)
}
function emitAgentHello(t: FakeTransport, capabilities: unknown = ['viewed_resize_v1']): void {
  t.emitText(JSON.stringify({
    type: 'hello',
    protocol_version: 1,
    device_id: 'dev_desktop',
    role: 'agent',
    capabilities,
  }))
}

describe('RemoteSession — bounded control JSON admission', () => {
  it('delivers an agent-shaped exact-byte-ceiling frame through the bounded parser', () => {
    const transport = new FakeTransport()
    const sessions: string[][] = []
    new RemoteSession(transport, 'tok', 'dev_browser', {
      onSessions: (ids) => sessions.push(ids),
    })
    transport.emitState('connected')
    emitAgentHello(transport)
    transport.emitText(JSON.stringify({
      type: 'auth_ok',
      account_id: 'acct',
      device_id: 'dev_browser',
    }))

    const message = JSON.stringify({ type: 'session_list_result', sessions: ['s-1'] })
    const exact = message + ' '.repeat(MAX_BROWSER_CONTROL_JSON_BYTES - message.length)
    expect(new TextEncoder().encode(exact)).toHaveLength(MAX_BROWSER_CONTROL_JSON_BYTES)
    transport.emitText(exact)

    expect(transport.closed).toBe(false)
    expect(sessions).toEqual([['s-1']])
  })

  it('retires the transport before dispatching an over-budget agent frame', () => {
    const transport = new FakeTransport()
    const sessions: string[][] = []
    new RemoteSession(transport, 'tok', 'dev_browser', {
      onSessions: (ids) => sessions.push(ids),
    })

    transport.emitText(`{"type":"session_list_result","sessions":[],"padding":"${'x'.repeat(MAX_BROWSER_CONTROL_JSON_BYTES)}"}`)

    expect(transport.closed).toBe(true)
    expect(sessions).toEqual([])
  })
})

class RecordingGridContext {
  font = ''
  fillStyle = ''
  strokeStyle = ''
  lineWidth = 1
  textBaseline = ''
  globalAlpha = 1
  imageSmoothingEnabled = true
  readonly texts: string[] = []
  paintPasses = 0

  measureText() {
    return { width: 9, actualBoundingBoxAscent: 12, actualBoundingBoxDescent: 3 }
  }
  setTransform() {}
  save() { this.paintPasses++ }
  restore() {}
  fillRect() {}
  fillText(text: string) { this.texts.push(text) }
  beginPath() {}
  moveTo() {}
  lineTo() {}
  stroke() {}
}

function recordingCanvas(): { canvas: HTMLCanvasElement; context: RecordingGridContext } {
  const context = new RecordingGridContext()
  const canvas = {
    width: 0,
    height: 0,
    style: {},
    getContext: () => context,
  } as unknown as HTMLCanvasElement
  return { canvas, context }
}

async function gzipBytes(bytes: Uint8Array): Promise<Uint8Array> {
  const input = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes)
      controller.close()
    },
  })
  const transform = new CompressionStream('gzip') as unknown as TransformStream<Uint8Array, Uint8Array>
  return new Uint8Array(await new Response(input.pipeThrough(transform)).arrayBuffer())
}

describe('RemoteSession — authenticated agent build identity', () => {
  it.each([
    ['0123456', '0123456'],
    ['0123456789abcdef0123456789abcdef01234567', '0123456789abcdef0123456789abcdef01234567'],
    ['012345', null],
    ['0123456789abcdef0123456789abcdef012345678', null],
    ['0123456-dirty', null],
    ['ABCDEF0', null],
    ['token=secret', null],
    [null, null],
  ] as const)('validates %# without accepting free-form build text', (value, expected) => {
    expect(parseAgentBuildGit(value)).toBe(expected)
  })

  it('publishes the build only from auth_ok, never a pre-auth hello', () => {
    const transport = new FakeTransport()
    const builds: Array<string | null> = []
    new RemoteSession(transport, 'tok', 'dev_browser', {
      onAgentBuild: (git) => builds.push(git),
    })
    transport.emitState('connected')
    transport.emitText(JSON.stringify({
      type: 'hello',
      protocol_version: 1,
      device_id: 'dev_desktop',
      role: 'agent',
      capabilities: [],
      agent_build_git: '0123456',
    }))
    expect(builds).toEqual([])

    transport.emitText(JSON.stringify({
      type: 'auth_ok',
      account_id: 'acct',
      device_id: 'dev_browser',
      agent_build_git: '0123456',
    }))
    expect(builds).toEqual(['0123456'])
  })

  it('maps legacy/invalid auth_ok fields to unknown and ignores a late auth_ok after close', () => {
    const transport = new FakeTransport()
    const builds: Array<string | null> = []
    new RemoteSession(transport, 'tok', 'dev_browser', {
      onAgentBuild: (git) => builds.push(git),
    })
    transport.emitState('connected')
    transport.emitText(JSON.stringify({
      type: 'auth_ok',
      account_id: 'acct',
      device_id: 'dev_browser',
      agent_build_git: 'token=secret',
    }))
    expect(builds).toEqual([null])

    transport.emitState('closed')
    transport.emitText(JSON.stringify({
      type: 'auth_ok',
      account_id: 'acct',
      device_id: 'dev_browser',
      agent_build_git: '89abcde',
    }))
    expect(builds).toEqual([null])
  })
})

describe('RemoteSession — auth boundary (connected ≠ authorized)', () => {
  let t: FakeTransport
  let states: ControlState[]
  let session: RemoteSession
  beforeEach(() => {
    t = new FakeTransport()
    states = []
    session = new RemoteSession(t, 'tok123', 'dev_browser', { onState: (s) => states.push(s) })
  })

  it('on connect, sends hello then auth — and refuses terminal ops before auth_ok', () => {
    t.emitState('connected')
    const types = t.sentText.map((s) => JSON.parse(s).type)
    expect(types).toEqual(['hello', 'auth'])
    expect(lastText(t)).toMatchObject({ type: 'auth', token: 'tok123' })

    // pre-auth: list/attach are no-ops (connected ≠ authorized)
    session.listSessions()
    session.attach('s1', 80, 24)
    expect(textsOfType(t, 'session_list')).toHaveLength(0)
    expect(textsOfType(t, 'attach_session')).toHaveLength(0)
    expect(session.isAuthenticated).toBe(false)
  })

  it('after auth_ok, terminal ops are allowed', () => {
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'acct', device_id: 'dev_browser' }))
    expect(session.isAuthenticated).toBe(true)
    expect(states).toContain('authenticated')

    session.listSessions()
    expect(textsOfType(t, 'session_list')).toHaveLength(1)
    session.attach('s1', 80, 24)
    expect(lastText(t)).toMatchObject({ type: 'attach_session', session_id: 's1', cols: 80, rows: 24, viewed: false })
    session.attach('s-bg', 80, 24, false, 'background', false)
    expect(lastText(t)).toMatchObject({ type: 'attach_session', session_id: 's-bg', viewed: false })
  })

  it('drops every state-bearing control reply before auth_ok, including transcript and metadata pushes', () => {
    let callbacks = 0
    session = new RemoteSession(t, 'tok123', 'dev_browser', {
      onSessions: () => { callbacks++ },
      onWorkspaceUpdate: () => { callbacks++ },
      onAttached: () => { callbacks++ },
      onError: () => { callbacks++ },
      onWinsizeOwnerChanged: () => { callbacks++ },
      onAgentSessions: () => { callbacks++ },
      onDirectoriesResult: () => { callbacks++ },
      onAgentSessionPreview: () => { callbacks++ },
      onSessionCreated: () => { callbacks++ },
      onDebugSyncSnapshot: () => { callbacks++ },
    })
    t.emitState('connected')

    for (const message of [
      { type: 'session_list_result', request_id: 'list', sessions: ['victim-session'] },
      { type: 'workspace_update', epoch: 7, sessions: ['victim-session'] },
      { type: 'attach_ok', request_id: 'attach', session_id: 'victim-session', channel: 12 },
      { type: 'error', code: 'input_rate_limited', message: 'retire transport' },
      { type: 'winsize_owner_changed', owner: 'remote' },
      { type: 'agent_sessions_result', request_id: 'history', sessions: [] },
      { type: 'directories_result', request_id: 'dirs', directories: ['/victim'] },
      {
        type: 'agent_session_preview',
        request_id: 'preview',
        lines: [{ role: 'user', text: 'victim transcript' }],
      },
      { type: 'session_created', request_id: 'create', session_id: 'victim-session' },
      { type: 'debug_sync_snapshot_result', request_id: 'debug', agent: { private: true } },
    ]) {
      t.emitText(JSON.stringify(message))
    }

    expect(callbacks).toBe(0)
    expect(textsOfType(t, 'workspace_update_ack')).toHaveLength(0)
    expect(t.closed).toBe(false)
    expect(session.isAuthenticated).toBe(false)

    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'acct', device_id: 'dev_browser' }))
    t.emitText(JSON.stringify({ type: 'session_list_result', request_id: 'list', sessions: ['owned-session'] }))
    expect(callbacks).toBe(1)
  })

  it('auth_refused leaves the session unauthenticated and surfaces the state', () => {
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_refused', reason: 'invalid' }))
    expect(session.isAuthenticated).toBe(false)
    expect(states).toContain('auth_refused')
    session.listSessions()
    expect(textsOfType(t, 'session_list')).toHaveLength(0)
  })

  it('auth_refused:revoked surfaces the revoked state', () => {
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_refused', reason: 'revoked' }))
    expect(states).toContain('revoked')
  })

  it('a late auth_ok after close cannot revive attach or binary handling', () => {
    const attached: string[] = []
    const grids: unknown[] = []
    session = new RemoteSession(t, 'tok123', 'dev_browser', {
      onAttached: (id) => attached.push(id),
      onGridSnapshot: (grid) => grids.push(grid),
    })
    t.emitState('connected')
    t.emitState('closed')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'acct', device_id: 'dev_browser' }))

    session.attach('stale', 80, 24)
    t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'stale', session_id: 'stale', channel: 7 }))
    t.emitBinary(encodeFrame(
      FrameKind.TerminalOutput,
      7,
      new TextEncoder().encode(JSON.stringify({ ev: 'grid', id: 'stale', grid: makeGrid() })),
    ))

    expect(session.isAuthenticated).toBe(false)
    expect(textsOfType(t, 'attach_session')).toHaveLength(0)
    expect(attached).toEqual([])
    expect(grids).toEqual([])
  })
})

describe('RemoteSession — same-channel authorization continuity', () => {
  const START = 1_000_000

  beforeEach(() => {
    vi.useFakeTimers()
    vi.setSystemTime(START)
  })
  afterEach(() => vi.useRealTimers())

  function setup(
    refresh: FakeTransport['refreshAuthorizationHandler'],
    authorizationNow: () => number = () => Date.now(),
  ): { t: FakeTransport; session: RemoteSession; states: ControlState[]; expiry: number } {
    const t = new FakeTransport()
    const expiry = START + 600_000
    t.authorization = { token: 'a', expiresAtMs: expiry, deadlineMs: expiry }
    t.refreshAuthorizationHandler = refresh
    const states: ControlState[] = []
    const session = new RemoteSession(
      t,
      'legacy',
      'dev_browser',
      { onState: (state) => states.push(state) },
      '',
      undefined,
      authorizationNow,
    )
    t.emitState('connected')
    emitAgentHello(t, [AUTHORIZATION_REFRESH_CAPABILITY])
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'acct', device_id: 'dev_browser' }))
    return { t, session, states, expiry }
  }

  it.each([-5 * 60_000, 5 * 60_000])(
    'derives a local TTL deadline and schedules before real expiry with browser clock skew %+dms',
    async (browserSkewMs) => {
      const serverIssuedAtMs = 10_000_000
      const localReceivedAtMs = serverIssuedAtMs + browserSkewMs
      const authorization = parseBoundAuthorization({
        token: 'a',
        issuedAtMs: serverIssuedAtMs,
        expiresAtMs: serverIssuedAtMs + 600_000,
      }, localReceivedAtMs)
      expect(authorization).toEqual({
        token: 'a',
        expiresAtMs: serverIssuedAtMs + 600_000,
        deadlineMs: localReceivedAtMs + 600_000,
      })
      vi.setSystemTime(localReceivedAtMs)
      let refreshAtMs: number | null = null
      const t = new FakeTransport()
      t.authorization = authorization
      t.refreshAuthorizationHandler = async () => {
        refreshAtMs = Date.now()
        return {
          token: 'successor',
          expiresAtMs: serverIssuedAtMs + 1_100_000,
          deadlineMs: localReceivedAtMs + 1_100_000,
        }
      }
      const session = new RemoteSession(t, 'legacy', 'dev_browser', {})
      t.emitState('connected')
      emitAgentHello(t, [AUTHORIZATION_REFRESH_CAPABILITY])
      t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'acct', device_id: 'dev_browser' }))

      // Token "a" has deterministic 97 ms jitter. Both skew directions use the same elapsed TTL duration.
      await vi.advanceTimersByTimeAsync(600_000 - AUTHORIZATION_REFRESH_LEAD_MS - 97)
      expect(refreshAtMs).toBe(localReceivedAtMs + 600_000 - AUTHORIZATION_REFRESH_LEAD_MS - 97)
      expect(refreshAtMs! - localReceivedAtMs).toBeLessThan(600_000)
      expect(textsOfType(t, 'auth_refresh')).toEqual([{ type: 'auth_refresh', token: 'successor' }])
      session.close()
    },
  )

  it('rejects missing, non-positive, or over-bounded server TTL metadata', () => {
    const base = { token: 'token', issuedAtMs: 1_000, expiresAtMs: 2_000 }
    expect(parseBoundAuthorization({ token: 'token', expiresAtMs: 2_000 }, START)).toBeNull()
    expect(parseBoundAuthorization({ ...base, expiresAtMs: base.issuedAtMs }, START)).toBeNull()
    expect(parseBoundAuthorization({
      ...base,
      expiresAtMs: base.issuedAtMs + MAX_BOUND_AUTHORIZATION_TTL_MS + 1,
    }, START)).toBeNull()
  })

  it('commits a successor only after its distinct ack and emits no second authenticated lifecycle', async () => {
    const nextExpiry = START + 1_100_000
    const { t, states } = setup(async () => ({
      token: 'successor', expiresAtMs: nextExpiry, deadlineMs: nextExpiry,
    }))
    // token "a" has deterministic 97ms jitter.
    await vi.advanceTimersByTimeAsync(600_000 - AUTHORIZATION_REFRESH_LEAD_MS - 97)
    expect(textsOfType(t, 'auth_refresh')).toEqual([{ type: 'auth_refresh', token: 'successor' }])
    t.emitText(JSON.stringify({ type: 'auth_refresh_ok', expires_at_ms: nextExpiry }))
    expect(states.filter((state) => state === 'authenticated')).toHaveLength(1)
    expect(textsOfType(t, 'session_list')).toHaveLength(0)
    expect(textsOfType(t, 'attach_session')).toHaveLength(0)

    // Even a duplicated legacy AuthOk is inert and cannot restart controller hydration.
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'acct', device_id: 'dev_browser' }))
    expect(states.filter((state) => state === 'authenticated')).toHaveLength(1)
    expect(textsOfType(t, 'session_list')).toHaveLength(0)
  })

  it('bounds retries and fails the transport closed when cloud refresh never succeeds', async () => {
    let attempts = 0
    const { t } = setup(async () => { attempts++; return null })
    await vi.advanceTimersByTimeAsync(600_000 - AUTHORIZATION_REFRESH_LEAD_MS - 97 + 30_000)
    expect(attempts).toBe(4)
    expect(t.closed).toBe(true)
    expect(textsOfType(t, 'auth_refresh')).toHaveLength(0)
  })

  it('does not refresh when the agent omits the exact capability', async () => {
    let calls = 0
    const t = new FakeTransport()
    t.authorization = { token: 'a', expiresAtMs: START + 600_000, deadlineMs: START + 600_000 }
    t.refreshAuthorizationHandler = async () => { calls++; return null }
    new RemoteSession(t, 'legacy', 'dev_browser', {})
    t.emitState('connected')
    emitAgentHello(t, [])
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'acct', device_id: 'dev_browser' }))
    await vi.advanceTimersByTimeAsync(600_000)
    expect(calls).toBe(0)
    expect(textsOfType(t, 'auth_refresh')).toHaveLength(0)
  })

  it('closes on ack timeout or an explicit refresh refusal', async () => {
    const nextExpiry = START + 1_100_000
    const timeout = setup(async () => ({
      token: 'timeout-successor', expiresAtMs: nextExpiry, deadlineMs: nextExpiry,
    }))
    await vi.advanceTimersByTimeAsync(600_000 - AUTHORIZATION_REFRESH_LEAD_MS - 97)
    await vi.advanceTimersByTimeAsync(AUTHORIZATION_REFRESH_ACK_TIMEOUT_MS)
    expect(timeout.t.closed).toBe(true)

    vi.setSystemTime(START)
    const refused = setup(async () => ({
      token: 'refused-successor', expiresAtMs: nextExpiry, deadlineMs: nextExpiry,
    }))
    await vi.advanceTimersByTimeAsync(600_000 - AUTHORIZATION_REFRESH_LEAD_MS - 97)
    refused.t.emitText(JSON.stringify({ type: 'auth_refresh_refused', reason: 'revoked' }))
    expect(refused.t.closed).toBe(true)
  })

  it.each([
    ['mismatched', START + 1_100_001],
    ['expired', START - 1],
  ])('closes on a %s refresh ack expiry', async (_label, ackExpiry) => {
    const nextExpiry = START + 1_100_000
    const { t } = setup(async () => ({
      token: 'candidate', expiresAtMs: nextExpiry, deadlineMs: nextExpiry,
    }))
    await vi.advanceTimersByTimeAsync(600_000 - AUTHORIZATION_REFRESH_LEAD_MS - 97)
    t.emitText(JSON.stringify({ type: 'auth_refresh_ok', expires_at_ms: ackExpiry }))
    expect(t.closed).toBe(true)
  })

  it('catches up after suspend while live, but never calls cloud after predecessor expiry', async () => {
    let wallNow = START
    let liveCalls = 0
    const live = setup(async () => {
      liveCalls++
      return {
        token: 'after-wake',
        expiresAtMs: START + 1_100_000,
        deadlineMs: START + 1_100_000,
      }
    }, () => wallNow)
    wallNow = START + 500_000
    await vi.advanceTimersByTimeAsync(600_000 - AUTHORIZATION_REFRESH_LEAD_MS - 97)
    expect(liveCalls).toBe(1)
    expect(textsOfType(live.t, 'auth_refresh')).toHaveLength(1)
    live.session.close()

    vi.setSystemTime(START)
    wallNow = START
    let staleCalls = 0
    const stale = setup(async () => { staleCalls++; return null }, () => wallNow)
    wallNow = stale.expiry + 1
    await vi.advanceTimersByTimeAsync(600_000 - AUTHORIZATION_REFRESH_LEAD_MS - 97)
    expect(staleCalls).toBe(0)
    expect(stale.t.closed).toBe(true)
  })

  it('cancels an in-flight stale successor when the session owner retires', async () => {
    let resolve!: (value: { token: string; expiresAtMs: number; deadlineMs: number }) => void
    const pending = new Promise<{ token: string; expiresAtMs: number; deadlineMs: number }>((r) => { resolve = r })
    const { t, session } = setup(async () => pending)
    await vi.advanceTimersByTimeAsync(600_000 - AUTHORIZATION_REFRESH_LEAD_MS - 97)
    session.close()
    resolve({
      token: 'stale-successor',
      expiresAtMs: START + 1_100_000,
      deadlineMs: START + 1_100_000,
    })
    await Promise.resolve()
    await Promise.resolve()
    expect(textsOfType(t, 'auth_refresh')).toHaveLength(0)
  })

  it('times out an AbortSignal-ignoring request and suppresses its late successor', async () => {
    let resolve!: (value: { token: string; expiresAtMs: number; deadlineMs: number }) => void
    const ignored = new Promise<{ token: string; expiresAtMs: number; deadlineMs: number }>((r) => { resolve = r })
    const { t, session } = setup(async () => ignored)
    await vi.advanceTimersByTimeAsync(600_000 - AUTHORIZATION_REFRESH_LEAD_MS - 97)
    await vi.advanceTimersByTimeAsync(AUTHORIZATION_REFRESH_REQUEST_TIMEOUT_MS)
    resolve({
      token: 'too-late',
      expiresAtMs: START + 1_100_000,
      deadlineMs: START + 1_100_000,
    })
    await Promise.resolve()
    await Promise.resolve()
    expect(textsOfType(t, 'auth_refresh')).toHaveLength(0)
    session.close()
  })
})

describe('RemoteSession — desktop access status capability', () => {
  it('accepts status only after exact capability negotiation and authentication', () => {
    const transport = new FakeTransport()
    const statuses: import('../protocol/control-messages').DesktopAccessStatusMsg[] = []
    new RemoteSession(transport, 'tok', 'dev_browser', {
      onDesktopAccessStatus: (status) => statuses.push(status),
    })
    const status = {
      type: 'desktop_access_status',
      platform: 'macos',
      full_disk_access: 'required',
    }

    transport.emitState('connected')
    transport.emitText(JSON.stringify(status))
    emitAgentHello(transport, [DESKTOP_ACCESS_STATUS_CAPABILITY])
    transport.emitText(JSON.stringify(status))
    expect(statuses).toEqual([])

    transport.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'acct', device_id: 'dev_browser' }))
    transport.emitText(JSON.stringify(status))
    expect(statuses).toEqual([status])

    transport.emitState('closed')
    transport.emitText(JSON.stringify(status))
    expect(statuses).toHaveLength(1)
  })

  it('keeps legacy and near-match agents at unknown by ignoring their status frames', () => {
    for (const capabilities of [undefined, [], ['desktop_access_status_v2']]) {
      const transport = new FakeTransport()
      const statuses: unknown[] = []
      new RemoteSession(transport, 'tok', 'dev_browser', {
        onDesktopAccessStatus: (status) => statuses.push(status),
      })
      transport.emitState('connected')
      if (capabilities === undefined) {
        transport.emitText(JSON.stringify({
          type: 'hello',
          protocol_version: 1,
          device_id: 'dev_desktop',
          role: 'agent',
        }))
      } else {
        emitAgentHello(transport, capabilities)
      }
      transport.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'acct', device_id: 'dev_browser' }))
      transport.emitText(JSON.stringify({
        type: 'desktop_access_status',
        platform: 'macos',
        full_disk_access: 'required',
      }))
      expect(statuses).toEqual([])
    }
  })
})

describe('RemoteSession — viewed resize mixed-version capability', () => {
  function authenticatedSession(agentHello?: Record<string, unknown>): {
    transport: FakeTransport
    session: RemoteSession
  } {
    const transport = new FakeTransport()
    const session = new RemoteSession(transport, 'tok', 'dev_browser')
    transport.emitState('connected')
    if (agentHello) transport.emitText(JSON.stringify(agentHello))
    transport.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    return { transport, session }
  }

  it('new browser + capable agent sends a background resize with viewed=false', () => {
    const { transport, session } = authenticatedSession({
      type: 'hello',
      protocol_version: 1,
      device_id: 'dev_desktop',
      role: 'agent',
      capabilities: ['viewed_resize_v1'],
    })

    session.resizeSession('s-background', 90, 20, false)

    expect(textsOfType(transport, 'resize')).toEqual([{
      type: 'resize',
      session_id: 's-background',
      cols: 90,
      rows: 20,
      viewed: false,
    }])
  })

  it('new browser + legacy agent suppresses background resize but still sends active resize', () => {
    const { transport, session } = authenticatedSession({
      type: 'hello',
      protocol_version: 1,
      device_id: 'dev_desktop',
      role: 'agent',
    })

    session.resizeSession('s-background', 90, 20, false)
    session.resizeSession('s-active', 100, 30, true)

    expect(textsOfType(transport, 'resize')).toEqual([{
      type: 'resize',
      session_id: 's-active',
      cols: 100,
      rows: 30,
      viewed: true,
    }])
  })

  it('only the exact allowlisted agent Hello capability enables background resize', () => {
    const { transport, session } = authenticatedSession()

    transport.emitText(JSON.stringify({
      type: 'auth_ok',
      account_id: 'a',
      device_id: 'dev_browser',
      capabilities: ['viewed_resize_v1'],
    }))
    transport.emitText(JSON.stringify({ type: 'future_message', capabilities: ['viewed_resize_v1'] }))
    emitAgentHello(transport, ['viewed_resize_v1_extra', 1, { name: 'viewed_resize_v1' }])
    session.resizeSession('s-background', 90, 20, false)
    expect(textsOfType(transport, 'resize')).toHaveLength(0)

    emitAgentHello(transport)
    session.resizeSession('s-background', 90, 20, false)
    expect(textsOfType(transport, 'resize')).toHaveLength(1)
  })

  it('resets capability across close/reopen and ignores a stale post-close Hello', () => {
    const { transport, session } = authenticatedSession({
      type: 'hello',
      protocol_version: 1,
      device_id: 'dev_desktop',
      role: 'agent',
      capabilities: ['viewed_resize_v1'],
    })
    session.resizeSession('s-first', 90, 20, false)
    expect(textsOfType(transport, 'resize')).toHaveLength(1)

    transport.emitState('closed')
    emitAgentHello(transport) // queued callback from the retired transport
    transport.emitState('connected')
    transport.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    session.resizeSession('s-after-reopen', 91, 21, false)
    expect(textsOfType(transport, 'resize')).toHaveLength(1)

    emitAgentHello(transport) // the replacement transport proves support for itself
    session.resizeSession('s-after-fresh-hello', 92, 22, false)
    expect(textsOfType(transport, 'resize')).toHaveLength(2)
  })
})

describe('RemoteSession — negotiated terminal gzip', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  function authenticated(agentCapabilities: unknown = [TERMINAL_GZIP_JSON_V1]): {
    transport: FakeTransport
    session: RemoteSession
  } {
    const transport = new FakeTransport()
    const session = new RemoteSession(transport, 'tok', 'dev_browser')
    transport.emitState('connected')
    emitAgentHello(transport, agentCapabilities)
    transport.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    return { transport, session }
  }

  it('proposes, requests, and selects only the exact capability intersection confirmed by attach_ok', () => {
    const { transport, session } = authenticated()
    expect(textsOfType(transport, 'hello')[0]?.capabilities).toEqual([
      CREATION_REQUEST_REPLAY_CAPABILITY,
      DESKTOP_ACCESS_STATUS_CAPABILITY,
      AUTHORIZATION_REFRESH_CAPABILITY,
      TERMINAL_GZIP_JSON_V1,
    ])

    session.attach('s1', 80, 24, false, 'gzip-attach')
    expect(textsOfType(transport, 'attach_session')[0]).toMatchObject({
      request_id: 'gzip-attach',
      terminal_encoding: TERMINAL_GZIP_JSON_V1,
    })
    transport.emitText(JSON.stringify({
      type: 'attach_ok',
      request_id: 'gzip-attach',
      session_id: 's1',
      channel: 4,
      terminal_encoding: TERMINAL_GZIP_JSON_V1,
    }))
    expect(session.channel).toBe(4)
    expect(transport.closed).toBe(false)
  })

  it('signals the final viewed channel after attach and every explicit pane switch', () => {
    const priorities = vi.spyOn(OrderedTerminalCodecDecoder.prototype, 'setActiveChannel')
    const { transport, session } = authenticated()
    session.attach('s1', 80, 24, false, 'a')
    transport.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'a', session_id: 's1', channel: 4 }))
    session.setActiveAttach('s2', 7)
    session.setViewedChannel(null)
    session.setActiveAttach('s1', 4)

    expect(priorities.mock.calls.map(([channel]) => channel)).toEqual([4, 7, null, 4])
  })

  it('does not let a background attach arrival overwrite the callback\'s viewed-channel correction', () => {
    const priorities = vi.spyOn(OrderedTerminalCodecDecoder.prototype, 'setActiveChannel')
    const transport = new FakeTransport()
    let session!: RemoteSession
    session = new RemoteSession(transport, 'tok', 'dev_browser', {
      onAttached: (sessionId) => {
        if (sessionId === 'background') session.setViewedChannel(4)
      },
    })
    transport.emitState('connected')
    transport.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    session.attach('viewed', 80, 24, false, 'viewed')
    transport.emitText(JSON.stringify({
      type: 'attach_ok', request_id: 'viewed', session_id: 'viewed', channel: 4,
    }))
    session.attach('background', 80, 24, false, 'background')
    transport.emitText(JSON.stringify({
      type: 'attach_ok', request_id: 'background', session_id: 'background', channel: 7,
    }))

    expect(priorities.mock.calls.map(([channel]) => channel)).toEqual([4, 4])
  })

  it('routes a negotiated gzip Grid through strict decode and the normal SyncState path', async () => {
    const transport = new FakeTransport()
    const grids: unknown[] = []
    const session = new RemoteSession(transport, 'tok', 'dev_browser', {
      onGridSnapshot: (grid) => grids.push(grid),
    })
    transport.emitState('connected')
    emitAgentHello(transport, [TERMINAL_GZIP_JSON_V1])
    transport.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    session.attach('s1', 80, 24, false, 'gzip-grid')
    transport.emitText(JSON.stringify({
      type: 'attach_ok', request_id: 'gzip-grid', session_id: 's1', channel: 6,
      terminal_encoding: TERMINAL_GZIP_JSON_V1,
    }))

    const decoded = new TextEncoder().encode(JSON.stringify({
      ev: 'grid', id: 's1', grid: makeV2Grid('hi'), padding: 'x'.repeat(6000),
    }))
    const encoded = await gzipBytes(decoded)
    const count = Math.ceil(encoded.byteLength / TERMINAL_CODEC_CHUNK_BYTES)
    for (let index = 0; index < count; index++) {
      const start = index * TERMINAL_CODEC_CHUNK_BYTES
      const chunk = encoded.subarray(start, Math.min(encoded.byteLength, start + TERMINAL_CODEC_CHUNK_BYTES))
      transport.emitBinary(encodeFrame(
        FrameKind.TerminalGzipJsonChunk,
        6,
        encodeTerminalGzipChunkPayload(index, count, encoded.byteLength, decoded.byteLength, chunk),
      ))
    }

    await vi.waitFor(() => expect(grids).toHaveLength(1))
    expect(grids[0]).toMatchObject({ version: 2, cols: 2, rows: 1, revision: 1 })
    expect(transport.closed).toBe(false)
  })

  it('does not select when the agent advertises gzip but this browser transport did not offer it', () => {
    vi.stubGlobal('DecompressionStream', undefined)
    const { transport, session } = authenticated()
    expect(textsOfType(transport, 'hello')[0]?.capabilities).toEqual([
      CREATION_REQUEST_REPLAY_CAPABILITY,
      DESKTOP_ACCESS_STATUS_CAPABILITY,
      AUTHORIZATION_REFRESH_CAPABILITY,
    ])

    session.attach('s1', 80, 24, false, 'legacy-attach')
    expect(textsOfType(transport, 'attach_session')[0]).not.toHaveProperty('terminal_encoding')
    transport.emitText(JSON.stringify({
      type: 'attach_ok',
      request_id: 'legacy-attach',
      session_id: 's1',
      channel: 5,
    }))
    expect(session.channel).toBe(5)
    expect(transport.closed).toBe(false)
  })

  it('keeps legacy mode for absent, near-match, malformed, and over-bound agent capabilities', () => {
    for (const capabilities of [
      undefined,
      ['terminal_gzip_json_v1_extra'],
      [TERMINAL_GZIP_JSON_V1, 1],
      Array.from({ length: 17 }, () => TERMINAL_GZIP_JSON_V1),
      ['x'.repeat(65)],
    ]) {
      const transport = new FakeTransport()
      const session = new RemoteSession(transport, 'tok', 'dev_browser')
      transport.emitState('connected')
      if (capabilities === undefined) {
        transport.emitText(JSON.stringify({
          type: 'hello', protocol_version: 1, device_id: 'dev_desktop', role: 'agent',
        }))
      } else {
        emitAgentHello(transport, capabilities)
      }
      transport.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
      session.attach('s1', 80, 24, false, 'a')
      expect(textsOfType(transport, 'attach_session')[0]).not.toHaveProperty('terminal_encoding')
    }
  })

  it('closes on an unproved confirmation or malformed compressed frame so reconnect can mint a fresh owner', () => {
    const unproved = authenticated()
    unproved.session.attach('s1', 80, 24, false, 'a')
    unproved.transport.emitText(JSON.stringify({
      type: 'attach_ok', request_id: 'other', session_id: 's1', channel: 1,
      terminal_encoding: TERMINAL_GZIP_JSON_V1,
    }))
    expect(unproved.transport.closed).toBe(true)

    const malformed = authenticated()
    malformed.session.attach('s1', 80, 24, false, 'a')
    malformed.transport.emitText(JSON.stringify({
      type: 'attach_ok', request_id: 'a', session_id: 's1', channel: 1,
      terminal_encoding: TERMINAL_GZIP_JSON_V1,
    }))
    malformed.transport.emitBinary(encodeFrame(
      FrameKind.TerminalGzipJsonChunk,
      1,
      new Uint8Array([1]),
    ))
    expect(malformed.transport.closed).toBe(true)
  })

  it('bounds pending attach ownership, clears correlated errors, and rejects a stale confirmation after timeout', async () => {
    const cleaned = authenticated()
    for (let i = 0; i < 40; i++) {
      const requestId = `clean-${i}`
      cleaned.session.attach('s1', 80, 24, false, requestId)
      cleaned.transport.emitText(JSON.stringify({
        type: 'error', code: 'attach_failed', message: 'failed', request_id: requestId, session_id: 's1',
      }))
    }
    expect(cleaned.transport.closed).toBe(false)

    const bounded = authenticated()
    for (let i = 0; i < 33; i++) bounded.session.attach(`s${i}`, 80, 24, false, `pending-${i}`)
    expect(bounded.transport.closed).toBe(true)

    vi.useFakeTimers()
    let now = 0
    const staleTransport = new FakeTransport()
    const staleSession = new RemoteSession(staleTransport, 'tok', 'dev_browser', {}, '', () => now)
    staleTransport.emitState('connected')
    emitAgentHello(staleTransport, [TERMINAL_GZIP_JSON_V1])
    staleTransport.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    staleSession.attach('s1', 80, 24, false, 'expires')
    now = 15_001
    await vi.advanceTimersByTimeAsync(15_001)
    staleTransport.emitText(JSON.stringify({
      type: 'attach_ok', request_id: 'expires', session_id: 's1', channel: 2,
      terminal_encoding: TERMINAL_GZIP_JSON_V1,
    }))
    expect(staleTransport.closed).toBe(true)
  })
})

describe('RemoteSession — session list + attach + input', () => {
  let t: FakeTransport
  let session: RemoteSession
  let sessionsSeen: {
    sessions: string[]
    metadata: import('./remote-session').RemoteSessionMetadata[]
    workspaceMetadata: import('./remote-client').RemoteWorkspaceMetadata | null
  }[]
  let attached: { id: string; channel: number }[]
  let workspaceUpdates: {
    epoch: number
    workspaceMetadata: import('./remote-client').RemoteWorkspaceMetadata | null
  }[]
  beforeEach(() => {
    t = new FakeTransport()
    sessionsSeen = []
    workspaceUpdates = []
    attached = []
    session = new RemoteSession(t, 'tok', 'dev_browser', {
      onSessions: (s, metadata = [], workspaceMetadata = null) => {
        sessionsSeen.push({ sessions: s, metadata, workspaceMetadata })
      },
      onWorkspaceUpdate: (epoch, workspaceMetadata) => {
        workspaceUpdates.push({ epoch, workspaceMetadata })
      },
      onAttached: (id, channel) => attached.push({ id, channel }),
    })
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
  })

  it('surfaces the session list', () => {
    session.listSessions()
    t.emitText(JSON.stringify({ type: 'session_list_result', request_id: 'list', sessions: ['s1', 's2'] }))
    expect(sessionsSeen).toEqual([{ sessions: ['s1', 's2'], metadata: [], workspaceMetadata: null }])
  })

  it('surfaces optional session metadata from the session list', () => {
    session.listSessions()
    t.emitText(JSON.stringify({
      type: 'session_list_result',
      request_id: 'list',
      sessions: ['s1'],
      session_metadata: [{ id: 's1', cwd: '/Users/test/home/app' }],
    }))
    expect(sessionsSeen).toEqual([{
      sessions: ['s1'],
      metadata: [{ id: 's1', cwd: '/Users/test/home/app' }],
      workspaceMetadata: null,
    }])
  })

  it('surfaces validated workspace metadata from the session list', () => {
    session.listSessions()
    t.emitText(JSON.stringify({
      type: 'session_list_result',
      request_id: 'list',
      sessions: ['s-build'],
      workspace_metadata: {
        projects: [{
          id: 'proj-capacity',
          name: 'capacity total',
          root: '/Users/test/home/Desktop/project-example',
          icon: '◉',
          accent_color: '#34d399',
          selected: true,
          launch_defaults: {
            agent: 'codex',
            resume_mode: 'resume',
            model: 'gpt-5',
            dangerous: true,
            custom_command: 'claude --foo',
          },
          directories: [{ name: 'api', path: '/Users/test/home/api' }],
          windows: [{
            id: 'win-main',
            name: 'Main window',
            focused: true,
            panes: [
              { id: 'pane-build', session_id: 's-build', name: 'Build', stashed: false, cwd: '/Users/test/home/api' },
              { id: 'pane-stale', session_id: 's-stale', name: 'Stale' },
            ],
          }],
        }],
      },
    }))
    expect(sessionsSeen).toEqual([{
      sessions: ['s-build'],
      metadata: [],
      workspaceMetadata: {
        projects: [{
          id: 'proj-capacity',
          name: 'capacity total',
          root: '/Users/test/home/Desktop/project-example',
          icon: '◉',
          accentColor: '#34d399',
          selected: true,
          launchDefaults: {
            agent: 'codex',
            resumeMode: 'resume',
            model: 'gpt-5',
            dangerouslySkipPermissions: true,
            customCommand: 'claude --foo',
          },
          directories: [{ name: 'api', path: '/Users/test/home/api' }],
          windows: [{
            id: 'win-main',
            name: 'Main window',
            focused: true,
            panes: [
              // The pane's cwd is parsed through so the split picker can default to the source window's folder.
              { id: 'pane-build', sessionId: 's-build', name: 'Build', stashed: false, live: true, cwd: '/Users/test/home/api' },
              { id: 'pane-stale', sessionId: 's-stale', name: 'Stale', stashed: true, live: false },
            ],
          }],
        }],
      },
    }])
  })

  it('traces EVERY wire message with direction (out/in) content-blind — the inspector ground truth', async () => {
    const { connTrace } = await import('./conn-trace')
    connTrace.clear()
    const events: { dir: string; detail: string }[] = []
    const off = connTrace.onEvent((e) => {
      if (e.leg === 'wire') events.push({ dir: e.stage, detail: e.detail })
    })

    // outbound (browser → agent)
    session.listSessions()
    // inbound (agent → browser)
    t.emitText(JSON.stringify({
      type: 'session_list_result',
      request_id: 'list',
      sessions: ['s1', 's2'],
      workspace_metadata: { projects: [{ id: 'p', name: 'P', root: '/', windows: [] }] },
    }))
    off()

    // BOTH directions present, tagged out vs in.
    expect(events.some((e) => e.dir === 'out' && /session_list/.test(e.detail))).toBe(true)
    expect(events.some((e) => e.dir === 'in' && /session_list_result sessions=2 projects=1/.test(e.detail))).toBe(true)
    // CONTENT-BLIND: no token/cookie/session-bytes leaked into any wire detail.
    const all = events.map((e) => e.detail).join(' | ').toLowerCase()
    for (const bad of ['tok', 'bearer', 'cookie', 'authorization']) expect(all).not.toContain(bad)
  })

  it('KEEPS an idle project whose pane has an empty (redacted) session_id — it must still surface', () => {
    // The agent redacts a hidden/idle session to an empty session_id but keeps the pane as a placeholder. The
    // browser must NOT drop that pane (→ window → project) — an idle project (e.g. Terminal) has to stay visible.
    session.listSessions()
    t.emitText(JSON.stringify({
      type: 'session_list_result',
      request_id: 'list',
      sessions: [], // no live sessions
      workspace_metadata: {
        projects: [{
          id: 'system-terminal',
          name: 'Terminal',
          root: '/Users/test/home',
          system: true,
          windows: [{
            id: 'system-terminal-window-1',
            name: 'Window 1',
            panes: [{ id: 'pane-1', session_id: '', name: 'Pane 1' }], // redacted → empty session_id
          }],
        }],
      },
    }))
    const wm = sessionsSeen[0].workspaceMetadata
    expect(wm?.projects).toHaveLength(1)
    expect(wm?.projects[0].id).toBe('system-terminal')
    expect(wm?.projects[0].windows).toHaveLength(1)
    expect(wm?.projects[0].windows[0].panes).toHaveLength(1)
    // the placeholder pane is present, non-live, stashed
    expect(wm?.projects[0].windows[0].panes[0]).toMatchObject({ id: 'pane-1', sessionId: '', live: false, stashed: true })
  })

  it('drops only the internal product-recovery project from older agent metadata', () => {
    session.listSessions()
    t.emitText(JSON.stringify({
      type: 'session_list_result',
      request_id: 'list',
      sessions: ['system-product-recovery-session', 's-terminal'],
      session_metadata: [
        { id: 'system-product-recovery-session', cwd: '/Users/test/home' },
        { id: 's-terminal', cwd: '/Users/test/home' },
      ],
      workspace_metadata: {
        projects: [
          {
            id: 'system-product-recovery',
            name: 'Product Recovery',
            root: '/Users/test/home',
            system: true,
            hidden: true,
            windows: [{
              id: 'system-product-recovery-window',
              panes: [{ id: 'system-product-recovery-pane', session_id: '' }],
            }],
          },
          {
            id: 'system-terminal',
            name: 'Terminal',
            root: '/Users/test/home',
            system: true,
            windows: [{
              id: 'system-terminal-window-1',
              panes: [{ id: 'pane-1', session_id: 's-terminal' }],
            }],
          },
        ],
      },
    }))

    expect(sessionsSeen[0].workspaceMetadata?.projects.map((project) => project.id)).toEqual([
      'system-terminal',
    ])
    expect(sessionsSeen[0].sessions).toEqual(['s-terminal'])
    expect(sessionsSeen[0].metadata).toEqual([{ id: 's-terminal', cwd: '/Users/test/home' }])
  })

  it('surfaces an unsolicited workspace_update push (live-sync, no page refresh) via onWorkspaceUpdate', () => {
    // Baseline session_list first — the push reuses the last-known session ids to parse.
    session.listSessions()
    t.emitText(JSON.stringify({ type: 'session_list_result', request_id: 'list', sessions: ['s1'] }))

    t.emitText(JSON.stringify({
      type: 'workspace_update',
      epoch: 1,
      workspace_metadata: {
        projects: [{ id: 'p1', name: 'New Project', root: '/tmp/p1', windows: [] }],
      },
    }))

    expect(workspaceUpdates).toEqual([{
      epoch: 1,
      workspaceMetadata: {
        projects: [{ id: 'p1', name: 'New Project', root: '/tmp/p1', windows: [] }],
      },
    }])
  })

  it('a workspace_update with omitted metadata surfaces null (same as session_list null semantics)', () => {
    session.listSessions()
    t.emitText(JSON.stringify({ type: 'session_list_result', request_id: 'list', sessions: [] }))
    t.emitText(JSON.stringify({ type: 'workspace_update', epoch: 2 }))
    expect(workspaceUpdates).toEqual([{ epoch: 2, workspaceMetadata: null }])
  })

  it('a workspace_update carrying sessions is SELF-SUFFICIENT: panes of a brand-new session parse LIVE and the callback receives the list', () => {
    const updates: { epoch: number; sessions?: string[] | null }[] = []
    const s = new RemoteSession(t, 'tok', 'dev_browser', {
      onWorkspaceUpdate: (epoch, workspaceMetadata, sessions) => {
        updates.push({ epoch, sessions })
        // The push's OWN session list drives pane liveness — 's-fresh' was never in any session_list,
        // yet its pane must parse live (before this, a desktop-created pane arrived as a dead
        // placeholder and clicking it did nothing until a manual refresh).
        expect(workspaceMetadata?.projects[0].windows[0].panes[0]).toMatchObject({ sessionId: 's-fresh', live: true })
      },
    })
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    void s
    t.emitText(JSON.stringify({
      type: 'workspace_update',
      epoch: 1,
      sessions: ['s-fresh'],
      workspace_metadata: {
        projects: [{
          id: 'p1', name: 'proj', root: '/r',
          windows: [{ id: 'w1', name: 'W1', panes: [{ id: 'pane-1', session_id: 's-fresh' }] }],
        }],
      },
    }))
    expect(updates).toEqual([{ epoch: 1, sessions: ['s-fresh'] }])
  })

  it('acks RECEIPT of every workspace_update — including a re-pushed duplicate epoch (Slice 4)', () => {
    t.emitText(JSON.stringify({ type: 'workspace_update', epoch: 3 }))
    expect(textsOfType(t, 'workspace_update_ack')).toEqual([{ type: 'workspace_update_ack', epoch: 3 }])
    // The agent re-pushed epoch 3 (our ack was lost). remote-client's guard will drop the duplicate APPLY,
    // but the session must still re-ack receipt — otherwise a lost ack re-pushes until retries exhaust.
    t.emitText(JSON.stringify({ type: 'workspace_update', epoch: 3 }))
    expect(textsOfType(t, 'workspace_update_ack')).toHaveLength(2)
  })

  it('does not ack a workspace_update with a malformed epoch', () => {
    t.emitText(JSON.stringify({ type: 'workspace_update', epoch: 'not-a-number' }))
    expect(textsOfType(t, 'workspace_update_ack')).toHaveLength(0)
  })

  it('db_write_trace is auth-gated, sends a correlated request, and publishes the result entries', async () => {
    const { onDbWrites, requestDbWrites } = await import('./inspector-hooks')
    const received: Record<string, unknown>[][] = []
    const off = onDbWrites((entries) => received.push(entries))

    // The constructor registered this session as the fetcher; the panel asks through the hooks.
    expect(requestDbWrites(200)).toBe(true)
    expect(textsOfType(t, 'db_write_trace')).toHaveLength(1)
    const sent = textsOfType(t, 'db_write_trace')[0]
    expect(sent).toMatchObject({ type: 'db_write_trace', count: 200 })
    expect(String(sent.request_id)).toMatch(/^dbw-/)

    // Content-blind ledger rows come back and reach the panel listener untouched.
    const entries = [
      { seq: 1, ts_ms: 5, who: 'hydra-agent', op: 'write', kind: 'Project', id: 'p1', ctx: 'remote:project_create rid=r1' },
      { seq: 2, ts_ms: 6, who: 'desktop-app', op: 'delete', kind: 'WindowLayout', id: 'w1' },
    ]
    t.emitText(JSON.stringify({ type: 'db_write_trace_result', request_id: 'dbw-1', entries }))
    expect(received).toEqual([entries])
    off()
  })

  it('sends project create/update/delete and surfaces project_edit replies', () => {
    const edited: [string, string | undefined][] = []
    const errors: [string, string][] = []
    const s = new RemoteSession(t, 'tok', 'dev_browser', {
      onProjectEditOk: (projectId, sessionId) => edited.push([projectId, sessionId]),
      onProjectEditError: (code, message) => errors.push([code, message]),
    })
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))

    s.createProject('project-create', {
      name: 'Hydra',
      root: '/Users/test/home/Desktop/project-example',
      icon: 'KP',
      accentColor: '#34d399',
      agent: 'codex',
    })
    expect(lastText(t)).toEqual({
      type: 'project_create',
      request_id: 'project-create',
      name: 'Hydra',
      root: '/Users/test/home/Desktop/project-example',
      icon: 'KP',
      accent_color: '#34d399',
      agent: 'codex',
    })
    s.updateProject('project-update', 'proj-hydra', { name: 'Hydra 2', agent: 'claude' })
    expect(lastText(t)).toEqual({
      type: 'project_update',
      request_id: 'project-update',
      project_id: 'proj-hydra',
      name: 'Hydra 2',
      agent: 'claude',
    })
    s.deleteProject('project-delete', 'proj-hydra')
    expect(lastText(t)).toEqual({
      type: 'delete_project',
      request_id: 'project-delete',
      project_id: 'proj-hydra',
    })
    // A CREATE reply carries the seeded pane's session id (auto-attach target); an update-style reply omits it.
    t.emitText(JSON.stringify({ type: 'project_edit_ok', request_id: 'project-create', project_id: 'proj-hydra', session_id: 's-seeded' }))
    t.emitText(JSON.stringify({ type: 'project_edit_ok', request_id: 'project-update', project_id: 'proj-hydra' }))
    t.emitText(JSON.stringify({ type: 'project_edit_error', request_id: 'project-update', code: 'invalid_name', message: 'bad' }))
    expect(edited).toEqual([['proj-hydra', 's-seeded'], ['proj-hydra', undefined]])
    expect(errors).toEqual([['invalid_name', 'bad']])
  })

  it('sends stash_pane and surfaces stash replies', () => {
    let ok = 0
    const errors: [string, string][] = []
    const s = new RemoteSession(t, 'tok', 'dev_browser', {
      onStashPaneOk: () => { ok += 1 },
      onStashPaneError: (code, message) => errors.push([code, message]),
    })
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))

    s.stashPane('stash-pane', 'win-main', 'pane-live')
    expect(lastText(t)).toEqual({
      type: 'stash_pane',
      request_id: 'stash-pane',
      window_id: 'win-main',
      pane_id: 'pane-live',
    })
    t.emitText(JSON.stringify({ type: 'stash_pane_ok', request_id: 'stash-pane' }))
    t.emitText(JSON.stringify({ type: 'stash_pane_error', request_id: 'stash-pane', code: 'internal', message: 'bad' }))
    expect(ok).toBe(1)
    expect(errors).toEqual([['internal', 'bad']])
  })

  it('sends rename for panes/windows and surfaces rename replies', () => {
    let ok = 0
    const errors: [string, string][] = []
    const s = new RemoteSession(t, 'tok', 'dev_browser', {
      onRenameOk: () => { ok += 1 },
      onRenameError: (code, message) => errors.push([code, message]),
    })
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))

    s.rename('rename-pane', 'win-main', 'Build pane', 'pane-build')
    expect(lastText(t)).toEqual({
      type: 'rename',
      request_id: 'rename-pane',
      window_id: 'win-main',
      pane_id: 'pane-build',
      name: 'Build pane',
    })
    s.rename('rename-window', 'win-main', 'Main window')
    expect(lastText(t)).toEqual({
      type: 'rename',
      request_id: 'rename-window',
      window_id: 'win-main',
      name: 'Main window',
    })
    t.emitText(JSON.stringify({ type: 'rename_ok', request_id: 'rename-pane' }))
    t.emitText(JSON.stringify({ type: 'rename_error', request_id: 'rename-window', code: 'invalid_name', message: 'bad' }))
    expect(ok).toBe(1)
    expect(errors).toEqual([['invalid_name', 'bad']])
  })

  it('sends close_window and surfaces close replies', () => {
    let ok = 0
    const errors: [string, string][] = []
    const s = new RemoteSession(t, 'tok', 'dev_browser', {
      onCloseWindowOk: () => { ok += 1 },
      onCloseWindowError: (code, message) => errors.push([code, message]),
    })
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))

    s.closeWindow('close-window', 'win-main')
    expect(lastText(t)).toEqual({
      type: 'close_window',
      request_id: 'close-window',
      window_id: 'win-main',
    })
    t.emitText(JSON.stringify({ type: 'close_window_ok', request_id: 'close-window' }))
    t.emitText(JSON.stringify({ type: 'close_window_error', request_id: 'close-window', code: 'window_not_found', message: 'missing' }))
    expect(ok).toBe(1)
    expect(errors).toEqual([['window_not_found', 'missing']])
  })

  it('sends focus_window and surfaces focus replies', () => {
    let ok = 0
    const errors: [string, string][] = []
    const s = new RemoteSession(t, 'tok', 'dev_browser', {
      onFocusWindowOk: () => { ok += 1 },
      onFocusWindowError: (code, message) => errors.push([code, message]),
    })
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))

    s.focusWindow('focus-window', 'win-main')
    expect(lastText(t)).toEqual({
      type: 'focus_window',
      request_id: 'focus-window',
      window_id: 'win-main',
    })
    t.emitText(JSON.stringify({ type: 'focus_window_ok', request_id: 'focus-window' }))
    t.emitText(JSON.stringify({ type: 'focus_window_error', request_id: 'focus-window', code: 'not_implemented', message: 'live desktop focus hook not ready' }))
    expect(ok).toBe(1)
    expect(errors).toEqual([['not_implemented', 'live desktop focus hook not ready']])
  })

  it('attach_ok wires the channel; input is sent as a binary terminal_input frame', () => {
    session.attach('s1', 80, 24)
    t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach', session_id: 's1', channel: 5 }))
    expect(attached).toEqual([{ id: 's1', channel: 5 }])
    expect(session.channel).toBe(5)

    session.sendKey({ key: 'a', ctrlKey: false, altKey: false, metaKey: false, shiftKey: false })
    expect(t.sentBinary).toHaveLength(1)
    const frame = t.sentBinary[0]!
    expect(frame[1]).toBe(FrameKind.TerminalInput)
    // channel 5 in the header
    expect(frame[3]).toBe(5)
  })

  it('sends a multi-codepoint IME commit as one literal interactive UTF-8 input frame', () => {
    session.attach('s1', 80, 24)
    t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach', session_id: 's1', channel: 5 }))

    session.sendText('e\u0301👩🏽‍💻')

    expect(t.sentBinary).toHaveLength(1)
    const decoded = decodeFrame(t.sentBinary[0]!)
    expect('ok' in decoded).toBe(true)
    if ('ok' in decoded) {
      expect(decoded.ok.kind).toBe(FrameKind.TerminalInput)
      expect(decoded.ok.channel).toBe(5)
      expect(new TextDecoder().decode(decoded.ok.payload)).toBe('e\u0301👩🏽‍💻')
    }
  })

  it('a rejected stale attach_ok drains without replacing the current channel or held terminal modes', () => {
    const transport = new FakeTransport()
    const accepted: { id: string; channel: number }[] = []
    const guarded = new RemoteSession(transport, 'tok', 'dev_browser', {
      shouldAcceptAttach: (id) => id !== 'stale',
      onAttached: (id, channel) => accepted.push({ id, channel }),
    })
    transport.emitState('connected')
    transport.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    guarded.attach('current', 80, 24)
    transport.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'current', session_id: 'current', channel: 1 }))
    transport.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
      ev: 'grid',
      id: 'current',
      grid: { ...makeV2Grid(), app_cursor: true },
    }))))
    expect(guarded.channel).toBe(1)
    expect(guarded.liveModes()?.app_cursor).toBe(true)

    guarded.attach('stale', 80, 24)
    transport.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'stale', session_id: 'stale', channel: 2 }))

    expect(accepted).toEqual([{ id: 'current', channel: 1 }])
    expect(guarded.channel).toBe(1)
    expect(guarded.liveModes()?.app_cursor).toBe(true)
    expect(textsOfType(transport, 'detach').at(-1)).toEqual({ type: 'detach', session_id: 'stale' })
  })

  it('resize/detach use the attached session id', () => {
    emitAgentHello(t)
    session.attach('s1', 80, 24)
    t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach', session_id: 's1', channel: 1 }))
    session.resize(100, 30)
    expect(t.sentText.map((s) => JSON.parse(s)).find((m) => m.type === 'resize')).toMatchObject({
      session_id: 's1',
      cols: 100,
      rows: 30,
      viewed: true,
    })
    session.resizeSession('s-background', 90, 20, false)
    expect(textsOfType(t, 'resize').at(-1)).toEqual({
      type: 'resize',
      session_id: 's-background',
      cols: 90,
      rows: 20,
      viewed: false,
    })
    session.detach()
    expect(t.sentText.map((s) => JSON.parse(s)).find((m) => m.type === 'detach')).toMatchObject({ session_id: 's1' })
    expect(session.channel).toBe(null)
  })

  it('detachSession sends a detach for a specific attached session without requiring it to be active', () => {
    session.attach('s1', 80, 24)
    t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach-a', session_id: 's1', channel: 1 }))
    session.setActiveAttach('s2', 2)
    session.detachSession('s1')
    expect(t.sentText.map((s) => JSON.parse(s)).filter((m) => m.type === 'detach').at(-1)).toMatchObject({ session_id: 's1' })
    expect(session.channel).toBe(2)
  })

  it('forwards optional attach-error correlation while accepting legacy uncorrelated errors', () => {
    const transport = new FakeTransport()
    const errors: Array<{ code: string; correlation?: { requestId?: string; sessionId?: string } }> = []
    new RemoteSession(transport, 'tok', 'dev_browser', {
      onError: (code, _message, correlation) => errors.push({ code, correlation }),
    })
    transport.emitState('connected')
    transport.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'acct', device_id: 'dev_browser' }))
    transport.emitText(JSON.stringify({
      type: 'error',
      code: 'attach_failed',
      message: 'failed',
      request_id: 'req-1',
      session_id: 's1',
    }))
    transport.emitText(JSON.stringify({ type: 'error', code: 'not_attached', message: 'legacy' }))

    expect(errors).toEqual([
      { code: 'attach_failed', correlation: { requestId: 'req-1', sessionId: 's1' } },
      { code: 'not_attached', correlation: undefined },
    ])
  })
})

describe('RemoteSession — terminal_output rendering path', () => {
  it('feeds a daemon grid frame from terminal_output into the sync/render path (no throw)', () => {
    const t = new FakeTransport()
    const session = new RemoteSession(t, 'tok', 'dev_browser')
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    session.attach('s1', 80, 24)
    t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach', session_id: 's1', channel: 3 }))

    // a daemon grid event line, carried in a terminal_output binary frame on channel 3
    const gridLine = JSON.stringify({ ev: 'grid', id: 's1', grid: makeGrid() })
    const frame = encodeFrame(FrameKind.TerminalOutput, 3, new TextEncoder().encode(gridLine))
    // no renderer attached (no canvas in this unit test) → must not throw; sync state advances.
    expect(() => t.emitBinary(frame)).not.toThrow()

    // a frame for the WRONG channel is ignored
    const otherFrame = encodeFrame(FrameKind.TerminalOutput, 99, new TextEncoder().encode(gridLine))
    expect(() => t.emitBinary(otherFrame)).not.toThrow()
  })

  it('surfaces live grid snapshots to browser-local UI subscribers', () => {
    const t = new FakeTransport()
    const grids: unknown[] = []
    const session = new RemoteSession(t, 'tok', 'dev_browser', { onGridSnapshot: (g) => grids.push(g) })
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    session.attach('s1', 80, 24)
    t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach', session_id: 's1', channel: 3 }))

    const grid = makeV2Grid('hi')
    t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 3, new TextEncoder().encode(JSON.stringify({ ev: 'grid', id: 's1', grid }))))

    expect(grids).toEqual([grid])
  })

  it('paints each live Grid/Damage once across re-entrant unchanged highlights and repaints user changes immediately', () => {
    vi.stubGlobal('window', { devicePixelRatio: 1 })
    try {
      const t = new FakeTransport()
      let session!: RemoteSession
      session = new RemoteSession(t, 'tok', 'dev_browser', {
        // Mirrors remote-app: every accepted frame recomputes and republishes a fresh-but-equal span array.
        onGridSnapshot: () => session.setSearchHighlights([]),
      })
      t.emitState('connected')
      t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
      session.attach('s1', 1, 1)
      t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach', session_id: 's1', channel: 3 }))

      const first = recordingCanvas()
      session.attachRenderer(first.canvas)
      const grid = { ...makeV2Grid('A'), cursor_visible: false }
      t.emitBinary(encodeFrame(
        FrameKind.TerminalOutput,
        3,
        new TextEncoder().encode(JSON.stringify({ ev: 'grid', id: 's1', grid })),
      ))
      t.emitBinary(encodeFrame(
        FrameKind.TerminalOutput,
        3,
        new TextEncoder().encode(JSON.stringify({
          ev: 'damage',
          frame: damageForV2Grid('B'),
        })),
      ))
      expect(first.context.paintPasses).toBe(2)

      const selected = [{ row: 0, startCol: 0, endCol: 1, active: true }] as const
      session.setSearchHighlights(selected)
      expect(first.context.paintPasses).toBe(3) // user-driven change is synchronous
      session.setSearchHighlights([{ ...selected[0] }])
      expect(first.context.paintPasses).toBe(3) // structurally identical publication is a no-op

      session.attachRenderer(first.canvas)
      expect(first.context.paintPasses).toBe(3) // same DOM surface is idempotent
      const replacement = recordingCanvas()
      session.attachRenderer(replacement.canvas)
      expect(replacement.context.paintPasses).toBe(1) // a genuinely new surface replays once
      expect(replacement.context.texts.join('')).toContain('B')
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('repaints the held live Grid when terminal chrome replaces the canvas without another daemon frame', () => {
    vi.stubGlobal('window', { devicePixelRatio: 1 })
    try {
      const t = new FakeTransport()
      const session = new RemoteSession(t, 'tok', 'dev_browser')
      t.emitState('connected')
      t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
      session.attach('s1', 80, 24)
      t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach', session_id: 's1', channel: 3 }))

      const first = recordingCanvas()
      session.attachRenderer(first.canvas)
      const grid = { ...makeV2Grid('prompt'), cursor_visible: false }
      t.emitBinary(encodeFrame(
        FrameKind.TerminalOutput,
        3,
        new TextEncoder().encode(JSON.stringify({ ev: 'grid', id: 's1', grid })),
      ))
      expect(first.context.texts.join('')).toBe('prompt')

      // Sidebar pointer-up rebuilds the shell/canvas after its live ResizeObserver has already settled. If that
      // geometry is a daemon no-op, no later Grid arrives; the replacement canvas must replay local held state.
      const second = recordingCanvas()
      session.attachRenderer(second.canvas)
      expect(second.context.texts.join('')).toBe('prompt')
      expect(textsOfType(t, 'resize')).toEqual([])
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('asks the controller for a fresh baseline when damage arrives before the first grid', () => {
    const t = new FakeTransport()
    const baseline: { sessionId: string; reason: string }[] = []
    const session = new RemoteSession(t, 'tok', 'dev_browser', {
      onBaselineRequired: (sessionId, reason) => baseline.push({ sessionId, reason }),
    })
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    session.attach('s1', 80, 24)
    t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach', session_id: 's1', channel: 3 }))

    t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 3, new TextEncoder().encode(JSON.stringify({
      ev: 'damage',
      frame: {
        schema: 1,
        id: 's1',
        generation: '00000000-0000-0000-0000-000000000001',
        base_revision: 1,
        revision: 2,
        cols: 80,
        rows: 24,
        cursor: { line: 0, col: 0, shape: 'block', visible: true },
        modes: {
          app_cursor: false,
          bracketed_paste: false,
          focus_reporting: false,
          mouse_report: false,
          mouse_drag: false,
          mouse_motion: false,
          mouse_sgr: false,
        },
        ops: [],
      },
    }))))

    expect(baseline).toEqual([{ sessionId: 's1', reason: 'damage before grid' }])
  })

  it('lets an optional terminal-frame hook consume decoded inbound frames before the single renderer path', () => {
    const t = new FakeTransport()
    const seen: { kind: FrameKind; channel: number; text: string }[] = []
    const session = new RemoteSession(t, 'tok', 'dev_browser', {
      onTerminalFrame: (frame) => {
        seen.push({ kind: frame.kind, channel: frame.channel, text: new TextDecoder().decode(frame.payload) })
        return true
      },
    })
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    session.attach('s1', 80, 24)
    t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach', session_id: 's1', channel: 3 }))

    const gridLine = JSON.stringify({ ev: 'grid', id: 's1', grid: makeGrid() })
    t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 3, new TextEncoder().encode(gridLine)))

    expect(seen).toEqual([{ kind: FrameKind.TerminalOutput, channel: 3, text: gridLine }])
  })

  it('reports chunk progress only for the current attached channel', () => {
    const t = new FakeTransport()
    const progress: string[] = []
    const session = new RemoteSession(t, 'tok', 'dev_browser', {
      onTerminalProgress: (sessionId) => progress.push(sessionId),
    })
    const emitChunk = (channel: number, text: string, isLast: boolean) => {
      const bytes = new TextEncoder().encode(text)
      const payload = new Uint8Array(bytes.length + 1)
      payload[0] = isLast ? 1 : 0
      payload.set(bytes, 1)
      t.emitBinary(encodeFrame(FrameKind.TerminalOutputChunk, channel, payload))
    }
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    emitChunk(3, 'before-attach', false)
    session.attach('s1', 80, 24)
    t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach', session_id: 's1', channel: 3 }))
    emitChunk(9, 'wrong-channel', false)
    emitChunk(3, 'current', false)
    session.setActiveAttach('s2', 4)
    emitChunk(3, 'stale-channel', true)
    emitChunk(4, 'new-current', false)
    session.detach()
    emitChunk(4, 'after-detach', true)
    expect(progress).toEqual(['s1', 's2'])
  })

  it('preserves a partial frame across a focus switch away and back', () => {
    const t = new FakeTransport()
    const grids: unknown[] = []
    const session = new RemoteSession(t, 'tok', 'dev_browser', {
      onGridSnapshot: (grid) => grids.push(grid),
    })
    const emitChunk = (channel: number, bytes: Uint8Array, isLast: boolean) => {
      const payload = new Uint8Array(bytes.length + 1)
      payload[0] = isLast ? 1 : 0
      payload.set(bytes, 1)
      t.emitBinary(encodeFrame(FrameKind.TerminalOutputChunk, channel, payload))
    }
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    session.attach('s1', 80, 24)
    t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach', session_id: 's1', channel: 3 }))

    const grid = makeV2Grid('focus-safe')
    const line = new TextEncoder().encode(JSON.stringify({ ev: 'grid', id: 's1', grid }))
    const splitAt = Math.floor(line.length / 2)
    emitChunk(3, line.subarray(0, splitAt), false)
    session.setActiveAttach('s2', 4)
    session.setActiveAttach('s1', 3)
    emitChunk(3, line.subarray(splitAt), true)

    expect(grids).toEqual([grid])
  })

  it('explicit detach retires a non-focused channel partial frame', () => {
    const t = new FakeTransport()
    const grids: unknown[] = []
    const session = new RemoteSession(t, 'tok', 'dev_browser', {
      onGridSnapshot: (grid) => grids.push(grid),
    })
    const emitChunk = (channel: number, bytes: Uint8Array, isLast: boolean) => {
      const payload = new Uint8Array(bytes.length + 1)
      payload[0] = isLast ? 1 : 0
      payload.set(bytes, 1)
      t.emitBinary(encodeFrame(FrameKind.TerminalOutputChunk, channel, payload))
    }
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    session.attach('s1', 80, 24)
    t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach', session_id: 's1', channel: 3 }))

    const grid = makeV2Grid('retire')
    const line = new TextEncoder().encode(JSON.stringify({ ev: 'grid', id: 's1', grid }))
    const splitAt = Math.floor(line.length / 2)
    emitChunk(3, line.subarray(0, splitAt), false)
    session.setActiveAttach('s2', 4)
    session.detachSession('s1')
    session.setActiveAttach('s1', 3)
    emitChunk(3, line.subarray(splitAt), true)

    expect(grids).toEqual([])
  })
})

describe('RemoteSession — scrollback (daemon Scrollback protocol)', () => {
  let t: FakeTransport
  let session: RemoteSession
  let views: { atLive: boolean; offset: number; historyLen: number }[]

  function attached(rows = 24) {
    t = new FakeTransport()
    views = []
    session = new RemoteSession(t, 'tok', 'dev_browser', { onScrollView: (v) => views.push(v) })
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    session.attach('s1', 80, rows)
    t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach', session_id: 's1', channel: 1 }))
    // a grid sets gridRows/gridCols so scrollback count == visible rows
    const grid = {
      ...makeV2Grid('x'.repeat(80)),
      cols: 80,
      rows,
      rows_cells: Array.from({ length: rows }, () => Array.from({ length: 80 }, () => cell('x'))),
    }
    t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({ ev: 'grid', id: 's1', grid }))))
  }

  it('scrolling up emits an async scrollback request with the offset + prefetched row count', () => {
    attached(24)
    session.scrollByRows(5) // up 5 rows
    const sb = textsOfType(t, 'scrollback')
    expect(sb).toHaveLength(1)
    expect(sb[0]).toMatchObject({ type: 'scrollback', session_id: 's1', offset_from_top: 5, count: 96 })
    expect(session.atLive).toBe(false)
  })

  it('keeps copy metadata paired with a cached history revision and clears older-peer absence', () => {
    attached(1)
    const state = session as unknown as { displayedHistory: { revision: number; cols: number; row_copy?: unknown } }
    const row_copy = [{ starts_line: null, soft_wrap: true, excluded_columns: [] },
      { starts_line: false, soft_wrap: false, excluded_columns: [] }]
    const reply = { ev: 'scrollback_rows', id: 's1', generation: '00000000-0000-0000-0000-000000000001',
      revision: 7, history_len: 20, offset_from_top: 2, rows: [[cell('a')], [cell('b')]], row_copy }
    const send = (event: unknown) => t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1,
      new TextEncoder().encode(JSON.stringify(event))))
    session.scrollByRows(2)
    send({ ...reply, row_copy: [null] })
    expect(state.displayedHistory).toBeNull()
    session.scrollByRows(1)
    expect(textsOfType(t, 'scrollback').at(-1)?.offset_from_top).toBe(3)
    send({ ...reply, offset_from_top: 3, id: 'foreign', row_copy: [null] })
    send({ ...reply, offset_from_top: 3 })
    expect(state.displayedHistory).toMatchObject({ revision: 7, cols: 1, row_copy: [row_copy[0]] })
    session.scrollByRows(-1)
    expect(state.displayedHistory.row_copy).toEqual([row_copy[1]])
    const retained = state.displayedHistory
    session.scrollByRows(3)
    send({ ...reply, offset_from_top: 5, row_copy: [null] })
    expect(state.displayedHistory).toBe(retained)
    session.scrollByRows(1)
    expect(textsOfType(t, 'scrollback').at(-1)?.offset_from_top).toBe(6)
    send({ ...reply, offset_from_top: 6, row_copy: null })
    expect(state.displayedHistory.row_copy).toBeUndefined()
  })

  it('scrollback before attach is a no-op (no request)', () => {
    t = new FakeTransport()
    session = new RemoteSession(t, 'tok', 'dev_browser')
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    session.scrollByRows(5)
    expect(textsOfType(t, 'scrollback')).toHaveLength(0)
  })

  it('keeps a viewport taller than the one-page protocol cap at live', () => {
    attached(257)
    session.scrollByRows(20)
    expect(textsOfType(t, 'scrollback')).toHaveLength(0)
    expect(session.atLive).toBe(true)
  })

  it('returns to live when a replacement Grid grows beyond the one-page cap', () => {
    attached(24)
    session.scrollByRows(5)
    t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
      ev: 'scrollback_rows', id: 's1', generation: '00000000-0000-0000-0000-000000000001',
      revision: 1, history_len: 100, offset_from_top: 5,
      rows: Array.from({ length: 24 }, () => [cell('h')]),
    }))))
    expect(session.atLive).toBe(false)

    const tall = {
      ...makeV2Grid('n'.repeat(80)), revision: 2, base_revision: 1, cols: 80, rows: 257,
      rows_cells: Array.from({ length: 257 }, () => Array.from({ length: 80 }, () => cell('n'))),
    }
    t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
      ev: 'grid', id: 's1', grid: tall,
    }))))
    expect(session.atLive).toBe(true)
    const before = textsOfType(t, 'scrollback').length
    session.scrollByRows(10)
    expect(textsOfType(t, 'scrollback')).toHaveLength(before)
  })

  it('ignores a same-offset reply for another session without settling the current owner', async () => {
    vi.useFakeTimers()
    try {
      attached(24)
      session.scrollByRows(5)
      t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
        ev: 'scrollback_rows', id: 's-other', generation: '00000000-0000-0000-0000-000000000001',
        revision: 1, history_len: 100, offset_from_top: 5, rows: [[cell('wrong')]],
      }))))
      await vi.advanceTimersByTimeAsync(SCROLLBACK_RESPONSE_TIMEOUT_MS - 1)
      expect(t.closed).toBe(false)
      t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
        ev: 'scrollback_rows', id: 's1', generation: '00000000-0000-0000-0000-000000000001',
        revision: 1, history_len: 100, offset_from_top: 5, rows: [[cell('right')]],
      }))))
      await vi.advanceTimersByTimeAsync(2)
      expect(t.closed).toBe(false)
      expect(session.atLive).toBe(false)
    } finally {
      vi.useRealTimers()
    }
  })

  it('settles a stale-generation reply by returning live without caching or timing out', async () => {
    vi.useFakeTimers()
    try {
      attached(24)
      session.scrollByRows(5)
      t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
        ev: 'scrollback_rows', id: 's1', generation: 'stale-generation',
        revision: 1, history_len: 100, offset_from_top: 5, rows: [[cell('stale')]],
      }))))
      expect(session.atLive).toBe(true)
      await vi.advanceTimersByTimeAsync(SCROLLBACK_RESPONSE_TIMEOUT_MS + 1)
      expect(t.closed).toBe(false)
    } finally {
      vi.useRealTimers()
    }
  })

  it('close synchronously retires pending attach and scrollback timers', async () => {
    vi.useFakeTimers()
    try {
      attached(24)
      session.scrollByRows(5)
      const fail = vi.spyOn(t, 'fail')
      session.close()
      expect(vi.getTimerCount()).toBe(0)
      await vi.advanceTimersByTimeAsync(SCROLLBACK_RESPONSE_TIMEOUT_MS + 1)
      expect(fail).not.toHaveBeenCalled()
    } finally {
      vi.useRealTimers()
    }
  })

  it('fails a lost scrollback reply only at the terminal response bound', async () => {
    vi.useFakeTimers()
    try {
      attached(24)
      session.scrollByRows(5)
      await vi.advanceTimersByTimeAsync(SCROLLBACK_RESPONSE_TIMEOUT_MS - 1)
      expect(t.closed).toBe(false)
      await vi.advanceTimersByTimeAsync(1)
      expect(t.closed).toBe(true)
    } finally {
      vi.useRealTimers()
    }
  })

  it('retiring the active channel cancels its lost-reply timeout', async () => {
    vi.useFakeTimers()
    try {
      attached(24)
      session.scrollByRows(5)
      session.detachSession('s1')
      await vi.advanceTimersByTimeAsync(SCROLLBACK_RESPONSE_TIMEOUT_MS + 1)
      expect(t.closed).toBe(false)
    } finally {
      vi.useRealTimers()
    }
  })

  it('does not settle another session trace that happens to use the same offset', async () => {
    vi.useFakeTimers()
    try {
      attached(24)
      const offset = session.requestInitialScrollbackWarm('s1', 24)!
      session.settleExternallyRoutedScrollback('s-other', offset)
      await vi.advanceTimersByTimeAsync(SCROLLBACK_RESPONSE_TIMEOUT_MS - 1)
      expect(t.closed).toBe(false)
      t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
        ev: 'scrollback_rows', id: 's1', generation: '00000000-0000-0000-0000-000000000001',
        revision: 1, history_len: 100, offset_from_top: offset,
        rows: Array.from({ length: 24 }, () => [cell('x')]),
      }))))
      await vi.advanceTimersByTimeAsync(2)
      expect(t.closed).toBe(false)
    } finally {
      vi.useRealTimers()
    }
  })

  it('handles scrollback_rows: learns history_len and notifies the scroll view', () => {
    attached(24)
    session.scrollByRows(10)
    t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
      ev: 'scrollback_rows', id: 's1', generation: '00000000-0000-0000-0000-000000000001',
      revision: 1, history_len: 200, offset_from_top: 10, rows: [[cell('o'), cell('l'), cell('d')]],
    }))))
    const last = views[views.length - 1]!
    expect(last).toMatchObject({ atLive: false, offset: 10, historyLen: 200 })
  })

  it('coalesces rapid scroll while pending, then requests only the latest uncached target', () => {
    attached(24)
    session.scrollByRows(3) // sends request 1 (pending)
    session.scrollByRows(3) // pending → suppressed
    expect(textsOfType(t, 'scrollback').map((m) => m.offset_from_top)).toEqual([3])

    t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
      ev: 'scrollback_rows', id: 's1', generation: '00000000-0000-0000-0000-000000000001',
      revision: 1, history_len: 200, offset_from_top: 3, rows: [[cell('3')]],
    }))))

    expect(textsOfType(t, 'scrollback').map((m) => m.offset_from_top)).toEqual([3, 6])
  })

  it('keeps one visible request in flight when the user reverses, then sends only the latest target', () => {
    attached(24)
    session.scrollByRows(60) // sends request 1, deeper than one viewport
    session.scrollByRows(-30) // reverse direction updates the target without admitting a second large reply
    expect(textsOfType(t, 'scrollback').map((m) => m.offset_from_top)).toEqual([60])

    // The old reply lands first. It may fill cache, but it must not clear the newer pending target.
    t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
      ev: 'scrollback_rows', id: 's1', generation: '00000000-0000-0000-0000-000000000001',
      revision: 1, history_len: 200, offset_from_top: 60, rows: [[cell('6')]],
    }))))
    expect(textsOfType(t, 'scrollback').map((m) => m.offset_from_top)).toEqual([60, 30])
    expect(views[views.length - 1]).toMatchObject({ atLive: false, offset: 30, historyLen: 200 })

    t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
      ev: 'scrollback_rows', id: 's1', generation: '00000000-0000-0000-0000-000000000001',
      revision: 1, history_len: 200, offset_from_top: 30, rows: [[cell('3')]],
    }))))
    expect(views[views.length - 1]).toMatchObject({ atLive: false, offset: 30, historyLen: 200 })
  })

  it('re-scrolling to a cached offset is instant — no second request', () => {
    attached(24)
    session.scrollByRows(6) // request offset 6
    t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
      ev: 'scrollback_rows', id: 's1', generation: '00000000-0000-0000-0000-000000000001',
      revision: 1, history_len: 200, offset_from_top: 6,
      rows: Array.from({ length: 24 }, () => [cell('a')]),
    }))))
    expect(textsOfType(t, 'scrollback')).toHaveLength(1)
    // go further then come back to offset 6 — should paint from cache, no new request for 6
    session.scrollByRows(6) // → offset 12 (new request)
    t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
      ev: 'scrollback_rows', id: 's1', generation: '00000000-0000-0000-0000-000000000001',
      revision: 1, history_len: 200, offset_from_top: 12,
      rows: Array.from({ length: 24 }, () => [cell('b')]),
    }))))
    session.scrollByRows(-6) // back to offset 6 — cached
    const sb = textsOfType(t, 'scrollback').map((m) => m.offset_from_top)
    expect(sb).toEqual([6, 12]) // offset 6 was NOT requested a second time
  })

  it('uses a prefetched scrollback window for nearby offsets without another desktop request', () => {
    attached(4)
    session.scrollByRows(8) // request offset 8, count 16
    t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
      ev: 'scrollback_rows', id: 's1', generation: '00000000-0000-0000-0000-000000000001',
      revision: 1, history_len: 200, offset_from_top: 8,
      rows: [
        [cell('8')], [cell('7')], [cell('6')], [cell('5')],
        [cell('4')], [cell('3')], [cell('2')], [cell('1')],
      ],
    }))))
    const before = textsOfType(t, 'scrollback').length
    session.scrollByRows(-2) // offset 6 is inside the fetched window
    expect(textsOfType(t, 'scrollback')).toHaveLength(before)
  })

  it('asynchronously prefetches the next deeper scrollback window after a visible reply', () => {
    vi.useFakeTimers()
    try {
      attached(4)
      session.scrollByRows(8) // visible request: count follows the live grid row count
      expect(textsOfType(t, 'scrollback')).toHaveLength(1)

      t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
        ev: 'scrollback_rows', id: 's1', generation: '00000000-0000-0000-0000-000000000001',
        revision: 1, history_len: 200, offset_from_top: 8,
        rows: [
          [cell('8')], [cell('7')], [cell('6')], [cell('5')],
          [cell('4')], [cell('3')], [cell('2')], [cell('1')],
        ],
      }))))

      expect(textsOfType(t, 'scrollback')).toHaveLength(1)
      vi.advanceTimersByTime(80)
      const sb = textsOfType(t, 'scrollback')
      expect(sb).toHaveLength(2)
      expect(sb[1]).toMatchObject({ type: 'scrollback', session_id: 's1', offset_from_top: 20, count: 16 })
    } finally {
      vi.useRealTimers()
    }
  })

  it('warms recent scrollback only when the controller requests it after the first grid', () => {
    attached(10)
    expect(textsOfType(t, 'scrollback')).toHaveLength(0)
    expect(session.requestInitialScrollbackWarm('s1', 10)).toBe(31)
    const sb = textsOfType(t, 'scrollback')
    expect(sb).toHaveLength(1)
    expect(sb[0]).toMatchObject({ type: 'scrollback', session_id: 's1', offset_from_top: 31, count: 40 })
    expect(session.atLive).toBe(true)
  })

  it('keeps ordinary pages at four viewports but caps a wide page to one complete viewport', () => {
    attached(24)
    expect(session.scrollbackRequestCount(24, 80)).toBe(96)
    expect(session.scrollbackRequestCount(70, 250)).toBe(70)
  })

  it('warms a wide terminal with one complete viewport instead of a multi-megabyte 256-row reply', () => {
    attached(70)
    expect(session.requestInitialScrollbackWarm('s1', 70, 250)).toBe(1)
    expect(textsOfType(t, 'scrollback').at(-1)).toMatchObject({
      session_id: 's1', offset_from_top: 1, count: 70,
    })
  })

  it('coalesces a 120-event gesture to one in-flight request and one latest target', () => {
    attached(70)
    for (let i = 0; i < 120; i++) session.scrollByRows(1)
    expect(textsOfType(t, 'scrollback').map((m) => m.offset_from_top)).toEqual([1])

    t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
      ev: 'scrollback_rows', id: 's1', generation: '00000000-0000-0000-0000-000000000001',
      revision: 1, history_len: 500, offset_from_top: 1, rows: [[cell('1')]],
    }))))
    expect(textsOfType(t, 'scrollback').map((m) => m.offset_from_top)).toEqual([1, 120])
  })

  it('does not recursively prefetch after the single adjacent look-ahead reply', () => {
    vi.useFakeTimers()
    try {
      attached(4)
      session.scrollByRows(8)
      t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
        ev: 'scrollback_rows', id: 's1', generation: '00000000-0000-0000-0000-000000000001',
        revision: 1, history_len: 200, offset_from_top: 8,
        rows: Array.from({ length: 8 }, (_, i) => [cell(String(i))]),
      }))))
      vi.advanceTimersByTime(80)
      const prefetch = textsOfType(t, 'scrollback').at(-1)!
      expect(prefetch).toMatchObject({ offset_from_top: 20, count: 16 })
      t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
        ev: 'scrollback_rows', id: 's1', generation: '00000000-0000-0000-0000-000000000001',
        revision: 1, history_len: 200, offset_from_top: 20,
        rows: Array.from({ length: 16 }, (_, i) => [cell(String(i))]),
      }))))
      vi.advanceTimersByTime(1_000)
      expect(textsOfType(t, 'scrollback')).toHaveLength(2)
    } finally {
      vi.useRealTimers()
    }
  })

  it('correlates a daemon-clamped offset and releases the sole in-flight request', () => {
    attached(24)
    session.scrollByRows(96)
    expect(textsOfType(t, 'scrollback').map((m) => m.offset_from_top)).toEqual([96])
    t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
      ev: 'scrollback_rows', id: 's1', generation: '00000000-0000-0000-0000-000000000001',
      revision: 1, history_len: 10, offset_from_top: 10,
      rows: Array.from({ length: 24 }, () => [cell('x')]),
    }))))
    session.scrollByRows(-5)
    expect(textsOfType(t, 'scrollback').map((m) => m.offset_from_top)).toEqual([96, 5])
  })

  it('detach clears the scroll cache', () => {
    attached(24)
    session.scrollByRows(6)
    t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
      ev: 'scrollback_rows', id: 's1', generation: '00000000-0000-0000-0000-000000000001',
      revision: 1, history_len: 200, offset_from_top: 6, rows: [[cell('a')]],
    }))))
    session.detach()
    expect(session.atLive).toBe(true) // back to live, scroll state reset
  })

  it('jumpToLive returns to live and reports atLive', () => {
    attached(24)
    session.scrollByRows(8)
    expect(session.atLive).toBe(false)
    session.jumpToLive()
    expect(session.atLive).toBe(true)
    expect(views[views.length - 1]).toMatchObject({ atLive: true, offset: 0 })
  })

  it('resize returns to live (no history reflow)', () => {
    attached(24)
    session.scrollByRows(8)
    expect(session.atLive).toBe(false)
    session.resize(100, 30)
    expect(session.atLive).toBe(true)
  })

  it('new output while scrolled up does NOT yank to live (stays in history view)', () => {
    attached(24)
    session.scrollByRows(8)
    // land the scrollback page so we're firmly in history view
    t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
      ev: 'scrollback_rows', id: 's1', generation: '00000000-0000-0000-0000-000000000001',
      revision: 1, history_len: 200, offset_from_top: 8, rows: [[cell('h')]],
    }))))
    expect(session.atLive).toBe(false)
    // live output arrives (a damage frame) — view must remain in history (still not at live)
    t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
      ev: 'damage', frame: { schema: 1, id: 's1', generation: '00000000-0000-0000-0000-000000000001',
        base_revision: 1, revision: 2, cols: 80, rows: 24, cursor: { row: 0, col: 0, shape: 'block', visible: true, blinking: false },
        modes: { app_cursor: false, bracketed_paste: false, focus_reporting: false, mouse: { mode: 'none', encoding: 'default' } },
        ops: [] },
    }))))
    expect(session.atLive).toBe(false)
  })

  it('replays the retained history viewport once when chrome replaces its canvas after live output', () => {
    vi.stubGlobal('window', { devicePixelRatio: 1 })
    try {
      attached(1)
      const first = recordingCanvas()
      session.attachRenderer(first.canvas)
      expect(first.context.paintPasses).toBe(1) // retained live Grid

      session.scrollByRows(1)
      t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
        ev: 'scrollback_rows', id: 's1', generation: '00000000-0000-0000-0000-000000000001',
        revision: 1, history_len: 20, offset_from_top: 1, rows: [[cell('H')]],
      }))))
      expect(first.context.paintPasses).toBe(2)

      // Live output invalidates the offset cache but intentionally leaves the displayed history pinned.
      t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(JSON.stringify({
        ev: 'damage',
        frame: {
          ...damageForV2Grid('N'), cols: 80, rows: 1, ops: [],
        },
      }))))
      expect(session.atLive).toBe(false)
      expect(first.context.paintPasses).toBe(2)

      session.attachRenderer(first.canvas)
      expect(first.context.paintPasses).toBe(2)
      const replacement = recordingCanvas()
      session.attachRenderer(replacement.canvas)
      expect(replacement.context.paintPasses).toBe(1)
      expect(replacement.context.texts.join('')).toContain('H')
      expect(replacement.context.texts.join('')).not.toContain('N')
    } finally {
      vi.unstubAllGlobals()
    }
  })
})

describe('RemoteSession — raw-PTY (xterm) renderer mode', () => {
  it('decodes a base64 output event and delivers raw bytes to onRawOutput', () => {
    const t = new FakeTransport()
    const got: Uint8Array[] = []
    const session = new RemoteSession(t, 'tok', 'dev_browser', { onRawOutput: (b) => got.push(b) })
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    session.attach('s1', 80, 24)
    t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach', session_id: 's1', channel: 1 }))
    // daemon raw Output event: data = base64("hi\r\n")
    const b64 = btoa('hi\r\n')
    const line = JSON.stringify({ ev: 'output', id: 's1', revision: 2, data: b64 })
    t.emitBinary(encodeFrame(FrameKind.TerminalOutput, 1, new TextEncoder().encode(line)))
    expect(got).toHaveLength(1)
    expect(new TextDecoder().decode(got[0]!)).toBe('hi\r\n')
  })

  it('sendRawInput sends a TerminalInput binary frame on the attached channel', () => {
    const t = new FakeTransport()
    const session = new RemoteSession(t, 'tok', 'dev_browser')
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    session.attach('s1', 80, 24)
    t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach', session_id: 's1', channel: 7 }))
    session.sendRawInput(new TextEncoder().encode('ls\n'))
    expect(t.sentBinary).toHaveLength(1)
    expect(t.sentBinary[0]![1]).toBe(FrameKind.TerminalInput)
    expect(t.sentBinary[0]![3]).toBe(7) // channel
  })

  it('sendRawInput chunks large input so every terminal_input frame fits the agent cap', () => {
    const t = new FakeTransport()
    const session = new RemoteSession(t, 'tok', 'dev_browser')
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    session.attach('s1', 80, 24)
    t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach', session_id: 's1', channel: 7 }))

    const bytes = new Uint8Array(MAX_INPUT_PAYLOAD + 3)
    bytes.fill(0x78)
    session.sendRawInput(bytes)

    expect(t.sentBinary).toHaveLength(2)
    const decoded = t.sentBinary.map((frame) => decodeFrame(frame))
    const payloads: Uint8Array[] = []
    for (const res of decoded) {
      expect('ok' in res).toBe(true)
      if ('ok' in res) {
        expect(res.ok.kind).toBe(FrameKind.TerminalInput)
        expect(res.ok.channel).toBe(7)
        expect(res.ok.payload.length).toBeLessThanOrEqual(MAX_INPUT_PAYLOAD)
        payloads.push(res.ok.payload)
      }
    }
    expect(payloads.map((p) => p.length)).toEqual([MAX_INPUT_PAYLOAD, 3])
  })

  it('admits a maximum bracketed paste as one ordered batch of independently balanced agent frames', () => {
    const t = new FakeTransport()
    const session = new RemoteSession(t, 'tok', 'dev_browser')
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    session.attach('s1', 80, 24)
    t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach', session_id: 's1', channel: 7 }))
    session.setActivePaneModesProvider(() => ({
      app_cursor: false,
      bracketed_paste: true,
      focus_reporting: false,
    }))

    session.sendPaste('x'.repeat(MAX_PASTE_BYTES + 100))

    expect(t.binaryBatchCalls).toBe(1)
    expect(t.bulkBinaryBatchCalls).toBe(1)
    expect(t.sentBinary).toHaveLength(MAX_PASTE_BYTES / MAX_INPUT_PAYLOAD)
    const payloads = t.sentBinary.map((frame) => {
      const decoded = decodeFrame(frame)
      expect('ok' in decoded).toBe(true)
      if ('err' in decoded) throw new Error(decoded.err.kind)
      expect(decoded.ok.kind).toBe(FrameKind.TerminalInput)
      expect(decoded.ok.channel).toBe(7)
      expect(decoded.ok.payload.byteLength).toBeLessThanOrEqual(MAX_INPUT_PAYLOAD)
      return decoded.ok.payload
    })
    const total = payloads.reduce((sum, payload) => sum + payload.byteLength, 0)
    expect(total).toBe(MAX_PASTE_BYTES)
    const decodedPayloads = payloads.map((payload) => new TextDecoder().decode(payload))
    expect(decodedPayloads.every((payload) => (
      payload.startsWith('\x1b[200~') && payload.endsWith('\x1b[201~')
    ))).toBe(true)
    const content = decodedPayloads.map((payload) => payload.slice(6, -6)).join('')
    expect(content).toBe('x'.repeat(MAX_PASTE_BYTES - payloads.length * 12))

    session.sendKey({ key: 'a', ctrlKey: false, metaKey: false, altKey: false, shiftKey: false })
    expect(t.binaryBatchCalls).toBe(2)
    expect(t.bulkBinaryBatchCalls).toBe(1)
    const final = decodeFrame(t.sentBinary[t.sentBinary.length - 1]!)
    expect('ok' in final && new TextDecoder().decode(final.ok.payload)).toBe('a')
  })

  it('fails a rejected logical paste without admitting a prefix, then a fresh owner can type', () => {
    const t = new FakeTransport()
    const session = new RemoteSession(t, 'tok', 'dev_browser')
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    session.attach('s1', 80, 24)
    t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach', session_id: 's1', channel: 7 }))
    t.dropBinaryBatchCount = 1

    session.sendRawInput(new Uint8Array(MAX_INPUT_PAYLOAD + 1))
    expect(t.sentBinary).toEqual([])
    expect(t.closed).toBe(true)

    const fresh = new FakeTransport()
    const reconnected = new RemoteSession(fresh, 'fresh-token', 'dev_browser')
    fresh.emitState('connected')
    fresh.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    reconnected.attach('s1', 80, 24)
    fresh.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach', session_id: 's1', channel: 8 }))
    reconnected.sendKey({ key: 'z', ctrlKey: false, metaKey: false, altKey: false, shiftKey: false })
    expect(fresh.sentBinary).toHaveLength(1)
    const decoded = decodeFrame(fresh.sentBinary[0]!)
    expect('ok' in decoded && new TextDecoder().decode(decoded.ok.payload)).toBe('z')
  })

  it('fails a refused structured-paste admission without reporting or recording a prefix', () => {
    const t = new FakeTransport()
    const session = new RemoteSession(t, 'tok', 'dev_browser')
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    session.attach('s1', 80, 24)
    t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach', session_id: 's1', channel: 7 }))
    t.dropBinaryBatchCount = 1

    session.sendPaste('x'.repeat(MAX_INPUT_PAYLOAD + 1))

    expect(t.bulkBinaryBatchCalls).toBe(1)
    expect(t.sentBinary).toEqual([])
    expect(t.closed).toBe(true)
  })

  it('retires the transport on an agent input-rate refusal instead of hiding a partial stream', () => {
    const t = new FakeTransport()
    const errors: string[] = []
    const states: ControlState[] = []
    new RemoteSession(t, 'tok', 'dev_browser', {
      onError: (code) => errors.push(code),
      onState: (state) => states.push(state),
    })
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    t.emitText(JSON.stringify({ type: 'error', code: 'input_rate_limited', message: 'input budget exceeded' }))
    expect(errors).toEqual(['input_rate_limited'])
    expect(t.closed).toBe(true)
    expect(states.filter((state) => state === 'closed')).toHaveLength(1)
    t.fail()
    expect(states.filter((state) => state === 'closed')).toHaveLength(1)
  })

  it('sendRawInput (paste) is a NO-OP before attach and after revoke — no input frame leaks', () => {
    const t = new FakeTransport()
    const session = new RemoteSession(t, 'tok', 'dev_browser')
    // pre-attach: nothing sent
    session.sendRawInput(new TextEncoder().encode('rm -rf /\n'))
    expect(t.sentBinary).toHaveLength(0)
    // after auth + attach: ok
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'a', device_id: 'dev_browser' }))
    session.attach('s1', 80, 24)
    t.emitText(JSON.stringify({ type: 'attach_ok', request_id: 'attach', session_id: 's1', channel: 1 }))
    // revoke tears down the attach → subsequent paste is a no-op (attachedChannel cleared)
    t.emitState('revoked')
    const before = t.sentBinary.length
    session.sendRawInput(new TextEncoder().encode('paste-after-revoke\n'))
    expect(t.sentBinary.length).toBe(before)
  })
})

// a minimal valid GridSnapshot the sync machine accepts
function makeGrid() {
  return {
    cols: 2,
    rows: 1,
    cursor: { row: 0, col: 0, shape: 'block', visible: true, blinking: false },
    app_cursor: false,
    bracketed_paste: false,
    focus_reporting: false,
    mouse: { mode: 'none', encoding: 'default' },
    generation: '00000000-0000-0000-0000-000000000001',
    revision: 1,
    rows_data: [[cell('h'), cell('i')]],
  }
}
function makeV2Grid(text = 'hi') {
  return {
    version: 2,
    generation: '00000000-0000-0000-0000-000000000001',
    revision: 1,
    base_revision: 0,
    cols: text.length,
    rows: 1,
    rows_cells: [Array.from(text).map(cell)],
    cursor_line: 0,
    cursor_col: 0,
    cursor_visible: true,
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
}
function damageForV2Grid(text: string) {
  return {
    schema: 1,
    id: 's1',
    generation: '00000000-0000-0000-0000-000000000001',
    base_revision: 1,
    revision: 2,
    cols: 1,
    rows: 1,
    cursor: { line: 0, col: 0, visible: false, shape: 'block' },
    modes: {
      alt_screen: false,
      app_cursor: false,
      bracketed_paste: false,
      focus_reporting: false,
      mouse_report: false,
      mouse_drag: false,
      mouse_motion: false,
      mouse_sgr: false,
    },
    ops: [{ op: 'row_span', row: 0, start: 0, cells: [cell(text)] }],
  }
}
function cell(text: string) {
  return {
    text,
    fg: { kind: 'named', name: 'foreground' },
    bg: { kind: 'named', name: 'background' },
    bold: false,
    italic: false,
    underline: 'none',
    inverse: false,
    strikeout: false,
    dim: false,
    hidden: false,
    width: 1,
  }
}

describe('RemoteSession — creation geometry', () => {
  function authed() {
    const transport = new FakeTransport()
    const session = new RemoteSession(transport, 'tok', 'dev_browser', {})
    transport.emitState('connected')
    transport.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'acct', device_id: 'dev_browser' }))
    return { transport, session }
  }

  it('emits the exact paired cols/rows on every session-creating request', () => {
    const { transport, session } = authed()
    const geometry = { cols: 132, rows: 41 }

    session.createSession('create-geometry', geometry)
    session.splitPane('split-geometry', 'win-1', 'pane-1', 'right', geometry)
    session.newPane('new-pane-geometry', 'win-1', 'pane-1', geometry)
    session.revivePane('revive-geometry', 'win-1', 'pane-2', geometry)
    session.startPaneSession('start-geometry', 'win-1', 'pane-3', geometry)
    session.newWindow('window-geometry', 'project-1', 'Window', geometry)
    session.createProject('project-geometry', { name: 'Project', root: '/work', ...geometry })

    expect(textsOfType(transport, 'create_session')).toEqual([{
      type: 'create_session',
      request_id: 'create-geometry',
      cols: 132,
      rows: 41,
    }])
    expect(textsOfType(transport, 'split_pane')).toEqual([{
      type: 'split_pane',
      request_id: 'split-geometry',
      window_id: 'win-1',
      from_pane_id: 'pane-1',
      dir: 'right',
      cols: 132,
      rows: 41,
    }])
    expect(textsOfType(transport, 'new_pane')).toEqual([{
      type: 'new_pane',
      request_id: 'new-pane-geometry',
      window_id: 'win-1',
      from_pane_id: 'pane-1',
      cols: 132,
      rows: 41,
    }])
    expect(textsOfType(transport, 'revive_pane')).toEqual([{
      type: 'revive_pane',
      request_id: 'revive-geometry',
      window_id: 'win-1',
      pane_id: 'pane-2',
      cols: 132,
      rows: 41,
    }])
    expect(textsOfType(transport, 'start_pane_session')).toEqual([{
      type: 'start_pane_session',
      request_id: 'start-geometry',
      window_id: 'win-1',
      pane_id: 'pane-3',
      cols: 132,
      rows: 41,
    }])
    expect(textsOfType(transport, 'new_window')).toEqual([{
      type: 'new_window',
      request_id: 'window-geometry',
      project_id: 'project-1',
      name: 'Window',
      cols: 132,
      rows: 41,
    }])
    expect(textsOfType(transport, 'project_create')).toEqual([{
      type: 'project_create',
      request_id: 'project-geometry',
      name: 'Project',
      root: '/work',
      cols: 132,
      rows: 41,
    }])
  })

  it('preserves legacy call and wire shapes when geometry is omitted', () => {
    const { transport, session } = authed()

    session.createSession('create-legacy')
    session.splitPane('split-legacy', 'win-1', 'pane-1', 'down')
    session.newPane('new-pane-legacy', 'win-1', 'pane-1')
    session.revivePane('revive-legacy', 'win-1', 'pane-2')
    session.startPaneSession('start-legacy', 'win-1', 'pane-3')
    session.newWindow('window-legacy', 'project-1', 'Window')
    session.createProject('project-legacy', { name: 'Project', root: '/work' })

    expect(textsOfType(transport, 'create_session')).toEqual([
      { type: 'create_session', request_id: 'create-legacy' },
    ])
    expect(textsOfType(transport, 'split_pane')).toEqual([{
      type: 'split_pane',
      request_id: 'split-legacy',
      window_id: 'win-1',
      from_pane_id: 'pane-1',
      dir: 'down',
    }])
    expect(textsOfType(transport, 'new_pane')).toEqual([{
      type: 'new_pane',
      request_id: 'new-pane-legacy',
      window_id: 'win-1',
      from_pane_id: 'pane-1',
    }])
    expect(textsOfType(transport, 'revive_pane')).toEqual([{
      type: 'revive_pane',
      request_id: 'revive-legacy',
      window_id: 'win-1',
      pane_id: 'pane-2',
    }])
    expect(textsOfType(transport, 'start_pane_session')).toEqual([{
      type: 'start_pane_session',
      request_id: 'start-legacy',
      window_id: 'win-1',
      pane_id: 'pane-3',
    }])
    expect(textsOfType(transport, 'new_window')).toEqual([{
      type: 'new_window',
      request_id: 'window-legacy',
      project_id: 'project-1',
      name: 'Window',
    }])
    expect(textsOfType(transport, 'project_create')).toEqual([{
      type: 'project_create',
      request_id: 'project-legacy',
      name: 'Project',
      root: '/work',
    }])
  })
})

describe('RemoteSession — capability-gated creation delivery replay', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  function authed(capabilities: unknown): { transport: FakeTransport; session: RemoteSession } {
    const transport = new FakeTransport()
    const session = new RemoteSession(transport, 'tok', 'dev_browser')
    transport.emitState('connected')
    emitAgentHello(transport, capabilities)
    transport.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'acct', device_id: 'dev_browser' }))
    return { transport, session }
  }

  it('retries the exact frozen frame once for every allocating creation kind', () => {
    const { transport, session } = authed([CREATION_REQUEST_REPLAY_CAPABILITY])
    session.createSession('replay-create', { cols: 101, rows: 31 })
    session.splitPane('replay-split', 'window', 'pane', 'right', { cols: 102, rows: 32 })
    session.newPane('replay-new-pane', 'window', 'pane', { cols: 103, rows: 33 })
    session.revivePane('replay-revive', 'window', 'pane', { cols: 104, rows: 34 })
    session.startPaneSession('replay-start', 'window', 'pane', { cols: 105, rows: 35 })
    session.newWindow('replay-window', 'project', 'Window', { cols: 106, rows: 36 })
    session.createProject('replay-project', { name: 'Project', root: '/work', cols: 107, rows: 37 })

    vi.advanceTimersByTime(CREATION_DELIVERY_RETRY_MS)

    for (const type of [
      'create_session',
      'split_pane',
      'new_pane',
      'revive_pane',
      'start_pane_session',
      'new_window',
      'project_create',
    ]) {
      const frames = transport.sentText.filter((frame) => JSON.parse(frame).type === type)
      expect(frames).toHaveLength(2)
      expect(frames[1]).toBe(frames[0])
    }
  })

  it('cancels a replay when the typed result arrives and refuses a changed frame under the same pending id', () => {
    const { transport, session } = authed([CREATION_REQUEST_REPLAY_CAPABILITY])
    session.createSession('same-id', { cols: 90, rows: 20 })
    session.createSession('same-id', { cols: 120, rows: 40 })
    transport.emitText(JSON.stringify({
      type: 'session_created',
      request_id: 'same-id',
      session_id: 'session-1',
    }))

    vi.advanceTimersByTime(CREATION_DELIVERY_RETRY_MS)

    expect(textsOfType(transport, 'create_session')).toEqual([{
      type: 'create_session',
      request_id: 'same-id',
      cols: 90,
      rows: 20,
    }])
  })

  it('keeps the request id and frozen frame locked after replay until its matching reply family arrives', () => {
    const { transport, session } = authed([CREATION_REQUEST_REPLAY_CAPABILITY])
    session.createSession('same-id', { cols: 90, rows: 20 })

    // A typed reply for a different creation family must not cancel this request's delivery retry.
    transport.emitText(JSON.stringify({
      type: 'new_window_error',
      request_id: 'same-id',
      code: 'missing',
      message: 'wrong family',
    }))
    vi.advanceTimersByTime(CREATION_DELIVERY_RETRY_MS)

    // Even after the one replay fired, the id remains bound to its exact original frame.
    session.createSession('same-id', { cols: 120, rows: 40 })
    const frames = transport.sentText.filter((frame) => JSON.parse(frame).type === 'create_session')
    expect(frames).toHaveLength(2)
    expect(frames[1]).toBe(frames[0])

    transport.emitText(JSON.stringify({
      type: 'session_created',
      request_id: 'same-id',
      session_id: 'session-1',
    }))
  })

  it('never retries against a legacy/near-match peer and cancels all timers when the transport retires', () => {
    const legacy = authed([])
    legacy.session.createSession('legacy')
    vi.advanceTimersByTime(CREATION_DELIVERY_RETRY_MS)
    expect(textsOfType(legacy.transport, 'create_session')).toHaveLength(1)

    const capable = authed([CREATION_REQUEST_REPLAY_CAPABILITY])
    capable.session.createSession('retired')
    capable.transport.emitState('closed')
    vi.advanceTimersByTime(CREATION_DELIVERY_RETRY_MS)
    expect(textsOfType(capable.transport, 'create_session')).toHaveLength(1)

    const explicitlyClosed = authed([CREATION_REQUEST_REPLAY_CAPABILITY])
    explicitlyClosed.session.createSession('explicit-close')
    explicitlyClosed.session.close()
    vi.advanceTimersByTime(CREATION_DELIVERY_RETRY_MS)
    expect(textsOfType(explicitlyClosed.transport, 'create_session')).toHaveLength(1)
  })
})

describe('RemoteSession — creation reply correlation', () => {
  it('appends the exact request_id to every creation success and error callback', () => {
    const transport = new FakeTransport()
    const calls: unknown[][] = []
    new RemoteSession(transport, 'tok', 'dev_browser', {
      onSessionCreated: (...args) => calls.push(['session_created', ...args]),
      onSessionCreateError: (...args) => calls.push(['session_create_error', ...args]),
      onSplitPaneOk: (...args) => calls.push(['split_pane_ok', ...args]),
      onSplitPaneError: (...args) => calls.push(['split_pane_error', ...args]),
      onRevivePaneOk: (...args) => calls.push(['revive_pane_ok', ...args]),
      onRevivePaneError: (...args) => calls.push(['revive_pane_error', ...args]),
      onStartPaneSessionOk: (...args) => calls.push(['start_pane_session_ok', ...args]),
      onStartPaneSessionError: (...args) => calls.push(['start_pane_session_error', ...args]),
      onNewWindowOk: (...args) => calls.push(['new_window_ok', ...args]),
      onNewWindowError: (...args) => calls.push(['new_window_error', ...args]),
      onProjectEditOk: (...args) => calls.push(['project_edit_ok', ...args]),
      onProjectEditError: (...args) => calls.push(['project_edit_error', ...args]),
    })
    transport.emitState('connected')
    transport.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'acct', device_id: 'dev_browser' }))

    const replies = [
      { type: 'session_created', request_id: 'create-ok', session_id: 'session-1' },
      { type: 'session_create_error', request_id: 'create-error', code: 'limit_reached', message: 'full' },
      { type: 'split_pane_ok', request_id: 'split-ok', session_id: 'session-2', tab_id: 'pane-2' },
      { type: 'split_pane_error', request_id: 'split-error', code: 'pane_limit', message: 'full' },
      { type: 'revive_pane_ok', request_id: 'revive-ok', session_id: 'session-3' },
      { type: 'revive_pane_error', request_id: 'revive-error', code: 'missing', message: 'gone' },
      { type: 'start_pane_session_ok', request_id: 'start-ok', session_id: 'session-4' },
      { type: 'start_pane_session_error', request_id: 'start-error', code: 'missing', message: 'gone' },
      { type: 'new_window_ok', request_id: 'window-ok', window_id: 'window-2', session_id: 'session-5' },
      { type: 'new_window_error', request_id: 'window-error', code: 'missing', message: 'gone' },
      { type: 'project_edit_ok', request_id: 'project-ok', project_id: 'project-2', session_id: 'session-6' },
      { type: 'project_edit_error', request_id: 'project-error', code: 'invalid', message: 'bad' },
    ]
    for (const reply of replies) transport.emitText(JSON.stringify(reply))

    expect(calls).toEqual([
      ['session_created', 'session-1', undefined, 'create-ok'],
      ['session_create_error', 'limit_reached', 'full', 'create-error'],
      ['split_pane_ok', 'session-2', 'pane-2', 'split-ok'],
      ['split_pane_error', 'pane_limit', 'full', 'split-error'],
      ['revive_pane_ok', 'session-3', 'revive-ok'],
      ['revive_pane_error', 'missing', 'gone', 'revive-error'],
      ['start_pane_session_ok', 'session-4', 'start-ok'],
      ['start_pane_session_error', 'missing', 'gone', 'start-error'],
      ['new_window_ok', 'window-2', 'session-5', 'window-ok'],
      ['new_window_error', 'missing', 'gone', 'window-error'],
      ['project_edit_ok', 'project-2', 'session-6', 'project-ok'],
      ['project_edit_error', 'invalid', 'bad', 'project-error'],
    ])
  })
})

describe('RemoteSession — create_session (Slice E)', () => {
  function authed() {
    const t = new FakeTransport()
    const created: string[] = []
    const errors: [string, string][] = []
    const session = new RemoteSession(t, 'tok', 'dev_browser', {
      onSessionCreated: (sid) => created.push(sid),
      onSessionCreateError: (code, msg) => errors.push([code, msg]),
    })
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'acct', device_id: 'dev_browser' }))
    return { t, session, created, errors }
  }

  it('createSession is a NO-OP before auth (no message sent)', () => {
    const t = new FakeTransport()
    const session = new RemoteSession(t, 'tok', 'dev_browser', {})
    t.emitState('connected') // not authed
    session.createSession('c1')
    expect(t.sentText.map((s) => JSON.parse(s).type)).not.toContain('create_session')
  })

  it('after auth, createSession sends a create_session request', () => {
    const { t, session } = authed()
    session.createSession('c1')
    const sent = t.sentText.map((s) => JSON.parse(s)).find((m) => m.type === 'create_session')
    expect(sent).toMatchObject({ type: 'create_session', request_id: 'c1' })
  })

  it('session_created reply fires onSessionCreated with the new id', () => {
    const { t, created } = authed()
    t.emitText(JSON.stringify({ type: 'session_created', request_id: 'c1', session_id: 's-abc12' }))
    expect(created).toEqual(['s-abc12'])
  })

  it('session_create_error reply fires onSessionCreateError with the code', () => {
    const { t, errors } = authed()
    t.emitText(JSON.stringify({ type: 'session_create_error', request_id: 'c1', code: 'limit_reached', message: 'too many' }))
    expect(errors).toEqual([['limit_reached', 'too many']])
  })

  it('malformed / non-matching replies are ignored safely', () => {
    const { t, created, errors } = authed()
    t.emitText(JSON.stringify({ type: 'session_created', request_id: 'c1' })) // no session_id
    t.emitText(JSON.stringify({ type: 'pong', nonce: 'n' }))
    t.emitText('not json')
    expect(created).toEqual([])
    expect(errors).toEqual([])
  })
})

describe('RemoteSession — session labels (F1)', () => {
  function authed() {
    const t = new FakeTransport()
    const created: Array<[string, string | undefined]> = []
    const session = new RemoteSession(t, 'tok', 'dev_browser', {
      onSessionCreated: (sid, label) => created.push([sid, label]),
    })
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'acct', device_id: 'dev_browser' }))
    return { t, session, created }
  }

  it('createSession sends the label when provided', () => {
    const { t, session } = authed()
    session.createSession('c1', 'build logs')
    const sent = t.sentText.map((s) => JSON.parse(s)).find((m) => m.type === 'create_session')
    expect(sent).toMatchObject({ type: 'create_session', request_id: 'c1', label: 'build logs' })
  })

  it('createSession sends desktop launch context when provided', () => {
    const { t, session } = authed()
    session.createSession('c1', {
      label: 'API pane',
      cwd: '/Users/test/home/app',
      agent: 'claude',
      launchFlags: { resumeMode: 'continue', model: 'opus' },
    })
    const sent = t.sentText.map((s) => JSON.parse(s)).find((m) => m.type === 'create_session')
    expect(sent).toMatchObject({
      type: 'create_session',
      request_id: 'c1',
      label: 'API pane',
      cwd: '/Users/test/home/app',
      agent: 'claude',
      launch_flags: { resumeMode: 'continue', model: 'opus' },
    })
  })

  it('createSession with no label omits it (old-client shape)', () => {
    const { t, session } = authed()
    session.createSession('c1')
    const sent = t.sentText.map((s) => JSON.parse(s)).find((m) => m.type === 'create_session')
    expect(sent).toEqual({ type: 'create_session', request_id: 'c1' })
  })

  it('onSessionCreated carries the echoed label', () => {
    const { t, created } = authed()
    t.emitText(JSON.stringify({ type: 'session_created', request_id: 'c1', session_id: 's-x', label: 'logs' }))
    expect(created).toEqual([['s-x', 'logs']])
  })
})

describe('RemoteSession — split_pane', () => {
  function authed() {
    const t = new FakeTransport()
    const oks: [string, string][] = []
    const errors: [string, string][] = []
    const session = new RemoteSession(t, 'tok', 'dev_browser', {
      onSplitPaneOk: (sid, tabId) => oks.push([sid, tabId]),
      onSplitPaneError: (code, msg) => errors.push([code, msg]),
    })
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'acct', device_id: 'dev_browser' }))
    return { t, session, oks, errors }
  }

  it('splitPane is a NO-OP before auth', () => {
    const t = new FakeTransport()
    const session = new RemoteSession(t, 'tok', 'dev_browser', {})
    t.emitState('connected')
    session.splitPane('sp1', 'win-main', 'pane-build', 'right')
    expect(textsOfType(t, 'split_pane')).toHaveLength(0)
  })

  it('splitPane sends the desktop window and source pane ids after auth', () => {
    const { t, session } = authed()
    session.splitPane('sp1', 'win-main', 'pane-build', 'right', { agent: 'codex' })
    const sent = textsOfType(t, 'split_pane')[0]
    expect(sent).toEqual({
      type: 'split_pane',
      request_id: 'sp1',
      window_id: 'win-main',
      from_pane_id: 'pane-build',
      dir: 'right',
      agent: 'codex',
    })
  })

  it('newPane sends new_pane after auth and does not use split_pane', () => {
    const { t, session } = authed()
    session.newPane('np1', 'win-main', 'pane-build', {
      agent: 'codex',
      cwd: ' /tmp/review ',
      paneName: '  Review  ',
      launchFlags: { model: 'gpt-5.2-codex' },
    })
    expect(textsOfType(t, 'split_pane')).toHaveLength(0)
    expect(textsOfType(t, 'new_pane')[0]).toEqual({
      type: 'new_pane',
      request_id: 'np1',
      window_id: 'win-main',
      from_pane_id: 'pane-build',
      agent: 'codex',
      cwd: '/tmp/review',
      pane_name: 'Review',
      launch_flags: { model: 'gpt-5.2-codex' },
    })
  })

  it('split_pane replies fire the split callbacks', () => {
    const { t, oks, errors } = authed()
    t.emitText(JSON.stringify({ type: 'split_pane_ok', request_id: 'sp1', session_id: 's-new', tab_id: 'pane-new' }))
    t.emitText(JSON.stringify({ type: 'split_pane_error', request_id: 'sp2', code: 'pane_limit', message: 'too many panes' }))
    expect(oks).toEqual([['s-new', 'pane-new']])
    expect(errors).toEqual([['pane_limit', 'too many panes']])
  })
})

describe('RemoteSession — revive_pane', () => {
  function authed() {
    const t = new FakeTransport()
    const oks: string[] = []
    const errors: [string, string][] = []
    const session = new RemoteSession(t, 'tok', 'dev_browser', {
      onRevivePaneOk: (sid) => oks.push(sid),
      onRevivePaneError: (code, msg) => errors.push([code, msg]),
    })
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'acct', device_id: 'dev_browser' }))
    return { t, session, oks, errors }
  }

  it('revivePane is a NO-OP before auth', () => {
    const t = new FakeTransport()
    const session = new RemoteSession(t, 'tok', 'dev_browser', {})
    t.emitState('connected')
    session.revivePane('rp1', 'win-main', 'pane-old')
    expect(textsOfType(t, 'revive_pane')).toHaveLength(0)
  })

  it('revivePane sends the desktop window and stashed pane ids after auth', () => {
    const { t, session } = authed()
    session.revivePane('rp1', 'win-main', 'pane-old')
    expect(textsOfType(t, 'revive_pane')[0]).toEqual({
      type: 'revive_pane',
      request_id: 'rp1',
      window_id: 'win-main',
      pane_id: 'pane-old',
    })
  })

  it('revive_pane replies fire the revive callbacks', () => {
    const { t, oks, errors } = authed()
    t.emitText(JSON.stringify({ type: 'revive_pane_ok', request_id: 'rp1', session_id: 's-old' }))
    t.emitText(JSON.stringify({ type: 'revive_pane_error', request_id: 'rp2', code: 'pane_not_found', message: 'missing' }))
    expect(oks).toEqual(['s-old'])
    expect(errors).toEqual([['pane_not_found', 'missing']])
  })
})

describe('RemoteSession — new_window', () => {
  function authed() {
    const t = new FakeTransport()
    const oks: [string, string][] = []
    const errors: [string, string][] = []
    const session = new RemoteSession(t, 'tok', 'dev_browser', {
      onNewWindowOk: (windowId, sid) => oks.push([windowId, sid]),
      onNewWindowError: (code, msg) => errors.push([code, msg]),
    })
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'acct', device_id: 'dev_browser' }))
    return { t, session, oks, errors }
  }

  it('newWindow is a NO-OP before auth', () => {
    const t = new FakeTransport()
    const session = new RemoteSession(t, 'tok', 'dev_browser', {})
    t.emitState('connected')
    session.newWindow('nw1', 'proj-capacity', 'Experiment')
    expect(textsOfType(t, 'new_window')).toHaveLength(0)
  })

  it('newWindow sends project/name/cwd/agent after auth', () => {
    const { t, session } = authed()
    session.newWindow('nw1', 'proj-capacity', 'Experiment', { cwd: '/tmp/experiment', agent: 'codex' })
    expect(textsOfType(t, 'new_window')[0]).toEqual({
      type: 'new_window',
      request_id: 'nw1',
      project_id: 'proj-capacity',
      name: 'Experiment',
      cwd: '/tmp/experiment',
      agent: 'codex',
    })
  })

  it('new_window replies fire the window callbacks', () => {
    const { t, oks, errors } = authed()
    t.emitText(JSON.stringify({ type: 'new_window_ok', request_id: 'nw1', window_id: 'w-new', session_id: 's-new' }))
    t.emitText(JSON.stringify({ type: 'new_window_error', request_id: 'nw2', code: 'project_not_found', message: 'missing' }))
    expect(oks).toEqual([['w-new', 's-new']])
    expect(errors).toEqual([['project_not_found', 'missing']])
  })
})

describe('RemoteSession — agent session list (gap-doc Step 2a)', () => {
  function authed() {
    const t = new FakeTransport()
    const results: import('../protocol/control-messages').AgentSessionsResultMsg[] = []
    const previews: import('../protocol/control-messages').AgentSessionPreviewReply[] = []
    const managed: import('../protocol/control-messages').AgentSessionManageReply[] = []
    const session = new RemoteSession(t, 'tok', 'dev_browser', {
      onAgentSessions: (r) => results.push(r),
      onAgentSessionPreview: (r) => previews.push(r),
      onAgentSessionManaged: (r) => managed.push(r),
    })
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'acct', device_id: 'dev_browser' }))
    return { t, session, results, previews, managed }
  }

  it('listAgentSessions sends the content-blind request after auth', () => {
    const { t, session } = authed()
    session.listAgentSessions('hist:gemini', 'gemini', '/Users/test/home/app')
    const sent = t.sentText.map((s) => JSON.parse(s)).find((m) => m.type === 'list_agent_sessions')
    expect(sent).toEqual({ type: 'list_agent_sessions', request_id: 'hist:gemini', agent: 'gemini', cwd: '/Users/test/home/app' })
  })

  it('listDirectories sends the content-blind desktop folder request after auth', () => {
    const { t, session } = authed()
    session.listDirectories('dirs:1', '/Users/test/home/Desktop')
    const sent = t.sentText.map((s) => JSON.parse(s)).find((m) => m.type === 'list_directories')
    expect(sent).toEqual({ type: 'list_directories', request_id: 'dirs:1', path: '/Users/test/home/Desktop' })
  })

  it('directories_result fires onDirectoriesResult with directory metadata', () => {
    const t = new FakeTransport()
    const results: import('../protocol/control-messages').DirectoriesResultMsg[] = []
    new RemoteSession(t, 'tok', 'dev_browser', {
      onDirectoriesResult: (r) => results.push(r),
    })
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'acct', device_id: 'dev_browser' }))
    t.emitText(JSON.stringify({
      type: 'directories_result',
      request_id: 'dirs:1',
      path: '/Users/test/home',
      parent: '/Users',
      entries: [{ name: 'Desktop', path: '/Users/test/home/Desktop', file_count: 999 }],
    }))
    expect(results).toEqual([{
      type: 'directories_result',
      request_id: 'dirs:1',
      path: '/Users/test/home',
      parent: '/Users',
      entries: [{ name: 'Desktop', path: '/Users/test/home/Desktop' }],
    }])
  })

  it('routes typed directory and agent-session errors to their dedicated callbacks', () => {
    const t = new FakeTransport()
    const directoryErrors: import('../protocol/control-messages').DirectoriesErrorMsg[] = []
    const sessionErrors: import('../protocol/control-messages').AgentSessionsErrorMsg[] = []
    new RemoteSession(t, 'tok', 'dev_browser', {
      onDirectoriesError: (error) => directoryErrors.push(error),
      onAgentSessionsError: (error) => sessionErrors.push(error),
    })
    t.emitState('connected')
    t.emitText(JSON.stringify({ type: 'auth_ok', account_id: 'acct', device_id: 'dev_browser' }))
    const common = {
      code: 'macos_full_disk_access_required',
      message: 'untrusted',
    }
    t.emitText(JSON.stringify({ type: 'directories_error', request_id: 'dirs:2', ...common }))
    t.emitText(JSON.stringify({ type: 'agent_sessions_error', request_id: 'hist:2', ...common }))
    expect(directoryErrors).toEqual([{ type: 'directories_error', request_id: 'dirs:2', ...common }])
    expect(sessionErrors).toEqual([{ type: 'agent_sessions_error', request_id: 'hist:2', ...common }])
  })

  it('agent_sessions_result fires onAgentSessions with parsed metadata', () => {
    const { t, results } = authed()
    t.emitText(JSON.stringify({
      type: 'agent_sessions_result',
      request_id: 'hist:codex',
      sessions: [{ id: 'sess-a', agent: 'codex', modified_at_ms: 2000, message_count: 4, in_use: true }],
    }))
    expect(results).toEqual([{
      type: 'agent_sessions_result',
      request_id: 'hist:codex',
      sessions: [{ id: 'sess-a', agent: 'codex', modifiedAtMs: 2000, messageCount: 4, inUse: true }],
    }])
  })

  it('previewAgentSession sends the explicit content-preview request after auth', () => {
    const { t, session } = authed()
    session.previewAgentSession('preview:gemini:sess-a', 'gemini', 'sess-a', '/Users/test/home/app', 20)
    const sent = t.sentText.map((s) => JSON.parse(s)).find((m) => m.type === 'preview_agent_session')
    expect(sent).toEqual({
      type: 'preview_agent_session',
      request_id: 'preview:gemini:sess-a',
      agent: 'gemini',
      session_id: 'sess-a',
      cwd: '/Users/test/home/app',
      max_lines: 20,
    })
  })

  it('agent_session_preview fires onAgentSessionPreview with transcript lines', () => {
    const { t, previews } = authed()
    t.emitText(JSON.stringify({
      type: 'agent_session_preview',
      request_id: 'preview:codex:sess-a',
      lines: [{ role: 'user', text: 'please inspect local dashboard' }],
    }))
    expect(previews).toEqual([{
      type: 'agent_session_preview',
      request_id: 'preview:codex:sess-a',
      lines: [{ role: 'user', text: 'please inspect local dashboard' }],
    }])
  })

  it('manageAgentSession sends rename/hide/delete requests after auth', () => {
    const { t, session } = authed()
    session.manageAgentSession('manage:rename', 'rename', 'claude', 'sess-a', { name: ' Cleaned up ' })
    session.manageAgentSession('manage:hide', 'hide', 'codex', 'sess-b')
    session.manageAgentSession('manage:delete', 'delete', 'gemini', 'sess-c', { cwd: '/Users/test/home/app' })
    const sent = t.sentText.map((s) => JSON.parse(s)).filter((m) => m.type === 'manage_agent_session')
    expect(sent).toEqual([
      {
        type: 'manage_agent_session',
        request_id: 'manage:rename',
        action: 'rename',
        agent: 'claude',
        session_id: 'sess-a',
        name: 'Cleaned up',
      },
      {
        type: 'manage_agent_session',
        request_id: 'manage:hide',
        action: 'hide',
        agent: 'codex',
        session_id: 'sess-b',
      },
      {
        type: 'manage_agent_session',
        request_id: 'manage:delete',
        action: 'delete',
        agent: 'gemini',
        session_id: 'sess-c',
        cwd: '/Users/test/home/app',
      },
    ])
  })

  it('manageAgentSession is a NO-OP before auth', () => {
    const t = new FakeTransport()
    const session = new RemoteSession(t, 'tok', 'dev_browser', {})
    t.emitState('connected')
    session.manageAgentSession('manage:rename', 'rename', 'claude', 'sess-a', { name: 'Cleaned up' })
    expect(t.sentText.map((s) => JSON.parse(s)).filter((m) => m.type === 'manage_agent_session')).toHaveLength(0)
  })

  it('agent_session_manage replies fire onAgentSessionManaged', () => {
    const { t, managed } = authed()
    t.emitText(JSON.stringify({ type: 'agent_session_managed', request_id: 'manage:rename' }))
    t.emitText(JSON.stringify({
      type: 'agent_session_manage_error',
      request_id: 'manage:delete',
      code: 'not_found',
      message: 'gone',
    }))
    expect(managed).toEqual([
      { type: 'agent_session_managed', request_id: 'manage:rename' },
      { type: 'agent_session_manage_error', request_id: 'manage:delete', code: 'not_found', message: 'gone' },
    ])
  })
})
