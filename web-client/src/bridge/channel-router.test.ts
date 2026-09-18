import { afterEach, describe, it, expect } from 'vitest'
import { ChannelRouter } from './channel-router'
import { FrameKind, type TerminalFrame } from '../protocol/terminal-frame'
import { disableRenderMetrics, enableRenderMetrics } from './render-metrics'

const enc = (s: string) => new TextEncoder().encode(s)

function out(channel: number, line: string): TerminalFrame {
  return { kind: FrameKind.TerminalOutput, channel, payload: enc(line) }
}
/** one chunk of TerminalOutputChunk: payload = [is_last][bytes] */
function chunk(channel: number, text: string, isLast: boolean): TerminalFrame {
  const body = enc(text)
  const payload = new Uint8Array(1 + body.length)
  payload[0] = isLast ? 1 : 0
  payload.set(body, 1)
  return { kind: FrameKind.TerminalOutputChunk, channel, payload }
}

describe('ChannelRouter', () => {
  afterEach(() => disableRenderMetrics())

  it('routes a TerminalOutput frame to the bound session', () => {
    const r = new ChannelRouter()
    r.bind(7, 's-a')
    expect(r.routeFrame(out(7, 'hello'))).toMatchObject({ channel: 7, sessionId: 's-a', line: 'hello' })
  })

  it('routes different channels to different sessions (N-up)', () => {
    const r = new ChannelRouter()
    r.bind(1, 's-a')
    r.bind(2, 's-b')
    expect(r.routeFrame(out(1, 'A'))!.sessionId).toBe('s-a')
    expect(r.routeFrame(out(2, 'B'))!.sessionId).toBe('s-b')
    expect(r.channelCount).toBe(2)
  })

  it('drops frames on unbound channels (not one of our panes)', () => {
    const r = new ChannelRouter()
    r.bind(1, 's-a')
    expect(r.routeFrame(out(99, 'noise'))).toBeNull()
  })

  it('ignores agent-bound input frames', () => {
    const r = new ChannelRouter()
    r.bind(1, 's-a')
    expect(r.routeFrame({ kind: FrameKind.TerminalInput, channel: 1, payload: enc('x') })).toBeNull()
  })

  it('reassembles chunked output per channel and tags the session', () => {
    const r = new ChannelRouter()
    r.bind(3, 's-c')
    expect(r.routeFrame(chunk(3, 'foo', false))).toBeNull() // accumulating
    expect(r.routeFrame(chunk(3, 'bar', true))).toMatchObject({ channel: 3, sessionId: 's-c', line: 'foobar' })
  })

  it('reports progress only for validated chunks on a currently bound channel', () => {
    const r = new ChannelRouter()
    const progress: string[] = []
    r.setProgressObserver((sessionId) => progress.push(sessionId))
    r.bind(3, 's-c')
    expect(r.routeFrame(chunk(99, 'wrong', false))).toBeNull()
    expect(r.routeFrame({ kind: FrameKind.TerminalOutputChunk, channel: 3, payload: new Uint8Array([7, 1]) })).toBeNull()
    expect(progress).toEqual([])
    expect(r.routeFrame(chunk(3, 'foo', false))).toBeNull()
    expect(progress).toEqual(['s-c'])
    r.unbind(3)
    expect(r.routeFrame(chunk(3, 'stale', true))).toBeNull()
    expect(progress).toEqual(['s-c'])
  })

  it('drops an aggregate over the line cap through its final chunk, then accepts the next line', () => {
    const r = new ChannelRouter(5)
    const progress: string[] = []
    r.setProgressObserver((sessionId) => progress.push(sessionId))
    r.bind(1, 's-a')
    expect(r.routeFrame(chunk(1, '1234', false))).toBeNull()
    expect(r.routeFrame(chunk(1, '56', false))).toBeNull() // aggregate overflow
    expect(r.routeFrame(chunk(1, 'tail', true))).toBeNull() // discard through logical-line end
    expect(progress).toEqual(['s-a'])
    expect(r.routeFrame(chunk(1, 'ok', true))).toMatchObject({ channel: 1, sessionId: 's-a', line: 'ok' })
    expect(progress).toEqual(['s-a', 's-a'])
  })

  it('discards a partial logical line through its final chunk after a malformed marker or empty payload', () => {
    const r = new ChannelRouter()
    r.bind(1, 's-a')

    expect(r.routeFrame(chunk(1, 'prefix', false))).toBeNull()
    expect(r.routeFrame({ kind: FrameKind.TerminalOutputChunk, channel: 1, payload: new Uint8Array([7]) })).toBeNull()
    expect(r.routeFrame(chunk(1, 'valid-looking-tail', true))).toBeNull()
    expect(r.routeFrame(chunk(1, 'fresh', true))).toMatchObject({ channel: 1, sessionId: 's-a', line: 'fresh' })

    expect(r.routeFrame(chunk(1, 'prefix', false))).toBeNull()
    expect(r.routeFrame({ kind: FrameKind.TerminalOutputChunk, channel: 1, payload: new Uint8Array() })).toBeNull()
    expect(r.routeFrame(chunk(1, 'valid-looking-tail', true))).toBeNull()
    expect(r.routeFrame(chunk(1, 'next', true))).toMatchObject({ channel: 1, sessionId: 's-a', line: 'next' })
  })

  it('bounds aggregate partial reassembly across channels', () => {
    const r = new ChannelRouter(5, 6)
    r.bind(1, 's-a')
    r.bind(2, 's-b')
    expect(r.routeFrame(chunk(1, '1234', false))).toBeNull()
    expect(r.routeFrame(chunk(2, 'abc', false))).toBeNull() // global 6-byte budget would be exceeded
    expect(r.routeFrame(chunk(2, 'tail', true))).toBeNull() // discarded through channel 2's final chunk
    expect(r.routeFrame(chunk(1, '5', true))).toMatchObject({ channel: 1, sessionId: 's-a', line: '12345' })
    expect(r.routeFrame(chunk(2, 'ok', true))).toMatchObject({ channel: 2, sessionId: 's-b', line: 'ok' })
  })

  it('interleaved chunks from two channels do not corrupt each other', () => {
    const r = new ChannelRouter()
    r.bind(1, 's-a')
    r.bind(2, 's-b')
    expect(r.routeFrame(chunk(1, 'aa', false))).toBeNull()
    expect(r.routeFrame(chunk(2, 'bb', false))).toBeNull()
    expect(r.routeFrame(chunk(1, 'AA', true))).toMatchObject({ channel: 1, sessionId: 's-a', line: 'aaAA' })
    expect(r.routeFrame(chunk(2, 'BB', true))).toMatchObject({ channel: 2, sessionId: 's-b', line: 'bbBB' })
  })

  it('lookups: sessionForChannel / channelForSession', () => {
    const r = new ChannelRouter()
    r.bind(5, 's-x')
    expect(r.sessionForChannel(5)).toBe('s-x')
    expect(r.sessionForChannel(6)).toBeNull()
    expect(r.channelForSession('s-x')).toBe(5)
    expect(r.channelForSession('s-none')).toBeNull()
  })

  it('unbind stops routing + drops partial chunks; rebind replaces session + clears chunks', () => {
    const r = new ChannelRouter()
    r.bind(1, 's-a')
    r.routeFrame(chunk(1, 'partial', false)) // buffered
    r.unbind(1)
    expect(r.routeFrame(out(1, 'x'))).toBeNull() // no longer ours
    expect(r.channelCount).toBe(0)
    // rebind to a new session: stale partial must not leak
    r.bind(1, 's-b')
    expect(r.routeFrame(out(1, 'fresh'))).toMatchObject({ channel: 1, sessionId: 's-b', line: 'fresh' })
  })

  it('reports exact wire/logical byte and chunk counts without retaining payload content', () => {
    let now = 10
    const r = new ChannelRouter(undefined, undefined, () => now)
    r.bind(4, 's-private')
    enableRenderMetrics(now)
    expect(r.routeFrame(chunk(4, 'secret-', false))).toBeNull()
    now = 25
    const routed = r.routeFrame(chunk(4, 'tail', true))
    expect(routed?.transport).toEqual({
      rawWireBytes: (8 + 1 + 7) + (8 + 1 + 4),
      logicalBytes: 11,
      encodedBytes: 11,
      decodedBytes: 11,
      chunkCount: 2,
      compressed: false,
      transferMs: 15,
      reassembleMs: 0,
    })
    expect(JSON.stringify(routed?.transport)).not.toContain('secret')
  })

  it('does not invoke the metric clock or retain transport traces while metrics are disabled', () => {
    let clockCalls = 0
    const r = new ChannelRouter(undefined, undefined, () => {
      clockCalls++
      return 1
    })
    r.bind(8, 's-a')
    expect(r.routeFrame(chunk(8, 'first-', false))).toBeNull()
    const routed = r.routeFrame(chunk(8, 'last', true))
    expect(routed).toMatchObject({ sessionId: 's-a', line: 'first-last' })
    expect(routed?.transport).toBeUndefined()
    expect(clockCalls).toBe(0)
  })

  it('drops partial metric state on malformed chunks, unbind, and rebind', () => {
    let now = 1
    const r = new ChannelRouter(undefined, undefined, () => now++)
    enableRenderMetrics(0)
    r.bind(1, 's-old')

    expect(r.routeFrame(chunk(1, 'discarded-prefix', false))).toBeNull()
    expect(r.routeFrame({
      kind: FrameKind.TerminalOutputChunk,
      channel: 1,
      payload: new Uint8Array([9, 1]),
    })).toBeNull()
    expect(r.routeFrame(chunk(1, 'discarded-tail', true))).toBeNull()
    const fresh = r.routeFrame(chunk(1, 'fresh', true))
    expect(fresh?.transport).toMatchObject({ chunkCount: 1, logicalBytes: 5, rawWireBytes: 14 })

    expect(r.routeFrame(chunk(1, 'old-partial', false))).toBeNull()
    r.unbind(1)
    r.bind(1, 's-new')
    const rebound = r.routeFrame(chunk(1, 'new', true))
    expect(rebound).toMatchObject({ sessionId: 's-new', line: 'new' })
    expect(rebound?.transport).toMatchObject({ chunkCount: 1, logicalBytes: 3, rawWireBytes: 12 })
  })
})
