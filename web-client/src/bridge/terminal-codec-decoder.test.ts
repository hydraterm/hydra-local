import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  encodeTerminalGzipChunkPayload,
  FrameKind,
  TERMINAL_CODEC_CHUNK_BYTES,
  type TerminalFrame,
} from '../protocol/terminal-frame'
import { disableRenderMetrics, enableRenderMetrics } from './render-metrics'
import {
  OrderedTerminalCodecDecoder,
  TERMINAL_CODEC_MAX_INFLATERS,
  TERMINAL_CODEC_MAX_QUEUED_ENTRIES,
  terminalGzipDecoderAvailable,
  type TerminalCodecDecoderOptions,
} from './terminal-codec-decoder'

async function gzip(bytes: Uint8Array): Promise<Uint8Array> {
  const input = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes)
      controller.close()
    },
  })
  const transform = new CompressionStream('gzip') as unknown as TransformStream<Uint8Array, Uint8Array>
  const output = input.pipeThrough(transform)
  return new Uint8Array(await new Response(output).arrayBuffer())
}

function gzipFrames(channel: number, encoded: Uint8Array, decodedLength: number): TerminalFrame[] {
  const count = Math.ceil(encoded.byteLength / TERMINAL_CODEC_CHUNK_BYTES)
  const frames: TerminalFrame[] = []
  for (let index = 0; index < count; index++) {
    const start = index * TERMINAL_CODEC_CHUNK_BYTES
    const bytes = encoded.subarray(start, Math.min(encoded.byteLength, start + TERMINAL_CODEC_CHUNK_BYTES))
    frames.push({
      kind: FrameKind.TerminalGzipJsonChunk,
      channel,
      payload: encodeTerminalGzipChunkPayload(index, count, encoded.byteLength, decodedLength, bytes),
    })
  }
  return frames
}

function legacy(channel: number, text: string): TerminalFrame {
  return { kind: FrameKind.TerminalOutput, channel, payload: new TextEncoder().encode(text) }
}

function legacyChunk(channel: number, text: string, final: boolean): TerminalFrame {
  const bytes = new TextEncoder().encode(text)
  const payload = new Uint8Array(bytes.byteLength + 1)
  payload[0] = final ? 1 : 0
  payload.set(bytes, 1)
  return { kind: FrameKind.TerminalOutputChunk, channel, payload }
}

function setup(
  channels = [1],
  now?: () => number,
  timeoutMs?: number,
  decodeGzip?: NonNullable<TerminalCodecDecoderOptions['decodeGzip']>,
) {
  const selected = new Set(channels)
  const bound = new Set(channels)
  const frames: TerminalFrame[] = []
  const failures: string[] = []
  const progress: number[] = []
  const decoder = new OrderedTerminalCodecDecoder({
    isSelected: (channel) => selected.has(channel),
    isBound: (channel) => bound.has(channel),
    onFrame: (frame) => frames.push(frame),
    onProgress: (channel) => progress.push(channel),
    onFatal: (reason) => failures.push(reason),
    now,
    timeoutMs,
    decodeGzip,
  })
  return { decoder, frames, failures, progress, selected, bound }
}

function syntheticGzipFrame(channel: number, marker = channel): TerminalFrame {
  const encoded = new Uint8Array(8).fill(marker)
  return gzipFrames(channel, encoded, 4096)[0]!
}

interface ControlledInflate {
  readonly marker: number
  readonly signal: AbortSignal
  aborted: boolean
  resolve: () => void
}

function controlledDecoder(): {
  readonly decode: NonNullable<TerminalCodecDecoderOptions['decodeGzip']>
  readonly calls: ControlledInflate[]
  readonly maxRunning: () => number
} {
  const calls: ControlledInflate[] = []
  let running = 0
  let maxRunning = 0
  const decode: NonNullable<TerminalCodecDecoderOptions['decodeGzip']> =
    (encoded, decodedLength, _startedAt, _timeoutMs, _now, signal) => new Promise((resolve, reject) => {
      running++
      maxRunning = Math.max(maxRunning, running)
      let settled = false
      const settle = (complete: () => void): void => {
        if (settled) return
        settled = true
        running--
        signal.removeEventListener('abort', abort)
        complete()
      }
      const call: ControlledInflate = {
        marker: encoded[0]!,
        signal,
        aborted: false,
        resolve: () => settle(() => resolve(new Uint8Array(decodedLength).fill(0x61))),
      }
      const abort = (): void => {
        call.aborted = true
        settle(() => reject(new Error('aborted')))
      }
      signal.addEventListener('abort', abort, { once: true })
      calls.push(call)
    })
  return { decode, calls, maxRunning: () => maxRunning }
}

async function waitForFrames(frames: TerminalFrame[], count: number): Promise<void> {
  await vi.waitFor(() => expect(frames).toHaveLength(count))
}

describe('negotiated terminal gzip ordered decoder', () => {
  afterEach(() => {
    disableRenderMetrics()
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  it('decodes a complete event asynchronously and exposes only content-blind compression metrics when enabled', async () => {
    const decoded = new TextEncoder().encode(JSON.stringify({ ev: 'grid', pad: 'x'.repeat(6000) }))
    const encoded = await gzip(decoded)
    const h = setup()
    enableRenderMetrics(0)
    for (const frame of gzipFrames(1, encoded, decoded.byteLength)) h.decoder.push(frame)
    await waitForFrames(h.frames, 1)
    expect(new TextDecoder().decode(h.frames[0]!.payload)).toBe(new TextDecoder().decode(decoded))
    expect(h.frames[0]!.decodedText).toBe(new TextDecoder().decode(decoded))
    expect(h.frames[0]!.transport).toMatchObject({
      encodedBytes: encoded.byteLength,
      decodedBytes: decoded.byteLength,
      compressed: true,
      chunkCount: Math.ceil(encoded.byteLength / TERMINAL_CODEC_CHUNK_BYTES),
    })
    expect(JSON.stringify(h.frames[0]!.transport)).not.toContain('xxxx')
    expect(h.failures).toEqual([])
  })

  it('does not advertise when a present DecompressionStream rejects gzip construction', () => {
    class ThrowingDecompressionStream {
      constructor() {
        throw new TypeError('gzip unsupported')
      }
    }
    vi.stubGlobal('DecompressionStream', ThrowingDecompressionStream)
    expect(terminalGzipDecoderAvailable()).toBe(false)
  })

  it('keeps compressed then legacy application ordered on the same pane while native decode is pending', async () => {
    const decoded = new TextEncoder().encode(JSON.stringify({ ev: 'grid', pad: 'a'.repeat(8000) }))
    const encoded = await gzip(decoded)
    const h = setup()
    for (const frame of gzipFrames(1, encoded, decoded.byteLength)) h.decoder.push(frame)
    h.decoder.push(legacy(1, 'legacy-after'))
    expect(h.frames).toEqual([])
    await waitForFrames(h.frames, 2)
    expect(new TextDecoder().decode(h.frames[0]!.payload)).toContain('"ev":"grid"')
    expect(new TextDecoder().decode(h.frames[1]!.payload)).toBe('legacy-after')
  })

  it('releases viewed-pane legacy chunks while a background gzip event is still incomplete', () => {
    const h = setup([1, 2])
    h.decoder.setActiveChannel(2)
    h.decoder.push({
      kind: FrameKind.TerminalGzipJsonChunk,
      channel: 1,
      payload: encodeTerminalGzipChunkPayload(
        0,
        2,
        TERMINAL_CODEC_CHUNK_BYTES + 8,
        32 * 1024,
        new Uint8Array(TERMINAL_CODEC_CHUNK_BYTES),
      ),
    })
    h.decoder.push(legacyChunk(2, 'active-first', false))
    h.decoder.push(legacyChunk(2, 'active-second', true))

    expect(h.frames.map((frame) => new TextDecoder().decode(frame.payload.subarray(1)))).toEqual([
      'active-first',
      'active-second',
    ])
    expect(h.frames.map((frame) => frame.kind)).toEqual([
      FrameKind.TerminalOutputChunk,
      FrameKind.TerminalOutputChunk,
    ])
    expect(h.failures).toEqual([])
    h.decoder.clearAll()
  })

  it('lets a complete sibling pass an earlier incomplete pane without corrupting either chunk stream', async () => {
    const noisy = Array.from({ length: 20_000 }, (_, i) => (i * 1103515245 + 12345) >>> 0).join(',')
    const a = new TextEncoder().encode(JSON.stringify({ ev: 'grid', noisy }))
    const b = new TextEncoder().encode(JSON.stringify({ ev: 'damage', pad: 'b'.repeat(6000) }))
    const [agz, bgz] = await Promise.all([gzip(a), gzip(b)])
    const af = gzipFrames(1, agz, a.byteLength)
    const bf = gzipFrames(2, bgz, b.byteLength)
    expect(af.length).toBeGreaterThan(1)
    const h = setup([1, 2])
    h.decoder.push(af[0]!)
    for (const frame of bf) h.decoder.push(frame)
    for (const frame of af.slice(1)) h.decoder.push(frame)
    await waitForFrames(h.frames, 2)
    expect(h.frames.map((frame) => frame.channel)).toEqual([2, 1])
    expect(h.progress).toEqual([1, ...Array(bf.length).fill(2), ...Array(af.length - 1).fill(1)])
  })

  it('decodes viewed work beside a hanging sibling with bounded concurrent inflaters', async () => {
    const controlled = controlledDecoder()
    const h = setup([1, 2], undefined, undefined, controlled.decode)
    h.decoder.setActiveChannel(2)
    h.decoder.push(syntheticGzipFrame(1))
    h.decoder.push(syntheticGzipFrame(2))

    expect(controlled.calls.map((call) => call.marker)).toEqual([1, 2])
    expect(controlled.maxRunning()).toBe(TERMINAL_CODEC_MAX_INFLATERS)
    controlled.calls[1]!.resolve()
    await waitForFrames(h.frames, 1)
    expect(h.frames.map((frame) => frame.channel)).toEqual([2])

    controlled.calls[0]!.resolve()
    await waitForFrames(h.frames, 2)
    expect(h.frames.map((frame) => frame.channel)).toEqual([2, 1])
    expect(h.failures).toEqual([])
  })

  it('promotes a newly viewed pane and requeues the superseded foreground without exceeding two inflaters', async () => {
    const controlled = controlledDecoder()
    const h = setup([1, 2, 3], undefined, undefined, controlled.decode)
    h.decoder.setActiveChannel(1)
    h.decoder.push(syntheticGzipFrame(1))
    h.decoder.push(syntheticGzipFrame(2))
    h.decoder.push(syntheticGzipFrame(3))
    expect(controlled.calls.map((call) => call.marker)).toEqual([1, 2])

    h.decoder.setActiveChannel(3)
    await vi.waitFor(() => expect(controlled.calls.map((call) => call.marker)).toEqual([1, 2, 3]))
    expect(controlled.calls[0]!.aborted).toBe(true)
    expect(controlled.maxRunning()).toBeLessThanOrEqual(TERMINAL_CODEC_MAX_INFLATERS)

    controlled.calls[2]!.resolve()
    await waitForFrames(h.frames, 1)
    expect(h.frames[0]!.channel).toBe(3)
    h.decoder.clearAll()
    expect(h.failures).toEqual([])
  })

  it('gives a ready sibling a bounded turn during a viewed-pane delivery backlog', async () => {
    const controlled = controlledDecoder()
    const h = setup([1, 2], undefined, undefined, controlled.decode)
    h.decoder.setActiveChannel(1)
    h.decoder.push(syntheticGzipFrame(1))
    h.decoder.push(syntheticGzipFrame(2))
    for (let i = 0; i < 20; i++) h.decoder.push(legacy(1, `active-${i}`))
    h.decoder.push(legacy(2, 'sibling-tail'))

    controlled.calls[0]!.resolve()
    controlled.calls[1]!.resolve()
    await waitForFrames(h.frames, 23)
    const siblingIndexes = h.frames
      .map((frame, index) => ({ channel: frame.channel, index }))
      .filter(({ channel }) => channel === 2)
      .map(({ index }) => index)
    expect(siblingIndexes[0]).toBeLessThan(20)
    expect(h.frames.filter((frame) => frame.channel === 1).map((frame) =>
      frame.payload.byteLength === 4096 ? 'gzip' : new TextDecoder().decode(frame.payload)
    )).toEqual(['gzip', ...Array.from({ length: 20 }, (_, i) => `active-${i}`)])
    expect(h.frames.filter((frame) => frame.channel === 2).map((frame) =>
      frame.payload.byteLength === 4096 ? 'gzip' : new TextDecoder().decode(frame.payload)
    )).toEqual(['gzip', 'sibling-tail'])
    expect(h.failures).toEqual([])
  })

  it('keeps sibling fairness debt across repeated focus churn', async () => {
    const frames: TerminalFrame[] = []
    const failures: string[] = []
    let seeded = false
    let decoder!: OrderedTerminalCodecDecoder
    decoder = new OrderedTerminalCodecDecoder({
      isSelected: () => true,
      isBound: () => true,
      onProgress: () => {},
      onFatal: (reason) => failures.push(reason),
      onFrame: (frame) => {
        frames.push(frame)
        if (!seeded) {
          seeded = true
          // Queue every contender reentrantly while drain is already active, so pane 3 is genuinely ready beside
          // both focus targets instead of being synchronously delivered before the churn begins.
          decoder.push(legacy(3, 'waiting-sibling'))
          for (let i = 0; i < 24; i++) decoder.push(legacy(i % 2 === 0 ? 1 : 2, `active-${i}`))
        }
        if (frame.channel === 1) decoder.setActiveChannel(2)
        else if (frame.channel === 2) decoder.setActiveChannel(1)
      },
    })
    decoder.setActiveChannel(1)
    decoder.push(legacy(1, 'seed'))

    await waitForFrames(frames, 26)
    const siblingIndex = frames.findIndex((frame) => frame.channel === 3)
    expect(siblingIndex).toBeGreaterThanOrEqual(0)
    expect(siblingIndex).toBeLessThanOrEqual(9)
    expect(failures).toEqual([])
  })

  it('serializes sibling-only native inflaters when there is no viewed-pane work', async () => {
    const NativeDecompressionStream = DecompressionStream
    let constructors = 0
    class CountingDecompressionStream {
      constructor(format: CompressionFormat) {
        constructors++
        return new NativeDecompressionStream(format) as unknown as CountingDecompressionStream
      }
    }
    vi.stubGlobal('DecompressionStream', CountingDecompressionStream)
    const a = new TextEncoder().encode(JSON.stringify({ ev: 'grid', pad: 'a'.repeat(6000) }))
    const b = new TextEncoder().encode(JSON.stringify({ ev: 'damage', pad: 'b'.repeat(6000) }))
    const [agz, bgz] = await Promise.all([gzip(a), gzip(b)])
    const h = setup([1, 2])
    for (const frame of gzipFrames(1, agz, a.byteLength)) h.decoder.push(frame)
    for (const frame of gzipFrames(2, bgz, b.byteLength)) h.decoder.push(frame)
    expect(constructors).toBe(1)
    await waitForFrames(h.frames, 2)
    expect(constructors).toBe(2)
    expect(h.failures).toEqual([])
  })

  it('rejects codec frames on legacy channels and malformed gzip/CRC/ISIZE/truncation/UTF-8', async () => {
    const good = new TextEncoder().encode(JSON.stringify({ ev: 'grid', pad: 'z'.repeat(6000) }))
    const gz = await gzip(good)

    const legacyOnly = setup()
    legacyOnly.selected.clear()
    legacyOnly.decoder.push(gzipFrames(1, gz, good.byteLength)[0]!)
    expect(legacyOnly.failures).toEqual(['codec_not_selected'])

    const cases: Array<{ encoded: Uint8Array; decodedLength: number; reasons: string[] }> = []
    const crc = gz.slice(); crc[crc.length - 8] ^= 1
    cases.push({ encoded: crc, decodedLength: good.byteLength, reasons: ['gzip'] })
    const size = gz.slice(); size[size.length - 4] ^= 1
    cases.push({ encoded: size, decodedLength: good.byteLength, reasons: ['decoded_length'] })
    // Remove one byte from the deflate body while preserving the complete trailer, so this specifically proves
    // truncated compressed data is rejected rather than being caught only by the early ISIZE check.
    const truncated = new Uint8Array(gz.byteLength - 1)
    truncated.set(gz.subarray(0, gz.byteLength - 9))
    truncated.set(gz.subarray(gz.byteLength - 8), gz.byteLength - 9)
    cases.push({ encoded: truncated, decodedLength: good.byteLength, reasons: ['gzip', 'decoded_length'] })
    const invalidUtf8 = new Uint8Array(5000); invalidUtf8.fill(0xff)
    cases.push({ encoded: await gzip(invalidUtf8), decodedLength: invalidUtf8.byteLength, reasons: ['utf8'] })
    for (const test of cases) {
      const h = setup()
      for (const frame of gzipFrames(1, test.encoded, test.decodedLength)) h.decoder.push(frame)
      await vi.waitFor(() => expect(test.reasons).toContain(h.failures[0]))
      expect(h.failures).toHaveLength(1)
      expect(h.frames).toEqual([])
    }
  })

  it('fails the whole owner and cancels other-pane work after malformed codec metadata', async () => {
    const controlled = controlledDecoder()
    const h = setup([1, 2], undefined, undefined, controlled.decode)
    h.decoder.setActiveChannel(2)
    h.decoder.push(syntheticGzipFrame(2))
    h.decoder.push({ kind: FrameKind.TerminalGzipJsonChunk, channel: 1, payload: new Uint8Array([1]) })

    expect(h.failures).toEqual(['metadata'])
    expect(controlled.calls[0]!.aborted).toBe(true)
    controlled.calls[0]!.resolve()
    await Promise.resolve()
    expect(h.frames).toEqual([])
  })

  it('rejects concatenated gzip members rather than accepting a valid prefix', async () => {
    const a = new TextEncoder().encode(JSON.stringify({ ev: 'grid', pad: 'a'.repeat(5000) }))
    const b = new TextEncoder().encode('tail'.repeat(1024))
    const [agz, bgz] = await Promise.all([gzip(a), gzip(b)])
    const joined = new Uint8Array(agz.byteLength + bgz.byteLength)
    joined.set(agz)
    joined.set(bgz, agz.byteLength)
    const h = setup()
    // The outer declaration matches the final member's ISIZE. Native gzip must still reject the leading member
    // rather than silently accepting either member or concatenating both.
    for (const frame of gzipFrames(1, joined, b.byteLength)) h.decoder.push(frame)
    await vi.waitFor(() => expect(['gzip', 'decoded_length']).toContain(h.failures[0]))
    expect(h.failures).toHaveLength(1)
  })

  it('enforces the shared 32 MiB declared budget before a sixth partial allocation', () => {
    const h = setup([1, 2, 3, 4, 5, 6])
    const encodedLength = 112 * TERMINAL_CODEC_CHUNK_BYTES
    const decodedLength = 2 * 1024 * 1024
    for (let channel = 1; channel <= 6; channel++) {
      h.decoder.push({
        kind: FrameKind.TerminalGzipJsonChunk,
        channel,
        payload: encodeTerminalGzipChunkPayload(
          0,
          112,
          encodedLength,
          decodedLength,
          new Uint8Array(TERMINAL_CODEC_CHUNK_BYTES),
        ),
      })
      if (h.failures.length) break
    }
    expect(h.failures).toEqual(['budget'])
    expect(h.frames).toEqual([])
  })

  it('bounds zero-byte legacy entries queued behind an incomplete same-pane event', () => {
    const h = setup()
    h.decoder.push({
      kind: FrameKind.TerminalGzipJsonChunk,
      channel: 1,
      payload: encodeTerminalGzipChunkPayload(
        0,
        2,
        TERMINAL_CODEC_CHUNK_BYTES + 8,
        32 * 1024,
        new Uint8Array(TERMINAL_CODEC_CHUNK_BYTES),
      ),
    })
    for (let i = 1; i < TERMINAL_CODEC_MAX_QUEUED_ENTRIES; i++) h.decoder.push(legacy(1, ''))
    expect(h.failures).toEqual([])
    h.decoder.push(legacy(1, ''))
    expect(h.failures).toEqual(['budget'])
    expect(h.frames).toEqual([])
  })

  it('times out an incomplete event with no follow-up and ignores the stale deadline after retirement', async () => {
    vi.useFakeTimers()
    let now = 0
    const frame: TerminalFrame = {
      kind: FrameKind.TerminalGzipJsonChunk,
      channel: 1,
      payload: encodeTerminalGzipChunkPayload(
        0,
        2,
        TERMINAL_CODEC_CHUNK_BYTES + 8,
        32 * 1024,
        new Uint8Array(TERMINAL_CODEC_CHUNK_BYTES),
      ),
    }
    const timedOut = setup([1], () => now, 10)
    timedOut.decoder.push(frame)
    now = 11
    await vi.advanceTimersByTimeAsync(10)
    expect(timedOut.failures).toEqual(['timeout'])

    const retired = setup([1], () => now, 10)
    retired.decoder.push(frame)
    retired.decoder.clearAll()
    now += 20
    await vi.advanceTimersByTimeAsync(20)
    expect(retired.failures).toEqual([])
  })

  it('times out a completed event whose native inflater never produces output', async () => {
    const decoded = new TextEncoder().encode(JSON.stringify({ ev: 'grid', pad: 't'.repeat(6000) }))
    const encoded = await gzip(decoded)
    vi.useFakeTimers()
    class HangingDecompressionStream {
      readonly readable = new ReadableStream<Uint8Array>()
      readonly writable = new WritableStream<Uint8Array>()
    }
    vi.stubGlobal('DecompressionStream', HangingDecompressionStream)
    let now = 0
    const h = setup([1], () => now, 10)
    for (const frame of gzipFrames(1, encoded, decoded.byteLength)) h.decoder.push(frame)
    now = 11
    await vi.advanceTimersByTimeAsync(11)
    expect(h.failures).toEqual(['timeout'])
    expect(h.frames).toEqual([])
  })

  it('detach cancels an in-flight decode and drops its queued legacy tail', async () => {
    const decoded = new TextEncoder().encode(JSON.stringify({ ev: 'grid', pad: 'd'.repeat(8000) }))
    const encoded = await gzip(decoded)
    const h = setup()
    for (const frame of gzipFrames(1, encoded, decoded.byteLength)) h.decoder.push(frame)
    h.decoder.push(legacy(1, 'must-not-escape'))
    h.decoder.clear(1)
    await new Promise((resolve) => setTimeout(resolve, 20))
    expect(h.frames).toEqual([])
    expect(h.failures).toEqual([])
  })

  it('does not allocate metric metadata when collection is disabled', async () => {
    const decoded = new TextEncoder().encode(JSON.stringify({ ev: 'grid', pad: 'm'.repeat(5000) }))
    const encoded = await gzip(decoded)
    const h = setup()
    for (const frame of gzipFrames(1, encoded, decoded.byteLength)) h.decoder.push(frame)
    await waitForFrames(h.frames, 1)
    expect(h.frames[0]!.transport).toBeUndefined()
  })
})
