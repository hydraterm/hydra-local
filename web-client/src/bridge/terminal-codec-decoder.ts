import {
  decodeTerminalGzipChunk,
  FrameKind,
  MAX_TERMINAL_CODEC_BYTES,
  TERMINAL_GZIP_JSON_V1,
  type TerminalFrame,
} from '../protocol/terminal-frame.js'
import { metricsOn } from './render-metrics.js'

/** Application-owned encoded/output buffers fit one owner-scoped budget. Native inflate concurrency is capped below. */
export const TERMINAL_CODEC_GLOBAL_BUDGET = 32 * 1024 * 1024
export const TERMINAL_CODEC_MAX_QUEUED_ENTRIES = 4_096
export const TERMINAL_CODEC_MAX_INFLATERS = 2
const INFLATE_INPUT_SLICE = 16 * 1024
const CODEC_TIMEOUT_MS = 10_000
const TERMINAL_FRAME_HEADER_BYTES = 8
const ACTIVE_DELIVERY_BURST = 8
const DELIVERY_FRAME_QUANTUM = 16
const DELIVERY_BYTE_QUANTUM = 256 * 1024

type CodecFailure =
  | 'codec_not_selected'
  | 'metadata'
  | 'sequence'
  | 'budget'
  | 'timeout'
  | 'gzip'
  | 'decoded_length'
  | 'utf8'

interface OrderedEntry {
  readonly sequence: number
  readonly channel: number
  readonly reserved: number
  ready: TerminalFrame | null
}

interface PendingGzip {
  readonly entry: OrderedEntry
  readonly count: number
  readonly encodedLength: number
  readonly decodedLength: number
  readonly encoded: Uint8Array
  readonly startedAt: number
  nextIndex: number
  offset: number
  rawWireBytes: number
  abort: AbortController | null
  restartAfterAbort: boolean
  assembledAt: number
}

type DecodeGzip = (
  encoded: Uint8Array,
  decodedLength: number,
  startedAt: number,
  timeoutMs: number,
  now: () => number,
  signal: AbortSignal,
) => Promise<Uint8Array>

export interface TerminalCodecDecoderOptions {
  readonly isSelected: (channel: number) => boolean
  readonly isBound: (channel: number) => boolean
  readonly onFrame: (frame: TerminalFrame) => void
  readonly onProgress?: (channel: number) => void
  readonly onFatal: (reason: CodecFailure) => void
  readonly now?: () => number
  readonly timeoutMs?: number
  /** Test seam for deterministic scheduling coverage. Production always uses the bounded native decoder below. */
  readonly decodeGzip?: DecodeGzip
}

/**
 * Owner-scoped terminal codec and per-channel order gate.
 *
 * A gzip logical event gets its channel order at chunk zero. Compressed and legacy frames cannot overtake earlier
 * work on the same pane, while a viewed pane may pass an unfinished sibling. One native inflater lane is reserved
 * for the viewed pane and one makes FIFO progress across siblings, so neither class can starve the other. No
 * terminal content enters an error, metric, or log.
 */
export class OrderedTerminalCodecDecoder {
  private readonly pending = new Map<number, PendingGzip>()
  private readonly inflight = new Set<PendingGzip>()
  private inflateQueue: PendingGzip[] = []
  private foregroundInflate: PendingGzip | null = null
  private backgroundInflate: PendingGzip | null = null
  private activeChannel: number | null = null
  private readonly ordered = new Map<number, OrderedEntry[]>()
  private nextSequence = 1
  private queuedEntries = 0
  private reserved = 0
  private failed = false
  private activeDeliveryBurst = 0
  private draining = false
  private drainTimer: ReturnType<typeof setTimeout> | null = null
  private deadlineEpoch = 1
  private deadlineTimer: ReturnType<typeof setTimeout> | null = null
  private readonly now: () => number
  private readonly timeoutMs: number
  private readonly decodeGzip: DecodeGzip

  constructor(private readonly options: TerminalCodecDecoderOptions) {
    this.now = options.now ?? (() => (typeof performance !== 'undefined' ? performance.now() : Date.now()))
    this.timeoutMs = options.timeoutMs ?? CODEC_TIMEOUT_MS
    this.decodeGzip = options.decodeGzip ?? decodeGzipBounded
  }

  push(frame: TerminalFrame): void {
    if (this.failed || !this.options.isBound(frame.channel)) return
    if (frame.kind !== FrameKind.TerminalGzipJsonChunk) {
      // A codec frame received without selection is a protocol error; every other legacy frame remains valid.
      this.enqueueReady(frame, frame.payload.byteLength)
      return
    }
    if (!this.options.isSelected(frame.channel)) {
      this.fatal('codec_not_selected')
      return
    }
    const parsed = decodeTerminalGzipChunk(frame.payload)
    if ('err' in parsed) {
      this.fatal('metadata')
      return
    }
    const chunk = parsed.ok
    let state = this.pending.get(frame.channel)
    if (!state) {
      if (chunk.index !== 0) {
        this.fatal('sequence')
        return
      }
      // Reserve the encoded owner buffer, fixed decoded output, and a worst-case native output chunk of the full
      // declared length. The reservation is global across panes; at most two opaque native inflaters run below.
      // Native inflater internals and the later parsed JavaScript object are outside this explicit byte budget.
      const reservation = chunk.encodedLength + chunk.decodedLength * 2
      if (
        reservation > TERMINAL_CODEC_GLOBAL_BUDGET - this.reserved ||
        this.queuedEntries >= TERMINAL_CODEC_MAX_QUEUED_ENTRIES
      ) {
        this.fatal('budget')
        return
      }
      const entry: OrderedEntry = {
        sequence: this.nextSequence++,
        channel: frame.channel,
        reserved: reservation,
        ready: null,
      }
      this.enqueueEntry(entry)
      state = {
        entry,
        count: chunk.count,
        encodedLength: chunk.encodedLength,
        decodedLength: chunk.decodedLength,
        encoded: new Uint8Array(chunk.encodedLength),
        startedAt: this.now(),
        nextIndex: 0,
        offset: 0,
        rawWireBytes: 0,
        abort: null,
        restartAfterAbort: false,
        assembledAt: 0,
      }
      this.pending.set(frame.channel, state)
      this.armPartialDeadline()
    }
    if (
      state.nextIndex !== chunk.index ||
      state.count !== chunk.count ||
      state.encodedLength !== chunk.encodedLength ||
      state.decodedLength !== chunk.decodedLength ||
      this.now() - state.startedAt > this.timeoutMs
    ) {
      this.fatal(this.now() - state.startedAt > this.timeoutMs ? 'timeout' : 'sequence')
      return
    }
    state.encoded.set(chunk.bytes, state.offset)
    state.offset += chunk.bytes.byteLength
    state.nextIndex++
    state.rawWireBytes += TERMINAL_FRAME_HEADER_BYTES + frame.payload.byteLength
    this.options.onProgress?.(frame.channel)
    if (!chunk.final) return
    if (state.offset !== state.encodedLength || state.nextIndex !== state.count) {
      this.fatal('decoded_length')
      return
    }

    this.pending.delete(frame.channel)
    this.armPartialDeadline()
    state.assembledAt = this.now()
    this.inflight.add(state)
    this.inflateQueue.push(state)
    this.pumpInflates()
  }

  /** Promote the pane the user is currently viewing. The signal is local-only and contains only a channel id. */
  setActiveChannel(channel: number | null): void {
    if (this.activeChannel === channel) return
    this.activeChannel = channel
    // Keep the global fairness debt across focus changes. Resetting it here lets rapid A/B focus churn continually
    // buy a fresh active burst and starve a ready third pane. A newly viewed pane can wait for at most the one
    // already-due sibling delivery before it receives the next active burst.
    this.rebalanceInflateLanes()
    this.pumpInflates()
    this.drain()
  }

  clear(channel: number): void {
    const state = this.pending.get(channel)
    if (state) {
      state.abort?.abort()
      this.pending.delete(channel)
    }
    for (const inflight of this.inflight) {
      if (inflight.entry.channel !== channel) continue
      inflight.restartAfterAbort = false
      inflight.abort?.abort()
      this.inflight.delete(inflight)
    }
    this.inflateQueue = this.inflateQueue.filter((inflight) => inflight.entry.channel !== channel)
    this.dropChannelEntries(channel)
    if (this.activeChannel === channel) this.activeChannel = null
    this.armPartialDeadline()
    this.rebalanceInflateLanes()
    this.pumpInflates()
    this.drain()
  }

  clearAll(): void {
    for (const state of this.pending.values()) state.abort?.abort()
    for (const state of this.inflight) {
      state.restartAfterAbort = false
      state.abort?.abort()
    }
    this.pending.clear()
    this.inflight.clear()
    this.inflateQueue = []
    this.ordered.clear()
    this.activeChannel = null
    this.queuedEntries = 0
    this.reserved = 0
    this.failed = false
    this.activeDeliveryBurst = 0
    this.cancelDrain()
    this.deadlineEpoch++
    this.cancelPartialDeadline()
  }

  private enqueueReady(frame: TerminalFrame, heldBytes: number): void {
    if (
      heldBytes > TERMINAL_CODEC_GLOBAL_BUDGET - this.reserved ||
      this.queuedEntries >= TERMINAL_CODEC_MAX_QUEUED_ENTRIES
    ) {
      this.fatal('budget')
      return
    }
    const entry: OrderedEntry = {
      sequence: this.nextSequence++,
      channel: frame.channel,
      reserved: heldBytes,
      ready: frame,
    }
    this.enqueueEntry(entry)
    this.drain()
  }

  private enqueueEntry(entry: OrderedEntry): void {
    const queue = this.ordered.get(entry.channel)
    if (queue) queue.push(entry)
    else this.ordered.set(entry.channel, [entry])
    this.queuedEntries++
    this.reserved += entry.reserved
  }

  private dropChannelEntries(channel: number): void {
    const queue = this.ordered.get(channel)
    if (!queue) return
    for (const entry of queue) this.reserved -= entry.reserved
    this.queuedEntries -= queue.length
    this.ordered.delete(channel)
  }

  private drain(): void {
    if (this.failed || this.draining) return
    this.draining = true
    let delivered = 0
    let deliveredBytes = 0
    try {
      while (delivered < DELIVERY_FRAME_QUANTUM && deliveredBytes < DELIVERY_BYTE_QUANTUM) {
        const entry = this.takeNextReady()
        if (!entry) break
        this.reserved -= entry.reserved
        delivered++
        deliveredBytes += entry.ready!.payload.byteLength
        this.options.onFrame(entry.ready!)
        if (this.failed) break
      }
    } finally {
      this.draining = false
    }
    if (this.hasReadyEntry()) this.scheduleDrain()
  }

  /** Active frames win, but after a bounded burst the oldest ready sibling gets one delivery quantum. */
  private takeNextReady(): OrderedEntry | null {
    const activeQueue = this.activeChannel === null ? undefined : this.ordered.get(this.activeChannel)
    const active = activeQueue?.[0]?.ready ? activeQueue[0] : null
    let background: OrderedEntry | null = null
    for (const [channel, queue] of this.ordered) {
      if (channel === this.activeChannel || !queue[0]?.ready) continue
      if (!background || queue[0].sequence < background.sequence) background = queue[0]
    }
    const chosen = active && (!background || this.activeDeliveryBurst < ACTIVE_DELIVERY_BURST)
      ? active
      : background
    if (!chosen) return null
    if (chosen.channel === this.activeChannel) {
      this.activeDeliveryBurst = Math.min(ACTIVE_DELIVERY_BURST, this.activeDeliveryBurst + 1)
    } else {
      this.activeDeliveryBurst = 0
    }
    const queue = this.ordered.get(chosen.channel)!
    queue.shift()
    this.queuedEntries--
    if (queue.length === 0) this.ordered.delete(chosen.channel)
    return chosen
  }

  private hasReadyEntry(): boolean {
    for (const queue of this.ordered.values()) {
      if (queue[0]?.ready) return true
    }
    return false
  }

  private scheduleDrain(): void {
    if (this.drainTimer !== null || this.failed) return
    this.drainTimer = setTimeout(() => {
      this.drainTimer = null
      this.drain()
    }, 0)
    this.drainTimer.unref?.()
  }

  private cancelDrain(): void {
    if (this.drainTimer !== null) clearTimeout(this.drainTimer)
    this.drainTimer = null
  }

  private armPartialDeadline(): void {
    this.cancelPartialDeadline()
    if (this.failed || this.pending.size === 0) return
    const earliest = Math.min(...[...this.pending.values()].map((state) => state.startedAt + this.timeoutMs))
    const generation = ++this.deadlineEpoch
    this.deadlineTimer = setTimeout(() => {
      this.deadlineTimer = null
      if (generation !== this.deadlineEpoch || this.failed) return
      const now = this.now()
      if ([...this.pending.values()].some((state) => now - state.startedAt >= this.timeoutMs)) {
        this.fatal('timeout')
      } else {
        this.armPartialDeadline()
      }
    }, Math.max(0, earliest - this.now()))
  }

  private cancelPartialDeadline(): void {
    if (this.deadlineTimer !== null) clearTimeout(this.deadlineTimer)
    this.deadlineTimer = null
  }

  private async finishGzip(state: PendingGzip, controller: AbortController): Promise<void> {
    const inflateStartedAt = this.now()
    let decoded: Uint8Array
    try {
      decoded = await this.decodeGzip(
        state.encoded,
        state.decodedLength,
        state.startedAt,
        this.timeoutMs,
        this.now,
        controller.signal,
      )
    } catch (error) {
      if (controller.signal.aborted) return
      this.fatal(error instanceof CodecDecodeError ? error.reason : 'gzip')
      return
    }
    if (
      controller.signal.aborted ||
      this.failed ||
      !this.inflight.has(state) ||
      state.abort !== controller
    ) return
    if (decoded.byteLength !== state.decodedLength) {
      this.fatal('decoded_length')
      return
    }
    // Strict UTF-8 validation happens exactly once before the bytes can reach JSON parsing/rendering. The local
    // string is carried with the frame so the normal routing path does not repeat a multi-megabyte decode.
    let decodedText: string
    try {
      decodedText = new TextDecoder('utf-8', { fatal: true }).decode(decoded)
    } catch {
      this.fatal('utf8')
      return
    }
    this.inflight.delete(state)
    const finishedAt = this.now()
    state.entry.ready = {
      kind: FrameKind.TerminalOutput,
      channel: state.entry.channel,
      payload: decoded,
      decodedText,
      transport: metricsOn()
        ? {
            rawWireBytes: state.rawWireBytes,
            encodedBytes: state.encodedLength,
            decodedBytes: state.decodedLength,
            chunkCount: state.count,
            compressed: true,
            transferMs: Math.max(0, state.assembledAt - state.startedAt),
            codecQueueMs: Math.max(0, inflateStartedAt - state.assembledAt),
            codecMs: Math.max(0, finishedAt - inflateStartedAt),
          }
        : undefined,
    }
    this.drain()
  }

  /** Keep one lane available to the viewed pane and one lane making oldest-first sibling progress. Two is a hard
   * ceiling because DecompressionStream's internal buffering is implementation-owned. */
  private pumpInflates(): void {
    if (this.failed) return
    this.rebalanceInflateLanes()
    if (this.foregroundInflate === null && this.activeChannel !== null) {
      const active = this.takeQueuedInflate((state) => state.entry.channel === this.activeChannel)
      if (active) this.startInflate(active, 'foreground')
    }
    if (this.backgroundInflate === null) {
      const background = this.takeQueuedInflate((state) => state.entry.channel !== this.activeChannel)
      if (background) this.startInflate(background, 'background')
    }
  }

  private takeQueuedInflate(predicate: (state: PendingGzip) => boolean): PendingGzip | null {
    let chosenIndex = -1
    let chosenSequence = Number.POSITIVE_INFINITY
    for (let i = 0; i < this.inflateQueue.length; i++) {
      const state = this.inflateQueue[i]!
      if (!this.inflight.has(state) || state.abort !== null || !predicate(state)) continue
      if (state.entry.sequence < chosenSequence) {
        chosenIndex = i
        chosenSequence = state.entry.sequence
      }
    }
    if (chosenIndex < 0) {
      this.inflateQueue = this.inflateQueue.filter((state) => this.inflight.has(state) && state.abort === null)
      return null
    }
    return this.inflateQueue.splice(chosenIndex, 1)[0]!
  }

  private startInflate(state: PendingGzip, lane: 'foreground' | 'background'): void {
    const controller = new AbortController()
    state.abort = controller
    state.restartAfterAbort = false
    if (lane === 'foreground') this.foregroundInflate = state
    else this.backgroundInflate = state
    void this.finishGzip(state, controller).finally(() => {
      if (this.foregroundInflate === state) this.foregroundInflate = null
      if (this.backgroundInflate === state) this.backgroundInflate = null
      const restart = state.restartAfterAbort && this.inflight.has(state) && !this.failed
      if (state.abort === controller) state.abort = null
      state.restartAfterAbort = false
      if (restart) this.inflateQueue.push(state)
      this.pumpInflates()
    })
  }

  /** A focus switch can reclassify an already-running inflater without restarting it. Only the old foreground is
   * canceled/requeued when both lanes are occupied by panes that are now background; this frees the reserved lane
   * for the new viewed pane without exceeding the two-inflater ceiling. */
  private rebalanceInflateLanes(): void {
    if (this.failed) return
    if (this.backgroundInflate?.entry.channel === this.activeChannel) {
      if (this.foregroundInflate === null) {
        this.foregroundInflate = this.backgroundInflate
        this.backgroundInflate = null
      } else if (this.foregroundInflate.entry.channel !== this.activeChannel) {
        const priorForeground = this.foregroundInflate
        this.foregroundInflate = this.backgroundInflate
        this.backgroundInflate = priorForeground
      }
    }
    if (this.foregroundInflate && this.foregroundInflate.entry.channel !== this.activeChannel) {
      if (this.backgroundInflate === null) {
        this.backgroundInflate = this.foregroundInflate
        this.foregroundInflate = null
      } else if (!this.foregroundInflate.restartAfterAbort) {
        this.foregroundInflate.restartAfterAbort = true
        this.foregroundInflate.abort?.abort()
      }
    }
  }

  private fatal(reason: CodecFailure): void {
    if (this.failed) return
    this.failed = true
    for (const state of this.pending.values()) state.abort?.abort()
    for (const state of this.inflight) {
      state.restartAfterAbort = false
      state.abort?.abort()
    }
    this.pending.clear()
    this.inflight.clear()
    this.inflateQueue = []
    this.ordered.clear()
    this.queuedEntries = 0
    this.reserved = 0
    this.activeDeliveryBurst = 0
    this.cancelDrain()
    this.deadlineEpoch++
    this.cancelPartialDeadline()
    this.options.onFatal(reason)
  }
}

class CodecDecodeError extends Error {
  constructor(readonly reason: CodecFailure) {
    super(reason)
  }
}

/** Native asynchronous streaming decode. It never receives the attacker-claimed decoded length; output is copied
 * into the already-budgeted fixed buffer only after each actual chunk passes the cumulative bound. */
async function decodeGzipBounded(
  encoded: Uint8Array,
  decodedLength: number,
  startedAt: number,
  timeoutMs: number,
  now: () => number,
  signal: AbortSignal,
): Promise<Uint8Array> {
  if (encoded.byteLength < 18 || encoded[0] !== 0x1f || encoded[1] !== 0x8b || encoded[2] !== 8) {
    throw new CodecDecodeError('gzip')
  }
  if ((encoded[3]! & 0xe0) !== 0) throw new CodecDecodeError('gzip')
  const trailer = new DataView(encoded.buffer, encoded.byteOffset + encoded.byteLength - 8, 8)
  const expectedSize = trailer.getUint32(4, true)
  if (expectedSize !== decodedLength) throw new CodecDecodeError('decoded_length')
  if (typeof DecompressionStream !== 'function') throw new CodecDecodeError('gzip')
  const output = new Uint8Array(decodedLength)
  let offset = 0
  let inputOffset = 0
  const input = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (signal.aborted) {
        controller.error(new CodecDecodeError('gzip'))
        return
      }
      const end = Math.min(encoded.byteLength, inputOffset + INFLATE_INPUT_SLICE)
      controller.enqueue(encoded.subarray(inputOffset, end))
      inputOffset = end
      if (inputOffset === encoded.byteLength) controller.close()
    },
  })
  const transform = new DecompressionStream('gzip') as unknown as TransformStream<Uint8Array, Uint8Array>
  const decoded = input.pipeThrough(transform)
  const reader = decoded.getReader()
  let rejectAborted: ((reason: CodecDecodeError) => void) | null = null
  const aborted = new Promise<never>((_, reject) => {
    rejectAborted = reject
  })
  const cancelOnAbort = (): void => {
    void reader.cancel().catch(() => undefined)
    rejectAborted?.(new CodecDecodeError('gzip'))
  }
  signal.addEventListener('abort', cancelOnAbort, { once: true })
  if (signal.aborted) cancelOnAbort()
  let timer: ReturnType<typeof setTimeout> | null = null
  let succeeded = false
  try {
    for (;;) {
      if (signal.aborted) throw new CodecDecodeError('gzip')
      const remaining = Math.max(0, timeoutMs - (now() - startedAt))
      if (remaining === 0) throw new CodecDecodeError('timeout')
      const result = await Promise.race([
        reader.read(),
        aborted,
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new CodecDecodeError('timeout')), remaining)
        }),
      ])
      if (timer) {
        clearTimeout(timer)
        timer = null
      }
      if (result.done) break
      const chunk = result.value
      if (offset + chunk.byteLength > decodedLength) throw new CodecDecodeError('decoded_length')
      output.set(chunk, offset)
      offset += chunk.byteLength
    }
    if (offset !== decodedLength) throw new CodecDecodeError('decoded_length')
    succeeded = true
    return output
  } catch (error) {
    if (error instanceof CodecDecodeError) throw error
    throw new CodecDecodeError('gzip')
  } finally {
    if (timer) clearTimeout(timer)
    signal.removeEventListener('abort', cancelOnAbort)
    if (!succeeded || signal.aborted) void reader.cancel().catch(() => undefined)
    else reader.releaseLock()
  }
}

let probedDecompressionStream: unknown
let probedDecompressionStreamAvailable = false

export function terminalGzipDecoderAvailable(): boolean {
  // Presence alone is insufficient: some embedded browsers expose the constructor but reject `gzip`. Cache per
  // constructor identity so tests/polyfills and a replaced browser implementation are each proved independently.
  const constructor = globalThis.DecompressionStream
  if (constructor !== probedDecompressionStream) {
    probedDecompressionStream = constructor
    try {
      if (typeof constructor !== 'function') throw new TypeError('DecompressionStream unavailable')
      new constructor('gzip')
      probedDecompressionStreamAvailable = true
    } catch {
      probedDecompressionStreamAvailable = false
    }
  }
  return probedDecompressionStreamAvailable && TERMINAL_GZIP_JSON_V1.length > 0 && MAX_TERMINAL_CODEC_BYTES > 0
}
