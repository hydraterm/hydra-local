// Pure N-channel terminal routing (roadmap §4 multi-pane foundation). RemoteSession today routes inbound
// terminal frames to ONE attached channel with ONE chunk buffer; true multi-pane needs the SAME logic for
// many channels at once. This is that logic, extracted and generalized — pure, transport-free, testable:
// it owns channel↔session bindings + per-channel chunk reassembly and yields a complete daemon line tagged
// with which session it belongs to. It does NOT own renderers/sync (the integration slice wires those next).

import { FrameKind, type TerminalFrame } from '../protocol/terminal-frame.js'
import { BoundedChunkReassembler } from './bounded-chunk-reassembler.js'
import { metricsOn } from './render-metrics.js'

/** A reassembled, fully-decoded daemon line tagged with the channel + session it routed to. */
export interface RoutedLine {
  readonly channel: number
  readonly sessionId: string
  readonly line: string
  /** Content-blind transport accounting for this complete logical line. */
  readonly transport?: RoutedTransportMetric
}

export interface RoutedTransportMetric {
  readonly rawWireBytes: number
  readonly logicalBytes: number
  readonly encodedBytes: number
  readonly decodedBytes: number
  readonly chunkCount: number
  readonly compressed: boolean
  readonly transferMs: number
  readonly reassembleMs: number
}

interface PendingTransportMetric {
  readonly firstAt: number
  readonly rawWireBytes: number
  readonly chunkCount: number
}

// terminal-frame.ts pins this exact header on the wire. `routeFrame` receives the decoded payload, so add the
// header back here rather than approximating DataChannel traffic from decoded string length.
const TERMINAL_FRAME_HEADER_BYTES = 8

function defaultNow(): number {
  return typeof performance !== 'undefined' ? performance.now() : Date.now()
}

export class ChannelRouter {
  /** channel id → session id (an attach binds the two). */
  private bindings = new Map<number, string>()
  /** Per-channel, protocol-bounded reassembly for chunked terminal_output. */
  private chunks: BoundedChunkReassembler
  private chunkMetrics = new Map<number, PendingTransportMetric>()
  private progressObserver: ((sessionId: string) => void) | null = null

  constructor(
    maxLineBytes?: number,
    maxAggregateBytes?: number,
    private readonly now: () => number = defaultNow,
  ) {
    this.chunks = new BoundedChunkReassembler(maxLineBytes, maxAggregateBytes)
  }

  setProgressObserver(observer: ((sessionId: string) => void) | null): void {
    this.progressObserver = observer
  }

  /** Bind a channel to a session (an attach). Re-binding a channel replaces the session + drops partial chunks. */
  bind(channel: number, sessionId: string): void {
    this.bindings.set(channel, sessionId)
    this.chunks.clear(channel)
    this.chunkMetrics.delete(channel)
  }

  /** Unbind a channel (a detach/close). Drops any partial chunk buffer for it. */
  unbind(channel: number): void {
    this.bindings.delete(channel)
    this.chunks.clear(channel)
    this.chunkMetrics.delete(channel)
  }

  sessionForChannel(channel: number): string | null {
    return this.bindings.get(channel) ?? null
  }

  channelForSession(sessionId: string): number | null {
    for (const [ch, sid] of this.bindings) if (sid === sessionId) return ch
    return null
  }

  get channelCount(): number {
    return this.bindings.size
  }

  /**
   * Route one inbound terminal frame. Returns the decoded line tagged with its session when a COMPLETE line
   * is ready, or null when:
   *  - the frame's channel isn't bound (not one of our panes),
   *  - it's a mid-stream chunk still accumulating,
   *  - or it's an agent-bound input frame (ignored here).
   * Chunk reassembly is per-channel, so interleaved frames from different channels don't corrupt each other.
   */
  routeFrame(frame: TerminalFrame): RoutedLine | null {
    const sessionId = this.bindings.get(frame.channel)
    if (sessionId === undefined) return null // not one of our channels

    if (frame.kind === FrameKind.TerminalOutputChunk) {
      const collecting = metricsOn()
      const receivedAt = collecting ? this.now() : 0
      const result = this.chunks.push(frame.channel, frame.payload)
      if (result.kind === 'dropped') {
        this.chunkMetrics.delete(frame.channel)
        return null
      }
      const prior = this.chunkMetrics.get(frame.channel)
      const trace: PendingTransportMetric | null = collecting
        ? {
            firstAt: prior?.firstAt ?? receivedAt,
            rawWireBytes: (prior?.rawWireBytes ?? 0) + TERMINAL_FRAME_HEADER_BYTES + frame.payload.byteLength,
            chunkCount: (prior?.chunkCount ?? 0) + 1,
          }
        : null
      // Invalid, overflowing, unbound, stale-channel, and empty chunks cannot keep an attach alive.
      if (result.chunkBytes > 0) this.progressObserver?.(sessionId)
      if (result.kind === 'partial') {
        if (trace) this.chunkMetrics.set(frame.channel, trace)
        else this.chunkMetrics.delete(frame.channel)
        return null
      }
      this.chunkMetrics.delete(frame.channel)
      const decodeStart = collecting ? this.now() : 0
      const line = new TextDecoder().decode(result.bytes)
      return {
        channel: frame.channel,
        sessionId,
        line,
        // If collection was enabled in the middle of an already-buffered line, omit that line rather than report
        // incomplete wire/chunk totals. Normal `?metrics=1` collection is enabled before the transport starts.
        transport: trace && (prior || result.totalBytes === result.chunkBytes)
          ? {
              rawWireBytes: trace.rawWireBytes,
              logicalBytes: result.totalBytes,
              encodedBytes: result.totalBytes,
              decodedBytes: result.totalBytes,
              chunkCount: trace.chunkCount,
              compressed: false,
              transferMs: Math.max(0, receivedAt - trace.firstAt),
              reassembleMs: Math.max(0, this.now() - decodeStart),
            }
          : undefined,
      }
    }

    if (frame.kind === FrameKind.TerminalOutput) {
      const collecting = metricsOn()
      const decodeStart = collecting ? this.now() : 0
      const line = frame.decodedText ?? new TextDecoder().decode(frame.payload)
      const localDecodeMs = collecting ? Math.max(0, this.now() - decodeStart) : 0
      return {
        channel: frame.channel,
        sessionId,
        line,
        transport: collecting
          ? {
              rawWireBytes: frame.transport?.rawWireBytes ?? TERMINAL_FRAME_HEADER_BYTES + frame.payload.byteLength,
              logicalBytes: frame.transport?.decodedBytes ?? frame.payload.byteLength,
              encodedBytes: frame.transport?.encodedBytes ?? frame.payload.byteLength,
              decodedBytes: frame.transport?.decodedBytes ?? frame.payload.byteLength,
              chunkCount: frame.transport?.chunkCount ?? 1,
              compressed: frame.transport?.compressed ?? false,
              transferMs: frame.transport?.transferMs ?? 0,
              reassembleMs: (frame.transport?.codecQueueMs ?? 0) +
                (frame.transport?.codecMs ?? 0) + localDecodeMs,
            }
          : undefined,
      }
    }

    return null // TerminalInput is agent-bound; ignore on the inbound path
  }
}
