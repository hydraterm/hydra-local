import { MAX_LINE_BYTES } from '../protocol/web-protocol.js'

export type ChunkAssemblyResult =
  | { kind: 'partial'; chunkBytes: number; totalBytes: number }
  | { kind: 'complete'; chunkBytes: number; totalBytes: number; bytes: Uint8Array }
  | { kind: 'dropped' }

interface PendingChunks {
  bytes: Uint8Array
  totalBytes: number
}

/** Protocol-bounded TerminalOutputChunk reassembly. Each line is capped at MAX_LINE_BYTES and all concurrently
 * pending channels share a 4× cap (64 MiB by default), rather than exposing the router's eight channels to an
 * implicit 8×16 MiB allocation. Overflow/malformed logical lines are discarded through their final chunk so a
 * tail can never be interpreted as a fresh daemon line. */
export class BoundedChunkReassembler {
  private pending = new Map<number, PendingChunks>()
  private discarding = new Set<number>()
  private pendingBytes = 0

  constructor(
    private readonly maxLineBytes = MAX_LINE_BYTES,
    private readonly maxAggregateBytes = MAX_LINE_BYTES * 4,
  ) {}

  push(channel: number, payload: Uint8Array): ChunkAssemblyResult {
    if (this.discarding.has(channel)) {
      if (payload[0] === 1) this.discarding.delete(channel)
      return { kind: 'dropped' }
    }
    if (payload.length < 1 || (payload[0] !== 0 && payload[0] !== 1)) {
      const interrupted = this.dropPending(channel)
      if (interrupted) this.discarding.add(channel)
      return { kind: 'dropped' }
    }

    const isLast = payload[0] === 1

    const body = payload.subarray(1)
    const current = this.pending.get(channel) ?? { bytes: new Uint8Array(0), totalBytes: 0 }
    const totalBytes = current.totalBytes + body.length
    if (totalBytes > this.maxLineBytes || this.pendingBytes + body.length > this.maxAggregateBytes) {
      this.dropPending(channel)
      if (!isLast) this.discarding.add(channel)
      return { kind: 'dropped' }
    }

    if (totalBytes > current.bytes.length) {
      const capacity = Math.min(this.maxLineBytes, Math.max(totalBytes, Math.max(1024, current.bytes.length * 2)))
      const grown = new Uint8Array(capacity)
      grown.set(current.bytes.subarray(0, current.totalBytes))
      current.bytes = grown
    }
    current.bytes.set(body, current.totalBytes)
    current.totalBytes = totalBytes
    this.pendingBytes += body.length
    if (!isLast) {
      this.pending.set(channel, current)
      return { kind: 'partial', chunkBytes: body.length, totalBytes }
    }

    this.pending.delete(channel)
    this.pendingBytes -= totalBytes
    return { kind: 'complete', chunkBytes: body.length, totalBytes, bytes: current.bytes.subarray(0, totalBytes) }
  }

  clear(channel: number): void {
    this.dropPending(channel)
    this.discarding.delete(channel)
  }

  clearAll(): void {
    this.pending.clear()
    this.discarding.clear()
    this.pendingBytes = 0
  }

  private dropPending(channel: number): boolean {
    const current = this.pending.get(channel)
    if (!current) return false
    this.pending.delete(channel)
    this.pendingBytes -= current.totalBytes
    return true
  }
}
