/**
 * Browser -> agent DataChannel flow control.
 *
 * Foreground control/input operations and structured paste use explicit fixed classes. Foreground operations remain
 * FIFO and indivisible. A complete structured paste is reserved atomically, but its independently balanced chunks
 * are safe scheduler boundaries: later foreground work may overtake only chunks that have not reached the native
 * DataChannel. Paste chunks remain FIFO, and a bounded foreground burst guarantees progress for accepted paste.
 *
 * Foreground may use the absolute native safety ceiling. Bulk paste uses a lower fixed soft ceiling plus one
 * asynchronously scheduled chunk quantum, leaving native headroom for newly-arrived foreground work. Draining waits
 * for `bufferedamountlow` after either ceiling; there is no poll, heartbeat, or dynamic allocator. A bounded overflow
 * or native send failure is fatal to this connection owner; reconnect establishes a fresh queue with no partial
 * local state.
 */

export const WEBRTC_OUTBOUND_BUFFER_HIGH_BYTES = 1024 * 1024
export const WEBRTC_OUTBOUND_BUFFER_LOW_BYTES = 128 * 1024
export const WEBRTC_OUTBOUND_BULK_BUFFER_HIGH_BYTES = 256 * 1024
export const WEBRTC_OUTBOUND_QUEUE_MAX_BYTES = 2 * 1024 * 1024
export const WEBRTC_OUTBOUND_QUEUE_MAX_ITEMS = 256
export const WEBRTC_OUTBOUND_FOREGROUND_BURST_OPERATIONS = 8

export type DataChannelSendFailure = 'overflow' | 'send_failed'

export interface BufferedDataChannelSink {
  readonly readyState: RTCDataChannelState
  readonly bufferedAmount: number
  bufferedAmountLowThreshold: number
  send(data: string | ArrayBuffer): void
}

interface QueuedText {
  readonly kind: 'text'
  readonly value: string
  readonly bytes: number
}

interface QueuedBinary {
  readonly kind: 'binary'
  readonly value: ArrayBuffer
  readonly bytes: number
}

type QueuedSend = QueuedText | QueuedBinary

interface QueuedOperation {
  readonly items: readonly QueuedSend[]
  next: number
}

export interface DataChannelSendQueueOptions {
  readonly highWaterBytes?: number
  readonly lowWaterBytes?: number
  readonly bulkHighWaterBytes?: number
  readonly maxQueuedBytes?: number
  readonly maxQueuedItems?: number
  readonly foregroundBurstOperations?: number
  /** One-shot task scheduling seam. The callback must not run inline. */
  readonly scheduleBulkDrain?: (callback: () => void) => void
}

const UTF8 = new TextEncoder()
const scheduleTask = (callback: () => void): void => {
  setTimeout(callback, 0)
}

export class DataChannelSendQueue {
  private readonly highWaterBytes: number
  private readonly lowWaterBytes: number
  private readonly bulkHighWaterBytes: number
  private readonly maxQueuedBytes: number
  private readonly maxQueuedItems: number
  private readonly foregroundBurstOperations: number
  private readonly scheduleBulkDrainTask: (callback: () => void) => void
  private readonly foreground: QueuedOperation[] = []
  private readonly bulk: QueuedOperation[] = []
  private pendingItems = 0
  private pendingBytes = 0
  private foregroundOperationsSinceBulk = 0
  private bulkDrainScheduled = false
  private bulkDrainScheduleEpoch = 0
  private draining = false
  private closed = false
  private failed = false

  constructor(
    private readonly channel: BufferedDataChannelSink,
    private readonly onFailure: (reason: DataChannelSendFailure) => void,
    options: DataChannelSendQueueOptions = {},
  ) {
    this.highWaterBytes = options.highWaterBytes ?? WEBRTC_OUTBOUND_BUFFER_HIGH_BYTES
    this.lowWaterBytes = options.lowWaterBytes ?? WEBRTC_OUTBOUND_BUFFER_LOW_BYTES
    this.bulkHighWaterBytes = options.bulkHighWaterBytes ??
      Math.min(
        WEBRTC_OUTBOUND_BULK_BUFFER_HIGH_BYTES,
        Math.ceil((this.lowWaterBytes + this.highWaterBytes) / 2),
      )
    this.maxQueuedBytes = options.maxQueuedBytes ?? WEBRTC_OUTBOUND_QUEUE_MAX_BYTES
    this.maxQueuedItems = options.maxQueuedItems ?? WEBRTC_OUTBOUND_QUEUE_MAX_ITEMS
    this.foregroundBurstOperations =
      options.foregroundBurstOperations ?? WEBRTC_OUTBOUND_FOREGROUND_BURST_OPERATIONS
    this.scheduleBulkDrainTask = options.scheduleBulkDrain ?? scheduleTask
    if (
      this.lowWaterBytes < 0 || this.highWaterBytes <= this.lowWaterBytes ||
      this.bulkHighWaterBytes <= this.lowWaterBytes ||
      this.bulkHighWaterBytes > this.highWaterBytes ||
      this.maxQueuedBytes <= 0 || this.maxQueuedItems <= 0 ||
      !Number.isSafeInteger(this.foregroundBurstOperations) ||
      this.foregroundBurstOperations <= 0
    ) {
      throw new RangeError('invalid DataChannel send-queue bounds')
    }
    this.channel.bufferedAmountLowThreshold = this.lowWaterBytes
  }

  enqueueText(value: string): boolean {
    const bytes = UTF8.encode(value).byteLength
    return this.enqueueOperation('foreground', [{ kind: 'text', value, bytes }], bytes)
  }

  enqueueBinary(value: Uint8Array): boolean {
    return this.enqueueBinaryBatch([value])
  }

  /**
   * Admit one control declaration followed by its complete binary body as one FIFO transaction.
   *
   * The remote benchmark uses this for the existing `input_batch` contract, but the primitive is generic: it
   * closes a real production-queue hazard where a declaration could be admitted before a later binary-batch
   * overflow. Either every item is copied into this owner-local FIFO, in order, or none of them is visible to the
   * DataChannel. Normal text and binary enqueue behavior is unchanged.
   */
  enqueueTextAndBinaryBatch(text: string, values: readonly Uint8Array[]): boolean {
    if (this.closed) return false
    const textBytes = UTF8.encode(text).byteLength
    let bytes = textBytes
    for (const value of values) {
      bytes += value.byteLength
      if (!Number.isSafeInteger(bytes)) return this.fail('overflow')
    }
    const itemCount = 1 + values.length
    if (!this.canAdmit(itemCount, bytes)) return this.fail('overflow')
    const items: QueuedSend[] = [
      { kind: 'text', value: text, bytes: textBytes },
      ...values.map((value): QueuedBinary => ({
        kind: 'binary',
        value: value.slice().buffer,
        bytes: value.byteLength,
      })),
    ]
    return this.enqueueAdmitted('foreground', items, bytes)
  }

  /** Admit every frame from one logical input operation or none of them. */
  enqueueBinaryBatch(values: readonly Uint8Array[]): boolean {
    return this.enqueueBinaryOperation('foreground', values)
  }

  /**
   * Atomically reserve a complete structured paste as bulk work.
   *
   * The caller supplies independently balanced, UTF-8/chunk-bounded paste frames. Once admitted, foreground may
   * overtake only between those frames; the frames themselves remain in exact order.
   */
  enqueueBulkBinaryBatch(values: readonly Uint8Array[]): boolean {
    return this.enqueueBinaryOperation('bulk', values)
  }

  private enqueueBinaryOperation(
    priority: 'foreground' | 'bulk',
    values: readonly Uint8Array[],
  ): boolean {
    if (this.closed) return false
    if (values.length === 0) return true
    let bytes = 0
    for (const value of values) {
      bytes += value.byteLength
      if (!Number.isSafeInteger(bytes)) return this.fail('overflow')
    }
    if (!this.canAdmit(values.length, bytes)) return this.fail('overflow')

    const items: QueuedBinary[] = values.map((value) => {
      // DataChannel.send must not observe later mutation of a caller-owned typed-array view.
      const copy = value.slice().buffer
      return { kind: 'binary', value: copy, bytes: value.byteLength }
    })
    return this.enqueueAdmitted(priority, items, bytes)
  }

  /** Called only by the channel's native `bufferedamountlow` event. */
  onBufferedAmountLow(): void {
    if (this.closed || this.channel.bufferedAmount > this.lowWaterBytes) return
    this.drain()
  }

  /** Retire this owner. Pending bytes never survive reconnect. */
  close(): void {
    if (this.closed) return
    this.closed = true
    this.invalidateScheduledBulkDrain()
    this.foreground.length = 0
    this.bulk.length = 0
    this.pendingItems = 0
    this.pendingBytes = 0
    this.foregroundOperationsSinceBulk = 0
  }

  private enqueueOperation(
    priority: 'foreground' | 'bulk',
    items: readonly QueuedSend[],
    bytes: number,
  ): boolean {
    if (this.closed) return false
    if (!this.canAdmit(items.length, bytes)) return this.fail('overflow')
    return this.enqueueAdmitted(priority, items, bytes)
  }

  private canAdmit(items: number, bytes: number): boolean {
    return items <= this.maxQueuedItems - this.pendingItems &&
      bytes <= this.maxQueuedBytes - this.pendingBytes
  }

  private enqueueAdmitted(
    priority: 'foreground' | 'bulk',
    items: readonly QueuedSend[],
    bytes: number,
  ): boolean {
    const operation = { items, next: 0 }
    if (priority === 'foreground') this.foreground.push(operation)
    else this.bulk.push(operation)
    this.pendingItems += items.length
    this.pendingBytes += bytes
    this.drain()
    return !this.closed
  }

  private drain(): void {
    if (this.closed || this.draining) return
    this.draining = true
    let sentBulkThisTurn = false
    try {
      for (;;) {
        if (this.channel.readyState !== 'open') {
          this.fail('send_failed')
          return
        }
        if (this.channel.bufferedAmount >= this.highWaterBytes) return

        const foreground = this.foreground[0]
        const bulk = this.bulk[0]
        if (!foreground && !bulk) {
          this.foregroundOperationsSinceBulk = 0
          return
        }

        // Once a foreground transaction has started, finish it before crossing classes. This keeps declarations
        // and binary bodies, as well as multi-frame ordinary input, contiguous even across native low-water waits.
        const foregroundInProgress = foreground !== undefined && foreground.next > 0
        const fairnessDue = bulk !== undefined &&
          this.foregroundOperationsSinceBulk >= this.foregroundBurstOperations
        if (foreground !== undefined && (foregroundInProgress || bulk === undefined || !fairnessDue)) {
          if (!this.sendNext(foreground)) return
          if (foreground.next === foreground.items.length) {
            this.foreground.shift()
            if (this.bulk.length > 0) this.foregroundOperationsSinceBulk += 1
            else this.foregroundOperationsSinceBulk = 0
          }
          continue
        }

        if (bulk === undefined) continue
        // A scheduled bulk quantum is already the progress owner. Foreground can still drain immediately, but a
        // second caller must not add another bulk quantum. Fairness invalidates the stale task and advances now.
        if (this.bulkDrainScheduled && !fairnessDue) return
        if (fairnessDue) this.invalidateScheduledBulkDrain()
        if (sentBulkThisTurn) {
          // The fairness quantum must still own the next task when this turn has already advanced bulk. Above the
          // bulk soft ceiling, a normal schedule would be refused and could strand foreground below the hard
          // ceiling until an unrelated low-water event. The forced task bypasses only the bulk soft ceiling; the
          // callback still observes the absolute native high-water ceiling before sending anything.
          this.scheduleBulkDrain(true)
          return
        }
        if (!fairnessDue && this.channel.bufferedAmount >= this.bulkHighWaterBytes) return

        if (!this.sendNext(bulk)) return
        sentBulkThisTurn = true
        this.foregroundOperationsSinceBulk = 0
        if (bulk.next === bulk.items.length) this.bulk.shift()

        if (this.bulk.length > 0) {
          this.scheduleBulkDrain()
          // Keep serving already-queued foreground after the one bulk quantum. The next bulk quantum remains a
          // separate task unless the bounded fairness rule advances it sooner.
          if (this.foreground.length === 0) return
        }
      }
    } finally {
      this.draining = false
    }
  }

  private sendNext(operation: QueuedOperation): boolean {
    const item = operation.items[operation.next]!
    try {
      this.channel.send(item.value)
    } catch {
      this.fail('send_failed')
      return false
    }
    operation.next += 1
    this.pendingItems -= 1
    this.pendingBytes -= item.bytes
    return true
  }

  private scheduleBulkDrain(forceFairness = false): void {
    if (
      this.closed || this.bulkDrainScheduled || this.bulk.length === 0 ||
      (!forceFairness && this.channel.bufferedAmount >= this.bulkHighWaterBytes)
    ) {
      return
    }
    this.bulkDrainScheduled = true
    const epoch = ++this.bulkDrainScheduleEpoch
    this.scheduleBulkDrainTask(() => {
      if (this.closed || !this.bulkDrainScheduled || epoch !== this.bulkDrainScheduleEpoch) return
      this.bulkDrainScheduled = false
      this.drain()
    })
  }

  private invalidateScheduledBulkDrain(): void {
    this.bulkDrainScheduled = false
    this.bulkDrainScheduleEpoch += 1
  }

  private fail(reason: DataChannelSendFailure): false {
    if (this.failed) return false
    this.failed = true
    this.close()
    this.onFailure(reason)
    return false
  }
}
