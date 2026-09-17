import { describe, expect, it } from 'vitest'
import {
  DataChannelSendQueue,
  WEBRTC_OUTBOUND_BULK_BUFFER_HIGH_BYTES,
  WEBRTC_OUTBOUND_BUFFER_HIGH_BYTES,
  WEBRTC_OUTBOUND_BUFFER_LOW_BYTES,
  WEBRTC_OUTBOUND_FOREGROUND_BURST_OPERATIONS,
  type BufferedDataChannelSink,
  type DataChannelSendFailure,
} from './datachannel-send-queue'

class FakeBufferedChannel implements BufferedDataChannelSink {
  readyState: RTCDataChannelState = 'open'
  bufferedAmount = 0
  bufferedAmountLowThreshold = 0
  readonly sent: Array<string | Uint8Array> = []
  throwOnSend = false

  send(value: string | ArrayBuffer): void {
    if (this.throwOnSend) throw new Error('synthetic send failure')
    if (typeof value === 'string') {
      this.sent.push(value)
      this.bufferedAmount += new TextEncoder().encode(value).byteLength
    } else {
      const copy = new Uint8Array(value.slice(0))
      this.sent.push(copy)
      this.bufferedAmount += copy.byteLength
    }
  }
}

describe('DataChannelSendQueue', () => {
  it('uses the fixed product ceilings and preserves foreground text/binary FIFO', () => {
    const channel = new FakeBufferedChannel()
    const failures: DataChannelSendFailure[] = []
    const queue = new DataChannelSendQueue(channel, (reason) => failures.push(reason))

    expect(channel.bufferedAmountLowThreshold).toBe(WEBRTC_OUTBOUND_BUFFER_LOW_BYTES)
    expect(WEBRTC_OUTBOUND_BUFFER_LOW_BYTES).toBeLessThan(WEBRTC_OUTBOUND_BULK_BUFFER_HIGH_BYTES)
    expect(WEBRTC_OUTBOUND_BULK_BUFFER_HIGH_BYTES).toBeLessThan(WEBRTC_OUTBOUND_BUFFER_HIGH_BYTES)
    expect(queue.enqueueText('control-a')).toBe(true)
    expect(queue.enqueueBinary(new Uint8Array([1, 2]))).toBe(true)
    expect(queue.enqueueText('control-b')).toBe(true)

    expect(channel.sent).toEqual(['control-a', new Uint8Array([1, 2]), 'control-b'])
    expect(channel.bufferedAmount).toBeLessThan(WEBRTC_OUTBOUND_BUFFER_HIGH_BYTES)
    expect(failures).toEqual([])
  })

  it('stops at high-water and wakes only after an authoritative low-water event', () => {
    const channel = new FakeBufferedChannel()
    const queue = new DataChannelSendQueue(channel, () => {}, {
      highWaterBytes: 10,
      lowWaterBytes: 3,
      maxQueuedBytes: 100,
    })

    expect(queue.enqueueText('123456')).toBe(true)
    expect(queue.enqueueText('abcdef')).toBe(true) // native buffer reaches 12 → paused
    expect(queue.enqueueText('after-low')).toBe(true)
    expect(channel.sent).toEqual(['123456', 'abcdef'])

    channel.bufferedAmount = 4
    queue.onBufferedAmountLow() // a stale/spurious event above low-water cannot drain
    expect(channel.sent).toEqual(['123456', 'abcdef'])

    channel.bufferedAmount = 3
    queue.onBufferedAmountLow()
    expect(channel.sent).toEqual(['123456', 'abcdef', 'after-low'])
  })

  it('rejects an overflowing binary batch atomically and fails the owner once', () => {
    const channel = new FakeBufferedChannel()
    channel.bufferedAmount = 10
    const failures: DataChannelSendFailure[] = []
    const queue = new DataChannelSendQueue(channel, (reason) => failures.push(reason), {
      highWaterBytes: 10,
      lowWaterBytes: 3,
      maxQueuedBytes: 5,
      maxQueuedItems: 4,
    })

    expect(queue.enqueueBinary(new Uint8Array([9, 9]))).toBe(true) // pending behind native high-water
    expect(queue.enqueueBinaryBatch([
      new Uint8Array([1, 2]),
      new Uint8Array([3, 4]),
    ])).toBe(false)
    expect(channel.sent).toEqual([]) // no prefix of the rejected logical batch escaped
    expect(failures).toEqual(['overflow'])

    channel.bufferedAmount = 0
    queue.onBufferedAmountLow()
    expect(channel.sent).toEqual([]) // failure also discarded older pending state
    expect(queue.enqueueText('late')).toBe(false)
    expect(failures).toEqual(['overflow'])
  })

  it('atomically admits bulk paste, then foreground overtakes only at complete chunk boundaries', () => {
    const channel = new FakeBufferedChannel()
    const scheduled: Array<() => void> = []
    const failures: DataChannelSendFailure[] = []
    const queue = new DataChannelSendQueue(channel, (reason) => failures.push(reason), {
      highWaterBytes: 100,
      lowWaterBytes: 10,
      bulkHighWaterBytes: 40,
      maxQueuedBytes: 100,
      scheduleBulkDrain: (callback) => scheduled.push(callback),
    })

    expect(queue.enqueueBulkBinaryBatch([
      new Uint8Array([1]),
      new Uint8Array([2]),
      new Uint8Array([3]),
    ])).toBe(true)
    expect(channel.sent).toEqual([new Uint8Array([1])])
    expect(scheduled).toHaveLength(1)

    expect(queue.enqueueText('control')).toBe(true)
    expect(queue.enqueueBinary(new Uint8Array([9]))).toBe(true)
    expect(channel.sent).toEqual([new Uint8Array([1]), 'control', new Uint8Array([9])])

    scheduled.shift()!()
    expect(channel.sent).toEqual([
      new Uint8Array([1]),
      'control',
      new Uint8Array([9]),
      new Uint8Array([2]),
    ])
    scheduled.shift()!()
    expect(channel.sent).toEqual([
      new Uint8Array([1]),
      'control',
      new Uint8Array([9]),
      new Uint8Array([2]),
      new Uint8Array([3]),
    ])
    expect(failures).toEqual([])
  })

  it('keeps foreground transactions indivisible while allowing bulk progress between them', () => {
    const channel = new FakeBufferedChannel()
    channel.bufferedAmount = 100
    const scheduled: Array<() => void> = []
    const queue = new DataChannelSendQueue(channel, () => {}, {
      highWaterBytes: 100,
      lowWaterBytes: 10,
      bulkHighWaterBytes: 40,
      maxQueuedBytes: 100,
      scheduleBulkDrain: (callback) => scheduled.push(callback),
      foregroundBurstOperations: 1,
    })

    expect(queue.enqueueBulkBinaryBatch([
      new Uint8Array([1]),
      new Uint8Array([2]),
    ])).toBe(true)
    expect(queue.enqueueTextAndBinaryBatch('decl', [
      new Uint8Array([7]),
      new Uint8Array([8]),
    ])).toBe(true)
    channel.bufferedAmount = 10
    queue.onBufferedAmountLow()

    expect(channel.sent).toEqual([
      'decl',
      new Uint8Array([7]),
      new Uint8Array([8]),
      new Uint8Array([1]),
    ])
    expect(scheduled).toHaveLength(1)
  })

  it('bounds foreground preference so continuous control/input cannot starve an accepted paste', () => {
    const channel = new FakeBufferedChannel()
    channel.bufferedAmount = 100
    const scheduled: Array<() => void> = []
    const queue = new DataChannelSendQueue(channel, () => {}, {
      highWaterBytes: 100,
      lowWaterBytes: 10,
      bulkHighWaterBytes: 40,
      maxQueuedBytes: 200,
      scheduleBulkDrain: (callback) => scheduled.push(callback),
      foregroundBurstOperations: 2,
    })

    expect(queue.enqueueBulkBinaryBatch([
      new Uint8Array([1]),
      new Uint8Array([2]),
    ])).toBe(true)
    expect(queue.enqueueText('control-a')).toBe(true)
    expect(queue.enqueueBinary(new Uint8Array([9]))).toBe(true)
    expect(queue.enqueueText('control-b')).toBe(true)
    channel.bufferedAmount = 10
    queue.onBufferedAmountLow()

    // Two complete foreground operations run, then one paste chunk, then foreground resumes.
    expect(channel.sent).toEqual([
      'control-a',
      new Uint8Array([9]),
      new Uint8Array([1]),
      'control-b',
    ])
    expect(scheduled).toHaveLength(1)
  })

  it('advances bulk after the fixed foreground burst even before its scheduled task runs', () => {
    const channel = new FakeBufferedChannel()
    const scheduled: Array<() => void> = []
    const queue = new DataChannelSendQueue(channel, () => {}, {
      highWaterBytes: 100,
      lowWaterBytes: 10,
      bulkHighWaterBytes: 80,
      maxQueuedBytes: 200,
      scheduleBulkDrain: (callback) => scheduled.push(callback),
      foregroundBurstOperations: 2,
    })

    expect(queue.enqueueBulkBinaryBatch([
      new Uint8Array([1]),
      new Uint8Array([2]),
      new Uint8Array([3]),
    ])).toBe(true)
    expect(scheduled).toHaveLength(1)
    expect(queue.enqueueText('a')).toBe(true)
    expect(queue.enqueueText('b')).toBe(true)

    // The second accepted foreground operation invalidates the stale task and advances exactly one bulk chunk.
    expect(channel.sent).toEqual([
      new Uint8Array([1]),
      'a',
      'b',
      new Uint8Array([2]),
    ])
    scheduled.shift()!() // stale task is inert
    expect(channel.sent).toHaveLength(4)
  })

  it('does not strand foreground when repeated fairness progress crosses the bulk soft ceiling', () => {
    const channel = new FakeBufferedChannel()
    channel.bufferedAmount = 100
    const scheduled: Array<() => void> = []
    const queue = new DataChannelSendQueue(channel, () => {}, {
      highWaterBytes: 100,
      lowWaterBytes: 10,
      bulkHighWaterBytes: 40,
      maxQueuedBytes: 200,
      scheduleBulkDrain: (callback) => scheduled.push(callback),
      foregroundBurstOperations: 2,
    })

    expect(queue.enqueueBulkBinaryBatch([
      new Uint8Array(20).fill(1),
      new Uint8Array(20).fill(2),
      new Uint8Array(20).fill(3),
    ])).toBe(true)
    for (const value of ['a', 'b', 'c', 'd', 'e', 'f', 'g']) {
      expect(queue.enqueueText(value.repeat(5))).toBe(true)
    }

    channel.bufferedAmount = 10
    queue.onBufferedAmountLow()
    expect(channel.sent).toEqual([
      'aaaaa',
      'bbbbb',
      new Uint8Array(20).fill(1),
      'ccccc',
      'ddddd',
    ])
    expect(channel.bufferedAmount).toBe(50)
    expect(scheduled).toHaveLength(1)

    scheduled.shift()!()
    expect(channel.sent).toEqual([
      'aaaaa',
      'bbbbb',
      new Uint8Array(20).fill(1),
      'ccccc',
      'ddddd',
      new Uint8Array(20).fill(2),
      'eeeee',
      'fffff',
    ])
    expect(channel.bufferedAmount).toBe(80)
    expect(scheduled).toHaveLength(1)

    scheduled.shift()!()
    expect(channel.sent).toEqual([
      'aaaaa',
      'bbbbb',
      new Uint8Array(20).fill(1),
      'ccccc',
      'ddddd',
      new Uint8Array(20).fill(2),
      'eeeee',
      'fffff',
      new Uint8Array(20).fill(3),
    ])
    expect(channel.bufferedAmount).toBe(100)
    expect(scheduled).toHaveLength(0)

    channel.bufferedAmount = 10
    queue.onBufferedAmountLow()
    expect(channel.sent.at(-1)).toBe('ggggg')
  })

  it('reserves native headroom for foreground while bulk waits at its fixed soft ceiling', () => {
    const channel = new FakeBufferedChannel()
    const scheduled: Array<() => void> = []
    const queue = new DataChannelSendQueue(channel, () => {}, {
      highWaterBytes: 20,
      lowWaterBytes: 5,
      bulkHighWaterBytes: 10,
      maxQueuedBytes: 100,
      scheduleBulkDrain: (callback) => scheduled.push(callback),
    })

    expect(queue.enqueueBulkBinaryBatch([
      new Uint8Array(6).fill(1),
      new Uint8Array(6).fill(2),
      new Uint8Array(6).fill(3),
    ])).toBe(true)
    scheduled.shift()!()
    expect(channel.bufferedAmount).toBe(12)
    expect(scheduled).toHaveLength(0) // bulk waits above its soft ceiling

    expect(queue.enqueueBinary(new Uint8Array([9]))).toBe(true)
    expect(channel.sent).toEqual([
      new Uint8Array(6).fill(1),
      new Uint8Array(6).fill(2),
      new Uint8Array([9]),
    ])

    channel.bufferedAmount = 5
    queue.onBufferedAmountLow()
    expect(channel.sent.at(-1)).toEqual(new Uint8Array(6).fill(3))
  })

  it('rejects an overflowing bulk paste atomically without exposing a prefix', () => {
    const channel = new FakeBufferedChannel()
    const failures: DataChannelSendFailure[] = []
    const queue = new DataChannelSendQueue(channel, (reason) => failures.push(reason), {
      highWaterBytes: 10,
      lowWaterBytes: 3,
      bulkHighWaterBytes: 6,
      maxQueuedBytes: 3,
      maxQueuedItems: 2,
    })

    expect(queue.enqueueBulkBinaryBatch([
      new Uint8Array([1, 2]),
      new Uint8Array([3, 4]),
    ])).toBe(false)
    expect(channel.sent).toEqual([])
    expect(failures).toEqual(['overflow'])
  })

  it('fails the owner after a partial native bulk send and releases every unsent reservation', () => {
    const channel = new FakeBufferedChannel()
    const scheduled: Array<() => void> = []
    const failures: DataChannelSendFailure[] = []
    const queue = new DataChannelSendQueue(channel, (reason) => failures.push(reason), {
      highWaterBytes: 100,
      lowWaterBytes: 10,
      bulkHighWaterBytes: 40,
      maxQueuedBytes: 100,
      scheduleBulkDrain: (callback) => scheduled.push(callback),
    })

    expect(queue.enqueueBulkBinaryBatch([
      new Uint8Array([1]),
      new Uint8Array([2]),
      new Uint8Array([3]),
    ])).toBe(true)
    expect(channel.sent).toEqual([new Uint8Array([1])])

    channel.throwOnSend = true
    scheduled.shift()!()
    expect(failures).toEqual(['send_failed'])
    channel.throwOnSend = false
    expect(queue.enqueueText('late')).toBe(false)
    for (const callback of scheduled) callback()
    expect(channel.sent).toEqual([new Uint8Array([1])])
    expect(failures).toEqual(['send_failed'])
  })

  it('close invalidates a scheduled bulk quantum and permits no owner-local tail to escape', () => {
    const channel = new FakeBufferedChannel()
    const scheduled: Array<() => void> = []
    const queue = new DataChannelSendQueue(channel, () => {}, {
      highWaterBytes: 100,
      lowWaterBytes: 10,
      bulkHighWaterBytes: 40,
      scheduleBulkDrain: (callback) => scheduled.push(callback),
    })

    expect(queue.enqueueBulkBinaryBatch([
      new Uint8Array([1]),
      new Uint8Array([2]),
    ])).toBe(true)
    queue.close()
    scheduled.shift()!()
    expect(channel.sent).toEqual([new Uint8Array([1])])
    expect(queue.enqueueBinaryBatch([])).toBe(false)
  })

  it('uses the product foreground fairness bound rather than an adaptive allocator', () => {
    expect(WEBRTC_OUTBOUND_FOREGROUND_BURST_OPERATIONS).toBe(8)
  })

  it('admits a text declaration and binary body as one indivisible FIFO transaction', () => {
    const channel = new FakeBufferedChannel()
    channel.bufferedAmount = 10
    const failures: DataChannelSendFailure[] = []
    const queue = new DataChannelSendQueue(channel, (reason) => failures.push(reason), {
      highWaterBytes: 10,
      lowWaterBytes: 3,
      maxQueuedBytes: 32,
      maxQueuedItems: 4,
    })
    const first = new Uint8Array([1, 2])
    const second = new Uint8Array([3, 4])
    expect(queue.enqueueTextAndBinaryBatch('decl', [first, second])).toBe(true)
    first.fill(9)
    second.fill(9)
    channel.bufferedAmount = 0
    queue.onBufferedAmountLow()
    expect(channel.sent).toEqual(['decl', new Uint8Array([1, 2]), new Uint8Array([3, 4])])
    expect(failures).toEqual([])
  })

  it('never exposes a declaration when its composite binary body cannot be admitted', () => {
    const channel = new FakeBufferedChannel()
    channel.bufferedAmount = 10
    const failures: DataChannelSendFailure[] = []
    const queue = new DataChannelSendQueue(channel, (reason) => failures.push(reason), {
      highWaterBytes: 10,
      lowWaterBytes: 3,
      maxQueuedBytes: 5,
      maxQueuedItems: 4,
    })
    expect(queue.enqueueTextAndBinaryBatch('decl', [new Uint8Array([1, 2])])).toBe(false)
    expect(channel.sent).toEqual([])
    expect(failures).toEqual(['overflow'])
  })

  it('fails once on native send error and never retries an ambiguous item', () => {
    const channel = new FakeBufferedChannel()
    channel.throwOnSend = true
    const failures: DataChannelSendFailure[] = []
    const queue = new DataChannelSendQueue(channel, (reason) => failures.push(reason))

    expect(queue.enqueueText('ambiguous')).toBe(false)
    expect(queue.enqueueText('late')).toBe(false)
    expect(failures).toEqual(['send_failed'])
    expect(channel.sent).toEqual([])
  })

  it('drops owner-local pending state on close and ignores a later low event', () => {
    const channel = new FakeBufferedChannel()
    channel.bufferedAmount = 10
    const queue = new DataChannelSendQueue(channel, () => {}, {
      highWaterBytes: 10,
      lowWaterBytes: 3,
    })
    expect(queue.enqueueText('old-owner')).toBe(true)
    queue.close()
    channel.bufferedAmount = 0
    queue.onBufferedAmountLow()
    expect(channel.sent).toEqual([])
  })

  it('copies binary input before the caller can mutate it', () => {
    const channel = new FakeBufferedChannel()
    channel.bufferedAmount = 10
    const queue = new DataChannelSendQueue(channel, () => {}, {
      highWaterBytes: 10,
      lowWaterBytes: 3,
    })
    const callerOwned = new Uint8Array([1, 2, 3])
    expect(queue.enqueueBinary(callerOwned)).toBe(true)
    callerOwned.fill(9)
    channel.bufferedAmount = 0
    queue.onBufferedAmountLow()
    expect(channel.sent).toEqual([new Uint8Array([1, 2, 3])])
  })
})
