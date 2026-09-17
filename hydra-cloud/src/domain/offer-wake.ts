// Content-blind wake hints for WebRTC signaling.
//
// A hint carries only a fixed-size, domain-separated digest of its routing tuple. It is never authority and never
// carries a raw account/device/session id, SDP, ICE, token, or terminal data. Every consumer must query the
// signaling store after a hint. The in-process hub deliberately retains no notification history:
// subscribe-before-query plus a bounded HTTP retry closes missed-wake races without turning this performance path
// into a second source of truth.

import { createHash } from 'node:crypto'

export const OFFER_WAKE_CHANNEL = 'hydra_signal_offer_v1'
export const PROGRESS_WAKE_CHANNEL = 'hydra_signal_progress_v1'
export const PENDING_OFFER_MAX_WAIT_MS = 6_000
export const SIGNAL_PROGRESS_MAX_WAIT_MS = 6_000
export const DEFAULT_OFFER_WAKE_TOTAL_LIMIT = 512
export const DEFAULT_OFFER_WAKE_PER_KEY_LIMIT = 2

const WAKE_KEY_RE = /^[a-f0-9]{64}$/

export type OfferWakeOutcome = 'hint' | 'timeout' | 'unavailable' | 'aborted'

export interface OfferWakeSubscription {
  wait(timeoutMs: number, signal?: AbortSignal): Promise<OfferWakeOutcome>
  close(): void
}

export type OfferWakeRegistration =
  | { kind: 'subscribed'; subscription: OfferWakeSubscription }
  | { kind: 'unavailable' | 'capacity' }

export interface OfferWakeSource {
  subscribe(key: string): OfferWakeRegistration
}

export interface OfferWakePublisher {
  publish(key: string): void
}

export type SignalingWakeOutcome = OfferWakeOutcome
export type SignalingWakeSubscription = OfferWakeSubscription
export type SignalingWakeRegistration = OfferWakeRegistration
export type SignalingWakeSource = OfferWakeSource
export type SignalingWakePublisher = OfferWakePublisher

/** A fixed-size, non-reversible routing hint. Length framing keeps the versioned tuple unambiguous even if an
 * upstream identity provider ever admits separator/control characters in an account identifier. */
export function offerWakeKey(accountId: string, targetDeviceId: string): string {
  return signalingWakeKey('hydra-offer-wake-v1', [accountId, targetDeviceId])
}

/** Browser/peer progress is scoped to one caller of one session. Both parties have distinct keys because their
 * peer-only candidate projections differ, while answer/status/global-cursor changes may wake both. */
export function progressWakeKey(accountId: string, sessionId: string, callerDeviceId: string): string {
  return signalingWakeKey('hydra-progress-wake-v1', [accountId, sessionId, callerDeviceId])
}

function signalingWakeKey(domain: string, values: readonly string[]): string {
  const digest = createHash('sha256').update(domain, 'utf8')
  for (const value of values) {
    const bytes = Buffer.from(value, 'utf8')
    const length = Buffer.allocUnsafe(4)
    length.writeUInt32BE(bytes.length)
    digest.update(length).update(bytes)
  }
  return digest.digest('hex')
}

export function isOfferWakeKey(value: string): boolean {
  return WAKE_KEY_RE.test(value)
}

export const isSignalingWakeKey = isOfferWakeKey

interface Waiter {
  settle(outcome: OfferWakeOutcome): void
}

/**
 * One replica-local, bounded set of one-shot waiters. `publish` coalesces naturally: it resolves the current
 * waiters and stores nothing for later. Listener loss flips the hub unavailable and releases every waiter so
 * callers immediately fall back to their authoritative query cadence.
 */
export class BoundedSignalingWakeHub implements SignalingWakeSource, SignalingWakePublisher {
  private readonly byKey = new Map<string, Set<Waiter>>()
  private waiterCount = 0
  private available: boolean

  constructor(
    options: {
      available?: boolean
      totalLimit?: number
      perKeyLimit?: number
    } = {},
  ) {
    this.available = options.available ?? false
    this.totalLimit = positiveInteger(options.totalLimit ?? DEFAULT_OFFER_WAKE_TOTAL_LIMIT, 'totalLimit')
    this.perKeyLimit = positiveInteger(options.perKeyLimit ?? DEFAULT_OFFER_WAKE_PER_KEY_LIMIT, 'perKeyLimit')
  }

  private readonly totalLimit: number
  private readonly perKeyLimit: number

  get isAvailable(): boolean {
    return this.available
  }

  get activeWaiters(): number {
    return this.waiterCount
  }

  markAvailable(): void {
    this.available = true
  }

  markUnavailable(): void {
    if (!this.available && this.waiterCount === 0) return
    this.available = false
    const waiters = [...this.byKey.values()].flatMap((set) => [...set])
    for (const waiter of waiters) waiter.settle('unavailable')
  }

  subscribe(key: string): OfferWakeRegistration {
    if (!isOfferWakeKey(key) || !this.available) return { kind: 'unavailable' }
    const existing = this.byKey.get(key)
    if (this.waiterCount >= this.totalLimit || (existing?.size ?? 0) >= this.perKeyLimit) {
      return { kind: 'capacity' }
    }

    let settled: OfferWakeOutcome | null = null
    let resolveOutcome!: (outcome: OfferWakeOutcome) => void
    const outcome = new Promise<OfferWakeOutcome>((resolve) => {
      resolveOutcome = resolve
    })
    let timer: ReturnType<typeof setTimeout> | null = null
    let abortSignal: AbortSignal | undefined
    let abortListener: (() => void) | null = null
    let waitStarted = false

    const remove = () => {
      const set = this.byKey.get(key)
      if (!set?.delete(waiter)) return
      this.waiterCount -= 1
      if (set.size === 0) this.byKey.delete(key)
    }
    const cleanupWait = () => {
      if (timer) clearTimeout(timer)
      timer = null
      if (abortSignal && abortListener) abortSignal.removeEventListener('abort', abortListener)
      abortSignal = undefined
      abortListener = null
    }
    const settle = (value: OfferWakeOutcome) => {
      if (settled !== null) return
      settled = value
      cleanupWait()
      remove()
      resolveOutcome(value)
    }
    const waiter: Waiter = { settle }
    const set = existing ?? new Set<Waiter>()
    if (!existing) this.byKey.set(key, set)
    set.add(waiter)
    this.waiterCount += 1

    return {
      kind: 'subscribed',
      subscription: {
        wait: (timeoutMs, signal) => {
          if (waitStarted) throw new Error('signaling wake subscription may only be awaited once')
          waitStarted = true
          if (settled !== null) return outcome
          if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
            settle('timeout')
            return outcome
          }
          if (signal?.aborted) {
            settle('aborted')
            return outcome
          }
          if (signal) {
            abortSignal = signal
            abortListener = () => settle('aborted')
            signal.addEventListener('abort', abortListener, { once: true })
          }
          timer = setTimeout(() => settle('timeout'), timeoutMs)
          return outcome
        },
        close: () => settle('aborted'),
      },
    }
  }

  publish(key: string): void {
    if (!isOfferWakeKey(key)) return
    const waiters = this.byKey.get(key)
    if (!waiters) return
    for (const waiter of [...waiters]) waiter.settle('hint')
  }
}

/** Compatibility name retained for existing offer-wake callers and tests. Both names address the same bounded,
 * content-blind primitive; domain-separated digests keep offer and progress waiter namespaces independent. */
export class BoundedOfferWakeHub extends BoundedSignalingWakeHub {}

function positiveInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1) throw new RangeError(`${name} must be a positive integer`)
  return value
}
