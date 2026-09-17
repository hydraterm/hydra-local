/**
 * One connection attempt has one progress-aware lifetime. The inactivity bound protects users from a stage that
 * stopped making progress; the absolute bound prevents a peer (or authenticator) from extending setup forever.
 *
 * Progress is keyed, not pulse-based. A poll that returns the same state cannot keep an attempt alive, and a
 * state that cycles back to an already-observed value cannot buy a second inactivity window. Callers should use
 * content-blind stage names only (never ids, tokens, SDP, ICE, or terminal data).
 */

export type ConnectDeadlineExpiry = 'inactivity' | 'absolute'

export interface ConnectDeadlineScope {
  readonly signal: AbortSignal
  progress(stage: string): boolean
  pauseInactivity(reason: string): void
  resumeInactivity(reason: string): void
}

export interface ProgressDeadlineOptions {
  inactivityMs: number
  absoluteMs: number
  onExpire: (kind: ConnectDeadlineExpiry) => void
}

/** Shared browser-controller/WebRTC setup bounds. The bridge consumes the controller-owned scope in production,
 * so these are not two competing watchdogs. A standalone bridge creates the same scope for tests/embedders. */
export const REMOTE_CONNECT_INACTIVITY_MS = 20_000
export const REMOTE_CONNECT_ABSOLUTE_MS = 90_000

export class ProgressDeadline implements ConnectDeadlineScope {
  readonly signal: AbortSignal

  private readonly abortController = new AbortController()
  private readonly seenStages = new Set<string>()
  private readonly pausedReasons = new Set<string>()
  private readonly absoluteAt: number
  private inactivityAt: number
  private pauseStartedAt: number | null = null
  private timer: ReturnType<typeof setTimeout> | null = null
  private finished = false

  constructor(private readonly options: ProgressDeadlineOptions) {
    if (!Number.isFinite(options.inactivityMs) || options.inactivityMs <= 0) {
      throw new RangeError('connect inactivity deadline must be positive')
    }
    if (!Number.isFinite(options.absoluteMs) || options.absoluteMs < options.inactivityMs) {
      throw new RangeError('connect absolute deadline must cover the inactivity deadline')
    }
    const now = Date.now()
    this.inactivityAt = now + options.inactivityMs
    this.absoluteAt = now + options.absoluteMs
    this.signal = this.abortController.signal
    this.arm()
  }

  /** Reset the inactivity budget exactly once for a meaningful stage. */
  progress(stage: string): boolean {
    if (this.finished || !stage || this.seenStages.has(stage)) return false
    this.seenStages.add(stage)
    // During a pause, anchor new progress to the start of the frozen interval. resumeInactivity() then shifts
    // that anchor by the exact paused duration, yielding one fresh budget from resume without double-counting
    // the time between pause and progress.
    const now = Date.now()
    this.inactivityAt = (this.pauseStartedAt ?? now) + this.options.inactivityMs
    this.arm()
    return true
  }

  /** Freeze only the inactivity clock while a native user interaction is outstanding. Nested reasons are safe. */
  pauseInactivity(reason: string): void {
    if (this.finished || !reason || this.pausedReasons.has(reason)) return
    if (this.pausedReasons.size === 0) this.pauseStartedAt = Date.now()
    this.pausedReasons.add(reason)
    this.arm()
  }

  /** Resume with the exact inactivity budget that remained when the first pause began. */
  resumeInactivity(reason: string): void {
    if (this.finished || !this.pausedReasons.delete(reason)) return
    if (this.pausedReasons.size === 0 && this.pauseStartedAt !== null) {
      this.inactivityAt += Math.max(0, Date.now() - this.pauseStartedAt)
      this.pauseStartedAt = null
    }
    this.arm()
  }

  /** Successful completion disarms the scope without aborting work that belongs to the established transport. */
  complete(): void {
    this.finish(false)
  }

  /** Supersession/teardown aborts every request carrying this attempt's signal. */
  abort(): void {
    this.finish(true)
  }

  private finish(abort: boolean): void {
    if (this.finished) return
    this.finished = true
    this.clearTimer()
    if (abort) this.abortController.abort()
  }

  private clearTimer(): void {
    if (this.timer) clearTimeout(this.timer)
    this.timer = null
  }

  private arm(): void {
    if (this.finished) return
    this.clearTimer()
    const now = Date.now()
    const nextAt = this.pausedReasons.size > 0
      ? this.absoluteAt
      : Math.min(this.inactivityAt, this.absoluteAt)
    const timer = setTimeout(() => {
      if (this.timer !== timer || this.finished) return
      this.timer = null
      this.expireIfDue()
    }, Math.max(0, nextAt - now))
    this.timer = timer
  }

  private expireIfDue(): void {
    if (this.finished) return
    const now = Date.now()
    const kind: ConnectDeadlineExpiry | null = now >= this.absoluteAt
      ? 'absolute'
      : this.pausedReasons.size === 0 && now >= this.inactivityAt
        ? 'inactivity'
        : null
    if (!kind) {
      this.arm()
      return
    }
    this.finished = true
    this.clearTimer()
    this.abortController.abort()
    this.options.onExpire(kind)
  }
}
