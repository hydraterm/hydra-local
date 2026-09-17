import { REMOTE_CONNECT_INACTIVITY_MS } from './connect-deadline.js'

/** The signaling session is no longer usable. Pollers retire it rather than retrying the same owner. */
export class SignalSessionDead extends Error {
  constructor(public readonly sessionId: string, public readonly status: number) {
    super(`signaling session ${sessionId} is dead (${status})`)
    this.name = 'SignalSessionDead'
  }
}

/** A confirmed capability miss, not an authorization, network or dead-session failure. */
export class SignalProgressUnsupported extends Error {
  constructor() {
    super('combined signaling progress is unsupported')
    this.name = 'SignalProgressUnsupported'
  }
}

export interface PollBackoff {
  fastMs: number // while actively connecting (awaiting answer/ICE)
  idleMs: number // once connected/idle
  staleTimeoutMs: number // give up if no progress by here
}

export const DEFAULT_BACKOFF: PollBackoff = {
  fastMs: 400,
  idleMs: 2000,
  staleTimeoutMs: REMOTE_CONNECT_INACTIVITY_MS,
}

/** Control-plane exchange for one peer connection. Implementations own endpoint and identity-provider
 * composition; this port carries only opaque offer/answer/ICE signaling, never terminal content.
 * Attempt ownership, proof verification and response validation remain in the consuming transport. */
export interface SignalingPort {
  createSession(targetDeviceId: string, offer: string, signal?: AbortSignal): Promise<string>
  fetchAnswer(sessionId: string, signal?: AbortSignal): Promise<string | null>
  postIce(sessionId: string, candidate: string, signal?: AbortSignal): Promise<void>
  /** Untrusted candidates/cursor snapshot; the transport validates the whole transaction before use. */
  fetchIce(sessionId: string, since: number, signal?: AbortSignal): Promise<unknown>
  /** Optional combined snapshot. Omission uses the existing separate readers; a present implementation
   * may signal only a confirmed capability miss with SignalProgressUnsupported. Other failures do not
   * authorize compatibility fallback. Successful response bodies remain untrusted. */
  fetchProgress?(
    sessionId: string,
    since: number,
    answerSeen: boolean,
    signal?: AbortSignal,
  ): Promise<unknown>
  cancel(sessionId: string, signal?: AbortSignal): Promise<void>
}
