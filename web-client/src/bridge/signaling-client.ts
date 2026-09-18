// S5 — S3a signaling client (browser side). Talks ONLY the documented S3a endpoints over HTTPS to the
// cloud, exchanging OPAQUE offer/answer/ICE blobs. NO terminal data ever goes here. Polling with backoff
// (no SSE/WebSocket): fast while connecting, slower when idle. Connection lifetime is owned by the shared
// progress deadline; `staleTimeoutMs` remains the standalone/test override for that inactivity budget.

import { SignalProgressUnsupported, SignalSessionDead, type SignalingPort } from './signaling-contract.js'
import { throwIfRemoteEntitlementRequired } from './remote-entitlement.js'

export * from './signaling-contract.js'

export interface SignalingConfig {
  /** Base URL of the cloud control plane (e.g. https://api.cambridgeslab.com). */
  baseUrl: string
  /** Bearer credential for the account session (S1 identity; dev stub `dev:<acct>`). */
  authToken: string
  /** This browser device's id (enrolled via S2). */
  deviceId: string
}

/** Kept below common proxy/ALB idle bounds. Empty responses are authoritative snapshots; PostgreSQL wake hints
 * normally finish this request as soon as the desktop commits an answer or peer ICE candidate. */
export const SIGNAL_PROGRESS_WAIT_MS = 6_000

/** A thin fetch-based S3a client. Injectable `fetchImpl` for tests. */
export class SignalingClient implements SignalingPort {
  private readonly fetchImpl: typeof fetch
  private progressWaitSupported = true
  constructor(
    private readonly cfg: SignalingConfig,
    // NOTE: the default MUST be bound to the global, or `this.fetchImpl(...)` throws
    // "Illegal invocation" in browsers (window.fetch loses its `this`). Tests pass their own.
    fetchImpl?: typeof fetch,
  ) {
    this.fetchImpl = fetchImpl ?? globalThis.fetch.bind(globalThis)
  }

  // COOKIE auth: when authToken is the marker 'cookie', send the httpOnly session cookie
  // (credentials:'include') and NO Authorization header. Otherwise (dev/tests) send the dev Bearer.
  private authInit(base: RequestInit): RequestInit {
    if (this.cfg.authToken === 'cookie') {
      return { ...base, credentials: 'include' }
    }
    return { ...base, headers: { ...(base.headers as Record<string, string>), authorization: `Bearer ${this.cfg.authToken}` } }
  }

  private async post(path: string, body: unknown, signal?: AbortSignal): Promise<{ status: number; json: any }> {
    const res = await this.fetchImpl(
      `${this.cfg.baseUrl}${path}`,
      this.authInit({
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        ...(signal ? { signal } : {}),
      }),
    )
    const json = await res.json().catch(() => ({}))
    return { status: res.status, json }
  }
  private async get(path: string, signal?: AbortSignal): Promise<{ status: number; json: any }> {
    const res = await this.fetchImpl(`${this.cfg.baseUrl}${path}`, this.authInit(signal ? { signal } : {}))
    const json = await res.json().catch(() => ({}))
    return { status: res.status, json }
  }

  /** Create a signaling session to `targetDeviceId` with our SDP offer. Returns the sessionId. */
  async createSession(targetDeviceId: string, offer: string, signal?: AbortSignal): Promise<string> {
    const { status, json } = await this.post('/v1/signal/sessions', {
      sourceDeviceId: this.cfg.deviceId,
      targetDeviceId,
      offer,
    }, signal)
    throwIfRemoteEntitlementRequired(status, json)
    if (status !== 201) throw new Error(`signal create failed: ${status} ${json?.error ?? ''}`)
    return json.sessionId as string
  }

  /** Poll the session for the agent's answer (status === 'answered'). Returns the answer SDP or null. */
  async fetchAnswer(sessionId: string, signal?: AbortSignal): Promise<string | null> {
    const { status, json } = await this.get(
      `/v1/signal/sessions/${encodeURIComponent(sessionId)}?deviceId=${encodeURIComponent(this.cfg.deviceId)}`,
      signal,
    )
    // 409 (expired/cancelled) or 404 (gone) = this signaling session is DEAD — throw so the poller stops hammering it
    // and reconnects with a FRESH session, instead of getting 409 forever (the stuck reconnect loop).
    if (status === 409 || status === 404) throw new SignalSessionDead(sessionId, status)
    if (status !== 200) return null // other non-200 = transient; keep polling
    return json.session?.answer ?? null
  }

  async postIce(sessionId: string, candidate: string, signal?: AbortSignal): Promise<void> {
    const { status } = await this.post(`/v1/signal/sessions/${encodeURIComponent(sessionId)}/ice`, {
      deviceId: this.cfg.deviceId,
      candidate,
    }, signal)
    if (status === 409 || status === 404) throw new SignalSessionDead(sessionId, status)
    if (status < 200 || status >= 300) throw new Error(`signal ICE post failed: ${status}`)
  }

  /** Fetch the peer's untrusted ICE response since `since`. A successful HTTP body stays `unknown`: the
   * attempt-owner boundary validates the complete candidates/cursor transaction before mutating its state. */
  async fetchIce(sessionId: string, since: number, signal?: AbortSignal): Promise<unknown> {
    const { status, json } = await this.get(
      `/v1/signal/sessions/${encodeURIComponent(sessionId)}/ice?deviceId=${encodeURIComponent(this.cfg.deviceId)}&since=${since}`,
      signal,
    )
    if (status === 409 || status === 404) throw new SignalSessionDead(sessionId, status) // dead session — stop polling
    if (status !== 200) return { candidates: [], nextSince: since }
    return json
  }

  /** Prefer the dedicated bounded long-poll route. A rolling old cloud's exact unknown-route body disables only
   * that capability and immediately retries the established `/progress` read; network/auth/server errors never
   * masquerade as capability misses. If even `/progress` is absent, the existing bridge fallback switches to the
   * two legacy answer/ICE readers. */
  async fetchProgress(
    sessionId: string,
    since: number,
    answerSeen: boolean,
    signal?: AbortSignal,
  ): Promise<unknown> {
    const query = `deviceId=${encodeURIComponent(this.cfg.deviceId)}&since=${since}&answerSeen=${answerSeen ? '1' : '0'}`
    if (this.progressWaitSupported) {
      const held = await this.get(
        `/v1/signal/sessions/${encodeURIComponent(sessionId)}/progress-wait?${query}&waitMs=${SIGNAL_PROGRESS_WAIT_MS}`,
        signal,
      )
      if (held.status === 404 && this.exactSignalError(held.json, 'not_found')) {
        this.progressWaitSupported = false
      } else {
        return this.decodeProgressResponse(sessionId, held.status, held.json, false)
      }
    }
    const { status, json } = await this.get(
      `/v1/signal/sessions/${encodeURIComponent(sessionId)}/progress?${query}`,
      signal,
    )
    return this.decodeProgressResponse(sessionId, status, json, true)
  }

  private exactSignalError(json: unknown, value: string): boolean {
    return !!json && typeof json === 'object' && !Array.isArray(json) &&
      Object.keys(json).length === 1 && (json as { error?: unknown }).error === value
  }

  private decodeProgressResponse(
    sessionId: string,
    status: number,
    json: unknown,
    allowUnsupported: boolean,
  ): unknown {
    const exactError = (value: string): boolean =>
      this.exactSignalError(json, value)
    if (allowUnsupported && status === 404 && exactError('not_found')) throw new SignalProgressUnsupported()
    if (
      (status === 404 && exactError('session_not_found')) ||
      (status === 409 && (exactError('expired') || exactError('cancelled')))
    ) throw new SignalSessionDead(sessionId, status)
    if (status !== 200) throw new Error(`signal progress fetch failed: ${status}`)
    return json
  }

  async cancel(sessionId: string, signal?: AbortSignal): Promise<void> {
    await this.post(`/v1/signal/sessions/${encodeURIComponent(sessionId)}/cancel`, {
      deviceId: this.cfg.deviceId,
    }, signal).catch(() => {})
  }
}
