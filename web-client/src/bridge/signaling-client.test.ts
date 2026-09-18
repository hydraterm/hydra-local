import { describe, it, expect } from 'vitest'
import {
  SIGNAL_PROGRESS_WAIT_MS,
  SignalingClient,
  SignalProgressUnsupported,
  SignalSessionDead,
} from './signaling-client'
import { RemoteEntitlementRequired } from './remote-entitlement'

function mockFetch(routes: Record<string, { status: number; json: unknown }>) {
  const calls: { url: string; method: string; body?: string; signal?: AbortSignal | null }[] = []
  const fetchImpl = (async (url: string | URL | Request, init?: RequestInit) => {
    const u = String(url)
    calls.push({
      url: u,
      method: init?.method ?? 'GET',
      body: init?.body ? String(init.body) : undefined,
      signal: init?.signal,
    })
    const key = Object.keys(routes).find((k) => u.includes(k))
    const r = key ? routes[key]! : { status: 404, json: {} }
    return new Response(JSON.stringify(r.json), { status: r.status })
  }) as unknown as typeof fetch
  return { fetchImpl, calls }
}

const cfg = { baseUrl: 'https://api.example', authToken: 'dev:acct', deviceId: 'web_dev' }

describe('SignalingClient — S3a shapes (opaque blobs only)', () => {
  it('createSession posts source/target/offer and returns the sessionId', async () => {
    const { fetchImpl, calls } = mockFetch({ '/v1/signal/sessions': { status: 201, json: { sessionId: 'sig_9' } } })
    const sc = new SignalingClient(cfg, fetchImpl)
    const id = await sc.createSession('dev_desk', 'OPAQUE_OFFER')
    expect(id).toBe('sig_9')
    const body = JSON.parse(calls[0]!.body!)
    expect(body).toEqual({ sourceDeviceId: 'web_dev', targetDeviceId: 'dev_desk', offer: 'OPAQUE_OFFER' })
    expect(calls[0]!.url).toContain('/v1/signal/sessions')
  })

  it('maps only the exact entitlement 402 to the stable typed refusal', async () => {
    const required = new SignalingClient(cfg, mockFetch({
      '/v1/signal/sessions': { status: 402, json: { error: 'remote_entitlement_required' } },
    }).fetchImpl)
    await expect(required.createSession('dev_desk', 'OPAQUE_OFFER')).rejects.toBeInstanceOf(
      RemoteEntitlementRequired,
    )

    const unavailable = new SignalingClient(cfg, mockFetch({
      '/v1/signal/sessions': { status: 503, json: { error: 'remote_entitlement_unavailable' } },
    }).fetchImpl)
    await expect(unavailable.createSession('dev_desk', 'OPAQUE_OFFER')).rejects.toThrow(
      'signal create failed: 503 remote_entitlement_unavailable',
    )
  })

  it('fetchAnswer returns the answer when answered, null otherwise', async () => {
    const sc1 = new SignalingClient(cfg, mockFetch({ '/v1/signal/sessions/sig_9': { status: 200, json: { session: { answer: 'OPAQUE_ANSWER' } } } }).fetchImpl)
    expect(await sc1.fetchAnswer('sig_9')).toBe('OPAQUE_ANSWER')
    const sc2 = new SignalingClient(cfg, mockFetch({ '/v1/signal/sessions/sig_9': { status: 200, json: { session: {} } } }).fetchImpl)
    expect(await sc2.fetchAnswer('sig_9')).toBe(null)
  })

  it('fetchAnswer/fetchIce THROW SignalSessionDead on 409/404 (so the poller stops hammering a dead session)', async () => {
    for (const status of [409, 404]) {
      const scA = new SignalingClient(cfg, mockFetch({ '/v1/signal/sessions/sig_9': { status, json: { error: 'expired' } } }).fetchImpl)
      await expect(scA.fetchAnswer('sig_9')).rejects.toBeInstanceOf(SignalSessionDead)
      const scI = new SignalingClient(cfg, mockFetch({ '/ice': { status, json: { error: 'expired' } } }).fetchImpl)
      await expect(scI.fetchIce('sig_9', 0)).rejects.toBeInstanceOf(SignalSessionDead)
    }
    // a transient non-200 (e.g. 500) still returns empty (keep polling), NOT dead.
    const scT = new SignalingClient(cfg, mockFetch({ '/v1/signal/sessions/sig_9': { status: 500, json: {} } }).fetchImpl)
    expect(await scT.fetchAnswer('sig_9')).toBe(null)
  })

  it('fetchIce returns peer candidates + advances the cursor', async () => {
    const sc = new SignalingClient(cfg, mockFetch({ '/ice': { status: 200, json: { candidates: [{ candidate: 'c1', seq: 1 }], nextSince: 1 } } }).fetchImpl)
    const out = await sc.fetchIce('sig_9', 0)
    expect(out).toEqual({ candidates: [{ candidate: 'c1', seq: 1 }], nextSince: 1 })
  })

  it('fetchProgress prefers one bounded progress-wait request and preserves its untrusted body', async () => {
    const { fetchImpl, calls } = mockFetch({
      '/progress': {
        status: 200,
        json: { status: 'pending', expiresAtMs: 9000, candidates: [], nextSince: 3 },
      },
    })
    const abort = new AbortController()
    const out = await new SignalingClient(cfg, fetchImpl).fetchProgress('sig_9', 3, true, abort.signal)
    expect(out).toEqual({ status: 'pending', expiresAtMs: 9000, candidates: [], nextSince: 3 })
    expect(calls).toHaveLength(1)
    expect(calls[0]!.url).toContain(
      `/v1/signal/sessions/sig_9/progress-wait?deviceId=web_dev&since=3&answerSeen=1&waitMs=${SIGNAL_PROGRESS_WAIT_MS}`,
    )
    expect(calls[0]!.signal).toBe(abort.signal)
  })

  it('falls back once from an exact old-cloud capability miss to the established progress route', async () => {
    const calls: string[] = []
    const fetchImpl = (async (input: string | URL | Request) => {
      const url = String(input)
      calls.push(url)
      if (url.includes('/progress-wait?')) {
        return new Response(JSON.stringify({ error: 'not_found' }), { status: 404 })
      }
      return new Response(JSON.stringify({
        status: 'pending', expiresAtMs: 9000, candidates: [], nextSince: 0,
      }), { status: 200 })
    }) as unknown as typeof fetch
    const client = new SignalingClient(cfg, fetchImpl)

    await expect(client.fetchProgress('sig_9', 0, false)).resolves.toMatchObject({ status: 'pending' })
    await expect(client.fetchProgress('sig_9', 0, false)).resolves.toMatchObject({ status: 'pending' })
    expect(calls).toHaveLength(3)
    expect(calls[0]).toContain('/progress-wait?')
    expect(calls[1]).toContain('/progress?')
    expect(calls[2]).toContain('/progress?')
  })

  it('never converts network/auth/server or malformed route errors into compatibility fallback', async () => {
    for (const response of [
      { status: 500, json: { error: 'internal_error' } },
      { status: 401, json: { error: 'not_found' } },
      { status: 404, json: { error: 'not_found', extra: true } },
    ]) {
      const { fetchImpl, calls } = mockFetch({ '/progress-wait': response })
      const client = new SignalingClient(cfg, fetchImpl)
      await expect(client.fetchProgress('sig_9', 0, false)).rejects.toThrow(
        `signal progress fetch failed: ${response.status}`,
      )
      expect(calls).toHaveLength(1)
      expect(calls[0]!.url).toContain('/progress-wait?')
    }
  })

  it('distinguishes exact old-cloud unsupported from typed dead and malformed 404 responses', async () => {
    const unsupported = new SignalingClient(cfg, mockFetch({
      '/progress': { status: 404, json: { error: 'not_found' } },
    }).fetchImpl)
    await expect(unsupported.fetchProgress('sig_9', 0, false)).rejects.toBeInstanceOf(SignalProgressUnsupported)

    for (const route of [
      { status: 404, json: { error: 'session_not_found' } },
      { status: 409, json: { error: 'expired' } },
      { status: 409, json: { error: 'cancelled' } },
    ]) {
      const dead = new SignalingClient(cfg, mockFetch({ '/progress': route }).fetchImpl)
      await expect(dead.fetchProgress('sig_9', 0, false)).rejects.toBeInstanceOf(SignalSessionDead)
    }

    for (const json of [{}, { error: 'not_found', extra: true }, { error: 'session_not_found', extra: true }]) {
      const malformed = new SignalingClient(cfg, mockFetch({
        '/progress': { status: 404, json },
      }).fetchImpl)
      await expect(malformed.fetchProgress('sig_9', 0, false)).rejects.toThrow('signal progress fetch failed: 404')
    }
  })

  it('does not normalize a malformed successful ICE body into a valid empty cursor advance', async () => {
    const sc = new SignalingClient(
      cfg,
      mockFetch({ '/ice': { status: 200, json: { unexpected: true } } }).fetchImpl,
    )
    expect(await sc.fetchIce('sig_9', 7)).toEqual({ unexpected: true })
  })

  it('postIce sends the candidate as an opaque blob', async () => {
    const { fetchImpl, calls } = mockFetch({ '/ice': { status: 200, json: { ok: true } } })
    await new SignalingClient(cfg, fetchImpl).postIce('sig_9', 'OPAQUE_CANDIDATE')
    expect(JSON.parse(calls[0]!.body!)).toEqual({ deviceId: 'web_dev', candidate: 'OPAQUE_CANDIDATE' })
  })

  it('postIce forwards attempt cancellation to fetch', async () => {
    const { fetchImpl, calls } = mockFetch({ '/ice': { status: 200, json: { ok: true } } })
    const abort = new AbortController()
    await new SignalingClient(cfg, fetchImpl).postIce('sig_9', 'OPAQUE_CANDIDATE', abort.signal)
    expect(calls[0]!.signal).toBe(abort.signal)
  })

  it('forwards the attempt signal through every setup read and write', async () => {
    const { fetchImpl, calls } = mockFetch({
      '/ice': { status: 200, json: { candidates: [], nextSince: 0 } },
      '/cancel': { status: 200, json: { ok: true } },
      '/v1/signal/sessions/sig_9': { status: 200, json: { session: {} } },
      '/v1/signal/sessions': { status: 201, json: { sessionId: 'sig_9' } },
    })
    const abort = new AbortController()
    const sc = new SignalingClient(cfg, fetchImpl)

    await sc.createSession('dev_desk', 'OPAQUE_OFFER', abort.signal)
    await sc.fetchAnswer('sig_9', abort.signal)
    await sc.fetchIce('sig_9', 0, abort.signal)
    await sc.cancel('sig_9', abort.signal)

    expect(calls).toHaveLength(4)
    expect(calls.every((call) => call.signal === abort.signal)).toBe(true)
  })

  it('postIce exposes dead sessions and transient HTTP failures to the owner retry policy', async () => {
    for (const status of [404, 409]) {
      const dead = new SignalingClient(
        cfg,
        mockFetch({ '/ice': { status, json: { error: 'expired' } } }).fetchImpl,
      )
      await expect(dead.postIce('sig_9', 'OPAQUE_CANDIDATE')).rejects.toBeInstanceOf(SignalSessionDead)
    }
    const transient = new SignalingClient(
      cfg,
      mockFetch({ '/ice': { status: 503, json: { error: 'unavailable' } } }).fetchImpl,
    )
    await expect(transient.postIce('sig_9', 'OPAQUE_CANDIDATE')).rejects.toThrow('signal ICE post failed: 503')
  })
})
