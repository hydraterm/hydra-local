import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  RELAY_CREDENTIAL_LOAD_TIMEOUT_MS,
  RELAY_CREDENTIAL_MAX_TTL_MS,
  RELAY_CREDENTIAL_REFRESH_MARGIN_MS,
  RelayCredentialCache,
  parseRelayCredentials,
  type RelayCredentialCacheKey,
} from './relay-credential-cache'
import { REMOTE_CONNECT_INACTIVITY_MS } from './connect-deadline'

const KEY: RelayCredentialCacheKey = {
  authority: 'https://api.example.test',
  accountId: 'acct_a',
  deviceId: 'dev_browser_a',
  credentialEpoch: 1,
}

function credentials(expiresAtMs: number) {
  return {
    urls: ['turn:relay.example.test:3478?transport=udp', 'turns:relay.example.test:5349?transport=tcp'],
    username: 'synthetic-user',
    credential: 'synthetic-turn-secret',
    expiresAtMs,
    stunUrls: ['stun:relay.example.test:3478'],
  }
}

function versionedCredentials(expiresAtMs: number, ttlMs: unknown = RELAY_CREDENTIAL_MAX_TTL_MS) {
  return { ...credentials(expiresAtMs), ttlMs }
}

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (error: unknown) => void
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}

describe('RelayCredentialCache', () => {
  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('keeps its owner timeout within the browser connection inactivity budget', () => {
    expect(RELAY_CREDENTIAL_LOAD_TIMEOUT_MS).toBeLessThanOrEqual(REMOTE_CONNECT_INACTIVITY_MS)
  })

  it('serves a fresh hit without another load and returns defensive copies', async () => {
    const monotonicNow = 10_000
    const cache = new RelayCredentialCache(8, () => monotonicNow)
    let loads = 0
    const loader = async () => { loads++; return versionedCredentials(1) }

    const first = await cache.get(KEY, loader)
    first!.urls.push('turn:mutated.invalid')
    const second = await cache.get(KEY, loader)

    expect(loads).toBe(1)
    expect(second).toEqual(credentials(1))
  })

  it('refreshes at the relative-ttl safety margin without consulting absolute server expiry', async () => {
    let monotonicNow = 50_000
    const cache = new RelayCredentialCache(8, () => monotonicNow)
    let loads = 0
    const loader = async () => versionedCredentials(++loads === 1 ? 1 : Number.MAX_SAFE_INTEGER)

    const first = await cache.get(KEY, loader)
    monotonicNow += RELAY_CREDENTIAL_MAX_TTL_MS - RELAY_CREDENTIAL_REFRESH_MARGIN_MS - 1
    const stillCached = await cache.get(KEY, loader)
    monotonicNow += 1
    const refreshed = await cache.get(KEY, loader)

    expect(first?.expiresAtMs).toBe(1)
    expect(stillCached?.expiresAtMs).toBe(1)
    expect(refreshed?.expiresAtMs).toBe(Number.MAX_SAFE_INTEGER)
    expect(loads).toBe(2)
  })

  it('fails closed after a backward wall jump when monotonic time barely advanced', async () => {
    let monotonicNow = 10_000
    let wallNow = 100_000
    const cache = new RelayCredentialCache(8, () => monotonicNow, () => wallNow)
    let loads = 0
    const loader = async () => { loads++; return versionedCredentials(loads) }

    await expect(cache.get(KEY, loader)).resolves.toEqual(credentials(1))
    monotonicNow += 1 // models a monotonic clock that barely advanced while the machine slept
    wallNow = 1_000
    await expect(cache.get(KEY, loader)).resolves.toEqual(credentials(2))
    expect(loads).toBe(2)
  })

  it('expires early after suspend-like forward wall elapsed even if the monotonic clock paused', async () => {
    let monotonicNow = 1_000
    let wallNow = 50_000
    const cache = new RelayCredentialCache(8, () => monotonicNow, () => wallNow)
    let loads = 0
    const loader = async () => { loads++; return versionedCredentials(loads) }

    await expect(cache.get(KEY, loader)).resolves.toEqual(credentials(1))
    monotonicNow += 1 // models a monotonic clock that barely advanced while the machine slept
    wallNow += RELAY_CREDENTIAL_MAX_TTL_MS - RELAY_CREDENTIAL_REFRESH_MARGIN_MS
    await expect(cache.get(KEY, loader)).resolves.toEqual(credentials(2))
    expect(loads).toBe(2)
  })

  it('deducts network latency by anchoring cache lifetime at load start', async () => {
    let monotonicNow = 1_000
    const pending = deferred<unknown>()
    const cache = new RelayCredentialCache(8, () => monotonicNow)
    let loads = 0
    const first = cache.get(KEY, () => { loads++; return pending.promise })
    await Promise.resolve()

    monotonicNow = 80_000
    pending.resolve(versionedCredentials(999_999))
    await expect(first).resolves.toEqual(credentials(999_999))

    // start(1_000) + ttl(120_000) - margin(30_000) = 91_000, not response-time + 90 seconds.
    monotonicNow = 90_999
    await expect(cache.get(KEY, async () => { loads++; return versionedCredentials(888_888) }))
      .resolves.toEqual(credentials(999_999))
    monotonicNow = 91_000
    await expect(cache.get(KEY, async () => { loads++; return versionedCredentials(888_888) }))
      .resolves.toEqual(credentials(888_888))
    expect(loads).toBe(2)
  })

  it('returns a valid response that arrives after its cache window once without caching it', async () => {
    let monotonicNow = 1_000
    let wallNow = 10_000
    const pending = deferred<unknown>()
    const cache = new RelayCredentialCache(8, () => monotonicNow, () => wallNow)
    let loads = 0
    const first = cache.get(KEY, () => { loads++; return pending.promise })
    await Promise.resolve()

    monotonicNow += RELAY_CREDENTIAL_MAX_TTL_MS - RELAY_CREDENTIAL_REFRESH_MARGIN_MS
    wallNow += RELAY_CREDENTIAL_MAX_TTL_MS - RELAY_CREDENTIAL_REFRESH_MARGIN_MS
    pending.resolve(versionedCredentials(1))
    await expect(first).resolves.toEqual(credentials(1))
    await expect(cache.get(KEY, async () => { loads++; return versionedCredentials(2) }))
      .resolves.toEqual(credentials(2))
    expect(loads).toBe(2)
  })

  it('uses a legacy cloud response once but never caches it', async () => {
    const cache = new RelayCredentialCache(8, () => 1_000)
    let loads = 0
    const loader = async () => { loads++; return credentials(1) }

    await expect(cache.get(KEY, loader)).resolves.toEqual(credentials(1))
    await expect(cache.get(KEY, loader)).resolves.toEqual(credentials(1))
    expect(loads).toBe(2)
  })

  it.each([
    ['at margin', RELAY_CREDENTIAL_REFRESH_MARGIN_MS],
    ['below margin', RELAY_CREDENTIAL_REFRESH_MARGIN_MS - 1],
    ['above approved maximum', RELAY_CREDENTIAL_MAX_TTL_MS + 1],
    ['fractional', 120_000.5],
    ['wrong type', '120000'],
  ])('uses a credential with %s ttl once but does not cache it', async (_name, ttlMs) => {
    const cache = new RelayCredentialCache(8, () => 1_000)
    let loads = 0
    const loader = async () => { loads++; return versionedCredentials(1, ttlMs) }

    await expect(cache.get(KEY, loader)).resolves.toEqual(credentials(1))
    await expect(cache.get(KEY, loader)).resolves.toEqual(credentials(1))
    expect(loads).toBe(2)
  })

  it('coalesces concurrent callers into one in-flight request', async () => {
    const pending = deferred<unknown>()
    const cache = new RelayCredentialCache(8, () => 1_000)
    let loads = 0
    const loader = () => { loads++; return pending.promise }

    const first = cache.get(KEY, loader)
    const second = cache.get(KEY, loader)
    await Promise.resolve()
    expect(loads).toBe(1)
    pending.resolve(versionedCredentials(100_000))

    await expect(Promise.all([first, second])).resolves.toEqual([
      credentials(100_000),
      credentials(100_000),
    ])
  })

  it('times out one hung shared load, aborts its fetch, and unblocks every waiter', async () => {
    vi.useFakeTimers()
    const pending = deferred<unknown>()
    const cache = new RelayCredentialCache(8, () => 1_000)
    let loads = 0
    let loaderSignal: AbortSignal | undefined
    const loader = (signal: AbortSignal) => {
      loads++
      loaderSignal = signal
      return pending.promise
    }

    const first = cache.get(KEY, loader)
    const second = cache.get(KEY, loader)
    const settled = Promise.allSettled([first, second])
    await Promise.resolve()

    expect(loads).toBe(1)
    await vi.advanceTimersByTimeAsync(RELAY_CREDENTIAL_LOAD_TIMEOUT_MS - 1)
    expect(loaderSignal?.aborted).toBe(false)
    await vi.advanceTimersByTimeAsync(1)

    const results = await settled
    expect(results.map((result) => result.status)).toEqual(['rejected', 'rejected'])
    for (const result of results) {
      expect(result.status === 'rejected' ? result.reason : null).toMatchObject({ name: 'TimeoutError' })
    }
    expect(loaderSignal?.aborted).toBe(true)
    expect(loaderSignal?.reason).toMatchObject({ name: 'TimeoutError' })
    expect(vi.getTimerCount()).toBe(0)
  })

  it('does not publish a late timed-out response and permits a fresh load', async () => {
    vi.useFakeTimers()
    const staleLoad = deferred<unknown>()
    const cache = new RelayCredentialCache(8, () => 1_000)
    let loads = 0
    const timedOut = cache.get(KEY, () => { loads++; return staleLoad.promise })
    const timeoutResult = timedOut.catch((error: unknown) => error)

    await vi.advanceTimersByTimeAsync(RELAY_CREDENTIAL_LOAD_TIMEOUT_MS)
    await expect(timeoutResult).resolves.toMatchObject({ name: 'TimeoutError' })

    await expect(cache.get(KEY, async () => { loads++; return versionedCredentials(200_000) }))
      .resolves.toEqual(credentials(200_000))
    staleLoad.resolve(versionedCredentials(100_000))
    await Promise.resolve()
    await Promise.resolve()

    await expect(cache.get(KEY, async () => { loads++; return versionedCredentials(300_000) }))
      .resolves.toEqual(credentials(200_000))
    expect(loads).toBe(2)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('shares one failed result with concurrent waiters without negative caching it', async () => {
    const pending = deferred<unknown>()
    const cache = new RelayCredentialCache(8, () => 1_000)
    let loads = 0
    const loader = () => { loads++; return pending.promise }

    const first = cache.get(KEY, loader)
    const second = cache.get(KEY, loader)
    pending.resolve(null)
    await expect(Promise.all([first, second])).resolves.toEqual([null, null])
    expect(loads).toBe(1)

    await expect(cache.get(KEY, async () => { loads++; return versionedCredentials(100_000) }))
      .resolves.toEqual(credentials(100_000))
    expect(loads).toBe(2)
  })

  it('aborts one waiter promptly without cancelling the shared load for another waiter', async () => {
    vi.useFakeTimers()
    const pending = deferred<unknown>()
    const cache = new RelayCredentialCache(8, () => 1_000)
    const firstOwner = new AbortController()
    const loaderSignal: AbortSignal[] = []
    const loader = (signal: AbortSignal) => { loaderSignal.push(signal); return pending.promise }

    const first = cache.get(KEY, loader, firstOwner.signal)
    const second = cache.get(KEY, loader)
    firstOwner.abort()

    await expect(first).rejects.toMatchObject({ name: 'AbortError' })
    expect(loaderSignal).toHaveLength(1)
    expect(loaderSignal[0]!.aborted).toBe(false)
    await vi.advanceTimersByTimeAsync(RELAY_CREDENTIAL_LOAD_TIMEOUT_MS - 1)
    expect(loaderSignal[0]!.aborted).toBe(false)
    pending.resolve(versionedCredentials(100_000))
    await expect(second).resolves.toEqual(credentials(100_000))
  })

  it('reset aborts in-flight work and a stale completion cannot repopulate a new authority or epoch', async () => {
    vi.useFakeTimers()
    const oldLoad = deferred<unknown>()
    const cache = new RelayCredentialCache(8, () => 1_000)
    let oldSignal: AbortSignal | undefined
    const oldResult = cache.get(KEY, (signal) => { oldSignal = signal; return oldLoad.promise })
    await Promise.resolve()

    cache.reset()
    expect(oldSignal?.aborted).toBe(true)
    expect(vi.getTimerCount()).toBe(0)
    await expect(oldResult).rejects.toMatchObject({ name: 'AbortError' })

    oldLoad.resolve(versionedCredentials(100_000))
    await Promise.resolve()
    let freshLoads = 0
    const nextKey = { ...KEY, authority: 'https://api.changed.example.test', credentialEpoch: 2 }
    await expect(cache.get(nextKey, async () => { freshLoads++; return versionedCredentials(200_000) }))
      .resolves.toEqual(credentials(200_000))
    await expect(cache.get(nextKey, async () => { freshLoads++; return versionedCredentials(300_000) }))
      .resolves.toEqual(credentials(200_000))
    expect(freshLoads).toBe(1)
  })

  it('evicts the least-recently-used bounded entry', async () => {
    const cache = new RelayCredentialCache(2, () => 1_000)
    const calls = new Map<string, number>()
    const load = (deviceId: string) => async () => {
      calls.set(deviceId, (calls.get(deviceId) ?? 0) + 1)
      return versionedCredentials(100_000)
    }
    const key = (deviceId: string) => ({ ...KEY, deviceId })

    await cache.get(key('a'), load('a'))
    await cache.get(key('b'), load('b'))
    await cache.get(key('a'), load('a')) // touch a, so b is oldest
    await cache.get(key('c'), load('c'))
    await cache.get(key('b'), load('b'))

    expect(Object.fromEntries(calls)).toEqual({ a: 1, b: 2, c: 1 })
  })

  it('does not cache null, failed, or malformed credential results', async () => {
    const cache = new RelayCredentialCache(8, () => 100_000)
    const invalid = [
      null,
      { ...versionedCredentials(120_000), expiresAtMs: Number.NaN },
      { ...versionedCredentials(120_000), urls: ['https://not-turn.example'] },
      { ...versionedCredentials(120_000), token: 'unknown-field' },
    ]
    let loads = 0
    for (const value of invalid) {
      await expect(cache.get(KEY, async () => { loads++; return value })).resolves.toBeNull()
    }
    await expect(cache.get(KEY, async () => { loads++; throw new Error('synthetic refusal') }))
      .rejects.toThrow('synthetic refusal')
    await expect(cache.get(KEY, async () => { loads++; return versionedCredentials(120_000) }))
      .resolves.toEqual(credentials(120_000))
    expect(loads).toBe(invalid.length + 2)
  })
})

describe('parseRelayCredentials', () => {
  it('accepts the legacy cloud shape', () => {
    expect(parseRelayCredentials(credentials(123_456))).toEqual(credentials(123_456))
  })

  it('accepts and strips only the negotiated ttl field', () => {
    expect(parseRelayCredentials(versionedCredentials(123_456))).toEqual(credentials(123_456))
    expect(parseRelayCredentials(versionedCredentials(123_456, 'invalid'))).toEqual(credentials(123_456))
  })

  it.each([
    ['null', null],
    ['array', []],
    ['unknown field', { ...credentials(123_456), token: 'must-not-enter-cache' }],
    ['missing expiry', (({ expiresAtMs: _, ...rest }) => rest)(credentials(123_456))],
    ['fractional expiry', { ...credentials(123_456), expiresAtMs: 123.5 }],
    ['unsafe expiry', { ...credentials(123_456), expiresAtMs: Number.MAX_SAFE_INTEGER + 1 }],
    ['empty urls', { ...credentials(123_456), urls: [] }],
    ['wrong turn scheme', { ...credentials(123_456), urls: ['stun:relay.example:3478'] }],
    ['embedded authority', { ...credentials(123_456), urls: ['turn:user@relay.example:3478'] }],
    ['bad transport query', { ...credentials(123_456), urls: ['turn:relay.example:3478?transport=sctp'] }],
    ['mixed url types', { ...credentials(123_456), urls: ['turn:relay.example:3478', 7] }],
    ['wrong stun scheme', { ...credentials(123_456), stunUrls: ['turn:relay.example:3478'] }],
    ['empty username', { ...credentials(123_456), username: '' }],
    ['oversized credential', { ...credentials(123_456), credential: 'x'.repeat(2_049) }],
  ])('rejects %s', (_name, value) => {
    expect(parseRelayCredentials(value)).toBeNull()
  })

  it('enforces bounded url lists', () => {
    expect(parseRelayCredentials({
      ...credentials(123_456),
      urls: Array.from({ length: 9 }, (_, index) => `turn:relay${index}.example:3478`),
    })).toBeNull()
    expect(parseRelayCredentials({
      ...credentials(123_456),
      stunUrls: Array.from({ length: 9 }, (_, index) => `stun:relay${index}.example:3478`),
    })).toBeNull()
  })
})
