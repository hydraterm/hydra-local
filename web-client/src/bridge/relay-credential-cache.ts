import type { RelayCredentials } from './relay-fallback.js'
import { REMOTE_CONNECT_INACTIVITY_MS } from './connect-deadline.js'

export const RELAY_CREDENTIAL_REFRESH_MARGIN_MS = 30_000
export const RELAY_CREDENTIAL_MAX_TTL_MS = 120_000
/** A cache-owned load must never outlive the browser connection inactivity budget. */
export const RELAY_CREDENTIAL_LOAD_TIMEOUT_MS = REMOTE_CONNECT_INACTIVITY_MS

const MAX_TURN_URLS = 8
const MAX_STUN_URLS = 8
const MAX_ICE_URI_BYTES = 2_048
const MAX_USERNAME_BYTES = 512
const MAX_CREDENTIAL_BYTES = 2_048

export interface RelayCredentialCacheKey {
  /** Public authority only; never an account credential. */
  authority: string
  accountId: string
  deviceId: string
  /** Entry-layer auth generation. Incremented synchronously on account/credential reset. */
  credentialEpoch: number
}

type RelayCredentialLoader = (signal: AbortSignal) => Promise<unknown | null>

interface InFlightLoad {
  controller: AbortController
  promise: Promise<RelayCredentials | null>
  timeout: ReturnType<typeof setTimeout> | null
}

interface CacheEntry {
  value?: {
    credentials: RelayCredentials
    refreshAtMonotonicMs: number
    loadStartedAtWallMs: number
    usableWindowMs: number
  }
  inFlight?: InFlightLoad
}

interface ParsedRelayCredentials {
  credentials: RelayCredentials
  /** A recognized but invalid/missing ttl is deliberately non-cacheable, not a credential refusal. */
  cacheTtlMs: number | null
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).byteLength
}

function boundedNonemptyString(value: unknown, maxBytes: number): value is string {
  return typeof value === 'string' && value.length > 0 && value.trim() === value &&
    utf8Length(value) <= maxBytes
}

function approvedIceUri(value: unknown, kind: 'turn' | 'stun'): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value ||
      utf8Length(value) > MAX_ICE_URI_BYTES || !/^[\x21-\x7e]+$/.test(value)) return false

  const separator = value.indexOf(':')
  if (separator <= 0) return false
  const scheme = value.slice(0, separator)
  if (kind === 'turn' ? scheme !== 'turn' && scheme !== 'turns' : scheme !== 'stun' && scheme !== 'stuns') {
    return false
  }
  const remainder = value.slice(separator + 1)
  if (!remainder || remainder.startsWith('//') || remainder.includes('#') || remainder.includes('@')) return false
  const queryAt = remainder.indexOf('?')
  const target = queryAt === -1 ? remainder : remainder.slice(0, queryAt)
  const query = queryAt === -1 ? '' : remainder.slice(queryAt + 1)
  if (!target || target.includes('/') || target.includes('?')) return false
  if (kind === 'stun') return query === ''
  return query === '' || query === 'transport=udp' || query === 'transport=tcp'
}

function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[]): boolean {
  const allowed = new Set([...required, ...optional])
  return required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
    Object.keys(value).every((key) => allowed.has(key))
}

function parseRelayCredentialResponse(value: unknown): ParsedRelayCredentials | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  const raw = value as Record<string, unknown>
  if (!exactKeys(raw, ['urls', 'username', 'credential', 'expiresAtMs'], ['stunUrls', 'ttlMs'])) return null
  if (!Array.isArray(raw.urls) || raw.urls.length === 0 || raw.urls.length > MAX_TURN_URLS ||
      !raw.urls.every((url) => approvedIceUri(url, 'turn'))) return null
  if (!boundedNonemptyString(raw.username, MAX_USERNAME_BYTES) ||
      !boundedNonemptyString(raw.credential, MAX_CREDENTIAL_BYTES) ||
      !Number.isSafeInteger(raw.expiresAtMs) || Number(raw.expiresAtMs) < 0) return null
  if (raw.stunUrls !== undefined && (!Array.isArray(raw.stunUrls) || raw.stunUrls.length > MAX_STUN_URLS ||
      !raw.stunUrls.every((url) => approvedIceUri(url, 'stun')))) return null

  return {
    credentials: {
      urls: [...raw.urls] as string[],
      username: raw.username,
      credential: raw.credential,
      expiresAtMs: raw.expiresAtMs as number,
      ...(raw.stunUrls === undefined ? {} : { stunUrls: [...raw.stunUrls] as string[] }),
    },
    cacheTtlMs: Number.isSafeInteger(raw.ttlMs) && Number(raw.ttlMs) >= 0
      ? raw.ttlMs as number
      : null,
  }
}

/** Strictly validate credentials before WebRTC use. Negotiated ttl metadata is stripped from the result. */
export function parseRelayCredentials(value: unknown): RelayCredentials | null {
  return parseRelayCredentialResponse(value)?.credentials ?? null
}

function cloneCredentials(value: RelayCredentials): RelayCredentials {
  return {
    urls: [...value.urls],
    username: value.username,
    credential: value.credential,
    expiresAtMs: value.expiresAtMs,
    ...(value.stunUrls === undefined ? {} : { stunUrls: [...value.stunUrls] }),
  }
}

function abortError(): DOMException {
  return new DOMException('Connection attempt was cancelled.', 'AbortError')
}

function loadTimeoutError(): DOMException {
  return new DOMException('Relay credential load timed out.', 'TimeoutError')
}

function signalAbortError(signal: AbortSignal): DOMException {
  return signal.reason instanceof DOMException && signal.reason.name === 'TimeoutError'
    ? signal.reason
    : abortError()
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw abortError()
}

function waitForSignal<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(signalAbortError(signal))
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => {
      cleanup()
      reject(signalAbortError(signal))
    }
    const cleanup = () => signal.removeEventListener('abort', onAbort)
    signal.addEventListener('abort', onAbort, { once: true })
    promise.then(
      (value) => { cleanup(); resolve(value) },
      (error) => { cleanup(); reject(error) },
    )
  })
}

function cacheKey(key: RelayCredentialCacheKey): string {
  return JSON.stringify([key.authority, key.accountId, key.deviceId, key.credentialEpoch])
}

/**
 * Small process-local LRU for TURN credentials only. It never persists data and never stores Hydra tokens,
 * signaling payloads, account credentials, SDP, ICE candidates, or terminal content.
 */
export class RelayCredentialCache {
  private readonly entries = new Map<string, CacheEntry>()
  private generation = 0

  constructor(
    private readonly capacity = 8,
    private readonly monotonicNowMs: () => number = () => performance.now(),
    private readonly wallNowMs: () => number = () => Date.now(),
  ) {
    if (!Number.isSafeInteger(capacity) || capacity < 1 || capacity > 8) {
      throw new Error('relay credential cache capacity must be between 1 and 8')
    }
  }

  /** Account/credential invalidation is synchronous and prevents every stale completion from publishing. */
  reset(): void {
    this.generation++
    for (const entry of this.entries.values()) {
      if (entry.inFlight) abortInFlight(entry.inFlight)
    }
    this.entries.clear()
  }

  async get(
    key: RelayCredentialCacheKey,
    loader: RelayCredentialLoader,
    callerSignal?: AbortSignal,
  ): Promise<RelayCredentials | null> {
    throwIfAborted(callerSignal)
    const id = cacheKey(key)
    let entry = this.entries.get(id)
    if (entry) this.touch(id, entry)

    const now = this.monotonicNowMs()
    if (entry?.value && entry.value.refreshAtMonotonicMs > now &&
        wallWindowOpen(entry.value.loadStartedAtWallMs, this.wallNowMs(), entry.value.usableWindowMs)) {
      return cloneCredentials(entry.value.credentials)
    }
    if (entry?.value) delete entry.value

    if (!entry) {
      this.evictForInsert()
      entry = {}
      this.entries.set(id, entry)
    }

    if (!entry.inFlight) this.startLoad(id, entry, loader)
    const inFlight = entry.inFlight
    if (!inFlight) throw new Error('relay credential load was not installed')
    const shared = inFlight.promise.then((value) => value && cloneCredentials(value))
    return callerSignal ? waitForSignal(shared, callerSignal) : shared
  }

  private startLoad(id: string, entry: CacheEntry, loader: RelayCredentialLoader): void {
    const controller = new AbortController()
    const generation = this.generation
    // Anchor at load start, not response arrival, so network time consumes the credential's usable cache window.
    const loadStartedAtMonotonicMs = this.monotonicNowMs()
    const loadStartedAtWallMs = this.wallNowMs()
    const flight = {} as InFlightLoad
    flight.controller = controller
    flight.timeout = null
    flight.promise = (async () => {
      try {
        const raw = await waitForSignal(Promise.resolve().then(() => loader(controller.signal)), controller.signal)
        const parsed = parseRelayCredentialResponse(raw)
        const current = this.entries.get(id)
        if (!parsed || controller.signal.aborted || generation !== this.generation || current !== entry ||
            current.inFlight !== flight) {
          return null
        }
        const cacheWindow = cacheRefreshWindow(loadStartedAtMonotonicMs, parsed.cacheTtlMs)
        if (cacheWindow !== null && cacheWindow.refreshAtMonotonicMs > this.monotonicNowMs() &&
            wallWindowOpen(loadStartedAtWallMs, this.wallNowMs(), cacheWindow.usableWindowMs)) {
          current.value = {
            credentials: cloneCredentials(parsed.credentials),
            refreshAtMonotonicMs: cacheWindow.refreshAtMonotonicMs,
            loadStartedAtWallMs,
            usableWindowMs: cacheWindow.usableWindowMs,
          }
        }
        this.touch(id, current)
        // Legacy, short, overlong, or late credentials remain usable for this load's callers, but never cache.
        return parsed.credentials
      } finally {
        clearLoadTimeout(flight)
        const current = this.entries.get(id)
        if (generation === this.generation && current === entry && current.inFlight === flight) {
          delete current.inFlight
          if (!current.value) this.entries.delete(id)
        }
      }
    })()
    const timeout = setTimeout(() => {
      if (flight.timeout !== timeout) return
      flight.timeout = null
      controller.abort(loadTimeoutError())
    }, RELAY_CREDENTIAL_LOAD_TIMEOUT_MS)
    flight.timeout = timeout
    entry.inFlight = flight
  }

  private touch(id: string, entry: CacheEntry): void {
    this.entries.delete(id)
    this.entries.set(id, entry)
  }

  private evictForInsert(): void {
    while (this.entries.size >= this.capacity) {
      const oldest = this.entries.entries().next().value as [string, CacheEntry] | undefined
      if (!oldest) return
      if (oldest[1].inFlight) abortInFlight(oldest[1].inFlight)
      this.entries.delete(oldest[0])
    }
  }
}

function clearLoadTimeout(flight: InFlightLoad): void {
  if (flight.timeout !== null) clearTimeout(flight.timeout)
  flight.timeout = null
}

function abortInFlight(flight: InFlightLoad): void {
  clearLoadTimeout(flight)
  flight.controller.abort()
}

function cacheRefreshWindow(
  loadStartedAtMonotonicMs: number,
  ttlMs: number | null,
): { refreshAtMonotonicMs: number; usableWindowMs: number } | null {
  if (ttlMs === null || ttlMs <= RELAY_CREDENTIAL_REFRESH_MARGIN_MS || ttlMs > RELAY_CREDENTIAL_MAX_TTL_MS) {
    return null
  }
  const usableWindowMs = ttlMs - RELAY_CREDENTIAL_REFRESH_MARGIN_MS
  const refreshAtMonotonicMs = loadStartedAtMonotonicMs + usableWindowMs
  return Number.isFinite(refreshAtMonotonicMs) ? { refreshAtMonotonicMs, usableWindowMs } : null
}

function wallWindowOpen(loadStartedAtWallMs: number, wallNowMs: number, usableWindowMs: number): boolean {
  if (!Number.isFinite(loadStartedAtWallMs) || !Number.isFinite(wallNowMs)) return false
  const elapsedMs = wallNowMs - loadStartedAtWallMs
  // Fail closed on either wall-clock discontinuity direction. In particular, some monotonic clocks pause
  // across suspend, so a backward wall jump must not leave an expired credential looking fresh after wake.
  return elapsedMs >= 0 && elapsedMs < usableWindowMs
}
