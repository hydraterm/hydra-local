// Client for the durable REMOTE-LAYOUT cloud endpoints (remote-layout API contract): the browser's per-window
// pane arrangement for ONE desktop connection, persisted server-side keyed by (account, device) so it restores from any
// browser (cross-browser) and survives reconnects. Replaces the per-browser localStorage last-layout-store.
//
// - GET  /v1/remote-layout?deviceId= → the saved layout JSON (or null)
// - PUT  /v1/remote-layout { deviceId, layout } → upsert (DEBOUNCED ~1s on the client so fast pane moves coalesce)
//
// Content-blind: `layout` carries only the exact versioned layout DTO (bounded ids, split topology, ratios and
// stash flags). UI names/titles/paths are projected out before encoding. Auth reuses the signaling authInit pattern.

import type { RemoteLayoutPort } from './remote-layout-contract.js'

export * from './remote-layout-contract.js'

export interface RemoteLayoutCloudConfig {
  /** Base URL of the cloud control plane (e.g. https://api.hydraterms.com). */
  baseUrl: string
  /** Bearer credential for the account session ('cookie' in prod → httpOnly cookie; dev stub `dev:<acct>`). A function
   * lets the caller supply the CURRENT credential per call (it can change across reconnects/sign-in). */
  authToken: string | (() => string)
}

const DEBOUNCE_MS = 1000

export class RemoteLayoutCloud implements RemoteLayoutPort {
  private readonly fetchImpl: typeof fetch
  private pendingTimer: ReturnType<typeof setTimeout> | null = null
  private pending: { deviceId: string; layout: string } | null = null

  constructor(
    private readonly cfg: RemoteLayoutCloudConfig,
    fetchImpl?: typeof fetch,
    private readonly debounceMs = DEBOUNCE_MS,
  ) {
    // Bind to the global or `this.fetchImpl(...)` throws "Illegal invocation" in browsers. Tests pass their own.
    this.fetchImpl = fetchImpl ?? globalThis.fetch.bind(globalThis)
  }

  private authInit(base: RequestInit): RequestInit {
    const token = typeof this.cfg.authToken === 'function' ? this.cfg.authToken() : this.cfg.authToken
    if (token === 'cookie') return { ...base, credentials: 'include' }
    return { ...base, headers: { ...(base.headers as Record<string, string>), authorization: `Bearer ${token}` } }
  }

  /** Fetch this device's saved layout JSON, or null (no row / any error → null, never throws — a restore must never
   * block the grid on the network). */
  async fetchLayout(deviceId: string): Promise<string | null> {
    try {
      const res = await this.fetchImpl(
        `${this.cfg.baseUrl}/v1/remote-layout?deviceId=${encodeURIComponent(deviceId)}`,
        this.authInit({}),
      )
      if (!res.ok) return null
      const json = await res.json().catch(() => ({}))
      return typeof json?.layout === 'string' ? json.layout : null
    } catch {
      return null
    }
  }

  /** Queue a layout PUT, coalesced: only the LAST layout within the debounce window is sent. */
  putLayout(deviceId: string, layout: string): void {
    this.pending = { deviceId, layout }
    if (this.pendingTimer) return // a flush is already scheduled; it will pick up the latest `pending`
    this.pendingTimer = setTimeout(() => { void this.flush() }, this.debounceMs)
  }

  /** Send the pending layout now (used by the debounce timer; also callable on disconnect to not lose the last edit). */
  async flush(): Promise<void> {
    if (this.pendingTimer) { clearTimeout(this.pendingTimer); this.pendingTimer = null }
    const p = this.pending
    if (!p) return
    this.pending = null
    try {
      await this.fetchImpl(
        `${this.cfg.baseUrl}/v1/remote-layout`,
        this.authInit({ method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(p) }),
      )
    } catch {
      // best-effort: a failed PUT just means this arrangement isn't durable yet; the next mutation re-sends it.
    }
  }

  /** Cancel any pending write (e.g. on teardown). */
  dispose(): void {
    if (this.pendingTimer) { clearTimeout(this.pendingTimer); this.pendingTimer = null }
    this.pending = null
  }
}
