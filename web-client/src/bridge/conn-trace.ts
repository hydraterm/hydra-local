// Connection tracer — structured, content-blind, correlated observability for the connect/sync lifecycle.
//
// WHY: connection stalls (stuck "Connecting…", session_list never arriving, revoke/enroll desync) were invisible —
// the browser only logged to the console, so a problem the user hit left no record to inspect. This gives every
// connect + sync action (auth, session_list, attach, stash/revive/remove/split, enroll/revoke) a structured trace
// event with timing. Browser trace IDs correlate local lifecycle events; wire request IDs remain opaque because some
// operations embed filesystem or session context in their internal identifiers.
//
// SHARED SCHEMA (must match the agent's TraceEvent in hydra-agent/src/conn_trace.rs — keep them in lockstep):
//   { traceId, ts, side, leg, stage, status, detail, elapsedMs? }
//     side   : 'browser' | 'agent' | 'cloud' | 'desktop'
//     leg    : the action/lifecycle group, e.g. 'connect' | 'session_list' | 'attach' | 'stash' | 'revive' | ...
//     stage  : a step within the leg, e.g. 'start' | 'auth_ok' | 'sent' | 'reply' | 'timeout' | 'phase:connecting'
//     status : 'ok' | 'pending' | 'warn' | 'error'
//     detail : short, NON-SENSITIVE string (states/counts/reasons) — NEVER raw identifiers, paths, terminal bytes,
//              keys, or tokens.
//
// CONTENT-BLIND by construction: callers pass only metadata. A ring buffer bounds memory; the whole buffer is
// copyable ("Copy debug log") so the user can paste it back for diagnosis.

import { diagnosticQueryFlag } from './diagnostic-flags.js'

export type TraceSide = 'browser' | 'agent' | 'cloud' | 'desktop'
export type TraceStatus = 'ok' | 'pending' | 'warn' | 'error'

export interface TraceEvent {
  readonly traceId: string
  readonly ts: number
  readonly side: TraceSide
  readonly leg: string
  readonly stage: string
  readonly status: TraceStatus
  readonly detail: string
  /** ms since the leg's first event with this traceId (filled by the tracer, not the caller). */
  readonly elapsedMs?: number
}

/** Max events kept in memory. A connect + a few sync actions is ~dozens of events; 500 covers a long session while
 * bounding memory. Oldest are dropped. */
export const TRACE_BUFFER_MAX = 500

/** A monotonic-ish now(): performance.now() for elapsed math where available, else Date.now(). Wall-clock ts uses
 * Date.now() so copied logs line up with the agent's ts. */
function wallNow(): number {
  return Date.now()
}

/** Mint a short, non-secret correlation id for one connect/sync action. Not crypto — just unique enough to grep.
 * Format t_<base36 time><rand> so it sorts roughly by time and is easy to eyeball. */
export function mintTraceId(): string {
  const t = wallNow().toString(36)
  const r = Math.floor(Math.random() * 1e9).toString(36)
  currentId = `t_${t}${r}`
  return currentId
}

/** Shorten an id for a compact, still-non-sensitive trace detail (e.g. dev_2f2cf40e-… → dev_2f2cf40e). Ids aren't
 * secret, but full uuids are noise; keep the recognizable head. */
export function short(id: string | null | undefined): string {
  if (!id) return '-'
  return id.length > 16 ? `${id.slice(0, 16)}…` : id
}

export class ConnTrace {
  private buf: TraceEvent[] = []
  // first-seen wall ts per (traceId|leg) so elapsedMs is meaningful within a leg.
  private legStart = new Map<string, number>()
  private listeners = new Set<(e: TraceEvent) => void>()
  // monotonic per-direction sequence so the wire-inspector can show ordering + spot gaps.
  private wireSeq = { out: 0, in: 0 }

  /** Record ONE wire message on the `wire` leg with an explicit direction. `out` = we SENT it (browser→agent),
   * `in` = we RECEIVED it (agent→browser). `type` is the message type; `detail` MUST be content-blind (counts/
   * sizes only, never bytes/token/cookie). A per-direction seq is prepended so ordering + gaps are visible. */
  wire(traceId: string, dir: 'out' | 'in', type: string, detail = '', status: TraceStatus = 'ok'): TraceEvent {
    const seq = (this.wireSeq[dir] += 1)
    const body = detail ? `${type} ${detail}` : type
    return this.log(traceId, 'wire', dir, status, `#${seq} ${body}`)
  }

  /** Reset the per-direction wire seq — call on a new connection so each connection's ordering starts at #1. */
  resetWireSeq(): void {
    this.wireSeq = { out: 0, in: 0 }
  }

  /** Record one structured event. `detail` MUST be content-blind. Returns the event (with elapsedMs filled). */
  log(traceId: string, leg: string, stage: string, status: TraceStatus, detail = ''): TraceEvent {
    const ts = wallNow()
    const key = `${traceId}|${leg}`
    const start = this.legStart.get(key)
    if (start === undefined) this.legStart.set(key, ts)
    const elapsedMs = start === undefined ? 0 : ts - start
    const safeDetail = scrubDetail(detail)
    const ev: TraceEvent = { traceId, ts, side: 'browser', leg, stage, status, detail: safeDetail, elapsedMs }
    this.buf.push(ev)
    if (this.buf.length > TRACE_BUFFER_MAX) this.buf.shift()
    // Keep production diagnostics in the bounded ring buffer. The explicit Diagnostics / Copy Debug Log surface
    // can expose this scrubbed data when the user chooses; normal page activity must not populate DevTools with
    // internal device/session correlation metadata.
    for (const l of this.listeners) {
      try {
        l(ev)
      } catch {
        /* a listener must never break tracing */
      }
    }
    return ev
  }

  /** All buffered events (oldest → newest). */
  events(): readonly TraceEvent[] {
    return this.buf
  }

  /** A copy-pasteable text dump (one line per event) for the "Copy debug log" affordance. Content-blind. */
  dump(): string {
    return this.buf
      .map(
        (e) =>
          `${new Date(e.ts).toISOString()} ${e.side} ${e.leg}/${e.stage} ${e.status} +${e.elapsedMs ?? 0}ms ${e.detail} ${e.traceId}`,
      )
      .join('\n')
  }

  /** Events for one traceId (to inspect a single action end to end once agent events are merged in). */
  forTrace(traceId: string): TraceEvent[] {
    return this.buf.filter((e) => e.traceId === traceId)
  }

  onEvent(fn: (e: TraceEvent) => void): () => void {
    this.listeners.add(fn)
    return () => this.listeners.delete(fn)
  }

  clear(): void {
    this.buf = []
    this.legStart.clear()
  }
}

export function scrubDetail(detail: string): string {
  if (!detail) return ''
  let out = detail.replace(
    /(authorization|cookie|set-cookie|token|signature|candidate|offer|answer|sdp|path|cwd|folder|project|projectName|session|sessionName)=\S+/gi,
    '$1=<redacted>',
  )
  out = out.replace(/\b\/Users\/[^\s,;)]*/g, '<redacted-path>')
  // Generic POSIX paths, including paths embedded after a request-id prefix (`...:claude:<home-path>`). Do not
  // mistake the double slash in an HTTP(S) URL for a filesystem path.
  out = out.replace(/(^|[\s=:])\/(?!\/)[^\s,;)]*/g, '$1<redacted-path>')
  out = out.replace(/\b(?:[A-Za-z]:\\|\\\\)[^\s,;)]*/g, '<redacted-path>')
  out = out.replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]+/gi, '$1<redacted>')
  out = out.replace(/hydra_session=[^;\s]+/gi, 'hydra_session=<redacted>')
  out = out.replace(/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g, '<redacted-pem>')
  return out.length > 240 ? `${out.slice(0, 240)}…` : out
}

/** The most-recently-minted trace id (updated by mintTraceId). Lets request layers (authFetch) tag outbound cloud
 * calls with the CURRENT connect/sync correlation id without threading the controller everywhere. */
let currentId = ''
export function currentTraceId(): string {
  return currentId
}

// Build stamp injected by vite.config.build.ts (define). Declared for TS; "unknown"/0 in dev where no define ran.
declare const __HYDRA_BUILD_GIT__: string | undefined
declare const __HYDRA_BUILD_TIME__: number | undefined

/** The web bundle's Git identity. Immutable release builds inject the exact 40-hex approved SHA; ordinary
 * developer builds retain their best-effort short SHA / dirty marker. Callers that expose this outside local
 * diagnostics must independently enforce their narrower public-display contract. */
export function buildGit(): string {
  return typeof __HYDRA_BUILD_GIT__ !== 'undefined' ? __HYDRA_BUILD_GIT__ : 'unknown'
}

/** The web bundle's build stamp (git SHA + build ms), for the connect trace — so browser↔agent version drift
 * is visible in the log. "unknown" in dev/test where the define didn't run. */
export function buildStamp(): string {
  const git = buildGit()
  const built = typeof __HYDRA_BUILD_TIME__ !== 'undefined' ? __HYDRA_BUILD_TIME__ : 0
  return `git=${git} built=${built}`
}

/** Process-wide singleton so any module can trace without threading it everywhere. The DevTools helper is exposed
 * only during an explicit `?inspect=1` diagnostic session. */
export const connTrace = new ConnTrace()
if (typeof globalThis !== 'undefined' && diagnosticQueryFlag('inspect')) {
  ;(globalThis as unknown as { __hydraConnTrace?: ConnTrace }).__hydraConnTrace = connTrace
}
