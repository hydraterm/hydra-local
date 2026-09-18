// Content-blind render/transport metrics used by the opt-in `?metrics=1` diagnostic path.
//
// Privacy contract: this module never receives terminal text/cells, commands, cwd, or credentials. A session id is
// used only as a key in a bounded in-memory alias table; snapshots expose `pane-N`, never the source identifier.
// Metrics stay in one bounded browser-memory ring behind the existing local DevTools helper; nothing uploads.

import {
  CONNECTION_ATTEMPT_PHASES,
  type ConnectionAttemptPhase,
  type Diagnostics,
} from './remote-transport.js'

export const TRANSPORT_METRIC_HISTORY_MAX = 256
export const CONNECTION_ATTEMPT_HISTORY_MAX = 256

export type ConnectionAttemptTrigger = 'restore' | 'user' | 'manual' | 'auto' | 'online' | 'visible'
export type ConnectionAttemptOutcome =
  | 'connected'
  | 'network_failure'
  | 'control_plane_failure'
  | 'authorization_required'
  | 'auth_refused'
  | 'revoked'
  | 'cancelled'
  | 'superseded'

export interface ConnectionAttemptMetricRecorder {
  /** Diagnostics are already enum-only/content-blind. The recorder extracts only the fixed allow-list below. */
  recordDiagnostics(diagnostics: Diagnostics, now?: number): void
  /** Record the first monotonic observation of one fixed, content-blind connection phase. */
  recordPhase(phase: ConnectionAttemptPhase, now?: number): void
  finish(outcome: ConnectionAttemptOutcome, now?: number): void
}

export type ConnectionAttemptPhaseTimings = Readonly<Record<ConnectionAttemptPhase, number | null>>
export type ConnectionQualificationMode = 'normal' | 'forced_relay' | 'unknown'

export interface ConnectionAttemptMetricEntry {
  readonly sequence: number
  readonly trigger: ConnectionAttemptTrigger
  readonly outcome: ConnectionAttemptOutcome | 'pending'
  readonly startedSincePageMs: number
  readonly durationMs: number | null
  readonly dcOpenMs: number | null
  readonly selectedPairMs: number | null
  readonly selectedPairAfterDcOpenMs: number | null
  readonly route: Diagnostics['route']
  readonly relayLeg: Diagnostics['relayLeg']
  readonly pairProtocol: Diagnostics['pairProtocol']
  readonly localTurnProtocol: Diagnostics['localTurnProtocol']
  readonly qualificationMode: ConnectionQualificationMode
  readonly phases: ConnectionAttemptPhaseTimings
}

export type InitialHistoryResult =
  | 'reply'
  | 'inactivity_timeout'
  | 'absolute_timeout'
  | 'not_available'
  | 'not_applicable'

export interface MultiPaneTerminalMetricInput {
  readonly sessionId: string
  readonly eventType: string
  readonly rawWireBytes: number
  readonly logicalBytes: number
  readonly encodedBytes?: number
  readonly decodedBytes?: number
  readonly chunkCount: number
  readonly compressed?: boolean
  readonly transferMs: number
  readonly reassembleMs: number
  readonly parseMs: number
  readonly applyMs: number
  readonly paintMs: number
  readonly active: boolean
  /** True only after this event passed the pane SyncState's materialization gate. */
  readonly materialized: boolean
}

export type TransportMetricEntry =
  | {
      readonly kind: 'terminal_event'
      readonly sinceTransportStartMs: number
      readonly pane: string
      readonly eventType: string
      readonly rawWireBytes: number
      readonly logicalBytes: number
      readonly encodedBytes: number
      readonly decodedBytes: number
      readonly compressed: boolean
      readonly compressionRatio: number
      readonly chunkCount: number
      readonly transferMs: number
      readonly reassembleMs: number
      readonly parseMs: number
      readonly applyMs: number
      readonly paintMs: number
      readonly active: boolean
      readonly firstGrid: boolean
    }
  | {
      readonly kind: 'initial_history_complete'
      readonly sinceTransportStartMs: number
      readonly pane: string
      readonly active: boolean
      readonly result: InitialHistoryResult
      readonly sinceFirstGridMs: number | null
    }

interface Metrics {
  frames: number // complete terminal lines; multi-pane entries additionally pass the sync/validation gate
  frameBytesTotal: number // logical/reassembled bytes
  frameBytesMax: number
  rawWireBytesTotal: number // exact terminal-frame header + payload bytes for validated multi-pane events
  encodedBytesTotal: number
  decodedBytesTotal: number
  compressedFrames: number
  chunksTotal: number
  ev: Record<string, number> // validated daemon event type counts
  paints: number // GridRenderer paint/paintRows calls
  paintMsTotal: number
  paintMsMax: number
  rowsPaintedTotal: number
  rowsPaintedMax: number
  since: number
  transport: TransportMetricEntry[]
}

let enabled = false
let m: Metrics = blank(0)
let aliases = new Map<string, string>()
let nextAlias = 1
let firstGridAt = new Map<string, number>()
let initialHistoryRecorded = new Set<string>()

type MutableConnectionEntry = ConnectionAttemptMetricEntry & {
  outcome: ConnectionAttemptMetricEntry['outcome']
  durationMs: number | null
  dcOpenMs: number | null
  selectedPairMs: number | null
  selectedPairAfterDcOpenMs: number | null
  route: Diagnostics['route']
  relayLeg: Diagnostics['relayLeg']
  pairProtocol: Diagnostics['pairProtocol']
  localTurnProtocol: Diagnostics['localTurnProtocol']
  qualificationMode: ConnectionQualificationMode
  phases: Record<ConnectionAttemptPhase, number | null>
  readonly startedAt: number
  pathCounted: boolean
  qualificationModeCounted: boolean
  dcOpenCounted: boolean
  selectedPairCounted: boolean
}

type ConnectionAggregates = {
  total: number
  completed: number
  byTrigger: Record<ConnectionAttemptTrigger, number>
  byOutcome: Record<ConnectionAttemptOutcome, number>
  byRoute: Record<Diagnostics['route'], number>
  byRelayLeg: Record<Diagnostics['relayLeg'], number>
  byPairProtocol: Record<Diagnostics['pairProtocol'], number>
  byLocalTurnProtocol: Record<Diagnostics['localTurnProtocol'], number>
  byQualificationMode: Record<ConnectionQualificationMode, number>
  dcOpenCount: number
  dcOpenMsTotal: number
  selectedPairCount: number
  selectedPairMsTotal: number
  phaseHitCount: Record<ConnectionAttemptPhase, number>
  phaseMsTotal: Record<ConnectionAttemptPhase, number>
}

let connectionPageSince = 0
let connectionSequence = 0
let connectionGeneration = 0
let connectionAttempts: MutableConnectionEntry[] = []
let connectionTruncated = false
let connectionAggregates = blankConnectionAggregates()

function monotonicNow(): number {
  return typeof performance !== 'undefined' ? performance.now() : Date.now()
}

function blank(since: number): Metrics {
  return {
    frames: 0,
    frameBytesTotal: 0,
    frameBytesMax: 0,
    rawWireBytesTotal: 0,
    encodedBytesTotal: 0,
    decodedBytesTotal: 0,
    compressedFrames: 0,
    chunksTotal: 0,
    ev: {},
    paints: 0,
    paintMsTotal: 0,
    paintMsMax: 0,
    rowsPaintedTotal: 0,
    rowsPaintedMax: 0,
    since,
    transport: [],
  }
}

function resetState(now: number): void {
  m = blank(now)
  aliases = new Map()
  nextAlias = 1
  firstGridAt = new Map()
  initialHistoryRecorded = new Set()
}

function enumCounts<T extends string>(values: readonly T[]): Record<T, number> {
  return Object.fromEntries(values.map((value) => [value, 0])) as Record<T, number>
}

function blankConnectionPhases(): Record<ConnectionAttemptPhase, number | null> {
  return Object.fromEntries(CONNECTION_ATTEMPT_PHASES.map((phase) => [phase, null])) as
    Record<ConnectionAttemptPhase, number | null>
}

const CONNECTION_PHASE_SET = new Set<ConnectionAttemptPhase>(CONNECTION_ATTEMPT_PHASES)

function blankConnectionAggregates(): ConnectionAggregates {
  return {
    total: 0,
    completed: 0,
    byTrigger: enumCounts(['restore', 'user', 'manual', 'auto', 'online', 'visible'] as const),
    byOutcome: enumCounts([
      'connected',
      'network_failure',
      'control_plane_failure',
      'authorization_required',
      'auth_refused',
      'revoked',
      'cancelled',
      'superseded',
    ] as const),
    byRoute: enumCounts(['direct', 'relay', 'unknown'] as const),
    byRelayLeg: enumCounts(['none', 'local', 'remote', 'both', 'unknown'] as const),
    byPairProtocol: enumCounts(['udp', 'tcp', 'unknown'] as const),
    byLocalTurnProtocol: enumCounts(['udp', 'tcp', 'tls', 'unknown', 'not_applicable'] as const),
    byQualificationMode: enumCounts(['normal', 'forced_relay', 'unknown'] as const),
    dcOpenCount: 0,
    dcOpenMsTotal: 0,
    selectedPairCount: 0,
    selectedPairMsTotal: 0,
    phaseHitCount: enumCounts(CONNECTION_ATTEMPT_PHASES),
    phaseMsTotal: enumCounts(CONNECTION_ATTEMPT_PHASES),
  }
}

function resetConnectionState(now: number): void {
  connectionGeneration++
  connectionPageSince = now
  connectionSequence = 0
  connectionAttempts = []
  connectionTruncated = false
  connectionAggregates = blankConnectionAggregates()
}

function adjustCount<T extends string>(counts: Record<T, number>, before: T | null, after: T): void {
  if (before === after) return
  if (before !== null) counts[before] = Math.max(0, counts[before] - 1)
  counts[after]++
}

function countOrUpdateQualificationMode(entry: MutableConnectionEntry, next: ConnectionQualificationMode): void {
  adjustCount(
    connectionAggregates.byQualificationMode,
    entry.qualificationModeCounted ? entry.qualificationMode : null,
    next,
  )
  entry.qualificationMode = next
  entry.qualificationModeCounted = true
}

function countOrUpdatePath(
  entry: MutableConnectionEntry,
  next: Pick<ConnectionAttemptMetricEntry, 'route' | 'relayLeg' | 'pairProtocol' | 'localTurnProtocol'>,
): void {
  adjustCount(connectionAggregates.byRoute, entry.pathCounted ? entry.route : null, next.route)
  adjustCount(connectionAggregates.byRelayLeg, entry.pathCounted ? entry.relayLeg : null, next.relayLeg)
  adjustCount(connectionAggregates.byPairProtocol, entry.pathCounted ? entry.pairProtocol : null, next.pairProtocol)
  adjustCount(
    connectionAggregates.byLocalTurnProtocol,
    entry.pathCounted ? entry.localTurnProtocol : null,
    next.localTurnProtocol,
  )
  entry.route = next.route
  entry.relayLeg = next.relayLeg
  entry.pairProtocol = next.pairProtocol
  entry.localTurnProtocol = next.localTurnProtocol
  entry.pathCounted = true
}

function paneAlias(sessionId: string): string {
  const prior = aliases.get(sessionId)
  if (prior) return prior
  if (aliases.size >= TRANSPORT_METRIC_HISTORY_MAX) {
    const oldest = aliases.keys().next().value as string | undefined
    if (oldest !== undefined) {
      aliases.delete(oldest)
      firstGridAt.delete(oldest)
      initialHistoryRecorded.delete(oldest)
    }
  }
  const alias = `pane-${nextAlias++}`
  aliases.set(sessionId, alias)
  return alias
}

function pushTransport(entry: TransportMetricEntry): void {
  m.transport.push(entry)
  if (m.transport.length > TRANSPORT_METRIC_HISTORY_MAX) m.transport.shift()
}

export function enableRenderMetrics(now = monotonicNow()): void {
  enabled = true
  resetState(now)
  resetConnectionState(now)
  ;(globalThis as Record<string, unknown>).__hydraMetrics = () => renderMetricsSnapshot(monotonicNow())
  ;(globalThis as Record<string, unknown>).__hydraMetricsReset = () => resetRenderMetrics(monotonicNow())
}

/** Test/debug cleanup. Production normally enables once for the lifetime of a `?metrics=1` page. */
export function disableRenderMetrics(): void {
  enabled = false
  resetState(0)
  resetConnectionState(0)
  delete (globalThis as Record<string, unknown>).__hydraMetrics
  delete (globalThis as Record<string, unknown>).__hydraMetricsReset
}

export function metricsOn(): boolean {
  return enabled
}

/** Explicit DevTools/test reset: clear both the current transport counters and the page-lifetime attempt history. */
export function resetRenderMetrics(now = monotonicNow()): void {
  if (!enabled) return
  resetState(now)
  resetConnectionState(now)
}

/** A transport lifetime owns aliases, first-paint timing, and terminal history. Connection attempts deliberately
 * survive this reset for the current page lifetime. */
export function resetTransportMetrics(now = monotonicNow()): void {
  if (!enabled) return
  resetState(now)
}

/** Start one content-blind connection-attempt record. Disabled metrics return a stable no-op recorder. */
export function beginConnectionAttempt(
  trigger: ConnectionAttemptTrigger,
  now = monotonicNow(),
): ConnectionAttemptMetricRecorder {
  if (!enabled) return NOOP_CONNECTION_RECORDER

  const recorderGeneration = connectionGeneration

  const entry: MutableConnectionEntry = {
    sequence: ++connectionSequence,
    trigger,
    outcome: 'pending',
    startedSincePageMs: Math.max(0, now - connectionPageSince),
    durationMs: null,
    dcOpenMs: null,
    selectedPairMs: null,
    selectedPairAfterDcOpenMs: null,
    route: 'unknown',
    relayLeg: 'unknown',
    pairProtocol: 'unknown',
    localTurnProtocol: 'unknown',
    qualificationMode: 'unknown',
    phases: blankConnectionPhases(),
    startedAt: now,
    pathCounted: false,
    qualificationModeCounted: false,
    dcOpenCounted: false,
    selectedPairCounted: false,
  }
  connectionAttempts.push(entry)
  if (connectionAttempts.length > CONNECTION_ATTEMPT_HISTORY_MAX) {
    connectionAttempts.shift()
    connectionTruncated = true
  }
  connectionAggregates.total++
  connectionAggregates.byTrigger[trigger]++

  return {
    recordPhase(phase, observedAt = monotonicNow()) {
      if (!enabled || recorderGeneration !== connectionGeneration || entry.outcome !== 'pending') return
      if (!CONNECTION_PHASE_SET.has(phase) || entry.phases[phase] !== null) return
      const relativeMs = observedAt - entry.startedAt
      if (!Number.isFinite(relativeMs) || relativeMs < 0) return
      entry.phases[phase] = relativeMs
      connectionAggregates.phaseHitCount[phase]++
      connectionAggregates.phaseMsTotal[phase] += relativeMs
    },
    recordDiagnostics(diagnostics, observedAt = monotonicNow()) {
      if (!enabled || recorderGeneration !== connectionGeneration) return
      const dcOpenMs = diagnostics.timing.toConnectedMs
      if (!entry.dcOpenCounted && typeof dcOpenMs === 'number' && Number.isFinite(dcOpenMs) && dcOpenMs >= 0) {
        entry.dcOpenMs = dcOpenMs
        entry.dcOpenCounted = true
        connectionAggregates.dcOpenCount++
        connectionAggregates.dcOpenMsTotal += dcOpenMs
      }
      const selectedPairMs = diagnostics.timing.toSelectedPairMs
      if (
        !entry.selectedPairCounted &&
        typeof selectedPairMs === 'number' && Number.isFinite(selectedPairMs) && selectedPairMs >= 0
      ) {
        entry.selectedPairMs = selectedPairMs
        entry.selectedPairAfterDcOpenMs = entry.dcOpenMs === null
          ? null
          : Math.max(0, selectedPairMs - entry.dcOpenMs)
        entry.selectedPairCounted = true
        connectionAggregates.selectedPairCount++
        connectionAggregates.selectedPairMsTotal += selectedPairMs
      }
      // Only the fixed enums are copied. `observedAt` is intentionally not retained: an absolute timestamp is
      // unnecessary, and all exported timing remains relative to this attempt/page.
      void observedAt
      countOrUpdateQualificationMode(entry, diagnostics.forcedRelay ? 'forced_relay' : 'normal')
      if (
        diagnostics.route !== 'unknown' || diagnostics.relayLeg !== 'unknown' ||
        diagnostics.pairProtocol !== 'unknown' || diagnostics.localTurnProtocol !== 'unknown'
      ) {
        countOrUpdatePath(entry, diagnostics)
      }
    },
    finish(outcome, finishedAt = monotonicNow()) {
      if (!enabled || recorderGeneration !== connectionGeneration || entry.outcome !== 'pending') return
      entry.outcome = outcome
      entry.durationMs = Math.max(0, finishedAt - entry.startedAt)
      connectionAggregates.completed++
      connectionAggregates.byOutcome[outcome]++
      if (!entry.pathCounted) countOrUpdatePath(entry, entry)
      if (!entry.qualificationModeCounted) countOrUpdateQualificationMode(entry, 'unknown')
    },
  }
}

const NOOP_CONNECTION_RECORDER: ConnectionAttemptMetricRecorder = {
  recordPhase: () => {},
  recordDiagnostics: () => {},
  finish: () => {},
}

/** Legacy single-pane line accounting. `recordEvent` runs separately after its daemon-event validation. */
export function recordFrame(bytes: number): void {
  if (!enabled) return
  m.frames++
  m.frameBytesTotal += bytes
  if (bytes > m.frameBytesMax) m.frameBytesMax = bytes
}

export function recordEvent(ev: string): void {
  if (!enabled) return
  m.ev[ev] = (m.ev[ev] ?? 0) + 1
}

/** Record one fully reassembled, decoded, and SyncState-accepted multi-pane event exactly once. */
export function recordMultiPaneTerminalEvent(input: MultiPaneTerminalMetricInput, now = monotonicNow()): void {
  if (!enabled) return
  const encodedBytes = input.encodedBytes ?? input.logicalBytes
  const decodedBytes = input.decodedBytes ?? input.logicalBytes
  const compressed = input.compressed ?? false
  const pane = paneAlias(input.sessionId)
  const firstGrid = input.eventType === 'grid' && input.materialized && !firstGridAt.has(input.sessionId)
  if (firstGrid) firstGridAt.set(input.sessionId, now)

  m.frames++
  m.frameBytesTotal += input.logicalBytes
  if (input.logicalBytes > m.frameBytesMax) m.frameBytesMax = input.logicalBytes
  m.rawWireBytesTotal += input.rawWireBytes
  m.encodedBytesTotal += encodedBytes
  m.decodedBytesTotal += decodedBytes
  if (compressed) m.compressedFrames++
  m.chunksTotal += input.chunkCount
  m.ev[input.eventType] = (m.ev[input.eventType] ?? 0) + 1

  pushTransport({
    kind: 'terminal_event',
    sinceTransportStartMs: Math.max(0, now - m.since),
    pane,
    eventType: input.eventType,
    rawWireBytes: input.rawWireBytes,
    logicalBytes: input.logicalBytes,
    encodedBytes,
    decodedBytes,
    compressed,
    compressionRatio: decodedBytes > 0
      ? Number((encodedBytes / decodedBytes).toFixed(4))
      : 1,
    chunkCount: input.chunkCount,
    transferMs: input.transferMs,
    reassembleMs: input.reassembleMs,
    parseMs: input.parseMs,
    applyMs: input.applyMs,
    paintMs: input.paintMs,
    active: input.active,
    firstGrid,
  })
}

/** Record the terminal-priority gate after first Grid. At most one completion is retained per pane/lifetime. */
export function recordInitialHistoryCompletion(
  sessionId: string,
  active: boolean,
  result: InitialHistoryResult,
  now = monotonicNow(),
): void {
  if (!enabled) return
  const pane = paneAlias(sessionId)
  if (initialHistoryRecorded.has(sessionId)) return
  initialHistoryRecorded.add(sessionId)
  const gridAt = firstGridAt.get(sessionId)
  pushTransport({
    kind: 'initial_history_complete',
    sinceTransportStartMs: Math.max(0, now - m.since),
    pane,
    active,
    result,
    sinceFirstGridMs: gridAt === undefined ? null : Math.max(0, now - gridAt),
  })
}

export function recordPaint(ms: number, rows: number): void {
  if (!enabled) return
  m.paints++
  m.paintMsTotal += ms
  if (ms > m.paintMsMax) m.paintMsMax = ms
  m.rowsPaintedTotal += rows
  if (rows > m.rowsPaintedMax) m.rowsPaintedMax = rows
}

export function renderMetricsSnapshot(now = monotonicNow()): Record<string, unknown> {
  const secs = Math.max(0.001, (now - m.since) / 1000)
  const connectionWindowMs = Math.max(0, now - connectionPageSince)
  const completed = connectionAggregates.completed
  return {
    windowSecs: Number(secs.toFixed(1)),
    frames: m.frames,
    framesPerSec: Number((m.frames / secs).toFixed(1)),
    frameBytesAvg: m.frames ? Math.round(m.frameBytesTotal / m.frames) : 0,
    frameBytesMax: m.frameBytesMax,
    rawWireBytesTotal: m.rawWireBytesTotal,
    encodedBytesTotal: m.encodedBytesTotal,
    decodedBytesTotal: m.decodedBytesTotal,
    compressedFrames: m.compressedFrames,
    compressionRatio: m.decodedBytesTotal > 0
      ? Number((m.encodedBytesTotal / m.decodedBytesTotal).toFixed(4))
      : 1,
    chunksTotal: m.chunksTotal,
    ev: { ...m.ev },
    paints: m.paints,
    paintsPerSec: Number((m.paints / secs).toFixed(1)),
    paintMsAvg: m.paints ? Number((m.paintMsTotal / m.paints).toFixed(2)) : 0,
    paintMsMax: Number(m.paintMsMax.toFixed(2)),
    rowsPaintedAvg: m.paints ? Math.round(m.rowsPaintedTotal / m.paints) : 0,
    rowsPaintedMax: m.rowsPaintedMax,
    // Return detached entries so a console consumer cannot mutate the bounded internal ring.
    transport: m.transport.map((entry) => ({ ...entry })),
    connections: {
      windowMs: connectionWindowMs,
      total: connectionAggregates.total,
      completed,
      pending: Math.max(0, connectionAggregates.total - completed),
      retained: connectionAttempts.length,
      truncated: connectionTruncated,
      byTrigger: { ...connectionAggregates.byTrigger },
      byOutcome: { ...connectionAggregates.byOutcome },
      byRoute: { ...connectionAggregates.byRoute },
      byRelayLeg: { ...connectionAggregates.byRelayLeg },
      byPairProtocol: { ...connectionAggregates.byPairProtocol },
      byLocalTurnProtocol: { ...connectionAggregates.byLocalTurnProtocol },
      byQualificationMode: { ...connectionAggregates.byQualificationMode },
      dcOpenCount: connectionAggregates.dcOpenCount,
      dcOpenMsAvg: connectionAggregates.dcOpenCount > 0
        ? Number((connectionAggregates.dcOpenMsTotal / connectionAggregates.dcOpenCount).toFixed(2))
        : null,
      selectedPairCount: connectionAggregates.selectedPairCount,
      selectedPairMsAvg: connectionAggregates.selectedPairCount > 0
        ? Number((connectionAggregates.selectedPairMsTotal / connectionAggregates.selectedPairCount).toFixed(2))
        : null,
      phaseHitCount: { ...connectionAggregates.phaseHitCount },
      phaseMsAvg: Object.fromEntries(CONNECTION_ATTEMPT_PHASES.map((phase) => [
        phase,
        connectionAggregates.phaseHitCount[phase] > 0
          ? Number((connectionAggregates.phaseMsTotal[phase] / connectionAggregates.phaseHitCount[phase]).toFixed(2))
          : null,
      ])) as Record<ConnectionAttemptPhase, number | null>,
      attempts: connectionAttempts.map((entry): ConnectionAttemptMetricEntry => ({
        sequence: entry.sequence,
        trigger: entry.trigger,
        outcome: entry.outcome,
        startedSincePageMs: entry.startedSincePageMs,
        durationMs: entry.durationMs,
        dcOpenMs: entry.dcOpenMs,
        selectedPairMs: entry.selectedPairMs,
        selectedPairAfterDcOpenMs: entry.selectedPairAfterDcOpenMs,
        route: entry.route,
        relayLeg: entry.relayLeg,
        pairProtocol: entry.pairProtocol,
        localTurnProtocol: entry.localTurnProtocol,
        qualificationMode: entry.qualificationMode,
        phases: { ...entry.phases },
      })),
    },
  }
}
