import { afterEach, describe, expect, it } from 'vitest'
import {
  beginConnectionAttempt,
  CONNECTION_ATTEMPT_HISTORY_MAX,
  disableRenderMetrics,
  enableRenderMetrics,
  recordInitialHistoryCompletion,
  recordMultiPaneTerminalEvent,
  renderMetricsSnapshot,
  resetRenderMetrics,
  resetTransportMetrics,
  TRANSPORT_METRIC_HISTORY_MAX,
  type ConnectionAttemptMetricEntry,
  type ConnectionAttemptPhaseTimings,
  type TransportMetricEntry,
} from './render-metrics'
import {
  CONNECTION_ATTEMPT_PHASES,
  defaultDiagnostics,
  type ConnectionAttemptPhase,
} from './remote-transport'

function terminalEvent(sessionId: string, eventType = 'damage') {
  return {
    sessionId,
    eventType,
    rawWireBytes: 111,
    logicalBytes: 100,
    chunkCount: 3,
    transferMs: 12,
    reassembleMs: 1,
    parseMs: 2,
    applyMs: 3,
    paintMs: 4,
    active: false,
    materialized: eventType === 'grid',
  }
}

function snapshot(now: number) {
  return renderMetricsSnapshot(now) as {
    frames: number
    frameBytesMax: number
    rawWireBytesTotal: number
    chunksTotal: number
    ev: Record<string, number>
    transport: TransportMetricEntry[]
  }
}

function phases(
  overrides: Partial<Record<ConnectionAttemptPhase, number | null>> = {},
): ConnectionAttemptPhaseTimings {
  return Object.fromEntries(CONNECTION_ATTEMPT_PHASES.map((phase) => [phase, overrides[phase] ?? null])) as
    ConnectionAttemptPhaseTimings
}

function phaseCounts(
  overrides: Partial<Record<ConnectionAttemptPhase, number>> = {},
): Record<ConnectionAttemptPhase, number> {
  return Object.fromEntries(CONNECTION_ATTEMPT_PHASES.map((phase) => [phase, overrides[phase] ?? 0])) as
    Record<ConnectionAttemptPhase, number>
}

describe('content-blind render metrics', () => {
  afterEach(() => disableRenderMetrics())

  it('tracks first Grid and initial-history completion with an opaque per-lifetime pane alias', () => {
    const privateSession = 'customer-session-uuid-must-not-escape'
    enableRenderMetrics(10)
    recordMultiPaneTerminalEvent({ ...terminalEvent(privateSession, 'grid'), active: true }, 25)
    recordInitialHistoryCompletion(privateSession, true, 'reply', 55)
    // A duplicate completion cannot double-count the priority gate.
    recordInitialHistoryCompletion(privateSession, true, 'absolute_timeout', 80)

    const got = snapshot(100)
    expect(got.frames).toBe(1)
    expect(got.transport).toHaveLength(2)
    expect(got.transport[0]).toMatchObject({ kind: 'terminal_event', pane: 'pane-1', firstGrid: true })
    expect(got.transport[1]).toEqual(expect.objectContaining({
      kind: 'initial_history_complete',
      pane: 'pane-1',
      active: true,
      result: 'reply',
      sinceFirstGridMs: 30,
    }))
    expect(JSON.stringify(got)).not.toContain(privateSession)
    expect(got.transport.some((entry) => 'ts' in entry || 'atMs' in entry || 'channel' in entry)).toBe(false)
  })

  it('keeps a strict bounded ring and reset retires all counters, aliases, and timing state', () => {
    enableRenderMetrics(0)
    for (let i = 0; i < TRANSPORT_METRIC_HISTORY_MAX + 20; i++) {
      recordMultiPaneTerminalEvent(terminalEvent(`private-${i}`), i + 1)
    }
    const full = snapshot(500)
    expect(full.frames).toBe(TRANSPORT_METRIC_HISTORY_MAX + 20)
    expect(full.transport).toHaveLength(TRANSPORT_METRIC_HISTORY_MAX)
    // Oldest entries fell off; aliases remain opaque rather than disclosing the source id.
    expect(full.transport[0]).toMatchObject({ pane: 'pane-21' })
    expect(JSON.stringify(full)).not.toContain('private-')

    resetRenderMetrics(600)
    expect(snapshot(610)).toMatchObject({
      frames: 0,
      frameBytesMax: 0,
      rawWireBytesTotal: 0,
      chunksTotal: 0,
      ev: {},
      transport: [],
    })
    recordMultiPaneTerminalEvent(terminalEvent('new-private-session', 'grid'), 620)
    expect(snapshot(630).transport[0]).toMatchObject({ pane: 'pane-1', firstGrid: true })
  })

  it('evicts alias, first-Grid, and history-completion state together at the pane-state cap', () => {
    enableRenderMetrics(0)
    recordMultiPaneTerminalEvent(terminalEvent('old-pane', 'grid'), 1)
    recordInitialHistoryCompletion('old-pane', true, 'reply', 2)
    for (let i = 0; i < TRANSPORT_METRIC_HISTORY_MAX; i++) {
      recordMultiPaneTerminalEvent(terminalEvent(`new-pane-${i}`), i + 3)
    }

    // `old-pane` was the FIFO alias victim. Re-entry must get a fresh opaque alias, a fresh first-Grid marker,
    // and a fresh history completion rather than leaving any of the three auxiliary structures unbounded/stale.
    recordMultiPaneTerminalEvent(terminalEvent('old-pane', 'grid'), 400)
    recordInitialHistoryCompletion('old-pane', true, 'reply', 410)
    const entries = snapshot(420).transport
    expect(entries.at(-2)).toMatchObject({
      kind: 'terminal_event', pane: `pane-${TRANSPORT_METRIC_HISTORY_MAX + 2}`, firstGrid: true,
    })
    expect(entries.at(-1)).toMatchObject({
      kind: 'initial_history_complete', pane: `pane-${TRANSPORT_METRIC_HISTORY_MAX + 2}`,
      sinceFirstGridMs: 10,
    })
  })

  it('does no accounting while the opt-in collector is disabled', () => {
    const attempt = beginConnectionAttempt('user', 0)
    attempt.recordPhase('preparation_ready', 0.5)
    attempt.finish('connected', 0.75)
    recordMultiPaneTerminalEvent(terminalEvent('never-recorded'), 1)
    recordInitialHistoryCompletion('never-recorded', true, 'reply', 2)
    expect(snapshot(3)).toMatchObject({ frames: 0, transport: [], connections: { total: 0, attempts: [] } })
  })

  it('exports independent fixed first hits and detaches attempt and aggregate snapshots', () => {
    enableRenderMetrics(100)
    const attempt = beginConnectionAttempt('user', 110)

    attempt.recordPhase('preparation_ready', 120)
    attempt.recordPhase('preparation_ready', 121) // duplicate cannot replace the first hit
    attempt.recordPhase('relay_fetch_start', 135)
    attempt.recordPhase('identity_ready', 140) // controller/transport callbacks may arrive out of enum order
    attempt.recordPhase('relay_fetch_ready', 105) // a pre-attempt custom clock observation is invalid
    attempt.recordPhase('relay_fetch_ready', 145)
    attempt.recordPhase('peer_created', Number.NaN)
    attempt.recordPhase('peer_created', 150)
    attempt.recordPhase('not_a_phase' as ConnectionAttemptPhase, 150) // runtime callers cannot extend the vocabulary
    attempt.finish('connected', 155)
    attempt.recordPhase('offer_created', 160) // a settled attempt is immutable

    const connections = (renderMetricsSnapshot(170) as any).connections
    const first = connections.attempts[0]
    expect(Object.keys(first.phases)).toEqual(CONNECTION_ATTEMPT_PHASES)
    expect(first.phases).toEqual(phases({
      preparation_ready: 10,
      identity_ready: 30,
      relay_fetch_start: 25,
      relay_fetch_ready: 35,
      peer_created: 40,
    }))
    expect(connections.phaseHitCount).toEqual(phaseCounts({
      preparation_ready: 1,
      identity_ready: 1,
      relay_fetch_start: 1,
      relay_fetch_ready: 1,
      peer_created: 1,
    }))
    expect(connections.phaseMsAvg).toEqual(phases({
      preparation_ready: 10,
      identity_ready: 30,
      relay_fetch_start: 25,
      relay_fetch_ready: 35,
      peer_created: 40,
    }))

    first.phases.preparation_ready = 999
    connections.phaseHitCount.preparation_ready = 999
    expect((renderMetricsSnapshot(171) as any).connections).toMatchObject({
      phaseHitCount: { preparation_ready: 1 },
      attempts: [{ phases: { preparation_ready: 10 } }],
    })
  })

  it('keeps a bounded page-lifetime connection accumulator across transport resets', () => {
    enableRenderMetrics(100)
    const first = beginConnectionAttempt('restore', 110)
    first.recordDiagnostics({
      ...defaultDiagnostics(),
      route: 'direct',
      relayLeg: 'none',
      pairProtocol: 'udp',
      localTurnProtocol: 'not_applicable',
      timing: { toFirstRelayMs: null, toConnectedMs: 20, toSelectedPairMs: 35 },
    }, 145)
    first.recordPhase('preparation_ready', 115)
    first.finish('connected', 160)

    // The terminal benchmark origin resets at each DataChannel, but connection attempts belong to the page.
    resetTransportMetrics(200)
    const second = beginConnectionAttempt('auto', 210)
    second.finish('network_failure', 250)

    const connections = (renderMetricsSnapshot(300) as any).connections
    expect(connections).toMatchObject({
      windowMs: 200,
      total: 2,
      completed: 2,
      pending: 0,
      retained: 2,
      truncated: false,
      byTrigger: { restore: 1, auto: 1 },
      byOutcome: { connected: 1, network_failure: 1 },
      byRoute: { direct: 1, unknown: 1 },
      dcOpenCount: 1,
      dcOpenMsAvg: 20,
      selectedPairCount: 1,
      selectedPairMsAvg: 35,
      phaseHitCount: { preparation_ready: 1 },
      phaseMsAvg: { preparation_ready: 5 },
    })
    expect(connections.attempts[0]).toEqual({
      sequence: 1,
      trigger: 'restore',
      outcome: 'connected',
      startedSincePageMs: 10,
      durationMs: 50,
      dcOpenMs: 20,
      selectedPairMs: 35,
      selectedPairAfterDcOpenMs: 15,
      route: 'direct',
      relayLeg: 'none',
      pairProtocol: 'udp',
      localTurnProtocol: 'not_applicable',
      qualificationMode: 'normal',
      phases: phases({ preparation_ready: 5 }),
    } satisfies ConnectionAttemptMetricEntry)
  })

  it('keeps forced-relay qualification attempts separate from normal and unclassified traffic', () => {
    enableRenderMetrics(0)

    const normal = beginConnectionAttempt('user', 1)
    normal.recordDiagnostics({ ...defaultDiagnostics(), forcedRelay: false }, 2)
    normal.finish('connected', 3)

    const forced = beginConnectionAttempt('manual', 4)
    forced.recordDiagnostics({ ...defaultDiagnostics(), forcedRelay: true }, 5)
    forced.finish('connected', 6)

    beginConnectionAttempt('auto', 7).finish('network_failure', 8)

    const connections = (renderMetricsSnapshot(10) as any).connections
    expect(connections.byQualificationMode).toEqual({
      normal: 1,
      forced_relay: 1,
      unknown: 1,
    })
    expect(connections.attempts.map((entry: ConnectionAttemptMetricEntry) => entry.qualificationMode)).toEqual([
      'normal',
      'forced_relay',
      'unknown',
    ])
  })

  it('keeps authorization, passkey, and revocation outcomes out of the network-failure bucket', () => {
    enableRenderMetrics(0)
    beginConnectionAttempt('user', 1).finish('authorization_required', 2)
    beginConnectionAttempt('manual', 3).finish('auth_refused', 4)
    beginConnectionAttempt('visible', 5).finish('revoked', 6)

    const connections = (renderMetricsSnapshot(10) as any).connections
    expect(connections.byOutcome).toMatchObject({
      authorization_required: 1,
      auth_refused: 1,
      revoked: 1,
      network_failure: 0,
    })
  })

  it('retains only 256 attempts while preserving whole-page aggregates and a truncation marker', () => {
    enableRenderMetrics(0)
    for (let i = 0; i < CONNECTION_ATTEMPT_HISTORY_MAX + 17; i++) {
      const attempt = beginConnectionAttempt('online', i)
      attempt.recordPhase('preparation_ready', i + (i % 2 === 0 ? 0.25 : 0.75))
      attempt.finish('network_failure', i + 0.5)
    }
    const connections = (renderMetricsSnapshot(500) as any).connections
    expect(connections).toMatchObject({
      total: CONNECTION_ATTEMPT_HISTORY_MAX + 17,
      completed: CONNECTION_ATTEMPT_HISTORY_MAX + 17,
      retained: CONNECTION_ATTEMPT_HISTORY_MAX,
      truncated: true,
      byTrigger: { online: CONNECTION_ATTEMPT_HISTORY_MAX + 17 },
      byOutcome: { network_failure: CONNECTION_ATTEMPT_HISTORY_MAX + 17 },
    })
    expect(connections.attempts[0].sequence).toBe(18)
    expect(connections.attempts[0].phases).toEqual(phases({ preparation_ready: 0.75 }))
    expect(connections.attempts.at(-1).phases).toEqual(phases({ preparation_ready: 0.25 }))
    expect(connections.phaseHitCount).toEqual(phaseCounts({
      preparation_ready: CONNECTION_ATTEMPT_HISTORY_MAX + 17,
    }))
    expect(connections.phaseMsAvg).toEqual(phases({ preparation_ready: 0.5 }))
  })

  it('exports only monotonic relative timing and fixed enum fields even if diagnostics carries extra data', () => {
    const secret = 'candidate:secret-address session-private token-private'
    enableRenderMetrics(1_000_000)
    const attempt = beginConnectionAttempt('user', 1_000_010)
    attempt.recordPhase('preparation_ready', 1_000_011)
    attempt.recordDiagnostics({
      ...defaultDiagnostics(),
      route: 'relay',
      relayLeg: 'remote',
      pairProtocol: 'tcp',
      localTurnProtocol: 'not_applicable',
      timing: { toFirstRelayMs: 4, toConnectedMs: 9, toSelectedPairMs: 12 },
      secret,
      accountId: secret,
    } as any, 1_000_022)
    attempt.finish('connected', 1_000_030)

    const serialized = JSON.stringify((renderMetricsSnapshot(1_000_040) as any).connections)
    expect(serialized).not.toContain(secret)
    expect(serialized).not.toMatch(/account|device|session|candidate|address|token|sdp|wall|timestamp|atMs/i)
    expect(serialized).toContain('"startedSincePageMs":10')
  })

  it('retires recorders from an explicitly reset collection generation', () => {
    enableRenderMetrics(0)
    const stale = beginConnectionAttempt('user', 1)
    stale.recordPhase('preparation_ready', 2)
    resetRenderMetrics(10)
    const current = beginConnectionAttempt('manual', 11)

    stale.recordDiagnostics({
      ...defaultDiagnostics(),
      route: 'relay',
      relayLeg: 'local',
      pairProtocol: 'tcp',
      localTurnProtocol: 'tls',
      timing: { toFirstRelayMs: 1, toConnectedMs: 2, toSelectedPairMs: 3 },
    }, 12)
    stale.finish('network_failure', 13)
    stale.recordPhase('relay_fetch_start', 13)
    current.recordPhase('preparation_ready', 13)
    current.finish('connected', 14)

    const connections = (renderMetricsSnapshot(20) as any).connections
    expect(connections).toMatchObject({
      total: 1,
      completed: 1,
      byTrigger: { user: 0, manual: 1 },
      byOutcome: { connected: 1, network_failure: 0 },
      byRoute: { relay: 0, unknown: 1 },
    })
    expect(connections.attempts[0].phases).toEqual(phases({ preparation_ready: 2 }))
    expect(connections.phaseHitCount).toEqual(phaseCounts({ preparation_ready: 1 }))
  })
})
