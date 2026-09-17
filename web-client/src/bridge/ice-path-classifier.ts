// Content-blind selected ICE-pair classification. This module consumes only the standardized enum-like
// portions of RTCStats; it never returns candidate addresses, URLs, foundations, SDP, or candidate strings.

import type {
  IcePairProtocol,
  IceRelayLeg,
  IceRoute,
  LocalTurnProtocol,
} from './remote-transport.js'

export type { IcePairProtocol, IceRelayLeg, IceRoute, LocalTurnProtocol } from './remote-transport.js'

export interface SelectedIcePath {
  readonly route: IceRoute
  readonly relayLeg: IceRelayLeg
  readonly pairProtocol: IcePairProtocol
  /** Browser stats can prove the transport to the browser's own TURN server only. Never infer the remote
   * candidate's TURN transport from `remote-candidate` stats. */
  readonly localTurnProtocol: LocalTurnProtocol
  /** Legacy diagnostics retain the selected candidate type without exposing either candidate itself. */
  readonly candidateType: 'host' | 'srflx' | 'prflx' | 'relay' | 'unknown'
  readonly candidateProtocol: 'udp' | 'tcp' | 'tls' | 'unknown'
}

type StatsRecord = Record<string, unknown> & { type?: unknown; id?: unknown }

function exactCandidateType(value: unknown): SelectedIcePath['candidateType'] {
  return value === 'host' || value === 'srflx' || value === 'prflx' || value === 'relay'
    ? value
    : 'unknown'
}

function pairProtocol(value: unknown): IcePairProtocol {
  if (typeof value !== 'string') return 'unknown'
  const normalized = value.toLowerCase()
  return normalized === 'udp' || normalized === 'tcp' ? normalized : 'unknown'
}

function turnProtocol(value: unknown): LocalTurnProtocol {
  if (typeof value !== 'string') return 'unknown'
  const normalized = value.toLowerCase()
  return normalized === 'udp' || normalized === 'tcp' || normalized === 'tls' ? normalized : 'unknown'
}

function effectiveId(record: StatsRecord, key: string): string {
  return typeof record.id === 'string' && record.id.length > 0 ? record.id : key
}

/**
 * Classify the one selected pair. `transport.selectedCandidatePairId` is authoritative whenever any transport
 * supplies it. The legacy `candidate-pair.selected` fallback is consulted only when that ID is absent entirely;
 * a stale `selected=true` pair can therefore never override a transport's explicit selection.
 *
 * `null` means the report has not materialized a complete selected pair yet and the caller may retry briefly.
 */
export function classifySelectedIcePair(stats: RTCStatsReport): SelectedIcePath | null {
  const records: Array<{ key: string; record: StatsRecord }> = []
  stats.forEach((value: unknown, key: string) => {
    if (value && typeof value === 'object') records.push({ key, record: value as StatsRecord })
  })

  let authoritativePairId: string | null = null
  for (const { record } of records) {
    if (record.type !== 'transport') continue
    const value = record.selectedCandidatePairId
    if (typeof value === 'string' && value.length > 0) {
      authoritativePairId = value
      break
    }
  }

  let pair: StatsRecord | null = null
  if (authoritativePairId !== null) {
    pair = records.find(({ key, record }) =>
      record.type === 'candidate-pair' && effectiveId(record, key) === authoritativePairId,
    )?.record ?? null
    // An explicit transport ID that has not appeared in this report is incomplete. Do not fall back to a
    // possibly-stale pair whose legacy `selected` bit happens to remain true.
    if (!pair) return null
  } else {
    pair = records.find(({ record }) => record.type === 'candidate-pair' && record.selected === true)?.record ?? null
    if (!pair) return null
  }

  const localId = typeof pair.localCandidateId === 'string' ? pair.localCandidateId : null
  const remoteId = typeof pair.remoteCandidateId === 'string' ? pair.remoteCandidateId : null
  if (!localId || !remoteId) return null

  const local = records.find(({ key, record }) =>
    record.type === 'local-candidate' && effectiveId(record, key) === localId,
  )?.record
  const remote = records.find(({ key, record }) =>
    record.type === 'remote-candidate' && effectiveId(record, key) === remoteId,
  )?.record
  if (!local || !remote) return null

  const localType = exactCandidateType(local.candidateType)
  const remoteType = exactCandidateType(remote.candidateType)
  const localRelay = localType === 'relay'
  const remoteRelay = remoteType === 'relay'
  const bothTypesKnown = localType !== 'unknown' && remoteType !== 'unknown'

  const route: IceRoute = localRelay || remoteRelay
    ? 'relay'
    : bothTypesKnown
      ? 'direct'
      : 'unknown'
  const relayLeg: IceRelayLeg = localRelay && remoteRelay
    ? 'both'
    : localRelay && remoteType !== 'unknown'
      ? 'local'
      : remoteRelay && localType !== 'unknown'
        ? 'remote'
        : bothTypesKnown
          ? 'none'
          : 'unknown'

  const localPairProtocol = pairProtocol(local.protocol)
  const remotePairProtocol = pairProtocol(remote.protocol)
  const selectedPairProtocol: IcePairProtocol =
    localPairProtocol !== 'unknown' && remotePairProtocol !== 'unknown'
      ? localPairProtocol === remotePairProtocol ? localPairProtocol : 'unknown'
      : localPairProtocol !== 'unknown'
        ? localPairProtocol
        : remotePairProtocol
  const localTurnProtocol: LocalTurnProtocol = localRelay
    ? turnProtocol(local.relayProtocol)
    : localType === 'unknown'
      ? 'unknown'
      : 'not_applicable'

  const candidateType: SelectedIcePath['candidateType'] = route === 'relay'
    ? 'relay'
    : localType !== 'unknown'
      ? localType
      : remoteType
  // Backward-compatible UI field. A browser-local relay may report its TURN transport (including TLS). A
  // remote-only relay may not: its TURN hop is outside this browser's stats authority, so report pair UDP/TCP.
  const candidateProtocol: SelectedIcePath['candidateProtocol'] = localRelay && (
    localTurnProtocol === 'udp' || localTurnProtocol === 'tcp' || localTurnProtocol === 'tls'
  ) ? localTurnProtocol : selectedPairProtocol

  return {
    route,
    relayLeg,
    pairProtocol: selectedPairProtocol,
    localTurnProtocol,
    candidateType,
    candidateProtocol,
  }
}
