import { describe, expect, it } from 'vitest'
import { classifySelectedIcePair } from './ice-path-classifier'

function report(entries: Array<[string, Record<string, unknown>]>): RTCStatsReport {
  return new Map(entries) as unknown as RTCStatsReport
}

function pairRecords(options: {
  pairId?: string
  selected?: boolean
  localType?: string
  remoteType?: string
  localProtocol?: string
  remoteProtocol?: string
  localRelayProtocol?: string
  remoteRelayProtocol?: string
} = {}): Array<[string, Record<string, unknown>]> {
  const pairId = options.pairId ?? 'pair'
  return [
    [pairId, {
      id: pairId,
      type: 'candidate-pair',
      selected: options.selected ?? true,
      localCandidateId: `${pairId}-local`,
      remoteCandidateId: `${pairId}-remote`,
    }],
    [`${pairId}-local`, {
      id: `${pairId}-local`,
      type: 'local-candidate',
      candidateType: options.localType ?? 'host',
      protocol: options.localProtocol ?? 'udp',
      ...(options.localRelayProtocol ? { relayProtocol: options.localRelayProtocol } : {}),
    }],
    [`${pairId}-remote`, {
      id: `${pairId}-remote`,
      type: 'remote-candidate',
      candidateType: options.remoteType ?? 'host',
      protocol: options.remoteProtocol ?? 'udp',
      // Deliberately accepted as fixture input so the assertion can prove the classifier never trusts it.
      ...(options.remoteRelayProtocol ? { relayProtocol: options.remoteRelayProtocol } : {}),
    }],
  ]
}

describe('selected ICE pair classification', () => {
  it('strictly prefers transport.selectedCandidatePairId over a conflicting legacy selected flag', () => {
    const stats = report([
      ['transport', { id: 'transport', type: 'transport', selectedCandidatePairId: 'authoritative' }],
      ...pairRecords({ pairId: 'stale', selected: true, localType: 'relay', localRelayProtocol: 'tls' }),
      ...pairRecords({ pairId: 'authoritative', selected: false, localType: 'host', remoteType: 'srflx' }),
    ])

    expect(classifySelectedIcePair(stats)).toEqual({
      route: 'direct',
      relayLeg: 'none',
      pairProtocol: 'udp',
      localTurnProtocol: 'not_applicable',
      candidateType: 'host',
      candidateProtocol: 'udp',
    })
  })

  it('does not fall back to selected=true when an authoritative pair id is present but incomplete', () => {
    const stats = report([
      ['transport', { id: 'transport', type: 'transport', selectedCandidatePairId: 'not-yet-visible' }],
      ...pairRecords({ pairId: 'stale', selected: true, localType: 'relay', localRelayProtocol: 'tls' }),
    ])
    expect(classifySelectedIcePair(stats)).toBeNull()
  })

  it('uses the legacy selected flag only when the transport pair id is absent', () => {
    const stats = report(pairRecords({ pairId: 'legacy', selected: true, localType: 'srflx', remoteType: 'host' }))
    expect(classifySelectedIcePair(stats)).toMatchObject({
      route: 'direct', relayLeg: 'none', pairProtocol: 'udp', localTurnProtocol: 'not_applicable',
    })
  })

  it.each([
    ['local', 'relay', 'host', 'local'],
    ['remote', 'host', 'relay', 'remote'],
    ['both', 'relay', 'relay', 'both'],
  ] as const)('classifies a %s relay leg without exposing candidate data', (_label, localType, remoteType, relayLeg) => {
    const stats = report([
      ['transport', { type: 'transport', selectedCandidatePairId: 'pair' }],
      ...pairRecords({
        localType,
        remoteType,
        localProtocol: 'tcp',
        remoteProtocol: 'tcp',
        localRelayProtocol: localType === 'relay' ? 'tls' : undefined,
        remoteRelayProtocol: remoteType === 'relay' ? 'tls' : undefined,
      }),
    ])
    const path = classifySelectedIcePair(stats)
    expect(path).toMatchObject({ route: 'relay', relayLeg, pairProtocol: 'tcp' })
    expect(JSON.stringify(path)).not.toMatch(/address|candidate:|relay\.example/i)
  })

  it('reports only browser-local TURN transport and never claims the remote relay transport', () => {
    const remoteRelay = classifySelectedIcePair(report([
      ['transport', { type: 'transport', selectedCandidatePairId: 'pair' }],
      ...pairRecords({
        localType: 'host',
        remoteType: 'relay',
        localProtocol: 'udp',
        remoteProtocol: 'udp',
        remoteRelayProtocol: 'tls',
      }),
    ]))
    expect(remoteRelay).toMatchObject({
      route: 'relay',
      relayLeg: 'remote',
      pairProtocol: 'udp',
      localTurnProtocol: 'not_applicable',
      candidateProtocol: 'udp',
    })

    const localRelay = classifySelectedIcePair(report([
      ['transport', { type: 'transport', selectedCandidatePairId: 'pair' }],
      ...pairRecords({
        localType: 'relay',
        remoteType: 'host',
        localProtocol: 'tcp',
        remoteProtocol: 'tcp',
        localRelayProtocol: 'tls',
      }),
    ]))
    expect(localRelay).toMatchObject({
      relayLeg: 'local', pairProtocol: 'tcp', localTurnProtocol: 'tls', candidateProtocol: 'tls',
    })
  })

  it('keeps the route and relay leg unknown until both candidate records have known types', () => {
    const path = classifySelectedIcePair(report([
      ['transport', { type: 'transport', selectedCandidatePairId: 'pair' }],
      ...pairRecords({ localType: 'host', remoteType: 'future-type' }),
    ]))
    expect(path).toMatchObject({ route: 'unknown', relayLeg: 'unknown', localTurnProtocol: 'not_applicable' })
  })
})
