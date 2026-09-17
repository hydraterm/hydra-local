import { SignalingBroker } from '@hydraterm/signaling-broker-core'
import type { SignalingBrokerStore } from '@hydraterm/signaling-broker-core/ports'
import type { AuditEvent, Device, SignalingSession, SignalingSessionHeader } from '@hydraterm/signaling-broker-core/types'

export function fixture() {
  let now = Date.now()
  const devices = new Map<string, Device>([
    ['browser', { deviceId: 'browser', accountId: 'synthetic-account', label: 'Synthetic browser',
      kind: 'browser', publicKey: 'synthetic-public-key', publicKeyAlg: 'p256', createdAtMs: now, revoked: false }],
    ['desktop', { deviceId: 'desktop', accountId: 'synthetic-account', label: 'Synthetic desktop',
      kind: 'desktop', publicKey: 'synthetic-desktop-public-key', createdAtMs: now, revoked: false }],
  ])
  const rows = new Map<string, SignalingSession>()
  const audits: AuditEvent[] = []
  const header = (row: SignalingSession): SignalingSessionHeader => {
    const { ice: _ice, ...rest } = row
    return rest
  }
  const peerIce = (row: SignalingSession, caller: string, since: number) => ({
    candidates: row.ice.filter((ice) => ice.from !== caller && ice.seq > since),
    nextSince: row.ice.at(-1)?.seq ?? 0,
  })
  // A complete independent 11-method adapter: no hosted Store, auth, billing or enrollment implementation.
  const store: SignalingBrokerStore = {
    getDevice: async (id) => devices.get(id) ?? null,
    appendAudit: async (event) => { audits.push(event) },
    createSession: async (row) => { rows.set(row.sessionId, row) },
    getSession: async (id) => rows.get(id) ?? null,
    getSessionHeader: async (id) => rows.has(id) ? header(rows.get(id)!) : null,
    listPendingOffers: async (account, target) => [...rows.values()]
      .filter((row) => row.accountId === account && row.targetDeviceId === target && row.status === 'pending')
      .sort((a, b) => a.createdAtMs - b.createdAtMs)
      .map(({ sessionId, sourceDeviceId, offer, createdAtMs, expiresAtMs }) =>
        ({ sessionId, sourceDeviceId, offer, createdAtMs, expiresAtMs })),
    getPeerIceSince: async (id, caller, since) => peerIce(rows.get(id)!, caller, since),
    getProgress: async (id, caller, since, answerSeen) => {
      const row = rows.get(id)
      if (!row) return null
      return {
        sessionId: id, accountId: row.accountId, sourceDeviceId: row.sourceDeviceId,
        targetDeviceId: row.targetDeviceId, status: row.status, expiresAtMs: row.expiresAtMs,
        ...(!answerSeen && row.answer !== undefined ? { answer: row.answer } : {}),
        ...peerIce(row, caller, since),
      }
    },
    setAnswer: async (id, answer) => { Object.assign(rows.get(id)!, { answer, status: 'answered', updatedAtMs: now }) },
    setStatus: async (id, status) => { Object.assign(rows.get(id)!, { status, updatedAtMs: now }) },
    appendIce: async (id, blob, max) => {
      const row = rows.get(id)
      if (!row) return { status: 'session_not_found' }
      const prior = row.ice.find((ice) => ice.from === blob.from && ice.candidate === blob.candidate)
      if (prior) return { status: 'existing', seq: prior.seq }
      if (row.ice.length >= max) return { status: 'too_many_candidates' }
      const seq = (row.ice.at(-1)?.seq ?? 0) + 1
      row.ice.push({ ...blob, seq })
      return { status: 'appended', seq }
    },
  }
  const broker = new SignalingBroker(store, { nowMs: () => now })
  return { store, broker, devices, audits, advance: (ms: number) => { now += ms } }
}
