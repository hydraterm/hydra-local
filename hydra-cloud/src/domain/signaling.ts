// Content-blind WebRTC signaling broker. Relays OPAQUE offer/answer/ICE blobs between two enrolled,
// non-revoked, same-account devices. The cloud does not parse them and the shipped schema does not
// intentionally route terminal data; an authorized peer could still hide text inside these size-capped opaque
// fields. There is no peer connection, DataChannel, TURN termination, or terminal streaming here. See
// docs/architecture/remote.md.

import { randomUUID } from 'node:crypto'
import type { SignalingBrokerStore } from './signaling-ports.js'
import { ContentBlindViolation } from './content-blind.js'
import { systemClock, type Clock } from './clock.js'
import type {
  AccountId,
  AuditEvent,
  IceCandidateBlob,
  PendingOffer,
  SignalingSession,
  SignalingSessionHeader,
} from './types.js'
import {
  PENDING_OFFER_MAX_WAIT_MS,
  SIGNAL_PROGRESS_MAX_WAIT_MS,
  offerWakeKey,
  progressWakeKey,
  type SignalingWakeSource,
} from './offer-wake.js'

// Approved caps (S3a).
export const SESSION_TTL_MS = 2 * 60 * 1000 // 2 min
export const MAX_OFFER_BYTES = 16 * 1024
export const MAX_ANSWER_BYTES = 16 * 1024
export const MAX_ICE_BYTES = 2 * 1024
export const MAX_ICE_PER_SESSION = 128

/** Typed refusal reasons — mapped to bounded audit `detail` (never a body). */
export type SignalRefusal =
  | 'unauthenticated'
  | 'device_not_enrolled'
  | 'revoked'
  | 'cross_account'
  | 'not_a_party'
  | 'target_invalid'
  | 'session_not_found'
  | 'expired'
  | 'cancelled'
  | 'too_large'
  | 'too_many_candidates'
  | 'not_source'
  | 'target_mismatch'
  | 'source_invalid'

export interface SignalProgressReply {
  status: 'pending' | 'answered'
  expiresAtMs: number
  answer?: string
  candidates: Array<Pick<IceCandidateBlob, 'candidate' | 'seq'>>
  nextSince: number
}

export class SignalError extends Error {
  constructor(public readonly refusal: SignalRefusal) {
    super(`signal refused: ${refusal}`)
    this.name = 'SignalError'
  }
}

/** A blob value must be a bounded string with no private-key material (the request-level guard already
 * rejected forbidden FIELD names; this caps the VALUE size + re-checks for private-key PEM). */
function assertBlob(value: unknown, maxBytes: number): asserts value is string {
  if (typeof value !== 'string' || value.length === 0) throw new SignalError('too_large')
  if (Buffer.byteLength(value, 'utf8') > maxBytes) throw new SignalError('too_large')
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(value)) {
    throw new ContentBlindViolation('private-key material in signaling blob')
  }
}

export class SignalingBroker {
  constructor(
    private readonly store: SignalingBrokerStore,
    private readonly clock: Clock = systemClock,
    private readonly offerWake?: SignalingWakeSource,
    private readonly progressWake: SignalingWakeSource | undefined = offerWake,
  ) {}

  private async audit(e: Omit<AuditEvent, 'id' | 'atMs'>): Promise<void> {
    // NOTE: never include offer/answer/candidate bodies — metadata only.
    await this.store.appendAudit({ id: randomUUID(), atMs: this.clock.nowMs(), ...e })
  }

  /** A device is usable iff it exists, belongs to `accountId`, and is not revoked. */
  private async enrolledDevice(accountId: AccountId, deviceId: string) {
    const d = await this.store.getDevice(deviceId)
    if (!d) return null
    if (d.accountId !== accountId) return 'cross_account' as const
    if (d.revoked) return 'revoked' as const
    return d
  }

  /** Enforce live-ness on either a narrow header or the legacy full projection (expire on read). */
  private async requireLive<T extends Pick<SignalingSessionHeader, 'status' | 'expiresAtMs'>>(
    s: T | null,
    sessionId: string,
  ): Promise<T> {
    if (!s) throw new SignalError('session_not_found')
    if (s.status === 'cancelled') throw new SignalError('cancelled')
    if (s.status === 'expired' || this.clock.nowMs() >= s.expiresAtMs) {
      if (s.status !== 'expired') await this.store.setStatus(sessionId, 'expired')
      throw new SignalError('expired')
    }
    return s
  }

  /** Header-only liveness read for mutations, token binding, and ICE polling. */
  private async liveSessionHeader(sessionId: string): Promise<SignalingSessionHeader> {
    return this.requireLive(await this.store.getSessionHeader(sessionId), sessionId)
  }

  /** Legacy full read retained only where the endpoint contract returns the complete session. */
  private async liveSession(sessionId: string): Promise<SignalingSession> {
    return this.requireLive(await this.store.getSession(sessionId), sessionId)
  }

  /** Assert `deviceId` is a usable device of `accountId`; throws the right refusal otherwise. */
  private async requireUsableDevice(accountId: AccountId, deviceId: string) {
    const r = await this.enrolledDevice(accountId, deviceId)
    if (r === null) throw new SignalError('device_not_enrolled')
    if (r === 'cross_account') throw new SignalError('cross_account')
    if (r === 'revoked') throw new SignalError('revoked')
    return r
  }

  /** Assert `deviceId` is the session's source or target (party check). */
  private assertParty(
    s: Pick<SignalingSessionHeader, 'sourceDeviceId' | 'targetDeviceId'>,
    deviceId: string,
  ) {
    if (deviceId !== s.sourceDeviceId && deviceId !== s.targetDeviceId) {
      throw new SignalError('not_a_party')
    }
  }

  /**
   * Create a signaling session: the SOURCE posts an OFFER to a same-account TARGET. Both devices must be
   * enrolled + non-revoked. Returns the new session id + expiry.
   */
  async createSession(input: {
    accountId: AccountId
    sourceDeviceId: string
    targetDeviceId: string
    offer: string
  }): Promise<{ sessionId: string; expiresAtMs: number }> {
    if (input.sourceDeviceId === input.targetDeviceId) {
      await this.audit({ accountId: input.accountId, kind: 'signal.refused', detail: 'target_invalid' })
      throw new SignalError('target_invalid')
    }
    assertBlob(input.offer, MAX_OFFER_BYTES)
    // Remote desktop signaling has one closed direction: a proof-bearing browser source to a desktop target.
    // Device kind is server-stored authority, not a caller label. Requiring an explicit browser key algorithm
    // also excludes legacy/keyless rows from creating a connection that could later receive a keyless token.
    const source = await this.requireUsableDevice(input.accountId, input.sourceDeviceId)
    if (source.kind !== 'browser' || !source.publicKey ||
        (source.publicKeyAlg !== 'ed25519' && source.publicKeyAlg !== 'p256')) {
      await this.audit({
        accountId: input.accountId,
        kind: 'signal.refused',
        deviceId: input.sourceDeviceId,
        detail: 'source_invalid',
      })
      throw new SignalError('source_invalid')
    }
    try {
      const target = await this.requireUsableDevice(input.accountId, input.targetDeviceId)
      if (target.kind !== 'desktop') throw new SignalError('target_invalid')
    } catch (e) {
      await this.audit({
        accountId: input.accountId,
        kind: 'signal.refused',
        deviceId: input.targetDeviceId,
        detail: e instanceof SignalError ? `target_${e.refusal}` : 'target_invalid',
      })
      throw e instanceof SignalError ? new SignalError('target_invalid') : e
    }
    const now = this.clock.nowMs()
    const session: SignalingSession = {
      sessionId: `sig_${randomUUID()}`,
      accountId: input.accountId,
      sourceDeviceId: input.sourceDeviceId,
      targetDeviceId: input.targetDeviceId,
      offer: input.offer,
      ice: [],
      status: 'pending',
      createdAtMs: now,
      updatedAtMs: now,
      expiresAtMs: now + SESSION_TTL_MS,
    }
    await this.store.createSession(session)
    await this.audit({
      accountId: input.accountId,
      kind: 'signal.created',
      deviceId: input.sourceDeviceId,
      detail: session.sessionId,
    })
    return { sessionId: session.sessionId, expiresAtMs: session.expiresAtMs }
  }

  /** The TARGET fetches its pending offers (live only). */
  async pendingForTarget(accountId: AccountId, deviceId: string): Promise<PendingOffer[]> {
    await this.requireUsableDevice(accountId, deviceId)
    const all = await this.store.listPendingOffers(accountId, deviceId)
    const now = this.clock.nowMs()
    return all.filter((s) => now < s.expiresAtMs)
  }

  /**
   * Device-agent-only bounded long poll. A PostgreSQL notification is only a wake hint: the response is always
   * produced by `pendingForTarget`, including its current device/revocation authority check. Registering the
   * replica-local waiter before each query closes the commit/query race. Timeout returns empty; the agent's next
   * signed request is the bounded authoritative fallback for a notification lost during listener downtime.
   */
  async pendingForTargetWait(
    accountId: AccountId,
    deviceId: string,
    waitMs: number,
    signal?: AbortSignal,
  ): Promise<PendingOffer[]> {
    const boundedWaitMs = Math.max(0, Math.min(PENDING_OFFER_MAX_WAIT_MS, Math.trunc(waitMs)))
    if (signal?.aborted) return []
    if (boundedWaitMs === 0 || !this.offerWake) return this.pendingForTarget(accountId, deviceId)

    const key = offerWakeKey(accountId, deviceId)
    const deadline = performance.now() + boundedWaitMs
    while (!signal?.aborted) {
      const registration = this.offerWake.subscribe(key)
      // Install cancellation before the initial authoritative read. That read itself is not abortable, but the
      // bounded offer slot must be released immediately if the device request disappears while PostgreSQL is slow.
      const remainingMs = deadline - performance.now()
      const wake = registration.kind === 'subscribed'
        ? registration.subscription.wait(remainingMs, signal)
        : null
      let sessions: PendingOffer[]
      try {
        sessions = await this.pendingForTarget(accountId, deviceId)
      } catch (error) {
        if (registration.kind === 'subscribed') registration.subscription.close()
        if (signal?.aborted) return []
        throw error
      }
      if (sessions.length > 0 || signal?.aborted) {
        if (registration.kind === 'subscribed') registration.subscription.close()
        return signal?.aborted ? [] : sessions
      }
      if (registration.kind !== 'subscribed') return []

      if (remainingMs <= 0) {
        registration.subscription.close()
        return []
      }
      const outcome = await wake!
      if (outcome !== 'hint') return []
      // Subscribe again before querying so a second commit cannot land between this query and the next wait.
    }
    return []
  }

  /** Read a session (source or target). Enforces live-ness + party. */
  async getSession(accountId: AccountId, deviceId: string, sessionId: string): Promise<SignalingSession> {
    await this.requireUsableDevice(accountId, deviceId)
    const s = await this.liveSession(sessionId)
    if (s.accountId !== accountId) throw new SignalError('cross_account')
    this.assertParty(s, deviceId)
    return s
  }

  /**
   * Validate that a signaling session is a legitimate target for a token bound to it. Used at token-mint
   * time so the minted token's `signal_session_id` names a session that actually exists, belongs to this
   * account, was opened BY this browser (source) FOR the selected desktop (target), and is unexpired.
   * This is what the agent's fail-closed `signal_session_id` binding relies on being trustworthy. Throws a
   * SignalError on any mismatch. `sourceDeviceId` = the connecting browser, `targetDeviceId` = the desktop.
   */
  async validateSignalBinding(input: {
    accountId: AccountId
    sessionId: string
    sourceDeviceId: string
    targetDeviceId: string
  }): Promise<SignalingSessionHeader> {
    // Both token parties must still be enrolled, account-owned, and non-revoked at MINT time. createSession checked
    // the same conditions earlier, but either device can be revoked between session creation and this binding read.
    // In particular, never mint a browser token for a session whose target desktop was revoked in that gap.
    const source = await this.requireUsableDevice(input.accountId, input.sourceDeviceId)
    if (source.kind !== 'browser' || !source.publicKey ||
        (source.publicKeyAlg !== 'ed25519' && source.publicKeyAlg !== 'p256')) {
      throw new SignalError('source_invalid')
    }
    const target = await this.requireUsableDevice(input.accountId, input.targetDeviceId)
    if (target.kind !== 'desktop') throw new SignalError('target_invalid')
    // Header-only liveness enforces existence + not-expired/cancelled.
    const s = await this.liveSessionHeader(input.sessionId)
    if (s.accountId !== input.accountId) throw new SignalError('cross_account')
    // Exact role match — not just "a party". The token holder must be the session's SOURCE, and the session
    // must target the desktop the token authorizes access to. A party-only check would let the desktop's own
    // signature mint a source-scoped token, or bind a token to a session aimed at a different desktop.
    if (s.sourceDeviceId !== input.sourceDeviceId) throw new SignalError('not_source')
    if (s.targetDeviceId !== input.targetDeviceId) throw new SignalError('target_mismatch')
    return s
  }

  /** The TARGET posts the ANSWER. */
  async answer(input: {
    accountId: AccountId
    deviceId: string
    sessionId: string
    answer: string
  }): Promise<void> {
    assertBlob(input.answer, MAX_ANSWER_BYTES)
    await this.requireUsableDevice(input.accountId, input.deviceId)
    const s = await this.liveSessionHeader(input.sessionId)
    if (s.accountId !== input.accountId) throw new SignalError('cross_account')
    // only the TARGET may answer.
    if (input.deviceId !== s.targetDeviceId) throw new SignalError('not_a_party')
    await this.store.setAnswer(input.sessionId, input.answer)
    await this.audit({
      accountId: input.accountId,
      kind: 'signal.answered',
      deviceId: input.deviceId,
      detail: input.sessionId,
    })
  }

  /** Either party trickles one ICE candidate blob. Returns its seq. */
  async addIce(input: {
    accountId: AccountId
    deviceId: string
    sessionId: string
    candidate: string
  }): Promise<number> {
    assertBlob(input.candidate, MAX_ICE_BYTES)
    await this.requireUsableDevice(input.accountId, input.deviceId)
    const s = await this.liveSessionHeader(input.sessionId)
    if (s.accountId !== input.accountId) throw new SignalError('cross_account')
    this.assertParty(s, input.deviceId)
    // Candidate POSTs are retried when a response is lost. The store owns exact-tuple idempotency, the shared
    // quota, and sequence allocation in one atomic operation; a broker-side read/check would race across cloud
    // replicas. The candidate stays an opaque bounded string and is never logged.
    const appended = await this.store.appendIce(input.sessionId, {
      from: input.deviceId,
      candidate: input.candidate,
    }, MAX_ICE_PER_SESSION)
    if (appended.status === 'session_not_found') throw new SignalError('session_not_found')
    if (appended.status === 'too_many_candidates') throw new SignalError('too_many_candidates')
    if (appended.status === 'existing') return appended.seq
    await this.audit({
      accountId: input.accountId,
      kind: 'signal.ice',
      deviceId: input.deviceId,
      detail: input.sessionId,
    })
    return appended.seq
  }

  /**
   * Fetch the PEER's ICE candidates since `since` (exclusive). Returns only candidates from the OTHER
   * party (a device doesn't need its own back), newest cursor included.
   */
  async iceSince(input: {
    accountId: AccountId
    deviceId: string
    sessionId: string
    since: number
  }): Promise<{ candidates: IceCandidateBlob[]; nextSince: number }> {
    await this.requireUsableDevice(input.accountId, input.deviceId)
    const s = await this.liveSessionHeader(input.sessionId)
    if (s.accountId !== input.accountId) throw new SignalError('cross_account')
    this.assertParty(s, input.deviceId)
    return this.store.getPeerIceSince(input.sessionId, input.deviceId, input.since)
  }

  /** One content-blind source-progress read: liveness/party authorization, optional opaque answer, peer ICE, and
   * the shared cursor come from one store snapshot. The HTTP boundary removes the peer id because the caller
   * already knows which party supplied every returned candidate. */
  async progress(input: {
    accountId: AccountId
    deviceId: string
    sessionId: string
    since: number
    answerSeen: boolean
  }): Promise<SignalProgressReply> {
    await this.requireUsableDevice(input.accountId, input.deviceId)
    const snapshot = await this.requireLive(
      await this.store.getProgress(input.sessionId, input.deviceId, input.since, input.answerSeen),
      input.sessionId,
    )
    if (snapshot.accountId !== input.accountId) throw new SignalError('cross_account')
    this.assertParty(snapshot, input.deviceId)
    return {
      status: snapshot.status as 'pending' | 'answered',
      expiresAtMs: snapshot.expiresAtMs,
      ...(snapshot.answer !== undefined ? { answer: snapshot.answer } : {}),
      candidates: snapshot.candidates.map(({ candidate, seq }) => ({ candidate, seq })),
      nextSince: snapshot.nextSince,
    }
  }

  /** Bounded browser/peer progress wait. The digest notification is only a hint; every return value comes from
   * `progress`, which repeats current device, account, party, revocation, and session-liveness authority checks.
   * Subscribe-before-query closes the commit/query race. A timeout/listener loss performs one final authoritative
   * read so a commit whose hint was missed is visible without another client round trip. */
  async progressWait(input: {
    accountId: AccountId
    deviceId: string
    sessionId: string
    since: number
    answerSeen: boolean
    waitMs: number
    signal?: AbortSignal
  }): Promise<SignalProgressReply | null> {
    const boundedWaitMs = Math.max(0, Math.min(SIGNAL_PROGRESS_MAX_WAIT_MS, Math.trunc(input.waitMs)))
    const read = () => this.progress(input)
    if (input.signal?.aborted) return null
    if (boundedWaitMs === 0 || !this.progressWake) return read()

    const key = progressWakeKey(input.accountId, input.sessionId, input.deviceId)
    const deadline = performance.now() + boundedWaitMs
    let lastSnapshot: SignalProgressReply | null = null
    while (!input.signal?.aborted) {
      const registration = this.progressWake.subscribe(key)
      // Arm cancellation before starting the authoritative read. Pool acquisition/query latency is not abortable,
      // but a disconnected HTTP owner must release its bounded hub slot immediately instead of retaining capacity
      // until that read settles.
      const remainingMs = deadline - performance.now()
      const wake = registration.kind === 'subscribed'
        ? registration.subscription.wait(remainingMs, input.signal)
        : null
      try {
        lastSnapshot = await read()
      } catch (error) {
        if (registration.kind === 'subscribed') registration.subscription.close()
        if (input.signal?.aborted) return null
        throw error
      }
      if (input.signal?.aborted) {
        if (registration.kind === 'subscribed') registration.subscription.close()
        return null
      }
      if (hasProgressDelta(lastSnapshot, input.since)) {
        if (registration.kind === 'subscribed') registration.subscription.close()
        return lastSnapshot
      }
      if (registration.kind !== 'subscribed') return lastSnapshot

      if (remainingMs <= 0) {
        registration.subscription.close()
        if (input.signal?.aborted) return null
        const finalSnapshot = await read()
        return input.signal?.aborted ? null : finalSnapshot
      }
      const outcome = await wake!
      if (outcome === 'hint') continue
      if (outcome === 'aborted' || input.signal?.aborted) return null
      const finalSnapshot = await read()
      return input.signal?.aborted ? null : finalSnapshot
    }
    return null
  }

  /** Either party cancels the session early. */
  async cancel(accountId: AccountId, deviceId: string, sessionId: string): Promise<void> {
    await this.requireUsableDevice(accountId, deviceId)
    // Preserve cancellation's idempotent observable semantics: a present expired/cancelled row can still be
    // party-checked, set cancelled, and audited. Only the projection changes; cancellation never needs ICE.
    const s = await this.store.getSessionHeader(sessionId)
    if (!s) throw new SignalError('session_not_found')
    if (s.accountId !== accountId) throw new SignalError('cross_account')
    this.assertParty(s, deviceId)
    await this.store.setStatus(sessionId, 'cancelled')
    await this.audit({ accountId, kind: 'signal.cancelled', deviceId, detail: sessionId })
  }
}

function hasProgressDelta(progress: SignalProgressReply, since: number): boolean {
  return progress.answer !== undefined || progress.candidates.length > 0 || progress.nextSince > since
}
