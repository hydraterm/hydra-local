import type {
  AccountId,
  AuditEvent,
  Device,
  IceCandidateBlob,
  PeerIceSince,
  PendingOffer,
  SignalingProgress,
  SignalingSession,
  SignalingSessionHeader,
  SignalingStatus,
} from './types.js'

/**
 * The SIGNALING sub-store — S3a WebRTC offer/answer/ICE store-and-forward (opaque blobs; the cloud never
 * parses SDP/ICE and stores no terminal data). Extracted so a focused adapter (Memory / Postgres) can back
 * just signaling. Sessions carry a TTL (expiresAtMs) enforced expire-on-read by the broker; a Postgres
 * adapter additionally GCs expired rows. NO terminal payload, NO tokens, NO private keys.
 */
export interface SignalingStore {
  createSession(s: SignalingSession): Promise<void>
  /** Legacy/full read retained for the browser answer endpoint. Avoid it for metadata-only checks. */
  getSession(sessionId: string): Promise<SignalingSession | null>
  /** Header-only read for liveness and party validation; never hydrates ICE. */
  getSessionHeader(sessionId: string): Promise<SignalingSessionHeader | null>
  /** Narrow pending offers addressed to `deviceId` within `accountId`, sorted by createdAtMs. */
  listPendingOffers(accountId: AccountId, deviceId: string): Promise<PendingOffer[]>
  /** Peer candidates after `since`, plus the max sequence across both parties in one consistent read. */
  getPeerIceSince(sessionId: string, callerDeviceId: string, since: number): Promise<PeerIceSince>
  /** Header/optional answer/peer ICE/global cursor in one authoritative snapshot. */
  getProgress(
    sessionId: string,
    callerDeviceId: string,
    since: number,
    answerSeen: boolean,
  ): Promise<SignalingProgress | null>
  setAnswer(sessionId: string, answer: string): Promise<void>
  setStatus(sessionId: string, status: SignalingStatus): Promise<void>
  /**
   * Atomically append one ICE blob under the session's shared quota. Exact retries are identified only by
   * `(sessionId, from, candidate)` and return the original sequence without consuming quota. Implementations
   * must serialize the duplicate check, quota check, sequence allocation, and insert for one session.
   */
  appendIce(
    sessionId: string,
    blob: Omit<IceCandidateBlob, 'seq'>,
    maxCandidates: number,
  ): Promise<AppendIceResult>
}

export type AppendIceResult =
  | { status: 'appended'; seq: number }
  | { status: 'existing'; seq: number }
  | { status: 'session_not_found' }
  | { status: 'too_many_candidates' }

/** Exact broker authority/storage surface. Device ownership and revocation are still checked by the broker;
 * implementations supply enrolled records and content-blind audit, never an identity or billing bypass. */
export interface SignalingBrokerStore extends SignalingStore {
  getDevice(deviceId: string): Promise<Device | null>
  appendAudit(event: AuditEvent): Promise<void>
}
