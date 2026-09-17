// Hydra control-plane domain types (S1). CLOSED schemas: only identity / device / link / token / audit
// fields exist. There is intentionally NO field anywhere that could carry terminal bytes, files, session
// output, a PTY stream, or any PRIVATE key. The cloud is content-blind by construction (N1).

/** Opaque account id from the managed-auth provider (we do NOT mint or store passwords/sessions). */
export type AccountId = string

/** A linked device (desktop, phone, laptop, or browser instance). */
export interface Device {
  deviceId: string
  accountId: AccountId
  /** Human label set at link time ("rk's phone"). Free text, but length-capped + scrubbed. */
  label: string
  /** The device's PUBLIC key (base64/hex). NEVER a private key — see assertPublicKeyMaterial. */
  publicKey: string
  /** Key algorithm for browser devices ('ed25519' | 'p256') so the agent can verify the offer PoP with the
   * right curve. Undefined for legacy/desktop records (treated as the desktop's ed25519 / raw path). */
  publicKeyAlg?: 'ed25519' | 'p256'
  kind: 'desktop' | 'mobile' | 'browser'
  createdAtMs: number
  /** Set when revoked; a revoked device is denied tokens + (later) has its live session cut. */
  revoked: boolean
  /** Last time the agent proved liveness via a SIGNED heartbeat — SERVER time, never client-claimed.
   * Undefined until the device has ever heartbeat. Honest presence only (no faked "online"). */
  lastSeenMs?: number
}

/** ACCESS PASSKEY (#11): the account's registered WebAuthn passkey PUBLIC key. The cloud STORES + RELAYS it
 * (to desktops at enrollment, and to browsers so they know which passkey to use) but holds NO passkey private
 * key — so it can relay a user-authorized browser certificate but cannot forge one. Content-blind: public key
 * material + metadata only. */
export type PasskeyAlgorithm = 'es256' | 'eddsa' | 'rs256'

export interface AccountPasskey {
  accountId: AccountId
  /** base64 (standard) SPKI DER of the passkey public key. */
  spkiB64: string
  /** COSE alg family: 'es256' (P-256) | 'eddsa' (Ed25519) | 'rs256' (RSA PKCS#1 v1.5/SHA-256). */
  alg: PasskeyAlgorithm
  /** The WebAuthn RP ID the passkey was registered for (e.g. "hydraterms.com"). */
  rpId: string
  /** The WebAuthn credential id (base64url), so the browser can target this passkey in the get() ceremony. */
  credentialId: string
  /** Monotonic account trust generation. Existing anchors migrate to 1; an atomic replacement increments it. */
  generation: number
  createdAtMs: number
}

/**
 * A short-lived, account-scoped passkey-replacement attempt. Completion also requires the current credential;
 * only hashes of the bearer id and WebAuthn challenges are persisted.
 */
export interface PasskeyRecoveryAttempt {
  recoveryIdHash: string
  accountId: AccountId
  challengeHash: string
  /** SHA-256 of the independent immediate assertion challenge; plaintext is returned only in options. */
  proofChallengeHash: string
  expectedCredentialId: string
  expectedGeneration: number
  createdAtMs: number
  expiresAtMs: number
  consumedAtMs?: number
  /** Exact verified completion request hash, retained only to make a lost-response retry idempotent. */
  completedResponseHash?: string
  completedGeneration?: number
  completedCredentialId?: string
  completedCreatedAtMs?: number
  completedRevokedDesktopCount?: number
}

/**
 * A short-lived, single-use initial passkey registration attempt. As with replacement, the plaintext bearer
 * id and WebAuthn challenge are returned once and only their SHA-256 hashes are persisted. Completion
 * metadata exists solely so one byte-identical retry can recover from a lost HTTP response.
 */
export interface PasskeyRegistrationAttempt {
  registrationIdHash: string
  accountId: AccountId
  challengeHash: string
  /** SHA-256 of the independent immediate assertion challenge; plaintext is returned only in options. */
  proofChallengeHash: string
  createdAtMs: number
  expiresAtMs: number
  consumedAtMs?: number
  completedResponseHash?: string
  completedCredentialId?: string
  completedCreatedAtMs?: number
  completedGeneration?: number
  completedRevokedDesktopCount?: number
}

/** Server-derived public passkey material ready to replace the current account anchor. */
export type ReplacementPasskey = Omit<AccountPasskey, 'accountId' | 'generation' | 'createdAtMs'>

/**
 * One short-lived authorization to issue a desktop enrollment code. The browser must prove the exact
 * account passkey generation captured here; only hashes of the bearer, WebAuthn challenge, client nonce,
 * completion request, and resulting link code are persisted.
 */
export interface DesktopEnrollmentAuthorizationAttempt {
  authorizationIdHash: string
  accountId: AccountId
  /** SHA-256 of the exact opaque Hydra session id or verified bearer that began the ceremony. */
  authoritySessionIdHash: string
  /** Authority epoch captured at the initial identity boundary; revocation at or after this instant wins. */
  authorityIssuedAtMs: number
  challengeHash: string
  completionNonceHash: string
  expectedCredentialId: string
  expectedGeneration: number
  intendedKind: 'desktop'
  createdAtMs: number
  expiresAtMs: number
  consumedAtMs?: number
  completedResponseHash?: string
  completedCodeHash?: string
  completedCodeExpiresAtMs?: number
}

/** A short-lived, single-use code shown on a desktop to LINK a new device to the account. */
export interface LinkCode {
  /** sha256 of the plaintext code — the plaintext is shown once and never stored. */
  codeHash: string
  accountId: AccountId
  /** The device kind this code is intended to link (optional hint). */
  intendedKind?: Device['kind']
  expiresAtMs: number
  /** Single-use: set when redeemed. */
  redeemed: boolean
  /** Every usable code is authorized by one exact account-passkey generation. Historical pre-v22 rows may
   * omit these fields only after the migration has permanently marked them redeemed. */
  authorizationIdHash?: string
  authorizedCredentialId?: string
  authorizedGeneration?: number
  authorityIssuedAtMs?: number
}

/**
 * The SHAPE of a minted per-device Hydra app-layer token. S1 only defines the contract — it does NOT
 * open a terminal session. The agent independently verifies the token (N2); the cloud never sees
 * terminal data as a result of minting one.
 */
export interface MintedToken {
  /** Opaque token string the device presents to the agent. Bound to a device + account. */
  token: string
  deviceId: string
  accountId: AccountId
  /** Server clock used for the signed iat_ms claim. Clients derive a TTL from this and expiresAtMs; they must
   * never compare either absolute server timestamp with an unsynchronized local wall clock. */
  issuedAtMs: number
  expiresAtMs: number
}

/** Append-only audit event for device/link/revoke/token actions. */
export interface AuditEvent {
  id: string
  accountId: AccountId
  atMs: number
  kind:
    | 'device.registered'
    | 'device.revoked'
    | 'device.self_revoked'
    | 'link.issued'
    | 'link.redeemed'
    | 'link.refused'
    | 'token.minted'
    | 'token.refused'
    | 'signal.created'
    | 'signal.answered'
    | 'signal.ice'
    | 'signal.cancelled'
    | 'signal.refused'
    | 'relay.minted'
    | 'relay.refused'
  /** Non-sensitive context (ids, kinds, reasons). NEVER terminal data, SDP/ICE bodies, or key material. */
  deviceId?: string
  detail?: string
}

/** A verified caller identity (from the managed-auth adapter). Identity only — no authority decisions. */
export interface Identity {
  accountId: AccountId
}

// ---- S3a signaling (content-blind WebRTC broker) ----------------------------------------------------
//
// CLOSED schema: offer/answer/candidate are OPAQUE signaling blobs (bounded strings), NOT terminal data.
// There is intentionally NO field that could carry terminal bytes/files/stdout/stderr/scrollback/
// keystrokes/commands/private keys. The cloud never parses these blobs — it store-and-forwards them.

export type SignalingStatus = 'pending' | 'answered' | 'cancelled' | 'expired'

/** One trickled ICE candidate (opaque blob) with a per-session monotonic sequence for the `since` cursor. */
export interface IceCandidateBlob {
  /** deviceId that sent it (source or target). */
  from: string
  /** Opaque ICE candidate string (size-capped). The cloud never parses it. */
  candidate: string
  /** Monotonic per-session sequence number (1-based). */
  seq: number
}

/** A signaling session brokering an offer/answer/ICE exchange between two same-account devices. */
export interface SignalingSession {
  sessionId: string
  accountId: AccountId
  sourceDeviceId: string
  targetDeviceId: string
  /** Opaque SDP offer (size-capped). */
  offer: string
  /** Opaque SDP answer (size-capped), set when the target answers. */
  answer?: string
  ice: IceCandidateBlob[]
  status: SignalingStatus
  createdAtMs: number
  updatedAtMs: number
  expiresAtMs: number
}

/** Session metadata without ICE children. Authorization/liveness checks must not hydrate the append-only
 * candidate stream merely to inspect account, parties, status, or expiry. */
export type SignalingSessionHeader = Omit<SignalingSession, 'ice'>

/** Exact target-inbox payload. The desktop needs only the source, opaque offer, and session lifetime to
 * decide whether to answer; ICE is fetched independently through its cursor endpoint. */
export type PendingOffer = Pick<
  SignalingSessionHeader,
  'sessionId' | 'sourceDeviceId' | 'offer' | 'createdAtMs' | 'expiresAtMs'
>

/** Peer-only ICE delta plus the authoritative global cursor for both parties. `nextSince` can advance even
 * when `candidates` is empty because the caller's own candidates also occupy the shared sequence. */
export interface PeerIceSince {
  candidates: IceCandidateBlob[]
  nextSince: number
}

/** One authoritative signaling read for the browser/source connect loop. The cloud still treats the answer and
 * candidate strings as bounded opaque blobs. Party/account fields are present only so the broker can enforce the
 * same fail-closed authorization as the legacy answer and ICE reads; the HTTP response omits them. */
export interface SignalingProgress {
  sessionId: string
  accountId: AccountId
  sourceDeviceId: string
  targetDeviceId: string
  status: SignalingStatus
  expiresAtMs: number
  /** Omitted once the exact caller reports that it installed the verified answer. */
  answer?: string
  candidates: IceCandidateBlob[]
  /** Authoritative maximum sequence across both parties, even when the peer delta is empty. */
  nextSince: number
}
