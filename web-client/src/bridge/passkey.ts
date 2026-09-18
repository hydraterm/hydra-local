// ACCESS PASSKEY (#11) — the browser side of the WebAuthn-passkey-signed browser certificate.
//
// Two ceremonies:
//  1. REGISTER/REPLACE: the server issues the complete `navigator.credentials.create()` options and verifies
//     the returned attestation. Only authenticator evidence leaves the browser; trusted SPKI/algorithm/RP
//     metadata is derived server-side.
//  2. AUTHORIZE A BROWSER (any browser, at connect): `navigator.credentials.get()` signs a challenge equal to
//     SHA-256 of the certificate's canonical bytes, binding this browser's device public key to the target
//     desktop + account + an expiry. The assertion + claims travel to the desktop in the WebRTC offer.
//
// The canonical cert bytes here MUST match hydra-agent/src/browser_cert.rs::cert_signed_bytes byte-for-byte.

/** A browser certificate ready to embed in the WebRTC offer (`hydra_browser_cert`). Field names match the
 * agent's serde (snake_case). */
export interface BrowserCert {
  browser_pubkey: string
  desktop_id: string
  account_id: string
  expiry_ms: number
  nonce: string
  assertion: {
    authenticator_data: string // base64url
    client_data_json: string // base64url
    signature: string // base64url
  }
}

/** The account passkey descriptor the browser fetches from /v1/account/passkey (to target the get()). */
export interface PasskeyDescriptor {
  spkiB64: string
  alg: 'es256' | 'eddsa' | 'rs256'
  rpId: string
  credentialId: string // base64url
}

/** JSON-safe WebAuthn creation options returned by registration/recovery APIs. Binary members are base64url. */
export interface PasskeyRegistrationCreationOptions {
  challenge: string
  rp: { id: string; name: string }
  user: { id: string; name: string; displayName: string }
  pubKeyCredParams: { type: 'public-key'; alg: number }[]
  timeout?: number
  authenticatorSelection?: AuthenticatorSelectionCriteria
  attestation?: AttestationConveyancePreference
  excludeCredentials?: { type: 'public-key'; id: string; transports?: AuthenticatorTransport[] }[]
}

/** JSON-safe registration result sent to a completion endpoint. The server verifies and derives
 * the public key; the browser never claims a trusted algorithm/SPKI/RP id. */
export interface PasskeyRegistrationCredential {
  id: string
  rawId: string
  type: 'public-key'
  authenticatorAttachment?: string
  response: {
    clientDataJSON: string
    attestationObject: string
    transports?: string[]
  }
  clientExtensionResults: AuthenticationExtensionsClientOutputs
}

/** Server-issued options for the immediate signed possession assertion. The client adds exactly the
 * credential id returned by create() to allowCredentials; the server verifies all fields independently. */
export interface PasskeyPossessionProofOptions {
  challenge: string
  rpId: string
  timeout?: number
  userVerification: 'required'
  allowCredentials?: { type: 'public-key'; id: string; transports?: AuthenticatorTransport[] }[]
}

export interface PasskeyPossessionProof {
  id: string
  rawId: string
  type: 'public-key'
  authenticatorAttachment?: string
  response: {
    clientDataJSON: string
    authenticatorData: string
    signature: string
    userHandle?: string
  }
  clientExtensionResults: AuthenticationExtensionsClientOutputs
}

const CERT_TTL_MS = 30 * 60 * 1000 // browser certs are short-lived; the user re-authorizes when they lapse
const CERT_REUSE_MIN_REMAINING_MS = 5_000
const CERT_SESSION_MAX_BYTES = 64 * 1024
const CERT_FUTURE_CLOCK_TOLERANCE_MS = 60_000
const CERT_SESSION_PREFIX = 'hydra.remote.browser-cert.v1:'
const PASSKEY_REPLACEMENT_AUTHORIZATION_DOMAIN = 'hydra-passkey-replacement-authorization-v1\0'
const DESKTOP_ENROLLMENT_AUTHORIZATION_DOMAIN = 'hydra-desktop-enrollment-authorization-v1\0'
const BASE64URL = /^[A-Za-z0-9_-]+$/
const browserCertCache = new Map<string, BrowserCert>()
const browserCertInFlight = new Map<string, { promise: Promise<BrowserCert>; signal?: AbortSignal }>()
let browserCertCacheEpoch = 0

function browserCertCacheKey(input: {
  passkey: PasskeyDescriptor
  browserPubkey: string
  desktopId: string
  accountId: string
}): string {
  // Credential id is part of the trust anchor. A recovery/rotation must never reuse a certificate signed by
  // the old authenticator even when account, desktop, and browser key are unchanged.
  return `${input.accountId}\n${input.desktopId}\n${input.browserPubkey}\n${input.passkey.credentialId}`
}

function browserCertStorageKey(input: {
  passkey: PasskeyDescriptor
  browserPubkey: string
  desktopId: string
  accountId: string
}): string {
  // JSON preserves component boundaries (unlike delimiter escaping) and encodeURIComponent keeps the key
  // storage-safe. All four trust dimensions are explicit: account, desktop, browser key, and anchor credential.
  return `${CERT_SESSION_PREFIX}${encodeURIComponent(JSON.stringify([
    input.accountId,
    input.desktopId,
    input.browserPubkey,
    input.passkey.credentialId,
  ]))}`
}

function sessionCache(): Storage | null {
  try {
    return typeof sessionStorage === 'undefined' ? null : sessionStorage
  } catch {
    return null
  }
}

function boundedString(value: unknown, max = 16 * 1024): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= max
}

function structurallyValidCert(value: unknown): value is BrowserCert {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false
  const cert = value as Record<string, unknown>
  const assertion = cert.assertion
  if (!assertion || typeof assertion !== 'object' || Array.isArray(assertion)) return false
  const proof = assertion as Record<string, unknown>
  return (
    Object.keys(cert).every((key) =>
      ['browser_pubkey', 'desktop_id', 'account_id', 'expiry_ms', 'nonce', 'assertion'].includes(key)) &&
    Object.keys(proof).every((key) =>
      ['authenticator_data', 'client_data_json', 'signature'].includes(key)) &&
    boundedString(cert.browser_pubkey) &&
    boundedString(cert.desktop_id, 1024) &&
    boundedString(cert.account_id, 1024) &&
    Number.isSafeInteger(cert.expiry_ms) &&
    Number(cert.expiry_ms) > 0 &&
    boundedString(cert.nonce, 1024) &&
    boundedString(proof.authenticator_data) &&
    boundedString(proof.client_data_json) &&
    boundedString(proof.signature)
  )
}

function loadSessionCert(
  input: Parameters<typeof browserCertStorageKey>[0] & { nowMs: number },
): BrowserCert | null {
  const storage = sessionCache()
  if (!storage) return null
  const key = browserCertStorageKey(input)
  try {
    const raw = storage.getItem(key)
    if (!raw) return null
    if (raw.length > CERT_SESSION_MAX_BYTES) {
      storage.removeItem(key)
      return null
    }
    const parsed: unknown = JSON.parse(raw)
    if (
      !structurallyValidCert(parsed) ||
      parsed.account_id !== input.accountId ||
      parsed.desktop_id !== input.desktopId ||
      parsed.browser_pubkey !== input.browserPubkey ||
      parsed.expiry_ms <= input.nowMs + CERT_REUSE_MIN_REMAINING_MS ||
      parsed.expiry_ms > input.nowMs + CERT_TTL_MS + CERT_FUTURE_CLOCK_TOLERANCE_MS
    ) {
      storage.removeItem(key)
      return null
    }
    return parsed
  } catch {
    try { storage.removeItem(key) } catch {}
    return null
  }
}

function saveSessionCert(input: Parameters<typeof browserCertStorageKey>[0], cert: BrowserCert): void {
  const storage = sessionCache()
  if (!storage) return
  try {
    storage.setItem(browserCertStorageKey(input), JSON.stringify(cert))
  } catch {
    // Storage can be disabled or quota-limited. Memory reuse remains correct; persistence is an optimization.
  }
}

function clearSessionCerts(): void {
  const storage = sessionCache()
  if (!storage) return
  try {
    const keys: string[] = []
    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i)
      if (key?.startsWith(CERT_SESSION_PREFIX)) keys.push(key)
    }
    for (const key of keys) storage.removeItem(key)
  } catch {
    // Clearing an unavailable storage backend must not block sign-out/account reset.
  }
}

// ---- base64 / bytes helpers ----
function b64urlEncode(bytes: ArrayBuffer | Uint8Array): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let s = ''
  for (const b of u8) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function b64urlDecode(s: string): Uint8Array<ArrayBuffer> {
  const pad = s.replace(/-/g, '+').replace(/_/g, '/')
  const bin = atob(pad + '==='.slice((pad.length + 3) % 4))
  const u8 = new Uint8Array(new ArrayBuffer(bin.length))
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i)
  return u8
}

/** Derive the replacement-only assertion challenge independently of the cloud. This prevents an API response
 * from turning the current passkey prompt into a signing oracle for a browser certificate or another protocol. */
export async function passkeyReplacementAuthorizationChallenge(proofChallenge: string): Promise<string> {
  if (
    typeof proofChallenge !== 'string' ||
    proofChallenge.length === 0 ||
    proofChallenge.length > 1024 ||
    !BASE64URL.test(proofChallenge)
  ) {
    throw new Error('passkey: server returned an invalid replacement proof challenge')
  }
  const bytes = new TextEncoder().encode(`${PASSKEY_REPLACEMENT_AUTHORIZATION_DOMAIN}${proofChallenge}`)
  return b64urlEncode(await crypto.subtle.digest('SHA-256', bytes))
}

async function sha256Bytes(value: string): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))
}

/** Generate the browser-owned completion nonce. Keeping this independent of the cloud makes an exact completion
 * request retryable after response loss while the server stores no plaintext code or nonce. */
export function newDesktopEnrollmentCompletionNonce(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return b64urlEncode(bytes)
}

export async function desktopEnrollmentCompletionNonceHash(completionNonce: string): Promise<string> {
  if (!/^[A-Za-z0-9_-]{43}$/.test(completionNonce)) {
    throw new Error('passkey: invalid desktop enrollment completion nonce')
  }
  return Array.from(await sha256Bytes(completionNonce), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

/** Independently derive the Add Desktop assertion challenge. A cloud response is accepted only when it matches
 * this account-, credential-, generation-, purpose-, nonce-, and server-seed-bound value. */
export async function desktopEnrollmentAuthorizationChallenge(input: {
  accountId: string
  currentCredentialId: string
  currentGeneration: number
  intendedKind: 'desktop'
  completionNonceHash: string
  challengeSeed: string
}): Promise<string> {
  if (
    !input.accountId || input.accountId.includes('\0') ||
    !BASE64URL.test(input.currentCredentialId) || input.currentCredentialId.length > 1024 ||
    !Number.isSafeInteger(input.currentGeneration) || input.currentGeneration < 1 ||
    input.intendedKind !== 'desktop' ||
    !/^[0-9a-f]{64}$/.test(input.completionNonceHash) ||
    !/^[A-Za-z0-9_-]{43}$/.test(input.challengeSeed)
  ) {
    throw new Error('passkey: invalid desktop enrollment authorization context')
  }
  const canonical = `${DESKTOP_ENROLLMENT_AUTHORIZATION_DOMAIN}${input.accountId}\0` +
    `${input.currentCredentialId}\0${input.currentGeneration}\0${input.intendedKind}\0` +
    `${input.completionNonceHash}\0${input.challengeSeed}`
  return b64urlEncode(await sha256Bytes(canonical))
}

/** Run a server-issued WebAuthn creation ceremony, then serialize only the authenticator evidence needed for
 * server verification. Cancellation throws and causes no trust mutation. */
export async function createPasskeyRegistrationCredential(
  options: PasskeyRegistrationCreationOptions,
  signal?: AbortSignal,
): Promise<PasskeyRegistrationCredential> {
  const credential = await navigator.credentials.create({
    ...(signal ? { signal } : {}),
    publicKey: {
      ...options,
      challenge: b64urlDecode(options.challenge) as BufferSource,
      user: { ...options.user, id: b64urlDecode(options.user.id) as BufferSource },
      excludeCredentials: options.excludeCredentials?.map((item) => ({
        ...item,
        id: b64urlDecode(item.id) as BufferSource,
      })),
    },
  })
  if (!(credential instanceof PublicKeyCredential)) throw new Error('passkey: authenticator returned no credential')
  const response = credential.response as AuthenticatorAttestationResponse
  if (!response?.clientDataJSON || !response?.attestationObject) {
    throw new Error('passkey: authenticator returned an invalid registration response')
  }
  const transports = response.getTransports?.()
  return {
    id: credential.id,
    rawId: b64urlEncode(credential.rawId),
    type: 'public-key',
    ...(credential.authenticatorAttachment ? { authenticatorAttachment: credential.authenticatorAttachment } : {}),
    response: {
      clientDataJSON: b64urlEncode(response.clientDataJSON),
      attestationObject: b64urlEncode(response.attestationObject),
      ...(transports?.length ? { transports: [...transports] } : {}),
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  }
}

/** Prove possession of one exact credential. Initial setup uses this as a separate native ceremony for the key
 * returned by create(), preserving broad `fmt=none` compatibility; replacement also uses it to authorize with
 * the current anchor. Cancellation or an account AbortSignal stops before any completion request is sent. */
export async function provePasskeyRegistrationCredential(
  credentialId: string,
  options: PasskeyPossessionProofOptions,
  signal?: AbortSignal,
): Promise<PasskeyPossessionProof> {
  if (
    options.allowCredentials &&
    (options.allowCredentials.length !== 1 || options.allowCredentials[0]?.id !== credentialId)
  ) {
    throw new Error('passkey: server authorization options do not match the expected credential')
  }
  const allowCredentials = options.allowCredentials ?? [{ type: 'public-key' as const, id: credentialId }]
  const credential = await navigator.credentials.get({
    ...(signal ? { signal } : {}),
    publicKey: {
      challenge: b64urlDecode(options.challenge) as BufferSource,
      rpId: options.rpId,
      timeout: options.timeout,
      userVerification: 'required',
      allowCredentials: allowCredentials.map((item) => ({
        ...item,
        id: b64urlDecode(item.id) as BufferSource,
      })),
    },
  })
  if (!(credential instanceof PublicKeyCredential) || credential.id !== credentialId) {
    throw new Error('passkey: authenticator returned the wrong possession credential')
  }
  const response = credential.response as AuthenticatorAssertionResponse
  if (!response?.clientDataJSON || !response?.authenticatorData || !response?.signature) {
    throw new Error('passkey: authenticator returned an invalid possession proof')
  }
  return {
    id: credential.id,
    rawId: b64urlEncode(credential.rawId),
    type: 'public-key',
    ...(credential.authenticatorAttachment ? { authenticatorAttachment: credential.authenticatorAttachment } : {}),
    response: {
      clientDataJSON: b64urlEncode(response.clientDataJSON),
      authenticatorData: b64urlEncode(response.authenticatorData),
      signature: b64urlEncode(response.signature),
      ...(response.userHandle ? { userHandle: b64urlEncode(response.userHandle) } : {}),
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  }
}

/** Authorize replacement with the current anchor only after locally proving the server challenge is in Hydra's
 * replacement domain. No authenticator prompt occurs for a substituted cross-protocol challenge. */
export async function provePasskeyReplacementAuthorization(
  credentialId: string,
  authorizationOptions: PasskeyPossessionProofOptions,
  proofChallenge: string,
  signal?: AbortSignal,
): Promise<PasskeyPossessionProof> {
  throwIfAborted(signal)
  const expectedChallenge = await passkeyReplacementAuthorizationChallenge(proofChallenge)
  throwIfAborted(signal)
  if (authorizationOptions.challenge !== expectedChallenge) {
    throw new Error('passkey: server replacement authorization challenge is not domain separated')
  }
  return provePasskeyRegistrationCredential(credentialId, authorizationOptions, signal)
}

/** Prompt only after proving that the server-supplied challenge is the exact Add Desktop domain the browser
 * independently derived. This prevents a compromised cloud from repurposing the current passkey prompt. */
export async function proveDesktopEnrollmentAuthorization(
  expected: { accountId: string; credentialId: string; generation: number },
  authorizationOptions: PasskeyPossessionProofOptions,
  input: { completionNonceHash: string; challengeSeed: string },
  signal?: AbortSignal,
): Promise<PasskeyPossessionProof> {
  throwIfAborted(signal)
  const expectedChallenge = await desktopEnrollmentAuthorizationChallenge({
    accountId: expected.accountId,
    currentCredentialId: expected.credentialId,
    currentGeneration: expected.generation,
    intendedKind: 'desktop',
    completionNonceHash: input.completionNonceHash,
    challengeSeed: input.challengeSeed,
  })
  throwIfAborted(signal)
  if (authorizationOptions.challenge !== expectedChallenge) {
    throw new Error('passkey: server desktop enrollment challenge is not domain separated')
  }
  return provePasskeyRegistrationCredential(expected.credentialId, authorizationOptions, signal)
}

/** Compatibility aliases for older call sites while registration and recovery converge on one evidence shape. */
export type PasskeyRecoveryCreationOptions = PasskeyRegistrationCreationOptions
export type PasskeyRecoveryCredential = PasskeyRegistrationCredential
export const createPasskeyRecoveryCredential = createPasskeyRegistrationCredential

/** The canonical certificate bytes the WebAuthn challenge is SHA-256'd over — MUST match browser_cert.rs. */
export function certSignedBytes(
  browserPubkey: string,
  desktopId: string,
  accountId: string,
  expiryMs: number,
  nonce: string,
): Uint8Array {
  const s = `hydra-browser-cert-v1\n${browserPubkey}\n${desktopId}\n${accountId}\n${expiryMs}\n${nonce}`
  return new TextEncoder().encode(s)
}

/** Is WebAuthn available in this context? (Requires a secure context + a platform/roaming authenticator.) */
export function passkeySupported(): boolean {
  return (
    typeof window !== 'undefined' &&
    !!window.PublicKeyCredential &&
    typeof navigator !== 'undefined' &&
    !!navigator.credentials
  )
}

/**
 * AUTHORIZE this browser: run a WebAuthn assertion whose challenge binds the browser key to the desktop +
 * account, producing a browser certificate to embed in the offer. `passkey` is the account descriptor
 * (which credential to use). This low-level helper returns null if WebAuthn is unavailable or the user cancels;
 * the production authorization wrapper converts null to a fail-closed refusal.
 */
export async function mintBrowserCert(input: {
  passkey: PasskeyDescriptor
  browserPubkey: string
  desktopId: string
  accountId: string
  nowMs: number
  signal?: AbortSignal
  onUserInteractionStart?: () => void
  onUserInteractionEnd?: () => void
}): Promise<BrowserCert | null> {
  throwIfAborted(input.signal)
  if (!passkeySupported()) return null
  const expiryMs = input.nowMs + CERT_TTL_MS
  // A fresh random nonce per cert (anti-replay; also makes each assertion unique).
  const nonceBytes = new Uint8Array(16)
  crypto.getRandomValues(nonceBytes)
  const nonce = b64urlEncode(nonceBytes)
  // challenge = SHA-256 of the canonical cert bytes (the desktop recomputes + compares).
  const signedBytes = certSignedBytes(input.browserPubkey, input.desktopId, input.accountId, expiryMs, nonce)
  const challenge = new Uint8Array(await crypto.subtle.digest('SHA-256', signedBytes as BufferSource))
  let assertion: PublicKeyCredential
  input.onUserInteractionStart?.()
  try {
    assertion = (await navigator.credentials.get({
      ...(input.signal ? { signal: input.signal } : {}),
      publicKey: {
        rpId: input.passkey.rpId,
        challenge: challenge as BufferSource,
        allowCredentials: [{ type: 'public-key', id: b64urlDecode(input.passkey.credentialId) as BufferSource }],
        userVerification: 'required',
        timeout: 60_000,
      },
    })) as PublicKeyCredential
  } catch {
    return null // user cancelled / no authenticator; the production wrapper refuses authorization
  } finally {
    input.onUserInteractionEnd?.()
  }
  const r = assertion.response as AuthenticatorAssertionResponse
  return {
    browser_pubkey: input.browserPubkey,
    desktop_id: input.desktopId,
    account_id: input.accountId,
    expiry_ms: expiryMs,
    nonce,
    assertion: {
      authenticator_data: b64urlEncode(new Uint8Array(r.authenticatorData)),
      client_data_json: b64urlEncode(new Uint8Array(r.clientDataJSON)),
      signature: b64urlEncode(new Uint8Array(r.signature)),
    },
  }
}

/**
 * Authorize this browser for a passkey-protected desktop. A successful short-lived
 * certificate is reused while this page is alive, so switching between the terminal
 * and dashboard does not trigger another WebAuthn ceremony. Once the account has a
 * passkey, cancellation/unavailable WebAuthn is a refusal, never a legacy fallback.
 */
export async function authorizeBrowserWithPasskey(input: {
  passkey: PasskeyDescriptor
  browserPubkey: string
  desktopId: string
  accountId: string
  nowMs: number
  signal?: AbortSignal
  onUserInteractionStart?: () => void
  onUserInteractionEnd?: () => void
}): Promise<BrowserCert> {
  throwIfAborted(input.signal)
  const key = browserCertCacheKey(input)
  const cached = browserCertCache.get(key)
  if (cached && cached.expiry_ms > input.nowMs + CERT_REUSE_MIN_REMAINING_MS) return cached

  browserCertCache.delete(key)
  const persisted = loadSessionCert(input)
  if (persisted) {
    browserCertCache.set(key, persisted)
    return persisted
  }
  const existing = browserCertInFlight.get(key)
  if (existing && !existing.signal?.aborted) return existing.promise
  if (existing) browserCertInFlight.delete(key)

  // Clearing on sign-out/account switch invalidates even a native WebAuthn prompt that was already in flight.
  // The original caller may still receive its result, but it must never repopulate memory/session state afterward.
  const cacheEpoch = browserCertCacheEpoch
  const pending = (async (): Promise<BrowserCert> => {
    const cert = await mintBrowserCert(input)
    if (!cert) throw new Error('passkey authorization was cancelled or unavailable')
    // Some authenticators/browser versions may resolve an assertion even after their AbortSignal fired. Treat the
    // attempt owner as authoritative: a superseded ceremony must not repopulate either memory or session storage.
    throwIfAborted(input.signal)
    if (browserCertCacheEpoch === cacheEpoch) {
      browserCertCache.set(key, cert)
      saveSessionCert(input, cert)
    }
    return cert
  })()
  const entry = { promise: pending, ...(input.signal ? { signal: input.signal } : {}) }
  browserCertInFlight.set(key, entry)
  try {
    return await pending
  } finally {
    // Delete only our own promise; clearBrowserCertCache() or a later operation may have replaced the entry.
    if (browserCertInFlight.get(key) === entry) browserCertInFlight.delete(key)
  }
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted) throw new DOMException('Connection attempt was cancelled.', 'AbortError')
}

/** Test/logout hook: cached authorization must not survive an account-context reset. */
export function clearBrowserCertCache(): void {
  browserCertCacheEpoch++
  browserCertCache.clear()
  browserCertInFlight.clear()
  clearSessionCerts()
}
