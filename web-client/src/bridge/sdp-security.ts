export type SdpFingerprintValidation =
  | { ok: true }
  | { ok: false; reason: 'missing_sdp' | 'missing_fingerprint' | 'weak_fingerprint_algorithm' | 'bad_sha256_fingerprint' }
type SdpFingerprintFailureReason = Extract<SdpFingerprintValidation, { ok: false }>['reason']
export type SecureRemoteDescriptionValidation =
  | { ok: true; description: RTCSessionDescriptionInit }
  | { ok: false; reason: 'invalid_description' | 'wrong_type' | SdpFingerprintFailureReason }
type SecureRemoteDescriptionFailureReason = Extract<SecureRemoteDescriptionValidation, { ok: false }>['reason']
type AnswerProofFailureReason =
  | SecureRemoteDescriptionFailureReason
  | 'missing_answer_proof'
  | 'bad_answer_proof'
  | 'answer_proof_mismatch'
  | 'answer_proof_unsupported'
  | 'answer_proof_bad_signature'
export type AnswerProofValidation =
  | { ok: true; description: RTCSessionDescriptionInit }
  | { ok: false; reason: AnswerProofFailureReason }

const SHA256_FINGERPRINT = /^([0-9a-f]{2}:){31}[0-9a-f]{2}$/i
const ANSWER_PROOF_PURPOSE = 'hydra-webrtc-answer-v1'

/**
 * Browser WebRTC verifies the DTLS certificate against the SDP fingerprint during the handshake. This
 * preflight keeps the signaling boundary strict: no missing fingerprints, no legacy hashes, and no malformed
 * SHA-256 values reach setRemoteDescription().
 */
export function validateSdpFingerprint(description: Pick<RTCSessionDescriptionInit, 'sdp'>): SdpFingerprintValidation {
  if (typeof description.sdp !== 'string' || description.sdp.trim() === '') return { ok: false, reason: 'missing_sdp' }
  const fingerprints = [...description.sdp.matchAll(/^a=fingerprint:([A-Za-z0-9-]+)\s+([0-9A-Fa-f:]+)\s*$/gm)]
  if (fingerprints.length === 0) return { ok: false, reason: 'missing_fingerprint' }
  for (const [, algorithm, fingerprint] of fingerprints) {
    if (algorithm.toLowerCase() !== 'sha-256') return { ok: false, reason: 'weak_fingerprint_algorithm' }
    if (!SHA256_FINGERPRINT.test(fingerprint)) return { ok: false, reason: 'bad_sha256_fingerprint' }
  }
  return { ok: true }
}

export function validateSecureRemoteDescription(value: unknown): SecureRemoteDescriptionValidation {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return { ok: false, reason: 'invalid_description' }
  const raw = value as Record<string, unknown>
  if (raw.type !== 'answer') return { ok: false, reason: 'wrong_type' }
  const description: RTCSessionDescriptionInit = { type: 'answer', sdp: typeof raw.sdp === 'string' ? raw.sdp : undefined }
  const validation = validateSdpFingerprint(description)
  if (!validation.ok) return validation
  return { ok: true, description }
}

export function parseSecureRemoteDescription(json: string): RTCSessionDescriptionInit {
  const validation = validateSecureRemoteDescription(JSON.parse(json))
  if (!validation.ok) throw new Error(`insecure_sdp_${validation.reason}`)
  return validation.description
}

export function extractSha256Fingerprint(sdp: string): string | null {
  const fingerprints = [...sdp.matchAll(/^a=fingerprint:([A-Za-z0-9-]+)\s+([0-9A-Fa-f:]+)\s*$/gm)]
  for (const [, algorithm, fingerprint] of fingerprints) {
    if (algorithm.toLowerCase() === 'sha-256' && SHA256_FINGERPRINT.test(fingerprint)) {
      return fingerprint.toLowerCase()
    }
  }
  return null
}

export async function verifyAndParseRemoteDescription(
  json: string,
  expected?: {
    deviceId: string
    publicKeyB64?: string | null
    signalSessionId?: string | null
    /** LOCAL escape hatch (dev / genuinely-legacy desktops without an answer proof). Default false → FAIL
     * CLOSED: without the desktop's public key we cannot verify the answer proof, so we REFUSE rather than
     * trust a fingerprint-only answer the cloud could have substituted. Set true only in dev; a production
     * browser requires the desktop key. */
    allowUnverifiedDesktop?: boolean
  },
): Promise<RTCSessionDescriptionInit> {
  const raw = JSON.parse(json)
  const validation = validateSecureRemoteDescription(raw)
  if (!validation.ok) throw new Error(`insecure_sdp_${validation.reason}`)
  if (!expected) return validation.description
  const publicKeyB64 = expected?.publicKeyB64?.trim()
  if (!publicKeyB64) {
    // FAIL CLOSED: no pinned desktop key → we can't bind the agent identity to the DTLS fingerprint. Refuse
    // unless the caller explicitly allows an unverified desktop (dev/legacy). This stops a cloud from
    // stripping the desktop's answer proof and handing us a fingerprint-only answer.
    if (expected.allowUnverifiedDesktop) return validation.description
    throw new Error('insecure_sdp_desktop_key_required')
  }
  const proof = validateAnswerProof(raw, validation.description, expected.deviceId, expected.signalSessionId ?? null)
  if (!proof.ok) throw new Error(`insecure_sdp_${proof.reason}`)
  const ok = await verifyEd25519RawB64(
    publicKeyB64,
    `${ANSWER_PROOF_PURPOSE}:${proof.signalSessionId}:${proof.deviceId}:${proof.fingerprint}`,
    proof.signature,
  )
  if (!ok) throw new Error('insecure_sdp_answer_proof_bad_signature')
  return validation.description
}

function validateAnswerProof(
  raw: unknown,
  description: RTCSessionDescriptionInit,
  expectedDeviceId: string,
  expectedSignalSessionId: string | null,
): { ok: true; deviceId: string; signalSessionId: string; fingerprint: string; signature: string } | { ok: false; reason: AnswerProofFailureReason } {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { ok: false, reason: 'bad_answer_proof' }
  const proof = (raw as Record<string, unknown>).hydra_answer_proof
  if (!proof || typeof proof !== 'object' || Array.isArray(proof)) return { ok: false, reason: 'missing_answer_proof' }
  const p = proof as Record<string, unknown>
  const deviceId = typeof p.device_id === 'string' ? p.device_id : ''
  const signalSessionId = typeof p.signal_session_id === 'string' ? p.signal_session_id : ''
  const fingerprint = typeof p.fingerprint === 'string' ? p.fingerprint.toLowerCase() : ''
  const signature = typeof p.signature === 'string' ? p.signature : ''
  const actualFingerprint = typeof description.sdp === 'string' ? extractSha256Fingerprint(description.sdp) : null
  if (!deviceId || !signalSessionId || !fingerprint || !signature || p.version !== 1) return { ok: false, reason: 'bad_answer_proof' }
  if (deviceId !== expectedDeviceId) return { ok: false, reason: 'answer_proof_mismatch' }
  if (expectedSignalSessionId && signalSessionId !== expectedSignalSessionId) return { ok: false, reason: 'answer_proof_mismatch' }
  if (!actualFingerprint || fingerprint !== actualFingerprint) return { ok: false, reason: 'answer_proof_mismatch' }
  return { ok: true, deviceId, signalSessionId, fingerprint, signature }
}

async function verifyEd25519RawB64(publicKeyB64: string, message: string, signatureB64: string): Promise<boolean> {
  const subtle = globalThis.crypto?.subtle
  if (!subtle) throw new Error('insecure_sdp_answer_proof_unsupported')
  try {
    const key = await subtle.importKey('raw', exactBuffer(b64ToBytes(publicKeyB64)), { name: 'Ed25519' } as Algorithm, false, ['verify'])
    return await subtle.verify({ name: 'Ed25519' } as Algorithm, key, exactBuffer(b64ToBytes(signatureB64)), new TextEncoder().encode(message))
  } catch {
    throw new Error('insecure_sdp_answer_proof_unsupported')
  }
}

function exactBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer
}

function b64ToBytes(s: string): Uint8Array {
  const normalized = s.replace(/-/g, '+').replace(/_/g, '/')
  const raw = atob(normalized)
  const out = new Uint8Array(raw.length)
  for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i)
  return out
}
