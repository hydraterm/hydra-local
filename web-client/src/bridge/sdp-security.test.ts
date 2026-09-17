import { describe, expect, it } from 'vitest'
import { generateKeyPairSync, sign } from 'node:crypto'
import { parseSecureRemoteDescription, validateSdpFingerprint, validateSecureRemoteDescription, verifyAndParseRemoteDescription } from './sdp-security'

const SHA256 = '11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:12:34:56:78:9A:BC:DE:F0:01:23:45:67:89:AB:CD:EF'

function answerWith(fingerprintLine: string): RTCSessionDescriptionInit {
  return {
    type: 'answer',
    sdp: [
      'v=0',
      'o=- 0 0 IN IP4 127.0.0.1',
      's=-',
      't=0 0',
      fingerprintLine,
      'm=application 9 UDP/DTLS/SCTP webrtc-datachannel',
    ].join('\r\n'),
  }
}

describe('SDP fingerprint security', () => {
  it('accepts a well-formed SHA-256 DTLS fingerprint from signaling', () => {
    expect(validateSdpFingerprint(answerWith(`a=fingerprint:sha-256 ${SHA256}`))).toEqual({ ok: true })
    expect(parseSecureRemoteDescription(JSON.stringify(answerWith(`a=fingerprint:sha-256 ${SHA256}`))).type).toBe('answer')
  })

  it('rejects non-answer or malformed remote descriptions before setRemoteDescription', () => {
    const validSdp = answerWith(`a=fingerprint:sha-256 ${SHA256}`).sdp

    expect(validateSecureRemoteDescription(null)).toEqual({ ok: false, reason: 'invalid_description' })
    expect(validateSecureRemoteDescription([])).toEqual({ ok: false, reason: 'invalid_description' })
    expect(validateSecureRemoteDescription({ type: 'offer', sdp: validSdp })).toEqual({
      ok: false,
      reason: 'wrong_type',
    })
    expect(validateSecureRemoteDescription({ type: 'answer' })).toEqual({ ok: false, reason: 'missing_sdp' })
    expect(() => parseSecureRemoteDescription(JSON.stringify({ type: 'offer', sdp: validSdp }))).toThrow(
      /insecure_sdp_wrong_type/,
    )
  })

  it('returns only the answer fields required by the browser remote-description API', () => {
    const parsed = parseSecureRemoteDescription(
      JSON.stringify({
        type: 'answer',
        sdp: answerWith(`a=fingerprint:sha-256 ${SHA256}`).sdp,
        candidate: 'not-an-sdp-field',
        secret: 'not-forwarded',
      }),
    )

    expect(parsed).toEqual({
      type: 'answer',
      sdp: answerWith(`a=fingerprint:sha-256 ${SHA256}`).sdp,
    })
  })

  it('rejects missing or weak fingerprints before setRemoteDescription can trust signaling', () => {
    expect(validateSdpFingerprint({ sdp: 'v=0\r\n' })).toEqual({ ok: false, reason: 'missing_fingerprint' })
    expect(validateSdpFingerprint(answerWith('a=fingerprint:sha-1 11:22'))).toEqual({ ok: false, reason: 'weak_fingerprint_algorithm' })
    expect(() => parseSecureRemoteDescription(JSON.stringify(answerWith('a=fingerprint:sha-384 11:22')))).toThrow(/insecure_sdp/)
  })

  it('rejects malformed SHA-256 fingerprints', () => {
    expect(validateSdpFingerprint(answerWith('a=fingerprint:sha-256 11:22'))).toEqual({ ok: false, reason: 'bad_sha256_fingerprint' })
  })

  it('verifies a device-signed answer fingerprint proof when a desktop public key is provided', async () => {
    const pair = generateKeyPairSync('ed25519')
    const publicKeyB64 = rawPublicKeyB64(pair.publicKey.export({ format: 'jwk' }) as JsonWebKey)
    const answer = answerWith(`a=fingerprint:sha-256 ${SHA256}`)
    const fingerprint = SHA256.toLowerCase()
    const signalSessionId = 'sig_1'
    const deviceId = 'dev_desk'
    const message = `hydra-webrtc-answer-v1:${signalSessionId}:${deviceId}:${fingerprint}`
    const signature = sign(null, Buffer.from(message), pair.privateKey).toString('base64')
    const parsed = await verifyAndParseRemoteDescription(
      JSON.stringify({
        ...answer,
        hydra_answer_proof: {
          version: 1,
          device_id: deviceId,
          signal_session_id: signalSessionId,
          fingerprint,
          signature,
        },
      }),
      { deviceId, signalSessionId, publicKeyB64 },
    )
    expect(parsed).toEqual(answer)
  })

  it('FAILS CLOSED when no desktop public key is pinned (cloud cannot strip the answer proof)', async () => {
    const answer = answerWith(`a=fingerprint:sha-256 ${SHA256}`)
    // expected present but publicKeyB64 null → refuse rather than trust a fingerprint-only answer
    await expect(
      verifyAndParseRemoteDescription(JSON.stringify(answer), { deviceId: 'dev_desk', publicKeyB64: null }),
    ).rejects.toThrow(/desktop_key_required/)
  })

  it('allows an unverified desktop ONLY with the explicit local dev/legacy opt-in', async () => {
    const answer = answerWith(`a=fingerprint:sha-256 ${SHA256}`)
    const parsed = await verifyAndParseRemoteDescription(JSON.stringify(answer), {
      deviceId: 'dev_desk',
      publicKeyB64: null,
      allowUnverifiedDesktop: true,
    })
    expect(parsed).toEqual(answer)
  })

  it('rejects a signed answer proof for the wrong signaling session', async () => {
    const pair = generateKeyPairSync('ed25519')
    const publicKeyB64 = rawPublicKeyB64(pair.publicKey.export({ format: 'jwk' }) as JsonWebKey)
    const answer = answerWith(`a=fingerprint:sha-256 ${SHA256}`)
    const signature = sign(
      null,
      Buffer.from(`hydra-webrtc-answer-v1:sig_other:dev_desk:${SHA256.toLowerCase()}`),
      pair.privateKey,
    ).toString('base64')
    await expect(
      verifyAndParseRemoteDescription(
        JSON.stringify({
          ...answer,
          hydra_answer_proof: {
            version: 1,
            device_id: 'dev_desk',
            signal_session_id: 'sig_other',
            fingerprint: SHA256.toLowerCase(),
            signature,
          },
        }),
        { deviceId: 'dev_desk', signalSessionId: 'sig_expected', publicKeyB64 },
      ),
    ).rejects.toThrow(/answer_proof_mismatch/)
  })

  it('rejects a missing answer proof when a desktop public key is known', async () => {
    const pair = generateKeyPairSync('ed25519')
    const publicKeyB64 = rawPublicKeyB64(pair.publicKey.export({ format: 'jwk' }) as JsonWebKey)
    await expect(
      verifyAndParseRemoteDescription(JSON.stringify(answerWith(`a=fingerprint:sha-256 ${SHA256}`)), {
        deviceId: 'dev_desk',
        signalSessionId: 'sig_1',
        publicKeyB64,
      }),
    ).rejects.toThrow(/missing_answer_proof/)
  })

  it('rejects a signed answer proof with a bad signature', async () => {
    const pair = generateKeyPairSync('ed25519')
    const other = generateKeyPairSync('ed25519')
    const publicKeyB64 = rawPublicKeyB64(pair.publicKey.export({ format: 'jwk' }) as JsonWebKey)
    const answer = answerWith(`a=fingerprint:sha-256 ${SHA256}`)
    const fingerprint = SHA256.toLowerCase()
    const signature = sign(
      null,
      Buffer.from(`hydra-webrtc-answer-v1:sig_1:dev_desk:${fingerprint}`),
      other.privateKey,
    ).toString('base64')
    await expect(
      verifyAndParseRemoteDescription(
        JSON.stringify({
          ...answer,
          hydra_answer_proof: {
            version: 1,
            device_id: 'dev_desk',
            signal_session_id: 'sig_1',
            fingerprint,
            signature,
          },
        }),
        { deviceId: 'dev_desk', signalSessionId: 'sig_1', publicKeyB64 },
      ),
    ).rejects.toThrow(/answer_proof_bad_signature|answer_proof_unsupported/)
  })
})

function rawPublicKeyB64(jwk: JsonWebKey): string {
  if (typeof jwk.x !== 'string') throw new Error('missing Ed25519 public key material')
  return Buffer.from(jwk.x, 'base64url').toString('base64')
}
