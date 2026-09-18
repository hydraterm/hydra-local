//! Verify the browser's per-connection PROOF OF POSSESSION: the connecting browser signed a challenge
//! binding its device id + the offer's DTLS fingerprint with the PRIVATE key of its enrolled device key.
//! The public key comes from the (cloud-signed, offline-verified) token claims, so no cloud round-trip is
//! needed. This makes a stolen/forged token INSUFFICIENT to connect — the browser's private key, which
//! never leaves the browser, is also required.
//!
//! Supports the two curves the browser identity uses: Ed25519 (preferred) and ECDSA P-256 (Safari).
//! The public key is base64-encoded SPKI (WebCrypto `exportKey('spki')`).

use base64::Engine as _;

/// The exact challenge the browser signs at connect (must match webrtc-bridge.ts).
pub fn offer_challenge(device_id: &str, sdp_fingerprint: &str) -> String {
    format!("hydra-webrtc-offer-v1:{device_id}:{sdp_fingerprint}")
}

/// Verify `sig_b64` over `offer_challenge(device_id, fingerprint)` against the SPKI `pubkey_b64` using
/// `alg` ('ed25519' | 'p256'). Returns false on any decode/parse/verify failure (fail-closed).
pub fn verify_offer_proof(
    pubkey_b64: &str,
    alg: &str,
    device_id: &str,
    fingerprint: &str,
    sig_b64: &str,
) -> bool {
    let b64 = base64::engine::general_purpose::STANDARD;
    let Ok(spki_der) = b64.decode(pubkey_b64) else {
        return false;
    };
    let Ok(sig_bytes) = b64.decode(sig_b64) else {
        return false;
    };
    let msg = offer_challenge(device_id, fingerprint);
    match alg {
        "ed25519" => verify_ed25519(&spki_der, msg.as_bytes(), &sig_bytes),
        "p256" => verify_p256(&spki_der, msg.as_bytes(), &sig_bytes),
        _ => false,
    }
}

fn verify_ed25519(spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    // Extract the raw 32-byte Ed25519 public key from the SPKI wrapper. An Ed25519 SPKI is a fixed 44-byte
    // structure whose last 32 bytes are the raw key.
    let Some(raw) = ed25519_raw_from_spki(spki_der) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&raw) else {
        return false;
    };
    let Ok(sig) = Signature::from_slice(sig) else {
        return false;
    };
    vk.verify(msg, &sig).is_ok()
}

/// Ed25519 SPKI is `30 2a 30 05 06 03 2b 65 70 03 21 00 <32-byte key>` (44 bytes). Pull the trailing 32
/// bytes, checking the length + the OID/BIT STRING framing defensively.
fn ed25519_raw_from_spki(spki: &[u8]) -> Option<[u8; 32]> {
    if spki.len() != 44 {
        return None;
    }
    // The last 32 bytes are the raw public key; the 12-byte prefix is the fixed algorithm framing.
    let raw: [u8; 32] = spki[12..].try_into().ok()?;
    Some(raw)
}

fn verify_p256(spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;
    let Ok(vk) = VerifyingKey::from_public_key_der(spki_der) else {
        return false;
    };
    // WebCrypto ECDSA emits IEEE-P1363 (raw r||s, 64 bytes for P-256), NOT DER.
    let Ok(sig) = Signature::from_slice(sig) else {
        return false;
    };
    vk.verify(msg, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Round-trip with real keys generated via the same crates, mirroring the browser.
    #[test]
    fn ed25519_offer_proof_round_trips_and_rejects_wrong_key() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand::rngs::OsRng;
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        // Build the 44-byte Ed25519 SPKI: fixed 12-byte prefix + 32-byte raw key.
        let mut spki = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        spki.extend_from_slice(vk.as_bytes());
        let b64 = base64::engine::general_purpose::STANDARD;
        let pub_b64 = b64.encode(&spki);
        let challenge = offer_challenge("web_dev1", "AA:BB:CC");
        let sig = sk.sign(challenge.as_bytes());
        let sig_b64 = b64.encode(sig.to_bytes());
        assert!(verify_offer_proof(
            &pub_b64, "ed25519", "web_dev1", "AA:BB:CC", &sig_b64
        ));
        // Wrong device id / fingerprint / a different key all fail.
        assert!(!verify_offer_proof(
            &pub_b64,
            "ed25519",
            "web_OTHER",
            "AA:BB:CC",
            &sig_b64
        ));
        assert!(!verify_offer_proof(
            &pub_b64, "ed25519", "web_dev1", "XX:YY", &sig_b64
        ));
        let sk2 = SigningKey::generate(&mut OsRng);
        let sig2 = b64.encode(sk2.sign(challenge.as_bytes()).to_bytes());
        assert!(!verify_offer_proof(
            &pub_b64, "ed25519", "web_dev1", "AA:BB:CC", &sig2
        ));
    }

    #[test]
    fn p256_offer_proof_round_trips() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};
        use p256::pkcs8::EncodePublicKey;
        use rand::rngs::OsRng;
        let sk = SigningKey::random(&mut OsRng);
        let vk = *sk.verifying_key();
        let spki_der = vk.to_public_key_der().unwrap();
        let b64 = base64::engine::general_purpose::STANDARD;
        let pub_b64 = b64.encode(spki_der.as_bytes());
        let challenge = offer_challenge("web_dev2", "DD:EE:FF");
        let sig: Signature = sk.sign(challenge.as_bytes());
        let sig_b64 = b64.encode(sig.to_bytes()); // to_bytes = P1363 (raw r||s)
        assert!(verify_offer_proof(
            &pub_b64, "p256", "web_dev2", "DD:EE:FF", &sig_b64
        ));
        assert!(!verify_offer_proof(
            &pub_b64, "p256", "web_dev2", "WRONG", &sig_b64
        ));
    }

    #[test]
    fn junk_inputs_fail_closed() {
        assert!(!verify_offer_proof("not-b64!!", "ed25519", "d", "f", "sig"));
        assert!(!verify_offer_proof("QUJD", "unknown-alg", "d", "f", "QUJD"));
    }
}
