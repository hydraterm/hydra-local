//! ACCESS PASSKEY (#11) — verify a WebAuthn-passkey-signed BROWSER CERTIFICATE.
//!
//! Problem this solves: the browser proof-of-possession (browser_pop.rs) proves the CONNECTING browser holds
//! the private key the CLOUD selected in the token. But the cloud chooses that key — a compromised cloud (or
//! a stolen cloud signing key) could mint a token naming an ATTACKER's browser key and connect. The cloud is
//! therefore still trusted to authorize browsers.
//!
//! The fix: at desktop enrollment the user registers a WebAuthn PASSKEY (Touch ID / phone / security key)
//! and the desktop stores its PUBLIC key locally. To authorize a NEW browser (e.g. one at school, remotely,
//! with nobody at home), the user performs a WebAuthn ceremony that signs a certificate binding the browser's
//! public key to THIS desktop + account + an expiry. The desktop verifies that certificate DIRECTLY against
//! the stored passkey public key — the cloud only relays it and CANNOT forge it (it has no passkey private
//! key). So a compromised cloud can no longer invent an authorized browser.
//!
//! WebAuthn constraint: an authenticator only signs `authenticatorData || SHA256(clientDataJSON)` during a
//! `navigator.credentials.get()` assertion, where the app-chosen challenge lives inside clientDataJSON. So
//! the certificate's canonical bytes ARE the challenge: `challenge = base64url(SHA256(cert_signed_bytes))`.
//! The desktop recomputes that hash, checks it equals the assertion's clientData challenge, then verifies the
//! assertion signature against the passkey public key.

use base64::Engine as _;
use sha2::{Digest, Sha256};

/// base64url no-pad — the encoding WebAuthn uses for clientDataJSON's `challenge`.
fn b64url() -> base64::engine::general_purpose::GeneralPurpose {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
}

/// A passkey public key the desktop pinned at enrollment. Accepted COSE algorithms are -7 = ES256 (P-256),
/// -8 = EdDSA (Ed25519), and -257 = RS256 (RSA PKCS#1 v1.5 with SHA-256).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PasskeyPublicKey {
    /// base64 (standard) SPKI DER of the passkey public key. The web side exports it once at registration.
    pub spki_b64: String,
    /// "es256" | "eddsa" | "rs256" — which verifier to use.
    pub alg: String,
    /// The WebAuthn RP ID the passkey was registered for (e.g. "hydraterms.com"). The assertion's
    /// authenticatorData carries SHA256(rpId); we check it matches so a passkey minted for another RP can't be
    /// replayed here.
    pub rp_id: String,
}

/// The certificate the browser presents: the signed CLAIMS + the WebAuthn assertion over them. The claims are
/// exactly the bytes the challenge hashes; changing any field invalidates the assertion.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BrowserCert {
    /// The browser device public key this cert authorizes (base64 SPKI, matches the token's browser_pubkey).
    pub browser_pubkey: String,
    /// Which desktop this cert authorizes access to (must equal this agent's device id).
    pub desktop_id: String,
    /// The account the cert is scoped to (must equal the token's account_id).
    pub account_id: String,
    /// Unix ms after which the cert is invalid (short-lived; the user re-authorizes when it lapses).
    pub expiry_ms: u64,
    /// Anti-replay nonce (opaque; the browser fills it, we only fold it into the signed bytes).
    pub nonce: String,
    /// The WebAuthn assertion authorizing the above.
    pub assertion: WebauthnAssertion,
}

/// The WebAuthn `navigator.credentials.get()` result, base64url-encoded on the wire.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WebauthnAssertion {
    /// base64url authenticatorData.
    pub authenticator_data: String,
    /// base64url clientDataJSON (UTF-8 JSON: {type, challenge, origin, ...}).
    pub client_data_json: String,
    /// base64url signature over `authenticatorData || SHA256(clientDataJSON)` in the selected algorithm's
    /// WebAuthn encoding (DER ECDSA, raw Ed25519, or fixed-width RSA).
    pub signature: String,
}

/// Why a browser cert was rejected. All map to a fail-closed refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertError {
    Expired,
    ExpiryTooFar, // expiry is further out than the allowed max TTL (a relayed far-future cert)
    BindingMismatch, // browser_pubkey / desktop_id / account_id don't match the token / this desktop
    BadChallenge, // clientData challenge != hash of the cert claims (cert was tampered / not what was signed)
    BadClientData, // clientDataJSON not the expected webauthn.get shape
    BadOrigin,    // origin is not allowed, or the client-data context is not strictly same-origin
    BadRpId,      // authenticatorData rpIdHash != SHA256(passkey.rp_id)
    UserNotPresent, // WebAuthn UP flag not set
    UserNotVerified, // WebAuthn UV flag not set (we require user verification)
    BadSignature, // assertion signature doesn't verify against the passkey public key
    Malformed,    // base64 / structure decode failure
}

/// Verification policy — the origin allowlist + the max cert TTL, so the exact strings live at the call site
/// (the agent) rather than baked into this crypto module. `max_ttl_ms` bounds how far in the future `expiry_ms`
/// may be (measured from `now_ms`), so a compromised cloud can't relay a far-future cert.
#[derive(Debug, Clone)]
pub struct CertPolicy {
    /// Exact allowed WebAuthn origins, e.g. ["https://app.hydraterms.com"].
    pub allowed_origins: Vec<String>,
    /// Max allowed (expiry_ms - now_ms). A small clock tolerance should be included by the caller.
    pub max_ttl_ms: u64,
}

/// The canonical bytes the WebAuthn challenge is computed over. MUST match the web side byte-for-byte. Simple,
/// stable, delimiter-joined (the fields are ids/base64/decimal — none contain `\n`).
pub fn cert_signed_bytes(
    browser_pubkey: &str,
    desktop_id: &str,
    account_id: &str,
    expiry_ms: u64,
    nonce: &str,
) -> Vec<u8> {
    format!(
        "hydra-browser-cert-v1\n{browser_pubkey}\n{desktop_id}\n{account_id}\n{expiry_ms}\n{nonce}"
    )
    .into_bytes()
}

/// Verify `cert` authorizes `expected_browser_pubkey` for `this_desktop_id` / `expected_account` at `now_ms`,
/// signed by `passkey`. Fail-closed: any decode/parse/verify/binding failure returns Err. On success the
/// caller may trust the browser INDEPENDENTLY of the cloud.
pub fn verify_browser_cert(
    cert: &BrowserCert,
    passkey: &PasskeyPublicKey,
    expected_browser_pubkey: &str,
    this_desktop_id: &str,
    expected_account: &str,
    now_ms: u64,
    policy: &CertPolicy,
) -> Result<(), CertError> {
    // 1. Binding: the cert must authorize THIS browser key, THIS desktop, THIS account.
    if cert.browser_pubkey != expected_browser_pubkey
        || cert.desktop_id != this_desktop_id
        || cert.account_id != expected_account
    {
        return Err(CertError::BindingMismatch);
    }
    // 2. Freshness — expired, AND not further out than the allowed max TTL (a relayed far-future cert).
    if now_ms >= cert.expiry_ms {
        return Err(CertError::Expired);
    }
    if cert.expiry_ms.saturating_sub(now_ms) > policy.max_ttl_ms {
        return Err(CertError::ExpiryTooFar);
    }

    // 3. Decode the assertion parts.
    let url = b64url();
    let auth_data = url
        .decode(&cert.assertion.authenticator_data)
        .map_err(|_| CertError::Malformed)?;
    let client_data = url
        .decode(&cert.assertion.client_data_json)
        .map_err(|_| CertError::Malformed)?;
    let sig = url
        .decode(&cert.assertion.signature)
        .map_err(|_| CertError::Malformed)?;

    // 4. clientDataJSON: must be a webauthn.get, with challenge == base64url(SHA256(cert_signed_bytes)), an
    //    origin in the allowlist, and a strictly same-origin context (a ceremony from our app only).
    let cdj: serde_json::Value =
        serde_json::from_slice(&client_data).map_err(|_| CertError::BadClientData)?;
    if cdj.get("type").and_then(|v| v.as_str()) != Some("webauthn.get") {
        return Err(CertError::BadClientData);
    }
    let expected_challenge = url.encode(Sha256::digest(cert_signed_bytes(
        &cert.browser_pubkey,
        &cert.desktop_id,
        &cert.account_id,
        cert.expiry_ms,
        &cert.nonce,
    )));
    match cdj.get("challenge").and_then(|v| v.as_str()) {
        Some(c) if c == expected_challenge => {}
        _ => return Err(CertError::BadChallenge),
    }
    // Origin must be one of ours (blocks a passkey ceremony run on an attacker-controlled page).
    let origin = cdj.get("origin").and_then(|v| v.as_str()).unwrap_or("");
    if !policy.allowed_origins.iter().any(|o| o == origin) {
        return Err(CertError::BadOrigin);
    }
    // crossOrigin, when present, MUST be the boolean false. A malformed value must not be treated like an
    // absent flag. topOrigin is emitted for embedded cross-origin ceremonies and is never expected for Hydra's
    // top-level same-origin flow, even if a caller forged crossOrigin=false. Keep this fail-closed contract in
    // sync with hydra-cloud's passkey registration/recovery verifier.
    if !matches!(
        cdj.get("crossOrigin"),
        None | Some(serde_json::Value::Bool(false))
    ) || cdj.get("topOrigin").is_some()
    {
        return Err(CertError::BadOrigin);
    }

    // 5. authenticatorData: rpIdHash (first 32 bytes) must equal SHA256(rp_id); UP + UV flags set.
    if auth_data.len() < 37 {
        return Err(CertError::Malformed);
    }
    let rp_id_hash = &auth_data[0..32];
    if rp_id_hash != Sha256::digest(passkey.rp_id.as_bytes()).as_slice() {
        return Err(CertError::BadRpId);
    }
    let flags = auth_data[32];
    if flags & 0x01 == 0 {
        return Err(CertError::UserNotPresent);
    }
    // UV (bit 2): we require user verification (biometric/PIN), not just presence — the browser requests
    // userVerification:'required', and we ENFORCE it here so the cloud can't relay a UV=0 assertion.
    if flags & 0x04 == 0 {
        return Err(CertError::UserNotVerified);
    }

    // 6. Verify the signature over `authenticatorData || SHA256(clientDataJSON)` against the passkey pubkey.
    let mut signed = auth_data.clone();
    signed.extend_from_slice(Sha256::digest(&client_data).as_slice());
    let spki_der = base64::engine::general_purpose::STANDARD
        .decode(&passkey.spki_b64)
        .map_err(|_| CertError::Malformed)?;
    let ok = match passkey.alg.as_str() {
        "es256" => verify_es256(&spki_der, &signed, &sig),
        "eddsa" => verify_eddsa(&spki_der, &signed, &sig),
        "rs256" => verify_rs256(&spki_der, &signed, &sig),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(CertError::BadSignature)
    }
}

/// ES256 (P-256 ECDSA over SHA-256). WebAuthn ES256 signatures are DER-encoded (unlike our browser PoP, which
/// is P1363) — accept DER, and fall back to raw P1363 defensively.
fn verify_es256(spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use p256::ecdsa::{signature::Verifier, DerSignature, Signature, VerifyingKey};
    use p256::pkcs8::DecodePublicKey;
    let Ok(vk) = VerifyingKey::from_public_key_der(spki_der) else {
        return false;
    };
    if let Ok(der) = DerSignature::try_from(sig) {
        if vk.verify(msg, &der).is_ok() {
            return true;
        }
    }
    if let Ok(p1363) = Signature::from_slice(sig) {
        return vk.verify(msg, &p1363).is_ok();
    }
    false
}

/// EdDSA (Ed25519). The 32-byte raw key is the trailing 32 bytes of the 44-byte Ed25519 SPKI.
fn verify_eddsa(spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    if spki_der.len() != 44 {
        return false;
    }
    let Ok(raw): Result<[u8; 32], _> = spki_der[12..].try_into() else {
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

/// RS256: RSA PKCS#1 v1.5 with SHA-256. The pinned key is a standard SubjectPublicKeyInfo DER value whose
/// algorithm must be `rsaEncryption`; its BIT STRING contains the PKCS#1 `RSAPublicKey` consumed by ring.
/// ring's selected verifier rejects moduli outside 2048–8192 bits as well as malformed DER/signatures.
fn verify_rs256(spki_der: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    const RSA_ENCRYPTION_OID: spki::ObjectIdentifier =
        spki::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

    let Ok(public_key) = spki::SubjectPublicKeyInfoRef::try_from(spki_der) else {
        return false;
    };
    if public_key.algorithm.oid != RSA_ENCRYPTION_OID
        || public_key
            .algorithm
            .parameters
            .is_some_and(|parameters| !parameters.is_null())
    {
        return false;
    }
    let Some(pkcs1_der) = public_key.subject_public_key.as_bytes() else {
        return false;
    };

    ring::signature::UnparsedPublicKey::new(&ring::signature::RSA_PKCS1_2048_8192_SHA256, pkcs1_der)
        .verify(msg, sig)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build a self-consistent ES256 passkey + a valid assertion over a cert, mirroring what the browser's
    // WebAuthn ceremony produces, so we exercise the FULL verify path with real crypto.
    fn make_es256_cert_with_origin_and_context(
        browser_pubkey: &str,
        desktop_id: &str,
        account_id: &str,
        expiry_ms: u64,
        rp_id: &str,
        origin: &str,
        context: serde_json::Map<String, serde_json::Value>,
    ) -> (PasskeyPublicKey, BrowserCert) {
        use p256::ecdsa::{signature::Signer, DerSignature, SigningKey};
        use p256::pkcs8::EncodePublicKey;
        use rand::rngs::OsRng;
        let sk = SigningKey::random(&mut OsRng);
        let vk = *sk.verifying_key();
        let spki = vk.to_public_key_der().unwrap();
        let spki_b64 = base64::engine::general_purpose::STANDARD.encode(spki.as_bytes());
        let passkey = PasskeyPublicKey {
            spki_b64,
            alg: "es256".into(),
            rp_id: rp_id.into(),
        };
        let nonce = "nonce-123";
        // challenge = base64url(SHA256(cert_signed_bytes))
        let url = b64url();
        let challenge = url.encode(Sha256::digest(cert_signed_bytes(
            browser_pubkey,
            desktop_id,
            account_id,
            expiry_ms,
            nonce,
        )));
        let mut client_data = serde_json::Map::from_iter([
            (
                "type".to_string(),
                serde_json::Value::String("webauthn.get".to_string()),
            ),
            (
                "challenge".to_string(),
                serde_json::Value::String(challenge),
            ),
            (
                "origin".to_string(),
                serde_json::Value::String(origin.to_string()),
            ),
        ]);
        client_data.extend(context);
        let client_data = serde_json::to_vec(&client_data).unwrap();
        // authenticatorData: SHA256(rpId) || flags(UP=1, UV=1) || counter(4 bytes)
        let mut auth_data = Sha256::digest(rp_id.as_bytes()).to_vec();
        auth_data.push(0x05); // UP (bit 0) + UV (bit 2) set
        auth_data.extend_from_slice(&[0, 0, 0, 1]);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(Sha256::digest(&client_data).as_slice());
        let der: DerSignature = sk.sign(&signed);
        let assertion = WebauthnAssertion {
            authenticator_data: url.encode(&auth_data),
            client_data_json: url.encode(&client_data),
            signature: url.encode(der.as_bytes()),
        };
        let cert = BrowserCert {
            browser_pubkey: browser_pubkey.into(),
            desktop_id: desktop_id.into(),
            account_id: account_id.into(),
            expiry_ms,
            nonce: nonce.into(),
            assertion,
        };
        (passkey, cert)
    }

    fn make_es256_cert_with_context(
        browser_pubkey: &str,
        desktop_id: &str,
        account_id: &str,
        expiry_ms: u64,
        rp_id: &str,
        context: serde_json::Map<String, serde_json::Value>,
    ) -> (PasskeyPublicKey, BrowserCert) {
        make_es256_cert_with_origin_and_context(
            browser_pubkey,
            desktop_id,
            account_id,
            expiry_ms,
            rp_id,
            "https://app.hydraterms.com",
            context,
        )
    }

    fn make_es256_cert(
        browser_pubkey: &str,
        desktop_id: &str,
        account_id: &str,
        expiry_ms: u64,
        rp_id: &str,
    ) -> (PasskeyPublicKey, BrowserCert) {
        make_es256_cert_with_context(
            browser_pubkey,
            desktop_id,
            account_id,
            expiry_ms,
            rp_id,
            serde_json::Map::from_iter([(
                "crossOrigin".to_string(),
                serde_json::Value::Bool(false),
            )]),
        )
    }

    // Public-only, fixed RS256 test vector. The signing key was ephemeral and is not tracked; keeping only
    // the SPKI and assertion makes the test deterministic without placing private key material in the repo.
    fn make_rs256_cert() -> (PasskeyPublicKey, BrowserCert) {
        const SPKI_B64: &str = concat!(
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2XRWZVXaz1ZV2QYYl21Me5yEbCT6Xh67",
            "CQ3WbUmW8BOs7wDlHp0xIGE6o293t6n24BXQODCdR0mLI/J+Mcz851CL/iQft5+U6nnL2aBpNa",
            "QP98kiBI/bwoLQqj4gAoj+2drmrJU0Luidaq017MFjbEfOnyy5nZ+bbKGMMKxFxF0rbgsbM/Lt",
            "/3pz82T1u7hKUJbCC9IPgFqR+lPov9Yq6ryLtRy21wuhLiZO934vmjdHZ6jAmXnTEuh09k1Nh",
            "RuPLOjPO9An/3/Dp1e0U5zY07Bg1aPhwu5PTx3Qo5PtKFq6FTKtGR3esjqtcJobgiurWmPkVc",
            "MU8soLPw011wXZSQIDAQAB"
        );
        const AUTHENTICATOR_DATA: &str = "DBPTlGur2WxMYNu04G0pipb7-yCdCzunWsqZHfREm7QFAAAAAQ";
        const CLIENT_DATA_JSON: &str = concat!(
            "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiUmg4UEtSa0JWM0RUQXNpdlpC",
            "aVowR3AtTFk4SlV4dkp2djZtajh3YkRjQSIsIm9yaWdpbiI6Imh0dHBzOi8vYXBwLmh5ZHJh",
            "dGVybXMuY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
        );
        const SIGNATURE: &str = concat!(
            "ZDXJNfBX01KwyULwa3h-fU8RE5yxkeM2mA7pIbYbB88bkRgawbs2xRNTKxj0wWC-MqEiaM1L",
            "LySyGGt1vMOnLp9jC1nvtYTodGOzbnVhRHhOl_y9yEZehpHqHhprLWW6F3T24ENy2fHRaR7a",
            "818elSC661JLkXcBK-Nx9J2HX2vzy1-JMdM9kWKIJcnXV9Gvm-WhdCBXIdxYSwIgFsNw_Ykr",
            "Z_rnaXZCAbKYGRrlA5iBKC0opcz1bqlxEE5viufW5t5XqzXrLnLidvZd48skmTec0JSxjosu",
            "qaGaaSst7TmZ0zvyglBiNN_VJTs3YsShYRfm58pqEILm3GNBFqck4g"
        );

        (
            PasskeyPublicKey {
                spki_b64: SPKI_B64.into(),
                alg: "rs256".into(),
                rp_id: "hydraterms.com".into(),
            },
            BrowserCert {
                browser_pubkey: "BPUB".into(),
                desktop_id: "dev_desk".into(),
                account_id: "acct".into(),
                expiry_ms: 2000,
                nonce: "nonce-rs256".into(),
                assertion: WebauthnAssertion {
                    authenticator_data: AUTHENTICATOR_DATA.into(),
                    client_data_json: CLIENT_DATA_JSON.into(),
                    signature: SIGNATURE.into(),
                },
            },
        )
    }

    fn der_length(length: usize) -> Vec<u8> {
        if length < 128 {
            return vec![length as u8];
        }
        let bytes = length.to_be_bytes();
        let first = bytes.iter().position(|byte| *byte != 0).unwrap();
        let encoded = &bytes[first..];
        let mut out = vec![0x80 | encoded.len() as u8];
        out.extend_from_slice(encoded);
        out
    }

    fn der_tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend_from_slice(&der_length(value.len()));
        out.extend_from_slice(value);
        out
    }

    // Build a syntactically valid rsaEncryption SPKI with a chosen modulus width. It is used only to prove
    // the verifier's lower/upper size policy; no private key exists for these synthetic public values.
    fn rsa_spki_with_modulus_bits(bits: usize) -> Vec<u8> {
        assert!(bits > 1);
        let byte_len = bits.div_ceil(8);
        let leading_bits = bits % 8;
        let mut modulus = vec![0; byte_len];
        modulus[0] = if leading_bits == 0 {
            0x80
        } else {
            1 << (leading_bits - 1)
        };
        *modulus.last_mut().unwrap() |= 1;

        let mut unsigned_modulus = Vec::with_capacity(modulus.len() + 1);
        if modulus[0] & 0x80 != 0 {
            unsigned_modulus.push(0);
        }
        unsigned_modulus.extend_from_slice(&modulus);
        let modulus = der_tlv(0x02, &unsigned_modulus);
        let exponent = der_tlv(0x02, &[0x01, 0x00, 0x01]);
        let pkcs1 = der_tlv(0x30, &[modulus, exponent].concat());

        // AlgorithmIdentifier { rsaEncryption, NULL }.
        const RSA_ALGORITHM: &[u8] = &[
            0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
            0x00,
        ];
        let bit_string = der_tlv(0x03, &[vec![0], pkcs1].concat());
        der_tlv(0x30, &[RSA_ALGORITHM, bit_string.as_slice()].concat())
    }

    // Default test policy: our app origin + a generous max TTL (the cert in the helper expires at 2000).
    fn policy() -> CertPolicy {
        CertPolicy {
            allowed_origins: vec!["https://app.hydraterms.com".to_string()],
            max_ttl_ms: 10_000,
        }
    }

    #[test]
    fn valid_es256_cert_verifies() {
        let (pk, cert) = make_es256_cert("BPUB", "dev_desk", "acct", 2000, "hydraterms.com");
        assert_eq!(
            verify_browser_cert(&cert, &pk, "BPUB", "dev_desk", "acct", 1000, &policy()),
            Ok(())
        );
    }

    #[test]
    fn valid_rs256_cert_verifies() {
        let (pk, cert) = make_rs256_cert();
        assert_eq!(
            verify_browser_cert(&cert, &pk, "BPUB", "dev_desk", "acct", 1000, &policy()),
            Ok(())
        );
    }

    #[test]
    fn rs256_tampered_signature_is_refused() {
        let (pk, mut cert) = make_rs256_cert();
        let url = b64url();
        let mut signature = url.decode(&cert.assertion.signature).unwrap();
        signature[0] ^= 1;
        cert.assertion.signature = url.encode(signature);
        assert_eq!(
            verify_browser_cert(&cert, &pk, "BPUB", "dev_desk", "acct", 1000, &policy()),
            Err(CertError::BadSignature)
        );
    }

    #[test]
    fn rs256_tampered_signed_data_is_refused() {
        let (pk, mut cert) = make_rs256_cert();
        let url = b64url();
        let mut authenticator_data = url.decode(&cert.assertion.authenticator_data).unwrap();
        // Change only the counter: RP hash and UP/UV remain valid, so failure comes from signing exact bytes.
        *authenticator_data.last_mut().unwrap() ^= 1;
        cert.assertion.authenticator_data = url.encode(authenticator_data);
        assert_eq!(
            verify_browser_cert(&cert, &pk, "BPUB", "dev_desk", "acct", 1000, &policy()),
            Err(CertError::BadSignature)
        );
    }

    #[test]
    fn rs256_wrong_public_key_is_refused() {
        let (mut pk, cert) = make_rs256_cert();
        let standard = base64::engine::general_purpose::STANDARD;
        let mut spki_der = standard.decode(&pk.spki_b64).unwrap();
        let (pkcs1_start, pkcs1_len) = {
            let parsed = spki::SubjectPublicKeyInfoRef::try_from(spki_der.as_slice()).unwrap();
            let pkcs1_der = parsed.subject_public_key.as_bytes().unwrap();
            let start = spki_der
                .windows(pkcs1_der.len())
                .position(|window| window == pkcs1_der)
                .unwrap();
            (start, pkcs1_der.len())
        };
        // The middle of PKCS#1 is inside the modulus, away from DER lengths and the exponent.
        spki_der[pkcs1_start + pkcs1_len / 2] ^= 1;
        pk.spki_b64 = standard.encode(spki_der);
        assert_eq!(
            verify_browser_cert(&cert, &pk, "BPUB", "dev_desk", "acct", 1000, &policy()),
            Err(CertError::BadSignature)
        );
    }

    #[test]
    fn rs256_malformed_key_and_signature_are_refused() {
        let (mut pk, cert) = make_rs256_cert();
        pk.spki_b64 = base64::engine::general_purpose::STANDARD.encode([0x30, 0x00]);
        assert_eq!(
            verify_browser_cert(&cert, &pk, "BPUB", "dev_desk", "acct", 1000, &policy()),
            Err(CertError::BadSignature)
        );

        let (pk, mut cert) = make_rs256_cert();
        cert.assertion.signature.truncate(16);
        assert_eq!(
            verify_browser_cert(&cert, &pk, "BPUB", "dev_desk", "acct", 1000, &policy()),
            Err(CertError::BadSignature)
        );
    }

    #[test]
    fn rs256_unsafe_modulus_sizes_are_refused() {
        let too_short = rsa_spki_with_modulus_bits(1024);
        let too_large = rsa_spki_with_modulus_bits(8193);
        assert!(!verify_rs256(&too_short, b"message", &[0; 128]));
        assert!(!verify_rs256(&too_large, b"message", &[0; 1025]));
    }

    #[test]
    fn unsupported_passkey_algorithm_is_refused() {
        let (mut pk, cert) = make_rs256_cert();
        pk.alg = "rs512".into();
        assert_eq!(
            verify_browser_cert(&cert, &pk, "BPUB", "dev_desk", "acct", 1000, &policy()),
            Err(CertError::BadSignature)
        );
    }

    #[test]
    fn expired_cert_is_refused() {
        let (pk, cert) = make_es256_cert("BPUB", "dev_desk", "acct", 2000, "hydraterms.com");
        assert_eq!(
            verify_browser_cert(&cert, &pk, "BPUB", "dev_desk", "acct", 2000, &policy()),
            Err(CertError::Expired)
        );
    }

    #[test]
    fn expiry_too_far_in_the_future_is_refused() {
        // A cert whose expiry is beyond max_ttl_ms from now (a relayed far-future cert) → refused.
        let (pk, cert) = make_es256_cert("BPUB", "dev_desk", "acct", 1_000_000, "hydraterms.com");
        assert_eq!(
            verify_browser_cert(&cert, &pk, "BPUB", "dev_desk", "acct", 1000, &policy()),
            Err(CertError::ExpiryTooFar)
        );
    }

    #[test]
    fn wrong_origin_is_refused() {
        let (pk, cert) = make_es256_cert("BPUB", "dev_desk", "acct", 2000, "hydraterms.com");
        let evil = CertPolicy {
            allowed_origins: vec!["https://evil.example".to_string()],
            max_ttl_ms: 10_000,
        };
        assert_eq!(
            verify_browser_cert(&cert, &pk, "BPUB", "dev_desk", "acct", 1000, &evil),
            Err(CertError::BadOrigin)
        );
    }

    #[test]
    fn staging_origin_is_accepted_only_by_the_staging_policy() {
        let (pk, cert) = make_es256_cert_with_origin_and_context(
            "BPUB",
            "dev_desk",
            "acct",
            2000,
            "hydraterms.com",
            "https://staging.hydraterms.com",
            serde_json::Map::from_iter([(
                "crossOrigin".to_string(),
                serde_json::Value::Bool(false),
            )]),
        );
        let staging = CertPolicy {
            allowed_origins: vec!["https://staging.hydraterms.com".to_string()],
            max_ttl_ms: 10_000,
        };
        assert_eq!(
            verify_browser_cert(&cert, &pk, "BPUB", "dev_desk", "acct", 1000, &staging),
            Ok(())
        );
        assert_eq!(
            verify_browser_cert(&cert, &pk, "BPUB", "dev_desk", "acct", 1000, &policy()),
            Err(CertError::BadOrigin)
        );

        let (prod_pk, prod_cert) =
            make_es256_cert("BPUB", "dev_desk", "acct", 2000, "hydraterms.com");
        assert_eq!(
            verify_browser_cert(&prod_cert, &prod_pk, "BPUB", "dev_desk", "acct", 1000, &staging,),
            Err(CertError::BadOrigin)
        );
    }

    #[test]
    fn only_absent_or_false_cross_origin_context_is_accepted() {
        let accepted = [
            serde_json::Map::new(),
            serde_json::Map::from_iter([(
                "crossOrigin".to_string(),
                serde_json::Value::Bool(false),
            )]),
        ];
        for context in accepted {
            let (pk, cert) = make_es256_cert_with_context(
                "BPUB",
                "dev_desk",
                "acct",
                2000,
                "hydraterms.com",
                context,
            );
            assert_eq!(
                verify_browser_cert(&cert, &pk, "BPUB", "dev_desk", "acct", 1000, &policy()),
                Ok(())
            );
        }

        let refused = [
            serde_json::Map::from_iter([(
                "crossOrigin".to_string(),
                serde_json::Value::Bool(true),
            )]),
            serde_json::Map::from_iter([(
                "crossOrigin".to_string(),
                serde_json::Value::String("false".to_string()),
            )]),
            serde_json::Map::from_iter([("crossOrigin".to_string(), serde_json::Value::Null)]),
            serde_json::Map::from_iter([(
                "crossOrigin".to_string(),
                serde_json::Value::Number(0.into()),
            )]),
            serde_json::Map::from_iter([(
                "crossOrigin".to_string(),
                serde_json::Value::Object(serde_json::Map::new()),
            )]),
            serde_json::Map::from_iter([(
                "crossOrigin".to_string(),
                serde_json::Value::Array(Vec::new()),
            )]),
            serde_json::Map::from_iter([
                ("crossOrigin".to_string(), serde_json::Value::Bool(false)),
                (
                    "topOrigin".to_string(),
                    serde_json::Value::String("https://embedder.example".to_string()),
                ),
            ]),
            serde_json::Map::from_iter([("topOrigin".to_string(), serde_json::Value::Null)]),
        ];
        for context in refused {
            let (pk, cert) = make_es256_cert_with_context(
                "BPUB",
                "dev_desk",
                "acct",
                2000,
                "hydraterms.com",
                context,
            );
            assert_eq!(
                verify_browser_cert(&cert, &pk, "BPUB", "dev_desk", "acct", 1000, &policy()),
                Err(CertError::BadOrigin)
            );
        }
    }

    #[test]
    fn user_not_verified_is_refused() {
        // Build a cert whose assertion has UV cleared (UP only) — should be refused (we require UV).
        let (_ignored, mut cert) =
            make_es256_cert("BPUB", "dev_desk", "acct", 2000, "hydraterms.com");
        use p256::ecdsa::{signature::Signer, DerSignature, SigningKey};
        use p256::pkcs8::EncodePublicKey;
        use rand::rngs::OsRng;
        let sk = SigningKey::random(&mut OsRng);
        let vk = *sk.verifying_key();
        let pk = PasskeyPublicKey {
            spki_b64: base64::engine::general_purpose::STANDARD
                .encode(vk.to_public_key_der().unwrap().as_bytes()),
            alg: "es256".into(),
            rp_id: "hydraterms.com".into(),
        };
        let url = b64url();
        let challenge = url.encode(Sha256::digest(cert_signed_bytes(
            "BPUB",
            "dev_desk",
            "acct",
            2000,
            &cert.nonce,
        )));
        let client_data = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"https://app.hydraterms.com","crossOrigin":false}}"#
        );
        let mut auth_data = Sha256::digest(b"hydraterms.com").to_vec();
        auth_data.push(0x01); // UP only, UV NOT set
        auth_data.extend_from_slice(&[0, 0, 0, 1]);
        let mut signed = auth_data.clone();
        signed.extend_from_slice(Sha256::digest(client_data.as_bytes()).as_slice());
        let der: DerSignature = sk.sign(&signed);
        cert.assertion = WebauthnAssertion {
            authenticator_data: url.encode(&auth_data),
            client_data_json: url.encode(client_data.as_bytes()),
            signature: url.encode(der.as_bytes()),
        };
        assert_eq!(
            verify_browser_cert(&cert, &pk, "BPUB", "dev_desk", "acct", 1000, &policy()),
            Err(CertError::UserNotVerified)
        );
    }

    #[test]
    fn binding_mismatch_is_refused() {
        let (pk, cert) = make_es256_cert("BPUB", "dev_desk", "acct", 2000, "hydraterms.com");
        assert_eq!(
            verify_browser_cert(&cert, &pk, "OTHER", "dev_desk", "acct", 1000, &policy()),
            Err(CertError::BindingMismatch)
        );
        assert_eq!(
            verify_browser_cert(&cert, &pk, "BPUB", "dev_OTHER", "acct", 1000, &policy()),
            Err(CertError::BindingMismatch)
        );
        assert_eq!(
            verify_browser_cert(&cert, &pk, "BPUB", "dev_desk", "OTHER", 1000, &policy()),
            Err(CertError::BindingMismatch)
        );
    }

    #[test]
    fn a_tampered_claim_breaks_the_challenge_binding() {
        let (pk, mut cert) = make_es256_cert("BPUB", "dev_desk", "acct", 2000, "hydraterms.com");
        cert.expiry_ms = 5000; // still within max_ttl but no longer matches the signed challenge
        assert_eq!(
            verify_browser_cert(&cert, &pk, "BPUB", "dev_desk", "acct", 1000, &policy()),
            Err(CertError::BadChallenge)
        );
    }

    #[test]
    fn wrong_passkey_is_refused() {
        let (_pk, cert) = make_es256_cert("BPUB", "dev_desk", "acct", 2000, "hydraterms.com");
        let (other_pk, _c) = make_es256_cert("BPUB", "dev_desk", "acct", 2000, "hydraterms.com");
        assert_eq!(
            verify_browser_cert(
                &cert,
                &other_pk,
                "BPUB",
                "dev_desk",
                "acct",
                1000,
                &policy()
            ),
            Err(CertError::BadSignature)
        );
    }

    #[test]
    fn wrong_rp_id_is_refused() {
        let (mut pk, cert) = make_es256_cert("BPUB", "dev_desk", "acct", 2000, "hydraterms.com");
        pk.rp_id = "evil.com".into();
        assert_eq!(
            verify_browser_cert(&cert, &pk, "BPUB", "dev_desk", "acct", 1000, &policy()),
            Err(CertError::BadRpId)
        );
    }

    #[test]
    fn junk_fails_closed() {
        let (pk, mut cert) = make_es256_cert("BPUB", "dev_desk", "acct", 2000, "hydraterms.com");
        cert.assertion.signature = "!!!not-b64!!!".into();
        assert_eq!(
            verify_browser_cert(&cert, &pk, "BPUB", "dev_desk", "acct", 1000, &policy()),
            Err(CertError::Malformed)
        );
    }
}
