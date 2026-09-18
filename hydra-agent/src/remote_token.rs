//! S3b — signed, device/session-scoped Hydra app-layer token (the format S1 currently stubs).
//!
//! The CLOUD signs these with its token key; the AGENT verifies them OFFLINE with the cloud's PUBLIC key
//! (no cloud round-trip in the hot path) and additionally re-checks REVOCATION (so a revoked device's
//! next privileged action fails / its live channel is closed). This is the access boundary for S3b's
//! control channel: a valid token is required before any privileged request — being connected over
//! WebRTC is NOT authorization.
//!
//! Wire form (compact, JWS-like): `<base64url(claims_json)>.<base64url(ed25519_sig)>`. The signature is
//! over the exact `base64url(claims_json)` bytes. No secrets in logs — only a token's claims ids/expiry
//! are ever logged, never the signature or a raw token.

use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The token's claims — what the agent enforces. Device + account scoped; optionally session-scoped.
/// `Default` is derived so test constructors can spread `..Default::default()` for the optional fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TokenClaims {
    /// Account the token belongs to.
    pub account_id: String,
    /// The device this token authorizes (must match the connecting peer's device).
    pub device_id: String,
    /// Optional signaling-session binding (S3b: present once we tie a token to a session).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Optional WebRTC signaling-session binding. Separate from `session_id`, which scopes terminal attach.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal_session_id: Option<String>,
    /// Exact enrolled desktop this connection authority targets. Required on production WebRTC authentication
    /// and every authorization successor; optional only for token uses that have no configured desktop target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_device_id: Option<String>,
    /// The enrolled BROWSER device's public key (base64 SPKI) — present only for browser-device tokens. The
    /// cloud embeds it (it signs the token), so the agent can verify the browser's per-connection offer
    /// proof-of-possession OFFLINE against this key. Order here MUST match the cloud's claimsJson.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_pubkey: Option<String>,
    /// The browser key algorithm ('ed25519' | 'p256') for verifying the offer proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser_pubkey_alg: Option<String>,
    /// SHA-256 lowercase hex of the immediately preceding wire token. Only an already-authenticated matching
    /// DataChannel may present a token carrying this claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_parent_sha256: Option<String>,
    /// Unix ms issued-at.
    pub iat_ms: u64,
    /// Unix ms expiry (short-lived).
    pub exp_ms: u64,
}

/// Why a token was rejected. Mapped to a generic `auth_refused` reason on the wire (no oracle).
#[derive(Debug, PartialEq, Eq)]
pub enum TokenError {
    Malformed,
    BadSignature,
    Expired,
    Revoked,
    /// Token's device != the device presenting it on this connection.
    WrongDevice,
}

/// Verify a token string against the cloud's public key, an expiry clock, the EXPECTED device for this
/// connection, and a revocation check. Returns the claims on success.
///
/// `revoked(account_id, device_id) -> bool` is the agent's live revocation source (e.g. the shared
/// device registry / a cloud re-check). A revoked device fails here EVEN with a still-valid signature.
pub fn verify_token(
    token: &str,
    cloud_pubkey: &VerifyingKey,
    now_ms: u64,
    expected_device_id: &str,
    revoked: impl Fn(&str, &str, u64) -> bool,
) -> Result<TokenClaims, TokenError> {
    let (claims_b64, sig_b64) = token.split_once('.').ok_or(TokenError::Malformed)?;
    let sig_bytes = B64.decode(sig_b64).map_err(|_| TokenError::Malformed)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| TokenError::Malformed)?;
    // Signature is over the exact base64url(claims) bytes (what was signed).
    cloud_pubkey
        .verify(claims_b64.as_bytes(), &sig)
        .map_err(|_| TokenError::BadSignature)?;
    let claims_json = B64.decode(claims_b64).map_err(|_| TokenError::Malformed)?;
    let claims: TokenClaims =
        serde_json::from_slice(&claims_json).map_err(|_| TokenError::Malformed)?;

    if now_ms >= claims.exp_ms {
        return Err(TokenError::Expired);
    }
    if claims.device_id != expected_device_id {
        return Err(TokenError::WrongDevice);
    }
    if revoked(&claims.account_id, &claims.device_id, claims.iat_ms) {
        return Err(TokenError::Revoked);
    }
    Ok(claims)
}

/// Sign claims with a cloud SIGNING key → the wire token. This is the CLOUD's job (S1 mint); included
/// here so tests can produce valid tokens and so the agent + cloud agree on the exact format.
#[cfg(any(test, feature = "token-sign"))]
pub fn sign_token(claims: &TokenClaims, signing: &ed25519_dalek::SigningKey) -> String {
    use ed25519_dalek::Signer;
    let claims_json = serde_json::to_vec(claims).expect("claims serialize");
    let claims_b64 = B64.encode(claims_json);
    let sig = signing.sign(claims_b64.as_bytes());
    format!("{claims_b64}.{}", B64.encode(sig.to_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn keypair() -> (SigningKey, VerifyingKey) {
        let mut seed = [7u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn cloud_exact_claims_json_with_browser_pubkey_verifies_and_deserializes() {
        // The CLOUD builds the claims JSON by hand (signed-token.ts claimsJson) in a FIXED key order. The
        // agent verifies the signature over those exact bytes, then serde-deserializes. This pins that the
        // agent's TokenClaims field order + serde match the cloud's byte order for the browser_pubkey
        // and continuity fields — a drift here breaks EVERY token signature. We reproduce the cloud's exact JSON.
        use base64::Engine as _;
        use ed25519_dalek::Signer;
        let (sk, vk) = keypair();
        let now = 1_000_000u64;
        let parent = "a".repeat(64);
        // Exactly what signed-token.ts emits for a fully bound browser successor.
        let cloud_json = format!(
            r#"{{"account_id":"acct","device_id":"dev_a","session_id":"terminal","signal_session_id":"signal","target_device_id":"desktop","browser_pubkey":"PUBB64","browser_pubkey_alg":"ed25519","refresh_parent_sha256":"{parent}","iat_ms":{now},"exp_ms":{}}}"#,
            now + 60_000
        );
        let claims_b64 = B64.encode(cloud_json.as_bytes());
        let sig = sk.sign(claims_b64.as_bytes());
        let token = format!("{claims_b64}.{}", B64.encode(sig.to_bytes()));
        let got = verify_token(&token, &vk, now + 1, "dev_a", NEVER_REVOKED).unwrap();
        assert_eq!(got.browser_pubkey.as_deref(), Some("PUBB64"));
        assert_eq!(got.browser_pubkey_alg.as_deref(), Some("ed25519"));
        assert_eq!(got.target_device_id.as_deref(), Some("desktop"));
        assert_eq!(got.refresh_parent_sha256.as_deref(), Some(parent.as_str()));
        assert_eq!(serde_json::to_string(&got).unwrap(), cloud_json);
    }

    fn claims(now: u64, dev: &str) -> TokenClaims {
        TokenClaims {
            account_id: "acct_rk".into(),
            device_id: dev.into(),
            session_id: Some("sig_1".into()),
            signal_session_id: None,
            target_device_id: None,
            browser_pubkey: None,
            browser_pubkey_alg: None,
            refresh_parent_sha256: None,
            iat_ms: now,
            exp_ms: now + 60_000,
        }
    }

    const NEVER_REVOKED: fn(&str, &str, u64) -> bool = |_, _, _| false;

    #[test]
    fn valid_token_verifies_and_returns_claims() {
        let (sk, vk) = keypair();
        let now = 1_000_000;
        let tok = sign_token(&claims(now, "dev_a"), &sk);
        let got = verify_token(&tok, &vk, now + 1000, "dev_a", NEVER_REVOKED).unwrap();
        assert_eq!(got.account_id, "acct_rk");
        assert_eq!(got.device_id, "dev_a");
    }

    #[test]
    fn expired_token_is_rejected() {
        let (sk, vk) = keypair();
        let now = 1_000_000;
        let tok = sign_token(&claims(now, "dev_a"), &sk);
        assert_eq!(
            verify_token(&tok, &vk, now + 60_000, "dev_a", NEVER_REVOKED),
            Err(TokenError::Expired)
        );
    }

    #[test]
    fn wrong_device_is_rejected() {
        let (sk, vk) = keypair();
        let now = 1_000_000;
        let tok = sign_token(&claims(now, "dev_a"), &sk);
        assert_eq!(
            verify_token(&tok, &vk, now + 1, "dev_OTHER", NEVER_REVOKED),
            Err(TokenError::WrongDevice)
        );
    }

    #[test]
    fn revoked_device_is_rejected_even_with_valid_signature() {
        let (sk, vk) = keypair();
        let now = 1_000_000;
        let tok = sign_token(&claims(now, "dev_a"), &sk);
        let revoked = |_a: &str, d: &str, _i: u64| d == "dev_a";
        assert_eq!(
            verify_token(&tok, &vk, now + 1, "dev_a", revoked),
            Err(TokenError::Revoked)
        );
    }

    #[test]
    fn tampered_claims_fail_the_signature() {
        let (sk, vk) = keypair();
        let now = 1_000_000;
        let tok = sign_token(&claims(now, "dev_a"), &sk);
        // flip the claims half → signature no longer matches
        let (claims_b64, sig_b64) = tok.split_once('.').unwrap();
        let mut bytes = B64.decode(claims_b64).unwrap();
        bytes[0] ^= 0xff;
        let tampered = format!("{}.{sig_b64}", B64.encode(bytes));
        assert_eq!(
            verify_token(&tampered, &vk, now + 1, "dev_a", NEVER_REVOKED),
            Err(TokenError::BadSignature)
        );
    }

    #[test]
    fn wrong_key_fails() {
        let (sk, _vk) = keypair();
        let (_sk2, other_vk) = keypair();
        let now = 1_000_000;
        let tok = sign_token(&claims(now, "dev_a"), &sk);
        assert_eq!(
            verify_token(&tok, &other_vk, now + 1, "dev_a", NEVER_REVOKED),
            Err(TokenError::BadSignature)
        );
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        let (_sk, vk) = keypair();
        for bad in ["", "noseparator", "a.b.c", "!!!.???"] {
            assert!(matches!(
                verify_token(bad, &vk, 1, "dev_a", NEVER_REVOKED),
                Err(TokenError::Malformed) | Err(TokenError::BadSignature)
            ));
        }
    }

    /// CROSS-LANGUAGE: a token MINTED BY THE CLOUD (hydra-cloud signed-token.ts, deterministic seed 0x42)
    /// must verify here. Pinned fixture — if the cloud's wire format drifts, this fails. Regenerate via
    /// `node --import tsx/esm` over signed-token.ts with the same seed if the format is intentionally
    /// changed (and update BOTH sides together).
    #[test]
    fn verifies_a_cloud_minted_token() {
        // public key (base64 STANDARD of the 32 raw ed25519 bytes) the cloud exposes as --cloud-pubkey.
        let pub_b64 = "IVL40Zt5HSRFMkLhXy6rbLfP+ntqXtMAl5YOBpiB2xI=";
        // a session-scoped token for dev_x / acct_local / sig_1, exp far in the future.
        let token = "eyJhY2NvdW50X2lkIjoiYWNjdF9sb2NhbCIsImRldmljZV9pZCI6ImRldl94Iiwic2Vzc2lvbl9pZCI6InNpZ18xIiwiaWF0X21zIjoxMDAwLCJleHBfbXMiOjk5OTk5OTk5OTk5OTl9.GZkrbinHEN7ui2Vrd-M5uI1Z3E1fMxQRHLYEBStO_zV_G1IMugTFo5mw0IkO1DBcjp8owbksbZF26omEVWt2Cg";

        use base64::engine::general_purpose::STANDARD;
        let pub_bytes: [u8; 32] = STANDARD.decode(pub_b64).unwrap().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&pub_bytes).unwrap();

        let claims =
            verify_token(token, &vk, 5000, "dev_x", NEVER_REVOKED).expect("cloud token verifies");
        assert_eq!(claims.account_id, "acct_local");
        assert_eq!(claims.device_id, "dev_x");
        assert_eq!(claims.session_id.as_deref(), Some("sig_1"));

        // and the same token is refused for the WRONG device (session/device binding holds cross-language).
        assert_eq!(
            verify_token(token, &vk, 5000, "dev_OTHER", NEVER_REVOKED),
            Err(TokenError::WrongDevice)
        );
    }

    /// FULL attach-authorization chain: verify_token (signature/expiry/device/revoke) THEN can_attach (session
    /// scope). The two layers are tested separately elsewhere; this pins that they compose correctly end to end —
    /// the actual gate a browser attach passes through. Hardening guard against either layer being bypassed.
    #[test]
    fn verify_then_can_attach_enforces_the_whole_chain() {
        use crate::remote_policy::{can_attach, AccessDenied, SameAsLocalPolicy};
        let (sk, vk) = keypair();
        let now = 1_000_000;
        // a session-scoped token (claims() binds session "sig_1") for dev_a.
        let tok = sign_token(&claims(now, "dev_a"), &sk);

        // happy path: valid token + attaching its BOUND session → allowed.
        let c = verify_token(&tok, &vk, now + 1000, "dev_a", NEVER_REVOKED).expect("verifies");
        assert_eq!(can_attach(&c, &SameAsLocalPolicy, "sig_1"), Ok(()));

        // replay onto a DIFFERENT session: verify still passes (same device/sig) but the scope gate refuses.
        assert_eq!(
            can_attach(&c, &SameAsLocalPolicy, "sig_OTHER"),
            Err(AccessDenied::SessionScopeMismatch)
        );

        // expired token never reaches can_attach — the chain stops at verify.
        assert_eq!(
            verify_token(&tok, &vk, now + 60_000, "dev_a", NEVER_REVOKED),
            Err(TokenError::Expired)
        );
        // wrong device never reaches can_attach either.
        assert_eq!(
            verify_token(&tok, &vk, now + 1000, "dev_OTHER", NEVER_REVOKED),
            Err(TokenError::WrongDevice)
        );
        // revoked device never reaches can_attach either (revoke is authoritative even with a valid sig).
        assert_eq!(
            verify_token(&tok, &vk, now + 1000, "dev_a", |_a, d, _i| d == "dev_a"),
            Err(TokenError::Revoked)
        );
    }
}
