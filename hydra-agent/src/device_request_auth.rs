//! Device-signed requests for production agent control-plane calls.
//!
//! The enrolled desktop signs signaling/relay requests with its device private key. The cloud verifies the
//! signature against the stored public key and derives account authority from the device record. This keeps
//! remote-peer free of human account cookies/JWTs while still authenticating the device.

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};

pub const DEVICE_REQUEST_PURPOSE: &str = "hydra-device-request-v1";
const B64_STD: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn body_sha256_hex(body: &str) -> String {
    let digest = Sha256::digest(body.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{b:02x}");
    }
    out
}

pub fn request_message(
    method: &str,
    path_with_query: &str,
    body_sha256: &str,
    timestamp_ms: u64,
) -> String {
    format!(
        "{DEVICE_REQUEST_PURPOSE}:{}:{path_with_query}:{body_sha256}:{timestamp_ms}",
        method.to_ascii_uppercase()
    )
}

pub fn signed_headers(
    method: &str,
    path_with_query: &str,
    body: &str,
    device_id: &str,
    key: &SigningKey,
) -> [(String, String); 3] {
    let timestamp_ms = now_ms();
    let body_sha = body_sha256_hex(body);
    let msg = request_message(method, path_with_query, &body_sha, timestamp_ms);
    let sig = key.sign(msg.as_bytes());
    [
        ("x-hydra-device-id".into(), device_id.to_string()),
        (
            "x-hydra-device-timestamp-ms".into(),
            timestamp_ms.to_string(),
        ),
        (
            "x-hydra-device-signature".into(),
            B64_STD.encode(sig.to_bytes()),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_message_is_stable() {
        let sha = body_sha256_hex(r#"{"ok":true}"#);
        assert_eq!(
            request_message("post", "/v1/x?y=1", &sha, 123),
            format!("hydra-device-request-v1:POST:/v1/x?y=1:{sha}:123")
        );
    }

    #[test]
    fn signed_headers_are_bounded_and_named() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let h = signed_headers(
            "GET",
            "/v1/signal/sessions/pending?deviceId=dev_a",
            "",
            "dev_a",
            &key,
        );
        assert_eq!(h[0].0, "x-hydra-device-id");
        assert_eq!(h[0].1, "dev_a");
        assert_eq!(h[1].0, "x-hydra-device-timestamp-ms");
        assert_eq!(h[2].0, "x-hydra-device-signature");
        assert!(h[2].1.len() <= 128);
    }
}
