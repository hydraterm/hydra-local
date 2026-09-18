//! Signed device heartbeat (agent side of Real Presence). While `remote-peer` runs, the agent periodically
//! proves liveness by signing a purpose-bound message with its ENROLLED device private key and POSTing it
//! to the cloud. The cloud verifies the signature against the device's stored PUBLIC key, requires the
//! device be non-revoked, and stamps `last_seen_ms` with SERVER time. NO account token, NO terminal/session
//! data, NO private key leaves the machine — only the detached signature.
//!
//! Canonical message (must match hydra-cloud `device-heartbeat.ts` EXACTLY):
//!   "hydra-heartbeat-v1:" + deviceId + ":" + timestampMs
//! The signature is base64 STANDARD (the cloud decodes it with standard base64), over the UTF-8 message
//! bytes.

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use std::time::Duration;

/// Standard base64 (the cloud verifies the signature via `Buffer.from(sig, 'base64')` = standard).
const B64_STD: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// The cloud's purpose prefix — pins the protocol so a heartbeat signature can't be replayed elsewhere.
pub const HEARTBEAT_PURPOSE: &str = "hydra-heartbeat-v1";

/// Default heartbeat cadence — conservative for beta; comfortably under the cloud's "Recently seen" window.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(45);

/// The exact bytes signed/verified for a heartbeat. Mirrors the cloud `heartbeatMessage`.
pub fn heartbeat_message(device_id: &str, timestamp_ms: u64) -> String {
    format!("{HEARTBEAT_PURPOSE}:{device_id}:{timestamp_ms}")
}

/// Sign a heartbeat for `(device_id, timestamp_ms)` → the base64 (standard) ed25519 signature. Pure;
/// the private key never leaves this function — only the detached signature is returned.
pub fn sign_heartbeat(key: &SigningKey, device_id: &str, timestamp_ms: u64) -> String {
    let sig = key.sign(heartbeat_message(device_id, timestamp_ms).as_bytes());
    B64_STD.encode(sig.to_bytes())
}

/// The minimal JSON body POSTed to /v1/devices/heartbeat. No account token, no terminal/session data.
pub fn heartbeat_body(
    device_id: &str,
    timestamp_ms: u64,
    signature_b64: &str,
) -> serde_json::Value {
    serde_json::json!({
        "deviceId": device_id,
        "timestampMs": timestamp_ms,
        "signature": signature_b64,
    })
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// (see the fuller doc on the fn below)
/// Sends one heartbeat. Returns the HTTP status code on a response (2xx = accepted, others = refused), or the
/// reqwest error on a transport failure. The caller classifies + persists a content-blind record.
pub async fn send_heartbeat(
    client: &reqwest::Client,
    cloud_base: &str,
    device_id: &str,
    key: &SigningKey,
) -> Result<u16, reqwest::Error> {
    let ts = now_ms();
    let sig = sign_heartbeat(key, device_id, ts);
    let url = format!("{}/v1/devices/heartbeat", cloud_base.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .json(&heartbeat_body(device_id, ts, &sig))
        .send()
        .await?;
    Ok(resp.status().as_u16())
}

/// Purpose prefix for a device SELF-REVOKE ("Remove Remote"). MUST match the cloud's SELF_REVOKE_PURPOSE.
pub const SELF_REVOKE_PURPOSE: &str = "hydra-self-revoke-v1";

/// The exact bytes signed for a self-revoke (distinct purpose prefix from the heartbeat, so signatures can't be
/// cross-replayed). Mirrors the cloud `selfRevokeMessage`.
pub fn self_revoke_message(device_id: &str, timestamp_ms: u64) -> String {
    format!("{SELF_REVOKE_PURPOSE}:{device_id}:{timestamp_ms}")
}

/// Sign + POST a device SELF-REVOKE to the cloud so the account's device list drops THIS device ("Remove Remote").
/// Device-signature auth (no account token), same possession-proof model as the heartbeat. Returns the HTTP status
/// (2xx = revoked/idempotent-ok) or the transport error. Blocking client (rare, not a hot path).
pub fn send_self_revoke_blocking(
    cloud_base: &str,
    device_id: &str,
    key: &SigningKey,
) -> Result<u16, String> {
    let ts = now_ms();
    let msg = self_revoke_message(device_id, ts);
    let sig = B64_STD.encode(key.sign(msg.as_bytes()).to_bytes());
    let url = format!(
        "{}/v1/devices/self-revoke",
        cloud_base.trim_end_matches('/')
    );
    let client = reqwest::blocking::Client::builder()
        // Remove Remote is a local fail-closed action first; cloud cleanup is
        // best-effort and must not pin the desktop UI for a long offline timeout.
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|e| e.to_string())?;
    let resp = client
        .post(&url)
        .json(&serde_json::json!({ "deviceId": device_id, "timestampMs": ts, "signature": sig }))
        .send()
        .map_err(|e| e.to_string())?;
    Ok(resp.status().as_u16())
}

/// Classify one heartbeat attempt into the content-blind persisted status shape. Pure so health/presence
/// behavior stays pinned without making HTTP calls in tests.
pub fn classify_heartbeat_attempt<E>(
    result: Result<u16, E>,
) -> (crate::heartbeat_status::Outcome, Option<u16>) {
    use crate::heartbeat_status::Outcome;
    match result {
        Ok(c) if (200..300).contains(&c) => (Outcome::Ok, Some(c)),
        Ok(c) => (Outcome::Refused, Some(c)),
        Err(_) => (Outcome::SendFailed, None),
    }
}

/// Is this heartbeat status a DEFINITIVE revoke/unknown-device (so we should clear the local enrollment)? Only 403
/// (revoked/forbidden) and 404 (unknown device) count — a transient network failure or a 5xx must NOT wipe a valid
/// enrollment. Pure so the decision is testable without HTTP.
pub fn is_revoked_status(code: u16) -> bool {
    code == 403 || code == 404
}

fn clear_revoked_heartbeat_enrollment(
    agent_dir: &std::path::Path,
    device_id: &str,
) -> anyhow::Result<bool> {
    crate::device_identity::remove_record_if_device_id(agent_dir, device_id)
}

/// Spawn a background task that heartbeats every `interval` while remote-peer runs. Failures are logged at
/// debug and retried next tick — a heartbeat blip NEVER kills the peer. A 403 (revoked) is surfaced at warn
/// but does not stop the task (the bridge's own revoke check is authoritative for cutting sessions).
/// A fresh enrollment picked up from disk after a revoke: the new device id + its signing key.
struct ReEnrollment {
    device_id: String,
    key: SigningKey,
}

/// After a revoke cleared our enrollment, watch `device.json` for a NEW enrollment (a re-add from the browser →
/// desktop) whose device_id DIFFERS from the just-revoked one, and return it so the heartbeat can resume with the
/// new identity. Polls at `interval`. Returns None only if we should stop (currently: never, until a shutdown
/// signal exists — the sleep is the sole await point, so the task ends when the runtime is dropped).
async fn wait_for_new_enrollment(
    agent_dir: &std::path::Path,
    revoked_device_id: &str,
    interval: Duration,
) -> Option<ReEnrollment> {
    loop {
        tokio::time::sleep(interval).await;
        // A record present with a DIFFERENT device id = a genuine re-enrollment (not the stale one we just cleared).
        if let Some(rec) = crate::device_identity::is_enrolled(agent_dir) {
            if rec.device_id != revoked_device_id {
                if let Ok(key) = crate::device_identity::load_or_create_key(agent_dir) {
                    return Some(ReEnrollment {
                        device_id: rec.device_id,
                        key,
                    });
                }
            }
        }
    }
}

pub fn spawn_heartbeat_loop(
    cloud_base: String,
    device_id: String,
    key: SigningKey,
    interval: Duration,
    agent_dir: std::path::PathBuf,
) -> tokio::task::JoinHandle<()> {
    use crate::heartbeat_status::{save, HeartbeatStatus, Outcome};
    tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("heartbeat: client build failed, presence disabled: {e}");
                return;
            }
        };
        // The identity we heartbeat with. Starts from the caller-provided device_id/key, but if the cloud REVOKES
        // this device we don't stop forever — we clear the local record and then WATCH device.json for a fresh
        // enrollment (a re-add from the browser), and resume with the NEW identity. This is what makes re-enroll and
        // revoke-then-re-add work WITHOUT restarting the agent (the old bug: the loop `break`d on revoke and the
        // running agent never picked the new device.json up, so presence went stale — "last seen 52m ago").
        let mut device_id = device_id;
        let mut key = key;
        tracing::info!(device = %device_id, secs = interval.as_secs(), "heartbeat: started");
        loop {
            // classify the attempt into a content-blind record (outcome + optional HTTP code only) and persist
            // it so an offline `hydra-agent health` can report cloud-reachability. A status-write failure is
            // ignored — it must never affect presence.
            let result = send_heartbeat(&client, &cloud_base, &device_id, &key).await;
            let (outcome, code) = classify_heartbeat_attempt(result.as_ref().copied());
            let mut revoked = false;
            match (outcome, code) {
                (Outcome::Ok, _) => {
                    tracing::debug!("heartbeat: ok");
                }
                (Outcome::Refused, Some(c)) if is_revoked_status(c) => {
                    // The cloud says this device is REVOKED (browser removed it). Clear the local enrollment so the
                    // desktop reflects it — the app's next model refresh sees "not enrolled" and the sidebar flips
                    // back to "Add Remote". Keep the device KEY (re-enroll reuses the same identity).
                    tracing::info!(
                        "heartbeat: device revoked by cloud ({c}); clearing local enrollment"
                    );
                    match clear_revoked_heartbeat_enrollment(&agent_dir, &device_id) {
                        Ok(true) => {}
                        Ok(false) => tracing::info!(
                            "heartbeat: revoke applied to an older identity; keeping current enrollment"
                        ),
                        Err(e) => {
                            tracing::warn!("heartbeat: could not clear enrollment after revoke: {e}")
                        }
                    }
                    revoked = true;
                }
                (Outcome::Refused, Some(c)) => {
                    // Non-revoke refusal (e.g. clock skew, transient 5xx) — do NOT wipe enrollment; retry next tick.
                    tracing::warn!("heartbeat: refused by cloud ({c}) (not a revoke; will retry)");
                }
                (Outcome::Refused, None) => {
                    tracing::warn!("heartbeat: refused by cloud (revoked or rejected)");
                }
                (Outcome::SendFailed, _) => {
                    let e = result
                        .err()
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "unknown".to_string());
                    tracing::debug!("heartbeat: send failed (will retry): {e}");
                }
            };
            let _ = save(
                &agent_dir,
                &HeartbeatStatus {
                    outcome,
                    status_code: code,
                    ts_ms: now_ms(),
                },
            );
            if revoked {
                // Don't die — WATCH for a fresh enrollment (device.json re-written with a DIFFERENT device_id) and
                // resume heartbeating with it. Poll at the normal interval; a re-add is detected within one tick.
                match wait_for_new_enrollment(&agent_dir, &device_id, interval).await {
                    Some(next) => {
                        tracing::info!(device = %next.device_id, "heartbeat: re-enrolled; resuming presence");
                        device_id = next.device_id;
                        key = next.key;
                        continue; // heartbeat the new identity immediately
                    }
                    None => break, // agent shutting down (channel closed) — stop cleanly
                }
            }
            tokio::time::sleep(interval).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heartbeat_status::Outcome;
    use ed25519_dalek::{Verifier, VerifyingKey};

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn create_safe_heartbeat_fixture_dir(path: &std::path::Path) {
        std::fs::create_dir_all(path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    fn heartbeat_test_path(name: String) -> std::path::PathBuf {
        std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(name)
    }

    #[test]
    fn canonical_message_matches_cloud_format() {
        assert_eq!(
            heartbeat_message("dev_abc", 1700000000000),
            "hydra-heartbeat-v1:dev_abc:1700000000000"
        );
    }

    #[test]
    fn only_403_and_404_count_as_revoked_not_transient_failures() {
        // Definitive revoke / unknown-device → clear enrollment.
        assert!(is_revoked_status(403));
        assert!(is_revoked_status(404));
        // Everything else must NOT wipe a valid enrollment (success, clock-skew, server errors).
        assert!(!is_revoked_status(200));
        assert!(!is_revoked_status(400));
        assert!(!is_revoked_status(429));
        assert!(!is_revoked_status(500));
        assert!(!is_revoked_status(503));
    }

    #[test]
    fn heartbeat_403_404_use_compare_delete_without_provider_outbox() {
        for code in [403, 404] {
            let dir = heartbeat_test_path(format!(
                "hydra-hb-no-provider-outbox-{code}-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            create_safe_heartbeat_fixture_dir(&dir);
            let record = crate::device_identity::DeviceRecord {
                device_id: format!("dev_revoked_{code}"),
                account_id: "acct_synthetic_heartbeat".into(),
                cloud_base: crate::release_trust::CLOUD_BASE.into(),
                passkey: None,
            };
            crate::device_identity::save_record(&dir, &record).unwrap();
            crate::device_identity::load_or_create_key(&dir).unwrap();

            assert!(is_revoked_status(code));
            assert!(clear_revoked_heartbeat_enrollment(&dir, &record.device_id).unwrap());
            assert!(crate::device_identity::load_record(&dir).unwrap().is_none());
            assert!(dir.join("device-key").is_file());
            assert!(
                !crate::lifecycle_cleanup::revocation_outbox_path(&dir).exists(),
                "heartbeat compare-delete is the documented no-outbox exception"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }

        let dir = heartbeat_test_path(format!(
            "hydra-hb-old-identity-no-outbox-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        create_safe_heartbeat_fixture_dir(&dir);
        let current = crate::device_identity::DeviceRecord {
            device_id: "dev_current_after_reenroll".into(),
            account_id: "acct_synthetic_heartbeat".into(),
            cloud_base: crate::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        crate::device_identity::save_record(&dir, &current).unwrap();
        assert!(!clear_revoked_heartbeat_enrollment(&dir, "dev_old").unwrap());
        assert_eq!(
            crate::device_identity::load_record(&dir)
                .unwrap()
                .unwrap()
                .device_id,
            current.device_id
        );
        assert!(!crate::lifecycle_cleanup::revocation_outbox_path(&dir).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn signature_verifies_against_the_device_public_key() {
        let key = test_key();
        let vk: VerifyingKey = key.verifying_key();
        let ts = 1700000000000u64;
        let sig_b64 = sign_heartbeat(&key, "dev_abc", ts);
        // decode + verify against the canonical message (what the cloud does)
        let sig_bytes = B64_STD.decode(&sig_b64).expect("std base64");
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).expect("sig");
        assert!(vk
            .verify(heartbeat_message("dev_abc", ts).as_bytes(), &sig)
            .is_ok());
    }

    #[test]
    fn signature_does_not_verify_for_a_different_message() {
        let key = test_key();
        let vk = key.verifying_key();
        let sig_bytes = B64_STD.decode(sign_heartbeat(&key, "dev_abc", 1)).unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        // a different timestamp must NOT verify (no replay/substitution)
        assert!(vk
            .verify(heartbeat_message("dev_abc", 2).as_bytes(), &sig)
            .is_err());
    }

    #[test]
    fn body_is_minimal_and_carries_no_terminal_or_key_material() {
        let body = heartbeat_body("dev_abc", 123, "SIGB64");
        let obj = body.as_object().unwrap();
        // exactly the three expected keys, nothing else
        let mut keys: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
        keys.sort();
        assert_eq!(keys, vec!["deviceId", "signature", "timestampMs"]);
        let blob = body.to_string().to_lowercase();
        for bad in [
            "private", "seed", "stdout", "pty", "token", "bearer", "cookie",
        ] {
            assert!(!blob.contains(bad), "heartbeat body must not contain {bad}");
        }
    }

    #[test]
    fn heartbeat_attempt_classification_is_content_blind_and_boundary_pinned() {
        assert_eq!(
            classify_heartbeat_attempt::<()>(Ok(200)),
            (Outcome::Ok, Some(200))
        );
        assert_eq!(
            classify_heartbeat_attempt::<()>(Ok(204)),
            (Outcome::Ok, Some(204))
        );
        assert_eq!(
            classify_heartbeat_attempt::<()>(Ok(299)),
            (Outcome::Ok, Some(299))
        );
        assert_eq!(
            classify_heartbeat_attempt::<()>(Ok(300)),
            (Outcome::Refused, Some(300))
        );
        assert_eq!(
            classify_heartbeat_attempt::<()>(Ok(403)),
            (Outcome::Refused, Some(403))
        );
        assert_eq!(
            classify_heartbeat_attempt::<&str>(Err("network timeout with private details")),
            (Outcome::SendFailed, None)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wait_for_new_enrollment_resumes_on_a_different_device_id() {
        use crate::device_identity::{save_record, DeviceRecord};
        let dir = heartbeat_test_path(format!("hydra-hb-rearm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        create_safe_heartbeat_fixture_dir(&dir);
        // A new enrollment (DIFFERENT device id) written after the watch starts must be picked up.
        save_record(
            &dir,
            &DeviceRecord {
                device_id: "dev_NEW".into(),
                account_id: "acct_1".into(),
                cloud_base: "https://api".into(),
                passkey: None,
            },
        )
        .unwrap();
        let got = wait_for_new_enrollment(&dir, "dev_OLD_revoked", Duration::from_millis(10)).await;
        let got = got.expect("a different-id enrollment resumes heartbeat");
        assert_eq!(got.device_id, "dev_NEW");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wait_for_new_enrollment_ignores_the_same_revoked_id() {
        use crate::device_identity::{save_record, DeviceRecord};
        let dir = heartbeat_test_path(format!("hydra-hb-same-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        create_safe_heartbeat_fixture_dir(&dir);
        // The SAME (just-revoked) id reappearing must NOT be treated as a re-enrollment (it would loop-heartbeat a
        // revoked device). Write it, then confirm the watcher does not return within a bounded number of ticks.
        save_record(
            &dir,
            &DeviceRecord {
                device_id: "dev_SAME".into(),
                account_id: "acct_1".into(),
                cloud_base: "https://api".into(),
                passkey: None,
            },
        )
        .unwrap();
        let res = tokio::time::timeout(
            Duration::from_millis(100),
            wait_for_new_enrollment(&dir, "dev_SAME", Duration::from_millis(10)),
        )
        .await;
        assert!(
            res.is_err(),
            "same revoked id must not resume the heartbeat"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
