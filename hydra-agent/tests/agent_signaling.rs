//! S3c-wiring — agent-side S3a signaling client round-trip against a tiny in-process HTTP server. Proves
//! the agent's `AgentSignaling` speaks the documented S3a shapes (pending/answer/ice) — no real cloud.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hydra_agent::remote_signaling::{
    AgentSignaling, FetchIceError, RevocationPoll, RevocationTerminalDenial,
};

#[derive(Debug)]
struct CapturedRequest {
    request_line: String,
    headers: HashMap<String, String>,
    body: String,
}

/// A one-shot fake cloud that answers a fixed JSON body for any request, capturing what it received.
fn fake_cloud(response_json: &'static str) -> (String, std::sync::mpsc::Receiver<CapturedRequest>) {
    fake_cloud_status(200, response_json)
}

fn fake_cloud_status(
    status: u16,
    response_json: &'static str,
) -> (String, std::sync::mpsc::Receiver<CapturedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = std::sync::mpsc::channel::<CapturedRequest>();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            // request line
            let mut req_line = String::new();
            reader.read_line(&mut req_line).ok();
            let mut headers = HashMap::new();
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).unwrap_or(0) == 0 {
                    break;
                }
                if h == "\r\n" || h == "\n" {
                    break;
                }
                if let Some((name, value)) = h.trim_end().split_once(':') {
                    headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
                }
            }
            let len = headers
                .get("content-length")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; len];
            if len > 0 {
                reader.read_exact(&mut body).ok();
            }
            let _ = tx.send(CapturedRequest {
                request_line: req_line.trim().to_string(),
                headers,
                body: String::from_utf8_lossy(&body).to_string(),
            });
            let resp = format!(
                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_json.len(),
                response_json
            );
            stream.write_all(resp.as_bytes()).ok();
        }
    });
    (format!("http://{addr}"), rx)
}

/// Accept one request and withhold the response until the test releases it. This makes cancellation observable
/// without relying on scheduler timing or waiting for the production HTTP timeout.
fn holding_cloud() -> (
    String,
    std::sync::mpsc::Receiver<CapturedRequest>,
    std::sync::mpsc::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (request_tx, request_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("pending request accepted");
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut headers = HashMap::new();
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap_or(0) == 0 || header == "\r\n" || header == "\n"
            {
                break;
            }
            if let Some((name, value)) = header.trim_end().split_once(':') {
                headers.insert(name.to_ascii_lowercase(), value.trim().to_string());
            }
        }
        request_tx
            .send(CapturedRequest {
                request_line: request_line.trim().to_string(),
                headers,
                body: String::new(),
            })
            .ok();
        if release_rx.recv_timeout(Duration::from_secs(5)).is_ok() {
            let body = r#"{"sessions":[]}"#;
            let response = format!(
                "HTTP/1.1 200 Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
            );
            stream.write_all(response.as_bytes()).ok();
        }
    });
    (format!("http://{addr}"), request_rx, release_tx)
}

/// Multi-request fake used to prove the instance-local relay credential cache and single-flight behavior.
fn relay_cloud(responses: Vec<(u16, String)>, delay: Duration) -> (String, Arc<AtomicUsize>) {
    assert!(!responses.is_empty());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let request_count = requests.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(stream) => stream,
                Err(_) => continue,
            };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            reader.read_line(&mut request_line).ok();
            let mut len = 0usize;
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap_or(0) == 0
                    || header == "\r\n"
                    || header == "\n"
                {
                    break;
                }
                if let Some(value) = header.to_lowercase().strip_prefix("content-length:") {
                    len = value.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; len];
            if len > 0 {
                reader.read_exact(&mut body).ok();
            }
            let index = request_count.fetch_add(1, Ordering::SeqCst);
            let (status, response_json) = &responses[index.min(responses.len() - 1)];
            if !delay.is_zero() {
                thread::sleep(delay);
            }
            let response = format!(
                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_json.len(),
                response_json
            );
            stream.write_all(response.as_bytes()).ok();
        }
    });
    (format!("http://{addr}"), requests)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn relay_json(expires_at_ms: u64) -> String {
    relay_json_with_ttl(expires_at_ms, serde_json::json!(120_000))
}

fn relay_json_with_ttl(expires_at_ms: u64, ttl_ms: serde_json::Value) -> String {
    serde_json::json!({
        "credentials": {
            "urls": ["turn:relay.example:3478?transport=udp"],
            "username": "synthetic-user",
            "credential": "synthetic-turn-secret",
            "expiresAtMs": expires_at_ms,
            "stunUrls": ["stun:relay.example:3478"],
            "ttlMs": ttl_ms
        }
    })
    .to_string()
}

#[tokio::test]
async fn relay_request_negotiates_the_version_two_relative_ttl_shape() {
    let (base, requests) = fake_cloud(
        r#"{"credentials":{"urls":["turn:relay.example:3478"],"username":"u","credential":"c","expiresAtMs":1,"ttlMs":120000}}"#,
    );
    let signaling = AgentSignaling::new(base, "dev:acct".into(), "dev_desk".into());

    assert!(signaling.relay_creds().await.is_some());
    let request = requests.recv().expect("captured relay request");
    let body: serde_json::Value = serde_json::from_str(&request.body).expect("request json");
    assert_eq!(
        body,
        serde_json::json!({ "deviceId": "dev_desk", "responseVersion": 2 })
    );
}

#[tokio::test]
async fn pending_parses_offers() {
    let (base, requests) = fake_cloud(
        r#"{"sessions":[{"sessionId":"sig_1","sourceDeviceId":"web_dev","offer":"OPAQUE"}]}"#,
    );
    let sig = AgentSignaling::new(base, "dev:acct".into(), "dev_desk".into());
    let pending = sig.pending().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].session_id, "sig_1");
    assert_eq!(pending[0].offer, "OPAQUE");
    assert_eq!(
        requests.recv().unwrap().request_line,
        "GET /v1/signal/sessions/pending?deviceId=dev_desk&waitMs=6000 HTTP/1.1"
    );
}

#[tokio::test]
async fn pending_long_poll_accepts_an_immediate_old_cloud_empty_response() {
    // An old cloud ignores the additive waitMs query and replies immediately. AgentSignaling must still accept
    // that ordinary 200 response; the outer peer loop applies the separately-tested one-second cycle floor.
    let (base, requests) = fake_cloud(r#"{"sessions":[]}"#);
    let sig = AgentSignaling::new(base, "dev:acct".into(), "dev_desk".into());

    assert!(sig.pending().await.unwrap().is_empty());
    assert_eq!(
        requests.recv().unwrap().request_line,
        "GET /v1/signal/sessions/pending?deviceId=dev_desk&waitMs=6000 HTTP/1.1"
    );
}

#[tokio::test]
async fn pending_signs_the_exact_canonical_long_poll_path() {
    use base64::Engine as _;

    let (base, requests) = fake_cloud(r#"{"sessions":[]}"#);
    let key = ed25519_dalek::SigningKey::from_bytes(&[17u8; 32]);
    let verifying_key = key.verifying_key();
    let sig =
        AgentSignaling::new_with_device_key(base, String::new(), "dev_desk".into(), Some(key));

    assert!(sig.pending().await.unwrap().is_empty());
    let request = requests.recv().expect("captured signed pending request");
    let expected_path = "/v1/signal/sessions/pending?deviceId=dev_desk&waitMs=6000";
    assert_eq!(
        request.request_line,
        format!("GET {expected_path} HTTP/1.1")
    );
    assert!(!request.headers.contains_key("authorization"));
    assert_eq!(
        request.headers.get("x-hydra-device-id").map(String::as_str),
        Some("dev_desk")
    );
    let timestamp_ms = request.headers["x-hydra-device-timestamp-ms"]
        .parse::<u64>()
        .expect("signed timestamp");
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(&request.headers["x-hydra-device-signature"])
        .expect("base64 signature");
    let signature = ed25519_dalek::Signature::from_bytes(
        &signature_bytes
            .try_into()
            .expect("ed25519 signature length"),
    );
    let body_sha = hydra_agent::device_request_auth::body_sha256_hex("");
    let message = hydra_agent::device_request_auth::request_message(
        "GET",
        expected_path,
        &body_sha,
        timestamp_ms,
    );
    verifying_key
        .verify_strict(message.as_bytes(), &signature)
        .expect("signature covers the exact canonical path and query");
}

#[tokio::test]
async fn cancelling_pending_drops_the_held_request_without_waiting_for_the_http_timeout() {
    let (base, requests, release) = holding_cloud();
    let sig = AgentSignaling::new(base, "dev:acct".into(), "dev_desk".into());
    let task = tokio::spawn(async move { sig.pending().await });

    let request = tokio::task::spawn_blocking(move || {
        requests
            .recv_timeout(Duration::from_secs(1))
            .expect("held pending request reached the server")
    })
    .await
    .expect("request observer thread joined");
    assert_eq!(
        request.request_line,
        "GET /v1/signal/sessions/pending?deviceId=dev_desk&waitMs=6000 HTTP/1.1"
    );
    task.abort();
    let joined = tokio::time::timeout(Duration::from_millis(250), task)
        .await
        .expect("cancelled request task must not wait for the 15-second client timeout");
    assert!(joined.expect_err("task should be cancelled").is_cancelled());
    release.send(()).ok();
}

#[tokio::test]
async fn answer_posts_the_documented_shape() {
    let (base, rx) = fake_cloud(r#"{"ok":true}"#);
    let sig = AgentSignaling::new(base, "dev:acct".into(), "dev_desk".into());
    sig.answer("sig_1", "OPAQUE_ANSWER").await.unwrap();
    let request = rx.recv().unwrap();
    assert!(request
        .request_line
        .contains("POST /v1/signal/sessions/sig_1/answer"));
    let v: serde_json::Value = serde_json::from_str(&request.body).unwrap();
    assert_eq!(v["deviceId"], "dev_desk");
    assert_eq!(v["answer"], "OPAQUE_ANSWER");
}

#[tokio::test]
async fn fetch_ice_parses_candidates_and_cursor() {
    let (base, _rx) = fake_cloud(r#"{"candidates":[{"candidate":"c1","seq":1}],"nextSince":1}"#);
    let sig = AgentSignaling::new(base, "dev:acct".into(), "dev_desk".into());
    let (cands, next) = sig.fetch_ice("sig_1", 0).await.unwrap();
    assert_eq!(cands.len(), 1);
    assert_eq!(cands[0].candidate, "c1");
    assert_eq!(next, 1);
}

#[tokio::test]
async fn fetch_ice_classifies_protocol_terminal_and_transient_failures() {
    let (base, _rx) = fake_cloud(r#"{"candidates":"not-an-array","nextSince":1}"#);
    let sig = AgentSignaling::new(base, "dev:acct".into(), "dev_desk".into());
    assert!(matches!(
        sig.fetch_ice("sig_1", 0).await,
        Err(FetchIceError::Protocol(_))
    ));

    for status in [401, 403, 404, 409] {
        let (base, _rx) = fake_cloud_status(status, r#"{"error":"terminal"}"#);
        let sig = AgentSignaling::new(base, "dev:acct".into(), "dev_desk".into());
        assert!(matches!(
            sig.fetch_ice("sig_1", 0).await,
            Err(FetchIceError::Terminal(_))
        ));
    }

    for status in [408, 425, 429, 503] {
        let (base, _rx) = fake_cloud_status(status, r#"{"error":"transient"}"#);
        let sig = AgentSignaling::new(base, "dev:acct".into(), "dev_desk".into());
        assert!(matches!(
            sig.fetch_ice("sig_1", 0).await,
            Err(FetchIceError::Transient(_))
        ));
    }
}

#[tokio::test]
async fn post_ice_sends_opaque_candidate() {
    let (base, rx) = fake_cloud(r#"{"ok":true,"seq":1}"#);
    let sig = AgentSignaling::new(base, "dev:acct".into(), "dev_desk".into());
    sig.post_ice("sig_1", "OPAQUE_CAND").await.unwrap();
    let request = rx.recv().unwrap();
    assert!(request
        .request_line
        .contains("POST /v1/signal/sessions/sig_1/ice"));
    let v: serde_json::Value = serde_json::from_str(&request.body).unwrap();
    assert_eq!(v["candidate"], "OPAQUE_CAND");
}

#[tokio::test]
async fn revocation_fetch_returns_terminal_denials_only_for_exact_cloud_responses() {
    for (status, body, expected) in [
        (
            404,
            r#"{"error":"unknown_device"}"#,
            RevocationTerminalDenial::UnknownDevice,
        ),
        (
            403,
            r#"{"error":"revoked"}"#,
            RevocationTerminalDenial::Revoked,
        ),
    ] {
        let (base, _rx) = fake_cloud_status(status, body);
        let sig = AgentSignaling::new(base, "dev:acct".into(), "dev_desk".into());
        assert_eq!(
            sig.fetch_revocations().await.unwrap(),
            RevocationPoll::TerminalDenial(expected)
        );
    }
}

#[tokio::test]
async fn revocation_fetch_keeps_generic_and_nonmatching_http_errors_transient() {
    for (status, body) in [
        (404, "not found"),
        (404, r#"{"error":"revoked"}"#),
        (404, r#"{"error":"unknown_device","detail":"not exact"}"#),
        (500, r#"{"error":"unknown_device"}"#),
    ] {
        let (base, _rx) = fake_cloud_status(status, body);
        let sig = AgentSignaling::new(base, "dev:acct".into(), "dev_desk".into());
        let error = sig.fetch_revocations().await.unwrap_err();
        assert_eq!(error, format!("revocations: HTTP {status}"));
    }
}

#[tokio::test]
async fn revocation_fetch_parses_a_successful_snapshot() {
    let (base, _rx) =
        fake_cloud(r#"{"selfRevoked":false,"revokedDeviceIds":["web_a"],"revokeBeforeMs":5000}"#);
    let sig = AgentSignaling::new(base, "dev:acct".into(), "dev_desk".into());
    let RevocationPoll::Snapshot(snapshot) = sig.fetch_revocations().await.unwrap() else {
        panic!("expected revocation snapshot");
    };
    assert!(!snapshot.self_revoked);
    assert_eq!(snapshot.revoked_device_ids, vec!["web_a"]);
    assert_eq!(snapshot.revoke_before_ms, 5000);
}

#[tokio::test]
async fn relay_credentials_are_cached_per_agent_signaling_instance() {
    // An absolute expiry that looks long-expired to this machine must not influence monotonic cache freshness.
    let (base, requests) = relay_cloud(vec![(200, relay_json(1))], Duration::ZERO);
    let signaling = AgentSignaling::new(base, "dev:acct".into(), "dev_desk".into());

    let first = signaling.relay_creds().await.expect("first credentials");
    let second = signaling.relay_creds().await.expect("cached credentials");

    assert_eq!(first, second);
    assert_eq!(requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn legacy_relay_credentials_are_used_once_but_never_cached() {
    let legacy = serde_json::json!({
        "credentials": {
            "urls": ["turn:relay.example:3478?transport=udp"],
            "username": "synthetic-user",
            "credential": "synthetic-turn-secret",
            "expiresAtMs": 9_007_199_254_740_991_u64,
            "stunUrls": ["stun:relay.example:3478"]
        }
    })
    .to_string();
    let (base, requests) = relay_cloud(vec![(200, legacy)], Duration::ZERO);
    let signaling = AgentSignaling::new(base, "dev:acct".into(), "dev_desk".into());

    assert!(signaling.relay_creds().await.is_some());
    assert!(signaling.relay_creds().await.is_some());
    assert_eq!(requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn concurrent_relay_callers_share_one_bounded_http_request() {
    let (base, requests) = relay_cloud(
        vec![(200, relay_json(now_ms() + 120_000))],
        Duration::from_millis(75),
    );
    let signaling = AgentSignaling::new(base, "dev:acct".into(), "dev_desk".into());

    let (first, second, third) = tokio::join!(
        signaling.relay_creds(),
        signaling.relay_creds(),
        signaling.relay_creds()
    );

    assert!(first.is_some() && second.is_some() && third.is_some());
    assert_eq!(requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn concurrent_relay_callers_share_one_refused_result_without_negative_caching() {
    let (base, requests) = relay_cloud(
        vec![
            (503, r#"{"error":"unavailable"}"#.to_string()),
            (200, relay_json(now_ms() + 120_000)),
        ],
        Duration::from_millis(75),
    );
    let signaling = AgentSignaling::new(base, "dev:acct".into(), "dev_desk".into());

    let (first, second, third) = tokio::join!(
        signaling.relay_creds(),
        signaling.relay_creds(),
        signaling.relay_creds()
    );
    assert!(first.is_none() && second.is_none() && third.is_none());
    assert_eq!(requests.load(Ordering::SeqCst), 1);

    // A failure is shared only with its concurrent waiters, never cached for a later connection attempt.
    assert!(signaling.relay_creds().await.is_some());
    assert_eq!(requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn short_relative_ttl_credentials_are_used_once_and_refetched() {
    let (base, requests) = relay_cloud(
        vec![
            (
                200,
                relay_json_with_ttl(now_ms() + 29_000, serde_json::json!(29_000)),
            ),
            (200, relay_json(now_ms() + 120_000)),
        ],
        Duration::ZERO,
    );
    let signaling = AgentSignaling::new(base, "dev:acct".into(), "dev_desk".into());

    assert!(signaling.relay_creds().await.is_some());
    assert!(signaling.relay_creds().await.is_some());
    assert_eq!(requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn malformed_relay_success_is_not_cached() {
    let malformed = serde_json::json!({
        "credentials": {
            "urls": ["https://not-turn.example"],
            "username": "synthetic-user",
            "credential": "synthetic-turn-secret",
            "expiresAtMs": now_ms() + 120_000
        }
    })
    .to_string();
    let (base, requests) = relay_cloud(
        vec![(200, malformed), (200, relay_json(now_ms() + 120_000))],
        Duration::ZERO,
    );
    let signaling = AgentSignaling::new(base, "dev:acct".into(), "dev_desk".into());

    assert!(signaling.relay_creds().await.is_none());
    assert!(signaling.relay_creds().await.is_some());
    assert_eq!(requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn relay_authorization_refusal_after_noncacheable_success_never_returns_stale_success() {
    let (base, requests) = relay_cloud(
        vec![
            (
                200,
                relay_json_with_ttl(now_ms() + 29_000, serde_json::json!(29_000)),
            ),
            (403, r#"{"error":"revoked"}"#.to_string()),
        ],
        Duration::ZERO,
    );
    let signaling = AgentSignaling::new(base, "dev:acct".into(), "dev_desk".into());

    assert!(signaling.relay_creds().await.is_some());
    assert!(signaling.relay_creds().await.is_none());
    assert_eq!(requests.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn separate_agent_signaling_instances_do_not_share_credentials() {
    let (base, requests) = relay_cloud(vec![(200, relay_json(now_ms() + 120_000))], Duration::ZERO);
    let first = AgentSignaling::new(base.clone(), "dev:acct".into(), "dev_desk".into());
    let second = AgentSignaling::new(base, "dev:acct".into(), "dev_desk".into());

    assert!(first.relay_creds().await.is_some());
    assert!(second.relay_creds().await.is_some());
    assert_eq!(requests.load(Ordering::SeqCst), 2);
}
