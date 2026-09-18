//! S3b-completion — LIVE two-peer WebRTC integration test (gated behind `--features webrtc`).
//!
//! Establishes a REAL RTCPeerConnection between two webrtc-rs peers on loopback (host candidates only —
//! NO external STUN, so the test needs no network), opens a DataChannel, wraps it in the concrete
//! `WebrtcTransport`, runs the agent's control-only protocol over it, and a scripted client on the other
//! side. Proves the full control flow + that no terminal-shaped message is accepted — over the REAL
//! channel, not a fake. Carries NO terminal data (control only).
//!
//! Run: `cargo test -p hydra-agent --features webrtc --test webrtc_peer`

#![cfg(feature = "webrtc")]

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use hydra_agent::remote_control::ControlChannel;
use hydra_agent::remote_token::{sign_token, TokenClaims};
use hydra_agent::remote_webrtc::rtc::WebrtcTransport;
use hydra_agent::remote_webrtc::run_control;
use tokio::sync::{mpsc, Mutex};
use webrtc::api::{setting_engine::SettingEngine, APIBuilder};
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::RTCPeerConnection;

fn keys() -> (SigningKey, VerifyingKey) {
    let mut seed = [5u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    (sk, vk)
}

/// Build two peers on a private in-memory network so host firewall/interface state cannot affect CI.
async fn new_peer_pair() -> (
    Arc<RTCPeerConnection>,
    Arc<RTCPeerConnection>,
    Arc<Mutex<webrtc::util::vnet::router::Router>>,
) {
    use webrtc::util::vnet::net::{Net, NetConfig};
    use webrtc::util::vnet::router::{Router, RouterConfig};

    let router = Arc::new(Mutex::new(
        Router::new(RouterConfig {
            cidr: "192.0.2.0/24".to_owned(),
            ..Default::default()
        })
        .unwrap(),
    ));
    let client_net = Arc::new(Net::new(Some(NetConfig {
        static_ips: vec!["192.0.2.1".to_owned()],
        ..Default::default()
    })));
    let agent_net = Arc::new(Net::new(Some(NetConfig {
        static_ips: vec!["192.0.2.2".to_owned()],
        ..Default::default()
    })));
    for network in [&client_net, &agent_net] {
        let nic = network.get_nic().unwrap();
        router.lock().await.add_net(Arc::clone(&nic)).await.unwrap();
        nic.lock()
            .await
            .set_router(Arc::clone(&router))
            .await
            .unwrap();
    }
    router.lock().await.start().await.unwrap();

    let mut client_settings = SettingEngine::default();
    client_settings.set_vnet(Some(client_net));
    let client = Arc::new(
        APIBuilder::new()
            .with_setting_engine(client_settings)
            .build()
            .new_peer_connection(RTCConfiguration::default())
            .await
            .unwrap(),
    );
    let mut agent_settings = SettingEngine::default();
    agent_settings.set_vnet(Some(agent_net));
    let agent = Arc::new(
        APIBuilder::new()
            .with_setting_engine(agent_settings)
            .build()
            .new_peer_connection(RTCConfiguration::default())
            .await
            .unwrap(),
    );
    (client, agent, router)
}

enum IceEvent {
    Candidate(RTCIceCandidateInit),
    Complete,
}

/// Capture ICE before installing either local description so early host candidates cannot be lost.
fn capture_ice(source: &Arc<RTCPeerConnection>) -> mpsc::UnboundedReceiver<IceEvent> {
    let (tx, rx) = mpsc::unbounded_channel();
    source.on_ice_candidate(Box::new(move |candidate| {
        let tx = tx.clone();
        Box::pin(async move {
            let event = match candidate {
                Some(candidate) => IceEvent::Candidate(candidate.to_json().unwrap()),
                None => IceEvent::Complete,
            };
            tx.send(event).expect("ICE capture remains live");
        })
    }));
    rx
}

async fn collect_ice(receiver: &mut mpsc::UnboundedReceiver<IceEvent>) -> Vec<RTCIceCandidateInit> {
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut candidates = Vec::new();
        loop {
            match receiver.recv().await.expect("ICE capture remains live") {
                IceEvent::Candidate(candidate) => candidates.push(candidate),
                IceEvent::Complete => return candidates,
            }
        }
    })
    .await
    .expect("ICE gathering completed")
}

/// Drive offer/answer between two local peers (in-memory signaling).
async fn handshake(
    client: &Arc<RTCPeerConnection>,
    agent: &Arc<RTCPeerConnection>,
    client_ice: &mut mpsc::UnboundedReceiver<IceEvent>,
    agent_ice: &mut mpsc::UnboundedReceiver<IceEvent>,
) {
    let offer = client.create_offer(None).await.unwrap();
    client.set_local_description(offer.clone()).await.unwrap();
    let client_candidates = collect_ice(client_ice).await;
    agent.set_remote_description(offer).await.unwrap();
    for candidate in client_candidates {
        agent.add_ice_candidate(candidate).await.unwrap();
    }
    agent
        .add_ice_candidate(RTCIceCandidateInit::default())
        .await
        .unwrap();

    let answer = agent.create_answer(None).await.unwrap();
    agent.set_local_description(answer.clone()).await.unwrap();
    let agent_candidates = collect_ice(agent_ice).await;
    client.set_remote_description(answer).await.unwrap();
    for candidate in agent_candidates {
        client.add_ice_candidate(candidate).await.unwrap();
    }
    client
        .add_ice_candidate(RTCIceCandidateInit::default())
        .await
        .unwrap();
}

/// Collect the client's inbound DataChannel text into an mpsc.
fn pipe_client_dc(dc: &Arc<RTCDataChannel>) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel::<String>(64);
    dc.on_message(Box::new(move |m: DataChannelMessage| {
        let tx = tx.clone();
        Box::pin(async move {
            if let Ok(s) = String::from_utf8(m.data.to_vec()) {
                let _ = tx.send(s).await;
            }
        })
    }));
    rx
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_two_peer_control_channel_enforces_the_boundary() {
    // webrtc-rs / rustls 0.23 needs a process-level crypto provider installed before any DTLS handshake.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let (sk, vk) = keys(); // VerifyingKey is Copy — moved into the spawned channel below

    // ---- two real peers on loopback ----
    let (client, agent, _router) = new_peer_pair().await;
    let mut client_ice = capture_ice(&client);
    let mut agent_ice = capture_ice(&agent);

    // The AGENT runs its control channel on whatever DataChannel the client opens.
    let agent_dc_tx = Arc::new(Mutex::new(None::<Arc<RTCDataChannel>>));
    let (opened_tx, mut opened_rx) = mpsc::channel::<Arc<RTCDataChannel>>(1);
    {
        let agent_dc_tx = agent_dc_tx.clone();
        agent.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
            let agent_dc_tx = agent_dc_tx.clone();
            let opened_tx = opened_tx.clone();
            Box::pin(async move {
                *agent_dc_tx.lock().await = Some(dc.clone());
                let dc2 = dc.clone();
                let opened_tx2 = opened_tx.clone();
                dc.on_open(Box::new(move || {
                    let dc2 = dc2.clone();
                    let opened_tx2 = opened_tx2.clone();
                    Box::pin(async move {
                        let _ = opened_tx2.send(dc2).await;
                    })
                }));
            })
        }));
    }

    // client creates the control DataChannel
    let client_dc = client
        .create_data_channel("hydra-control", None)
        .await
        .unwrap();
    let mut client_rx = pipe_client_dc(&client_dc);
    let (client_open_tx, mut client_open_rx) = mpsc::channel::<()>(1);
    {
        let t = client_open_tx.clone();
        client_dc.on_open(Box::new(move || {
            let t = t.clone();
            Box::pin(async move {
                let _ = t.send(()).await;
            })
        }));
    }

    handshake(&client, &agent, &mut client_ice, &mut agent_ice).await;

    // wait for both ends of the DataChannel to open
    let agent_dc = tokio::time::timeout(Duration::from_secs(10), opened_rx.recv())
        .await
        .expect("agent DataChannel opened")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), client_open_rx.recv())
        .await
        .expect("client DataChannel opened");

    // ---- run the agent's control protocol over the REAL DataChannel ----
    // Revocation flips on when we set the flag (proves live-revoke over the real channel).
    let revoked = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let revoked_for_channel = revoked.clone();
    let transport = WebrtcTransport::new(agent_dc);
    let agent_task = tokio::spawn(async move {
        let channel = ControlChannel::new(
            vk, // owned (Copy)
            "dev_a".into(),
            move |_a: &str, _d: &str, _iat_ms: u64| {
                revoked_for_channel.load(std::sync::atomic::Ordering::SeqCst)
            },
        );
        run_control(transport, channel, || 500).await
    });

    // helper: send a control message from the client, await one reply line
    async fn send(dc: &Arc<RTCDataChannel>, s: &str) {
        dc.send_text(s.to_string()).await.unwrap();
    }
    async fn recv(rx: &mut mpsc::Receiver<String>, stage: &str) -> String {
        // This is a live DTLS/SCTP integration test, and shared macOS CI runners can occasionally
        // pause the peer tasks for more than five seconds under load. Keep the bound finite while
        // naming the exact protocol stage if the real channel does not answer.
        tokio::time::timeout(Duration::from_secs(15), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("control reply within timeout at {stage}"))
            .expect("channel open")
    }

    // 1. hello
    send(
        &client_dc,
        r#"{"type":"hello","protocol_version":1,"device_id":"dev_a","role":"client"}"#,
    )
    .await;
    assert!(recv(&mut client_rx, "hello").await.contains("\"hello\""));

    // 2. pre-auth privileged request → refused
    send(&client_dc, r#"{"type":"list_request","request_id":"r0"}"#).await;
    assert!(recv(&mut client_rx, "pre-auth list")
        .await
        .contains("\"auth_refused\""));

    // 3. terminal-shaped message → rejected over the REAL channel
    send(&client_dc, r#"{"type":"data","bytes":"AAAA"}"#).await;
    let rej = recv(&mut client_rx, "terminal-message rejection").await;
    assert!(
        rej.contains("\"error\""),
        "terminal-shaped msg must be rejected: {rej}"
    );

    // 4. auth with a valid token → accepted
    let tok = sign_token(
        &TokenClaims {
            account_id: "acct".into(),
            device_id: "dev_a".into(),
            session_id: Some("sig".into()),
            signal_session_id: None,
            target_device_id: None,
            browser_pubkey: None,
            browser_pubkey_alg: None,
            refresh_parent_sha256: None,
            iat_ms: 0,
            exp_ms: 1_000_000,
        },
        &sk,
    );
    send(&client_dc, &format!(r#"{{"type":"auth","token":"{tok}"}}"#)).await;
    assert!(recv(&mut client_rx, "authentication")
        .await
        .contains("\"auth_ok\""));

    // 5. a session-scoped token cannot reach account-wide control state
    send(&client_dc, r#"{"type":"list_request","request_id":"r1"}"#).await;
    let lr = recv(&mut client_rx, "post-auth list").await;
    assert!(
        lr.contains("\"error\"") && lr.contains("\"code\":\"session_scope\""),
        "session-scoped token must be refused over the live channel: {lr}"
    );

    // 6. revoke → next privileged action fails
    revoked.store(true, std::sync::atomic::Ordering::SeqCst);
    send(&client_dc, r#"{"type":"list_request","request_id":"r2"}"#).await;
    assert!(recv(&mut client_rx, "post-revocation list")
        .await
        .contains("\"auth_refused\""));

    // 7. bye closes cleanly
    send(&client_dc, r#"{"type":"bye"}"#).await;
    assert!(recv(&mut client_rx, "bye").await.contains("\"bye\""));

    // The agent pump must return cleanly after bye/close; do not let a leaked or panicked task turn
    // into a false-positive boundary test.
    tokio::time::timeout(Duration::from_secs(15), agent_task)
        .await
        .expect("agent control task stopped after bye")
        .expect("agent control task did not panic")
        .expect("agent control task returned cleanly");

    // teardown
    let _ = client.close().await;
    let _ = agent.close().await;
}
