//! S3b — WebRTC transport seam. The control channel (`remote_control`) is transport-agnostic; this
//! module isolates the WebRTC dependency behind a tiny `RtcTransport` trait so the security boundary is
//! testable WITHOUT a live ICE connection, and so webrtc-rs stays optional (`webrtc` feature).
//!
//! S3b scope: CONTROL-ONLY DataChannel. NO PTY bridge, NO terminal streaming, NO files, NO TURN/relay
//! (direct/STUN only — public STUN is PROOF/PROTOTYPE only; the final product uses Hydra-managed
//! STUN/TURN; NO terminal data ever traverses STUN). The agent dials out via signaling — no public
//! listener.

use crate::remote_control::{ControlChannel, OutboundMsg};

/// A duplex control-message transport: one JSON message per `recv`, one per `send`. The WebRTC impl maps
/// these to DataChannel messages; the test impl is an in-memory queue.
pub trait RtcTransport {
    /// Receive the next inbound control line (JSON), or None when the channel is closed.
    fn recv(&mut self) -> impl std::future::Future<Output = Option<String>> + Send;
    /// Send one outbound control line (JSON).
    fn send(
        &mut self,
        line: String,
    ) -> impl std::future::Future<Output = anyhow::Result<()>> + Send;
    /// Close the channel (e.g. on revoke / bye).
    fn close(&mut self) -> impl std::future::Future<Output = ()> + Send;
}

/// Pump the agent's control channel over a transport until close. Each inbound line is handled by the
/// `ControlChannel` (auth boundary enforced there) and the reply sent back. On a `Bye`/close, returns.
/// `now_ms` supplies the clock for token expiry. NOTE: carries ONLY control messages — no terminal data.
pub async fn run_control<T, R>(
    mut transport: T,
    mut channel: ControlChannel<R>,
    now_ms: impl Fn() -> u64,
) -> anyhow::Result<()>
where
    T: RtcTransport,
    R: Fn(&str, &str, u64) -> bool,
{
    while let Some(line) = transport.recv().await {
        if let Some(reply) = channel.handle(&line, now_ms()) {
            let is_bye = matches!(reply, OutboundMsg::Bye);
            let json = serde_json::to_string(&reply)?;
            if transport.send(json).await.is_err() {
                break;
            }
            if is_bye {
                break;
            }
        }
    }
    transport.close().await;
    Ok(())
}

// ---- webrtc-rs transport (behind the `webrtc` feature) ----------------------------------------------
//
// A concrete `RtcTransport` over a webrtc-rs DataChannel. The offer/answer/ICE that build the peer
// connection come from signaling (S3a in production; an in-memory harness in tests) — this module does
// NOT talk to the cloud and carries ONLY control messages. Gated behind `webrtc` so the security-boundary
// core builds/tests without the heavy dep.
#[cfg(feature = "webrtc")]
pub mod rtc {
    //! ICE servers are built at connect time from the cloud relay creds (TURN + STUN on OUR relay host —
    //! never a public third party). NO terminal data ever traverses STUN/TURN (DTLS terminates at the two
    //! peers). For LOCAL two-peer tests we pass NO ice servers (host candidates on loopback) so the test
    //! needs no external network.

    use super::RtcTransport;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::{mpsc, Mutex};
    use webrtc::data_channel::data_channel_message::DataChannelMessage;
    use webrtc::data_channel::RTCDataChannel;

    /// webrtc-sctp 0.10 starts DATA retransmission after three seconds. A final control reply gets
    /// one retransmission plus a two-second acknowledgement margin before the separately bounded
    /// SCTP stream reset begins.
    const CONTROL_CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
    const CONTROL_CLOSE_TIMEOUT: Duration = Duration::from_secs(2);
    const CONTROL_CLOSE_DRAIN_POLL_INTERVAL: Duration = Duration::from_millis(10);

    /// Minimal close seam kept independent of `RTCDataChannel` so the final-frame ordering and
    /// stalled-peer bound are deterministic to test. In webrtc-sctp, `buffered_amount` reaches zero
    /// when SACK processing releases the queued application bytes; `send_text().await` alone only
    /// proves local queue admission.
    trait GracefullyClosableDataChannel: Send + Sync {
        async fn buffered_amount(&self) -> usize;
        async fn close_data_channel(&self);
    }

    impl GracefullyClosableDataChannel for RTCDataChannel {
        async fn buffered_amount(&self) -> usize {
            RTCDataChannel::buffered_amount(self).await
        }

        async fn close_data_channel(&self) {
            let _ = self.close().await;
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct GracefulCloseOutcome {
        drained: bool,
        close_returned: bool,
    }

    async fn drain_and_close_data_channel<C: GracefullyClosableDataChannel + ?Sized>(
        dc: &C,
        drain_timeout: Duration,
        close_timeout: Duration,
    ) -> GracefulCloseOutcome {
        let drained = tokio::time::timeout(drain_timeout, async {
            loop {
                if dc.buffered_amount().await == 0 {
                    return true;
                }
                tokio::time::sleep(CONTROL_CLOSE_DRAIN_POLL_INTERVAL).await;
            }
        })
        .await
        .unwrap_or(false);
        if !drained {
            tracing::warn!("remote-webrtc: final control reply did not drain before bounded close");
        }
        let close_returned = tokio::time::timeout(close_timeout, dc.close_data_channel())
            .await
            .is_ok();
        if !close_returned {
            tracing::warn!("remote-webrtc: DataChannel close timed out");
        }
        GracefulCloseOutcome {
            drained,
            close_returned,
        }
    }

    /// A control-message transport over a webrtc-rs DataChannel. Inbound DataChannel messages land on an
    /// mpsc the pump `recv()`s; `send()` writes via `send_text`. Text-framed JSON, one message per frame.
    pub struct WebrtcTransport {
        dc: Arc<RTCDataChannel>,
        inbound_rx: Mutex<mpsc::Receiver<String>>,
    }

    impl WebrtcTransport {
        /// Wrap a DataChannel. Registers an on_message handler that forwards text frames to `recv()`.
        pub fn new(dc: Arc<RTCDataChannel>) -> Arc<Self> {
            let (tx, rx) = mpsc::channel::<String>(64);
            let dc_for_handler = dc.clone();
            dc_for_handler.on_message(Box::new(move |msg: DataChannelMessage| {
                let tx = tx.clone();
                Box::pin(async move {
                    // Control channel is TEXT JSON; ignore binary (no byte-stream message type exists).
                    if let Ok(s) = String::from_utf8(msg.data.to_vec()) {
                        let _ = tx.send(s).await;
                    }
                })
            }));
            Arc::new(WebrtcTransport {
                dc,
                inbound_rx: Mutex::new(rx),
            })
        }
    }

    impl RtcTransport for Arc<WebrtcTransport> {
        async fn recv(&mut self) -> Option<String> {
            self.inbound_rx.lock().await.recv().await
        }
        async fn send(&mut self, line: String) -> anyhow::Result<()> {
            self.dc.send_text(line).await?;
            Ok(())
        }
        async fn close(&mut self) {
            let _ = drain_and_close_data_channel(
                self.dc.as_ref(),
                CONTROL_CLOSE_DRAIN_TIMEOUT,
                CONTROL_CLOSE_TIMEOUT,
            )
            .await;
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        #[derive(Default)]
        struct ControlledCloseDataChannel {
            buffered_amount: AtomicUsize,
            close_started: AtomicBool,
            closed_before_drain: AtomicBool,
            stall_close: AtomicBool,
        }

        impl GracefullyClosableDataChannel for ControlledCloseDataChannel {
            async fn buffered_amount(&self) -> usize {
                self.buffered_amount.load(Ordering::Acquire)
            }

            async fn close_data_channel(&self) {
                self.close_started.store(true, Ordering::Release);
                if self.buffered_amount.load(Ordering::Acquire) != 0 {
                    self.closed_before_drain.store(true, Ordering::Release);
                }
                if self.stall_close.load(Ordering::Acquire) {
                    std::future::pending::<()>().await;
                }
            }
        }

        #[tokio::test(start_paused = true)]
        async fn final_control_close_waits_for_sctp_drain() {
            let dc = Arc::new(ControlledCloseDataChannel::default());
            dc.buffered_amount.store(1, Ordering::Release);

            let dc_for_close = dc.clone();
            let close_task = tokio::spawn(async move {
                drain_and_close_data_channel(
                    dc_for_close.as_ref(),
                    Duration::from_secs(5),
                    Duration::from_secs(2),
                )
                .await
            });
            tokio::task::yield_now().await;
            assert!(
                !dc.close_started.load(Ordering::Acquire),
                "close must not overtake a queued final frame"
            );

            dc.buffered_amount.store(0, Ordering::Release);
            tokio::time::advance(CONTROL_CLOSE_DRAIN_POLL_INTERVAL).await;

            assert_eq!(
                close_task.await.expect("close task must finish"),
                GracefulCloseOutcome {
                    drained: true,
                    close_returned: true,
                }
            );
            assert!(dc.close_started.load(Ordering::Acquire));
            assert!(!dc.closed_before_drain.load(Ordering::Acquire));
        }

        #[tokio::test(start_paused = true)]
        async fn final_control_close_is_bounded_when_peer_never_drains() {
            let dc = ControlledCloseDataChannel::default();
            dc.buffered_amount.store(1, Ordering::Release);
            let started = tokio::time::Instant::now();

            assert_eq!(
                drain_and_close_data_channel(
                    &dc,
                    Duration::from_millis(25),
                    Duration::from_millis(25),
                )
                .await,
                GracefulCloseOutcome {
                    drained: false,
                    close_returned: true,
                },
                "a stalled drain must use the bounded close fallback"
            );

            assert_eq!(started.elapsed(), Duration::from_millis(25));
            assert!(dc.close_started.load(Ordering::Acquire));
            assert!(dc.closed_before_drain.load(Ordering::Acquire));
        }

        #[tokio::test(start_paused = true)]
        async fn final_control_close_is_bounded_when_stream_reset_never_returns() {
            let dc = ControlledCloseDataChannel::default();
            dc.stall_close.store(true, Ordering::Release);
            let started = tokio::time::Instant::now();

            assert_eq!(
                drain_and_close_data_channel(
                    &dc,
                    Duration::from_secs(5),
                    Duration::from_millis(25),
                )
                .await,
                GracefulCloseOutcome {
                    drained: true,
                    close_returned: false,
                }
            );

            assert_eq!(started.elapsed(), Duration::from_millis(25));
            assert!(dc.close_started.load(Ordering::Acquire));
            assert!(!dc.closed_before_drain.load(Ordering::Acquire));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_control::ControlChannel;
    use crate::remote_token::{sign_token, TokenClaims};
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use std::collections::VecDeque;

    /// In-memory transport: feed scripted inbound lines, capture outbound. No WebRTC needed.
    struct FakeTransport {
        inbound: VecDeque<String>,
        pub outbound: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        closed: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }
    impl RtcTransport for FakeTransport {
        async fn recv(&mut self) -> Option<String> {
            self.inbound.pop_front()
        }
        async fn send(&mut self, line: String) -> anyhow::Result<()> {
            self.outbound.lock().unwrap().push(line);
            Ok(())
        }
        async fn close(&mut self) {
            self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn keys() -> (SigningKey, VerifyingKey) {
        let mut seed = [9u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[tokio::test]
    async fn pump_runs_control_messages_over_a_fake_transport() {
        let (sk, vk) = keys();
        let tok = sign_token(
            &TokenClaims {
                account_id: "acct".into(),
                device_id: "dev_a".into(),
                // This test exercises the ordinary connection-wide control path. A value here is a
                // least-privilege daemon-session scope (not a signaling-session id) and must therefore
                // forbid `list_request` under the centralized scope policy.
                session_id: None,
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
        let inbound = VecDeque::from(vec![
            r#"{"type":"hello","protocol_version":1,"device_id":"dev_a","role":"client"}"#
                .to_string(),
            r#"{"type":"list_request","request_id":"r0"}"#.to_string(), // pre-auth → refused
            format!(r#"{{"type":"auth","token":"{tok}"}}"#),
            r#"{"type":"list_request","request_id":"r1"}"#.to_string(), // post-auth → ok
            r#"{"type":"bye"}"#.to_string(),
        ]);
        let outbound = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let closed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let transport = FakeTransport {
            inbound,
            outbound: outbound.clone(),
            closed: closed.clone(),
        };
        let channel = ControlChannel::new(vk, "dev_a".into(), |_, _, _| false);

        run_control(transport, channel, || 500).await.unwrap();

        let out = outbound.lock().unwrap().clone();
        let joined = out.join("\n");
        assert!(joined.contains("\"hello\""));
        assert!(joined.contains("\"auth_refused\"")); // the pre-auth list_request
        assert!(joined.contains("\"auth_ok\""));
        assert!(joined.contains("\"list_result\"")); // post-auth privileged request worked
        assert!(joined.contains("\"bye\""));
        assert!(
            closed.load(std::sync::atomic::Ordering::SeqCst),
            "transport closed at end"
        );
        // No terminal data ever appears on the wire.
        assert!(!joined.contains("\"pty\"") && !joined.contains("\"stdout\""));
    }
}
