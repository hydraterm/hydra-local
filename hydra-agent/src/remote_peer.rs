//! S3c-wiring — the `remote-peer` runtime: the desktop agent's WebRTC peer that DIALS OUT via S3a
//! signaling (no public listener), answers a browser's offer, opens the control DataChannel, runs the
//! tested `ControlChannel` (token gate), and after auth bridges terminal traffic to the local daemon via
//! the production `DaemonBackend` + `TerminalBridge`. Direct OR relayed is transparent here — the browser
//! chooses the ICE path; the agent just answers and relays its own candidates.
//!
//! Feature-gated (`webrtc`). NO public listener. Content-blind: terminal bytes ride the DTLS DataChannel only;
//! only opaque SDP/ICE go to the cloud. A capability-gated additive Attach/restore-Grid generation echo gives
//! the agent an exact local daemon-output ownership boundary; retained daemons stay on legacy routing.

use std::collections::VecDeque;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::Context as _;
use base64::Engine as _;
use ed25519_dalek::Signer;
use ed25519_dalek::{SigningKey, VerifyingKey};
use tokio::sync::{mpsc, oneshot, watch, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

use crate::remote_bridge::{
    Outbound, TerminalBridge, TerminalEncoding, TerminalMsg, TerminalOutputTarget, TerminalReply,
    WorkspaceMetadata,
};
use crate::remote_control::{AuthenticatedAuthoritySnapshot, ControlChannel};
use crate::remote_daemon_backend::{
    spawn_daemon_task_with_policy, DaemonOutputReservation, RoutedDaemonOutput,
};
use crate::remote_frame::{decode, FrameKind};
use crate::remote_policy::SameAsLocalPolicy;
use crate::remote_signaling::{AgentSignaling, FetchIceError, IceCandidate};
use crate::setup_deadline::{DeadlineExpiry, ProgressDeadline};

/// Config for one remote-peer run.
pub struct PeerConfig {
    pub sock: PathBuf,
    /// Headless service peers bind to the fixed independently managed daemon socket and use the
    /// Unix account's trusted login shell for empty terminals. Desktop peers retain endpoint
    /// re-resolution and the established bare-shell launch policy.
    pub headless_server: bool,
    pub cloud_base: String,
    pub auth: String,      // cloud bearer (dev `dev:<acct>`)
    pub device_id: String, // THIS desktop device id (signaling target)
    /// Account id from the local enrollment snapshot. `Some` marks a production/enrolled channel: control auth
    /// independently binds tokens to this account and requires browser offer proof. None is only for explicit dev
    /// runs without device.json.
    pub enrolled_account_id: Option<String>,
    pub cloud_pubkey: VerifyingKey,
    /// Exact browser origins accepted for passkey browser certificates. Product services provide one
    /// release-bound origin; direct development callers may provide an explicit bounded list.
    pub allowed_origins: Vec<String>,
    /// The enrolled device PRIVATE key, used to sign presence heartbeats. None in dev/unenrolled runs
    /// (then no heartbeats are sent — presence just stays "Last seen …"). Never leaves the agent.
    pub device_key: Option<SigningKey>,
    pub seed_sessions: Vec<String>,
    /// agent data dir — where the heartbeat loop persists its content-blind last-status for `health`.
    pub agent_dir: PathBuf,
}

/// Max session ids remembered in the "already handled" set — bounds memory under an offer flood (oldest age out).
const MAX_HANDLED_SESSIONS: usize = 256;
/// Max concurrent serve tasks (each = one expensive WebRTC peer/DTLS setup). Over this, new offers wait for a
/// slot. Generous for real use (a few devices / refreshes) but caps a bogus-offer flood.
const MAX_CONCURRENT_SERVES: usize = 16;
/// An old cloud returns an empty pending-offer response immediately. Preserve the established one-request/second
/// floor for that rolling-upgrade case; a capable cloud holds for six seconds, so the next request renews without
/// an additional client-side delay.
const PENDING_OFFER_EMPTY_CYCLE_FLOOR: std::time::Duration =
    std::time::Duration::from_millis(1_000);
const PENDING_OFFER_ERROR_BACKOFF: std::time::Duration = std::time::Duration::from_millis(1_500);
/// The signaling service accepts 128 opaque candidates total from both peers. Reserve one half for the browser,
/// bound each candidate to the service's 2 KiB contract, and keep the agent's entire pre-open FIFO in memory only.
const MAX_LOCAL_ICE_CANDIDATES_PER_SESSION: usize = 64;
const MAX_LOCAL_ICE_CANDIDATE_BYTES: usize = 2 * 1024;
const MAX_REMOTE_ICE_CANDIDATES_PER_SESSION: usize = 64;
const MAX_REMOTE_ICE_CANDIDATE_BYTES: usize = 2 * 1024;
const MAX_REMOTE_ICE_BYTES_PER_SESSION: usize =
    MAX_REMOTE_ICE_CANDIDATES_PER_SESSION * MAX_REMOTE_ICE_CANDIDATE_BYTES;
const MAX_SIGNAL_ICE_SEQUENCE: u64 =
    (MAX_LOCAL_ICE_CANDIDATES_PER_SESSION + MAX_REMOTE_ICE_CANDIDATES_PER_SESSION) as u64;
const LOCAL_ICE_POST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const REMOTE_ICE_APPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const INBOUND_ICE_POLL_CADENCE: InboundIcePollCadence = InboundIcePollCadence {
    settled_interval: std::time::Duration::from_millis(700),
    early_delay: std::time::Duration::from_millis(250),
};
const SETUP_INACTIVITY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
const SETUP_ABSOLUTE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);
const SETUP_PROGRESS_QUEUE_CAPACITY: usize = 256;
const DATA_CHANNEL_PUBLICATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const LOCAL_ICE_RETRY_DELAYS: [std::time::Duration; 3] = [
    std::time::Duration::from_millis(100),
    std::time::Duration::from_millis(250),
    std::time::Duration::from_millis(500),
];
/// Explicit ICE liveness contract for the agent peer. Without this, webrtc-rs silently applies its 5s/25s/2s
/// defaults, and 5s-to-`Disconnected` plus the (previously 5s) owner grace below turned any transient forced-relay
/// gap — relay-side NAT/conntrack churn, allocation pruning, pair re-selection — into a permanent close in ~10s:
/// exactly the observed 5-12s forced-relay session death. 10s tolerates those gaps and mirrors the browser
/// bridge's own 10s disconnected grace (`WEBRTC_DISCONNECTED_GRACE_MS`).
const ICE_DISCONNECTED_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Library-terminal `Failed` verdict. Kept above disconnected+grace so OUR bounded, resource-releasing close
/// always fires before webrtc-rs declares failure on its own schedule, never after it.
const ICE_FAILED_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// webrtc-rs default, pinned explicitly so a library default change cannot silently alter this liveness math.
const ICE_KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
/// A disconnected transport may recover during a short network handoff. Do not hold a serve slot, daemon bridge,
/// and remote winsize presence until the ICE failure timeout, though: if neither the PeerConnection nor ICE state
/// recovers within this window after `Disconnected`, the session owner closes the peer explicitly. Worst-case
/// owner close = ICE_DISCONNECTED_TIMEOUT + this grace (20s), still ahead of ICE_FAILED_TIMEOUT (30s).
const PEER_DISCONNECTED_GRACE: std::time::Duration = std::time::Duration::from_secs(10);
const ANSWER_PROOF_PURPOSE: &str = "hydra-webrtc-answer-v1";
const B64_STD: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

/// Maximum daemon-envelope prefix inspected solely to choose a content-blind tracing label. The daemon's
/// internally tagged serde representation always emits `ev` as the first member, so production terminal frames
/// need only a few bytes regardless of how large their grid/scrollback payload is. Small non-canonical fixtures
/// are parsed completely to preserve JSON key-order tolerance without turning a multi-MiB terminal line into a
/// second full JSON parse.
const TERMINAL_EVENT_PREFIX_LIMIT: usize = 1024;

fn pending_offer_empty_cycle_delay(elapsed: std::time::Duration) -> std::time::Duration {
    PENDING_OFFER_EMPTY_CYCLE_FLOOR.saturating_sub(elapsed)
}

fn headless_authority_changed(
    headless_server: bool,
    account: &str,
    revoked: &impl Fn(&str, &str, u64) -> bool,
) -> bool {
    headless_server && revoked(account, "", 0)
}

fn allowlisted_terminal_event_label(event: &str) -> Option<&'static str> {
    Some(match event {
        "daemon_info" => "daemon_info",
        "terminal_bell" => "terminal_bell",
        "terminal_title" => "terminal_title",
        "terminal_clipboard_store" => "terminal_clipboard_store",
        "output" => "output",
        "grid" => "grid",
        "scrollback_rows" => "scrollback_rows",
        "damage" => "damage",
        "session_exited" => "session_exited",
        "resync_required" => "resync_required",
        "sessions" => "sessions",
        "channel" => "channel",
        "error" => "error",
        _ => return None,
    })
}

fn canonical_terminal_event_second_key(event: &str) -> Option<&'static str> {
    Some(match event {
        "daemon_info" => "protocol_version",
        "terminal_bell"
        | "terminal_title"
        | "terminal_clipboard_store"
        | "output"
        | "grid"
        | "scrollback_rows"
        | "session_exited"
        | "resync_required" => "id",
        "damage" => "frame",
        "sessions" => "ids",
        "channel" => "event",
        "error" => "message",
        _ => return None,
    })
}

struct CompleteTerminalEventLabel(Option<&'static str>);

impl<'de> serde::Deserialize<'de> for CompleteTerminalEventLabel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CompleteVisitor;

        impl<'de> serde::de::Visitor<'de> for CompleteVisitor {
            type Value = CompleteTerminalEventLabel;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a bounded daemon event object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut saw_event = false;
                let mut label = None;
                while let Some(key) = map.next_key::<String>()? {
                    if key == "ev" {
                        if saw_event {
                            return Err(serde::de::Error::duplicate_field("ev"));
                        }
                        saw_event = true;
                        let event = map.next_value::<String>()?;
                        label = allowlisted_terminal_event_label(&event);
                    } else {
                        map.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
                Ok(CompleteTerminalEventLabel(label))
            }
        }

        deserializer.deserialize_map(CompleteVisitor)
    }
}

fn skip_json_whitespace(bytes: &[u8], cursor: &mut usize) {
    while matches!(
        bytes.get(*cursor).copied(),
        Some(b' ' | b'\n' | b'\r' | b'\t')
    ) {
        *cursor += 1;
    }
}

fn bounded_json_string(bytes: &[u8], cursor: &mut usize) -> Option<String> {
    skip_json_whitespace(bytes, cursor);
    let start = *cursor;
    if bytes.get(*cursor) != Some(&b'"') {
        return None;
    }
    *cursor += 1;
    let mut escaped = false;
    while let Some(byte) = bytes.get(*cursor).copied() {
        *cursor += 1;
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' => escaped = true,
            b'"' => return serde_json::from_slice(&bytes[start..*cursor]).ok(),
            0x00..=0x1f => return None,
            _ => {}
        }
    }
    None
}

fn canonical_terminal_event_label(prefix: &[u8]) -> Option<&'static str> {
    let mut cursor = 0;
    skip_json_whitespace(prefix, &mut cursor);
    if prefix.get(cursor) != Some(&b'{') {
        return None;
    }
    cursor += 1;
    let key = bounded_json_string(prefix, &mut cursor)?;
    if key != "ev" {
        // Large reordered input is not the daemon's canonical serialization. Do not search through an
        // attacker-controlled payload for a plausible tag; fail to the fixed `unknown` label instead.
        return None;
    }
    skip_json_whitespace(prefix, &mut cursor);
    if prefix.get(cursor) != Some(&b':') {
        return None;
    }
    cursor += 1;
    let event = bounded_json_string(prefix, &mut cursor)?;
    let label = allowlisted_terminal_event_label(&event)?;
    skip_json_whitespace(prefix, &mut cursor);
    if prefix.get(cursor) != Some(&b',') {
        return None;
    }
    cursor += 1;
    let second_key = bounded_json_string(prefix, &mut cursor)?;
    if Some(second_key.as_str()) != canonical_terminal_event_second_key(&event) {
        return None;
    }
    skip_json_whitespace(prefix, &mut cursor);
    if prefix.get(cursor) != Some(&b':') {
        return None;
    }
    Some(label)
}

/// Extract a fixed tracing label without copying, logging, or fully decoding terminal content. Small envelopes can
/// tolerate legal JSON member reordering and are checked completely (including duplicate `ev` rejection). Large
/// envelopes use only the daemon serializer's canonical first-member contract and never inspect beyond the fixed
/// prefix. Unknown, malformed, non-string, future, or non-canonical inputs all retain the legacy `unknown` fallback.
fn terminal_event_log_label(line: &str) -> &'static str {
    let label = if line.len() <= TERMINAL_EVENT_PREFIX_LIMIT {
        serde_json::from_str::<CompleteTerminalEventLabel>(line)
            .ok()
            .and_then(|parsed| parsed.0)
    } else {
        let prefix = &line.as_bytes()[..TERMINAL_EVENT_PREFIX_LIMIT];
        canonical_terminal_event_label(prefix)
    };
    label.unwrap_or("unknown")
}

type LiveRevocationCheck = dyn Fn(&str, &str, u64) -> bool + Send + Sync;

/// The binary DataChannel callback runs independently of `serve_control`. Keep its authority in a
/// separate fail-closed gate so waiting for an outbound frame's physical completion can never let
/// an expired or newly-revoked browser continue writing to a PTY.
#[derive(Clone)]
struct ConnectionAuthorityGate {
    peer_device_id: Arc<str>,
    revoked: Arc<LiveRevocationCheck>,
    authority: Arc<std::sync::RwLock<Option<AuthenticatedAuthoritySnapshot>>>,
    revocation_observed: Arc<AtomicBool>,
    end_event_sent: Arc<AtomicBool>,
}

impl ConnectionAuthorityGate {
    fn new(
        peer_device_id: impl Into<Arc<str>>,
        revoked: impl Fn(&str, &str, u64) -> bool + Send + Sync + 'static,
    ) -> Self {
        Self {
            peer_device_id: peer_device_id.into(),
            revoked: Arc::new(revoked),
            authority: Arc::new(std::sync::RwLock::new(None)),
            revocation_observed: Arc::new(AtomicBool::new(false)),
            end_event_sent: Arc::new(AtomicBool::new(false)),
        }
    }

    fn replace(&self, authority: Option<AuthenticatedAuthoritySnapshot>) {
        match self.authority.write() {
            Ok(mut slot) => *slot = authority,
            Err(poisoned) => {
                // A panicked authority writer must never leave its last positive grant usable.
                *poisoned.into_inner() = None;
            }
        }
    }

    fn clear(&self) {
        self.replace(None);
    }

    /// A rejected peer can continue flooding binary callbacks until transport teardown reaches the
    /// owner. Admit exactly one event into the otherwise-unbounded liveness channel.
    fn claim_end_event(&self) -> bool {
        !self.end_event_sent.swap(true, Ordering::AcqRel)
    }

    fn permits_at(&self, now_ms: u64) -> bool {
        if self.revocation_observed.load(Ordering::Acquire) {
            return false;
        }
        match self.authority.read() {
            Ok(slot) => slot
                .as_ref()
                .is_some_and(|authority| now_ms < authority.expires_at_ms),
            // Lock poisoning is an integrity failure, therefore a denial rather than recovery to
            // the possibly-stale positive value.
            Err(_) => false,
        }
    }

    /// Linearize admission with authority replacement/removal while executing one synchronous PTY
    /// enqueue. A watcher that has taken the write side cannot be overtaken by a callback whose
    /// earlier fast check passed.
    fn with_permit_at<T>(&self, now_ms: u64, action: impl FnOnce() -> T) -> Option<T> {
        if self.revocation_observed.load(Ordering::Acquire) {
            return None;
        }
        let authority = self.authority.read().ok()?;
        if self.revocation_observed.load(Ordering::Acquire)
            || authority
                .as_ref()
                .is_none_or(|authority| now_ms >= authority.expires_at_ms)
        {
            return None;
        }
        Some(action())
    }

    fn deny_observed_authority(&self) {
        // Publish removal before waiting behind any already-admitted PTY enqueue. New callbacks
        // consult this monotonic bit before taking the read side, so queued readers cannot barge
        // ahead of cleanup or extend authority while the writer waits.
        self.revocation_observed.store(true, Ordering::Release);
        let mut authority = match self.authority.write() {
            Ok(authority) => authority,
            Err(poisoned) => poisoned.into_inner(),
        };
        *authority = None;
    }

    /// Refresh the potentially-I/O-backed revocation source outside the high-rate input callback.
    /// Once observed, removal is monotonic for this concrete DataChannel lifetime.
    fn observe_revocation_at(&self, now_ms: u64) -> Option<bool> {
        let authority = match self.authority.read() {
            Ok(slot) => slot.clone(),
            Err(_) => None,
        };
        let authority = authority?;
        if now_ms >= authority.expires_at_ms
            || (self.revoked)(
                &authority.account_id,
                &self.peer_device_id,
                authority.revocation_iat_ms,
            )
        {
            self.deny_observed_authority();
            return Some(false);
        }
        Some(true)
    }
}

async fn run_connection_authority_watchdog(
    authority: ConnectionAuthorityGate,
    liveness_tx: mpsc::UnboundedSender<PeerTransportEvent>,
) {
    let mut check = tokio::time::interval(REVOKE_CHECK_INTERVAL);
    check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // `interval`'s first tick is immediate. Consume it so each connection performs at most one
    // potentially filesystem-backed local-enrollment check per configured interval.
    check.tick().await;
    loop {
        check.tick().await;
        if authority.observe_revocation_at(now_ms()) == Some(false) {
            if authority.claim_end_event() {
                let _ = liveness_tx.send(PeerTransportEvent::AuthorityEnded);
            }
            return;
        }
    }
}

struct ConnectionAuthorityCleanup(ConnectionAuthorityGate);

impl Drop for ConnectionAuthorityCleanup {
    fn drop(&mut self) {
        self.0.clear();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerTransportEvent {
    Peer(RTCPeerConnectionState),
    Ice(RTCIceConnectionState),
    DataChannelClosed,
    OutboundSenderFailed,
    AuthorityEnded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SetupPeerState {
    Unspecified,
    New,
    Connecting,
    Connected,
    Disconnected,
    Failed,
    Closed,
}

impl From<RTCPeerConnectionState> for SetupPeerState {
    fn from(state: RTCPeerConnectionState) -> Self {
        match state {
            RTCPeerConnectionState::Unspecified => Self::Unspecified,
            RTCPeerConnectionState::New => Self::New,
            RTCPeerConnectionState::Connecting => Self::Connecting,
            RTCPeerConnectionState::Connected => Self::Connected,
            RTCPeerConnectionState::Disconnected => Self::Disconnected,
            RTCPeerConnectionState::Failed => Self::Failed,
            RTCPeerConnectionState::Closed => Self::Closed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SetupIceState {
    Unspecified,
    New,
    Checking,
    Connected,
    Completed,
    Disconnected,
    Failed,
    Closed,
}

impl From<RTCIceConnectionState> for SetupIceState {
    fn from(state: RTCIceConnectionState) -> Self {
        match state {
            RTCIceConnectionState::Unspecified => Self::Unspecified,
            RTCIceConnectionState::New => Self::New,
            RTCIceConnectionState::Checking => Self::Checking,
            RTCIceConnectionState::Connected => Self::Connected,
            RTCIceConnectionState::Completed => Self::Completed,
            RTCIceConnectionState::Disconnected => Self::Disconnected,
            RTCIceConnectionState::Failed => Self::Failed,
            RTCIceConnectionState::Closed => Self::Closed,
        }
    }
}

/// Content-blind, owner-local setup milestones. Numbered ICE keys are monotonic counts, never candidate data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SetupProgressKey {
    RelayCredentialsFetched,
    PeerConnectionCreated,
    RemoteDescriptionInstalled,
    AnswerCreated,
    LocalDescriptionInstalled,
    AnswerAcknowledged,
    LocalIcePosted(u64),
    InboundIceApplied(u64),
    PeerState(SetupPeerState),
    IceState(SetupIceState),
}

#[derive(Debug, Clone, Copy)]
struct SetupProgressEvent {
    key: SetupProgressKey,
    observed_at: tokio::time::Instant,
}

#[derive(Clone)]
struct SetupProgressReporter {
    tx: mpsc::Sender<SetupProgressEvent>,
}

impl SetupProgressReporter {
    fn channel() -> (Self, mpsc::Receiver<SetupProgressEvent>) {
        let (tx, rx) = mpsc::channel(SETUP_PROGRESS_QUEUE_CAPACITY);
        (Self { tx }, rx)
    }

    fn report(&self, key: SetupProgressKey) -> bool {
        self.tx
            .try_send(SetupProgressEvent {
                key,
                observed_at: tokio::time::Instant::now(),
            })
            .is_ok()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerCloseReason {
    PeerFailed,
    IceFailed,
    PeerClosed,
    IceClosed,
    DataChannelClosed,
    OutboundSenderFailed,
    AuthorityEnded,
    DisconnectedGraceExpired,
}

impl std::fmt::Display for PeerCloseReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = match self {
            Self::PeerFailed => "peer connection failed",
            Self::IceFailed => "ICE connection failed",
            Self::PeerClosed => "peer connection closed",
            Self::IceClosed => "ICE connection closed",
            Self::DataChannelClosed => "DataChannel closed",
            Self::OutboundSenderFailed => "outbound DataChannel sender failed",
            Self::AuthorityEnded => "remote authority ended",
            Self::DisconnectedGraceExpired => "peer remained disconnected past grace",
        };
        f.write_str(reason)
    }
}

/// Owner-scoped transport liveness. WebRTC callbacks enqueue state changes; the one session owner consumes them
/// from its existing select loop. A duplicate callback cannot extend the original grace deadline, a healthy state
/// cancels it, and callbacks racing after owner teardown are harmless because their send simply fails.
struct PeerLiveness {
    rx: mpsc::UnboundedReceiver<PeerTransportEvent>,
    peer_disconnected: bool,
    ice_disconnected: bool,
    disconnected_deadline: Option<tokio::time::Instant>,
    grace: std::time::Duration,
}

impl PeerLiveness {
    fn channel(
        grace: std::time::Duration,
    ) -> (mpsc::UnboundedSender<PeerTransportEvent>, PeerLiveness) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            tx,
            Self {
                rx,
                peer_disconnected: false,
                ice_disconnected: false,
                disconnected_deadline: None,
                grace,
            },
        )
    }

    fn observe(
        &mut self,
        event: PeerTransportEvent,
        now: tokio::time::Instant,
    ) -> Option<PeerCloseReason> {
        let terminal = match event {
            PeerTransportEvent::Peer(RTCPeerConnectionState::Failed) => {
                Some(PeerCloseReason::PeerFailed)
            }
            PeerTransportEvent::Ice(RTCIceConnectionState::Failed) => {
                Some(PeerCloseReason::IceFailed)
            }
            PeerTransportEvent::Peer(RTCPeerConnectionState::Closed) => {
                Some(PeerCloseReason::PeerClosed)
            }
            PeerTransportEvent::Ice(RTCIceConnectionState::Closed) => {
                Some(PeerCloseReason::IceClosed)
            }
            PeerTransportEvent::DataChannelClosed => Some(PeerCloseReason::DataChannelClosed),
            PeerTransportEvent::OutboundSenderFailed => Some(PeerCloseReason::OutboundSenderFailed),
            PeerTransportEvent::AuthorityEnded => Some(PeerCloseReason::AuthorityEnded),
            _ => None,
        };
        if terminal.is_some() {
            return terminal;
        }

        // A source that reported Disconnected remains outstanding through Connecting/Checking: those states mean a
        // recovery is being attempted, not that it succeeded. Only Connected (or ICE Completed) clears that source.
        match event {
            PeerTransportEvent::Peer(RTCPeerConnectionState::Disconnected) => {
                self.peer_disconnected = true
            }
            PeerTransportEvent::Peer(RTCPeerConnectionState::Connected) => {
                self.peer_disconnected = false
            }
            PeerTransportEvent::Ice(RTCIceConnectionState::Disconnected) => {
                self.ice_disconnected = true
            }
            PeerTransportEvent::Ice(
                RTCIceConnectionState::Connected | RTCIceConnectionState::Completed,
            ) => self.ice_disconnected = false,
            _ => {}
        }

        if self.peer_disconnected || self.ice_disconnected {
            // `get_or_insert` is intentional: duplicate Disconnected callbacks must not prolong a dead peer.
            self.disconnected_deadline.get_or_insert(now + self.grace);
        } else {
            // Connected/Completed recovery from every source that reported Disconnected cancels the grace.
            self.disconnected_deadline = None;
        }
        None
    }

    /// Before the DataChannel is Open, one progress deadline owns setup. Consume terminal transport states
    /// immediately, but do not start the established connection's five-second disconnect grace yet. Source state
    /// is retained so `activate_established` can begin that unchanged post-open policy from the handoff point.
    fn observe_setup(&mut self, event: PeerTransportEvent) -> Option<PeerCloseReason> {
        let terminal = match event {
            PeerTransportEvent::Peer(RTCPeerConnectionState::Failed) => {
                Some(PeerCloseReason::PeerFailed)
            }
            PeerTransportEvent::Ice(RTCIceConnectionState::Failed) => {
                Some(PeerCloseReason::IceFailed)
            }
            PeerTransportEvent::Peer(RTCPeerConnectionState::Closed) => {
                Some(PeerCloseReason::PeerClosed)
            }
            PeerTransportEvent::Ice(RTCIceConnectionState::Closed) => {
                Some(PeerCloseReason::IceClosed)
            }
            PeerTransportEvent::DataChannelClosed => Some(PeerCloseReason::DataChannelClosed),
            PeerTransportEvent::OutboundSenderFailed => Some(PeerCloseReason::OutboundSenderFailed),
            PeerTransportEvent::AuthorityEnded => Some(PeerCloseReason::AuthorityEnded),
            _ => None,
        };
        if terminal.is_some() {
            return terminal;
        }

        match event {
            PeerTransportEvent::Peer(RTCPeerConnectionState::Disconnected) => {
                self.peer_disconnected = true
            }
            PeerTransportEvent::Peer(RTCPeerConnectionState::Connected) => {
                self.peer_disconnected = false
            }
            PeerTransportEvent::Ice(RTCIceConnectionState::Disconnected) => {
                self.ice_disconnected = true
            }
            PeerTransportEvent::Ice(
                RTCIceConnectionState::Connected | RTCIceConnectionState::Completed,
            ) => self.ice_disconnected = false,
            _ => {}
        }
        self.disconnected_deadline = None;
        None
    }

    async fn wait_until_setup_terminal(&mut self) -> PeerCloseReason {
        loop {
            let Some(event) = self.rx.recv().await else {
                return std::future::pending().await;
            };
            if let Some(reason) = self.observe_setup(event) {
                return reason;
            }
        }
    }

    fn activate_established(&mut self, now: tokio::time::Instant) {
        self.disconnected_deadline =
            (self.peer_disconnected || self.ice_disconnected).then_some(now + self.grace);
    }

    async fn wait_until_dead(&mut self) -> PeerCloseReason {
        loop {
            if let Some(deadline) = self.disconnected_deadline {
                tokio::select! {
                    event = self.rx.recv() => {
                        let Some(event) = event else {
                            return std::future::pending().await;
                        };
                        if let Some(reason) = self.observe(event, tokio::time::Instant::now()) {
                            return reason;
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        // The deadline is cleared synchronously by a genuine recovery event. Reaching this arm with
                        // a deadline still installed therefore means at least one transport stayed disconnected.
                        if self.disconnected_deadline.is_some() {
                            return PeerCloseReason::DisconnectedGraceExpired;
                        }
                    }
                }
            } else {
                let Some(event) = self.rx.recv().await else {
                    return std::future::pending().await;
                };
                if let Some(reason) = self.observe(event, tokio::time::Instant::now()) {
                    return reason;
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalIceEnqueueError {
    Retired,
    Empty,
    EncodeFailed,
    TooLarge,
    SessionLimit,
    QueueClosed,
    QueueFull,
}

fn enqueue_local_ice_candidate(
    tx: &mpsc::Sender<String>,
    accepted: &AtomicUsize,
    retired: &AtomicBool,
    candidate: String,
) -> Result<(), LocalIceEnqueueError> {
    if retired.load(Ordering::Acquire) {
        return Err(LocalIceEnqueueError::Retired);
    }
    let bytes = candidate.len();
    if bytes == 0 {
        return Err(LocalIceEnqueueError::Empty);
    }
    if bytes > MAX_LOCAL_ICE_CANDIDATE_BYTES {
        return Err(LocalIceEnqueueError::TooLarge);
    }
    accepted
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            (count < MAX_LOCAL_ICE_CANDIDATES_PER_SESSION).then_some(count + 1)
        })
        .map_err(|_| LocalIceEnqueueError::SessionLimit)?;
    tx.try_send(candidate).map_err(|error| match error {
        mpsc::error::TrySendError::Closed(_) => LocalIceEnqueueError::QueueClosed,
        mpsc::error::TrySendError::Full(_) => LocalIceEnqueueError::QueueFull,
    })
}

type LocalIcePostFuture = Pin<Box<dyn Future<Output = Result<(), ()>> + Send>>;

/// Drain agent-local candidates in native gathering order. Only one POST can be in flight; retries retain the FIFO
/// head. Any exhausted pre-open failure retires this exact serve owner through its existing liveness channel. The
/// task itself is session-owned and aborted as soon as the DataChannel opens, so setup signaling can never delay or
/// tear down an already-established channel.
async fn run_local_ice_poster<P>(
    mut rx: mpsc::Receiver<String>,
    post: P,
    setup_failure_tx: mpsc::Sender<()>,
    retired: Arc<AtomicBool>,
    post_timeout: std::time::Duration,
    retry_delays: &[std::time::Duration],
) where
    P: Fn(String) -> LocalIcePostFuture,
{
    while let Some(candidate) = rx.recv().await {
        let mut failures = 0usize;
        loop {
            if retired.load(Ordering::Acquire) {
                return;
            }
            let result = tokio::time::timeout(post_timeout, post(candidate.clone())).await;
            if matches!(result, Ok(Ok(()))) {
                break;
            }
            let Some(delay) = retry_delays.get(failures).copied() else {
                if !retired.load(Ordering::Acquire) {
                    let _ = setup_failure_tx.try_send(());
                }
                return;
            };
            failures += 1;
            tokio::time::sleep(delay).await;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboundIceValidationError {
    CandidateCount,
    CandidateBytes,
    AggregateBytes,
    CandidateSequence,
    Cursor,
    CandidateParse,
}

struct StagedInboundIceBatch {
    candidates: Vec<RTCIceCandidateInit>,
    bytes: usize,
    next_since: u64,
}

/// The cloud candidate list is untrusted setup input. Keep the committed cursor and resource accounting together
/// so a malformed suffix can never admit a valid prefix or advance `since`. Sequence gaps are valid because both
/// peers share the cloud session's global sequence; duplicates, reordering, regressions, and values beyond that
/// global quota are not.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct InboundIceAdmission {
    since: u64,
    accepted_candidates: usize,
    accepted_bytes: usize,
}

impl InboundIceAdmission {
    fn stage(
        &self,
        candidates: Vec<IceCandidate>,
        next_since: u64,
    ) -> Result<StagedInboundIceBatch, InboundIceValidationError> {
        let remaining_candidates =
            MAX_REMOTE_ICE_CANDIDATES_PER_SESSION.saturating_sub(self.accepted_candidates);
        if candidates.len() > remaining_candidates {
            return Err(InboundIceValidationError::CandidateCount);
        }
        if next_since < self.since || next_since > MAX_SIGNAL_ICE_SEQUENCE {
            return Err(InboundIceValidationError::Cursor);
        }

        let mut staged = Vec::with_capacity(candidates.len());
        let mut staged_bytes = 0usize;
        let mut previous_seq = self.since;
        for candidate in candidates {
            let bytes = candidate.candidate.len();
            if bytes == 0 || bytes > MAX_REMOTE_ICE_CANDIDATE_BYTES {
                return Err(InboundIceValidationError::CandidateBytes);
            }
            if candidate.seq == 0
                || candidate.seq > MAX_SIGNAL_ICE_SEQUENCE
                || candidate.seq <= previous_seq
            {
                return Err(InboundIceValidationError::CandidateSequence);
            }
            staged_bytes = staged_bytes
                .checked_add(bytes)
                .ok_or(InboundIceValidationError::AggregateBytes)?;
            if self
                .accepted_bytes
                .checked_add(staged_bytes)
                .is_none_or(|total| total > MAX_REMOTE_ICE_BYTES_PER_SESSION)
            {
                return Err(InboundIceValidationError::AggregateBytes);
            }
            let init = serde_json::from_str::<RTCIceCandidateInit>(&candidate.candidate)
                .map_err(|_| InboundIceValidationError::CandidateParse)?;
            staged.push(init);
            previous_seq = candidate.seq;
        }
        if next_since < previous_seq {
            return Err(InboundIceValidationError::Cursor);
        }
        Ok(StagedInboundIceBatch {
            candidates: staged,
            bytes: staged_bytes,
            next_since,
        })
    }

    fn commit(&mut self, candidate_count: usize, bytes: usize, next_since: u64) {
        self.accepted_candidates += candidate_count;
        self.accepted_bytes += bytes;
        self.since = next_since;
    }
}

type RemoteIceApplyFuture = Pin<Box<dyn Future<Output = Result<(), ()>> + Send>>;
type InboundIceFetchFuture =
    Pin<Box<dyn Future<Output = Result<(Vec<IceCandidate>, u64), FetchIceError>> + Send>>;

/// The production candidate applier can only be obtained after `set_remote_description` succeeds. This makes the
/// WebRTC ordering invariant structural: the inbound pump has no `RTCPeerConnection` handle with which to apply a
/// candidate until the exact offer is installed.
#[derive(Clone)]
struct InstalledRemoteDescription {
    pc: Arc<RTCPeerConnection>,
}

async fn install_remote_description(
    pc: Arc<RTCPeerConnection>,
    offer: RTCSessionDescription,
) -> anyhow::Result<InstalledRemoteDescription> {
    pc.set_remote_description(offer).await?;
    Ok(InstalledRemoteDescription { pc })
}

trait RemoteIceApplier: Send + Sync + 'static {
    fn apply(&self, candidate: RTCIceCandidateInit) -> RemoteIceApplyFuture;
}

impl RemoteIceApplier for InstalledRemoteDescription {
    fn apply(&self, candidate: RTCIceCandidateInit) -> RemoteIceApplyFuture {
        let pc = self.pc.clone();
        Box::pin(async move { pc.add_ice_candidate(candidate).await.map_err(|_| ()) })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboundIceBatchError {
    Invalid(InboundIceValidationError),
    ApplicationFailed,
    ApplicationTimedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboundIceBatchOutcome {
    Committed,
    Retired,
}

/// Stage the complete batch before making any WebRTC call. Application is FIFO and the admission cursor/count/byte
/// accounting commits only after every candidate succeeds. An application failure can leave a native prefix on the
/// doomed PeerConnection, but it cannot make that prefix durable: the exact setup owner is retired and reconnects
/// with a fresh signaling session.
async fn apply_inbound_ice_batch<A: RemoteIceApplier>(
    admission: &mut InboundIceAdmission,
    candidates: Vec<IceCandidate>,
    next_since: u64,
    applier: &A,
    retired: &AtomicBool,
    apply_timeout: std::time::Duration,
) -> Result<InboundIceBatchOutcome, InboundIceBatchError> {
    let staged = admission
        .stage(candidates, next_since)
        .map_err(InboundIceBatchError::Invalid)?;
    let candidate_count = staged.candidates.len();
    for candidate in staged.candidates {
        if retired.load(Ordering::Acquire) {
            return Ok(InboundIceBatchOutcome::Retired);
        }
        let result = tokio::time::timeout(apply_timeout, applier.apply(candidate)).await;
        // Native DataChannel Open retires setup signaling. It wins even if an unabortable add operation completes
        // with an error in the same turn; the owner will abort and join this worker immediately after publication.
        if retired.load(Ordering::Acquire) {
            return Ok(InboundIceBatchOutcome::Retired);
        }
        match result {
            Ok(Ok(())) => {}
            Ok(Err(())) => return Err(InboundIceBatchError::ApplicationFailed),
            Err(_) => return Err(InboundIceBatchError::ApplicationTimedOut),
        }
    }
    if retired.load(Ordering::Acquire) {
        return Ok(InboundIceBatchOutcome::Retired);
    }
    admission.commit(candidate_count, staged.bytes, staged.next_since);
    Ok(InboundIceBatchOutcome::Committed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboundIcePumpExit {
    Retired,
    SetupFailed,
}

/// The first empty inbound-ICE fetch is followed by one bounded early fetch, then the schedule catches up to the
/// existing 700 ms cadence. This inserts a useful 250 ms pickup point without moving the old 700 ms checkpoint or
/// turning an empty/failed setup into sustained short polling. Committed candidate progress may add another early
/// read only inside that same fixed regular window; a transient cloud failure settles immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InboundIcePollCadence {
    settled_interval: std::time::Duration,
    early_delay: std::time::Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboundIcePollOutcome {
    CandidateProgress,
    Empty,
    TransientFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboundIcePollKind {
    Regular,
    Early,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InboundIcePollPlan {
    kind: InboundIcePollKind,
    wait: std::time::Duration,
    /// Time left until the one pre-existing regular checkpoint, measured before this plan's wait. Every
    /// progress-triggered early poll consumes this same budget; none may create a fresh checkpoint of its own.
    checkpoint_remaining: Option<std::time::Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InboundIceRegularPhase {
    Initial,
    CatchUp,
    Settled,
}

#[derive(Debug, Clone, Copy)]
struct InboundIcePollSchedule {
    cadence: InboundIcePollCadence,
    regular_phase: InboundIceRegularPhase,
}

impl InboundIcePollSchedule {
    fn new(cadence: InboundIcePollCadence) -> Self {
        debug_assert!(cadence.early_delay <= cadence.settled_interval);
        Self {
            cadence,
            regular_phase: InboundIceRegularPhase::Initial,
        }
    }

    fn initial(&self) -> InboundIcePollPlan {
        InboundIcePollPlan {
            kind: InboundIcePollKind::Regular,
            wait: std::time::Duration::ZERO,
            checkpoint_remaining: None,
        }
    }

    fn early_within_checkpoint(
        &mut self,
        checkpoint_remaining: std::time::Duration,
    ) -> InboundIcePollPlan {
        self.regular_phase = InboundIceRegularPhase::CatchUp;
        if checkpoint_remaining <= self.cadence.early_delay {
            return self.regular(checkpoint_remaining);
        }
        InboundIcePollPlan {
            kind: InboundIcePollKind::Early,
            wait: self.cadence.early_delay,
            checkpoint_remaining: Some(checkpoint_remaining),
        }
    }

    fn regular(&mut self, wait: std::time::Duration) -> InboundIcePollPlan {
        InboundIcePollPlan {
            kind: InboundIcePollKind::Regular,
            wait,
            checkpoint_remaining: None,
        }
    }

    fn after_regular(&mut self, outcome: InboundIcePollOutcome) -> InboundIcePollPlan {
        if outcome == InboundIcePollOutcome::CandidateProgress {
            return self.early_within_checkpoint(self.cadence.settled_interval);
        }
        if outcome == InboundIcePollOutcome::TransientFailure {
            self.regular_phase = InboundIceRegularPhase::Settled;
            return self.regular(self.cadence.settled_interval);
        }
        match self.regular_phase {
            InboundIceRegularPhase::Initial => {
                self.early_within_checkpoint(self.cadence.settled_interval)
            }
            InboundIceRegularPhase::CatchUp | InboundIceRegularPhase::Settled => {
                self.regular_phase = InboundIceRegularPhase::Settled;
                self.regular(self.cadence.settled_interval)
            }
        }
    }

    fn after_early(
        &mut self,
        outcome: InboundIcePollOutcome,
        catch_up_remaining: std::time::Duration,
    ) -> InboundIcePollPlan {
        if outcome == InboundIcePollOutcome::CandidateProgress {
            return self.early_within_checkpoint(catch_up_remaining);
        }
        // Empty and transient early responses both yield to the old checkpoint. A transient response does not
        // receive another accelerated retry; the catch-up fetch is the regular 700 ms-cadence fetch.
        self.regular_phase = InboundIceRegularPhase::CatchUp;
        self.regular(catch_up_remaining)
    }

    fn after_early_timeout(&mut self) -> InboundIcePollPlan {
        self.regular_phase = InboundIceRegularPhase::CatchUp;
        self.regular(std::time::Duration::ZERO)
    }

    fn after(
        &mut self,
        plan: InboundIcePollPlan,
        outcome: InboundIcePollOutcome,
        catch_up_remaining: std::time::Duration,
    ) -> InboundIcePollPlan {
        match plan.kind {
            InboundIcePollKind::Regular => self.after_regular(outcome),
            InboundIcePollKind::Early => self.after_early(outcome, catch_up_remaining),
        }
    }
}

fn signal_setup_ice_failure(setup_failure_tx: &mpsc::Sender<()>, retired: &AtomicBool) {
    if !retired.load(Ordering::Acquire) {
        // Capacity one is deliberate: the first integrity/application failure decides this exact setup owner.
        let _ = setup_failure_tx.try_send(());
    }
}

async fn run_inbound_ice_pump<F, A>(
    fetch: F,
    applier: A,
    setup_failure_tx: mpsc::Sender<()>,
    retired: Arc<AtomicBool>,
    poll_cadence: InboundIcePollCadence,
    apply_timeout: std::time::Duration,
    setup_progress: Option<SetupProgressReporter>,
) -> InboundIcePumpExit
where
    F: FnMut(u64) -> InboundIceFetchFuture,
    A: RemoteIceApplier,
{
    run_inbound_ice_pump_with_sleep(
        fetch,
        applier,
        setup_failure_tx,
        retired,
        poll_cadence,
        apply_timeout,
        setup_progress,
        |delay| {
            Box::pin(async move {
                let started = tokio::time::Instant::now();
                tokio::time::sleep(delay).await;
                started.elapsed()
            })
        },
    )
    .await
}

type InboundIceSleepFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = std::time::Duration> + Send + 'static>>;

#[allow(clippy::too_many_arguments)]
async fn run_inbound_ice_pump_with_sleep<F, A, S>(
    mut fetch: F,
    applier: A,
    setup_failure_tx: mpsc::Sender<()>,
    retired: Arc<AtomicBool>,
    poll_cadence: InboundIcePollCadence,
    apply_timeout: std::time::Duration,
    setup_progress: Option<SetupProgressReporter>,
    mut sleep: S,
) -> InboundIcePumpExit
where
    F: FnMut(u64) -> InboundIceFetchFuture,
    A: RemoteIceApplier,
    S: FnMut(std::time::Duration) -> InboundIceSleepFuture,
{
    let mut admission = InboundIceAdmission::default();
    let mut schedule = InboundIcePollSchedule::new(poll_cadence);
    let mut plan = schedule.initial();
    loop {
        if retired.load(Ordering::Acquire) {
            return InboundIcePumpExit::Retired;
        }
        let iteration_started = tokio::time::Instant::now();
        let slept_elapsed = if plan.wait.is_zero() {
            std::time::Duration::ZERO
        } else {
            sleep(plan.wait).await
        };
        if retired.load(Ordering::Acquire) {
            return InboundIcePumpExit::Retired;
        }
        let work_started = tokio::time::Instant::now();
        let checkpoint_remaining = plan.checkpoint_remaining;
        let fetched = if let Some(checkpoint_remaining) = checkpoint_remaining {
            // `sleep` reports its observed elapsed time so tests can model a delayed event-loop wake. The live
            // clock additionally accounts for scheduling overhead before the HTTP future starts.
            let elapsed_before_fetch = slept_elapsed.max(iteration_started.elapsed());
            let fetch_budget = checkpoint_remaining.saturating_sub(elapsed_before_fetch);
            match tokio::time::timeout(fetch_budget, fetch(admission.since)).await {
                Ok(result) => result,
                Err(_) => {
                    // The extra early request is expendable. Never let it push the pre-existing regular poll past
                    // its cadence checkpoint.
                    plan = schedule.after_early_timeout();
                    continue;
                }
            }
        } else {
            fetch(admission.since).await
        };
        let mut poll_outcome = InboundIcePollOutcome::Empty;
        match fetched {
            Ok((candidates, next_since)) => {
                if retired.load(Ordering::Acquire) {
                    return InboundIcePumpExit::Retired;
                }
                let candidate_count = candidates.len();
                match apply_inbound_ice_batch(
                    &mut admission,
                    candidates,
                    next_since,
                    &applier,
                    retired.as_ref(),
                    apply_timeout,
                )
                .await
                {
                    Ok(InboundIceBatchOutcome::Committed) => {
                        if candidate_count != 0 {
                            poll_outcome = InboundIcePollOutcome::CandidateProgress;
                            if let Some(progress) = setup_progress.as_ref() {
                                progress.report(SetupProgressKey::InboundIceApplied(
                                    admission.accepted_candidates as u64,
                                ));
                            }
                        }
                    }
                    Ok(InboundIceBatchOutcome::Retired) => return InboundIcePumpExit::Retired,
                    Err(_) => {
                        signal_setup_ice_failure(&setup_failure_tx, retired.as_ref());
                        return if retired.load(Ordering::Acquire) {
                            InboundIcePumpExit::Retired
                        } else {
                            InboundIcePumpExit::SetupFailed
                        };
                    }
                }
            }
            Err(FetchIceError::Protocol(_) | FetchIceError::Terminal(_)) => {
                signal_setup_ice_failure(&setup_failure_tx, retired.as_ref());
                return if retired.load(Ordering::Acquire) {
                    InboundIcePumpExit::Retired
                } else {
                    InboundIcePumpExit::SetupFailed
                };
            }
            // Preserve the current signaling retry policy for transport/HTTP failures. Long-polling and cadence
            // changes belong to the separate latency checkpoint.
            Err(FetchIceError::Transient(_)) => {
                poll_outcome = InboundIcePollOutcome::TransientFailure;
            }
        }
        // Include HTTP and candidate-application time, plus any runtime overhead not represented by an injected
        // sleep result. This keeps the regular checkpoint absolute across every progress-triggered early poll.
        let modeled_elapsed = slept_elapsed.saturating_add(work_started.elapsed());
        let catch_up_remaining = checkpoint_remaining
            .unwrap_or_default()
            .saturating_sub(modeled_elapsed.max(iteration_started.elapsed()));
        if retired.load(Ordering::Acquire) {
            return InboundIcePumpExit::Retired;
        }
        plan = schedule.after(plan, poll_outcome, catch_up_remaining);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetupWaitError {
    DataChannelClosed,
    DataChannelPublicationTimeout,
    Deadline(DeadlineExpiry),
    IceSetupFailed,
    Peer(PeerCloseReason),
}

/// The peer may make the native DataChannel Open before its asynchronous `on_open` handler publishes the fully
/// wired `OpenDataChannel` owner. Keep a weak reference from discovery onward so setup-failure arbitration can
/// consult the transport's authoritative state without extending its lifetime or creating a callback cycle.
#[derive(Clone, Default)]
struct DiscoveredDataChannel {
    inner: Arc<std::sync::Mutex<Option<std::sync::Weak<RTCDataChannel>>>>,
}

impl DiscoveredDataChannel {
    fn observe(&self, dc: &Arc<RTCDataChannel>) {
        *self
            .inner
            .lock()
            .expect("discovered DataChannel lock poisoned") = Some(Arc::downgrade(dc));
    }

    fn is_open(&self) -> bool {
        self.inner
            .lock()
            .expect("discovered DataChannel lock poisoned")
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .is_some_and(|dc| dc.ready_state() == RTCDataChannelState::Open)
    }
}

impl std::fmt::Display for SetupWaitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DataChannelClosed => f.write_str("DataChannel channel closed"),
            Self::DataChannelPublicationTimeout => {
                f.write_str("native DataChannel opened but its owner was not published")
            }
            Self::Deadline(DeadlineExpiry::Inactivity) => {
                f.write_str("remote setup made no progress before its inactivity deadline")
            }
            Self::Deadline(DeadlineExpiry::Absolute) => {
                f.write_str("remote setup exceeded its absolute deadline")
            }
            Self::IceSetupFailed => f.write_str("ICE setup signaling failed"),
            Self::Peer(reason) => write!(
                f,
                "peer transport ended before DataChannel opened: {reason}"
            ),
        }
    }
}

impl std::error::Error for SetupWaitError {}

fn note_setup_progress(
    deadline: &mut ProgressDeadline<SetupProgressKey>,
    key: SetupProgressKey,
    observed_at: tokio::time::Instant,
    handled_at: tokio::time::Instant,
) -> Result<(), SetupWaitError> {
    if let Some(expiry) = deadline.expired(observed_at) {
        return Err(SetupWaitError::Deadline(expiry));
    }
    deadline.observe(key, observed_at);
    // A queued event is anchored to its source time. If the owner dequeues it after the resulting budget has
    // already elapsed, it cannot resurrect setup merely because this select branch won over an already-ready timer.
    if let Some(expiry) = deadline.expired(handled_at) {
        return Err(SetupWaitError::Deadline(expiry));
    }
    Ok(())
}

fn note_setup_progress_now(
    deadline: &mut ProgressDeadline<SetupProgressKey>,
    key: SetupProgressKey,
    discovered_data_channel: &DiscoveredDataChannel,
) -> Result<(), SetupWaitError> {
    if discovered_data_channel.is_open() {
        return Ok(());
    }
    let now = tokio::time::Instant::now();
    note_setup_progress(deadline, key, now, now)
}

async fn wait_for_setup_operation<F>(
    operation: F,
    deadline: &mut ProgressDeadline<SetupProgressKey>,
    progress_rx: &mut mpsc::Receiver<SetupProgressEvent>,
    peer_liveness: &mut PeerLiveness,
    discovered_data_channel: &DiscoveredDataChannel,
) -> Result<F::Output, SetupWaitError>
where
    F: Future,
{
    tokio::pin!(operation);
    loop {
        if discovered_data_channel.is_open() {
            // The operation still has its existing finite native/HTTP bound, but setup-only liveness and deadline
            // authority end at native Open. This covers the rare race where the cloud exposes a persisted answer
            // before its HTTP acknowledgement reaches the agent.
            return Ok(operation.await);
        }
        let deadline_sleep = tokio::time::sleep_until(deadline.next_at());
        tokio::pin!(deadline_sleep);
        tokio::select! {
            biased;
            reason = peer_liveness.wait_until_setup_terminal() => {
                if discovered_data_channel.is_open() {
                    continue;
                }
                return Err(SetupWaitError::Peer(reason));
            }
            Some(progress) = progress_rx.recv() => {
                if discovered_data_channel.is_open() {
                    continue;
                }
                note_setup_progress(
                    deadline,
                    progress.key,
                    progress.observed_at,
                    tokio::time::Instant::now(),
                )?;
            }
            output = &mut operation => {
                if discovered_data_channel.is_open() {
                    return Ok(output);
                }
                if let Some(expiry) = deadline.expired(tokio::time::Instant::now()) {
                    return Err(SetupWaitError::Deadline(expiry));
                }
                return Ok(output);
            }
            _ = &mut deadline_sleep => {
                if discovered_data_channel.is_open() {
                    continue;
                }
                if let Some(expiry) = deadline.expired(tokio::time::Instant::now()) {
                    return Err(SetupWaitError::Deadline(expiry));
                }
            }
        }
    }
}

/// Setup-only arbitration. If a DataChannel and a queued local-ICE failure become ready in the same owner turn,
/// the established transport wins; the setup receiver is then dropped and can never poison post-open liveness.
async fn wait_for_setup_data_channel<T>(
    dc_rx: &mut mpsc::Receiver<T>,
    setup_ice_failure_rx: &mut mpsc::Receiver<()>,
    peer_liveness: &mut PeerLiveness,
    discovered_data_channel: &DiscoveredDataChannel,
    deadline: &mut ProgressDeadline<SetupProgressKey>,
    progress_rx: &mut mpsc::Receiver<SetupProgressEvent>,
    publication_timeout: std::time::Duration,
) -> Result<T, SetupWaitError> {
    let mut ignore_setup_ice_failures = false;
    let mut native_open = false;
    let mut publication_deadline = None;
    loop {
        if !native_open && discovered_data_channel.is_open() {
            // Native Open is the authoritative setup-success boundary. Its asynchronous on_open callback may still
            // be publishing the fully wired owner; no setup-only error or setup deadline may defeat it in that
            // interval. A separate short handoff bound still prevents a broken callback from leaking this serve slot.
            ignore_setup_ice_failures = true;
            native_open = true;
            publication_deadline = Some(tokio::time::Instant::now() + publication_timeout);
        }
        let deadline_sleep = tokio::time::sleep_until(deadline.next_at());
        let publication_sleep = tokio::time::sleep_until(
            publication_deadline.unwrap_or_else(tokio::time::Instant::now),
        );
        tokio::pin!(deadline_sleep);
        tokio::pin!(publication_sleep);
        tokio::select! {
            biased;
            result = dc_rx.recv() => {
                return result.ok_or(SetupWaitError::DataChannelClosed);
            }
            Some(()) = setup_ice_failure_rx.recv(), if !ignore_setup_ice_failures => {
                if discovered_data_channel.is_open() {
                    // The DTLS/SCTP transport is already established. The on_open publication may be queued
                    // behind this owner turn, so a setup-only signaling failure can no longer defeat it.
                    ignore_setup_ice_failures = true;
                    continue;
                }
                return Err(SetupWaitError::IceSetupFailed);
            }
            reason = peer_liveness.wait_until_setup_terminal(), if !native_open => {
                if discovered_data_channel.is_open() {
                    ignore_setup_ice_failures = true;
                    native_open = true;
                    publication_deadline = Some(tokio::time::Instant::now() + publication_timeout);
                    continue;
                }
                return Err(SetupWaitError::Peer(reason));
            }
            Some(progress) = progress_rx.recv(), if !native_open => {
                note_setup_progress(
                    deadline,
                    progress.key,
                    progress.observed_at,
                    tokio::time::Instant::now(),
                )?;
            }
            _ = &mut deadline_sleep, if !native_open => {
                if discovered_data_channel.is_open() {
                    ignore_setup_ice_failures = true;
                    native_open = true;
                    publication_deadline = Some(tokio::time::Instant::now() + publication_timeout);
                    continue;
                }
                if let Some(expiry) = deadline.expired(tokio::time::Instant::now()) {
                    return Err(SetupWaitError::Deadline(expiry));
                }
            }
            _ = &mut publication_sleep, if native_open => {
                return Err(SetupWaitError::DataChannelPublicationTimeout);
            }
        }
    }
}

fn register_datachannel_close_liveness(
    dc: &RTCDataChannel,
    session_id: String,
    liveness_tx: mpsc::UnboundedSender<PeerTransportEvent>,
) {
    // A DataChannel may close while PeerConnection and ICE both remain Connected (for example after a
    // browser sleep or an SCTP-only failure). Feed that terminal state into this serve owner's existing
    // teardown channel instead of waiting for a PC/ICE callback that may never arrive. The sender is
    // scoped to this serve_session, so a callback racing after teardown cannot affect a replacement.
    dc.on_close(Box::new(move || {
        tracing::info!(session = %session_id, "STAGE datachannel_closed");
        let _ = liveness_tx.send(PeerTransportEvent::DataChannelClosed);
        Box::pin(async {})
    }));
}

/// One counted serve slot. Dropping it is the single release path, including liveness-triggered teardown and
/// future early returns. The existing winsize state machine still owns its 10-second fallback policy; this guard
/// only feeds the same serving-count transition at the moment the dead session task actually ends.
struct ServingSlot {
    serving: Arc<std::sync::atomic::AtomicUsize>,
    owner: Arc<std::sync::Mutex<crate::winsize_owner::WinsizeOwner>>,
}

impl ServingSlot {
    fn acquire(
        serving: Arc<std::sync::atomic::AtomicUsize>,
        owner: Arc<std::sync::Mutex<crate::winsize_owner::WinsizeOwner>>,
    ) -> Self {
        // Serialize the counter mutation and its owner feed under the same mutex. Otherwise a concurrent drop can
        // publish a newer count first and this acquire can overwrite it later with a stale captured count.
        let mut owner_guard = owner.lock().unwrap_or_else(|e| e.into_inner());
        let count = serving.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
        owner_guard.set_serving(count, now_ms());
        drop(owner_guard);
        Self { serving, owner }
    }
}

impl Drop for ServingSlot {
    fn drop(&mut self) {
        // Lock before touching the counter for the same ordering guarantee as acquire. `fetch_update` prevents a
        // release-build underflow if an invariant is ever violated; keep the owner fail-safe at zero and report it.
        let mut owner_guard = self.owner.lock().unwrap_or_else(|e| e.into_inner());
        match self.serving.fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |count| count.checked_sub(1),
        ) {
            Ok(previous) => owner_guard.set_serving(previous - 1, now_ms()),
            Err(0) => {
                tracing::error!(
                    "serve slot release observed a zero count; preserving fail-safe zero"
                );
                owner_guard.set_serving(0, now_ms());
            }
            Err(_) => unreachable!("checked_sub only rejects zero"),
        }
    }
}

/// A detached per-session Tokio task would outlive its serve slot when its JoinHandle is dropped. Own every such
/// task, explicitly abort+await it during normal teardown, and retain Drop abort as defense for panic or a future
/// early-return path that forgets to call shutdown.
struct OwnedSessionTask {
    task: Option<tokio::task::JoinHandle<()>>,
    label: &'static str,
}

impl OwnedSessionTask {
    fn new(label: &'static str, task: tokio::task::JoinHandle<()>) -> Self {
        Self {
            task: Some(task),
            label,
        }
    }

    async fn shutdown(&mut self) {
        let Some(task) = self.task.take() else {
            return;
        };
        task.abort();
        if let Err(error) = task.await {
            if !error.is_cancelled() {
                tracing::warn!(%error, task = self.label, "remote-peer: owned task failed during teardown");
            }
        }
    }
}

impl Drop for OwnedSessionTask {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn shutdown_setup_tasks(
    retired: &AtomicBool,
    local_ice_poster: &mut OwnedSessionTask,
    inbound_ice_pump: &mut OwnedSessionTask,
) {
    retired.store(true, Ordering::Release);
    local_ice_poster.shutdown().await;
    inbound_ice_pump.shutdown().await;
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Poll signaling for ONE pending offer, answer it, and serve the session until the channel closes. Loops
/// so the agent stays available for the next connection. `revoked` is the live-revoke check.
pub async fn run_remote_peer(
    cfg: PeerConfig,
    revoked: impl Fn(&str, &str, u64) -> bool + Clone + Send + Sync + 'static,
) -> anyhow::Result<()> {
    let cfg = Arc::new(cfg);
    let signaling = Arc::new(AgentSignaling::new_with_device_key(
        cfg.cloud_base.clone(),
        cfg.auth.clone(),
        cfg.device_id.clone(),
        cfg.device_key.clone(),
    ));
    tracing::info!(device = %cfg.device_id, build = %crate::build_stamp(), "remote-peer: polling signaling (dial-out, no listener)");
    // Emit the agent's build stamp into the shared conn-trace so browser↔agent version drift is visible in the log
    // (the "did my fix actually deploy?" gap). Uncorrelated (no browser trace id yet at startup) — side:"agent".
    crate::conn_trace::append(
        &cfg.agent_dir,
        "",
        "build",
        "agent",
        crate::conn_trace::TraceStatus::Ok,
        &crate::build_stamp(),
        now_ms(),
    );

    // presence: while remote-peer runs, periodically send a SIGNED heartbeat so the hosted app can show
    // "Recently seen". Only when we have the enrolled device key (prod); dev/unenrolled runs skip it. The
    // task self-retries on failure and never affects the peer loop below.
    let _heartbeat = cfg.device_key.clone().map(|key| {
        crate::heartbeat::spawn_heartbeat_loop(
            cfg.cloud_base.clone(),
            cfg.device_id.clone(),
            key,
            crate::heartbeat::DEFAULT_INTERVAL,
            cfg.agent_dir.clone(),
        )
    });

    // LIVE REVOCATION DELIVERY: poll the account's revocation state so an ALREADY-CONNECTED browser's channel
    // is closed mid-session (before the token's 10-min expiry) when the browser / this desktop / the account
    // is revoked. Only runs when device-signed (prod key present); dev/unenrolled runs skip it (the poll would
    // be unauthenticated). We COMPOSE the cloud-fed state with the caller's local-enrollment `revoked` check:
    // a connection is revoked if EITHER says so. Authority is remove-only (the cloud can't add trust here).
    let revocation_state = crate::revocation::RevocationState::new();
    let _revocation_poller = if cfg.device_key.is_some() {
        Some(crate::revocation::spawn_revocation_poller(
            signaling.clone(),
            revocation_state.clone(),
            crate::revocation::DEFAULT_POLL_INTERVAL,
        ))
    } else {
        None
    };
    // Retain the caller's local account/enrollment authority separately. The composed closure below
    // also consults browser-token revocations, whose API requires a real browser id and token time;
    // the headless account guard must never probe that state with synthetic values.
    let local_authority = revoked.clone();
    let revoked = {
        let local = revoked;
        let state = revocation_state.clone();
        move |account: &str, browser_device: &str, token_iat_ms: u64| {
            local(account, browser_device, token_iat_ms)
                || state.is_revoked(browser_device, token_iat_ms)
        }
    };

    // ONE global live-sync watcher for this peer: polls the store's data_version + publishes it on a watch channel.
    // Every serve_control subscribes to this single receiver (shared DB poll; per-connection filter/diff/push). None
    // when there's no store (unenrolled/dev) → live-sync simply doesn't run.
    let data_version_rx = spawn_data_version_watcher();

    // sessions we've already attempted — don't re-pick a still-`pending` session we failed to set up
    // (e.g. a malformed offer), which would otherwise busy-loop until it expires. BOUNDED: a flood of bogus
    // offers (each a fresh session id) must not grow this without limit (memory DoS) — oldest ids age out.
    let mut handled = crate::seen_set::BoundedSeen::new(MAX_HANDLED_SESSIONS);
    // Bound concurrent serve tasks: each offer spawns an EXPENSIVE WebRTC peer (DTLS handshake). A flood of
    // offers must not spawn unbounded concurrent setups — over the cap, we skip new offers until one finishes.
    let serving = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    // Winsize-owner Phase 2b: ONE shared owner state machine across ALL remote sessions for this peer. Fed by the
    // `serving` counter (below, on every connect/drop) so its 10s grace runs off live peer count, and settable by a
    // browser `set_winsize_owner` (threaded into serve_control). A background tick re-evaluates effective() and
    // mirrors it to `<agent_dir>/winsize-owner` for the desktop (Phase 2c) to read.
    let owner = std::sync::Arc::new(std::sync::Mutex::new(
        crate::winsize_owner::WinsizeOwner::new(),
    ));
    // The public desktop receives ownership only through this fixed same-user typed control socket.
    // Failure to bind is fatal for this peer: serving remote resizes without a trustworthy local
    // projection would let the two viewports race the same PTY.
    let _viewport_control =
        crate::viewport_control::ViewportControlServer::start(&cfg.agent_dir, owner.clone())
            .map_err(|_| anyhow::anyhow!("remote viewport control socket is unavailable"))?;
    // STARTUP: force the effective-owner file to "local" so a stale "remote" left on disk from a previous run
    // (crash / a prior remote that owned the size) can't make the desktop suppress local resize when no remote
    // is connected — the "resize button stuck on after reopen" bug. A real remote re-grabs it on connect.
    if let Err(error) =
        crate::winsize_owner::initialize_owner_publication(&cfg.agent_dir, &owner, now_ms())
    {
        tracing::debug!("winsize-owner: startup publication failed: {error}");
    }
    // Background poll: recompute the effective owner every ~2s and write it to the file ON CHANGE. This is what makes
    // the 10s GRACE actually expire — without a periodic re-eval, effective() is only recomputed on set_serving /
    // set_remote_selected events, so a serving→0 drop with no further events would never fall back to Local on disk.
    {
        let owner = owner.clone();
        let agent_dir = cfg.agent_dir.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                let publication_needed = {
                    let g = owner.lock().unwrap_or_else(|e| e.into_inner());
                    g.publication_needed(now_ms())
                };
                // Publish both files through the same serialized writer as eager creation leases. The last
                // successful snapshot lives in WinsizeOwner itself, so eager reserve/rollback and a process sleep
                // past lease expiry cannot be hidden by a stale poll-local cache.
                if publication_needed {
                    if let Err(e) =
                        crate::winsize_owner::publish_owner_state(&agent_dir, &owner, now_ms())
                    {
                        tracing::debug!("winsize-owner: state publication failed: {e}");
                    }
                }
            }
        });
    }

    loop {
        // The fixed headless service pins HOME at setup so provider discovery/history and child
        // launches share one account root. If passwd HOME changes while this long-lived peer is
        // already running, retire it before another cloud poll or session can mix old and new
        // authority. The caller's remove-only closure performs this live account check.
        if headless_authority_changed(cfg.headless_server, &cfg.auth, &local_authority) {
            anyhow::bail!("headless account authority changed; remote peer retired");
        }
        // wait for a pending offer addressed to us
        let pending_cycle_started = std::time::Instant::now();
        let pending = match signaling.pending().await {
            Ok(p) => p,
            Err(e) => {
                tracing::debug!("pending poll error: {e}");
                tokio::time::sleep(PENDING_OFFER_ERROR_BACKOFF).await;
                continue;
            }
        };
        // Backpressure: if we're already serving the max concurrent offers, don't pick a new one this tick.
        // (A browser refresh's new offer is picked up once a serve slot frees — bogus-offer floods can't pile
        // up unbounded expensive WebRTC setups.)
        if serving.load(std::sync::atomic::Ordering::Relaxed) >= MAX_CONCURRENT_SERVES {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            continue;
        }
        let Some(sess) = pending
            .into_iter()
            .find(|s| !handled.contains(&s.session_id))
        else {
            let delay = pending_offer_empty_cycle_delay(pending_cycle_started.elapsed());
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            continue;
        };
        // The existence of this service-owned peer is the effective Open state. Close synchronously
        // stops and removes the service, so there is no replayable public positive-gate file here.
        handled.insert(&sess.session_id);
        tracing::info!(session = %sess.session_id, source = %sess.source_device_id, "remote-peer: answering offer");
        // Serve each session in its OWN task so a browser REFRESH (new offer) isn't blocked behind the old
        // session's serve loop. The poll loop continues immediately and picks up the new offer.
        let cfg = cfg.clone();
        let signaling = signaling.clone();
        let revoked = revoked.clone();
        let sid = sess.session_id.clone();
        let offer = sess.offer.clone();
        let src = sess.source_device_id.clone();
        let serving = serving.clone();
        let owner = owner.clone();
        // Each connection subscribes to the ONE shared watcher.
        let data_version_rx = data_version_rx.clone();
        // The guard is the one release path for the bounded serve slot and its winsize-presence feed, including
        // transport-liveness teardown and every existing early-return/error path.
        let serving_slot = ServingSlot::acquire(serving, owner.clone());
        let owner_for_task = owner.clone();
        tokio::spawn(async move {
            let _serving_slot = serving_slot;
            if let Err(e) = serve_session(
                &cfg,
                &signaling,
                &sid,
                &offer,
                &src,
                owner_for_task.clone(),
                revoked,
                data_version_rx,
            )
            .await
            {
                tracing::warn!(session = %sid, "session ended: {e}");
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_session(
    cfg: &PeerConfig,
    signaling: &Arc<AgentSignaling>,
    session_id: &str,
    offer_sdp: &str,
    peer_device_id: &str,
    owner: Arc<std::sync::Mutex<crate::winsize_owner::WinsizeOwner>>,
    revoked: impl Fn(&str, &str, u64) -> bool + Clone + Send + Sync + 'static,
    data_version_rx: Option<tokio::sync::watch::Receiver<i64>>,
) -> anyhow::Result<()> {
    // Own the PeerConnection close out here so we GUARANTEE pc.close().await runs on EVERY exit path (Ok, ?-error,
    // timeout). webrtc-rs leaks fds (DTLS/ICE/SCTP sockets) if the pc is merely dropped without close() — that was
    // the "Too many open files (os error 24)" leak: any error after pc creation left the pc (and the detached
    // ICE/output tasks holding its Arc) open. `serve_session_inner` hands the pc back via `pc_out` as soon as it's
    // built; whatever the inner returns, we then close the pc.
    let mut pc_out: Option<Arc<RTCPeerConnection>> = None;
    let result = serve_session_inner(
        &mut pc_out,
        cfg,
        signaling,
        session_id,
        offer_sdp,
        peer_device_id,
        owner,
        revoked,
        data_version_rx,
    )
    .await;
    if let Some(pc) = pc_out {
        // Best-effort — a close error must not mask the session result. Keep this one close owned and awaited:
        // webrtc-rs marks the PeerConnection closed before it finishes releasing DataChannel/SCTP/DTLS/ICE state,
        // so cancelling or detaching this future can strand resources and make a retry return without cleanup.
        let _ = pc.close().await;
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn serve_session_inner(
    pc_out: &mut Option<Arc<RTCPeerConnection>>,
    cfg: &PeerConfig,
    signaling: &Arc<AgentSignaling>,
    session_id: &str,
    offer_sdp: &str,
    peer_device_id: &str,
    owner: Arc<std::sync::Mutex<crate::winsize_owner::WinsizeOwner>>,
    revoked: impl Fn(&str, &str, u64) -> bool + Clone + Send + Sync + 'static,
    data_version_rx: Option<tokio::sync::watch::Receiver<i64>>,
) -> anyhow::Result<()> {
    // --- WebRTC peer (answerer) ---
    let (setup_progress, mut setup_progress_rx) = SetupProgressReporter::channel();
    let discovered_data_channel = DiscoveredDataChannel::default();
    let mut setup_deadline = ProgressDeadline::new(
        tokio::time::Instant::now(),
        SETUP_INACTIVITY_TIMEOUT,
        SETUP_ABSOLUTE_TIMEOUT,
    );
    // Created before the PeerConnection so the same owner can drive every bounded setup operation. No callbacks
    // exist until the PC is installed, but using one receiver avoids a second watchdog or detached timer.
    let (peer_liveness_tx, mut peer_liveness) = PeerLiveness::channel(PEER_DISCONNECTED_GRACE);
    // Explicit ICE liveness timeouts (see the ICE_* constants): webrtc-rs's silent 5s-to-Disconnected default
    // is what turned transient forced-relay gaps into permanent ~10s session deaths.
    let mut ice_setting_engine = webrtc::api::setting_engine::SettingEngine::default();
    ice_setting_engine.set_ice_timeouts(
        Some(ICE_DISCONNECTED_TIMEOUT),
        Some(ICE_FAILED_TIMEOUT),
        Some(ICE_KEEPALIVE_INTERVAL),
    );
    let api = APIBuilder::new()
        .with_setting_engine(ice_setting_engine)
        .build();

    // Fetch our own relay (TURN) creds so the agent can present RELAY candidates — REQUIRED for a
    // relay-only browser peer to connect (otherwise the agent only offers host/srflx, which a relay-only
    // peer refuses → no DataChannel). The terminal data still rides DTLS E2E; the relay sees ciphertext.
    let mut ice_servers = Vec::new();
    let relay_creds = wait_for_setup_operation(
        signaling.relay_creds(),
        &mut setup_deadline,
        &mut setup_progress_rx,
        &mut peer_liveness,
        &discovered_data_channel,
    )
    .await?;
    note_setup_progress_now(
        &mut setup_deadline,
        SetupProgressKey::RelayCredentialsFetched,
        &discovered_data_channel,
    )?;
    if let Some(creds) = relay_creds {
        ice_servers.push(webrtc::ice_transport::ice_server::RTCIceServer {
            urls: creds.urls,
            username: creds.username,
            credential: creds.credential,
            credential_type:
                webrtc::ice_transport::ice_credential_type::RTCIceCredentialType::Password,
        });
        // STUN on OUR relay host (never a public third party) for server-reflexive candidates on the direct
        // path. No credentials for STUN. Empty ⇒ host candidates only.
        if !creds.stun_urls.is_empty() {
            ice_servers.push(webrtc::ice_transport::ice_server::RTCIceServer {
                urls: creds.stun_urls,
                ..Default::default()
            });
        }
        tracing::debug!("remote-peer: TURN relay + own-host STUN configured for this session");
    } else {
        tracing::debug!("remote-peer: no relay creds (direct-only)");
    }
    let config = RTCConfiguration {
        ice_servers,
        ..Default::default()
    };
    let pc = Arc::new(
        wait_for_setup_operation(
            api.new_peer_connection(config),
            &mut setup_deadline,
            &mut setup_progress_rx,
            &mut peer_liveness,
            &discovered_data_channel,
        )
        .await??,
    );
    note_setup_progress_now(
        &mut setup_deadline,
        SetupProgressKey::PeerConnectionCreated,
        &discovered_data_channel,
    )?;
    // Hand the pc to the caller IMMEDIATELY so it's closed on every exit path (see serve_session). A clone stays
    // here for the rest of setup; the detached ICE/output tasks also hold clones, and close() tears them down.
    *pc_out = Some(pc.clone());

    // STAGE LOGGING: one clear line per connection-state + ICE-state transition, so a stuck handshake is
    // diagnosable at a glance (no need to trace webrtc_dtls/sctp). The same owner-scoped channel drives prompt
    // teardown below; it is not a global cancellation source and cannot affect a replacement session.
    {
        let sid = session_id.to_string();
        let liveness_tx = peer_liveness_tx.clone();
        let setup_progress = setup_progress.clone();
        pc.on_peer_connection_state_change(Box::new(move |s| {
            tracing::info!(session = %sid, "STAGE pc_state={s}");
            setup_progress.report(SetupProgressKey::PeerState(s.into()));
            let _ = liveness_tx.send(PeerTransportEvent::Peer(s));
            Box::pin(async {})
        }));
    }
    {
        let sid = session_id.to_string();
        let liveness_tx = peer_liveness_tx.clone();
        let setup_progress = setup_progress.clone();
        pc.on_ice_connection_state_change(Box::new(move |s| {
            tracing::info!(session = %sid, "STAGE ice_state={s}");
            setup_progress.report(SetupProgressKey::IceState(s.into()));
            let _ = liveness_tx.send(PeerTransportEvent::Ice(s));
            Box::pin(async {})
        }));
    }

    // local ICE → bounded, ordered, failure-aware trickle to the browser. Gathering may begin before the answer is
    // published, so callbacks only enqueue. The one session-owned POST worker is deliberately started only after
    // the cloud acknowledges the answer; setup failures use a setup-only channel and never enter peer liveness.
    let setup_ice_retired = Arc::new(AtomicBool::new(false));
    let local_ice_accepted = Arc::new(AtomicUsize::new(0));
    let (local_ice_tx, local_ice_rx) = mpsc::channel(MAX_LOCAL_ICE_CANDIDATES_PER_SESSION);
    // One failure retires setup; duplicates carry no information and must not create an unbounded side queue.
    let (setup_ice_failure_tx, mut setup_ice_failure_rx) = mpsc::channel(1);
    {
        let tx = local_ice_tx;
        let accepted = local_ice_accepted;
        let retired = setup_ice_retired.clone();
        let setup_failure_tx = setup_ice_failure_tx.clone();
        pc.on_ice_candidate(Box::new(move |candidate| {
            if let Some(candidate) = candidate {
                let result = candidate
                    .to_json()
                    .map_err(|_| LocalIceEnqueueError::EncodeFailed)
                    .and_then(|candidate| {
                        serde_json::to_string(&candidate)
                            .map_err(|_| LocalIceEnqueueError::EncodeFailed)
                    })
                    .and_then(|candidate| {
                        enqueue_local_ice_candidate(&tx, &accepted, &retired, candidate)
                    });
                if let Err(error) = result {
                    if error != LocalIceEnqueueError::Retired && !retired.load(Ordering::Acquire) {
                        let _ = setup_failure_tx.try_send(());
                    }
                }
            }
            Box::pin(async {})
        }));
    }

    // The bridge is created ON auth. The DataChannel + the inbound message handlers are wired the MOMENT
    // the channel appears (in on_data_channel), BEFORE on_open fires — otherwise the browser's hello/auth
    // (sent immediately on open) can arrive before our handler exists and be DROPPED (webrtc-rs doesn't
    // buffer pre-handler messages). TEXT → text_tx (control loop); BINARY terminal_input → bridge.
    let bridge: SharedBridge = Arc::new(Mutex::new(None));
    let terminal_input_authority =
        ConnectionAuthorityGate::new(peer_device_id.to_string(), revoked.clone());
    let (text_tx, text_rx) = mpsc::channel::<String>(256);
    let (dc_tx, mut dc_rx) = mpsc::channel::<OpenDataChannel>(1);
    let datachannel_claimed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let dc_tx = dc_tx.clone();
        let bridge_h = bridge.clone();
        let text_tx_h = text_tx.clone();
        let liveness_tx_h = peer_liveness_tx.clone();
        let sid_h = session_id.to_string();
        let datachannel_claimed_h = datachannel_claimed.clone();
        let setup_ice_retired_h = setup_ice_retired.clone();
        let discovered_data_channel_h = discovered_data_channel.clone();
        let terminal_input_authority_h = terminal_input_authority.clone();
        pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
            discovered_data_channel_h.observe(&dc);
            let dc_tx = dc_tx.clone();
            let bridge = bridge_h.clone();
            let text_tx = text_tx_h.clone();
            let liveness_tx = liveness_tx_h.clone();
            let sid = sid_h.clone();
            let datachannel_claimed = datachannel_claimed_h.clone();
            let setup_ice_retired = setup_ice_retired_h.clone();
            let terminal_input_authority = terminal_input_authority_h.clone();
            Box::pin(async move {
                register_datachannel_close_liveness(&dc, sid, liveness_tx.clone());
                // Install event-driven SCTP backpressure before the channel opens. The callback captures only
                // the bounded wake sender (never the DataChannel), so it cannot create DC → handler → DC.
                let (buffered_amount_wake, output_backpressure) = buffered_amount_low_channel();
                let graceful_drain = output_backpressure.clone();
                let (outbound, outbound_owner) = outbound_scheduler_channel(liveness_tx.clone());
                dc.on_buffered_amount_low(Box::new(move || {
                    let _ = buffered_amount_wake.signal();
                    Box::pin(async {})
                }))
                .await;
                dc.set_buffered_amount_low_threshold(DC_BUFFER_LOW).await;
                // register the message handler IMMEDIATELY (before on_open) so nothing is lost.
                // Handlers are stored inside the DataChannel, so they must not capture that same channel strongly.
                // The scheduler handle owns queues only (never the DataChannel), so this remains cycle-free.
                let bridge_m = bridge.clone();
                let text_tx_m = text_tx.clone();
                let outbound_m = outbound.clone();
                let terminal_input_authority_m = terminal_input_authority.clone();
                let input_liveness_tx_m = liveness_tx.clone();
                dc.on_message(Box::new(move |msg: DataChannelMessage| {
                    let bridge = bridge_m.clone();
                    let text_tx = text_tx_m.clone();
                    let outbound = outbound_m.clone();
                    let terminal_input_authority = terminal_input_authority_m.clone();
                    let input_liveness_tx = input_liveness_tx_m.clone();
                    Box::pin(async move {
                        if msg.is_string {
                            if let Ok(s) = String::from_utf8(msg.data.to_vec()) {
                                let _ = text_tx.send(s).await;
                            }
                            return;
                        }
                        match decode(&msg.data) {
                            Ok(frame) if frame.kind == FrameKind::TerminalInput => {
                                tracing::debug!(
                                    "STAGE terminal_input ch={} bytes={}",
                                    frame.channel,
                                    frame.payload.len()
                                );
                                match handle_binary_terminal_input(
                                    &bridge,
                                    &terminal_input_authority,
                                    frame.channel,
                                    frame.payload,
                                    now_ms,
                                )
                                .await
                                {
                                    TerminalInputOutcome::Handled(outs) => {
                                        let _ = send_outbounds(&outbound, outs).await;
                                    }
                                    TerminalInputOutcome::AuthorityEnded => {
                                        // Fail closed without depending on control-loop progress. The
                                        // event wakes owner teardown once any already-bounded outbound wait unwinds.
                                        if terminal_input_authority.claim_end_event() {
                                            let _ = input_liveness_tx
                                                .send(PeerTransportEvent::AuthorityEnded);
                                        }
                                    }
                                }
                            }
                            Ok(_) => {}
                            Err(e) => tracing::warn!("STAGE binary decode FAILED {e:?}"),
                        }
                    })
                }));
                // signal the DataChannel is ready (use on_open so we serve after it's truly open).
                let dc2 = Arc::downgrade(&dc);
                let dc_tx2 = dc_tx.clone();
                let outbound_for_open = outbound.clone();
                let graceful_drain_for_open = graceful_drain.clone();
                dc.on_open(Box::new(move || {
                    let dc2 = dc2.clone();
                    let dc_tx2 = dc_tx2.clone();
                    let outbound = outbound_for_open.clone();
                    let graceful_drain = graceful_drain_for_open.clone();
                    let datachannel_claimed = datachannel_claimed.clone();
                    Box::pin(async move {
                        if datachannel_claimed
                            .compare_exchange(
                                false,
                                true,
                                std::sync::atomic::Ordering::AcqRel,
                                std::sync::atomic::Ordering::Acquire,
                            )
                            .is_err()
                        {
                            if let Some(dc) = dc2.upgrade() {
                                let _ = close_data_channel_bounded(
                                    dc.as_ref(),
                                    DATA_CHANNEL_CLOSE_TIMEOUT,
                                )
                                .await;
                            }
                            return;
                        }
                        // The established DTLS/SCTP transport no longer needs setup signaling. Prevent any callback
                        // race from enqueueing more candidates before the serve owner aborts and joins the poster.
                        setup_ice_retired.store(true, Ordering::Release);
                        if let Some(dc2) = dc2.upgrade() {
                            // The owner starts only once the DataChannel is open. Its JoinHandle travels with the
                            // open notification, so timeout/teardown always aborts it; it is never detached.
                            let dc_for_owner = dc2.clone();
                            let task = tokio::spawn(async move {
                                outbound_owner
                                    .run(
                                        dc_for_owner.as_ref(),
                                        output_backpressure,
                                        DC_BUFFER_STALL_TIMEOUT,
                                    )
                                    .await;
                            });
                            let _ = dc_tx2
                                .send(OpenDataChannel {
                                    dc: dc2,
                                    outbound,
                                    outbound_owner: OwnedSessionTask::new(
                                        "outbound DataChannel scheduler",
                                        task,
                                    ),
                                    graceful_drain,
                                })
                                .await;
                        }
                    })
                }));
            })
        }));
    }

    // Extract the browser's per-connection PROOF OF POSSESSION from the offer JSON (if present): the
    // `hydra_offer_proof` object + the offer's DTLS fingerprint. Verified later at Auth against the browser
    // public key in the token. Parsing the raw JSON (not the typed RTCSessionDescription) since the proof is
    // a sibling field the WebRTC type ignores.
    let offer_proof = extract_offer_proof(offer_sdp);
    // ACCESS PASSKEY (#11): the browser certificate (WebAuthn-passkey-signed), if the offer carried one.
    let browser_cert = extract_browser_cert(offer_sdp);

    // apply offer → answer → signal
    let offer: RTCSessionDescription = serde_json::from_str(offer_sdp)?;
    let installed_remote = wait_for_setup_operation(
        install_remote_description(pc.clone(), offer),
        &mut setup_deadline,
        &mut setup_progress_rx,
        &mut peer_liveness,
        &discovered_data_channel,
    )
    .await??;
    note_setup_progress_now(
        &mut setup_deadline,
        SetupProgressKey::RemoteDescriptionInstalled,
        &discovered_data_channel,
    )?;
    let answer = wait_for_setup_operation(
        pc.create_answer(None),
        &mut setup_deadline,
        &mut setup_progress_rx,
        &mut peer_liveness,
        &discovered_data_channel,
    )
    .await??;
    note_setup_progress_now(
        &mut setup_deadline,
        SetupProgressKey::AnswerCreated,
        &discovered_data_channel,
    )?;
    wait_for_setup_operation(
        pc.set_local_description(answer.clone()),
        &mut setup_deadline,
        &mut setup_progress_rx,
        &mut peer_liveness,
        &discovered_data_channel,
    )
    .await??;
    note_setup_progress_now(
        &mut setup_deadline,
        SetupProgressKey::LocalDescriptionInstalled,
        &discovered_data_channel,
    )?;
    // FAIL CLOSED on the desktop identity proof: a PRODUCTION desktop (enrolled → device.json present) MUST
    // sign its answer so the browser can bind the agent identity to the DTLS fingerprint. If we're enrolled
    // but somehow lack the signing key, refuse rather than send a fingerprint-only answer the browser can't
    // authenticate. (Unenrolled dev runs legitimately have no key and no enrollment → they skip the proof.)
    if cfg.device_key.is_none() && crate::device_identity::is_enrolled(&cfg.agent_dir).is_some() {
        anyhow::bail!(
            "refusing to answer: enrolled desktop is missing its signing key (would be fingerprint-only)"
        );
    }
    let answer_json =
        signed_answer_json(&answer, session_id, &cfg.device_id, cfg.device_key.as_ref())?;
    wait_for_setup_operation(
        signaling.answer(session_id, &answer_json),
        &mut setup_deadline,
        &mut setup_progress_rx,
        &mut peer_liveness,
        &discovered_data_channel,
    )
    .await?
    .map_err(|e| anyhow::anyhow!(e))?;
    note_setup_progress_now(
        &mut setup_deadline,
        SetupProgressKey::AnswerAcknowledged,
        &discovered_data_channel,
    )?;

    // The answer now exists in the broker. Start draining candidates gathered during answer creation only after
    // that acknowledgement, so the cloud cannot expose an agent candidate before it can expose the matching SDP.
    let mut local_ice_poster = {
        let signaling = signaling.clone();
        let session_id = session_id.to_string();
        let setup_failure_tx = setup_ice_failure_tx.clone();
        let retired = setup_ice_retired.clone();
        let setup_progress = setup_progress.clone();
        let posted = Arc::new(AtomicUsize::new(0));
        OwnedSessionTask::new(
            "local ICE poster",
            tokio::spawn(async move {
                run_local_ice_poster(
                    local_ice_rx,
                    move |candidate| {
                        let signaling = signaling.clone();
                        let session_id = session_id.clone();
                        let setup_progress = setup_progress.clone();
                        let posted = posted.clone();
                        Box::pin(async move {
                            let result = signaling
                                .post_ice(&session_id, &candidate)
                                .await
                                .map_err(|_| ());
                            if result.is_ok() {
                                let count = posted.fetch_add(1, Ordering::AcqRel) + 1;
                                setup_progress
                                    .report(SetupProgressKey::LocalIcePosted(count as u64));
                            }
                            result
                        })
                    },
                    setup_failure_tx,
                    retired,
                    LOCAL_ICE_POST_TIMEOUT,
                    &LOCAL_ICE_RETRY_DELAYS,
                )
                .await;
            }),
        )
    };

    // Pump the browser's ICE candidates in only through the installed-description capability. This task is
    // setup-owned and is aborted+joined immediately on DataChannel Open; there is no post-open polling tail.
    let mut inbound_ice_pump = {
        let signaling = signaling.clone();
        let session_id = session_id.to_string();
        let setup_failure_tx = setup_ice_failure_tx;
        let retired = setup_ice_retired.clone();
        OwnedSessionTask::new(
            "inbound ICE poll",
            tokio::spawn(async move {
                let _ = run_inbound_ice_pump(
                    move |since| {
                        let signaling = signaling.clone();
                        let session_id = session_id.clone();
                        Box::pin(async move { signaling.fetch_ice(&session_id, since).await })
                    },
                    installed_remote,
                    setup_failure_tx,
                    retired,
                    INBOUND_ICE_POLL_CADENCE,
                    REMOTE_ICE_APPLY_TIMEOUT,
                    Some(setup_progress.clone()),
                )
                .await;
            }),
        )
    };

    // Wait for the DataChannel to open (bounded), but do not retain a setup slot until that timeout if WebRTC has
    // already declared the peer dead. The outer owner closes the PeerConnection on either exit.
    let dc_result = wait_for_setup_data_channel(
        &mut dc_rx,
        &mut setup_ice_failure_rx,
        &mut peer_liveness,
        &discovered_data_channel,
        &mut setup_deadline,
        &mut setup_progress_rx,
        DATA_CHANNEL_PUBLICATION_TIMEOUT,
    )
    .await
    .map_err(|error| anyhow::anyhow!(error.to_string()));
    let OpenDataChannel {
        dc,
        outbound,
        mut outbound_owner,
        mut graceful_drain,
    } = match dc_result {
        Ok(dc) => dc,
        Err(error) => {
            shutdown_setup_tasks(
                setup_ice_retired.as_ref(),
                &mut local_ice_poster,
                &mut inbound_ice_pump,
            )
            .await;
            return Err(error);
        }
    };
    shutdown_setup_tasks(
        setup_ice_retired.as_ref(),
        &mut local_ice_poster,
        &mut inbound_ice_pump,
    )
    .await;
    peer_liveness.activate_established(tokio::time::Instant::now());
    tracing::info!(session = %session_id, "STAGE datachannel_open");

    // --- daemon backend (async task) --- (bridge + text handler were wired in on_data_channel above)
    // Re-resolve the desktop's CURRENT daemon socket per session: the app republishes endpoint.json with a NEW socket
    // on every restart/window cycle, so the socket captured when remote-peer started (cfg.sock) goes stale. Connecting
    // to the stale path failed with `os error 2` (ENOENT) right after datachannel_open → "session ended" → flaky
    // connects / "Loading forever". Falls back to cfg.sock when nothing newer is published.
    let live_sock = if cfg.headless_server {
        cfg.sock.clone()
    } else {
        crate::remote_daemon_backend::current_daemon_socket(&cfg.sock)
    };
    let daemon_result: anyhow::Result<_> = tokio::select! {
        result = spawn_daemon_task_with_policy(
            live_sock,
            cfg.seed_sessions.clone(),
            cfg.headless_server,
        ) => {
            result.map_err(anyhow::Error::from)
        },
        reason = peer_liveness.wait_until_dead() => {
            Err(anyhow::anyhow!("peer transport ended while attaching daemon bridge: {reason}"))
        }
    };
    let (backend, daemon_out) = match daemon_result {
        Ok(daemon) => daemon,
        Err(error) => {
            outbound_owner.shutdown().await;
            inbound_ice_pump.shutdown().await;
            return Err(error);
        }
    };

    // Forward daemon OUTPUT → terminal_output binary frames (only when the session is attached on a bridge). The
    // forwarder arbitrates complete events per pane before codec/chunk work so one background Grid cannot hold the
    // viewed pane behind its entire logical event. This task is session-owned too: waiting for the daemon socket to
    // notice closure is not a deterministic teardown.
    let mut daemon_output_forwarder = {
        let bridge = bridge.clone();
        let outbound = outbound.clone();
        let output_liveness_tx = peer_liveness_tx.clone();
        OwnedSessionTask::new(
            "daemon output forwarder",
            tokio::spawn(async move {
                if let Err(error) =
                    run_daemon_output_forwarder(daemon_out, &bridge, &outbound).await
                {
                    tracing::warn!(
                        error = ?error,
                        "STAGE send_output FAILED; tearing down peer"
                    );
                }
                // A closed daemon-output receiver means this peer can no longer deliver terminal state. Treat it
                // exactly like a wire send failure instead of leaving auth/control apparently healthy forever.
                // Normal teardown aborts this owned task, so it does not execute this tail; a duplicate signal from
                // an already-failed send is harmless and owner-scoped.
                let _ = output_liveness_tx.send(PeerTransportEvent::OutboundSenderFailed);
            }),
        )
    };

    let control_result = serve_control(
        text_rx,
        &outbound,
        &bridge,
        backend,
        cfg.cloud_pubkey,
        cfg.allowed_origins.clone(),
        peer_device_id.to_string(),
        session_id.to_string(),
        cfg.agent_dir.clone(),
        cfg.enrolled_account_id.clone(),
        owner,
        revoked,
        terminal_input_authority,
        peer_liveness_tx.clone(),
        data_version_rx,
        offer_proof,
        browser_cert,
        cfg.device_id.to_string(),
        peer_liveness,
    )
    .await;
    // One final cleanup path for every control-loop exit (Bye, closed receiver, send/error, revoke, or liveness).
    // Taking the bridge breaks the otherwise idle daemon-forwarder retention cycle before the outer owner closes PC.
    shutdown_session_resources(
        &dc,
        &bridge,
        &mut daemon_output_forwarder,
        &mut outbound_owner,
        &mut inbound_ice_pump,
        &mut graceful_drain,
        matches!(&control_result, Ok(ControlLoopExit::PeerBye)),
    )
    .await;
    control_result?;
    Ok(())
}

fn answer_proof_message(session_id: &str, device_id: &str, fingerprint: &str) -> String {
    format!("{ANSWER_PROOF_PURPOSE}:{session_id}:{device_id}:{fingerprint}")
}

fn extract_sha256_fingerprint(sdp: &str) -> Option<String> {
    sdp.lines().find_map(|line| {
        let trimmed = line.trim();
        let rest = trimmed.strip_prefix("a=fingerprint:")?;
        let mut parts = rest.split_whitespace();
        let algorithm = parts.next()?;
        let fingerprint = parts.next()?;
        if algorithm.eq_ignore_ascii_case("sha-256") {
            Some(fingerprint.to_ascii_lowercase())
        } else {
            None
        }
    })
}

/// The browser's per-connection proof-of-possession, extracted from the offer for later verification at
/// Auth. `device_id`/`alg`/`sig` come from the offer's `hydra_offer_proof`; `fingerprint` from its SDP.
#[derive(Debug, Clone)]
struct OfferProofData {
    device_id: String,
    fingerprint: String,
    sig_b64: String,
}

/// Pull `hydra_offer_proof` + the DTLS fingerprint out of the raw offer JSON. Returns None when the offer
/// carries no proof (legacy/dev) — the control channel then relies on token-presence to decide fail-closed.
fn extract_offer_proof(offer_json: &str) -> Option<OfferProofData> {
    let v: serde_json::Value = serde_json::from_str(offer_json).ok()?;
    let proof = v.get("hydra_offer_proof")?;
    let device_id = proof.get("device_id")?.as_str()?.to_string();
    let sig_b64 = proof.get("sig")?.as_str()?.to_string();
    // alg is carried but the verifier reads it from the token's browser_pubkey_alg (authoritative); we only
    // need device_id + sig here. Fingerprint comes from the offer SDP.
    let sdp = v.get("sdp")?.as_str()?;
    let fingerprint = extract_sha256_fingerprint(sdp)?;
    Some(OfferProofData {
        device_id,
        fingerprint,
        sig_b64,
    })
}

/// ACCESS PASSKEY (#11): pull the `hydra_browser_cert` (WebAuthn-passkey-signed browser certificate) out of
/// the offer JSON, if present. None means no certificate was supplied. The enrolled Auth handler still requires
/// browser-key offer proof and, when a passkey is pinned, refuses the missing/malformed certificate.
fn extract_browser_cert(offer_json: &str) -> Option<crate::browser_cert::BrowserCert> {
    let v: serde_json::Value = serde_json::from_str(offer_json).ok()?;
    let cert = v.get("hydra_browser_cert")?;
    serde_json::from_value(cert.clone()).ok()
}

fn signed_answer_json(
    answer: &RTCSessionDescription,
    session_id: &str,
    device_id: &str,
    device_key: Option<&SigningKey>,
) -> anyhow::Result<String> {
    let mut value = serde_json::to_value(answer)?;
    if let (Some(key), Some(sdp)) = (device_key, value.get("sdp").and_then(|v| v.as_str())) {
        if let Some(fingerprint) = extract_sha256_fingerprint(sdp) {
            let msg = answer_proof_message(session_id, device_id, &fingerprint);
            let sig = key.sign(msg.as_bytes());
            value["hydra_answer_proof"] = serde_json::json!({
                "version": 1,
                "device_id": device_id,
                "signal_session_id": session_id,
                "fingerprint": fingerprint,
                "signature": B64_STD.encode(sig.to_bytes()),
            });
        }
    }
    Ok(serde_json::to_string(&value)?)
}

type SharedBridge = Arc<
    Mutex<Option<TerminalBridge<crate::remote_daemon_backend::DaemonBackend, SameAsLocalPolicy>>>,
>;

struct OpenDataChannel {
    dc: Arc<RTCDataChannel>,
    outbound: OutboundScheduler,
    outbound_owner: OwnedSessionTask,
    graceful_drain: BufferedAmountGate,
}

/// SCTP send-buffer high-water mark. A big terminal dump (e.g. a 1 MB grid replay) is ~70 chunks; firing them all
/// back-to-back overflowed the DataChannel's buffer → `dc.send` errored → the whole output forwarder stopped and the
/// session died ("Loading its projects…" hung; 35 send_output FAILEDs in the log). Backpressure: before each send, if
/// the buffer is above HIGH we wait until it drains below LOW so we never overrun it.
const DC_BUFFER_HIGH: usize = 1024 * 1024; // 1 MiB queued → pause
const DC_BUFFER_LOW: usize = 256 * 1024; // drained below 256 KiB → resume
const DC_BUFFER_STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// webrtc-sctp 0.10 (pinned through webrtc 0.11) starts DATA retransmission at 3 seconds. A peer-requested `Bye`
/// is the only path that attempts a graceful wire drain, so allow one retransmission plus a 2-second ACK margin.
/// Keep the subsequent DataChannel stream reset independently bounded so a stalled peer can never retain a serve
/// slot indefinitely.
const PINNED_SCTP_INITIAL_RTO: std::time::Duration = std::time::Duration::from_secs(3);
const GRACEFUL_CLOSE_DRAIN_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(PINNED_SCTP_INITIAL_RTO.as_secs() + 2);
/// Bound direct SCTP stream resets used by graceful Bye and duplicate-channel rejection. Fail-fast owner teardown
/// instead quiesces all producers before the single uncancelled PeerConnection close below.
const DATA_CHANNEL_CLOSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// The scheduler is deliberately byte-bounded in addition to its message-count bounds. Control can contain a
/// bounded debug-ledger response, so its budget must admit that existing response shape; terminal traffic is already
/// split into 16 KiB wire frames and needs only a short reservoir ahead of SCTP. These are per-peer maxima, not
/// eagerly allocated buffers.
const OUTBOUND_CONTROL_QUEUE_BYTES: usize = 8 * 1024 * 1024;
const OUTBOUND_TERMINAL_QUEUE_BYTES: usize = 2 * 1024 * 1024;
const OUTBOUND_CONTROL_QUEUE_ITEMS: usize = 256;
const OUTBOUND_TERMINAL_QUEUE_ITEMS: usize = 256;

/// Immutable native-buffer admission policy owned by one outbound scheduler. Production always constructs the
/// legacy hysteresis below, preserving its pre-existing byte-for-byte behavior: both classes may send while the
/// current native amount is at most 1 MiB and, once above it, resume only below 256 KiB. The non-shipping channel
/// benchmark may instead reserve native headroom by applying a smaller ceiling to terminal frames only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OutboundBufferPolicy {
    control_high: usize,
    terminal_ceiling: Option<usize>,
    low: usize,
}

impl OutboundBufferPolicy {
    const fn production() -> Self {
        Self {
            control_high: DC_BUFFER_HIGH,
            terminal_ceiling: None,
            low: DC_BUFFER_LOW,
        }
    }

    fn high_before_send(self, terminal: bool, frame_bytes: usize) -> usize {
        match (terminal, self.terminal_ceiling) {
            (true, Some(ceiling)) => ceiling.saturating_sub(frame_bytes),
            _ => self.control_high,
        }
    }
}

/// Complete daemon events retained while panes arbitrate codec and wire access. Production events carry their
/// original daemon-queue permits into this arbiter, so queued ingress plus arbitration share one aggregate bound.
/// These mirrored limits defend synthetic/internal callers too. Overflow is fail-stop because dropping a revisioned
/// event and continuing is never safe. Gzip output scratch is at most 7/8 of the retained decoded lines: 32 MiB
/// retained + 28 MiB encoded scratch = a 60 MiB application event-buffer peak, plus one 16 KiB wire quantum and
/// bounded fixed encoder/task overhead.
const DAEMON_FORWARDER_QUEUE_BYTES: usize =
    crate::remote_daemon_backend::DAEMON_OUTPUT_QUEUE_BYTE_CAP;
const DAEMON_FORWARDER_QUEUE_ITEMS: usize = crate::remote_daemon_backend::DAEMON_OUTPUT_QUEUE_CAP;

/// Give the viewed pane a fixed burst, then one ready sibling chunk. This keeps foreground latency bounded by one
/// 16 KiB quantum without allowing sustained foreground output to starve a visible/background pane forever.
const ACTIVE_PANE_BURST_CHUNKS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputSendError {
    BufferStalled,
    DataChannelClosed,
    EncodeFailed,
    QueueClosed,
    SchedulerRetired,
    QueueItemTooLarge,
    ForwarderQueueFull,
    CompressionFailed,
    CompressionCancelled,
}

#[derive(Debug)]
enum TerminalOutputState {
    /// Only gzip-selected events enter this state. At most the FIFO head of each pane is prepared concurrently,
    /// so codec completion can never reorder events within one pane.
    WaitingForCodec(Vec<u8>),
    Preparing {
        cancelled: Arc<AtomicBool>,
    },
    Ready {
        output: PreparedTerminalLine,
        offset: usize,
    },
}

#[derive(Debug)]
struct QueuedTerminalOutput {
    ticket: u64,
    byte_cost: usize,
    original_len: usize,
    event_label: &'static str,
    state: TerminalOutputState,
    wire_started: Option<std::time::Instant>,
    chunks_sent: usize,
    /// Present on the production daemon path. Holding the original permits makes daemon ingress plus this arbiter
    /// one aggregate bounded reservoir rather than two independently refillable queues.
    _daemon_reservation: Option<DaemonOutputReservation>,
}

/// Complete admission request for one daemon event before it receives its queue ticket. Keeping the
/// routing identity, accounting, prepared state, and original daemon reservation together prevents
/// callers from accidentally mixing accounting from one event with the payload or reservation of
/// another.
#[derive(Debug)]
struct TerminalOutputAdmission {
    session_id: String,
    target: TerminalOutputTarget,
    byte_cost: usize,
    original_len: usize,
    event_label: &'static str,
    state: TerminalOutputState,
    daemon_reservation: Option<DaemonOutputReservation>,
}

#[derive(Debug)]
struct PaneTerminalOutput {
    session_id: String,
    target: TerminalOutputTarget,
    retired: bool,
    events: VecDeque<QueuedTerminalOutput>,
}

#[derive(Debug)]
struct PendingTerminalChunk {
    ticket: u64,
    frame: Vec<u8>,
    next_offset: usize,
    completes_event: bool,
    selected_as_active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CompletedTerminalOutput {
    event_label: &'static str,
    original_len: usize,
    chunks: usize,
    elapsed_ms: u128,
}

/// Content-blind per-pane arbitration for complete daemon events. `panes` is kept in sibling round-robin order;
/// each pane's `events` deque is strict FIFO. Only one chunk is exposed at a time, and state advances only after the
/// existing one-owner DataChannel scheduler confirms that chunk was physically accepted.
struct TerminalOutputArbiter {
    panes: VecDeque<PaneTerminalOutput>,
    queued_items: usize,
    queued_bytes: usize,
    max_items: usize,
    max_bytes: usize,
    next_ticket: u64,
    active_burst_chunks: usize,
    active_burst_limit: usize,
    priority_served_targets: Vec<TerminalOutputTarget>,
}

impl TerminalOutputArbiter {
    fn new() -> Self {
        Self::with_limits(
            DAEMON_FORWARDER_QUEUE_ITEMS,
            DAEMON_FORWARDER_QUEUE_BYTES,
            ACTIVE_PANE_BURST_CHUNKS,
        )
    }

    fn with_limits(max_items: usize, max_bytes: usize, active_burst_limit: usize) -> Self {
        assert!(max_items > 0);
        assert!(max_bytes > 0);
        assert!(active_burst_limit > 0);
        Self {
            panes: VecDeque::new(),
            queued_items: 0,
            queued_bytes: 0,
            max_items,
            max_bytes,
            next_ticket: 1,
            active_burst_chunks: 0,
            active_burst_limit,
            priority_served_targets: Vec::with_capacity(active_burst_limit),
        }
    }

    #[cfg(test)]
    fn enqueue(
        &mut self,
        session_id: String,
        target: TerminalOutputTarget,
        line: String,
    ) -> Result<u64, OutputSendError> {
        self.enqueue_reserved(session_id, target, line, None)
    }

    fn enqueue_reserved(
        &mut self,
        session_id: String,
        target: TerminalOutputTarget,
        line: String,
        daemon_reservation: Option<DaemonOutputReservation>,
    ) -> Result<u64, OutputSendError> {
        let event_label = terminal_event_log_label(&line);
        let original_len = line.len();
        let byte_cost = line
            .capacity()
            .checked_add(session_id.capacity())
            .ok_or(OutputSendError::QueueItemTooLarge)?
            .max(1);
        let bytes = line.into_bytes();
        let state = match target.encoding {
            TerminalEncoding::Legacy => TerminalOutputState::Ready {
                output: PreparedTerminalLine::Legacy(bytes),
                offset: 0,
            },
            TerminalEncoding::GzipJsonV1
                if bytes.len() >= crate::remote_frame::TERMINAL_GZIP_MIN_DECODED_BYTES
                    && bytes.len() <= crate::remote_frame::MAX_TERMINAL_CODEC_BYTES =>
            {
                TerminalOutputState::WaitingForCodec(bytes)
            }
            TerminalEncoding::GzipJsonV1 => TerminalOutputState::Ready {
                output: PreparedTerminalLine::Legacy(bytes),
                offset: 0,
            },
        };
        self.enqueue_admission(TerminalOutputAdmission {
            session_id,
            target,
            byte_cost,
            original_len,
            event_label,
            state,
            daemon_reservation,
        })
    }

    #[cfg(test)]
    fn enqueue_state(
        &mut self,
        session_id: String,
        target: TerminalOutputTarget,
        byte_cost: usize,
        original_len: usize,
        event_label: &'static str,
        state: TerminalOutputState,
    ) -> Result<u64, OutputSendError> {
        self.enqueue_admission(TerminalOutputAdmission {
            session_id,
            target,
            byte_cost,
            original_len,
            event_label,
            state,
            daemon_reservation: None,
        })
    }

    fn enqueue_admission(
        &mut self,
        admission: TerminalOutputAdmission,
    ) -> Result<u64, OutputSendError> {
        let TerminalOutputAdmission {
            session_id,
            target,
            byte_cost,
            original_len,
            event_label,
            state,
            daemon_reservation,
        } = admission;
        let next_items = self
            .queued_items
            .checked_add(1)
            .ok_or(OutputSendError::ForwarderQueueFull)?;
        let next_bytes = self
            .queued_bytes
            .checked_add(byte_cost)
            .ok_or(OutputSendError::ForwarderQueueFull)?;
        if byte_cost > self.max_bytes {
            return Err(OutputSendError::QueueItemTooLarge);
        }
        if next_items > self.max_items || next_bytes > self.max_bytes {
            return Err(OutputSendError::ForwarderQueueFull);
        }

        let ticket = self.next_ticket;
        self.next_ticket = self.next_ticket.wrapping_add(1).max(1);
        let event = QueuedTerminalOutput {
            ticket,
            byte_cost,
            original_len,
            event_label,
            state,
            wire_started: None,
            chunks_sent: 0,
            _daemon_reservation: daemon_reservation,
        };
        if let Some(pane) = self
            .panes
            .iter_mut()
            .find(|pane| !pane.retired && pane.session_id == session_id && pane.target == target)
        {
            pane.events.push_back(event);
        } else {
            self.panes.push_back(PaneTerminalOutput {
                session_id,
                target,
                retired: false,
                events: VecDeque::from([event]),
            });
        }
        self.queued_items = next_items;
        self.queued_bytes = next_bytes;
        Ok(ticket)
    }

    /// Start at most one codec job per pane. Jobs for different panes are independent, so a large background Grid
    /// cannot hold the viewed pane behind its compression. A later event on the same pane cannot even begin codec
    /// work until the prior event has completely reached the wire.
    fn start_preparations(
        &mut self,
        preparations: &mut JoinSet<(u64, Result<PreparedTerminalLine, OutputSendError>)>,
    ) {
        for pane in &mut self.panes {
            if pane.retired {
                continue;
            }
            let Some(head) = pane.events.front_mut() else {
                continue;
            };
            if !matches!(head.state, TerminalOutputState::WaitingForCodec(_)) {
                continue;
            }
            let cancelled = Arc::new(AtomicBool::new(false));
            let TerminalOutputState::WaitingForCodec(line) = std::mem::replace(
                &mut head.state,
                TerminalOutputState::Preparing {
                    cancelled: cancelled.clone(),
                },
            ) else {
                unreachable!("codec state was checked immediately before replacement")
            };
            let ticket = head.ticket;
            preparations.spawn(async move {
                (
                    ticket,
                    prepare_terminal_line_with_cancel(line, cancelled).await,
                )
            });
        }
    }

    fn finish_preparation(
        &mut self,
        ticket: u64,
        prepared: Result<PreparedTerminalLine, OutputSendError>,
    ) -> Result<(), OutputSendError> {
        let Some(pane_index) = self.panes.iter().position(|pane| {
            pane.events
                .front()
                .is_some_and(|event| event.ticket == ticket)
        }) else {
            return Err(OutputSendError::CompressionFailed);
        };
        if !self.panes[pane_index]
            .events
            .front()
            .is_some_and(|event| matches!(event.state, TerminalOutputState::Preparing { .. }))
        {
            return Err(OutputSendError::CompressionFailed);
        }
        if self.panes[pane_index].retired {
            let event = self.panes[pane_index]
                .events
                .pop_front()
                .expect("retired codec head still exists");
            self.queued_items -= 1;
            self.queued_bytes -= event.byte_cost;
            self.panes.remove(pane_index);
            drop(prepared);
            return Ok(());
        }
        let prepared = prepared?;
        self.panes[pane_index]
            .events
            .front_mut()
            .expect("codec ticket lookup found the FIFO head")
            .state = TerminalOutputState::Ready {
            output: prepared,
            offset: 0,
        };
        Ok(())
    }

    /// Invalidate work whose exact attachment generation is no longer current. Ready/waiting events can be dropped
    /// because a detach ends that consumer and a reattach establishes a fresh daemon baseline. A codec-in-flight
    /// head retains its charged item/bytes until the bounded worker acknowledges cancellation/completion; this keeps
    /// rapid detach/reattach churn from creating unaccounted blocking tasks or buffers.
    fn retire_stale_targets(
        &mut self,
        mut live_target: impl FnMut(&str) -> Option<TerminalOutputTarget>,
    ) {
        let mut pane_index = 0;
        while pane_index < self.panes.len() {
            if self.panes[pane_index].retired
                || live_target(&self.panes[pane_index].session_id)
                    == Some(self.panes[pane_index].target)
            {
                pane_index += 1;
                continue;
            }

            let preparing = self.panes[pane_index]
                .events
                .front()
                .is_some_and(|event| matches!(event.state, TerminalOutputState::Preparing { .. }));
            if preparing {
                if let Some(QueuedTerminalOutput {
                    state: TerminalOutputState::Preparing { cancelled },
                    ..
                }) = self.panes[pane_index].events.front()
                {
                    cancelled.store(true, Ordering::Release);
                }
                self.panes[pane_index].retired = true;
                while self.panes[pane_index].events.len() > 1 {
                    let event = self.panes[pane_index]
                        .events
                        .pop_back()
                        .expect("retired pane has a queued tail");
                    self.queued_items -= 1;
                    self.queued_bytes -= event.byte_cost;
                }
                pane_index += 1;
            } else {
                let pane = self
                    .panes
                    .remove(pane_index)
                    .expect("stale pane index is valid");
                for event in pane.events {
                    self.queued_items -= 1;
                    self.queued_bytes -= event.byte_cost;
                }
            }
        }
    }

    fn next_chunk(
        &mut self,
        active_session: Option<&str>,
    ) -> Result<Option<PendingTerminalChunk>, OutputSendError> {
        let active_index = active_session.and_then(|active| {
            self.panes.iter().position(|pane| {
                !pane.retired
                    && pane.session_id == active
                    && pane.events.front().is_some_and(|event| {
                        matches!(event.state, TerminalOutputState::Ready { .. })
                    })
            })
        });
        let fairness_index = self.panes.iter().position(|pane| {
            !pane.retired
                && pane
                    .events
                    .front()
                    .is_some_and(|event| matches!(event.state, TerminalOutputState::Ready { .. }))
                && !self.priority_served_targets.contains(&pane.target)
        });
        let any_ready_index = self.panes.iter().position(|pane| {
            !pane.retired
                && pane
                    .events
                    .front()
                    .is_some_and(|event| matches!(event.state, TerminalOutputState::Ready { .. }))
        });
        let selected_as_active =
            active_index.is_some() && self.active_burst_chunks < self.active_burst_limit;
        let selected_index = if selected_as_active {
            active_index
        } else {
            fairness_index.or(any_ready_index)
        };
        let Some(selected_index) = selected_index else {
            return Ok(None);
        };
        let channel = self.panes[selected_index].target.channel;
        let event = self.panes[selected_index]
            .events
            .front_mut()
            .expect("a selected pane has a ready FIFO head");
        event
            .wire_started
            .get_or_insert_with(std::time::Instant::now);
        let TerminalOutputState::Ready { output, offset } = &event.state else {
            return Err(OutputSendError::EncodeFailed);
        };
        let (frame, next_offset, completes_event) =
            encode_next_terminal_chunk(channel, output, *offset)?;
        Ok(Some(PendingTerminalChunk {
            ticket: event.ticket,
            frame,
            next_offset,
            completes_event,
            selected_as_active,
        }))
    }

    fn commit_chunk(
        &mut self,
        sent: PendingTerminalChunk,
    ) -> Result<Option<CompletedTerminalOutput>, OutputSendError> {
        let Some(pane_index) = self.panes.iter().position(|pane| {
            pane.events
                .front()
                .is_some_and(|event| event.ticket == sent.ticket)
        }) else {
            return Err(OutputSendError::EncodeFailed);
        };
        let event = self.panes[pane_index]
            .events
            .front_mut()
            .expect("ticket lookup found the FIFO head");
        let TerminalOutputState::Ready { offset, .. } = &mut event.state else {
            return Err(OutputSendError::EncodeFailed);
        };
        *offset = sent.next_offset;
        event.chunks_sent += 1;

        if sent.selected_as_active {
            let target = self.panes[pane_index].target;
            if !self.priority_served_targets.contains(&target) {
                self.priority_served_targets.push(target);
            }
            self.active_burst_chunks = self
                .active_burst_chunks
                .saturating_add(1)
                .min(self.active_burst_limit);
        } else {
            self.active_burst_chunks = 0;
            self.priority_served_targets.clear();
        }

        let completed = if sent.completes_event {
            let event = self.panes[pane_index]
                .events
                .pop_front()
                .expect("the sent FIFO head still exists");
            self.queued_items -= 1;
            self.queued_bytes -= event.byte_cost;
            Some(CompletedTerminalOutput {
                event_label: event.event_label,
                original_len: event.original_len,
                chunks: event.chunks_sent,
                elapsed_ms: event
                    .wire_started
                    .expect("a sent event records its wire start")
                    .elapsed()
                    .as_millis(),
            })
        } else {
            None
        };

        // A background quantum moves its pane behind every sibling that was ready behind it. The viewed pane stays
        // in place during its bounded burst; strict FIFO inside either pane is never altered.
        if sent.selected_as_active {
            if self.panes[pane_index].events.is_empty() {
                self.panes.remove(pane_index);
            }
        } else {
            let pane = self
                .panes
                .remove(pane_index)
                .expect("the committed pane still exists");
            if !pane.events.is_empty() {
                self.panes.push_back(pane);
            }
        }
        Ok(completed)
    }

    fn is_empty(&self) -> bool {
        self.queued_items == 0
    }

    #[cfg(test)]
    fn queued_items(&self) -> usize {
        self.queued_items
    }

    #[cfg(test)]
    fn queued_bytes(&self) -> usize {
        self.queued_bytes
    }
}

fn encode_next_terminal_chunk(
    channel: u16,
    output: &PreparedTerminalLine,
    offset: usize,
) -> Result<(Vec<u8>, usize, bool), OutputSendError> {
    match output {
        PreparedTerminalLine::Legacy(line) => {
            if offset > line.len() || (offset == line.len() && !line.is_empty()) {
                return Err(OutputSendError::EncodeFailed);
            }
            let end = (offset + OUTPUT_CHUNK_BYTES).min(line.len());
            let is_last = end >= line.len();
            let mut payload = Vec::with_capacity(1 + end.saturating_sub(offset));
            payload.push(u8::from(is_last));
            payload.extend_from_slice(&line[offset..end]);
            let frame = crate::remote_frame::encode(
                crate::remote_frame::FrameKind::TerminalOutputChunk,
                channel,
                &payload,
            )
            .map_err(|_| OutputSendError::EncodeFailed)?;
            Ok((frame, end, is_last))
        }
        PreparedTerminalLine::Gzip {
            encoded,
            decoded_len,
        } => {
            use crate::remote_frame::{
                encode_terminal_gzip_chunk_payload, FrameKind, TERMINAL_CODEC_CHUNK_BYTES,
            };
            if encoded.is_empty()
                || offset >= encoded.len()
                || !offset.is_multiple_of(TERMINAL_CODEC_CHUNK_BYTES)
            {
                return Err(OutputSendError::EncodeFailed);
            }
            let count = encoded.len().div_ceil(TERMINAL_CODEC_CHUNK_BYTES);
            let count_u16 = u16::try_from(count).map_err(|_| OutputSendError::EncodeFailed)?;
            let index = offset / TERMINAL_CODEC_CHUNK_BYTES;
            let end = (offset + TERMINAL_CODEC_CHUNK_BYTES).min(encoded.len());
            let payload = encode_terminal_gzip_chunk_payload(
                u16::try_from(index).map_err(|_| OutputSendError::EncodeFailed)?,
                count_u16,
                encoded
                    .len()
                    .try_into()
                    .map_err(|_| OutputSendError::EncodeFailed)?,
                *decoded_len,
                &encoded[offset..end],
            )
            .map_err(|_| OutputSendError::EncodeFailed)?;
            let frame =
                crate::remote_frame::encode(FrameKind::TerminalGzipJsonChunk, channel, &payload)
                    .map_err(|_| OutputSendError::EncodeFailed)?;
            Ok((frame, end, end == encoded.len()))
        }
    }
}

async fn admit_daemon_output(
    routed: RoutedDaemonOutput,
    bridge: &SharedBridge,
    arbiter: &mut TerminalOutputArbiter,
) -> Result<(), OutputSendError> {
    let session_id = &routed.output.session_id;
    let target = {
        let guard = bridge.lock().await;
        guard
            .as_ref()
            .and_then(|bridge| bridge.exact_output_target(session_id))
    };
    enqueue_routed_daemon_output(routed, target, arbiter)
}

fn enqueue_routed_daemon_output(
    routed: RoutedDaemonOutput,
    target: Option<TerminalOutputTarget>,
    arbiter: &mut TerminalOutputArbiter,
) -> Result<(), OutputSendError> {
    let RoutedDaemonOutput {
        output,
        attachment,
        reservation,
    } = routed;
    let session_id = output.session_id;
    let target = target.filter(|target| attachment.accepts(target.generation));
    if let Some(target) = target {
        arbiter.enqueue_reserved(session_id, target, output.line, Some(reservation))?;
    }
    Ok(())
}

fn finish_codec_job(
    joined: Result<(u64, Result<PreparedTerminalLine, OutputSendError>), tokio::task::JoinError>,
    arbiter: &mut TerminalOutputArbiter,
) -> Result<(), OutputSendError> {
    let (ticket, prepared) = joined.map_err(|_| OutputSendError::CompressionFailed)?;
    arbiter.finish_preparation(ticket, prepared)
}

async fn run_daemon_output_forwarder(
    mut daemon_out: crate::remote_daemon_backend::DaemonOutputReceiver,
    bridge: &SharedBridge,
    outbound: &OutboundScheduler,
) -> Result<(), OutputSendError> {
    let mut arbiter = TerminalOutputArbiter::new();
    let mut preparations = JoinSet::new();
    let mut input_closed = false;

    loop {
        // At every wire-chunk boundary, first pull the already-bounded daemon prefix into the per-pane arbiter. This
        // is the key HOL break: a viewed event already waiting behind background events becomes selectable before
        // another background chunk is committed. A continuous producer can only reach the hard arbiter limit, at
        // which point this function fails the owner instead of dropping a revision and continuing.
        if !input_closed {
            loop {
                match daemon_out.try_recv_routed() {
                    Ok(output) => admit_daemon_output(output, bridge, &mut arbiter).await?,
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        input_closed = true;
                        break;
                    }
                }
            }
        }
        let next_chunk = {
            let guard = bridge.lock().await;
            arbiter.retire_stale_targets(|session_id| {
                guard
                    .as_ref()
                    .and_then(|bridge| bridge.exact_output_target(session_id))
            });
            arbiter.start_preparations(&mut preparations);
            while let Some(joined) = preparations.try_join_next() {
                finish_codec_job(joined, &mut arbiter)?;
            }
            let active_session = guard.as_ref().and_then(|bridge| bridge.viewed_session());
            arbiter.next_chunk(active_session)?
        };
        if let Some(mut chunk) = next_chunk {
            // This is the only terminal submission in flight. Awaiting it is intentional: the existing scheduler
            // reconsiders its strict control queue before every frame, and a focus/output arrival waits for at most
            // this one bounded chunk. Never race/cancel an enqueue future after it has published a wire item.
            let frame = std::mem::take(&mut chunk.frame);
            outbound.send_terminal_binary(frame).await?;
            if let Some(stats) = arbiter.commit_chunk(chunk)? {
                tracing::debug!(
                    "STAGE send_output ok ev={} bytes={} chunks={} ms={} chunk_bytes={OUTPUT_CHUNK_BYTES}",
                    stats.event_label,
                    stats.original_len,
                    stats.chunks,
                    stats.elapsed_ms
                );
            }
            continue;
        }

        if input_closed && arbiter.is_empty() {
            return Err(OutputSendError::QueueClosed);
        }

        match (input_closed, preparations.is_empty()) {
            (false, false) => {
                tokio::select! {
                    biased;
                    output = daemon_out.recv_routed() => match output {
                        Some(output) => admit_daemon_output(output, bridge, &mut arbiter).await?,
                        None => input_closed = true,
                    },
                    joined = preparations.join_next() => {
                        let joined = joined.ok_or(OutputSendError::CompressionFailed)?;
                        finish_codec_job(joined, &mut arbiter)?;
                    }
                }
            }
            (false, true) => match daemon_out.recv_routed().await {
                Some(output) => admit_daemon_output(output, bridge, &mut arbiter).await?,
                None => input_closed = true,
            },
            (true, false) => {
                let joined = preparations
                    .join_next()
                    .await
                    .ok_or(OutputSendError::CompressionFailed)?;
                finish_codec_job(joined, &mut arbiter)?;
            }
            (true, true) => return Err(OutputSendError::EncodeFailed),
        }
    }
}

/// Minimal async surface used by the output sender. Keeping the hysteresis state independent of
/// `RTCDataChannel` makes missed-wake and timeout behavior deterministic to test without weakening the real
/// callback wiring.
trait BufferedDataChannel: Send + Sync {
    async fn buffered_amount(&self) -> usize;
    async fn send_bytes(&self, bytes: bytes::Bytes) -> Result<(), ()>;
    async fn send_text_frame(&self, text: String) -> Result<(), ()>;
}

/// The extra operations needed only for a peer-requested graceful close. Keeping this separate from the hot-path
/// sender trait prevents ordinary output scheduling from gaining close authority and makes the bounded drain
/// contract deterministic to test.
trait GracefullyClosableDataChannel: BufferedDataChannel {
    async fn set_drain_threshold(&self, threshold: usize);
    async fn close_data_channel(&self) -> Result<(), ()>;
}

impl BufferedDataChannel for RTCDataChannel {
    async fn buffered_amount(&self) -> usize {
        RTCDataChannel::buffered_amount(self).await
    }

    async fn send_bytes(&self, bytes: bytes::Bytes) -> Result<(), ()> {
        self.send(&bytes).await.map(|_| ()).map_err(|_| ())
    }

    async fn send_text_frame(&self, text: String) -> Result<(), ()> {
        self.send_text(text).await.map(|_| ()).map_err(|_| ())
    }
}

impl GracefullyClosableDataChannel for RTCDataChannel {
    async fn set_drain_threshold(&self, threshold: usize) {
        self.set_buffered_amount_low_threshold(threshold).await;
    }

    async fn close_data_channel(&self) -> Result<(), ()> {
        self.close().await.map_err(|_| ())
    }
}

/// A monotonic watch generation makes the low-water callback edge race-safe without polling. Unlike a capacity-one
/// queue, a real low edge cannot be silently coalesced behind an older unread token; every callback advances the
/// generation while retaining only constant storage.
#[derive(Clone)]
struct BufferedAmountLowWake {
    tx: watch::Sender<u64>,
}

impl BufferedAmountLowWake {
    fn signal(&self) -> bool {
        let has_receiver = self.tx.receiver_count() > 0;
        self.tx
            .send_modify(|generation| *generation = generation.wrapping_add(1));
        has_receiver
    }

    #[cfg(test)]
    fn generation(&self) -> u64 {
        *self.tx.borrow()
    }
}

#[derive(Clone)]
struct BufferedAmountGate {
    rx: watch::Receiver<u64>,
}

fn buffered_amount_low_channel() -> (BufferedAmountLowWake, BufferedAmountGate) {
    let (tx, rx) = watch::channel(0);
    (BufferedAmountLowWake { tx }, BufferedAmountGate { rx })
}

impl BufferedAmountGate {
    #[cfg(test)]
    async fn wait_before_send<C: BufferedDataChannel + ?Sized>(
        &mut self,
        dc: &C,
        stall_timeout: std::time::Duration,
    ) -> Result<(), OutputSendError> {
        self.wait_before_send_with_limits(dc, stall_timeout, DC_BUFFER_HIGH, DC_BUFFER_LOW)
            .await
    }

    async fn wait_before_send_with_limits<C: BufferedDataChannel + ?Sized>(
        &mut self,
        dc: &C,
        stall_timeout: std::time::Duration,
        high: usize,
        low: usize,
    ) -> Result<(), OutputSendError> {
        debug_assert!(low <= high);
        if dc.buffered_amount().await <= high {
            return Ok(());
        }

        let deadline = tokio::time::Instant::now() + stall_timeout;
        loop {
            // Once HIGH is crossed, preserve hysteresis and wait for LOW. This read also covers a drain that
            // completed before the callback was able to enqueue its edge.
            if dc.buffered_amount().await <= low {
                return Ok(());
            }
            match tokio::time::timeout_at(deadline, self.rx.changed()).await {
                Ok(Ok(())) => {
                    // The observed generation may correspond to an older edge, or the buffer may have risen
                    // again. Re-read the authoritative amount; every later crossing has a newer generation.
                }
                Ok(Err(_)) | Err(_) => return Err(OutputSendError::BufferStalled),
            }
        }
    }

    /// Wait until SCTP reports every queued application byte acknowledged by the peer. webrtc-sctp decrements
    /// `buffered_amount` from its SACK processing (`on_buffer_released`), so zero is the library's bounded,
    /// content-blind delivery barrier; `send_text().await` alone is only local queue admission.
    async fn wait_until_empty<C: BufferedDataChannel + ?Sized>(&mut self, dc: &C) -> bool {
        loop {
            if dc.buffered_amount().await == 0 {
                return true;
            }
            if self.rx.changed().await.is_err() {
                return false;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GracefulCloseOutcome {
    drained: bool,
    close_returned: bool,
}

async fn drain_and_close_data_channel<C: GracefullyClosableDataChannel + ?Sized>(
    dc: &C,
    drain: &mut BufferedAmountGate,
    drain_timeout: std::time::Duration,
    close_timeout: std::time::Duration,
) -> GracefulCloseOutcome {
    // Reuse the already-installed low-water callback, but move its final threshold to zero only after the outbound
    // owner is stopped. No sender can then race this one-shot drain or restore the normal scheduling threshold.
    let drained = tokio::time::timeout(drain_timeout, async {
        dc.set_drain_threshold(0).await;
        drain.wait_until_empty(dc).await
    })
    .await
    .unwrap_or(false);
    if !drained {
        tracing::warn!("remote-peer: graceful DataChannel drain timed out; forcing bounded close");
    }

    let close_returned = close_data_channel_bounded(dc, close_timeout).await;
    GracefulCloseOutcome {
        drained,
        close_returned,
    }
}

async fn close_data_channel_bounded<C: GracefullyClosableDataChannel + ?Sized>(
    dc: &C,
    close_timeout: std::time::Duration,
) -> bool {
    match tokio::time::timeout(close_timeout, dc.close_data_channel()).await {
        Ok(Ok(())) => true,
        Ok(Err(())) => {
            tracing::debug!("remote-peer: DataChannel close returned an error");
            true
        }
        Err(_) => {
            tracing::warn!(
                "remote-peer: DataChannel close timed out; peer owner will close the connection"
            );
            false
        }
    }
}

#[cfg(test)]
async fn send_binary<C: BufferedDataChannel + ?Sized>(
    dc: &C,
    backpressure: &mut BufferedAmountGate,
    bytes: Vec<u8>,
    stall_timeout: std::time::Duration,
) -> Result<(), OutputSendError> {
    backpressure.wait_before_send(dc, stall_timeout).await?;
    dc.send_bytes(bytes::Bytes::from(bytes))
        .await
        .map_err(|_| OutputSendError::DataChannelClosed)
}

#[derive(Debug)]
enum ScheduledFrame {
    Text(String),
    Binary(bytes::Bytes),
}

impl ScheduledFrame {
    fn byte_len(&self) -> usize {
        match self {
            Self::Text(text) => text.len(),
            Self::Binary(bytes) => bytes.len(),
        }
    }
}

struct ScheduledItem {
    frame: ScheduledFrame,
    // Holding the permit in the queue item makes queued + currently-sending bytes part of the same hard bound.
    _byte_permit: OwnedSemaphorePermit,
    completion: oneshot::Sender<Result<(), OutputSendError>>,
}

struct FinalScheduledItem {
    text: String,
    completion: oneshot::Sender<Result<(), OutputSendError>>,
}

/// One admission epoch shared by both ordinary queues and the dedicated final-control barrier. Producers may do
/// bounded-capacity waits before taking `commit`, but the actual queue insertion is serialized with retirement.
/// Consequently a producer either commits before the barrier (and is visible for the owner to reject) or observes
/// retirement; it cannot insert a wire write after final authority has been established.
#[derive(Default)]
struct OutboundAdmission {
    retired: AtomicBool,
    commit: std::sync::Mutex<()>,
}

impl OutboundAdmission {
    fn is_retired(&self) -> bool {
        self.retired.load(Ordering::Acquire)
    }

    fn lock_commit(&self) -> std::sync::MutexGuard<'_, ()> {
        self.commit
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
}

#[derive(Clone)]
struct OutboundQueue {
    tx: mpsc::Sender<ScheduledItem>,
    byte_budget: Arc<Semaphore>,
    max_bytes: usize,
    admission: Arc<OutboundAdmission>,
    // Tokio's mutex waiters are FIFO. Serializing permit acquisition + channel insertion preserves class order even
    // when independent WebRTC callbacks submit concurrently. It is released before waiting for wire completion.
    enqueue_order: Arc<Mutex<()>>,
}

impl OutboundQueue {
    async fn enqueue(&self, frame: ScheduledFrame) -> Result<(), OutputSendError> {
        if self.admission.is_retired() {
            return Err(OutputSendError::SchedulerRetired);
        }
        let bytes = frame.byte_len().max(1);
        if bytes > self.max_bytes || bytes > u32::MAX as usize {
            return Err(OutputSendError::QueueItemTooLarge);
        }

        let order = self.enqueue_order.lock().await;
        if self.admission.is_retired() {
            return Err(OutputSendError::SchedulerRetired);
        }
        let permit = self
            .byte_budget
            .clone()
            .acquire_many_owned(bytes as u32)
            .await
            .map_err(|_| OutputSendError::QueueClosed)?;
        let slot = self
            .tx
            .reserve()
            .await
            .map_err(|_| OutputSendError::QueueClosed)?;
        let (completion, completed) = oneshot::channel();
        {
            let _commit = self.admission.lock_commit();
            if self.admission.is_retired() {
                return Err(OutputSendError::SchedulerRetired);
            }
            slot.send(ScheduledItem {
                frame,
                _byte_permit: permit,
                completion,
            });
        }
        drop(order);

        completed.await.unwrap_or(Err(OutputSendError::QueueClosed))
    }
}

/// One per-peer outbound surface. Every DataChannel write enters one owner task through these two fixed-priority
/// queues. Control includes auth/revoke/liveness/control-plane and terminal-metadata replies; the per-pane arbiter
/// above submits at most one daemon terminal chunk here at a time. This owner therefore remains the final strict
/// control-over-terminal gate for the one shipping DataChannel.
#[derive(Clone)]
struct OutboundScheduler {
    control: OutboundQueue,
    terminal: OutboundQueue,
    final_control_tx: mpsc::Sender<FinalScheduledItem>,
    admission: Arc<OutboundAdmission>,
    liveness_tx: mpsc::UnboundedSender<PeerTransportEvent>,
}

impl OutboundScheduler {
    async fn send_control_text(&self, text: String) -> Result<(), OutputSendError> {
        self.send(&self.control, ScheduledFrame::Text(text)).await
    }

    async fn send_control_binary(&self, bytes: Vec<u8>) -> Result<(), OutputSendError> {
        self.send(
            &self.control,
            ScheduledFrame::Binary(bytes::Bytes::from(bytes)),
        )
        .await
    }

    async fn send_terminal_binary(&self, bytes: Vec<u8>) -> Result<(), OutputSendError> {
        self.send(
            &self.terminal,
            ScheduledFrame::Binary(bytes::Bytes::from(bytes)),
        )
        .await
    }

    /// Atomically retire ordinary outbound admission and enqueue the one final control reply on a dedicated
    /// highest-priority barrier. The owner rejects everything still queued before writing this frame and exits
    /// immediately afterwards, so successful completion means there can be no later wire write.
    async fn send_final_control_text(&self, text: String) -> Result<(), OutputSendError> {
        if self.admission.is_retired() {
            return Err(OutputSendError::SchedulerRetired);
        }
        if text.len() > self.control.max_bytes {
            return Err(OutputSendError::QueueItemTooLarge);
        }

        let slot = self
            .final_control_tx
            .reserve()
            .await
            .map_err(|_| OutputSendError::QueueClosed)?;
        let (completion, completed) = oneshot::channel();
        {
            let _commit = self.admission.lock_commit();
            if self.admission.is_retired() {
                return Err(OutputSendError::SchedulerRetired);
            }
            self.admission.retired.store(true, Ordering::Release);
            slot.send(FinalScheduledItem { text, completion });
        }

        let result = completed.await.unwrap_or(Err(OutputSendError::QueueClosed));
        if result.is_err() {
            let _ = self
                .liveness_tx
                .send(PeerTransportEvent::OutboundSenderFailed);
        }
        result
    }

    async fn send(
        &self,
        queue: &OutboundQueue,
        frame: ScheduledFrame,
    ) -> Result<(), OutputSendError> {
        let result = queue.enqueue(frame).await;
        if result.is_err() && result != Err(OutputSendError::SchedulerRetired) {
            // Queue closure, an over-bound frame, buffer stall, and DC failure all make the one-peer outbound path
            // incomplete. Wake its existing owner-scoped teardown path rather than leaving control apparently live.
            let _ = self
                .liveness_tx
                .send(PeerTransportEvent::OutboundSenderFailed);
        }
        result
    }
}

struct OutboundSchedulerOwner {
    final_control_rx: mpsc::Receiver<FinalScheduledItem>,
    control_rx: mpsc::Receiver<ScheduledItem>,
    terminal_rx: mpsc::Receiver<ScheduledItem>,
    liveness_tx: mpsc::UnboundedSender<PeerTransportEvent>,
    buffer_policy: OutboundBufferPolicy,
}

fn outbound_scheduler_channel(
    liveness_tx: mpsc::UnboundedSender<PeerTransportEvent>,
) -> (OutboundScheduler, OutboundSchedulerOwner) {
    outbound_scheduler_channel_with_limits(
        liveness_tx,
        OUTBOUND_CONTROL_QUEUE_BYTES,
        OUTBOUND_TERMINAL_QUEUE_BYTES,
        OUTBOUND_CONTROL_QUEUE_ITEMS,
        OUTBOUND_TERMINAL_QUEUE_ITEMS,
    )
}

fn outbound_scheduler_channel_with_limits(
    liveness_tx: mpsc::UnboundedSender<PeerTransportEvent>,
    control_bytes: usize,
    terminal_bytes: usize,
    control_items: usize,
    terminal_items: usize,
) -> (OutboundScheduler, OutboundSchedulerOwner) {
    outbound_scheduler_channel_with_policy_and_limits(
        liveness_tx,
        OutboundBufferPolicy::production(),
        control_bytes,
        terminal_bytes,
        control_items,
        terminal_items,
    )
}

fn outbound_scheduler_channel_with_policy_and_limits(
    liveness_tx: mpsc::UnboundedSender<PeerTransportEvent>,
    buffer_policy: OutboundBufferPolicy,
    control_bytes: usize,
    terminal_bytes: usize,
    control_items: usize,
    terminal_items: usize,
) -> (OutboundScheduler, OutboundSchedulerOwner) {
    assert!(control_bytes <= u32::MAX as usize && terminal_bytes <= u32::MAX as usize);
    let (control_tx, control_rx) = mpsc::channel(control_items);
    let (terminal_tx, terminal_rx) = mpsc::channel(terminal_items);
    let (final_control_tx, final_control_rx) = mpsc::channel(1);
    let admission = Arc::new(OutboundAdmission::default());
    let scheduler = OutboundScheduler {
        control: OutboundQueue {
            tx: control_tx,
            byte_budget: Arc::new(Semaphore::new(control_bytes)),
            max_bytes: control_bytes,
            admission: admission.clone(),
            enqueue_order: Arc::new(Mutex::new(())),
        },
        terminal: OutboundQueue {
            tx: terminal_tx,
            byte_budget: Arc::new(Semaphore::new(terminal_bytes)),
            max_bytes: terminal_bytes,
            admission: admission.clone(),
            enqueue_order: Arc::new(Mutex::new(())),
        },
        final_control_tx,
        admission,
        liveness_tx: liveness_tx.clone(),
    };
    (
        scheduler,
        OutboundSchedulerOwner {
            final_control_rx,
            control_rx,
            terminal_rx,
            liveness_tx,
            buffer_policy,
        },
    )
}

impl OutboundSchedulerOwner {
    async fn run<C: BufferedDataChannel + ?Sized>(
        mut self,
        dc: &C,
        mut backpressure: BufferedAmountGate,
        stall_timeout: std::time::Duration,
    ) {
        if let Err(error) = self
            .run_until_closed(dc, &mut backpressure, stall_timeout)
            .await
        {
            tracing::warn!(
                error = ?error,
                "remote-peer: outbound scheduler failed; tearing down peer"
            );
            let _ = self
                .liveness_tx
                .send(PeerTransportEvent::OutboundSenderFailed);
        }
    }

    async fn run_until_closed<C: BufferedDataChannel + ?Sized>(
        &mut self,
        dc: &C,
        backpressure: &mut BufferedAmountGate,
        stall_timeout: std::time::Duration,
    ) -> Result<(), OutputSendError> {
        let mut final_control_closed = false;
        let mut control_closed = false;
        let mut terminal_closed = false;

        loop {
            // The final-control barrier has absolute priority at each frame boundary. It cannot interrupt a native
            // send already in progress, but after it is selected both ordinary queues are retired before Bye is
            // written. Ordinary control retains strict priority over terminal messages, whose 16 KiB cap bounds the
            // time to the next frame boundary.
            if !final_control_closed {
                match self.final_control_rx.try_recv() {
                    Ok(item) => {
                        return self
                            .send_final_and_retire(dc, backpressure, stall_timeout, item)
                            .await;
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => final_control_closed = true,
                    Err(mpsc::error::TryRecvError::Empty) => {}
                }
            }
            if !control_closed {
                match self.control_rx.try_recv() {
                    Ok(item) => {
                        Self::send_item(
                            dc,
                            backpressure,
                            stall_timeout,
                            self.buffer_policy,
                            false,
                            item,
                        )
                        .await?;
                        continue;
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => control_closed = true,
                    Err(mpsc::error::TryRecvError::Empty) => {}
                }
            }
            if final_control_closed && control_closed && terminal_closed {
                return Ok(());
            }

            tokio::select! {
                biased;
                item = self.final_control_rx.recv(), if !final_control_closed => match item {
                    Some(item) => {
                        return self
                            .send_final_and_retire(dc, backpressure, stall_timeout, item)
                            .await;
                    }
                    None => final_control_closed = true,
                },
                item = self.control_rx.recv(), if !control_closed => match item {
                    Some(item) => {
                        Self::send_item(
                            dc,
                            backpressure,
                            stall_timeout,
                            self.buffer_policy,
                            false,
                            item,
                        )
                        .await?;
                    }
                    None => control_closed = true,
                },
                item = self.terminal_rx.recv(), if !terminal_closed => match item {
                    Some(item) => {
                        Self::send_item(
                            dc,
                            backpressure,
                            stall_timeout,
                            self.buffer_policy,
                            true,
                            item,
                        )
                        .await?;
                    }
                    None => terminal_closed = true,
                },
                else => return Ok(()),
            }
        }
    }

    async fn send_final_and_retire<C: BufferedDataChannel + ?Sized>(
        &mut self,
        dc: &C,
        backpressure: &mut BufferedAmountGate,
        stall_timeout: std::time::Duration,
        item: FinalScheduledItem,
    ) -> Result<(), OutputSendError> {
        // Close first so capacity/permit waiters wake, then explicitly fail every item the barrier preempted. A
        // producer holding a pre-close mpsc reservation still cannot commit: global admission was retired before
        // this item became visible. There is therefore no remaining source of a post-Bye wire write.
        self.final_control_rx.close();
        self.control_rx.close();
        self.terminal_rx.close();
        while let Ok(pending) = self.control_rx.try_recv() {
            let _ = pending
                .completion
                .send(Err(OutputSendError::SchedulerRetired));
        }
        while let Ok(pending) = self.terminal_rx.try_recv() {
            let _ = pending
                .completion
                .send(Err(OutputSendError::SchedulerRetired));
        }
        while let Ok(pending) = self.final_control_rx.try_recv() {
            let _ = pending
                .completion
                .send(Err(OutputSendError::SchedulerRetired));
        }

        let frame_bytes = item.text.len();
        let result = async {
            backpressure
                .wait_before_send_with_limits(
                    dc,
                    stall_timeout,
                    self.buffer_policy.high_before_send(false, frame_bytes),
                    self.buffer_policy.low,
                )
                .await?;
            dc.send_text_frame(item.text)
                .await
                .map_err(|_| OutputSendError::DataChannelClosed)
        }
        .await;
        let _ = item.completion.send(result);
        result
    }

    async fn send_item<C: BufferedDataChannel + ?Sized>(
        dc: &C,
        backpressure: &mut BufferedAmountGate,
        stall_timeout: std::time::Duration,
        buffer_policy: OutboundBufferPolicy,
        terminal: bool,
        item: ScheduledItem,
    ) -> Result<(), OutputSendError> {
        let frame_bytes = item.frame.byte_len();
        let result = async {
            backpressure
                .wait_before_send_with_limits(
                    dc,
                    stall_timeout,
                    buffer_policy.high_before_send(terminal, frame_bytes),
                    buffer_policy.low,
                )
                .await?;
            match item.frame {
                ScheduledFrame::Text(text) => dc
                    .send_text_frame(text)
                    .await
                    .map_err(|_| OutputSendError::DataChannelClosed),
                ScheduledFrame::Binary(bytes) => dc
                    .send_bytes(bytes)
                    .await
                    .map_err(|_| OutputSendError::DataChannelClosed),
            }
        }
        .await;
        let _ = item.completion.send(result);
        result
    }
}

/// Max bytes of daemon payload per chunk. WebRTC DataChannel rejects large single messages, so a big
/// terminal_output (e.g. a multi-MB Grid) is split into TerminalOutputChunk frames the client reassembles.
const OUTPUT_CHUNK_BYTES: usize = 16 * 1024;

/// Bound live-revoke propagation for an already-authenticated remote channel. A connection-owned watchdog
/// rechecks potentially I/O-backed authority at this cadence independently of the control select loop. Binary
/// input separately checks the cached removal result and exact token/certificate deadline at its PTY boundary,
/// so an outbound stall cannot extend write authority.
const REVOKE_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);
const DESKTOP_ACCESS_STATUS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
/// How often the ONE global live-sync watcher polls the store's data_version. ~300ms = near-instant push without
/// busy-spinning; the poll is a single cheap pragma read on the cached connection.
const WORKSPACE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(300);
/// Slice 4 (ack + re-push): how long an unacked `workspace_update` may sit before it is re-sent, how often the
/// re-push condition is checked, and how many re-sends are attempted per epoch. Bounded on purpose: a browser
/// build that never acks (pre-Slice-4) costs at most MAX_PUSH_RETRIES redundant snapshots per change and then
/// goes quiet — the next store change pushes a fresh snapshot anyway, so convergence never depends on retries.
const PUSH_ACK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const PUSH_RETRY_CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);
const MAX_PUSH_RETRIES: u32 = 3;
/// How often EACH live connection re-evaluates its push payload even without a store commit. The live PTY set is
/// NOT in the store: a pane's session going live (spawn finishing after the creation commit) or dying bumps no
/// data_version, yet it changes the push payload (the `sessions` list AND the metadata redaction of that pane's
/// session_id). Without this tick the "naming" push never fires and a desktop-created project stays stashed and
/// unclickable in the browser until a manual refresh — the 2026-07-07 live incident (conn 86sc21: creation push
/// went out 58ms after the DB write, before the PTY was up → pane redacted; no further DB write for 4 minutes →
/// no re-evaluation → the browser's landing-pending state could never complete). The byte-diff downstream dedupes,
/// so a quiet tick pushes nothing; cost is one list_sessions + filter + serialize per second per connection —
/// the same work a `session_list` request does on demand.
const LIVE_SESSION_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// Connection-LEVEL messages `serve_control` handles itself — not bridge terminal ops (`TerminalMsg`), not
/// auth/control ops (`remote_control::InboundMsg`). The shipping surface contains only the workspace ack. Explicit
/// QA binaries may compile the inspector variants with `remote-diagnostics`; a browser query flag alone can never
/// grant that authority.
#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ConnectionMsg {
    /// The browser's RECEIPT ack for an unsolicited `workspace_update` push. The browser acks every push it
    /// receives — even one its epoch guard drops as a duplicate — so a lost ack (not a lost push) also
    /// converges instead of re-pushing forever.
    WorkspaceUpdateAck { epoch: u64 },
    /// Debug surface: fetch the tail of the desktop's db-write.jsonl — the two-writer
    /// DB mutation ledger (content-blind by construction: who/op/kind/id/fields/ctx, never values).
    /// Compiled only into explicit non-shipping diagnostics binaries; `count` is clamped server-side.
    #[cfg(feature = "remote-diagnostics")]
    DbWriteTrace {
        request_id: String,
        #[serde(default)]
        count: Option<u32>,
    },
    /// Content-blind live-sync debugger: summarize the exact per-connection workspace payload the agent would
    /// currently use for session_list/workspace_update. No PTY bytes, command text, or terminal payload.
    #[cfg(feature = "remote-diagnostics")]
    DebugSyncSnapshot { request_id: String },
}

/// Server-side clamp for a db_write_trace fetch (the file itself is bounded at 4MiB anyway).
#[cfg(feature = "remote-diagnostics")]
const DB_WRITE_TRACE_MAX: usize = 500;

/// What the Slice-4 retry tick should do. Factored pure (like `should_close_for_revoke`) so the
/// re-push policy is unit-testable without a DataChannel.
#[derive(Debug, PartialEq, Eq)]
enum PushRetryAction {
    /// Acked (or nothing pushed, or not yet timed out): do nothing.
    None,
    /// Unacked past the timeout with retries left: re-send the SAME epoch's payload.
    Resend,
    /// Unacked past the timeout, retries exhausted: stop the retry clock (the next store change
    /// pushes a fresh snapshot anyway — convergence never depends on retries).
    GiveUp,
}

/// Pure Slice-4 re-push decision. `timed_out` is false when nothing is in flight (retry clock stopped).
fn push_retry_action(
    push_epoch: u64,
    last_acked_epoch: u64,
    timed_out: bool,
    retries: u32,
) -> PushRetryAction {
    if push_epoch <= last_acked_epoch || !timed_out {
        return PushRetryAction::None;
    }
    if retries < MAX_PUSH_RETRIES {
        PushRetryAction::Resend
    } else {
        PushRetryAction::GiveUp
    }
}

/// Spawn the SINGLE global live-sync watcher: one task polls the shared store's `data_version` (cached connection)
/// and publishes it on a `watch` channel. ALL remote connections subscribe to this ONE channel — so the DB poll is
/// shared (not per-browser). Each connection independently reacts (filter → diff → push) when the value changes, so
/// redaction/epoch/ack stay per-connection. Returns a receiver connections clone; the sender lives in the task.
/// The initial watch value is the current data_version so a fresh connection can SEED its baseline (no spurious
/// first push). Returns `None` when there's no DB (e.g. unenrolled/dev without a store) → no watcher, no push.
fn spawn_data_version_watcher() -> Option<tokio::sync::watch::Receiver<i64>> {
    let paths = maestro_shell::AppPaths::production().ok()?;
    let read = move || -> Option<i64> {
        let conn = maestro_shell::db::conn_for(paths.base()).ok()?;
        let guard = conn.lock().ok()?;
        maestro_shell::db::data_version(&guard).ok()
    };
    let initial = read()?;
    let (tx, rx) = tokio::sync::watch::channel(initial);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(WORKSPACE_POLL_INTERVAL);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            if let Some(v) = read() {
                // send_if_modified only notifies subscribers when the value actually changed (coalesced).
                tx.send_if_modified(|cur| {
                    if *cur != v {
                        *cur = v;
                        true
                    } else {
                        false
                    }
                });
            }
        }
    });
    Some(rx)
}

/// Send a daemon output line for `channel` as one or more TerminalOutputChunk frames. Each chunk payload is
/// `[is_last:u8][bytes...]`; the client joins them until is_last=1, then renders the joined buffer.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OutputSendStats {
    chunks: usize,
    elapsed_ms: u128,
}

#[cfg(test)]
async fn send_output_chunked<C: BufferedDataChannel + ?Sized>(
    dc: &C,
    backpressure: &mut BufferedAmountGate,
    channel: u16,
    line: &[u8],
    stall_timeout: std::time::Duration,
) -> Result<OutputSendStats, OutputSendError> {
    let started = std::time::Instant::now();
    let total = line.len();
    let mut off = 0;
    let mut chunks = 0usize;
    loop {
        let end = (off + OUTPUT_CHUNK_BYTES).min(total);
        let is_last = end >= total;
        let mut payload = Vec::with_capacity(1 + (end - off));
        payload.push(if is_last { 1u8 } else { 0u8 });
        payload.extend_from_slice(&line[off..end]);
        let frame = crate::remote_frame::encode(
            crate::remote_frame::FrameKind::TerminalOutputChunk,
            channel,
            &payload,
        )
        .map_err(|_| OutputSendError::EncodeFailed)?;
        send_binary(dc, backpressure, frame, stall_timeout).await?;
        chunks += 1;
        if is_last {
            return Ok(OutputSendStats {
                chunks,
                elapsed_ms: started.elapsed().as_millis(),
            });
        }
        off = end;
    }
}

#[cfg(test)]
async fn send_output_chunked_and_signal<C: BufferedDataChannel + ?Sized>(
    dc: &C,
    backpressure: &mut BufferedAmountGate,
    channel: u16,
    line: &[u8],
    stall_timeout: std::time::Duration,
    liveness_tx: &mpsc::UnboundedSender<PeerTransportEvent>,
) -> Result<OutputSendStats, OutputSendError> {
    let result = send_output_chunked(dc, backpressure, channel, line, stall_timeout).await;
    if result.is_err() {
        // This sender belongs to exactly one serve_session. A dead output path must end that owner instead of
        // leaving auth/control apparently live while the terminal silently stops. Late sends after teardown fail
        // harmlessly because the owner has dropped its receiver.
        let _ = liveness_tx.send(PeerTransportEvent::OutboundSenderFailed);
    }
    result
}

#[cfg(test)]
async fn schedule_terminal_output_chunked(
    outbound: &OutboundScheduler,
    channel: u16,
    line: &[u8],
) -> Result<OutputSendStats, OutputSendError> {
    let started = std::time::Instant::now();
    let total = line.len();
    let mut off = 0;
    let mut chunks = 0usize;
    loop {
        let end = (off + OUTPUT_CHUNK_BYTES).min(total);
        let is_last = end >= total;
        let mut payload = Vec::with_capacity(1 + (end - off));
        payload.push(if is_last { 1u8 } else { 0u8 });
        payload.extend_from_slice(&line[off..end]);
        let frame = crate::remote_frame::encode(
            crate::remote_frame::FrameKind::TerminalOutputChunk,
            channel,
            &payload,
        )
        .map_err(|_| OutputSendError::EncodeFailed)?;
        outbound.send_terminal_binary(frame).await?;
        chunks += 1;
        if is_last {
            return Ok(OutputSendStats {
                chunks,
                elapsed_ms: started.elapsed().as_millis(),
            });
        }
        off = end;
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PreparedTerminalLine {
    Legacy(Vec<u8>),
    Gzip { encoded: Vec<u8>, decoded_len: u32 },
}

struct CompressionCancelGuard {
    cancelled: Arc<AtomicBool>,
    armed: bool,
}

impl Drop for CompressionCancelGuard {
    fn drop(&mut self) {
        if self.armed {
            self.cancelled.store(true, Ordering::Release);
        }
    }
}

struct CappedCompressionBuffer {
    bytes: Vec<u8>,
    limit: usize,
}

impl CappedCompressionBuffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(64 * 1024)),
            limit,
        }
    }
}

impl std::io::Write for CappedCompressionBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let next_len = self.bytes.len().checked_add(buf.len()).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "terminal gzip output length overflowed its bound",
            )
        })?;
        if next_len > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "terminal gzip output exceeded its bounded savings limit",
            ));
        }
        // Avoid Vec's default geometric growth where possible. `try_reserve_exact` is still permitted to
        // over-allocate inside the allocator, so `limit` is a strict encoded-wire-length bound rather than a
        // claim about allocator capacity. Peak memory remains bounded separately by the 16 MiB decoded/event
        // contract and the fixed peer/worker limits.
        if next_len > self.bytes.capacity() {
            self.bytes
                .try_reserve_exact(next_len - self.bytes.len())
                .map_err(|_| {
                    std::io::Error::other("terminal gzip output allocation failed within its bound")
                })?;
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Compress one complete daemon JSON event away from Tokio's async workers. The blocking job checks owner
/// cancellation between 64 KiB slices, so retiring a peer cannot leave an unbounded detached compressor running.
#[cfg(test)]
async fn prepare_terminal_line(line: Vec<u8>) -> Result<PreparedTerminalLine, OutputSendError> {
    prepare_terminal_line_with_cancel(line, Arc::new(AtomicBool::new(false))).await
}

async fn prepare_terminal_line_with_cancel(
    line: Vec<u8>,
    cancelled: Arc<AtomicBool>,
) -> Result<PreparedTerminalLine, OutputSendError> {
    use crate::remote_frame::{MAX_TERMINAL_CODEC_BYTES, TERMINAL_GZIP_MIN_DECODED_BYTES};
    if line.len() < TERMINAL_GZIP_MIN_DECODED_BYTES || line.len() > MAX_TERMINAL_CODEC_BYTES {
        return Ok(PreparedTerminalLine::Legacy(line));
    }
    let worker_cancelled = cancelled.clone();
    let mut guard = CompressionCancelGuard {
        cancelled,
        armed: true,
    };
    let result = tokio::task::spawn_blocking(move || {
        compress_terminal_line_blocking(line, worker_cancelled)
    })
    .await
    .map_err(|_| OutputSendError::CompressionFailed)?;
    guard.armed = false;
    result
}

fn compress_terminal_line_blocking(
    line: Vec<u8>,
    cancelled: Arc<AtomicBool>,
) -> Result<PreparedTerminalLine, OutputSendError> {
    use crate::remote_frame::MAX_TERMINAL_CODEC_BYTES;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    let decoded_len = line.len();
    // Never allocate an encoded buffer that already cannot pass the 12.5% savings gate. Repeated Grid JSON normally
    // compresses far below 25%; reserving decoded_len / 4 would needlessly allocate roughly a megabyte for a common
    // full snapshot before producing only a few KiB. The bounded writer turns an incompressible event into a safe
    // legacy fallback before Vec growth could overshoot the protocol's encoded-size contract.
    let encoded_limit = MAX_TERMINAL_CODEC_BYTES.min(decoded_len.saturating_mul(7) / 8);
    let mut encoder = GzEncoder::new(
        CappedCompressionBuffer::new(encoded_limit),
        Compression::new(1),
    );
    for slice in line.chunks(64 * 1024) {
        if cancelled.load(Ordering::Acquire) {
            return Err(OutputSendError::CompressionCancelled);
        }
        if encoder.write_all(slice).is_err() {
            return Ok(PreparedTerminalLine::Legacy(line));
        }
    }
    if cancelled.load(Ordering::Acquire) {
        return Err(OutputSendError::CompressionCancelled);
    }
    let encoded = match encoder.finish() {
        Ok(buffer) => buffer.bytes,
        Err(_) => return Ok(PreparedTerminalLine::Legacy(line)),
    };
    // At least 12.5% savings. A fallback is byte-identical to the legacy chunk path.
    if encoded.len() > MAX_TERMINAL_CODEC_BYTES
        || (encoded.len() as u64) * 8 > (decoded_len as u64) * 7
    {
        return Ok(PreparedTerminalLine::Legacy(line));
    }
    Ok(PreparedTerminalLine::Gzip {
        encoded,
        decoded_len: decoded_len as u32,
    })
}

#[cfg(test)]
async fn schedule_terminal_gzip_chunked(
    outbound: &OutboundScheduler,
    channel: u16,
    encoded: &[u8],
    decoded_len: u32,
) -> Result<OutputSendStats, OutputSendError> {
    use crate::remote_frame::{
        encode_terminal_gzip_chunk_payload, FrameKind, TERMINAL_CODEC_CHUNK_BYTES,
    };
    let started = std::time::Instant::now();
    let count = encoded.len().div_ceil(TERMINAL_CODEC_CHUNK_BYTES);
    let count_u16 = u16::try_from(count).map_err(|_| OutputSendError::EncodeFailed)?;
    for (index, chunk) in encoded.chunks(TERMINAL_CODEC_CHUNK_BYTES).enumerate() {
        let payload = encode_terminal_gzip_chunk_payload(
            index as u16,
            count_u16,
            encoded.len() as u32,
            decoded_len,
            chunk,
        )
        .map_err(|_| OutputSendError::EncodeFailed)?;
        let frame =
            crate::remote_frame::encode(FrameKind::TerminalGzipJsonChunk, channel, &payload)
                .map_err(|_| OutputSendError::EncodeFailed)?;
        outbound.send_terminal_binary(frame).await?;
    }
    Ok(OutputSendStats {
        chunks: count,
        elapsed_ms: started.elapsed().as_millis(),
    })
}

#[derive(Debug, PartialEq, Eq)]
enum TerminalInputOutcome {
    Handled(Vec<Outbound>),
    AuthorityEnded,
}

/// Admit one binary terminal-input frame only under the independent live authority gate. The
/// second check is essential: an earlier control reply may hold the bridge mutex while its outbound
/// physical completion waits, so authority can expire or be revoked between receipt and lock
/// acquisition. The clock is invoked after that wait and is injectable for deterministic race tests.
async fn handle_binary_terminal_input<B, P>(
    bridge: &Arc<Mutex<Option<TerminalBridge<B, P>>>>,
    authority: &ConnectionAuthorityGate,
    channel: u16,
    bytes: &[u8],
    clock: impl Fn() -> u64,
) -> TerminalInputOutcome
where
    B: crate::remote_bridge::SessionBackend,
    P: crate::remote_policy::SessionPolicy,
{
    if !authority.permits_at(clock()) {
        return TerminalInputOutcome::AuthorityEnded;
    }
    let mut bridge = bridge.lock().await;
    match authority.with_permit_at(clock(), || {
        bridge
            .as_mut()
            .map(|bridge| bridge.handle_input(channel, bytes))
            .unwrap_or_default()
    }) {
        Some(outbound) => TerminalInputOutcome::Handled(outbound),
        None => TerminalInputOutcome::AuthorityEnded,
    }
}

/// Run the control loop: TEXT messages go through the ControlChannel (auth gate). On the FIRST successful
/// auth we build the `TerminalBridge` with the VERIFIED claims (so its token-scope check is real), and
/// thereafter route terminal METADATA (session_list/attach/resize/detach) to it. Live-revoke drops the
/// channel's auth (and we revoke the bridge so all attaches close).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlLoopExit {
    TransportEnded,
    PeerBye,
}

struct RemoteCreationLeaseCleanup {
    publisher: crate::winsize_owner::RemoteCreationLeasePublisher,
}

impl Drop for RemoteCreationLeaseCleanup {
    fn drop(&mut self) {
        if let Err(error) = self.publisher.clear_connection(now_ms()) {
            tracing::debug!("winsize-owner: creation lease connection cleanup failed: {error}");
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_control(
    mut rx: mpsc::Receiver<String>,
    outbound: &OutboundScheduler,
    bridge: &SharedBridge,
    backend: crate::remote_daemon_backend::DaemonBackend,
    cloud_pubkey: VerifyingKey,
    allowed_origins: Vec<String>,
    peer_device_id: String,
    signal_session_id: String,
    agent_dir: std::path::PathBuf,
    enrolled_account_id: Option<String>,
    owner: Arc<std::sync::Mutex<crate::winsize_owner::WinsizeOwner>>,
    revoked: impl Fn(&str, &str, u64) -> bool + Clone + Send + Sync + 'static,
    terminal_input_authority: ConnectionAuthorityGate,
    authority_liveness_tx: mpsc::UnboundedSender<PeerTransportEvent>,
    data_version_rx: Option<tokio::sync::watch::Receiver<i64>>,
    offer_proof: Option<OfferProofData>,
    browser_cert: Option<crate::browser_cert::BrowserCert>,
    this_desktop_id: String,
    mut peer_liveness: PeerLiveness,
) -> anyhow::Result<ControlLoopExit> {
    // Clear binary authority on every return path, including `?` errors while serializing or
    // delivering a control reply. The retained daemon PTY is owned below this connection and is not
    // terminated by clearing this gate.
    let _terminal_input_authority_cleanup =
        ConnectionAuthorityCleanup(terminal_input_authority.clone());
    let mut terminal_input_authority_watchdog = OwnedSessionTask::new(
        "binary input authority watchdog",
        tokio::spawn(run_connection_authority_watchdog(
            terminal_input_authority.clone(),
            authority_liveness_tx,
        )),
    );
    // Every allocating adapter cloned from this daemon facade must establish its connection-scoped size
    // authority before publishing a new SessionRecord/layout. The drop guard clears only this connection's
    // unconsumed leases on every control-loop exit; normal viewed attach consumes a lease earlier.
    let creation_lease_publisher = crate::winsize_owner::RemoteCreationLeasePublisher::new(
        owner.clone(),
        agent_dir.clone(),
        signal_session_id.clone(),
    );
    backend.set_remote_creation_lease_publisher(creation_lease_publisher.clone());
    let _creation_lease_cleanup = RemoteCreationLeaseCleanup {
        publisher: creation_lease_publisher,
    };
    let mut channel = ControlChannel::new(cloud_pubkey, peer_device_id, revoked.clone());
    channel.set_expected_signal_session_id(signal_session_id.clone());
    // Feed the browser's offer proof-of-possession (if any) so the Auth handler can verify it against the
    // browser public key embedded in the token.
    if let Some(p) = offer_proof {
        channel.set_offer_proof(p.device_id, p.fingerprint, p.sig_b64);
    }
    // Bind the signed token to the immutable local enrollment snapshot before considering cloud-selected browser
    // authority. Reload device.json only to obtain its passkey, and refuse if it no longer matches this running
    // peer's desktop/account identity. A supervisor restart will pick up a legitimate same-owner replacement.
    let pinned_passkey = if let Some(expected_account_id) = enrolled_account_id {
        let record = crate::device_identity::load_record(&agent_dir)
            .context("load enrollment for control authorization")?
            .ok_or_else(|| {
                anyhow::anyhow!("enrollment disappeared before control authorization")
            })?;
        if record.account_id != expected_account_id || record.device_id != this_desktop_id {
            anyhow::bail!("enrollment changed before control authorization");
        }
        crate::device_identity::require_passkey_for_remote_authority(&record)
            .context("authorize enrolled remote control")?;
        channel.set_enrollment_context(expected_account_id);
        record.passkey
    } else {
        None
    };
    // ACCESS PASSKEY (#11): pin the account passkey (from device.json) + this desktop's id, and feed the
    // browser cert (if any). FAIL-CLOSED: when a passkey is pinned, a valid cert is MANDATORY — the cloud
    // cannot downgrade by omitting the cert/browser_pubkey. Legacy browser bypass is retired, and a persisted
    // pre-passkey enrollment was refused above without deleting its local identity or daemon-owned PTYs.
    let allow_legacy_browsers = false;
    // WebAuthn cert policy: product services bind one exact release origin in their launchd/systemd argv.
    // It is deliberately not read from ambient process state here.
    let cert_policy = crate::browser_cert::CertPolicy {
        allowed_origins,
        // The browser mints 30-min certs; allow that plus a 5-min clock-skew tolerance. A cert claiming a
        // far-future expiry (a relayed / forged-window cert) is refused as ExpiryTooFar.
        max_ttl_ms: 35 * 60 * 1000,
    };
    channel.set_passkey_context(
        pinned_passkey,
        this_desktop_id,
        allow_legacy_browsers,
        cert_policy,
    );
    if let Some(cert) = browser_cert {
        channel.set_browser_cert(cert);
    }
    // Share the serving-fed owner into the control channel so a `set_winsize_owner` from THIS browser updates the
    // same state (and its recomputed effective owner is broadcast + mirrored to the file by the background tick).
    channel.set_winsize_owner(owner.clone());
    // Correlated connection trace: `trace()` writes one same-schema event to conn-trace.jsonl tagged with the
    // browser's trace id (captured on the auth message) so `grep <traceId>` spans browser+agent. Content-blind.
    let trace = |leg: &str,
                 stage: &str,
                 status: crate::conn_trace::TraceStatus,
                 detail: &str,
                 tid: &str| {
        crate::conn_trace::append(&agent_dir, tid, leg, stage, status, detail, now_ms());
    };
    let mut backend_slot = Some(backend);
    let mut desktop_access_status_check = tokio::time::interval_at(
        tokio::time::Instant::now() + DESKTOP_ACCESS_STATUS_INTERVAL,
        DESKTOP_ACCESS_STATUS_INTERVAL,
    );
    desktop_access_status_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Live-sync: subscribe to the ONE shared data_version watcher (the DB poll is global, not per-connection). When
    // the desktop app commits, the watcher notifies; THIS connection then recomputes ITS filtered metadata + byte-
    // diffs vs the last we sent (per-connection redaction + epoch + diff). Slice 2 = log-only; push in Slice 3.
    // `latest_snapshot_bytes` is seeded from the FIRST session_list reply (below) so a fresh connection's baseline
    // doesn't cause a spurious first push — a change only counts when it differs from what the reply already sent.
    let mut data_version_rx = data_version_rx;
    let mut latest_snapshot_bytes: Option<String> = None;
    let mut push_epoch: u64 = 0; // per-connection monotonic push counter
                                 // Slice 4 delivery tracking: `last_acked_epoch` is the browser's receipt high-water mark. While
                                 // `push_epoch > last_acked_epoch`, the exact pushed payload (`last_pushed_meta`, SAME epoch) is re-sent on
                                 // the retry tick — bounded by MAX_PUSH_RETRIES, then we go quiet and let the next store change converge.
    let mut last_acked_epoch: u64 = 0;
    let mut last_pushed_meta: Option<(
        Vec<String>,
        Vec<crate::remote_bridge::SessionMetadata>,
        Option<WorkspaceMetadata>,
    )> = None;
    let mut last_push_sent_at: Option<tokio::time::Instant> = None;
    let mut push_retries: u32 = 0;
    let mut push_retry_check = tokio::time::interval(PUSH_RETRY_CHECK_INTERVAL);
    push_retry_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Session-liveness poll (see LIVE_SESSION_POLL_INTERVAL): live-sync must ALSO wake when only the live PTY
    // set changed (no store commit). Only meaningful when a store watcher exists at all — a storeless agent
    // keeps its legacy no-push behavior (live_sync_wakeup pends forever in that case).
    let mut live_session_poll = tokio::time::interval(LIVE_SESSION_POLL_INTERVAL);
    live_session_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Per-serve-loop only: a permission snapshot never survives this authenticated attempt. This keeps refreshes
    // scoped to the same account/token/DataChannel owner and prevents a replacement attempt observing stale state.
    let mut last_desktop_access_status = None;
    let mut exit = ControlLoopExit::TransportEnded;

    loop {
        tokio::select! {
            reason = peer_liveness.wait_until_dead() => {
                tracing::info!(reason = %reason, "remote-peer: transport liveness ended session");
                // Return to the single cleanup path, which revokes the bridge and joins every producer before the
                // outer serve owner closes the PeerConnection.
                break;
            }
            maybe_line = rx.recv() => {
                let Some(line) = maybe_line else {
                    break;
                };

                // If authed (and not expired/revoked), the bridge exists → route terminal METADATA to it.
                // Synchronize the independent binary gate before any await in this branch. The gate repeats its
                // own deadline/revocation check at the eventual PTY write boundary.
                let live_authority = channel.authenticated_authority_snapshot_at(now_ms());
                let authenticated = live_authority.is_some();
                terminal_input_authority.replace(live_authority);
                if authenticated {
                    // CONNECTION-level messages are intercepted before the bridge's TerminalMsg routing — their
                    // state/effects live in this loop, not the bridge. Production recognizes only the push ack;
                    // inspector RPC variants do not exist unless this binary was explicitly built for diagnostics.
                    if let Ok(conn_msg) = serde_json::from_str::<ConnectionMsg>(&line) {
                        let tid = channel.trace_id().to_string();
                        match conn_msg {
                            // Slice 4 ack: the high-water mark only advances.
                            ConnectionMsg::WorkspaceUpdateAck { epoch } => {
                                if epoch > last_acked_epoch {
                                    last_acked_epoch = epoch;
                                }
                                if last_acked_epoch >= push_epoch {
                                    // Everything we pushed was received; stop the retry clock.
                                    last_push_sent_at = None;
                                    push_retries = 0;
                                }
                                trace(
                                    "wire",
                                    "in",
                                    crate::conn_trace::TraceStatus::Ok,
                                    &format!("workspace_update_ack epoch={epoch}"),
                                    &tid,
                                );
                            }
                            // Debug ledger fetch: tail db-write.jsonl (both writers' events).
                            #[cfg(feature = "remote-diagnostics")]
                            ConnectionMsg::DbWriteTrace { request_id, count } => {
                                trace(
                                    "wire",
                                    "in",
                                    crate::conn_trace::TraceStatus::Ok,
                                    &format!("db_write_trace rid={request_id}"),
                                    &tid,
                                );
                                let max = count
                                    .map(|c| c as usize)
                                    .unwrap_or(200)
                                    .min(DB_WRITE_TRACE_MAX);
                                let entries = maestro_shell::AppPaths::production()
                                    .ok()
                                    .map(|p| maestro_shell::write_trace::tail_jsonl(p.base(), max))
                                    .unwrap_or_default();
                                trace(
                                    "wire",
                                    "out",
                                    crate::conn_trace::TraceStatus::Ok,
                                    &format!(
                                        "db_write_trace_result rid={request_id} entries={}",
                                        entries.len()
                                    ),
                                    &tid,
                                );
                                let reply = serde_json::json!({
                                    "type": "db_write_trace_result",
                                    "request_id": request_id,
                                    "entries": entries,
                                });
                                if let Ok(json) = serde_json::to_string(&reply) {
                                    if outbound.send_control_text(json).await.is_err() {
                                        break;
                                    }
                                }
                            }
                            #[cfg(feature = "remote-diagnostics")]
                            ConnectionMsg::DebugSyncSnapshot { request_id } => {
                                trace(
                                    "wire",
                                    "in",
                                    crate::conn_trace::TraceStatus::Ok,
                                    &format!("debug_sync_snapshot rid={request_id}"),
                                    &tid,
                                );
                                let payload = bridge
                                    .lock()
                                    .await
                                    .as_ref()
                                    .and_then(|b| b.workspace_push_payload());
                                let reply = serde_json::json!({
                                    "type": "debug_sync_snapshot_result",
                                    "request_id": request_id,
                                    "agent": debug_sync_snapshot_value(
                                        payload.as_ref(),
                                        latest_snapshot_bytes.as_ref(),
                                        push_epoch,
                                        last_acked_epoch,
                                    ),
                                });
                                trace(
                                    "wire",
                                    "out",
                                    crate::conn_trace::TraceStatus::Ok,
                                    &format!("debug_sync_snapshot_result rid={request_id}"),
                                    &tid,
                                );
                                if let Ok(json) = serde_json::to_string(&reply) {
                                    if outbound.send_control_text(json).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                        continue;
                    }
                    let mut bridge_guard = bridge.lock().await;
                    if let Some(b) = bridge_guard.as_mut() {
                        if let Ok(msg) = serde_json::from_str::<TerminalMsg>(&line) {
                            // STAGE: name the terminal op (no payload) so attach/input/resize are visible.
                            let op = match &msg {
                                TerminalMsg::SessionList { .. } => "session_list",
                                TerminalMsg::AttachSession { .. } => "attach",
                                TerminalMsg::Resize { .. } => "resize",
                                TerminalMsg::Scrollback { .. } => "scrollback",
                                TerminalMsg::Detach { .. } => "detach",
                            };
                            tracing::debug!("STAGE terminal_msg={op}");
                            let tid = channel.trace_id().to_string();
                            // WIRE TRACE (inbound ← browser): every control message the agent RECEIVES, so `grep
                            // <traceId>` on conn-trace.jsonl interleaves with the browser's wire log into one
                            // correlated both-ends timeline. Content-blind (op name only).
                            trace("wire", "in", crate::conn_trace::TraceStatus::Ok, op, &tid);
                            // `terminal_encoding` is an additive attach-only field deliberately kept outside the
                            // legacy TerminalMsg Rust API. Missing = legacy; a non-string or near-match is passed as
                            // an invalid proposal and rejected by the bridge before it touches the daemon.
                            let terminal_encoding = if op == "attach" {
                                serde_json::from_str::<serde_json::Value>(&line)
                                    .ok()
                                    .and_then(|value| match value.get("terminal_encoding") {
                                        None => None,
                                        Some(serde_json::Value::String(value)) => Some(value.clone()),
                                        Some(_) => Some(String::new()),
                                    })
                            } else {
                                None
                            };
                            let outs = b.handle_with_terminal_encoding(
                                msg,
                                terminal_encoding.as_deref(),
                            );
                            // WIRE TRACE (outbound → browser): the replies this message produced (count only).
                            if !outs.is_empty() {
                                trace("wire", "out", crate::conn_trace::TraceStatus::Ok, &format!("{op}_reply x{}", outs.len()), &tid);
                            }
                            // Keep the high-value session_list/attach reply trace for existing greps.
                            if op == "session_list" || op == "attach" {
                                trace(op, "reply", crate::conn_trace::TraceStatus::Ok, &format!("{} outbound", outs.len()), &tid);
                            }
                            // SEED the live-sync baseline from the session_list reply: the browser now HAS this exact
                            // workspace metadata, so a subsequent watcher tick must only push if it DIFFERS from this
                            // (no spurious first push). Uses the same factored metadata → byte-identical to the reply.
                            if op == "session_list" {
                                // Seed with the SAME payload shape the watcher will diff against: the full
                                // (sessions, session_metadata, workspace_metadata) triple the reply carried
                                // (forbidden → no baseline, and the watcher won't push a forbidden connection).
                                if let Some(payload) = b.workspace_push_payload() {
                                    latest_snapshot_bytes = Some(serde_json::to_string(&payload).unwrap_or_default());
                                }
                            }
                            // Keep this bridge guard until the synchronous metadata reply is physically accepted by
                            // the scheduler owner. In particular, AttachOk must reach the wire before the daemon
                            // output forwarder can reacquire the bridge and enqueue that attachment's first Grid.
                            let send_result = send_outbounds(outbound, outs).await;
                            drop(bridge_guard);
                            if send_result.is_err() {
                                break;
                            }
                            continue;
                        }
                    }
                    drop(bridge_guard);
                } else if should_close_for_revoke(bridge.lock().await.is_some(), false) {
                    // We were authenticated but the device was revoked or the token expired.
                    tracing::info!("remote-peer: revoke observed on inbound message; closing DataChannel");
                    break;
                }

                // control (hello/auth/ping/bye/error) AND all control-plane MUTATIONS
                // (create_session/split_pane/new_window/project_create/delete_project/…).
                let mut mutation_ctx: Option<String> = None;
                if let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) {
                    if let Some(op) = value.get("type").and_then(|t| t.as_str()) {
                        tracing::debug!("STAGE control_msg={op}");
                        // WIRE TRACE (inbound ← browser): the browser traces EVERY message both directions; the agent
                        // previously traced only terminal ops + the push, so mutations were invisible on this end.
                        // Content-blind: op name + request id only (ids, never payload). `request_id` is the browser-
                        // minted correlation id — the join key between this wire event and the DB writes it causes.
                        let detail = match value.get("request_id").and_then(|r| r.as_str()) {
                            Some(rid) => format!("{op} rid={rid}"),
                            None => op.to_string(),
                        };
                        let tid = channel.trace_id().to_string();
                        trace("wire", "in", crate::conn_trace::TraceStatus::Ok, &detail, &tid);
                        mutation_ctx = Some(format!("remote:{detail}"));
                    }
                }
                // Run the handler under the mutation context so every DB write it performs is stamped
                // "remote:<op> rid=<id>" in db-write.jsonl — wire event ↔ store rows join directly.
                // The handler's SQLite mutations are synchronous on this thread (maestro-shell services).
                let reply = match mutation_ctx.as_deref() {
                    Some(ctx) => maestro_shell::write_trace::with_mutation_context(ctx, || {
                        channel.handle(&line, now_ms())
                    }),
                    None => channel.handle(&line, now_ms()),
                };
                // A refused successor is terminal by this serve-loop contract, and Bye ends authority before its
                // courtesy reply is physically delivered. Otherwise mirror the channel's exact current token,
                // certificate, and initial-revocation epoch into the independent binary callback gate.
                let reply_ends_authority = matches!(
                    &reply,
                    Some(crate::remote_control::OutboundMsg::AuthRefreshRefused { .. })
                        | Some(crate::remote_control::OutboundMsg::Bye)
                );
                let live_authority = (!reply_ends_authority)
                    .then(|| channel.authenticated_authority_snapshot_at(now_ms()))
                    .flatten();
                terminal_input_authority.replace(live_authority);
                // build the bridge the moment auth succeeds, with the real claims.
                if matches!(
                    reply,
                    Some(crate::remote_control::OutboundMsg::AuthOk { .. })
                ) {
                    if let (Some(claims), Some(be)) =
                        (channel.authenticated_claims().cloned(), backend_slot.take())
                    {
                        tracing::info!("STAGE authed → bridge ready");
                        // Correlated build stamp: now that we have the browser's trace id, log THIS agent's build under
                        // it so a browser-vs-agent version mismatch is obvious in the merged trace.
                        trace("connect", "agent_build", crate::conn_trace::TraceStatus::Ok, &crate::build_stamp(), channel.trace_id());
                        trace("connect", "auth_ok", crate::conn_trace::TraceStatus::Ok, "bridge ready", channel.trace_id());
                        // Raw record-less `create_session` deliberately remains unwired for this release: a
                        // pre-Grid conditional-Start ambiguity has no durable operation-token owner across an
                        // agent restart. Desktop-backed new_pane/split_pane below retain their prepared durable
                        // topology and remain available.
                        if let Some(splitter) = be.pane_splitter() {
                            channel.set_pane_splitter(Box::new(splitter));
                        }
                        if let Some(reviver) = be.pane_reviver() {
                            channel.set_pane_reviver(Box::new(reviver));
                        }
                        if let Some(starter) = be.pane_session_starter() {
                            channel.set_pane_session_starter(Box::new(starter));
                        }
                        if let Some(stasher) = be.pane_stasher() {
                            channel.set_pane_stasher(Box::new(stasher));
                        }
                        if let Some(remover) = be.pane_remover() {
                            channel.set_pane_remover(Box::new(remover));
                        }
                        if let Some(renamer) = be.renamer() {
                            channel.set_renamer(Box::new(renamer));
                        }
                        if let Some(closer) = be.window_closer() {
                            channel.set_window_closer(Box::new(closer));
                        }
                        if let Some(focuser) = be.window_focuser() {
                            channel.set_window_focuser(Box::new(focuser));
                        }
                        if let Some(opener) = be.window_opener() {
                            channel.set_window_opener(Box::new(opener));
                        }
                        if let Some(editor) = be.project_editor() {
                            channel.set_project_editor(Box::new(editor));
                        }
                        if let Some(previewer) = be.session_previewer() {
                            channel.set_session_previewer(Box::new(previewer));
                        }
                        if let Some(manager) = be.session_manager() {
                            channel.set_session_manager(Box::new(manager));
                        }
                        *bridge.lock().await = Some(
                            TerminalBridge::new(be, SameAsLocalPolicy, claims)
                                // WINSIZE (#25): browser resizes drive per-pane presence ownership.
                                .with_winsize_owner(owner.clone(), signal_session_id.clone())
                                .with_terminal_gzip(channel.browser_supports_terminal_gzip()),
                        );
                        // Winsize-owner Phase 2b: tell the freshly-authed browser the CURRENT effective owner so it
                        // knows up-front whether it may size the shared PTY (before any toggle). Content-blind word.
                        let snapshot = crate::remote_control::OutboundMsg::WinsizeOwnerChanged {
                            owner: channel.effective_winsize_owner(now_ms()).into(),
                        };
                        if let Ok(json) = serde_json::to_string(&snapshot) {
                            if outbound.send_control_text(json).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                if let Some(reply) = reply {
                    let auth_ok = matches!(
                        &reply,
                        crate::remote_control::OutboundMsg::AuthOk { .. }
                    );
                    let auth_refresh_refused = matches!(
                        &reply,
                        crate::remote_control::OutboundMsg::AuthRefreshRefused { .. }
                    );
                    // STAGE: name every control reply (hello/auth_ok/auth_refused/pong/error) so a stuck auth is
                    // diagnosable. auth_refused includes the bounded reason (no token, no secret).
                    match &reply {
                        crate::remote_control::OutboundMsg::AuthOk { .. } => {
                            tracing::debug!("STAGE reply=auth_ok")
                        }
                        crate::remote_control::OutboundMsg::AuthRefused { reason } => {
                            tracing::debug!("STAGE reply=auth_refused reason={reason}");
                            trace("connect", "auth_refused", crate::conn_trace::TraceStatus::Error, reason, channel.trace_id());
                        }
                        crate::remote_control::OutboundMsg::AuthRefreshOk { .. } => {
                            tracing::debug!("STAGE reply=auth_refresh_ok")
                        }
                        crate::remote_control::OutboundMsg::AuthRefreshRefused { reason } => {
                            tracing::debug!("STAGE reply=auth_refresh_refused reason={reason}");
                            trace("connect", "auth_refresh_refused", crate::conn_trace::TraceStatus::Error, reason, channel.trace_id());
                        }
                        crate::remote_control::OutboundMsg::Hello { .. } => {
                            tracing::debug!("STAGE reply=hello")
                        }
                        crate::remote_control::OutboundMsg::WinsizeOwnerChanged { .. } => {
                            // A set_winsize_owner just recomputed the effective owner. Mirror it to the desktop's file
                            // EAGERLY (don't wait up to 2s for the poll tick) so an explicit "Sized: Local" flip yields
                            // immediately. Publish the per-session set in the same serialized snapshot; an explicit
                            // Local selection must remove any in-flight creation lease from the desktop too.
                            if let Err(e) = crate::winsize_owner::publish_owner_state(
                                &agent_dir,
                                &owner,
                                now_ms(),
                            ) {
                                tracing::debug!("winsize-owner: eager state publication failed: {e}");
                            }
                        }
                        crate::remote_control::OutboundMsg::Error { code, .. } => {
                            tracing::debug!("STAGE reply=error code={code}")
                        }
                        _ => {}
                    }
                    let json = serde_json::to_string(&reply)?;
                    // WIRE TRACE (outbound → browser): every control reply, symmetric with the inbound trace above.
                    // The type tag is read back from the serialized JSON so ALL OutboundMsg variants are covered
                    // without a hand-maintained match. Content-blind (type name only). Control-rate traffic — cheap.
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
                        if let Some(reply_op) = v.get("type").and_then(|t| t.as_str()) {
                            let detail = match v.get("request_id").and_then(|r| r.as_str()) {
                                Some(rid) => format!("{reply_op} rid={rid}"),
                                None => reply_op.to_string(),
                            };
                            let tid = channel.trace_id().to_string();
                            trace("wire", "out", crate::conn_trace::TraceStatus::Ok, &detail, &tid);
                        }
                    }
                    let peer_bye = matches!(reply, crate::remote_control::OutboundMsg::Bye);
                    let send_result = if peer_bye {
                        outbound.send_final_control_text(json).await
                    } else {
                        outbound.send_control_text(json).await
                    };
                    if send_result.is_err() {
                        break;
                    }
                    if auth_refresh_refused {
                        // A failed successor is terminal for this authority epoch. Do not leave the old token and
                        // bridge live while the browser believes refresh failed closed.
                        break;
                    }
                    if auth_ok && channel.browser_supports_desktop_access_status() {
                        // Additive permission snapshot follows (never precedes) this attempt's successful auth. A
                        // legacy browser ignores the unknown type; a capable browser can explain why protected
                        // remote folder operations are unavailable without provoking a macOS prompt.
                        let (status, status_reply) =
                            channel.desktop_access_status_snapshot();
                        let json = serde_json::to_string(&status_reply)?;
                        trace(
                            "wire",
                            "out",
                            crate::conn_trace::TraceStatus::Ok,
                            "desktop_access_status",
                            channel.trace_id(),
                        );
                        if outbound.send_control_text(json).await.is_err() {
                            break;
                        }
                        let _ = should_send_desktop_access_status(
                            &mut last_desktop_access_status,
                            status,
                            true,
                        );
                    }
                    if peer_bye {
                        exit = ControlLoopExit::PeerBye;
                        break;
                    }
                }
            }
            _ = desktop_access_status_check.tick(),
                if channel.browser_supports_desktop_access_status() =>
            {
                let authenticated = channel.authenticated_claims_at(now_ms()).is_some();
                if !authenticated {
                    continue;
                }
                let (status, status_reply) = channel.desktop_access_status_snapshot();
                if should_send_desktop_access_status(
                    &mut last_desktop_access_status,
                    status,
                    authenticated,
                ) {
                    let json = serde_json::to_string(&status_reply)?;
                    trace(
                        "wire",
                        "out",
                        crate::conn_trace::TraceStatus::Ok,
                        "desktop_access_status",
                        channel.trace_id(),
                    );
                    if outbound.send_control_text(json).await.is_err() {
                        break;
                    }
                }
            }
            _ = push_retry_check.tick() => {
                // Slice 4 re-push: the latest workspace_update is unacked past the timeout → send it again with
                // the SAME epoch (the browser acks receipt even when its guard drops a duplicate apply). Bounded:
                // after MAX_PUSH_RETRIES we go quiet for this epoch — the next store change pushes fresh anyway.
                let timed_out = last_push_sent_at
                    .map(|t| t.elapsed() >= PUSH_ACK_TIMEOUT)
                    .unwrap_or(false);
                match push_retry_action(push_epoch, last_acked_epoch, timed_out, push_retries) {
                    PushRetryAction::None => {}
                    PushRetryAction::Resend => {
                        if let Some((sessions, session_metadata, meta)) = last_pushed_meta.clone() {
                            push_retries += 1;
                            last_push_sent_at = Some(tokio::time::Instant::now());
                            let counts = workspace_payload_counts(&sessions, &meta);
                            tracing::info!("STAGE workspace_update RE-push epoch={push_epoch} attempt={push_retries} {counts}");
                            trace("wire", "out", crate::conn_trace::TraceStatus::Ok, &format!("workspace_update re-push epoch={push_epoch} attempt={push_retries}"), channel.trace_id());
                            if send_outbounds(
                                outbound,
                                vec![Outbound::Json(TerminalReply::WorkspaceUpdate {
                                    epoch: push_epoch,
                                    sessions,
                                    session_metadata,
                                    workspace_metadata: meta,
                                })],
                            )
                            .await
                            .is_err()
                            {
                                break;
                            }
                        }
                    }
                    PushRetryAction::GiveUp => {
                        // Retries exhausted (likely a pre-ack browser build): stop the clock, log once.
                        tracing::info!("STAGE workspace_update unacked after {push_retries} retries epoch={push_epoch}; going quiet until the next change");
                        last_push_sent_at = None;
                    }
                }
            }
            wake = live_sync_wakeup(&mut data_version_rx, &mut live_session_poll) => {
                // The ONE shared watcher signalled a store commit, OR the session-liveness poll ticked (the live
                // PTY set is not in the store — see LIVE_SESSION_POLL_INTERVAL). Recompute THIS connection's push
                // payload, serialize deterministically, diff vs the last we sent (seeded from the session_list
                // baseline), and PUSH a workspace_update if it differs. Per-connection redaction + epoch.
                if matches!(wake, LiveSyncWake::Closed) {
                    // Watcher sender dropped (agent shutting down): stop selecting on it so this arm can't spin;
                    // the poll keeps live-sync alive for whatever remains of the connection.
                    data_version_rx = None;
                }
                if live_sync_should_eval(&wake, latest_snapshot_bytes.is_some())
                    && channel.authenticated_claims().is_some() {
                    // forbidden → None → no push; allowed → Some(meta-or-None), same semantics as the session_list reply.
                    let payload = bridge.lock().await.as_ref().and_then(|b| b.workspace_push_payload());
                    if let Some(payload) = payload {
                        let bytes = serde_json::to_string(&payload).unwrap_or_default();
                        if latest_snapshot_bytes.as_deref() != Some(bytes.as_str()) {
                            latest_snapshot_bytes = Some(bytes);
                            push_epoch += 1;
                            // Slice 4: keep the exact pushed payload + arm the ack/retry clock for THIS epoch.
                            last_pushed_meta = Some(payload.clone());
                            last_push_sent_at = Some(tokio::time::Instant::now());
                            push_retries = 0;
                            let counts = workspace_payload_counts(&payload.0, &payload.2);
                            tracing::info!("STAGE workspace_update push epoch={push_epoch} {counts}");
                            // WIRE TRACE (outbound → browser): the unsolicited live-sync push, so it shows on both ends.
                            trace("wire", "out", crate::conn_trace::TraceStatus::Ok, &format!("workspace_update epoch={push_epoch}"), channel.trace_id());
                            let (sessions, session_metadata, meta) = payload;
                            if send_outbounds(
                                outbound,
                                vec![Outbound::Json(TerminalReply::WorkspaceUpdate {
                                    epoch: push_epoch,
                                    sessions,
                                    session_metadata,
                                    workspace_metadata: meta,
                                })],
                            )
                            .await
                            .is_err()
                            {
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    // Stop admission before joining the independent owner. This does not touch the bridge or its
    // retained daemon PTYs; outer connection cleanup performs the normal remote detach.
    terminal_input_authority.clear();
    terminal_input_authority_watchdog.shutdown().await;
    Ok(exit)
}

/// Why the live-sync evaluation woke (the select arm above).
#[derive(Debug, PartialEq, Eq)]
enum LiveSyncWake {
    /// The shared store watcher signalled a data_version change (a DB commit).
    Store,
    /// The per-connection session-liveness poll ticked — the live PTY set may have changed with NO DB commit
    /// (a pane's session spawned/exited). See LIVE_SESSION_POLL_INTERVAL for the incident this covers.
    SessionPoll,
    /// The watcher's sender dropped (agent shutting down).
    Closed,
}

/// Await the next live-sync wakeup: a data_version change from the shared watcher OR the session-liveness poll
/// tick. When there's NO watcher (no store), this pends FOREVER so the select! arm simply never fires —
/// live-sync stays inert without a DB, exactly the legacy behavior.
async fn live_sync_wakeup(
    rx: &mut Option<tokio::sync::watch::Receiver<i64>>,
    poll: &mut tokio::time::Interval,
) -> LiveSyncWake {
    match rx {
        Some(r) => tokio::select! {
            changed = r.changed() => {
                if changed.is_ok() { LiveSyncWake::Store } else { LiveSyncWake::Closed }
            }
            _ = poll.tick() => LiveSyncWake::SessionPoll,
        },
        None => std::future::pending().await,
    }
}

/// Pure live-sync evaluation gate (testable like `push_retry_action`): every push must be a delta against a
/// `session_list` baseline the browser already applied. Sending a workspace_update before that baseline lets the
/// later session_list overwrite the push with stale data (fresh-connect race: project appears stashed/dead until a
/// manual refresh). `Closed` never evaluates.
fn live_sync_should_eval(wake: &LiveSyncWake, has_baseline: bool) -> bool {
    match wake {
        LiveSyncWake::Store | LiveSyncWake::SessionPoll => has_baseline,
        LiveSyncWake::Closed => false,
    }
}

fn workspace_payload_counts(sessions: &[String], metadata: &Option<WorkspaceMetadata>) -> String {
    let mut projects = 0usize;
    let mut windows = 0usize;
    let mut panes = 0usize;
    let mut named_panes = 0usize;
    let mut redacted_panes = 0usize;
    if let Some(metadata) = metadata {
        projects = metadata.projects.len();
        for project in &metadata.projects {
            windows += project.windows.len();
            for window in &project.windows {
                panes += window.panes.len();
                for pane in &window.panes {
                    if pane.session_id.is_empty() {
                        redacted_panes += 1;
                    } else {
                        named_panes += 1;
                    }
                }
            }
        }
    }
    format!(
        "sessions={} projects={projects} windows={windows} panes={panes} named_panes={named_panes} redacted_panes={redacted_panes}",
        sessions.len()
    )
}

#[cfg(feature = "remote-diagnostics")]
fn debug_sync_snapshot_value(
    payload: Option<&(
        Vec<String>,
        Vec<crate::remote_bridge::SessionMetadata>,
        Option<WorkspaceMetadata>,
    )>,
    latest_snapshot_bytes: Option<&String>,
    push_epoch: u64,
    last_acked_epoch: u64,
) -> serde_json::Value {
    let Some((sessions, session_metadata, metadata)) = payload else {
        return serde_json::json!({
            "allowed": false,
            "reason": "no_workspace_payload",
            "push_epoch": push_epoch,
            "last_acked_epoch": last_acked_epoch,
        });
    };
    let mut windows = 0usize;
    let mut panes = 0usize;
    let mut named_panes = 0usize;
    let mut redacted_panes = 0usize;
    let projects = metadata
        .as_ref()
        .map(|m| {
            m.projects
                .iter()
                .map(|project| {
                    let project_windows = project
                        .windows
                        .iter()
                        .map(|window| {
                            windows += 1;
                            let window_panes = window
                                .panes
                                .iter()
                                .map(|pane| {
                                    panes += 1;
                                    if pane.session_id.is_empty() {
                                        redacted_panes += 1;
                                    } else {
                                        named_panes += 1;
                                    }
                                    serde_json::json!({
                                        "id": pane.id,
                                        "session_id_present": !pane.session_id.is_empty(),
                                        "session_live": !pane.session_id.is_empty() && sessions.contains(&pane.session_id),
                                        "stashed": pane.stashed,
                                    })
                                })
                                .collect::<Vec<_>>();
                            serde_json::json!({
                                "id": window.id,
                                "focused": window.focused,
                                "stashed": window.stashed,
                                "panes": window_panes,
                            })
                        })
                        .collect::<Vec<_>>();
                    serde_json::json!({
                        "id": project.id,
                        "selected": project.selected,
                        "windows": project_windows,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let bytes = serde_json::to_string(&(sessions, session_metadata, metadata)).unwrap_or_default();
    serde_json::json!({
        "allowed": true,
        "push_epoch": push_epoch,
        "last_acked_epoch": last_acked_epoch,
        "session_count": sessions.len(),
        "project_count": projects.len(),
        "window_count": windows,
        "pane_count": panes,
        "named_panes": named_panes,
        "redacted_panes": redacted_panes,
        "payload_differs_from_last_sent": latest_snapshot_bytes.map(|last| last != &bytes).unwrap_or(true),
        "projects": projects,
    })
}

fn should_close_for_revoke(bridge_ready: bool, still_authenticated: bool) -> bool {
    bridge_ready && !still_authenticated
}

fn should_send_desktop_access_status(
    last_sent: &mut Option<maestro_shell::desktop_access::DesktopAccessStatus>,
    current: maestro_shell::desktop_access::DesktopAccessStatus,
    authenticated: bool,
) -> bool {
    if !authenticated || *last_sent == Some(current) {
        return false;
    }
    *last_sent = Some(current);
    true
}

async fn revoke_bridge(bridge: &SharedBridge) {
    // Take the bridge out of the shared slot, rather than leaving an inert bridge/backend retained by the daemon
    // output forwarder. Dropping it after revoke closes its backend sender once the control loop's facades drop,
    // allowing the per-connection daemon tasks to finish even when the PTY is idle and emits no final output.
    if let Some(mut b) = bridge.lock().await.take() {
        b.revoke();
    }
}

async fn shutdown_session_resources(
    dc: &Arc<RTCDataChannel>,
    bridge: &SharedBridge,
    daemon_output_forwarder: &mut OwnedSessionTask,
    outbound_owner: &mut OwnedSessionTask,
    inbound_ice_pump: &mut OwnedSessionTask,
    graceful_drain: &mut BufferedAmountGate,
    peer_bye: bool,
) {
    if peer_bye {
        // Authorization/session presence ends before any courtesy drain. Then stop every producer and the sole
        // DataChannel writer, establishing that the already-accepted Bye is the final possible write. Only this
        // peer-requested path waits for its SCTP acknowledgement; revoke/liveness/error paths remain fail-fast.
        revoke_bridge(bridge).await;
        daemon_output_forwarder.shutdown().await;
        outbound_owner.shutdown().await;
        inbound_ice_pump.shutdown().await;
        let _ = drain_and_close_data_channel(
            dc.as_ref(),
            graceful_drain,
            GRACEFUL_CLOSE_DRAIN_TIMEOUT,
            DATA_CHANNEL_CLOSE_TIMEOUT,
        )
        .await;
    } else {
        shutdown_fail_fast_session_resources(
            bridge,
            daemon_output_forwarder,
            outbound_owner,
            inbound_ice_pump,
        )
        .await;
    }
}

async fn shutdown_fail_fast_session_resources(
    bridge: &SharedBridge,
    daemon_output_forwarder: &mut OwnedSessionTask,
    outbound_owner: &mut OwnedSessionTask,
    inbound_ice_pump: &mut OwnedSessionTask,
) {
    // Authorization/session presence and every possible DataChannel producer end before the control loop returns.
    // `serve_session` is the sole fail-fast transport owner and performs one owned, uncancelled PeerConnection close,
    // rather than first closing the DataChannel here and then making webrtc-rs repeat the same close inside pc.close().
    revoke_bridge(bridge).await;
    daemon_output_forwarder.shutdown().await;
    outbound_owner.shutdown().await;
    inbound_ice_pump.shutdown().await;
}

async fn send_outbounds(
    outbound: &OutboundScheduler,
    outs: Vec<Outbound>,
) -> Result<(), OutputSendError> {
    for o in outs {
        match o {
            Outbound::Json(reply) => {
                let json =
                    serde_json::to_string(&reply).map_err(|_| OutputSendError::EncodeFailed)?;
                outbound.send_control_text(json).await?;
            }
            Outbound::Binary(bytes) => {
                outbound.send_control_binary(bytes).await?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        apply_inbound_ice_batch, buffered_amount_low_channel, close_data_channel_bounded,
        compress_terminal_line_blocking, drain_and_close_data_channel, enqueue_local_ice_candidate,
        enqueue_routed_daemon_output, handle_binary_terminal_input, headless_authority_changed,
        live_sync_should_eval, outbound_scheduler_channel_with_limits,
        pending_offer_empty_cycle_delay, prepare_terminal_line, push_retry_action,
        register_datachannel_close_liveness, run_connection_authority_watchdog,
        run_inbound_ice_pump, run_inbound_ice_pump_with_sleep, run_local_ice_poster,
        schedule_terminal_gzip_chunked, schedule_terminal_output_chunked, send_binary,
        send_output_chunked_and_signal, should_close_for_revoke, should_send_desktop_access_status,
        shutdown_fail_fast_session_resources, shutdown_session_resources, shutdown_setup_tasks,
        signed_answer_json, terminal_event_log_label, wait_for_setup_data_channel,
        BufferedDataChannel, CappedCompressionBuffer, ConnectionAuthorityGate, ConnectionMsg,
        DiscoveredDataChannel, GracefullyClosableDataChannel, InboundIceAdmission,
        InboundIceBatchError, InboundIceBatchOutcome, InboundIceFetchFuture, InboundIcePollCadence,
        InboundIcePollKind, InboundIcePollOutcome, InboundIcePollSchedule, InboundIcePumpExit,
        InboundIceValidationError, LiveSyncWake, LocalIceEnqueueError, LocalIcePostFuture,
        OutputSendError, OwnedSessionTask, PeerCloseReason, PeerLiveness, PeerTransportEvent,
        PreparedTerminalLine, PushRetryAction, RemoteIceApplier, RemoteIceApplyFuture, ServingSlot,
        SetupProgressKey, SetupProgressReporter, SharedBridge, TerminalInputOutcome,
        TerminalOutputArbiter, TerminalOutputState, TerminalOutputTarget, ACTIVE_PANE_BURST_CHUNKS,
        DC_BUFFER_HIGH, DC_BUFFER_LOW, GRACEFUL_CLOSE_DRAIN_TIMEOUT, ICE_DISCONNECTED_TIMEOUT,
        ICE_FAILED_TIMEOUT, MAX_LOCAL_ICE_CANDIDATES_PER_SESSION, MAX_LOCAL_ICE_CANDIDATE_BYTES,
        MAX_PUSH_RETRIES, MAX_REMOTE_ICE_BYTES_PER_SESSION, MAX_REMOTE_ICE_CANDIDATES_PER_SESSION,
        MAX_REMOTE_ICE_CANDIDATE_BYTES, MAX_SIGNAL_ICE_SEQUENCE, OUTPUT_CHUNK_BYTES,
        PEER_DISCONNECTED_GRACE, PENDING_OFFER_EMPTY_CYCLE_FLOOR, PENDING_OFFER_ERROR_BACKOFF,
        PINNED_SCTP_INITIAL_RTO, REVOKE_CHECK_INTERVAL, TERMINAL_EVENT_PREFIX_LIMIT,
    };
    use crate::remote_signaling::{FetchIceError, IceCandidate};
    use crate::setup_deadline::ProgressDeadline;
    use ed25519_dalek::SigningKey;
    use maestro_shell::desktop_access::DesktopAccessStatus;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use webrtc::api::setting_engine::SettingEngine;
    use webrtc::api::APIBuilder;
    use webrtc::data_channel::data_channel_state::RTCDataChannelState;
    use webrtc::data_channel::RTCDataChannel;
    use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
    use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;
    use webrtc::peer_connection::configuration::RTCConfiguration;
    use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
    use webrtc::peer_connection::sdp::{
        sdp_type::RTCSdpType, session_description::RTCSessionDescription,
    };
    use webrtc::peer_connection::RTCPeerConnection;

    fn test_setup_deadline(
        inactivity: Duration,
        absolute: Duration,
    ) -> (
        ProgressDeadline<SetupProgressKey>,
        tokio::sync::mpsc::Receiver<super::SetupProgressEvent>,
    ) {
        let (_reporter, rx) = SetupProgressReporter::channel();
        (
            ProgressDeadline::new(tokio::time::Instant::now(), inactivity, absolute),
            rx,
        )
    }

    fn test_ice_poll_cadence(
        settled_interval: Duration,
        early_delay: Duration,
    ) -> InboundIcePollCadence {
        InboundIcePollCadence {
            settled_interval,
            early_delay,
        }
    }

    #[test]
    fn pending_offer_empty_cycle_preserves_old_cloud_floor_and_renews_after_a_hold() {
        assert_eq!(
            pending_offer_empty_cycle_delay(Duration::ZERO),
            Duration::from_secs(1),
            "an immediate old-cloud response retains the established one-second floor"
        );
        assert_eq!(
            pending_offer_empty_cycle_delay(Duration::from_millis(250)),
            Duration::from_millis(750),
            "response time is part of the full empty cycle"
        );
        assert_eq!(
            pending_offer_empty_cycle_delay(Duration::from_secs(6)),
            Duration::ZERO,
            "a held response renews immediately instead of adding another second"
        );
        assert_eq!(
            pending_offer_empty_cycle_delay(Duration::from_secs(60)),
            Duration::ZERO,
            "saturating subtraction cannot underflow after a delayed wake"
        );
        assert_eq!(PENDING_OFFER_EMPTY_CYCLE_FLOOR, Duration::from_secs(1));
        assert_eq!(PENDING_OFFER_ERROR_BACKOFF, Duration::from_millis(1_500));
    }

    #[test]
    fn live_account_retirement_applies_only_to_headless_polling() {
        let changed = |account: &str, device: &str, issued_at: u64| {
            assert_eq!(account, "acct_server");
            assert_eq!(device, "");
            assert_eq!(issued_at, 0);
            true
        };
        assert!(headless_authority_changed(true, "acct_server", &changed));
        let desktop = |_: &str, _: &str, _: u64| {
            panic!("desktop polling must not use the headless account guard")
        };
        assert!(!headless_authority_changed(false, "acct_server", &desktop));
    }

    fn remote_candidate_blob(label: &str) -> String {
        serde_json::to_string(&RTCIceCandidateInit {
            candidate: format!("candidate:{label} 1 udp 1 192.0.2.1 5000 typ host"),
            sdp_mid: Some("0".into()),
            sdp_mline_index: Some(0),
            username_fragment: None,
        })
        .expect("synthetic remote candidate must serialize")
    }

    fn remote_candidate_with_exact_blob_bytes(seq: u64, bytes: usize) -> IceCandidate {
        let empty = serde_json::to_string(&RTCIceCandidateInit {
            candidate: String::new(),
            sdp_mid: None,
            sdp_mline_index: None,
            username_fragment: None,
        })
        .unwrap();
        assert!(bytes >= empty.len());
        let candidate = serde_json::to_string(&RTCIceCandidateInit {
            candidate: "x".repeat(bytes - empty.len()),
            sdp_mid: None,
            sdp_mline_index: None,
            username_fragment: None,
        })
        .unwrap();
        assert_eq!(candidate.len(), bytes);
        IceCandidate { candidate, seq }
    }

    fn remote_candidate(seq: u64, label: &str) -> IceCandidate {
        IceCandidate {
            candidate: remote_candidate_blob(label),
            seq,
        }
    }

    struct RecordingRemoteIceApplier {
        calls: Arc<Mutex<Vec<String>>>,
        results: Mutex<VecDeque<Result<(), ()>>>,
        retire_on_call: Option<(usize, Arc<AtomicBool>)>,
    }

    impl RecordingRemoteIceApplier {
        fn succeeding() -> (Self, Arc<Mutex<Vec<String>>>) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    calls: calls.clone(),
                    results: Mutex::new(VecDeque::new()),
                    retire_on_call: None,
                },
                calls,
            )
        }

        fn with_results(
            results: impl IntoIterator<Item = Result<(), ()>>,
        ) -> (Self, Arc<Mutex<Vec<String>>>) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    calls: calls.clone(),
                    results: Mutex::new(results.into_iter().collect()),
                    retire_on_call: None,
                },
                calls,
            )
        }
    }

    impl RemoteIceApplier for RecordingRemoteIceApplier {
        fn apply(&self, candidate: RTCIceCandidateInit) -> RemoteIceApplyFuture {
            let mut calls = self.calls.lock().unwrap();
            calls.push(candidate.candidate);
            let call_count = calls.len();
            drop(calls);
            if let Some((retire_at, retired)) = &self.retire_on_call {
                if call_count == *retire_at {
                    retired.store(true, Ordering::Release);
                }
            }
            let result = self.results.lock().unwrap().pop_front().unwrap_or(Ok(()));
            Box::pin(async move { result })
        }
    }

    struct HangingRemoteIceApplier;

    impl RemoteIceApplier for HangingRemoteIceApplier {
        fn apply(&self, _candidate: RTCIceCandidateInit) -> RemoteIceApplyFuture {
            Box::pin(std::future::pending())
        }
    }

    struct FakeBufferedDataChannel {
        amounts: Mutex<VecDeque<usize>>,
        current_amount: AtomicUsize,
        amount_reads: AtomicUsize,
        sends: AtomicUsize,
        fail_send: AtomicBool,
    }

    impl FakeBufferedDataChannel {
        fn new(current_amount: usize) -> Self {
            Self {
                amounts: Mutex::new(VecDeque::new()),
                current_amount: AtomicUsize::new(current_amount),
                amount_reads: AtomicUsize::new(0),
                sends: AtomicUsize::new(0),
                fail_send: AtomicBool::new(false),
            }
        }

        fn with_amount_script(amounts: impl IntoIterator<Item = usize>) -> Self {
            Self {
                amounts: Mutex::new(amounts.into_iter().collect()),
                ..Self::new(0)
            }
        }
    }

    impl BufferedDataChannel for FakeBufferedDataChannel {
        async fn buffered_amount(&self) -> usize {
            self.amount_reads.fetch_add(1, Ordering::Relaxed);
            self.amounts
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| self.current_amount.load(Ordering::Relaxed))
        }

        async fn send_bytes(&self, _bytes: bytes::Bytes) -> Result<(), ()> {
            if self.fail_send.load(Ordering::Relaxed) {
                return Err(());
            }
            self.sends.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn send_text_frame(&self, _text: String) -> Result<(), ()> {
            if self.fail_send.load(Ordering::Relaxed) {
                return Err(());
            }
            self.sends.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum RecordedFrame {
        Text(String),
        Binary(Vec<u8>),
    }

    struct RecordingDataChannel {
        sent: Mutex<Vec<RecordedFrame>>,
        binary_sends: AtomicUsize,
        block_first_binary: AtomicBool,
        first_binary_started: tokio::sync::Notify,
        first_binary_release: tokio::sync::Semaphore,
        fail_send: AtomicBool,
    }

    impl RecordingDataChannel {
        fn new() -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                binary_sends: AtomicUsize::new(0),
                block_first_binary: AtomicBool::new(false),
                first_binary_started: tokio::sync::Notify::new(),
                first_binary_release: tokio::sync::Semaphore::new(0),
                fail_send: AtomicBool::new(false),
            }
        }

        fn blocking_first_binary() -> Self {
            let dc = Self::new();
            dc.block_first_binary.store(true, Ordering::Relaxed);
            dc
        }

        async fn wait_for_first_binary(&self) {
            self.first_binary_started.notified().await;
        }

        fn release_first_binary(&self) {
            self.first_binary_release.add_permits(1);
        }

        fn frames(&self) -> Vec<RecordedFrame> {
            self.sent.lock().unwrap().clone()
        }
    }

    impl BufferedDataChannel for RecordingDataChannel {
        async fn buffered_amount(&self) -> usize {
            0
        }

        async fn send_bytes(&self, bytes: bytes::Bytes) -> Result<(), ()> {
            if self.fail_send.load(Ordering::Relaxed) {
                return Err(());
            }
            let send_index = self.binary_sends.fetch_add(1, Ordering::Relaxed);
            if send_index == 0 && self.block_first_binary.load(Ordering::Relaxed) {
                self.first_binary_started.notify_one();
                let permit = self.first_binary_release.acquire().await.map_err(|_| ())?;
                permit.forget();
            }
            self.sent
                .lock()
                .unwrap()
                .push(RecordedFrame::Binary(bytes.to_vec()));
            Ok(())
        }

        async fn send_text_frame(&self, text: String) -> Result<(), ()> {
            if self.fail_send.load(Ordering::Relaxed) {
                return Err(());
            }
            self.sent.lock().unwrap().push(RecordedFrame::Text(text));
            Ok(())
        }
    }

    /// Deterministic SCTP model for graceful-close tests: `send_*` is only local queue admission, `ack_pending`
    /// is the peer acknowledgement that releases buffered bytes, and close records whether it raced delivery.
    struct AckControlledDataChannel {
        buffered: AtomicUsize,
        pending: Mutex<Vec<RecordedFrame>>,
        delivered: Mutex<Vec<RecordedFrame>>,
        drain_threshold: AtomicUsize,
        close_started: AtomicBool,
        closed_before_delivery: AtomicBool,
        stall_close: AtomicBool,
    }

    impl AckControlledDataChannel {
        fn new() -> Self {
            Self {
                buffered: AtomicUsize::new(0),
                pending: Mutex::new(Vec::new()),
                delivered: Mutex::new(Vec::new()),
                drain_threshold: AtomicUsize::new(usize::MAX),
                close_started: AtomicBool::new(false),
                closed_before_delivery: AtomicBool::new(false),
                stall_close: AtomicBool::new(false),
            }
        }

        fn acknowledge_pending(&self) {
            let mut pending = self.pending.lock().unwrap();
            let mut delivered = self.delivered.lock().unwrap();
            delivered.extend(pending.drain(..));
            self.buffered.store(0, Ordering::Release);
        }

        fn delivered(&self) -> Vec<RecordedFrame> {
            self.delivered.lock().unwrap().clone()
        }
    }

    impl BufferedDataChannel for AckControlledDataChannel {
        async fn buffered_amount(&self) -> usize {
            self.buffered.load(Ordering::Acquire)
        }

        async fn send_bytes(&self, bytes: bytes::Bytes) -> Result<(), ()> {
            self.buffered.fetch_add(bytes.len(), Ordering::AcqRel);
            self.pending
                .lock()
                .unwrap()
                .push(RecordedFrame::Binary(bytes.to_vec()));
            Ok(())
        }

        async fn send_text_frame(&self, text: String) -> Result<(), ()> {
            self.buffered.fetch_add(text.len(), Ordering::AcqRel);
            self.pending.lock().unwrap().push(RecordedFrame::Text(text));
            Ok(())
        }
    }

    impl GracefullyClosableDataChannel for AckControlledDataChannel {
        async fn set_drain_threshold(&self, threshold: usize) {
            self.drain_threshold.store(threshold, Ordering::Release);
        }

        async fn close_data_channel(&self) -> Result<(), ()> {
            self.close_started.store(true, Ordering::Release);
            if !self.pending.lock().unwrap().is_empty() {
                self.closed_before_delivery.store(true, Ordering::Release);
            }
            if self.stall_close.load(Ordering::Acquire) {
                return std::future::pending().await;
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn peer_bye_waits_for_sctp_ack_before_closing() {
        let (liveness_tx, _liveness) = PeerLiveness::channel(Duration::from_secs(1));
        let (scheduler, owner) = outbound_scheduler_channel_with_limits(liveness_tx, 64, 64, 8, 8);
        let dc = Arc::new(AckControlledDataChannel::new());
        let (wake, gate) = buffered_amount_low_channel();
        let mut graceful_drain = gate.clone();
        let dc_for_owner = dc.clone();
        let owner_task = tokio::spawn(async move {
            owner
                .run(dc_for_owner.as_ref(), gate, Duration::from_secs(1))
                .await;
        });

        scheduler
            .send_final_control_text(r#"{"type":"bye"}"#.to_string())
            .await
            .expect("Bye must be admitted by the final-control barrier");
        assert!(
            dc.delivered().is_empty(),
            "local send completion is not a peer ack"
        );
        owner_task
            .await
            .expect("the final-control barrier must terminate its owner");
        drop(scheduler);

        let dc_for_ack = dc.clone();
        let ack_task = tokio::spawn(async move {
            tokio::task::yield_now().await;
            dc_for_ack.acknowledge_pending();
            let _ = wake.signal();
        });
        let outcome = drain_and_close_data_channel(
            dc.as_ref(),
            &mut graceful_drain,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await;
        ack_task.await.expect("ack fixture must finish");

        assert_eq!(
            outcome,
            super::GracefulCloseOutcome {
                drained: true,
                close_returned: true,
            }
        );
        assert_eq!(dc.drain_threshold.load(Ordering::Acquire), 0);
        assert_eq!(
            dc.delivered(),
            vec![RecordedFrame::Text(r#"{"type":"bye"}"#.to_string())]
        );
        assert!(dc.close_started.load(Ordering::Acquire));
        assert!(
            !dc.closed_before_delivery.load(Ordering::Acquire),
            "the DataChannel must close only after its final reply is acknowledged"
        );
    }

    #[tokio::test]
    async fn peer_bye_teardown_is_bounded_when_peer_never_drains_or_closes() {
        let dc = AckControlledDataChannel::new();
        dc.stall_close.store(true, Ordering::Release);
        dc.send_text_frame(r#"{"type":"bye"}"#.to_string())
            .await
            .expect("stalled fixture must accept the final local write");
        let (_wake, mut graceful_drain) = buffered_amount_low_channel();

        let outcome = tokio::time::timeout(
            Duration::from_millis(100),
            drain_and_close_data_channel(
                &dc,
                &mut graceful_drain,
                Duration::from_millis(10),
                Duration::from_millis(10),
            ),
        )
        .await
        .expect("both graceful teardown phases must stay inside their independent bounds");

        assert_eq!(
            outcome,
            super::GracefulCloseOutcome {
                drained: false,
                close_returned: false,
            }
        );
        assert!(dc.close_started.load(Ordering::Acquire));
        assert!(dc.closed_before_delivery.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn direct_data_channel_close_is_bounded_when_close_stalls() {
        let dc = AckControlledDataChannel::new();
        dc.stall_close.store(true, Ordering::Release);

        let close_returned = tokio::time::timeout(
            Duration::from_millis(100),
            close_data_channel_bounded(&dc, Duration::from_millis(10)),
        )
        .await
        .expect("the direct close helper must honor its injected bound");

        assert!(!close_returned);
        assert!(dc.close_started.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn fail_fast_teardown_quiesces_all_owners_before_outer_peer_close() {
        use crate::winsize_owner::WinsizeOwner;

        struct DropMarker(Arc<AtomicBool>);
        impl Drop for DropMarker {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        async fn pending_owner(label: &'static str, dropped: Arc<AtomicBool>) -> OwnedSessionTask {
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                let _marker = DropMarker(dropped);
                let _ = started_tx.send(());
                std::future::pending::<()>().await;
            });
            started_rx.await.expect("owned task must start");
            OwnedSessionTask::new(label, task)
        }

        let serving = Arc::new(AtomicUsize::new(0));
        let owner = Arc::new(Mutex::new(WinsizeOwner::new()));
        let slot = ServingSlot::acquire(serving.clone(), owner);
        assert_eq!(serving.load(Ordering::Acquire), 1);

        let output_dropped = Arc::new(AtomicBool::new(false));
        let outbound_dropped = Arc::new(AtomicBool::new(false));
        let ice_dropped = Arc::new(AtomicBool::new(false));
        let mut daemon_output_forwarder =
            pending_owner("fail-fast output", output_dropped.clone()).await;
        let mut outbound_owner =
            pending_owner("fail-fast outbound", outbound_dropped.clone()).await;
        let mut inbound_ice_pump = pending_owner("fail-fast ICE", ice_dropped.clone()).await;

        let bridge: SharedBridge = Arc::new(tokio::sync::Mutex::new(None));
        let (quiesced_tx, quiesced_rx) = tokio::sync::oneshot::channel();
        let (allow_outer_close_tx, allow_outer_close_rx) = tokio::sync::oneshot::channel();
        let cleanup = tokio::spawn(async move {
            let _slot = slot;
            shutdown_fail_fast_session_resources(
                &bridge,
                &mut daemon_output_forwarder,
                &mut outbound_owner,
                &mut inbound_ice_pump,
            )
            .await;
            let _ = quiesced_tx.send(());
            // This gate models the single outer `pc.close().await`: the serve slot remains owned while transport
            // cleanup runs, but every sender that could hold the DataChannel mutex has already been joined.
            let _ = allow_outer_close_rx.await;
        });

        tokio::time::timeout(Duration::from_secs(1), quiesced_rx)
            .await
            .expect("fail-fast cleanup must quiesce all producers promptly")
            .expect("cleanup task must report its ordering checkpoint");
        assert!(
            output_dropped.load(Ordering::Acquire)
                && outbound_dropped.load(Ordering::Acquire)
                && ice_dropped.load(Ordering::Acquire),
            "all output/ICE owners must be stopped before the outer PeerConnection close"
        );
        assert_eq!(
            serving.load(Ordering::Acquire),
            1,
            "the serve slot must remain owned until the outer PeerConnection close finishes"
        );

        let _ = allow_outer_close_tx.send(());
        tokio::time::timeout(Duration::from_secs(1), cleanup)
            .await
            .expect("the completed outer close must release the serve owner")
            .expect("cleanup task must not panic");
        assert_eq!(serving.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn graceful_drain_allows_one_initial_rto_plus_ack_margin() {
        assert_eq!(PINNED_SCTP_INITIAL_RTO, Duration::from_secs(3));
        assert!(
            GRACEFUL_CLOSE_DRAIN_TIMEOUT > PINNED_SCTP_INITIAL_RTO,
            "the production bound must permit at least one pinned-SCTP retransmission"
        );

        // Exercise the same injected-duration logic at 100:1 scale: the acknowledgement lands after the modeled
        // initial RTO but before the modeled production margin. This keeps the suite fast while proving the drain
        // does not retain the old two-second-before-three-second ordering bug.
        let modeled_rto = Duration::from_millis(30);
        let modeled_ack = Duration::from_millis(35);
        let modeled_drain_bound = Duration::from_millis(50);
        assert!(modeled_ack > modeled_rto && modeled_drain_bound > modeled_ack);

        let dc = Arc::new(AckControlledDataChannel::new());
        dc.send_text_frame(r#"{"type":"bye"}"#.to_string())
            .await
            .expect("fixture must accept the final local write");
        let (wake, mut graceful_drain) = buffered_amount_low_channel();
        let dc_for_ack = dc.clone();
        let ack_task = tokio::spawn(async move {
            tokio::time::sleep(modeled_ack).await;
            dc_for_ack.acknowledge_pending();
            let _ = wake.signal();
        });

        let outcome = drain_and_close_data_channel(
            dc.as_ref(),
            &mut graceful_drain,
            modeled_drain_bound,
            Duration::from_millis(20),
        )
        .await;
        ack_task.await.expect("delayed ack fixture must finish");
        assert_eq!(
            outcome,
            super::GracefulCloseOutcome {
                drained: true,
                close_returned: true,
            }
        );
        assert_eq!(
            dc.delivered(),
            vec![RecordedFrame::Text(r#"{"type":"bye"}"#.to_string())]
        );
    }

    async fn wait_for_amount_reads(dc: &FakeBufferedDataChannel, expected: usize) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while dc.amount_reads.load(Ordering::Relaxed) < expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("buffer amount reads must reach the expected count");
    }

    fn terminal_target(
        channel: u16,
        encoding: crate::remote_bridge::TerminalEncoding,
    ) -> TerminalOutputTarget {
        TerminalOutputTarget {
            channel,
            encoding,
            generation: u64::from(channel),
        }
    }

    fn enqueue_legacy(
        arbiter: &mut TerminalOutputArbiter,
        session_id: &str,
        channel: u16,
        bytes: usize,
        fill: char,
    ) {
        arbiter
            .enqueue(
                session_id.to_string(),
                terminal_target(channel, crate::remote_bridge::TerminalEncoding::Legacy),
                std::iter::repeat_n(fill, bytes).collect(),
            )
            .expect("legacy fixture must fit the arbiter");
    }

    fn commit_next_arbiter_chunk(
        arbiter: &mut TerminalOutputArbiter,
        active_session: Option<&str>,
    ) -> (crate::remote_frame::FrameKind, u16, Vec<u8>) {
        let chunk = arbiter
            .next_chunk(active_session)
            .expect("chunk encoding must succeed")
            .expect("a ready fixture must produce one chunk");
        let frame = crate::remote_frame::decode(&chunk.frame)
            .expect("arbiter output must be a canonical remote frame");
        let recorded = (frame.kind, frame.channel, frame.payload.to_vec());
        arbiter
            .commit_chunk(chunk)
            .expect("the selected chunk must commit");
        recorded
    }

    #[test]
    fn terminal_event_log_label_accepts_only_daemon_event_names() {
        let allowed = [
            "daemon_info",
            "terminal_bell",
            "terminal_title",
            "terminal_clipboard_store",
            "output",
            "grid",
            "scrollback_rows",
            "damage",
            "session_exited",
            "resync_required",
            "sessions",
            "channel",
            "error",
        ];
        for event in allowed {
            let line = format!(r#"{{"ev":"{event}","id":"fixture"}}"#);
            assert_eq!(terminal_event_log_label(&line), event, "event={event}");
        }

        for event in ["Grid", "some_future_event", "user-controlled-label"] {
            let line = format!(r#"{{"ev":"{event}"}}"#);
            assert_eq!(terminal_event_log_label(&line), "unknown", "event={event}");
        }
    }

    #[test]
    fn terminal_event_log_label_supports_bounded_json_order_and_whitespace() {
        let cases = [
            (r#" { "ev" : "grid" } "#, "grid"),
            (r#"{"id":"s1", "ev" : "output", "data":""}"#, "output"),
            (
                r#"{"metadata":{"nested":[1,true,null]},"ev":"damage","id":"s1"}"#,
                "damage",
            ),
            (
                r#"{"note":"embedded \"ev\":\"grid\" text","ev":"resync_required"}"#,
                "resync_required",
            ),
        ];
        for (line, expected) in cases {
            assert_eq!(terminal_event_log_label(line), expected, "line={line}");
        }
    }

    #[test]
    fn terminal_event_log_label_handles_escaped_json_strings_semantically() {
        assert_eq!(
            terminal_event_log_label(r#"{"\u0065v":"gr\u0069d"}"#),
            "grid"
        );
        assert_eq!(
            terminal_event_log_label(r#"{"ev":"gr\\id"}"#),
            "unknown",
            "a decoded backslash is not an allowlisted event name"
        );
        assert_eq!(
            terminal_event_log_label(r#"{"text":"\"ev\":\"damage\""}"#),
            "unknown",
            "an event-shaped substring inside a JSON string is not a top-level tag"
        );
    }

    #[test]
    fn terminal_event_log_label_is_bounded_for_huge_and_malicious_prefixes() {
        let huge_payload = "x".repeat(TERMINAL_EVENT_PREFIX_LIMIT * 2048);
        let canonical = format!(r#"{{"ev":"grid","id":"s1","grid":{{"cells":"{huge_payload}"}}}}"#);
        assert_eq!(
            terminal_event_log_label(&canonical),
            "grid",
            "the canonical first-member tag must not require parsing the huge payload"
        );

        let reordered = format!(r#"{{"padding":"{huge_payload}","ev":"grid"}}"#);
        assert_eq!(
            terminal_event_log_label(&reordered),
            "unknown",
            "large non-canonical input must not trigger an unbounded search"
        );

        let nested_decoy =
            format!(r#"{{"payload":{{"ev":"damage","padding":"{huge_payload}"}},"ev":"output"}}"#);
        assert_eq!(
            terminal_event_log_label(&nested_decoy),
            "unknown",
            "a nested decoy before a far-away top-level tag must not be misclassified"
        );

        let oversized_event = format!(r#"{{"ev":"{huge_payload}","id":"s1"}}"#);
        assert_eq!(terminal_event_log_label(&oversized_event), "unknown");

        let duplicate = format!(r#"{{"ev":"grid","ev":"damage","padding":"{huge_payload}"}}"#);
        assert_eq!(
            terminal_event_log_label(&duplicate),
            "unknown",
            "the large canonical path must reject a duplicated tag in the bounded envelope"
        );

        let wrong_envelope = format!(r#"{{"ev":"grid","frame":{{"padding":"{huge_payload}"}}}}"#);
        assert_eq!(
            terminal_event_log_label(&wrong_envelope),
            "unknown",
            "an allowlisted tag with another event's envelope must not be mislabeled"
        );
    }

    #[test]
    fn terminal_event_log_label_rejects_missing_duplicate_and_wrong_type_tags() {
        let unknown = [
            "{}",
            r#"{"event":"grid"}"#,
            r#"{"payload":{"ev":"grid"}}"#,
            r#"{"ev":"grid","ev":"grid"}"#,
            r#"{"ev":"grid","ev":"damage"}"#,
            r#"{"ev":null}"#,
            r#"{"ev":true}"#,
            r#"{"ev":7}"#,
            r#"{"ev":["grid"]}"#,
            r#"{"ev":{"name":"grid"}}"#,
        ];
        for line in unknown {
            assert_eq!(terminal_event_log_label(line), "unknown", "line={line}");
        }
    }

    #[test]
    fn terminal_event_log_label_preserves_legacy_unknown_fallback() {
        for line in ["", "plain terminal output", "output", "[]", "null"] {
            assert_eq!(terminal_event_log_label(line), "unknown", "line={line}");
        }
    }

    #[test]
    fn active_pane_overtakes_an_unfinished_background_event_after_one_chunk() {
        let mut arbiter = TerminalOutputArbiter::with_limits(8, 256 * 1024, 8);
        enqueue_legacy(
            &mut arbiter,
            "background",
            1,
            OUTPUT_CHUNK_BYTES * 2 + 1,
            'b',
        );

        let (_, first_channel, first_payload) = commit_next_arbiter_chunk(&mut arbiter, None);
        assert_eq!(first_channel, 1);
        assert_eq!(first_payload[0], 0, "the background event is unfinished");

        enqueue_legacy(&mut arbiter, "active", 2, 1, 'a');
        let (_, promoted_channel, promoted_payload) =
            commit_next_arbiter_chunk(&mut arbiter, Some("active"));
        assert_eq!(promoted_channel, 2);
        assert_eq!(&promoted_payload[1..], b"a");

        let (_, resumed_channel, resumed_payload) =
            commit_next_arbiter_chunk(&mut arbiter, Some("active"));
        assert_eq!(resumed_channel, 1);
        assert_eq!(resumed_payload[0], 0);
    }

    #[test]
    fn same_pane_fifo_never_changes_while_siblings_interleave() {
        let mut arbiter = TerminalOutputArbiter::with_limits(8, 256 * 1024, 1);
        enqueue_legacy(&mut arbiter, "active", 1, OUTPUT_CHUNK_BYTES + 1, 'a');
        enqueue_legacy(&mut arbiter, "active", 1, 1, 'z');
        enqueue_legacy(&mut arbiter, "sibling", 2, 1, 's');

        let mut channels = Vec::new();
        let mut active_events = Vec::new();
        let mut active_partial = Vec::new();
        while !arbiter.is_empty() {
            let (_, channel, payload) = commit_next_arbiter_chunk(&mut arbiter, Some("active"));
            channels.push(channel);
            if channel == 1 {
                active_partial.extend_from_slice(&payload[1..]);
                if payload[0] == 1 {
                    active_events.push(std::mem::take(&mut active_partial));
                }
            }
        }

        assert_eq!(channels, vec![1, 2, 1, 1]);
        assert_eq!(
            active_events,
            vec![vec![b'a'; OUTPUT_CHUNK_BYTES + 1], vec![b'z']],
            "a later event on the active pane cannot pass its unfinished predecessor"
        );
    }

    #[test]
    fn active_burst_has_a_hard_sibling_starvation_bound() {
        let burst = ACTIVE_PANE_BURST_CHUNKS;
        let mut arbiter = TerminalOutputArbiter::with_limits(8, 1024 * 1024, burst);
        enqueue_legacy(
            &mut arbiter,
            "active",
            1,
            OUTPUT_CHUNK_BYTES * burst * 2,
            'a',
        );
        enqueue_legacy(&mut arbiter, "sibling", 2, OUTPUT_CHUNK_BYTES * 2, 's');

        let channels: Vec<u16> = (0..(burst + 1) * 2)
            .map(|_| commit_next_arbiter_chunk(&mut arbiter, Some("active")).1)
            .collect();
        let mut expected = Vec::new();
        for _ in 0..2 {
            expected.extend(std::iter::repeat_n(1, burst));
            expected.push(2);
        }
        assert_eq!(channels, expected);
    }

    #[test]
    fn focus_churn_cannot_reset_the_global_sibling_starvation_bound() {
        let mut arbiter = TerminalOutputArbiter::with_limits(8, 256 * 1024, 2);
        for (session_id, channel) in [("a", 1), ("b", 2), ("sibling", 3)] {
            enqueue_legacy(
                &mut arbiter,
                session_id,
                channel,
                OUTPUT_CHUNK_BYTES * 2,
                char::from(b'a' + channel as u8 - 1),
            );
        }

        let channels = [Some("a"), Some("b"), Some("a")]
            .into_iter()
            .map(|active| commit_next_arbiter_chunk(&mut arbiter, active).1)
            .collect::<Vec<_>>();
        assert_eq!(
            channels,
            vec![1, 2, 3],
            "two different priority panes still consume one global burst; the unserved sibling is forced next"
        );
    }

    #[test]
    fn active_ready_output_is_not_blocked_by_background_codec_work() {
        let mut arbiter = TerminalOutputArbiter::with_limits(8, 128 * 1024, 8);
        arbiter
            .enqueue_state(
                "background".into(),
                terminal_target(1, crate::remote_bridge::TerminalEncoding::GzipJsonV1),
                16,
                16,
                "grid",
                TerminalOutputState::Preparing {
                    cancelled: Arc::new(AtomicBool::new(false)),
                },
            )
            .unwrap();
        arbiter
            .enqueue_state(
                "background".into(),
                terminal_target(1, crate::remote_bridge::TerminalEncoding::GzipJsonV1),
                1,
                1,
                "damage",
                TerminalOutputState::Ready {
                    output: PreparedTerminalLine::Legacy(vec![b'l']),
                    offset: 0,
                },
            )
            .unwrap();
        enqueue_legacy(&mut arbiter, "active", 2, 1, 'a');

        let (_, channel, payload) = commit_next_arbiter_chunk(&mut arbiter, Some("active"));
        assert_eq!(channel, 2);
        assert_eq!(&payload[1..], b"a");
        assert!(
            arbiter.next_chunk(Some("active")).unwrap().is_none(),
            "the later background event must remain behind its pane's codec-in-flight head"
        );
    }

    #[tokio::test]
    async fn codec_starts_one_fifo_head_per_pane_without_global_serial_waiting() {
        let mut arbiter = TerminalOutputArbiter::with_limits(8, 128 * 1024, 8);
        let line = "x".repeat(crate::remote_frame::TERMINAL_GZIP_MIN_DECODED_BYTES);
        for (session_id, channel) in [("background", 1), ("background", 1), ("active", 2)] {
            arbiter
                .enqueue(
                    session_id.into(),
                    terminal_target(channel, crate::remote_bridge::TerminalEncoding::GzipJsonV1),
                    line.clone(),
                )
                .unwrap();
        }

        let mut preparations = tokio::task::JoinSet::new();
        arbiter.start_preparations(&mut preparations);
        assert_eq!(
            preparations.len(),
            2,
            "both pane heads start independently while the later same-pane event waits"
        );
        while let Some(joined) = preparations.join_next().await {
            let (ticket, prepared) = joined.unwrap();
            arbiter.finish_preparation(ticket, prepared).unwrap();
        }

        let (_, channel, _) = commit_next_arbiter_chunk(&mut arbiter, Some("active"));
        assert_eq!(
            channel, 2,
            "the prepared viewed pane wins regardless of codec completion order"
        );
        assert!(matches!(
            arbiter
                .panes
                .iter()
                .find(|pane| pane.session_id == "background")
                .and_then(|pane| pane.events.get(1))
                .map(|event| &event.state),
            Some(TerminalOutputState::WaitingForCodec(_))
        ));
    }

    #[test]
    fn forwarder_queue_has_hard_item_and_byte_bounds() {
        let ready = |byte: u8| TerminalOutputState::Ready {
            output: PreparedTerminalLine::Legacy(vec![byte]),
            offset: 0,
        };
        let mut arbiter = TerminalOutputArbiter::with_limits(2, 8, 1);
        arbiter
            .enqueue_state(
                "one".into(),
                terminal_target(1, crate::remote_bridge::TerminalEncoding::Legacy),
                4,
                1,
                "output",
                ready(1),
            )
            .unwrap();
        arbiter
            .enqueue_state(
                "two".into(),
                terminal_target(2, crate::remote_bridge::TerminalEncoding::Legacy),
                4,
                1,
                "output",
                ready(2),
            )
            .unwrap();
        assert_eq!(arbiter.queued_items(), 2);
        assert_eq!(arbiter.queued_bytes(), 8);
        assert_eq!(
            arbiter.enqueue_state(
                "three".into(),
                terminal_target(3, crate::remote_bridge::TerminalEncoding::Legacy),
                1,
                1,
                "output",
                ready(3),
            ),
            Err(OutputSendError::ForwarderQueueFull)
        );
        assert_eq!(arbiter.queued_items(), 2);
        assert_eq!(arbiter.queued_bytes(), 8);

        commit_next_arbiter_chunk(&mut arbiter, None);
        assert_eq!(arbiter.queued_items(), 1);
        assert_eq!(arbiter.queued_bytes(), 4);
        arbiter
            .enqueue_state(
                "three".into(),
                terminal_target(3, crate::remote_bridge::TerminalEncoding::Legacy),
                4,
                1,
                "output",
                ready(3),
            )
            .unwrap();
        assert_eq!(arbiter.queued_items(), 2);
        assert_eq!(arbiter.queued_bytes(), 8);

        let mut oversized = TerminalOutputArbiter::with_limits(2, 8, 1);
        assert_eq!(
            oversized.enqueue_state(
                "one".into(),
                terminal_target(1, crate::remote_bridge::TerminalEncoding::Legacy),
                9,
                1,
                "output",
                ready(1),
            ),
            Err(OutputSendError::QueueItemTooLarge)
        );
        assert!(oversized.is_empty());
    }

    #[test]
    fn stale_attachment_generation_drops_ready_backlog_before_reattach_output() {
        let mut arbiter = TerminalOutputArbiter::with_limits(8, 128, 1);
        let old_target = TerminalOutputTarget {
            channel: 7,
            encoding: crate::remote_bridge::TerminalEncoding::Legacy,
            generation: 1,
        };
        let new_target = TerminalOutputTarget {
            channel: 8,
            encoding: crate::remote_bridge::TerminalEncoding::Legacy,
            generation: 2,
        };
        arbiter
            .enqueue("pane".into(), old_target, "old-one".into())
            .unwrap();
        arbiter
            .enqueue("pane".into(), old_target, "old-two".into())
            .unwrap();

        arbiter.retire_stale_targets(|session_id| {
            assert_eq!(session_id, "pane");
            Some(new_target)
        });
        assert!(arbiter.is_empty());
        assert_eq!(arbiter.queued_items(), 0);
        assert_eq!(arbiter.queued_bytes(), 0);

        arbiter
            .enqueue("pane".into(), new_target, "new".into())
            .unwrap();
        let (_, channel, payload) = commit_next_arbiter_chunk(&mut arbiter, Some("pane"));
        assert_eq!(channel, 8);
        assert_eq!(&payload[1..], b"new");
        assert!(arbiter.is_empty());
    }

    #[test]
    fn upstream_output_keeps_its_ingress_generation_across_reattach() {
        let mut arbiter = TerminalOutputArbiter::with_limits(8, 128, 1);
        let current_target = TerminalOutputTarget {
            channel: 8,
            encoding: crate::remote_bridge::TerminalEncoding::Legacy,
            generation: 2,
        };
        let old = crate::remote_daemon_backend::RoutedDaemonOutput::fixture(
            crate::remote_daemon_backend::DaemonOutput {
                session_id: "pane".into(),
                line: "old".into(),
            },
            crate::remote_daemon_backend::DaemonOutputAttachment::Exact(1),
        );
        enqueue_routed_daemon_output(old, Some(current_target), &mut arbiter).unwrap();
        assert!(
            arbiter.is_empty(),
            "an event stamped before detach cannot be relabelled onto the new target"
        );

        let current = crate::remote_daemon_backend::RoutedDaemonOutput::fixture(
            crate::remote_daemon_backend::DaemonOutput {
                session_id: "pane".into(),
                line: "new".into(),
            },
            crate::remote_daemon_backend::DaemonOutputAttachment::Exact(2),
        );
        enqueue_routed_daemon_output(current, Some(current_target), &mut arbiter).unwrap();
        let (_, channel, payload) = commit_next_arbiter_chunk(&mut arbiter, Some("pane"));
        assert_eq!(channel, 8);
        assert_eq!(&payload[1..], b"new");
    }

    #[test]
    fn unconfirmed_echo_route_fails_closed_while_legacy_route_stays_compatible() {
        let mut arbiter = TerminalOutputArbiter::with_limits(8, 128, 1);
        let target = TerminalOutputTarget {
            channel: 8,
            encoding: crate::remote_bridge::TerminalEncoding::Legacy,
            generation: 2,
        };
        let pending = crate::remote_daemon_backend::RoutedDaemonOutput::fixture(
            crate::remote_daemon_backend::DaemonOutput {
                session_id: "pane".into(),
                line: "pending".into(),
            },
            crate::remote_daemon_backend::DaemonOutputAttachment::Unconfirmed,
        );
        enqueue_routed_daemon_output(pending, Some(target), &mut arbiter).unwrap();
        assert!(
            arbiter.is_empty(),
            "strict pre-baseline output must be dropped"
        );

        let legacy = crate::remote_daemon_backend::RoutedDaemonOutput::fixture(
            crate::remote_daemon_backend::DaemonOutput {
                session_id: "pane".into(),
                line: "legacy".into(),
            },
            crate::remote_daemon_backend::DaemonOutputAttachment::Legacy,
        );
        enqueue_routed_daemon_output(legacy, Some(target), &mut arbiter).unwrap();
        let (_, channel, payload) = commit_next_arbiter_chunk(&mut arbiter, Some("pane"));
        assert_eq!(channel, 8);
        assert_eq!(&payload[1..], b"legacy");
    }

    #[tokio::test]
    async fn stale_codec_head_is_cancelled_charged_until_join_and_never_sends() {
        let mut arbiter = TerminalOutputArbiter::with_limits(8, 256 * 1024, 1);
        let old_target = TerminalOutputTarget {
            channel: 7,
            encoding: crate::remote_bridge::TerminalEncoding::GzipJsonV1,
            generation: 1,
        };
        let ticket = arbiter
            .enqueue("pane".into(), old_target, "x".repeat(128 * 1024))
            .unwrap();
        arbiter
            .enqueue("pane".into(), old_target, "later".into())
            .unwrap();
        let mut preparations = tokio::task::JoinSet::new();
        arbiter.start_preparations(&mut preparations);
        let cancelled = match &arbiter.panes[0].events[0].state {
            TerminalOutputState::Preparing { cancelled } => cancelled.clone(),
            other => panic!("expected a live codec head, got {other:?}"),
        };
        let head_bytes = arbiter.panes[0].events[0].byte_cost;

        arbiter.retire_stale_targets(|_| None);
        assert_eq!(arbiter.queued_items(), 1);
        assert_eq!(arbiter.queued_bytes(), head_bytes);
        assert!(
            cancelled.load(Ordering::Acquire),
            "retiring a stale codec head must actively cancel its worker"
        );
        assert!(arbiter.next_chunk(Some("pane")).unwrap().is_none());

        let (joined_ticket, prepared) = preparations.join_next().await.unwrap().unwrap();
        assert_eq!(joined_ticket, ticket);
        assert_eq!(prepared, Err(OutputSendError::CompressionCancelled));
        arbiter.finish_preparation(ticket, prepared).unwrap();
        assert!(arbiter.is_empty());
        assert_eq!(arbiter.queued_bytes(), 0);
        assert!(arbiter.next_chunk(Some("pane")).unwrap().is_none());
    }

    #[test]
    fn gzip_chunks_remain_indexed_and_same_pane_legacy_stays_behind_them() {
        let mut arbiter = TerminalOutputArbiter::with_limits(8, 256 * 1024, 8);
        let encoded = vec![0x5a; crate::remote_frame::TERMINAL_CODEC_CHUNK_BYTES + 7];
        arbiter
            .enqueue_state(
                "background".into(),
                terminal_target(12, crate::remote_bridge::TerminalEncoding::GzipJsonV1),
                64 * 1024,
                64 * 1024,
                "grid",
                TerminalOutputState::Ready {
                    output: PreparedTerminalLine::Gzip {
                        encoded: encoded.clone(),
                        decoded_len: 64 * 1024,
                    },
                    offset: 0,
                },
            )
            .unwrap();
        arbiter
            .enqueue(
                "background".into(),
                terminal_target(12, crate::remote_bridge::TerminalEncoding::GzipJsonV1),
                "z".into(),
            )
            .unwrap();

        let first = commit_next_arbiter_chunk(&mut arbiter, None);
        enqueue_legacy(&mut arbiter, "active", 13, 1, 'a');
        let promoted = commit_next_arbiter_chunk(&mut arbiter, Some("active"));
        let second = commit_next_arbiter_chunk(&mut arbiter, Some("active"));
        let tail = commit_next_arbiter_chunk(&mut arbiter, Some("active"));

        assert_eq!(
            [first.1, promoted.1, second.1, tail.1],
            [12, 13, 12, 12],
            "only the other pane may interleave with the unfinished gzip event"
        );
        for (index, recorded) in [first, second].iter().enumerate() {
            assert_eq!(
                recorded.0,
                crate::remote_frame::FrameKind::TerminalGzipJsonChunk
            );
            let chunk = crate::remote_frame::decode_terminal_gzip_chunk(&recorded.2)
                .expect("gzip chunk metadata must remain canonical");
            assert_eq!(usize::from(chunk.index), index);
            assert_eq!(chunk.count, 2);
            assert_eq!(chunk.encoded_len as usize, encoded.len());
            assert_eq!(chunk.final_chunk, index == 1);
        }
        assert_eq!(tail.0, crate::remote_frame::FrameKind::TerminalOutputChunk);
        assert_eq!(&tail.2[1..], b"z");
    }

    #[tokio::test]
    async fn output_below_high_water_sends_immediately() {
        let dc = FakeBufferedDataChannel::new(DC_BUFFER_HIGH);
        let (_wake, mut gate) = buffered_amount_low_channel();

        send_binary(&dc, &mut gate, vec![1, 2, 3], Duration::from_secs(1))
            .await
            .expect("a buffer at the high-water mark is still immediately writable");

        assert_eq!(dc.amount_reads.load(Ordering::Relaxed), 1);
        assert_eq!(dc.sends.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn output_waits_for_low_water_callback_without_polling() {
        let dc = Arc::new(FakeBufferedDataChannel::new(DC_BUFFER_HIGH + 1));
        let (wake, mut gate) = buffered_amount_low_channel();
        let dc_for_send = dc.clone();
        let send = tokio::spawn(async move {
            send_binary(
                dc_for_send.as_ref(),
                &mut gate,
                vec![4, 5, 6],
                Duration::from_secs(1),
            )
            .await
        });

        wait_for_amount_reads(&dc, 2).await;
        let reads_while_blocked = dc.amount_reads.load(Ordering::Relaxed);
        for _ in 0..32 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            dc.amount_reads.load(Ordering::Relaxed),
            reads_while_blocked,
            "the blocked sender must sleep on the callback channel, not poll buffered_amount"
        );
        assert_eq!(dc.sends.load(Ordering::Relaxed), 0);

        dc.current_amount.store(DC_BUFFER_LOW, Ordering::Relaxed);
        assert!(wake.signal());
        send.await
            .expect("sender task must join")
            .expect("low-water callback must release the sender");
        assert_eq!(dc.sends.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn buffered_low_signal_is_missed_wake_safe() {
        // Advance the generation before wait_before_send reaches changed(). The watch channel must retain it. The scripted
        // reads keep the first two observations above LOW, then expose the completed drain after that stored edge.
        let dc = FakeBufferedDataChannel::with_amount_script([
            DC_BUFFER_HIGH + 1,
            DC_BUFFER_HIGH + 1,
            DC_BUFFER_LOW,
        ]);
        let (wake, mut gate) = buffered_amount_low_channel();
        assert!(wake.signal());

        send_binary(&dc, &mut gate, vec![7], Duration::from_secs(1))
            .await
            .expect("a callback racing before recv must not be lost");

        assert_eq!(dc.amount_reads.load(Ordering::Relaxed), 3);
        assert_eq!(dc.sends.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn stale_low_edge_cannot_coalesce_a_real_edge_before_rebound() {
        let dc = Arc::new(FakeBufferedDataChannel::new(DC_BUFFER_HIGH + 1));
        let (wake, mut gate) = buffered_amount_low_channel();

        // An unread stale edge exists. The real low crossing must still advance the generation before an unrelated
        // control send raises the shared SCTP buffer again.
        assert!(wake.signal());
        dc.current_amount.store(DC_BUFFER_LOW, Ordering::Relaxed);
        assert!(wake.signal());
        assert_eq!(wake.generation(), 2, "the real edge must not coalesce");
        dc.current_amount
            .store(DC_BUFFER_HIGH + 1, Ordering::Relaxed);

        let dc_for_send = dc.clone();
        let send = tokio::spawn(async move {
            send_binary(
                dc_for_send.as_ref(),
                &mut gate,
                vec![9],
                Duration::from_secs(1),
            )
            .await
        });
        wait_for_amount_reads(&dc, 3).await;
        assert_eq!(dc.sends.load(Ordering::Relaxed), 0);

        // The next genuine drain is a third generation and releases the waiting terminal sender.
        dc.current_amount.store(DC_BUFFER_LOW, Ordering::Relaxed);
        assert!(wake.signal());
        send.await
            .expect("sender task must join")
            .expect("the post-rebound low edge must release the sender");
        assert_eq!(wake.generation(), 3);
        assert_eq!(dc.sends.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn stalled_output_backpressure_has_a_bounded_timeout() {
        let dc = FakeBufferedDataChannel::new(DC_BUFFER_HIGH + 1);
        let (_wake, mut gate) = buffered_amount_low_channel();
        let (liveness_tx, mut liveness) = PeerLiveness::channel(Duration::from_secs(5));

        let result = send_output_chunked_and_signal(
            &dc,
            &mut gate,
            8,
            br#"{"ev":"Grid"}"#,
            Duration::from_millis(20),
            &liveness_tx,
        )
        .await;

        assert_eq!(result, Err(OutputSendError::BufferStalled));
        assert_eq!(dc.sends.load(Ordering::Relaxed), 0);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), liveness.wait_until_dead())
                .await
                .expect("a stalled output buffer must wake liveness after the bound"),
            PeerCloseReason::OutboundSenderFailed
        );
    }

    #[tokio::test]
    async fn terminal_output_failure_signals_owner_liveness_teardown() {
        let dc = FakeBufferedDataChannel::new(0);
        dc.fail_send.store(true, Ordering::Relaxed);
        let (_wake, mut gate) = buffered_amount_low_channel();
        let (liveness_tx, mut liveness) = PeerLiveness::channel(Duration::from_secs(5));

        let result = send_output_chunked_and_signal(
            &dc,
            &mut gate,
            9,
            br#"{"ev":"Grid"}"#,
            Duration::from_secs(1),
            &liveness_tx,
        )
        .await;
        assert_eq!(result, Err(OutputSendError::DataChannelClosed));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), liveness.wait_until_dead())
                .await
                .expect("output failure must wake liveness immediately"),
            PeerCloseReason::OutboundSenderFailed
        );
    }

    #[test]
    fn buffered_low_callback_after_owner_drop_is_harmless() {
        let (wake, gate) = buffered_amount_low_channel();
        drop(gate);
        assert!(!wake.signal());
        assert!(!wake.signal());
    }

    #[tokio::test]
    async fn attach_control_reply_precedes_an_already_queued_first_grid() {
        let (liveness_tx, _liveness) = PeerLiveness::channel(Duration::from_secs(1));
        let (scheduler, owner) = outbound_scheduler_channel_with_limits(liveness_tx, 64, 64, 8, 8);

        let terminal = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.send_terminal_binary(vec![7]).await })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            while owner.terminal_rx.len() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the first Grid chunk must be queued for the ordering fixture");
        let control = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.send_control_text("attach_ok".to_string()).await })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            while owner.control_rx.len() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("attach_ok must be queued for the ordering fixture");

        let dc = Arc::new(RecordingDataChannel::new());
        let dc_for_owner = dc.clone();
        let (_wake, gate) = buffered_amount_low_channel();
        let owner_task = tokio::spawn(async move {
            owner
                .run(dc_for_owner.as_ref(), gate, Duration::from_secs(1))
                .await;
        });
        control
            .await
            .expect("control producer must join")
            .expect("attach_ok must send");
        terminal
            .await
            .expect("terminal producer must join")
            .expect("Grid must send");
        drop(scheduler);
        owner_task.await.expect("scheduler owner must join");

        assert_eq!(
            dc.frames(),
            vec![
                RecordedFrame::Text("attach_ok".to_string()),
                RecordedFrame::Binary(vec![7]),
            ],
            "strict control priority preserves attach_ok-before-first-Grid even when both are ready"
        );
    }

    #[tokio::test]
    async fn final_control_barrier_retires_queued_and_future_writes_then_terminates_owner() {
        let (liveness_tx, _liveness) = PeerLiveness::channel(Duration::from_secs(1));
        let (scheduler, owner) = outbound_scheduler_channel_with_limits(liveness_tx, 64, 2, 8, 8);
        let dc = Arc::new(RecordingDataChannel::blocking_first_binary());
        let dc_for_owner = dc.clone();
        let (_wake, gate) = buffered_amount_low_channel();
        let owner_task = tokio::spawn(async move {
            owner
                .run(dc_for_owner.as_ref(), gate, Duration::from_secs(1))
                .await;
        });

        // Hold one native send in progress so both ordinary classes are deterministically queued when the barrier
        // becomes authoritative. That in-flight frame may finish; neither queued frame may follow the final Bye.
        let active = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.send_terminal_binary(vec![1]).await })
        };
        dc.wait_for_first_binary().await;
        let queued_control = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.send_control_text("queued-control".into()).await })
        };
        let queued_terminal = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.send_terminal_binary(vec![2]).await })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            while scheduler.control.tx.capacity() != 7 || scheduler.terminal.tx.capacity() != 7 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both ordinary frames must be queued behind the in-flight send");
        let capacity_waiter = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.send_terminal_binary(vec![3]).await })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if scheduler.terminal.enqueue_order.try_lock().is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("a pre-barrier producer must be waiting on the exhausted byte budget");

        let final_send = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.send_final_control_text("bye".into()).await })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            while !scheduler.admission.is_retired() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the final barrier must establish retirement");
        assert_eq!(
            scheduler.send_control_text("future-control".into()).await,
            Err(OutputSendError::SchedulerRetired),
            "future producers must fail without entering either queue"
        );
        assert_eq!(
            scheduler.send_terminal_binary(vec![4]).await,
            Err(OutputSendError::SchedulerRetired),
            "future terminal output must fail without entering either queue"
        );

        dc.release_first_binary();
        assert_eq!(active.await.expect("active producer must join"), Ok(()));
        assert_eq!(final_send.await.expect("final producer must join"), Ok(()));
        assert_eq!(
            queued_control.await.expect("queued control must join"),
            Err(OutputSendError::SchedulerRetired)
        );
        assert_eq!(
            queued_terminal.await.expect("queued terminal must join"),
            Err(OutputSendError::SchedulerRetired)
        );
        assert!(
            matches!(
                capacity_waiter.await.expect("capacity waiter must join"),
                Err(OutputSendError::QueueClosed | OutputSendError::SchedulerRetired)
            ),
            "a producer already waiting for capacity must be unblocked by retirement"
        );
        tokio::time::timeout(Duration::from_secs(1), owner_task)
            .await
            .expect("the final barrier must terminate the scheduler task")
            .expect("scheduler task must join cleanly");
        assert_eq!(
            dc.frames(),
            vec![
                RecordedFrame::Binary(vec![1]),
                RecordedFrame::Text("bye".into()),
            ],
            "the owner must perform no queued or future wire write after final Bye"
        );
    }

    #[tokio::test]
    async fn terminal_flood_yields_to_control_after_each_chunk() {
        let (liveness_tx, _liveness) = PeerLiveness::channel(Duration::from_secs(1));
        let (scheduler, owner) =
            outbound_scheduler_channel_with_limits(liveness_tx, 64, OUTPUT_CHUNK_BYTES * 2, 8, 8);
        let dc = Arc::new(RecordingDataChannel::blocking_first_binary());
        let dc_for_owner = dc.clone();
        let (_wake, gate) = buffered_amount_low_channel();
        let owner_task = tokio::spawn(async move {
            owner
                .run(dc_for_owner.as_ref(), gate, Duration::from_secs(1))
                .await;
        });

        let terminal_dump = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move {
                schedule_terminal_output_chunked(&scheduler, 7, &vec![b'x'; OUTPUT_CHUNK_BYTES * 2])
                    .await
            })
        };
        dc.wait_for_first_binary().await;
        let control = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.send_control_text("pong".into()).await })
        };
        dc.release_first_binary();

        let stats = terminal_dump
            .await
            .expect("terminal producer must join")
            .expect("terminal dump must send");
        assert_eq!(stats.chunks, 2);
        control
            .await
            .expect("control producer must join")
            .expect("control must send");
        drop(scheduler);
        owner_task.await.expect("scheduler owner must join");

        let frames = dc.frames();
        assert_eq!(frames.len(), 3);
        assert!(matches!(&frames[0], RecordedFrame::Binary(_)));
        assert_eq!(frames[1], RecordedFrame::Text("pong".to_string()));
        assert!(matches!(&frames[2], RecordedFrame::Binary(_)));
        for (index, sent) in [frames[0].clone(), frames[2].clone()].iter().enumerate() {
            let RecordedFrame::Binary(bytes) = sent else {
                unreachable!()
            };
            let frame = crate::remote_frame::decode(bytes).expect("terminal chunk must decode");
            assert_eq!(
                frame.kind,
                crate::remote_frame::FrameKind::TerminalOutputChunk
            );
            assert_eq!(frame.payload[0], if index == 1 { 1 } else { 0 });
        }
    }

    #[tokio::test]
    async fn outbound_queues_are_byte_bounded_and_release_permits() {
        let (liveness_tx, _liveness) = PeerLiveness::channel(Duration::from_secs(1));
        let (scheduler, owner) = outbound_scheduler_channel_with_limits(liveness_tx, 4, 4, 8, 8);
        let first = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.send_control_text("1234".into()).await })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            while owner.control_rx.len() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the first byte-budget fixture must queue");
        assert_eq!(scheduler.control.byte_budget.available_permits(), 0);

        let blocked = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.send_control_text("x".into()).await })
        };
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !blocked.is_finished(),
            "the fifth byte must wait for budget"
        );
        assert_eq!(owner.control_rx.len(), 1, "the count queue still has room");

        let dc = Arc::new(RecordingDataChannel::new());
        let dc_for_owner = dc.clone();
        let (_wake, gate) = buffered_amount_low_channel();
        let owner_task = tokio::spawn(async move {
            owner
                .run(dc_for_owner.as_ref(), gate, Duration::from_secs(1))
                .await;
        });
        first
            .await
            .expect("first producer must join")
            .expect("first bounded frame must send");
        blocked
            .await
            .expect("blocked producer must join")
            .expect("released byte budget must admit the next frame");
        assert_eq!(scheduler.control.byte_budget.available_permits(), 4);

        let oversized = scheduler.send_control_text("12345".into()).await;
        assert_eq!(oversized, Err(OutputSendError::QueueItemTooLarge));
        let empty = scheduler.send_terminal_binary(Vec::new()).await;
        assert_eq!(
            empty,
            Ok(()),
            "zero-byte payloads reserve one permit and cannot deadlock"
        );
        assert_eq!(scheduler.terminal.byte_budget.available_permits(), 4);

        drop(scheduler);
        owner_task.await.expect("scheduler owner must join");
    }

    #[tokio::test]
    async fn dropping_owner_fails_every_waiter_and_releases_all_bytes() {
        let (liveness_tx, _liveness) = PeerLiveness::channel(Duration::from_secs(1));
        let (scheduler, owner) = outbound_scheduler_channel_with_limits(liveness_tx, 4, 4, 8, 8);
        let control = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.send_control_text("1234".into()).await })
        };
        let terminal = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.send_terminal_binary(vec![1, 2, 3, 4]).await })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            while owner.control_rx.len() != 1 || owner.terminal_rx.len() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both owner-drop fixtures must queue");
        assert_eq!(scheduler.control.byte_budget.available_permits(), 0);
        assert_eq!(scheduler.terminal.byte_budget.available_permits(), 0);

        drop(owner);
        assert_eq!(
            control.await.expect("control waiter must join"),
            Err(OutputSendError::QueueClosed)
        );
        assert_eq!(
            terminal.await.expect("terminal waiter must join"),
            Err(OutputSendError::QueueClosed)
        );
        assert_eq!(scheduler.control.byte_budget.available_permits(), 4);
        assert_eq!(scheduler.terminal.byte_budget.available_permits(), 4);
    }

    #[tokio::test]
    async fn scheduler_send_failure_is_owner_fatal_and_unblocks_other_classes() {
        let (liveness_tx, mut liveness) = PeerLiveness::channel(Duration::from_secs(1));
        let (scheduler, owner) = outbound_scheduler_channel_with_limits(liveness_tx, 64, 64, 8, 8);
        let control = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.send_control_text("pong".into()).await })
        };
        let terminal = {
            let scheduler = scheduler.clone();
            tokio::spawn(async move { scheduler.send_terminal_binary(vec![9]).await })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            while owner.control_rx.len() != 1 || owner.terminal_rx.len() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("both failure fixtures must queue");

        let dc = Arc::new(RecordingDataChannel::new());
        dc.fail_send.store(true, Ordering::Relaxed);
        let (_wake, gate) = buffered_amount_low_channel();
        owner.run(dc.as_ref(), gate, Duration::from_secs(1)).await;

        assert_eq!(
            control.await.expect("failed control waiter must join"),
            Err(OutputSendError::DataChannelClosed)
        );
        assert_eq!(
            terminal.await.expect("orphaned terminal waiter must join"),
            Err(OutputSendError::QueueClosed)
        );
        assert_eq!(
            liveness.wait_until_dead().await,
            PeerCloseReason::OutboundSenderFailed
        );
    }

    #[tokio::test]
    async fn terminal_codec_threshold_savings_and_level_one_round_trip_are_exact() {
        use flate2::read::GzDecoder;
        use std::io::Read;

        let small = vec![b'x'; crate::remote_frame::TERMINAL_GZIP_MIN_DECODED_BYTES - 1];
        assert_eq!(
            prepare_terminal_line(small.clone()).await.unwrap(),
            PreparedTerminalLine::Legacy(small)
        );

        let compressible =
            br#"{"ev":"grid","cells":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.repeat(512);
        let PreparedTerminalLine::Gzip {
            encoded,
            decoded_len,
        } = prepare_terminal_line(compressible.clone())
            .await
            .expect("compression worker must succeed")
        else {
            panic!("a repeated terminal Grid must clear the savings gate")
        };
        assert_eq!(decoded_len as usize, compressible.len());
        assert!((encoded.len() as u64) * 8 <= (decoded_len as u64) * 7);
        let mut decoded = Vec::new();
        GzDecoder::new(encoded.as_slice())
            .read_to_end(&mut decoded)
            .expect("level-one gzip must round trip");
        assert_eq!(decoded, compressible);

        // Deterministic xorshift bytes do not save 12.5%, so they must stay byte-identical on the legacy path.
        let mut value = 0x9e37_79b9_u32;
        let incompressible: Vec<u8> = (0..8192)
            .map(|_| {
                value ^= value << 13;
                value ^= value >> 17;
                value ^= value << 5;
                value as u8
            })
            .collect();
        assert_eq!(
            prepare_terminal_line(incompressible.clone()).await.unwrap(),
            PreparedTerminalLine::Legacy(incompressible)
        );
    }

    #[test]
    fn terminal_compression_worker_observes_owner_cancellation_before_content_work() {
        let cancelled = Arc::new(AtomicBool::new(true));
        assert_eq!(
            compress_terminal_line_blocking(vec![b'x'; 128 * 1024], cancelled),
            Err(OutputSendError::CompressionCancelled)
        );
    }

    #[test]
    fn terminal_compression_buffer_enforces_the_savings_wire_limit() {
        use std::io::Write;

        // This two-step growth used to trigger Vec's geometric 64 KiB -> 128 KiB reserve even though the declared
        // savings limit was only 100,000 bytes.
        let mut buffer = CappedCompressionBuffer::new(100_000);
        buffer.write_all(&vec![1; 65_000]).unwrap();
        buffer.write_all(&vec![2; 30_000]).unwrap();
        assert_eq!(buffer.bytes.len(), 95_000);
        assert!(buffer.write_all(&vec![3; 5_001]).is_err());
        assert_eq!(buffer.bytes.len(), 95_000);
    }

    #[tokio::test]
    async fn gzip_scheduler_emits_canonical_indexed_chunks_then_legacy_without_reordering() {
        let (liveness_tx, _liveness) = PeerLiveness::channel(Duration::from_secs(1));
        let (scheduler, owner) =
            outbound_scheduler_channel_with_limits(liveness_tx, 64, 128 * 1024, 8, 16);
        let dc = Arc::new(RecordingDataChannel::new());
        let dc_for_owner = dc.clone();
        let (_wake, gate) = buffered_amount_low_channel();
        let owner_task = tokio::spawn(async move {
            owner
                .run(dc_for_owner.as_ref(), gate, Duration::from_secs(1))
                .await;
        });

        let encoded = vec![0x5a; crate::remote_frame::TERMINAL_CODEC_CHUNK_BYTES + 7];
        let stats = schedule_terminal_gzip_chunked(&scheduler, 12, &encoded, 64 * 1024)
            .await
            .expect("canonical gzip chunks must send");
        assert_eq!(stats.chunks, 2);
        schedule_terminal_output_chunked(&scheduler, 12, b"legacy-tail")
            .await
            .expect("legacy tail must send after gzip");
        drop(scheduler);
        owner_task.await.expect("scheduler owner must join");

        let frames = dc.frames();
        assert_eq!(frames.len(), 3);
        let mut reassembled = Vec::new();
        for (index, recorded) in frames[..2].iter().enumerate() {
            let RecordedFrame::Binary(bytes) = recorded else {
                panic!("gzip scheduler emitted text")
            };
            let frame = crate::remote_frame::decode(bytes).expect("outer frame must decode");
            assert_eq!(
                frame.kind,
                crate::remote_frame::FrameKind::TerminalGzipJsonChunk
            );
            assert_eq!(frame.channel, 12);
            let chunk = crate::remote_frame::decode_terminal_gzip_chunk(frame.payload)
                .expect("chunk metadata must be canonical");
            assert_eq!(usize::from(chunk.index), index);
            assert_eq!(chunk.count, 2);
            assert_eq!(chunk.encoded_len as usize, encoded.len());
            assert_eq!(chunk.decoded_len, 64 * 1024);
            assert_eq!(chunk.final_chunk, index == 1);
            reassembled.extend_from_slice(chunk.bytes);
        }
        assert_eq!(reassembled, encoded);
        let RecordedFrame::Binary(tail) = &frames[2] else {
            panic!("legacy tail emitted text")
        };
        assert_eq!(
            crate::remote_frame::decode(tail).unwrap().kind,
            crate::remote_frame::FrameKind::TerminalOutputChunk,
            "one ordered scheduler channel cannot let the later legacy event overtake gzip"
        );
    }

    #[tokio::test]
    async fn terminal_scheduler_never_queues_more_than_one_wire_chunk_per_item() {
        let (liveness_tx, _liveness) = PeerLiveness::channel(Duration::from_secs(1));
        let (scheduler, owner) =
            outbound_scheduler_channel_with_limits(liveness_tx, 64, OUTPUT_CHUNK_BYTES * 2, 8, 8);
        let dc = Arc::new(RecordingDataChannel::new());
        let dc_for_owner = dc.clone();
        let (_wake, gate) = buffered_amount_low_channel();
        let owner_task = tokio::spawn(async move {
            owner
                .run(dc_for_owner.as_ref(), gate, Duration::from_secs(1))
                .await;
        });

        let stats = schedule_terminal_output_chunked(
            &scheduler,
            11,
            &vec![b'x'; OUTPUT_CHUNK_BYTES * 2 + 1],
        )
        .await
        .expect("bounded terminal chunks must send");
        assert_eq!(stats.chunks, 3);
        let frames = dc.frames();
        assert_eq!(frames.len(), 3);
        for (index, sent) in frames.iter().enumerate() {
            let RecordedFrame::Binary(bytes) = sent else {
                panic!("terminal scheduler emitted a text frame")
            };
            let frame = crate::remote_frame::decode(bytes).expect("wire chunk must decode");
            assert_eq!(
                frame.kind,
                crate::remote_frame::FrameKind::TerminalOutputChunk
            );
            assert!(frame.payload.len() <= OUTPUT_CHUNK_BYTES + 1);
            assert_eq!(frame.payload[0], if index == 2 { 1 } else { 0 });
        }

        drop(scheduler);
        owner_task.await.expect("scheduler owner must join");
    }

    fn test_answer() -> RTCSessionDescription {
        let mut answer = RTCSessionDescription::default();
        answer.sdp_type = RTCSdpType::Answer;
        answer.sdp = "v=0\r\na=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n".into();
        answer
    }

    async fn new_loopback_peer_pair() -> (
        Arc<RTCPeerConnection>,
        Arc<RTCPeerConnection>,
        Arc<tokio::sync::Mutex<webrtc::util::vnet::router::Router>>,
    ) {
        use webrtc::util::vnet::net::{Net, NetConfig};
        use webrtc::util::vnet::router::{Router, RouterConfig};

        let router = Arc::new(tokio::sync::Mutex::new(
            Router::new(RouterConfig {
                cidr: "192.0.2.0/24".to_owned(),
                ..Default::default()
            })
            .expect("loopback virtual router must be created"),
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
            let nic = network
                .get_nic()
                .expect("loopback virtual interface must exist");
            router
                .lock()
                .await
                .add_net(Arc::clone(&nic))
                .await
                .expect("loopback virtual interface must join the router");
            nic.lock()
                .await
                .set_router(Arc::clone(&router))
                .await
                .expect("loopback virtual interface must bind the router");
        }
        router
            .lock()
            .await
            .start()
            .await
            .expect("loopback virtual router must start");

        let mut client_settings = SettingEngine::default();
        client_settings.set_vnet(Some(client_net));
        let client_api = APIBuilder::new()
            .with_setting_engine(client_settings)
            .build();
        let client = Arc::new(
            client_api
                .new_peer_connection(RTCConfiguration::default())
                .await
                .expect("loopback client peer creation must succeed"),
        );

        let mut agent_settings = SettingEngine::default();
        agent_settings.set_vnet(Some(agent_net));
        let agent_api = APIBuilder::new()
            .with_setting_engine(agent_settings)
            .build();
        let agent = Arc::new(
            agent_api
                .new_peer_connection(RTCConfiguration::default())
                .await
                .expect("loopback agent peer creation must succeed"),
        );
        (client, agent, router)
    }

    enum LoopbackIceEvent {
        Candidate(RTCIceCandidateInit),
        Complete,
    }

    fn capture_loopback_ice(
        source: &Arc<RTCPeerConnection>,
    ) -> tokio::sync::mpsc::UnboundedReceiver<LoopbackIceEvent> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        source.on_ice_candidate(Box::new(move |candidate| {
            let tx = tx.clone();
            Box::pin(async move {
                let event = match candidate {
                    Some(candidate) => LoopbackIceEvent::Candidate(
                        candidate
                            .to_json()
                            .expect("loopback ICE candidate must serialize"),
                    ),
                    None => LoopbackIceEvent::Complete,
                };
                tx.send(event)
                    .expect("loopback ICE capture must remain live");
            })
        }));
        rx
    }

    async fn collect_loopback_ice(
        receiver: &mut tokio::sync::mpsc::UnboundedReceiver<LoopbackIceEvent>,
    ) -> Vec<RTCIceCandidateInit> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut candidates = Vec::new();
            loop {
                match receiver
                    .recv()
                    .await
                    .expect("loopback ICE capture must remain live")
                {
                    LoopbackIceEvent::Candidate(candidate) => candidates.push(candidate),
                    LoopbackIceEvent::Complete => return candidates,
                }
            }
        })
        .await
        .expect("loopback ICE gathering must complete")
    }

    async fn handshake_loopback_peers(
        offerer: &Arc<RTCPeerConnection>,
        answerer: &Arc<RTCPeerConnection>,
        offerer_ice: &mut tokio::sync::mpsc::UnboundedReceiver<LoopbackIceEvent>,
        answerer_ice: &mut tokio::sync::mpsc::UnboundedReceiver<LoopbackIceEvent>,
    ) {
        let offer = offerer
            .create_offer(None)
            .await
            .expect("loopback offer must be created");
        offerer
            .set_local_description(offer.clone())
            .await
            .expect("loopback offer must be installed locally");
        let offerer_candidates = collect_loopback_ice(offerer_ice).await;
        answerer
            .set_remote_description(offer)
            .await
            .expect("loopback offer must be installed remotely");
        for candidate in offerer_candidates {
            answerer
                .add_ice_candidate(candidate)
                .await
                .expect("captured offerer ICE candidate must be installed");
        }
        answerer
            .add_ice_candidate(RTCIceCandidateInit::default())
            .await
            .expect("offerer end-of-candidates must be installed");
        let answer = answerer
            .create_answer(None)
            .await
            .expect("loopback answer must be created");
        answerer
            .set_local_description(answer.clone())
            .await
            .expect("loopback answer must be installed locally");
        let answerer_candidates = collect_loopback_ice(answerer_ice).await;
        offerer
            .set_remote_description(answer)
            .await
            .expect("loopback answer must be installed remotely");
        for candidate in answerer_candidates {
            offerer
                .add_ice_candidate(candidate)
                .await
                .expect("captured answerer ICE candidate must be installed");
        }
        offerer
            .add_ice_candidate(RTCIceCandidateInit::default())
            .await
            .expect("answerer end-of-candidates must be installed");
    }

    async fn wait_for_connected_loopback_peer(pc: &Arc<RTCPeerConnection>) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let peer_connected = pc.connection_state() == RTCPeerConnectionState::Connected;
                let ice_connected = matches!(
                    pc.ice_connection_state(),
                    RTCIceConnectionState::Connected | RTCIceConnectionState::Completed
                );
                if peer_connected && ice_connected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("loopback PC and ICE must connect");
    }

    #[tokio::test]
    async fn loopback_ice_capture_retains_early_candidates_until_installation() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        tx.send(LoopbackIceEvent::Candidate(RTCIceCandidateInit {
            candidate: "candidate:early".into(),
            ..Default::default()
        }))
        .unwrap();
        tx.send(LoopbackIceEvent::Complete).unwrap();

        let captured = collect_loopback_ice(&mut rx).await;
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].candidate, "candidate:early");
    }

    #[test]
    fn signed_answer_json_embeds_device_signed_fingerprint_proof() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let json = signed_answer_json(&test_answer(), "sig_1", "dev_desk", Some(&key)).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let proof = &v["hydra_answer_proof"];
        assert_eq!(proof["version"], 1);
        assert_eq!(proof["device_id"], "dev_desk");
        assert_eq!(proof["signal_session_id"], "sig_1");
        assert_eq!(
            proof["fingerprint"],
            "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99"
        );
        assert!(proof["signature"].as_str().unwrap().len() > 40);
    }

    #[test]
    fn unsigned_answer_json_keeps_legacy_shape_when_no_device_key() {
        let json = signed_answer_json(&test_answer(), "sig_1", "dev_desk", None).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("hydra_answer_proof").is_none());
    }

    #[test]
    fn workspace_update_ack_parses_and_other_messages_do_not() {
        // The ack the (Slice-4) browser sends after RECEIVING a push.
        let epoch = match serde_json::from_str::<ConnectionMsg>(
            r#"{"type":"workspace_update_ack","epoch":7}"#,
        )
        .expect("ack must parse")
        {
            ConnectionMsg::WorkspaceUpdateAck { epoch } => epoch,
            #[cfg(feature = "remote-diagnostics")]
            _ => panic!("parsed as the wrong ConnectionMsg variant"),
        };
        assert_eq!(epoch, 7);
        // Terminal/control ops must NOT be swallowed by the connection-level interceptor.
        assert!(serde_json::from_str::<ConnectionMsg>(
            r#"{"type":"session_list","request_id":"r1"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ConnectionMsg>(r#"{"type":"auth","token":"t"}"#).is_err());
        // A malformed ack (no epoch) must not parse either — it falls through to the error path.
        assert!(
            serde_json::from_str::<ConnectionMsg>(r#"{"type":"workspace_update_ack"}"#).is_err()
        );

        let diagnostic_requests = [
            r#"{"type":"db_write_trace","request_id":"ledger","count":100}"#,
            r#"{"type":"debug_sync_snapshot","request_id":"snapshot"}"#,
        ];
        #[cfg(not(feature = "remote-diagnostics"))]
        for request in diagnostic_requests {
            assert!(
                serde_json::from_str::<ConnectionMsg>(request).is_err(),
                "shipping builds must not recognize inspector RPCs: {request}"
            );
        }
        #[cfg(feature = "remote-diagnostics")]
        for request in diagnostic_requests {
            assert!(
                serde_json::from_str::<ConnectionMsg>(request).is_ok(),
                "explicit diagnostics builds retain the QA RPC: {request}"
            );
        }
    }

    #[test]
    fn push_retry_policy_resends_only_unacked_timed_out_with_retries_left() {
        use PushRetryAction::*;
        // Fully acked → never retry, timed out or not.
        assert_eq!(push_retry_action(3, 3, true, 0), None);
        assert_eq!(push_retry_action(3, 5, true, 0), None); // ack ahead (reconnect edge) → quiet
                                                            // Unacked but not timed out (or nothing in flight) → wait.
        assert_eq!(push_retry_action(3, 2, false, 0), None);
        // Unacked + timed out + retries left → re-send the same epoch.
        assert_eq!(push_retry_action(3, 2, true, 0), Resend);
        assert_eq!(push_retry_action(3, 2, true, MAX_PUSH_RETRIES - 1), Resend);
        // Retries exhausted → give up (stop the clock); the next store change converges.
        assert_eq!(push_retry_action(3, 2, true, MAX_PUSH_RETRIES), GiveUp);
        // Nothing ever pushed → nothing to do.
        assert_eq!(push_retry_action(0, 0, false, 0), None);
    }

    #[test]
    fn live_sync_evaluates_on_store_commits_and_on_session_polls_only_after_baseline() {
        // Store commits and session-liveness ticks both wait for the initial session_list baseline; otherwise a
        // pre-list push can be overwritten by the stale list reply that follows it.
        assert!(!live_sync_should_eval(&LiveSyncWake::Store, false));
        assert!(live_sync_should_eval(&LiveSyncWake::Store, true));
        assert!(live_sync_should_eval(&LiveSyncWake::SessionPoll, true));
        assert!(!live_sync_should_eval(&LiveSyncWake::SessionPoll, false));
        // Watcher closed (shutdown) → never evaluate.
        assert!(!live_sync_should_eval(&LiveSyncWake::Closed, true));
        assert!(!live_sync_should_eval(&LiveSyncWake::Closed, false));
    }

    #[derive(Default)]
    struct RetainedInputState {
        inputs: Vec<Vec<u8>>,
        detaches: usize,
    }

    #[derive(Clone)]
    struct RetainedInputBackend(Arc<Mutex<RetainedInputState>>);

    impl crate::remote_bridge::SessionBackend for RetainedInputBackend {
        fn list_sessions(&self) -> Vec<String> {
            vec!["retained-session".to_string()]
        }

        fn attach(
            &mut self,
            _session_id: &str,
            _cols: u16,
            _rows: u16,
            _raw: bool,
        ) -> Result<(), String> {
            Ok(())
        }

        fn attach_with_output_generation(
            &mut self,
            session_id: &str,
            cols: u16,
            rows: u16,
            raw: bool,
            _output_generation: u64,
            _deferred_resize_authority: Option<crate::winsize_owner::DeferredResizeAuthority>,
        ) -> Result<(), String> {
            // This input-authority fixture has no asynchronous Grid route. Opt it into the
            // successful attach its tests model instead of inheriting the production-safe default.
            self.attach(session_id, cols, rows, raw)
        }

        fn input(&mut self, _session_id: &str, bytes: &[u8]) -> Result<(), String> {
            self.0.lock().unwrap().inputs.push(bytes.to_vec());
            Ok(())
        }

        fn resize(&mut self, _session_id: &str, _cols: u16, _rows: u16) -> Result<(), String> {
            Ok(())
        }

        fn scrollback(
            &mut self,
            _session_id: &str,
            _offset_from_top: u32,
            _count: u16,
        ) -> Result<(), String> {
            Ok(())
        }

        fn detach(&mut self, _session_id: &str) {
            self.0.lock().unwrap().detaches += 1;
        }
    }

    type RetainedInputBridge = crate::remote_bridge::TerminalBridge<
        RetainedInputBackend,
        crate::remote_policy::SameAsLocalPolicy,
    >;

    type RetainedInputBridgeFixture = (
        Arc<Mutex<RetainedInputState>>,
        Arc<tokio::sync::Mutex<Option<RetainedInputBridge>>>,
        u16,
    );

    fn retained_input_bridge() -> RetainedInputBridgeFixture {
        use crate::remote_bridge::{TerminalMsg, TerminalReply};

        let state = Arc::new(Mutex::new(RetainedInputState::default()));
        let claims = crate::remote_token::TokenClaims {
            account_id: "account-a".to_string(),
            device_id: "browser-a".to_string(),
            iat_ms: 10,
            exp_ms: 1_000,
            ..crate::remote_token::TokenClaims::default()
        };
        let mut terminal = RetainedInputBridge::new(
            RetainedInputBackend(state.clone()),
            crate::remote_policy::SameAsLocalPolicy,
            claims,
        );
        let channel = match terminal
            .handle(TerminalMsg::AttachSession {
                request_id: "attach".to_string(),
                session_id: "retained-session".to_string(),
                cols: 80,
                rows: 24,
                raw: false,
                viewed: true,
            })
            .into_iter()
            .next()
        {
            Some(crate::remote_bridge::Outbound::Json(TerminalReply::AttachOk {
                channel, ..
            })) => channel,
            other => panic!("expected attach, got {other:?}"),
        };
        (
            state,
            Arc::new(tokio::sync::Mutex::new(Some(terminal))),
            channel,
        )
    }

    #[test]
    fn revoke_gate_is_route_agnostic_after_ice_selection() {
        // ICE route selection is intentionally absent from the post-auth owner loop. These labels prove the
        // shared gate has no route branch; physical Direct/Relay qualification remains a separate acceptance gate.
        for route in ["direct", "relay"] {
            assert!(!should_close_for_revoke(false, false), "{route}");
            assert!(!should_close_for_revoke(false, true), "{route}");
            assert!(!should_close_for_revoke(true, true), "{route}");
            assert!(should_close_for_revoke(true, false), "{route}");
        }
    }

    #[test]
    fn binary_input_authority_gate_rechecks_exact_deadline_and_live_revocation() {
        let revoked = Arc::new(AtomicBool::new(false));
        let revoked_for_gate = revoked.clone();
        let gate = ConnectionAuthorityGate::new(
            "browser-a".to_string(),
            move |_account, browser, _iat| {
                browser == "browser-a" && revoked_for_gate.load(Ordering::Acquire)
            },
        );
        gate.replace(Some(
            crate::remote_control::AuthenticatedAuthoritySnapshot {
                account_id: "account-a".to_string(),
                revocation_iat_ms: 10,
                expires_at_ms: 100,
            },
        ));

        assert!(gate.permits_at(99));
        assert!(!gate.permits_at(100), "the exact expiry millisecond denies");

        gate.replace(Some(
            crate::remote_control::AuthenticatedAuthoritySnapshot {
                account_id: "account-a".to_string(),
                revocation_iat_ms: 10,
                expires_at_ms: 1_000,
            },
        ));
        revoked.store(true, Ordering::Release);
        assert_eq!(gate.observe_revocation_at(101), Some(false));
        assert!(
            !gate.permits_at(101),
            "a delivered live-revocation snapshot denies without control-loop progress"
        );
        assert!(gate.claim_end_event());
        assert!(
            !gate.claim_end_event(),
            "rejected-input floods cannot grow the owner liveness queue"
        );
        gate.clear();
        revoked.store(false, Ordering::Release);
        assert!(!gate.permits_at(1), "missing authority fails closed");
    }

    #[tokio::test(start_paused = true)]
    async fn authority_watchdog_observes_revocation_without_control_loop_progress() {
        let revoked = Arc::new(AtomicBool::new(false));
        let revoked_for_gate = revoked.clone();
        let gate = ConnectionAuthorityGate::new("browser-a".to_string(), move |_, _, _| {
            revoked_for_gate.load(Ordering::Acquire)
        });
        gate.replace(Some(
            crate::remote_control::AuthenticatedAuthoritySnapshot {
                account_id: "account-a".to_string(),
                revocation_iat_ms: 10,
                expires_at_ms: u64::MAX,
            },
        ));
        let (liveness_tx, mut liveness) = PeerLiveness::channel(Duration::from_secs(1));
        let watcher = tokio::spawn(run_connection_authority_watchdog(gate.clone(), liveness_tx));
        tokio::task::yield_now().await;
        assert!(gate.permits_at(1));

        revoked.store(true, Ordering::Release);
        tokio::time::advance(REVOKE_CHECK_INTERVAL).await;
        assert_eq!(
            liveness.wait_until_dead().await,
            PeerCloseReason::AuthorityEnded
        );
        assert!(!gate.permits_at(1));
        watcher
            .await
            .expect("watchdog must stop after authority ends");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn observed_deny_precedes_writer_wait_and_reader_flood_fails_closed() {
        let (state, bridge, channel) = retained_input_bridge();
        let live_revoked = Arc::new(AtomicBool::new(false));
        let live_revoked_for_gate = live_revoked.clone();
        let gate = ConnectionAuthorityGate::new("browser-a".to_string(), move |_, _, _| {
            live_revoked_for_gate.load(Ordering::Acquire)
        });
        gate.replace(Some(
            crate::remote_control::AuthenticatedAuthoritySnapshot {
                account_id: "account-a".to_string(),
                revocation_iat_ms: 10,
                expires_at_ms: 1_000,
            },
        ));

        // Hold one already-admitted synchronous enqueue at the authority read side. Cleanup must
        // wait for this operation, but publishing deny must not wait with it.
        let (permit_entered_tx, permit_entered_rx) = tokio::sync::oneshot::channel();
        let (release_permit_tx, release_permit_rx) = std::sync::mpsc::channel();
        let held_gate = gate.clone();
        let held_reader = tokio::task::spawn_blocking(move || {
            held_gate.with_permit_at(1, || {
                permit_entered_tx
                    .send(())
                    .expect("test must observe the held authority permit");
                release_permit_rx
                    .recv_timeout(Duration::from_secs(2))
                    .expect("test must release the held authority permit");
            })
        });
        tokio::time::timeout(Duration::from_secs(1), permit_entered_rx)
            .await
            .expect("old reader must take its permit")
            .expect("old reader must report its permit");

        // Queue one callback behind a stalled bridge while authority is still live. The injected
        // clock signals synchronously before the first check; the spawned task cannot yield back to
        // this test until that check passes and the locked bridge makes it wait.
        let bridge_guard = bridge.lock().await;
        let (authority_event_tx, mut authority_event_rx) = tokio::sync::mpsc::unbounded_channel();
        let (queued_admitted_tx, queued_admitted_rx) = tokio::sync::oneshot::channel();
        let queued_bridge = bridge.clone();
        let queued_gate = gate.clone();
        let queued_event_tx = authority_event_tx.clone();
        let queued_input = tokio::spawn(async move {
            let admission = Mutex::new(Some(queued_admitted_tx));
            let outcome = handle_binary_terminal_input(
                &queued_bridge,
                &queued_gate,
                channel,
                b"queued-before-live-revocation",
                move || {
                    if let Some(admitted) = admission.lock().unwrap().take() {
                        let _ = admitted.send(());
                    }
                    1
                },
            )
            .await;
            if outcome == TerminalInputOutcome::AuthorityEnded && queued_gate.claim_end_event() {
                let _ = queued_event_tx.send(PeerTransportEvent::AuthorityEnded);
            }
            outcome
        });
        tokio::time::timeout(Duration::from_secs(1), queued_admitted_rx)
            .await
            .expect("queued input must reach its live pre-lock authority check")
            .expect("queued input must report admission");
        assert!(
            !queued_input.is_finished(),
            "pre-revocation input must be waiting behind the stalled bridge"
        );

        live_revoked.store(true, Ordering::Release);
        let writer_gate = gate.clone();
        let writer_event_tx = authority_event_tx.clone();
        let writer = tokio::task::spawn_blocking(move || {
            let result = writer_gate.observe_revocation_at(1);
            if result == Some(false) && writer_gate.claim_end_event() {
                let _ = writer_event_tx.send(PeerTransportEvent::AuthorityEnded);
            }
            result
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !gate.revocation_observed.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("deny must publish before waiting for the authority writer");
        assert!(
            !writer.is_finished(),
            "snapshot cleanup must still be waiting behind the admitted reader"
        );

        // Every later binary callback must return from the monotonic pre-lock denial rather than
        // joining the already-queued bridge waiter or barging ahead of the authority writer.
        let mut callbacks = Vec::new();
        for _ in 0..64 {
            let callback_bridge = bridge.clone();
            let callback_gate = gate.clone();
            let authority_event_tx = authority_event_tx.clone();
            callbacks.push(tokio::spawn(async move {
                let outcome = handle_binary_terminal_input(
                    &callback_bridge,
                    &callback_gate,
                    channel,
                    b"must-not-reach-retained-pty",
                    || 1,
                )
                .await;
                if outcome == TerminalInputOutcome::AuthorityEnded
                    && callback_gate.claim_end_event()
                {
                    let _ = authority_event_tx.send(PeerTransportEvent::AuthorityEnded);
                }
                outcome
            }));
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            for callback in callbacks {
                let outcome = callback.await.expect("binary callback must join");
                assert_eq!(outcome, TerminalInputOutcome::AuthorityEnded);
            }
        })
        .await
        .expect("new binary callbacks must deny while writer cleanup remains blocked");
        assert!(
            !writer.is_finished(),
            "denied callbacks cannot barge ahead of the waiting writer"
        );
        assert!(
            !queued_input.is_finished(),
            "the pre-revocation callback remains stalled until the bridge is released"
        );
        assert!(
            bridge_guard.is_some(),
            "live revocation does not remove or kill the retained session"
        );

        // The callback admitted before revocation now reaches the post-lock check. It must observe
        // the already-published deny and never write its queued bytes.
        drop(bridge_guard);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), queued_input)
                .await
                .expect("queued input must finish after the bridge is released")
                .expect("queued input callback must join"),
            TerminalInputOutcome::AuthorityEnded
        );
        assert_eq!(
            authority_event_rx.try_recv(),
            Ok(PeerTransportEvent::AuthorityEnded),
            "the rejected-input flood emits the owner teardown event"
        );
        assert!(
            matches!(
                authority_event_rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "queued and fresh rejected input emit exactly one AuthorityEnded"
        );
        assert!(
            bridge.lock().await.is_some(),
            "input denial leaves the retained session present without a kill"
        );
        {
            let state = state.lock().unwrap();
            assert!(
                state.inputs.is_empty(),
                "live-revoked queued bytes never reach the PTY"
            );
            assert_eq!(
                state.detaches, 0,
                "authority cleanup preserves the retained daemon PTY"
            );
        }

        release_permit_tx
            .send(())
            .expect("held authority permit must still be live");
        assert_eq!(held_reader.await.expect("held reader must join"), Some(()));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), writer)
                .await
                .expect("writer cleanup must finish after the old permit exits")
                .expect("writer cleanup must join"),
            Some(false)
        );
        assert!(
            matches!(
                authority_event_rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
            ),
            "watchdog completion cannot emit a duplicate AuthorityEnded"
        );
        assert!(
            gate.authority.read().unwrap().is_none(),
            "writer cleanup clears the stale snapshot"
        );
    }

    #[tokio::test]
    async fn stalled_outbound_completion_cannot_carry_binary_input_past_expiry() {
        let (state, bridge, channel) = retained_input_bridge();

        let gate = ConnectionAuthorityGate::new("browser-a".to_string(), |_, _, _| false);
        gate.replace(Some(
            crate::remote_control::AuthenticatedAuthoritySnapshot {
                account_id: "account-a".to_string(),
                revocation_iat_ms: 10,
                expires_at_ms: 100,
            },
        ));
        let clock = Arc::new(AtomicU64::new(99));

        let (liveness_tx, _liveness) = PeerLiveness::channel(Duration::from_secs(1));
        let (scheduler, owner) = outbound_scheduler_channel_with_limits(liveness_tx, 64, 64, 8, 8);
        let bridge_for_control = bridge.clone();
        let scheduler_for_control = scheduler.clone();
        let blocked_control = tokio::spawn(async move {
            let _bridge_guard = bridge_for_control.lock().await;
            scheduler_for_control
                .send_control_text("physically-blocked".to_string())
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while owner.control_rx.len() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("control reply must be awaiting outbound physical completion");

        let bridge_for_input = bridge.clone();
        let gate_for_input = gate.clone();
        let clock_for_input = clock.clone();
        let input = tokio::spawn(async move {
            handle_binary_terminal_input(
                &bridge_for_input,
                &gate_for_input,
                channel,
                b"must-not-reach-pty",
                || clock_for_input.load(Ordering::Acquire),
            )
            .await
        });
        tokio::task::yield_now().await;
        assert!(
            !input.is_finished(),
            "the fixture must hold input behind the same bridge guard as the stalled control reply"
        );

        // Authority expires while the binary callback waits. Releasing the outbound owner lets the
        // control await unwind, but the post-lock deadline check must still deny the stale frame.
        clock.store(100, Ordering::Release);
        drop(owner);
        assert_eq!(
            blocked_control.await.expect("control task must join"),
            Err(OutputSendError::QueueClosed)
        );
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), input)
                .await
                .expect("binary gate must not wait for a revoke tick")
                .expect("binary input task must join"),
            TerminalInputOutcome::AuthorityEnded
        );
        let state = state.lock().unwrap();
        assert!(state.inputs.is_empty(), "expired bytes never reach the PTY");
        assert_eq!(
            state.detaches, 0,
            "input denial does not kill or detach the retained daemon PTY"
        );
    }

    #[test]
    fn desktop_access_refresh_is_authenticated_attempt_local_and_change_only() {
        let mut first_attempt = None;
        assert!(!should_send_desktop_access_status(
            &mut first_attempt,
            DesktopAccessStatus::Required,
            false,
        ));
        assert_eq!(first_attempt, None, "pre-auth state is never retained");
        assert!(should_send_desktop_access_status(
            &mut first_attempt,
            DesktopAccessStatus::Required,
            true,
        ));
        assert!(!should_send_desktop_access_status(
            &mut first_attempt,
            DesktopAccessStatus::Required,
            true,
        ));
        assert!(should_send_desktop_access_status(
            &mut first_attempt,
            DesktopAccessStatus::Granted,
            true,
        ));

        let mut replacement_attempt = None;
        assert!(
            should_send_desktop_access_status(
                &mut replacement_attempt,
                DesktopAccessStatus::Granted,
                true,
            ),
            "a replacement serve owner starts with no inherited snapshot"
        );
    }

    #[test]
    fn inbound_ice_stages_complete_batches_without_mutating_committed_state() {
        let admission = InboundIceAdmission::default();
        let staged = admission
            .stage(
                vec![
                    remote_candidate(2, "gap-two"),
                    remote_candidate(4, "gap-four"),
                ],
                5,
            )
            .expect("global sequence gaps from the opposite peer are valid");
        assert_eq!(staged.candidates.len(), 2);
        assert_eq!(staged.next_since, 5);
        assert_eq!(admission, InboundIceAdmission::default());

        let before = admission;
        assert!(matches!(
            admission.stage(
                vec![
                    remote_candidate(1, "valid-prefix"),
                    IceCandidate {
                        candidate: "not-json".into(),
                        seq: 2,
                    }
                ],
                2,
            ),
            Err(InboundIceValidationError::CandidateParse)
        ));
        assert_eq!(
            admission, before,
            "a malformed suffix cannot admit its prefix"
        );
    }

    #[test]
    fn inbound_ice_enforces_utf8_blob_and_aggregate_byte_bounds() {
        let admission = InboundIceAdmission::default();
        admission
            .stage(
                vec![remote_candidate_with_exact_blob_bytes(
                    1,
                    MAX_REMOTE_ICE_CANDIDATE_BYTES,
                )],
                1,
            )
            .expect("the exact 2 KiB opaque candidate bound must fit");
        assert!(matches!(
            admission.stage(
                vec![remote_candidate_with_exact_blob_bytes(
                    1,
                    MAX_REMOTE_ICE_CANDIDATE_BYTES + 1,
                )],
                1,
            ),
            Err(InboundIceValidationError::CandidateBytes)
        ));

        let unicode_blob = serde_json::to_string(&RTCIceCandidateInit {
            candidate: "é".repeat(1_100),
            ..Default::default()
        })
        .unwrap();
        assert!(unicode_blob.chars().count() < unicode_blob.len());
        assert!(unicode_blob.len() > MAX_REMOTE_ICE_CANDIDATE_BYTES);
        assert!(matches!(
            admission.stage(
                vec![IceCandidate {
                    candidate: unicode_blob,
                    seq: 1,
                }],
                1,
            ),
            Err(InboundIceValidationError::CandidateBytes)
        ));

        let nearly_full = InboundIceAdmission {
            since: 1,
            accepted_candidates: 1,
            accepted_bytes: MAX_REMOTE_ICE_BYTES_PER_SESSION - 1,
        };
        assert!(matches!(
            nearly_full.stage(vec![remote_candidate(2, "aggregate-overflow")], 2),
            Err(InboundIceValidationError::AggregateBytes)
        ));
    }

    #[test]
    fn inbound_ice_rejects_sequence_and_cursor_regressions_table() {
        let cases = [
            (
                InboundIceAdmission::default(),
                vec![remote_candidate(0, "zero")],
                1,
                InboundIceValidationError::CandidateSequence,
            ),
            (
                InboundIceAdmission::default(),
                vec![remote_candidate(MAX_SIGNAL_ICE_SEQUENCE + 1, "too-high")],
                MAX_SIGNAL_ICE_SEQUENCE,
                InboundIceValidationError::CandidateSequence,
            ),
            (
                InboundIceAdmission::default(),
                vec![
                    remote_candidate(1, "first"),
                    remote_candidate(1, "duplicate"),
                ],
                1,
                InboundIceValidationError::CandidateSequence,
            ),
            (
                InboundIceAdmission::default(),
                vec![
                    remote_candidate(2, "second"),
                    remote_candidate(1, "reordered"),
                ],
                2,
                InboundIceValidationError::CandidateSequence,
            ),
            (
                InboundIceAdmission {
                    since: 5,
                    ..Default::default()
                },
                Vec::new(),
                4,
                InboundIceValidationError::Cursor,
            ),
            (
                InboundIceAdmission::default(),
                vec![remote_candidate(2, "cursor-behind")],
                1,
                InboundIceValidationError::Cursor,
            ),
            (
                InboundIceAdmission::default(),
                Vec::new(),
                MAX_SIGNAL_ICE_SEQUENCE + 1,
                InboundIceValidationError::Cursor,
            ),
            (
                InboundIceAdmission {
                    since: 5,
                    ..Default::default()
                },
                vec![remote_candidate(5, "not-after-cursor")],
                5,
                InboundIceValidationError::CandidateSequence,
            ),
        ];

        for (admission, candidates, next_since, expected) in cases {
            let before = admission;
            assert!(
                matches!(admission.stage(candidates, next_since), Err(error) if error == expected)
            );
            assert_eq!(admission, before);
        }
    }

    #[tokio::test]
    async fn inbound_ice_applies_fifo_and_commits_only_after_the_complete_batch() {
        let mut admission = InboundIceAdmission::default();
        let (applier, calls) = RecordingRemoteIceApplier::succeeding();
        let retired = AtomicBool::new(false);
        assert_eq!(
            apply_inbound_ice_batch(
                &mut admission,
                vec![remote_candidate(2, "first"), remote_candidate(4, "second")],
                5,
                &applier,
                &retired,
                Duration::from_secs(1),
            )
            .await,
            Ok(InboundIceBatchOutcome::Committed)
        );
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            [
                "candidate:first 1 udp 1 192.0.2.1 5000 typ host",
                "candidate:second 1 udp 1 192.0.2.1 5000 typ host",
            ]
        );
        assert_eq!(admission.since, 5);
        assert_eq!(admission.accepted_candidates, 2);

        assert_eq!(
            apply_inbound_ice_batch(
                &mut admission,
                Vec::new(),
                9,
                &applier,
                &retired,
                Duration::from_secs(1),
            )
            .await,
            Ok(InboundIceBatchOutcome::Committed)
        );
        assert_eq!(
            admission.since, 9,
            "an empty batch may advance the global cursor"
        );
    }

    #[tokio::test]
    async fn inbound_ice_reserves_exactly_half_the_cloud_candidate_quota() {
        let mut admission = InboundIceAdmission::default();
        let (applier, calls) = RecordingRemoteIceApplier::succeeding();
        let retired = AtomicBool::new(false);
        let exact_half = (1..=MAX_REMOTE_ICE_CANDIDATES_PER_SESSION)
            .map(|index| remote_candidate(index as u64, &format!("candidate-{index}")))
            .collect();
        assert_eq!(
            apply_inbound_ice_batch(
                &mut admission,
                exact_half,
                MAX_REMOTE_ICE_CANDIDATES_PER_SESSION as u64,
                &applier,
                &retired,
                Duration::from_secs(1),
            )
            .await,
            Ok(InboundIceBatchOutcome::Committed)
        );
        assert_eq!(
            calls.lock().unwrap().len(),
            MAX_REMOTE_ICE_CANDIDATES_PER_SESSION
        );
        let before = admission;
        assert!(matches!(
            admission.stage(
                vec![remote_candidate(
                    MAX_REMOTE_ICE_CANDIDATES_PER_SESSION as u64 + 1,
                    "one-too-many",
                )],
                MAX_REMOTE_ICE_CANDIDATES_PER_SESSION as u64 + 1,
            ),
            Err(InboundIceValidationError::CandidateCount)
        ));
        assert_eq!(admission, before);
    }

    #[tokio::test]
    async fn inbound_ice_rejects_whole_malformed_batch_before_applying_valid_prefix() {
        let mut admission = InboundIceAdmission::default();
        let (applier, calls) = RecordingRemoteIceApplier::succeeding();
        let retired = AtomicBool::new(false);
        assert_eq!(
            apply_inbound_ice_batch(
                &mut admission,
                vec![
                    remote_candidate(1, "valid-prefix"),
                    IceCandidate {
                        candidate: "not-json".into(),
                        seq: 2,
                    },
                ],
                2,
                &applier,
                &retired,
                Duration::from_secs(1),
            )
            .await,
            Err(InboundIceBatchError::Invalid(
                InboundIceValidationError::CandidateParse
            ))
        );
        assert!(calls.lock().unwrap().is_empty());
        assert_eq!(admission, InboundIceAdmission::default());
    }

    #[tokio::test]
    async fn inbound_ice_application_failure_and_timeout_leave_cursor_uncommitted() {
        let retired = AtomicBool::new(false);
        let mut failed_admission = InboundIceAdmission::default();
        let (failing, calls) = RecordingRemoteIceApplier::with_results([Ok(()), Err(())]);
        assert_eq!(
            apply_inbound_ice_batch(
                &mut failed_admission,
                vec![
                    remote_candidate(1, "first"),
                    remote_candidate(2, "rejected")
                ],
                2,
                &failing,
                &retired,
                Duration::from_secs(1),
            )
            .await,
            Err(InboundIceBatchError::ApplicationFailed)
        );
        assert_eq!(calls.lock().unwrap().len(), 2);
        assert_eq!(failed_admission, InboundIceAdmission::default());

        let mut timed_out_admission = InboundIceAdmission::default();
        assert_eq!(
            apply_inbound_ice_batch(
                &mut timed_out_admission,
                vec![remote_candidate(1, "hung")],
                1,
                &HangingRemoteIceApplier,
                &retired,
                Duration::from_millis(5),
            )
            .await,
            Err(InboundIceBatchError::ApplicationTimedOut)
        );
        assert_eq!(timed_out_admission, InboundIceAdmission::default());
    }

    #[test]
    fn inbound_ice_schedule_adds_one_early_poll_without_moving_old_checkpoints() {
        let cadence = test_ice_poll_cadence(Duration::from_millis(700), Duration::from_millis(250));
        let mut schedule = InboundIcePollSchedule::new(cadence);
        let initial = schedule.initial();
        assert_eq!(initial.kind, InboundIcePollKind::Regular);
        assert_eq!(initial.wait, Duration::ZERO);

        let early = schedule.after(initial, InboundIcePollOutcome::Empty, Duration::ZERO);
        assert_eq!(early.kind, InboundIcePollKind::Early);
        assert_eq!(early.wait, Duration::from_millis(250));
        assert_eq!(early.checkpoint_remaining, Some(Duration::from_millis(700)));

        // A 50 ms cloud response still lands the regular catch-up fetch at the old t=700 ms checkpoint:
        // 250 ms early wait + 50 ms request + 400 ms remaining.
        let catch_up = schedule.after(
            early,
            InboundIcePollOutcome::Empty,
            Duration::from_millis(400),
        );
        assert_eq!(catch_up.kind, InboundIcePollKind::Regular);
        assert_eq!(catch_up.wait, Duration::from_millis(400));
        assert_eq!(catch_up.checkpoint_remaining, None);

        let settled = schedule.after(catch_up, InboundIcePollOutcome::Empty, Duration::ZERO);
        assert_eq!(settled.kind, InboundIcePollKind::Regular);
        assert_eq!(settled.wait, Duration::from_millis(700));
        assert_eq!(
            schedule.after_early_timeout().wait,
            Duration::ZERO,
            "a slow expendable early fetch must yield immediately at the old checkpoint"
        );
    }

    #[test]
    fn inbound_ice_progress_adds_early_polls_without_resetting_regular_checkpoint() {
        let cadence = test_ice_poll_cadence(Duration::from_millis(700), Duration::from_millis(250));
        let mut schedule = InboundIcePollSchedule::new(cadence);
        let initial = schedule.initial();
        let early = schedule.after(
            initial,
            InboundIcePollOutcome::CandidateProgress,
            Duration::ZERO,
        );
        assert_eq!(early.kind, InboundIcePollKind::Early);
        assert_eq!(early.wait, Duration::from_millis(250));

        let next_early = schedule.after(
            early,
            InboundIcePollOutcome::CandidateProgress,
            Duration::from_millis(450),
        );
        assert_eq!(next_early.kind, InboundIcePollKind::Early);
        assert_eq!(next_early.wait, Duration::from_millis(250));
        assert_eq!(
            next_early.checkpoint_remaining,
            Some(Duration::from_millis(450))
        );

        let catch_up = schedule.after(
            next_early,
            InboundIcePollOutcome::Empty,
            Duration::from_millis(200),
        );
        assert_eq!(catch_up.kind, InboundIcePollKind::Regular);
        assert_eq!(catch_up.wait, Duration::from_millis(200));
        assert_eq!(
            early.wait + next_early.wait + catch_up.wait,
            Duration::from_millis(700),
            "progress-triggered early polls must share, not reset, the original checkpoint"
        );

        let settled = schedule.after(
            catch_up,
            InboundIcePollOutcome::TransientFailure,
            Duration::ZERO,
        );
        assert_eq!(settled.kind, InboundIcePollKind::Regular);
        assert_eq!(settled.wait, Duration::from_millis(700));
    }

    #[test]
    fn inbound_ice_schedule_bounds_latency_and_offer_flood_load() {
        fn periodic_poll_count(interval_ms: u64, horizon_ms: u64) -> usize {
            if horizon_ms == 0 {
                return 0;
            }
            (1 + (horizon_ms - 1) / interval_ms) as usize
        }

        let horizon_ms = 90_000;
        let current_empty = periodic_poll_count(700, horizon_ms);
        let adaptive_empty = current_empty + 1;
        assert_eq!(current_empty, 129);
        assert_eq!(adaptive_empty, 130);
        assert_eq!(periodic_poll_count(500, horizon_ms), 180);
        assert_eq!(periodic_poll_count(250, horizon_ms), 360);

        // In the first 700 ms after an immediate empty response, current polling has one t=700 pickup point.
        // The adaptive schedule inserts t=250 while retaining t=700. Across every integer arrival millisecond,
        // its maximum wait is 450 ms and its mean is about 189 ms instead of about 350 ms.
        let mut current_total_delay = 0u64;
        let mut adaptive_total_delay = 0u64;
        let mut adaptive_worst_delay = 0u64;
        for arrival_ms in 1..=700 {
            let current_delay = 700 - arrival_ms;
            let adaptive_pickup = if arrival_ms <= 250 { 250 } else { 700 };
            let adaptive_delay = adaptive_pickup - arrival_ms;
            current_total_delay += current_delay;
            adaptive_total_delay += adaptive_delay;
            adaptive_worst_delay = adaptive_worst_delay.max(adaptive_delay);
        }
        assert!(adaptive_worst_delay <= 450);
        assert!(adaptive_total_delay * 100 < current_total_delay * 55);

        // Continuous one-candidate progress inserts two early starts into each fixed 700 ms window. The final
        // 200 ms catch-up gap means at most five starts fit in any one-second window. The immutable 16-serve and
        // 64-remote-candidate caps therefore bound this short burst to 80 requests/s aggregate and at most 64
        // progress responses per setup; empty setups settle at the old 700 ms rate after one extra read.
        let max_progress_polls_per_second = 5;
        assert_eq!(
            max_progress_polls_per_second * super::MAX_CONCURRENT_SERVES,
            80
        );
        assert_eq!(super::MAX_REMOTE_ICE_CANDIDATES_PER_SESSION, 64);
    }

    #[tokio::test]
    async fn inbound_ice_pump_keeps_progress_polls_inside_original_regular_window() {
        let responses = Arc::new(Mutex::new(VecDeque::from([
            Ok((Vec::new(), 0u64)),
            Ok((vec![remote_candidate(1, "progress")], 1u64)),
            Ok((Vec::new(), 1u64)),
            Err(FetchIceError::Transient("retry at settled cadence".into())),
            Err(FetchIceError::Terminal("stop test owner".into())),
        ])));
        let observed_since = Arc::new(Mutex::new(Vec::new()));
        let sleeps = Arc::new(Mutex::new(Vec::new()));
        let (failure_tx, mut failure_rx) = tokio::sync::mpsc::channel(1);
        let retired = Arc::new(AtomicBool::new(false));
        let (applier, calls) = RecordingRemoteIceApplier::succeeding();

        let exit = run_inbound_ice_pump_with_sleep(
            {
                let responses = responses.clone();
                let observed_since = observed_since.clone();
                move |since| {
                    observed_since.lock().unwrap().push(since);
                    let response = responses
                        .lock()
                        .unwrap()
                        .pop_front()
                        .expect("the terminal response bounds the pump");
                    Box::pin(async move { response }) as InboundIceFetchFuture
                }
            },
            applier,
            failure_tx,
            retired,
            test_ice_poll_cadence(Duration::from_millis(700), Duration::from_millis(250)),
            Duration::from_secs(1),
            None,
            {
                let sleeps = sleeps.clone();
                move |delay| {
                    sleeps.lock().unwrap().push(delay);
                    Box::pin(async move { delay })
                }
            },
        )
        .await;

        assert_eq!(exit, InboundIcePumpExit::SetupFailed);
        assert_eq!(failure_rx.recv().await, Some(()));
        assert_eq!(observed_since.lock().unwrap().as_slice(), [0, 0, 1, 1, 1]);
        assert_eq!(calls.lock().unwrap().len(), 1);
        let sleeps = sleeps.lock().unwrap();
        assert_eq!(sleeps.len(), 4);
        assert_eq!(sleeps[0], Duration::from_millis(250));
        assert_eq!(
            sleeps[1],
            Duration::from_millis(250),
            "committed progress adds another early poll inside the existing window"
        );
        assert!(
            !sleeps[2].is_zero() && sleeps[2] <= Duration::from_millis(200),
            "the catch-up wait must consume only the remainder of the original 700 ms window"
        );
        assert_eq!(
            sleeps[3],
            Duration::from_millis(700),
            "a transient regular fetch must not restart the burst"
        );
    }

    #[tokio::test]
    async fn inbound_ice_pump_cancels_pending_early_fetch_at_original_checkpoint() {
        struct DropMarker(Arc<AtomicBool>);

        impl Drop for DropMarker {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let polls = Arc::new(AtomicUsize::new(0));
        let pending_fetch_dropped = Arc::new(AtomicBool::new(false));
        let sleeps = Arc::new(Mutex::new(Vec::new()));
        let (failure_tx, mut failure_rx) = tokio::sync::mpsc::channel(1);
        let retired = Arc::new(AtomicBool::new(false));
        let (applier, calls) = RecordingRemoteIceApplier::succeeding();
        let started = tokio::time::Instant::now();

        let exit = tokio::time::timeout(
            Duration::from_secs(2),
            run_inbound_ice_pump_with_sleep(
                {
                    let polls = polls.clone();
                    let pending_fetch_dropped = pending_fetch_dropped.clone();
                    move |since| {
                        let poll = polls.fetch_add(1, Ordering::AcqRel);
                        assert_eq!(since, 0, "a cancelled early read cannot advance admission");
                        match poll {
                            0 => {
                                Box::pin(async { Ok((Vec::new(), 0u64)) }) as InboundIceFetchFuture
                            }
                            1 => {
                                let marker = DropMarker(pending_fetch_dropped.clone());
                                Box::pin(async move {
                                    let _marker = marker;
                                    std::future::pending::<
                                        Result<(Vec<IceCandidate>, u64), FetchIceError>,
                                    >()
                                    .await
                                }) as InboundIceFetchFuture
                            }
                            2 => {
                                assert!(
                                    pending_fetch_dropped.load(Ordering::Acquire),
                                    "timeout must cancel and drop the expendable HTTP future before catch-up"
                                );
                                Box::pin(async {
                                    Err(FetchIceError::Terminal("stop test owner".into()))
                                }) as InboundIceFetchFuture
                            }
                            _ => panic!("the regular catch-up response bounds the pump"),
                        }
                    }
                },
                applier,
                failure_tx,
                retired,
                test_ice_poll_cadence(Duration::from_millis(700), Duration::from_millis(250)),
                Duration::from_secs(1),
                None,
                {
                    let sleeps = sleeps.clone();
                    move |delay| {
                        sleeps.lock().unwrap().push(delay);
                        // A normal, on-time 250 ms wake. Returning the observed duration without sleeping keeps
                        // the test fast while the genuinely pending HTTP future consumes its real positive budget.
                        Box::pin(async move { delay })
                    }
                },
            ),
        )
        .await
        .expect("the positive-budget cancellation path must remain bounded");

        assert_eq!(exit, InboundIcePumpExit::SetupFailed);
        assert_eq!(failure_rx.recv().await, Some(()));
        assert_eq!(polls.load(Ordering::Acquire), 3);
        assert!(pending_fetch_dropped.load(Ordering::Acquire));
        assert!(calls.lock().unwrap().is_empty());
        assert_eq!(
            sleeps.lock().unwrap().as_slice(),
            [Duration::from_millis(250)],
            "after the 450 ms request budget expires, regular polling runs at the original logical t=700 checkpoint without another sleep"
        );
        assert!(
            started.elapsed() >= Duration::from_millis(400),
            "the early HTTP future must receive a positive approximately-450 ms budget, not a zero-budget cancellation"
        );
    }

    #[tokio::test]
    async fn inbound_ice_pump_cancels_a_slow_early_fetch_before_regular_catch_up() {
        let polls = Arc::new(AtomicUsize::new(0));
        let sleeps = Arc::new(Mutex::new(Vec::new()));
        let (failure_tx, mut failure_rx) = tokio::sync::mpsc::channel(1);
        let retired = Arc::new(AtomicBool::new(false));
        let (applier, calls) = RecordingRemoteIceApplier::succeeding();

        let exit = run_inbound_ice_pump_with_sleep(
            {
                let polls = polls.clone();
                move |since| {
                    let poll = polls.fetch_add(1, Ordering::AcqRel);
                    assert_eq!(since, 0, "a cancelled early read cannot advance admission");
                    match poll {
                        0 => Box::pin(async { Ok((Vec::new(), 0u64)) }) as InboundIceFetchFuture,
                        1 => Box::pin(async {
                            std::future::pending::<Result<(Vec<IceCandidate>, u64), FetchIceError>>(
                            )
                            .await
                        }) as InboundIceFetchFuture,
                        2 => Box::pin(async {
                            Err(FetchIceError::Terminal("stop test owner".into()))
                        }) as InboundIceFetchFuture,
                        _ => panic!("the regular catch-up response bounds the pump"),
                    }
                }
            },
            applier,
            failure_tx,
            retired,
            test_ice_poll_cadence(Duration::from_millis(700), Duration::from_millis(250)),
            Duration::from_secs(1),
            None,
            {
                let sleeps = sleeps.clone();
                move |delay| {
                    sleeps.lock().unwrap().push(delay);
                    // Model an event-loop wake later than the entire old cadence. The early fetch receives a zero
                    // remaining budget and the regular catch-up starts without another sleep.
                    Box::pin(async { Duration::from_millis(800) })
                }
            },
        )
        .await;

        assert_eq!(exit, InboundIcePumpExit::SetupFailed);
        assert_eq!(failure_rx.recv().await, Some(()));
        assert_eq!(polls.load(Ordering::Acquire), 3);
        assert!(calls.lock().unwrap().is_empty());
        assert_eq!(
            sleeps.lock().unwrap().as_slice(),
            [Duration::from_millis(250)]
        );
    }

    #[tokio::test]
    async fn inbound_ice_protocol_and_terminal_failures_use_one_bounded_setup_signal() {
        for error in [
            FetchIceError::Protocol("invalid response".into()),
            FetchIceError::Terminal("dead session".into()),
        ] {
            let (failure_tx, mut failure_rx) = tokio::sync::mpsc::channel(1);
            let retired = Arc::new(AtomicBool::new(false));
            let (applier, _calls) = RecordingRemoteIceApplier::succeeding();
            let mut error = Some(error);
            let exit = run_inbound_ice_pump(
                move |_| {
                    let error = error.take().expect("terminal fetch is called once");
                    Box::pin(async move { Err(error) }) as InboundIceFetchFuture
                },
                applier,
                failure_tx,
                retired,
                test_ice_poll_cadence(Duration::ZERO, Duration::ZERO),
                Duration::from_secs(1),
                None,
            )
            .await;
            assert_eq!(exit, InboundIcePumpExit::SetupFailed);
            assert_eq!(failure_rx.recv().await, Some(()));
            assert!(matches!(
                failure_rx.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
            ));
        }
    }

    #[tokio::test]
    async fn native_open_retirement_wins_an_inflight_inbound_ice_failure_and_stops_polling() {
        let polls = Arc::new(AtomicUsize::new(0));
        let retired = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let applier = RecordingRemoteIceApplier {
            calls: calls.clone(),
            results: Mutex::new(VecDeque::from([Err(())])),
            retire_on_call: Some((1, retired.clone())),
        };
        let (failure_tx, mut failure_rx) = tokio::sync::mpsc::channel(1);
        let exit = run_inbound_ice_pump(
            {
                let polls = polls.clone();
                move |since| {
                    let poll = polls.fetch_add(1, Ordering::AcqRel);
                    assert_eq!(since, 0, "a transient fetch cannot advance the cursor");
                    if poll == 0 {
                        Box::pin(async { Err(FetchIceError::Transient("retry".into())) })
                            as InboundIceFetchFuture
                    } else {
                        Box::pin(async { Ok((vec![remote_candidate(1, "open-race")], 1u64)) })
                            as InboundIceFetchFuture
                    }
                }
            },
            applier,
            failure_tx,
            retired,
            test_ice_poll_cadence(Duration::ZERO, Duration::ZERO),
            Duration::from_secs(1),
            None,
        )
        .await;
        assert_eq!(exit, InboundIcePumpExit::Retired);
        assert_eq!(polls.load(Ordering::Acquire), 2);
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert!(matches!(
            failure_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));
    }

    #[tokio::test]
    async fn inbound_ice_worker_is_aborted_and_joined_on_open_owner_teardown() {
        struct DropMarker(Arc<AtomicBool>);
        impl Drop for DropMarker {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let mut marker = Some(DropMarker(dropped.clone()));
        let (started_notify_tx, started_notify_rx) = tokio::sync::oneshot::channel();
        let mut started_notify_tx = Some(started_notify_tx);
        let (failure_tx, _failure_rx) = tokio::sync::mpsc::channel(1);
        let retired = Arc::new(AtomicBool::new(false));
        let (applier, _calls) = RecordingRemoteIceApplier::succeeding();
        let task = tokio::spawn(async move {
            let _ = run_inbound_ice_pump(
                move |_| {
                    let marker = marker.take().expect("fetch is entered only once");
                    let started_notify_tx = started_notify_tx
                        .take()
                        .expect("fetch start notification is sent once");
                    Box::pin(async move {
                        let _marker = marker;
                        let _ = started_notify_tx.send(());
                        std::future::pending::<Result<(Vec<IceCandidate>, u64), FetchIceError>>()
                            .await
                    }) as InboundIceFetchFuture
                },
                applier,
                failure_tx,
                retired,
                test_ice_poll_cadence(Duration::from_secs(60), Duration::from_millis(250)),
                Duration::from_secs(1),
                None,
            )
            .await;
        });
        started_notify_rx.await.unwrap();
        let mut owner = OwnedSessionTask::new("test inbound ICE", task);
        owner.shutdown().await;
        assert!(dropped.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn local_ice_admission_reserves_half_the_cloud_quota_and_is_byte_bounded() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(MAX_LOCAL_ICE_CANDIDATES_PER_SESSION);
        let accepted = AtomicUsize::new(0);
        let retired = AtomicBool::new(false);

        assert_eq!(
            enqueue_local_ice_candidate(&tx, &accepted, &retired, String::new()),
            Err(LocalIceEnqueueError::Empty)
        );
        assert_eq!(
            enqueue_local_ice_candidate(
                &tx,
                &accepted,
                &retired,
                "x".repeat(MAX_LOCAL_ICE_CANDIDATE_BYTES + 1),
            ),
            Err(LocalIceEnqueueError::TooLarge)
        );
        for index in 0..MAX_LOCAL_ICE_CANDIDATES_PER_SESSION {
            enqueue_local_ice_candidate(&tx, &accepted, &retired, format!("candidate-{index}"))
                .expect("the agent half of the cloud quota must fit exactly");
        }
        assert_eq!(
            enqueue_local_ice_candidate(&tx, &accepted, &retired, "one-too-many".into()),
            Err(LocalIceEnqueueError::SessionLimit)
        );
        assert_eq!(
            accepted.load(Ordering::Acquire),
            MAX_LOCAL_ICE_CANDIDATES_PER_SESSION
        );

        let mut drained = Vec::new();
        while let Ok(candidate) = rx.try_recv() {
            drained.push(candidate);
        }
        assert_eq!(drained.len(), MAX_LOCAL_ICE_CANDIDATES_PER_SESSION);
        assert_eq!(drained.first().map(String::as_str), Some("candidate-0"));
        assert_eq!(drained.last().map(String::as_str), Some("candidate-63"));
    }

    #[tokio::test]
    async fn local_ice_poster_retries_the_fifo_head_without_reordering() {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tx.send("first".into()).await.unwrap();
        tx.send("second".into()).await.unwrap();
        drop(tx);
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let first_failures = Arc::new(AtomicUsize::new(0));
        let (failure_tx, mut failure_rx) = tokio::sync::mpsc::channel(1);

        run_local_ice_poster(
            rx,
            {
                let calls = calls.clone();
                let first_failures = first_failures.clone();
                move |candidate| {
                    let calls = calls.clone();
                    let first_failures = first_failures.clone();
                    Box::pin(async move {
                        calls.lock().unwrap().push(candidate.clone());
                        if candidate == "first" && first_failures.fetch_add(1, Ordering::AcqRel) < 2
                        {
                            Err(())
                        } else {
                            Ok(())
                        }
                    }) as LocalIcePostFuture
                }
            },
            failure_tx,
            Arc::new(AtomicBool::new(false)),
            Duration::from_millis(50),
            &[Duration::ZERO, Duration::ZERO, Duration::ZERO],
        )
        .await;

        assert_eq!(
            calls.lock().unwrap().as_slice(),
            ["first", "first", "first", "second"]
        );
        assert!(matches!(
            failure_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));
    }

    #[tokio::test]
    async fn local_ice_exhaustion_fails_the_pre_open_owner() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tx.send("candidate".into()).await.unwrap();
        drop(tx);
        let (failure_tx, mut failure_rx) = tokio::sync::mpsc::channel(1);

        run_local_ice_poster(
            rx,
            |_| Box::pin(async { Err(()) }) as LocalIcePostFuture,
            failure_tx,
            Arc::new(AtomicBool::new(false)),
            Duration::from_millis(50),
            &[Duration::ZERO, Duration::ZERO],
        )
        .await;

        assert_eq!(failure_rx.recv().await, Some(()));
    }

    #[tokio::test]
    async fn local_ice_hung_posts_are_bounded_and_fail_the_pre_open_owner() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tx.send("candidate".into()).await.unwrap();
        drop(tx);
        let calls = Arc::new(AtomicUsize::new(0));
        let (failure_tx, mut failure_rx) = tokio::sync::mpsc::channel(1);

        run_local_ice_poster(
            rx,
            {
                let calls = calls.clone();
                move |_| {
                    calls.fetch_add(1, Ordering::AcqRel);
                    Box::pin(async { std::future::pending::<Result<(), ()>>().await })
                        as LocalIcePostFuture
                }
            },
            failure_tx,
            Arc::new(AtomicBool::new(false)),
            Duration::from_millis(5),
            &[Duration::ZERO],
        )
        .await;

        assert_eq!(calls.load(Ordering::Acquire), 2);
        assert_eq!(failure_rx.recv().await, Some(()));
    }

    #[tokio::test]
    async fn local_ice_retirement_stops_retries_without_harming_the_open_owner() {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tx.send("candidate".into()).await.unwrap();
        drop(tx);
        let retired = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let (failure_tx, mut failure_rx) = tokio::sync::mpsc::channel(1);

        run_local_ice_poster(
            rx,
            {
                let retired = retired.clone();
                let calls = calls.clone();
                move |_| {
                    let retired = retired.clone();
                    let calls = calls.clone();
                    Box::pin(async move {
                        calls.fetch_add(1, Ordering::AcqRel);
                        retired.store(true, Ordering::Release);
                        Err(())
                    }) as LocalIcePostFuture
                }
            },
            failure_tx,
            retired,
            Duration::from_millis(50),
            &[Duration::ZERO, Duration::ZERO],
        )
        .await;

        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert!(matches!(
            failure_rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));
    }

    #[test]
    fn delayed_pre_deadline_progress_cannot_resurrect_expired_setup() {
        let start = tokio::time::Instant::now();
        let mut deadline =
            ProgressDeadline::new(start, Duration::from_secs(20), Duration::from_secs(90));

        assert_eq!(
            super::note_setup_progress(
                &mut deadline,
                SetupProgressKey::RelayCredentialsFetched,
                start + Duration::from_secs(19),
                start + Duration::from_secs(45),
            ),
            Err(super::SetupWaitError::Deadline(
                crate::setup_deadline::DeadlineExpiry::Inactivity
            ))
        );
    }

    #[tokio::test]
    async fn setup_progress_queue_is_bounded_and_stale_owner_is_isolated() {
        let (stale, mut stale_rx) = SetupProgressReporter::channel();
        for _ in 0..super::SETUP_PROGRESS_QUEUE_CAPACITY {
            assert!(stale.report(SetupProgressKey::PeerState(
                super::SetupPeerState::Connecting
            )));
        }
        assert!(
            !stale.report(SetupProgressKey::AnswerCreated),
            "callbacks must never allocate beyond the fixed owner queue"
        );
        while stale_rx.try_recv().is_ok() {}
        drop(stale_rx);
        assert!(
            !stale.report(SetupProgressKey::AnswerAcknowledged),
            "late progress loses authority when its serve owner is gone"
        );

        let (replacement, mut replacement_rx) = SetupProgressReporter::channel();
        assert!(replacement.report(SetupProgressKey::RelayCredentialsFetched));
        assert_eq!(
            replacement_rx.recv().await.map(|event| event.key),
            Some(SetupProgressKey::RelayCredentialsFetched)
        );
    }

    #[tokio::test]
    async fn pre_open_disconnected_uses_setup_inactivity_not_established_grace() {
        let (_dc_tx, mut dc_rx) = tokio::sync::mpsc::channel::<u8>(1);
        let (_failure_tx, mut failure_rx) = tokio::sync::mpsc::channel(1);
        let (peer_tx, mut peer_liveness) = PeerLiveness::channel(Duration::from_millis(5));
        let (mut deadline, mut progress_rx) =
            test_setup_deadline(Duration::from_millis(100), Duration::from_millis(200));
        peer_tx
            .send(PeerTransportEvent::Peer(
                RTCPeerConnectionState::Disconnected,
            ))
            .unwrap();

        let waiter = tokio::spawn(async move {
            wait_for_setup_data_channel(
                &mut dc_rx,
                &mut failure_rx,
                &mut peer_liveness,
                &DiscoveredDataChannel::default(),
                &mut deadline,
                &mut progress_rx,
                Duration::from_millis(20),
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !waiter.is_finished(),
            "the post-open five-second policy must not become a pre-open disconnect timer"
        );
        peer_tx
            .send(PeerTransportEvent::Peer(RTCPeerConnectionState::Failed))
            .unwrap();
        assert_eq!(
            waiter.await.unwrap(),
            Err(super::SetupWaitError::Peer(PeerCloseReason::PeerFailed))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn setup_deadline_teardown_aborts_and_joins_both_ice_workers() {
        struct DropMarker(Arc<AtomicUsize>);
        impl Drop for DropMarker {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::AcqRel);
            }
        }

        let dropped = Arc::new(AtomicUsize::new(0));
        let make_task = |label| {
            let marker = DropMarker(dropped.clone());
            OwnedSessionTask::new(
                label,
                tokio::spawn(async move {
                    let _marker = marker;
                    std::future::pending::<()>().await;
                }),
            )
        };
        let mut local = make_task("test local ICE");
        let mut inbound = make_task("test inbound ICE");
        tokio::task::yield_now().await;
        let retired = AtomicBool::new(false);

        let (_dc_tx, mut dc_rx) = tokio::sync::mpsc::channel::<u8>(1);
        let (_failure_tx, mut failure_rx) = tokio::sync::mpsc::channel(1);
        let (_peer_tx, mut peer_liveness) = PeerLiveness::channel(Duration::from_secs(1));
        let (mut deadline, mut progress_rx) =
            test_setup_deadline(Duration::from_millis(10), Duration::from_millis(20));
        assert_eq!(
            wait_for_setup_data_channel(
                &mut dc_rx,
                &mut failure_rx,
                &mut peer_liveness,
                &DiscoveredDataChannel::default(),
                &mut deadline,
                &mut progress_rx,
                Duration::from_millis(5),
            )
            .await,
            Err(super::SetupWaitError::Deadline(
                crate::setup_deadline::DeadlineExpiry::Inactivity
            ))
        );

        shutdown_setup_tasks(&retired, &mut local, &mut inbound).await;

        assert!(retired.load(Ordering::Acquire));
        assert_eq!(dropped.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn ready_datachannel_wins_over_a_queued_setup_only_ice_failure() {
        let (dc_tx, mut dc_rx) = tokio::sync::mpsc::channel(1);
        let (failure_tx, mut failure_rx) = tokio::sync::mpsc::channel(1);
        let (_peer_tx, mut peer_liveness) = PeerLiveness::channel(Duration::from_secs(1));
        let (mut deadline, mut progress_rx) =
            test_setup_deadline(Duration::from_secs(1), Duration::from_secs(2));

        failure_tx.try_send(()).unwrap();
        dc_tx.send(7u8).await.unwrap();

        assert_eq!(
            wait_for_setup_data_channel(
                &mut dc_rx,
                &mut failure_rx,
                &mut peer_liveness,
                &DiscoveredDataChannel::default(),
                &mut deadline,
                &mut progress_rx,
                Duration::from_secs(1),
            )
            .await,
            Ok(7)
        );
        assert_eq!(failure_rx.try_recv(), Ok(()));
    }

    #[tokio::test]
    async fn queued_setup_ice_failure_still_fails_when_no_native_channel_is_open() {
        let (_dc_tx, mut dc_rx) = tokio::sync::mpsc::channel::<u8>(1);
        let (failure_tx, mut failure_rx) = tokio::sync::mpsc::channel(1);
        let (_peer_tx, mut peer_liveness) = PeerLiveness::channel(Duration::from_secs(1));
        let (mut deadline, mut progress_rx) =
            test_setup_deadline(Duration::from_secs(1), Duration::from_secs(2));
        failure_tx.try_send(()).unwrap();

        assert_eq!(
            wait_for_setup_data_channel(
                &mut dc_rx,
                &mut failure_rx,
                &mut peer_liveness,
                &DiscoveredDataChannel::default(),
                &mut deadline,
                &mut progress_rx,
                Duration::from_secs(1),
            )
            .await,
            Err(super::SetupWaitError::IceSetupFailed)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn native_open_datachannel_wins_before_open_notification_is_published() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (client, agent, _loopback_router) = new_loopback_peer_pair().await;
        let mut client_ice = capture_loopback_ice(&client);
        let mut agent_ice = capture_loopback_ice(&agent);
        agent.on_data_channel(Box::new(|_dc| Box::pin(async {})));

        let dc = client
            .create_data_channel("hydra-control", None)
            .await
            .expect("native DataChannel must be created");
        let discovered = DiscoveredDataChannel::default();
        discovered.observe(&dc);

        let (dc_tx, mut dc_rx) = tokio::sync::mpsc::channel(1);
        let (failure_tx, mut failure_rx) = tokio::sync::mpsc::channel(1);
        let (_peer_tx, mut peer_liveness) = PeerLiveness::channel(Duration::from_secs(1));
        let (mut deadline, mut progress_rx) =
            test_setup_deadline(Duration::from_millis(1), Duration::from_millis(2));
        failure_tx.try_send(()).unwrap();

        handshake_loopback_peers(&client, &agent, &mut client_ice, &mut agent_ice).await;
        tokio::time::timeout(Duration::from_secs(10), async {
            while dc.ready_state() != RTCDataChannelState::Open {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("native DataChannel must become Open");
        tokio::time::sleep(Duration::from_millis(3)).await;

        // Native Open retires setup-only failures/deadlines, but a broken on_open callback must not leak a serve
        // slot forever. Exercise that internal handoff bound before proving the successful delayed publication.
        assert!(matches!(
            tokio::time::timeout(
                Duration::from_millis(250),
                wait_for_setup_data_channel(
                    &mut dc_rx,
                    &mut failure_rx,
                    &mut peer_liveness,
                    &discovered,
                    &mut deadline,
                    &mut progress_rx,
                    Duration::from_millis(15),
                ),
            )
            .await
            .expect("native-open publication bound must itself be bounded"),
            Err(super::SetupWaitError::DataChannelPublicationTimeout)
        ));

        // The setup-only failure is already queued, while the native channel is Open and the on_open owner
        // notification is deliberately withheld. The waiter must remain alive for that publication.
        let discovered_for_wait = discovered.clone();
        let waiter = tokio::spawn(async move {
            wait_for_setup_data_channel(
                &mut dc_rx,
                &mut failure_rx,
                &mut peer_liveness,
                &discovered_for_wait,
                &mut deadline,
                &mut progress_rx,
                Duration::from_secs(1),
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(
            !waiter.is_finished(),
            "queued setup ICE failure must not defeat a native Open DataChannel"
        );

        dc_tx
            .send(dc.clone())
            .await
            .expect("withheld open notification must publish");
        let opened = waiter
            .await
            .expect("setup waiter must not panic")
            .expect("native Open DataChannel must win");
        assert!(Arc::ptr_eq(&opened, &dc));

        let _ = client.close().await;
        let _ = agent.close().await;
    }

    #[tokio::test]
    async fn failed_transport_ends_the_owner_immediately() {
        let (tx, mut liveness) = PeerLiveness::channel(Duration::from_secs(5));
        tx.send(PeerTransportEvent::Peer(RTCPeerConnectionState::Failed))
            .unwrap();

        let reason = tokio::time::timeout(Duration::from_millis(100), liveness.wait_until_dead())
            .await
            .expect("a failed peer must not wait for the disconnected grace");
        assert_eq!(reason, PeerCloseReason::PeerFailed);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn datachannel_close_ends_connected_owner_and_releases_serve_slot() {
        use crate::winsize_owner::{Owner, WinsizeOwner};

        struct DropMarker(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for DropMarker {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        // webrtc-rs/rustls needs one process-wide provider before its loopback DTLS handshake. No STUN/TURN
        // servers are configured below, so this test never depends on a public network.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (client, agent, _loopback_router) = new_loopback_peer_pair().await;
        let mut client_ice = capture_loopback_ice(&client);
        let mut agent_ice = capture_loopback_ice(&agent);

        let (liveness_tx, mut liveness) = PeerLiveness::channel(Duration::from_secs(5));
        let (agent_dc_tx, mut agent_dc_rx) = tokio::sync::mpsc::channel(1);
        {
            let liveness_tx = liveness_tx.clone();
            agent.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
                let liveness_tx = liveness_tx.clone();
                let agent_dc_tx = agent_dc_tx.clone();
                Box::pin(async move {
                    // Exercise the exact callback registration used by serve_session_inner.
                    register_datachannel_close_liveness(
                        &dc,
                        "loopback-close".to_string(),
                        liveness_tx,
                    );
                    let dc_weak = Arc::downgrade(&dc);
                    dc.on_open(Box::new(move || {
                        let dc_weak = dc_weak.clone();
                        let agent_dc_tx = agent_dc_tx.clone();
                        Box::pin(async move {
                            if let Some(dc) = dc_weak.upgrade() {
                                let _ = agent_dc_tx.send(dc).await;
                            }
                        })
                    }));
                })
            }));
        }
        // Keep the callback installed on the real agent DataChannel as the only producer used by this test.
        drop(liveness_tx);

        let client_dc = client
            .create_data_channel("hydra-control", None)
            .await
            .expect("client DataChannel must be created");
        let (client_open_tx, client_open_rx) = tokio::sync::oneshot::channel();
        client_dc.on_open(Box::new(move || {
            Box::pin(async move {
                let _ = client_open_tx.send(());
            })
        }));

        handshake_loopback_peers(&client, &agent, &mut client_ice, &mut agent_ice).await;
        let agent_dc = match tokio::time::timeout(Duration::from_secs(10), agent_dc_rx.recv()).await {
            Ok(Some(agent_dc)) => agent_dc,
            _ => panic!(
                "agent DataChannel must open; client peer={:?} ICE={:?}, agent peer={:?} ICE={:?}, client channel={:?}",
                client.connection_state(),
                client.ice_connection_state(),
                agent.connection_state(),
                agent.ice_connection_state(),
                client_dc.ready_state(),
            ),
        };
        tokio::time::timeout(Duration::from_secs(10), client_open_rx)
            .await
            .expect("client DataChannel must open")
            .expect("client DataChannel open callback must run");
        wait_for_connected_loopback_peer(&agent).await;

        let serving = Arc::new(AtomicUsize::new(0));
        let owner = Arc::new(Mutex::new(WinsizeOwner::new()));
        owner.lock().unwrap().set_remote_selected(Some(true));
        let slot = ServingSlot::acquire(serving.clone(), owner.clone());

        // Stand-ins for the two real owned serve tasks let the test run the factored production cleanup path and
        // prove it aborts+awaits both owners before the serve slot is released.
        let output_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let output_marker = DropMarker(output_dropped.clone());
        let (output_started_tx, output_started_rx) = tokio::sync::oneshot::channel();
        let output_task = tokio::spawn(async move {
            let _marker = output_marker;
            let _ = output_started_tx.send(());
            std::future::pending::<()>().await;
        });
        let mut daemon_output_forwarder = OwnedSessionTask::new("loopback output", output_task);

        let ice_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ice_marker = DropMarker(ice_dropped.clone());
        let (ice_started_tx, ice_started_rx) = tokio::sync::oneshot::channel();
        let ice_task = tokio::spawn(async move {
            let _marker = ice_marker;
            let _ = ice_started_tx.send(());
            std::future::pending::<()>().await;
        });
        let mut inbound_ice_pump = OwnedSessionTask::new("loopback ICE", ice_task);
        let outbound_dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let outbound_marker = DropMarker(outbound_dropped.clone());
        let (outbound_started_tx, outbound_started_rx) = tokio::sync::oneshot::channel();
        let outbound_task = tokio::spawn(async move {
            let _marker = outbound_marker;
            let _ = outbound_started_tx.send(());
            std::future::pending::<()>().await;
        });
        let mut outbound_owner = OwnedSessionTask::new("loopback outbound", outbound_task);
        output_started_rx.await.expect("output owner must start");
        ice_started_rx.await.expect("ICE owner must start");
        outbound_started_rx
            .await
            .expect("outbound owner must start");

        let bridge: SharedBridge = Arc::new(tokio::sync::Mutex::new(None));
        let (_graceful_wake, mut graceful_drain) = buffered_amount_low_channel();
        let (reason_tx, reason_rx) = tokio::sync::oneshot::channel();
        let (continue_cleanup_tx, continue_cleanup_rx) = tokio::sync::oneshot::channel();
        let agent_for_owner = agent.clone();
        let task = tokio::spawn(async move {
            let _slot = slot;
            let reason = liveness.wait_until_dead().await;
            let _ = reason_tx.send(reason);
            // Pause only so the assertion below can observe that the DataChannel alone closed. Production proceeds
            // directly into the same cleanup helper and then closes the PeerConnection in serve_session.
            let _ = continue_cleanup_rx.await;
            shutdown_session_resources(
                &agent_dc,
                &bridge,
                &mut daemon_output_forwarder,
                &mut outbound_owner,
                &mut inbound_ice_pump,
                &mut graceful_drain,
                false,
            )
            .await;
            let _ = agent_for_owner.close().await;
            reason
        });

        // Close from the remote end. webrtc-rs must deliver this through the real agent DataChannel's on_close;
        // no PeerTransportEvent is injected by the test.
        tokio::time::timeout(Duration::from_secs(5), client_dc.close())
            .await
            .expect("remote DataChannel close must complete")
            .expect("remote DataChannel close must succeed");
        let reason = tokio::time::timeout(Duration::from_secs(5), reason_rx)
            .await
            .expect("real on_close must end liveness without PC/ICE failure or disconnect grace")
            .expect("owner must report its close reason");
        assert_eq!(reason, PeerCloseReason::DataChannelClosed);
        assert_eq!(agent.connection_state(), RTCPeerConnectionState::Connected);
        assert!(
            matches!(
                agent.ice_connection_state(),
                RTCIceConnectionState::Connected | RTCIceConnectionState::Completed
            ),
            "ICE must remain healthy when only the DataChannel closes"
        );

        let _ = continue_cleanup_tx.send(());
        let joined_reason = tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("owner cleanup and PeerConnection close must be bounded")
            .expect("liveness owner task must not panic");
        assert_eq!(joined_reason, PeerCloseReason::DataChannelClosed);
        assert!(output_dropped.load(Ordering::Acquire));
        assert!(outbound_dropped.load(Ordering::Acquire));
        assert!(ice_dropped.load(Ordering::Acquire));
        assert_eq!(serving.load(Ordering::Relaxed), 0);
        assert_eq!(
            owner.lock().unwrap().effective(super::now_ms() + 10_001),
            Owner::Local,
            "serve-owner teardown must let the existing winsize grace return ownership local"
        );

        let _ = client.close().await;
    }

    #[tokio::test]
    async fn silent_half_open_releases_its_serve_slot_well_before_webrtc_default_failure() {
        use crate::winsize_owner::WinsizeOwner;

        // The owner-driven close (Disconnected detection + grace) must always beat the library's own terminal
        // `Failed` verdict, so slot/bridge/winsize release stays deterministic and owner-scoped.
        assert!(ICE_DISCONNECTED_TIMEOUT + PEER_DISCONNECTED_GRACE < ICE_FAILED_TIMEOUT);
        let serving = Arc::new(AtomicUsize::new(0));
        let owner = Arc::new(Mutex::new(WinsizeOwner::new()));
        let slot = ServingSlot::acquire(serving.clone(), owner);
        assert_eq!(serving.load(Ordering::Relaxed), 1);

        // Use the same owner/monitor path as production with a short injected grace so the test is bounded and does
        // not sleep for five seconds. No DataChannel close or webrtc-rs failed callback is supplied: this is the
        // silent-half-open case that previously retained the slot until the library's default timeout.
        let (tx, mut liveness) = PeerLiveness::channel(Duration::from_millis(15));
        let task = tokio::spawn(async move {
            let _slot = slot;
            liveness.wait_until_dead().await
        });
        tx.send(PeerTransportEvent::Peer(RTCPeerConnectionState::Connected))
            .unwrap();
        tx.send(PeerTransportEvent::Ice(RTCIceConnectionState::Disconnected))
            .unwrap();

        let reason = tokio::time::timeout(Duration::from_millis(500), task)
            .await
            .expect("half-open owner must finish under the deterministic bound")
            .expect("liveness owner task must not panic");
        assert_eq!(reason, PeerCloseReason::DisconnectedGraceExpired);
        assert_eq!(serving.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn transient_disconnect_recovery_cancels_teardown() {
        let (tx, mut liveness) = PeerLiveness::channel(Duration::from_millis(20));
        let task = tokio::spawn(async move { liveness.wait_until_dead().await });

        tx.send(PeerTransportEvent::Peer(RTCPeerConnectionState::Connected))
            .unwrap();
        tx.send(PeerTransportEvent::Ice(RTCIceConnectionState::Disconnected))
            .unwrap();
        tx.send(PeerTransportEvent::Ice(RTCIceConnectionState::Completed))
            .unwrap();

        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(
            !task.is_finished(),
            "Completed recovery must cancel the pending disconnect grace"
        );

        // Prove the same owner remains responsive and a later terminal state still closes it.
        tx.send(PeerTransportEvent::Ice(RTCIceConnectionState::Failed))
            .unwrap();
        let reason = tokio::time::timeout(Duration::from_millis(100), task)
            .await
            .expect("the recovered owner must still receive later state")
            .expect("liveness owner task must not panic");
        assert_eq!(reason, PeerCloseReason::IceFailed);
    }

    #[tokio::test]
    async fn inbound_ice_pump_is_cancelled_and_joined_on_owner_teardown() {
        struct DropMarker(Arc<std::sync::atomic::AtomicBool>);
        impl Drop for DropMarker {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let marker = DropMarker(dropped.clone());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _marker = marker;
            let _ = started_tx.send(());
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();

        let mut pump = OwnedSessionTask::new("test pending task", task);
        pump.shutdown().await;
        assert!(
            dropped.load(Ordering::Acquire),
            "shutdown must await cancellation until the polling future is dropped"
        );
        // Idempotent so the explicit teardown plus Drop cannot double-handle the task.
        pump.shutdown().await;
    }

    #[test]
    fn duplicate_disconnect_does_not_extend_the_original_grace() {
        let (_tx, mut liveness) = PeerLiveness::channel(Duration::from_secs(5));
        let started = tokio::time::Instant::now();
        assert_eq!(
            liveness.observe(
                PeerTransportEvent::Peer(RTCPeerConnectionState::Disconnected),
                started,
            ),
            None
        );
        let original_deadline = liveness.disconnected_deadline;
        assert_eq!(
            liveness.observe(
                PeerTransportEvent::Peer(RTCPeerConnectionState::Disconnected),
                started + Duration::from_secs(4),
            ),
            None
        );
        assert_eq!(liveness.disconnected_deadline, original_deadline);

        assert_eq!(
            liveness.observe(
                PeerTransportEvent::Peer(RTCPeerConnectionState::Connecting),
                started + Duration::from_secs(4),
            ),
            None
        );
        assert_eq!(
            liveness.disconnected_deadline, original_deadline,
            "an in-progress reconnect is not a successful recovery"
        );
    }

    #[tokio::test]
    async fn one_source_cannot_mask_the_other_sources_disconnect() {
        let (tx, mut liveness) = PeerLiveness::channel(Duration::from_millis(15));
        tx.send(PeerTransportEvent::Peer(
            RTCPeerConnectionState::Disconnected,
        ))
        .unwrap();
        // ICE can report Completed before the aggregate PeerConnection callback catches up. That must not cancel a
        // still-current PeerConnection Disconnected state.
        tx.send(PeerTransportEvent::Ice(RTCIceConnectionState::Completed))
            .unwrap();
        let reason = tokio::time::timeout(Duration::from_millis(500), liveness.wait_until_dead())
            .await
            .expect("remaining peer disconnect must still expire");
        assert_eq!(reason, PeerCloseReason::DisconnectedGraceExpired);
    }

    #[test]
    fn callback_after_owner_teardown_is_harmless() {
        let (tx, liveness) = PeerLiveness::channel(Duration::from_secs(5));
        drop(liveness);
        assert!(
            tx.send(PeerTransportEvent::Ice(RTCIceConnectionState::Failed))
                .is_err(),
            "stale callbacks are ignored once their owner is gone"
        );
    }

    #[tokio::test]
    async fn stale_datachannel_close_cannot_end_replacement_owner() {
        let (stale_tx, stale_owner) = PeerLiveness::channel(Duration::from_secs(5));
        drop(stale_owner);

        let (replacement_tx, mut replacement_owner) = PeerLiveness::channel(Duration::from_secs(5));
        let replacement_task =
            tokio::spawn(async move { replacement_owner.wait_until_dead().await });

        assert!(
            stale_tx
                .send(PeerTransportEvent::DataChannelClosed)
                .is_err(),
            "a closed DataChannel callback must lose authority with its serve owner"
        );
        tokio::task::yield_now().await;
        assert!(
            !replacement_task.is_finished(),
            "a stale owner callback must not reach the replacement liveness channel"
        );

        replacement_tx
            .send(PeerTransportEvent::DataChannelClosed)
            .unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_millis(100), replacement_task)
                .await
                .expect("replacement owner must receive its own close")
                .expect("replacement liveness task must not panic"),
            PeerCloseReason::DataChannelClosed
        );
    }

    #[test]
    fn serving_slot_serializes_atomic_count_with_owner_feed() {
        use crate::winsize_owner::{Owner, WinsizeOwner};

        let serving = Arc::new(AtomicUsize::new(0));
        let owner = Arc::new(Mutex::new(WinsizeOwner::new()));
        owner.lock().unwrap().set_remote_selected(Some(true));

        // While the owner mutex is held, acquire must not advance the atomic count ahead of the corresponding
        // set_serving feed. The worker first proves it sees our held lock, then enters acquire and blocks on it.
        let owner_guard = owner.lock().unwrap();
        let (acquire_started_tx, acquire_started_rx) = std::sync::mpsc::channel();
        let acquire_serving = serving.clone();
        let acquire_owner = owner.clone();
        let acquire_thread = std::thread::spawn(move || {
            assert!(acquire_owner.try_lock().is_err());
            acquire_started_tx.send(()).unwrap();
            ServingSlot::acquire(acquire_serving, acquire_owner)
        });
        acquire_started_rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(
            serving.load(Ordering::Relaxed),
            0,
            "acquire count must wait for the owner mutex"
        );
        drop(owner_guard);
        let slot = acquire_thread.join().unwrap();
        assert_eq!(serving.load(Ordering::Relaxed), 1);

        // Drop has the same ordering: it may not publish zero until it can feed zero to the owner under that lock.
        let owner_guard = owner.lock().unwrap();
        let owner_for_drop = owner.clone();
        let (drop_started_tx, drop_started_rx) = std::sync::mpsc::channel();
        let drop_thread = std::thread::spawn(move || {
            assert!(owner_for_drop.try_lock().is_err());
            drop_started_tx.send(()).unwrap();
            drop(slot);
        });
        drop_started_rx.recv().unwrap();
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(
            serving.load(Ordering::Relaxed),
            1,
            "release count must wait for the owner mutex"
        );
        drop(owner_guard);
        drop_thread.join().unwrap();
        assert_eq!(serving.load(Ordering::Relaxed), 0);
        assert_eq!(
            owner.lock().unwrap().effective(super::now_ms() + 10_001),
            Owner::Local,
            "the final ordered zero feed must let the existing winsize grace expire"
        );
    }

    #[test]
    fn serving_slot_release_fails_safe_instead_of_underflowing() {
        use crate::winsize_owner::WinsizeOwner;

        let serving = Arc::new(AtomicUsize::new(0));
        let owner = Arc::new(Mutex::new(WinsizeOwner::new()));
        drop(ServingSlot {
            serving: serving.clone(),
            owner,
        });
        assert_eq!(serving.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn serving_feed_updates_shared_owner_effective() {
        // Mirrors the run_remote_peer feed: on connect we set_serving(count) with the incremented counter; on drop we
        // set_serving with the decremented counter. With remote selected, effective tracks connected → grace → local.
        use crate::winsize_owner::{Owner, WinsizeOwner};
        let serving = Arc::new(AtomicUsize::new(0));
        let owner = Arc::new(Mutex::new(WinsizeOwner::new()));
        owner.lock().unwrap().set_remote_selected(Some(true)); // user picked Remote (manual override)

        // Peer connects: fetch_add THEN feed the new count (as run_remote_peer does).
        serving.fetch_add(1, Ordering::Relaxed);
        owner
            .lock()
            .unwrap()
            .set_serving(serving.load(Ordering::Relaxed), 0);
        assert_eq!(owner.lock().unwrap().effective(0), Owner::Remote); // serving>0 + selected

        // Peer drops at t=1000: fetch_sub THEN feed the decremented count → grace starts.
        serving.fetch_sub(1, Ordering::Relaxed);
        owner
            .lock()
            .unwrap()
            .set_serving(serving.load(Ordering::Relaxed), 1_000);
        assert_eq!(owner.lock().unwrap().effective(1_000), Owner::Remote); // within grace
        assert_eq!(
            owner.lock().unwrap().effective(1_000 + 10_000),
            Owner::Local
        ); // grace expired
    }
}
