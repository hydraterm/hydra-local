//! S3c-wiring — agent-side S3a signaling client. The agent is the signaling TARGET: it polls the cloud
//! for pending offers addressed to it, posts its SDP answer, and trickles/fetches ICE candidates. Talks
//! ONLY the documented S3a endpoints over HTTP(S). In dev, it can use a `dev:<acct>` bearer. In prod, it
//! signs each request with the enrolled device key; the cloud verifies that signature against the stored
//! public key and derives account authority from the device record. Opaque SDP/ICE blobs only; NO terminal
//! data ever here.

use ed25519_dalek::SigningKey;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

const RELAY_CREDENTIAL_REFRESH_MARGIN_MS: u64 = 30_000;
const RELAY_CREDENTIAL_MAX_TTL_MS: u64 = 120_000;
const MAX_RELAY_URLS: usize = 8;
const MAX_STUN_URLS: usize = 8;
const MAX_ICE_URI_BYTES: usize = 2_048;
const MAX_RELAY_USERNAME_BYTES: usize = 512;
const MAX_RELAY_CREDENTIAL_BYTES: usize = 2_048;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
/// Rolling-upgrade-safe pending-offer hold requested from a capable cloud. Older clouds ignore the additive query
/// parameter and return immediately; the outer poll loop retains its one-second empty-cycle floor in that case.
const PENDING_OFFER_WAIT_MS: u64 = 6_000;

/// A pending signaling session addressed to this device (the agent answers it).
#[derive(Debug, Clone, serde::Deserialize)]
pub struct PendingSession {
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "sourceDeviceId")]
    pub source_device_id: String,
    pub offer: String,
}

/// The account's live revocation state, polled by the agent so it can close an already-connected browser's
/// channel mid-session (before the token's 10-min expiry) when the browser / this desktop / the account is
/// revoked. Content-blind: device ids + a boolean, never terminal data / tokens / keys.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Deserialize)]
pub struct Revocations {
    #[serde(rename = "selfRevoked")]
    pub self_revoked: bool,
    #[serde(rename = "revokedDeviceIds")]
    pub revoked_device_ids: Vec<String>,
    /// #20 account revoke-before marker (0 if unset): a connection whose token iat_ms <= this is closed.
    #[serde(rename = "revokeBeforeMs", default)]
    pub revoke_before_ms: u64,
}

/// An authenticated cloud denial that permanently removes this enrolled desktop's authority. The status/body
/// pairs are deliberately exact so an ordinary 404, proxy error, or malformed response cannot revoke locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationTerminalDenial {
    UnknownDevice,
    Revoked,
}

/// Result of a live-revocation poll. Terminal device denials are data, not transport errors, so the poller can
/// fail closed for those two exact cloud responses while retaining its prior snapshot for every transient error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationPoll {
    Snapshot(Revocations),
    TerminalDenial(RevocationTerminalDenial),
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationDenialBody {
    error: String,
}

fn terminal_revocation_denial(status: u16, body: &str) -> Option<RevocationTerminalDenial> {
    let denial: RevocationDenialBody = serde_json::from_str(body).ok()?;
    match (status, denial.error.as_str()) {
        (404, "unknown_device") => Some(RevocationTerminalDenial::UnknownDevice),
        (403, "revoked") => Some(RevocationTerminalDenial::Revoked),
        _ => None,
    }
}

/// One peer ICE candidate (opaque blob) + its sequence.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct IceCandidate {
    pub candidate: String,
    pub seq: u64,
}

/// Candidate polling distinguishes an untrusted successful response whose JSON/shape is malformed from a
/// transient request/HTTP failure. The remote-peer setup owner may retry transport failures, but it must retire a
/// pre-open attempt whose broker response cannot be validated without guessing a cursor or candidate prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchIceError {
    Transient(String),
    Protocol(String),
    Terminal(String),
}

impl std::fmt::Display for FetchIceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transient(message) | Self::Protocol(message) | Self::Terminal(message) => {
                f.write_str(message)
            }
        }
    }
}

impl std::error::Error for FetchIceError {}

/// S3a client. `base` is like `https://api.hydraterms.com`; `auth` is the bearer for dev
/// (`dev:<acct>`). In prod, `device_key` is present and requests are device-signed instead.
pub struct AgentSignaling {
    base: String,
    auth: String,
    device_id: String,
    device_key: Option<SigningKey>,
    client: reqwest::Client,
    /// TURN credentials only. Signaling sessions, Hydra tokens, SDP, ICE, and account credentials are never
    /// cached. One owner performs the bounded HTTP request while concurrent callers wait on its exact result;
    /// there is no detached task and a cancelled owner wakes every waiter fail-closed.
    relay_credential_cache: RelayCredentialCache,
}

impl AgentSignaling {
    pub fn new(base: String, auth: String, device_id: String) -> Self {
        Self::new_with_device_key(base, auth, device_id, None)
    }

    pub fn new_with_device_key(
        base: String,
        auth: String,
        device_id: String,
        device_key: Option<SigningKey>,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        AgentSignaling {
            base,
            auth,
            device_id,
            device_key,
            client,
            relay_credential_cache: RelayCredentialCache::new(),
        }
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<(u16, String), String> {
        let body = body.unwrap_or("");
        let url = format!("{}{}", self.base.trim_end_matches('/'), path);
        let method_parsed = method
            .parse::<reqwest::Method>()
            .map_err(|e| format!("bad method {method}: {e}"))?;
        let mut req = self.client.request(method_parsed, &url);
        if let Some(key) = &self.device_key {
            for (k, v) in
                crate::device_request_auth::signed_headers(method, path, body, &self.device_id, key)
            {
                req = req.header(k, v);
            }
        } else {
            req = req.header("authorization", format!("Bearer {}", self.auth));
        }
        if method != "GET" {
            req = req
                .header("content-type", "application/json")
                .body(body.to_string());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("request {method} {path}: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| format!("read response: {e}"))?;
        Ok((status, text))
    }
}

impl AgentSignaling {
    /// Poll pending offers addressed to this agent device.
    pub async fn pending(&self) -> Result<Vec<PendingSession>, String> {
        let path = format!(
            "/v1/signal/sessions/pending?deviceId={}&waitMs={PENDING_OFFER_WAIT_MS}",
            url_enc(&self.device_id),
        );
        let (status, body) = self.request("GET", &path, None).await?;
        if status != 200 {
            return Err(format!("pending: HTTP {status}"));
        }
        #[derive(serde::Deserialize)]
        struct Resp {
            sessions: Vec<PendingSession>,
        }
        let parsed: Resp =
            serde_json::from_str(&body).map_err(|e| format!("pending parse: {e}"))?;
        Ok(parsed.sessions)
    }

    /// Poll this account's live revocation state (device-signed). Returns whether THIS desktop is revoked and
    /// the set of the account's revoked device ids — so the agent can close an already-connected browser's
    /// channel mid-session (before token expiry) when that browser/account/desktop is revoked.
    pub async fn fetch_revocations(&self) -> Result<RevocationPoll, String> {
        let path = format!(
            "/v1/devices/revocations?deviceId={}",
            url_enc(&self.device_id)
        );
        let (status, body) = self.request("GET", &path, None).await?;
        if status != 200 {
            if let Some(denial) = terminal_revocation_denial(status, &body) {
                return Ok(RevocationPoll::TerminalDenial(denial));
            }
            return Err(format!("revocations: HTTP {status}"));
        }
        serde_json::from_str(&body)
            .map(RevocationPoll::Snapshot)
            .map_err(|e| format!("revocations parse: {e}"))
    }

    /// Post this agent's SDP answer for a session.
    pub async fn answer(&self, session_id: &str, answer_sdp: &str) -> Result<(), String> {
        let path = format!("/v1/signal/sessions/{}/answer", url_enc(session_id));
        let body =
            serde_json::json!({ "deviceId": self.device_id, "answer": answer_sdp }).to_string();
        let (status, _) = self.request("POST", &path, Some(&body)).await?;
        if !(200..300).contains(&status) {
            return Err(format!("answer: HTTP {status}"));
        }
        Ok(())
    }

    /// Trickle one ICE candidate (opaque) to the peer.
    pub async fn post_ice(&self, session_id: &str, candidate: &str) -> Result<(), String> {
        let path = format!("/v1/signal/sessions/{}/ice", url_enc(session_id));
        let body =
            serde_json::json!({ "deviceId": self.device_id, "candidate": candidate }).to_string();
        let (status, _) = self.request("POST", &path, Some(&body)).await?;
        if !(200..300).contains(&status) {
            return Err(format!("post_ice: HTTP {status}"));
        };
        Ok(())
    }

    /// Fetch short-lived relay (TURN) credentials for `device_id` from the cloud (S3c). The agent needs
    /// these so it can present RELAY candidates — required for a relay-only peer to connect. Returns
    /// `RelayCreds` (TURN urls/username/credential + our-host STUN urls) or None if the cloud has no relay
    /// configured / refuses. The STUN urls are on OUR relay host — never a public third party.
    pub async fn relay_creds(&self) -> Option<RelayCreds> {
        match self.relay_credential_cache.begin(RelayCacheTime::now()) {
            RelayCredentialCacheAction::Ready(creds) => Some(creds),
            RelayCredentialCacheAction::Wait(mut result) => loop {
                if let Some(value) = result.borrow().clone() {
                    break value;
                }
                if result.changed().await.is_err() {
                    break None;
                }
            },
            RelayCredentialCacheAction::Load(load_id) => {
                let mut owner =
                    RelayCredentialLoadOwner::new(&self.relay_credential_cache, load_id);
                let result = self.fetch_relay_creds_uncached().await;
                let published =
                    self.relay_credential_cache
                        .complete(load_id, result, RelayCacheTime::now());
                owner.complete();
                published
            }
        }
    }

    async fn fetch_relay_creds_uncached(&self) -> Option<ParsedRelayCreds> {
        let body =
            serde_json::json!({ "deviceId": self.device_id, "responseVersion": 2 }).to_string();
        let (status, resp) = self
            .request("POST", "/v1/relay/creds", Some(&body))
            .await
            .ok()?;
        if status != 200 {
            return None;
        }
        let v: serde_json::Value = serde_json::from_str(&resp).ok()?;
        parse_relay_creds(&v)
    }

    /// Fetch the peer's ICE candidates since `since`; returns (candidates, next_since).
    pub async fn fetch_ice(
        &self,
        session_id: &str,
        since: u64,
    ) -> Result<(Vec<IceCandidate>, u64), FetchIceError> {
        let path = format!(
            "/v1/signal/sessions/{}/ice?deviceId={}&since={since}",
            url_enc(session_id),
            url_enc(&self.device_id)
        );
        let (status, body) = self
            .request("GET", &path, None)
            .await
            .map_err(FetchIceError::Transient)?;
        if status != 200 {
            let message = format!("fetch_ice: HTTP {status}");
            return Err(if matches!(status, 408 | 425 | 429 | 500..=599) {
                FetchIceError::Transient(message)
            } else {
                // Session-dead, auth, quota/protocol, and unexpected statuses cannot become valid by advancing or
                // retaining this setup owner's cursor. Fail closed and let a fresh signaling session reconnect.
                FetchIceError::Terminal(message)
            });
        }
        #[derive(serde::Deserialize)]
        struct Resp {
            candidates: Vec<IceCandidate>,
            #[serde(rename = "nextSince")]
            next_since: u64,
        }
        let parsed: Resp = serde_json::from_str(&body)
            .map_err(|e| FetchIceError::Protocol(format!("ice parse: {e}")))?;
        Ok((parsed.candidates, parsed.next_since))
    }
}

/// Parsed `/v1/relay/creds` response: TURN creds plus STUN urls on our own relay host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCreds {
    pub urls: Vec<String>,
    pub username: String,
    pub credential: String,
    /// STUN urls on OUR relay host (coturn serves STUN too). No credentials. Empty ⇒ no STUN offered.
    pub stun_urls: Vec<String>,
    /// Server-authoritative wall-clock expiry retained for coturn/API compatibility, never cache freshness.
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedRelayCreds {
    credentials: RelayCreds,
    /// Missing or malformed relative TTL remains usable once but is deliberately non-cacheable.
    cache_ttl_ms: Option<u64>,
}

type RelayLoadResult = Option<RelayCreds>;

#[derive(Clone, Copy)]
struct RelayCacheTime {
    monotonic: Instant,
    wall: SystemTime,
}

impl RelayCacheTime {
    fn now() -> Self {
        Self {
            monotonic: Instant::now(),
            wall: SystemTime::now(),
        }
    }
}

struct RelayCredentialCache {
    inner: Mutex<RelayCredentialCacheInner>,
}

struct RelayCredentialCacheInner {
    next_load_id: u64,
    state: RelayCredentialCacheState,
}

enum RelayCredentialCacheState {
    Empty,
    Ready {
        credentials: RelayCreds,
        refresh_at: Instant,
        load_started_at_wall: SystemTime,
        usable_window: Duration,
    },
    Loading {
        load_id: u64,
        load_started_at: RelayCacheTime,
        result: tokio::sync::watch::Sender<Option<RelayLoadResult>>,
    },
}

enum RelayCredentialCacheAction {
    Ready(RelayCreds),
    Wait(tokio::sync::watch::Receiver<Option<RelayLoadResult>>),
    Load(u64),
}

impl RelayCredentialCache {
    fn new() -> Self {
        Self {
            inner: Mutex::new(RelayCredentialCacheInner {
                next_load_id: 0,
                state: RelayCredentialCacheState::Empty,
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RelayCredentialCacheInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn begin(&self, now: RelayCacheTime) -> RelayCredentialCacheAction {
        let mut inner = self.lock();
        if let RelayCredentialCacheState::Ready {
            credentials,
            refresh_at,
            load_started_at_wall,
            usable_window,
        } = &inner.state
        {
            if *refresh_at > now.monotonic
                && wall_window_open(*load_started_at_wall, now.wall, *usable_window)
            {
                return RelayCredentialCacheAction::Ready(credentials.clone());
            }
            // Once the monotonic deadline is reached, a denied/malformed refresh cannot restore this value.
            inner.state = RelayCredentialCacheState::Empty;
        }
        if let RelayCredentialCacheState::Loading { result, .. } = &inner.state {
            return RelayCredentialCacheAction::Wait(result.subscribe());
        }
        inner.next_load_id = inner.next_load_id.wrapping_add(1).max(1);
        let load_id = inner.next_load_id;
        let (result, _) = tokio::sync::watch::channel(None);
        inner.state = RelayCredentialCacheState::Loading {
            load_id,
            load_started_at: now,
            result,
        };
        RelayCredentialCacheAction::Load(load_id)
    }

    fn complete(
        &self,
        load_id: u64,
        candidate: Option<ParsedRelayCreds>,
        now: RelayCacheTime,
    ) -> RelayLoadResult {
        let mut inner = self.lock();
        let old_state = std::mem::replace(&mut inner.state, RelayCredentialCacheState::Empty);
        let RelayCredentialCacheState::Loading {
            load_id: current_id,
            load_started_at,
            result,
        } = old_state
        else {
            inner.state = old_state;
            return None;
        };
        if current_id != load_id {
            inner.state = RelayCredentialCacheState::Loading {
                load_id: current_id,
                load_started_at,
                result,
            };
            return None;
        }
        let cache_value = candidate.as_ref().and_then(|parsed| {
            relay_cache_window(load_started_at.monotonic, parsed.cache_ttl_ms)
                .filter(|(refresh_at, usable_window)| {
                    *refresh_at > now.monotonic
                        && wall_window_open(load_started_at.wall, now.wall, *usable_window)
                })
                .map(|(refresh_at, usable_window)| {
                    (parsed.credentials.clone(), refresh_at, usable_window)
                })
        });
        let published = candidate.map(|parsed| parsed.credentials);
        inner.state = cache_value.map_or(
            RelayCredentialCacheState::Empty,
            |(credentials, refresh_at, usable_window)| RelayCredentialCacheState::Ready {
                credentials,
                refresh_at,
                load_started_at_wall: load_started_at.wall,
                usable_window,
            },
        );
        result.send_replace(Some(published.clone()));
        published
    }

    fn cancel(&self, load_id: u64) {
        let mut inner = self.lock();
        let old_state = std::mem::replace(&mut inner.state, RelayCredentialCacheState::Empty);
        let RelayCredentialCacheState::Loading {
            load_id: current_id,
            load_started_at,
            result,
        } = old_state
        else {
            inner.state = old_state;
            return;
        };
        if current_id == load_id {
            // The request future was cancelled with its caller. Wake existing waiters with the shared fail-closed
            // result; a later independent caller may begin a fresh bounded request.
            result.send_replace(Some(None));
        } else {
            inner.state = RelayCredentialCacheState::Loading {
                load_id: current_id,
                load_started_at,
                result,
            };
        }
    }
}

struct RelayCredentialLoadOwner<'a> {
    cache: &'a RelayCredentialCache,
    load_id: u64,
    completed: bool,
}

impl<'a> RelayCredentialLoadOwner<'a> {
    fn new(cache: &'a RelayCredentialCache, load_id: u64) -> Self {
        Self {
            cache,
            load_id,
            completed: false,
        }
    }

    fn complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for RelayCredentialLoadOwner<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.cache.cancel(self.load_id);
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayCredsEnvelope {
    credentials: Option<RelayCredsWire>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RelayCredsWire {
    urls: Vec<String>,
    username: String,
    credential: String,
    expires_at_ms: u64,
    #[serde(default)]
    stun_urls: Vec<String>,
    #[serde(default)]
    ttl_ms: Option<serde_json::Value>,
}

/// Pure parse of a `/v1/relay/creds` response body, including optional negotiated cache metadata. Split out
/// of `relay_creds` so the connectivity-critical shape is testable without a live server: a credential shape
/// deviation silently disables RELAY. `stunUrls` and `ttlMs` are optional for rolling compatibility; a missing
/// or malformed ttl keeps otherwise valid credentials usable once but never cacheable.
fn parse_relay_creds(v: &serde_json::Value) -> Option<ParsedRelayCreds> {
    let c = serde_json::from_value::<RelayCredsEnvelope>(v.clone())
        .ok()?
        .credentials?;
    if c.urls.is_empty()
        || c.urls.len() > MAX_RELAY_URLS
        || c.stun_urls.len() > MAX_STUN_URLS
        || !c.urls.iter().all(|url| approved_ice_uri(url, true))
        || !c.stun_urls.iter().all(|url| approved_ice_uri(url, false))
        || !bounded_nonempty(&c.username, MAX_RELAY_USERNAME_BYTES)
        || !bounded_nonempty(&c.credential, MAX_RELAY_CREDENTIAL_BYTES)
        || c.expires_at_ms > MAX_SAFE_INTEGER
    {
        return None;
    }
    let cache_ttl_ms = c.ttl_ms.and_then(|value| value.as_u64());
    Some(ParsedRelayCreds {
        credentials: RelayCreds {
            urls: c.urls,
            username: c.username,
            credential: c.credential,
            stun_urls: c.stun_urls,
            expires_at_ms: c.expires_at_ms,
        },
        cache_ttl_ms,
    })
}

fn relay_cache_window(
    load_started_at: Instant,
    ttl_ms: Option<u64>,
) -> Option<(Instant, Duration)> {
    let ttl_ms = ttl_ms?;
    if ttl_ms <= RELAY_CREDENTIAL_REFRESH_MARGIN_MS || ttl_ms > RELAY_CREDENTIAL_MAX_TTL_MS {
        return None;
    }
    let usable_window = Duration::from_millis(ttl_ms - RELAY_CREDENTIAL_REFRESH_MARGIN_MS);
    load_started_at
        .checked_add(usable_window)
        .map(|refresh_at| (refresh_at, usable_window))
}

fn wall_window_open(load_started_at: SystemTime, now: SystemTime, usable_window: Duration) -> bool {
    match now.duration_since(load_started_at) {
        Ok(elapsed) => elapsed < usable_window,
        // Fail closed: some monotonic clocks pause across suspend, so a backward wall jump must not
        // leave an expired credential looking fresh after wake.
        Err(_) => false,
    }
}

fn bounded_nonempty(value: &str, max_bytes: usize) -> bool {
    !value.is_empty() && value.trim() == value && value.len() <= max_bytes
}

fn approved_ice_uri(value: &str, turn: bool) -> bool {
    if value.is_empty()
        || value.trim() != value
        || value.len() > MAX_ICE_URI_BYTES
        || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return false;
    }
    let Some((scheme, remainder)) = value.split_once(':') else {
        return false;
    };
    if (turn && !matches!(scheme, "turn" | "turns"))
        || (!turn && !matches!(scheme, "stun" | "stuns"))
        || remainder.is_empty()
        || remainder.starts_with("//")
        || remainder.contains(['#', '@'])
    {
        return false;
    }
    let (target, query) = remainder
        .split_once('?')
        .map_or((remainder, None), |(target, query)| (target, Some(query)));
    if target.is_empty() || target.contains(['/', '?']) {
        return false;
    }
    if turn {
        query.is_none() || matches!(query, Some("transport=udp" | "transport=tcp"))
    } else {
        query.is_none()
    }
}

/// Minimal URL-encoding for path/query ids (ids are `dev_<uuid>` / `sig_<uuid>` — alnum + `_-`).
fn url_enc(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.') {
                c.to_string()
            } else {
                format!("%{:02X}", c as u32)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_enc_passes_ids_and_escapes_others() {
        assert_eq!(url_enc("dev_abc-123"), "dev_abc-123");
        assert_eq!(url_enc("a b"), "a%20b");
    }

    #[test]
    fn https_base_is_allowed_now() {
        let s = AgentSignaling::new("https://x".into(), "a".into(), "d".into());
        assert_eq!(s.base, "https://x");
    }

    #[test]
    fn revocation_denial_requires_the_exact_status_and_body_shape() {
        assert_eq!(
            terminal_revocation_denial(404, r#"{"error":"unknown_device"}"#),
            Some(RevocationTerminalDenial::UnknownDevice)
        );
        assert_eq!(
            terminal_revocation_denial(403, r#"{"error":"revoked"}"#),
            Some(RevocationTerminalDenial::Revoked)
        );

        for (status, body) in [
            (404, "not found"),
            (404, r#"{"error":"not_found"}"#),
            (404, r#"{"error":"unknown_device","detail":"proxy"}"#),
            (404, r#"{"error":"not_found","error":"unknown_device"}"#),
            (403, r#"{"error":"unknown_device"}"#),
            (404, r#"{"error":"revoked"}"#),
            (500, r#"{"error":"unknown_device"}"#),
        ] {
            assert_eq!(terminal_revocation_denial(status, body), None);
        }
    }

    #[test]
    fn parse_relay_creds_reads_the_well_formed_shape() {
        let v = serde_json::json!({
            "credentials": {
                "urls": ["turn:relay.example:3478", "turns:relay.example:5349"],
                "username": "u-synthetic",
                "credential": "c-synthetic",
                "expiresAtMs": 9_999_999_999_999_u64,
            }
        });
        let parsed = parse_relay_creds(&v).expect("well-formed creds parse");
        let creds = parsed.credentials;
        assert_eq!(
            creds.urls,
            vec!["turn:relay.example:3478", "turns:relay.example:5349"]
        );
        assert_eq!(creds.username, "u-synthetic");
        assert_eq!(creds.credential, "c-synthetic");
        assert_eq!(creds.expires_at_ms, 9_999_999_999_999);
        assert!(creds.stun_urls.is_empty()); // no stunUrls field → defaults to empty (host + TURN only)
        assert_eq!(parsed.cache_ttl_ms, None); // legacy cloud response → use once, never cache
    }

    #[test]
    fn parse_relay_creds_reads_stun_urls_when_present() {
        let v = serde_json::json!({
            "credentials": {
                "urls": ["turns:relay.example:5349"],
                "username": "u",
                "credential": "c",
                "expiresAtMs": 9_999_999_999_999_u64,
                "stunUrls": ["stun:relay.example:3478", "stun:relay.example:5349"],
            }
        });
        let creds = parse_relay_creds(&v).expect("parse").credentials;
        // our-host STUN urls are read exactly.
        assert_eq!(
            creds.stun_urls,
            vec!["stun:relay.example:3478", "stun:relay.example:5349"]
        );
    }

    #[test]
    fn parse_relay_creds_accepts_only_ttl_as_additive_metadata() {
        let v = serde_json::json!({
            "credentials": {
                "urls": ["turns:relay.example:5349"],
                "username": "u",
                "credential": "c",
                "expiresAtMs": 1_u64,
                "ttlMs": 120_000_u64,
            }
        });
        let parsed = parse_relay_creds(&v).expect("versioned response parses");
        assert_eq!(parsed.credentials.expires_at_ms, 1);
        assert_eq!(parsed.cache_ttl_ms, Some(120_000));

        let malformed_ttl = serde_json::json!({
            "credentials": {
                "urls": ["turns:relay.example:5349"],
                "username": "u",
                "credential": "c",
                "expiresAtMs": 1_u64,
                "ttlMs": "120000",
            }
        });
        let parsed = parse_relay_creds(&malformed_ttl).expect("credentials remain usable once");
        assert_eq!(parsed.cache_ttl_ms, None);
    }

    #[test]
    fn parse_relay_creds_returns_none_on_a_missing_or_wrong_shape() {
        // each of these would SILENTLY disable relay if mis-parsed — pin that they map to None, not a panic.
        let cases = [
            serde_json::json!({}),                    // no credentials
            serde_json::json!({ "credentials": {} }), // no urls/username/credential
            serde_json::json!({ "credentials": { "urls": "not-an-array", "username": "u", "credential": "c", "expiresAtMs": 9_999_999_999_999_u64 } }),
            serde_json::json!({ "credentials": { "urls": ["turn:r"], "credential": "c", "expiresAtMs": 9_999_999_999_999_u64 } }), // missing username
            serde_json::json!({ "credentials": { "urls": ["turn:r"], "username": "u", "expiresAtMs": 9_999_999_999_999_u64 } }), // missing credential
            serde_json::json!({ "credentials": { "urls": ["turn:r"], "username": "u", "credential": "c" } }), // missing expiry
            serde_json::json!({ "credentials": { "urls": ["turn:r"], "username": "u", "credential": "c", "expiresAtMs": 9_999_999_999_999_u64, "extra": true } }),
            serde_json::json!({ "credentials": { "urls": ["https://not-turn"], "username": "u", "credential": "c", "expiresAtMs": 9_999_999_999_999_u64 } }),
            serde_json::json!({ "credentials": { "urls": ["turn:r"], "username": "u", "credential": "c", "expiresAtMs": 9_999_999_999_999_u64, "stunUrls": ["turn:not-stun"] } }),
        ];
        for v in cases {
            assert!(parse_relay_creds(&v).is_none(), "expected None for {v}");
        }
    }

    #[test]
    fn parse_relay_creds_rejects_mixed_url_entries() {
        let v = serde_json::json!({
            "credentials": { "urls": ["turn:a", 42, null, "turns:b"], "username": "u", "credential": "c", "expiresAtMs": 9_999_999_999_999_u64 }
        });
        assert!(parse_relay_creds(&v).is_none());
    }

    #[test]
    fn cache_deadline_uses_load_start_and_the_exact_relative_ttl_bounds() {
        let start = Instant::now();
        assert_eq!(
            relay_cache_window(start, Some(120_000)),
            start
                .checked_add(Duration::from_millis(90_000))
                .map(|deadline| (deadline, Duration::from_millis(90_000)))
        );
        assert!(relay_cache_window(start, None).is_none());
        assert!(relay_cache_window(start, Some(30_000)).is_none());
        assert!(relay_cache_window(start, Some(120_001)).is_none());
    }

    #[test]
    fn network_latency_consumes_the_monotonic_cache_window() {
        let cache = RelayCredentialCache::new();
        let load_started_at = Instant::now();
        let load_started = RelayCacheTime {
            monotonic: load_started_at,
            wall: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
        };
        let RelayCredentialCacheAction::Load(load_id) = cache.begin(load_started) else {
            panic!("expected load owner");
        };
        let credentials = RelayCreds {
            urls: vec!["turn:relay.example:3478".into()],
            username: "synthetic-user".into(),
            credential: "synthetic-secret".into(),
            stun_urls: Vec::new(),
            expires_at_ms: 1,
        };
        let parsed = ParsedRelayCreds {
            credentials: credentials.clone(),
            cache_ttl_ms: Some(120_000),
        };

        let response_at = RelayCacheTime {
            monotonic: load_started_at + Duration::from_millis(80_000),
            wall: load_started.wall + Duration::from_millis(80_000),
        };
        assert_eq!(
            cache.complete(load_id, Some(parsed), response_at),
            Some(credentials)
        );
        assert!(matches!(
            cache.begin(RelayCacheTime {
                monotonic: load_started_at + Duration::from_millis(89_999),
                wall: load_started.wall + Duration::from_millis(89_999),
            }),
            RelayCredentialCacheAction::Ready(_)
        ));
        assert!(matches!(
            cache.begin(RelayCacheTime {
                monotonic: load_started_at + Duration::from_millis(90_000),
                wall: load_started.wall + Duration::from_millis(90_000),
            }),
            RelayCredentialCacheAction::Load(_)
        ));
    }

    #[test]
    fn a_response_after_the_cache_window_is_returned_once_but_not_cached() {
        let cache = RelayCredentialCache::new();
        let started = RelayCacheTime {
            monotonic: Instant::now(),
            wall: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
        };
        let RelayCredentialCacheAction::Load(load_id) = cache.begin(started) else {
            panic!("expected load owner");
        };
        let credentials = RelayCreds {
            urls: vec!["turn:relay.example:3478".into()],
            username: "synthetic-user".into(),
            credential: "synthetic-secret".into(),
            stun_urls: Vec::new(),
            expires_at_ms: 1,
        };
        let parsed = ParsedRelayCreds {
            credentials: credentials.clone(),
            cache_ttl_ms: Some(120_000),
        };
        let late = RelayCacheTime {
            monotonic: started.monotonic + Duration::from_millis(90_000),
            wall: started.wall + Duration::from_millis(90_000),
        };

        assert_eq!(
            cache.complete(load_id, Some(parsed), late),
            Some(credentials)
        );
        assert!(matches!(
            cache.begin(late),
            RelayCredentialCacheAction::Load(_)
        ));
    }

    #[test]
    fn suspend_like_wall_elapsed_expires_a_cache_when_monotonic_time_pauses() {
        let cache = RelayCredentialCache::new();
        let started = RelayCacheTime {
            monotonic: Instant::now(),
            wall: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
        };
        let RelayCredentialCacheAction::Load(load_id) = cache.begin(started) else {
            panic!("expected load owner");
        };
        let parsed = ParsedRelayCreds {
            credentials: RelayCreds {
                urls: vec!["turn:relay.example:3478".into()],
                username: "synthetic-user".into(),
                credential: "synthetic-secret".into(),
                stun_urls: Vec::new(),
                expires_at_ms: 1,
            },
            cache_ttl_ms: Some(120_000),
        };
        assert!(cache.complete(load_id, Some(parsed), started).is_some());

        assert!(matches!(
            cache.begin(RelayCacheTime {
                monotonic: started.monotonic + Duration::from_millis(1),
                wall: started.wall + Duration::from_millis(90_000),
            }),
            RelayCredentialCacheAction::Load(_)
        ));
    }

    #[test]
    fn backward_wall_jump_with_paused_monotonic_time_requires_a_fresh_load() {
        let cache = RelayCredentialCache::new();
        let started = RelayCacheTime {
            monotonic: Instant::now(),
            wall: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
        };
        let RelayCredentialCacheAction::Load(load_id) = cache.begin(started) else {
            panic!("expected load owner");
        };
        let parsed = ParsedRelayCreds {
            credentials: RelayCreds {
                urls: vec!["turn:relay.example:3478".into()],
                username: "synthetic-user".into(),
                credential: "synthetic-secret".into(),
                stun_urls: Vec::new(),
                expires_at_ms: MAX_SAFE_INTEGER,
            },
            cache_ttl_ms: Some(120_000),
        };
        assert!(cache.complete(load_id, Some(parsed), started).is_some());

        assert!(matches!(
            cache.begin(RelayCacheTime {
                monotonic: started.monotonic + Duration::from_millis(1),
                wall: SystemTime::UNIX_EPOCH,
            }),
            RelayCredentialCacheAction::Load(_)
        ));
    }

    #[tokio::test]
    async fn cancelled_relay_load_owner_wakes_waiters_and_allows_a_fresh_owner() {
        let cache = RelayCredentialCache::new();
        let now = RelayCacheTime::now();
        let RelayCredentialCacheAction::Load(first_id) = cache.begin(now) else {
            panic!("expected first load owner");
        };
        let RelayCredentialCacheAction::Wait(mut waiter) = cache.begin(now) else {
            panic!("expected concurrent waiter");
        };

        drop(RelayCredentialLoadOwner::new(&cache, first_id));
        waiter
            .changed()
            .await
            .expect("owner publishes cancellation");
        assert_eq!(waiter.borrow().clone(), Some(None));
        assert!(matches!(
            cache.begin(now),
            RelayCredentialCacheAction::Load(_)
        ));
    }

    #[test]
    fn cache_drops_a_stale_value_before_a_refused_refresh() {
        let cache = RelayCredentialCache::new();
        let load_started_at = RelayCacheTime::now();
        let RelayCredentialCacheAction::Load(first_id) = cache.begin(load_started_at) else {
            panic!("expected first load owner");
        };
        let creds = RelayCreds {
            urls: vec!["turn:relay.example:3478".into()],
            username: "synthetic-user".into(),
            credential: "synthetic-secret".into(),
            stun_urls: Vec::new(),
            expires_at_ms: 170_000,
        };
        let parsed = ParsedRelayCreds {
            credentials: creds.clone(),
            cache_ttl_ms: Some(120_000),
        };
        assert_eq!(
            cache.complete(first_id, Some(parsed), load_started_at),
            Some(creds.clone())
        );
        assert!(matches!(
            cache.begin(RelayCacheTime {
                monotonic: load_started_at.monotonic + Duration::from_millis(89_999),
                wall: load_started_at.wall + Duration::from_millis(89_999),
            }),
            RelayCredentialCacheAction::Ready(_)
        ));

        let refresh_at = RelayCacheTime {
            monotonic: load_started_at.monotonic + Duration::from_millis(90_000),
            wall: load_started_at.wall + Duration::from_millis(90_000),
        };
        let RelayCredentialCacheAction::Load(refresh_id) = cache.begin(refresh_at) else {
            panic!("the exact margin must discard the cached credentials");
        };
        assert_eq!(cache.complete(refresh_id, None, refresh_at), None);
        let RelayCredentialCacheAction::Load(next_id) = cache.begin(refresh_at) else {
            panic!("a refusal is not negative-cached and cannot restore stale credentials");
        };
        cache.cancel(next_id);
    }
}
