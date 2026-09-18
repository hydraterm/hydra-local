//! LIVE REVOCATION DELIVERY. The cloud can revoke a browser device, disable an account, or "log out
//! everywhere" — but an ALREADY-CONNECTED browser's DataChannel would otherwise keep working until the
//! token's 10-minute expiry. This module holds a shared, cloud-fed revocation snapshot and a background
//! poller that refreshes it. Each connection has an independent authority watchdog, so binary terminal
//! input is denied within <=2s after the next authoritative post-revocation result lands even if its control
//! loop is waiting for outbound physical completion. Do not derive a fixed 15+5+2 observation bound: polling
//! is sequential, so an in-flight pre-revocation snapshot can arrive near its 15s deadline, followed by the
//! 5s delay, another request of up to 15s, and the watchdog (an approximately 37s edge sequence). Intermittent
//! failures leave the remaining signed-token lifetime (at most 10 minutes) as the universal terminal-input
//! authority bound: the input gate checks that deadline synchronously. Visible transport teardown can lag while
//! one already-bounded outbound completion unwinds; it does not restore input authority.
//!
//! Authority direction: the cloud may only REMOVE access through this mechanism (mark ids revoked). It can
//! never ADD a locally-trusted browser — the agent's trust in a browser still comes from the (offline-
//! verified) cloud-signed token + the browser proof-of-possession, not from this poll.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Default delay between completed polls. Once an authoritative post-revocation result is delivered, the
/// per-connection authority watchdog observes it within <=2s. A sequential in-flight old result can make the
/// illustrative 15s + 5s + 15s + 2s edge approach 37s. Intermittent failures admit no shorter universal
/// terminal-input authority bound than the remaining 10-minute signed-token lifetime, enforced synchronously
/// by the input gate; transport teardown may visibly follow after bounded outbound cleanup.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Default)]
struct Snapshot {
    /// This desktop is revoked → close ALL connections (matches the local-enrollment check, but delivered
    /// live from the cloud so we don't depend solely on the heartbeat clearing device.json).
    self_revoked: bool,
    /// The account's revoked device ids. A connection whose peer (browser) id is in here is closed.
    revoked_ids: HashSet<String>,
    /// #20 account revoke-before marker: a connection whose token was minted (iat_ms) AT OR BEFORE this is
    /// closed — covers session/account revocation (Clerk logout-everywhere, user.deleted) reaching live channels.
    revoke_before_ms: u64,
    /// True once at least one successful poll has landed. Until then we do NOT report anything as revoked
    /// from this source (fail-OPEN for the live-delivery layer specifically) — the existing token expiry +
    /// local-enrollment checks still bound access, and we must not tear down healthy connections just because
    /// the (best-effort) poll hasn't answered yet or the cloud is briefly unreachable.
    primed: bool,
}

/// A cheap-to-clone handle to the shared revocation snapshot. Readers (the per-connection revoke tick) call
/// `is_revoked`; the poller calls `update`.
#[derive(Clone)]
pub struct RevocationState {
    inner: Arc<RwLock<Snapshot>>,
}

impl Default for RevocationState {
    fn default() -> Self {
        Self::new()
    }
}

impl RevocationState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Snapshot::default())),
        }
    }

    /// Replace the snapshot after a successful poll. Marks the state primed.
    pub fn update(&self, self_revoked: bool, revoked_ids: HashSet<String>, revoke_before_ms: u64) {
        let mut g = self.inner.write().unwrap();
        g.self_revoked = self_revoked;
        g.revoked_ids = revoked_ids;
        // Monotonic: the account revoke-before marker only moves forward (a stale poll can't un-revoke).
        if revoke_before_ms > g.revoke_before_ms {
            g.revoke_before_ms = revoke_before_ms;
        }
        g.primed = true;
    }

    /// An exact authenticated cloud denial means this enrolled desktop no longer has authority. Preserve all
    /// prior remove-only evidence and mark the snapshot primed/self-revoked; transient failures never call this.
    #[cfg(any(feature = "webrtc", test))]
    fn mark_self_revoked(&self) {
        let mut g = self.inner.write().unwrap();
        g.self_revoked = true;
        g.primed = true;
    }

    /// Should a live connection to `browser_device_id` (whose token was minted at `token_iat_ms`) be closed?
    /// True iff a successful poll has landed AND (this desktop is revoked, OR the peer browser id is in the
    /// revoked set, OR the token is at or before the account revoke-before marker — session/account revocation).
    /// Fail-OPEN before the first successful poll so a transient cloud outage doesn't drop healthy sessions.
    pub fn is_revoked(&self, browser_device_id: &str, token_iat_ms: u64) -> bool {
        let g = self.inner.read().unwrap();
        if !g.primed {
            return false;
        }
        g.self_revoked
            || g.revoked_ids.contains(browser_device_id)
            || (g.revoke_before_ms > 0 && token_iat_ms <= g.revoke_before_ms)
    }
}

#[cfg(any(feature = "webrtc", test))]
fn apply_revocation_poll(
    state: &RevocationState,
    result: Result<crate::remote_signaling::RevocationPoll, String>,
) {
    match result {
        Ok(crate::remote_signaling::RevocationPoll::Snapshot(r)) => {
            let ids: HashSet<String> = r.revoked_device_ids.into_iter().collect();
            state.update(r.self_revoked, ids, r.revoke_before_ms);
        }
        Ok(crate::remote_signaling::RevocationPoll::TerminalDenial(denial)) => {
            state.mark_self_revoked();
            tracing::warn!(?denial, "revocation poll received terminal device denial");
        }
        Err(e) => {
            // Keep the previous snapshot; a transient failure must not tear down live sessions.
            tracing::debug!("revocation poll failed (keeping prior state): {e}");
        }
    }
}

/// Spawn the background poller: device-sign `GET /v1/devices/revocations` sequentially, then wait `interval`
/// after each completed or failed attempt before starting the next. Best-effort — a failed poll leaves the
/// previous snapshot in place (no flip to revoked on a transient error). The task holds an
/// `Arc<AgentSignaling>` and runs for the life of the peer.
#[cfg(feature = "webrtc")]
pub fn spawn_revocation_poller(
    signaling: std::sync::Arc<crate::remote_signaling::AgentSignaling>,
    state: RevocationState,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            apply_revocation_poll(&state, signaling.fetch_revocations().await);
            tokio::time::sleep(interval).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fails_open_until_the_first_successful_poll() {
        let s = RevocationState::new();
        // before any poll: nothing is considered revoked (don't drop healthy sessions on a cold/unreachable start)
        assert!(!s.is_revoked("web_a", 1000));
    }

    #[test]
    fn closes_a_revoked_peer_after_a_poll() {
        let s = RevocationState::new();
        s.update(false, HashSet::from(["web_a".to_string()]), 0);
        assert!(s.is_revoked("web_a", 1000)); // this browser was revoked → close it
        assert!(!s.is_revoked("web_b", 1000)); // a different, live browser stays
    }

    #[test]
    fn self_revoked_closes_every_connection() {
        let s = RevocationState::new();
        s.update(true, HashSet::new(), 0);
        assert!(s.is_revoked("web_a", 1000));
        assert!(s.is_revoked("anyone", 1000));
    }

    #[test]
    fn a_later_poll_can_clear_a_revocation() {
        // (defensive) if a device is un-revoked via an explicit relink, a later poll drops it from the set.
        let s = RevocationState::new();
        s.update(false, HashSet::from(["web_a".to_string()]), 0);
        assert!(s.is_revoked("web_a", 1000));
        s.update(false, HashSet::new(), 0);
        assert!(!s.is_revoked("web_a", 1000));
    }

    #[test]
    fn account_revoke_before_closes_tokens_minted_at_or_before_it() {
        // #20: a token minted AT OR BEFORE the account revoke-before marker is closed (session/account
        // revocation), while a token minted AFTER (a fresh re-login) stays live.
        let s = RevocationState::new();
        s.update(false, HashSet::new(), 5000); // revoke everything issued at or before t=5000
        assert!(s.is_revoked("web_a", 4999)); // old token → closed
        assert!(s.is_revoked("web_a", 5000)); // exact same-ms token → closed
        assert!(!s.is_revoked("web_a", 6000)); // newer token → live
    }

    #[test]
    fn exact_terminal_denials_mark_the_desktop_revoked() {
        use crate::remote_signaling::{RevocationPoll, RevocationTerminalDenial};

        for denial in [
            RevocationTerminalDenial::UnknownDevice,
            RevocationTerminalDenial::Revoked,
        ] {
            let state = RevocationState::new();
            apply_revocation_poll(&state, Ok(RevocationPoll::TerminalDenial(denial)));
            assert!(state.is_revoked("any-browser", u64::MAX));
        }
    }

    #[test]
    fn transient_poll_errors_preserve_the_previous_snapshot() {
        let state = RevocationState::new();
        state.update(false, HashSet::from(["web_revoked".to_string()]), 5000);

        apply_revocation_poll(&state, Err("temporary HTTP 503".to_string()));

        assert!(state.is_revoked("web_revoked", 6000));
        assert!(state.is_revoked("web_other", 5000));
        assert!(!state.is_revoked("web_other", 5001));
    }
}
