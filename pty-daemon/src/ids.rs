//! Typed identifiers. Sessions and channels are the two core nouns of the
//! daemon (Option X: sessions own channel subscriptions). Keeping them as
//! distinct newtypes prevents mixing a session id where a channel id is meant.
//!
//! The newtypes themselves now live in the shared `maestro-protocol` crate (the wire is keyed by
//! them) and are re-exported here so existing daemon code keeps referring to `crate::ids::{...}`
//! against the SAME types the protocol crate defines. Only `mint`, a daemon-local concern, stays
//! here.

pub use maestro_protocol::ids::{ChannelId, SessionId};
use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic local id generator. The UI assigns its own stable ids (a pane's
/// config id), but the daemon mints ids for anything it originates so two
/// callers can't collide.
static COUNTER: AtomicU64 = AtomicU64::new(1);

#[expect(
    dead_code,
    reason = "used once the daemon mints ids for things it originates"
)]
pub fn mint(prefix: &str) -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{n}")
}
