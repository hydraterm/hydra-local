//! Typed wire identifiers. Sessions and channels are the two core nouns keyed on the wire;
//! keeping them as distinct newtypes prevents mixing a session id where a channel id is meant.
//!
//! Both serialize as a BARE JSON string (`SessionId("s1")` -> `"s1"`), so a session id is just a
//! string on the wire — the app shell mints `session_id` as a matching `String` and it round-trips
//! unchanged. The serde shape here is identical to the daemon's original `ids.rs`.

use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct SessionId(pub String);

#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Debug)]
pub struct ChannelId(pub String);

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for ChannelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
