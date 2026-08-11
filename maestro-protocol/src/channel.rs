//! The channel-bus payload. A Channel is the bus that makes multi-agent structural: sessions join
//! a channel, their output is published onto it, and orchestration policies subscribe and inject
//! `Prompt`/`Control` events back. Human chat is just `ChatMsg` on the same bus.
//!
//! These are the WIRE payload types only — the daemon owns the actual `Channel` runtime (its log,
//! membership, and broadcast). The serde shape here is identical to the daemon's original
//! `protocol.rs` definitions: `ChannelEventKind` is internally tagged by `kind` (snake_case) and
//! `ChannelEvent` flattens that kind alongside `channel`/`from`/`ts`.

use crate::ids::{ChannelId, SessionId};
use serde::{Deserialize, Serialize};

/// What kind of thing flowed through a channel. The orchestration policy (e.g. Work Together) is a
/// consumer of these events, not a special path — that's what makes multi-agent structural rather
/// than bolted on.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChannelEventKind {
    /// Raw PTY output bytes from a session (utf8-lossy for the wire).
    Output { text: String },
    /// A prompt injected toward a session (e.g. the orchestrator's next turn).
    Prompt { text: String },
    /// A control signal (resize, interrupt, done-signal, etc.).
    Control { name: String, arg: Option<String> },
    /// A human- or agent-authored chat message on the channel.
    ChatMsg { text: String },
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ChannelEvent {
    pub channel: ChannelId,
    pub from: Option<SessionId>,
    #[serde(flatten)]
    pub kind: ChannelEventKind,
    /// Unix millis.
    pub ts: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ChannelEvent` flattens its `kind` (internally tagged by `kind`, snake_case) alongside
    /// `channel`/`from`/`ts`. This pins the unchanged wire shape: a `ChatMsg` carrying a `from`
    /// session id serializes to exactly the daemon's original bytes.
    #[test]
    fn channel_event_chat_msg_shape_unchanged() {
        let ev = ChannelEvent {
            channel: ChannelId("c1".into()),
            from: Some(SessionId("s1".into())),
            kind: ChannelEventKind::ChatMsg { text: "hi".into() },
            ts: 1700,
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert_eq!(
            json,
            r#"{"channel":"c1","from":"s1","kind":"chat_msg","text":"hi","ts":1700}"#
        );
        let back: ChannelEvent = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            back.kind,
            ChannelEventKind::ChatMsg { text } if text == "hi"
        ));
    }

    /// A `Control` event with a null `arg` and no `from` keeps the daemon's shape: `from` is
    /// `null`, the `kind` discriminator is `control`, and `arg` is present-but-null.
    #[test]
    fn channel_event_control_shape_unchanged() {
        let ev = ChannelEvent {
            channel: ChannelId("c1".into()),
            from: None,
            kind: ChannelEventKind::Control {
                name: "interrupt".into(),
                arg: None,
            },
            ts: 5,
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert_eq!(
            json,
            r#"{"channel":"c1","from":null,"kind":"control","name":"interrupt","arg":null,"ts":5}"#
        );
    }
}
