//! A Channel is the bus that makes multi-agent structural. Sessions join a
//! channel and their output is published onto it; orchestration policies (e.g.
//! Work Together) subscribe to the channel's event stream and inject Prompt /
//! Control events back. Human "chat" is just ChatMsg events on the same bus.
//!
//! Because the channel and its log live in the daemon, an orchestration that
//! runs as a channel policy survives a UI restart.

use crate::ids::{ChannelId, SessionId};
use crate::protocol::ChannelEvent;
use anyhow::{anyhow, Result};
use std::collections::VecDeque;
use tokio::sync::broadcast;

/// Retained channel events for late-joiner replay (and audit / chat history).
const LOG_EVENT_CAP: usize = 512;
/// Aggregate encoded bytes retained for one channel's late-joiner replay.
const LOG_BYTE_CAP: usize = 1024 * 1024;
/// A single channel event must remain small even though the generic daemon frame
/// limit is intentionally large enough for terminal snapshots.
pub(crate) const MAX_CHANNEL_EVENT_BYTES: usize = 64 * 1024;
/// Live subscribers retain at most this many events while lagging. Together with
/// `MAX_CHANNEL_EVENT_BYTES`, this gives the broadcast ring a finite byte ceiling.
const LIVE_EVENT_CAP: usize = 64;

struct RetainedChannelEvent {
    encoded_bytes: usize,
    event: ChannelEvent,
}

pub struct Channel {
    #[expect(dead_code, reason = "reserved until channel fan-out is wired")]
    pub id: ChannelId,
    pub members: Vec<SessionId>,
    /// Recent events for replay to a newly-attached client / policy.
    log: VecDeque<RetainedChannelEvent>,
    log_bytes: usize,
    /// Live fan-out of channel events to subscribers (UI clients + policies).
    pub event_tx: broadcast::Sender<ChannelEvent>,
}

impl Channel {
    pub fn new(id: ChannelId) -> Self {
        let (event_tx, _rx) = broadcast::channel::<ChannelEvent>(LIVE_EVENT_CAP);
        Channel {
            id,
            members: Vec::new(),
            log: VecDeque::with_capacity(LOG_EVENT_CAP),
            log_bytes: 0,
            event_tx,
        }
    }

    pub fn join(&mut self, session: SessionId) {
        if !self.members.contains(&session) {
            self.members.push(session);
        }
    }

    /// Record + fan out an event. Send errors (no live subscribers) are fine —
    /// the log still captured it for later replay.
    pub fn publish(&mut self, event: ChannelEvent) -> Result<()> {
        let encoded_bytes = serde_json::to_vec(&event)
            .map_err(|error| anyhow!("channel event could not be encoded: {error}"))?
            .len();
        if encoded_bytes > MAX_CHANNEL_EVENT_BYTES {
            return Err(anyhow!(
                "channel event exceeds the encoded byte limit ({MAX_CHANNEL_EVENT_BYTES})"
            ));
        }

        self.log.push_back(RetainedChannelEvent {
            encoded_bytes,
            event: event.clone(),
        });
        self.log_bytes += encoded_bytes;
        while self.log.len() > LOG_EVENT_CAP || self.log_bytes > LOG_BYTE_CAP {
            if let Some(discarded) = self.log.pop_front() {
                self.log_bytes = self.log_bytes.saturating_sub(discarded.encoded_bytes);
            }
        }
        let _ = self.event_tx.send(event);
        Ok(())
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "called by late-joiner replay once channels are wired"
        )
    )]
    pub fn replay(&self) -> Vec<ChannelEvent> {
        self.log.iter().map(|entry| entry.event.clone()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::ChannelEventKind;

    fn event(text: String, ts: u64) -> ChannelEvent {
        ChannelEvent {
            channel: ChannelId("bounded-channel".into()),
            from: None,
            kind: ChannelEventKind::ChatMsg { text },
            ts,
        }
    }

    #[test]
    fn oversized_event_is_rejected_without_retaining_or_broadcasting_it() {
        let mut channel = Channel::new(ChannelId("bounded-channel".into()));
        let mut receiver = channel.event_tx.subscribe();

        let error = channel
            .publish(event("x".repeat(MAX_CHANNEL_EVENT_BYTES), 1))
            .expect_err("encoded event must exceed the byte ceiling");

        assert!(error.to_string().contains("encoded byte limit"));
        assert!(channel.log.is_empty());
        assert_eq!(channel.log_bytes, 0);
        assert!(matches!(
            receiver.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn retained_log_evicts_oldest_events_to_stay_under_both_caps() {
        let mut channel = Channel::new(ChannelId("bounded-channel".into()));
        let payload = "x".repeat(16 * 1024);

        for ts in 0..200 {
            channel.publish(event(payload.clone(), ts)).unwrap();
        }

        assert!(channel.log.len() <= LOG_EVENT_CAP);
        assert!(channel.log_bytes <= LOG_BYTE_CAP);
        assert!(channel.log.front().unwrap().event.ts > 0);
        assert_eq!(channel.log.back().unwrap().event.ts, 199);
        assert_eq!(
            channel.log_bytes,
            channel
                .log
                .iter()
                .map(|entry| entry.encoded_bytes)
                .sum::<usize>()
        );
    }
}
