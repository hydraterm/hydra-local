//! A bounded "recently seen" set with FIFO eviction. The remote-peer poll loop must remember which signaling
//! sessions it already handled (so it doesn't re-answer / busy-loop on a still-pending offer it failed to set
//! up), but an UNBOUNDED set is a memory-DoS vector: a flood of bogus offers, each with a fresh session id,
//! would grow it without limit. This caps the memory at `capacity` ids and evicts the oldest when full.
//!
//! Pure + deterministic (no clock, no async) so it's unit-testable in isolation. Content-blind — it only ever
//! holds opaque session-id strings, never offers/SDP/tokens/PTY.

use std::collections::{HashSet, VecDeque};

/// A fixed-capacity insertion-ordered set. `contains` is O(1); inserting past capacity evicts the oldest id.
#[derive(Debug)]
pub struct BoundedSeen {
    capacity: usize,
    set: HashSet<String>,
    order: VecDeque<String>,
}

impl BoundedSeen {
    pub fn new(capacity: usize) -> Self {
        BoundedSeen {
            capacity: capacity.max(1),
            set: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    pub fn contains(&self, id: &str) -> bool {
        self.set.contains(id)
    }

    /// Record `id` as seen. Returns false if it was already present (no-op), true if newly inserted. When the
    /// set is at capacity, inserting a new id evicts the oldest first — so memory stays bounded under a flood.
    pub fn insert(&mut self, id: &str) -> bool {
        if self.set.contains(id) {
            return false;
        }
        if self.order.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.set.remove(&oldest);
            }
        }
        self.order.push_back(id.to_string());
        self.set.insert(id.to_string());
        true
    }

    pub fn len(&self) -> usize {
        self.set.len()
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remembers_inserted_ids() {
        let mut s = BoundedSeen::new(4);
        assert!(s.insert("a"));
        assert!(s.contains("a"));
        assert!(!s.insert("a")); // already present → no-op
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn never_grows_past_capacity_under_a_flood() {
        let mut s = BoundedSeen::new(8);
        for i in 0..10_000 {
            s.insert(&format!("sess-{i}"));
            assert!(s.len() <= 8, "bounded at capacity even under a flood");
        }
        assert_eq!(s.len(), 8);
    }

    #[test]
    fn evicts_oldest_first_fifo() {
        let mut s = BoundedSeen::new(3);
        s.insert("a");
        s.insert("b");
        s.insert("c");
        s.insert("d"); // evicts "a"
        assert!(!s.contains("a"));
        assert!(s.contains("b") && s.contains("c") && s.contains("d"));
        s.insert("e"); // evicts "b"
        assert!(!s.contains("b"));
        assert!(s.contains("c") && s.contains("d") && s.contains("e"));
    }

    #[test]
    fn capacity_zero_is_clamped_to_one() {
        let mut s = BoundedSeen::new(0);
        s.insert("a");
        assert!(s.contains("a"));
        assert_eq!(s.len(), 1);
    }
}
