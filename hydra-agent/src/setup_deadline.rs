//! Pure progress-aware setup deadline used by one remote-peer serve owner.
//!
//! Callers supply content-blind, owner-local progress keys. A key can extend the inactivity budget exactly once;
//! the absolute budget never moves. The state machine owns no task or timer, so the serve owner can select on its
//! current deadline without leaving a detached watchdog behind after setup succeeds or is retired.

use std::collections::HashSet;
use std::hash::Hash;
use std::time::Duration;

use tokio::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeadlineExpiry {
    Inactivity,
    Absolute,
}

#[derive(Debug)]
pub(crate) struct ProgressDeadline<K> {
    inactivity: Duration,
    inactivity_at: Instant,
    absolute_at: Instant,
    last_progress_at: Instant,
    seen: HashSet<K>,
}

impl<K> ProgressDeadline<K>
where
    K: Eq + Hash,
{
    pub(crate) fn new(started_at: Instant, inactivity: Duration, absolute: Duration) -> Self {
        assert!(
            !inactivity.is_zero(),
            "setup inactivity deadline must be positive"
        );
        assert!(
            absolute >= inactivity,
            "setup absolute deadline must cover inactivity"
        );
        Self {
            inactivity,
            inactivity_at: started_at + inactivity,
            absolute_at: started_at + absolute,
            last_progress_at: started_at,
            seen: HashSet::new(),
        }
    }

    /// Record one meaningful stage/state. Delayed delivery is anchored to the event's source timestamp, never to
    /// the time the owner happened to dequeue it. An out-of-order old event is remembered but cannot move the
    /// deadline backwards or buy a fresh window after newer progress.
    pub(crate) fn observe(&mut self, key: K, observed_at: Instant) -> bool {
        if self.expired(observed_at).is_some() || !self.seen.insert(key) {
            return false;
        }
        if observed_at > self.last_progress_at {
            self.last_progress_at = observed_at;
            self.inactivity_at = observed_at + self.inactivity;
        }
        true
    }

    pub(crate) fn next_at(&self) -> Instant {
        self.inactivity_at.min(self.absolute_at)
    }

    pub(crate) fn expired(&self, now: Instant) -> Option<DeadlineExpiry> {
        if now >= self.absolute_at {
            Some(DeadlineExpiry::Absolute)
        } else if now >= self.inactivity_at {
            Some(DeadlineExpiry::Inactivity)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{DeadlineExpiry, ProgressDeadline};
    use std::time::Duration;
    use tokio::time::Instant;

    #[test]
    fn unique_progress_extends_inactivity_but_repeated_state_does_not() {
        let start = Instant::now();
        let mut deadline =
            ProgressDeadline::new(start, Duration::from_secs(20), Duration::from_secs(90));

        assert!(deadline.observe("relay", start + Duration::from_secs(15)));
        assert_eq!(deadline.next_at(), start + Duration::from_secs(35));
        assert!(!deadline.observe("relay", start + Duration::from_secs(30)));
        assert_eq!(deadline.next_at(), start + Duration::from_secs(35));
        assert_eq!(
            deadline.expired(start + Duration::from_secs(35)),
            Some(DeadlineExpiry::Inactivity)
        );
    }

    #[test]
    fn absolute_cap_never_moves_despite_slow_legitimate_progress() {
        let start = Instant::now();
        let mut deadline =
            ProgressDeadline::new(start, Duration::from_secs(20), Duration::from_secs(90));

        for (key, second) in [
            ("relay", 15),
            ("answer", 34),
            ("local-ice", 53),
            ("remote-ice", 72),
        ] {
            assert!(deadline.observe(key, start + Duration::from_secs(second)));
        }
        assert_eq!(deadline.next_at(), start + Duration::from_secs(90));
        assert_eq!(
            deadline.expired(start + Duration::from_secs(90)),
            Some(DeadlineExpiry::Absolute)
        );
    }

    #[test]
    fn delayed_or_late_events_cannot_resurrect_or_rewind_an_owner() {
        let start = Instant::now();
        let mut deadline =
            ProgressDeadline::new(start, Duration::from_secs(20), Duration::from_secs(90));

        assert!(deadline.observe("newer", start + Duration::from_secs(10)));
        assert!(deadline.observe("older-but-unique", start + Duration::from_secs(5)));
        assert_eq!(deadline.next_at(), start + Duration::from_secs(30));
        assert!(!deadline.observe("too-late", start + Duration::from_secs(30)));
        assert_eq!(
            deadline.expired(start + Duration::from_secs(30)),
            Some(DeadlineExpiry::Inactivity)
        );
    }

    #[test]
    fn owners_do_not_share_progress_or_absolute_budgets() {
        let start = Instant::now();
        let mut stale =
            ProgressDeadline::new(start, Duration::from_secs(20), Duration::from_secs(90));
        let replacement_start = start + Duration::from_secs(25);
        let replacement = ProgressDeadline::<&str>::new(
            replacement_start,
            Duration::from_secs(20),
            Duration::from_secs(90),
        );

        assert!(!stale.observe("late-stale-event", start + Duration::from_secs(20)));
        assert_eq!(
            replacement.next_at(),
            replacement_start + Duration::from_secs(20)
        );
        assert_eq!(
            replacement.expired(replacement_start + Duration::from_secs(19)),
            None
        );
    }
}
