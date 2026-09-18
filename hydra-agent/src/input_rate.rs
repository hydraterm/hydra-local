//! Per-connection input backpressure: a content-blind byte token-bucket. The per-FRAME cap (MAX_INPUT_PAYLOAD)
//! stops one giant frame; this stops a FLOOD of many at-cap frames from an untrusted browser swamping the PTY.
//!
//! Pure + time-injected (no wall clock) so the decision is deterministic and unit-testable. The bucket holds a
//! byte allowance that refills at a steady rate up to a burst capacity; each accepted input frame spends its
//! byte length. When the bucket can't cover a frame, the frame is REFUSED (dropped before the daemon) — it is
//! never partially forwarded. No payload bytes are ever touched here, only the length.

/// Token bucket over BYTES. `capacity` = max burst (also the high-water allowance); `refill_per_sec` = sustained
/// bytes/sec. Defaults are generous for real typing/paste yet bound sustained abuse.
#[derive(Debug, Clone)]
pub struct InputRateLimiter {
    capacity: u64,
    refill_per_sec: u64,
    /// current available bytes (≤ capacity).
    tokens: u64,
    /// last time we refilled, unix ms. None until the first call seeds it.
    last_ms: Option<u64>,
}

/// Sustained input budget: 256 KiB/sec. A human types/pastes far below this; a flood of at-cap (64 KiB) frames
/// (MiB/sec) is throttled.
pub const DEFAULT_REFILL_PER_SEC: u64 = 256 * 1024;
/// Burst capacity: 1 MiB. Absorbs a legitimate large paste (chunked into ≤64 KiB frames by the browser) without
/// stalling, while still bounding instantaneous abuse.
pub const DEFAULT_CAPACITY: u64 = 1024 * 1024;

impl Default for InputRateLimiter {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY, DEFAULT_REFILL_PER_SEC)
    }
}

impl InputRateLimiter {
    pub fn new(capacity: u64, refill_per_sec: u64) -> Self {
        InputRateLimiter {
            capacity,
            refill_per_sec,
            tokens: capacity,
            last_ms: None,
        }
    }

    /// Refill the bucket for the elapsed time since the last call, then try to spend `bytes`. Returns true if
    /// the frame is within budget (and the bytes are spent); false if it should be refused. Monotonic `now_ms`
    /// is expected; a backwards clock simply doesn't refill (saturating).
    pub fn allow(&mut self, bytes: u64, now_ms: u64) -> bool {
        match self.last_ms {
            None => self.last_ms = Some(now_ms),
            Some(prev) => {
                let elapsed_ms = now_ms.saturating_sub(prev);
                if elapsed_ms > 0 {
                    // bytes added = refill_per_sec * elapsed_ms / 1000, saturating into the capacity.
                    let added = self.refill_per_sec.saturating_mul(elapsed_ms) / 1000;
                    self.tokens = self.tokens.saturating_add(added).min(self.capacity);
                    self.last_ms = Some(now_ms);
                }
            }
        }
        if bytes <= self.tokens {
            self.tokens -= bytes;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_frame_within_capacity_is_allowed() {
        let mut rl = InputRateLimiter::new(1000, 1000);
        assert!(rl.allow(500, 0));
        assert!(rl.allow(500, 0)); // exactly drains the bucket
        assert!(!rl.allow(1, 0)); // empty now → refused
    }

    #[test]
    fn a_frame_larger_than_capacity_is_always_refused() {
        let mut rl = InputRateLimiter::new(1000, 1000);
        assert!(!rl.allow(1001, 0));
    }

    #[test]
    fn tokens_refill_over_time_up_to_capacity() {
        let mut rl = InputRateLimiter::new(1000, 1000); // 1000 bytes/sec
        assert!(rl.allow(1000, 0)); // drain
        assert!(!rl.allow(1, 0)); // empty
        assert!(rl.allow(500, 500)); // 500ms → +500 bytes refilled → 500 available
        assert!(!rl.allow(1, 500)); // drained again
                                    // long wait refills only up to capacity, not beyond.
        assert!(rl.allow(1000, 100_000));
        assert!(!rl.allow(1, 100_000));
    }

    #[test]
    fn a_burst_of_at_cap_frames_is_throttled() {
        // defaults: 1 MiB burst, 256 KiB/s. 64 KiB frames sent back-to-back at the SAME instant.
        let mut rl = InputRateLimiter::default();
        let frame = 64 * 1024;
        let mut accepted = 0;
        for _ in 0..64 {
            if rl.allow(frame, 0) {
                accepted += 1;
            }
        }
        // only the 1 MiB burst worth (16 frames) is accepted instantaneously; the rest is throttled.
        assert_eq!(accepted, 16);
        assert!(!rl.allow(frame, 0));
        // after 1 second, ~256 KiB refilled → ~4 more frames.
        let mut more = 0;
        for _ in 0..64 {
            if rl.allow(frame, 1000) {
                more += 1;
            }
        }
        assert_eq!(more, 4);
    }

    #[test]
    fn backwards_clock_does_not_refill() {
        let mut rl = InputRateLimiter::new(1000, 1000);
        assert!(rl.allow(1000, 5000));
        assert!(!rl.allow(1, 4000)); // clock went backwards → no refill, still empty
    }
}
