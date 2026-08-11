//! Exact byte-bounded per-client daemon output queue.
//!
//! Tokio's bounded MPSC limits item count, but a [`DaemonEvent`] can range from a tiny bell to a
//! multi-megabyte Grid. Counting only items therefore does not bound retained memory. This queue
//! serializes each event exactly once before enqueueing and holds one semaphore permit per encoded
//! newline-delimited byte until the writer finishes with that line. The budget covers encoded and
//! reserved queue storage; an already-constructed source event and allocator bookkeeping remain
//! outside it.

use crate::protocol::DaemonEvent;
use std::io::Write as _;
use std::sync::Arc;
use tokio::sync::{mpsc, watch, Mutex, OwnedSemaphorePermit, Semaphore, TryAcquireError};

/// Additive connection-local ownership metadata for events emitted by one Attach forwarder. It is
/// kept outside `DaemonEvent` so retained clients decode their existing event variants unchanged.
#[derive(serde::Serialize)]
struct AttachmentEvent {
    #[serde(flatten)]
    event: DaemonEvent,
    #[serde(skip_serializing_if = "Option::is_none")]
    live_output_generation: Option<u64>,
}

#[derive(Clone)]
pub(crate) struct OutboundSender {
    tx: mpsc::Sender<QueuedLine>,
    budget: Arc<Semaphore>,
    // All producers for one client publish through one FIFO gate. This preserves the daemon event
    // order across reserve -> encode -> enqueue even when a large baseline and a small live frame
    // are produced by different tasks at nearly the same time.
    admission: Arc<Mutex<()>>,
    max_bytes: usize,
    fatal_tx: watch::Sender<bool>,
}

pub(crate) struct OutboundReceiver {
    rx: mpsc::Receiver<QueuedLine>,
    fatal_tx: watch::Sender<bool>,
}

pub(crate) struct QueuedLine {
    // Boxed slice discards Vec's spare capacity, so the charged encoded length is the allocation
    // retained by the queue (apart from the separately item-bounded envelope overhead).
    bytes: Box<[u8]>,
    // Dropping the line after its write completes returns its exact encoded size to the queue.
    _permit: OwnedSemaphorePermit,
}

impl QueuedLine {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SendError {
    Closed,
    Full,
    TooLarge,
}

pub(crate) fn channel(
    item_cap: usize,
    byte_cap: usize,
) -> (OutboundSender, OutboundReceiver, watch::Receiver<bool>) {
    assert!(item_cap > 0, "outbound item capacity must be non-zero");
    assert!(
        byte_cap > 0 && byte_cap <= u32::MAX as usize,
        "outbound byte capacity must fit acquire_many_owned"
    );
    let (tx, rx) = mpsc::channel(item_cap);
    let (fatal_tx, fatal_rx) = watch::channel(false);
    let sender = OutboundSender {
        tx,
        budget: Arc::new(Semaphore::new(byte_cap)),
        admission: Arc::new(Mutex::new(())),
        max_bytes: byte_cap,
        fatal_tx: fatal_tx.clone(),
    };
    let receiver = OutboundReceiver { rx, fatal_tx };
    (sender, receiver, fatal_rx)
}

impl OutboundSender {
    // The shared framing cap covers the complete newline-delimited wire line, including its
    // delimiter. Keeping the newline inside the same cap is one byte stricter than the legacy
    // readers and guarantees every queued line is accepted by every canonical consumer.
    const MAX_LINE_WITH_NEWLINE: usize = crate::protocol::MAX_LINE_BYTES;

    fn encode(&self, event: &impl serde::Serialize) -> Result<Box<[u8]>, SendError> {
        struct CappedWriter {
            bytes: Vec<u8>,
            limit: usize,
        }

        impl std::io::Write for CappedWriter {
            fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
                if input.len() > self.limit.saturating_sub(self.bytes.len()) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "daemon event exceeds the shared line limit",
                    ));
                }
                let next_len = self.bytes.len() + input.len();
                if next_len > self.bytes.capacity() {
                    let target_capacity = self
                        .bytes
                        .capacity()
                        .max(4 * 1024)
                        .saturating_mul(2)
                        .max(next_len)
                        .min(self.limit);
                    self.bytes
                        .try_reserve_exact(target_capacity - self.bytes.len())
                        .map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::OutOfMemory,
                                "daemon event allocation failed",
                            )
                        })?;
                }
                self.bytes.extend_from_slice(input);
                Ok(input.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut writer = CappedWriter {
            // Grow in bounded geometric steps rather than reallocating for every small token the
            // serde formatter emits. The complete wire line is still capped below and converted to
            // a boxed slice before enqueue, so retained queue capacity equals its encoded length.
            bytes: Vec::with_capacity(Self::MAX_LINE_WITH_NEWLINE.min(64 * 1024)),
            limit: Self::MAX_LINE_WITH_NEWLINE,
        };
        serde_json::to_writer(&mut writer, event).map_err(|_| {
            self.fail();
            // DaemonEvent is a canonical in-memory value, so its serializer has no data-dependent
            // failure. The only error source here is the capped writer (limit/allocation); either
            // makes this ordered client stream unrepresentable and therefore fatal.
            SendError::TooLarge
        })?;
        writer.write_all(b"\n").map_err(|_| {
            self.fail();
            SendError::TooLarge
        })?;
        Ok(writer.bytes.into_boxed_slice())
    }

    fn trim_reservation(
        &self,
        mut reservation: OwnedSemaphorePermit,
        actual_bytes: usize,
    ) -> Result<OwnedSemaphorePermit, SendError> {
        let unused = Self::MAX_LINE_WITH_NEWLINE.saturating_sub(actual_bytes);
        if unused > 0 {
            drop(reservation.split(unused).ok_or_else(|| {
                self.fail();
                SendError::TooLarge
            })?);
        }
        Ok(reservation)
    }

    /// Guaranteed delivery into the bounded writer queue. When the byte budget is exhausted this
    /// waits rather than dropping a revision-dependent event. That backpressure lets the session
    /// broadcast detect lag and use its existing atomic ResyncRequired + Grid recovery.
    pub(crate) async fn send(&self, event: DaemonEvent) -> Result<(), SendError> {
        self.send_serializable(event).await
    }

    /// Guaranteed delivery for an event owned by one Attach forwarder. A late event from an aborted
    /// old forwarder may race past a newer baseline; the echoed generation lets a proxy reject that
    /// line without changing daemon task/session ownership.
    pub(crate) async fn send_for_attachment(
        &self,
        event: DaemonEvent,
        output_generation: Option<u64>,
    ) -> Result<(), SendError> {
        if output_generation.is_none() {
            return self.send(event).await;
        }
        self.send_serializable(AttachmentEvent {
            event,
            live_output_generation: output_generation,
        })
        .await
    }

    async fn send_serializable(&self, event: impl serde::Serialize) -> Result<(), SendError> {
        // Tokio's mutex admits waiters in FIFO order. Hold it through the MPSC enqueue: otherwise
        // a later tiny Damage can finish serialization before an earlier large Grid and invalidate
        // the receiver's revision chain during resync.
        let _admission = self.admission.lock().await;
        if Self::MAX_LINE_WITH_NEWLINE > self.max_bytes {
            self.fail();
            return Err(SendError::TooLarge);
        }
        // Reserve the maximum canonical line before serialization. Thus queued/writing bytes plus
        // the one in-flight encoder always stay inside the same byte budget; no complete uncharged
        // JSON copy can wait beside an already-full queue.
        let reservation = self
            .budget
            .clone()
            .acquire_many_owned(Self::MAX_LINE_WITH_NEWLINE as u32)
            .await
            .map_err(|_| SendError::Closed)?;
        let bytes = self.encode(&event)?;
        let permit = self.trim_reservation(reservation, bytes.len())?;
        self.tx
            .send(QueuedLine {
                bytes,
                _permit: permit,
            })
            .await
            .map_err(|_| {
                self.fail();
                SendError::Closed
            })
    }

    /// Best-effort delivery for advisory/error responses. Item or byte saturation preserves the
    /// previous try-send semantics; malformed or individually over-budget events are fatal because
    /// continuing after an unrepresentable baseline would leave the consumer inconsistent.
    pub(crate) fn try_send(&self, event: DaemonEvent) -> Result<(), SendError> {
        // Best-effort events may not overtake a guaranteed sender already admitted or queued. A
        // busy admission gate is therefore the same advisory saturation result as a full queue.
        let _admission = self.admission.try_lock().map_err(|_| SendError::Full)?;
        if self.tx.capacity() == 0 {
            return Err(SendError::Full);
        }
        if Self::MAX_LINE_WITH_NEWLINE > self.max_bytes {
            self.fail();
            return Err(SendError::TooLarge);
        }
        let reservation = match self
            .budget
            .clone()
            .try_acquire_many_owned(Self::MAX_LINE_WITH_NEWLINE as u32)
        {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => return Err(SendError::Full),
            Err(TryAcquireError::Closed) => return Err(SendError::Closed),
        };
        let bytes = self.encode(&event)?;
        let permit = self.trim_reservation(reservation, bytes.len())?;
        self.tx
            .try_send(QueuedLine {
                bytes,
                _permit: permit,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => SendError::Full,
                mpsc::error::TrySendError::Closed(_) => {
                    self.fail();
                    SendError::Closed
                }
            })
    }

    fn fail(&self) {
        let _ = self.fatal_tx.send(true);
    }

    #[cfg(test)]
    pub(crate) fn available_bytes(&self) -> usize {
        self.budget.available_permits()
    }

    #[cfg(test)]
    async fn hold_admission(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.admission.lock().await
    }
}

impl OutboundReceiver {
    pub(crate) async fn recv(&mut self) -> Option<QueuedLine> {
        self.rx.recv().await
    }

    #[cfg(test)]
    pub(crate) async fn recv_event(&mut self) -> Option<DaemonEvent> {
        let line = self.recv().await?;
        serde_json::from_slice(&line.bytes[..line.bytes.len() - 1]).ok()
    }

    #[cfg(test)]
    pub(crate) fn try_recv_event(&mut self) -> Result<DaemonEvent, ()> {
        let line = self.rx.try_recv().map_err(|_| ())?;
        serde_json::from_slice(&line.bytes[..line.bytes.len() - 1]).map_err(|_| ())
    }

    /// A socket write failure invalidates the one ordered client stream. Wake the read side so it
    /// drops every attachment instead of leaving producer tasks connected to a dead writer.
    pub(crate) fn fail(&self) {
        let _ = self.fatal_tx.send(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn event(message: &str) -> DaemonEvent {
        DaemonEvent::Error {
            message: message.to_string(),
        }
    }

    #[tokio::test]
    async fn queued_lines_are_exact_newline_json_and_release_their_bytes_on_drop() {
        let expected = serde_json::to_vec(&event("bounded")).unwrap().len() + 1;
        let cap = OutboundSender::MAX_LINE_WITH_NEWLINE;
        let (tx, mut rx, _fatal) = channel(4, cap);
        tx.send(event("bounded")).await.unwrap();
        assert_eq!(tx.available_bytes(), cap - expected);

        let line = rx.recv().await.unwrap();
        assert_eq!(line.bytes().last(), Some(&b'\n'));
        let decoded: DaemonEvent = serde_json::from_slice(&line.bytes()[..expected - 1]).unwrap();
        assert!(matches!(decoded, DaemonEvent::Error { message } if message == "bounded"));
        drop(line);
        assert_eq!(tx.available_bytes(), cap);
    }

    #[tokio::test]
    async fn attachment_send_adds_a_tolerated_top_level_generation_tag() {
        let cap = OutboundSender::MAX_LINE_WITH_NEWLINE;
        let (tx, mut rx, _fatal) = channel(4, cap);
        tx.send_for_attachment(event("tagged"), Some(42))
            .await
            .unwrap();
        let line = rx.recv().await.unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&line.bytes()[..line.bytes().len() - 1]).unwrap();
        assert_eq!(value["ev"], "error");
        assert_eq!(value["message"], "tagged");
        assert_eq!(value["live_output_generation"], 42);
        let decoded: DaemonEvent =
            serde_json::from_slice(&line.bytes()[..line.bytes().len() - 1]).unwrap();
        assert!(matches!(decoded, DaemonEvent::Error { message } if message == "tagged"));
    }

    #[tokio::test]
    async fn exact_byte_budget_backpressures_without_dropping_or_reordering() {
        let one_line = serde_json::to_vec(&event("same-size")).unwrap().len() + 1;
        let cap = OutboundSender::MAX_LINE_WITH_NEWLINE;
        let (tx, mut rx, _fatal) = channel(4, cap);
        tx.send(event("same-size")).await.unwrap();
        assert_eq!(tx.available_bytes(), cap - one_line);

        let second_tx = tx.clone();
        let second = tokio::spawn(async move { second_tx.send(event("same-size")).await });
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(
            !second.is_finished(),
            "second line must wait for exact byte permits"
        );

        let first = rx.recv().await.unwrap();
        drop(first);
        tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .expect("second send should wake after the first write releases permits")
            .unwrap()
            .unwrap();
        let second = rx.recv().await.unwrap();
        assert!(second.bytes().ends_with(b"\n"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fifo_admission_prevents_a_small_live_frame_overtaking_a_large_baseline() {
        // Model the production two-reservation budget. Manually hold admission so the earlier
        // large baseline and later tiny frame are both scheduled before either may encode. The
        // single-thread runtime plus yields makes their lock arrival order deterministic.
        let cap = 2 * OutboundSender::MAX_LINE_WITH_NEWLINE;
        let (tx, mut rx, _fatal) = channel(4, cap);
        let held = tx.hold_admission().await;

        let baseline_tx = tx.clone();
        let baseline =
            tokio::spawn(
                async move { baseline_tx.send(event(&"g".repeat(2 * 1024 * 1024))).await },
            );
        tokio::task::yield_now().await;

        let live_tx = tx.clone();
        let live = tokio::spawn(async move { live_tx.send(event("damage-n-plus-one")).await });
        tokio::task::yield_now().await;
        drop(held);

        baseline.await.unwrap().unwrap();
        live.await.unwrap().unwrap();

        let first = rx.recv_event().await.unwrap();
        let second = rx.recv_event().await.unwrap();
        assert!(
            matches!(first, DaemonEvent::Error { message } if message.len() == 2 * 1024 * 1024)
        );
        assert!(matches!(second, DaemonEvent::Error { message } if message == "damage-n-plus-one"));
    }

    #[tokio::test]
    async fn individually_oversized_event_fails_the_client_stream() {
        let (tx, _rx, mut fatal) = channel(4, OutboundSender::MAX_LINE_WITH_NEWLINE);
        let oversized = "x".repeat(crate::protocol::MAX_LINE_BYTES);
        assert_eq!(tx.send(event(&oversized)).await, Err(SendError::TooLarge));
        tokio::time::timeout(Duration::from_secs(1), fatal.changed())
            .await
            .expect("fatal stream notification")
            .expect("fatal sender remains live");
        assert!(*fatal.borrow());
    }

    #[test]
    fn best_effort_send_obeys_the_same_byte_budget() {
        let (tx, _rx, _fatal) = channel(4, OutboundSender::MAX_LINE_WITH_NEWLINE);
        tx.try_send(event("one")).unwrap();
        assert_eq!(tx.try_send(event("two")), Err(SendError::Full));
    }

    #[tokio::test]
    async fn cancelling_a_waiting_send_releases_its_reservation() {
        let cap = OutboundSender::MAX_LINE_WITH_NEWLINE;
        let (tx, mut rx, _fatal) = channel(4, cap);
        tx.send(event("first")).await.unwrap();

        let waiting_tx = tx.clone();
        let waiting = tokio::spawn(async move { waiting_tx.send(event("second")).await });
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(!waiting.is_finished());
        waiting.abort();
        let _ = waiting.await;

        drop(rx.recv().await.unwrap());
        assert_eq!(tx.available_bytes(), cap);
    }

    #[tokio::test]
    async fn closing_the_receiver_releases_queued_and_failed_send_permits() {
        let cap = OutboundSender::MAX_LINE_WITH_NEWLINE;
        let (tx, rx, _fatal) = channel(4, cap);
        tx.send(event("queued")).await.unwrap();
        drop(rx);
        assert_eq!(tx.available_bytes(), cap);

        assert_eq!(tx.send(event("closed")).await, Err(SendError::Closed));
        assert_eq!(tx.available_bytes(), cap);
    }
}
