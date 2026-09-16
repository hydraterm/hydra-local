//! Worker-owned overlapped operations for the final ConPTY backend.
//! Shared Session's ConPTY backend consumes these workers without a second output pump.
//!
//! A foreground write timeout is ambiguous: the kernel may have accepted bytes already.
//! Cancellation is requested, never replayed; this worker drains the exact operation before
//! dequeuing later bytes. Final ConPTY integration must retain its one-writer-per-endpoint gate.

use crate::windows_job::raw_handle;
use crate::windows_private_pipe::Event;
use std::io::{self, Read, Write};
use std::os::windows::io::OwnedHandle;
use std::ptr::null_mut;
use std::sync::{mpsc, Arc};
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_PIPE_NOT_CONNECTED, HANDLE,
    WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::Threading::{
    ResetEvent, WaitForMultipleObjects, WaitForSingleObject, INFINITE,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

// Internal transport/backpressure timings, not user task or concurrency limits.
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const IO_REPLY_POLL: Duration = Duration::from_millis(25);

pub(super) struct PipeEndpoint {
    handle: OwnedHandle,
    cancel: Arc<Event>,
    #[cfg(test)]
    pending: Option<mpsc::Sender<()>>,
    #[cfg(test)]
    finished: Option<mpsc::Sender<()>>,
}

impl PipeEndpoint {
    pub(super) fn new(handle: OwnedHandle, cancel: Arc<Event>) -> Self {
        Self {
            handle,
            cancel,
            #[cfg(test)]
            pending: None,
            #[cfg(test)]
            finished: None,
        }
    }
}

pub(super) struct OverlappedReader {
    endpoint: Arc<PipeEndpoint>,
    requests: mpsc::SyncSender<ReadRequest>,
}

struct ReadRequest {
    capacity: usize,
    reply: mpsc::Sender<io::Result<Vec<u8>>>,
}

impl OverlappedReader {
    pub(super) fn start(endpoint: Arc<PipeEndpoint>) -> io::Result<Self> {
        let event = Event::manual_reset()?;
        let (requests, incoming) = mpsc::sync_channel(1);
        let worker_endpoint = endpoint.clone();
        #[cfg(test)]
        let finished = endpoint.finished.clone();
        std::thread::Builder::new()
            .name("conpty-output-io".into())
            .spawn(move || {
                read_worker(worker_endpoint, event, incoming);
                #[cfg(test)]
                if let Some(finished) = finished {
                    let _ = finished.send(());
                }
            })?;
        Ok(Self { endpoint, requests })
    }
}

impl Read for OverlappedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let (reply, result) = mpsc::channel();
        enqueue_io_request(
            &self.requests,
            ReadRequest {
                capacity: buffer.len().min(u32::MAX as usize),
                reply,
            },
            "read",
        )?;

        loop {
            match result.recv_timeout(IO_REPLY_POLL) {
                Ok(data) => {
                    let data = data?;
                    debug_assert!(data.len() <= buffer.len());
                    buffer[..data.len()].copy_from_slice(&data);
                    return Ok(data.len());
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if event_is_set(&self.endpoint.cancel)? {
                        // The worker owns its buffer and OVERLAPPED until Windows completes the
                        // cancellation, so this caller can leave without a borrowed-buffer UAF.
                        return Err(cancelled_io_error());
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "Windows terminal read worker stopped",
                    ));
                }
            }
        }
    }
}

pub(super) struct OverlappedWriter {
    endpoint: Arc<PipeEndpoint>,
    requests: mpsc::SyncSender<WriteRequest>,
}

struct WriteRequest {
    data: Vec<u8>,
    deadline: Arc<Event>,
    reply: mpsc::Sender<io::Result<usize>>,
}

impl OverlappedWriter {
    pub(super) fn start(endpoint: Arc<PipeEndpoint>) -> io::Result<Self> {
        let event = Event::manual_reset()?;
        let (requests, incoming) = mpsc::sync_channel(1);
        let worker_endpoint = endpoint.clone();
        #[cfg(test)]
        let finished = endpoint.finished.clone();
        std::thread::Builder::new()
            .name("conpty-input-io".into())
            .spawn(move || {
                write_worker(worker_endpoint, event, incoming);
                #[cfg(test)]
                if let Some(finished) = finished {
                    let _ = finished.send(());
                }
            })?;
        Ok(Self { endpoint, requests })
    }
}

impl Write for OverlappedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if event_is_set(&self.endpoint.cancel)? {
            return Err(cancelled_io_error());
        }
        let deadline = Arc::new(Event::manual_reset()?);
        let (reply, result) = mpsc::channel();
        enqueue_io_request(
            &self.requests,
            WriteRequest {
                data: buffer[..buffer.len().min(u32::MAX as usize)].to_vec(),
                deadline: deadline.clone(),
                reply,
            },
            "write",
        )?;
        match result.recv_timeout(WRITE_TIMEOUT) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // The worker, not this stack frame, owns the bytes and OVERLAPPED. It can safely
                // finish cancellation after this bounded call returns to the request handler.
                if let Err(error) = deadline.set() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("Windows terminal write timed out; cancellation could not be signalled: {error}"),
                    ));
                }
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Windows terminal write exceeded its two-second deadline",
                ))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Windows terminal write worker stopped",
            )),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        // A pipe write is visible when its OVERLAPPED completes. FlushFileBuffers would wait for
        // the other side to consume all bytes and would reintroduce an unbounded terminal write.
        Ok(())
    }
}

fn enqueue_io_request<T>(
    sender: &mpsc::SyncSender<T>,
    request: T,
    direction: &'static str,
) -> io::Result<()> {
    match sender.try_send(request) {
        Ok(()) => Ok(()),
        Err(mpsc::TrySendError::Full(_)) => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            format!("Windows terminal {direction} queue is full"),
        )),
        Err(mpsc::TrySendError::Disconnected(_)) => Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            format!("Windows terminal {direction} worker stopped"),
        )),
    }
}

fn read_worker(endpoint: Arc<PipeEndpoint>, event: Event, requests: mpsc::Receiver<ReadRequest>) {
    while let Ok(request) = requests.recv() {
        let mut data = vec![0u8; request.capacity];
        let result = overlapped_io_worker(&endpoint, &event, None, |handle, op| unsafe {
            ReadFile(handle, data.as_mut_ptr(), data.len() as u32, null_mut(), op)
        })
        .map(|count| {
            data.truncate(count);
            data
        });
        let _ = request.reply.send(result);
    }
}

fn write_worker(endpoint: Arc<PipeEndpoint>, event: Event, requests: mpsc::Receiver<WriteRequest>) {
    while let Ok(request) = requests.recv() {
        let result = overlapped_io_worker(
            &endpoint,
            &event,
            Some(&request.deadline),
            |handle, op| unsafe {
                WriteFile(
                    handle,
                    request.data.as_ptr(),
                    request.data.len() as u32,
                    null_mut(),
                    op,
                )
            },
        );
        let _ = request.reply.send(result);
    }
}

fn overlapped_io_worker(
    endpoint: &PipeEndpoint,
    event: &Event,
    request_deadline: Option<&Event>,
    start: impl FnOnce(HANDLE, *mut OVERLAPPED) -> i32,
) -> io::Result<usize> {
    if event_is_set(&endpoint.cancel)? {
        return Err(cancelled_io_error());
    }
    if let Some(deadline) = request_deadline {
        if event_is_set(deadline)? {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Windows terminal write deadline elapsed before I/O admission",
            ));
        }
    }
    if unsafe { ResetEvent(event.raw()) } == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut operation = OVERLAPPED {
        hEvent: event.raw(),
        ..OVERLAPPED::default()
    };
    let handle = raw_handle(&endpoint.handle);
    if start(handle, &mut operation) != 0 {
        // With FILE_FLAG_OVERLAPPED, the byte-count parameter passed to ReadFile/WriteFile must be
        // null. Query the OVERLAPPED result even on immediate success so synchronous and pending
        // completions use one authoritative count path.
        return overlapped_result(handle, &operation);
    }

    let error = unsafe { GetLastError() };
    if is_pipe_eof(error) {
        return Ok(0);
    }
    if error != ERROR_IO_PENDING {
        return Err(io::Error::from_raw_os_error(error as i32));
    }

    #[cfg(test)]
    if let Some(pending) = &endpoint.pending {
        // Observe genuine ERROR_IO_PENDING, never an assumed pipe-buffer saturation.
        let _ = pending.send(());
    }

    let handles = [
        event.raw(),
        endpoint.cancel.raw(),
        request_deadline.map_or(null_mut(), Event::raw),
    ];
    let handle_count = if request_deadline.is_some() { 3 } else { 2 };
    match unsafe { WaitForMultipleObjects(handle_count, handles.as_ptr(), 0, INFINITE) } {
        WAIT_OBJECT_0 => overlapped_result(handle, &operation),
        value if value == WAIT_OBJECT_0 + 1 => {
            cancel_and_complete(handle, &operation);
            Err(cancelled_io_error())
        }
        value if value == WAIT_OBJECT_0 + 2 && request_deadline.is_some() => {
            cancel_and_complete(handle, &operation);
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Windows terminal write deadline elapsed during I/O",
            ))
        }
        WAIT_FAILED => {
            let error = io::Error::last_os_error();
            cancel_and_complete(handle, &operation);
            Err(error)
        }
        unexpected => {
            cancel_and_complete(handle, &operation);
            Err(io::Error::other(format!(
                "unexpected Windows I/O wait result: {unexpected}"
            )))
        }
    }
}

fn event_is_set(event: &Event) -> io::Result<bool> {
    match unsafe { WaitForSingleObject(event.raw(), 0) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        WAIT_FAILED => Err(io::Error::last_os_error()),
        unexpected => Err(io::Error::other(format!(
            "unexpected Windows event wait result: {unexpected}"
        ))),
    }
}

fn cancelled_io_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "Windows terminal I/O was cancelled",
    )
}

fn overlapped_result(handle: HANDLE, operation: &OVERLAPPED) -> io::Result<usize> {
    let mut transferred = 0u32;
    if unsafe { GetOverlappedResult(handle, operation, &mut transferred, 0) } != 0 {
        return Ok(transferred as usize);
    }
    let error = unsafe { GetLastError() };
    if is_pipe_eof(error) {
        Ok(0)
    } else {
        Err(io::Error::from_raw_os_error(error as i32))
    }
}

fn cancel_and_complete(handle: HANDLE, operation: &OVERLAPPED) {
    // `ERROR_NOT_FOUND` means the exact operation completed before cancellation reached it. Other
    // failures are handled by the completion query below; the handle and OVERLAPPED remain valid.
    let _ = unsafe { CancelIoEx(handle, operation) };
    // The worker owns the OVERLAPPED structure and buffer until completion. Waiting here is the
    // memory-safety half of CancelIoEx; if the kernel delays completion it stalls only this isolated
    // worker, never the caller, Tokio runtime, Session pump, or daemon authority lock.
    let mut ignored = 0u32;
    unsafe {
        GetOverlappedResult(handle, operation, &mut ignored, 1);
    }
}

fn is_pipe_eof(error: u32) -> bool {
    matches!(error, ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED)
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::windows_private_pipe::{private_pipe, PipeDirection};
    use std::fs::File;
    use std::process::{Child, Command, Stdio};
    use std::time::Instant;

    const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(5);
    const CHILD_TIMEOUT: Duration = Duration::from_secs(15);
    const CHILD_CASE: &str = "HYDRA_WINDOWS_IO_FIXTURE";

    #[test]
    fn native_cancellation_is_an_error_not_pipe_eof() {
        assert!(is_pipe_eof(ERROR_BROKEN_PIPE));
        assert!(is_pipe_eof(ERROR_PIPE_NOT_CONNECTED));
        assert!(!is_pipe_eof(
            windows_sys::Win32::Foundation::ERROR_OPERATION_ABORTED
        ));
    }

    struct OwnedFixtureChild(Child);

    impl Drop for OwnedFixtureChild {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                // Child owns the exact Windows process handle; no PID lookup or foreign kill.
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }

    fn run_in_owned_child(case: &str) -> bool {
        let exact = format!("windows_overlapped_io::tests::{case}");
        run_exact_owned_child(&exact)
    }

    pub(crate) fn run_exact_owned_child(exact: &str) -> bool {
        if std::env::var_os(CHILD_CASE).as_deref() == Some(std::ffi::OsStr::new(&exact)) {
            return false;
        }
        // Only the same exact test is executable. No arbitrary command or shell; the marker
        // is child-local. Isolating each case also covers stalled synchronous fixture reads.
        let mut child = OwnedFixtureChild(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", exact, "--nocapture"])
                .env(CHILD_CASE, exact)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let mut stdout = child.0.stdout.take().unwrap();
        let deadline = Instant::now() + CHILD_TIMEOUT;
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(
                    status.success(),
                    "owned Windows fixture failed: {exact}: {status}"
                );
                // Fixture descendants never inherit this stdout pipe. After the exact child
                // exits its writer is closed; a bad filter selecting zero tests cannot pass.
                let mut output = String::new();
                stdout.read_to_string(&mut output).unwrap();
                let marker = format!("HYDRA_WINDOWS_IO_PASS:{exact}");
                assert!(
                    output.lines().any(|line| line == marker),
                    "missing completion marker: {exact}"
                );
                return true;
            }
            assert!(
                Instant::now() < deadline,
                "owned Windows fixture timed out: {exact}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        // The parent observes a deadline, then exact-process kill/wait cleans up. It does
        // not free any live child's OVERLAPPED storage from another thread or process.
    }

    struct Fixture {
        endpoint: Arc<PipeEndpoint>,
        peer: Option<File>,
        pending: mpsc::Receiver<()>,
        finished: mpsc::Receiver<()>,
    }

    impl Fixture {
        fn new(direction: PipeDirection) -> Self {
            let (handle, peer) = private_pipe(direction).unwrap();
            let (pending_tx, pending) = mpsc::channel();
            let (finished_tx, finished) = mpsc::channel();
            Self {
                endpoint: Arc::new(PipeEndpoint {
                    handle,
                    cancel: Arc::new(Event::manual_reset().unwrap()),
                    pending: Some(pending_tx),
                    finished: Some(finished_tx),
                }),
                peer: Some(File::from(peer)),
                pending,
                finished,
            }
        }

        fn pending(&self) {
            self.pending.recv_timeout(OBSERVATION_TIMEOUT).unwrap();
        }

        fn finished(&self) {
            // Sent only after the worker function has dropped its endpoint/event/storage.
            self.finished.recv_timeout(OBSERVATION_TIMEOUT).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.endpoint.cancel.set();
            self.peer.take();
            // These observation waits are not a hard teardown bound: workers keep pending
            // storage alive until the kernel reaches terminal completion after cancellation.
        }
    }

    #[test]
    fn reader_reuses_completion_event_and_preserves_exact_byte_order() {
        if run_in_owned_child("reader_reuses_completion_event_and_preserves_exact_byte_order") {
            return;
        }
        let mut fixture = Fixture::new(PipeDirection::HydraReads);
        let mut reader = OverlappedReader::start(fixture.endpoint.clone()).unwrap();
        fixture
            .peer
            .as_mut()
            .unwrap()
            .write_all(b"firstnext!")
            .unwrap();
        assert_eq!(reader.read(&mut []).unwrap(), 0);
        let mut bytes = [0; 5];
        reader.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"first");
        reader.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"next!");
        drop(reader);
        fixture.finished();
        println!("\nHYDRA_WINDOWS_IO_PASS:windows_overlapped_io::tests::reader_reuses_completion_event_and_preserves_exact_byte_order");
    }

    #[test]
    fn writer_reuses_completion_event_and_preserves_exact_byte_order() {
        if run_in_owned_child("writer_reuses_completion_event_and_preserves_exact_byte_order") {
            return;
        }
        let mut fixture = Fixture::new(PipeDirection::HydraWrites);
        let mut writer = OverlappedWriter::start(fixture.endpoint.clone()).unwrap();
        assert_eq!(writer.write(&[]).unwrap(), 0);
        writer.write_all(b"first").unwrap();
        writer.write_all(b"next!").unwrap();
        writer.flush().unwrap();
        let mut bytes = [0; 10];
        fixture
            .peer
            .as_mut()
            .unwrap()
            .read_exact(&mut bytes)
            .unwrap();
        assert_eq!(&bytes, b"firstnext!");
        drop(writer);
        fixture.finished();
        println!("\nHYDRA_WINDOWS_IO_PASS:windows_overlapped_io::tests::writer_reuses_completion_event_and_preserves_exact_byte_order");
    }

    #[test]
    fn genuine_pending_read_cancels_without_mutating_borrowed_caller_buffer() {
        if run_in_owned_child(
            "genuine_pending_read_cancels_without_mutating_borrowed_caller_buffer",
        ) {
            return;
        }
        let fixture = Fixture::new(PipeDirection::HydraReads);
        let mut reader = OverlappedReader::start(fixture.endpoint.clone()).unwrap();
        let (reply, outcome) = mpsc::channel();
        let caller = std::thread::spawn(move || {
            let mut bytes = [0x55; 8];
            let result = reader.read(&mut bytes);
            let _ = reply.send((result, bytes));
        });
        fixture.pending();
        fixture.endpoint.cancel.set().unwrap();
        let (result, bytes) = outcome.recv_timeout(OBSERVATION_TIMEOUT).unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(bytes, [0x55; 8]);
        caller.join().unwrap();
        fixture.finished();
        println!("\nHYDRA_WINDOWS_IO_PASS:windows_overlapped_io::tests::genuine_pending_read_cancels_without_mutating_borrowed_caller_buffer");
    }

    #[test]
    fn abandoned_read_reply_is_retired_before_next_request() {
        if run_in_owned_child("abandoned_read_reply_is_retired_before_next_request") {
            return;
        }
        let mut fixture = Fixture::new(PipeDirection::HydraReads);
        let mut reader = OverlappedReader::start(fixture.endpoint.clone()).unwrap();
        let (reply, abandoned) = mpsc::channel();
        reader
            .requests
            .send(ReadRequest { capacity: 3, reply })
            .unwrap();
        fixture.pending();
        drop(abandoned);
        fixture.peer.as_mut().unwrap().write_all(b"oldnew").unwrap();
        let mut bytes = [0; 3];
        reader.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"new");
        drop(reader);
        fixture.finished();
        println!("\nHYDRA_WINDOWS_IO_PASS:windows_overlapped_io::tests::abandoned_read_reply_is_retired_before_next_request");
    }

    #[test]
    fn deadline_retires_genuine_pending_io_before_same_event_and_pipe_reuse() {
        if run_in_owned_child(
            "deadline_retires_genuine_pending_io_before_same_event_and_pipe_reuse",
        ) {
            return;
        }
        // Deterministic shared deadline branch proof, using a silent pipe's ReadFile.
        // This is NOT a claim that a particular WriteFile size saturates the kernel quota.
        let mut fixture = Fixture::new(PipeDirection::HydraReads);
        let endpoint = fixture.endpoint.clone();
        let deadline = Arc::new(Event::manual_reset().unwrap());
        let worker_deadline = deadline.clone();
        let (reply, outcomes) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let event = Event::manual_reset().unwrap();
            let mut bytes = [0; 1];
            let result = overlapped_io_worker(
                &endpoint,
                &event,
                Some(&worker_deadline),
                |handle, op| unsafe { ReadFile(handle, bytes.as_mut_ptr(), 1, null_mut(), op) },
            );
            let _ = reply.send((result, bytes));
            // The first exact operation is terminal before this second one can start.
            let result = overlapped_io_worker(&endpoint, &event, None, |handle, op| unsafe {
                ReadFile(handle, bytes.as_mut_ptr(), 1, null_mut(), op)
            });
            let _ = reply.send((result, bytes));
        });
        fixture.pending();
        deadline.set().unwrap();
        let (result, _) = outcomes.recv_timeout(OBSERVATION_TIMEOUT).unwrap();
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        fixture.pending();
        fixture.peer.as_mut().unwrap().write_all(b"n").unwrap();
        let (result, bytes) = outcomes.recv_timeout(OBSERVATION_TIMEOUT).unwrap();
        assert_eq!(result.unwrap(), 1);
        assert_eq!(&bytes, b"n");
        worker.join().unwrap();
        println!("\nHYDRA_WINDOWS_IO_PASS:windows_overlapped_io::tests::deadline_retires_genuine_pending_io_before_same_event_and_pipe_reuse");
    }

    #[test]
    fn foreground_write_timeout_keeps_owned_bytes_and_expired_request_is_not_replayed() {
        if run_in_owned_child(
            "foreground_write_timeout_keeps_owned_bytes_and_expired_request_is_not_replayed",
        ) {
            return;
        }
        let mut fixture = Fixture::new(PipeDirection::HydraWrites);
        // Deliberately defer admission to exercise the real foreground two-second timeout,
        // then hand that same owned request to the real worker. No kernel-write claim here.
        let (requests, incoming) = mpsc::sync_channel(1);
        let mut caller_writer = OverlappedWriter {
            endpoint: fixture.endpoint.clone(),
            requests,
        };
        let (reply, outcome) = mpsc::channel();
        let caller = std::thread::spawn(move || {
            let bytes = vec![b'o', b'l', b'd'];
            let result = caller_writer.write(&bytes);
            drop(bytes);
            let _ = reply.send(result);
        });
        let mut expired = incoming.recv_timeout(OBSERVATION_TIMEOUT).unwrap();
        let error = outcome
            .recv_timeout(OBSERVATION_TIMEOUT)
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        caller.join().unwrap();
        assert_eq!(expired.data, b"old");
        assert!(event_is_set(&expired.deadline).unwrap());
        assert!(
            expired.reply.send(Ok(3)).is_err(),
            "late result has no receiver"
        );
        // Observe retirement with a fresh fixture-only reply; the owned bytes/deadline
        // are unchanged. This also avoids racing the one-request backpressure queue.
        let (retired_reply, retired) = mpsc::channel();
        expired.reply = retired_reply;
        let mut writer = OverlappedWriter::start(fixture.endpoint.clone()).unwrap();
        writer.requests.send(expired).unwrap();
        assert_eq!(
            retired
                .recv_timeout(OBSERVATION_TIMEOUT)
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
        writer.write_all(b"new").unwrap();
        let mut bytes = [0; 3];
        fixture
            .peer
            .as_mut()
            .unwrap()
            .read_exact(&mut bytes)
            .unwrap();
        assert_eq!(&bytes, b"new", "expired request must issue no bytes");
        drop(writer);
        fixture.finished();
        println!("\nHYDRA_WINDOWS_IO_PASS:windows_overlapped_io::tests::foreground_write_timeout_keeps_owned_bytes_and_expired_request_is_not_replayed");
    }

    #[test]
    fn expired_request_reports_reason_before_admission_then_worker_continues() {
        if run_in_owned_child(
            "expired_request_reports_reason_before_admission_then_worker_continues",
        ) {
            return;
        }
        let mut fixture = Fixture::new(PipeDirection::HydraWrites);
        let mut writer = OverlappedWriter::start(fixture.endpoint.clone()).unwrap();
        let deadline = Arc::new(Event::manual_reset().unwrap());
        deadline.set().unwrap();
        let (reply, outcome) = mpsc::channel();
        writer
            .requests
            .send(WriteRequest {
                data: b"old".to_vec(),
                deadline,
                reply,
            })
            .unwrap();
        let error = outcome
            .recv_timeout(OBSERVATION_TIMEOUT)
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("before I/O admission"));
        writer.write_all(b"new").unwrap();
        let mut bytes = [0; 3];
        fixture
            .peer
            .as_mut()
            .unwrap()
            .read_exact(&mut bytes)
            .unwrap();
        assert_eq!(&bytes, b"new");
        drop(writer);
        fixture.finished();
        println!("\nHYDRA_WINDOWS_IO_PASS:windows_overlapped_io::tests::expired_request_reports_reason_before_admission_then_worker_continues");
    }

    #[test]
    fn closed_peer_yields_eof_and_cancelled_writer_issues_nothing() {
        if run_in_owned_child("closed_peer_yields_eof_and_cancelled_writer_issues_nothing") {
            return;
        }
        let mut fixture = Fixture::new(PipeDirection::HydraReads);
        let mut reader = OverlappedReader::start(fixture.endpoint.clone()).unwrap();
        fixture.peer.take();
        assert_eq!(reader.read(&mut [0; 1]).unwrap(), 0);
        drop(reader);
        fixture.finished();
        let fixture = Fixture::new(PipeDirection::HydraWrites);
        let mut writer = OverlappedWriter::start(fixture.endpoint.clone()).unwrap();
        fixture.endpoint.cancel.set().unwrap();
        assert_eq!(
            writer.write(b"no").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        drop(writer);
        fixture.finished();
        println!("\nHYDRA_WINDOWS_IO_PASS:windows_overlapped_io::tests::closed_peer_yields_eof_and_cancelled_writer_issues_nothing");
    }

    #[test]
    fn queue_backpressure_and_disconnection_do_not_replay_requests() {
        if run_in_owned_child("queue_backpressure_and_disconnection_do_not_replay_requests") {
            return;
        }
        let (sender, receiver) = mpsc::sync_channel(1);
        enqueue_io_request(&sender, 1, "write").unwrap();
        assert_eq!(
            enqueue_io_request(&sender, 2, "write").unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(receiver.recv().unwrap(), 1);
        assert_eq!(receiver.try_recv().unwrap_err(), mpsc::TryRecvError::Empty);
        drop(receiver);
        assert_eq!(
            enqueue_io_request(&sender, 3, "write").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        println!("\nHYDRA_WINDOWS_IO_PASS:windows_overlapped_io::tests::queue_backpressure_and_disconnection_do_not_replay_requests");
    }
}
