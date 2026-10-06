//! Local daemon transport only. Windows uses the shell's authenticated pipe implementation;
//! the async adapter never opens a second connection or changes the shared daemon wire.

use std::{io, path::Path};

#[cfg(windows)]
pub(crate) use maestro_shell::WindowsPipeStream as SyncDaemonStream;
#[cfg(unix)]
pub(crate) use std::os::unix::net::UnixStream as SyncDaemonStream;
#[cfg(unix)]
pub(crate) use tokio::net::UnixStream as AsyncDaemonStream;
#[cfg(windows)]
pub(crate) type AsyncDaemonStream = blocking::AsyncStream<SyncDaemonStream>;

pub(crate) fn connect_sync(path: &Path) -> io::Result<SyncDaemonStream> {
    #[cfg(unix)]
    {
        SyncDaemonStream::connect(path)
    }
    #[cfg(windows)]
    {
        SyncDaemonStream::connect_until(
            path,
            std::time::Instant::now() + std::time::Duration::from_millis(750),
        )
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::Duration,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    fn endpoint() -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        format!(
            r"\\.\pipe\Hydra.Maestro.agent-transport-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )
        .into()
    }

    async fn pair() -> (AsyncDaemonStream, NamedPipeServer) {
        let path = endpoint();
        // Publish our owned server before connecting. Production absent-pipe behavior must not
        // gain an implicit retry just to conceal a fixture readiness race.
        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&path)
            .unwrap();
        let (client, accepted) = tokio::join!(connect_async(&path), server.connect());
        accepted.unwrap();
        let client = client.unwrap();
        let mut prelude = [0];
        server.read_exact(&mut prelude).await.unwrap();
        assert_eq!(prelude, [b'\n']);
        assert_eq!(client.server_pid(), std::process::id());
        (client, server)
    }

    #[tokio::test]
    async fn windows_authenticated_adapter_keeps_probe_and_operational_bytes_on_one_pipe() {
        let (mut client, mut server) = pair().await;
        let witness = client.daemon_process_witness();
        assert!(witness
            .matches_live(&client.daemon_process_witness())
            .unwrap());
        server.write_all(b"probe\noutput\n").await.unwrap();
        let mut probe = [0; 6];
        client.read_exact(&mut probe).await.unwrap();
        assert_eq!(&probe, b"probe\n");
        let (mut read, mut write) = client.into_split();
        let mut output = [0; 7];
        read.read_exact(&mut output).await.unwrap();
        assert_eq!(&output, b"output\n");
        write.write_all(b"input").await.unwrap();
        let mut input = [0; 5];
        tokio::time::timeout(Duration::from_secs(2), server.read_exact(&mut input))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&input, b"input");
        drop(read);
        drop(write);
        let mut byte = [0];
        let closed = tokio::time::timeout(Duration::from_secs(2), server.read(&mut byte))
            .await
            .unwrap();
        assert!(
            matches!(closed, Ok(0) | Err(_)),
            "a process witness must not retain a pipe attachment"
        );
    }

    #[tokio::test]
    async fn windows_adapter_absent_endpoint_is_not_a_timeout() {
        let error = match connect_async(&endpoint()).await {
            Ok(_) => panic!("fresh absent pipe unexpectedly connected"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[tokio::test]
    async fn windows_native_flush_waits_for_backpressure_and_reports_disconnect() {
        let (mut client, mut server) = pair().await;
        let block: Vec<u8> = (0..64 * 1024).map(|index| (index % 251) as u8).collect();
        let mut stalled = false;
        let mut admitted = 0;
        for _ in 0..128 {
            client.write_all(&block).await.unwrap();
            admitted += block.len();
            if tokio::time::timeout(Duration::from_millis(30), client.flush())
                .await
                .is_err()
            {
                stalled = true;
                break;
            }
        }
        assert!(
            stalled,
            "native flush must wait when the owned server stops reading"
        );
        let mut received = vec![0; admitted];
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::try_join!(client.flush(), server.read_exact(&mut received))
        })
        .await
        .unwrap()
        .unwrap();
        for chunk in received.chunks_exact(block.len()) {
            assert_eq!(chunk, block);
        }
        // Flush proves native publication, not remote consumption. A timeout also includes
        // worker scheduling, and an already completed kernel write can race disconnect.
        // Verify every admitted byte above, then require a *new* post-disconnect write to fail.
        // Controlled-stream tests separately prove pending write/flush failures stay sticky.
        server.disconnect().unwrap();
        client.write_all(b"post-disconnect").await.unwrap();
        let error = tokio::time::timeout(Duration::from_secs(2), client.flush())
            .await
            .unwrap();
        assert!(
            error.is_err(),
            "a fresh post-disconnect publication must fail during native completion"
        );
        assert!(client.flush().await.is_err(), "write failure stays sticky");
    }

    #[tokio::test]
    async fn windows_adapter_blocked_writer_cancels_without_waiting_for_server_read() {
        let (mut client, mut server) = pair().await;
        let payload = vec![0; 8 * 1024 * 1024];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), client.write_all(&payload))
                .await
                .is_err()
        );
        drop(client);
        // Drain only after dropping the client. EOF/error must follow the bounded admitted bytes.
        let mut received = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), server.read_to_end(&mut received))
            .await
            .unwrap();
        assert!(received.len() < payload.len());
    }
}

pub(crate) async fn connect_async(path: &Path) -> io::Result<AsyncDaemonStream> {
    #[cfg(unix)]
    {
        AsyncDaemonStream::connect(path).await
    }
    #[cfg(windows)]
    {
        // Establish the deadline before queueing; a saturated blocking pool cannot extend it.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(750);
        let path = path.to_path_buf();
        let stream =
            tokio::task::spawn_blocking(move || SyncDaemonStream::connect_until(&path, deadline))
                .await
                .map_err(io::Error::other)??;
        AsyncDaemonStream::new(stream)
    }
}

#[cfg(any(windows, test))]
mod blocking {
    use std::{
        future::Future,
        io::{self, Read, Write},
        net::Shutdown,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };
    #[cfg(test)]
    use tokio::io::AsyncReadExt;
    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

    // Two independent directions are essential: an idle read must never serialize PTY input.
    // Input has one fixed-size buffer and one bounded duplex queue. Output admits at most one
    // fixed-size native write at a time, and flush waits for its actual write/flush completion.
    // No unbounded channel, payload log, or blocking call runs on a Tokio async worker.
    const BUFFER_BYTES: usize = 64 * 1024;

    pub(crate) trait BlockingStream: Read + Write + Send + Unpin + 'static {
        fn clone_stream(&self) -> io::Result<Self>
        where
            Self: Sized;
        fn abort(&self);
    }

    #[cfg(windows)]
    impl BlockingStream for maestro_shell::WindowsPipeStream {
        fn clone_stream(&self) -> io::Result<Self> {
            self.try_clone()
        }
        fn abort(&self) {
            let _ = self.shutdown(Shutdown::Both);
        }
    }

    #[cfg(all(test, unix))]
    impl BlockingStream for std::os::unix::net::UnixStream {
        fn clone_stream(&self) -> io::Result<Self> {
            self.try_clone()
        }
        fn abort(&self) {
            let _ = self.shutdown(Shutdown::Both);
        }
    }

    fn copy_error(error: &io::Error) -> io::Error {
        match error.raw_os_error() {
            Some(code) => io::Error::from_raw_os_error(code),
            None => io::Error::new(error.kind(), error.to_string()),
        }
    }

    pub(crate) struct AsyncStream<S: BlockingStream> {
        io: DuplexStream,
        control: S,
        read_failure: Arc<Mutex<Option<io::Error>>>,
        pending_write: Option<tokio::task::JoinHandle<io::Result<()>>>,
        write_failure: Option<io::Error>,
        write_closed: bool,
    }

    impl<S: BlockingStream> AsyncStream<S> {
        pub(crate) fn new(stream: S) -> io::Result<Self> {
            let mut input = stream.clone_stream()?;
            let (io, mut from_pipe) = tokio::io::duplex(BUFFER_BYTES);
            let read_failure = Arc::new(Mutex::new(None));
            let worker_failure = read_failure.clone();
            let read_runtime = tokio::runtime::Handle::current();
            tokio::task::spawn_blocking(move || {
                let mut buffer = vec![0; BUFFER_BYTES];
                loop {
                    let count = match input.read(&mut buffer) {
                        Ok(0) => break,
                        Err(error) => {
                            *worker_failure
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error);
                            break;
                        }
                        Ok(count) => count,
                    };
                    if read_runtime
                        .block_on(from_pipe.write_all(&buffer[..count]))
                        .is_err()
                    {
                        break;
                    }
                }
                // EOF is a read-side event, not permission to discard already accepted output.
                // The operational owner may retire the connection after observing EOF; its Drop
                // then cancels native I/O. An observer retaining this stream can still flush it.
                let _ = read_runtime.block_on(from_pipe.shutdown());
            });
            Ok(Self {
                io,
                control: stream,
                read_failure,
                pending_write: None,
                write_failure: None,
                write_closed: false,
            })
        }

        fn fail_write(&mut self, error: io::Error) -> io::Error {
            self.control.abort();
            self.write_failure = Some(error);
            copy_error(self.write_failure.as_ref().expect("stored write failure"))
        }

        fn poll_write_completion(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            if let Some(error) = &self.write_failure {
                return Poll::Ready(Err(copy_error(error)));
            }
            let Some(pending) = &mut self.pending_write else {
                return Poll::Ready(Ok(()));
            };
            let result = match Pin::new(pending).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result.map_err(io::Error::other).and_then(|result| result),
            };
            self.pending_write = None;
            Poll::Ready(result.map_err(|error| self.fail_write(error)))
        }

        pub(crate) fn into_split(self) -> (tokio::io::ReadHalf<Self>, tokio::io::WriteHalf<Self>) {
            tokio::io::split(self)
        }
    }

    #[cfg(windows)]
    impl AsyncStream<maestro_shell::WindowsPipeStream> {
        pub(crate) fn daemon_process_witness(&self) -> maestro_shell::WindowsDaemonProcessWitness {
            self.control.daemon_process_witness()
        }
        pub(crate) fn server_pid(&self) -> u32 {
            self.control.server_pid()
        }
    }

    impl<S: BlockingStream> Drop for AsyncStream<S> {
        fn drop(&mut self) {
            // Cancellation of the protocol probe or both operational halves interrupts native
            // reads/writes immediately. Retained process witnesses do not keep this pipe alive.
            self.control.abort();
        }
    }

    impl<S: BlockingStream> AsyncRead for AsyncStream<S> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let before = buf.filled().len();
            match Pin::new(&mut this.io).poll_read(cx, buf) {
                Poll::Ready(Ok(())) if before == buf.filled().len() && buf.remaining() != 0 => {
                    let failure = this
                        .read_failure
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    Poll::Ready(match failure.as_ref() {
                        Some(error) => Err(copy_error(error)),
                        None => Ok(()),
                    })
                }
                result => result,
            }
        }
    }
    impl<S: BlockingStream> AsyncWrite for AsyncStream<S> {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            std::task::ready!(this.poll_write_completion(cx))?;
            if this.write_closed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "daemon writer is shut down",
                )));
            }
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let mut writer = match this.control.clone_stream() {
                Ok(writer) => writer,
                Err(error) => return Poll::Ready(Err(this.fail_write(error))),
            };
            let count = buf.len().min(BUFFER_BYTES);
            let bytes = buf[..count].to_vec();
            this.pending_write = Some(tokio::task::spawn_blocking(move || {
                writer.write_all(&bytes)?;
                writer.flush()
            }));
            // Like any buffered writer this admits bytes before native completion. A second
            // write cannot pass this one, and flush/shutdown must observe its real result.
            Poll::Ready(Ok(count))
        }
        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.get_mut().poll_write_completion(cx)
        }
        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            std::task::ready!(this.poll_write_completion(cx))?;
            this.write_closed = true;
            this.control.abort();
            Poll::Ready(Ok(()))
        }
    }

    #[cfg(test)]
    mod completion_tests {
        use super::*;
        use std::{sync::Condvar, time::Duration};

        #[derive(Default)]
        struct State {
            read_eof: bool,
            write_started: bool,
            allow_write: bool,
            flush_started: bool,
            allow_flush: bool,
            fail_write: bool,
            fail_flush: bool,
            aborted: bool,
            bytes: Vec<u8>,
        }

        #[derive(Clone, Default)]
        struct ControlledStream(Arc<(Mutex<State>, Condvar)>);

        impl ControlledStream {
            fn change(&self, update: impl FnOnce(&mut State)) {
                update(&mut self.0 .0.lock().unwrap());
                self.0 .1.notify_all();
            }
            async fn wait_for(&self, ready: impl Fn(&State) -> bool) {
                tokio::time::timeout(Duration::from_secs(2), async {
                    while !ready(&self.0 .0.lock().unwrap()) {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                })
                .await
                .unwrap();
            }
        }

        impl Read for ControlledStream {
            fn read(&mut self, _bytes: &mut [u8]) -> io::Result<usize> {
                let mut state = self.0 .0.lock().unwrap();
                while !state.read_eof && !state.aborted {
                    state = self.0 .1.wait(state).unwrap();
                }
                Ok(0)
            }
        }

        impl Write for ControlledStream {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let mut state = self.0 .0.lock().unwrap();
                state.write_started = true;
                self.0 .1.notify_all();
                while !state.allow_write && !state.aborted {
                    state = self.0 .1.wait(state).unwrap();
                }
                if state.aborted || state.fail_write {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "controlled write failure",
                    ));
                }
                state.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                let mut state = self.0 .0.lock().unwrap();
                state.flush_started = true;
                self.0 .1.notify_all();
                while !state.allow_flush && !state.aborted {
                    state = self.0 .1.wait(state).unwrap();
                }
                if state.aborted || state.fail_flush {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "controlled flush failure",
                    ));
                }
                Ok(())
            }
        }

        impl BlockingStream for ControlledStream {
            fn clone_stream(&self) -> io::Result<Self> {
                Ok(self.clone())
            }
            fn abort(&self) {
                self.change(|state| state.aborted = true);
            }
        }

        #[tokio::test]
        async fn flush_waits_for_native_write_and_native_flush_completion() {
            let transport = ControlledStream::default();
            let mut client = AsyncStream::new(transport.clone()).unwrap();
            client.write_all(b"request").await.unwrap();
            transport.wait_for(|state| state.write_started).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(30), client.flush())
                    .await
                    .is_err()
            );
            assert!(transport.0 .0.lock().unwrap().bytes.is_empty());
            transport.change(|state| state.allow_write = true);
            transport.wait_for(|state| state.flush_started).await;
            assert!(
                tokio::time::timeout(Duration::from_millis(30), client.flush())
                    .await
                    .is_err()
            );
            transport.change(|state| state.allow_flush = true);
            client.flush().await.unwrap();
            assert_eq!(&transport.0 .0.lock().unwrap().bytes, b"request");
        }

        #[tokio::test]
        async fn native_write_and_flush_failures_are_returned_and_sticky() {
            for fail_write in [true, false] {
                let transport = ControlledStream::default();
                transport.change(|state| {
                    state.allow_write = true;
                    state.allow_flush = true;
                    state.fail_write = fail_write;
                    state.fail_flush = !fail_write;
                });
                let mut client = AsyncStream::new(transport.clone()).unwrap();
                client.write_all(b"request").await.unwrap();
                assert_eq!(
                    client.flush().await.unwrap_err().kind(),
                    io::ErrorKind::ConnectionReset
                );
                assert_eq!(
                    client.flush().await.unwrap_err().kind(),
                    io::ErrorKind::ConnectionReset
                );
                assert_eq!(
                    client.write_all(b"later").await.unwrap_err().kind(),
                    io::ErrorKind::ConnectionReset
                );
                let state = transport.0 .0.lock().unwrap();
                assert!(state.aborted);
                assert_eq!(
                    state.bytes.as_slice(),
                    if fail_write {
                        b"".as_slice()
                    } else {
                        b"request".as_slice()
                    }
                );
            }
        }

        #[tokio::test]
        async fn read_eof_does_not_discard_an_accepted_write() {
            let transport = ControlledStream::default();
            let mut client = AsyncStream::new(transport.clone()).unwrap();
            client.write_all(b"request").await.unwrap();
            transport.wait_for(|state| state.write_started).await;
            transport.change(|state| state.read_eof = true);
            let mut byte = [0];
            assert_eq!(client.read(&mut byte).await.unwrap(), 0);
            assert!(!transport.0 .0.lock().unwrap().aborted);
            assert!(
                tokio::time::timeout(Duration::from_millis(30), client.flush())
                    .await
                    .is_err()
            );
            transport.change(|state| {
                state.allow_write = true;
                state.allow_flush = true;
            });
            client.flush().await.unwrap();
            assert_eq!(&transport.0 .0.lock().unwrap().bytes, b"request");
        }

        #[tokio::test]
        async fn shutdown_waits_for_accepted_output_then_rejects_new_writes() {
            let transport = ControlledStream::default();
            let mut client = AsyncStream::new(transport.clone()).unwrap();
            client.write_all(b"request").await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(30), client.shutdown())
                    .await
                    .is_err()
            );
            transport.change(|state| {
                state.allow_write = true;
                state.allow_flush = true;
            });
            client.shutdown().await.unwrap();
            assert_eq!(&transport.0 .0.lock().unwrap().bytes, b"request");
            assert_eq!(
                client.write_all(b"later").await.unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
        }
    }

    #[cfg(all(test, unix))]
    mod tests {
        use super::*;
        use std::{os::unix::net::UnixStream, time::Duration};

        #[tokio::test]
        async fn buffered_probe_preserves_operational_bytes_and_idle_read_allows_write() {
            let (client, mut server) = UnixStream::pair().unwrap();
            let mut client = AsyncStream::new(client).unwrap();
            let fixture = std::thread::spawn(move || {
                server
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                server.write_all(b"probe\noutput\n").unwrap();
                let mut request = [0; 5];
                server.read_exact(&mut request).unwrap();
                assert_eq!(&request, b"input");
            });
            let mut byte = [0];
            for expected in b"probe\n" {
                client.read_exact(&mut byte).await.unwrap();
                assert_eq!(byte[0], *expected);
            }
            let (mut read, mut write) = client.into_split();
            let mut remaining = [0; 7];
            read.read_exact(&mut remaining).await.unwrap();
            assert_eq!(&remaining, b"output\n");
            write.write_all(b"input").await.unwrap();
            write.flush().await.unwrap();
            tokio::task::spawn_blocking(move || fixture.join().unwrap())
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn dropping_both_halves_interrupts_idle_native_read() {
            let (client, mut server) = UnixStream::pair().unwrap();
            server
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let client = AsyncStream::new(client).unwrap();
            let (read, write) = client.into_split();
            drop(read);
            drop(write);
            let closed = tokio::task::spawn_blocking(move || {
                let mut byte = [0];
                server.read(&mut byte).unwrap()
            })
            .await
            .unwrap();
            assert_eq!(closed, 0);
        }

        #[tokio::test]
        async fn blocked_writer_is_bounded_and_cancellable() {
            let (client, _server) = UnixStream::pair().unwrap();
            let mut client = AsyncStream::new(client).unwrap();
            let payload = vec![0; 8 * 1024 * 1024];
            assert!(
                tokio::time::timeout(Duration::from_millis(100), client.write_all(&payload))
                    .await
                    .is_err()
            );
            drop(client);
            // Runtime teardown waits for the native workers; a leaked blocked write hangs this test.
        }
    }
}
